"""Host-only isolated builds and exact selectable-artifact replay checks.

These are local evidence checks, never BinRadar FINAL verification.
"""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shutil
import sys
from tempfile import TemporaryDirectory

from .dataset import PreparedDataset
from .execution import ExecutionUnavailable, execute_built, sha256
from .family import parse_candidate
from .native import kill_process, native_environment


async def build_candidate(dataset: PreparedDataset, predicate: str, directory: Path) -> dict:
    """Build one exact predicate in a newly reserved private artifact directory.

    Frozen inputs are authenticated before copying and after the subprocess
    settles. Native commands retain the shared fail-closed Linux sandbox.
    """
    import binradar
    from binradar import paths

    candidate = Path(directory).resolve()
    if candidate == dataset.root.resolve() or dataset.root.resolve() in candidate.parents:
        raise ValueError('build directory must be outside frozen dataset')
    with dataset.validation() as validated:
        parsed = parse_candidate(validated.patch_format, predicate)
        candidate.mkdir(mode=0o700, parents=True)
        names = [validated.binary + '.orig', 'patch-location', 'patch-destination', 'patch-format']
        if validated.patch_format == 'ERM CWE-805':
            names.append('stack-size')
            (candidate / 'trace').mkdir(mode=0o700)
            names.extend(f'trace/{allocator}.{suffix}'
                         for allocator in ('malloc', 'calloc', 'realloc')
                         for suffix in ('calls', 'returns')
                         if f'trace/{allocator}.{suffix}' in validated.manifest['artifacts'])
        for name in names:
            destination = candidate / name
            shutil.copyfile(validated.artifact(name), destination)
            if sha256(destination) != validated.manifest['artifacts'][name]['sha256']:
                raise ValueError('build copied artifact mismatch')
            destination.chmod(0o500 if name.endswith('.orig') else 0o600)
        original = candidate / (validated.binary + '.orig')
        expected = validated.manifest['artifacts'][validated.binary + '.orig']['sha256']
        config = candidate / 'config.env'
        with config.open('x', encoding='utf-8') as stream:
            os.chmod(config, 0o600)
            stream.write(f'BINARY={validated.binary}\n')
        environment = native_environment()
        environment.update(E9TOOL=paths.e9tool(), E9COMPILE=paths.e9compile())
        roots = list(dict.fromkeys([str(Path(__file__).resolve().parent.parent),
                                  str(Path(binradar.__file__).resolve().parent.parent),
                                  *(str(Path(p).resolve()) for p in sys.path if p and Path(p).is_absolute())]))
        bootstrap = ('import json,sys;from pathlib import Path;sys.path[:0]=json.loads(sys.argv[1]);'
                     'from taosc_llm.builder import generate_patch;from taosc_llm.native import build_command;'
                     'print(json.dumps(generate_patch(Path(sys.argv[2]),Path(sys.argv[3]),sys.argv[4],native_runner=build_command)))')
        process = await asyncio.create_subprocess_exec(
            sys.executable, '-I', '-c', bootstrap, json.dumps(roots), str(config),
            str(candidate), parsed.expression, cwd=candidate, env=environment,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, start_new_session=True)
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=1800)
        except BaseException:
            await kill_process(process)
            raise
        log = candidate.parent / 'build.log'
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(stderr[:65536])
        if process.returncode or len(stdout) > 1024 * 1024:
            raise RuntimeError('isolated candidate build failed; see private build.log')
        result = json.loads(stdout)
        if (not isinstance(result, dict) or result.get('status') != 'built'
                or result.get('verified') is not False or result.get('predicate') != parsed.expression
                or result.get('descriptor') != parsed.descriptor):
            raise RuntimeError('unexpected native build result')
        if sha256(original) != expected:
            raise ValueError('build changed frozen original copy')
        result['original_sha256'] = expected
        artifacts = result.get('artifacts')
        if not isinstance(artifacts, dict) or not artifacts:
            raise RuntimeError('missing native build artifacts')
        for name, value in artifacts.items():
            path = Path(value)
            if (Path(name).name != name or path != candidate / name
                    or path.is_symlink() or not path.is_file()):
                raise ValueError('native build artifact escapes candidate directory')
            path.chmod(0o500 if name in (validated.binary + '.patched', validated.binary + '.brpatched') else 0o600)
        result['artifact_hashes'] = {name: sha256(Path(path)) for name, path in artifacts.items()}
        result['native_isolation'] = 'linux-landlock-seccomp'
        _authenticated_build(validated, result)
    dataset.verify_artifacts()
    return result


def _authenticated_build(dataset, build):
    parsed = parse_candidate(dataset.patch_format, build['predicate'])
    if (build.get('status') != 'built' or build.get('verified') is not False
            or build.get('binary') != dataset.binary or build.get('patch_format') != dataset.patch_format
            or build.get('descriptor') != parsed.descriptor
            or build.get('source_predicate') != parsed.source_predicate
            or build.get('patch_location') != hex(dataset.manifest['patch']['location'])
            or build.get('patch_destination') != hex(dataset.manifest['patch']['destination'])
            or build.get('binradar_activation') != {'PATCH_ID': '1'}
            or build.get('original_sha256') != dataset.manifest['artifacts'][dataset.binary + '.orig']['sha256']):
        raise ValueError('build identity mismatch')
    artifacts, hashes = build.get('artifacts'), build.get('artifact_hashes')
    if not isinstance(artifacts, dict) or not isinstance(hashes, dict) or artifacts.keys() != hashes.keys():
        raise ValueError('build artifact inventory mismatch')
    required = {
        'patch-format', 'predicates', 'brpatches.json', 'brpatches.inc', 'brpatch.c',
        'taosc-llm-runtime.c', 'taosc-llm-selector.c', 'predicate.h',
        *(dataset.binary + suffix + extension
          for suffix in ('.patched', '.brpatched')
          for extension in ('', '.json', '.e9map.json')),
    }
    if artifacts.keys() != required:
        raise ValueError('fixed/selectable build artifact inventory mismatch')
    roots = set()
    for name, value in artifacts.items():
        path = Path(value)
        if (Path(name).name != name or not path.is_absolute() or path.name != name
                or path.is_symlink() or not path.is_file() or sha256(path) != hashes[name]):
            raise ValueError('build artifact identity mismatch')
        roots.add(path.parent.resolve())
    if len(roots) != 1:
        raise ValueError('build artifacts must share one owned directory')
    root = roots.pop()
    if dataset.root.resolve() == root or dataset.root.resolve() in root.parents:
        raise ValueError('build directory must be outside frozen dataset')
    original = root / (dataset.binary + '.orig')
    if original.is_symlink() or not original.is_file() or sha256(original) != build['original_sha256']:
        raise ValueError('built original identity mismatch')
    from binradar.binradar_taosc_predicates import load_runtime_predicates, predicate_descriptor
    family, table = load_runtime_predicates(Path(artifacts['brpatches.json']))
    if family != parsed.family or set(table) != {1} or predicate_descriptor(table[1]) != parsed.descriptor:
        raise ValueError('built runtime predicate identity mismatch')
    if (Path(artifacts['patch-format']).read_text().strip() != dataset.patch_format
            or Path(artifacts['predicates']).read_text().strip() != parsed.source_predicate):
        raise ValueError('built source predicate identity mismatch')
    return parsed


def _normalized_outcome(dataset, case, outcome):
    from .evaluation import _same_crash
    from binradar.binradar_verifier import CONCRETE_ORACLE

    if not isinstance(outcome, dict):
        return None
    if outcome.get('oracle', outcome.get('concrete-oracle')) != CONCRETE_ORACLE:
        return None
    observed = outcome.get('outcome')
    if observed is None:
        observed = {'ok': 'normal', 'crash': 'crash'}.get(outcome.get('exit'))
    if observed == 'normal':
        return 'normal'
    same = _same_crash(dataset, case, {'outcome': outcome})
    if observed != 'crash' or same is None:
        return None
    # Normalized program fault address, not E9 trampoline/runtime PC.
    address = outcome.get('fault_addr', outcome.get('fault-addr'))
    return ('target_crash' if same else 'other_crash', address)


def verify_built_candidate(dataset: PreparedDataset, build: dict, evaluation: dict, *, workers=1) -> dict:
    """Compare exact fixed/id1 execution and selectable id0 neutral controls.

    Mutation plans cannot be transferred to this artifact: they remain explicitly
    unavailable. Incomplete/trapped/unknown evidence is never a passing check.
    Each concrete case needs at most three actual target executions. Any actual
    outcome or ordered text-vector mismatch raises ValueError; matched is local
    artifact parity, never repair verification or BinRadar FINAL.
    """
    if type(workers) is not int or not 1 <= workers <= 32:
        raise ValueError('workers must be in 1..32')
    with dataset.validation() as validated:
        parsed = _authenticated_build(validated, build)
        if (evaluation.get('dataset_id') != validated.dataset_id
                or evaluation.get('descriptor') != parsed.descriptor
                or evaluation.get('predicate') != parsed.expression):
            raise ValueError('evaluation identity mismatch')
        items = evaluation.get('cases')
        if not isinstance(items, list):
            raise ValueError('evaluation cases unavailable')
        from .poc import poc_case
        by_id = {case['id']: case for case in validated.cases()}
        poc = poc_case(validated)
        if poc is not None:
            by_id.setdefault(poc['id'], poc)
        seen = set()
        for item in items:
            case_id = item.get('case_id') if isinstance(item, dict) else None
            if case_id not in by_id or case_id in seen or item.get('domain') != by_id[case_id]['domain']:
                raise ValueError('unknown or duplicate scoped evaluation case')
            seen.add(case_id)
        with TemporaryDirectory(prefix='taosc-built-replay-') as temporary:
            def check(item):
                case = by_id[item['case_id']]
                result = {'case_id': case['id'], 'domain': case['domain'], 'status': 'unavailable'}
                if case['domain'] != 'system':
                    return {**result, 'reason': 'built-artifact-mutation-replay-unavailable'}
                expected = _normalized_outcome(validated, case, item.get('outcome'))
                branches = item.get('branches')
                if (item.get('status') == 'unavailable' or expected is None
                        or not isinstance(branches, list) or any(type(b) is not int or b not in (0, 1) for b in branches)):
                    return {**result, 'reason': 'evaluation-evidence-unavailable'}
                neutral = item.get('neutral_baseline')
                neutral_outcome = _normalized_outcome(validated, case, neutral.get('outcome')) if isinstance(neutral, dict) else None
                neutral_branches = neutral.get('branches') if isinstance(neutral, dict) else None
                if (neutral_outcome is None or neutral.get('status') == 'unavailable'
                        or not isinstance(neutral_branches, list)
                        or any(type(b) is not int or b != 0 for b in neutral_branches)):
                    return {**result, 'reason': 'neutral-evidence-unavailable'}
                observations = {}
                for mode, artifact, patch_id, wanted_outcome, wanted_branches in (
                        ('selectable_id1', 'selectable', 1, expected, branches),
                        ('selectable_id0', 'selectable', 0, neutral_outcome, neutral_branches),
                        # Deliberately request id0: the fixed runtime must remain on.
                        ('fixed', 'fixed', 0, expected, branches)):
                    try:
                        actual = execute_built(validated, case, build, Path(temporary),
                                               artifact=artifact, patch_id=patch_id)
                    except ExecutionUnavailable as error:
                        return {**result, 'reason': str(error), 'mode': mode,
                                'observations': observations}
                    outcome = _normalized_outcome(validated, case, actual.get('outcome'))
                    if actual.get('branches') != wanted_branches:
                        raise ValueError(f'built candidate branch mismatch: {case["id"]} ({mode})')
                    if outcome is None:
                        return {**result, 'reason': 'built-outcome-oracle-unavailable', 'mode': mode,
                                'observations': observations}
                    if outcome != wanted_outcome:
                        raise ValueError(f'built candidate outcome mismatch: {case["id"]} ({mode})')
                    suffix = '.patched' if artifact == 'fixed' else '.brpatched'
                    if actual.get('artifact_sha256') != build['artifact_hashes'][validated.binary + suffix]:
                        raise ValueError('built execution artifact identity mismatch')
                    observations[mode] = actual
                actual = observations['selectable_id1']
                return {**result, 'status': 'matched', 'reason': 'actual-fixed-selectable-id0-id1-replay',
                        'branches': actual['branches'], 'outcome': actual['outcome'],
                        'artifact_sha256': actual['artifact_sha256'], 'observations': observations}
            with ThreadPoolExecutor(max_workers=workers) as pool:
                checks = list(pool.map(check, items))
        _authenticated_build(validated, build)
    dataset.verify_artifacts()
    matched = sum(item['status'] == 'matched' for item in checks)
    return {'status': 'matched' if checks and matched == len(checks) else 'partial' if matched else 'unavailable',
            'verified': False, 'binradar_verification': 'not_run',
            'activation': {'PATCH_ID': '1'}, 'cases': checks,
            'summary': {'total': len(checks), 'matched': matched, 'unavailable': len(checks) - matched}}
