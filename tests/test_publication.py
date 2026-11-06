"""Host publication boundaries; no provider, compiler or target is launched here."""
import asyncio
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from taosc_llm import publication
from taosc_llm.dataset import PreparedDataset, canonical
from taosc_llm.execution import ExecutionUnavailable, sha256
from taosc_llm.family import parse_candidate
from test_context_tools import make_dataset


def concrete_dataset(tmp_path):
    dataset = make_dataset(tmp_path / 'dataset', count=1)
    root = dataset.root
    (root / 'input').write_bytes(b'owned input')
    rows = dataset.cases()
    rows.append({'id': 'system:0', 'domain': 'system', 'input_path': 'input',
                 'input_sha256': sha256(root / 'input'), 'capture': None,
                 'source': {}, 'observation': {}})
    path = root / 'cases.jsonl'
    path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
    manifest = dict(dataset.manifest)
    manifest['cases'] = {'path': 'cases.jsonl', 'sha256': sha256(path)}
    manifest['oracles'] = {'concrete_reference': 0x1000}
    manifest.pop('dataset_id')
    import hashlib
    manifest['dataset_id'] = hashlib.sha256(canonical(manifest)).hexdigest()
    return PreparedDataset(root, manifest)


def built_candidate(dataset, directory):
    directory.mkdir(exist_ok=True)
    parsed = parse_candidate(dataset.patch_format, 'rax < 0')
    names = ('patch-format', 'predicates', 'brpatches.json', 'brpatches.inc', 'brpatch.c',
             'taosc-llm-runtime.c', 'taosc-llm-selector.c', 'predicate.h',
             *(f'fixture.{suffix}{extension}' for suffix in ('patched', 'brpatched')
               for extension in ('', '.json', '.e9map.json')))
    artifacts = {}
    for name in names:
        path = directory / name
        path.write_bytes(name.encode())
        artifacts[name] = str(path)
    from binradar.binradar_taosc_predicates import PredicateRecord, write_runtime_predicates
    write_runtime_predicates(directory / 'brpatches.json', parsed.family,
                             [PredicateRecord(1, 1, parsed.source_predicate, parsed.parsed)])
    (directory / 'patch-format').write_text(dataset.patch_format + '\n')
    (directory / 'predicates').write_text(parsed.source_predicate + '\n')
    original = directory / 'fixture.orig'
    if not original.exists():
        original.write_bytes(dataset.artifact('fixture.orig').read_bytes())
    return {'status': 'built', 'verified': False, 'binary': dataset.binary,
            'patch_format': dataset.patch_format, 'predicate': parsed.expression,
            'source_predicate': parsed.source_predicate, 'descriptor': parsed.descriptor,
            'patch_location': '0x1000', 'patch_destination': '0x1001',
            'binradar_activation': {'PATCH_ID': '1'},
            'original_sha256': dataset.manifest['artifacts']['fixture.orig']['sha256'],
            'artifacts': artifacts, 'artifact_hashes': {name: sha256(Path(path)) for name, path in artifacts.items()}}


def evaluated(dataset, build):
    return {'dataset_id': dataset.dataset_id, 'predicate': build['predicate'],
            'descriptor': build['descriptor'], 'cases': [
                {'case_id': 'system:0', 'domain': 'system', 'status': 'not_rejected',
                 'branches': [0, 1, 0, 1],
                 'outcome': {'oracle': 'qasan-main-v2', 'outcome': 'normal'},
                 'neutral_baseline': {'status': 'reject_same_crash', 'branches': [0, 0, 0, 0],
                                      'outcome': {'oracle': 'qasan-main-v2', 'outcome': 'crash',
                                                  'fault_valid': True, 'fault_addr': 0x1000}}}]}


def test_publication_import_does_not_load_model_or_context(tmp_path):
    root = str(Path(publication.__file__).resolve().parent.parent)
    code = ('import sys;sys.path.insert(0,sys.argv[1]);import taosc_llm.publication;'
            'assert not any(n in sys.modules for n in '
            '("taosc_llm.provider","taosc_llm.context","taosc_llm.bridge","taosc_llm.synthesis"))')
    result = subprocess.run([sys.executable, '-I', '-c', code, root],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_build_uses_dataset_and_exact_predicate_without_context(tmp_path, monkeypatch):
    dataset = concrete_dataset(tmp_path)
    directory = tmp_path / 'build'
    observed = []
    class Process:
        returncode = 0
        async def communicate(self):
            return json.dumps(built_candidate(dataset, directory)).encode(), b'private diagnostic'
    async def spawn(*argv, **kwargs):
        observed.append((argv, kwargs))
        assert kwargs['cwd'] == directory
        assert kwargs['start_new_session'] is True
        assert 'PROVIDER_SECRET' not in kwargs['env']
        assert 'PYTHONPATH' not in kwargs['env']
        return Process()
    monkeypatch.setenv('PROVIDER_SECRET', 'not inherited')
    monkeypatch.setattr(publication.asyncio, 'create_subprocess_exec', spawn)
    result = asyncio.run(publication.build_candidate(dataset, 'rax < 0', directory))
    assert observed and result['verified'] is False
    assert result['native_isolation'] == 'linux-landlock-seccomp'
    assert result['artifact_hashes']['fixture.brpatched'] == sha256(directory / 'fixture.brpatched')
    assert (directory.stat().st_mode & 0o777) == 0o700
    assert ((directory / 'fixture.orig').stat().st_mode & 0o777) == 0o500
    assert ((directory.parent / 'build.log').stat().st_mode & 0o777) == 0o600
    with pytest.raises(FileExistsError):
        asyncio.run(publication.build_candidate(dataset, 'rax < 0', directory))


def test_build_cancellation_reaps_owned_subprocess(tmp_path, monkeypatch):
    dataset = concrete_dataset(tmp_path)
    process = SimpleNamespace(returncode=None)
    reaped = []
    async def communicate():
        raise asyncio.CancelledError()
    process.communicate = communicate
    async def spawn(*args, **kwargs):
        return process
    async def reap(child):
        reaped.append(child)
    monkeypatch.setattr(publication.asyncio, 'create_subprocess_exec', spawn)
    monkeypatch.setattr(publication, 'kill_process', reap)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(publication.build_candidate(dataset, 'rax < 0', tmp_path / 'build'))
    assert reaped == [process]
    assert (tmp_path / 'build' / 'fixture.orig').is_file()


def test_built_validation_reexecutes_full_ordered_vector_and_never_final(tmp_path, monkeypatch):
    dataset = concrete_dataset(tmp_path)
    build = built_candidate(dataset, tmp_path / 'build')
    evaluation = evaluated(dataset, build)
    calls = []
    def execute(validated, case, selected, directory, *, artifact, patch_id):
        calls.append((case['id'], selected, directory, artifact, patch_id))
        wanted = (evaluation['cases'][0]['neutral_baseline']
                  if artifact == 'selectable' and patch_id == 0 else evaluation['cases'][0])
        suffix = '.patched' if artifact == 'fixed' else '.brpatched'
        return {'branches': wanted['branches'], 'outcome': wanted['outcome'],
                'artifact_sha256': build['artifact_hashes']['fixture' + suffix]}
    monkeypatch.setattr(publication, 'execute_built', execute)
    result = publication.verify_built_candidate(dataset, build, evaluation, workers=2)
    assert [call[0] for call in calls] == ['system:0'] * 3
    assert [(call[3], call[4]) for call in calls] == [('selectable', 1), ('selectable', 0), ('fixed', 0)]
    assert set(result['cases'][0]['observations']) == {'selectable_id1', 'selectable_id0', 'fixed'}
    assert result['status'] == 'matched' and result['summary']['matched'] == 1
    assert result['verified'] is False and result['binradar_verification'] == 'not_run'
    assert result['activation'] == {'PATCH_ID': '1'}
    assert not calls[0][2].exists()


@pytest.mark.parametrize('changed', ['branches', 'outcome'])
def test_built_validation_rejects_semantic_mismatch(tmp_path, monkeypatch, changed):
    dataset = concrete_dataset(tmp_path)
    build = built_candidate(dataset, tmp_path / 'build')
    evaluation = evaluated(dataset, build)
    actual = {'branches': [0, 1, 0, 1], 'outcome': evaluation['cases'][0]['outcome']}
    actual[changed] = ([1, 0, 1, 0] if changed == 'branches' else
                       {'oracle': 'qasan-main-v2', 'outcome': 'crash', 'fault_valid': True, 'fault_addr': 0x1000})
    monkeypatch.setattr(publication, 'execute_built', lambda *args, **kwargs: actual)
    with pytest.raises(ValueError, match=f'{"branch" if changed == "branches" else "outcome"} mismatch'):
        publication.verify_built_candidate(dataset, build, evaluation)


def test_built_validation_keeps_mutation_and_execution_unavailable(tmp_path, monkeypatch):
    dataset = concrete_dataset(tmp_path)
    build = built_candidate(dataset, tmp_path / 'build')
    evaluation = evaluated(dataset, build)
    evaluation['cases'].append({'case_id': 'function:0', 'domain': 'function', 'status': 'not_rejected',
                                'branches': [1], 'outcome': {'outcome': 'normal'}})
    def unavailable(*args, **kwargs):
        raise ExecutionUnavailable('execution-unavailable')
    monkeypatch.setattr(publication, 'execute_built', unavailable)
    result = publication.verify_built_candidate(dataset, build, evaluation)
    assert result['status'] == 'unavailable'
    assert result['summary']['matched'] == 0
    assert [case['reason'] for case in result['cases']] == [
        'execution-unavailable', 'built-artifact-mutation-replay-unavailable']


@pytest.mark.parametrize('change', ['bytes', 'symlink', 'case', 'descriptor'])
def test_built_validation_fails_closed_before_execution(tmp_path, monkeypatch, change):
    dataset = concrete_dataset(tmp_path)
    build = built_candidate(dataset, tmp_path / 'build')
    evaluation = evaluated(dataset, build)
    path = Path(build['artifacts']['fixture.brpatched'])
    if change == 'bytes':
        path.write_bytes(b'not the artifact selected')
    elif change == 'symlink':
        outside = tmp_path / 'outside'
        path.rename(outside)
        path.symlink_to(outside)
    elif change == 'case':
        evaluation['cases'][0]['case_id'] = 'system:1000'
    else:
        evaluation['descriptor'] = 'p0'
    def forbidden(*args):
        pytest.fail('invalid publication must not execute')
    monkeypatch.setattr(publication, 'execute_built', forbidden)
    with pytest.raises(ValueError):
        publication.verify_built_candidate(dataset, build, evaluation)


@pytest.mark.parametrize('change', ['fixed-missing', 'runtime', 'original'])
def test_build_authentication_binds_runtime_and_original(tmp_path, monkeypatch, change):
    dataset = concrete_dataset(tmp_path)
    build = built_candidate(dataset, tmp_path / 'build')
    if change == 'fixed-missing':
        build['artifacts'].pop('fixture.patched')
        build['artifact_hashes'].pop('fixture.patched')
    elif change == 'runtime':
        path = Path(build['artifacts']['brpatches.json'])
        data = json.loads(path.read_text())
        data['predicates'][0]['descriptor'] = 'p0'
        path.write_text(json.dumps(data))
        build['artifact_hashes']['brpatches.json'] = sha256(path)
    else:
        (tmp_path / 'build' / 'fixture.orig').write_bytes(b'not frozen original')
    def forbidden(*args, **kwargs):
        pytest.fail('unauthenticated build must not execute')
    monkeypatch.setattr(publication, 'execute_built', forbidden)
    with pytest.raises(ValueError):
        publication.verify_built_candidate(dataset, build, evaluated(dataset, build))


def test_missing_neutral_cannot_publish_matched_artifact(tmp_path, monkeypatch):
    dataset = concrete_dataset(tmp_path)
    build = built_candidate(dataset, tmp_path / 'build')
    evaluation = evaluated(dataset, build)
    evaluation['cases'][0].pop('neutral_baseline')
    def forbidden(*args, **kwargs):
        pytest.fail('missing control must not claim artifact parity')
    monkeypatch.setattr(publication, 'execute_built', forbidden)
    result = publication.verify_built_candidate(dataset, build, evaluation)
    assert result['status'] == 'unavailable'
    assert result['cases'][0]['reason'] == 'neutral-evidence-unavailable'


@pytest.mark.parametrize('bad_mode', ['selectable_id0', 'fixed'])
def test_candidate_id1_match_cannot_hide_bad_other_runtime(tmp_path, monkeypatch, bad_mode):
    dataset = concrete_dataset(tmp_path)
    build = built_candidate(dataset, tmp_path / 'build')
    evaluation = evaluated(dataset, build)
    def execute(validated, case, selected, directory, *, artifact, patch_id):
        mode = 'fixed' if artifact == 'fixed' else f'selectable_id{patch_id}'
        wanted = evaluation['cases'][0]['neutral_baseline'] if mode == 'selectable_id0' else evaluation['cases'][0]
        suffix = '.patched' if artifact == 'fixed' else '.brpatched'
        return {'branches': [1] if mode == bad_mode else wanted['branches'],
                'outcome': wanted['outcome'],
                'artifact_sha256': build['artifact_hashes']['fixture' + suffix]}
    monkeypatch.setattr(publication, 'execute_built', execute)
    with pytest.raises(ValueError, match=f'branch mismatch.*{bad_mode}'):
        publication.verify_built_candidate(dataset, build, evaluation)
