"""Identity-bound offline inference and independent concrete candidate evaluation.

Host rejection statuses remain rejected, not rejected, or unavailable. Attached
reports distinguish outcomes, neutral controls and actual activation; neither
branch equivalence nor a normal process exit is a claim of repair verification.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from types import MappingProxyType
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from binradar.binradar_feedback_capture import read_case, read_header, unpack_branches
from binradar.binradar_taosc_predicates import (
    evaluate_cached_predicate, load_runtime_predicates, parse_cached_snapshots,
    parse_predicate_descriptor, predicate_descriptor, predicate_stack_bytes,
)
from binradar.binradar_verifier import CONCRETE_ORACLE

from .dataset import load_dataset
from .execution import ExecutionUnavailable, execute_capture, execution_identity, sha256
from .family import parse_candidate


def _reason(error) -> str:
    text = str(error)
    if re.fullmatch(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)*', text):
        return text
    if 'truncated' in text or 'partial' in text:
        return 'capture-truncated'
    if 'family' in text or 'stack' in text:
        return 'capture-family-or-stack-mismatch'
    if 'E9 instruction identity' in text:
        return 'instruction-identity-unavailable'
    return 'capture-or-execution-unavailable'


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _atomic(path: Path, value) -> None:
    fd, part = tempfile.mkstemp(prefix='.part-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True, separators=(',', ':'))
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(part, path)
    finally:
        if os.path.exists(part):
            os.unlink(part)


@contextmanager
def _lock(path: Path):
    # flock is per open file description, protecting both threads and processes.
    with path.open('a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


@dataclass(frozen=True)
class _CaptureMetadata:
    artifact_sha256: str
    pie: bool
    cwe: bool
    stack_bytes: int


def _capture_metadata(dataset):
    with dataset.artifact(dataset.binary + '.brcached').open('rb') as stream:
        header = stream.read(20)
    return _CaptureMetadata(
        dataset.manifest['artifacts'][dataset.binary + '.brcached']['sha256'],
        len(header) >= 18 and header[:4] == b'\x7fELF'
        and int.from_bytes(header[16:18], 'little' if header[5] == 1 else 'big') == 3,
        dataset.patch_format == 'ERM CWE-805',
        int(dataset.execution_environment().get('BRCACHE_STACK_SIZE', '0'), 0))


def _snapshots(dataset, capture):
    """Authenticate a capture even when called outside an evaluation/tool scope."""
    with dataset.validation() as validated:
        return _validated_snapshots(validated, capture, _capture_metadata(validated))


def _validated_snapshots(dataset, capture, metadata):
    if capture.get('complete') is not True:
        raise ValueError(capture.get('reason', 'incomplete-capture'))
    descriptor = capture.get('descriptor')
    if not isinstance(descriptor, str) or not descriptor:
        raise ValueError('capture-descriptor-unavailable')
    parsed = parse_predicate_descriptor(descriptor)
    if descriptor != 'p0' and isinstance(parsed, str) == metadata.cwe:
        raise ValueError('capture-descriptor-family-mismatch')
    if capture.get('artifact_sha256') != metadata.artifact_sha256:
        raise ValueError('capture-artifact-mismatch')
    if 1 in capture.get('branches', []) and metadata.pie:
        raise ValueError('pie-descriptor-relocation-capability-unavailable')
    path = Path(capture['path'])
    if not path.is_absolute():
        snapshots = dataset.snapshots(capture)
        expected_id = capture.get('patch_id', capture.get('capture_id', 0))
        if any(state.patch_id != expected_id for state in snapshots):
            raise ValueError('capture-id-mismatch')
        return snapshots
    # Absolute paths arise only from our owned cache or authenticated journals.
    if sha256(path) != capture['sha256']:
        raise ValueError('capture-hash-mismatch')
    snapshots, error = parse_cached_snapshots(path.read_bytes())
    if error:
        raise ValueError(error)
    if [s.branch for s in snapshots] != capture['branches']:
        raise ValueError('capture-vector-mismatch')
    expected_id = capture.get('patch_id', capture.get('capture_id', 0))
    if any(state.patch_id != expected_id for state in snapshots):
        raise ValueError('capture-id-mismatch')
    if any(s.is_CWE805 != metadata.cwe
           or (metadata.cwe and len(s.stack) != metadata.stack_bytes) for s in snapshots):
        raise ValueError('capture-family-or-stack-mismatch')
    return snapshots


def _vector(descriptor, snapshots):
    if descriptor == 'p0':
        return [0] * len(snapshots)
    parsed = parse_predicate_descriptor(descriptor)
    required = predicate_stack_bytes(parsed)
    if any(len(state.stack) < required for state in snapshots):
        raise ValueError('representative-stack-unavailable')
    return evaluate_cached_predicate(parsed, snapshots)


@dataclass(frozen=True)
class _ProducerMetadata:
    run: str
    descriptors: object
    manifest_sha256: str
    environment_sha256: str | None
    original_sha256: str
    qemu_sha256: str


def _producer_metadata(dataset, identity):
    """Freeze expected identities, never trust mutable producer records ahead of use."""
    run = dataset.manifest.get('sources', {}).get('concrete_run')
    if run is None or not identity.get('qemu'):
        return None
    _, predicates = load_runtime_predicates(dataset.artifact('brpatches.json'))
    artifacts = dataset.manifest['artifacts']
    env_entry = artifacts.get('binradar.env')
    return _ProducerMetadata(run, MappingProxyType({
        number: predicate_descriptor(predicate) for number, predicate in predicates.items()
    }), artifacts['brpatches.json']['sha256'],
        env_entry['sha256'] if env_entry else None,
        artifacts[dataset.binary + '.orig']['sha256'], identity['qemu'])


def _external_captures(dataset, case, producer, metadata):
    """Read only complete producer commits; producers never share our locks."""
    if case['domain'] != 'system' or producer is None:
        return
    number = case.get('source', {}).get('case_id')
    if type(number) is not int:
        return
    for channel in ('baseline', 'verifier'):
        try:
            # Producers may republish this channel between cases. Authenticate
            # its current header before consuming any of its mutable commits.
            header = read_header(producer.run, channel)
            if not header or header.get('brpatches.json') != producer.manifest_sha256:
                continue
            if header.get('binradar.env') != producer.environment_sha256:
                continue
            context = header['context']
            if (context.get('original_sha256') != producer.original_sha256
                    or context.get('qemu_sha256') != producer.qemu_sha256):
                continue
            matched = False
            for row in read_case(producer.run, channel, number):
                if row['kind'] == 'input':
                    matched = row.get('sha256') == case.get('input_sha256') and row.get('file') == case.get('source', {}).get('filename')
                    continue
                if not matched or row['kind'] != 'trace' or row.get('state_reason') != 'none':
                    continue
                if row.get('artifact') != metadata.artifact_sha256:
                    continue
                representative = row.get('representative')
                if representative == 0:
                    descriptor = 'p0'
                elif representative in producer.descriptors:
                    descriptor = producer.descriptors[representative]
                else:
                    continue
                branches = unpack_branches(row['hits'], row['branches'])
                if branches is None:
                    continue
                path = Path(producer.run) / 'feedback-capture' / 'states' / (row['state_sha256'] + '.brch')
                yield {'path': str(path), 'sha256': row['state_sha256'],
                       'artifact_sha256': row['artifact'], 'descriptor': descriptor,
                       'branches': branches, 'outcome': row, 'complete': True,
                       'capture_id': row.get('capture_id')}
        except (OSError, ValueError, KeyError, TypeError):
            # A missing/partial producer is not an empty execution.
            continue

def _same_crash(dataset, case, capture):
    if case['domain'] == 'function':
        # Preparation authenticates committed frame + typed attempt-1 oracle.
        return capture.get('same_crash') if type(capture.get('same_crash')) is bool else None
    outcome = capture.get('outcome', {})
    oracle = outcome.get('oracle', outcome.get('concrete-oracle'))
    observed = outcome.get('outcome')
    if observed is None:
        observed = {'ok': 'normal', 'crash': 'crash'}.get(outcome.get('exit'))
    if oracle != CONCRETE_ORACLE:
        return None
    if observed == 'normal':
        return False
    reference = dataset.manifest.get('oracles', {}).get('concrete_reference')
    if (observed != 'crash' or type(reference) is not int
            or outcome.get('fault_valid', outcome.get('concrete-fault-valid')) is not True):
        return None
    address = outcome.get('fault_addr', outcome.get('fault-addr'))
    return address == reference if type(address) is int else None


def _cache_record(path, key):
    try:
        value = json.loads(path.read_text())
        if not isinstance(value, dict) or value.get('identity') != key:
            return None
        capture = value.get('capture')
        return capture if isinstance(capture, dict) else None
    except (OSError, ValueError, TypeError):
        return None


def _case_result(dataset, case, candidate, descriptor, execute, root, base_identity,
                 metadata, producer):
    base = {'case_id': case['id'], 'domain': case['domain'], 'source': 'unavailable',
            'status': 'unavailable', 'reason': 'capture-unavailable', 'branches': None,
            'descriptor': descriptor, 'offline_branches': None, 'first_divergence': None,
            'offline_reference': None}
    if candidate is not None and candidate.required_stack_bytes > metadata.stack_bytes:
        return {**base, 'reason': 'candidate-stack-unavailable'}
    identity = {**base_identity, 'input': case.get('input_sha256'), 'case': case['id'],
                'descriptor': descriptor, 'observation': case.get('observation'),
                'source': case.get('source')}
    key = _digest(identity)
    record_path = root / (key + '.json')
    with _lock(root / (key + '.lock')):
        captures = []
        own = _cache_record(record_path, identity)
        if own:
            captures.append((own, 'cache'))
        if case.get('capture'):
            captures.append((case['capture'], 'offline' if case['domain'] == 'function' else 'cache'))
        captures.extend((c, 'cache') for c in _external_captures(dataset, case, producer, metadata))
        # Reuse neutral own captures across candidates without trusting a prior
        # result summary; validate their complete state and mirror every time.
        neutral_identity = {**identity, 'descriptor': 'p0'}
        neutral = _cache_record(root / (_digest(neutral_identity) + '.json'), neutral_identity)
        if neutral and descriptor != 'p0':
            captures.append((neutral, 'cache'))
        for capture, source in captures:
            try:
                snapshots = _validated_snapshots(dataset, capture, metadata)
                if candidate is not None and any(len(s.stack) < candidate.required_stack_bytes for s in snapshots):
                    raise ValueError('candidate-stack-unavailable')
                actual = capture['branches']
                if _vector(capture['descriptor'], snapshots) != actual:
                    raise ValueError('representative-evaluator-mismatch')
                branches = _vector(descriptor, snapshots)
                base['offline_branches'] = branches
                base['offline_reference'] = capture
                divergence = next((i for i, (a, b) in enumerate(zip(branches, actual)) if a != b), None)
                base['first_divergence'] = divergence
                if branches != actual:
                    base['reason'] = 'branch-divergence'
                    continue
                base['reuse'] = ('exact-descriptor' if descriptor == capture['descriptor']
                                 else 'full-vector-equivalent')
                if 2 in branches:
                    return {**base, 'source': source, 'branches': branches,
                            'reason': 'predicate-trap', 'outcome': capture.get('outcome'), 'capture': capture}
                same = _same_crash(dataset, case, capture)
                return {**base, 'source': source, 'status': 'reject_same_crash' if same is True else ('not_rejected' if same is False else 'unavailable'),
                        'reason': 'same-crash' if same is True else ('observed-not-same-crash' if same is False else 'oracle-unavailable'),
                        'branches': actual, 'outcome': capture.get('outcome'), 'capture': capture}
            except (OSError, ValueError, KeyError, TypeError) as error:
                base['reason'] = _reason(error)
        if case['domain'] != 'system' or not execute:
            return base
        try:
            capture = execute_capture(dataset, case, descriptor, root / 'states')
            # Save actual executions even when BRCH is unavailable. Such entries
            # are diagnostic only and never become reusable branch evidence.
            _atomic(record_path, {'identity': identity, 'capture': capture})
            base.update(source='executed', reuse='fresh', branches=capture.get('branches'),
                        outcome=capture.get('outcome'), capture=capture)
            snapshots = _validated_snapshots(dataset, capture, metadata)
            if _vector(descriptor, snapshots) != capture['branches']:
                raise ExecutionUnavailable('candidate-evaluator-mismatch')
            if 2 in capture['branches']:
                return {**base, 'reason': 'predicate-trap'}
            same = _same_crash(dataset, case, capture)
            return {**base, 'source': 'executed', 'branches': capture['branches'],
                    'status': 'reject_same_crash' if same is True else ('not_rejected' if same is False else 'unavailable'),
                    'reason': 'same-crash' if same is True else ('observed-not-same-crash' if same is False else 'oracle-unavailable'),
                    'outcome': capture['outcome'], 'capture': capture}
        except (OSError, ValueError, RuntimeError, KeyError) as error:
            return {**base, 'reason': _reason(error)}


def _replay_evaluate(dataset, candidate, *, case_ids, socket_path):
    from . import replay
    function_ids = {case['id'] for case in dataset.cases('function')}
    if case_ids is not None and any(case not in function_ids for case in case_ids):
        raise ValueError('live replay selects only function cases')
    result = replay.evaluate_replay(dataset, candidate, socket_path=socket_path)
    if case_ids is not None:
        selected = set(case_ids)
        result['cases'] = [item for item in result['cases'] if item['case_id'] in selected]
        counts = {status: sum(item['status'] == status for item in result['cases'])
                  for status in ('reject_same_crash', 'not_rejected', 'unavailable')}
        result['status'] = ('reject_same_crash' if counts['reject_same_crash'] else
                            'unavailable' if not result['cases'] or counts['unavailable']
                            else 'not_rejected')
        result['summary'] = {'total': len(result['cases']), **counts}
    result.update(dataset_id=dataset.dataset_id,
                  candidate_id=_digest({'dataset': dataset.dataset_id,
                                        'descriptor': candidate.descriptor,
                                        'replay': result['replay']}),
                  predicate=candidate.expression, descriptor=candidate.descriptor,
                  verified=False)
    return result


def _evaluate(dataset, candidate, descriptor, *, case_ids, workers, execute, cache_dir,
              replay_socket=None, include_poc=True):
    """Evaluate one candidate inside the caller's active validation scope.

    ``replay_socket`` selects the trusted live host bridge for **function**
    cases.  It is a host-side option only: neither the model nor a public patch
    entry can name a socket.  Concrete ``system`` cases keep their existing
    capture/cache/execution path and never use the live mutation snapshot.
    ``execute=False`` suppresses both concrete execution and socket access.
    Function observations without a retained native plan stay offline even
    when the host enables replay.
    """
    if dataset.patch_format not in ('ERM generic', 'ERM CWE-805'):
        raise ValueError('only ERM generic and ERM CWE-805 evaluation is supported')
    if type(workers) is not int or not 1 <= workers <= 32:
        raise ValueError('workers must be in 1..32')
    # Public entry points hold a validation scope until all worker threads settle.
    from .poc import poc_case
    original_poc = poc_case(dataset) if include_poc else None
    prepared = dataset.cases()
    by_id = {case['id']: case for case in prepared}
    if original_poc is not None:
        by_id.setdefault(original_poc['id'], original_poc)
    if case_ids is None:
        cases = list(by_id.values())
    else:
        if any(case_id not in by_id for case_id in case_ids):
            raise ValueError('unknown scoped case id')
        cases = [by_id[case_id] for case_id in case_ids]
    if len({c['id'] for c in cases}) != len(cases):
        raise ValueError('duplicate case ids')
    if (original_poc is not None
            and not any(case.get('input_sha256') == original_poc['input_sha256']
                        for case in cases if case['domain'] == 'system')):
        cases.append(original_poc)
    # Offline is an API guarantee, even if a trusted context has an endpoint.
    if not execute:
        replay_socket = None
    if replay_socket is not None and candidate is None:
        raise ValueError('live replay requires a candidate predicate, not --warm')
    live_cases = [c for c in cases if c['domain'] == 'function']
    if replay_socket is not None:
        from . import replay
        # Requesting a bridge for a dataset without a frozen mutation run must
        # not silently degrade to concrete-only evaluation.
        replay.dataset_socket(dataset)
    # A dataset with a mutation run can still retain zero useful cases.  The
    # bridge then has nothing to evaluate, and concrete cases take their normal
    # path instead of failing the whole candidate.
    use_replay = replay_socket is not None and bool(live_cases)
    cache_base = Path(cache_dir) if cache_dir is not None else Path.home() / '.cache' / 'taosc-llm'
    root = cache_base / 'evaluation-v2' / _digest(dataset.dataset_id)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    base_identity = {'dataset': dataset.dataset_id, 'artifacts': dataset.manifest['artifacts'],
                     'environment': dataset.execution_environment(), 'family': dataset.patch_format,
                     'patch': dataset.manifest['patch'], 'oracles': dataset.manifest.get('oracles'),
                     'runtime': execution_identity(), 'evaluator': sha256(Path(__file__))}
    metadata = _capture_metadata(dataset)
    producer = (_producer_metadata(dataset, base_identity['runtime'])
                if any(case['domain'] == 'system'
                       and type(case.get('source', {}).get('case_id')) is int
                       for case in cases) else None)
    def neutral_baseline(case):
        # Finish the p0 operation before taking the candidate lock. Equal keys
        # (warming/neutral candidates) must never recursively acquire flock.
        return _case_result(dataset, case, None, 'p0', execute, root,
                            base_identity, metadata, producer)

    def evaluate(case):
        neutral = neutral_baseline(case)
        item = (dict(live[case['id']]) if case['id'] in live else
                neutral.copy() if descriptor == 'p0' else
                _case_result(dataset, case, candidate, descriptor, execute, root,
                             base_identity, metadata, producer))
        item['neutral_baseline'] = neutral
        return item
    live = {}
    replay_result = None
    if use_replay:
        replay_result = _replay_evaluate(dataset, candidate,
                                         case_ids=sorted(c['id'] for c in live_cases),
                                         socket_path=replay_socket)
        live = {item['case_id']: item for item in replay_result['cases']}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        evaluated = {item['case_id']: item
                     for item in pool.map(evaluate, cases)}
    from .evidence import _project_case, summarize_reports
    results = [evaluated[case['id']] for case in cases]
    for case, item in zip(cases, results):
        item['report'] = _project_case(dataset, case, item, metadata=metadata, descriptor=descriptor)
    counts = {status: sum(c['status'] == status for c in results)
              for status in ('reject_same_crash', 'not_rejected', 'unavailable')}
    status = ('reject_same_crash' if counts['reject_same_crash'] else
              'unavailable' if not results or counts['unavailable'] else 'not_rejected')
    result = {'dataset_id': dataset.dataset_id, 'candidate_id': _digest({'base': base_identity, 'descriptor': descriptor}),
              'predicate': candidate.expression if candidate is not None else None,
              'descriptor': descriptor, 'status': status, 'verified': False,
              'cases': results, 'summary': {'total': len(results), **counts},
              'evaluation_mode': 'host' if execute else 'offline',
              'report_summary': summarize_reports(item['report'] for item in results)}
    if replay_result is not None:
        result['replay'] = replay_result['replay']
        result['candidate_id'] = _digest({'base': base_identity,
                                          'descriptor': descriptor,
                                          'replay': replay_result['replay']})
    result_id = _digest(result)
    result['result_id'] = result_id
    _atomic(root / (result_id + '.result.json'), result)
    return result


def evaluate_dataset(dataset, predicate: str, *, case_ids: list[str] | None = None,
                     workers: int = 1, execute: bool = True, cache_dir: Path | None = None,
                     replay_socket=None, include_poc: bool = True) -> dict:
    """Evaluate a family predicate; ``replay_socket`` is trusted host input.

    It is never serialized into a model tool argument or a public patch entry.
    The frozen original POC participates by default, even when absent from the
    prepared system population or an explicit selection. ``include_poc`` is a
    trusted host-only control; no caller-defined cases or inputs are accepted.
    """
    if isinstance(dataset, (str, Path)):
        dataset = load_dataset(Path(dataset))
    with dataset.validation() as validated:
        candidate = parse_candidate(validated.patch_format, predicate)
        return _evaluate(validated, candidate, candidate.descriptor, case_ids=case_ids,
                         workers=workers, execute=execute, cache_dir=cache_dir,
                         replay_socket=replay_socket, include_poc=include_poc)


def warm_dataset(dataset, *, workers: int = 1, cache_dir: Path | None = None) -> dict:
    """Collect neutral p0 concrete observations, including empty manifests."""
    if isinstance(dataset, (str, Path)):
        dataset = load_dataset(Path(dataset))
    with dataset.validation() as validated:
        return _evaluate(validated, None, 'p0',
                         case_ids=[c['id'] for c in validated.cases('system')],
                         workers=workers, execute=True, cache_dir=cache_dir)
