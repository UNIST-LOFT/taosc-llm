"""Behavioral evaluation contracts; no provider or research target execution."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
from pathlib import Path
import threading
import time

import pytest

from binradar.binradar_taosc_predicates import (
    CACHED_SNAPSHOT_HEADER, CACHED_SNAPSHOT_MAGIC, CACHED_SNAPSHOT_VERSION,
    CACHED_SNAPSHOT_REGS, CACHED_SNAPSHOT_CLAMPS, CACHED_SNAPSHOT_FLAG_CWE805,
)
from taosc_llm import evaluation
from taosc_llm.execution import sha256


class Dataset:
    binary = 'harmless'
    patch_format = 'ERM generic'
    dataset_id = 'test-dataset'

    def __init__(self, root):
        self.root = root
        self.workdir = root / 'artifacts'
        self.workdir.mkdir()
        for name in ('harmless.orig', 'harmless.brcached'):
            (self.workdir / name).write_bytes(b'harmless-' + name.encode())
        (self.workdir / 'brpatches.json').write_text('{"version":1,"kind":"generic-erm","predicates":[]}')
        self.manifest = {'artifacts': {name: {'sha256': sha256(path)} for name, path in
                                     ((p.name, p) for p in self.workdir.iterdir())},
                         'patch': {'location': '0x10', 'destination': '0x20', 'address_domain': 'elf-va'},
                         'sources': {'concrete_run': None},
                         'oracles': {'concrete_reference': 33}}
        (root / 'input').write_bytes(b'input')
        self.rows = [{'id': 'system:0', 'domain': 'system', 'input_path': 'input',
                      'input_sha256': sha256(root / 'input'), 'source': {}, 'observation': {}, 'capture': None}]

    def artifact(self, name):
        return self.workdir / name

    def execution_environment(self):
        return {'BINARY': self.binary, 'TEST_CMD': '@@', 'BRCACHE_STACK_SIZE': '0'}

    def verify_artifacts(self):
        for name, record in self.manifest['artifacts'].items():
            if sha256(self.artifact(name)) != record['sha256']:
                raise ValueError('fixture artifact mismatch')

    @contextmanager
    def validation(self, *, check=None):
        if check is not None:
            check()
        self.verify_artifacts()
        yield self

    def cases(self, domain='all'):
        return [row for row in self.rows if domain == 'all' or row['domain'] == domain]

    def case(self, case_id):
        return next(row for row in self.rows if row['id'] == case_id)


def capture(dataset, *, values=(0,), branches=(0,), descriptor='p0', normal=False, same=None,
            cwe=False):
    raw = b''
    for value, branch in zip(values, branches):
        registers = [0] * 16
        # BinRadar register layout uses rax at index 0.
        registers[0] = value
        flags = CACHED_SNAPSHOT_FLAG_CWE805 if cwe else 0
        raw += CACHED_SNAPSHOT_HEADER.pack(CACHED_SNAPSHOT_MAGIC, CACHED_SNAPSHOT_VERSION, 0, branch, 0, flags)
        if cwe:
            clamps = [(100, 200)] + [(0, 0)] * 255
            raw += CACHED_SNAPSHOT_CLAMPS.pack(*(cell for clamp in clamps for cell in clamp))
        raw += CACHED_SNAPSHOT_REGS.pack(*registers)
    digest = hashlib.sha256(raw).hexdigest()
    path = dataset.root / (digest + '.brch')
    path.write_bytes(raw)
    result = {'path': str(path), 'sha256': digest, 'artifact_sha256': sha256(dataset.artifact('harmless.brcached')),
              'branches': list(branches), 'descriptor': descriptor, 'complete': True,
              'outcome': {'outcome': 'normal' if normal else 'crash', 'oracle': 'qasan-main-v2',
                          'fault_valid': not normal, 'fault_addr': 33}}
    if same is not None:
        result['same_crash'] = same
    return result


@pytest.fixture
def dataset(tmp_path, monkeypatch):
    monkeypatch.setattr(evaluation, 'execution_identity', lambda: {'qemu': 'fixture', 'oracle': 'qasan-main-v2'})
    return Dataset(tmp_path)


@pytest.mark.parametrize('observations,expected', [
    (('normal', 'missing'), 'not_rejected'),
    (('target', 'missing'), 'reject_same_crash'),
    (('missing', 'missing'), 'not_rejected'),
    ((), 'unavailable'),
])
def test_aggregate_rejection_preserves_case_availability(
        dataset, tmp_path, observations, expected):
    original = dataset.rows[0]
    dataset.rows = [
        {**original, 'id': f'system:{index}',
         'capture': None if observation == 'missing' else
             capture(dataset, normal=observation == 'normal')}
        for index, observation in enumerate(observations)
    ]
    result = evaluation.evaluate_dataset(
        dataset, 'rax != 0', execute=False, include_poc=False,
        cache_dir=tmp_path / 'cache')
    assert result['status'] == expected
    assert result['verified'] is False
    assert result['summary'] == {
        'total': len(observations),
        'reject_same_crash': observations.count('target'),
        'not_rejected': observations.count('normal'),
        'unavailable': observations.count('missing'),
    }
    for row, observation in zip(result['cases'], observations):
        if observation == 'missing':
            assert row['status'] == 'unavailable'
            assert row['reason'] == 'capture-unavailable'
            assert row['branches'] is None


def test_complete_equal_vector_reuses_real_same_crash(dataset, tmp_path):
    dataset.rows[0]['capture'] = capture(dataset, values=(0, 0), branches=(0, 0))
    result = evaluation.evaluate_dataset(dataset, 'rax != 0', execute=False, cache_dir=tmp_path / 'cache')
    assert result['status'] == 'reject_same_crash'
    assert result['verified'] is False
    assert result['cases'][0]['branches'] == [0, 0]
    assert result['cases'][0]['first_divergence'] is None


def test_first_divergence_executes_actual_candidate(dataset, tmp_path, monkeypatch):
    dataset.rows[0]['capture'] = capture(dataset, values=(0, 1, 0), branches=(0, 0, 0))
    calls = []
    def run(ds, case, descriptor, directory):
        calls.append(descriptor)
        return capture(ds, values=(0, 1), branches=(0, 1), descriptor=descriptor, normal=True)
    monkeypatch.setattr(evaluation, 'execute_capture', run)
    result = evaluation.evaluate_dataset(dataset, 'rax != 0', cache_dir=tmp_path / 'cache')
    assert len(calls) == 1
    row = result['cases'][0]
    assert row['source'] == 'executed'
    assert row['first_divergence'] == 1
    assert row['branches'] == [0, 1]
    assert row['status'] == 'not_rejected'


@pytest.mark.parametrize('state', ['absent', 'partial'])
def test_missing_or_partial_capture_requires_independent_execution(dataset, tmp_path, monkeypatch, state):
    if state == 'partial':
        dataset.rows[0]['capture'] = capture(dataset)
        Path(dataset.rows[0]['capture']['path']).write_bytes(b'BR')
    calls = []
    def run(ds, case, descriptor, directory):
        calls.append(case['id'])
        return capture(ds, descriptor=descriptor)
    monkeypatch.setattr(evaluation, 'execute_capture', run)
    result = evaluation.evaluate_dataset(dataset, 'rax != 0', cache_dir=tmp_path / 'cache')
    assert calls == ['system:0']
    # The host collected a real neutral control, then reused its equal vector.
    row = result['cases'][0]
    assert row['neutral_baseline']['source'] == 'executed'
    assert row['capture'] == row['neutral_baseline']['capture']
    assert row['report']['activation']['status'] == 'not_fired'


def test_owned_cache_reused_offline_and_environment_invalidates(dataset, tmp_path, monkeypatch):
    calls = []
    def run(ds, case, descriptor, directory):
        calls.append(descriptor)
        return capture(ds, descriptor=descriptor)
    monkeypatch.setattr(evaluation, 'execute_capture', run)
    root = tmp_path / 'cache'
    first = evaluation.evaluate_dataset(dataset, 'rax != 0', cache_dir=root)
    second = evaluation.evaluate_dataset(dataset, 'rax != 0', cache_dir=root, execute=False)
    assert first['status'] == second['status'] == 'reject_same_crash'
    assert second['cases'][0]['source'] == 'cache'
    dataset.execution_environment = lambda: {'BINARY': 'harmless', 'TEST_CMD': 'different'}
    third = evaluation.evaluate_dataset(dataset, 'rax != 0', cache_dir=root, execute=False)
    assert third['status'] == 'not_rejected'
    assert third['cases'][0]['status'] == 'unavailable'
    assert len(calls) == 1


def test_cached_capture_tampering_is_not_hidden_by_earlier_result(dataset, tmp_path, monkeypatch):
    monkeypatch.setattr(evaluation, 'execute_capture',
                        lambda ds, case, descriptor, directory: capture(ds, descriptor=descriptor))
    cache = tmp_path / 'cache'
    first = evaluation.evaluate_dataset(dataset, '0', cache_dir=cache)
    assert first['status'] == 'reject_same_crash'
    Path(first['cases'][0]['capture']['path']).write_bytes(b'tampered after evaluation')
    monkeypatch.setattr(evaluation, 'execute_capture', lambda *args: pytest.fail('offline target execution'))
    second = evaluation.evaluate_dataset(dataset, '0', execute=False, cache_dir=cache)
    assert second['status'] == 'not_rejected'
    assert second['cases'][0]['status'] == 'unavailable'
    assert second['cases'][0]['reason'] == 'capture-hash-mismatch'
    assert second['cases'][0]['branches'] is None


@pytest.mark.parametrize('operation', ['evaluate', 'warm', 'snapshots'])
def test_independent_evaluation_operations_revalidate_prepared_artifacts(tmp_path, operation):
    from test_context_tools import make_dataset
    dataset = make_dataset(tmp_path / 'prepared', concrete_run=None)
    evaluation.evaluate_dataset(dataset, '0', execute=False, cache_dir=tmp_path / 'cache')
    committed = dataset.case('function:0')['capture']
    dataset.artifact(dataset.binary + '.orig').write_bytes(b'tampered after evaluation')
    with pytest.raises(ValueError, match='hash mismatch'):
        if operation == 'evaluate':
            evaluation.evaluate_dataset(dataset, '0', execute=False, cache_dir=tmp_path / 'cache')
        elif operation == 'warm':
            evaluation.warm_dataset(dataset, cache_dir=tmp_path / 'cache')
        else:
            evaluation._snapshots(dataset, committed)


def test_function_same_crash_offline_only_and_no_divergence_inference(dataset, tmp_path, monkeypatch):
    dataset.rows[0].update(id='function:0', domain='function', capture=capture(dataset, same=True))
    monkeypatch.setattr(evaluation, 'execute_capture', lambda *a: pytest.fail('mutation executed'))
    result = evaluation.evaluate_dataset(dataset, 'rax != 0', cache_dir=tmp_path / 'cache')
    assert result['status'] == 'reject_same_crash'
    result = evaluation.evaluate_dataset(dataset, '1', cache_dir=tmp_path / 'cache')
    assert result['status'] == 'not_rejected'
    assert result['cases'][0]['status'] == 'unavailable'
    assert result['cases'][0]['first_divergence'] == 0


def test_unavailable_oracle_is_not_rejection_or_success(dataset, tmp_path):
    dataset.rows[0]['capture'] = capture(dataset)
    dataset.rows[0]['capture']['outcome']['oracle'] = 'unavailable'
    result = evaluation.evaluate_dataset(dataset, '0', execute=False, cache_dir=tmp_path / 'cache')
    assert result['status'] == 'not_rejected'
    assert result['cases'][0]['status'] == 'unavailable'
    assert result['cases'][0]['reason'] == 'oracle-unavailable'


def test_representative_mirror_mismatch_not_reused(dataset, tmp_path):
    dataset.rows[0]['capture'] = capture(dataset, values=(1,), branches=(1,), descriptor='p0')
    result = evaluation.evaluate_dataset(dataset, '1', execute=False, cache_dir=tmp_path / 'cache')
    assert result['status'] == 'not_rejected'
    assert result['cases'][0]['status'] == 'unavailable'
    assert result['cases'][0]['reason'] == 'representative-evaluator-mismatch'


def test_branch_two_is_unavailable_not_safe_original_branch(dataset, tmp_path):
    from taosc_llm.family import parse_candidate
    candidate = parse_candidate('ERM generic', 'rax / 0')
    dataset.rows[0]['capture'] = capture(dataset, branches=(2,), descriptor=candidate.descriptor)
    result = evaluation.evaluate_dataset(dataset, 'rax / 0', execute=False, cache_dir=tmp_path / 'cache')
    assert result['status'] == 'not_rejected'
    assert result['cases'][0]['status'] == 'unavailable'
    assert result['cases'][0]['branches'] == [2]
    assert result['cases'][0]['reason'] == 'predicate-trap'


def test_bounded_workers_and_duplicate_lock(dataset, tmp_path, monkeypatch):
    guard = threading.Lock()
    active = peak = calls = 0
    committed = capture(dataset)
    def run(ds, case, descriptor, directory):
        nonlocal active, peak, calls
        with guard:
            active += 1
            peak = max(peak, active)
            calls += 1
        time.sleep(.02)
        result = {**committed, 'descriptor': descriptor}
        with guard:
            active -= 1
        return result
    monkeypatch.setattr(evaluation, 'execute_capture', run)
    dataset.rows += [{**dataset.rows[0], 'id': f'system:{i}'} for i in range(1, 5)]
    root = tmp_path / 'cache'
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: evaluation.evaluate_dataset(dataset, '0', workers=2, cache_dir=root), range(2)))
    assert calls == 5
    assert peak <= 4  # Two independently bounded callers; duplicate cases serialize.
    assert all(r['status'] == 'reject_same_crash' for r in results)


@pytest.mark.parametrize('qemu', ['fixture', None])
def test_late_journal_commit_requires_tracer_identity_and_preserves_producer(dataset, tmp_path, monkeypatch, qemu):
    import json
    monkeypatch.setattr(evaluation, 'execution_identity', lambda: {'qemu': qemu, 'oracle': 'qasan-main-v2'})
    committed = capture(dataset)
    run = tmp_path / 'producer'
    channel = run / 'feedback-capture' / 'baseline'
    states = run / 'feedback-capture' / 'states'
    channel.mkdir(parents=True)
    states.mkdir()
    dataset.manifest['sources']['concrete_run'] = str(run)
    dataset.rows[0]['source'] = {'case_id': 0, 'filename': 'input'}
    root = tmp_path / 'cache'
    first = evaluation.evaluate_dataset(dataset, '0', execute=False, cache_dir=root)
    assert first['status'] == 'not_rejected'
    assert first['cases'][0]['status'] == 'unavailable'
    header = {'version': 1, 'channel': 'baseline', 'candidates': 'none',
              'brpatches.json': sha256(dataset.artifact('brpatches.json')), 'binradar.env': None,
              'context': {'original_sha256': sha256(dataset.artifact('harmless.orig')), 'qemu_sha256': qemu}}
    (channel / 'header.json').write_text(json.dumps(header))
    (states / (committed['sha256'] + '.brch')).write_bytes(Path(committed['path']).read_bytes())
    input_row = {'kind': 'input', 'case': 0, 'file': 'input', 'sha256': dataset.rows[0]['input_sha256']}
    trace = {'kind': 'trace', 'representative': 0, 'artifact': committed['artifact_sha256'],
             'state_reason': 'none', 'state_sha256': committed['sha256'], 'capture_id': 0,
             'hits': 1, 'branches': '00', **committed['outcome']}
    journal = channel / '0.jsonl'
    journal.write_text(json.dumps(input_row) + '\n' + json.dumps(trace))
    partial = evaluation.evaluate_dataset(dataset, '0', execute=False, cache_dir=root)
    assert partial['status'] == 'not_rejected'
    assert partial['cases'][0]['status'] == 'unavailable'
    with journal.open('a') as stream:
        stream.write('\n')
    before = journal.read_bytes()
    final = evaluation.evaluate_dataset(dataset, '0', execute=False, cache_dir=root)
    assert final['status'] == ('reject_same_crash' if qemu else 'not_rejected')
    assert final['cases'][0]['status'] == ('reject_same_crash' if qemu else 'unavailable')
    assert final['cases'][0]['source'] == ('cache' if qemu else 'unavailable')
    assert journal.read_bytes() == before


def test_republished_producer_header_is_reauthenticated_between_cases(dataset, tmp_path, monkeypatch):
    import json
    committed = capture(dataset)
    run = tmp_path / 'producer'
    channel = run / 'feedback-capture' / 'baseline'
    states = run / 'feedback-capture' / 'states'
    channel.mkdir(parents=True)
    states.mkdir()
    dataset.manifest['sources']['concrete_run'] = str(run)
    dataset.rows[0]['source'] = {'case_id': 0, 'filename': 'input'}
    dataset.rows.append({**dataset.rows[0], 'id': 'system:1',
                         'source': {'case_id': 1, 'filename': 'input'}})
    header = {'version': 1, 'channel': 'baseline', 'candidates': 'none',
              'brpatches.json': sha256(dataset.artifact('brpatches.json')), 'binradar.env': None,
              'context': {'original_sha256': sha256(dataset.artifact('harmless.orig')),
                          'qemu_sha256': 'fixture'}}
    header_path = channel / 'header.json'
    header_path.write_text(json.dumps(header))
    (states / (committed['sha256'] + '.brch')).write_bytes(Path(committed['path']).read_bytes())
    input_row = {'kind': 'input', 'case': 1, 'file': 'input',
                 'sha256': dataset.rows[1]['input_sha256']}
    trace = {'kind': 'trace', 'representative': 0, 'artifact': committed['artifact_sha256'],
             'state_reason': 'none', 'state_sha256': committed['sha256'], 'capture_id': 0,
             'hits': 1, 'branches': '00', **committed['outcome']}
    (channel / '1.jsonl').write_text(json.dumps(input_row) + '\n' + json.dumps(trace) + '\n')

    def execute_after_republication(ds, case, descriptor, directory):
        if case['id'] == 'system:0':
            # Case 0 has no journal capture. While it executes, the producer
            # republishes the same channel under a different tracer identity.
            replaced = {**header, 'context': {**header['context'], 'qemu_sha256': 'other-tracer'}}
            header_path.write_text(json.dumps(replaced))
            return committed
        raise evaluation.ExecutionUnavailable('replacement-producer-unavailable')

    monkeypatch.setattr(evaluation, 'execute_capture', execute_after_republication)
    root = tmp_path / 'cache'
    result = evaluation.evaluate_dataset(dataset, '0', workers=1, cache_dir=root)
    assert result['cases'][0]['status'] == 'reject_same_crash'
    assert result['cases'][1]['status'] == 'unavailable'
    assert result['cases'][1]['source'] == 'unavailable'
    # The journal bytes are reusable only after a currently matching header
    # authenticates them, not because a previous operation trusted this path.
    header_path.write_text(json.dumps(header))
    restored = evaluation.evaluate_dataset(dataset, '0', case_ids=['system:1'],
                                           execute=False, cache_dir=root)
    assert restored['cases'][0]['status'] == 'reject_same_crash'
    assert restored['cases'][0]['source'] == 'cache'


@pytest.mark.parametrize('value', [[], None, 1, 'cache', {'identity': {}, 'capture': []}])
def test_malformed_cache_records_are_unavailable(tmp_path, value):
    import json
    path = tmp_path / 'record.json'
    path.write_text(json.dumps(value))
    assert evaluation._cache_record(path, {}) is None


@pytest.mark.parametrize('cwe', [False, True])
def test_absolute_capture_descriptor_must_match_dataset_family(dataset, tmp_path, cwe):
    from taosc_llm.family import parse_candidate
    if cwe:
        dataset.patch_format = 'ERM CWE-805'
        descriptor = parse_candidate('ERM generic', '0').descriptor
        predicate = 's->rax >= i->begin && s->rax < i->end'
        committed = capture(dataset, values=(), branches=(), descriptor=descriptor)
    else:
        descriptor = parse_candidate('ERM CWE-805', 's->rax >= i->begin && s->rax < i->end').descriptor
        predicate = '1'
        committed = capture(dataset, branches=(1,), descriptor=descriptor)
    dataset.rows[0]['capture'] = committed
    result = evaluation.evaluate_dataset(dataset, predicate, execute=False, cache_dir=tmp_path / 'cache')
    assert result['status'] == 'not_rejected'
    assert result['cases'][0]['status'] == 'unavailable'
    assert result['cases'][0]['reason'] == 'capture-descriptor-family-mismatch'


def test_warm_is_explicit_neutral_descriptor(dataset, tmp_path, monkeypatch):
    dataset.patch_format = 'ERM CWE-805'
    calls = []
    def run(ds, case, descriptor, directory):
        calls.append(descriptor)
        # No hits is valid for either family and needs no fabricated predicate.
        return capture(ds, values=(), branches=(), descriptor=descriptor)
    monkeypatch.setattr(evaluation, 'execute_capture', run)
    result = evaluation.warm_dataset(dataset, cache_dir=tmp_path / 'cache')
    assert calls == ['p0']
    assert result['predicate'] is None
    assert result['verified'] is False


def representative_scenario(dataset, cwe):
    from taosc_llm.family import parse_candidate
    pointer = 's->rax >= i->begin && s->rax < i->end'
    dataset.patch_format = 'ERM CWE-805' if cwe else 'ERM generic'
    expressions = ((pointer, f'({pointer}) || ({pointer})', '1 * s->rax < i->end - i->begin')
                   if cwe else ('rax != 0', 'rax > 0', 'rax == 0'))
    values = (99, 100, 99) if cwe else (1, 0, 1)
    candidates = [parse_candidate(dataset.patch_format, expression) for expression in expressions]
    dataset.rows[0]['capture'] = capture(dataset, values=values, branches=(0, 0, 0), cwe=cwe)
    return expressions, candidates, values


@pytest.mark.parametrize('cwe', [False, True])
def test_durable_nonneutral_representative_reuses_different_descriptor(dataset, tmp_path, monkeypatch, cwe):
    expressions, candidates, values = representative_scenario(dataset, cwe)
    actual = {candidates[0].descriptor: (1, 0, 1), candidates[2].descriptor: (0, 1, 0)}
    executions = []
    def run(ds, case, descriptor, directory):
        executions.append(descriptor)
        return capture(ds, values=values, branches=actual[descriptor], descriptor=descriptor,
                       normal=True, cwe=cwe)
    monkeypatch.setattr(evaluation, 'execute_capture', run)
    cache = tmp_path / 'cache'
    first = evaluation.evaluate_dataset(dataset, expressions[0], cache_dir=cache)
    assert first['cases'][0]['source'] == 'executed'
    assert first['cases'][0]['branches'] == [1, 0, 1]
    # A separate API operation must discover the real A capture through the
    # durable pool; B has no exact record and differs from the neutral vector.
    second = evaluation.evaluate_dataset(dataset, expressions[1], execute=False, cache_dir=cache)
    row = second['cases'][0]
    assert row['status'] == 'not_rejected'
    assert row['source'] == 'cache'
    assert row['reuse'] == 'full-vector-equivalent'
    assert row['capture']['descriptor'] == candidates[0].descriptor
    assert row['report']['candidate']['capture']['total_hits'] == 3
    third = evaluation.evaluate_dataset(dataset, expressions[2], cache_dir=cache)
    assert third['cases'][0]['source'] == 'executed'
    assert third['cases'][0]['branches'] == [0, 1, 0]
    assert executions == [candidates[0].descriptor, candidates[2].descriptor]


@pytest.mark.parametrize('cwe', [False, True])
def test_parallel_equivalent_descriptors_share_real_representative(dataset, tmp_path, monkeypatch, cwe):
    expressions, candidates, values = representative_scenario(dataset, cwe)
    gate = threading.Barrier(2)
    executions = []
    def run(ds, case, descriptor, directory):
        executions.append(descriptor)
        time.sleep(0.03)
        return capture(ds, values=values, branches=(1, 0, 1), descriptor=descriptor,
                       normal=True, cwe=cwe)
    monkeypatch.setattr(evaluation, 'execute_capture', run)
    def evaluate(expression):
        gate.wait(timeout=5)
        return evaluation.evaluate_dataset(dataset, expression, cache_dir=tmp_path / 'cache')
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(evaluate, expressions[:2]))
    assert len(executions) == 1
    assert all(result['cases'][0]['status'] == 'not_rejected' for result in results)
    assert {result['cases'][0]['source'] for result in results} == {'executed', 'cache'}
    assert all(result['cases'][0]['capture']['descriptor'] == executions[0] for result in results)


@pytest.mark.parametrize('change', ['dataset', 'input', 'case', 'source', 'observation',
                                    'environment', 'oracle', 'runtime', 'evaluator'])
def test_representative_pool_retains_every_non_descriptor_identity(dataset, tmp_path, monkeypatch, change):
    expressions, candidates, values = representative_scenario(dataset, False)
    monkeypatch.setattr(evaluation, 'execute_capture', lambda ds, case, descriptor, directory:
                        capture(ds, values=values, branches=(1, 0, 1), descriptor=descriptor, normal=True))
    cache = tmp_path / 'cache'
    assert evaluation.evaluate_dataset(dataset, expressions[0], cache_dir=cache)['status'] == 'not_rejected'
    if change == 'dataset':
        dataset.dataset_id = 'other-dataset'
    elif change == 'input':
        dataset.rows[0]['input_sha256'] = 'f' * 64
    elif change == 'case':
        dataset.rows[0]['id'] = 'system:9'
    elif change == 'source':
        dataset.rows[0]['source'] = {'filename': 'other-input'}
    elif change == 'observation':
        dataset.rows[0]['observation'] = {'exit': 'ok'}
    elif change == 'environment':
        monkeypatch.setattr(dataset, 'execution_environment', lambda: {'BINARY': 'harmless', 'TEST_CMD': 'changed'})
    elif change == 'oracle':
        dataset.manifest['oracles']['concrete_reference'] = 44
    elif change == 'runtime':
        monkeypatch.setattr(evaluation, 'execution_identity', lambda: {'qemu': 'other', 'oracle': 'qasan-main-v2'})
    else:
        original_sha256 = evaluation.sha256
        monkeypatch.setattr(evaluation, 'sha256', lambda path:
                            'e' * 64 if Path(path) == Path(evaluation.__file__) else original_sha256(path))
    second = evaluation.evaluate_dataset(dataset, expressions[1], execute=False, cache_dir=cache)
    assert second['status'] == 'not_rejected'
    assert second['cases'][0]['status'] == 'unavailable'
    assert second['cases'][0]['branches'] is None


@pytest.mark.parametrize('damage', ['bytes', 'partial', 'selector', 'mirror', 'sidecar', 'index', 'record', 'metadata'])
def test_damaged_durable_representative_never_becomes_success(dataset, tmp_path, monkeypatch, damage):
    import json
    expressions, candidates, values = representative_scenario(dataset, False)
    monkeypatch.setattr(evaluation, 'execute_capture', lambda ds, case, descriptor, directory:
                        capture(ds, values=values, branches=(1, 0, 1), descriptor=descriptor, normal=True))
    cache = tmp_path / 'cache'
    first = evaluation.evaluate_dataset(dataset, expressions[0], cache_dir=cache)
    saved = first['cases'][0]['capture']
    root = cache / 'evaluation-v2' / evaluation._digest(dataset.dataset_id)
    index_path = next(root.glob('*.representatives.json'))
    index = json.loads(index_path.read_text())
    identity = {**index['identity'], 'descriptor': candidates[0].descriptor}
    record_path = root / (evaluation._digest(identity) + '.json')
    record = json.loads(record_path.read_text())
    if damage == 'bytes':
        Path(saved['path']).write_bytes(b'corrupt')
    elif damage == 'partial':
        raw = Path(saved['path']).read_bytes()[:-1]
        Path(saved['path']).write_bytes(raw)
        record['capture']['sha256'] = hashlib.sha256(raw).hexdigest()
    elif damage == 'selector':
        record['capture']['patch_id'] = 27
    elif damage == 'mirror':
        record['capture']['descriptor'] = 'p0'
    elif damage == 'sidecar':
        sidecar = tmp_path / 'sidecar.sbsv'
        sidecar.write_text('changed')
        record['capture']['sidecar'] = {'path': str(sidecar), 'sha256': '0' * 64}
    elif damage == 'index':
        index['descriptors'].append(None)
        index_path.write_text(json.dumps(index))
    elif damage == 'metadata':
        record['capture']['outcome']['fault_addr'] = 999
    else:
        record = {'identity': identity, 'capture': []}
    if damage != 'metadata' and isinstance(record.get('capture'), dict):
        record['capture_digest'] = evaluation._digest(record['capture'])
    record_path.write_text(json.dumps(record))
    second = evaluation.evaluate_dataset(dataset, expressions[1], execute=False, cache_dir=cache)
    assert second['status'] == 'not_rejected'
    assert second['cases'][0]['status'] == 'unavailable'
    assert second['cases'][0]['branches'] is None


@pytest.mark.parametrize('cwe', [False, True])
@pytest.mark.parametrize('state', ['trap', 'timeout', 'incomplete'])
def test_unusable_real_execution_is_not_published_as_representative(dataset, tmp_path, monkeypatch, cwe, state):
    from taosc_llm.family import parse_candidate
    expressions, candidates, values = representative_scenario(dataset, cwe)
    branches = (1, 0, 1)
    if state == 'trap':
        atom = '8 * s->rax < i->end - i->begin' if cwe else 'rax / 0'
        expressions = (atom, f'({atom}) || ({atom})')
        candidates = [parse_candidate(dataset.patch_format, expression) for expression in expressions]
        values = ((1 << 64) - 1,) if cwe else (1,)
        branches = (2,)
        dataset.rows[0]['capture'] = capture(dataset, values=values, branches=(0,), cwe=cwe)
    def run(ds, case, descriptor, directory):
        result = capture(ds, values=values, branches=branches, descriptor=descriptor, normal=True, cwe=cwe)
        if state == 'timeout':
            result['outcome']['outcome'] = 'timeout'
        elif state == 'incomplete':
            result['complete'] = False
        return result
    monkeypatch.setattr(evaluation, 'execute_capture', run)
    cache = tmp_path / 'cache'
    first = evaluation.evaluate_dataset(dataset, expressions[0], cache_dir=cache)
    assert first['status'] == 'not_rejected'
    assert first['cases'][0]['status'] == 'unavailable'
    assert first['cases'][0]['source'] == 'executed'
    second = evaluation.evaluate_dataset(dataset, expressions[1], execute=False, cache_dir=cache)
    assert second['status'] == 'not_rejected'
    assert second['cases'][0]['status'] == 'unavailable'
    assert second['cases'][0]['branches'] is None
    root = cache / 'evaluation-v2' / evaluation._digest(dataset.dataset_id)
    assert not list(root.glob('*.representatives.json'))


def test_operation_stop_propagates_and_prevents_remaining_concrete_cases(dataset, tmp_path, monkeypatch):
    class SearchStopped(RuntimeError):
        pass
    stopped = threading.Event()
    executions = []
    dataset.rows += [{**dataset.rows[0], 'id': f'system:{index}'} for index in range(1, 20)]
    def check():
        if stopped.is_set():
            raise SearchStopped('cancelled')
    def run(ds, case, descriptor, directory):
        executions.append((case['id'], descriptor))
        stopped.set()
        return capture(ds, descriptor=descriptor)
    monkeypatch.setattr(evaluation, 'execute_capture', run)
    cache = tmp_path / 'cache'
    with pytest.raises(SearchStopped, match='cancelled'):
        evaluation.evaluate_dataset(dataset, '1', workers=1, cache_dir=cache, operation_check=check)
    assert executions == [('system:0', 'p0')]
    root = cache / 'evaluation-v2' / evaluation._digest(dataset.dataset_id)
    assert not list(root.glob('*.result.json'))


def test_operation_stop_interrupts_contended_pool_lock_without_releasing_owner(tmp_path):
    class SearchStopped(RuntimeError):
        pass
    path = tmp_path / 'pool.lock'
    checks = 0
    def check():
        nonlocal checks
        checks += 1
        if checks > 1:
            raise SearchStopped('cancelled while waiting')
    with evaluation._lock(path):
        with pytest.raises(SearchStopped, match='while waiting'):
            with evaluation._lock(path, operation_check=check):
                pytest.fail('contended cancelled operation acquired lock')
        # The interrupted waiter must not unlock the original owner's flock.
        with path.open('a') as contender:
            with pytest.raises(BlockingIOError):
                evaluation.fcntl.flock(contender, evaluation.fcntl.LOCK_EX | evaluation.fcntl.LOCK_NB)
    with evaluation._lock(path, operation_check=lambda: None):
        assert path.is_file()
