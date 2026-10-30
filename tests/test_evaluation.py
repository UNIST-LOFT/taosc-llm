"""Behavioral evaluation contracts; no provider or research target execution."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
from pathlib import Path
import threading
import time

import pytest

from binradar.binradar_taosc_predicates import (
    CACHED_SNAPSHOT_HEADER, CACHED_SNAPSHOT_MAGIC, CACHED_SNAPSHOT_VERSION,
    CACHED_SNAPSHOT_REGS,
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
        pass

    def cases(self, domain='all'):
        return [row for row in self.rows if domain == 'all' or row['domain'] == domain]

    def case(self, case_id):
        return next(row for row in self.rows if row['id'] == case_id)


def capture(dataset, *, values=(0,), branches=(0,), descriptor='p0', normal=False, same=None):
    raw = b''
    for value, branch in zip(values, branches):
        registers = [0] * 16
        # BinRadar register layout uses rax at index 0.
        registers[0] = value
        raw += CACHED_SNAPSHOT_HEADER.pack(CACHED_SNAPSHOT_MAGIC, CACHED_SNAPSHOT_VERSION, 0, branch, 0, 0)
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
    assert result['cases'][0]['source'] == 'executed'


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
    assert third['status'] == 'unavailable'
    assert len(calls) == 1


def test_function_same_crash_offline_only_and_no_divergence_inference(dataset, tmp_path, monkeypatch):
    dataset.rows[0].update(id='function:0', domain='function', capture=capture(dataset, same=True))
    monkeypatch.setattr(evaluation, 'execute_capture', lambda *a: pytest.fail('mutation executed'))
    result = evaluation.evaluate_dataset(dataset, 'rax != 0', cache_dir=tmp_path / 'cache')
    assert result['status'] == 'reject_same_crash'
    result = evaluation.evaluate_dataset(dataset, '1', cache_dir=tmp_path / 'cache')
    assert result['status'] == 'unavailable'
    assert result['cases'][0]['first_divergence'] == 0


def test_unavailable_oracle_is_not_rejection_or_success(dataset, tmp_path):
    dataset.rows[0]['capture'] = capture(dataset)
    dataset.rows[0]['capture']['outcome']['oracle'] = 'unavailable'
    result = evaluation.evaluate_dataset(dataset, '0', execute=False, cache_dir=tmp_path / 'cache')
    assert result['status'] == 'unavailable'
    assert result['cases'][0]['reason'] == 'oracle-unavailable'


def test_representative_mirror_mismatch_not_reused(dataset, tmp_path):
    dataset.rows[0]['capture'] = capture(dataset, values=(1,), branches=(1,), descriptor='p0')
    result = evaluation.evaluate_dataset(dataset, '1', execute=False, cache_dir=tmp_path / 'cache')
    assert result['status'] == 'unavailable'
    assert result['cases'][0]['reason'] == 'representative-evaluator-mismatch'


def test_branch_two_is_unavailable_not_safe_original_branch(dataset, tmp_path):
    from taosc_llm.family import parse_candidate
    candidate = parse_candidate('ERM generic', 'rax / 0')
    dataset.rows[0]['capture'] = capture(dataset, branches=(2,), descriptor=candidate.descriptor)
    result = evaluation.evaluate_dataset(dataset, 'rax / 0', execute=False, cache_dir=tmp_path / 'cache')
    assert result['status'] == 'unavailable'
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
    assert first['status'] == 'unavailable'
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
    assert partial['status'] == 'unavailable'
    with journal.open('a') as stream:
        stream.write('\n')
    before = journal.read_bytes()
    final = evaluation.evaluate_dataset(dataset, '0', execute=False, cache_dir=root)
    assert final['status'] == ('reject_same_crash' if qemu else 'unavailable')
    assert final['cases'][0]['source'] == ('cache' if qemu else 'unavailable')
    assert journal.read_bytes() == before


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
    assert result['status'] == 'unavailable'
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
