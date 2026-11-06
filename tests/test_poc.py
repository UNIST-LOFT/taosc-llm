"""Frozen POC identity, acquisition, reuse and provenance; no target execution."""
import copy
import json
from pathlib import Path

import pytest
from binradar import binradar_taosc_predicates as predicates

from taosc_llm import evaluation, poc
from taosc_llm.dataset import canonical, load_dataset
from taosc_llm.execution import ExecutionUnavailable, sha256
from test_context_tools import make_dataset


ORIGINAL = {'outcome': 'crash', 'oracle': 'qasan-main-v2',
            'fault_valid': True, 'fault_addr': 4096}


def prepared(root, *, family='ERM generic', matches=(), recorded=True, captured=True):
    dataset = make_dataset(root, count=0, patch_format=family, concrete_run=None)
    manifest = copy.deepcopy(dataset.manifest)
    payload = b'actual frozen POC, never model text'
    dataset.workdir.joinpath('poc').write_bytes(payload)
    manifest['artifacts']['poc'] = {'path': 'workdir/poc', 'sha256': sha256(dataset.workdir / 'poc')}
    manifest['oracles'] = {'concrete_reference': 4096}
    rows = []
    for number in matches:
        row = {'id': f'system:{number}', 'domain': 'system',
               'input_path': 'workdir/poc', 'input_sha256': manifest['artifacts']['poc']['sha256'],
               'source': {'kind': 'original-result', 'case_id': number, 'filename': f'input-{number}'},
               'observation': ORIGINAL if recorded else None, 'capture': None}
        if captured is True or (isinstance(captured, tuple) and number in captured):
            raw = (predicates.CACHED_SNAPSHOT_HEADER.pack(
                predicates.CACHED_SNAPSHOT_MAGIC, 1, 0, 0, 0, 2 if family == 'ERM CWE-805' else 0)
                + (b'\0' * predicates.CACHED_SNAPSHOT_CLAMPS.size if family == 'ERM CWE-805' else b'')
                + predicates.CACHED_SNAPSHOT_REGS.pack(17, *([0] * 15)))
            state = root / 'poc.brch'
            state.write_bytes(raw)
            row['capture'] = {'path': 'poc.brch', 'sha256': sha256(state), 'complete': True,
                              'artifact_sha256': manifest['artifacts']['fixture.brcached']['sha256'],
                              'branches': [0], 'descriptor': 'p0', 'outcome': {
                                  'outcome': 'normal', 'oracle': 'qasan-main-v2', 'fault_valid': False}}
        rows.append(row)
    (root / 'cases.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
    manifest['cases']['sha256'] = sha256(root / 'cases.jsonl')
    manifest.pop('dataset_id')
    import hashlib
    manifest['dataset_id'] = hashlib.sha256(canonical(manifest)).hexdigest()
    (root / 'manifest.json').write_text(json.dumps(manifest))
    return load_dataset(root)


def no_execution(*args, **kwargs):
    pytest.fail('offline/reusable POC must not execute a target or socket')


@pytest.mark.parametrize('family', ['ERM generic', 'ERM CWE-805'])
def test_exact_original_input_reuses_real_observation_and_neutral_states(tmp_path, monkeypatch, family):
    dataset = prepared(tmp_path / 'dataset', family=family, matches=(861, 900), captured=(900,))
    monkeypatch.setattr(poc, 'execute_original', no_execution)
    monkeypatch.setattr(evaluation, 'execute_capture', no_execution)
    result = poc.poc_observation(dataset, cache_dir=tmp_path / 'cache', execute=False)
    assert result['case']['id'] == 'system:861'
    assert result['matching_case_ids'] == ['system:861', 'system:900']
    assert result['original']['source'] == 'recorded'
    assert result['original']['outcome']['fault_addr'] == 4096
    assert result['neutral']['basis'] == 'neutral-cached-artifact'
    assert result['neutral']['first_hit_registers']['rax'] == '17'
    assert result['neutral']['outcome']['outcome'] == 'normal'
    assert result['subject']['input_bytes'] == dataset.artifact('poc').stat().st_size
    assert result['subject']['args'] == ['<input>']
    assert 'note' not in result
    assert 'actual frozen POC' not in json.dumps(result)


def test_absent_prepared_case_is_frozen_poc_not_manifest_mutation(tmp_path, monkeypatch):
    dataset = prepared(tmp_path / 'dataset')
    before = (dataset.root / 'manifest.json').read_bytes(), (dataset.root / 'cases.jsonl').read_bytes()
    monkeypatch.setattr(poc, 'execute_original', no_execution)
    monkeypatch.setattr(evaluation, 'execute_capture', no_execution)
    result = poc.poc_observation(dataset, cache_dir=tmp_path / 'cache', execute=False)
    case = result['case']
    assert case['id'] == 'system:0'
    assert case['input_sha256'] == dataset.manifest['artifacts']['poc']['sha256']
    assert case['input_path'] == dataset.manifest['artifacts']['poc']['path']
    assert result['original']['outcome'] is None
    assert 'first_hit_registers' not in result['neutral']
    # Even an explicitly empty host selection includes the original POC by default.
    candidate = evaluation.evaluate_dataset(dataset, '0', case_ids=[], execute=False,
                                            cache_dir=tmp_path / 'cache')
    assert [row['case_id'] for row in candidate['cases']] == [case['id']]
    assert before == ((dataset.root / 'manifest.json').read_bytes(), (dataset.root / 'cases.jsonl').read_bytes())


def test_missing_original_is_collected_once_and_runtime_bound(tmp_path, monkeypatch):
    dataset = prepared(tmp_path / 'dataset', matches=(861,), recorded=False)
    runtime = {'qemu': 'first-tracer', 'oracle': 'qasan-main-v2'}
    monkeypatch.setattr(poc, 'execution_identity', lambda: dict(runtime))
    calls = []
    def original(ds, case, directory):
        calls.append(case['id'])
        return {'artifact_sha256': ds.manifest['artifacts']['fixture.orig']['sha256'],
                'outcome': dict(ORIGINAL)}
    monkeypatch.setattr(poc, 'execute_original', original)
    monkeypatch.setattr(evaluation, 'execute_capture', no_execution)
    cache = tmp_path / 'cache'
    first = poc.poc_observation(dataset, cache_dir=cache, execute=True)
    second = poc.poc_observation(dataset, cache_dir=cache, execute=False)
    assert first['original']['source'] == 'executed'
    assert second['original']['source'] == 'cache'
    assert calls == ['system:861']
    runtime['qemu'] = 'changed-tracer'
    third = poc.poc_observation(dataset, cache_dir=cache, execute=False)
    assert third['original']['outcome'] is None
    assert calls == ['system:861']


def test_owned_original_record_tamper_cannot_forge_observation(tmp_path, monkeypatch):
    dataset = prepared(tmp_path / 'dataset', matches=(861,), recorded=False)
    monkeypatch.setattr(poc, 'execute_original', lambda ds, case, directory: {
        'artifact_sha256': ds.manifest['artifacts']['fixture.orig']['sha256'], 'outcome': dict(ORIGINAL)})
    cache = tmp_path / 'cache'
    poc.poc_observation(dataset, cache_dir=cache, execute=True)
    path = next((cache / 'poc-v1').rglob('*.json'))
    record = json.loads(path.read_text())
    record['record']['outcome']['fault_addr'] = 12345
    path.write_text(json.dumps(record))
    monkeypatch.setattr(poc, 'execute_original', no_execution)
    result = poc.poc_observation(dataset, cache_dir=cache, execute=False)
    assert result['original']['outcome'] is None
    assert result['neutral']['first_hit_registers']['rax'] == '17'


def test_capture_tamper_fails_closed_and_does_not_become_original_registers(tmp_path, monkeypatch):
    dataset = prepared(tmp_path / 'dataset', matches=(861,))
    # Frozen dataset corruption is rejected before collection or cached reuse.
    (dataset.root / 'poc.brch').write_bytes(b'changed')
    monkeypatch.setattr(poc, 'execute_original', no_execution)
    monkeypatch.setattr(evaluation, 'execute_capture', no_execution)
    with pytest.raises(ValueError, match='hash mismatch'):
        poc.poc_observation(dataset, cache_dir=tmp_path / 'cache', execute=False)


def test_real_failure_remains_one_concise_limitation_without_fake_example(tmp_path, monkeypatch):
    dataset = prepared(tmp_path / 'dataset')
    def unavailable(*args, **kwargs):
        raise ExecutionUnavailable('/private/secret/runtime failed')
    monkeypatch.setattr(poc, 'execute_original', unavailable)
    monkeypatch.setattr(evaluation, 'execute_capture', unavailable)
    result = poc.poc_observation(dataset, cache_dir=tmp_path / 'cache', execute=True)
    assert result['original']['outcome'] is None
    assert 'first_hit_registers' not in result['neutral']
    assert '/private/' not in result['note']


@pytest.mark.parametrize('family', ['ERM generic', 'ERM CWE-805'])
def test_absent_poc_fresh_capture_is_reused_and_candidate_evaluated(tmp_path, monkeypatch, family):
    dataset = prepared(tmp_path / 'dataset', family=family)
    calls = []
    monkeypatch.setattr(poc, 'execute_original', lambda ds, case, directory: {
        'artifact_sha256': ds.manifest['artifacts']['fixture.orig']['sha256'], 'outcome': dict(ORIGINAL)})
    def collect(ds, case, descriptor, directory):
        calls.append((case['id'], descriptor))
        assert (ds.root / case['input_path']).read_bytes() == ds.artifact('poc').read_bytes()
        branch = 0 if descriptor == 'p0' else 1
        raw = (predicates.CACHED_SNAPSHOT_HEADER.pack(
            predicates.CACHED_SNAPSHOT_MAGIC, 1, 0, branch, 0, 2 if family == 'ERM CWE-805' else 0)
            + (b'\0' * predicates.CACHED_SNAPSHOT_CLAMPS.size if family == 'ERM CWE-805' else b'')
            + predicates.CACHED_SNAPSHOT_REGS.pack(17, *([0] * 15)))
        directory.mkdir(parents=True, exist_ok=True)
        path = (directory / f'{branch}.brch').resolve()
        path.write_bytes(raw)
        return {'path': str(path), 'sha256': sha256(path), 'complete': True,
                'artifact_sha256': ds.manifest['artifacts']['fixture.brcached']['sha256'],
                'branches': [branch], 'descriptor': descriptor,
                'outcome': dict(ORIGINAL) if branch == 0 else {
                    'outcome': 'normal', 'oracle': 'qasan-main-v2', 'fault_valid': False}}
    monkeypatch.setattr(evaluation, 'execute_capture', collect)
    cache = tmp_path / 'cache'
    observation = poc.poc_observation(dataset, cache_dir=cache, execute=True)
    assert observation['neutral']['first_hit_registers']['rax'] == '17'
    assert observation['original']['source'] == 'executed'
    assert 'note' not in observation
    reused = poc.poc_observation(dataset, cache_dir=cache, execute=False)
    assert reused['neutral']['source'] == 'cache'
    expression = '1' if family == 'ERM generic' else 's->rax >= i->begin && s->rax < i->end'
    candidate = evaluation.evaluate_dataset(dataset, expression, cache_dir=cache)
    assert candidate['cases'][0]['case_id'] == observation['case']['id']
    assert candidate['cases'][0]['source'] == 'executed'
    assert candidate['cases'][0]['branches'] == [1]
    assert calls == [('system:0', 'p0'), ('system:0', candidate['descriptor'])]


def test_fixture_without_frozen_poc_has_no_synthetic_case(tmp_path):
    dataset = make_dataset(tmp_path / 'dataset', count=0)
    assert poc.poc_case(dataset) is None
