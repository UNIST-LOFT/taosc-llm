"""Reports distinguish observed outcomes, controls and actual activation."""
import json

import pytest

from taosc_llm import evaluation
from taosc_llm.evidence import mutation_provenance, oracle_reference, project_case, summarize_reports
from taosc_llm.family import parse_candidate
from taosc_llm.execution import sha256
from test_evaluation import Dataset, capture


@pytest.fixture
def dataset(tmp_path, monkeypatch):
    monkeypatch.setattr(evaluation, 'execution_identity', lambda: {'qemu': 'fixture', 'oracle': 'qasan-main-v2'})
    return Dataset(tmp_path)


def observed(committed, *, same=True, reason=None):
    return {'capture': committed, 'outcome': committed['outcome'], 'descriptor': committed['descriptor'],
            'status': 'reject_same_crash' if same else 'not_rejected',
            'reason': reason or ('same-crash' if same else 'observed-not-same-crash'),
            'source': 'cache'}


@pytest.mark.parametrize(('branches', 'predicate', 'values', 'status', 'hits'), [
    ((0, 1, 0, 1), 'rax != 0', (0, 1, 0, 1), 'fired', (2, 2, 0)),
    ((0, 0), 'rax != 0', (0, 0), 'not_fired', (2, 0, 0)),
    ((), 'rax != 0', (), 'zero_hits', (0, 0, 0)),
    ((2,), 'rax / 0', (1,), 'trapped', (0, 0, 1)),
])
def test_activation_requires_authenticated_complete_actual_capture(dataset, branches, predicate, values, status, hits):
    descriptor = parse_candidate(dataset.patch_format, predicate).descriptor
    committed = capture(dataset, branches=branches, descriptor=descriptor, values=values)
    report = project_case(dataset, dataset.rows[0], observed(committed))
    assert report['activation'] == dict(zip(('status', 'original_hits', 'repair_hits', 'trap_hits'), (status, *hits)))
    assert report['candidate']['capture']['status'] == ('zero_hits' if not branches else 'complete')


@pytest.mark.parametrize('kind', ['missing', 'partial', 'tampered', 'wrong-artifact', 'wrong-selector', 'mirror-mismatch'])
def test_unknown_capture_never_counts_as_zero_or_predicted_activity(dataset, kind):
    committed = capture(dataset)
    if kind == 'missing':
        committed = None
    elif kind == 'partial':
        committed['complete'] = False
    elif kind == 'tampered':
        committed['sha256'] = '0' * 64
    elif kind == 'wrong-artifact':
        committed['artifact_sha256'] = '0' * 64
    elif kind == 'wrong-selector':
        committed['patch_id'] = 99
    else:
        committed['descriptor'] = parse_candidate(dataset.patch_format, '1').descriptor
    row = {'capture': committed, 'status': 'unavailable', 'reason': 'branch-divergence',
           'offline_branches': [1, 1], 'first_divergence': 0}
    report = project_case(dataset, dataset.rows[0], row)
    assert report['activation'] == {'status': 'unknown', 'original_hits': None, 'repair_hits': None, 'trap_hits': None}
    # A capture gap must not erase a separately known host outcome.
    assert report['candidate']['outcome'] == ('unknown' if kind in ('missing', 'wrong-artifact') else 'target_crash')


def test_legacy_activation_requires_explicit_candidate_identity(dataset):
    descriptor = parse_candidate(dataset.patch_format, '1').descriptor
    committed = capture(dataset, branches=(1,), values=(1,), descriptor=descriptor, normal=True)
    legacy = observed(committed, same=False)
    del legacy['descriptor']
    assert project_case(dataset, dataset.rows[0], legacy)['activation']['status'] == 'unknown'
    assert project_case(dataset, dataset.rows[0], legacy, descriptor=descriptor)['activation']['status'] == 'fired'
    assert project_case(dataset, dataset.rows[0], legacy, predicate='1')['activation']['status'] == 'fired'


def test_authenticated_baseline_is_not_actual_divergent_candidate(dataset):
    baseline = capture(dataset)
    row = {**observed(baseline), 'descriptor': parse_candidate(dataset.patch_format, '1').descriptor}
    report = project_case(dataset, dataset.rows[0], row)
    assert report['activation']['status'] == 'unknown'
    assert report['activation']['original_hits'] is None
    assert report['candidate']['capture']['status'] == 'invalid'
    assert report['candidate']['outcome'] == 'target_crash'


@pytest.mark.parametrize('kind', ['missing', 'incomplete', 'tampered', 'wrong-artifact', 'repair-branch'])
def test_invalid_neutral_control_cannot_support_pairing_or_mismatch_warning(dataset, kind):
    neutral = capture(dataset, normal=True)
    if kind == 'missing':
        control = {'status': 'not_rejected', 'outcome': {'outcome': 'normal'}}
    else:
        if kind == 'incomplete':
            neutral['complete'] = False
        elif kind == 'tampered':
            neutral['sha256'] = '0' * 64
        elif kind == 'wrong-artifact':
            neutral['artifact_sha256'] = '0' * 64
        else:
            neutral = capture(dataset, branches=(1,), values=(1,), normal=True,
                              descriptor=parse_candidate(dataset.patch_format, '1').descriptor)
        control = observed(neutral, same=False)
    candidate = capture(dataset, normal=True)
    report = project_case(dataset, dataset.rows[0], {**observed(candidate, same=False), 'neutral_baseline': control})
    assert report['neutral_baseline']['compatible_control'] is False
    assert report['transition']['neutral_to_candidate'] is None
    assert report['transition']['neutral_paired'] is False
    assert report['transition']['fired_and_target_to_normal'] is False
    assert report['warnings'] == []


def test_known_outcome_does_not_require_capture(dataset):
    row = {'status': 'not_rejected', 'reason': 'capture-truncated', 'source': 'executed',
           'outcome': {'outcome': 'normal'}}
    report = project_case(dataset, dataset.rows[0], row)
    assert report['candidate']['outcome'] == 'normal'
    assert report['candidate']['capture']['status'] == 'unavailable'
    assert report['activation']['status'] == 'unknown'


def test_original_and_same_artifact_neutral_keep_fixed_oracle_and_mismatch(dataset):
    case = dataset.rows[0]
    original = capture(dataset)['outcome']
    case['observation'] = original
    neutral = capture(dataset)
    neutral['outcome'] = {**neutral['outcome'], 'fault_addr': 44}
    candidate = capture(dataset, branches=(1,), values=(1,), descriptor=parse_candidate(dataset.patch_format, '1').descriptor, normal=True)
    row = {**observed(candidate, same=False), 'neutral_baseline': observed(neutral, same=False)}
    report = project_case(dataset, case, row)
    assert report['oracle']['target']['address'] == '0x21'
    assert report['oracle']['artifact_sha256'] == dataset.manifest['artifacts']['harmless.orig']['sha256']
    assert report['neutral_baseline']['observed_fault']['address'] == '0x2c'
    assert report['original_baseline']['outcome'] == 'target_crash'
    assert report['neutral_baseline']['outcome'] == 'other_crash'
    assert report['candidate']['outcome'] == 'normal'
    assert report['transition']['neutral_to_candidate'] == 'other_crash->normal'
    assert report['transition']['original_to_candidate'] == 'target_crash->normal'
    assert report['transition']['fired_and_target_to_normal'] is False
    assert report['warnings'] == ['control_does_not_reproduce_target']


def test_offline_divergence_is_unknown_not_firing(dataset, tmp_path, monkeypatch):
    dataset.rows[0]['capture'] = capture(dataset)
    monkeypatch.setattr(evaluation, 'execute_capture', lambda *a: pytest.fail('offline execution'))
    result = evaluation.evaluate_dataset(dataset, '1', execute=False, cache_dir=tmp_path / 'cache')
    assert result['evaluation_mode'] == 'offline'
    row = result['cases'][0]
    assert row['offline_branches'] == [1]
    assert row['offline_reference'] == dataset.rows[0]['capture']
    assert row['report']['offline_prediction'] == {
        'branches': [1], 'total_hits': 1, 'truncated': False, 'first_divergence': 0,
        'basis': 'reference_capture_not_candidate_execution'}
    assert row['report']['candidate']['outcome'] == 'unknown'
    assert row['report']['activation']['status'] == 'unknown'
    assert row['report']['neutral_baseline']['outcome'] == 'target_crash'
    assert result['report_summary']['activation']['unknown'] == 1
    stale = {**row, 'offline_reference': {**row['offline_reference'], 'patch_id': 88}}
    assert 'offline_prediction' not in project_case(dataset, dataset.rows[0], stale)


def test_host_collects_and_reuses_neutral_before_divergent_candidate(dataset, tmp_path, monkeypatch):
    calls = []
    def execute(ds, case, descriptor, directory):
        calls.append(descriptor)
        neutral = descriptor == 'p0'
        return capture(ds, branches=(0,) if neutral else (1,), values=(1,), descriptor=descriptor, normal=not neutral)
    monkeypatch.setattr(evaluation, 'execute_capture', execute)
    root = tmp_path / 'cache'
    first = evaluation.evaluate_dataset(dataset, '1', cache_dir=root)
    assert calls == ['p0', parse_candidate(dataset.patch_format, '1').descriptor]
    assert first['evaluation_mode'] == 'host'
    assert first['cases'][0]['neutral_baseline']['capture']['descriptor'] == 'p0'
    assert first['cases'][0]['report']['transition']['fired_and_target_to_normal'] is True
    monkeypatch.setattr(evaluation, 'execute_capture', lambda *a: pytest.fail('cached offline execution'))
    second = evaluation.evaluate_dataset(dataset, '1', execute=False, cache_dir=root)
    assert second['cases'][0]['report']['activation']['status'] == 'fired'
    assert second['cases'][0]['report']['neutral_baseline']['outcome'] == 'target_crash'


def test_function_prepared_neutral_and_replay_other_crash_are_distinct(dataset):
    case = dataset.rows[0]
    case.update(id='function:7', domain='function', capture=capture(dataset, same=True))
    dataset.manifest['oracles']['mutation_reference'] = {'address': 99, 'source': 'main', 'image': 'build-id', 'offset': 9}
    candidate = capture(dataset, branches=(1,), values=(1,), descriptor=parse_candidate(dataset.patch_format, '1').descriptor, same=False)
    candidate['outcome'] = {'outcome': 'other-crash'}
    report = project_case(dataset, case, {**observed(candidate, same=False), 'reuse': 'full-vector-equivalent'})
    assert report['original_baseline']['outcome'] == 'unknown'
    assert report['neutral_baseline']['outcome'] == 'target_crash'
    assert report['candidate']['outcome'] == 'other_crash'
    assert report['candidate']['reuse'] == 'full-vector-equivalent'
    assert report['transition']['neutral_to_candidate'] == 'target_crash->other_crash'
    assert report['oracle'] == oracle_reference(dataset, 'function')
    assert report['mutation']['status'] == 'unavailable'


def test_summary_keeps_domains_unknown_denominators_and_reason_groups(dataset):
    case = dataset.rows[0]
    first = project_case(dataset, case, {'reason': 'branch-divergence'})
    function = {**case, 'id': 'function:7', 'domain': 'function', 'capture': capture(dataset, same=True)}
    second = project_case(dataset, function, {'reason': 'unsupported-external-state'})
    summary = summarize_reports([first, second])
    assert summary['total'] == 2
    assert summary['domains']['system']['total'] == summary['domains']['function']['total'] == 1
    assert summary['activation']['unknown'] == 2
    assert summary['hits_eligible'] == 0
    assert summary['transitions']['neutral_to_candidate'] == {'eligible': 0, 'unpaired': 2, 'not_applicable': 0, 'counts': {}}
    assert summary['outcomes']['original_baseline']['unknown'] == 1
    assert summary['outcomes']['original_baseline']['not_applicable'] == 1
    assert summary['transitions']['original_to_candidate']['not_applicable'] == 1
    assert all('not-applicable' not in reason for reason in summary['unknown_reasons'])
    assert summary['unknown_reasons']['candidate:branch-divergence'] == {'count': 1, 'representative_ids': ['system:0']}
    assert summary['unknown_reasons']['candidate:unsupported-external-state']['representative_ids'] == ['function:7']


def test_private_values_and_untrusted_reasons_are_not_projected(dataset):
    case = dataset.rows[0]
    case['source'] = {'run': '/private/producer', 'filename': 'secret-input'}
    row = {'status': 'not_rejected', 'source': '/private/runner', 'reason': '/private/failure',
           'outcome': {'outcome': 'normal', 'fault_valid': True, 'fault_addr': 5,
                       'fault_source': '/private/source', 'fault_image': '/private/image'},
           'environment': {'TOKEN': 'secret-token'}}
    public = json.dumps(project_case(dataset, case, row))
    assert '/private/' not in public
    assert 'secret-input' not in public
    assert 'secret-token' not in public


def test_missing_oracle_does_not_convert_crash_to_other_crash(dataset):
    dataset.manifest['oracles']['concrete_reference'] = None
    row = {'outcome': capture(dataset)['outcome'], 'status': 'unavailable', 'reason': 'oracle-unavailable'}
    report = project_case(dataset, dataset.rows[0], row)
    assert report['oracle']['target'] is None
    assert report['candidate']['outcome'] == 'unknown'
    assert report['transition']['neutral_paired'] is False


def test_quality_requires_actual_repair_and_matching_target_baselines(dataset):
    case = dataset.rows[0]
    neutral = capture(dataset)
    case['observation'] = neutral['outcome']
    descriptor = parse_candidate(dataset.patch_format, '1').descriptor
    candidate = capture(dataset, branches=(1,), values=(1,), descriptor=descriptor, normal=True)
    row = {**observed(candidate, same=False), 'neutral_baseline': observed(neutral)}
    report = project_case(dataset, case, row)
    assert report['quality']['category'] == 'improved'
    from taosc_llm.evidence import quality_case_sets, summarize_quality
    assert summarize_quality([report])['status'] == 'improved'
    sets = quality_case_sets({'cases': [{'case_id': case['id'], 'report': report}]})
    assert sets['improved'] == {case['id']}
    assert not sets['known_normals']
    # Same normal candidate, but the neutral does not reproduce the original.
    row['neutral_baseline'] = observed(capture(dataset, normal=True), same=False)
    mismatch = project_case(dataset, case, row)
    assert 'baseline_gaps' in mismatch['quality']['facets']
    assert 'improved' not in mismatch['quality']['facets']
    assert summarize_quality([mismatch])['status'] == 'regressed'  # actual normal branch divergence remains visible
    assert 'original-neutral-disagreement' in mismatch['quality']['reasons']
    sets = quality_case_sets({'cases': [{'case_id': case['id'], 'report': mismatch}]})
    assert sets['observed_normals'] == sets['branch_regressions'] == sets['baseline_gaps'] == {case['id']}
    assert not sets['known_normals'] and not sets['improved']


@pytest.mark.parametrize(('neutral_branches', 'candidate_branches', 'values', 'difference'), [
    ((0, 0, 0), (0, 1), (0, 1), (1, 0, 1, 3, 2)),
    ((0, 0), (0,), (0,), (1, 0, None, 2, 1)),
    ((0,), (0, 1), (0, 1), (1, None, 1, 1, 2)),
])
def test_normal_complete_vector_differences_have_exact_counterexamples(
        dataset, neutral_branches, candidate_branches, values, difference):
    case = dataset.rows[0]
    neutral = capture(dataset, branches=neutral_branches, values=(0,) * len(neutral_branches), normal=True)
    case['observation'] = neutral['outcome']
    candidate = capture(dataset, branches=candidate_branches, values=values, normal=True,
                        descriptor=parse_candidate(dataset.patch_format, 'rax != 0').descriptor)
    report = project_case(dataset, case, {**observed(candidate, same=False),
                                         'neutral_baseline': observed(neutral, same=False)})
    quality = report['quality']
    assert quality['category'] == 'branch_regression'
    assert quality['known_normal'] is quality['observed_normal'] is True
    assert quality['branch_difference'] == dict(zip(
        ('first_difference', 'neutral_branch', 'candidate_branch', 'neutral_hits', 'candidate_hits'), difference),
        basis='actual_complete_vectors')
    from taosc_llm.evidence import quality_case_sets, summarize_quality
    assert summarize_quality([report])['status'] == 'regressed'
    sets = quality_case_sets({'cases': [{'case_id': case['id'], 'report': report}]})
    assert sets['branch_regressions'] == sets['known_normals'] == sets['observed_normals'] == {case['id']}


@pytest.mark.parametrize('kind', ['predicted', 'partial', 'invalid', 'wrong-artifact',
                                  'unmatched-control', 'wrong-case', 'wrong-domain', 'wrong-control-case'])
def test_inference_or_incompatible_capture_never_establishes_branch_regression(dataset, kind):
    case = dataset.rows[0]
    neutral = capture(dataset, normal=True)
    case['observation'] = neutral['outcome']
    descriptor = parse_candidate(dataset.patch_format, '1').descriptor
    candidate = capture(dataset, branches=(1,), values=(1,), descriptor=descriptor, normal=True)
    row = {**observed(candidate, same=False), 'neutral_baseline': observed(neutral, same=False)}
    if kind == 'predicted':
        row.update(capture=None, offline_reference=neutral, offline_branches=[1], first_divergence=0)
    elif kind == 'partial':
        candidate['complete'] = False
    elif kind == 'invalid':
        candidate['sha256'] = '0' * 64
    elif kind == 'wrong-artifact':
        candidate['artifact_sha256'] = '0' * 64
    elif kind == 'wrong-case':
        row['case_id'] = 'system:99'
    elif kind == 'wrong-domain':
        row['domain'] = 'function'
    elif kind == 'wrong-control-case':
        row['neutral_baseline']['case_id'] = 'system:99'
    else:
        neutral['artifact_sha256'] = '0' * 64
    report = project_case(dataset, case, row)
    assert 'branch_regressions' not in report['quality']['facets']
    assert 'improved' not in report['quality']['facets']
    assert report['branch_comparison']['status'] == 'unavailable'


@pytest.mark.parametrize(('neutral_normal', 'candidate_kind', 'predicate', 'category', 'facets'), [
    (False, 'normal', '0', 'unproven', {'unproven'}),
    (False, 'normal', 'rax / 0', 'unproven', {'unproven'}),
    (False, 'other', '1', 'other_crash', {'other_crashes'}),
    (False, 'target', '1', 'target_miss', {'target_misses'}),
    (True, 'other', '1', 'crash_regression', {'crash_regressions', 'other_crashes'}),
    (True, 'target', '1', 'crash_regression', {'crash_regressions'}),
    (True, 'normal', '0', 'preserved_normal', {'preserved_normal'}),
])
def test_quality_separates_target_misses_other_faults_traps_and_unproven_normals(
        dataset, neutral_normal, candidate_kind, predicate, category, facets):
    case = dataset.rows[0]
    neutral = capture(dataset, normal=neutral_normal)
    case['observation'] = neutral['outcome']
    descriptor = parse_candidate(dataset.patch_format, predicate).descriptor
    branch = 2 if '/' in predicate else 0 if predicate == '0' else 1
    candidate = capture(dataset, values=(1,), branches=(branch,), descriptor=descriptor,
                        normal=candidate_kind == 'normal')
    if candidate_kind == 'other':
        candidate['outcome']['fault_addr'] = 44
    report = project_case(dataset, case, {**observed(candidate, same=candidate_kind == 'target'),
                                         'neutral_baseline': observed(neutral, same=not neutral_normal)})
    assert report['quality']['category'] == category
    assert set(report['quality']['facets']) == facets


def test_all_baseline_gaps_and_all_preserved_normals_are_not_repair_success(dataset):
    from taosc_llm.evidence import summarize_quality
    case = dataset.rows[0]
    neutral = capture(dataset, normal=True)
    descriptor = parse_candidate(dataset.patch_format, '0').descriptor
    candidate = capture(dataset, normal=True, descriptor=descriptor)
    row = {**observed(candidate, same=False), 'neutral_baseline': observed(neutral, same=False)}
    case['observation'] = capture(dataset)['outcome']
    mismatch = project_case(dataset, case, row)
    quality = summarize_quality([mismatch])
    assert quality['status'] == 'incomplete'
    assert quality['counts']['baseline_gaps'] == 1
    assert quality['counts']['improved'] == 0
    case['observation'] = neutral['outcome']
    preserved = project_case(dataset, case, row)
    assert summarize_quality([preserved])['status'] == 'unproven'
    assert summarize_quality([])['status'] == 'incomplete'


def test_mutation_write_provenance_is_ordered_authenticated_and_not_state(dataset, tmp_path):
    committed = capture(dataset, same=True)
    case = {**dataset.rows[0], 'id': 'function:7', 'domain': 'function', 'capture': committed}
    sidecar = tmp_path / 'mutation.sbsv'
    sidecar.write_text(
        '[binradar-feedback] [version 3] [iteration 7] [patch 0] [snapshot-file private.brch] '
        '[snapshot-count 1] [branches 0] [outcome crash] [fault-addr 21] [fault-valid true] '
        '[fault-source main] [poc-fault-addr 21] [poc-fault-valid true] [poc-fault-source main] '
        '[same-fault true] [result malicious] [mutation-writes 2] '
        '[fault-image none] [fault-image-offset 0] [poc-fault-image none] [poc-fault-image-offset 0]\n'
        '[binradar-mutation] [index 0] [kind bytes] [addr dead] [size 8] '
        '[value ffffffffffffffff] [target-extent 8]\n'
        '[binradar-mutation] [index 1] [kind pointer-fresh] [addr beef] [size 8] '
        '[value dynamic] [target-extent 32]\n')
    committed['sidecar'] = {'path': 'mutation.sbsv', 'sha256': sha256(sidecar)}
    def verify(record):
        path = dataset.root / record['path']
        if sha256(path) != record['sha256']:
            raise ValueError('sidecar-hash-mismatch')
        return path
    dataset._verify = verify
    report = project_case(dataset, case)
    assert report['mutation'] == {'status': 'available', 'complete_state': False,
                                  'total_writes': 2, 'truncated': False, 'writes': [
        {'kind': 'bytes', 'size': 8, 'value': 'ffffffffffffffff', 'target_extent': 8},
        {'kind': 'pointer-fresh', 'size': 8, 'value': 'dynamic', 'target_extent': 32}]}
    assert 'dead' not in json.dumps(report['mutation'])
    header = sidecar.read_text().splitlines()[0].replace('[mutation-writes 2]', '[mutation-writes 33]')
    writes = []
    for index in range(33):
        size = 600 if index == 0 else 1
        writes.append(f'[binradar-mutation] [index {index}] [kind bytes] [addr dead] '
                      f'[size {size}] [value {"ff" * size}] [target-extent {size}]\n')
    sidecar.write_text(header + '\n' + ''.join(writes))
    committed['sidecar']['sha256'] = sha256(sidecar)
    bounded = project_case(dataset, case)['mutation']
    assert bounded['total_writes'] == 33 and bounded['truncated'] is True
    assert len(bounded['writes']) == 32
    assert bounded['writes'][0]['value'] is None
    assert len(bounded['writes'][0]['value_prefix']) == 1024
    full = mutation_provenance(dataset, case)
    assert len(full['writes']) == 33
    assert full['writes'][0]['value'] == 'ff' * 600
    sidecar.write_text('replaced authenticated sidecar')
    assert project_case(dataset, case)['mutation']['status'] == 'unavailable'
