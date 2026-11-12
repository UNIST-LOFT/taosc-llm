"""Consumer-visible evidence boundaries, not wording snapshots."""
import json

import pytest

from taosc_llm import evaluation
from taosc_llm.cases import case_records
from taosc_llm.evidence import project_case
from taosc_llm.family import parse_candidate
from taosc_llm.presentation import compact_case, feedback, poc_example, sample_cases
from test_evaluation import Dataset, capture


@pytest.fixture
def dataset(tmp_path, monkeypatch):
    monkeypatch.setattr(evaluation, 'execution_identity', lambda: {'qemu': 'fixture', 'oracle': 'qasan-main-v2'})
    return Dataset(tmp_path)


def report(number, *, domain='system', candidate='target_crash', neutral='target_crash',
           original='target_crash', compatible=True, applicable=True, activity='not_fired', writes=()):
    return {'case_id': f'{domain}:{number}', 'domain': domain,
            'original_baseline': {'outcome': original, 'applicable': applicable},
            'neutral_baseline': {'outcome': neutral, 'compatible_control': compatible,
                                 'artifact_sha256': 'a' * 64, 'capture': {'status': 'complete'}},
            'candidate': {'outcome': candidate, 'artifact_sha256': 'a' * 64,
                          'capture': {'status': 'complete' if activity != 'unknown' else 'unavailable'},
                          'observed_fault': {'address': '0xbad', 'image': 'b' * 64}},
            'activation': {'status': activity, 'original_hits': None, 'repair_hits': None, 'trap_hits': None},
            'oracle': {'oracle_id': 'private-oracle', 'artifact_sha256': 'c' * 64,
                       'evaluation_artifact_sha256': 'a' * 64, 'target': {'address': '0x21'}},
            'branch_comparison': {'status': 'equal', 'basis': 'actual_complete_vectors',
                                  'neutral_hits': 1, 'candidate_hits': 1},
            'warnings': [],
            'mutation': {'status': 'available' if writes else 'unavailable', 'writes': list(writes)}}


def evaluation_for(dataset, reports):
    template = dataset.rows[0]
    dataset.rows = [{**template, 'id': row['case_id'], 'domain': row['domain']} for row in reports]
    return {'predicate': 'rax != 0', 'cases': [
        {'case_id': row['case_id'], 'report': row, 'source': '/private/source',
         'status': 'reject_same_crash', 'capture_id': 'd' * 64} for row in reports]}


def test_examples_bound_each_population_and_choose_domain_mutation_diversity(dataset):
    writes = [{'kind': 'bytes', 'size': 1, 'value': 'ff', 'target_extent': 1}]
    reports = [report(i, candidate=outcome, neutral=outcome) for outcome, start in
               (('target_crash', 0), ('normal', 20)) for i in range(start, start + 8)]
    reports += [report(100, domain='function', writes=writes),
                report(101, domain='function', candidate='normal', neutral='normal', writes=writes)]
    records = case_records(dataset, evaluation_for(dataset, reports))
    examples = sample_cases(dataset, records)
    assert len(examples['crash']) == len(examples['non_crash']) == 3
    assert any(row['case_id'].startswith('function:') for row in examples['crash'])
    assert any(row['case_id'].startswith('function:') for row in examples['non_crash'])
    assert sample_cases(dataset, list(reversed(records))) == examples
    assert all(row['basis'] == 'candidate' for group in examples.values() for row in group)
    public = json.dumps(examples)
    assert '/private/' not in public
    assert all(char * 64 not in public for char in 'abcd')
    assert 'oracle' not in public
    assert 'cursor' not in examples and 'total' not in examples


@pytest.mark.parametrize('candidate', ['other_crash', 'unknown'])
def test_initial_samples_never_fall_back_to_good_old_baselines(dataset, candidate):
    records = case_records(dataset, evaluation_for(dataset, [report(0, candidate=candidate)]))
    assert sample_cases(dataset, records) == {'crash': [], 'non_crash': []}


@pytest.mark.parametrize('neutral', ['other_crash', 'unknown'])
def test_only_ignored_or_unknown_prepared_cases_do_not_become_examples(dataset, neutral):
    row = report(0, candidate='unknown', neutral=neutral, original='unknown', compatible=False)
    record = {'case': dataset.rows[0], 'evaluated': None, 'report': row}
    assert sample_cases(dataset, [record]) == {'crash': [], 'non_crash': []}


def test_prepared_original_fallback_is_explicit_not_candidate_or_neutral_state(dataset):
    row = report(0, neutral='unknown', compatible=False)
    record = {'case': dataset.rows[0], 'evaluated': None, 'report': row}
    example = sample_cases(dataset, [record])['crash'][0]
    assert example['basis'] == 'original_baseline'
    assert example['outcome'] == 'target_crash'
    assert 'registers' not in example
    assert 'activation' not in example


def test_feedback_counts_actual_targets_and_separates_strict_diagnostics(dataset):
    reports = [report(i) for i in range(8)]
    reports += [report(i, neutral='normal') for i in range(20, 25)]
    # Missing controls do not erase actual designated target outcomes.
    reports += [report(40, original='normal', neutral='unknown', compatible=False),
                report(41, domain='function', original='normal', neutral='unknown',
                       applicable=False, compatible=False)]
    reports += [report(60, neutral='normal', candidate='other_crash'),
                report(61, candidate='normal'), report(62, candidate='unknown')]
    response = feedback(dataset, evaluation_for(dataset, reports))
    objective = response['objective']
    assert objective == {
        'target_status': 'target_present', 'candidate_known': 17, 'candidate_unknown': 1,
        'candidate_target_crashes': 15, 'branch_comparable': 0, 'branch_regressions': 0,
        'domains': {
            'system': {'target_status': 'target_present', 'candidate_known': 16, 'candidate_unknown': 1,
                       'candidate_target_crashes': 14, 'branch_comparable': 0, 'branch_regressions': 0},
            'function': {'target_status': 'target_present', 'candidate_known': 1, 'candidate_unknown': 0,
                         'candidate_target_crashes': 1, 'branch_comparable': 0, 'branch_regressions': 0},
        },
    }
    assert response['missed_target_crashes']['count'] == 15
    assert len(response['missed_target_crashes']['examples']) == 3
    assert all(row['outcome'] == 'target_crash' and 'category' not in row
               for row in response['missed_target_crashes']['examples'])
    diagnostics = response['diagnostics']
    quality = diagnostics['quality']
    assert quality['status'] == 'rejected'
    assert quality['counts']['crash_regressions'] == 6
    assert quality['counts']['other_crashes'] == 1
    other = diagnostics['examples']['other_crashes'][0]
    assert (other['case_id'], other['outcome'], other['category']) == ('system:60', 'other_crash', 'crash_regression')
    assert quality['counts']['unavailable'] == 1
    assert quality['counts']['unproven'] == 1
    assert isinstance(diagnostics['warning'], str)
    assert all(len(examples) <= 3 for examples in diagnostics['examples'].values())
    public = json.dumps(response)
    assert '0xbad' not in public and '/private/' not in public and 'private-oracle' not in public
    assert all(char * 64 not in public for char in 'abcd')
    assert not any(key in response for key in ('quality', 'regressions', 'warning', 'outcomes', 'report_summary'))


def test_feedback_exposes_bounded_authenticated_branch_witnesses_and_gap_counts(dataset):
    reports = [report(i, neutral='normal', original='normal', candidate='normal', activity='fired')
               for i in range(8)]
    difference = {'status': 'different', 'basis': 'actual_complete_vectors', 'neutral_hits': 2,
                  'candidate_hits': 1, 'first_difference': 1, 'neutral_branch': 0, 'candidate_branch': None}
    for row in reports:
        row['branch_comparison'] = difference
    reports += [report(20, candidate='normal', activity='fired', compatible=False),
                report(21, candidate='unknown', activity='unknown')]
    response = feedback(dataset, evaluation_for(dataset, reports))
    assert response['objective']['target_status'] == 'target_absent'
    assert response['objective']['candidate_known'] == 9
    assert response['objective']['candidate_unknown'] == 1
    assert response['objective']['branch_comparable'] == response['objective']['branch_regressions'] == 8
    assert response['branch_regressions']['count'] == 8
    assert len(response['branch_regressions']['examples']) == 3
    for example in response['branch_regressions']['examples']:
        assert 'category' not in example
        assert example['outcome'] == example['neutral_baseline'] == 'normal'
        assert example['branch_difference'] == {key: value for key, value in difference.items() if key != 'status'}
    diagnostics = response['diagnostics']
    assert diagnostics['quality']['status'] == 'incomplete'
    assert diagnostics['quality']['counts']['baseline_gaps'] == 1
    assert diagnostics['quality']['counts']['unavailable'] == 1
    assert diagnostics['quality']['counts']['improved'] == 0
    assert all(len(examples) <= 3 for examples in diagnostics['examples'].values())


@pytest.mark.parametrize(('candidate', 'status', 'known', 'unknown', 'targets'), [
    ('normal', 'target_absent', 1, 0, 0),
    ('other_crash', 'target_absent', 1, 0, 0),
    ('target_crash', 'target_present', 1, 0, 1),
    ('unknown', 'not_observed', 0, 1, 0),
])
def test_objective_uses_actual_outcomes_not_legacy_quality(dataset, candidate, status, known, unknown, targets):
    row = report(0, candidate=candidate, compatible=False, activity='unknown')
    # A saved strict verdict/facet is not the objective, in either direction.
    row['quality'] = {'category': 'improved', 'facets': ['improved'], 'reasons': [],
                      'known_normal': False, 'observed_normal': True}
    response = feedback(dataset, evaluation_for(dataset, [row]))
    objective = response['objective']
    assert objective['target_status'] == status
    assert objective['candidate_known'] == known
    assert objective['candidate_unknown'] == unknown
    assert objective['candidate_target_crashes'] == targets
    assert response['missed_target_crashes']['count'] == targets
    assert response['branch_regressions'] == {'count': 0, 'examples': []}
    assert 'status' not in response and 'quality' not in response


def test_target_free_other_crashes_are_diagnostic_not_rejection(dataset):
    response = feedback(dataset, evaluation_for(dataset, [report(0, candidate='other_crash')]))
    assert response['objective']['target_status'] == 'target_absent'
    assert response['objective']['candidate_known'] == 1
    assert response['objective']['candidate_target_crashes'] == 0
    assert response['diagnostics']['quality']['status'] == 'rejected'
    assert response['diagnostics']['quality']['counts']['other_crashes'] == 1
    assert response['diagnostics']['examples']['other_crashes'][0]['outcome'] == 'other_crash'
    assert 'rejected' not in json.dumps(response['objective'])


@pytest.mark.parametrize('limitation', ['artifact', 'control', 'capture', 'activity', 'prediction', 'other_crash'])
def test_branch_counterexamples_require_authenticated_actual_normal_comparison(dataset, limitation):
    row = report(0, neutral='normal', original='normal', candidate='normal', activity='fired')
    row['branch_comparison'] = {
        'status': 'different', 'basis': 'actual_complete_vectors', 'first_difference': 0,
        'neutral_branch': 0, 'candidate_branch': 1, 'neutral_hits': 1, 'candidate_hits': 1}
    if limitation == 'artifact':
        row['candidate']['artifact_sha256'] = 'b' * 64
    elif limitation == 'control':
        row['neutral_baseline']['compatible_control'] = False
    elif limitation == 'capture':
        row['candidate']['capture']['status'] = 'incomplete'
    elif limitation == 'activity':
        row['activation']['status'] = 'trapped'
    elif limitation == 'prediction':
        row['branch_comparison']['basis'] = 'offline_prediction'
    else:
        row['candidate']['outcome'] = 'other_crash'
    row['quality'] = {'category': 'branch_regression', 'facets': ['branch_regressions'], 'reasons': [],
                      'known_normal': True, 'observed_normal': True}
    response = feedback(dataset, evaluation_for(dataset, [row]))
    assert response['objective']['branch_comparable'] == response['objective']['branch_regressions'] == 0
    assert response['branch_regressions'] == {'count': 0, 'examples': []}


def test_branch_witnesses_do_not_depend_on_legacy_quality_facets(dataset):
    row = report(0, neutral='normal', original='normal', candidate='normal', activity='fired')
    row['branch_comparison'] = {
        'status': 'different', 'basis': 'actual_complete_vectors', 'first_difference': 0,
        'neutral_branch': 0, 'candidate_branch': 1, 'neutral_hits': 1, 'candidate_hits': 1,
        'private_path': '/private/branch', 'artifact_sha256': 'b' * 64}
    row['quality'] = {'category': 'preserved_normal', 'facets': ['preserved_normal'], 'reasons': [],
                      'known_normal': True, 'observed_normal': True}
    response = feedback(dataset, evaluation_for(dataset, [row]))
    assert response['objective']['branch_regressions'] == response['branch_regressions']['count'] == 1
    witness = response['branch_regressions']['examples'][0]['branch_difference']
    assert witness['first_difference'] == 0 and witness['candidate_branch'] == 1
    assert 'private_path' not in witness and 'artifact_sha256' not in witness


def test_empty_inventory_does_not_establish_target_removal(dataset):
    response = feedback(dataset, evaluation_for(dataset, []))
    assert response['objective']['target_status'] == 'not_observed'
    assert response['objective']['candidate_known'] == response['objective']['candidate_unknown'] == 0
    assert response['missed_target_crashes'] == response['branch_regressions'] == {'count': 0, 'examples': []}


def test_normal_unknown_activity_and_nonreproducing_control_have_diagnostic_warning(dataset):
    row = report(0, candidate='normal', neutral='normal', activity='unknown')
    row['warnings'] = ['control_does_not_reproduce_target']
    response = feedback(dataset, evaluation_for(dataset, [row]))
    assert response['missed_target_crashes']['count'] == response['branch_regressions']['count'] == 0
    assert response['objective']['target_status'] == 'target_absent'
    assert response['objective']['branch_comparable'] == 0
    diagnostics = response['diagnostics']
    assert diagnostics['quality']['status'] == 'incomplete'
    assert diagnostics['quality']['counts']['unavailable'] == 1
    assert diagnostics['quality']['counts']['baseline_gaps'] == 1
    assert diagnostics['quality']['counts']['improved'] == 0
    assert isinstance(diagnostics['warning'], str)
    assert not any(key in response for key in ('repaired', 'success', 'verified', 'activation', 'warning'))


def test_function_original_not_applicable_is_not_a_coverage_gap(dataset):
    row = report(0, domain='function', original='unknown', applicable=False,
                 candidate='normal', activity='fired')
    response = feedback(dataset, evaluation_for(dataset, [row]))
    assert 'warning' not in response['diagnostics']
    assert response['objective']['domains']['function']['target_status'] == 'target_absent'
    assert response['objective']['domains']['system']['target_status'] == 'not_observed'
    assert response['missed_target_crashes']['count'] == response['branch_regressions']['count'] == 0


def test_explicit_detail_is_allowlisted_and_does_not_invent_activity(dataset):
    writes = [{'kind': 'bytes', 'size': 8, 'value': 'ffffffffffffffff', 'target_extent': 8}]
    row = report(0, candidate='unknown', neutral='other_crash', activity='unknown', writes=writes)
    row['private_path'] = '/private/secret'
    row['offline_prediction'] = {'branches': [1], 'basis': 'not_actual_candidate'}
    result = compact_case(dataset, row, predicate='rax < 0')
    assert result['original_baseline'] == 'target_crash'
    assert result['mutation']['writes'] == writes
    assert result['mutation']['basis'] == 'ordered_input_writes_not_full_state'
    assert result['neutral_baseline'] == 'other_crash'
    assert result['quality']['category'] == 'unavailable'
    assert set(result) == {'case_id', 'original_baseline', 'neutral_baseline', 'quality', 'mutation'}
    assert 'ffffffffffffffff' in json.dumps(result)  # Real bytes are not provenance digests.


def test_authenticated_candidate_registers_do_not_use_prepared_state(dataset):
    case = dataset.rows[0]
    case['capture'] = capture(dataset, values=(0,), branches=(0,))
    descriptor = parse_candidate(dataset.patch_format, 'rax != 0').descriptor
    candidate = capture(dataset, values=(7,), branches=(1,), descriptor=descriptor, normal=True)
    evaluated = {'case_id': case['id'], 'descriptor': descriptor, 'capture': candidate,
                 'outcome': candidate['outcome'], 'status': 'not_rejected'}
    evaluated['report'] = project_case(dataset, case, evaluated)
    records = case_records(dataset, {'predicate': 'rax != 0', 'cases': [evaluated]})
    example = sample_cases(dataset, records, predicate='rax != 0')['non_crash'][0]
    assert example['activation'] == 'fired'
    assert example['registers']['basis'] == 'candidate_capture'
    assert example['registers']['hits'][0]['registers'] == {'rax': '7'}
    # A complete representative that is not candidate-equivalent supplies no
    # actual candidate state, even when a separate normal outcome is known.
    evaluated['descriptor'] = parse_candidate(dataset.patch_format, 'rax == 0').descriptor
    evaluated['report'] = project_case(dataset, case, evaluated)
    records = case_records(dataset, {'cases': [evaluated]})
    example = sample_cases(dataset, records, predicate='rax != 0')['non_crash'][0]
    assert 'registers' not in example and 'activation' not in example


def test_prepared_registers_have_neutral_not_original_basis(dataset):
    case = dataset.rows[0]
    case['capture'] = capture(dataset, values=(-1 & ((1 << 64) - 1),), branches=(0,))
    example = sample_cases(dataset, case_records(dataset), predicate='rax < 0')['crash'][0]
    assert example['basis'] == 'neutral_baseline'
    assert example['registers']['basis'] == 'neutral_capture'
    assert example['registers']['hits'][0]['registers'] == {'rax': '-1'}


def test_poc_keeps_actual_original_and_neutral_register_meanings_distinct(dataset):
    committed = capture(dataset, values=(13,), branches=(0,), normal=True)
    original = capture(dataset)['outcome']
    private = {'subject': {'program': 'harmless', 'args': ['@@'], 'input_bytes': 5,
                           'private_path': '/private/program'},
               'case': dataset.rows[0], 'matching_case_ids': ['system:0'],
               'original': {'basis': 'original-artifact', 'source': 'recorded', 'outcome': original},
               'neutral': {'capture': committed, 'outcome': committed['outcome'],
                           'descriptor': 'p0', 'status': 'not_rejected'}}
    example = poc_example(dataset, private)
    assert example['subject'] == {'program': 'harmless', 'args': ['@@'], 'input_bytes': 5}
    assert example['original_baseline'] == 'target_crash'
    assert example['neutral_baseline'] == 'normal'
    assert 'warning' in example
    target = capture(dataset, values=(13,), branches=(0,))
    matched = poc_example(dataset, {**private, 'neutral': {'capture': target,
        'outcome': target['outcome'], 'descriptor': 'p0', 'status': 'reject_same_crash'}})
    assert 'warning' not in matched
    assert 'candidate' not in example
    assert example['registers']['basis'] == 'neutral_capture'
    assert example['registers']['hits'][0]['registers']['rax'] == '13'
    public = json.dumps(example)
    assert '/private/' not in public and 'sha256' not in public and 'source' not in public
    private['original']['outcome'] = None
    missing = poc_example(dataset, private)
    assert 'original_baseline' not in missing
    assert isinstance(missing['warning'], str)
    assert missing['neutral_baseline'] == 'normal'
