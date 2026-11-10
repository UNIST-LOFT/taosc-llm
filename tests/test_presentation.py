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


def test_feedback_counts_full_population_and_partitions_same_artifact_regressions(dataset):
    reports = [report(i) for i in range(8)]
    reports += [report(i, neutral='normal') for i in range(20, 25)]
    # An original normal is not a compatible neutral normal, in either domain.
    reports += [report(40, original='normal', neutral='unknown', compatible=False),
                report(41, domain='function', original='normal', neutral='unknown',
                       applicable=False, compatible=False)]
    reports += [report(60, neutral='normal', candidate='other_crash'),
                report(61, candidate='normal'), report(62, candidate='unknown')]
    response = feedback(dataset, evaluation_for(dataset, reports))
    assert response['missed_target_crashes']['count'] == 10
    assert response['regressions']['count'] == 6
    assert len(response['missed_target_crashes']['examples']) == 3
    assert len(response['regressions']['examples']) == 3
    assert all(row['neutral_baseline'] == 'normal' for row in response['regressions']['examples'])
    quality = response['quality']
    assert quality['status'] == 'regressed'
    assert quality['counts']['other_crashes'] == 1
    other = quality['examples']['other_crashes'][0]
    assert (other['case_id'], other['outcome'], other['category']) == ('system:60', 'other_crash', 'crash_regression')
    assert quality['counts']['unavailable'] == 1
    assert quality['counts']['unproven'] == 1
    assert isinstance(response['warning'], str)
    public = json.dumps(response)
    assert '0xbad' not in public and '/private/' not in public
    assert all(char * 64 not in public for char in 'abcd')
    assert 'outcomes' not in response and 'report_summary' not in response


def test_feedback_exposes_bounded_exact_branch_counterexamples_and_gap_counts(dataset):
    reports = [report(i, neutral='normal', original='normal', candidate='normal', activity='fired')
               for i in range(8)]
    difference = {'status': 'different', 'basis': 'actual_complete_vectors', 'neutral_hits': 2,
                  'candidate_hits': 1, 'first_difference': 1, 'neutral_branch': 0, 'candidate_branch': None}
    for row in reports:
        row['branch_comparison'] = difference
    reports += [report(20, candidate='normal', activity='fired', compatible=False),
                report(21, candidate='unknown', activity='unknown')]
    response = feedback(dataset, evaluation_for(dataset, reports))
    assert response['quality']['status'] == 'regressed'
    assert response['branch_regressions']['count'] == 8
    assert len(response['branch_regressions']['examples']) == 3
    for example in response['branch_regressions']['examples']:
        assert example['category'] == 'branch_regression'
        assert example['outcome'] == example['neutral_baseline'] == 'normal'
        assert example['branch_difference'] == {key: value for key, value in difference.items() if key != 'status'}
    assert response['quality']['counts']['baseline_gaps'] == 1
    assert response['quality']['counts']['unavailable'] == 1
    assert response['quality']['counts']['improved'] == 0
    assert all(len(examples) <= 3 for examples in response['quality']['examples'].values())


def test_normal_unknown_activity_and_nonreproducing_control_have_one_warning(dataset):
    row = report(0, candidate='normal', neutral='normal', activity='unknown')
    row['warnings'] = ['control_does_not_reproduce_target']
    response = feedback(dataset, evaluation_for(dataset, [row]))
    assert response['missed_target_crashes']['count'] == response['regressions']['count'] == 0
    assert response['branch_regressions']['count'] == 0
    assert response['quality']['status'] == 'incomplete'
    assert response['quality']['counts']['unavailable'] == 1
    assert response['quality']['counts']['baseline_gaps'] == 1
    assert response['quality']['counts']['improved'] == 0
    assert isinstance(response['warning'], str)
    assert not any(key in response for key in ('repaired', 'success', 'verified', 'activation'))


def test_function_original_not_applicable_is_not_a_coverage_gap(dataset):
    row = report(0, domain='function', original='unknown', applicable=False,
                 candidate='normal', activity='fired')
    response = feedback(dataset, evaluation_for(dataset, [row]))
    assert 'warning' not in response
    assert response['missed_target_crashes']['count'] == response['regressions']['count'] == 0


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
