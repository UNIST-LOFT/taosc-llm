"""Collector semantics are independent of the producer's stricter quality gate."""
from copy import deepcopy

import pytest

from taosc_llm.collection_metrics import collect_metrics


ARTIFACT = 'a' * 64


def case(number=0, *, domain='system', original='target_crash', neutral='target_crash',
         outcome='normal', comparison='different'):
    case_id = f'{domain}:{number}'
    def observation(value):
        return {'outcome': value, 'artifact_sha256': ARTIFACT,
                'capture': {'status': 'complete', 'total_hits': 1}, 'applicable': True}
    report = {
        'case_id': case_id, 'domain': domain,
        'oracle': {'target': {'address': '0x123'}, 'evaluation_artifact_sha256': ARTIFACT},
        'original_baseline': {**observation(original), 'applicable': domain == 'system'},
        'neutral_baseline': {**observation(neutral), 'compatible_control': True},
        'candidate': observation(outcome),
        'activation': {'status': 'fired'},
        'branch_comparison': {'status': comparison, 'basis': 'actual_complete_vectors'},
        # These saved producer fields are not the collector's target objective.
        'quality': {'category': 'other_crash', 'facets': ['other_crashes']},
    }
    return {'case_id': case_id, 'domain': domain, 'report': report}


def metrics(*cases):
    return collect_metrics({'cases': list(cases), 'quality': {'status': 'rejected'},
                            'status': 'reject_same_crash'}, candidate_present=True)


@pytest.mark.parametrize('outcome', ['normal', 'other_crash'])
def test_target_to_normal_or_other_is_target_fixed_despite_legacy_rejection(outcome):
    result = metrics(case(outcome=outcome))
    assert result['target_status'] == 'target_absent'
    assert result['target_baselines'] == result['target_fixed'] == result['candidate_known'] == 1
    assert result['target_remaining'] == result['target_unobserved'] == 0
    assert result['candidate_other_crashes'] == (outcome == 'other_crash')
    assert result['branch_comparable'] == result['branch_regressions'] == 0


def test_preexisting_other_and_new_other_are_informational_only():
    result = metrics(case(0, original='other_crash', neutral='other_crash', outcome='other_crash'),
                     case(1, original='normal', neutral='normal', outcome='other_crash'))
    assert result['target_status'] == 'target_absent'
    assert result['candidate_other_crashes'] == 2
    assert result['target_baselines'] == result['new_target_failures'] == 0
    assert result['branch_regressions'] == result['branch_comparable'] == 0


@pytest.mark.parametrize('capture_status', ['unavailable', 'incomplete', 'invalid'])
@pytest.mark.parametrize('outcome', ['normal', 'other_crash', 'target_crash'])
def test_partial_capture_and_baseline_gap_cannot_erase_known_outcomes(capture_status, outcome):
    row = case(outcome=outcome)
    report = row['report']
    report['candidate']['capture']['status'] = capture_status
    report['activation']['status'] = 'unknown'
    report['neutral_baseline']['compatible_control'] = False
    report['neutral_baseline']['outcome'] = 'unknown'
    report['quality'] = {'category': 'unavailable', 'facets': ['unavailable', 'baseline_gaps']}
    result = metrics(row)
    assert result['target_status'] == ('target_present' if outcome == 'target_crash' else 'target_absent')
    assert result['candidate_known'] == result['candidate_capture_incomplete'] == result['baseline_gaps'] == 1
    assert result['candidate_unknown'] == 0
    assert result['target_baselines'] == 1
    assert result['target_fixed'] == (outcome != 'target_crash')
    assert result['target_remaining'] == (outcome == 'target_crash')


def test_residual_target_dominates_normal_other_and_unknown_cases():
    result = metrics(case(0), case(1, outcome='other_crash'), case(2, outcome='unknown'),
                     case(3, outcome='target_crash'))
    assert result['target_status'] == 'target_present'
    assert result['candidate_total'] == result['target_baselines'] == 4
    assert result['candidate_known'] == 3
    assert result['candidate_unknown'] == 1
    assert result['target_fixed'] == 2
    assert result['target_remaining'] == result['target_unobserved'] == 1


@pytest.mark.parametrize('candidate_present', [True, False])
def test_missing_evaluation_is_null_not_an_empty_population(candidate_present):
    result = collect_metrics(None, candidate_present=candidate_present)
    for field, value in result.items():
        if field.endswith('target_status'):
            assert value == ('not_observed' if candidate_present else 'no_candidate')
        else:
            assert value is None


@pytest.mark.parametrize('candidate_present', [True, False])
def test_empty_evaluation_has_zero_counters_but_is_not_target_absent(candidate_present):
    result = collect_metrics({'cases': []}, candidate_present=candidate_present)
    for field, value in result.items():
        assert value == (('not_observed' if candidate_present else 'no_candidate')
                         if field.endswith('target_status') else 0)


def test_all_unknown_and_missing_reports_never_inherit_raw_outcomes_or_summary():
    missing = {'case_id': 'system:1', 'domain': 'system', 'status': 'not_rejected',
               'outcome': {'outcome': 'normal'}, 'capture': {'complete': True}}
    explicit_null = {'case_id': 'function:2', 'domain': 'function', 'report': None}
    result = metrics(case(0, outcome='unknown'), missing, explicit_null)
    assert result['target_status'] == 'not_observed'
    assert result['candidate_total'] == result['candidate_unknown'] == 3
    assert result['candidate_known'] == result['target_fixed'] == 0
    assert result['target_unobserved'] == 1
    assert result['candidate_capture_incomplete'] == 2
    assert result['baseline_gaps'] == 2


def test_domains_use_original_or_inapplicable_original_neutral_without_fallback():
    system = case(0, original='target_crash', neutral='normal', outcome='other_crash')
    unknown_original = case(1, original='unknown', neutral='target_crash')
    function = case(0, domain='function', original='normal', neutral='target_crash')
    result = metrics(system, unknown_original, function)
    assert result['target_baselines'] == result['target_fixed'] == 2
    assert result['system_target_baselines'] == result['system_target_fixed'] == 1
    assert result['function_target_baselines'] == result['function_target_fixed'] == 1
    assert result['original_neutral_mismatches'] == 1
    assert result['baseline_gaps'] == 1
    assert result['system_candidate_total'] == 2
    assert result['function_candidate_total'] == 1


def test_empty_domain_is_not_observed_not_missing_evaluation():
    result = metrics(case(domain='function'))
    assert result['target_status'] == result['function_target_status'] == 'target_absent'
    assert result['system_target_status'] == 'not_observed'
    assert result['system_candidate_total'] == result['system_target_fixed'] == 0


def test_target_transition_does_not_require_firing_or_matching_neutral():
    row = case(original='target_crash', neutral='normal')
    row['report']['activation']['status'] = 'not_fired'
    result = metrics(row)
    assert result['target_fixed'] == result['original_neutral_mismatches'] == 1
    assert result['branch_comparable'] == result['branch_regressions'] == 1
    assert result['target_status'] == 'target_absent'


def test_branch_denominator_preserves_actual_neutral_pairs_despite_original_gaps():
    differing = case(0, original='target_crash', neutral='normal')
    equal = case(1, original='unknown', neutral='normal', comparison='equal')
    result = metrics(differing, equal, case(2), case(3, outcome='unknown'))
    assert result['branch_comparable'] == 2
    assert result['branch_regressions'] == 1
    assert result['branch_comparison_unavailable'] == 2
    assert result['original_neutral_mismatches'] == 1
    assert result['baseline_gaps'] == 1
    assert result['target_fixed'] == 2


@pytest.mark.parametrize('kind', [
    'predicted', 'unavailable', 'partial', 'invalid', 'unmatched-control',
    'wrong-neutral-artifact', 'wrong-candidate-artifact', 'wrong-oracle-artifact',
    'partial-neutral', 'trap', 'activation-unknown', 'other-outcome', 'unknown-outcome',
])
def test_unavailable_or_predicted_branch_pairs_cannot_enter_denominator(kind):
    row = case(original='normal', neutral='normal')
    report = row['report']
    if kind == 'predicted':
        report['branch_comparison']['basis'] = 'offline_prediction'
    elif kind == 'unavailable':
        report['branch_comparison']['status'] = 'unavailable'
    elif kind in ('partial', 'invalid'):
        report['candidate']['capture']['status'] = 'incomplete' if kind == 'partial' else 'invalid'
    elif kind == 'unmatched-control':
        report['neutral_baseline']['compatible_control'] = False
    elif kind == 'wrong-neutral-artifact':
        report['neutral_baseline']['artifact_sha256'] = 'b' * 64
    elif kind == 'wrong-candidate-artifact':
        report['candidate']['artifact_sha256'] = 'b' * 64
    elif kind == 'wrong-oracle-artifact':
        report['oracle']['evaluation_artifact_sha256'] = None
    elif kind == 'partial-neutral':
        report['neutral_baseline']['capture']['status'] = 'incomplete'
    elif kind == 'trap':
        report['activation']['status'] = 'trapped'
    elif kind == 'activation-unknown':
        report['activation']['status'] = 'unknown'
    elif kind == 'other-outcome':
        report['candidate']['outcome'] = 'other_crash'
    else:
        report['candidate']['outcome'] = 'unknown'
    result = metrics(row)
    assert result['branch_comparable'] == result['branch_regressions'] == 0
    assert result['branch_comparison_unavailable'] == 1
    assert result['predicate_traps'] == (kind == 'trap')
    assert result['candidate_capture_incomplete'] == (kind in ('partial', 'invalid'))


def test_authenticated_empty_vectors_are_comparable_not_missing():
    row = case(original='normal', neutral='normal', comparison='equal')
    for role in ('neutral_baseline', 'candidate'):
        row['report'][role]['capture'] = {'status': 'zero_hits', 'total_hits': 0}
    row['report']['activation']['status'] = 'zero_hits'
    result = metrics(row)
    assert result['branch_comparable'] == 1
    assert result['branch_comparison_unavailable'] == result['branch_regressions'] == 0
    assert result['candidate_capture_incomplete'] == 0


@pytest.mark.parametrize(('original', 'neutral', 'outcome', 'expected'), [
    ('normal', 'target_crash', 'target_crash', 0),
    ('target_crash', 'normal', 'target_crash', 1),
    ('unknown', 'normal', 'target_crash', 1),
    ('normal', 'normal', 'other_crash', 0),
    ('normal', 'normal', 'unknown', 0),
])
def test_new_target_failures_compare_neutral_not_instrumentation_changes(original, neutral, outcome, expected):
    result = metrics(case(original=original, neutral=neutral, outcome=outcome))
    assert result['new_target_failures'] == expected


@pytest.mark.parametrize('compatible', [False, True])
def test_new_target_failure_needs_control_but_not_complete_candidate_capture(compatible):
    row = case(original='normal', neutral='normal', outcome='target_crash')
    row['report']['neutral_baseline']['compatible_control'] = compatible
    row['report']['candidate']['capture'] = None
    row['report']['activation']['status'] = 'unknown'
    result = metrics(row)
    assert result['new_target_failures'] == int(compatible)
    assert result['target_status'] == 'target_present'


def test_evidence_loss_changes_denominator_not_known_target_result():
    row = case(original='normal', neutral='normal')
    before = metrics(row)
    lost = deepcopy(row)
    lost['report']['candidate']['capture'] = None
    lost['report']['activation'] = None
    lost['report']['branch_comparison'] = None
    after = metrics(lost)
    assert before['branch_regressions'] == before['branch_comparable'] == 1
    assert after['branch_regressions'] == after['branch_comparable'] == 0
    assert after['branch_comparison_unavailable'] == after['candidate_capture_incomplete'] == 1
    assert after['candidate_known'] == before['candidate_known'] == 1
    assert after['target_status'] == before['target_status'] == 'target_absent'


@pytest.mark.parametrize('evaluation', [[], 1, 'invalid', {}, {'cases': None}, {'cases': {}},
                                        {'cases': [None]}, {'cases': [{}]}])
def test_malformed_evaluations_are_rejected(evaluation):
    with pytest.raises(ValueError):
        collect_metrics(evaluation, candidate_present=True)


def test_duplicate_case_ids_are_rejected_even_when_one_report_is_missing():
    row = case()
    with pytest.raises(ValueError, match='duplicate case_id'):
        metrics(row, {'case_id': row['case_id'], 'domain': 'system'})


@pytest.mark.parametrize(('path', 'value'), [
    (('case_id',), 'function:0'),
    (('case_id',), 'system:not-a-number'),
    (('domain',), 'unknown'),
    (('report',), []),
    (('report', 'case_id'), 'system:99'),
    (('report', 'domain'), 'function'),
    (('report', 'candidate'), []),
    (('report', 'candidate', 'outcome'), 'success'),
    (('report', 'candidate', 'capture'), []),
    (('report', 'candidate', 'capture', 'status'), 'partial'),
    (('report', 'candidate', 'artifact_sha256'), []),
    (('report', 'original_baseline', 'applicable'), 'false'),
    (('report', 'neutral_baseline', 'compatible_control'), 1),
    (('report', 'activation'), []),
    (('report', 'activation', 'status'), 'predicted_fired'),
    (('report', 'branch_comparison'), []),
    (('report', 'branch_comparison', 'status'), 'predicted_different'),
    (('report', 'oracle', 'target'), '0x123'),
    (('report', 'oracle', 'evaluation_artifact_sha256'), []),
])
def test_malformed_case_structure_or_identity_is_rejected(path, value):
    row = case()
    parent = row
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    with pytest.raises(ValueError):
        metrics(row)


def test_original_neutral_mismatch_survives_missing_candidate_evidence():
    row = case(original='target_crash', neutral='normal', outcome='unknown')
    row['report']['candidate'] = None
    row['report']['activation'] = None
    row['report']['branch_comparison'] = None
    result = metrics(row)
    assert result['original_neutral_mismatches'] == 1
    assert result['target_baselines'] == result['target_unobserved'] == 1
    assert result['target_status'] == 'not_observed'


def test_candidate_presence_must_be_explicit_boolean():
    with pytest.raises(ValueError, match='candidate_present'):
        collect_metrics(None, candidate_present='yes')
