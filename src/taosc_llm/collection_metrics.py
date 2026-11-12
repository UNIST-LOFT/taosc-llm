"""Read saved case reports without importing the evaluator or native runtime.

Target outcomes describe the observed cohort, not universal or causal repair.
Other crashes are informational: target -> other is a fixed target. Missing
controls, partial captures, traps and strict producer quality never veto a known
candidate outcome. Branch regressions have their own authenticated denominator.
"""
from __future__ import annotations


_FIELDS = (
    'target_status',
    'candidate_total', 'candidate_known', 'candidate_unknown', 'candidate_normal',
    'candidate_target_crashes', 'candidate_other_crashes',
    'target_baselines', 'target_fixed', 'target_remaining', 'target_unobserved',
    'branch_regressions', 'branch_comparable', 'branch_comparison_unavailable',
    'new_target_failures', 'baseline_gaps', 'original_neutral_mismatches',
    'candidate_capture_incomplete', 'predicate_traps',
)
METRIC_FIELDS: tuple[str, ...] = tuple(
    prefix + field for prefix in ('', 'system_', 'function_') for field in _FIELDS
)
_OUTCOMES = ('normal', 'target_crash', 'other_crash', 'unknown')
_ACTIVATIONS = ('fired', 'not_fired', 'zero_hits', 'trapped', 'unknown')
_CAPTURES = ('complete', 'zero_hits', 'incomplete', 'invalid', 'unavailable')


def _object(parent: dict, key: str) -> dict:
    value = parent.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f'{key} must be an object or null')
    return value


def _enum(parent: dict, key: str, choices: tuple[str, ...], default: str) -> str:
    value = parent.get(key, default)
    if value not in choices:
        raise ValueError(f'invalid {key}: {value!r}')
    return value


def _observation(report: dict, role: str) -> dict:
    observation = _object(report, role)
    _enum(observation, 'outcome', _OUTCOMES, 'unknown')
    if 'applicable' in observation and type(observation['applicable']) is not bool:
        raise ValueError(f'{role}.applicable must be boolean')
    artifact = observation.get('artifact_sha256')
    if artifact is not None and not isinstance(artifact, str):
        raise ValueError(f'{role}.artifact_sha256 must be a string or null')
    capture = _object(observation, 'capture')
    _enum(capture, 'status', _CAPTURES, 'unavailable')
    return observation


def _reports(evaluation: dict) -> list[tuple[str, dict]]:
    cases = evaluation.get('cases')
    if not isinstance(cases, list):
        raise ValueError('evaluation.cases must be a list')
    seen = set()
    reports = []
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError('evaluation cases must be objects')
        report = _object(case, 'report')
        case_id = case.get('case_id', report.get('case_id'))
        domain = case.get('domain', report.get('domain'))
        if domain not in ('system', 'function'):
            raise ValueError('case domain must be system or function')
        if (not isinstance(case_id, str) or not case_id.startswith(domain + ':')
                or not case_id[len(domain) + 1:].isascii()
                or not case_id[len(domain) + 1:].isdigit()):
            raise ValueError('case_id must be a domain-scoped numeric ID')
        if case_id in seen:
            raise ValueError(f'duplicate case_id: {case_id}')
        seen.add(case_id)
        if report.get('case_id', case_id) != case_id or report.get('domain', domain) != domain:
            raise ValueError(f'report identity disagrees with case: {case_id}')
        for role in ('original_baseline', 'neutral_baseline', 'candidate'):
            _observation(report, role)
        neutral = _object(report, 'neutral_baseline')
        if 'compatible_control' in neutral and type(neutral['compatible_control']) is not bool:
            raise ValueError('compatible_control must be boolean')
        activation = _object(report, 'activation')
        _enum(activation, 'status', _ACTIVATIONS, 'unknown')
        comparison = _object(report, 'branch_comparison')
        _enum(comparison, 'status', ('equal', 'different', 'unavailable'), 'unavailable')
        oracle = _object(report, 'oracle')
        if oracle.get('target') is not None and not isinstance(oracle['target'], dict):
            raise ValueError('oracle.target must be an object or null')
        artifact = oracle.get('evaluation_artifact_sha256')
        if artifact is not None and not isinstance(artifact, str):
            raise ValueError('evaluation_artifact_sha256 must be a string or null')
        reports.append((domain, report))
    return reports


def _branch_evidence(report: dict) -> tuple[bool, bool, bool, bool]:
    """Shared control/capture authentication for collection and selection."""
    neutral = _object(report, 'neutral_baseline')
    candidate = _object(report, 'candidate')
    artifact = _object(report, 'oracle').get('evaluation_artifact_sha256')
    control_compatible = (neutral.get('compatible_control') is True and bool(artifact)
                          and neutral.get('artifact_sha256') == artifact)
    compatible = control_compatible and candidate.get('artifact_sha256') == artifact
    capture_complete = _object(candidate, 'capture').get('status') in ('complete', 'zero_hits')
    actual = capture_complete and _object(report, 'activation').get('status') in (
        'fired', 'not_fired', 'zero_hits')
    neutral_complete = _object(neutral, 'capture').get('status') in ('complete', 'zero_hits')
    comparison = _object(report, 'branch_comparison')
    comparable = (compatible and actual and neutral_complete
                  and neutral.get('outcome') == candidate.get('outcome') == 'normal'
                  and comparison.get('basis') == 'actual_complete_vectors'
                  and comparison.get('status') in ('equal', 'different'))
    return control_compatible, compatible, capture_complete, comparable


def selection_case_sets(evaluation: dict | None) -> dict[str, frozenset[str]]:
    """Observed objective evidence, independent of strict producer quality."""
    result = {key: set() for key in ('known', 'target_crashes', 'branch_comparable',
                                    'branch_regressions')}
    reports = [] if evaluation is None else _reports(evaluation)
    for case, (_, report) in zip([] if evaluation is None else evaluation['cases'], reports):
        case_id = case.get('case_id', report.get('case_id'))
        outcome = _object(report, 'candidate').get('outcome', 'unknown')
        if outcome != 'unknown':
            result['known'].add(case_id)
        if outcome == 'target_crash':
            result['target_crashes'].add(case_id)
        if _branch_evidence(report)[3]:
            result['branch_comparable'].add(case_id)
            if report['branch_comparison']['status'] == 'different':
                result['branch_regressions'].add(case_id)
    return {key: frozenset(ids) for key, ids in result.items()}


def _summarize(reports: list[tuple[str, dict]] | None, candidate_present: bool) -> dict:
    result = {field: None if reports is None else 0 for field in _FIELDS}
    result['target_status'] = 'not_observed' if candidate_present else 'no_candidate'
    if reports is None:
        return result
    for domain, report in reports:
        original = _object(report, 'original_baseline')
        neutral = _object(report, 'neutral_baseline')
        candidate = _object(report, 'candidate')
        activation = _object(report, 'activation').get('status', 'unknown')
        comparison = _object(report, 'branch_comparison')
        oracle = _object(report, 'oracle')
        outcome = candidate.get('outcome', 'unknown')
        original_applicable = original.get('applicable', domain == 'system')
        # An unknown applicable original must not borrow a known neutral outcome.
        baseline = original if original_applicable else neutral
        baseline_outcome = baseline.get('outcome', 'unknown')
        neutral_outcome = neutral.get('outcome', 'unknown')
        result['candidate_total'] += 1
        result['candidate_unknown' if outcome == 'unknown' else 'candidate_known'] += 1
        outcome_field = {'normal': 'candidate_normal', 'target_crash': 'candidate_target_crashes',
                         'other_crash': 'candidate_other_crashes'}.get(outcome)
        if outcome_field is not None:
            result[outcome_field] += 1
        if baseline_outcome == 'target_crash':
            result['target_baselines'] += 1
            transition = ('target_remaining' if outcome == 'target_crash' else
                          'target_unobserved' if outcome == 'unknown' else 'target_fixed')
            result[transition] += 1
        control_compatible, compatible, capture_complete, comparable = _branch_evidence(report)
        neutral_complete = _object(neutral, 'capture').get('status') in ('complete', 'zero_hits')
        if compatible and neutral_complete and neutral_outcome == 'normal' and outcome == 'target_crash':
            result['new_target_failures'] += 1
        if comparable:
            result['branch_comparable'] += 1
            result['branch_regressions'] += comparison['status'] == 'different'
        else:
            result['branch_comparison_unavailable'] += 1
        if not capture_complete:
            result['candidate_capture_incomplete'] += 1
        if activation == 'trapped':
            result['predicate_traps'] += 1
        # Gaps are availability diagnostics. Known disagreement is separate and
        # cannot erase either an original target transition or a neutral pair.
        if (baseline_outcome == 'unknown' or neutral_outcome == 'unknown'
                or not compatible or not neutral_complete or oracle.get('target') is None):
            result['baseline_gaps'] += 1
        if (original_applicable and control_compatible and original.get('outcome', 'unknown') != 'unknown'
                and neutral_outcome != 'unknown' and original['outcome'] != neutral_outcome):
            result['original_neutral_mismatches'] += 1
    if candidate_present:
        if result['candidate_target_crashes']:
            result['target_status'] = 'target_present'
        elif result['candidate_known']:
            result['target_status'] = 'target_absent'
    return result


def selection_objective(evaluation: dict | None) -> dict:
    """Public observed-outcome objective; counts never imply universal repair."""
    metrics = collect_metrics(evaluation, candidate_present=True)
    fields = ('target_status', 'candidate_known', 'candidate_unknown',
              'candidate_target_crashes', 'branch_comparable', 'branch_regressions')
    return {**{field: metrics[field] for field in fields},
            'domains': {domain: {field: metrics[domain + '_' + field] for field in fields}
                        for domain in ('system', 'function')}}


def collect_metrics(evaluation: dict | None, *, candidate_present: bool) -> dict:
    """Return ordered overall/system/function metrics from saved reports only.

    ``None`` means no evaluation is available (null counters); ``cases=[]`` is
    an observed empty inventory (zero counters). Absent/null per-case reports
    remain unknown, even when legacy summaries, outcomes or quality say otherwise.
    Malformed structures and duplicate IDs raise ``ValueError`` for the caller to
    surface as collection errors rather than silently double-counting evidence.

    Target transitions use an applicable original, otherwise the neutral. Branch
    counts require matching artifact identities, a compatible neutral, complete
    actual normal captures and the saved actual-vector comparison. Their
    unavailable count is the complement of that denominator across all cases.
    ``candidate_capture_incomplete`` counts missing/invalid/partial captures;
    a complete trapped capture is instead recorded by ``predicate_traps``.
    """
    if type(candidate_present) is not bool:
        raise ValueError('candidate_present must be boolean')
    if evaluation is not None and not isinstance(evaluation, dict):
        raise ValueError('evaluation must be an object or null')
    reports = None if evaluation is None else _reports(evaluation)
    result = _summarize(reports, candidate_present)
    for domain in ('system', 'function'):
        selected = None if reports is None else [row for row in reports if row[0] == domain]
        result.update({domain + '_' + key: value for key, value in _summarize(selected, candidate_present).items()})
    return result
