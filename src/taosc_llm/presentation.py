"""Small model-facing examples over the full, private evidence reports.

The host reports remain authoritative. Omission here is not normal termination,
zero predicate activity, or a repair verdict.
"""
from __future__ import annotations

from binradar.binradar_taosc_predicates import REGISTER_TO_VAR

from .cases import case_order, case_records, relevant_registers
from .evidence import classify_quality, project_case, summarize_quality


_VISIBLE = frozenset(('target_crash', 'normal'))
_DEFAULT_REGISTERS = 'rax rdi rsi rdx rcx'


def _outcome(observation):
    if observation.get('applicable', True) and observation.get('outcome') in _VISIBLE:
        return observation['outcome']
    return None


def _mutation(report):
    mutation = report.get('mutation', {})
    if mutation.get('status') != 'available' or not mutation.get('writes'):
        return None
    writes = []
    for write in mutation['writes'][:3]:
        item = {key: write[key] for key in ('kind', 'size', 'target_extent') if key in write}
        value = write.get('value')
        if isinstance(value, str):
            if len(value) <= 128:
                item['value'] = value
            else:
                item['value_prefix'] = value[:128]
        elif isinstance(write.get('value_prefix'), str):
            item['value_prefix'] = write['value_prefix'][:128]
        writes.append(item)
    result = {'basis': 'ordered_input_writes_not_full_state', 'writes': writes}
    total = mutation.get('total_writes', len(mutation['writes']))
    if total > len(writes):
        result['total_writes'] = total
    return result


def compact_case(dataset, report, *, predicate=None):
    """Explicit case detail without private identities or outcome placeholders.

    State retrieval belongs to the caller: a report alone cannot authenticate a
    candidate capture, and must never substitute prepared registers for it.
    """
    result = {'case_id': report['case_id']}
    for role in ('original_baseline', 'neutral_baseline', 'candidate'):
        observation = report.get(role, {})
        outcome = observation.get('outcome') if observation.get('applicable', True) else None
        if outcome in ('target_crash', 'normal', 'other_crash'):
            result[role] = outcome
    quality = report.get('quality') or classify_quality(report)
    result['quality'] = {key: quality[key] for key in ('category', 'reasons', 'branch_difference') if key in quality}
    activation = report.get('activation', {})
    if activation.get('status') in ('fired', 'not_fired', 'zero_hits', 'trapped'):
        result['activation'] = {key: activation[key] for key in
                                ('status', 'original_hits', 'repair_hits', 'trap_hits')
                                if activation.get(key) is not None}
    mutation = _mutation(report)
    if mutation is not None:
        result['mutation'] = mutation
    return result


def _registers(dataset, record, predicate):
    # Preserve actual numeric values; these are machine registers, not inferred
    # pointers, lengths or source-language types. Bound even a large predicate.
    import re
    names = [name for name in REGISTER_TO_VAR
             if re.search(r'\b' + name + r'\b', predicate or _DEFAULT_REGISTERS)][:6]
    if not names:
        return None
    if record['evaluated'] is None and not record['report'].get('neutral_baseline', {}).get('compatible_control'):
        return None
    registers = relevant_registers(dataset, record, ' '.join(names))
    if registers is None or not registers['hits']:
        return None
    result = {'basis': 'candidate_capture' if record['evaluated'] is not None else 'neutral_capture',
              'hits': registers['hits']}
    if registers['truncated']:
        result['total_hits'] = registers['total_hits']
    return result


def _basis(record):
    report = record['report']
    if record['evaluated'] is not None:
        # An evaluated unknown/other fault is never an old-baseline success.
        return 'candidate', _outcome(report.get('candidate', {}))
    neutral = report.get('neutral_baseline', {})
    if neutral.get('outcome') != 'unknown':
        return 'neutral_baseline', _outcome(neutral)
    return 'original_baseline', _outcome(report.get('original_baseline', {}))


def _features(record):
    report = record['report']
    writes = report.get('mutation', {}).get('writes', [])
    shape = tuple(tuple(write.get(key) for key in ('kind', 'size', 'value', 'value_prefix', 'target_extent'))
                  for write in writes)
    return (report.get('domain'), shape, report.get('activation', {}).get('status'))


def _representatives(records):
    """Deterministic diversity across domains, mutation shapes and activity."""
    remaining = sorted(records, key=lambda record: case_order(record['report']['case_id']))
    selected, seen = [], [set(), set(), set()]
    while remaining and len(selected) < 3:
        def novelty(record):
            return sum(weight for weight, feature, known in zip((4, 2, 1), _features(record), seen)
                       if feature not in known)
        index = max(range(len(remaining)), key=lambda index: novelty(remaining[index]))
        record = remaining.pop(index)
        selected.append(record)
        for feature, known in zip(_features(record), seen):
            known.add(feature)
    return selected


def _example(dataset, record, predicate):
    report = record['report']
    basis, outcome = _basis(record)
    result = {'case_id': report['case_id'], 'basis': basis, 'outcome': outcome}
    if basis == 'candidate':
        neutral = report.get('neutral_baseline', {})
        if neutral.get('compatible_control') is True and _outcome(neutral) is not None:
            result['neutral_baseline'] = neutral['outcome']
        activation = report.get('activation', {}).get('status')
        if activation in ('fired', 'not_fired', 'zero_hits', 'trapped'):
            result['activation'] = activation
    registers = _registers(dataset, record, predicate)
    if registers is not None:
        result['registers'] = registers
    mutation = _mutation(report)
    if mutation is not None:
        result['mutation'] = mutation
    return result


def sample_cases(dataset, records, *, predicate=None):
    """At most three target-crash and three actual normal examples, never pages."""
    groups = {'crash': [], 'non_crash': []}
    for record in records:
        _, outcome = _basis(record)
        if outcome in _VISIBLE:
            groups['crash' if outcome == 'target_crash' else 'non_crash'].append(record)
    return {key: [_example(dataset, record, predicate) for record in _representatives(group)]
            for key, group in groups.items()}


def _counterexample(dataset, record, predicate):
    report = record['report']
    quality = report.get('quality') or classify_quality(report)
    result = _example(dataset, record, predicate)
    # An explicit failure counterexample is not an initial normal/crash sample.
    # Other faults and unknown outcomes must stay visible, without fault PCs.
    result.update(basis='candidate', outcome=report['candidate']['outcome'],
                  category=quality['category'])
    neutral = report.get('neutral_baseline', {})
    if neutral.get('compatible_control') is True:
        result['neutral_baseline'] = neutral.get('outcome', 'unknown')
    if quality['reasons']:
        result['reasons'] = quality['reasons']
    if 'branch_difference' in quality:
        result['branch_difference'] = quality['branch_difference']
    return result


def feedback(dataset, evaluation):
    """Public quality counts and at most three examples per failure/gap facet.

    Crash regressions and target misses are disjoint. Other crashes and baseline
    gaps are orthogonal facets; counts must not be summed into a population.
    Raw reports, capture identities and observed fault addresses remain private.
    """
    records = case_records(dataset, evaluation)
    groups = {key: [] for key in ('target_misses', 'crash_regressions', 'branch_regressions',
                                  'other_crashes', 'unavailable', 'baseline_gaps', 'unproven')}
    for record in records:
        quality = record['report'].get('quality') or classify_quality(record['report'])
        for facet in quality['facets']:
            if facet in groups:
                groups[facet].append(record)
    predicate = evaluation.get('predicate')
    def examples(group):
        return [_counterexample(dataset, record, predicate) for record in _representatives(group)]
    quality = summarize_quality(record['report'] for record in records)
    quality['examples'] = {key: examples(groups[key]) for key in
                          ('other_crashes', 'unavailable', 'baseline_gaps', 'unproven') if groups[key]}
    result = {'quality': quality}
    for public, private in (('missed_target_crashes', 'target_misses'),
                            ('regressions', 'crash_regressions'), ('branch_regressions', 'branch_regressions')):
        result[public] = {'count': len(groups[private]), 'examples': examples(groups[private])}
    if not records or any(groups[key] for key in ('unavailable', 'baseline_gaps', 'unproven')):
        result['warning'] = ('Limited evidence: missing candidate evidence, unmatched controls or unproven repair. '
                             'Normal observations alone do not establish repair.')
    return result


def poc_example(dataset, private_observation):
    """The real original POC and its separately labeled neutral captured state."""
    original = private_observation.get('original', {}).get('outcome')
    case = {**private_observation['case'],
            'observation': original if isinstance(original, dict) else {}}
    neutral = private_observation.get('neutral') or {}
    evaluated = {**neutral, 'descriptor': 'p0', 'neutral_baseline': neutral}
    report = project_case(dataset, case, evaluated, descriptor='p0')
    result = {'case_id': case['id'], 'subject': {key: private_observation['subject'][key]
                          for key in ('program', 'args', 'input_bytes')
                          if key in private_observation.get('subject', {})}}
    if type(neutral.get('total_hits')) is int:
        result['patch_hits'] = neutral['total_hits']
    for role in ('original_baseline', 'neutral_baseline'):
        outcome = _outcome(report.get(role, {}))
        if outcome is not None:
            result[role] = outcome
    registers = _registers(dataset, {'case': case, 'evaluated': evaluated, 'report': report}, None)
    if registers is not None:
        registers['basis'] = 'neutral_capture'
        result['registers'] = registers
    note = private_observation.get('note')
    if note:
        # The collector owns concise, sanitized material limitations.
        result['warning'] = note
    elif original is None:
        result['warning'] = 'Original POC observation is missing; shown registers are neutral, not original state.'
    elif any(report.get(role, {}).get('outcome') in ('normal', 'other_crash')
             for role in ('original_baseline', 'neutral_baseline')):
        result['warning'] = ('POC executions do not consistently reproduce the configured target; '
                             'site values alone do not prove repair.')
    return result
