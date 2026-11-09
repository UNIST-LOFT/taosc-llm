"""Allowlisted outcome, control and activation evidence; never a repair verdict."""
from __future__ import annotations

from collections import Counter
from io import StringIO
import re

import sbsv

from binradar import binradar_feedback
from binradar.binradar_verifier import CONCRETE_ORACLE


_OUTCOMES = ('target_crash', 'normal', 'other_crash', 'unknown')
_ACTIVATIONS = ('fired', 'not_fired', 'zero_hits', 'trapped', 'unknown')
POC_SUMMARY_BYTES = 65536
POC_LOG_BYTES = 1048576


def poc_log(dataset, *, limit=POC_LOG_BYTES):
    """Read only the frozen diagnostic artifact, never a model-supplied path.

    The manifest authenticates bytes, not the execution that produced this log.
    Keep the raw artifact unchanged; only the model-facing copy loses paths.
    """
    artifacts = dataset.manifest['artifacts']
    record = artifacts.get('trace/qasan.log')
    result = {'status': 'missing', 'source': {
        'kind': 'frozen-workdir-qasan-trace',
        'log_sha256': record['sha256'] if record else None,
        'poc_sha256': artifacts.get('poc', {}).get('sha256'),
        'binary_sha256': artifacts[dataset.binary + '.orig']['sha256'],
        'execution_binding': 'not-recorded'},
        'source_bytes': 0, 'read_bytes': 0, 'source_limit_bytes': limit,
        'source_truncated': False, 'text': ''}
    if record is None:
        return result
    path = dataset.artifact('trace/qasan.log')
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    clipped = len(raw) > limit
    raw = raw[:limit]
    if clipped:
        # Do not expose a partially redacted path or partial UTF-8 sequence.
        end = raw.rfind(b'\n')
        raw = raw[:end + 1] if end >= 0 else b''
    text = raw.decode('utf-8', errors='replace')
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
    text = ''.join(char for char in text if char in '\n\t' or ord(char) >= 32 and ord(char) != 127)
    text = re.sub(r'''(?<![\w])/(?:[^\s()<>\[\]"']+)''',
                  lambda match: '<path>/' + match.group().rsplit('/', 1)[-1], text)
    source_bytes = path.stat().st_size
    result.update(status='present' if source_bytes else 'empty',
                  source_bytes=source_bytes, read_bytes=len(raw), source_truncated=clipped, text=text)
    return result


def poc_diagnostic(dataset):
    """Compact first-report summary; this does not define the target oracle."""
    from .context import canonical, digest
    log = poc_log(dataset, limit=POC_SUMMARY_BYTES)
    text = log.pop('text')
    header = re.search(r'ERROR:\s+(?:QEMU-)?AddressSanitizer:\s*([^\n]+)', text)
    result = {**log, 'role': 'original-poc-diagnostic', 'summary_scope': 'first-report',
              'address_domain': 'reported-runtime-addresses', 'error': None, 'error_truncated': False,
              'reported_address': None, 'reported_pc': None, 'access': None,
              'fault_stack': [], 'stack_truncated': False,
              'details': {'tool': 'get_patch_context', 'view': 'poc_log'}}
    if header is not None:
        message = header.group(1)
        result['status'] = 'recognized'
        error = re.split(r'\s+(?:\(pc\s|at pc\s)', message)[0]
        result['error'] = error[:512]
        result['error_truncated'] = len(error) > 512
        for name, pattern in (('reported_address', r'\bon (?:unknown )?address\s+(0x[0-9a-fA-F]{1,16})\b'),
                              ('reported_pc', r'\bpc\s+(0x[0-9a-fA-F]{1,16})\b')):
            match = re.search(pattern, message)
            if match:
                result[name] = hex(int(match.group(1), 16))
        # Stop at the first completed stack block. Allocation/free stacks and
        # later sanitizer reports must not become frames of the fault stack.
        started = False
        for line in text[header.end():].splitlines():
            access = re.match(r'\s*(READ|WRITE) of size (\d{1,20})\b', line)
            if access and not started:
                result['access'] = {'operation': access.group(1), 'size': int(access.group(2))}
            frame = re.match(r'\s*#(\d+)\s+0x[0-9a-fA-F]+\b', line)
            if frame:
                if started and not frame.group(1).strip('0'):
                    break
                started = True
                if len(result['fault_stack']) == 6:
                    result['stack_truncated'] = True
                    break
                frame_text = line.strip()
                result['fault_stack'].append(frame_text[:512])
                result['stack_truncated'] |= len(frame_text) > 512
            elif started or re.search(r'ERROR:|SUMMARY:|freed by|allocated by|previously allocated', line):
                break
    elif log['status'] == 'present':
        result['status'] = 'unrecognized'
    if log['source']['log_sha256'] is not None:
        result['evidence_id'] = 'poc:' + digest(canonical([dataset.dataset_id, result]))
    return result


def _label(value):
    # Fault sources/image identities are labels, not authority to expose paths.
    return value if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.:+-]{1,160}', value) else None


def _reason(value, default='evidence-unavailable'):
    return value if isinstance(value, str) and re.fullmatch(r'[a-z][a-z0-9_-]{0,159}', value) else default


def _fault(outcome):
    address = outcome.get('fault_addr', outcome.get('fault-addr', outcome.get('concrete-fault-addr')))
    valid = outcome.get('fault_valid', outcome.get('fault-valid', outcome.get('concrete-fault-valid')))
    if valid is not True or type(address) is not int:
        return None
    offset = outcome.get('fault_offset', outcome.get('fault-image-offset'))
    return {'address': hex(address),
            'source': _label(outcome.get('fault_source', outcome.get('fault-source', outcome.get('concrete-fault-source')))),
            'image': _label(outcome.get('fault_image', outcome.get('fault-image'))),
            'offset': hex(offset) if type(offset) is int else None}


def oracle_reference(dataset, domain):
    """Return the fixed domain oracle, independently of case availability."""
    if domain not in ('system', 'function'):
        raise ValueError('oracle domain must be system or function')
    oracles = dataset.manifest.get('oracles', {})
    function = domain == 'function'
    reference = oracles.get('mutation_reference') if function else oracles.get('concrete_reference')
    if function:
        target = ({'address': hex(reference['address']) if type(reference.get('address')) is int else None,
                   'source': _label(reference.get('source')), 'image': _label(reference.get('image')),
                   'offset': hex(reference['offset']) if type(reference.get('offset')) is int else None}
                  if isinstance(reference, dict) else None)
    else:
        target = ({'address': hex(reference), 'source': CONCRETE_ORACLE, 'image': None, 'offset': None}
                  if type(reference) is int else None)
    artifacts = dataset.manifest['artifacts']
    evaluation_artifact = artifacts.get(dataset.binary + '.brcached', {}).get('sha256')
    reference_artifact = evaluation_artifact if function else artifacts.get(dataset.binary + '.orig', {}).get('sha256')
    return {'oracle_id': 'selected-artifact-attempt1' if function else CONCRETE_ORACLE,
            'domain': domain, 'reference_origin': 'committed-attempt1' if function else 'original-probe',
            'artifact_sha256': reference_artifact, 'evaluation_artifact_sha256': evaluation_artifact,
            'target': target}


def _capture(dataset, capture, metadata, descriptor=None):
    if not isinstance(capture, dict):
        return {'status': 'unavailable', 'total_hits': None}, None
    if capture.get('complete') is not True:
        return {'status': 'incomplete', 'total_hits': None}, None
    from .evaluation import _validated_snapshots, _vector
    try:
        snapshots = _validated_snapshots(dataset, capture, metadata)
        branches = [state.branch for state in snapshots]
        if _vector(capture['descriptor'], snapshots, dataset=dataset) != branches:
            raise ValueError('representative-evaluator-mismatch')
        if descriptor is not None:
            from .evaluation import _descriptor
            parsed = _descriptor(dataset, descriptor)
            if descriptor != 'p0' and isinstance(parsed, str) == metadata.cwe:
                raise ValueError('candidate-descriptor-family-mismatch')
            if _vector(descriptor, snapshots, dataset=dataset) != branches:
                raise ValueError('candidate-evaluator-mismatch')
        return {'status': 'complete' if branches else 'zero_hits', 'total_hits': len(branches)}, branches
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        return {'status': 'invalid', 'total_hits': None}, None


def _observation(dataset, case, record, *, artifact, source, metadata, descriptor=None):
    record = record if isinstance(record, dict) else {}
    capture = record.get('capture')
    outcome = record.get('outcome')
    if not isinstance(outcome, dict):
        outcome = capture.get('outcome', {}) if isinstance(capture, dict) else {}
    if not isinstance(outcome, dict):
        outcome = {}
    capture_status, branches = _capture(dataset, capture, metadata, descriptor)
    observed = outcome.get('outcome')
    if observed is None:
        observed = {'ok': 'normal', 'crash': 'crash'}.get(outcome.get('exit'))
    same = None
    if record.get('status') == 'reject_same_crash':
        same = True
    elif record.get('status') == 'not_rejected':
        same = False
    elif case['domain'] == 'function':
        if isinstance(capture, dict) and type(capture.get('same_crash')) is bool:
            same = capture['same_crash']
    else:
        from .evaluation import _same_crash
        same = _same_crash(dataset, case, {'outcome': outcome})
    # A definite normal exit is still an observation if its oracle is missing.
    category = ('target_crash' if same is True else 'normal' if observed == 'normal'
                else 'other_crash' if observed in ('crash', 'other-crash') and same is False else 'unknown')
    if category in ('target_crash', 'other_crash') and oracle_reference(dataset, case['domain'])['target'] is None:
        category = 'unknown'
    if isinstance(capture, dict) and (capture.get('artifact_sha256') != artifact
            or (record.get('source') == 'prepared-neutral' and branches is None)):
        category = 'unknown'
    reason = _reason(record.get('reason'),
                     'oracle-unavailable' if observed == 'crash' and same is None
                     else 'outcome-unavailable' if category == 'unknown' else 'observed')
    if reason in ('same-crash', 'observed-not-same-crash'):
        reason = {'target_crash': 'target-crash', 'normal': 'observed-normal',
                  'other_crash': 'observed-other-crash', 'unknown': 'oracle-unavailable'}[category]
    result = {'outcome': category, 'reason': reason, 'applicable': True,
              'capture': capture_status, 'evidence_source': _reason(record.get('source'), source),
              'artifact_sha256': artifact, 'observed_fault': _fault(outcome),
              'reuse': record.get('reuse') if record.get('reuse') in
              ('fresh', 'exact-descriptor', 'full-vector-equivalent') else None}
    return result, branches


def mutation_provenance(dataset, case):
    """Full authenticated ordered writes for host matching, not model paging."""
    with dataset.validation() as validated:
        return _mutation_provenance(validated, case)


def _mutation_provenance(dataset, case):
    from .dataset import canonical
    from .evaluation import _memo
    fields = ('kind', 'size', 'value', 'target_extent')
    def load():
        result = _read_mutation_provenance(dataset, case)
        return result['status'], tuple(tuple(write[field] for field in fields)
                                       for write in result['writes'])
    status, writes = _memo(dataset, 'mutation-provenance',
                           (case['id'], case['domain'], canonical(case.get('capture'))), load)
    return {'status': status, 'writes': [dict(zip(fields, write)) for write in writes],
            'complete_state': False}


def _read_mutation_provenance(dataset, case):
    if case['domain'] != 'function':
        return {'status': 'unavailable', 'writes': [], 'complete_state': False}
    capture = case.get('capture')
    sidecar = capture.get('sidecar') if isinstance(capture, dict) else None
    if not isinstance(sidecar, dict):
        return {'status': 'unavailable', 'writes': [], 'complete_state': False}
    try:
        # The sidecar is frozen together with the prepared case, not candidate state.
        record_bytes = getattr(dataset, '_record_bytes', None)
        text = (record_bytes(sidecar).decode() if record_bytes is not None
                else dataset._verify(sidecar).read_text())
        parser = sbsv.parser()
        parser.add_schema(binradar_feedback._FEEDBACK_SCHEMA)
        parser.add_schema(binradar_feedback._MUTATION_SCHEMA)
        with StringIO(text) as stream:
            header = parser.parse_line_detached(stream.readline())
            if (header is None or header.get_name() != 'binradar-feedback'
                    or header['version'] != 3 or header['iteration'] != int(case['id'].split(':', 1)[1])
                    or header['patch'] != capture.get('patch_id', 0)
                    or capture.get('descriptor') != 'p0'):
                raise ValueError('mutation-header-unavailable')
            writes = []
            for line in stream:
                row = parser.parse_line_detached(line)
                if (row is None or row.get_name() != 'binradar-mutation'
                        or row['index'] != len(writes) or row['size'] <= 0
                        or row['kind'] not in ('bytes', 'pointer-null', 'pointer-oob', 'pointer-fresh')
                        or (row['kind'] == 'pointer-fresh' and row['value'] != 'dynamic')
                        or (row['kind'] != 'pointer-fresh' and re.fullmatch(r'[0-9a-f]{%d}' % (2 * row['size']), row['value']) is None)):
                    raise ValueError('mutation-writes-invalid')
                writes.append({'kind': row['kind'], 'size': row['size'], 'value': row['value'],
                               'target_extent': row['target-extent']})
            if len(writes) != header['mutation-writes']:
                raise ValueError('mutation-writes-incomplete')
        return {'status': 'available', 'writes': writes, 'complete_state': False}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {'status': 'unavailable', 'writes': [], 'complete_state': False}


def _mutation(dataset, case):
    result = _mutation_provenance(dataset, case)
    writes = result['writes']
    projected = []
    for write in writes[:32]:
        item = dict(write)
        if len(item['value']) > 1024:
            item.update(value=None, value_prefix=write['value'][:1024],
                        value_total_chars=len(write['value']), value_truncated=True)
        projected.append(item)
    return {**result, 'writes': projected, 'total_writes': len(writes),
            'truncated': len(writes) > 32 or any(write.get('value_truncated') for write in projected)}


def _offline_prediction(dataset, evaluated, metadata):
    capture = evaluated.get('offline_reference')
    if not isinstance(capture, dict) or not isinstance(evaluated.get('offline_branches'), list):
        return None
    from .evaluation import _validated_snapshots, _vector
    try:
        snapshots = _validated_snapshots(dataset, capture, metadata)
        actual = capture['branches']
        if _vector(capture['descriptor'], snapshots, dataset=dataset) != actual:
            return None
        branches = _vector(evaluated['descriptor'], snapshots, dataset=dataset)
        divergence = next((index for index, (a, b) in enumerate(zip(branches, actual)) if a != b), None)
        if branches != evaluated['offline_branches'] or divergence != evaluated.get('first_divergence'):
            return None
        return {'branches': branches[:256], 'total_hits': len(branches), 'truncated': len(branches) > 256,
                'first_divergence': divergence, 'basis': 'reference_capture_not_candidate_execution'}
    except (OSError, ValueError, KeyError, TypeError, RuntimeError):
        return None


def project_case(dataset, case, evaluated=None, *, descriptor=None, predicate=None):
    """Project a case; legacy results may supply their overall candidate identity."""
    with dataset.validation() as validated:
        if descriptor is None and predicate is not None:
            from .family import parse_candidate
            descriptor = parse_candidate(validated.patch_format, predicate).descriptor
        return _project_case(validated, case, evaluated, descriptor=descriptor)


def _project_case(dataset, case, evaluated, *, metadata=None, descriptor=None):
    if metadata is None:
        from .evaluation import _capture_metadata
        metadata = _capture_metadata(dataset)
    evaluated = evaluated if isinstance(evaluated, dict) else {}
    case_descriptor = evaluated.get('descriptor')
    if not isinstance(case_descriptor, str) or not case_descriptor:
        case_descriptor = descriptor
    oracle = oracle_reference(dataset, case['domain'])
    artifact = oracle['evaluation_artifact_sha256']
    original_artifact = dataset.manifest['artifacts'].get(dataset.binary + '.orig', {}).get('sha256')
    # Mutation observations are selected-artifact neutral runs, not originals.
    original_record = {'outcome': case.get('observation', {})} if case['domain'] == 'system' else {}
    original, _ = _observation(dataset, case, original_record, artifact=original_artifact,
                               source='original-observation' if case['domain'] == 'system' else 'original-unavailable',
                               metadata=metadata)
    if case['domain'] == 'function':
        original.update(applicable=False, reason='not-applicable', evidence_source='not-applicable')
    neutral_record = evaluated.get('neutral_baseline')
    if not isinstance(neutral_record, dict):
        prepared = case.get('capture')
        neutral_record = ({'capture': prepared, 'source': 'prepared-neutral'}
                          if isinstance(prepared, dict) and prepared.get('descriptor') == 'p0' else {})
    neutral, neutral_branches = _observation(dataset, case, neutral_record, artifact=artifact,
                                             source='neutral-unavailable', metadata=metadata, descriptor='p0')
    neutral_compatible = neutral_branches is not None
    neutral['compatible_control'] = neutral_compatible
    candidate, branches = _observation(dataset, case, evaluated, artifact=artifact,
                                       source='candidate-unavailable', metadata=metadata, descriptor=case_descriptor)
    if case_descriptor is None:
        branches = None
    activation = {'status': 'unknown', 'original_hits': None, 'repair_hits': None, 'trap_hits': None}
    if branches is not None:
        counts = Counter(branches)
        activation.update(original_hits=counts[0], repair_hits=counts[1], trap_hits=counts[2])
        activation['status'] = ('trapped' if counts[2] else 'fired' if counts[1]
                                else 'not_fired' if branches else 'zero_hits')
    # Values predicted on old states are intentionally absent from actual activation.
    def transition(baseline):
        return (baseline['outcome'] + '->' + candidate['outcome']
                if baseline.get('applicable', True) and baseline['outcome'] != 'unknown'
                and candidate['outcome'] != 'unknown' else None)
    neutral_transition = transition(neutral) if neutral_compatible else None
    original_transition = transition(original)
    warnings = []
    if neutral_compatible and neutral['outcome'] in ('normal', 'other_crash') and oracle['target'] is not None:
        warnings.append('control_does_not_reproduce_target')
    if neutral_compatible and neutral['outcome'] == 'normal' and candidate['outcome'] in ('target_crash', 'other_crash'):
        warnings.append('normal_control_to_candidate_crash')
    prediction = _offline_prediction(dataset, evaluated, metadata)
    return {'case_id': case['id'], 'domain': case['domain'], 'oracle': oracle,
            **({'offline_prediction': prediction} if prediction is not None else {}),
            'original_baseline': original, 'neutral_baseline': neutral, 'candidate': candidate,
            'activation': activation,
            'transition': {'neutral_to_candidate': neutral_transition, 'original_to_candidate': original_transition,
                           'neutral_paired': neutral_transition is not None,
                           'original_paired': original_transition is not None,
                           'fired_and_target_to_normal': activation['status'] == 'fired' and neutral_transition == 'target_crash->normal'},
            'warnings': warnings, 'mutation': _mutation(dataset, case),
            'evidence_source': candidate['evidence_source']}


def summarize_reports(reports):
    """Count observations with explicit unknown and unpaired denominators."""
    reports = list(reports)
    def summarize(rows):
        result = {'total': len(rows),
                  'outcomes': {role: {**{outcome: sum(row[role].get('applicable', True)
                                                        and row[role]['outcome'] == outcome for row in rows)
                                         for outcome in _OUTCOMES},
                                      'not_applicable': sum(not row[role].get('applicable', True) for row in rows)}
                               for role in ('original_baseline', 'neutral_baseline', 'candidate')},
                  'activation': {status: sum(row['activation']['status'] == status for row in rows) for status in _ACTIVATIONS},
                  'hits': {name: sum(row['activation'][name] or 0 for row in rows)
                           for name in ('original_hits', 'repair_hits', 'trap_hits')},
                  'hits_eligible': sum(row['activation']['status'] != 'unknown' for row in rows),
                  'transitions': {}, 'unknown_reasons': {}, 'warnings': {}}
        for role in ('neutral', 'original'):
            values = [row['transition'][role + '_to_candidate'] for row in rows]
            eligible = sum(value is not None for value in values)
            not_applicable = sum(not row[role + '_baseline'].get('applicable', True) for row in rows)
            result['transitions'][role + '_to_candidate'] = {
                'eligible': eligible, 'unpaired': len(rows) - eligible - not_applicable,
                'not_applicable': not_applicable,
                'counts': dict(sorted(Counter(value for value in values if value is not None).items()))}
        result['fired_and_target_to_normal'] = sum(row['transition']['fired_and_target_to_normal'] for row in rows)
        groups = {}
        for row in rows:
            for role in ('original_baseline', 'neutral_baseline', 'candidate'):
                if row[role].get('applicable', True) and row[role]['outcome'] == 'unknown':
                    groups.setdefault(role + ':' + row[role]['reason'], []).append(row['case_id'])
            if row['activation']['status'] == 'unknown':
                groups.setdefault('activation:' + row['candidate']['capture']['status'], []).append(row['case_id'])
        result['unknown_reasons'] = {reason: {'count': len(ids), 'representative_ids': sorted(ids)[:3]}
                                     for reason, ids in sorted(groups.items())}
        result['warnings'] = dict(sorted(Counter(warning for row in rows for warning in row['warnings']).items()))
        return result
    return {**summarize(reports), 'domains': {domain: summarize([row for row in reports if row['domain'] == domain])
                                            for domain in sorted({row['domain'] for row in reports})}}
