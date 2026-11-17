"""Publish a predicate binding to the exact frozen artifact used for evaluation.

No compiler, relinker, new binary or cross-artifact replay is involved. The
binding requires explicit activation; it is not an always-enabled fixed patch.
"""
from __future__ import annotations

import hashlib

from .collection_metrics import candidate_admission
from .dataset import PreparedDataset, canonical
from .family import parse_candidate


def _candidate_record(dataset, predicate, evaluation):
    parsed = parse_candidate(dataset.patch_format, predicate)
    stack_size = str(dataset.execution_environment().get('BRCACHE_STACK_SIZE', '0'))
    if parsed.required_stack_bytes > int(stack_size):
        raise ValueError('candidate stack cell exceeds prepared stack-size')
    if (not isinstance(evaluation, dict)
            or evaluation.get('dataset_id') != dataset.dataset_id
            or evaluation.get('descriptor') != parsed.descriptor
            or parse_candidate(dataset.patch_format, evaluation.get('predicate')).descriptor != parsed.descriptor):
        raise ValueError('publication evaluation identity mismatch')
    admission = candidate_admission(evaluation)
    if admission['status'] != 'eligible':
        raise ValueError('publication rejected: predicate-trap')
    from .poc import poc_case
    expected = {case['id'] for case in dataset.cases()}
    poc = poc_case(dataset)
    if poc is not None:
        expected.add(poc['id'])
    if ({case['case_id'] for case in evaluation['cases']} != expected
            or any(case.get('descriptor') != parsed.descriptor for case in evaluation['cases'])):
        raise ValueError('publication requires a full candidate evaluation including original POC')
    name = dataset.binary + '.brcached'
    return {
        'schema_version': 2,
        'evaluation_sha256': hashlib.sha256(canonical(evaluation)).hexdigest(),
        'status': 'published',
        'kind': 'cached-predicate',
        'dataset_id': dataset.dataset_id,
        'binary': dataset.binary,
        'patch_format': dataset.patch_format,
        'patch_location': hex(dataset.manifest['patch']['location']),
        'patch_destination': hex(dataset.manifest['patch']['destination']),
        'predicate': parsed.expression,
        'source_predicate': parsed.source_predicate,
        'descriptor': parsed.descriptor,
        'artifact': {'path': str(dataset.artifact(name)),
                     'sha256': dataset.manifest['artifacts'][name]['sha256']},
        # Direct descriptor mode; never inherit the magic shared-memory selector.
        'activation': {'PATCH_ID': '0', 'TAOSC_PRED': parsed.descriptor,
                       'BRCACHE_STACK_SIZE': stack_size},
        'verified': False,
        'binradar_verification': 'not_run',
    }


def publish_candidate(dataset: PreparedDataset, predicate: str, *, evaluation: dict, check=None) -> dict:
    """Bind the runtime only after full identity-bound evaluation and trap admission."""
    with dataset.validation(check=check) as validated:
        return _candidate_record(validated, predicate, evaluation)


def validate_publication(dataset: PreparedDataset, record: dict, predicate: str, *,
                         evaluation: dict, check=None) -> None:
    """Recheck admission and reject changed runtime, predicate or evaluation on resume."""
    with dataset.validation(check=check) as validated:
        if record != _candidate_record(validated, predicate, evaluation):
            raise ValueError('published cached candidate identity mismatch')
