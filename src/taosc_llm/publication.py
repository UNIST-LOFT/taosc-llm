"""Publish a predicate binding to the exact frozen artifact used for evaluation.

No compiler, relinker, new binary or cross-artifact replay is involved. The
binding requires explicit activation; it is not an always-enabled fixed patch.
"""
from __future__ import annotations

from .dataset import PreparedDataset
from .family import parse_candidate


def _candidate_record(dataset, predicate):
    parsed = parse_candidate(dataset.patch_format, predicate)
    stack_size = str(dataset.execution_environment().get('BRCACHE_STACK_SIZE', '0'))
    if parsed.required_stack_bytes > int(stack_size):
        raise ValueError('candidate stack cell exceeds prepared stack-size')
    name = dataset.binary + '.brcached'
    return {
        'schema_version': 1,
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


def publish_candidate(dataset: PreparedDataset, predicate: str, *, check=None) -> dict:
    """Authenticate the dataset and bind a candidate without rebuilding its runtime."""
    with dataset.validation(check=check) as validated:
        return _candidate_record(validated, predicate)


def validate_publication(dataset: PreparedDataset, record: dict, predicate: str, *, check=None) -> None:
    """Reject changed runtime bytes, activation, predicate or dataset on resume."""
    with dataset.validation(check=check) as validated:
        if record != _candidate_record(validated, predicate):
            raise ValueError('published cached candidate identity mismatch')
