"""Cached publication binds exact runtime bytes and activation, without rebuilding."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from taosc_llm import publication
from taosc_llm.execution import sha256
from taosc_llm.family import parse_candidate
from test_context_tools import make_dataset


def evaluated(dataset, predicate):
    parsed = parse_candidate(dataset.patch_format, predicate)
    return {'dataset_id': dataset.dataset_id, 'predicate': parsed.expression,
            'descriptor': parsed.descriptor, 'cases': [
                {'case_id': case['id'], 'domain': case['domain'], 'descriptor': parsed.descriptor,
                 'report': {'case_id': case['id'], 'domain': case['domain'],
                            'candidate': {'outcome': 'unknown'}, 'activation': {'status': 'unknown'}}}
                for case in dataset.cases()]}


def test_publication_import_does_not_load_model_or_context(tmp_path):
    root = str(Path(publication.__file__).resolve().parent.parent)
    code = ('import sys;sys.path.insert(0,sys.argv[1]);import taosc_llm.publication;'
            'assert not any(n in sys.modules for n in '
            '("taosc_llm.provider","taosc_llm.context","taosc_llm.bridge","taosc_llm.synthesis"))')
    result = subprocess.run([sys.executable, '-I', '-c', code, root],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('patch_format,predicate', [
    ('ERM generic', 'rax < 0'),
    ('ERM CWE-805', 's->rax >= i->begin && s->rax < i->end'),
])
@pytest.mark.parametrize('destination', [0, 4097])
def test_publication_preserves_evaluated_artifact_and_explicit_activation(tmp_path, patch_format, predicate, destination):
    dataset = make_dataset(tmp_path / 'dataset', patch_format=patch_format, destination=destination)
    binary = dataset.artifact('fixture.brcached')
    before = binary.read_bytes()
    evaluation = evaluated(dataset, predicate)
    record = publication.publish_candidate(dataset, predicate, evaluation=evaluation)
    assert record['artifact'] == {'path': str(binary), 'sha256': sha256(binary)}
    assert record['activation'] == {'PATCH_ID': '0', 'TAOSC_PRED': record['descriptor'],
                                    'BRCACHE_STACK_SIZE': '0'}
    assert record['patch_destination'] == hex(destination)
    assert record['status'] == 'published' and record['kind'] == 'cached-predicate'
    assert record['verified'] is False and record['binradar_verification'] == 'not_run'
    assert binary.read_bytes() == before
    publication.validate_publication(dataset, json.loads(json.dumps(record)), predicate,
                                     evaluation=evaluation)


@pytest.mark.parametrize('changed', ['runtime', 'descriptor', 'activation', 'artifact', 'dataset'])
def test_saved_publication_cannot_rebind_runtime_or_predicate(tmp_path, changed):
    dataset = make_dataset(tmp_path / 'dataset')
    evaluation = evaluated(dataset, 'rax < 0')
    record = deepcopy(publication.publish_candidate(dataset, 'rax < 0', evaluation=evaluation))
    if changed == 'runtime':
        dataset.artifact('fixture.brcached').write_bytes(b'changed cached runtime')
    elif changed == 'descriptor':
        record['descriptor'] = 'p0'
    elif changed == 'activation':
        record['activation']['TAOSC_PRED'] = 'p0'
    elif changed == 'artifact':
        record['artifact']['path'] = str(tmp_path / 'unrelated.brcached')
    else:
        record['dataset_id'] = 'another dataset'
    with pytest.raises(ValueError):
        publication.validate_publication(dataset, record, 'rax < 0', evaluation=evaluation)


def test_stack_admission_and_cancellation_prevent_publication(tmp_path):
    dataset = make_dataset(tmp_path / 'dataset', patch_format='ERM CWE-805')
    with pytest.raises(ValueError, match='stack-size'):
        publication.publish_candidate(dataset, '1 * ((uint8_t *)s->rsp)[0] < i->end - i->begin',
                                      evaluation={})
    def cancelled():
        raise InterruptedError('cancelled publication')
    with pytest.raises(InterruptedError):
        publication.publish_candidate(dataset, '1 * s->rax < i->end - i->begin',
                                      evaluation={}, check=cancelled)


@pytest.mark.parametrize('changed', ['missing', 'dataset', 'descriptor', 'predicate', 'subset',
                                    'case-descriptor', 'trap'])
def test_publication_rejects_unbound_partial_or_trapped_evidence(tmp_path, changed):
    dataset = make_dataset(tmp_path / 'dataset')
    evaluation = evaluated(dataset, 'rax < 0')
    if changed == 'missing':
        evaluation = None
    elif changed == 'subset':
        evaluation['cases'].pop()
    elif changed == 'case-descriptor':
        evaluation['cases'][0]['descriptor'] = 'p0'
    elif changed == 'trap':
        evaluation['cases'][0]['report']['candidate']['reason'] = 'predicate-trap'
    else:
        evaluation[{'dataset': 'dataset_id'}.get(changed, changed)] = (
            'rax > 0' if changed == 'predicate' else 'different')
    with pytest.raises(ValueError):
        publication.publish_candidate(dataset, 'rax < 0', evaluation=evaluation)


def test_resume_rechecks_trap_evidence_not_only_saved_publication(tmp_path):
    dataset = make_dataset(tmp_path / 'dataset')
    evaluation = evaluated(dataset, 'rax < 0')
    record = publication.publish_candidate(dataset, 'rax < 0', evaluation=evaluation)
    evaluation['cases'][1]['report']['activation']['status'] = 'trapped'
    with pytest.raises(ValueError, match='predicate-trap'):
        publication.validate_publication(dataset, record, 'rax < 0', evaluation=evaluation)

