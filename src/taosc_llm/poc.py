"""Private, authenticated original-input observations and neutral cached states.

Nothing here changes the immutable population or the configured crash oracle.
The sanctioned extra case is derived only from the frozen POC artifact.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shlex

from binradar.binradar_taosc_predicates import REGISTER_TO_VAR, wrap64
from binradar.binradar_verifier import CONCRETE_ORACLE

from .dataset import load_dataset
from .execution import execute_original, execution_identity, sha256


def poc_case(dataset) -> dict | None:
    """Resolve the frozen POC to a prepared case or a deterministic internal case.

    No arbitrary case/input is admitted, and the returned synthetic row is never
    written into the frozen manifest.
    """
    with dataset.validation() as validated:
        return _poc_case(validated)


def _poc_case(dataset):
    artifact = dataset.manifest['artifacts'].get('poc')
    if artifact is None:
        return None
    cases = dataset.cases('system')
    for case in cases:
        if case.get('input_sha256') == artifact['sha256']:
            return case
    number = max((int(case['id'].split(':')[1]) for case in cases), default=-1) + 1
    return {'id': f'system:{number}', 'domain': 'system',
            'input_path': artifact['path'], 'input_sha256': artifact['sha256'],
            'source': {'kind': 'frozen-poc'}, 'observation': None, 'capture': None}


def _original_available(observation):
    if not isinstance(observation, dict):
        return False
    return (observation.get('oracle', observation.get('concrete-oracle')) == CONCRETE_ORACLE
            and observation.get('outcome', observation.get('exit')) in ('normal', 'ok', 'crash'))


def _subject(dataset):
    settings = dataset.execution_environment()
    tokens = shlex.split(settings.get('TEST_CMD', ''))
    # Invocation text is data, not an executable command for the model. Replace
    # paths without exposing workdir/POC names; keep actual options and @@ roles.
    def sanitize(token):
        if token in ('@@', '@@@'):
            return '<input>'
        if '/' in token:
            if token.startswith('-') and '=' in token:
                return token.split('=', 1)[0] + '=<path>'
            return '<path>'
        return re.sub(r'[\x00-\x1f\x7f]', '', token)[:256]
    if tokens and Path(tokens[0]).name in (dataset.binary, dataset.binary + '.orig'):
        tokens = tokens[1:]
    return {'program': Path(dataset.binary).name,
            'args': [sanitize(token) for token in tokens],
            'input_bytes': dataset.artifact('poc').stat().st_size}


def poc_observation(dataset, *, cache_dir, execute: bool) -> dict:
    """Collect/reuse actual .orig outcomes and independently authenticated p0 states.

    Offline never launches a target or contacts a replay socket. Original .orig
    observations do not contain .brcached registers; those have a separate basis.
    The return value is JSON serializable private host evidence.
    """
    from . import evaluation
    if isinstance(dataset, (str, Path)):
        dataset = load_dataset(Path(dataset))
    with dataset.validation() as validated:
        case = poc_case(validated)
        if case is None:
            return {'subject': None, 'case': None, 'matching_case_ids': [],
                    'original': {'basis': 'original-artifact', 'source': 'unavailable', 'outcome': None},
                    'neutral': None, 'note': 'The frozen dataset has no original POC artifact.'}
        matches = [row for row in validated.cases('system')
                   if row.get('input_sha256') == case['input_sha256']]
        original = {'basis': 'original-artifact', 'source': 'unavailable', 'outcome': None}
        for row in matches:
            if _original_available(row.get('observation')):
                original.update(source='recorded', outcome=row['observation'])
                break
        cache_base = Path(cache_dir) if cache_dir is not None else Path.home() / '.cache' / 'taosc-llm'
        root = cache_base / 'poc-v1' / evaluation._digest(validated.dataset_id)
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        identity = {'dataset': validated.dataset_id, 'artifacts': validated.manifest['artifacts'],
                    'input': case['input_sha256'], 'family': validated.patch_format,
                    'environment': validated.execution_environment(),
                    'runtime': execution_identity(), 'collector': sha256(Path(__file__))}
        key = evaluation._digest(identity)
        path = root / (key + '.json')
        if original['outcome'] is None:
            with evaluation._lock(root / (key + '.lock')):
                try:
                    saved = json.loads(path.read_text())
                    if not isinstance(saved, dict) or not isinstance(saved.get('record'), dict):
                        raise ValueError('original-record-invalid')
                    record = saved['record']
                    if (saved.get('identity') == identity
                            and saved.get('record_digest') == evaluation._digest(record)
                            and record.get('artifact_sha256') == validated.manifest['artifacts'][validated.binary + '.orig']['sha256']
                            and _original_available(record.get('outcome'))):
                        original.update(source='cache', outcome=record['outcome'])
                except (OSError, ValueError, KeyError, TypeError):
                    pass
                if original['outcome'] is None and execute:
                    try:
                        record = execute_original(validated, case, root / 'executions')
                        if (record.get('artifact_sha256') != validated.manifest['artifacts'][validated.binary + '.orig']['sha256']
                                or not _original_available(record.get('outcome'))):
                            raise ValueError('original-observation-unavailable')
                        evaluation._atomic(path, {'identity': identity, 'record': record,
                                                  'record_digest': evaluation._digest(record)})
                        original.update(source='executed', outcome=record['outcome'])
                    except (OSError, ValueError, RuntimeError, KeyError):
                        pass
        # Look across every exact-input case before allowing a new execution.
        # This reuses the same authentication and cache namespace as candidates.
        ids = [row['id'] for row in matches] or [case['id']]
        result = evaluation._evaluate(validated, None, 'p0', case_ids=ids,
                                      workers=1, execute=False, cache_dir=cache_dir)
        metadata = evaluation._capture_metadata(validated)
        def admitted(item):
            try:
                states = evaluation._validated_snapshots(validated, item['capture'], metadata)
                return (item.get('branches') == [0] * len(states)
                        and item['capture']['branches'] == [0] * len(states))
            except (OSError, ValueError, KeyError, TypeError):
                return False
        neutral = next((item for item in result['cases'] if admitted(item)), None)
        if neutral is None and execute:
            result = evaluation._evaluate(validated, None, 'p0', case_ids=[case['id']],
                                          workers=1, execute=True, cache_dir=cache_dir)
            neutral = result['cases'][0]
        if neutral is None:
            neutral = result['cases'][0]
        neutral = dict(neutral)
        neutral['basis'] = 'neutral-cached-artifact'
        available = admitted(neutral)
        if available:
            states = evaluation._validated_snapshots(validated, neutral['capture'], metadata)
            neutral['first_hit_registers'] = ({name: str(wrap64(states[0].registers[slot]))
                                                for name, slot in REGISTER_TO_VAR.items()} if states else None)
            neutral['total_hits'] = len(states)
        # A copied workdir sanitizer log is not execution-bound original evidence.
        case = {**case, 'observation': original['outcome']}
        observation = {'subject': _subject(validated), 'case': case,
                       'matching_case_ids': [row['id'] for row in matches],
                       'original': original, 'neutral': neutral}
        missing = []
        if original['outcome'] is None:
            missing.append('original-binary observation')
        if not available:
            missing.append('complete neutral patch-site capture')
        if missing:
            observation['note'] = 'Original POC: ' + ' and '.join(missing) + ' unavailable.'
        return observation
