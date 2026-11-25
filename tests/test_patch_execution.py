"""Observation boundaries; fakes here exercise contracts, never establish repair QA."""
import os
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from binradar import binradar_verifier as verifier
from taosc_llm import patch_execution as observation
from taosc_llm.execution import ExecutionUnavailable, sha256


@pytest.fixture
def subject(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    for name in ('fixture.orig', 'fixture.patched', 'fixture.brpatched'):
        (source / name).write_bytes(name.encode())
        (source / name).chmod(0o755)
        if not name.endswith('.orig'):
            (source / (name + '.json')).write_text('{}')
    input_file = tmp_path / 'input'
    input_file.write_bytes(b'input')
    settings = {'BINARY': 'fixture', 'TEST_CMD': '@@', 'PATCH_LOC': '0x10',
                'BINRADAR_QEMU_EXEC_TIMEOUT': '0.25'}
    return source, input_file, settings, tmp_path / 'scratch'


def _probe(exit_info='ok', hits=1):
    return verifier.BinRadarProbeResult(
        0x10, 0, [], exit_info, hits, 0, 0x10 if exit_info == 'crash' else 0, [],
        concrete_oracle=verifier.CONCRETE_ORACLE,
        concrete_fault_valid=exit_info == 'crash',
        concrete_fault_source='native' if exit_info == 'crash' else 'unavailable')


def test_original_never_requires_cached_dataset_or_fixed_metadata(subject, monkeypatch):
    source, input_file, settings, scratch = subject
    # These producer values must not even be parsed during an original run.
    settings.update(BRPATCHED_E9_RELOCATED_CALL_JUMPS='not-addresses',
                    BRCACHED_E9_EXCLUDE_RANGES='stale', OPENAI_API_KEY='not-forwarded')
    monkeypatch.setenv('OPENAI_API_KEY', 'not-forwarded')
    seen = []
    def capture(runner, artifact, patch_id, environment, work):
        assert artifact == 'fixture.orig' and patch_id == 0
        assert runner.e9_metadata_for_binary(str(work / artifact)) == ('', [])
        assert 'OPENAI_API_KEY' not in environment
        assert 'AFL_QEMU_INST_RANGES' not in environment
        assert sorted(path.name for path in work.iterdir()) == [
            '.observation-input', '.observation-output', 'fixture.orig']
        assert runner.exec_timeout == 0.25
        assert (work / '.observation-input').read_bytes() == b'input'
        seen.append(work)
        return _probe(), b''
    monkeypatch.setattr(observation, '_capture', capture)
    monkeypatch.setattr(observation, '_metadata', lambda *a: pytest.fail('original has no E9 map'))
    result = observation.observe(source, settings, input_file, artifact='fixture.orig', directory=scratch)
    assert result['artifact_sha256'] == sha256(source / 'fixture.orig')
    assert result['input_sha256'] == sha256(input_file)
    assert result['outcome']['outcome'] == 'normal'
    assert set(result) == {'artifact_sha256', 'input_sha256', 'outcome',
                           'probe', 'patch_hits', 'branches'}
    assert result['probe'].startswith('[version 4] ')
    assert result['patch_hits'] == 1 and result['branches'] is None
    assert not seen[0].exists()
    assert sorted(source.iterdir()) == sorted(source.glob('fixture.*'))
    assert input_file.read_bytes() == b'input'


@pytest.mark.parametrize('artifact', ['fixture.orig', 'fixture.patched', 'fixture.brpatched'])
def test_cwe823_output_is_private_host_owned_and_removed(subject, monkeypatch, artifact):
    source, input_file, settings, scratch = subject
    ambient = source / 'must-not-write'
    settings['TAOSC_OUTPUT'] = str(ambient)
    monkeypatch.setenv('TAOSC_OUTPUT', str(ambient))
    outputs = []
    def capture(runner, selected, patch_id, environment, work):
        output = Path(environment['TAOSC_OUTPUT'])
        assert output.parent == work and output.is_file() and not output.is_symlink()
        assert output.stat().st_mode & 0o777 == 0o600
        assert output.read_bytes() == b''
        output.write_bytes(b'private CWE823 snapshot')
        outputs.append(output)
        return _probe(hits=0), b''
    monkeypatch.setattr(observation, '_capture', capture)
    monkeypatch.setattr(observation, '_metadata', lambda *a: ('', []))
    monkeypatch.setattr(observation._FixedRunner, 'load_instruction_map', lambda *a: {})
    result = observation.observe(source, settings, input_file, artifact=artifact, directory=scratch)
    assert result['outcome']['outcome'] == 'normal'
    assert outputs and not outputs[0].exists()
    assert not ambient.exists() and list(scratch.iterdir()) == []


@pytest.mark.parametrize('artifact', ['fixture.patched', 'fixture.brpatched'])
def test_fixed_artifact_uses_own_metadata_and_active_patch_id(subject, monkeypatch, artifact):
    source, input_file, settings, scratch = subject
    seen = []
    def metadata(work, selected, original, location, timeout):
        assert selected == artifact and original == 'fixture.orig'
        assert (work / (selected + '.json')).read_text() == '{}'
        assert not (work / 'fixture.brcached').exists()
        seen.append((selected, location, timeout))
        return '0x1000-0x2000', ['0x1100:0x10:0x15']
    def load(runner, binary):
        assert Path(binary).name == artifact
        return {}
    def capture(runner, selected, patch_id, environment, work):
        assert selected == artifact and patch_id == 1
        assert environment['PATCH_ID'] == '1'
        assert environment['AFL_QEMU_INST_RANGES'] == '0x1000-0x2000'
        assert runner.e9_metadata_for_binary(str(work / selected))[1] == ['0x1100:0x10:0x15']
        assert runner.e9_metadata_for_binary(str(work / 'fixture.orig')) == ('', [])
        return _probe(), b'[patch] [id 1] [br 1] [v 0]\n'
    monkeypatch.setattr(observation, '_metadata', metadata)
    monkeypatch.setattr(observation._FixedRunner, 'load_instruction_map', load)
    monkeypatch.setattr(observation, '_capture', capture)
    result = observation.observe(source, settings, input_file, artifact=artifact,
                                 directory=scratch, patch_id=1)
    assert result['artifact_sha256'] == sha256(source / artifact)
    assert result['branches'] == [1]
    assert seen == [(artifact, 0x10, 0.25)]


@pytest.mark.parametrize('artifact', ['../fixture.orig', '/fixture.orig', 'fixture.brcached', 'other.orig'])
def test_artifact_boundary_rejects_paths_and_cached_aliases(subject, artifact):
    source, input_file, settings, scratch = subject
    with pytest.raises(ExecutionUnavailable, match='invalid-observation-artifact'):
        observation.observe(source, settings, input_file, artifact=artifact, directory=scratch)
    assert not scratch.exists()


@pytest.mark.parametrize('patch_id', [True, -1, 2**31, '1'])
def test_patch_id_boundary_rejects_coercion_and_overflow(subject, patch_id):
    source, input_file, settings, scratch = subject
    with pytest.raises(ExecutionUnavailable, match='invalid-patch-id'):
        observation.observe(source, settings, input_file, artifact='fixture.brpatched',
                            directory=scratch, patch_id=patch_id)


@pytest.mark.parametrize('timeout', ['nan', 'inf', '0', '-1'])
def test_timeout_boundary_is_finite_and_positive(subject, timeout):
    source, input_file, settings, scratch = subject
    settings['BINRADAR_QEMU_EXEC_TIMEOUT'] = timeout
    with pytest.raises(ExecutionUnavailable, match='finite positive'):
        observation.observe(source, settings, input_file, artifact='fixture.orig', directory=scratch)


def test_scratch_cannot_modify_source_tree(subject):
    source, input_file, settings, _ = subject
    with pytest.raises(ExecutionUnavailable, match='overlaps-source'):
        observation.observe(source, settings, input_file, artifact='fixture.orig', directory=source / 'scratch')
    assert not (source / 'scratch').exists()


@pytest.mark.parametrize('name', ['fixture.orig', 'fixture.brpatched.json', 'input'])
def test_symlink_sources_are_not_frozen_evidence(subject, name):
    source, input_file, settings, scratch = subject
    path = input_file if name == 'input' else source / name
    contents = path.read_bytes()
    other = path.with_name(path.name + '.real')
    path.rename(other)
    path.symlink_to(other)
    with pytest.raises(ExecutionUnavailable, match='required-regular-file'):
        observation.observe(source, settings, input_file,
                            artifact='fixture.orig' if name != 'fixture.brpatched.json' else 'fixture.brpatched',
                            directory=scratch, patch_id=0)
    assert other.read_bytes() == contents


@pytest.mark.parametrize('changed', ['fixture.orig', '.observation-input'])
def test_private_target_writes_cannot_authenticate_initial_bytes(subject, monkeypatch, changed):
    source, input_file, settings, scratch = subject
    def capture(runner, artifact, patch_id, environment, work):
        (work / changed).write_bytes(b'changed')
        return _probe(), b''
    monkeypatch.setattr(observation, '_capture', capture)
    with pytest.raises(ExecutionUnavailable, match='changed'):
        observation.observe(source, settings, input_file, artifact='fixture.orig', directory=scratch)
    assert (source / 'fixture.orig').read_bytes() == b'fixture.orig'
    assert input_file.read_bytes() == b'input'


@pytest.mark.parametrize('text,hits,expected', [
    (b'', 0, []), (b'', 1, None),
    (b'[patch] [id 1] [br 0]\n[patch] [id 1] [br 1]\n', 2, [0, 1]),
])
def test_absent_branch_capture_is_unknown_not_fake_empty(text, hits, expected):
    assert observation._branches(text, 1, hits) == expected


@pytest.mark.parametrize('text,hits', [
    (b'[patch] [id 2] [br 1]\n', 1),
    (b'[patch] [id 1] [br 1]\n[patch] [id 2] [br 0]\n', 2),
    (b'[patch] [id 1] [br 2]\n', 1),
    (b'[patch] [id 1] [br 1]\n', 2),
    (b'not a branch row\n', 1),
])
def test_malformed_or_other_patch_branch_channel_is_unavailable(text, hits):
    with pytest.raises(ExecutionUnavailable, match='branch-capture-mismatch'):
        observation._branches(text, 1, hits)


def _control(exit_info='ok', fault_addr=0x10):
    kind = 'end' if exit_info == 'ok' else 'crash'
    fault = (f'[fault-addr] [idx 0] [addr 0x{fault_addr:x}] [symbol main]\n'
             if exit_info == 'crash' and fault_addr is not None else '')
    return (f'[patch-info] [set true] [location 0x10]\n'
            f'[qemu-exit] [kind {kind}] [detail guest]\n'
            f'[exit] [result {exit_info}]\n'
            f'{fault}'
            '[patch-cov] [location 0x10] [covered true] [hits 1]\n').encode()


def _process(monkeypatch, *, stderr, status=7, timeout=False):
    seen = {}
    class Process:
        pid = 987654321
        def __init__(self, command, **options):
            seen.update(command=command, **options)
            options['stderr'].write(stderr)
        def wait(self, timeout=None):
            if timeout is not None and timeout_failure:
                raise observation.subprocess.TimeoutExpired(seen['command'], timeout)
            return status
    timeout_failure = timeout
    monkeypatch.setattr(observation.subprocess, 'Popen', Process)
    monkeypatch.setattr(observation.os, 'killpg', lambda *a: None)
    monkeypatch.setattr(observation.PROCESS_REGISTRY, 'register', lambda p: None)
    monkeypatch.setattr(observation.PROCESS_REGISTRY, 'unregister', lambda p: None)
    return seen


def _runner():
    return SimpleNamespace(
        exec_timeout=0.25,
        get_qemu_stacktrace_command_for_binary=lambda binary, input_file: ['qemu', binary, input_file],
        _normalize_probe=lambda probe, binary: None)


@pytest.mark.parametrize('status', [0, 7, 125, 255])
def test_acknowledged_normal_exit_is_usable_regardless_of_status(tmp_path, monkeypatch, status):
    seen = _process(monkeypatch, stderr=_control(), status=status)
    probe, text = observation._capture(_runner(), 'fixture.orig', 0, {}, tmp_path)
    assert probe.exit_info == 'ok'
    assert seen['command'] == ['qemu', 'fixture.orig', '.observation-input']
    assert seen['stdout'] == observation.subprocess.DEVNULL
    assert seen['stdin'] == observation.subprocess.DEVNULL
    assert seen['start_new_session'] is True
    assert text == b''


def test_guest_crash_is_outcome_not_infrastructure(tmp_path, monkeypatch):
    _process(monkeypatch, stderr=_control('crash'), status=0)
    probe, _ = observation._capture(_runner(), 'fixture.orig', 0, {}, tmp_path)
    assert concrete_outcome(probe) == 'crash'


def test_crash_without_main_image_provenance_is_unavailable(tmp_path, monkeypatch):
    _process(monkeypatch, stderr=_control('crash', fault_addr=None), status=0)
    with pytest.raises(ExecutionUnavailable, match='qasan-crash-identity-unavailable'):
        observation._capture(_runner(), 'fixture.orig', 0, {}, tmp_path)


@pytest.mark.parametrize('artifact', ['fixture.patched', 'fixture.brpatched'])
@pytest.mark.parametrize('raw_pc,identity,expected', [
    (0x1200, None, None),             # E9 runtime PC without an instruction mapping
    (0x1100, 0x10, 0x10),           # exact mapped relocation
    (0x20, None, 0x20),             # evidenced native text outside E9
    (0x3000, None, None),           # outside the original executable image
])
def test_capture_requires_exact_normalized_fault_identity(
        tmp_path, monkeypatch, artifact, raw_pc, identity, expected):
    _process(monkeypatch, stderr=_control('crash', raw_pc), status=0)
    runner = observation._FixedRunner(str(tmp_path), 'fixture', '@@', '0x10')
    runner.observed_artifact = artifact
    runner.observed_metadata = ('0x1000-0x2000', [])
    runner._instruction_native_ranges[str(tmp_path / artifact)] = [(0x10, 0x100)]
    monkeypatch.setattr(runner, 'load_instruction_map',
                        lambda binary: {raw_pc: identity} if identity is not None else {})
    monkeypatch.setattr(runner, 'get_qemu_stacktrace_command_for_binary',
                        lambda binary, input_file: ['qemu', binary, input_file])
    if expected is None:
        with pytest.raises(ExecutionUnavailable, match='qasan-crash-identity-unavailable'):
            observation._capture(runner, artifact, 1, {}, tmp_path)
    else:
        probe, _ = observation._capture(runner, artifact, 1, {}, tmp_path)
        outcome = observation.concrete_result(probe)
        assert outcome['outcome'] == 'crash' and outcome['fault_valid'] is True
        assert outcome['fault_addr'] == expected


def concrete_outcome(probe):
    return observation.concrete_result(probe)['outcome']


@pytest.mark.parametrize('stderr,status,reason', [
    (b'native isolation failed: RuntimeError\n', 125, 'native-isolation'),
    (b'libqasan.so cannot be preloaded\n' + _control(), 0, 'qasan-preload'),
    (b'', 0, 'qasan-outcome'),
    (b'[patch-info] [set true] [location 0x10]\n[exit] [result ok]\n', 0, 'qasan-outcome'),
    (_control(), -9, 'wrapper-terminated'),
])
def test_wrapper_failure_never_becomes_guest_normal(tmp_path, monkeypatch, stderr, status, reason):
    _process(monkeypatch, stderr=stderr, status=status)
    with pytest.raises(ExecutionUnavailable, match=reason):
        observation._capture(_runner(), 'fixture.orig', 0, {}, tmp_path)


def test_partial_normal_control_rows_do_not_override_timeout(tmp_path, monkeypatch):
    _process(monkeypatch, stderr=_control(), timeout=True)
    with pytest.raises(ExecutionUnavailable, match='timeout'):
        observation._capture(_runner(), 'fixture.orig', 0, {}, tmp_path)


def test_standalone_faults_use_their_exact_instruction_map(monkeypatch):
    runner = observation._FixedRunner('/private', 'fixture', '@@', '0x10')
    runner.observed_artifact = 'fixture.patched'
    runner.observed_metadata = ('0x1000-0x2000', [])
    runner._instruction_native_ranges['/private/fixture.patched'] = [(0x10, 0x100)]
    monkeypatch.setattr(runner, 'load_instruction_map', lambda binary: {0x1100: 0x10})
    assert runner.concrete_fault_identity(0x1100, '/private/fixture.patched') == (0x10, 'relocated')
    assert runner.concrete_fault_identity(0x1200, '/private/fixture.patched') == (0x1200, 'unavailable')
    assert runner.concrete_fault_identity(0x10, '/private/fixture.patched') == (0x10, 'native')
    assert runner.concrete_fault_identity(0x1100, '/private/fixture.orig') == (0x1100, 'native')


DIVISION_FIXTURE = r'''
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc != 2) return 90;
    FILE *input = fopen(argv[1], "rb");
    if (!input) return 91;
    int divisor = fgetc(input) - '0';
    fclose(input);
    int quotient = 7, remainder = 0;
    __asm__ volatile(".globl fixture_divide\nfixture_divide:\n\tidivl %%ecx\n"
                     : "+a"(quotient), "+d"(remainder) : "c"(divisor) : "cc");
    return 7;
}
'''


MEMORY_FIXTURE = r'''
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc != 2) return 90;
    FILE *input = fopen(argv[1], "rb");
    if (!input) return 91;
    int use_stack = fgetc(input) - '0';
    fclose(input);
    int value = 7, result;
    int *pointer = use_stack ? &value : 0;
    __asm__ volatile(".globl fixture_load\nfixture_load:\n\tmovl (%1), %0\n"
                     : "=r"(result) : "r"(pointer) : "memory");
    return 7;
}
'''


@pytest.mark.parametrize('fixture,family', [
    (DIVISION_FIXTURE, '369'),
    (MEMORY_FIXTURE, '823'),
])
def test_real_qasan_original_selectable_and_fixed_outcomes(tmp_path, fixture, family):
    """Real prepare/stage/QASAN; only a newly compiled harmless fixture is run.

    Requires the current installed taosc-prepare/taosc-patch-stage toolchain,
    QASAN plus sibling preload, gcc and explicit E9TOOL/E9COMPILE. No dataset,
    cached artifact, benchmark workdir, copied probe, or fabricated trace is used.
    """
    from binradar import paths
    for name in ('gcc', 'taosc-prepare', 'taosc-patch-stage'):
        if shutil.which(name) is None:
            pytest.skip(f'real Single observation requires {name}')
    for name in ('E9TOOL', 'E9COMPILE'):
        if not os.environ.get(name) or shutil.which(os.environ[name]) is None:
            pytest.skip(f'real Single observation requires explicit {name}')
    qemu = Path(paths.QASAN_QEMU_BIN)
    if not qemu.is_file() or not qemu.with_name('libqasan.so').is_file():
        pytest.skip('real Single observation requires QASAN and its sibling library')
    source = tmp_path / 'fixture.c'
    source.write_text(fixture)
    program = tmp_path / 'fixture'
    subprocess.run(['gcc', '-O0', '-g', '-no-pie', str(source), '-o', str(program)],
                   check=True, capture_output=True, timeout=30)
    poc = tmp_path / 'poc'
    poc.mkdir()
    malicious = poc / 'division-by-zero'
    malicious.write_bytes(b'0')
    normal = tmp_path / 'normal'
    normal.write_bytes(b'1')
    work = tmp_path / 'prepared'
    subprocess.run(['taosc-prepare', '5', str(work), str(poc), str(program), '@@'],
                   check=True, capture_output=True, timeout=120)
    location = int((work / 'trace/crash.address').read_text().strip(), 16)
    candidates = [line.split() for line in (work / 'patch-candidates').read_text().splitlines()]
    matching = [row for row in candidates if row and int(row[0], 16) == location]
    assert matching and len(matching[0]) >= 2, 'real preparation must retain the fault-site action association'
    # Scout rows are unvalidated candidates; the first address can loop or crash.
    # This observation test needs the action already accepted by PoC preparation.
    assert int((work / 'patch-location').read_text().strip(), 16) == location
    destination = (work / 'patch-destination').read_text().strip()
    assert int(destination, 16) in {int(value, 16) for value in matching[0][1:]}
    settings = {'BINARY': 'fixture', 'TEST_CMD': '@@', 'PATCH_LOC': f'0x{location:x}',
                'BINRADAR_QEMU_EXEC_TIMEOUT': '5'}
    scratch = tmp_path / 'observations'
    original_bytes = (work / 'fixture.orig').read_bytes()
    crash = observation.observe(work, settings, malicious, artifact='fixture.orig', directory=scratch)
    benign = observation.observe(work, settings, normal, artifact='fixture.orig', directory=scratch)
    assert crash['outcome']['outcome'] == 'crash' and crash['outcome']['fault_addr'] == location
    assert benign['outcome']['outcome'] == 'normal'
    assert crash['patch_hits'] == benign['patch_hits'] == 1
    assert crash['branches'] is benign['branches'] is None
    subprocess.run(['taosc-patch-stage', '5', str(work), f'Single CWE-{family}',
                    f'{location:x}', destination],
                   check=True, capture_output=True, timeout=60)
    for artifact in ('fixture.brpatched', 'fixture.patched'):
        neutral = observation.observe(work, settings, malicious, artifact=artifact,
                                      directory=scratch, patch_id=0)
        repaired = observation.observe(work, settings, malicious, artifact=artifact,
                                       directory=scratch, patch_id=1)
        unchanged = observation.observe(work, settings, normal, artifact=artifact,
                                        directory=scratch, patch_id=1)
        assert neutral['outcome']['outcome'] == 'crash'
        assert neutral['outcome']['fault_addr'] == crash['outcome']['fault_addr']
        assert repaired['outcome']['outcome'] == 'normal'
        assert unchanged['outcome']['outcome'] == 'normal'
        assert neutral['patch_hits'] == repaired['patch_hits'] == unchanged['patch_hits'] == 1
        assert neutral['branches'] == unchanged['branches'] == [0]
        assert repaired['branches'] == [1]
        assert repaired['artifact_sha256'] == sha256(work / artifact)
    assert (work / 'fixture.orig').read_bytes() == original_bytes
    assert malicious.read_bytes() == b'0' and normal.read_bytes() == b'1'
    assert list(scratch.iterdir()) == []
