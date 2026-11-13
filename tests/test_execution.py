"""Exercise per-execution ownership without running a target or a provider."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from taosc_llm import execution


class FixtureDataset:
    binary = 'fixture'
    patch_format = 'ERM generic'

    def __init__(self, root):
        self.root = root
        self.workdir = root / 'frozen'
        self.workdir.mkdir()
        for name in ('fixture.orig', 'fixture.brcached'):
            (self.workdir / name).write_bytes(b'harmless')
        (root / 'input').write_bytes(b'input')
        self.manifest = {'patch': {'location': 0x10, 'destination': 0x20},
                         'artifacts': {
                             path.name: {'sha256': execution.sha256(path)}
                             for path in self.workdir.iterdir()}}

    def artifact(self, name):
        return self.workdir / name

    def execution_environment(self):
        return {'BINARY': self.binary, 'TEST_CMD': '@@', 'PATCH_LOC': '0x10'}


def test_each_execution_owns_runner_cwd_env_input_and_capture_channels(tmp_path, monkeypatch):
    dataset = FixtureDataset(tmp_path)
    case = {'input_path': 'input', 'input_sha256': execution.sha256(tmp_path / 'input')}
    observed = []
    class Runner:
        def __init__(self, directory, binary, test_cmd, patch_loc, metadata, kind, stack, timeout):
            self.dir = directory
            self.brcache_stack_size = stack
            self.run_results = None
        def load_instruction_map(self, binary):
            assert Path(binary).parent == Path(self.dir)
        def e9_metadata_for_binary(self, binary):
            return '', []
        def _test_with_capture(self, binary, patch_id, input_file, *, capture_cached, base_env):
            assert capture_cached
            assert Path(input_file).parent == Path(self.dir)
            assert Path(input_file).read_bytes() == b'input'
            assert 'TEST_PROVIDER_SECRET' not in base_env
            assert 'PYTHONPATH' not in base_env
            assert 'LD_PRELOAD' not in base_env
            observed.append((self, self.dir, input_file, base_env))
            Path(self.dir, 'private-output').write_bytes(b'worker-local')
            self.run_results = SimpleNamespace(success=True, timed_out=False)
            probe = SimpleNamespace(exit_info='ok', patch_hit_cnt=0, concrete_fault_addr=None,
                                    concrete_oracle='qasan-main-v2')
            return probe, b'', b''
    def configure(directory, environment):
        return SimpleNamespace(dir=directory, binary='fixture', test_cmd='@@', patch_loc='0x10',
                               e9_metadata={}, patch_kind='generic-erm', brcache_stack_size=0, exec_timeout=5)
    monkeypatch.setattr(execution.verifier.BinRadarQemuRunner, 'from_env', configure)
    monkeypatch.setattr(execution, '_PrivateRunner', Runner)
    monkeypatch.setenv('TEST_PROVIDER_SECRET', 'must-not-reach-target')
    monkeypatch.setenv('PYTHONPATH', '/private/python')
    monkeypatch.setenv('LD_PRELOAD', '/private/preload')
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: execution.execute_capture(dataset, case, 'p0', tmp_path / 'owned'), range(2)))
    assert len({item[1] for item in observed}) == 2
    assert observed[0][0] is not observed[1][0]
    assert observed[0][3] is not observed[1][3]
    assert all(r['complete'] and r['branches'] == [] for r in results)
    assert not (dataset.workdir / 'private-output').exists()
    assert all(not Path(item[1]).exists() for item in observed)


def test_original_observation_runs_orig_without_neutral_state_channel(tmp_path, monkeypatch):
    dataset = FixtureDataset(tmp_path)
    case = {'input_path': 'input', 'input_sha256': execution.sha256(tmp_path / 'input')}
    observed = []
    class Runner:
        def __init__(self, directory, binary, test_cmd, patch_loc, metadata, kind, stack, timeout):
            self.dir = directory
            self.brcache_stack_size = stack
            self.run_results = None
        def load_instruction_map(self, binary):
            pytest.fail('original observation must not load a cached instruction map')
        def e9_metadata_for_binary(self, binary):
            return '', []
        def _test_with_capture(self, binary, patch_id, input_file, *, capture_cached, base_env):
            assert Path(binary).name == 'fixture.orig'
            assert not capture_cached
            assert Path(binary).read_bytes() == dataset.artifact('fixture.orig').read_bytes()
            assert Path(input_file).read_bytes() == b'input'
            assert 'TEST_PROVIDER_SECRET' not in base_env
            observed.append(self.dir)
            self.run_results = SimpleNamespace(success=True, timed_out=False)
            return SimpleNamespace(exit_info='crash', concrete_fault_addr=33, patch_hit_cnt=3,
                                   concrete_oracle='qasan-main-v2'), None, None
    monkeypatch.setattr(execution.verifier.BinRadarQemuRunner, 'from_env',
                        lambda directory, environment: SimpleNamespace(
                            dir=directory, binary='fixture', test_cmd='@@', patch_loc='0x10',
                            e9_metadata={}, patch_kind='generic-erm', brcache_stack_size=0, exec_timeout=5))
    monkeypatch.setattr(execution, '_PrivateRunner', Runner)
    monkeypatch.setenv('TEST_PROVIDER_SECRET', 'must-not-reach-target')
    result = execution.execute_original(dataset, case, tmp_path / 'owned')
    assert result['artifact_sha256'] == execution.sha256(dataset.artifact('fixture.orig'))
    assert result['outcome']['outcome'] == 'crash'
    assert result['patch_hits'] == 3
    assert 'path' not in result and 'branches' not in result
    assert observed and not Path(observed[0]).exists()


def test_relative_cache_directory_resolves_before_launch(tmp_path, monkeypatch):
    """The launcher cwd is the scratch dir; a relative --scratch used to double."""
    dataset = FixtureDataset(tmp_path)
    case = {'input_path': 'input', 'input_sha256': execution.sha256(tmp_path / 'input')}
    seen = []
    class Runner:
        def __init__(self, directory, binary, test_cmd, patch_loc, metadata, kind, stack, timeout):
            self.dir = directory
            self.brcache_stack_size = stack
            self.run_results = None
        def load_instruction_map(self, binary):
            pass
        def e9_metadata_for_binary(self, binary):
            return '', []
        def _test_with_capture(self, binary, patch_id, input_file, *, capture_cached, base_env):
            seen.append(Path(self.dir))
            self.run_results = SimpleNamespace(success=True, timed_out=False)
            return SimpleNamespace(exit_info='ok', patch_hit_cnt=0, concrete_fault_addr=None,
                                   concrete_oracle='qasan-main-v2'), b'', b''
    monkeypatch.setattr(execution.verifier.BinRadarQemuRunner, 'from_env',
                        lambda directory, environment: SimpleNamespace(
                            dir=directory, binary='fixture', test_cmd='@@', patch_loc='0x10',
                            e9_metadata={}, patch_kind='generic-erm', brcache_stack_size=0,
                            exec_timeout=5))
    monkeypatch.setattr(execution, '_PrivateRunner', Runner)
    monkeypatch.chdir(tmp_path)
    result = execution.execute_capture(dataset, case, 'p0', Path('relative-cache'))
    assert result['complete']
    # The worker must be rooted at the resolved absolute cache path, not a path
    # that the launcher would re-resolve relative to that same directory.
    assert seen and seen[0].is_absolute()
    assert (tmp_path / 'relative-cache') in seen[0].parents


@pytest.mark.parametrize('changed', ['fixture.orig', 'fixture.brcached', '.evaluation-input'])
def test_changed_private_copy_never_reaches_runner(tmp_path, monkeypatch, changed):
    dataset = FixtureDataset(tmp_path)
    case = {'input_path': 'input', 'input_sha256': execution.sha256(tmp_path / 'input')}
    copy = execution.shutil.copyfile

    def change_copy(source, destination, *args, **kwargs):
        result = copy(source, destination, *args, **kwargs)
        if Path(destination).name == changed:
            Path(destination).write_bytes(b'changed benign fixture')
        return result

    def forbidden_runner(*args, **kwargs):
        pytest.fail('changed copied bytes must fail before constructing a runner')

    monkeypatch.setattr(execution.shutil, 'copyfile', change_copy)
    monkeypatch.setattr(execution.verifier.BinRadarQemuRunner, 'from_env', forbidden_runner)
    reason = 'copied-input-mismatch' if changed == '.evaluation-input' else 'copied-artifact-mismatch'
    with pytest.raises(execution.ExecutionUnavailable, match=reason):
        execution.execute_capture(dataset, case, 'p0', tmp_path / 'owned')
    assert dataset.artifact('fixture.orig').read_bytes() == b'harmless'
    assert (tmp_path / 'input').read_bytes() == b'input'


def test_private_qasan_command_always_uses_fail_closed_launcher(tmp_path, monkeypatch):
    runtime = tmp_path / 'host-runtime'
    runtime.mkdir()
    qemu = runtime / 'afl-qemu-trace'
    qemu.write_bytes(b'host tracer')
    library = runtime / 'libqasan.so'
    library.write_bytes(b'host preload')
    library.chmod(0o500)
    monkeypatch.setattr(execution.paths, 'QASAN_QEMU_BIN', str(qemu))
    runner = execution._PrivateRunner(str(tmp_path), 'fixture', '@@', '0x10')
    command = runner.get_qemu_stacktrace_command_for_binary(str(tmp_path / 'fixture.brcached'), str(tmp_path / 'input'))
    assert command[1:3] == ['-I', '-S']
    assert command[3].endswith('/_sandbox.py')
    assert command[command.index('--scratch') + 1] == str(tmp_path)
    assert '--asan' in command
    reads = [command[index + 1] for index, value in enumerate(command) if value == '--read']
    assert str(qemu) in reads
    assert str(library) in reads
    assert str(runtime) not in reads  # Never expose the whole checkout directory.


@pytest.mark.parametrize('present', [False, True])
def test_private_qasan_command_requires_loadable_sibling(tmp_path, monkeypatch, present):
    qemu = tmp_path / 'afl-qemu-trace'
    qemu.write_bytes(b'host tracer')
    if present:
        library = qemu.with_name('libqasan.so')
        library.write_bytes(b'non-executable preload')
        library.chmod(0o400)
    monkeypatch.setattr(execution.paths, 'QASAN_QEMU_BIN', str(qemu))
    runner = execution._PrivateRunner(str(tmp_path), 'fixture', '@@', '0x10')
    with pytest.raises(execution.ExecutionUnavailable, match='qasan-library-unavailable'):
        runner.get_qemu_stacktrace_command_for_binary(str(tmp_path / 'fixture.orig'), str(tmp_path / 'input'))


def test_execution_identity_binds_qasan_preload_bytes(tmp_path, monkeypatch):
    qemu = tmp_path / 'afl-qemu-trace'
    qemu.write_bytes(b'host tracer')
    library = qemu.with_name('libqasan.so')
    library.write_bytes(b'preload one')
    monkeypatch.setattr(execution.paths, 'QASAN_QEMU_BIN', str(qemu))
    first = execution.execution_identity()
    library.write_bytes(b'preload two')
    second = execution.execution_identity()
    assert first['qemu'] == second['qemu']
    assert first['qasan_library'] != second['qasan_library']
    library.unlink()
    assert execution.execution_identity()['qasan_library'] is None


@pytest.mark.parametrize('original', [False, True])
def test_silent_preload_failure_is_not_an_observation(tmp_path, monkeypatch, original):
    dataset = FixtureDataset(tmp_path)
    case = {'input_path': 'input', 'input_sha256': execution.sha256(tmp_path / 'input')}
    class Runner:
        def __init__(self, directory, binary, test_cmd, patch_loc, metadata, kind, stack, timeout):
            self.dir = directory
            self.brcache_stack_size = stack
        def load_instruction_map(self, binary):
            pass
        def e9_metadata_for_binary(self, binary):
            return '', []
        def _test_with_capture(self, binary, patch_id, input_file, *, capture_cached, base_env):
            assert base_env['AFL_PATH'] == str(Path(execution.paths.QASAN_QEMU_BIN).resolve().parent)
            self.run_results = SimpleNamespace(
                success=True, timed_out=False,
                stderr="ERROR: ld.so: object '/host/libqasan.so' from LD_PRELOAD cannot be preloaded (cannot open shared object file): ignored.\n")
            return SimpleNamespace(exit_info='ok', patch_hit_cnt=0, concrete_fault_addr=None,
                                   concrete_oracle='qasan-main-v2'), b'', b''
    monkeypatch.setattr(execution.verifier.BinRadarQemuRunner, 'from_env',
                        lambda directory, environment: SimpleNamespace(
                            dir=directory, binary='fixture', test_cmd='@@', patch_loc='0x10',
                            e9_metadata={}, patch_kind='generic-erm', brcache_stack_size=0, exec_timeout=5))
    monkeypatch.setattr(execution, '_PrivateRunner', Runner)
    monkeypatch.setenv('AFL_PATH', '/untrusted-parent-runtime')
    with pytest.raises(execution.ExecutionUnavailable, match='qasan-preload-unavailable'):
        if original:
            execution.execute_original(dataset, case, tmp_path / 'owned')
        else:
            execution.execute_capture(dataset, case, 'p0', tmp_path / 'owned')


@pytest.mark.parametrize('destination', [0, 0x20])
def test_pie_candidate_capability_is_explicit_not_false_execution(tmp_path, destination):
    dataset = FixtureDataset(tmp_path)
    dataset.manifest['patch']['destination'] = destination
    header = bytearray(20)
    header[:6] = b'\x7fELF\x02\x01'
    header[16:18] = (3).to_bytes(2, 'little')
    dataset.artifact('fixture.brcached').write_bytes(header)
    dataset.manifest['artifacts']['fixture.brcached']['sha256'] = execution.sha256(dataset.artifact('fixture.brcached'))
    case = {'input_path': 'input', 'input_sha256': execution.sha256(tmp_path / 'input')}
    with pytest.raises(execution.ExecutionUnavailable, match='pie-descriptor-relocation-capability-unavailable'):
        execution.execute_capture(dataset, case, 'p1', tmp_path / 'owned')



