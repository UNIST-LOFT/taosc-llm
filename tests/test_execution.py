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
        self.manifest = {'artifacts': {
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


def test_private_qasan_command_always_uses_fail_closed_launcher(tmp_path):
    runner = execution._PrivateRunner(str(tmp_path), 'fixture', '@@', '0x10')
    command = runner.get_qemu_stacktrace_command_for_binary(str(tmp_path / 'fixture.brcached'), str(tmp_path / 'input'))
    assert command[1:3] == ['-I', '-S']
    assert command[3].endswith('/_sandbox.py')
    assert command[command.index('--scratch') + 1] == str(tmp_path)
    assert '--asan' in command


def test_pie_candidate_capability_is_explicit_not_false_execution(tmp_path):
    import pytest
    dataset = FixtureDataset(tmp_path)
    header = bytearray(20)
    header[:6] = b'\x7fELF\x02\x01'
    header[16:18] = (3).to_bytes(2, 'little')
    dataset.artifact('fixture.brcached').write_bytes(header)
    dataset.manifest['artifacts']['fixture.brcached']['sha256'] = execution.sha256(dataset.artifact('fixture.brcached'))
    case = {'input_path': 'input', 'input_sha256': execution.sha256(tmp_path / 'input')}
    with pytest.raises(execution.ExecutionUnavailable, match='pie-descriptor-relocation-capability-unavailable'):
        execution.execute_capture(dataset, case, 'p1', tmp_path / 'owned')
