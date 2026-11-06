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


@pytest.mark.parametrize('artifact,selector', [('selectable', 1), ('selectable', 0), ('fixed', 0)])
def test_built_execution_runs_id1_and_uses_its_exact_metadata(tmp_path, monkeypatch, artifact, selector):
    from binradar import binradar_setup
    dataset = FixtureDataset(tmp_path)
    case = {'input_path': 'input', 'input_sha256': execution.sha256(tmp_path / 'input')}
    source = tmp_path / 'built'
    source.mkdir()
    artifacts = {}
    for name, payload in (('fixture.brpatched', b'actual-selected'),
                          ('fixture.brpatched.json', b'exact-json'),
                          ('fixture.brpatched.e9map.json', b'exact-map'),
                          ('fixture.patched', b'actual-fixed'),
                          ('fixture.patched.json', b'fixed-json'),
                          ('fixture.patched.e9map.json', b'fixed-map')):
        path = source / name
        path.write_bytes(payload)
        artifacts[name] = str(path)
    build = {'descriptor': 'p1', 'patch_location': '0x10', 'artifacts': artifacts,
             'artifact_hashes': {name: execution.sha256(Path(path)) for name, path in artifacts.items()}}
    observed = []
    expected_binary = b'actual-fixed' if artifact == 'fixed' else b'actual-selected'
    expected_json = b'fixed-json' if artifact == 'fixed' else b'exact-json'
    expected_map = b'fixed-map' if artifact == 'fixed' else b'exact-map'
    runtime_id = 1 if artifact == 'fixed' else selector
    def metadata(binary, json_path, original, location):
        assert binary.name == 'fixture.brpatched' and binary.read_bytes() == expected_binary
        assert json_path.read_bytes() == expected_json
        assert original.read_bytes() == b'harmless' and location == 0x10
        Path(str(binary) + '.e9map.json').write_bytes(expected_map)
        return SimpleNamespace(exclude_ranges_str=lambda: '0x200-0x300',
                               relocated_calls_str=lambda: '0x210:0x10:0x15')
    def configure(directory, environment):
        assert environment['BRPATCHED_E9_EXCLUDE_RANGES'] == '0x200-0x300'
        assert environment['BRPATCHED_E9_RELOCATED_CALL_JUMPS'] == '0x210:0x10:0x15'
        return SimpleNamespace(dir=directory, binary='fixture', test_cmd='@@', patch_loc='0x10',
                               e9_metadata={}, patch_kind='generic-erm', brcache_stack_size=0, exec_timeout=5)
    class Runner:
        def __init__(self, directory, *args):
            self.dir = directory
            self.brcache_stack_size = 0
        def load_instruction_map(self, binary):
            assert Path(binary + '.e9map.json').read_bytes() == expected_map
        def e9_metadata_for_binary(self, binary):
            return '0x200-0x300', []
        def _test_with_capture(self, binary, patch_id, input_file, *, capture_cached, base_env):
            assert Path(binary).name == 'fixture.brpatched'
            assert Path(binary).read_bytes() == expected_binary
            # copyfile creates mode 0644 by default; QEMU cannot execute it.
            assert Path(binary).stat().st_mode & 0o111
            assert patch_id == str(selector) and base_env['PATCH_ID'] == str(selector)
            assert base_env['AFL_QEMU_INST_RANGES'] == '0x200-0x300'
            assert not capture_cached
            observed.append(self.dir)
            self.run_results = SimpleNamespace(success=True, timed_out=False)
            return SimpleNamespace(exit_info='ok', patch_hit_cnt=4, concrete_fault_addr=None,
                                   concrete_oracle='qasan-main-v2'), b'ordered text rows', None
    monkeypatch.setattr(binradar_setup, 'extract_e9_runtime_metadata', metadata)
    monkeypatch.setattr(execution.verifier.BinRadarQemuRunner, 'from_env', configure)
    monkeypatch.setattr(execution, '_PrivateRunner', Runner)
    monkeypatch.setattr(execution.verifier.BinRadarPatchResult, 'from_log',
                        lambda text: SimpleNamespace(patch_id=runtime_id, br_selection=[0, 1, 0, 1]))
    result = execution.execute_built(dataset, case, build, tmp_path / 'owned',
                                     artifact=artifact, patch_id=selector)
    assert result['branches'] == [0, 1, 0, 1] and result['patch_id'] == runtime_id
    assert result['artifact'] == artifact
    suffix = '.patched' if artifact == 'fixed' else '.brpatched'
    assert result['artifact_sha256'] == build['artifact_hashes']['fixture' + suffix]
    assert observed and not Path(observed[0]).exists()
    assert Path(artifacts['fixture.brpatched.e9map.json']).read_bytes() == b'exact-map'
