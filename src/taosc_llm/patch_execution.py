"""Actual, isolated QASAN observations of originals and fixed Single artifacts.

The compatibility tracer writes control records to stderr, not stdout. Its guest
exit syscalls preserve the guest's low-byte exit status; a nonzero *normal* exit
is not an infrastructure failure. Observations authenticate the acknowledged
outcome and available branch capture, not target output or external effects.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile

import elftools
import sbsv
from binradar import binradar_setup, paths
from binradar import binradar_verifier as verifier
from binradar.binradar_feedback_capture import concrete_result
from binradar.binradar_runtime import PROCESS_REGISTRY

from .execution import ExecutionUnavailable, _PrivateRunner, sha256
from .native import native_environment, run_native


_DIAGNOSTIC_LIMIT = 1024 * 1024


def _copy(source: Path, destination: Path) -> str:
    """Bind a regular source and private copy, rejecting concurrent writes."""
    if source.is_symlink() or not source.is_file():
        raise ExecutionUnavailable(f'required-regular-file-unavailable: {source.name}')
    before = source.stat()
    identity = sha256(source)
    shutil.copyfile(source, destination)
    shutil.copymode(source, destination)
    after = source.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
            before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                   after.st_mtime_ns, after.st_ctime_ns) or (
            sha256(source) != identity or sha256(destination) != identity):
        raise ExecutionUnavailable(f'copied-file-identity-mismatch: {source.name}')
    return identity


def _metadata(work: Path, artifact: str, original: str, location: int,
              timeout: float) -> tuple[str, list[str]]:
    """Extract identities from this exact binary/JSON pair under a finite cap.

    The ordinary extractor invokes objdump without a timeout. Keep it in an
    owned sandboxed process; never let it modify producer sidecars or inherit
    Python/provider configuration. Only the three trusted runtime packages are
    exposed, not their enclosing checkout or the source workdir.
    """
    packages = [Path(module.__file__).resolve().parent
                for module in (binradar_setup, sbsv, elftools)]
    roots = list(dict.fromkeys(str(p.parent) for p in packages))
    # A venv interpreter reads <prefix>/pyvenv.cfg during site initialization,
    # before our explicit sys.path insertion. Landlock must admit that file or
    # every fixed-artifact observation fails before metadata extraction.
    for prefix in (sys.prefix, sys.base_prefix):
        if prefix and prefix not in roots:
            roots.append(prefix)
    code = (
        'import sys; from pathlib import Path; '
        f'sys.path[:0] = {roots!r}; '
        'from binradar.binradar_setup import extract_e9_runtime_metadata; '
        f'm = extract_e9_runtime_metadata(Path({artifact!r}), '
        f'Path({(artifact + ".json")!r}), Path({original!r}), {location!r}); '
        'import json; Path(".observation-e9.json").write_text(json.dumps('
        '[m.exclude_ranges_str(), m.relocated_calls_str()]))'
    )
    run_native([sys.executable, '-I', '-c', code], work,
               timeout=max(1, math.ceil(timeout)),
               readable=tuple(Path(root) for root in roots))
    ranges, calls = json.loads((work / '.observation-e9.json').read_text())
    return ranges, calls.split(',') if calls else []


class _FixedRunner(_PrivateRunner):
    """Extend exact E9 normalization to standalone .patched, without aliases."""

    def e9_metadata_for_binary(self, binary):
        if Path(binary).name == self.observed_artifact:
            return self.observed_metadata
        return '', []

    def concrete_fault_identity(self, fault_addr, binary=None):
        if binary is None or Path(binary).name != self.observed_artifact:
            return fault_addr, 'native'
        mapping = self.load_instruction_map(binary)
        if fault_addr in mapping:
            return mapping[fault_addr], 'relocated'
        ranges, _ = self.e9_metadata_for_binary(binary)
        native = self._instruction_native_ranges[os.path.abspath(binary)]
        if not verifier.addr_in_e9_ranges(fault_addr, ranges) and (
                fault_addr == 0 or any(start <= fault_addr < end for start, end in native)):
            return fault_addr, 'native'
        return fault_addr, 'unavailable'


def _capture(runner, artifact: str, patch_id: int, environment: dict,
             work: Path) -> tuple[object, bytes]:
    """Own the process session and diagnostics; require a guest acknowledgment."""
    command = runner.get_qemu_stacktrace_command_for_binary(artifact, '.observation-input')
    process = None
    with tempfile.TemporaryFile(dir=work) as errors, tempfile.TemporaryFile(dir=work) as patch:
        settings = dict(environment, PATCH_FD=str(patch.fileno()))
        try:
            process = subprocess.Popen(command, cwd=work, env=settings,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=errors, pass_fds=(patch.fileno(),),
                                       start_new_session=True)
            PROCESS_REGISTRY.register(process)
            try:
                status = process.wait(timeout=runner.exec_timeout)
            except subprocess.TimeoutExpired as exc:
                raise ExecutionUnavailable('timeout') from exc
        finally:
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                PROCESS_REGISTRY.unregister(process)
        errors.seek(0)
        stderr = errors.read(_DIAGNOSTIC_LIMIT + 1)
        patch.seek(0)
        text = patch.read(_DIAGNOSTIC_LIMIT + 1)
        if len(stderr) > _DIAGNOSTIC_LIMIT or len(text) > _DIAGNOSTIC_LIMIT:
            raise ExecutionUnavailable('observation-diagnostic-limit')
        diagnostics = stderr.decode('utf-8', errors='replace')
        if 'native isolation failed:' in diagnostics:
            raise ExecutionUnavailable('native-isolation-unavailable')
        if any('libqasan.so' in line and 'cannot be preloaded' in line
               for line in diagnostics.splitlines()):
            raise ExecutionUnavailable('qasan-preload-unavailable')
        # A host signal is not an acknowledged guest outcome. The wrapper emits
        # guest crashes as control rows then exits normally; guest exit(125),
        # unlike a launcher failure, has an authenticated end acknowledgment.
        if status < 0:
            raise ExecutionUnavailable(f'wrapper-terminated-by-signal: {-status}')
        probe = verifier.BinRadarProbeResult.from_log(diagnostics)
        if probe is not None and probe.exit_info == 'timeout':
            raise ExecutionUnavailable('timeout')
        if (probe is None or probe.exit_info not in ('ok', 'crash')
                or probe.concrete_oracle != verifier.CONCRETE_ORACLE):
            raise ExecutionUnavailable('qasan-outcome-unavailable')
        runner._normalize_probe(probe, str(work / artifact))
        if probe.exit_info == 'crash' and probe.concrete_fault_addr is None:
            raise ExecutionUnavailable('qasan-crash-identity-unavailable')
        return probe, text


def _branches(text: bytes, patch_id: int, hits: int) -> list[int] | None:
    if not text:
        return [] if hits == 0 else None
    # Do not let the ordinary parser silently discard a second patch ID.
    parser = verifier.BinRadarPatchResult.line_parser
    branches = []
    for line in text.decode('utf-8', errors='strict').splitlines():
        row = parser.parse_line_detached(line)
        if (row is None or row.get_name() != 'patch' or row['id'] != patch_id
                or type(row['br']) is not int or row['br'] not in (0, 1)):
            raise ExecutionUnavailable('branch-capture-mismatch')
        branches.append(row['br'])
    if len(branches) != hits:
        raise ExecutionUnavailable('branch-capture-mismatch')
    return branches


def observe(workdir: Path, environment: dict, input_path: Path, *, artifact: str,
            directory: Path, patch_id: int = 0) -> dict:
    """Observe an immutable original or fixed artifact in a private sandbox.

    ``environment`` supplies BINARY, TEST_CMD, PATCH_LOC and an optional finite
    BINRADAR_QEMU_EXEC_TIMEOUT (default 60s). No environment entry is inherited
    by the native guest except these parsed settings. Only basename arguments
    are accepted for artifacts; .brcached is intentionally unsupported. Fixed
    artifacts require their own e9tool .json; extraction produces a fresh bound
    .e9map.json privately, never borrowing persisted execution environments.

    ``branches=None`` means the artifact has no complete branch channel; it is
    not fabricated branch preservation. Infrastructure, missing acknowledgment,
    timeout and changing source bytes fail closed.
    """
    try:
        settings = {name: environment[name] for name in (
            'BINARY', 'TEST_CMD', 'PATCH_LOC', 'BINRADAR_QEMU_EXEC_TIMEOUT')
            if name in environment}
        binary = settings.get('BINARY')
        if (not isinstance(binary, str) or not re.fullmatch(r'[A-Za-z0-9_.+-]+', binary)
                or binary in ('.', '..')):
            raise ExecutionUnavailable('invalid-binary-basename')
        if not isinstance(artifact, str) or artifact not in (
                binary + '.orig', binary + '.patched', binary + '.brpatched'):
            raise ExecutionUnavailable('invalid-observation-artifact')
        if type(patch_id) is not int or not 0 <= patch_id <= 0x7fffffff:
            raise ExecutionUnavailable('invalid-patch-id')
        if artifact.endswith('.orig') and patch_id != 0:
            raise ExecutionUnavailable('original-requires-patch-id-zero')
        location = settings.get('PATCH_LOC')
        if not isinstance(location, str) or not re.fullmatch(r'0[xX][0-9a-fA-F]{1,16}', location):
            raise ExecutionUnavailable('invalid-patch-location')
        if not int(location, 16):
            raise ExecutionUnavailable('invalid-patch-location')
        if not isinstance(settings.get('TEST_CMD'), str):
            raise ExecutionUnavailable('invalid-test-command')
        workdir = Path(workdir).resolve(strict=True)
        input_path = Path(input_path)
        directory = Path(directory).resolve()
        if directory == workdir or directory.is_relative_to(workdir):
            raise ExecutionUnavailable('scratch-directory-overlaps-source')
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(prefix='observation-', dir=directory) as temporary:
            work = Path(temporary)
            # Explicit allowlist: no experiment outputs, cache, credentials,
            # source symlinks, or unrelated artifacts enter the owned worker.
            original = binary + '.orig'
            originals = {original: _copy(workdir / original, work / original)}
            if artifact != original:
                originals[artifact] = _copy(workdir / artifact, work / artifact)
                originals[artifact + '.json'] = _copy(
                    workdir / (artifact + '.json'), work / (artifact + '.json'))
            input_hash = _copy(input_path, work / '.observation-input')
            configured = verifier.BinRadarQemuRunner.from_env(str(work), settings)
            runner = _FixedRunner(
                configured.dir, configured.binary, configured.test_cmd, configured.patch_loc,
                {}, configured.patch_kind, configured.brcache_stack_size, configured.exec_timeout)
            runner.observed_artifact = artifact if artifact != original else None
            runner.observed_metadata = ('', [])
            if artifact != original:
                runner.observed_metadata = _metadata(
                    work, artifact, original, int(location, 16), runner.exec_timeout)
                runner.load_instruction_map(str(work / artifact))
            # CWE-823 initializes its output before the patch selector and
            # proc maps. Supply an owned capability even when no snapshots are
            # requested; never inherit TAOSC_OUTPUT or write into the source.
            output_path = work / '.observation-output'
            descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
            native = native_environment()
            native.update(HOME=str(work), TMPDIR=str(work), LC_ALL='C',
                          AFL_PATH=str(Path(paths.QASAN_QEMU_BIN).resolve().parent),
                          AFL_USE_QASAN='1', PATCH_ID=str(patch_id),
                          TAOSC_OUTPUT=str(output_path))
            ranges, _ = runner.e9_metadata_for_binary(str(work / artifact))
            if ranges:
                native['AFL_QEMU_INST_RANGES'] = ranges
            probe, text = _capture(runner, artifact, patch_id, native, work)
            if probe.patch_loc != int(location, 16) or type(probe.patch_hit_cnt) is not int or probe.patch_hit_cnt < 0:
                raise ExecutionUnavailable('probe-site-or-hit-mismatch')
            branches = _branches(text, patch_id, probe.patch_hit_cnt) if artifact != original else None
            # Target execution may write its scratch files. Such modification
            # cannot change which immutable bytes this observation authenticates.
            for name, digest in originals.items():
                if sha256(workdir / name) != digest or sha256(work / name) != digest:
                    raise ExecutionUnavailable(f'executed-artifact-changed: {name}')
            if sha256(input_path) != input_hash or sha256(work / '.observation-input') != input_hash:
                raise ExecutionUnavailable('executed-input-changed')
            return {'artifact_sha256': originals[artifact], 'input_sha256': input_hash,
                    'outcome': concrete_result(probe), 'patch_hits': probe.patch_hit_cnt,
                    'probe': probe.serialize(), 'branches': branches}
    except ExecutionUnavailable:
        raise
    except (OSError, ValueError, TypeError, KeyError, RuntimeError,
            subprocess.SubprocessError) as exc:
        raise ExecutionUnavailable(f'observation-unavailable: {type(exc).__name__}: {exc}') from exc
