"""Private, fail-closed concrete execution using BinRadar's QASAN protocol."""
from __future__ import annotations

import hashlib
import math
import os
from pathlib import Path
import shutil
import sys
import tempfile
from importlib.resources import files

from binradar import paths
from binradar import binradar_verifier as verifier
from binradar.binradar_feedback_capture import concrete_result
from binradar.binradar_taosc_predicates import parse_cached_snapshots

from .native import _SYSTEM_READ
from .provider import native_environment


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


class ExecutionUnavailable(RuntimeError):
    """An execution capability is missing; it is never a passing observation."""


class _PrivateRunner(verifier.BinRadarQemuRunner):
    def get_qemu_stacktrace_command_for_binary(self, binary, input_file, patch_func_entry=0):
        command = super().get_qemu_stacktrace_command_for_binary(binary, input_file, patch_func_entry)
        command[0] = str(Path(command[0]).resolve())
        launcher = str(files('taosc_llm').joinpath('_sandbox.py'))
        argv = [sys.executable, '-I', '-S', launcher, '--scratch', self.dir,
                '--qemu-self-maps', '--timeout', str(max(1, math.ceil(self.exec_timeout)))]
        for root in (*_SYSTEM_READ, command[0]):
            argv.extend(('--read', str(root)))
        return [*argv, '--', *command]


def execute_capture(dataset, case: dict, descriptor: str, directory: Path) -> dict:
    """Run an explicit descriptor (including neutral p0), never manifest selection.

    Every call owns a copied artifact tree, input, environment, cwd and runner.
    The ordinary collector's empty-manifest fallback is deliberately not used.
    """
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix='execution-', dir=directory) as temporary:
        scratch = Path(temporary)
        work = scratch / 'work'
        shutil.copytree(dataset.workdir, work, symlinks=False)
        # Only frozen artifacts may enter a worker. Dataset validation binds them.
        binary = work / (dataset.binary + '.brcached')
        original = work / (dataset.binary + '.orig')
        if not binary.is_file() or not original.is_file():
            raise ExecutionUnavailable('cached-artifact-unavailable')
        artifact_hash = sha256(binary)
        for name, record in dataset.manifest['artifacts'].items():
            try:
                relative = dataset.artifact(name).relative_to(dataset.workdir)
            except ValueError:
                # Provenance outside the frozen workdir is not a worker input.
                continue
            copied = work / relative
            if not copied.is_file() or sha256(copied) != record['sha256']:
                raise ExecutionUnavailable('copied-artifact-mismatch')
        # Existing cached PIE builds have not established descriptor relocation
        # parity. p0 cannot take a repair destination; candidate repair must not
        # be inferred from that baseline or silently executed with wrong VAs.
        with binary.open('rb') as stream:
            header = stream.read(20)
        if (len(header) >= 18 and header[:4] == b'\x7fELF'
                and int.from_bytes(header[16:18], 'little' if header[5] == 1 else 'big') == 3
                and descriptor != 'p0'):
            raise ExecutionUnavailable('pie-descriptor-relocation-capability-unavailable')
        source = (dataset.root / case['input_path']).resolve(strict=True)
        if sha256(source) != case['input_sha256']:
            raise ExecutionUnavailable('input-identity-mismatch')
        input_file = work / '.evaluation-input'
        shutil.copyfile(source, input_file)
        if sha256(input_file) != case['input_sha256']:
            raise ExecutionUnavailable('copied-input-mismatch')
        settings = dataset.execution_environment()
        configured = verifier.BinRadarQemuRunner.from_env(str(work), settings)
        runner = _PrivateRunner(
            configured.dir, configured.binary, configured.test_cmd, configured.patch_loc,
            configured.e9_metadata, configured.patch_kind, configured.brcache_stack_size,
            configured.exec_timeout)
        runner.load_instruction_map(str(binary))
        environment = native_environment()
        environment.update(HOME=str(work), TMPDIR=str(work), LC_ALL='C',
                           AFL_USE_QASAN='1', PATCH_ID='0', TAOSC_PRED=descriptor,
                           BRCACHE_STACK_SIZE=str(runner.brcache_stack_size))
        ranges, _ = runner.e9_metadata_for_binary(str(binary))
        if ranges:
            environment['AFL_QEMU_INST_RANGES'] = ranges
        # Only host-approved execution settings, not provider/Python environment.
        for key in ('BRCACHE_MAX_HITS', 'BRCACHE_MAX_BYTES'):
            if key in settings:
                environment[key] = settings[key]
        probe, text, raw = runner._test_with_capture(
            str(binary), '0', str(input_file), capture_cached=True, base_env=environment)
        execution = runner.run_results
        if (execution is None or not execution.success or execution.timed_out
                or probe is None or probe.exit_info not in ('ok', 'crash')):
            raise ExecutionUnavailable('execution-unavailable')
        patch = verifier.BinRadarPatchResult.from_log(text.decode(errors='replace')) if text else None
        if probe.patch_hit_cnt == 0 and not text:
            branches = []
        elif patch is None or patch.patch_id != 0 or len(patch.br_selection) != probe.patch_hit_cnt:
            raise ExecutionUnavailable('branch-capture-mismatch')
        else:
            branches = patch.br_selection
        snapshots, error = parse_cached_snapshots(raw) if raw is not None else ([], 'missing-brch')
        complete = error is None and len(snapshots) == len(branches) and [s.branch for s in snapshots] == branches
        expected_cwe = dataset.patch_format == 'ERM CWE-805'
        if complete and any(s.patch_id != 0 or s.is_CWE805 != expected_cwe
                            or (expected_cwe and len(s.stack) != runner.brcache_stack_size)
                            for s in snapshots):
            complete, error = False, 'capture-family-or-stack-mismatch'
        digest = hashlib.sha256(raw or b'').hexdigest()
        state = directory / (digest + '.brch')
        if complete:
            # State files are owned here, never in a producer's run directory.
            fd, part = tempfile.mkstemp(prefix='.state-', dir=directory)
            try:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw or b'')
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(part, state)
            finally:
                if os.path.exists(part):
                    os.unlink(part)
        return {'path': str(state), 'sha256': digest, 'artifact_sha256': artifact_hash,
                'branches': branches, 'descriptor': descriptor, 'complete': complete,
                'reason': error or ('none' if complete else 'capture-hit-mismatch'),
                'outcome': concrete_result(probe)}


def execution_identity() -> dict:
    """Bind cache entries to the actual host tracer and evaluator implementations."""
    from binradar import binradar_taosc_predicates as predicates
    return {'qemu': sha256(Path(paths.QASAN_QEMU_BIN)) if Path(paths.QASAN_QEMU_BIN).is_file() else None,
            'predicates': sha256(Path(predicates.__file__)),
            'verifier': sha256(Path(verifier.__file__)),
            'execution': sha256(Path(__file__)), 'oracle': verifier.CONCRETE_ORACLE}
