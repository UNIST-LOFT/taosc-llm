"""Host-owned native execution without provider credentials or host-file access."""

import os
import shutil
import signal
import subprocess
import sys
from importlib.resources import files
from pathlib import Path
from tempfile import TemporaryDirectory, TemporaryFile

from .provider import native_environment

_SYSTEM_READ = ("/usr", "/bin", "/lib", "/lib64", "/gnu/store", "/etc/ld.so.cache")


def run_native(command: list[str], scratch: Path, *, timeout: int = 300,
               extra_env: dict[str, str] | None = None, check: bool = True,
               readable: tuple[Path, ...] = (),
               self_signals: bool = False) -> subprocess.CompletedProcess:
    """Run an argv, not a shell command; only scratch is writable.

    This deliberately fails closed when Landlock/seccomp is unavailable. Extra
    environment is restricted to the fixture selector, never arbitrary preload,
    shell, dynamic-loader or provider configuration. Self-signaling is an
    opt-in for childless fixture replay, not builds or concrete workers.
    """
    if not command:
        raise ValueError("empty native command")
    environment = native_environment()
    if extra_env:
        if set(extra_env) - {"PATCH_ID"}:
            raise ValueError("unsupported native environment field")
        environment.update(extra_env)
    executable = shutil.which(command[0], path=environment.get("PATH"))
    if executable is None:
        raise FileNotFoundError("native executable is unavailable")
    command = [str(Path(executable).absolute()), *command[1:]]
    scratch = Path(scratch).resolve(strict=True)
    launcher = str(files("taosc_llm").joinpath("_sandbox.py"))
    roots = [Path(path) for path in _SYSTEM_READ]
    roots.extend(readable)
    roots.append(Path(command[0]))
    with TemporaryDirectory(prefix=".native-", dir=scratch) as temporary:
        environment.update(HOME=temporary, TMPDIR=temporary, LC_ALL="C")
        argv = [sys.executable, "-I", "-S", launcher, "--scratch", str(scratch),
                "--timeout", str(timeout)]
        if self_signals:
            argv.append("--self-signals")
        for root in roots:
            argv.extend(("--read", str(root)))
        argv.extend(("--", *command))
        with TemporaryFile() as output, TemporaryFile() as errors:
            process = subprocess.Popen(argv, cwd=scratch, env=environment,
                                       stdin=subprocess.DEVNULL, stdout=output,
                                       stderr=errors, start_new_session=True)
            try:
                returncode = process.wait(timeout=timeout + 5)
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                raise
            output.seek(0)
            errors.seek(0)
            stdout = output.read(65537)
            stderr = errors.read(65537)
            if len(stdout) > 65536 or len(stderr) > 65536:
                raise RuntimeError("native diagnostic output exceeded 64 KiB")
            result = subprocess.CompletedProcess(command, returncode, stdout, stderr)
    if returncode == 125:
        raise RuntimeError("native isolation could not start (Landlock/seccomp required)")
    if check and returncode:
        # Diagnostics contain only candidate-owned inputs, never auth material.
        if stderr:
            sys.stderr.write(stderr.decode("utf-8", errors="replace"))
        raise subprocess.CalledProcessError(returncode, command, stdout, stderr)
    return result


def build_command(command: list[str], stage: Path) -> None:
    run_native(command, stage)
