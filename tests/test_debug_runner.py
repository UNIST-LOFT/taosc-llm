"""Focused Bash runner contracts; not simulated pipeline acceptance.

Only preparation uses a stub uv to hold/fail a child. Producer supervision uses
real local sleep/exit processes. Real generation/setup/synthesis belongs to the
benign integration smoke, not these lifecycle tests.
"""
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest


RUNNER = Path(__file__).resolve().parents[1] / "run.sh"


def shell(code, *args, cwd=None, timeout=15):
    return subprocess.run(
        ["bash", "-c", 'source "$1"; shift; ' + code, "runner-test", str(RUNNER), *map(str, args)],
        cwd=cwd, text=True, capture_output=True, timeout=timeout,
    )


def test_relative_paths_and_short_alias_stay_lexical(tmp_path):
    target = tmp_path / ("long" * 35)
    target.mkdir()
    (tmp_path / "short").symlink_to(target, target_is_directory=True)
    result = shell('absolute_path short/../short/output', cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(tmp_path / "short/output")


def test_socket_limit_counts_utf8_bytes():
    # 103 codepoints but 133 UTF-8 bytes: the former character-count check passed.
    path = "/" + "é" * 30 + "a" * 72
    result = shell('if socket_path_fits "$1"; then exit 11; fi', path)
    assert result.returncode == 0
    assert shell('socket_path_fits "$1"', "/" + "a" * 106).returncode == 0
    assert shell('socket_path_fits "$1"', "/" + "a" * 107).returncode != 0


def test_roots_are_exclusive_and_long_utf8_falls_back(tmp_path):
    result = shell('allocate_runs "$1"; a=$RUNS; allocate_runs "$1"; printf "%s\\n%s\\n" "$a" "$RUNS"', tmp_path)
    assert result.returncode == 0, result.stderr
    first, second = map(Path, result.stdout.splitlines())
    try:
        assert first != second
        assert first.is_dir() and second.is_dir()
        assert list(first.iterdir()) == []
    finally:
        first.rmdir()
        if second != first:
            second.rmdir()
    result = shell('allocate_runs "$1"; printf "%s\\n" "$RUNS"', tmp_path / ("é" * 40))
    assert result.returncode == 0, result.stderr
    fallback = Path(result.stdout.strip())
    try:
        assert fallback.parent == Path("/tmp")
        assert fallback.is_dir()
        assert len(str(fallback / "br-gen-bin-00000/replay.sock").encode()) <= 107
    finally:
        fallback.rmdir()


def test_short_symlink_root_is_not_resolved(tmp_path):
    target = tmp_path / ("long" * 35)
    target.mkdir()
    # /tmp keeps the alias genuinely short regardless of pytest's own root.
    import tempfile
    with tempfile.TemporaryDirectory(prefix="br-alias-") as short:
        alias = Path(short) / "a"
        alias.symlink_to(target, target_is_directory=True)
        result = shell('allocate_runs "$(absolute_path "$1")"; printf "%s\\n" "$RUNS"', alias)
        assert result.returncode == 0, result.stderr
        root = Path(result.stdout.strip())
        assert root.parent == alias
        assert root.is_dir()


@pytest.mark.parametrize("failed_producer", ["concrete", "resident"])
@pytest.mark.parametrize("exit_code", [0, 7])
def test_wait_observes_both_producers(failed_producer, exit_code):
    if failed_producer == "concrete" and exit_code == 0:
        # A successful concrete producer may finish before ready.
        expected = 0
        waiter = "sleep 0.4"
    else:
        expected = 1
        waiter = "sleep 30"
    result = shell('''
OWNED_PIDS=(); CONCRETE_PID=; MUTATION_PID=; LOG=/unused
trap 'for p in "${OWNED_PIDS[@]}"; do kill -KILL -- "-$p" 2>/dev/null || true; done' EXIT
start_job bash -c 'sleep 0.1; exit "$1"' child "$2"
if [ "$1" = concrete ]; then CONCRETE_PID=$STARTED_PID; else MUTATION_PID=$STARTED_PID; fi
start_job bash -c "$3"
wait_job "$STARTED_PID"
''', failed_producer, exit_code, waiter, timeout=5)
    assert result.returncode == expected, result.stderr
    if expected:
        assert "generation" in result.stderr


def preparation_runner(tmp_path, command):
    subject = tmp_path / "subject"
    workdir = subject / "prepared"
    workdir.mkdir(parents=True)
    (workdir / "patch-location").write_text("prepared\n")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    uv = bindir / "uv"
    uv.write_text("#!/bin/bash\n" + command + "\n")
    uv.chmod(0o755)
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", CHILD_FILE=str(tmp_path / "child"))
    process = subprocess.Popen(
        [str(RUNNER), "--subject", "subject", "--workdir", "prepared", "--outdir", "out",
         "--rea", "/bin/true", "--no-llm", "--predicate", "0"],
        cwd=tmp_path, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    return process


def test_preparation_preserves_failure_status(tmp_path):
    process = preparation_runner(tmp_path, "exit 7")
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 7, (stdout, stderr)
    assert "candidate synthesis" not in stdout


@pytest.mark.parametrize("sig,expected", [(signal.SIGINT, 130), (signal.SIGTERM, 143)])
def test_signal_during_preparation_stops_owned_descendants(tmp_path, sig, expected):
    process = preparation_runner(tmp_path, '''
# Simulate uv forwarding without exec, including a stubborn descendant.
bash -c 'trap "" TERM; echo $$ > "$CHILD_FILE"; exec sleep 60' &
wait
''')
    child_file = tmp_path / "child"
    deadline = time.monotonic() + 5
    try:
        while not child_file.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert child_file.exists(), process.communicate(timeout=5)
        child = int(child_file.read_text())
        process.send_signal(sig)
        stdout, stderr = process.communicate(timeout=12)
        assert process.returncode == expected, (stdout, stderr)
        assert "candidate synthesis" not in stdout
        # An orphan can briefly remain as a zombie under a non-reaping CI PID 1;
        # a zombie is not an executing leaked descendant.
        stat = Path(f"/proc/{child}/stat")
        assert not stat.exists() or stat.read_text().split(") ", 1)[1].startswith("Z ")
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
