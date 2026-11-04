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


def test_diagnostic_roots_are_exclusive_and_producer_leaves_are_fixed(tmp_path):
    result = shell('''
OUTPUT_ALIAS=
allocate_runs "$1"; first=$RUNS; first_alias=$OUTPUT_ALIAS
allocate_runs "$1"
printf '%s\\n' "$first" "$RUNS" "$CONCRETE_RUN" "$MUTATION_RUN"
if [ -n "$first_alias" ]; then rm "$first_alias/out"; rmdir "$first_alias"; fi
if [ -n "$OUTPUT_ALIAS" ]; then rm "$OUTPUT_ALIAS/out"; rmdir "$OUTPUT_ALIAS"; fi
''', tmp_path)
    assert result.returncode == 0, result.stderr
    first, second, concrete, mutation = map(Path, result.stdout.splitlines())
    assert first != second
    assert first.parent == second.parent == tmp_path
    assert first.is_dir() and second.is_dir()
    assert list(first.iterdir()) == []
    # Pytest's root can itself exceed the socket limit; aliases are covered below.
    assert concrete.name == "br-gen-con"
    assert mutation.name == "br-gen-bin"
    assert concrete.parent == mutation.parent
    if mutation.parent != tmp_path:
        assert mutation.parent.name == "out"
        assert mutation.parent.parent.parent == Path("/tmp")


@pytest.mark.parametrize("ending,status", [("exit 0", 0), ("exit 7", 7),
                                           ("kill -INT $$", 130), ("kill -TERM $$", 143)])
def test_long_utf8_alias_binds_and_lives_until_owned_shutdown(tmp_path, ending, status):
    target = tmp_path / ("é" * 60)
    result = shell('''
OWNED_PIDS=(); CONCRETE_PID=; MUTATION_PID=; MUTATION_SOCKET=; OUTPUT_ALIAS=; LOG=
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
allocate_runs "$1"
printf '%s\\n' "$RUNS" "$OUTPUT_ALIAS" "$CONCRETE_RUN" "$MUTATION_SOCKET"
mkdir -p "$CONCRETE_RUN" "$MUTATION_RUN"
printf retained > "$CONCRETE_RUN/marker"
python3 -c 'import socket, sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])' "$MUTATION_SOCKET"
start_job python3 -c '
import pathlib, signal, sys, time
alias, target = map(pathlib.Path, sys.argv[1:])
def stop(*_):
    if (alias / "out").is_symlink():
        (target / "stopped").write_text("alive")
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
(target / "ready").touch()
while True:
    time.sleep(0.1)
' "$OUTPUT_ALIAS" "$1"
while [ ! -f "$1/ready" ]; do sleep 0.02; done
eval "$2"
''', target, ending)
    assert result.returncode == status, result.stderr
    diagnostic, alias, concrete, socket_path = map(Path, result.stdout.splitlines())
    assert diagnostic.parent == target
    assert diagnostic.is_dir()
    assert alias.parent == Path("/tmp")
    assert not alias.exists()
    assert len(str(socket_path).encode()) <= 107
    assert concrete == alias / "out/br-gen-con"
    assert (target / "br-gen-bin/replay.sock").is_socket()
    assert (target / "br-gen-con/marker").read_text() == "retained"
    assert (target / "stopped").read_text().strip() == "alive"


def test_failed_alias_link_allocation_removes_owned_parent_only(tmp_path):
    target = tmp_path / ("é" * 60)
    target.mkdir()
    (target / "retained").write_text("existing output")
    result = shell('''
OWNED_PIDS=(); CONCRETE_PID=; MUTATION_PID=; MUTATION_SOCKET=; OUTPUT_ALIAS=; LOG=
trap cleanup EXIT
ln() { printf '%s\\n' "$4"; return 9; }
allocate_runs "$1"
''', target)
    assert result.returncode == 9, result.stderr
    alias_link = Path(result.stdout.strip())
    assert alias_link.parent.parent == Path("/tmp")
    assert not alias_link.parent.exists()
    assert (target / "retained").read_text() == "existing output"


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


def preparation_runner(tmp_path, command, outdir="out"):
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
        [str(RUNNER), "--subject", "subject", "--workdir", "prepared",
         *(["--outdir", outdir] if outdir is not None else []),
         "--rea", "/bin/true", "--no-llm", "--predicate", "0"],
        cwd=tmp_path, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    return process


@pytest.mark.parametrize("outdir", [None, "custom-output"])
def test_preparation_preserves_failure_status_and_physical_output_base(tmp_path, outdir):
    process = preparation_runner(tmp_path, "exit 7", outdir=outdir)
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 7, (stdout, stderr)
    assert "candidate synthesis" not in stdout
    base = tmp_path / outdir if outdir else tmp_path / "subject/prepared/out"
    lines = stdout.splitlines()
    assert f"  concrete     {base / 'br-gen-con'}" in lines
    assert f"  mutation     {base / 'br-gen-bin'}" in lines
    roots = list(base.glob("runs-debug-*"))
    assert len(roots) == 1
    assert f"artifact root: {roots[0]}" in lines
    assert (roots[0] / "logs").is_dir()


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
