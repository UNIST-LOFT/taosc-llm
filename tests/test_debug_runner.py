"""Focused Bash runner contracts; not simulated pipeline acceptance.

Preparation uses a stub uv to hold/fail a child; runtime-resolution failure uses
a failing Guix command. Producer supervision uses real local sleep/exit processes.
Real generation/setup/synthesis belongs to the benign integration smoke, not
these lifecycle tests.
"""
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest


RUNNER = Path(__file__).resolve().parents[1] / "run.sh"
BASH = shutil.which("bash")
assert BASH is not None


def shell(code, *args, cwd=None, timeout=15):
    # Guix can inherit SIGINT=SIG_IGN; Bash cannot trap an initially ignored
    # signal. Model a foreground invocation without changing pytest's handlers.
    return subprocess.run(
        ["env", "--default-signal=INT", BASH, "-c",
         'source "$1"; shift; ' + code, "runner-test", str(RUNNER), *map(str, args)],
        cwd=cwd, text=True, capture_output=True, timeout=timeout,
    )


def test_relative_paths_and_short_alias_stay_lexical(tmp_path):
    target = tmp_path / ("long" * 35)
    target.mkdir()
    (tmp_path / "short").symlink_to(target, target_is_directory=True)
    result = shell('absolute_path short/../short/output', cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(tmp_path / "short/output")


@pytest.mark.parametrize("leaf", ["out", "long-run-" + "x" * 110, "é" * 60])
def test_diagnostic_roots_are_exclusive_and_producer_leaves_are_fixed(tmp_path, leaf):
    target = tmp_path / leaf
    result = shell('''
allocate_runs "$1"; first=$RUNS
allocate_runs "$1"
printf '%s\\n' "$first" "$RUNS" "$CONCRETE_RUN" "$MUTATION_RUN" "$MUTATION_SOCKET"
''', target)
    assert result.returncode == 0, result.stderr
    first, second, concrete, mutation, socket_path = map(Path, result.stdout.splitlines())
    assert first != second
    assert first.parent == second.parent == target
    assert first.is_dir() and second.is_dir()
    assert list(first.iterdir()) == []
    assert concrete == target / "br-gen-con"
    assert mutation == target / "br-gen-bin"
    assert socket_path == mutation / "replay.sock"


@pytest.mark.parametrize("ending,status", [("exit 0", 0), ("exit 7", 7),
                                           ("kill -INT $$", 130), ("kill -TERM $$", 143)])
def test_cleanup_preserves_long_physical_outputs(tmp_path, ending, status):
    target = tmp_path / ("é" * 60)
    result = shell('''
OWNED_PIDS=(); CONCRETE_PID=; MUTATION_PID=; MUTATION_SOCKET=; LOG=
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
allocate_runs "$1"
printf '%s\\n' "$RUNS" "$CONCRETE_RUN" "$MUTATION_RUN"
mkdir -p "$CONCRETE_RUN" "$MUTATION_RUN"
printf retained > "$CONCRETE_RUN/marker"
start_job python3 -c '
import pathlib, signal, sys, time
target = pathlib.Path(sys.argv[1])
def stop(*_):
    (target / "stopped").write_text("stopped")
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
(target / "ready").touch()
while True:
    time.sleep(0.1)
' "$1"
while [ ! -f "$1/ready" ]; do sleep 0.02; done
eval "$2"
''', target, ending)
    assert result.returncode == status, result.stderr
    diagnostic, concrete, mutation = map(Path, result.stdout.splitlines())
    assert diagnostic.parent == target
    assert diagnostic.is_dir()
    assert concrete == target / "br-gen-con"
    assert mutation == target / "br-gen-bin"
    assert mutation.is_dir()
    assert (concrete / "marker").read_text() == "retained"
    assert (target / "stopped").read_text() == "stopped"


def test_short_symlink_root_is_not_resolved(tmp_path):
    target = tmp_path / ("long" * 35)
    target.mkdir()
    # /tmp keeps the alias genuinely short regardless of pytest's own root.
    import tempfile
    with tempfile.TemporaryDirectory(prefix="br-alias-", dir="/tmp") as short:
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


def preparation_runner(tmp_path, command, outdir="out", *, rea="/bin/true", flags=()):
    subject = tmp_path / "subject"
    workdir = subject / "prepared"
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "patch-location").write_text("prepared\n")
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    uv = bindir / "uv"
    uv.write_text(f"#!{BASH}\n" + command + "\n")
    uv.chmod(0o755)
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", CHILD_FILE=str(tmp_path / "child"))
    process = subprocess.Popen(
        ["env", "--default-signal=INT", str(RUNNER),
         "--subject", "subject", "--workdir", "prepared",
         *(["--outdir", outdir] if outdir is not None else []),
         *(["--rea", rea] if rea is not None else []), "--no-llm", "--predicate", "0", *flags],
        cwd=tmp_path, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    return process


def test_concrete_modes_are_mutually_exclusive_before_work(tmp_path):
    process = preparation_runner(
        tmp_path, 'touch "$CHILD_FILE"; exit 9', rea=None,
        flags=("--skip-concrete", "--only-concrete"))
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 2, (stdout, stderr)
    assert "--skip-concrete" in stderr and "--only-concrete" in stderr
    assert not (tmp_path / "child").exists()
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("empty_manifest", [False, True])
def test_skip_requires_concrete_evidence_before_mutating_outputs(tmp_path, empty_manifest):
    output = tmp_path / "subject/prepared/out"
    concrete, mutation = output / "br-gen-con", output / "br-gen-bin"
    concrete.mkdir(parents=True)
    mutation.mkdir()
    (concrete / "retained-input").write_bytes(b"prior concrete input")
    (mutation / "prior-run").write_bytes(b"prior mutation output")
    if empty_manifest:
        (concrete / "minimizer.sbsv").touch()
    process = preparation_runner(
        tmp_path, 'touch "$CHILD_FILE"; exit 9', outdir=None, rea=None,
        flags=("--skip-concrete",))
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 2, (stdout, stderr)
    assert "--skip-concrete" in stderr
    assert not (tmp_path / "child").exists()
    assert {path.name for path in output.iterdir()} == {"br-gen-con", "br-gen-bin"}
    assert (concrete / "retained-input").read_bytes() == b"prior concrete input"
    assert (mutation / "prior-run").read_bytes() == b"prior mutation output"


def test_concrete_only_does_not_require_analysis_or_a_predicate(tmp_path, monkeypatch):
    monkeypatch.delenv("TAOSC_LLM_REA", raising=False)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    guix = bindir / "guix"
    guix.write_text(f'#!{BASH}\ntouch "$CHILD_FILE"; exit 17\n')
    guix.chmod(0o755)
    # Reaching concrete preparation, rather than runtime or predicate validation,
    # must preserve the actual preparation failure status.
    process = preparation_runner(
        tmp_path, "exit 7", rea=None,
        flags=("--only-concrete", "--predicate", "", "--provider-env", ""))
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 7, (stdout, stderr)
    assert not (tmp_path / "child").exists()


def test_runtime_resolution_failure_preserves_existing_outputs(tmp_path, monkeypatch):
    monkeypatch.delenv("TAOSC_LLM_REA", raising=False)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    guix = bindir / "guix"
    guix.write_text(f"#!{BASH}\nexit 17\n")
    guix.chmod(0o755)
    # A failing build must not fall back to a seemingly usable ambient executable.
    rea = bindir / "rea"
    rea.write_text(f"#!{BASH}\nexit 0\n")
    rea.chmod(0o755)
    output = tmp_path / "subject/prepared/out"
    for name in ("br-gen-con", "br-gen-bin"):
        directory = output / name
        directory.mkdir(parents=True)
        (directory / "prior-run").write_bytes(b"preserve this producer output")
    process = preparation_runner(tmp_path, 'touch "$CHILD_FILE"; exit 9',
                                 outdir=None, rea=None)
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 17, (stdout, stderr)
    assert not (tmp_path / "child").exists()
    assert {path.name for path in output.iterdir()} == {"br-gen-con", "br-gen-bin"}
    for name in ("br-gen-con", "br-gen-bin"):
        assert (output / name / "prior-run").read_bytes() == b"preserve this producer output"


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
