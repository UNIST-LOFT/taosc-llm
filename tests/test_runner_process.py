"""Linux lifecycle contracts with real Python processes, no native runtime."""

import os
import select
import signal
import subprocess
import sys
import threading
import time
from contextlib import suppress
from pathlib import Path

import pytest

from taosc_llm.runner_process import RunnerInterrupted, RunnerTimeout, Supervisor


STUBBORN = """
import os, signal, sys, time
from pathlib import Path
signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
Path(sys.argv[1]).write_text(str(os.getpid()))
while True:
    time.sleep(1)
"""


def eventually(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            pytest.fail("process condition did not settle before deadline")
        time.sleep(0.01)


@pytest.fixture
def processes():
    """Always kill pinned test children, even when a lifecycle assertion fails."""
    supervisors = []
    descriptors = []

    def supervisor(grace=0.1):
        instance = Supervisor(grace)
        supervisors.append(instance)
        return instance

    def pin(path):
        eventually(lambda: path.exists() and bool(path.read_text()))
        pid = int(path.read_text())
        descriptor = os.pidfd_open(pid)
        descriptors.append(descriptor)
        return pid, descriptor

    yield supervisor, pin
    for instance in supervisors:
        instance.request_stop()
        instance.request_stop()
        with suppress(Exception):
            instance.close()
    for descriptor in descriptors:
        with suppress(ProcessLookupError):
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
        os.close(descriptor)
    for instance in supervisors:
        for job in instance.jobs:
            if job.process.poll() is None:
                job.process.kill()
                with suppress(subprocess.TimeoutExpired):
                    job.process.wait(timeout=2)


def command(code, *arguments):
    return [sys.executable, "-c", code, *map(str, arguments)]


def assert_reaped(pid, descriptor):
    assert select.select([descriptor], [], [], 0)[0], f"owned PID {pid} is still executing"
    assert not Path(f"/proc/{pid}").exists(), f"owned PID {pid} was not reaped"


def test_command_status_sessions_and_merged_log(processes, tmp_path):
    factory, _ = processes
    log = tmp_path / "both.log"
    with factory() as supervisor:
        job = supervisor.start(command("""
import os, sys
assert os.getsid(0) == os.getpid()
assert os.getpgrp() == os.getpid()
print('stdout', flush=True)
print('stderr', file=sys.stderr, flush=True)
sys.exit(7)
"""), stdout=log, stderr=log, name="short command")
        assert supervisor.wait(job) == 7
        assert job.returncode == 7
        assert job.pid != job.process.pid
        assert job.stdout_path == log and job.stderr_path == log
    assert log.read_text() == "stdout\nstderr\n"
    assert job.poll() == 7
    assert job.process.returncode == 0
    assert job._channel.connection.fileno() == -1
    # No parent-owned log descriptor is retained through or after cleanup.
    assert all(not fd.is_symlink() or os.readlink(fd) != str(log)
               for fd in Path("/proc/self/fd").iterdir() if fd.exists())


def test_lexical_log_paths_environment_and_cwd(processes, tmp_path):
    factory, _ = processes
    physical = tmp_path / "physical"
    physical.mkdir()
    lexical = tmp_path / "link"
    lexical.symlink_to(physical, target_is_directory=True)
    log = lexical / "result"
    (physical / "marker").write_text("present")
    with factory() as supervisor:
        job = supervisor.start(command("""
import os
from pathlib import Path
assert Path('marker').read_text() == 'present'
print(os.environ['SUPERVISOR_TEST'])
"""), cwd=lexical, env={**os.environ, "SUPERVISOR_TEST": "kept"},
            stdout=log, name="cwd command")
        assert supervisor.wait(job) == 0
        assert job.stdout_path == log
    assert log.read_text() == "kept\n"


def test_wall_timeout_is_preserved_and_logs_are_kept(processes, tmp_path):
    factory, pin = processes
    marker = tmp_path / "pid"
    log = tmp_path / "long.log"
    with pytest.raises(RunnerTimeout) as caught:
        with factory() as supervisor:
            job = supervisor.start(command(STUBBORN, marker), stdout=log, stderr=log, name="long stage")
            pid, descriptor = pin(marker)
            supervisor.wait(job, timeout=0.05)
    assert caught.value.job is job
    assert caught.value.exit_code == 124
    assert "long stage" in str(caught.value)
    assert log.exists()
    assert_reaped(pid, descriptor)


def test_wait_calls_health_callback_and_preserves_failure(processes, tmp_path):
    factory, pin = processes
    failure = ValueError("producer failed with its original diagnostic")
    marker = tmp_path / "pid"
    calls = []
    with pytest.raises(ValueError) as caught:
        with factory() as supervisor:
            job = supervisor.start(command(STUBBORN, marker), name="foreground")
            pid, descriptor = pin(marker)

            def health():
                calls.append(time.monotonic())
                if len(calls) == 3:
                    supervisor.request_stop(signal.SIGINT)
                    raise failure

            supervisor.wait(job, tick=health)
    assert caught.value is failure
    assert len(calls) == 3
    assert calls[-1] - calls[0] < 1
    assert_reaped(pid, descriptor)


def test_discovery_tolerates_task_losing_thread_group_identity(tmp_path, monkeypatch):
    # /proc enumeration and pidfd_open are not atomic. During exec/exit, a
    # previously enumerated leader can no longer be a thread-group leader.
    # Feed that snapshot race with a real Linux non-leader TID, not a mocked
    # syscall result; the still-live command must remain owned.
    from taosc_llm.runner_process import _discover
    marker = tmp_path / "tid"
    child = subprocess.Popen(command("""
import threading, time, sys
from pathlib import Path
def worker():
    Path(sys.argv[1]).write_text(str(threading.get_native_id()))
    time.sleep(60)
threading.Thread(target=worker).start()
time.sleep(60)
""", marker))
    owned = {}
    try:
        eventually(lambda: marker.exists() and marker.read_text())
        tid = int(marker.read_text())
        original_iterdir = Path.iterdir
        def snapshot(path):
            if path == Path('/proc'):
                return iter((Path(f'/proc/{tid}'), Path(f'/proc/{child.pid}')))
            return original_iterdir(path)
        monkeypatch.setattr(Path, 'iterdir', snapshot)
        _discover(owned, os.getpid())
        assert child.pid in owned
        assert tid not in owned
    finally:
        child.kill()
        child.wait(timeout=3)
        for _, descriptor in owned.values():
            os.close(descriptor)


def test_completed_guardian_reset_preserves_terminal_record():
    import socket
    from taosc_llm.runner_process import _Channel
    parent, peer = socket.socketpair()
    try:
        channel = _Channel(parent)
        peer.sendall(b'{"survivors": []}\n')
        # Closing with an unread shutdown request causes a real Unix-stream
        # ECONNRESET after the queued terminal record, not a guardian failure.
        parent.sendall(b'{"stop": true}\n')
        peer.close()
        assert channel.receive() == [{"survivors": []}]
        assert channel.receive() == []
        assert channel.eof
    finally:
        parent.close()
        peer.close()


def test_guard_exit_even_zero_is_not_healthy(processes):
    factory, _ = processes
    with factory() as supervisor:
        guard = supervisor.start(command("pass"), name="resident")
        assert supervisor.wait(guard) == 0
        with pytest.raises(RuntimeError, match="resident exited before shutdown .*exit 0"):
            supervisor.check((guard,))


def test_wait_checks_guard_before_returning_completed_job(processes):
    factory, _ = processes
    with factory() as supervisor:
        guard = supervisor.start(command("raise SystemExit(9)"), name="resident")
        stage = supervisor.start(command("pass"), name="stage")
        assert supervisor.wait(guard) == 9
        assert supervisor.wait(stage) == 0
        with pytest.raises(RuntimeError, match="resident.*exit 9"):
            supervisor.wait(stage, guards=(guard,))


@pytest.mark.parametrize("signum,exit_code", [(signal.SIGINT, 130), (signal.SIGTERM, 143)])
def test_actual_signal_cancels_wait_and_restores_handlers(processes, tmp_path, signum, exit_code):
    factory, pin = processes
    original = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    marker = tmp_path / "pid"
    with pytest.raises(RunnerInterrupted) as caught:
        with factory() as supervisor:
            job = supervisor.start(command(STUBBORN, marker), name="interrupted")
            pid, descriptor = pin(marker)
            os.kill(os.getpid(), signum)
            supervisor.wait(job)
    assert caught.value.exit_code == exit_code
    assert supervisor.exit_code == exit_code and supervisor.interrupted
    assert {number: signal.getsignal(number) for number in original} == original
    assert_reaped(pid, descriptor)


def test_repeated_signal_escalates_without_replacing_original(processes, tmp_path):
    factory, pin = processes
    marker = tmp_path / "pid"
    timer = None
    try:
        with pytest.raises(RunnerInterrupted) as caught:
            with factory(grace=5) as supervisor:
                job = supervisor.start(command(STUBBORN, marker), name="stubborn")
                pid, descriptor = pin(marker)
                supervisor.request_stop(signal.SIGINT)
                # Like the signal handler, the timer only sets cancellation flags.
                timer = threading.Timer(0.1, supervisor.request_stop, args=(signal.SIGTERM,))
                timer.start()
                started = time.monotonic()
                supervisor.wait(job)
        assert time.monotonic() - started < 2
        assert caught.value.exit_code == 130
        assert_reaped(pid, descriptor)
    finally:
        if timer is not None:
            timer.cancel()
            timer.join()


def test_leader_exit_and_detached_child_and_grandchild_are_owned(processes, tmp_path):
    factory, pin = processes
    child_file, grandchild_file = tmp_path / "child", tmp_path / "grandchild"
    child_code = """
import os, signal, subprocess, sys, time
from pathlib import Path
signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
subprocess.Popen([sys.executable, '-c', sys.argv[3], sys.argv[2]], start_new_session=True)
Path(sys.argv[1]).write_text(str(os.getpid()))
while True:
    time.sleep(1)
"""
    leader_code = """
import subprocess, sys
subprocess.Popen([sys.executable, '-c', sys.argv[1], *sys.argv[2:]], start_new_session=True)
"""
    external = subprocess.Popen(command("import time;time.sleep(60)"), start_new_session=True)
    try:
        with factory() as supervisor:
            job = supervisor.start(command(leader_code, child_code, child_file, grandchild_file, STUBBORN), name="launcher")
            child, child_fd = pin(child_file)
            grandchild, grandchild_fd = pin(grandchild_file)
            assert supervisor.wait(job) == 0
            assert job.process.poll() is None, "guardian must outlive the argv leader"
            assert os.getsid(child) == child
            assert os.getsid(grandchild) == grandchild
        assert_reaped(child, child_fd)
        assert_reaped(grandchild, grandchild_fd)
        assert external.poll() is None, "an external reused server must remain untouched"
    finally:
        external.kill()
        external.wait(timeout=3)


def test_guardian_retains_directory_lock_until_owned_children_are_reaped(tmp_path):
    import fcntl
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    contender = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    marker = tmp_path / "pid"
    try:
        with Supervisor(0.1, held_fds=(descriptor,)) as supervisor:
            job = supervisor.start(command(STUBBORN, marker), name="lock owner")
            eventually(lambda: marker.exists() and marker.read_text())
            # The guardian's inherited open-file description must retain the
            # lock even if the runner releases its copy (e.g. SIGKILL).
            os.close(descriptor)
            descriptor = -1
            with pytest.raises(BlockingIOError):
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert not Path(f'/proc/{job.pid}').exists()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(contender)


def test_parent_channel_eof_cleans_children_without_orphaning_guardian(processes, tmp_path):
    factory, pin = processes
    marker = tmp_path / "pid"
    # Closing the parent endpoint is the same kernel event as parent death,
    # but retaining the guardian's parent here lets the test reap it too.
    with pytest.raises(RuntimeError, match="guardian"):
        with factory() as supervisor:
            job = supervisor.start(command(STUBBORN, marker), name="lost parent")
            pid, descriptor = pin(marker)
            job._channel.connection.close()
            eventually(lambda: job.process.poll() is not None)
            assert_reaped(pid, descriptor)
    assert "guardian" in supervisor.cleanup_error


def test_cleanup_failure_does_not_replace_original_error(processes, tmp_path, capsys):
    factory, pin = processes
    marker = tmp_path / "pid"
    original = ValueError("original stage failure")
    with pytest.raises(ValueError) as caught:
        with factory() as supervisor:
            job = supervisor.start(command(STUBBORN, marker), name="lost parent")
            pid, descriptor = pin(marker)
            job._channel.connection.close()
            eventually(lambda: job.process.poll() is not None)
            assert_reaped(pid, descriptor)
            raise original
    assert caught.value is original
    assert "guardian" in supervisor.cleanup_error
    assert "runner cleanup:" in capsys.readouterr().err


def test_cancellation_without_wait_is_not_success(processes):
    factory, _ = processes
    with pytest.raises(RunnerInterrupted) as caught:
        with factory() as supervisor:
            supervisor.request_stop(signal.SIGTERM)
    assert caught.value.exit_code == 143


def test_close_is_idempotent_and_start_after_close_rejected(processes):
    factory, _ = processes
    with factory() as supervisor:
        job = supervisor.start(command("pass"), name="short")
        assert supervisor.wait(job) == 0
    supervisor.close()
    assert supervisor.cleanup_error is None
    assert job._channel.connection.fileno() == -1
    with pytest.raises(RuntimeError, match="closed"):
        supervisor.start(command("pass"), name="too late")


def test_missing_executable_is_not_reported_as_command_success(processes, tmp_path):
    factory, _ = processes
    with pytest.raises(RuntimeError, match="missing-command"):
        with factory() as supervisor:
            supervisor.start([str(tmp_path / "missing-command")], name="missing command")


def test_non_main_thread_does_not_install_signal_handlers(processes):
    factory, _ = processes
    handlers = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    errors = []

    def worker():
        try:
            with factory() as supervisor:
                job = supervisor.start(command("pass"), name="thread command")
                assert supervisor.wait(job) == 0
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert not errors
    assert {number: signal.getsignal(number) for number in handlers} == handlers
