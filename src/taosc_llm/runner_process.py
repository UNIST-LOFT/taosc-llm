"""Bounded Linux process supervision, including descendants that call setsid.

Each job has a small, dedicated subreaper. It never adopts another caller's
children, and remains alive after the command exits to own orphaned descendants.
PID file descriptors, rather than remembered process-group numbers, authorize
signals. No process-wide subreaper setting is changed in the calling process.
"""

import ctypes
import errno
import json
import math
import os
import select
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path

_POLL = 0.02
_KILL_WAIT = 1.0


class RunnerInterrupted(Exception):
    def __init__(self, signum: int = signal.SIGINT):
        self.signum = signum
        self.exit_code = 128 + signum
        super().__init__(f"runner interrupted by signal {signum}")


class RunnerTimeout(Exception):
    def __init__(self, job: "Job", timeout: float):
        self.job = job
        self.timeout = timeout
        self.exit_code = 124
        super().__init__(f"{job.name} exceeded {timeout:g}s wall timeout")


class _Channel:
    def __init__(self, connection: socket.socket):
        self.connection = connection
        self.buffer = b""
        self.eof = False

    def send(self, message: dict) -> None:
        self.connection.sendall(json.dumps(message).encode() + b"\n")

    def receive(self) -> list[dict]:
        try:
            data = self.connection.recv(65536)
        except BlockingIOError:
            return []
        except ConnectionResetError:
            # A guardian can close after its terminal record while our stop
            # request remains unread. Preserve that record and observe EOF.
            data = b""
        if not data:
            self.eof = True
        self.buffer += data
        lines = self.buffer.split(b"\n")
        self.buffer = lines.pop()
        return [json.loads(line) for line in lines]


@dataclass
class Job:
    """Command status is separate from its descendant-owning guardian status.

    ``process`` is the guardian Popen; use ``poll`` / ``returncode`` for the
    command, whose PID is ``pid``. The guardian may outlive a completed command.
    """

    process: subprocess.Popen
    name: str
    stdout_path: Path | None
    stderr_path: Path | None
    _channel: _Channel = field(repr=False)
    pid: int = 0
    _returncode: int | None = field(default=None, repr=False)
    _done: bool = field(default=False, repr=False)
    _survivors: list[int] = field(default_factory=list, repr=False)
    _error: str | None = field(default=None, repr=False)

    def _drain(self) -> None:
        if self._channel.connection.fileno() < 0:
            return
        while select.select([self._channel.connection], [], [], 0)[0]:
            for event in self._channel.receive():
                if "pid" in event:
                    self.pid = event["pid"]
                if "returncode" in event:
                    self._returncode = event["returncode"]
                if "error" in event:
                    self._error = event["error"]
                if "survivors" in event:
                    self._survivors = event["survivors"]
                    self._done = True
            if self._channel.eof:
                break

    def poll(self) -> int | None:
        self._drain()
        if self._error:
            raise RuntimeError(f"{self.name}: {self._error}")
        if self._channel.eof and not self._done:
            raise RuntimeError(f"{self.name}: process guardian exited unexpectedly")
        return self._returncode

    @property
    def returncode(self) -> int | None:
        return self.poll()


class Supervisor:
    def __init__(self, graceful_timeout: float, *, held_fds: tuple[int, ...] = ()):
        if not math.isfinite(graceful_timeout) or graceful_timeout <= 0:
            raise ValueError("graceful_timeout must be positive and finite")
        self.graceful_timeout = graceful_timeout
        # Keep directory flock descriptions alive if the orchestrator dies.
        # Only guardians inherit them; their actual commands close all extra fds.
        self.held_fds = held_fds
        self.jobs: list[Job] = []
        self._signal: int | None = None
        self._force = False
        self._handlers: dict[int, Callable | int | None] = {}
        self._closed = False
        self._entered = False
        self.survivors: list[int] = []
        self.cleanup_error: str | None = None

    @property
    def interrupted(self) -> bool:
        return self._signal is not None

    @property
    def exit_code(self) -> int | None:
        return 128 + self._signal if self._signal is not None else None

    def request_stop(self, signum: int = signal.SIGINT) -> None:
        # Signal handlers only update flags: no I/O, waits, or reentrant cleanup.
        if self._signal is None:
            self._signal = signum
        else:
            self._force = True

    def __enter__(self) -> "Supervisor":
        if self._entered or self._closed:
            raise RuntimeError("supervisor cannot be entered twice")
        self._entered = True
        if threading.current_thread() is threading.main_thread():
            for signum in (signal.SIGINT, signal.SIGTERM):
                self._handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, lambda number, frame: self.request_stop(number))
        return self

    def check(self, guards: tuple[Job, ...] = ()) -> None:
        if self._signal is not None:
            raise RunnerInterrupted(self._signal)
        for guard in guards:
            status = guard.poll()
            if status is not None:
                raise RuntimeError(f"{guard.name} exited before shutdown (exit {status})")

    def start(self, argv: list[str], *, cwd: Path | None = None,
              stdout: Path | None = None, stderr: Path | None = None,
              env: dict | None = None, name: str) -> Job:
        if self._closed:
            raise RuntimeError("supervisor is closed")
        self.check()
        if not argv:
            raise ValueError("empty command")
        stdout = Path(stdout) if stdout is not None else None
        stderr = Path(stderr) if stderr is not None else None
        parent, child = socket.socketpair()
        try:
            with ExitStack() as files:
                output = files.enter_context(open(stdout, "wb")) if stdout is not None else None
                errors = (subprocess.STDOUT if stdout is not None and stdout == stderr else
                          files.enter_context(open(stderr, "wb")) if stderr is not None else None)
                bootstrap = ("import sys;sys.path.insert(0,sys.argv.pop(1));"
                             "from taosc_llm.runner_process import _guardian;_guardian()")
                process = subprocess.Popen(
                    [sys.executable, "-c", bootstrap, str(Path(__file__).parent.parent), str(child.fileno())],
                    stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
                    pass_fds=(child.fileno(), *self.held_fds), start_new_session=True)
            child.close()
            channel = _Channel(parent)
            job = Job(process, name, Path(stdout) if stdout is not None else None,
                      Path(stderr) if stderr is not None else None, channel)
            self.jobs.append(job)
            parent.settimeout(10)
            channel.send({"argv": argv, "cwd": str(cwd) if cwd is not None else None,
                          "env": env, "grace": self.graceful_timeout})
            parent.setblocking(False)
            startup_deadline = time.monotonic() + 10
            while not job.pid:
                self.check()
                job.poll()
                if time.monotonic() >= startup_deadline:
                    raise RuntimeError(f"{name}: process startup handshake exceeded 10s")
                time.sleep(_POLL)
            return job
        except BaseException:
            child.close()
            if not any(job._channel.connection is parent for job in self.jobs):
                parent.close()
            raise

    def wait(self, job: Job, *, timeout: float = 0,
             guards: tuple[Job, ...] = (), tick: Callable[[], None] | None = None) -> int:
        if not math.isfinite(timeout) or timeout < 0:
            raise ValueError("timeout must be nonnegative and finite")
        deadline = time.monotonic() + timeout if timeout else None
        while True:
            self.check(guards)
            if tick is not None:
                tick()
            self.check()
            status = job.poll()
            if status is not None:
                return status
            if deadline is not None and time.monotonic() >= deadline:
                raise RunnerTimeout(job, timeout)
            time.sleep(_POLL)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        failures = []
        forced = False

        def drain(job):
            try:
                job._drain()
            except (OSError, ValueError) as error:
                # A broken status channel must not skip cleanup of other jobs.
                # EOF tells this guardian to clean its own descendants too.
                job._error = f"guardian status channel failed: {error}"
                job._channel.connection.close()

        try:
            for job in self.jobs:
                try:
                    job._channel.send({"stop": True, "force": self._force})
                except OSError:
                    pass
            deadline = time.monotonic() + self.graceful_timeout + min(self.graceful_timeout, 1) + _KILL_WAIT + 2
            while True:
                pending = []
                for job in self.jobs:
                    drain(job)
                    if job.process.poll() is None:
                        pending.append(job)
                if not pending or time.monotonic() >= deadline:
                    break
                if self._force and not forced:
                    for job in pending:
                        try:
                            job._channel.send({"force": True})
                        except OSError:
                            pass
                    forced = True
                time.sleep(_POLL)
            for job in self.jobs:
                drain(job)
                self.survivors.extend(job._survivors)
                if job._error:
                    failures.append(f"{job.name}: {job._error}")
                if not job._done or job.process.poll() is None:
                    failures.append(f"{job.name}: guardian did not finish bounded cleanup (pid {job.process.pid})")
                job._channel.connection.close()
            if self.survivors:
                failures.append(f"owned processes survived SIGKILL: {self.survivors}")
        finally:
            for signum, handler in self._handlers.items():
                signal.signal(signum, handler)
            self._handlers.clear()
        if failures:
            self.cleanup_error = "; ".join(failures)
            raise RuntimeError(self.cleanup_error)

    def __exit__(self, kind, error, traceback) -> bool:
        pending_interrupt = RunnerInterrupted(self._signal) if error is None and self._signal is not None else None
        try:
            self.close()
        except BaseException as cleanup_error:
            self.cleanup_error = str(cleanup_error)
            try:
                print(f"runner cleanup: {self.cleanup_error}", file=sys.stderr)
            except (OSError, ValueError):
                pass  # A closed diagnostic stream must not replace the original failure.
            original = error or pending_interrupt
            if original is None and self._signal is not None:
                original = pending_interrupt = RunnerInterrupted(self._signal)
            if original is None:
                raise
        if pending_interrupt is not None:
            raise pending_interrupt
        if error is None and self._signal is not None:
            raise RunnerInterrupted(self._signal)
        return False


def _stat(pid: int) -> tuple[int, int] | None:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        return int(fields[1]), int(fields[19])  # ppid and starttime
    except (OSError, IndexError, ValueError):
        return None


def _discover(owned: dict[int, tuple[int, int]], owner: int) -> None:
    """Pin verified descendants before using their PID as a signal target."""
    candidates = {}
    for entry in Path("/proc").iterdir():
        if entry.name.isdecimal():
            pid = int(entry.name)
            identity = _stat(pid)
            if identity is not None:
                candidates[pid] = identity
    changed = True
    while changed:
        changed = False
        for pid, (ppid, started) in tuple(candidates.items()):
            if pid in owned or (ppid != owner and ppid not in owned):
                continue
            try:
                descriptor = os.pidfd_open(pid)
            except OSError as error:
                # /proc snapshots race exit/exec: the task may disappear or
                # cease to be a TGID (pidfd_open(..., flags=0) then gives EINVAL).
                # A non-leader TID is not a separately signalable owned process.
                if error.errno not in (errno.ESRCH, errno.EINVAL):
                    raise
                continue
            # Re-read after pinning. The parent must still have the identity we
            # own; stale /proc snapshots must not turn PID reuse into ownership.
            current = _stat(pid)
            parent = _stat(ppid) if ppid != owner else None
            if current != (ppid, started) or (ppid != owner and
                    (parent is None or parent[1] != owned[ppid][0])):
                os.close(descriptor)
                continue
            owned[pid] = (started, descriptor)
            candidates.pop(pid)
            changed = True


def _guardian() -> None:
    """Private subprocess entrypoint; all adopted children belong to one job."""
    connection = socket.socket(fileno=int(sys.argv[1]))
    connection.set_inheritable(False)
    channel = _Channel(connection)
    initial = []
    while not initial:
        initial = channel.receive()
        if channel.eof:
            return
    configuration = initial[0]
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        channel.send({"error": f"cannot enable child subreaper: errno {ctypes.get_errno()}", "survivors": []})
        return
    stop_signal = [False, False]

    def interrupted(number, frame):
        if stop_signal[0]:
            stop_signal[1] = True
        stop_signal[0] = True

    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    try:
        command = subprocess.Popen(configuration["argv"], cwd=configuration["cwd"],
                                   env=configuration["env"], start_new_session=True)
    except (OSError, ValueError) as error:
        channel.send({"error": str(error), "survivors": []})
        return
    connection.setblocking(False)
    owned: dict[int, tuple[int, int]] = {}
    grace = configuration["grace"]
    stopping = None
    kill_started = None
    sent: dict[int, int] = {}
    leader_done = False
    disconnected = False

    def notify(event):
        nonlocal disconnected
        if not disconnected:
            try:
                channel.send(event)
            except OSError:
                disconnected = True

    notify({"pid": command.pid})
    try:
        while True:
            _discover(owned, os.getpid())
            while True:
                try:
                    pid, status = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    pid = 0
                if not pid:
                    break
                if pid == command.pid:
                    command.returncode = os.waitstatus_to_exitcode(status)
                    leader_done = True
                    notify({"returncode": command.returncode})
            for pid, (_, descriptor) in tuple(owned.items()):
                if select.select([descriptor], [], [], 0)[0]:
                    os.close(descriptor)
                    owned.pop(pid)
                    sent.pop(pid, None)
            # An orphan may be adopted after the snapshot, even if every
            # previously observed process has exited. waitid's non-reaping
            # probe distinguishes an empty tree from a just-adopted child.
            if leader_done and not owned:
                try:
                    os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                except ChildProcessError:
                    notify({"survivors": []})
                    return
            if not channel.eof and select.select([connection], [], [], 0)[0]:
                try:
                    for event in channel.receive():
                        stop_signal[0] |= bool(event.get("stop"))
                        stop_signal[1] |= bool(event.get("force"))
                except OSError:
                    channel.eof = True
            now = time.monotonic()
            if stop_signal[0] or channel.eof or disconnected:
                if stopping is None:
                    stopping = now
                elapsed = now - stopping
                signum = signal.SIGINT
                if elapsed >= grace:
                    signum = signal.SIGTERM
                if stop_signal[1] or elapsed >= grace + min(grace, 1):
                    signum = signal.SIGKILL
                    if kill_started is None:
                        kill_started = now
                for pid, (_, descriptor) in owned.items():
                    if sent.get(pid) != signum:
                        try:
                            signal.pidfd_send_signal(descriptor, signum)
                        except ProcessLookupError:
                            pass
                        sent[pid] = signum
                if kill_started is not None and now - kill_started >= _KILL_WAIT:
                    notify({"survivors": sorted(owned)})
                    return
            time.sleep(_POLL)
    finally:
        for _, descriptor in owned.values():
            os.close(descriptor)
        connection.close()
