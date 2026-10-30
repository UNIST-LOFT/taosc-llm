"""Single-process ownership with durable, fail-closed remote reservations.

The fixed per-user scope deliberately does not encode credentials or endpoints.
It cannot account for external provider clients: operators must stop those first.
"""

import asyncio
import fcntl
import json
import os
import pwd
import stat
import uuid
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path

from .provider import ProviderConfig


class AdmissionError(RuntimeError):
    pass


class QuotaOwnerBusy(AdmissionError):
    pass


class QuotaQuarantinedError(AdmissionError):
    pass


def _default_state_dir() -> Path:
    # Not selected by environment or by provider/account material.
    return Path(pwd.getpwuid(os.getuid()).pw_dir) / ".local" / "state" / "taosc-llm" / "quota"


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise AdmissionError("unsafe quota state directory")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise AdmissionError("quota state directory must be private")


def _open_private(path: Path, flags: int) -> int:
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1):
        os.close(fd)
        raise AdmissionError("unsafe quota state file")
    return fd


@contextmanager
def _locked(state_dir: Path):
    _private_directory(state_dir)
    fd = _open_private(state_dir / "owner.lock", os.O_RDWR | os.O_CREAT)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise QuotaOwnerBusy("quota owner already running") from None
        yield
    finally:
        os.close(fd)


def _read_state(state_dir: Path) -> dict[str, str]:
    try:
        fd = _open_private(state_dir / "reservations.json", os.O_RDONLY)
    except FileNotFoundError:
        return {}
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            data = json.load(stream, object_pairs_hook=_unique_object)
        if (not isinstance(data, dict) or set(data) != {"schema_version", "reservations"}
                or type(data["schema_version"]) is not int or data["schema_version"] != 1
                or not isinstance(data["reservations"], dict)
                or any(not isinstance(key, str) or not key or value not in ("uncertain", "quarantined")
                       for key, value in data["reservations"].items())):
            raise ValueError
        return data["reservations"]
    except (ValueError, UnicodeError, TypeError):
        raise AdmissionError("invalid quota reservation state") from None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _write_state(state_dir: Path, reservations: dict[str, str]) -> None:
    # fsync data before atomic publication, then fsync the directory before
    # allowing the caller to make any request. A crash can only over-reserve.
    temporary = state_dir / f".reservations-{uuid.uuid4().hex}"
    try:
        fd = _open_private(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"schema_version": 1, "reservations": reservations}, stream,
                      sort_keys=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, state_dir / "reservations.json")
        directory_fd = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def recover_reservations(*, confirm_provider_settled: bool,
                         state_dir: Path | None = None) -> list[str]:
    """Explicit operator recovery, only after ALL remote work is known settled.

    CLI callers must use the default scope, never expose a fresh state-dir bypass.
    Returns cleared identifiers for a redacted recovery journal.
    """
    if confirm_provider_settled is not True:
        raise AdmissionError("provider settlement confirmation required")
    directory = Path(state_dir) if state_dir is not None else _default_state_dir()
    with _locked(directory):
        reservations = _read_state(directory)
        _write_state(directory, {})
        return sorted(reservations)


class Reservation:
    """One whole provider operation, uncertain until explicitly settled."""

    def __init__(self, identifier: str):
        self.identifier = identifier
        self._settled = False
        self._finished = False

    def settle(self) -> None:
        """Assert remote AND transport completion, not merely local process exit."""
        if self._finished:
            raise AdmissionError("reservation already closed")
        self._settled = True


class QuotaOwner:
    def __init__(self, config: ProviderConfig, state_dir: Path | None = None):
        self.config = config
        self.state_dir = Path(state_dir) if state_dir is not None else _default_state_dir()
        self.limit = min(config.workers, config.max_in_flight) if config.max_in_flight else config.workers
        self._lock = None
        self._open = False
        self._used = False
        self._state: dict[str, str] = {}
        self._changed = asyncio.Event()
        self._failed = False

    def __enter__(self):
        if self._used:
            raise AdmissionError("quota owner cannot be reused")
        self._used = True
        self._lock = _locked(self.state_dir)
        self._lock.__enter__()
        try:
            self._state = _read_state(self.state_dir)
            if self._state:
                raise QuotaQuarantinedError("unresolved provider reservations require explicit recovery")
            self._open = True
            return self
        except BaseException:
            self._lock.__exit__(None, None, None)
            self._lock = None
            raise

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if self._state:
                self._state = {identifier: "quarantined" for identifier in self._state}
                _write_state(self.state_dir, self._state)
        finally:
            self._open = False
            self._changed.set()
            if self._lock is not None:
                self._lock.__exit__(exc_type, exc_value, traceback)
                self._lock = None

    @asynccontextmanager
    async def reserve(self):
        # Single event-loop transitions contain no await: all waiters observe a
        # persisted reservation before the next task can attempt admission.
        while True:
            if not self._open or self._failed:
                raise AdmissionError("quota owner unavailable")
            if len(self._state) < self.limit:
                break
            if all(value == "quarantined" for value in self._state.values()):
                raise QuotaQuarantinedError("provider capacity quarantined")
            self._changed.clear()
            await self._changed.wait()
        reservation = Reservation(uuid.uuid4().hex)
        self._state[reservation.identifier] = "uncertain"
        try:
            _write_state(self.state_dir, self._state)
        except BaseException:
            self._failed = True
            self._changed.set()
            raise
        try:
            yield reservation
        finally:
            # No await here: cancellation cannot interrupt durable quarantine or
            # settlement publication, even when a task receives repeated cancels.
            reservation._finished = True
            if self._open:
                if reservation._settled:
                    del self._state[reservation.identifier]
                else:
                    self._state[reservation.identifier] = "quarantined"
                try:
                    _write_state(self.state_dir, self._state)
                except BaseException:
                    self._failed = True
                    raise
                finally:
                    self._changed.set()
