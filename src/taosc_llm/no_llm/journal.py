"""Private, single-writer, append-only search evidence storage.

Events have no implicit transaction semantics: only the engine interprets commits.
Every resume seals the exact bytes of the preceding segment in a new header,
including any uncommitted final partial line. No existing file is rewritten.
"""
from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import uuid
from pathlib import Path


class JournalError(ValueError):
    """Invalid identity, evidence, journal structure, or storage boundary."""


# Linux renameat2 is the atomic no-overwrite operation required here. A
# link/unlink publication can leave a second hard link after SIGKILL; ordinary
# rename can replace evidence created between the existence check and publish.
try:
    _renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
except AttributeError:
    _renameat2 = None
else:
    _renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint)
    _renameat2.restype = ctypes.c_int


def _publish(parent: int, temporary: str, name: str) -> None:
    if _renameat2 is None:
        raise JournalError("Linux renameat2 is required for immutable journal storage")
    if _renameat2(parent, os.fsencode(temporary), parent, os.fsencode(name), 1) != 0:
        code = ctypes.get_errno()
        if code in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP):
            raise JournalError("filesystem lacks atomic no-overwrite journal publication")
        raise OSError(code, os.strerror(code), name)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _decode(data: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise JournalError("duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(data, object_pairs_hook=pairs,
                           parse_constant=lambda value: (_ for _ in ()).throw(
                               JournalError(f"invalid JSON constant: {value}")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise JournalError("invalid journal JSON") from exc
    if not isinstance(value, dict):
        raise JournalError("journal JSON must be an object")
    return value


def _checked(record: dict) -> str:
    checksum = record.get("sha256")
    unsigned = {key: value for key, value in record.items() if key != "sha256"}
    if not isinstance(checksum, str) or checksum != _digest(_canonical(unsigned)):
        raise JournalError("journal checksum mismatch")
    return checksum


def _signed(record: dict) -> dict:
    return {**record, "sha256": _digest(_canonical(record))}


def _write_all(fd: int, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        written = os.write(fd, remaining)
        if written <= 0:
            raise OSError("short journal write")
        remaining = remaining[written:]


def _private(info: os.stat_result, *, directory: bool = False) -> None:
    correct_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (not correct_type or info.st_uid != os.geteuid() or info.st_mode & 0o077
            or (not directory and info.st_nlink != 1)):
        raise JournalError("journal storage must be private, owned, and not linked")


def _directory(path: Path, *, create: bool) -> int:
    """Traverse with directory descriptors; no ancestor may be a symlink."""
    path = Path(os.path.abspath(path))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in path.parts[1:]:
            if create:
                try:
                    os.mkdir(name, 0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
            next_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


class Journal:
    """Durable journal; use exclusively inside its context manager.

    ``events`` contains validated event records, never segment headers. Payload
    references are ``{'path': 'payloads/<sha256>.<suffix>', 'sha256': ...}``.
    ``torn_tails`` records segment names whose final incomplete line was ignored.
    Concurrent writers fail immediately rather than wait for another session.
    """

    def __init__(self, directory: Path, identity: dict, *, resume: bool = False):
        if not isinstance(identity, dict):
            raise TypeError("journal identity must be a dict")
        self.directory = Path(os.path.abspath(directory))
        self._identity_bytes = _canonical(identity)
        self.identity = _decode(self._identity_bytes)
        self.resume = resume
        self.events: list[dict] = []
        self.torn_tails: list[str] = []
        self._fds: list[int] = []
        self._created: list[tuple[int, str, int, bool]] = []
        self._active = False
        self._entered = False
        self._poisoned = False
        self._recovering = False
        self._seq = 0
        self._chain = ""

    def _keep(self, fd: int) -> int:
        self._fds.append(fd)
        return fd

    def _create(self, parent: int, name: str, *, directory: bool = False) -> int:
        if directory:
            os.mkdir(name, 0o700, dir_fd=parent)
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            self._created.append((parent, name, info.st_ino, True))
            return self._keep(os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                      dir_fd=parent))
        fd = self._keep(os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                               0o600 if name == ".writer.lock" else 0o400, dir_fd=parent))
        self._created.append((parent, name, os.fstat(fd).st_ino, False))
        return fd

    def _read(self, parent: int, name: str) -> bytes:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(fd)
            _private(info)
            if info.st_mode & 0o222:
                raise JournalError("journal evidence files must be immutable")
            chunks = []
            while chunk := os.read(fd, 1024 * 1024):
                chunks.append(chunk)
            if self._recovering:
                # A prior writer may have died between write/rename and fsync.
                # Seal only bytes made durable again by this recovery.
                os.fsync(fd)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def _subdirectory(self, name: str) -> int:
        fd = self._keep(os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=self._root))
        _private(os.fstat(fd), directory=True)
        return fd

    def __enter__(self) -> Journal:
        if self._entered:
            raise RuntimeError("a Journal context cannot be entered twice")
        self._entered = True
        try:
            self._root = self._keep(_directory(self.directory, create=not self.resume))
            if self.resume:
                # Identity is checked before opening a writable descriptor or creating anything.
                _private(os.fstat(self._root), directory=True)
                header = _decode(self._read(self._root, "identity.json"))
                self._validate_identity(header)
                self._lock = self._keep(os.open(".writer.lock", os.O_RDWR | os.O_NOFOLLOW
                                                | os.O_NONBLOCK, dir_fd=self._root))
                _private(os.fstat(self._lock))
            else:
                self._check_new_output()
            # Lock the directory inode as well as the named reservation. Replacing
            # .writer.lock must not let a second writer bypass the first lock.
            try:
                fcntl.flock(self._root, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise JournalError("journal already has an active writer") from exc
            if not self.resume:
                self._lock = self._create(self._root, ".writer.lock")
            try:
                fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise JournalError("journal already has an active writer") from exc
            os.fsync(self._lock)
            if self.resume:
                # Recheck under the lock before examining the append-only stream.
                self._recovering = True
                header = _decode(self._read(self._root, "identity.json"))
                self._validate_identity(header)
                self._segments = self._subdirectory("segments")
                self._payloads = self._subdirectory("payloads")
                previous, number, torn = self._replay(header["sha256"])
                os.fsync(self._payloads)
                os.fsync(self._segments)
                os.fsync(self._root)
                self._recovering = False
            else:
                self._check_new_output(locked=True)
                os.fchmod(self._root, 0o700)
                header = _signed({"schema": 1, "identity": _decode(self._identity_bytes)})
                fd = self._create(self._root, "identity.json")
                _write_all(fd, _canonical(header) + b"\n")
                os.fsync(fd)
                self._segments = self._create(self._root, "segments", directory=True)
                self._payloads = self._create(self._root, "payloads", directory=True)
                os.fsync(self._root)
                self._chain = header["sha256"]
                previous, number, torn = None, 1, None
            self._identity_info = os.stat("identity.json", dir_fd=self._root,
                                          follow_symlinks=False)
            self._check_storage()
            segment_header = _signed({"schema": 1, "segment": number,
                                      "next_seq": self._seq + 1, "prev": self._chain,
                                      "previous_segment_sha256": previous,
                                      "previous_torn_tail_sha256": torn})
            self._segment_number = number
            self._segment = self._create(self._segments, f"{number:08d}.jsonl")
            _write_all(self._segment, _canonical(segment_header) + b"\n")
            os.fsync(self._segment)
            os.fsync(self._segments)
            self._chain = segment_header["sha256"]
            self._active = True
            self._check_storage()
            self._created.clear()
            return self
        except BaseException:
            # Remove only files/inodes created by this failed entry. Never remove
            # another contender's reservation or any pre-existing journal bytes.
            for parent, name, inode, directory in reversed(self._created):
                try:
                    if os.stat(name, dir_fd=parent, follow_symlinks=False).st_ino == inode:
                        if directory:
                            os.rmdir(name, dir_fd=parent)
                        else:
                            os.unlink(name, dir_fd=parent)
                        os.fsync(parent)
                except OSError:
                    pass
            self._close()
            raise

    def _check_new_output(self, *, locked: bool = False) -> None:
        if os.fstat(self._root).st_uid != os.geteuid():
            raise JournalError("output directory must be owned by the journal writer")
        allowed = {"cache", ".writer.lock"} if locked else {"cache"}
        for name in os.listdir(self._root):
            if name not in allowed:
                raise FileExistsError("output is not a new no-LLM journal directory")
            if name == "cache":
                info = os.stat(name, dir_fd=self._root, follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode):
                    raise JournalError("output cache must be a real directory")

    def _validate_identity(self, header: dict) -> None:
        _checked(header)
        if (set(header) != {"schema", "identity", "sha256"}
                or type(header["schema"]) is not int or header["schema"] != 1):
            raise JournalError("unsupported journal identity schema")
        if _canonical(header["identity"]) != self._identity_bytes:
            raise JournalError("journal identity mismatch")

    def _replay(self, initial: str) -> tuple[str | None, int, str | None]:
        names = sorted(os.listdir(self._segments))
        self._chain = initial
        previous = torn = None
        for number, name in enumerate(names, 1):
            if name != f"{number:08d}.jsonl":
                raise JournalError("invalid or missing journal segment")
            raw = self._read(self._segments, name)
            lines = raw.split(b"\n")
            expected = {"schema": 1, "segment": number, "next_seq": self._seq + 1,
                        "prev": self._chain, "previous_segment_sha256": previous,
                        "previous_torn_tail_sha256": torn}
            if len(lines) < 2:
                # A kill can interrupt the first write of a new segment, too.
                # Its exact bytes become part of the next segment's recovery link.
                header = self._check_torn(raw)
                if header is not None:
                    self._segment_header(header, expected)
                self.torn_tails.append(name)
                previous, torn = _digest(raw), _digest(raw)
                continue
            header = _decode(lines[0])
            self._segment_header(header, expected)
            self._chain = header["sha256"]
            for line in lines[1:-1]:
                record = _decode(line)
                self._event(record)
                self.events.append(record)
                self._seq += 1
                self._chain = record["sha256"]
            tail = lines[-1]
            if tail:
                pending = self._check_torn(tail)
                if pending is not None:
                    self._event(pending)
                self.torn_tails.append(name)
            previous = _digest(raw)
            torn = _digest(tail) if tail else None
        if not names:
            raise JournalError("journal has no initial segment")
        return previous, len(names) + 1, torn

    @staticmethod
    def _segment_header(header: dict, expected: dict) -> None:
        _checked(header)
        if (any(type(header.get(key)) is not int for key in ("schema", "segment", "next_seq"))
                or {key: value for key, value in header.items() if key != "sha256"} != expected):
            raise JournalError("journal segment chain mismatch")

    def _event(self, record: dict) -> None:
        _checked(record)
        if (set(record) != {"seq", "kind", "data", "prev", "sha256"}
                or type(record["seq"]) is not int or record["seq"] != self._seq + 1
                or record["prev"] != self._chain or not isinstance(record["kind"], str)
                or not record["kind"] or not isinstance(record["data"], dict)):
            raise JournalError("journal event sequence or structure mismatch")
        self._references(record["data"])

    @staticmethod
    def _check_torn(tail: bytes) -> dict | None:
        # Only a valid JSON prefix can be a torn write. Garbage without a final
        # newline is corruption, not permission to skip an unauthenticated row.
        partial_utf8 = False
        try:
            text = tail.decode("utf-8")
        except UnicodeDecodeError as exc:
            if exc.reason != "unexpected end of data" or exc.end != len(tail):
                raise JournalError("invalid journal UTF-8") from exc
            text = tail[:exc.start].decode("utf-8")
            partial_utf8 = True
            if not text:
                return None
        try:
            json.loads(text)
        except json.JSONDecodeError as exc:
            remaining = text[exc.pos:]
            incomplete_string = exc.msg.startswith("Unterminated string")
            incomplete = (
                incomplete_string
                or (exc.pos == len(text) and exc.msg in {
                    "Expecting value", "Expecting ',' delimiter", "Expecting ':' delimiter",
                    "Expecting property name enclosed in double quotes"})
                or (exc.msg == "Expecting value" and remaining in {
                    "t", "tr", "tru", "f", "fa", "fal", "fals", "n", "nu", "nul", "-"})
                or (exc.msg == "Expecting ',' delimiter"
                    and re.fullmatch(r"(?:\.|[eE][+-]?)", remaining) is not None)
                or (exc.msg == "Invalid \\uXXXX escape"
                    and re.fullmatch(r"u[0-9a-fA-F]{0,3}", remaining) is not None)
            )
            if incomplete and (not partial_utf8 or incomplete_string):
                return None
            raise JournalError("malformed final journal record") from exc
        if partial_utf8:
            raise JournalError("invalid trailing journal UTF-8")
        return _decode(tail)

    def _check_storage(self) -> None:
        """Reject renamed/unlinked storage instead of writing through stale fds."""
        def same(actual, expected):
            if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                raise JournalError("journal storage was replaced")

        try:
            root = _directory(self.directory, create=False)
            try:
                same(os.fstat(root), os.fstat(self._root))
                _private(os.fstat(root), directory=True)
            finally:
                os.close(root)
            for name, fd, directory in ((".writer.lock", self._lock, False),
                                         ("segments", self._segments, True),
                                         ("payloads", self._payloads, True)):
                info = os.stat(name, dir_fd=self._root, follow_symlinks=False)
                same(info, os.fstat(fd))
                _private(info, directory=directory)
            identity = os.stat("identity.json", dir_fd=self._root, follow_symlinks=False)
            same(identity, self._identity_info)
            _private(identity)
            if identity.st_mode & 0o222:
                raise JournalError("journal evidence files must be immutable")
            if self._active:
                name = f"{self._segment_number:08d}.jsonl"
                info = os.stat(name, dir_fd=self._segments, follow_symlinks=False)
                same(info, os.fstat(self._segment))
                _private(info)
                if info.st_mode & 0o222:
                    raise JournalError("journal evidence files must be immutable")
        except OSError as exc:
            raise JournalError("missing or unsafe journal storage") from exc

    def _require_active(self) -> None:
        if not self._active or self._poisoned:
            raise RuntimeError("journal is not an active healthy writer")
        try:
            self._check_storage()
        except BaseException:
            self._poisoned = True
            raise

    def append(self, kind: str, data: dict) -> dict:
        """Persist one event; caller, not the journal, defines semantic commits."""
        self._require_active()
        if not isinstance(kind, str) or not kind or not isinstance(data, dict):
            raise TypeError("journal events require a nonempty kind and dict data")
        record = _signed({"seq": self._seq + 1, "kind": kind,
                          "data": _decode(_canonical(data)), "prev": self._chain})
        self._references(record["data"])
        try:
            _write_all(self._segment, _canonical(record) + b"\n")
            os.fsync(self._segment)
            self._check_storage()
        except BaseException:
            self._poisoned = True
            raise
        self._seq += 1
        self._chain = record["sha256"]
        self.events.append(record)
        return _decode(_canonical(record))

    @staticmethod
    def _reference(reference: dict) -> tuple[str, str]:
        if not isinstance(reference, dict):
            raise JournalError("invalid payload reference")
        path, digest = reference.get("path"), reference.get("sha256")
        if (not isinstance(path, str) or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or not re.fullmatch(r"payloads/[0-9a-f]{64}\.[A-Za-z0-9][A-Za-z0-9._-]{0,31}", path)
                or path.split("/", 1)[1].split(".", 1)[0] != digest):
            raise JournalError("invalid or escaping payload reference")
        return path.split("/", 1)[1], digest

    def _load_bytes(self, reference: dict) -> bytes:
        name, digest = self._reference(reference)
        try:
            data = self._read(self._payloads, name)
        except OSError as exc:
            raise JournalError("missing or unsafe journal payload") from exc
        if _digest(data) != digest:
            raise JournalError("payload checksum mismatch")
        return data

    def _references(self, value: object, seen: set[str] | None = None) -> None:
        if seen is None:
            seen = set()
        if isinstance(value, dict):
            path = value.get("path")
            owned_prefix = str(self.directory / "payloads") + "/"
            if isinstance(path, str) and path.startswith(owned_prefix):
                # Canonical capture consumers need absolute paths; these still
                # belong to this journal and require descriptor-relative reads.
                path = "payloads/" + path[len(owned_prefix):]
            if isinstance(path, str) and path.startswith("payloads/"):
                reference = {**value, "path": path}
                # Validate even repeated references: a duplicate path with a
                # different digest must not be hidden by the traversal cache.
                self._reference(reference)
                if path not in seen:
                    seen.add(path)
                    raw = self._load_bytes(reference)
                    if path.endswith(".json"):
                        self._references(_decode(raw), seen)
            for child in value.values():
                self._references(child, seen)
        elif isinstance(value, list):
            for child in value:
                self._references(child, seen)

    def store(self, value: dict) -> dict:
        if not isinstance(value, dict):
            raise TypeError("journal JSON payload must be a dict")
        return self.store_bytes(_canonical(value), suffix=".json")

    def store_bytes(self, data: bytes, suffix: str = ".bin") -> dict:
        """Publish immutable bytes only after their contents have reached storage."""
        self._require_active()
        if not isinstance(data, bytes):
            raise TypeError("journal byte payload must be bytes")
        if not isinstance(suffix, str) or not re.fullmatch(r"\.[A-Za-z0-9][A-Za-z0-9._-]{0,31}", suffix):
            raise JournalError("unsafe payload suffix")
        digest = _digest(data)
        name = digest + suffix
        reference = {"path": "payloads/" + name, "sha256": digest}
        try:
            os.stat(name, dir_fd=self._payloads, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            self._load_bytes(reference)
            return reference
        temporary = ".pending-" + uuid.uuid4().hex
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o400, dir_fd=self._payloads)
            try:
                _write_all(fd, data)
                os.fsync(fd)
                try:
                    _publish(self._payloads, temporary, name)
                except FileExistsError:
                    # A substituted file must be authenticated, never overwritten.
                    self._load_bytes(reference)
            finally:
                os.close(fd)
                try:
                    os.unlink(temporary, dir_fd=self._payloads)
                except FileNotFoundError:
                    pass
            os.fsync(self._payloads)
            self._check_storage()
            self._load_bytes(reference)
        except BaseException:
            # In particular, a failed directory fsync can leave a visible but
            # not durable payload. Do not let deduplication commit it on retry.
            self._poisoned = True
            raise
        return reference

    def load(self, reference: dict) -> dict:
        self._require_active()
        value = _decode(self._load_bytes(reference))
        self._references(value)
        return value

    def _close(self) -> None:
        self._active = False
        for fd in reversed(self._fds):
            os.close(fd)
        self._fds.clear()

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self._close()
