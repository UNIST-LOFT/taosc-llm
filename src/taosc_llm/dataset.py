"""Identity-bound, file-backed prepared datasets (no P1 evidence compatibility)."""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from threading import RLock
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from binradar import binradar_setup
from binradar import binradar_taosc_predicates as predicates


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path):
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"duplicate JSON field: {key}")
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def bound_path(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ValueError("dataset path must be root-relative")
    path = root / relative
    if not path.resolve().is_relative_to(root.resolve()) or path.is_symlink():
        raise ValueError("dataset path escapes immutable root")
    return path


def _capture_selector(capture: dict) -> int:
    branches = capture.get("branches")
    if (not isinstance(branches, list)
            or any(type(branch) is not int or branch not in (0, 1, 2) for branch in branches)):
        raise ValueError("capture-vector-invalid")
    selector = capture.get("patch_id", capture.get("capture_id", 0))
    if (type(selector) is not int or not -1 <= selector <= 0xffffffff
            or (selector == -1 and branches)):
        raise ValueError("capture-id-invalid")
    return selector


@dataclass(frozen=True)
class PreparedDataset:
    root: Path
    manifest: dict

    @property
    def dataset_id(self) -> str:
        return self.manifest["dataset_id"]

    @property
    def workdir(self) -> Path:
        return self.root / "workdir"

    @property
    def binary(self) -> str:
        return self.manifest["binary"]

    @property
    def patch_format(self) -> str:
        return self.manifest["patch_format"]

    def artifact(self, name: str) -> Path:
        try:
            record = self.manifest["artifacts"][name]
        except KeyError as exc:
            raise ValueError(f"dataset artifact unavailable: {name}") from exc
        return bound_path(self.root, record["path"])

    def _verify(self, record: dict) -> Path:
        path = bound_path(self.root, record["path"])
        if not path.is_file() or sha256(path) != record["sha256"]:
            raise ValueError(f"dataset hash mismatch: {record['path']}")
        return path

    @contextmanager
    def validation(self, *, check=None):
        """Authenticate one operation; never retain trust on the source dataset.

        The yielded view may be shared with read-only workers which finish before
        this context exits. Nested scopes on that view reuse its validation.
        """
        if check is not None:
            check()
        validated = _ValidatedDataset(self)
        try:
            validated._validate_all(check=check)
            validated.execution_environment()
            if check is not None:
                check()
            yield validated
        finally:
            validated._expire()

    def verify_artifacts(self) -> None:
        with self.validation():
            pass

    def _validate_all(self, *, check=None) -> None:
        identity = dict(self.manifest)
        identity.pop("dataset_id", None)
        if hashlib.sha256(canonical(identity)).hexdigest() != self.dataset_id:
            raise ValueError("dataset manifest identity mismatch")
        for record in (*self.manifest["artifacts"].values(), *self.manifest["analysis"]):
            if check is not None:
                check()
            self._verify(record)
        self._verify(self.manifest["cases"])
        seen = set()
        for case in self._case_rows():
            if check is not None:
                check()
            if case["id"] in seen or case["domain"] not in ("system", "function"):
                raise ValueError("duplicate or invalid case")
            seen.add(case["id"])
            if not re.fullmatch(r"(?:system|function):[0-9]+", case["id"]) or not case["id"].startswith(case["domain"] + ":"):
                raise ValueError("invalid scoped case id/domain binding")
            if case["input_path"] is not None:
                self._verify({"path": case["input_path"], "sha256": case["input_sha256"]})
            if case["domain"] == "function" and (
                    not isinstance(case["capture"], dict)
                    or case["capture"].get("timeout_excluded") is not True
                    or case["capture"].get("outcome", {}).get("outcome")
                    in ("timeout", "cancelled")):
                raise ValueError(
                    "function evidence lacks authenticated timeout exclusion; regenerate "
                    "the BinRadar mutation run and prepare a new dataset (old caches are not reusable)")
            if case["capture"] is not None:
                self.snapshots(case["capture"])

    def _case_rows(self) -> list[dict]:
        # Internal readers must not mutate these rows or expose them to callers.
        path = self._verify(self.manifest["cases"])
        with path.open() as stream:
            return [json.loads(line) for line in stream if line.strip()]

    def cases(self, domain: str = "all") -> list[dict]:
        if domain not in ("all", "system", "function"):
            raise ValueError("invalid case domain")
        return [row for row in self._case_rows() if domain == "all" or row["domain"] == domain]

    def case(self, case_id: str) -> dict:
        if not isinstance(case_id, str) or not re.fullmatch(r"(?:system|function):[0-9]+", case_id):
            raise ValueError("invalid scoped case id")
        for row in self.cases():
            if row["id"] == case_id:
                return row
        raise ValueError(f"unknown dataset case: {case_id}")

    def snapshots(self, capture: dict) -> list[predicates.CachedSnapshot]:
        if capture.get("complete") is not True:
            raise ValueError("incomplete capture")
        if capture.get("artifact_sha256") != self.manifest["artifacts"][self.binary + ".brcached"]["sha256"]:
            raise ValueError("capture artifact identity mismatch")
        selector = _capture_selector(capture)
        snapshots = self._parsed_capture(capture)
        if [item.branch for item in snapshots] != capture.get("branches"):
            raise ValueError("capture branch vector mismatch")
        cwe805 = self.patch_format == "ERM CWE-805"
        stack = int(self.execution_environment().get("BRCACHE_STACK_SIZE", "0"), 0)
        if any(item.is_CWE805 != cwe805 or len(item.stack) != (stack if cwe805 else 0)
               for item in snapshots):
            raise ValueError("capture family/stack mismatch")
        if not isinstance(capture.get("descriptor"), str) or not capture["descriptor"]:
            raise ValueError("capture descriptor unavailable")
        descriptor = self._memo("descriptor", capture["descriptor"],
                                lambda: predicates.parse_predicate_descriptor(capture["descriptor"]))
        if capture["descriptor"] != "p0" and isinstance(descriptor, str) == cwe805:
            raise ValueError("capture descriptor family mismatch")
        if any(item.patch_id != selector for item in snapshots):
            raise ValueError("capture selector identity mismatch")
        return list(snapshots)

    def _memo(self, namespace, key, factory):
        # Raw datasets retain no trust or derived state between operations.
        return factory()

    def _capture_payload(self, capture: dict) -> bytes:
        def read_record(record):
            path = Path(record["path"])
            absolute = path.is_absolute()
            if not absolute:
                path = bound_path(self.root, record["path"])
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != record["sha256"]:
                raise ValueError("capture-hash-mismatch" if absolute
                                 else f"dataset hash mismatch: {record['path']}")
            return raw
        if "sidecar" in capture:
            read_record(capture["sidecar"])
        return read_record(capture)

    def _parsed_capture(self, capture: dict) -> tuple[predicates.CachedSnapshot, ...]:
        # Parsing is context-free, but every referenced path and sidecar must
        # authenticate before content-addressed parse reuse is allowed.
        raw = self._capture_payload(capture)
        def parse():
            snapshots, error = predicates.parse_cached_snapshots(raw)
            if error:
                raise ValueError(error)
            return tuple(snapshots)
        return self._memo("parsed-brch", capture["sha256"], parse)

    def capture_bytes(self, capture: dict) -> bytes:
        """Return bytes only after the complete capture binding is authenticated."""
        from .evaluation import _snapshots
        with self.validation() as validated:
            _snapshots(validated, capture)
            return validated._capture_payload(capture)

    def execution_environment(self) -> dict[str, str]:
        allowed = {"BINARY", "TEST_CMD", "POC_INPUT", "POC_DIR", "MEMCHECK", "PATCH_LOC", "PATCH_DEST",
                   "BRCACHE_STACK_SIZE", "BINRADAR_QEMU_EXEC_TIMEOUT", "BINRADAR_PROBE_TRACER_TIMEOUT",
                   "BINRADAR_FORKSERVER_CHILD_TIMEOUT_CAP"}
        result = {}
        for name in ("config.env", "binradar.env", "generate-concrete.env", "generate-binradar.env"):
            if name not in self.manifest["artifacts"]:
                continue
            self._verify(self.manifest["artifacts"][name])
            for key, value in binradar_setup.load_env(self.artifact(name)).items():
                if key in allowed or key.startswith(("E9_", "BRCACHED_E9_", "BRPATCHED_E9_")):
                    if key in ("PATCH_LOC", "PATCH_DEST"):
                        field = "location" if key == "PATCH_LOC" else "destination"
                        if int(value, 16) != self.manifest["patch"][field]:
                            raise ValueError(f"{name} {key} identity mismatch")
                    if "\x00" in value or "\n" in value:
                        raise ValueError("invalid execution environment value")
                    result[key] = value
        if result.get("BINARY") != self.binary or "TEST_CMD" not in result:
            raise ValueError("missing explicit execution configuration")
        for key in ("BINRADAR_QEMU_EXEC_TIMEOUT", "BINRADAR_PROBE_TRACER_TIMEOUT", "BINRADAR_FORKSERVER_CHILD_TIMEOUT_CAP"):
            if key in result:
                import math
                number = float(result[key])
                if not math.isfinite(number) or number <= 0:
                    raise ValueError(f"invalid {key}")
        if self.patch_format == "ERM CWE-805":
            stack_record = self.manifest["artifacts"].get("stack-size")
            if stack_record is None:
                raise ValueError("CWE-805 stack-size unavailable")
            stack_text = self._verify(stack_record).read_text().strip()
            if "BRCACHE_STACK_SIZE" in result and int(result["BRCACHE_STACK_SIZE"], 0) != int(stack_text, 0):
                raise ValueError("capture and family stack sizes disagree")
            result["BRCACHE_STACK_SIZE"] = stack_text
        stack = int(result.get("BRCACHE_STACK_SIZE", "0"), 0)
        if not 0 <= stack <= 0x100000:
            raise ValueError("invalid capture stack size")
        return result


class _ValidatedDataset(PreparedDataset):
    """Short-lived trust state, owned by exactly one validation context."""

    def __init__(self, source: PreparedDataset):
        root = source.root.resolve(strict=True)
        if root != source.root.absolute() or not root.is_dir():
            raise ValueError("dataset root is no longer immutable")
        object.__setattr__(self, "root", root)
        object.__setattr__(self, "manifest", deepcopy(source.manifest))
        object.__setattr__(self, "_active", True)
        object.__setattr__(self, "_lock", RLock())
        object.__setattr__(self, "_paths", {})
        object.__setattr__(self, "_verified", {})
        object.__setattr__(self, "_rows", None)
        object.__setattr__(self, "_case_index", {})
        object.__setattr__(self, "_captures", {})
        object.__setattr__(self, "_operation_cache", {})
        object.__setattr__(self, "_environment", None)

    def __getattribute__(self, name):
        if not name.startswith("_"):
            object.__getattribute__(self, "_ensure_active")()
        return object.__getattribute__(self, name)

    def _ensure_active(self):
        if not self._active:
            raise ValueError("dataset validation scope has expired")

    def _expire(self):
        with self._lock:
            object.__setattr__(self, "_active", False)
            self._paths.clear()
            self._verified.clear()
            self._case_index.clear()
            self._captures.clear()
            self._operation_cache.clear()
            object.__setattr__(self, "_rows", None)
            object.__setattr__(self, "_environment", None)
            object.__setattr__(self, "manifest", {})

    @contextmanager
    def validation(self, *, check=None):
        self._ensure_active()
        if check is not None:
            check()
        yield self

    def _memo(self, namespace, key, factory):
        """Share immutable derived values only within this authenticated operation."""
        with self._lock:
            self._ensure_active()
            cache = self._operation_cache.setdefault(namespace, {})
            if key not in cache:
                cache[key] = factory()
            return cache[key]

    def _capture_payload(self, capture: dict) -> bytes:
        # Authenticate sidecars independently even when BRCH bytes are shared.
        sidecar = capture.get("sidecar")
        if sidecar is not None:
            self._record_bytes(sidecar)
        return self._record_bytes(capture)

    def _record_bytes(self, record: dict) -> bytes:
        key = (record["path"], record["sha256"])
        def load():
            path = Path(record["path"])
            absolute = path.is_absolute()
            if not absolute:
                path = self._path(record["path"])
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != record["sha256"]:
                raise ValueError("capture-hash-mismatch" if absolute
                                 else f"dataset hash mismatch: {record['path']}")
            if not absolute:
                self._verified[key] = path
            return raw
        return self._memo("record-bytes", key, load)

    def _path(self, relative):
        self._ensure_active()
        if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise ValueError("dataset path must be root-relative")
        if relative not in self._paths:
            path = self.root / relative
            # Let the kernel resolve current ancestry for every unseen path.
            # Python's Path.resolve() lstats every absolute ancestor for every
            # sibling; caching those ancestors would miss mid-operation link
            # replacement before an as-yet unauthenticated sibling is read.
            try:
                fd = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
            except FileNotFoundError:
                # Preserve non-strict path lookup and _verify's hash-mismatch
                # error for missing records; no successful path trust is cached.
                return bound_path(self.root, relative)
            try:
                try:
                    resolved = Path(os.readlink(f"/proc/self/fd/{fd}"))
                except OSError as exc:
                    raise ValueError(
                        "dataset validation requires accessible Linux /proc/self/fd") from exc
                # Intermediate links may leave and return inside the root, but
                # leaf links are forbidden even when their bytes would match.
                if (stat.S_ISLNK(os.fstat(fd).st_mode)
                        or not resolved.is_relative_to(self.root)):
                    raise ValueError("dataset path escapes immutable root")
            finally:
                os.close(fd)
            self._paths[relative] = path
        return self._paths[relative]

    def artifact(self, name: str) -> Path:
        with self._lock:
            try:
                record = self.manifest["artifacts"][name]
            except KeyError as exc:
                raise ValueError(f"dataset artifact unavailable: {name}") from exc
            return self._path(record["path"])

    def _verify(self, record: dict) -> Path:
        with self._lock:
            self._ensure_active()
            key = (record["path"], record["sha256"])
            if key not in self._verified:
                path = self._path(record["path"])
                if not path.is_file() or sha256(path) != record["sha256"]:
                    raise ValueError(f"dataset hash mismatch: {record['path']}")
                self._verified[key] = path
            return self._verified[key]

    def _case_rows(self) -> list[dict]:
        with self._lock:
            self._ensure_active()
            if self._rows is None:
                rows = super()._case_rows()
                object.__setattr__(self, "_rows", rows)
                self._case_index.update((row["id"], row) for row in rows)
            return self._rows

    def cases(self, domain: str = "all") -> list[dict]:
        with self._lock:
            if domain not in ("all", "system", "function"):
                raise ValueError("invalid case domain")
            return deepcopy([row for row in self._case_rows() if domain == "all" or row["domain"] == domain])

    def case(self, case_id: str) -> dict:
        with self._lock:
            if not isinstance(case_id, str) or not re.fullmatch(r"(?:system|function):[0-9]+", case_id):
                raise ValueError("invalid scoped case id")
            if self._rows is None:
                self._case_rows()
            try:
                return deepcopy(self._case_index[case_id])
            except KeyError as exc:
                raise ValueError(f"unknown dataset case: {case_id}") from exc

    def snapshots(self, capture: dict) -> list[predicates.CachedSnapshot]:
        with self._lock:
            # Bind every field, not just the byte digest: descriptors, branch
            # vectors, sidecars and selectors are independent trust assertions.
            key = canonical(capture)
            if key not in self._captures:
                self._captures[key] = tuple(super().snapshots(capture))
            # CachedSnapshot is frozen and contains only tuples/bytes/scalars.
            # Copy the small outer list, never large stacks or register data.
            return list(self._captures[key])

    def execution_environment(self) -> dict[str, str]:
        with self._lock:
            if self._environment is None:
                object.__setattr__(self, "_environment", super().execution_environment())
            return dict(self._environment)


def load_dataset(path: Path) -> PreparedDataset:
    path = Path(path).resolve(strict=True)
    manifest_path = path / "manifest.json" if path.is_dir() else path
    manifest = read_json(manifest_path)
    if manifest.get("schema_version") != 2 or manifest.get("patch_format") not in ("ERM generic", "ERM CWE-805"):
        raise ValueError("only prepared v2 ERM datasets are supported")
    binary = manifest.get("binary")
    if not isinstance(binary, str) or Path(binary).name != binary or binary in ("", ".", ".."):
        raise ValueError("invalid dataset binary")
    patch = manifest.get("patch", {})
    if patch.get("address_domain") != "elf-va" or any(
            type(patch.get(key)) is not int or not minimum <= patch[key] < 2**64
            for key, minimum in (("location", 1), ("destination", 0))):
        raise ValueError("invalid ELF patch addresses")
    dataset = PreparedDataset(manifest_path.parent, manifest)
    dataset.verify_artifacts()
    return dataset
