"""Identity-bound, file-backed prepared datasets (no P1 evidence compatibility)."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

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

    def verify_artifacts(self) -> None:
        identity = dict(self.manifest)
        identity.pop("dataset_id", None)
        if hashlib.sha256(canonical(identity)).hexdigest() != self.dataset_id:
            raise ValueError("dataset manifest identity mismatch")
        for record in self.manifest["artifacts"].values():
            self._verify(record)
        for record in self.manifest["analysis"]:
            self._verify(record)
        self._verify(self.manifest["cases"])
        seen = set()
        for case in self.cases():
            if case["id"] in seen or case["domain"] not in ("system", "function"):
                raise ValueError("duplicate or invalid case")
            seen.add(case["id"])
            if not re.fullmatch(r"(?:system|function):[0-9]+", case["id"]) or not case["id"].startswith(case["domain"] + ":"):
                raise ValueError("invalid scoped case id/domain binding")
            if case["input_path"] is not None:
                self._verify({"path": case["input_path"], "sha256": case["input_sha256"]})
            if case["capture"] is not None:
                self.snapshots(case["capture"])

    def cases(self, domain: str = "all") -> list[dict]:
        if domain not in ("all", "system", "function"):
            raise ValueError("invalid case domain")
        path = self._verify(self.manifest["cases"])
        with path.open() as stream:
            rows = [json.loads(line) for line in stream if line.strip()]
        return [row for row in rows if domain == "all" or row["domain"] == domain]

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
        path = self._verify(capture)
        if "sidecar" in capture:
            self._verify(capture["sidecar"])
        snapshots, error = predicates.parse_cached_snapshots(path.read_bytes())
        if error or [item.branch for item in snapshots] != capture.get("branches"):
            raise ValueError(error or "capture branch vector mismatch")
        cwe805 = self.patch_format == "ERM CWE-805"
        stack = int(self.execution_environment().get("BRCACHE_STACK_SIZE", "0"), 0)
        if any(item.is_CWE805 != cwe805 or len(item.stack) != (stack if cwe805 else 0)
               for item in snapshots):
            raise ValueError("capture family/stack mismatch")
        if not isinstance(capture.get("descriptor"), str) or not capture["descriptor"]:
            raise ValueError("capture descriptor unavailable")
        descriptor = predicates.parse_predicate_descriptor(capture["descriptor"])
        if capture["descriptor"] != "p0" and isinstance(descriptor, str) == cwe805:
            raise ValueError("capture descriptor family mismatch")
        if "patch_id" in capture and any(item.patch_id != capture["patch_id"] for item in snapshots):
            raise ValueError("capture selector identity mismatch")
        return snapshots

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
    if patch.get("address_domain") != "elf-va" or any(type(patch.get(key)) is not int or not 0 < patch[key] < 2**64 for key in ("location", "destination")):
        raise ValueError("invalid ELF patch addresses")
    dataset = PreparedDataset(manifest_path.parent, manifest)
    dataset.verify_artifacts()
    dataset.execution_environment()
    return dataset
