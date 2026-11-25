"""Single-first patch selection over common Taosc preparation.

``taosc-llm-patch`` consumes a completed common ``taosc-prepare`` workdir and a
completed original-only concrete run. It tries applicable fixed Single
families at captured site/action associations and publishes one accepted artifact,
or falls back to clean ERM preparation for the existing predicate-synthesis path.

A trial is accepted only after every admitted concrete input is re-observed:
each input must still reach the collection site; additional sites get fresh
original observations, including nonhits in the full proof. A moved selection
publishes a new original-only run containing exactly its observed hit cases.
A target crash must become a
candidate normal with a fired repair branch; a normal input must stay normal; an
unrelated original crash must stay that same unrelated crash. A plain "does
not crash" replay is insufficient. Unavailable observations, timeouts and
artifact changes are errors, not Single rejection, so infrastructure failure is
never reported as an exhausted Single search.

The source preparation and concrete run stay immutable. The caller names a
fresh output workdir; the selector copies only common inputs under a private
staging root and publishes atomically. Trials and their observations remain
under ``trials/``; ``patch-selection.json`` binds the selected artifacts, the
concrete corpus and the trial verdict by SHA-256. ``verified`` stays false:
acceptance here is corpus observation, never BinRadar FINAL.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Any

from .patch_execution import observe


SINGLE_FORMATS = ("Single CWE-617", "Single CWE-369", "Single CWE-823", "Single CWE-805")
ERM_FORMATS = ("ERM generic", "ERM CWE-805")
FORMATS = SINGLE_FORMATS + ERM_FORMATS
_COMMON_FILES = (
    "args", "poc", "poc-exit-code", "source-binary", "original-sha256",
    "patch-candidates", "patch-location", "destinations", "patch-destination",
    "generate-concrete.env",
)
# Optional completed-stage evidence retained when a source workdir already has
# it; common-only preparation does not require these family-specific inputs.
_OPTIONAL_FILES = ("patch-format", "patch-stage.json", "stack-size")
_ENVIRONMENT_FILES = ("generate-concrete.env",)
_SELECTION = "patch-selection.json"
_DIAGNOSTIC_LIMIT = 1024 * 1024
_CHUNK = 64
_PUBLISHED_SINGLE = ("patched", "patched.json", "brpatched", "brpatched.json")


class SelectionError(RuntimeError):
    """A required selector input, trial or publication failed."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _reference(root: Path, path: Path) -> dict:
    return {"path": str(path.relative_to(root)), "sha256": _sha256(path)}


def _atomic_json(path: Path, value) -> None:
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_json(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise SelectionError(f"required regular file unavailable: {path}")
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise SelectionError(f"unreadable JSON: {path}: {error}") from error
    if not isinstance(value, dict):
        raise SelectionError(f"expected a JSON object: {path}")
    return value


def _read_hex(path: Path, *, allow_zero: bool = False) -> tuple[int, str]:
    if path.is_symlink() or not path.is_file():
        raise SelectionError(f"required regular file unavailable: {path.name}")
    text = path.read_text().strip().lower().removeprefix("0x")
    if not re.fullmatch(r"[0-9a-f]{1,16}", text):
        raise SelectionError(f"invalid hexadecimal address: {path.name}")
    number = int(text, 16)
    if number < (0 if allow_zero else 1):
        raise SelectionError(f"invalid zero address: {path.name}")
    return number, f"0x{number:x}"


def _parse_hex(value: object, *, allow_zero: bool = False) -> tuple[int, str]:
    if not isinstance(value, str):
        raise SelectionError("invalid hexadecimal address")
    text = value.strip().lower().removeprefix("0x")
    if not re.fullmatch(r"[0-9a-f]{1,16}", text):
        raise SelectionError("invalid hexadecimal address")
    number = int(text, 16)
    if number < (0 if allow_zero else 1):
        raise SelectionError("invalid zero address")
    return number, f"0x{number:x}"


def _candidates(path: Path) -> dict[int, list[int]]:
    rows: dict[int, list[int]] = {}
    for line in path.read_text().splitlines():
        fields = line.split()
        if not fields:
            continue
        try:
            location = _parse_hex(fields[0])[0]
            destinations = [_parse_hex(value, allow_zero=True)[0] for value in fields[1:]]
        except SelectionError as error:
            raise SelectionError(f"invalid patch-candidates row: {line}") from error
        # Scout retains sites with no discovered recovery action. Preserve that
        # evidence without inventing an exit action or treating it as a trial.
        rows.setdefault(location, [])
        for destination in destinations:
            if destination not in rows[location]:
                rows[location].append(destination)
    if not rows:
        raise SelectionError("patch-candidates is empty")
    return rows


def _destinations(path: Path) -> list[int]:
    result = []
    for line in path.read_text().splitlines():
        value = line.strip()
        if not value:
            continue
        try:
            number = int(value.removeprefix("0x"), 16)
        except ValueError as error:
            raise SelectionError(f"invalid destination: {value}") from error
        if number not in result:
            result.append(number)
    if not result:
        raise SelectionError("destinations is empty")
    return result


def _invocation(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError as error:
        raise SelectionError(f"invalid target invocation: {error}") from error


def _poc_identity(source: Path, environment: dict, representative: str) -> dict:
    name, directory = environment.get("POC_INPUT", ""), environment.get("POC_DIR", "")
    if (not name or not directory or Path(name).is_absolute() or Path(directory).is_absolute()
            or ".." in Path(name).parts or ".." in Path(directory).parts):
        raise SelectionError("invocation PoC must select the copied prepared PoC bytes")
    poc, poc_dir = source / name, source / directory
    if (poc.is_symlink() or not poc.is_file() or poc_dir.is_symlink()
            or poc.resolve() != (source / "input/poc" / representative).resolve()
            or poc_dir.resolve() != (source / "input/poc").resolve()):
        raise SelectionError("invocation PoC disagrees with authenticated prepared PoC")
    return {"path": str(poc.relative_to(source)), "sha256": _sha256(poc)}


def _subject_configuration(subject: Path, source: Path, metadata: dict) -> dict:
    from binradar.binradar_utils import load_env

    config = subject / "config.env"
    if config.is_symlink() or not config.is_file():
        raise SelectionError(f"subject config.env not found: {config}")
    environment = load_env(str(config))
    if (environment.get("BINARY") != metadata["binary"]
            or "TEST_CMD" not in environment
            or _invocation(environment["TEST_CMD"]) != metadata["invocation"]):
        raise SelectionError("subject config.env invocation disagrees with common preparation")
    if _poc_identity(source, environment, metadata["poc"]) != metadata["poc_identity"]:
        raise SelectionError("subject config.env PoC disagrees with common preparation")
    return _reference(subject, config)


def _environments(source: Path) -> dict:
    result = {}
    for name in _ENVIRONMENT_FILES:
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise SelectionError(f"missing invocation environment: {name}")
        environment = {}
        for line in path.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                environment[key.strip()] = value.strip().strip('"').strip("'")
        result[name] = environment
    return result


def _metadata(source: Path) -> dict:
    """Authenticate a current common preparation; no family metadata is required."""
    for name in _COMMON_FILES:
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise SelectionError(f"missing common preparation input: {name}")
    args = (source / "args").read_text().split(None, 1)
    if not args or Path(args[0]).name != args[0] or args[0] in (".", ".."):
        raise SelectionError("invalid binary basename in args")
    binary = args[0]
    digest = (source / "original-sha256").read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise SelectionError("invalid original-sha256")
    original = source / f"{binary}.orig"
    if original.is_symlink() or not original.is_file() or _sha256(original) != digest:
        raise SelectionError("frozen original hash mismatch")
    source_binary = (source / "source-binary").read_text().strip()
    if not source_binary.startswith("/") or Path(source_binary).name != binary:
        raise SelectionError("invalid source-binary")
    exit_code = (source / "poc-exit-code").read_text().strip()
    if not re.fullmatch(r"[0-9]{1,3}", exit_code) or int(exit_code) > 255:
        raise SelectionError("invalid poc-exit-code")
    location, location_text = _read_hex(source / "patch-location")
    destination, destination_text = _read_hex(source / "patch-destination", allow_zero=True)
    destinations = _destinations(source / "destinations")
    if destination not in destinations:
        raise SelectionError("patch-destination is absent from destinations")
    candidates = _candidates(source / "patch-candidates")
    if location not in candidates or destination not in candidates[location]:
        raise SelectionError("prepared site/action is absent from patch-candidates")
    crash, _ = _read_hex(source / "trace/crash.address")
    poc = (source / "poc").read_text().strip()
    if Path(poc).name != poc or not (source / "input/poc" / poc).is_file():
        raise SelectionError("missing representative PoC")
    environment = _environments(source)["generate-concrete.env"]
    if environment.get("BINARY") != binary:
        raise SelectionError("generate-concrete.env binary identity disagrees")
    if "PATCH_LOC" not in environment or int(environment["PATCH_LOC"], 16) != location:
        raise SelectionError("generate-concrete.env patch location identity disagrees")
    if "TEST_CMD" not in environment:
        raise SelectionError("generate-concrete.env has no TEST_CMD")
    invocation = _invocation(environment["TEST_CMD"])
    if _invocation(args[1] if len(args) > 1 else "") != invocation:
        raise SelectionError("args invocation disagrees with generate-concrete.env")
    poc_identity = _poc_identity(source, environment, poc)
    return {"invocation": invocation, "poc_identity": poc_identity, "binary": binary, "original_sha256": digest, "exit_code": int(exit_code),
            "location": location, "location_text": location_text,
            "destination": destination, "destination_text": destination_text,
            "destinations": destinations, "candidates": candidates,
            "crash": crash, "poc": poc, "environment": environment}


def _allocator(source: Path, exit_code: int) -> bool:
    if exit_code != 139:
        return False
    log = source / "trace/qasan.log"
    if log.is_symlink() or not log.is_file():
        raise SelectionError("missing trace/qasan.log")
    pattern = re.compile(r"#0 0x[0-9a-f]+ in __libqasan_.*alloc", re.IGNORECASE)
    return any(pattern.search(line) for line in log.read_text(errors="replace").splitlines())


def _single_family(metadata: dict, allocator: bool) -> str | None:
    exit_code = metadata["exit_code"]
    if exit_code == 134:
        return "Single CWE-617"
    if exit_code == 136 and metadata["location"] == metadata["crash"]:
        return "Single CWE-369"
    if exit_code == 139 and not allocator and metadata["location"] == metadata["crash"]:
        return "Single CWE-823"
    if exit_code == 139 and allocator and metadata["location"] == metadata["crash"]:
        return "Single CWE-805"
    return None


def _erm_family(allocator: bool) -> str:
    return "ERM CWE-805" if allocator else "ERM generic"


def _concrete_rows(run: Path, location: int, *, check_inputs: bool) -> tuple[list[dict], str]:
    """Original-only rows at the collection site, with a terminal marker.

    ``done`` and the graceful ``wall-time-reached`` stop are both completed
    retained corpora; a missing marker may mean an interrupted append, so its
    rows cannot establish the corpus. The marker kind is part of the identity.
    """
    from binradar import binradar_verifier
    import sbsv

    path = run / "minimizer.sbsv"
    if path.is_symlink() or not path.is_file():
        raise SelectionError(f"concrete run has no minimizer manifest: {path}")
    parser = sbsv.parser()
    parser.add_schema("[testcase] [original-result] [id: int] [file: str] [input-sha256: str] "
                      + binradar_verifier.PROBE_RESULT_SCHEMA_V4.removeprefix("[probe-info] ")
                      + " [time: int]")
    rows, seen, terminal = [], set(), None
    with path.open() as stream:
        header = stream.readline()
        if header != "[minimizer] [baseline] [version 1] [baseline original]\n":
            raise SelectionError("concrete run is not an original-only baseline v1")
        for line in stream:
            if not line.endswith("\n"):
                raise SelectionError("incomplete concrete manifest row")
            if "[minimizer] [done]" in line:
                terminal = "done"
            elif "[minimizer] [stopped] [reason wall-time-reached]" in line:
                terminal = "wall-time-reached"
            elif "[original-result" in line:
                if terminal is not None:
                    raise SelectionError("concrete result follows terminal marker")
                try:
                    row = parser.parse_line_detached(line)
                except (ValueError, TypeError, KeyError) as error:
                    raise SelectionError("malformed concrete original-result row") from error
                if row is None:
                    raise SelectionError("malformed concrete original-result row")
                data = dict(row.data)
                if data.get("version") != binradar_verifier.CURRENT_PROBE_RESULT_VERSION:
                    raise SelectionError("unsupported concrete original-result version")
                if data.get("concrete-oracle") != binradar_verifier.CONCRETE_ORACLE:
                    raise SelectionError("concrete result has an unknown oracle")
                case_id, filename = data.pop("id", None), data.pop("file", None)
                expected = data.pop("input-sha256", None)
                if type(case_id) is not int or case_id < 0 or case_id in seen:
                    raise SelectionError("invalid or duplicate concrete case id")
                if (not isinstance(filename, str) or Path(filename).name != filename
                        or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected)):
                    raise SelectionError("invalid concrete input identity")
                if data.get("patch-loc") != location or type(data.get("patch-hit")) is not int or data["patch-hit"] <= 0:
                    raise SelectionError("concrete result belongs to another site or has no hit")
                if data.get("exit") not in ("crash", "ok"):
                    raise SelectionError("concrete result has an unknown exit outcome")
                if data.get("exit") == "crash":
                    if (data.get("concrete-fault-valid") is not True
                            or type(data.get("fault-addr")) is not int or data["fault-addr"] <= 0
                            or data.get("concrete-fault-source") not in ("native", "relocated")
                            or type(data.get("raw-fault-addr")) is not int
                            or not 0 <= data["raw-fault-addr"] <= 0xffffffffffffffff
                            or (data["concrete-fault-source"] == "native"
                                and data["raw-fault-addr"] != data["fault-addr"])):
                        raise SelectionError("concrete crash lacks a proved fault identity")
                elif data.get("concrete-fault-valid") is not False or data.get("fault-addr") != 0:
                    raise SelectionError("concrete normal result has a fault identity")
                # The producer may legitimately retain a crash at another site;
                # setup filter admits that shape too. Only the exact original
                # fault is a target crash/repair obligation.
                source = run / "minimized" / filename
                if source.is_symlink() or not source.is_file():
                    raise SelectionError(f"concrete input is missing: {source}")
                if check_inputs and _sha256(source) != expected:
                    raise SelectionError(f"concrete input identity changed: {source}")
                seen.add(case_id)
                rows.append({"id": case_id, "path": source, "sha256": expected,
                             "original": data})
    if terminal is None:
        raise SelectionError("concrete run lacks a completed minimizer marker")
    if not rows:
        raise SelectionError("concrete run has no admitted original-site cases")
    return rows, terminal


def _case_digest(rows: list[dict], terminal: str) -> str:
    return hashlib.sha256(_canonical([
        terminal,
        [[row["id"], row["sha256"], row["original"].get("exit"),
          row["original"].get("fault-addr")] for row in sorted(rows, key=lambda item: item["id"])]
    ])).hexdigest()


def _execution_identity(run: Path, *, derived: bool = False) -> dict:
    path = run / "original-identity.json"
    if path.is_symlink() or not path.is_file():
        raise SelectionError("concrete run lacks producer original-identity.json; regenerate original-only evidence")
    identity = _read_json(path)
    kind = "selected-site-original-reobservation" if derived else "original-only-minimizer"
    invocation, poc = identity.get("invocation"), identity.get("poc")
    if (identity.get("schema_version") != 1 or identity.get("kind") != kind
            or not isinstance(invocation, list) or any(not isinstance(arg, str) for arg in invocation)
            or not isinstance(poc, dict) or not isinstance(poc.get("path"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", str(poc.get("sha256", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(identity.get("original_sha256", "")))):
        raise SelectionError("invalid producer original-only execution identity")
    _parse_hex(identity.get("patch_location"))
    return identity


def _match_execution_identity(identity: dict, metadata: dict) -> None:
    expected = {"binary": metadata["binary"], "original_sha256": metadata["original_sha256"],
                "invocation": metadata["invocation"], "patch_location": metadata["location_text"],
                "poc": metadata["poc_identity"]}
    if any(identity.get(key) != value for key, value in expected.items()):
        raise SelectionError("producer original-only identity disagrees with common preparation (original, invocation, PoC or site)")


def _concrete(run: Path, metadata: dict, *, derived: bool = False) -> dict:
    identity = _execution_identity(run, derived=derived)
    _match_execution_identity(identity, metadata)
    rows, terminal = _concrete_rows(run, metadata["location"], check_inputs=True)
    return {"path": str(run), "minimizer_sha256": _sha256(run / "minimizer.sbsv"),
            "identity": _reference(run, run / "original-identity.json"),
            "location": identity["patch_location"], "binary": identity["binary"],
            "original_sha256": identity["original_sha256"], "cases": len(rows),
            "terminal": terminal, "cases_sha256": _case_digest(rows, terminal), "rows": rows}


def _copy_tree(source: Path, destination: Path) -> None:
    """Copy bytes only; never hard-link files a downstream tool may rewrite."""
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    for child in sorted(source.iterdir()):
        target = destination / child.name
        if child.is_dir() and not child.is_symlink():
            _copy_tree(child, target)
        elif child.is_file() and not child.is_symlink():
            shutil.copy2(child, target)
        else:
            raise SelectionError(f"unsupported preparation entry: {child}")


def _source_references(source: Path, binary: str) -> dict:
    paths = [source / name for name in _COMMON_FILES]
    paths.append(source / f"{binary}.orig")
    for directory in (source / "trace", source / "input/poc"):
        if directory.is_symlink() or not directory.is_dir():
            raise SelectionError(f"missing regular source directory: {directory}")
        entries = list(directory.rglob("*"))
        if any(path.is_symlink() for path in entries):
            raise SelectionError(f"source evidence must not contain symlinks: {directory}")
        paths.extend(path for path in entries if path.is_file())
    return {str(path.relative_to(source)): _reference(source, path)
            for path in sorted(paths)}


def _stage_source(source: Path, metadata: dict, root: Path, subject: Path) -> None:
    """Copy only common inputs; never out/, old artifacts or caches."""
    for name in _COMMON_FILES:
        shutil.copy2(source / name, root / name)
    shutil.copy2(source / f"{metadata['binary']}.orig", root / f"{metadata['binary']}.orig")
    config = subject / "config.env"
    if config.is_symlink() or not config.is_file():
        raise SelectionError(f"subject config.env not found: {config}")
    shutil.copy2(config, root / "config.env")
    if not (source / "trace").is_dir() or (source / "trace").is_symlink():
        raise SelectionError("missing source trace directory")
    _copy_tree(source / "trace", root / "trace")
    if not (source / "input/poc").is_dir() or (source / "input/poc").is_symlink():
        raise SelectionError("missing source PoC directory")
    _copy_tree(source / "input" / "poc", root / "input" / "poc")


def _run(command: list[str], *, cwd: Path, timeout: float, environment: dict,
         stage: bool) -> None:
    try:
        completed = subprocess.run(command, cwd=cwd, stdin=subprocess.DEVNULL,
                                   capture_output=True, timeout=timeout, env=environment,
                                   check=False)
    except FileNotFoundError as error:
        raise SelectionError(f"{command[0]} is unavailable; install the prepared Taosc/BinRadar backend") from error
    except subprocess.TimeoutExpired as error:
        raise SelectionError(f"{command[0]} exceeded its timeout") from error
    if completed.returncode != 0:
        text = (completed.stderr or completed.stdout)[-_DIAGNOSTIC_LIMIT:].decode(
            "utf-8", errors="replace").strip()
        kind = "taosc-patch-stage" if stage else "binradar-setup"
        raise SelectionError(f"{kind} failed ({completed.returncode}): {text}")


def _stage(workdir: Path, format_text: str, location: str, destination: str,
           timeout: float, environment: dict) -> dict:
    command = [os.environ.get("TAOSC_PATCH_STAGE", "taosc-patch-stage"), str(timeout),
               str(workdir), format_text, location, destination]
    _run(command, cwd=workdir, timeout=timeout + 5, environment=environment, stage=True)
    marker = _read_json(workdir / "patch-stage.json")
    expected_status = "prepared" if format_text in ERM_FORMATS else "built"
    if (marker.get("kind") != "taosc-patch-stage" or marker.get("verified") is not False
            or marker.get("status") != expected_status
            or marker.get("patch_format") != format_text
            or _parse_hex(marker.get("patch_location"))[0] != _parse_hex(location)[0]
            or _parse_hex(marker.get("patch_destination"), allow_zero=True)[0]
            != _parse_hex(destination, allow_zero=True)[0]):
        raise SelectionError("taosc-patch-stage provenance disagrees with the requested stage")
    return marker


def _setup(workdir: Path, timeout: float, environment: dict) -> dict:
    _run([sys.executable, "-m", "binradar.binradar_setup", "setup", "-w", str(workdir)],
         cwd=workdir, timeout=timeout, environment=environment, stage=False)
    path = workdir / "binradar.env"
    if path.is_symlink() or not path.is_file():
        raise SelectionError("binradar-setup did not publish binradar.env")
    result = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip().strip('"').strip("'")
    if result.get("TOTAL_PATCHES") not in ("0", "1"):
        raise SelectionError("binradar-setup did not publish a definite TOTAL_PATCHES")
    return result


def _settings(metadata: dict) -> dict:
    environment = metadata["environment"]
    settings = {"BINARY": metadata["binary"], "TEST_CMD": environment["TEST_CMD"],
                "PATCH_LOC": metadata["location_text"],
                "BINRADAR_QEMU_EXEC_TIMEOUT": environment.get("BINRADAR_QEMU_EXEC_TIMEOUT", "60")}
    return settings


def _compact(observation: dict) -> dict:
    return {"outcome": observation["outcome"]["outcome"],
            "fault_addr": observation["outcome"].get("fault_addr"),
            "fault_valid": observation["outcome"].get("fault_valid"),
            "patch_hits": observation.get("patch_hits"),
            "branches": observation.get("branches")}


def _checked_observation(observation: dict, workdir: Path, artifact: str, row: dict) -> str:
    """Reject unusable observations even when a backend forgets to raise."""
    if (observation.get("artifact_sha256") != _sha256(workdir / artifact)
            or observation.get("input_sha256") != row["sha256"]
            or _sha256(row["path"]) != row["sha256"]):
        raise SelectionError(f"observation identity changed for case {row['id']}")
    outcome = observation.get("outcome", {})
    kind = outcome.get("outcome")
    if kind not in ("normal", "crash"):
        raise SelectionError(f"observation unavailable for case {row['id']}: {kind}")
    fault = outcome.get("fault_addr")
    if kind == "crash":
        if outcome.get("fault_valid") is not True or type(fault) is not int or fault <= 0:
            raise SelectionError(f"observation unavailable for case {row['id']}: unknown crash fault")
    elif outcome.get("fault_valid") is not False or fault != 0:
        raise SelectionError(f"observation unavailable for case {row['id']}: invalid normal fault")
    hits = observation.get("patch_hits")
    if type(hits) is not int or hits < 0:
        raise SelectionError(f"invalid observed site hits for case {row['id']}")
    return kind


def _observe_original(workdir: Path, metadata: dict, row: dict, directory: Path,
                      *, require_hit: bool = True) -> dict:
    artifact = f"{metadata['binary']}.orig"
    try:
        observation = observe(workdir, _settings(metadata), row["path"],
                              artifact=artifact, directory=directory)
    except RuntimeError as error:
        raise SelectionError(f"case {row['id']} original observation unavailable: {error}") from error
    observed = _checked_observation(observation, workdir, artifact, row)
    if observation["artifact_sha256"] != metadata["original_sha256"]:
        raise SelectionError(f"original artifact identity drifted for case {row['id']}")
    data = row["original"]
    expected = {"crash": "crash", "ok": "normal"}.get(data.get("exit"))
    if expected is None or observed != expected:
        raise SelectionError(f"original outcome drifted for case {row['id']}: "
                             f"{data.get('exit')} -> {observed}")
    if observed == "crash" and observation["outcome"]["fault_addr"] != data["fault-addr"]:
        raise SelectionError(f"original fault drifted for case {row['id']}")
    observation["target_crash"] = observed == "crash" and data["fault-addr"] == metadata["crash"]
    if require_hit and observation["patch_hits"] <= 0:
        raise SelectionError(f"original no longer reaches the site for case {row['id']}")
    return observation


def _observe_candidate(workdir: Path, metadata: dict, row: dict, original: dict,
                       directory: Path) -> dict:
    artifact = f"{metadata['binary']}.brpatched"
    try:
        observation = observe(workdir, _settings(metadata), row["path"],
                              artifact=artifact, directory=directory, patch_id=1)
    except RuntimeError as error:
        raise SelectionError(f"case {row['id']} candidate observation unavailable: {error}") from error
    outcome = _checked_observation(observation, workdir, artifact, row)
    record = {"id": row["id"], "input_sha256": row["sha256"],
              "original": _compact(original), "candidate": _compact(observation)}
    fault = observation["outcome"]["fault_addr"]
    if original["target_crash"]:
        if outcome == "normal":
            branches = observation.get("branches")
            if not isinstance(branches, list) or not any(
                    type(branch) is int and branch == 1 for branch in branches):
                return {**record, "status": "rejected", "reason": "repair_not_observed"}
            return {**record, "status": "repaired"}
        return {**record, "status": "rejected",
                "reason": "target_crash" if fault == metadata["crash"] else "other_crash"}
    if original["outcome"]["outcome"] == "crash":
        if outcome == "crash" and fault == original["outcome"]["fault_addr"]:
            return {**record, "status": "preserved", "same_other_crash": True}
        return {**record, "status": "rejected", "reason": "unrelated_crash_changed"}
    if outcome != "normal":
        return {**record, "status": "rejected",
                "reason": "target_crash" if fault == metadata["crash"] else "other_crash"}
    return {**record, "status": "preserved"}


def _evaluate(workdir: Path, metadata: dict, rows: list[dict], originals: list[dict],
              workers: int, directory: Path) -> dict:
    accepted = {"repaired": 0, "preserved": 0}
    observations = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for start in range(0, len(rows), _CHUNK):
            batch = list(zip(rows[start:start + _CHUNK], originals[start:start + _CHUNK]))
            results = list(pool.map(
                lambda item: _observe_candidate(workdir, metadata, item[0], item[1], directory),
                batch))
            observations.extend(results)
            for result in results:
                if result["status"] == "unavailable":
                    raise SelectionError(f"candidate observation unavailable: {result['reason']}")
            rejected = next((result for result in results if result["status"] == "rejected"), None)
            if rejected is not None:
                return {"status": "rejected", "reason": rejected["reason"],
                        "rejected_id": rejected["id"], "observations": observations}
            for result in results:
                accepted[result["status"]] += 1
    return {"status": "accepted", "observations": observations, "summary": accepted}


def _trial_artifacts(trial: Path, binary: str) -> dict:
    result = {}
    for suffix in _PUBLISHED_SINGLE:
        path = trial / f"{binary}.{suffix}"
        if path.is_symlink() or not path.is_file() or not path.stat().st_size:
            raise SelectionError(f"trial is missing {path.name}")
        result[suffix] = _reference(trial, path)
    return result


def _allocator_files(workdir: Path) -> tuple[Path, Path]:
    from binradar.binradar_taosc_predicates import parse_allocator_trace

    try:
        allocator = parse_allocator_trace(workdir / "trace")
    except (OSError, ValueError) as error:
        raise SelectionError(f"invalid allocator trace: {error}") from error
    if allocator is None:
        raise SelectionError("CWE-805 requires a complete allocator trace")
    paths = tuple(workdir / "trace" / f"{allocator.kind}.{suffix}"
                  for suffix in ("calls", "returns"))
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise SelectionError("allocator traces must be regular files")
    return paths


def _site_metadata(metadata: dict, location: int) -> dict:
    text = f"0x{location:x}"
    return {**metadata, "location": location, "location_text": text,
            "destinations": metadata["candidates"][location],
            "environment": {**metadata["environment"], "PATCH_LOC": text}}


def _generation_site(workdir: Path, metadata: dict) -> None:
    path = workdir / "generate-concrete.env"
    lines = [line for line in path.read_text().splitlines()
             if line.split("=", 1)[0].strip() != "PATCH_LOC"]
    path.write_text("\n".join([*lines, f'PATCH_LOC="{metadata["location_text"]}"', ""]))


def _original_proof(rows: list[dict], originals: list[dict]) -> list[dict]:
    return [{"id": row["id"], "input_sha256": row["sha256"], **original}
            for row, original in zip(rows, originals)]


def _publish_concrete(staging: Path, output: Path, metadata: dict,
                      source: dict, originals: list[dict]) -> dict:
    """Create a new original-only run; never relabel the producer's rows."""
    run = staging / "concrete"
    (run / "minimized").mkdir(parents=True, mode=0o700)
    lines = ["[minimizer] [baseline] [version 1] [baseline original]"]
    expected = []
    for row, observation in zip(source["rows"], originals):
        if observation["patch_hits"] == 0:
            continue
        probe = observation.get("probe")
        if not isinstance(probe, str) or "\n" in probe:
            raise SelectionError("original observation lacks its probe serialization")
        filename = row["path"].name
        shutil.copy2(row["path"], run / "minimized" / filename)
        lines.append(f"[testcase] [original-result] [id {row['id']}] [file {filename}] "
                     f"[input-sha256 {row['sha256']}] {probe} [time 0]")
        expected.append((row, observation))
    lines.extend(["[minimizer] [done]", ""])
    (run / "minimizer.sbsv").write_text("\n".join(lines))
    if not originals:
        raise SelectionError("selected-site identity lacks fresh original observations")
    identity = {"schema_version": 1, "kind": "selected-site-original-reobservation",
                "binary": metadata["binary"],
                "original_sha256": originals[0]["artifact_sha256"],
                "invocation": _invocation(_settings(metadata)["TEST_CMD"]),
                "patch_location": _settings(metadata)["PATCH_LOC"],
                "poc": _poc_identity(staging, metadata["environment"], metadata["poc"])}
    _atomic_json(run / "original-identity.json", identity)
    concrete = _concrete(run, metadata, derived=True)
    for fresh, (old, observation) in zip(concrete["rows"], expected):
        saved = fresh["original"]
        if (fresh["id"] != old["id"] or fresh["sha256"] != old["sha256"]
                or saved["patch-hit"] != observation["patch_hits"]
                or saved["exit"] != ("crash" if observation["outcome"]["outcome"] == "crash" else "ok")
                or saved["fault-addr"] != observation["outcome"]["fault_addr"]):
            raise SelectionError("original probe disagrees with the observed result")
    concrete.update(path=str(output / "concrete"), relative_path="concrete",
                    provenance={"kind": "selected-site-original-reobservation",
                                "source_terminal": source["terminal"],
                                "source_minimizer_sha256": source["minimizer_sha256"],
                                "source_identity_sha256": source["identity"]["sha256"],
                                "evaluated_cases": len(source["rows"])})
    return concrete


def _publish_single(staging: Path, trial: Path, metadata: dict) -> None:
    """Copy the built, accepted Single artifacts over the ERM staging base."""
    if (trial / "patch-format").read_text().strip() == "Single CWE-805":
        for path in _allocator_files(trial):
            shutil.copy2(path, staging / "trace" / path.name)
    for suffix in _PUBLISHED_SINGLE:
        shutil.copy2(trial / f"{metadata['binary']}.{suffix}",
                     staging / f"{metadata['binary']}.{suffix}")
    for name in ("filter.sbsv", "binradar.env", "brpatches.json"):
        path = trial / name
        if path.is_file() and not path.is_symlink():
            shutil.copy2(path, staging / name)
    for name in ("patch-stage.json", "patch-format", "patch-location",
                 "destinations", "patch-destination"):
        shutil.copy2(trial / name, staging / name)


def _candidate_copy(staging: Path, trial: Path, metadata: dict) -> None:
    """Give each trial a private copy of common inputs, never another trial."""
    trial.mkdir(mode=0o700)
    for name in _COMMON_FILES:
        shutil.copy2(staging / name, trial / name)
    shutil.copy2(staging / f"{metadata['binary']}.orig", trial / f"{metadata['binary']}.orig")
    shutil.copy2(staging / "config.env", trial / "config.env")
    _copy_tree(staging / "trace", trial / "trace")
    _copy_tree(staging / "input" / "poc", trial / "input" / "poc")
    # A completed ERM preparation is not stage output for a new Single trial.
    for name in ("patch-stage.json", "patch-format", "stack-size"):
        (trial / name).unlink(missing_ok=True)
    for suffix in _PUBLISHED_SINGLE:
        (trial / f"{metadata['binary']}.{suffix}").unlink(missing_ok=True)


def select(args) -> int:
    source = args.workdir.resolve(strict=True)
    run = args.concrete_run.resolve(strict=True)
    output = args.output
    if output.is_symlink() or os.path.lexists(output):
        raise SelectionError(f"output already exists: {output}")
    if output == source or output.is_relative_to(source):
        raise SelectionError("output must be outside the immutable source workdir")
    if output.is_relative_to(run):
        raise SelectionError("output must be outside the immutable concrete run")
    metadata = _metadata(source)
    source_artifacts = _source_references(source, metadata["binary"])
    subject = args.subject.resolve(strict=True)
    subject_config = _subject_configuration(subject, source, metadata)
    concrete = _concrete(run, metadata)
    environment = dict(os.environ)
    allocator = _allocator(source, metadata["exit_code"])
    sites = [metadata["location"], *sorted(set(metadata["candidates"]) - {metadata["location"]})]
    applicable = [(site, _single_family(_site_metadata(metadata, site), allocator))
                  for site in sites if metadata["candidates"][site]]
    applicable = [(site, family) for site, family in applicable if family is not None]
    erm_format = _erm_family(allocator)
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    scratch = Path(tempfile.mkdtemp(prefix=f".{output.name}.scratch-", dir=output.parent))
    selected: dict[str, Any] | None = None
    try:
        _stage_source(source, metadata, staging, subject)
        if _subject_configuration(staging, staging, metadata) != subject_config:
            raise SelectionError("copied subject configuration changed before selection")
        trials_dir = staging / "trials"
        trials_dir.mkdir(mode=0o700)
        trial_records = []
        # Prove source-site evidence first, even when only a different site is
        # applicable. New sites may legitimately have zero hits for some cases.
        originals_by_site = {}
        rows = concrete["rows"]
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            originals_by_site[metadata["location"]] = list(pool.map(
                lambda row: _observe_original(staging, metadata, row,
                                              scratch / "original"), rows))
        _atomic_json(staging / "original-evidence.json", {
            "location": metadata["location_text"],
            "observations": _original_proof(rows, originals_by_site[metadata["location"]])})
        index = 0
        for location, family in applicable:
            trial_metadata = _site_metadata(metadata, location)
            if location not in originals_by_site:
                with ThreadPoolExecutor(max_workers=args.workers) as pool:
                    originals_by_site[location] = list(pool.map(
                        lambda row: _observe_original(staging, trial_metadata, row,
                                                      scratch / f"original-0x{location:x}",
                                                      require_hit=False), rows))
            originals = originals_by_site[location]
            for destination in trial_metadata["destinations"]:
                name = f"{index:03d}-{family.removeprefix('Single ').lower()}-0x{destination:x}"
                index += 1
                trial = trials_dir / name
                _candidate_copy(staging, trial, metadata)
                _generation_site(trial, trial_metadata)
                marker = _stage(trial, family, trial_metadata["location_text"],
                                f"0x{destination:x}", args.timeout, environment)
                setup = _setup(trial, args.setup_timeout, environment)
                record = {"family": family, "location": trial_metadata["location_text"],
                          "destination": f"0x{destination:x}",
                          "originals": _original_proof(rows, originals)}
                artifacts = None
                if setup["TOTAL_PATCHES"] == "0":
                    result = {"status": "rejected", "reason": "setup_rejected"}
                else:
                    artifacts = _trial_artifacts(trial, metadata["binary"])
                    result = _evaluate(trial, trial_metadata, rows, originals,
                                       args.workers, scratch / name)
                    if _trial_artifacts(trial, metadata["binary"]) != artifacts:
                        raise SelectionError("trial artifacts changed during evaluation")
                    record.update(artifacts=artifacts, stage=marker,
                                  setup={"TOTAL_PATCHES": setup["TOTAL_PATCHES"]})
                record.update(result)
                _atomic_json(trial / "evaluation.json", record)
                record["evaluation"] = _reference(staging, trial / "evaluation.json")
                trial_records.append(record)
                if result["status"] == "accepted":
                    selected = {"trial": trial, "name": name, "record": record,
                                "destination": destination, "format": family,
                                "metadata": trial_metadata, "originals": originals,
                                "marker": marker, "artifacts": artifacts}
                    break
            if selected is not None:
                break
        source_concrete = {key: value for key, value in concrete.items() if key != "rows"}
        selected_metadata = metadata if selected is None else selected["metadata"]
        if selected is None:
            for name in ("patch-stage.json", "patch-format"):
                (staging / name).unlink(missing_ok=True)
            # The staged ERM family re-measures the selected site's stack and
            # re-traces allocator evidence; a source stack-size must not be
            # inherited as though it belonged to the new site.
            (staging / "stack-size").unlink(missing_ok=True)
            marker = _stage(staging, erm_format, metadata["location_text"],
                            metadata["destination_text"], args.timeout, environment)
            if marker.get("status") != "prepared":
                raise SelectionError("ERM fallback did not publish prepared provenance")
            format_text = erm_format
            destination = metadata["destination"]
        else:
            _publish_single(staging, selected["trial"], metadata)
            for suffix, reference in selected["artifacts"].items():
                if _sha256(staging / f"{metadata['binary']}.{suffix}") != reference["sha256"]:
                    raise SelectionError("accepted artifact changed during publication")
            format_text = selected["format"]
            destination = selected["destination"]
            if selected_metadata["location"] != metadata["location"]:
                concrete = _publish_concrete(staging, output, selected_metadata,
                                             concrete, selected["originals"])
        _generation_site(staging, selected_metadata)
        if (staging / "patch-format").read_text().strip() != format_text:
            raise SelectionError("published patch-format disagrees with the selection")
        if _read_hex(staging / "patch-location")[1] != selected_metadata["location_text"]:
            raise SelectionError("published patch-location disagrees with the selection")
        if _read_hex(staging / "patch-destination", allow_zero=True)[1] != f"0x{destination:x}":
            raise SelectionError("published patch-destination disagrees with the selection")
        artifacts = {}
        for path in sorted(staging.rglob("*")):
            if path.is_file() and not path.is_symlink():
                relative = path.relative_to(staging)
                if relative.parts[0] == "trials" or relative.name in ("patch-selection.json", ".run.json.tmp"):
                    continue
                artifacts[str(relative)] = _reference(staging, path)
        selection = {
            "schema_version": 1, "kind": "single-first-selection", "status": "selected",
            "selection": "single" if selected is not None else "erm",
            "binary": metadata["binary"], "patch_format": format_text,
            "patch_location": selected_metadata["location_text"],
            "patch_destination": f"0x{destination:x}",
            "concrete_run": concrete["path"],
            "concrete": {key: value for key, value in concrete.items() if key != "rows"},
            "source_concrete": source_concrete,
            "source": {"workdir": str(source), "original_sha256": metadata["original_sha256"],
                       "exit_code": metadata["exit_code"], "allocator": allocator,
                       "configuration": {"subject": str(subject), "artifact": subject_config},
                       "artifacts": source_artifacts},
            "trials": [{"family": record["family"], "location": record["location"],
                        "destination": record["destination"],
                        "status": record["status"], "reason": record.get("reason"),
                        "evaluation": record["evaluation"]}
                       for record in trial_records],
            "artifacts": artifacts, "verified": False, "binradar_verification": "not_run",
        }
        if selected is not None:
            evaluation = staging / "evaluation.json"
            record = dict(selected["record"])
            _atomic_json(evaluation, {"schema_version": 1, "status": "accepted",
                                      "binary": metadata["binary"], "patch_format": format_text,
                                      "patch_location": selected_metadata["location_text"],
                                      "patch_destination": f"0x{destination:x}",
                                      **record, "verified": False,
                                      "binradar_verification": "not_run"})
            artifacts["evaluation.json"] = _reference(staging, evaluation)
            selection["evaluation"] = artifacts["evaluation.json"]
            selection["publication"] = {
                "kind": "single-patch", "status": "published",
                "artifact": artifacts[f"{metadata['binary']}.brpatched"],
                "patch_format": format_text, "patch_location": selected_metadata["location_text"],
                "patch_destination": f"0x{destination:x}",
                "verified": False, "binradar_verification": "not_run",
            }
            selection["artifacts"] = artifacts
        _atomic_json(staging / _SELECTION, selection)
        if _sha256(staging / f"{metadata['binary']}.orig") != metadata["original_sha256"]:
            raise SelectionError("staged original changed during selection")
        if (_metadata(source) != metadata
                or _source_references(source, metadata["binary"]) != source_artifacts):
            raise SelectionError("source preparation changed during selection")
        if _subject_configuration(subject, source, metadata) != subject_config:
            raise SelectionError("subject configuration changed during selection")
        current = _concrete(run, metadata)
        if {key: value for key, value in current.items() if key != "rows"} != source_concrete:
            raise SelectionError("source concrete evidence changed during selection")
        _publish_directory(staging, output)
        print(json.dumps({"selection": selection["selection"], "output": str(output),
                          "patch_format": format_text,
                          "patch_destination": f"0x{destination:x}",
                          "trials": selection["trials"]}, sort_keys=True))
        return 0
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _publish_directory(staging: Path, output: Path) -> None:
    """Linux atomic no-replace rename, including an empty concurrent output."""
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    if libc.renameat2(-100, os.fsencode(staging), -100, os.fsencode(output), 1) != 0:
        error = ctypes.get_errno()
        raise SelectionError(f"cannot publish fresh output {output}: {os.strerror(error)}")


def _selected_reference(root: Path, reference: object) -> Path:
    if not isinstance(reference, dict) or not isinstance(reference.get("path"), str):
        raise SelectionError("artifact reference requires a relative path and checksum")
    relative = Path(reference["path"])
    if relative.is_absolute() or not relative.parts or any(part in (".", "..") for part in relative.parts):
        raise SelectionError("unsafe selected artifact path")
    path = root
    for part in relative.parts:
        path = path / part
        if path.is_symlink():
            raise SelectionError("selected artifact path must not contain symlinks")
    if not path.is_file() or _sha256(path) != reference.get("sha256"):
        raise SelectionError(f"selected artifact checksum mismatch: {path}")
    return path


def _authenticate_corpus(concrete: dict, run: Path, binary: str) -> list[dict]:
    if not run.is_absolute() or not run.is_dir() or run.is_symlink():
        raise SelectionError("selected concrete run must be an immutable absolute directory")
    location = _parse_hex(concrete.get("location"))[0]
    if concrete.get("binary") != binary:
        raise SelectionError("concrete binary disagrees with the selection")
    reference = concrete.get("identity")
    if not isinstance(reference, dict) or reference.get("path") != "original-identity.json":
        raise SelectionError("selection lacks required producer original-only identity")
    _selected_reference(run, reference)
    identity = _execution_identity(run, derived=concrete.get("relative_path") == "concrete")
    if (identity.get("binary") != binary or identity.get("patch_location") != concrete.get("location")
            or identity.get("original_sha256") != concrete.get("original_sha256")):
        raise SelectionError("producer original-only identity disagrees with selected corpus")
    rows, terminal = _concrete_rows(run, location, check_inputs=True)
    if (concrete.get("terminal") != terminal or concrete.get("cases") != len(rows)
            or concrete.get("cases_sha256") != _case_digest(rows, terminal)):
        raise SelectionError("concrete corpus identity changed since selection")
    if concrete.get("minimizer_sha256") != _sha256(run / "minimizer.sbsv"):
        raise SelectionError("concrete minimizer changed since selection")
    return rows


def _authenticate_reobservation(value: dict, evaluation: dict, source_rows: list[dict],
                                rows: list[dict], target_fault: int) -> None:
    from binradar import binradar_verifier
    import sbsv

    originals = evaluation.get("originals")
    observations = evaluation.get("observations")
    if (evaluation.get("status") != "accepted" or not isinstance(originals, list)
            or not isinstance(observations, list) or len(originals) != len(source_rows)
            or len(observations) != len(source_rows)):
        raise SelectionError("selected-site proof does not evaluate every source input")
    parser = sbsv.parser()
    parser.add_schema(binradar_verifier.PROBE_RESULT_SCHEMA_V4)
    hits = []
    for row, original, candidate in zip(source_rows, originals, observations):
        if (original.get("id") != row["id"] or original.get("input_sha256") != row["sha256"]
                or original.get("artifact_sha256") != value["concrete"]["original_sha256"]
                or candidate.get("id") != row["id"] or candidate.get("input_sha256") != row["sha256"]
                or candidate.get("status") not in ("repaired", "preserved")
                or candidate.get("original") != _compact(original)):
            raise SelectionError("selected-site proof input or artifact identity disagrees")
        try:
            probe = parser.parse_line_detached("[probe-info] " + original["probe"])
            data = dict(probe.data)
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            raise SelectionError("selected-site proof lacks an original probe") from error
        outcome = original.get("outcome", {})
        if (data.get("version") != binradar_verifier.CURRENT_PROBE_RESULT_VERSION
                or data.get("patch-loc") != _parse_hex(value["patch_location"])[0]
                or data.get("patch-hit") != original.get("patch_hits")
                or type(original.get("patch_hits")) is not int or original["patch_hits"] < 0
                or data.get("concrete-oracle") != binradar_verifier.CONCRETE_ORACLE
                or data.get("exit") != row["original"]["exit"]
                or data.get("fault-addr") != row["original"]["fault-addr"]
                or outcome.get("fault_addr") != data["fault-addr"]
                or outcome.get("fault_valid") != data.get("concrete-fault-valid")
                or outcome.get("outcome") != ("crash" if data["exit"] == "crash" else "normal")):
            raise SelectionError("selected-site original probe identity disagrees")
        target = data["exit"] == "crash" and data["fault-addr"] == target_fault
        patched = candidate.get("candidate", {})
        kind, fault = patched.get("outcome"), patched.get("fault_addr")
        if (original.get("target_crash") is not target
                or kind not in ("normal", "crash")
                or (kind == "crash" and (patched.get("fault_valid") is not True
                                         or type(fault) is not int or fault <= 0))
                or (kind == "normal" and (patched.get("fault_valid") is not False or fault != 0))):
            raise SelectionError("selected-site candidate proof has an unknown identity")
        if target:
            branches = patched.get("branches")
            accepted = (kind == "normal" and candidate["status"] == "repaired"
                        and isinstance(branches, list)
                        and any(type(branch) is int and branch == 1 for branch in branches))
        elif data["exit"] == "crash":
            accepted = (kind == "crash" and fault == data["fault-addr"]
                        and candidate["status"] == "preserved")
        else:
            accepted = kind == "normal" and candidate["status"] == "preserved"
        if not accepted:
            raise SelectionError("selected-site candidate proof does not preserve or repair the input")
        if original["patch_hits"] > 0:
            hits.append((row, data))
    if len(hits) != len(rows):
        raise SelectionError("selected concrete run must contain exactly observed original hits")
    for fresh, (source, data) in zip(rows, hits):
        if (fresh["id"] != source["id"] or fresh["sha256"] != source["sha256"]
                or {key: item for key, item in fresh["original"].items() if key != "time"} != data):
            raise SelectionError("selected concrete row is not the fresh original observation")


def load_patch_selection(workdir: Path) -> dict:
    """Authenticate the published selection and its concrete corpus reference."""
    path = Path(workdir) / _SELECTION
    value = _read_json(path)
    if (value.get("schema_version") != 1 or value.get("kind") != "single-first-selection"
            or value.get("status") != "selected" or value.get("selection") not in ("single", "erm")):
        raise SelectionError("invalid saved patch selection")
    binary = value.get("binary")
    if not isinstance(binary, str) or Path(binary).name != binary or binary in (".", ".."):
        raise SelectionError("invalid selected binary")
    format_text = value.get("patch_format")
    if format_text not in FORMATS:
        raise SelectionError("unsupported selected patch format")
    if value["selection"] == "single" and format_text not in SINGLE_FORMATS:
        raise SelectionError("single selection has an ERM format")
    if value["selection"] == "erm" and format_text not in ERM_FORMATS:
        raise SelectionError("ERM selection has a Single format")
    _parse_hex(value.get("patch_location"))
    _parse_hex(value.get("patch_destination"), allow_zero=True)
    concrete = value.get("concrete")
    if not isinstance(concrete, dict):
        raise SelectionError("selection lacks concrete corpus identity")
    if concrete.get("path") != value.get("concrete_run"):
        raise SelectionError("concrete path disagrees with concrete_run")
    relative = concrete.get("relative_path")
    if relative is not None and relative != "concrete":
        raise SelectionError("invalid selected concrete relative path")
    run = Path(workdir).absolute() / relative if relative else Path(str(value.get("concrete_run", "")))
    rows = _authenticate_corpus(concrete, run, binary)
    if _parse_hex(concrete.get("location"))[0] != _parse_hex(value["patch_location"])[0]:
        raise SelectionError("selected concrete site disagrees with the selection")
    source_concrete = value.get("source_concrete")
    if not isinstance(source_concrete, dict):
        raise SelectionError("selection lacks required source concrete identity; incomplete selections must be regenerated")
    source_rows = _authenticate_corpus(source_concrete, Path(str(source_concrete.get("path", ""))), binary)
    if source_concrete.get("original_sha256") != concrete.get("original_sha256"):
        raise SelectionError("source and selected originals disagree")
    source = value.get("source")
    if not isinstance(source, dict):
        raise SelectionError("selection lacks source preparation identities")
    if source.get("original_sha256") != concrete.get("original_sha256"):
        raise SelectionError("source original identity disagrees with the selection")
    source_root = Path(str(source.get("workdir", "")))
    references = source.get("artifacts")
    if not source_root.is_absolute() or not isinstance(references, dict) or not references:
        raise SelectionError("selection lacks source preparation identities; incomplete selections must be regenerated")
    for name, reference in references.items():
        if not isinstance(reference, dict) or reference.get("path") != name:
            raise SelectionError("invalid source preparation reference")
        _selected_reference(source_root, reference)
    if _source_references(source_root, binary) != references:
        raise SelectionError("source preparation identity set is incomplete or changed")
    source_metadata = _metadata(source_root)
    _match_execution_identity(_execution_identity(Path(source_concrete["path"])), source_metadata)
    selected_metadata = _site_metadata(source_metadata, _parse_hex(value["patch_location"])[0])
    _match_execution_identity(_execution_identity(run, derived=relative is not None), selected_metadata)
    configuration = source.get("configuration")
    if not isinstance(configuration, dict) or not isinstance(configuration.get("subject"), str):
        raise SelectionError("selection lacks source configuration identity")
    subject = Path(configuration["subject"])
    if not subject.is_absolute() or _subject_configuration(subject, source_root, source_metadata) != configuration.get("artifact"):
        raise SelectionError("source configuration identity changed since selection")
    trials = value.get("trials")
    if not isinstance(trials, list):
        raise SelectionError("selection lacks trial verdicts")
    for trial in trials:
        if (not isinstance(trial, dict) or trial.get("family") not in SINGLE_FORMATS
                or trial.get("status") not in ("accepted", "rejected")
                or not isinstance(trial.get("destination"), str)):
            raise SelectionError("invalid saved trial verdict")
        _parse_hex(trial["destination"], allow_zero=True)
        _selected_reference(Path(workdir), trial.get("evaluation"))
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        raise SelectionError("selection has no authenticated artifacts")
    for name, reference in artifacts.items():
        if not isinstance(name, str) or not isinstance(reference, dict) or reference.get("path") != name:
            raise SelectionError("invalid artifact name")
        _selected_reference(Path(workdir), reference)
    original = artifacts.get(f"{binary}.orig")
    if original is None or original.get("sha256") != concrete.get("original_sha256"):
        raise SelectionError("selected original artifact identity disagrees")
    if _environments(Path(workdir))["generate-concrete.env"].get("PATCH_LOC") != value["patch_location"]:
        raise SelectionError("selected generation environment has the wrong site")
    moved = source_concrete.get("location") != concrete.get("location")
    if moved != bool(relative) or (moved and value["selection"] != "single"):
        raise SelectionError("changed site requires a new bound original-only concrete run")
    if format_text in ("Single CWE-805", "ERM CWE-805"):
        for trace in _allocator_files(Path(workdir)):
            name = str(trace.relative_to(workdir))
            if name not in artifacts:
                raise SelectionError("allocator dependency is absent from authenticated artifacts")
    if value["selection"] == "single":
        publication = value.get("publication")
        if (not isinstance(publication, dict) or publication.get("kind") != "single-patch"
                or publication.get("status") != "published" or publication.get("verified") is not False):
            raise SelectionError("single selection lacks a fixed publication")
        artifact = publication.get("artifact")
        reference = artifacts.get(artifact.get("path")) if isinstance(artifact, dict) else None
        if reference is None or reference.get("sha256") != artifact.get("sha256"):
            raise SelectionError("publication artifact is absent from authenticated artifacts")
        evaluation_path = _selected_reference(Path(workdir), value.get("evaluation"))
        if artifact.get("path") != f"{binary}.brpatched":
            raise SelectionError("publication does not bind the selected .brpatched")
        if relative:
            provenance = concrete.get("provenance")
            if provenance != {"kind": "selected-site-original-reobservation",
                              "source_terminal": source_concrete["terminal"],
                              "source_minimizer_sha256": source_concrete["minimizer_sha256"],
                              "source_identity_sha256": source_concrete["identity"]["sha256"],
                              "evaluated_cases": len(source_rows)}:
                raise SelectionError("selected-site concrete provenance disagrees")
            target_fault = _read_hex(Path(workdir) / "trace/crash.address")[0]
            _authenticate_reobservation(value, _read_json(evaluation_path), source_rows, rows, target_fault)
    elif format_text == "ERM CWE-805":
        stack = artifacts.get("stack-size")
        if stack is None:
            raise SelectionError("ERM CWE-805 selection lacks stack-size")
        size = int(_selected_reference(Path(workdir), stack).read_text().strip(), 0)
        if not 0 <= size <= 1048576:
            raise SelectionError("invalid selected stack-size")
    if value.get("verified") is not False or value.get("binradar_verification") != "not_run":
        raise SelectionError("selection cannot claim verification")
    if relative:
        value["concrete_run"] = str(run)
        concrete["path"] = str(run)
    return value


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="taosc-llm-patch", allow_abbrev=False,
        description="Select a fixed Single patch or clean ERM preparation from common Taosc artifacts.")
    parser.add_argument("--subject", type=Path,
                        help="subject directory containing config.env; defaults to cwd")
    parser.add_argument("--workdir", type=Path, required=True,
                        help="completed common taosc-prepare workdir")
    parser.add_argument("--concrete-run", type=Path, required=True,
                        help="completed original-only br-gen-con producer")
    parser.add_argument("--output", type=Path,
                        help="fresh output workdir; default sibling <WORKDIR>-patch")
    parser.add_argument("--timeout", type=float, default=900,
                        help="per taosc-patch-stage wall seconds (default 900)")
    parser.add_argument("--setup-timeout", type=float, default=3600,
                        help="per binradar-setup wall seconds (default 3600)")
    parser.add_argument("--workers", type=int, default=4,
                        help="parallel concrete observations, 1..32 (default 4)")
    args = parser.parse_args(argv)
    cwd = Path(os.getcwd())
    args.subject = Path(os.path.abspath(args.subject.expanduser() if args.subject else cwd))
    args.workdir = Path(os.path.abspath(args.workdir.expanduser()))
    args.concrete_run = Path(os.path.abspath(args.concrete_run.expanduser()))
    args.output = (Path(os.path.abspath(args.output.expanduser())) if args.output is not None
                   else args.workdir.with_name(args.workdir.name + "-patch"))
    if not 1 <= args.workers <= 32:
        parser.error("--workers must be between 1 and 32")
    if not (0 < args.timeout and args.timeout != float("inf")):
        parser.error("--timeout must be positive finite seconds")
    if not (0 < args.setup_timeout and args.setup_timeout != float("inf")):
        parser.error("--setup-timeout must be positive finite seconds")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        return select(args)
    except SelectionError as error:
        print(f"taosc-llm-patch: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, RuntimeError) as error:
        print(f"taosc-llm-patch: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
