"""Import explicit generation runs into a new immutable dataset revision."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import tempfile

import sbsv
from binradar import binradar_baseline, binradar_evidence, binradar_feedback, binradar_setup, binradar_verifier
from elftools.elf.elffile import ELFFile
from binradar import binradar_taosc_predicates as predicates

from .analysis import prepare_analysis
from .dataset import PreparedDataset, canonical, load_dataset, read_json, sha256


def _copy(source: Path, root: Path, relative: str) -> dict:
    """Copy a stable snapshot, rejecting concurrent replacement or modification."""
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"required regular input unavailable: {source}")
    before = source.stat()
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    shutil.copymode(source, destination)
    after = source.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or sha256(source) != sha256(destination):
        raise ValueError(f"input changed during preparation: {source}")
    return {"path": relative, "sha256": sha256(destination)}


def _address(path: Path) -> int:
    value = path.read_text().strip()
    if not re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]{1,16}", value):
        raise ValueError(f"invalid ELF address: {path.name}")
    number = int(value, 16)
    if not 0 < number < 2**64:
        raise ValueError(f"invalid zero/overflow ELF address: {path.name}")
    return number


def _check_map(root: Path, binary: str) -> None:
    data = read_json(root / "workdir" / f"{binary}.brcached.e9map.json")
    if data.get("version") != 1 or data.get("artifact-sha256") != sha256(root / "workdir" / f"{binary}.brcached") or data.get("original-sha256") != sha256(root / "workdir" / f"{binary}.orig"):
        raise ValueError("exact E9 map artifact/original identity mismatch")
    entries = data.get("instructions")
    if not isinstance(entries, list):
        raise ValueError("exact E9 map lacks instruction identities")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or any(type(entry.get(key)) is not int or not 0 <= entry[key] < 2**64 for key in ("relocated", "original")) or entry["relocated"] in seen:
            raise ValueError("invalid/duplicate exact E9 map instruction")
        seen.add(entry["relocated"])


def _original_cases(root: Path, run: Path, location: int) -> list[dict]:
    path = run / "minimizer.sbsv"
    if not path.is_file():
        return []
    parser = sbsv.parser()
    parser.add_schema("[testcase] [original-result] [id: int] [file: str] [input-sha256: str] " + binradar_verifier.PROBE_RESULT_SCHEMA_V4.removeprefix("[probe-info] ") + " [time: int]")
    rows, seen = [], set()
    with path.open() as stream:
        header = stream.readline()
        if header != "[minimizer] [baseline] [version 1] [baseline original]\n":
            raise ValueError("concrete run must publish original-only minimizer baseline v1")
        for line in stream:
            if not line.endswith("\n"):
                break  # An append in flight is not a committed row.
            if "[testcase] [original-result]" not in line:
                continue
            try:
                row = parser.parse_line_detached(line)
            except ValueError:
                continue
            if row is None:
                continue
            data = dict(row.data)
            if data.get("version") != binradar_verifier.CURRENT_PROBE_RESULT_VERSION:
                continue  # Unknown result semantics cannot establish an original observation.
            case_id, filename, expected = data.pop("id"), data.pop("file"), data.pop("input-sha256")
            if type(case_id) is not int or case_id < 0 or case_id in seen:
                raise ValueError("invalid/duplicate original case id")
            if Path(filename).name != filename or filename in ("", ".", "..") or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise ValueError("invalid original input identity")
            if data.get("patch-loc") != location or type(data.get("patch-hit")) is not int or data["patch-hit"] <= 0:
                raise ValueError("original result belongs to another patch location or has no hit")
            source = run / "minimized" / filename
            if not source.is_file() or source.is_symlink():
                continue
            try:
                record = _copy(source, root, f"inputs/system-{case_id}")
            except (FileNotFoundError, ValueError):
                continue
            if record["sha256"] != expected:
                (root / record["path"]).unlink()
                continue  # Producer may be publishing/replacing the bytes.
            seen.add(case_id)
            rows.append({"id": f"system:{case_id}", "domain": "system", "input_path": record["path"],
                         "input_sha256": expected, "source": {"kind": "original-result", "run": str(run),
                         "case_id": case_id, "filename": filename}, "observation": data, "capture": None})
    return rows


def _mutation_cases(root: Path, workdir: Path, run: Path, binary: str, artifacts: dict) -> tuple[list[dict], dict | None]:
    context_path = run / "feedback-capture" / "mutation.json"
    if not context_path.is_file():
        raise ValueError("mutation run lacks artifact-bound capture context")
    context_record = _copy(context_path, root, "sources/mutation-context.json")
    artifacts["mutation-context.json"] = context_record
    context = read_json(root / context_record["path"])
    if context.get("version") != 1:
        raise ValueError("unsupported mutation capture context version")
    checks = {"artifact": artifacts[binary + ".brcached"]["sha256"], "artifact_name": binary + ".brcached",
              "brpatches.json": artifacts["brpatches.json"]["sha256"],
              "generate-binradar.env": artifacts["generate-binradar.env"]["sha256"],
              "input_sha256": artifacts["poc"]["sha256"]}
    if any(context.get(key) != value for key, value in checks.items()):
        raise ValueError("mutation capture context artifact/configuration/POC identity mismatch")
    evidence = run / "binradar.br"
    reference = binradar_baseline.read_mutation_reference(evidence)
    request = binradar_feedback.FeedbackExportRequest(str(workdir), str(run), binary, "", "", 0,
              lambda _: None, (), poc_memcheck_policy=binradar_verifier.MEMCHECK_POLICY)
    pairs = binradar_feedback._committed_mutation_pairs(request, reference)
    parser = sbsv.parser()
    parser.add_schema(binradar_feedback._FEEDBACK_SCHEMA)
    parser.add_schema(binradar_feedback._MUTATION_SCHEMA)
    committed = {(frame.iteration, group.representative): group
                 for frame in binradar_evidence.read_binradar(evidence) for group in frame.groups}
    cases = []
    for snapshot, sidecar in pairs:
        # Freeze before reading so an external producer cannot change validated evidence underneath us.
        stem = Path(snapshot).stem
        brch = _copy(Path(snapshot), root, f"captures/{stem}.brch")
        metadata = _copy(Path(sidecar), root, f"captures/{stem}.sbsv")
        with (root / metadata["path"]).open() as stream:
            row = parser.parse_line_detached(stream.readline())
        data = dict(row.data)
        if data["patch"] != 0:
            raise ValueError("generation mutation evidence must be raw patch0")
        iteration = data["iteration"]
        group = committed.get((iteration, 0))
        if group is None:
            raise ValueError("mutation pair lost committed evidence")
        if group.branches is None:
            (root / brch["path"]).unlink()
            (root / metadata["path"]).unlink()
            continue  # Unknown is not a complete zero-hit capture.
        binradar_feedback._validate_mutation_pair(reference,
            (str(root / brch["path"]), str(root / metadata["path"])), iteration, group, parser)
        branches = [] if data["branches"] == "none" else [int(value) for value in data["branches"].split(",")]
        outcome = {"outcome": data["outcome"], "fault_valid": data["fault-valid"],
                   "fault_addr": data["fault-addr"], "fault_source": data["fault-source"],
                   "fault_image": data["fault-image"], "fault_offset": data["fault-image-offset"]}
        same_crash = bool(data["same-fault"]) if reference is not None else None
        capture = {**brch, "artifact_sha256": checks["artifact"], "branches": branches,
                   "outcome": outcome, "same_crash": same_crash, "complete": True, "descriptor": "p0",
                   "sidecar": metadata, "oracle": "selected-artifact-attempt1", "patch_id": 0}
        cases.append({"id": f"function:{iteration}", "domain": "function", "input_path": None,
                      "input_sha256": None, "source": {"kind": "committed-mutation", "run": str(run),
                      "iteration": iteration, "patch_id": 0, "sidecar": metadata},
                      "observation": outcome, "capture": capture})
    oracle = ({"address": reference.address, "source": reference.source,
               "image": reference.image_id, "offset": reference.image_offset} if reference is not None else None)
    return cases, oracle


def prepare_dataset(config: Path, workdir: Path, concrete_run: Path, mutation_run: Path | None, *,
                    output: Path | None = None, rea: str | None = None,
                    analysis_provider: str = "ghidra") -> PreparedDataset:
    config, workdir, concrete_run = (Path(path).resolve(strict=True) for path in (config, workdir, concrete_run))
    mutation_run = Path(mutation_run).resolve(strict=True) if mutation_run is not None else None
    if not workdir.is_dir() or not concrete_run.is_dir() or (mutation_run is not None and not mutation_run.is_dir()):
        raise ValueError("explicit workdir and run directories are required")
    env = binradar_setup.load_env(config)
    binary = env.get("BINARY", "")
    if not binary or Path(binary).name != binary or binary in (".", ".."):
        raise ValueError("BINARY must be an executable basename")
    patch_format = (workdir / "patch-format").read_text().strip()
    if patch_format not in ("ERM generic", "ERM CWE-805"):
        raise ValueError("only explicit ERM generic and ERM CWE-805 families are supported")
    location, destination = _address(workdir / "patch-location"), _address(workdir / "patch-destination")
    parent = Path(output).absolute().parent if output is not None else workdir / "taosc-llm-datasets"
    parent.mkdir(parents=True, exist_ok=True)
    if output is not None and Path(output).exists():
        raise FileExistsError("prepared dataset destinations are immutable; select a new revision")
    with tempfile.TemporaryDirectory(prefix=".prepare-", dir=parent) as temporary:
        root = Path(temporary)
        artifacts = {"config.env": _copy(config, root, "workdir/config.env")}
        required = [f"{binary}.orig", f"{binary}.brcached", f"{binary}.brcached.json",
                    f"{binary}.brcached.e9map.json", "brpatches.json", "patch-format", "patch-location",
                    "patch-destination", "generate-concrete.env"]
        if mutation_run is not None:
            required.append("generate-binradar.env")
        optional = ["binradar.env", "generate-binradar.env", "stack-size", "predicates"]
        for name in required + [name for name in optional if name not in required and (workdir / name).is_file()]:
            artifacts[name] = _copy(workdir / name, root, f"workdir/{name}")
        for name in ("binradar.env", "generate-concrete.env", "generate-binradar.env"):
            if name not in artifacts:
                continue
            generation = binradar_setup.load_env(root / artifacts[name]["path"])
            if any(key in generation and generation[key] != env.get(key) for key in ("BINARY", "TEST_CMD", "POC_INPUT")):
                raise ValueError(f"{name} invocation disagrees with explicit configuration")
            if "PATCH_LOC" in generation and int(generation["PATCH_LOC"], 16) != location:
                raise ValueError(f"{name} patch location identity mismatch")
        for path in sorted((workdir / "trace").glob("*")):
            if path.is_file():
                name = f"trace/{path.name}"
                artifacts[name] = _copy(path, root, f"workdir/{name}")
        poc_input = env.get("POC_INPUT", "")
        poc = binradar_setup.resolve_poc(config.parent, workdir, poc_input) if poc_input else None
        if poc is None:
            raise ValueError("explicit configuration must resolve a POC input")
        poc_relative = poc_input if not Path(poc_input).is_absolute() and ".." not in Path(poc_input).parts else "poc"
        if poc_relative in artifacts:
            raise ValueError("POC path collides with a required artifact")
        artifacts["poc"] = _copy(poc, root, f"workdir/{poc_relative}")
        _check_map(root, binary)
        with (root / "workdir" / f"{binary}.orig").open("rb") as stream:
            elf = ELFFile(stream)
            if elf.elfclass != 64 or not elf.little_endian or elf["e_machine"] != "EM_X86_64":
                raise ValueError("ERM cached-state datasets require little-endian x86-64 ELF")
            ranges = [(int(segment["p_vaddr"]), int(segment["p_vaddr"]) + int(segment["p_filesz"]))
                      for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD" and segment["p_flags"] & 1]
            if any(not any(start <= address < end for start, end in ranges) for address in (location, destination)):
                raise ValueError("patch addresses must belong to original executable file-backed ELF ranges")
        concrete_reference = None
        probe_path = concrete_run / "probe-results.sbsv"
        if probe_path.is_file():
            probe_record = _copy(probe_path, root, "sources/concrete-probe.sbsv")
            artifacts["concrete-probe.sbsv"] = probe_record
            probe = binradar_verifier.BinRadarProbeResult.from_sbsv(str(root / probe_record["path"]))
            if probe is not None and probe.patch_loc == location and probe.concrete_oracle == binradar_verifier.CONCRETE_ORACLE:
                concrete_reference = probe.concrete_fault_addr
        family, _ = predicates.load_runtime_predicates(root / "workdir/brpatches.json")
        if family != predicates.parse_patch_format(root / "workdir"):
            raise ValueError("runtime manifest family disagrees with patch-format")
        if patch_format == "ERM CWE-805":
            if "stack-size" not in artifacts or predicates.parse_allocator_trace(root / "workdir/trace") is None:
                raise ValueError("CWE-805 requires complete allocator traces and stack-size")
            stack = int((root / "workdir/stack-size").read_text().strip(), 0)
            if not 0 <= stack <= 0x100000:
                raise ValueError("invalid CWE-805 stack-size")
        cases = _original_cases(root, concrete_run, location)
        oracle = None
        if mutation_run is not None:
            mutations, oracle = _mutation_cases(root, workdir, mutation_run, binary, artifacts)
            cases.extend(mutations)
        case_path = root / "cases.jsonl"
        with case_path.open("wb") as stream:
            for case in cases:
                stream.write(canonical(case) + b"\n")
        analysis = prepare_analysis(root, root / "workdir" / f"{binary}.orig",
                                    {"patch": location, "destination": destination}, rea=rea, provider=analysis_provider)
        manifest = {"schema_version": 2, "binary": binary, "patch_format": patch_format,
                    "patch": {"location": location, "destination": destination, "address_domain": "elf-va"},
                    "artifacts": artifacts, "sources": {"concrete_run": str(concrete_run),
                    "mutation_run": str(mutation_run) if mutation_run else None}, "analysis": analysis,
                    "cases": {"path": "cases.jsonl", "sha256": sha256(case_path)},
                    "oracles": {"mutation_reference": oracle,
                                "concrete": binradar_verifier.CONCRETE_ORACLE,
                                "concrete_reference": concrete_reference}}
        manifest["dataset_id"] = hashlib.sha256(canonical(manifest)).hexdigest()
        (root / "manifest.json").write_bytes(canonical(manifest) + b"\n")
        dataset = PreparedDataset(root, manifest)
        dataset.verify_artifacts()
        dataset.execution_environment()
        destination_root = Path(output).absolute() if output is not None else parent / manifest["dataset_id"]
        if destination_root.exists():
            if output is None:
                return load_dataset(destination_root)
            raise FileExistsError(destination_root)
        # rename publishes the whole revision; source producer files are never changed.
        os.rename(root, destination_root)
    return load_dataset(destination_root)
