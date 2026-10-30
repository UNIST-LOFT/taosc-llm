"""Real publication/import boundaries, using inert copies of the Python ELF only."""
import hashlib
import json
from pathlib import Path
import shutil
import struct
import sys
import zlib

import pytest
from elftools.elf.elffile import ELFFile
from binradar import binradar_verifier
from binradar import binradar_taosc_predicates as predicates
from taosc_llm import analysis
from taosc_llm.dataset import canonical, load_dataset, sha256
from taosc_llm.preparation import prepare_dataset


def preparation_inputs(tmp_path, patch_format="ERM generic"):
    """Build real setup inputs without running a program or manufacturing a manifest."""
    work = tmp_path / "work"
    run = tmp_path / "concrete"
    work.mkdir()
    (run / "minimized").mkdir(parents=True)
    source = Path(sys.executable).resolve()
    with source.open("rb") as stream:
        elf = ELFFile(stream)
        address = next(int(segment["p_vaddr"]) for segment in elf.iter_segments()
                       if segment["p_type"] == "PT_LOAD" and segment["p_flags"] & 1)
    for suffix in ("orig", "brcached"):
        shutil.copyfile(source, work / f"fixture.{suffix}")
    (work / "fixture.brcached.json").write_text("{}\n")
    (work / "fixture.brcached.e9map.json").write_text(json.dumps({"version": 1,
        "artifact-sha256": sha256(work / "fixture.brcached"),
        "original-sha256": sha256(work / "fixture.orig"), "instructions": []}))
    (work / "patch-format").write_text(patch_format + "\n")
    (work / "patch-location").write_text(hex(address))
    (work / "patch-destination").write_text(hex(address + 1))
    (work / "poc").write_bytes(b"harmless")
    config = tmp_path / "config.env"
    config.write_text("BINARY=fixture\nTEST_CMD=@@\nPOC_INPUT=poc\n")
    (work / "generate-concrete.env").write_text(config.read_text())
    (work / "generate-binradar.env").write_text(config.read_text())
    kind = "generic-erm" if patch_format == "ERM generic" else "CWE805-erm"
    (work / "brpatches.json").write_text(json.dumps({"version": 1, "kind": kind, "predicates": []}))
    if patch_format == "ERM CWE-805":
        (work / "stack-size").write_text("8\n")
        (work / "trace").mkdir()
        (work / "trace/malloc.calls").write_text(f"0 {address:x}\n")
        (work / "trace/malloc.returns").write_text(f"{address + 1:x}\n")
    probe = binradar_verifier.BinRadarProbeResult(
        patch_loc=address, patch_func_entry=address, stacktrace=[], exit_info="ok",
        patch_hit_cnt=1, patch_func_hit_cnt=1, fault_addr=0, patch_func_candidates=[],
        tracer_fault_reference=None, concrete_oracle=binradar_verifier.CONCRETE_ORACLE,
        concrete_fault_valid=False, raw_fault_addr=0, concrete_fault_source="unavailable")
    (run / "minimized/0_input").write_bytes(b"case bytes")
    row = ("2026-01-01 00:00:00,000 - [testcase] [original-result] [id 0] [file 0_input] "
           f"[input-sha256 {sha256(run / 'minimized/0_input')}] {probe.serialize()} [time 1]\n")
    (run / "minimizer.sbsv").write_text("[minimizer] [baseline] [version 1] [baseline original]\n" + row)
    return config, work, run


@pytest.fixture(autouse=True)
def unavailable_rea(monkeypatch):
    monkeypatch.delenv("TAOSC_LLM_REA", raising=False)
    monkeypatch.setattr(analysis.shutil, "which", lambda _: None)


@pytest.mark.parametrize("family", ["ERM generic", "ERM CWE-805"])
def test_prepares_original_rows_and_revision_isolation(tmp_path, family):
    config, work, run = preparation_inputs(tmp_path, family)
    first = prepare_dataset(config, work, run, None, output=tmp_path / "first")
    case = first.case("system:0")
    assert first.patch_format == family
    assert case["capture"] is None
    assert case["observation"]["patch-hit"] == 1
    assert case["source"]["case_id"] == 0
    assert (first.root / case["input_path"]).read_bytes() == b"case bytes"
    assert all(record["availability"] == "unavailable" for record in first.manifest["analysis"])
    if family == "ERM CWE-805":
        assert first.execution_environment()["BRCACHE_STACK_SIZE"] == "8"
        assert first.artifact("trace/malloc.calls").is_file()
    (run / "minimized/0_input").write_bytes(b"not published yet")
    second = prepare_dataset(config, work, run, None, output=tmp_path / "second")
    assert second.cases() == []
    assert first.case("system:0")["input_sha256"] == hashlib.sha256(b"case bytes").hexdigest()
    load_dataset(first.root).verify_artifacts()
    with pytest.raises(FileExistsError):
        prepare_dataset(config, work, run, None, output=first.root)


def test_unterminated_row_is_unavailable_not_zero_hit(tmp_path):
    config, work, run = preparation_inputs(tmp_path)
    path = run / "minimizer.sbsv"
    path.write_text(path.read_text().rstrip("\n"))
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset")
    assert dataset.cases() == []


@pytest.mark.parametrize("version", [3, 99])
def test_unknown_original_result_schema_is_not_admitted(tmp_path, version):
    config, work, run = preparation_inputs(tmp_path)
    path = run / "minimizer.sbsv"
    path.write_text(path.read_text().replace(
        f"[version {binradar_verifier.CURRENT_PROBE_RESULT_VERSION}]", f"[version {version}]"))
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset")
    assert dataset.cases() == []


@pytest.mark.parametrize("env_file", ["config.env", "binradar.env", "generate-concrete.env", "generate-binradar.env"])
@pytest.mark.parametrize("key", ["PATCH_LOC", "PATCH_DEST"])
def test_rejects_configured_address_mismatch(tmp_path, env_file, key):
    config, work, run = preparation_inputs(tmp_path)
    path = config if env_file == "config.env" else work / env_file
    path.write_text(config.read_text() + f"{key}=ffffffff\n")
    with pytest.raises(ValueError, match="identity mismatch"):
        prepare_dataset(config, work, run, None, output=tmp_path / "dataset")
    assert not (tmp_path / "dataset").exists()


@pytest.mark.parametrize("defect", ["destination", "map", "family", "manifest-family"])
def test_rejects_mismatched_setup_identity(tmp_path, defect):
    config, work, run = preparation_inputs(tmp_path)
    if defect == "destination":
        (work / "patch-destination").write_text("0")
    elif defect == "map":
        path = work / "fixture.brcached.e9map.json"
        value = json.loads(path.read_text())
        value["original-sha256"] = "0" * 64
        path.write_text(json.dumps(value))
    elif defect == "family":
        (work / "patch-format").write_text("CWE-805")
    else:
        (work / "brpatches.json").write_text('{"version":1,"kind":"CWE805-erm","predicates":[]}')
    with pytest.raises(ValueError):
        prepare_dataset(config, work, run, None, output=tmp_path / "dataset")
    assert not (tmp_path / "dataset").exists()


def _frame(payload):
    header = struct.pack("<HH", 4, 0)
    checksum = zlib.crc32(payload, zlib.crc32(header))
    return struct.pack("<I", len(payload)) + header + payload + struct.pack("<I", checksum & 0xffffffff)


def mutation_inputs(tmp_path, work, *, torn=False, oracle=True, unknown=False):
    run = tmp_path / "mutation"
    directory = run / "binradar-feedback"
    directory.mkdir(parents=True)
    (run / "feedback-capture").mkdir()
    (run / "feedback-capture/mutation.json").write_text(json.dumps({"version": 1,
        "artifact": sha256(work / "fixture.brcached"), "artifact_name": "fixture.brcached",
        "brpatches.json": sha256(work / "brpatches.json"),
        "generate-binradar.env": sha256(work / "generate-binradar.env"),
        "input_sha256": sha256(work / "poc")}))
    def group(crash, missing=False):
        # One typed v4 patch0 group, member 0; a null vector stays distinct from empty.
        return struct.pack("<IBBHQII", 0, 2 if crash else 1, 1 if missing else 0, 1 if crash else 0,
                           0x1234 if crash else 0, 0 if missing else 1, 1) + (b"\0" if missing else b"\0\0")
    evidence = struct.pack("<8sHHI", b"BRDATAB1", 4, 3, 0)
    evidence += _frame(struct.pack("<II", 1, 1) + group(oracle))
    second = _frame(struct.pack("<II", 2, 1) + group(oracle, unknown))
    (run / "binradar.br").write_bytes(evidence + (second[:-2] if torn else second))
    stem = "iteration-00000002-patch-00000000"
    cwe = (work / "patch-format").read_text().strip() == "ERM CWE-805"
    payload = predicates.CACHED_SNAPSHOT_HEADER.pack(predicates.CACHED_SNAPSHOT_MAGIC, 1, 0, 0, 8 if cwe else 0, 2 if cwe else 0)
    if cwe:
        payload += b"\0" * predicates.CACHED_SNAPSHOT_CLAMPS.size
    payload += b"\0" * predicates.CACHED_SNAPSHOT_REGS.size + (b"\0" * 8 if cwe else b"")
    (directory / f"{stem}.brch").write_bytes(payload)
    valid = str(oracle).lower()
    source = "guest-signal" if oracle else "unavailable"
    fault = "1234" if oracle else "0"
    outcome = "crash" if oracle else "normal"
    result = "malicious" if oracle else "benign"
    (directory / f"{stem}.sbsv").write_text(
        f"[binradar-feedback] [version 3] [iteration 2] [patch 0] [snapshot-file {stem}.brch] "
        f"[snapshot-count 1] [branches 0] [outcome {outcome}] [fault-addr {fault}] "
        f"[fault-valid {valid}] [fault-source {source}] [poc-fault-addr {fault}] "
        f"[poc-fault-valid {valid}] [poc-fault-source {source}] [same-fault {valid}] "
        f"[result {result}] [mutation-writes 0] [fault-image none] [fault-image-offset 0] "
        "[poc-fault-image none] [poc-fault-image-offset 0]\n")
    return run


@pytest.mark.parametrize("family", ["ERM generic", "ERM CWE-805"])
def test_imports_committed_mutation_and_typed_oracle(tmp_path, family):
    config, work, concrete = preparation_inputs(tmp_path, family)
    mutation = mutation_inputs(tmp_path, work)
    dataset = prepare_dataset(config, work, concrete, mutation, output=tmp_path / "dataset")
    capture = dataset.case("function:2")["capture"]
    assert capture["same_crash"] is True
    assert capture["branches"] == [0]
    assert len(dataset.snapshots(capture)) == 1
    assert dataset.manifest["oracles"]["mutation_reference"]["address"] == 0x1234


@pytest.mark.parametrize("defect", ["torn", "orphan", "malformed", "context"])
def test_unpublished_or_bad_mutation_never_supplies_verdict(tmp_path, defect):
    config, work, concrete = preparation_inputs(tmp_path)
    mutation = mutation_inputs(tmp_path, work, torn=defect == "torn")
    directory = mutation / "binradar-feedback"
    if defect == "orphan":
        next(directory.glob("*.sbsv")).unlink()
    elif defect == "malformed":
        next(directory.glob("*.brch")).write_bytes(b"partial")
    elif defect == "context":
        context = mutation / "feedback-capture/mutation.json"
        value = json.loads(context.read_text())
        value["artifact"] = "0" * 64
        context.write_text(json.dumps(value))
    if defect in ("malformed", "context"):
        with pytest.raises(ValueError):
            prepare_dataset(config, work, concrete, mutation, output=tmp_path / "dataset")
    else:
        dataset = prepare_dataset(config, work, concrete, mutation, output=tmp_path / "dataset")
        assert dataset.cases("function") == []


def test_untyped_normal_attempt1_does_not_authorize_same_crash(tmp_path):
    config, work, concrete = preparation_inputs(tmp_path)
    mutation = mutation_inputs(tmp_path, work, oracle=False)
    dataset = prepare_dataset(config, work, concrete, mutation, output=tmp_path / "dataset")
    assert dataset.case("function:2")["capture"]["same_crash"] is None


@pytest.mark.parametrize("payload", [{"ok": False, "error": "backend failed"},
                                     {"success": False, "reason": "backend not installed"},
                                     {"complete": False, "reason": "partial function"},
                                     {"truncated": True},
                                     {"facet_availability": {"pseudocode": {"available": False}}},
                                     {"relationship_coverage": {"status": "partial"}}])
def test_analysis_backend_failure_and_partial_output_remain_unavailable(tmp_path, monkeypatch, payload):
    from types import SimpleNamespace
    config, work, run = preparation_inputs(tmp_path)
    monkeypatch.setenv("PRIVATE_PROVIDER_TOKEN", "must-not-reach-static-child")
    def invoke(argv, **kwargs):
        assert "PRIVATE_PROVIDER_TOKEN" not in kwargs["env"]
        if argv[-1] == "--help":
            return SimpleNamespace(returncode=0, stdout="rea@6.8.0", stderr="")
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
    monkeypatch.setattr(analysis.subprocess, "run", invoke)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset", rea="/host/rea")
    assert all(row["availability"] == "unavailable" and not row["complete"]
               for row in dataset.manifest["analysis"])


@pytest.mark.parametrize("defect", [None, "artifact", "provider", "operation", "address", "missing-result", "facet"])
def test_static_views_require_bound_producer_evidence(tmp_path, monkeypatch, defect):
    from types import SimpleNamespace
    config, work, run = preparation_inputs(tmp_path)
    operations = {"function": "analyze_function", "instructions": "read_function_instructions",
                  "decompile": "procedure_pseudo_code", "xrefs": "xrefs"}

    def invoke(argv, **kwargs):
        if argv[-1] == "--help":
            return SimpleNamespace(returncode=0, stdout="rea@6.8.0", stderr="")
        command, binary, address = argv[1:4]
        # REA 6.8 CLI envelope/operation names observed from its actual Ghidra outputs.
        procedure = {"address": address, "body": {"available": True}}
        normalized = {"function": {"procedure": procedure, "assembly": [f"{address}: NOP"]},
                      "instructions": {"procedure": procedure, "instructions": [f"{address}: NOP"]},
                      "decompile": "void fixture(void) { return; }", "xrefs": []}
        data = {"subject": {"digest": {"sha256": sha256(Path(binary))}},
                "provider": {"id": "ghidra", "version": "12.1"},
                "operation": operations[command],
                "parameters": {"address" if command == "xrefs" else "procedure": address},
                "normalized_result": normalized[command]}
        if defect == "artifact":
            data["subject"]["digest"]["sha256"] = "0" * 64
        elif defect == "provider":
            data["provider"]["id"] = "another-provider"
        elif defect == "operation":
            data["operation"] = "another-operation"
        elif defect == "address":
            data["parameters"] = {key: "0xffff" for key in data["parameters"]}
        elif defect == "missing-result":
            data.pop("normalized_result")
        elif defect == "facet":
            data["facet_availability"] = {"pseudocode": {"available": False}}
        return SimpleNamespace(returncode=0, stdout=json.dumps({"ok": True, "data": data}), stderr="")

    monkeypatch.setattr(analysis.subprocess, "run", invoke)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset", rea="/host/rea")
    assert all(record["availability"] == ("available" if defect is None else "unavailable")
               and record["complete"] is (defect is None) for record in dataset.manifest["analysis"])


def test_case_scope_must_match_domain_even_with_valid_hashes(tmp_path):
    config, work, run = preparation_inputs(tmp_path)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset")
    case = dataset.case("system:0")
    case["id"] = "function:0"
    path = dataset.root / "cases.jsonl"
    path.write_bytes(canonical(case) + b"\n")
    manifest = dataset.manifest
    manifest["cases"]["sha256"] = sha256(path)
    manifest.pop("dataset_id")
    manifest["dataset_id"] = hashlib.sha256(canonical(manifest)).hexdigest()
    (dataset.root / "manifest.json").write_bytes(canonical(manifest))
    with pytest.raises(ValueError, match="id/domain binding"):
        load_dataset(dataset.root)


def test_hashes_and_scoped_ids_are_enforced(tmp_path):
    config, work, run = preparation_inputs(tmp_path)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset")
    with pytest.raises(ValueError, match="scoped"):
        dataset.case("0")
    dataset.artifact("fixture.orig").write_bytes(b"changed")
    with pytest.raises(ValueError, match="hash mismatch"):
        load_dataset(dataset.root)
