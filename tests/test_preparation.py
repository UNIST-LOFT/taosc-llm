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
    inventory = analysis.analysis_inventory(first)
    assert inventory["procedures"] == inventory["windows"] == []
    assert inventory["references"] == {} and inventory["same_procedure"] is False
    assert all(site["procedure_id"] is None and site["limitation"] for site in inventory["sites"].values())
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


@pytest.mark.parametrize("family", ["ERM generic", "ERM CWE-805"])
def test_imports_patch0_mutations_after_predicate_table_changes(tmp_path, family):
    config, work, concrete = preparation_inputs(tmp_path, family)
    mutation = mutation_inputs(tmp_path, work)
    runtime_family, _ = predicates.load_runtime_predicates(work / "brpatches.json")
    if family == "ERM generic":
        source = "rax != 0"
        parsed = predicates.predicate_to_branch_patch_str(source)
    else:
        source = "s->rax >= i->begin && s->rax < i->end"
        parsed = predicates.parse_CWE805_predicate(source)
    predicates.write_runtime_predicates(work / "brpatches.json", runtime_family,
        [predicates.PredicateRecord(1, 1, source, parsed)])

    dataset = prepare_dataset(config, work, concrete, mutation, output=tmp_path / "dataset")
    capture = dataset.case("function:2")["capture"]
    assert capture["descriptor"] == "p0"
    assert capture["same_crash"] is True
    assert [state.branch for state in dataset.snapshots(capture)] == [0]
    assert predicates.evaluate_cached_predicate(parsed, dataset.snapshots(capture)) == [1]


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


def static_session(monkeypatch, transform=lambda payload: payload):
    calls = []

    class Session:
        version = "6.8.0"

        def __init__(self, executable, binary, digest, environment, directory, timeout, query_timeout):
            assert "PRIVATE_PROVIDER_TOKEN" not in environment
            self.digest = digest

        def __enter__(self):
            return self

        def close(self):
            pass

        def query(self, operation, address):
            calls.append((operation, address))
            entry = address & ~15
            procedure = {"address": hex(entry), "body": {"available": True,
                         "ranges": [{"start": hex(entry), "end": hex(entry + 15)}]}}
            normalized = {
                "resolve_containing_procedure": {"query_address": hex(address), "found": True, "procedure": procedure},
                "analyze_function": {"procedure": procedure, "assembly": [f"{hex(entry)}: NOP"],
                                     "pseudocode": "void fixture(void) { return; }",
                                     "facet_availability": {"assembly": {"available": True}, "pseudocode": {"available": True}}},
                "read_function_instructions": {"procedure": procedure,
                    "instructions": [f"{hex(entry + index)}: NOP" for index in range(16)]},
                "xrefs": [{"to": hex(address)}],
            }
            data = {"subject": {"digest": {"sha256": self.digest}},
                    "provider": {"id": "ghidra", "version": "12.1"}, "operation": operation,
                    "parameters": {"address" if operation in ("resolve_containing_procedure", "xrefs") else "procedure": hex(address)},
                    "normalized_result": normalized[operation]}
            return transform({"ok": True, "data": data})

    monkeypatch.setattr(analysis, "ReaSession", Session)
    return calls


@pytest.mark.parametrize("payload", [{"ok": False, "error": "backend failed"},
                                     {"success": False, "reason": "backend not installed"},
                                     {"complete": False, "reason": "partial function"},
                                     {"truncated": True},
                                     {"facet_availability": {"pseudocode": {"available": False}}},
                                     {"relationship_coverage": {"status": "partial"}}])
def test_analysis_backend_failure_and_partial_output_remain_unavailable(tmp_path, monkeypatch, payload):
    config, work, run = preparation_inputs(tmp_path)
    monkeypatch.setenv("PRIVATE_PROVIDER_TOKEN", "must-not-reach-static-child")
    static_session(monkeypatch, lambda _: payload)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset", rea="/host/rea")
    assert all(row["availability"] == "unavailable" and not row["complete"]
               for row in dataset.manifest["analysis"])


@pytest.mark.parametrize("defect", [None, "artifact", "provider", "operation", "address", "missing-result"])
def test_static_views_require_bound_producer_evidence(tmp_path, monkeypatch, defect):
    config, work, run = preparation_inputs(tmp_path)

    def corrupt(payload):
        data = payload["data"]
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
        return payload

    static_session(monkeypatch, corrupt)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset", rea="/host/rea")
    assert all(record["availability"] == ("available" if defect is None else "unavailable")
               and record["complete"] is (defect is None) for record in dataset.manifest["analysis"])


def test_same_function_reuses_dossier_but_not_address_references(tmp_path, monkeypatch):
    config, work, run = preparation_inputs(tmp_path)
    calls = static_session(monkeypatch)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset", rea="/host/rea")
    records = {(row["function_id"], row["view"]): row for row in dataset.manifest["analysis"]}
    patch = int((work / "patch-location").read_text(), 16)
    destination = int((work / "patch-destination").read_text(), 16)
    assert calls.count(("analyze_function", patch & ~15)) == 1
    assert calls.count(("read_function_instructions", patch & ~15)) == 1
    for view in ("function", "instructions", "decompilation"):
        row = records["destination", view]
        assert row["reused_from"] == "patch" and row["requested_address"] == destination
        assert row["analysis_address"] == patch & ~15
        output = json.loads((dataset.root / row["path"]).read_text())
        assert output["resolution"]["data"]["parameters"]["address"] == hex(destination)
        assert output["evidence"]["data"]["parameters"]["procedure"] == hex(patch & ~15)
    for role, address in (("patch", patch), ("destination", destination)):
        row = records[role, "references"]
        assert "reused_from" not in row
        output = json.loads((dataset.root / row["path"]).read_text())
        assert output["evidence"]["data"]["normalized_result"] == [{"to": hex(address)}]


def test_different_function_destination_is_collected_separately(tmp_path, monkeypatch):
    config, work, run = preparation_inputs(tmp_path)
    patch = int((work / "patch-location").read_text(), 16)
    destination = patch + 32
    (work / "patch-destination").write_text(hex(destination))
    calls = static_session(monkeypatch)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset", rea="/host/rea")
    assert {address for operation, address in calls if operation == "analyze_function"} == {patch, destination}
    assert all("reused_from" not in row for row in dataset.manifest["analysis"])
    inventory = analysis.analysis_inventory(dataset)
    assert inventory["same_procedure"] is False
    assert len(inventory["procedures"]) == len(inventory["windows"]) == 2
    assert inventory["sites"]["patch"]["procedure_id"] != inventory["sites"]["destination"]["procedure_id"]
    with pytest.raises(ValueError, match="valid sites: patch"):
        analysis.analysis_view(dataset, inventory["sites"]["patch"]["procedure_id"], "references", site="destination")


def test_containment_does_not_infer_across_body_gaps(tmp_path, monkeypatch):
    config, work, run = preparation_inputs(tmp_path)
    patch = int((work / "patch-location").read_text(), 16)

    def gap(payload):
        data = payload["data"]
        if data["operation"] == "resolve_containing_procedure":
            data["normalized_result"]["procedure"]["body"]["ranges"] = [
                {"start": hex(patch), "end": hex(patch)},
                {"start": hex(patch + 2), "end": hex(patch + 15)}]
        return payload

    calls = static_session(monkeypatch, gap)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset", rea="/host/rea")
    for row in dataset.manifest["analysis"]:
        if row["function_id"] == "destination" and row["view"] != "references":
            assert row["availability"] == "unavailable" and "reused_from" not in row
    assert calls.count(("analyze_function", patch)) == 1


def test_native_decompile_failure_preserves_completed_listing_views(tmp_path, monkeypatch):
    config, work, run = preparation_inputs(tmp_path)

    def decompile_timeout(payload):
        data = payload["data"]
        if data["operation"] == "analyze_function":
            data["normalized_result"]["pseudocode"] = ""
            data["normalized_result"]["facet_availability"]["pseudocode"] = {
                "available": False, "reason": "native decompile deadline exceeded"}
        return payload

    static_session(monkeypatch, decompile_timeout)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset", rea="/host/rea")
    for row in dataset.manifest["analysis"]:
        if row["view"] in ("instructions", "references", "function"):
            assert row["availability"] == "available"
            if row["view"] == "function":
                assert row["complete"] is False
                assert row["facets"]["assembly"]["available"] is True
                assert row["facets"]["pseudocode"]["available"] is False
        else:
            assert row["availability"] == "unavailable"
            assert row["reason"] == "native decompile deadline exceeded"


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


def test_static_inventory_has_one_procedure_and_distinct_site_references(tmp_path, monkeypatch):
    config, work, run = preparation_inputs(tmp_path)
    calls = static_session(monkeypatch)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset", rea="/host/rea")
    collected_calls = list(calls)
    inventory = analysis.analysis_inventory(dataset)
    assert calls == collected_calls  # Retrieval cannot create new analyzer authority.
    assert inventory["same_procedure"] is True
    assert len(inventory["procedures"]) == len(inventory["windows"]) == 1
    procedure = inventory["procedures"][0]
    patch = dataset.manifest["patch"]["location"]
    assert procedure["procedure_id"] == f"procedure:{hex(patch)}"
    assert set(procedure["available_views"]) == {"function", "instructions", "decompilation", "references"}
    assert set(inventory["windows"][0]["sites"]) == {"patch", "destination"}
    assert {site["procedure_id"] for site in inventory["sites"].values()} == {procedure["procedure_id"]}
    references = inventory["references"]
    assert references["patch"]["references"] == [{"to": hex(patch)}]
    assert references["destination"]["references"] == [{"to": hex(patch + 1)}]
    assert references["patch"]["evidence_id"] != references["destination"]["evidence_id"]
    view = analysis.analysis_view(dataset, procedure["procedure_id"], "decompilation")
    assert view["text"] == "void fixture(void) { return; }"
    assert view["address_mapping"] == "unavailable"
    assert "normalized_result" not in json.dumps(inventory)
    assert "subject" not in json.dumps(view)


def test_partial_callee_does_not_hide_independent_static_facets(tmp_path, monkeypatch):
    config, work, run = preparation_inputs(tmp_path)

    def partial(payload):
        if payload["data"]["operation"] == "analyze_function":
            value = payload["data"]["normalized_result"]
            value["callees"] = [{"address": "0x42", "name": "known_call",
                                  "relationship_coverage": {"status": "partial", "reason": "indirect target unresolved"}}]
        return payload

    static_session(monkeypatch, partial)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset", rea="/host/rea")
    function_records = [row for row in dataset.manifest["analysis"] if row["view"] == "function"]
    assert all(row["availability"] == "available" and not row["complete"] for row in function_records)
    # Reproduce a saved dataset's old coarse classification without changing raw evidence.
    for record in function_records:
        record["availability"], record["complete"], record["reason"] = "unavailable", False, "partial"
    manifest = dataset.manifest
    manifest.pop("dataset_id")
    manifest["dataset_id"] = hashlib.sha256(canonical(manifest)).hexdigest()
    (dataset.root / "manifest.json").write_bytes(canonical(manifest))
    dataset = load_dataset(dataset.root)
    inventory = analysis.analysis_inventory(dataset)
    procedure = inventory["procedures"][0]
    assert "function" in procedure["available_views"]
    assert "decompilation" in procedure["available_views"]
    assert "callees" in procedure["available_facets"]
    function = analysis.analysis_view(dataset, procedure["procedure_id"], "function", facet="callees")
    assert function["availability"] == "available" and not function["complete"]
    assert function["records"] == [{"address": "0x42", "name": "known_call"}]
    assert function["note"]
    assert "limitations" not in function and "facets" not in function
    decompilation = analysis.analysis_view(dataset, procedure["procedure_id"], "decompilation")
    assert decompilation["text"] == "void fixture(void) { return; }"


def test_static_paging_preserves_actual_multibyte_pseudocode_and_instruction_order(tmp_path, monkeypatch):
    config, work, run = preparation_inputs(tmp_path)
    patch = int((work / "patch-location").read_text(), 16)
    pseudocode = "".join(f"  /* строка {index} */ return_value += {index};\n" for index in range(400))

    def large(payload):
        value = payload["data"]["normalized_result"]
        if isinstance(value, dict) and "procedure" in value:
            value["procedure"]["body"]["ranges"] = [{"start": hex(patch), "end": hex(patch + 511)}]
        if payload["data"]["operation"] == "analyze_function":
            value["pseudocode"] = pseudocode
        if payload["data"]["operation"] == "read_function_instructions":
            value["instructions"] = [f"{hex(patch + index)}: NOP" for index in range(512)]
        return payload

    static_session(monkeypatch, large)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset", rea="/host/rea")
    procedure_id = f"procedure:{hex(patch)}"
    offset, chunks, evidence_ids = 0, [], set()
    while offset is not None:
        page = analysis.analysis_view(dataset, procedure_id, "decompilation", offset=offset)
        assert len(page["text"].encode()) <= 8192
        assert len(page["text"].splitlines()) <= 120
        assert page["range"]["start"] == offset
        assert page["range"]["end"] == offset + len(page["text"].encode())
        assert page["total"] == len(pseudocode.encode())
        assert page["address_mapping"] == "unavailable"
        assert page["evidence_id"] not in evidence_ids
        evidence_ids.add(page["evidence_id"])
        chunks.append(page["text"])
        offset = page["next_offset"]
    assert "".join(chunks) == pseudocode
    assert len(chunks) > 1
    window = {"address": hex(patch + 200), "before": 100, "after": 100}
    offset, addresses = 0, []
    while offset is not None:
        page = analysis.analysis_view(dataset, procedure_id, "instructions", window=window, offset=offset)
        addresses.extend(row["address"] for row in page["instructions"])
        assert page["total"] == 201
        offset = page["next_offset"]
    assert addresses == [hex(patch + index) for index in range(100, 301)]


def test_instruction_windows_stop_at_body_gaps_and_reject_noninstructions(tmp_path, monkeypatch):
    config, work, run = preparation_inputs(tmp_path)
    patch = int((work / "patch-location").read_text(), 16)

    def discontinuous(payload):
        value = payload["data"]["normalized_result"]
        if isinstance(value, dict) and "procedure" in value:
            value["procedure"]["body"]["ranges"] = [
                {"start": hex(patch), "end": hex(patch + 3)},
                {"start": hex(patch + 8), "end": hex(patch + 15)}]
        if payload["data"]["operation"] == "read_function_instructions":
            value["instructions"] = [f"{hex(patch + index)}: NOP" for index in [*range(4), *range(8, 16)]]
        return payload

    static_session(monkeypatch, discontinuous)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset", rea="/host/rea")
    procedure_id = f"procedure:{hex(patch)}"
    view = analysis.analysis_view(dataset, procedure_id, "instructions",
                                  window={"address": hex(patch + 8), "before": 100, "after": 100})
    assert [row["address"] for row in view["instructions"]] == [hex(patch + index) for index in range(8, 16)]
    assert view["body_range"] == {"start": hex(patch + 8), "end": hex(patch + 16), "range_end": "exclusive"}
    assert all("body_range" not in row for row in view["instructions"])
    for address in (patch + 4, patch - 1, patch + 16):
        with pytest.raises(ValueError, match="exact frozen instruction"):
            analysis.analysis_view(dataset, procedure_id, "instructions", window={"address": hex(address)})


@pytest.mark.parametrize("procedure,view,arguments,reason", [
    ("patch", "instructions", {}, "valid choices"),
    ("function:patch", "instructions", {}, "valid choices"),
    (None, "instructions", {}, "valid choices"),
    ("canonical", "unknown", {}, "view must"),
    ("canonical", "references", {}, "requires site"),
    ("canonical", "references", {"site": "unrelated"}, "valid sites"),
    ("canonical", "function", {"window": {}}, "only supported"),
    ("canonical", "instructions", {"facet": "cfg"}, "only supported"),
    ("canonical", "decompilation", {"address": "0x1"}, "only supported"),
    ("canonical", "function", {"facet": "unknown"}, "facet must"),
    ("canonical", "function", {"address": "0x1"}, "requires a function facet"),
    ("canonical", "function", {"facet": "cfg", "address": 1}, "address string"),
    ("canonical", "function", {"facet": "cfg", "address": "0x1"}, "inside the frozen procedure body"),
    ("canonical", "function", {"facet": "native_api", "address": "0x1"}, "procedure-wide"),
    ("canonical", "instructions", {"window": {"before": 101}}, "0..100"),
    ("canonical", "instructions", {"window": {"after": True}}, "0..100"),
    ("canonical", "instructions", {"window": {"address": 1}}, "address string"),
    ("canonical", "instructions", {"window": {"unexpected": 1}}, "window must"),
    ("canonical", "decompilation", {"offset": -1}, "nonnegative"),
    ("canonical", "decompilation", {"offset": 9999}, "offset outside"),
])
def test_static_scope_and_bounds_fail_usefully(tmp_path, monkeypatch, procedure, view, arguments, reason):
    config, work, run = preparation_inputs(tmp_path)
    static_session(monkeypatch)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset", rea="/host/rea")
    procedure_id = f"procedure:{hex(dataset.manifest['patch']['location'])}" if procedure == "canonical" else procedure
    with pytest.raises(ValueError, match=reason):
        analysis.analysis_view(dataset, procedure_id, view, **arguments)


def test_static_reads_reauthenticate_frozen_evidence(tmp_path, monkeypatch):
    config, work, run = preparation_inputs(tmp_path)
    static_session(monkeypatch)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset", rea="/host/rea")
    inventory = analysis.analysis_inventory(dataset)
    (dataset.root / dataset.manifest["analysis"][0]["path"]).write_text("{}")
    with pytest.raises(ValueError, match="hash mismatch"):
        analysis.analysis_view(dataset, inventory["procedures"][0]["procedure_id"], "instructions")
    with pytest.raises(ValueError, match="hash mismatch"):
        analysis.analysis_inventory(dataset)


@pytest.mark.parametrize("defect,reason", [
    ("string", "malformed frozen instruction"),
    ("address", "malformed frozen instruction address"),
    ("missing-text", "decoded text unavailable"),
    ("empty-text", "decoded text unavailable"),
    ("record", "malformed frozen instruction record"),
    ("outside", "outside resolved procedure body"),
    ("duplicate", "duplicate frozen instruction address"),
])
def test_invalid_frozen_instructions_are_not_silently_omitted(tmp_path, monkeypatch, defect, reason):
    config, work, run = preparation_inputs(tmp_path)
    patch = int((work / "patch-location").read_text(), 16)

    def invalid(payload):
        if payload["data"]["operation"] == "read_function_instructions":
            rows = payload["data"]["normalized_result"]["instructions"]
            replacement = {
                "string": "not an addressed instruction",
                "address": {"address": "not-an-address", "text": "NOP"},
                "missing-text": {"address": hex(patch + 2)},
                "empty-text": f"{hex(patch + 2)}:   ",
                "record": None,
                "outside": f"{hex(patch + 16)}: NOP",
                "duplicate": rows[0],
            }
            rows[2] = replacement[defect]
        return payload

    static_session(monkeypatch, invalid)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset", rea="/host/rea")
    with pytest.raises(ValueError, match=reason):
        analysis.analysis_view(dataset, f"procedure:{hex(patch)}", "instructions")
    with pytest.raises(ValueError, match=reason):
        analysis.analysis_inventory(dataset)


@pytest.mark.parametrize("many", [False, True])
def test_instruction_calls_expose_compact_resolved_target_without_name_facet(tmp_path, monkeypatch, many):
    config, work, run = preparation_inputs(tmp_path)
    patch = int((work / "patch-location").read_text(), 16)

    def resolved(payload):
        if payload["data"]["operation"] == "analyze_function":
            value = payload["data"]["normalized_result"]
            value["facet_availability"]["strings_names"] = {"available": False}
            value["facet_availability"]["references"] = {"available": True}
            value["referenced_names"] = []
            value["outgoing_references"] = [{
                "source_address": hex(patch), "target_address": "0x403130", "kind": {"call": True},
                "target_procedure": {"address": "0x403130", "name": "<EXTERNAL>::qsort",
                    "body": {"ranges": [{"start": "0x403130", "end": "0x403135"}]},
                    "classification": {"thunk": True, "external": False, "thunk_target": "0x651080"}}}]
            if many:
                value["outgoing_references"].extend({"source_address": hex(patch),
                    "target_address": hex(0x403200 + index), "kind": {"call": True},
                    "target_procedure": {"name": "long_label_" + "x" * 1000}} for index in range(12))
        if payload["data"]["operation"] == "read_function_instructions":
            payload["data"]["normalized_result"]["instructions"][0] = f"{hex(patch)}: CALL 0x403130"
        return payload

    static_session(monkeypatch, resolved)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset", rea="/host/rea")
    page = analysis.analysis_view(dataset, f"procedure:{hex(patch)}", "instructions")
    call = page["instructions"][0]
    assert call["call_targets"][0] == {"address": "0x403130", "name": "<EXTERNAL>::qsort",
                                       "thunk": True, "external": False, "thunk_target": "0x651080"}
    assert call["call_targets_truncated"] is many
    assert len(call["call_targets"]) == (8 if many else 1)
    if many:
        assert all(len(target["name"]) == 256 and target["label_truncated"]
                   for target in call["call_targets"][1:])
    assert all("body" not in target for target in call["call_targets"])
    assert "referenced_names" not in call


@pytest.fixture
def selective_static(tmp_path, monkeypatch):
    config, work, run = preparation_inputs(tmp_path)
    patch = int((work / "patch-location").read_text(), 16)
    ids = [f"{hex(patch + offset)}#{index}" for index, offset in enumerate((4, 4, 8, 12))]

    def enrich(payload):
        if payload["data"]["operation"] != "analyze_function":
            return payload
        value = payload["data"]["normalized_result"]
        value["facet_availability"].update({key: {"available": True} for key in
            ("callees", "callers", "cfg", "strings_names", "references")})
        value["callees"] = [{"address": "0x42", "name": "selected_call", "body": {"private": "not model data"}}]
        value["callers"] = [{"address": "0x52", "name": "saved_caller"}]
        value["basic_blocks"] = [
            {"start": hex(patch), "end": hex(patch + 4), "successors": [hex(patch + 4), hex(patch + 8)]},
            {"start": hex(patch + 4), "end": hex(patch + 8), "successors": [hex(patch + 8)]},
            {"start": hex(patch + 8), "end": hex(patch + 16), "successors": []}]
        value["referenced_names"] = [{"address": "0x42", "source_address": hex(patch + 4), "value": "selected_call"}]
        value["referenced_strings"] = [{"address": "0x62", "source_address": hex(patch + 8), "value": "saved string"}]
        value["outgoing_references"] = [
            {"source_address": hex(patch + 4), "target_address": "0x42", "kind": {"call": True},
             "target_procedure": {"address": "0x42", "name": "selected_call", "body": {"private": "not model data"}}},
            {"source_address": hex(patch + 8), "target_address": "0x62", "kind": {"data": True}}]
        value["incoming_references"] = [{"source_address": "0x52", "target_address": hex(patch),
                                         "kind": {"call": True}}]
        value["native_api"] = {"available": True, "calling_convention": "__stdcall", "signature_source": "default",
            "parameters": [{"name": "param_1", "ordinal": 0, "data_type": "long", "storage": "RDI:8",
                            "confidence": "low", "evidence": [{"private": "not model data"}]}],
            "return_type": {"data_type": "long", "storage": "RAX:8", "confidence": "low"}}
        value["native_value_flow"] = {"available": True, "truncated": True, "known_omitted_edges": 2,
            "operations": [
                {"id": identifier, "address": hex(patch + offset), "opcode": "COPY", "sequence": index,
                 "is_dead": True, "block_membership": "member",
                 "inputs": [{"kind": "register", "location": "register:0x0", "size_bytes": 8,
                             "private_audit": "not model data"}],
                 "output": {"kind": "register", "location": "register:0x8", "size_bytes": 8}}
                for index, (identifier, offset) in enumerate(zip(ids, (4, 4, 8, 12)))],
            "def_use": [{"definition": ids[2], "use": ids[0], "input_index": 0},
                        {"definition": ids[0], "use": ids[1], "input_index": 0},
                        {"definition": ids[1], "use": ids[2], "input_index": 0},
                        {"definition": ids[2], "use": ids[3], "input_index": 0}],
            "effects": [{"kind": "memory_write", "operation": ids[0], "value_input": 0},
                        {"kind": "memory_write", "operation": ids[2], "value_input": 0}],
            "parameter_uses": [{"ordinal": 0, "use": ids[1], "input_index": 0},
                               {"ordinal": 0, "use": ids[3], "input_index": 0}]}
        # Useful selected facts must not be hidden behind unrelated dossier pages.
        value["comments"] = [{"text": "unrelated dossier payload " * 2000} for _ in range(30)]
        return payload

    calls = static_session(monkeypatch, enrich)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset", rea="/host/rea")
    return dataset, patch, ids, calls


@pytest.mark.parametrize("facet,expected", [("callees", "selected_call"), ("callers", "saved_caller"),
    ("strings", "saved string"), ("references", "source_address")])
def test_function_facets_do_not_page_unrelated_dossier_data(selective_static, facet, expected):
    dataset, patch, _ids, calls = selective_static
    collected_calls = list(calls)
    page = analysis.analysis_view(dataset, f"procedure:{hex(patch)}", "function", facet=facet)
    assert expected in json.dumps(page["records"])
    assert page["facet"] == facet and page["next_offset"] is None
    assert page["complete"] is True
    assert "unrelated dossier payload" not in json.dumps(page)
    assert "not model data" not in json.dumps(page)
    assert "facet" not in json.dumps(page["records"])
    assert len(canonical(page["records"])) <= 8192
    assert calls == collected_calls


def test_function_default_is_compact_facet_inventory(selective_static):
    dataset, patch, _ids, _calls = selective_static
    page = analysis.analysis_view(dataset, f"procedure:{hex(patch)}", "function")
    assert page["records"] == [] and page["total"] == 0
    assert set(page["procedure"]["available_facets"]) == set(analysis.FUNCTION_FACETS)
    assert not {"facets", "limitations", "unavailable_views", "signature"} & page["procedure"].keys()
    assert "native_api" not in page and "native_value_flow" not in page
    assert len(canonical(page)) < 2048


def test_cfg_address_selects_real_local_block_predecessors_and_successors(selective_static):
    dataset, patch, _ids, calls = selective_static
    collected_calls = list(calls)
    procedure_id = f"procedure:{hex(patch)}"
    page = analysis.analysis_view(dataset, procedure_id, "function", facet="cfg", address=str(patch + 4))
    assert page["address"] == hex(patch + 4)
    assert page["range_end"] == "exclusive"
    assert page["records"] == [
        {"relation": "block", "start": hex(patch + 4), "end": hex(patch + 8)},
        {"relation": "predecessor", "start": hex(patch), "end": hex(patch + 4)},
        {"relation": "successor", "address": hex(patch + 8), "start": hex(patch + 8), "end": hex(patch + 16)}]
    boundary = analysis.analysis_view(dataset, procedure_id, "function", facet="cfg", address=hex(patch + 8))
    assert boundary["records"][0]["start"] == hex(patch + 8)
    assert [row["relation"] for row in boundary["records"]] == ["block", "predecessor", "predecessor"]
    default = analysis.analysis_view(dataset, procedure_id, "function", facet="cfg", site="destination")
    assert default["address"] == hex(patch + 1)
    assert default["records"][0]["start"] == hex(patch)
    assert page["evidence_id"] != boundary["evidence_id"]
    continuation = analysis.analysis_view(dataset, procedure_id, "instructions",
        window={"address": hex(patch + 8), "before": 0, "after": 1})
    assert continuation["instructions"][0]["address"] == hex(patch + 8)
    assert calls == collected_calls


def test_address_local_relationships_use_matching_saved_reference_coordinates(selective_static):
    dataset, patch, _ids, _calls = selective_static
    procedure_id = f"procedure:{hex(patch)}"
    callees = analysis.analysis_view(dataset, procedure_id, "function", facet="callees", address=hex(patch + 4))
    assert len(callees["records"]) == 1
    assert callees["records"][0]["target_procedure"] == {"address": "0x42", "name": "selected_call"}
    assert callees["records"][0]["source_address"] == hex(patch + 4)
    absent = analysis.analysis_view(dataset, procedure_id, "function", facet="callees", address=hex(patch + 8))
    assert absent["records"] == []  # Data references are not invented call relationships.
    callers = analysis.analysis_view(dataset, procedure_id, "function", facet="callers", address=hex(patch))
    assert callers["records"][0]["source_address"] == "0x52"
    strings = analysis.analysis_view(dataset, procedure_id, "function", facet="strings", address=hex(patch + 8))
    assert [row["value"] for row in strings["records"]] == ["saved string"]
    references = analysis.analysis_view(dataset, procedure_id, "function", facet="references", address=hex(patch + 4))
    assert [row["direction"] for row in references["records"]] == ["outgoing"]
    assert references["records"][0]["source_address"] == hex(patch + 4)
    assert callees["evidence_id"] != references["evidence_id"]


def test_native_api_remains_optional_and_default_signature_low_confidence(selective_static):
    dataset, patch, _ids, _calls = selective_static
    procedure_id = f"procedure:{hex(patch)}"
    inventory = analysis.analysis_inventory(dataset)
    assert "__stdcall" not in json.dumps(inventory)
    page = analysis.analysis_view(dataset, procedure_id, "function", facet="native_api")
    assert page["records"][0] == {"kind": "signature", "calling_convention": "__stdcall",
                                  "signature_source": "default", "confidence": "low"}
    assert [row["confidence"] for row in page["records"]] == ["low", "low", "low"]
    assert page["note"] and "not model data" not in json.dumps(page)
    assert "address_mapping" not in page


def test_value_flow_is_address_local_with_incident_edges_and_saved_flags(selective_static):
    dataset, patch, ids, calls = selective_static
    collected_calls = list(calls)
    page = analysis.analysis_view(dataset, f"procedure:{hex(patch)}", "function", facet="value_flow", address=hex(patch + 4))
    operations = [row for row in page["records"] if row["kind"] == "operation"]
    assert {row["id"] for row in operations} == set(ids[:2])
    assert {row["address"] for row in operations} == {hex(patch + 4)}
    assert all(row["is_dead"] is True and row["block_membership"] == "member" for row in operations)
    edges = [row for row in page["records"] if row["kind"] == "def_use"]
    assert [(row["definition"], row["use"]) for row in edges] == [(ids[2], ids[0]), (ids[0], ids[1]), (ids[1], ids[2])]
    assert [row["operation"] for row in page["records"] if row["kind"] == "effects"] == [ids[0]]
    assert [row["use"] for row in page["records"] if row["kind"] == "parameter_uses"] == [ids[1]]
    assert page["complete"] is False and page["note"]
    assert "private_audit" not in json.dumps(page)
    assert "not model data" not in json.dumps(page)
    assert len(canonical(page["records"])) <= 8192
    assert calls == collected_calls


def test_missing_native_facet_is_concise_not_fabricated(tmp_path, monkeypatch):
    config, work, run = preparation_inputs(tmp_path)
    calls = static_session(monkeypatch)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset", rea="/host/rea")
    collected_calls = list(calls)
    procedure_id = f"procedure:{hex(dataset.manifest['patch']['location'])}"
    for facet in ("native_api", "value_flow", "cfg"):
        page = analysis.analysis_view(dataset, procedure_id, "function", facet=facet)
        assert page["availability"] == "unavailable" and page["complete"] is False
        assert page["total"] == 0 and page["next_offset"] is None
        assert page["note"] and len(page["note"]) < 257
        assert not {"facets", "limitations", "unavailable_views"} & page.keys()
    assert calls == collected_calls


def test_native_value_flow_pages_only_the_selected_address(tmp_path, monkeypatch):
    config, work, run = preparation_inputs(tmp_path)
    patch = int((work / "patch-location").read_text(), 16)

    def large_flow(payload):
        if payload["data"]["operation"] == "analyze_function":
            payload["data"]["normalized_result"]["native_value_flow"] = {"available": True, "operations": [
                {"id": f"{hex(patch + offset)}#{index}", "address": hex(patch + offset), "opcode": "COPY",
                 "inputs": [{"kind": "constant", "constant_hex": "1", "size_bytes": 8} for _ in range(25)]}
                for offset in (0, 8) for index in range(250)], "def_use": []}
        return payload

    calls = static_session(monkeypatch, large_flow)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset", rea="/host/rea")
    collected_calls = list(calls)
    records, offset, evidence_ids = [], 0, set()
    while offset is not None:
        page = analysis.analysis_view(dataset, f"procedure:{hex(patch)}", "function", facet="value_flow",
                                      address=hex(patch), offset=offset)
        assert len(canonical(page["records"])) <= 8192
        assert page["total"] == 250
        assert page["evidence_id"] not in evidence_ids
        evidence_ids.add(page["evidence_id"])
        records.extend(page["records"])
        offset = page["next_offset"]
    assert len(records) == 250
    assert all(row["address"] == hex(patch) and row["inputs_truncated"] is True for row in records)
    assert len(evidence_ids) > 1
    assert calls == collected_calls


@pytest.mark.parametrize("address_offset", [2, 8])
def test_cfg_never_infers_blocks_across_body_gaps(tmp_path, monkeypatch, address_offset):
    config, work, run = preparation_inputs(tmp_path)
    patch = int((work / "patch-location").read_text(), 16)

    def gapped(payload):
        value = payload["data"]["normalized_result"]
        if isinstance(value, dict) and "procedure" in value:
            value["procedure"]["body"]["ranges"] = [
                {"start": hex(patch), "end": hex(patch + 3)},
                {"start": hex(patch + 8), "end": hex(patch + 15)}]
        if payload["data"]["operation"] == "read_function_instructions":
            value["instructions"] = [f"{hex(patch + offset)}: NOP" for offset in (*range(4), *range(8, 16))]
        if payload["data"]["operation"] == "analyze_function":
            value["facet_availability"]["cfg"] = {"available": True}
            value["basic_blocks"] = [
                {"start": hex(patch), "end": hex(patch + 12), "successors": [hex(patch + 8)]},
                {"start": hex(patch + 8), "end": hex(patch + 16), "successors": []}]
        return payload

    calls = static_session(monkeypatch, gapped)
    dataset = prepare_dataset(config, work, run, None, output=tmp_path / "dataset", rea="/host/rea")
    collected_calls = list(calls)
    procedure_id = f"procedure:{hex(patch)}"
    page = analysis.analysis_view(dataset, procedure_id, "function", facet="cfg", address=hex(patch + address_offset))
    assert page["complete"] is False and page["note"]
    if address_offset == 2:
        assert page["records"] == []
    else:
        assert page["records"] == [{"relation": "block", "start": hex(patch + 8), "end": hex(patch + 16)}]
    with pytest.raises(ValueError, match="inside the frozen procedure body"):
        analysis.analysis_view(dataset, procedure_id, "function", facet="cfg", address=hex(patch + 4))
    assert calls == collected_calls
