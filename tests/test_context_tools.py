"""Real file-backed prepared datasets; no provider or native execution."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
from pathlib import Path
import threading

import pytest
from binradar import binradar_taosc_predicates as predicates
from taosc_llm.context import canonical, digest, prepare_context
from taosc_llm.dataset import load_dataset


def make_dataset(root, *, count=2, patch_format="ERM generic", binradar_run=None,
                 concrete_run="/private/source-run"):
    root.mkdir(parents=True, exist_ok=True)
    workdir = root / "workdir"
    workdir.mkdir()
    payloads = {"config.env": b"BINARY=fixture\nTEST_CMD=./fixture @@\n", "fixture.orig": b"harmless fixture identity",
                "fixture.brcached": b"harmless cached identity", "patch-format": patch_format.encode(),
                "patch-location": b"1000", "patch-destination": b"1001"}
    cwe805 = patch_format == "ERM CWE-805"
    if cwe805:
        payloads["stack-size"] = b"0\n"
    artifacts = {}
    for name, data in payloads.items():
        path = workdir / name
        path.write_bytes(data)
        artifacts[name] = {"path": "workdir/" + name, "sha256": digest(data)}
    analysis_records = []
    procedure = {"address": "0x1000", "body": {"available": True,
                 "ranges": [{"start": "0x1000", "end": "0x11ff"}]}}
    extent = {"entry": 4096, "start": 4096, "end": 4608,
              "ranges": [{"start": 4096, "end": 4608}], "confidence": "ghidra-function-body",
              "address_domain": "elf-va"}
    def evidence(operation, address, normalized):
        return {"ok": True, "data": {"subject": {"digest": {"sha256": artifacts["fixture.orig"]["sha256"]}},
            "provider": {"id": "ghidra", "version": "12.1"}, "operation": operation,
            "parameters": {"address" if operation in ("resolve_containing_procedure", "xrefs") else "procedure": hex(address)},
            "normalized_result": normalized}}
    for role, address in (("patch", 4096), ("destination", 4097)):
        resolution = evidence("resolve_containing_procedure", address,
            {"query_address": hex(address), "found": True, "procedure": procedure})
        for view in ("instructions", "decompilation", "references"):
            path = root / (role + "-" + view + ".json")
            operation = {"instructions": "read_function_instructions", "decompilation": "analyze_function", "references": "xrefs"}[view]
            normalized = ({"procedure": procedure, "instructions": [hex(4096 + i) + ": NOP" for i in range(512)]}
                if view == "instructions" else {"procedure": procedure, "pseudocode": "\n".join("  /* é */ step_" + str(i) + "();" for i in range(500)),
                    "facet_availability": {"pseudocode": {"available": True}}} if view == "decompilation" else ["0x1002"])
            record = {"function_id": role, "view": view, "path": path.name, "availability": "available",
                "reason": None, "complete": True, "backend": "ghidra", "backend_version": "12.1",
                "range": extent, "requested_address": address, "analysis_address": address if view == "references" else 4096,
                "artifact_sha256": artifacts["fixture.orig"]["sha256"]}
            payload = {"metadata": record, "resolution": resolution,
                       "evidence": evidence(operation, record["analysis_address"], normalized)}
            if view == "decompilation":
                payload["value"] = normalized["pseudocode"]
            path.write_bytes(canonical(payload))
            analysis_records.append({**record, "sha256": digest(path.read_bytes())})
    capture = root / "state.brch"
    capture.write_bytes(predicates.CACHED_SNAPSHOT_HEADER.pack(
        predicates.CACHED_SNAPSHOT_MAGIC, 1, 0, 0, 0, 2 if cwe805 else 0)
        + (b"\0" * predicates.CACHED_SNAPSHOT_CLAMPS.size if cwe805 else b"")
        + predicates.CACHED_SNAPSHOT_REGS.pack((1 << 64) - 3, *([0] * 15)))
    cases = []
    for index in range(count):
        cases.append({"id": f"function:{index}", "domain": "function", "input_path": None, "input_sha256": None,
                      "source": {"run": "/private/source-run", "case_id": index}, "observation": {},
                      "capture": {"path": "state.brch", "sha256": digest(capture.read_bytes()),
                                  "artifact_sha256": artifacts["fixture.brcached"]["sha256"], "branches": [0],
                                  "outcome": {}, "same_crash": None, "timeout_excluded": True,
                                  "complete": True, "descriptor": "p0"}})
    case_path = root / "cases.jsonl"
    case_path.write_text("".join(json.dumps(c) + "\n" for c in cases))
    manifest = {"schema_version": 2, "binary": "fixture", "patch_format": patch_format,
                "patch": {"location": 4096, "destination": 4097, "address_domain": "elf-va"},
                "artifacts": artifacts, "sources": {"concrete_run": concrete_run,
                                                   "binradar_run": None if binradar_run is None else str(binradar_run)},
                "analysis": analysis_records,
                "cases": {"path": "cases.jsonl", "sha256": digest(case_path.read_bytes())}}
    from taosc_llm.dataset import canonical as dataset_canonical
    manifest["dataset_id"] = digest(dataset_canonical(manifest))
    (root / "manifest.json").write_text(json.dumps(manifest))
    return load_dataset(root)


@pytest.fixture
def context(tmp_path):
    return prepare_context(make_dataset(tmp_path / "dataset"), run_dir=tmp_path / "run")


def query(context, name, **args):
    return context.call_tool(name, {"context_id": context.context_id, **args})


def proposal(context, **changes):
    value = {"schema_version": 1, "context_id": context.context_id, "decision": "candidate", "predicate": "rax < 0",
             "evidence_ids": ["function:0"], "assumptions": [], "reason": "Offline fixture only; no verified claim."}
    value.update(changes)
    return json.dumps(value)


def test_dataset_identity_and_private_projection(context):
    other = prepare_context(context.dataset)
    assert other.context_id != context.context_id
    assert other.call_tool("get_patch_context", {"context_id": context.context_id})["error"]["code"] == "stale_context"
    assert all(record["sha256"] not in context.initial_prompt()
               for record in context.dataset.manifest["artifacts"].values())
    assert "/private/source-run" not in context.initial_prompt()
    original = context.projection
    original["patch"]["location"] = 0
    assert int(context.projection["patch"]["location"], 16) == 4096
    context.dataset.artifact("fixture.orig").write_bytes(b"changed")
    with pytest.raises(ValueError):
        context.verify_artifacts()
    assert not query(context, "get_patch_context")["ok"]


@pytest.mark.parametrize('name,args', [
    ('get_patch_context', {}),
    ('get_function_analysis', {'procedure_id': 'procedure:0x1000', 'view': 'instructions'}),
    ('list_cases', {'domain': 'all'}),
    ('get_case', {'case_id': 'function:0'}),
    ('evaluate_predicate', {'predicate': '0'}),
    ('test_candidate', {'predicate': '0'}),
    ('get_candidate_result', {'result_id': 'earlier'}),
])
def test_each_tool_revalidates_after_an_earlier_success(context, name, args):
    assert query(context, 'get_patch_context')['ok']
    context._results['earlier'] = {'cases': []}
    context.dataset.artifact('fixture.orig').write_bytes(b'changed between tools')
    result = query(context, name, **args)
    assert result['ok'] is False
    assert result['error']['code'] == 'backend_error'


@pytest.mark.parametrize("name", ["evaluate_predicate", "test_candidate"])
def test_invalid_predicate_fails_before_dataset_io_but_valid_predicate_authenticates(context, monkeypatch, name):
    from taosc_llm import evaluation

    def forbidden_evaluation(*args, **kwargs):
        pytest.fail("unauthenticated candidate reached evaluation")

    monkeypatch.setattr(evaluation, "evaluate_dataset", forbidden_evaluation)
    before_results = dict(context._results)
    before_evidence = set(context._evidence_ids)
    # A malformed candidate has no evidence/target authority and needs only the
    # canonical family parser, even if the prepared source is now unavailable.
    context.dataset.artifact("fixture.orig").unlink()
    result = query(context, name, predicate="rax[")
    assert result["error"]["code"] == "invalid_predicate"
    # Successful parsing must still authenticate every record before evaluation.
    result = query(context, name, predicate="0")
    assert result["error"]["code"] == "backend_error"
    assert context._results == before_results
    assert set(context._evidence_ids) == before_evidence


def test_parallel_tool_evaluation_does_not_share_validation_scope(context, monkeypatch):
    original = context.dataset
    validation = type(original).validation
    entered, release = threading.Event(), threading.Event()

    @contextmanager
    def pause_validated_operation(dataset):
        with validation(dataset) as validated:
            entered.set()
            if not release.wait(10):
                raise RuntimeError('test operation was not released')
            yield validated

    monkeypatch.setattr(type(original), 'validation', pause_validated_operation)
    with ThreadPoolExecutor(max_workers=1) as pool:
        running = pool.submit(query, context, 'evaluate_predicate', predicate='0')
        try:
            assert entered.wait(10)
            assert context.dataset is original
            original.artifact('fixture.orig').write_bytes(b'changed during independent operation')
            # The new operation must authenticate independently, not borrow the
            # in-flight operation's already authenticated view.
            second = query(context, 'get_patch_context')
            assert second['ok'] is False
            assert second['error']['code'] == 'backend_error'
            assert context.dataset is original
        finally:
            release.set()
        first = running.result(timeout=10)
    assert first['ok'] is True
    assert context._results[first["result_id"]]["cases"][0]["report"]["activation"]["status"] == "not_fired"
    assert context.dataset is original


def test_scoped_authority(context):
    assert query(context, "shell")["error"]["code"] == "out_of_scope"
    for name, extra in (("test_candidate", {"predicate": "0", "case_ids": []}),
                        ("get_patch_context", {"path": "/etc/passwd"}),
                        ("evaluate_predicate", {"predicate": "0", "execute": True})):
        assert query(context, name, **extra)["error"]["code"] == "invalid_arguments"
    assert query(context, "get_case", case_id="system:999")["error"]["code"] == "out_of_scope"
    assert "/private" not in json.dumps(query(context, "get_case", case_id="function:0"))


def test_real_offline_evaluation_and_result_reference(context):
    result = query(context, "evaluate_predicate", predicate="rax < 0")
    assert result["ok"] and result["mode"] == "offline"
    assert result["missed_target_crashes"]["count"] == 0
    assert result["regressions"]["count"] == 0
    assert "warning" in result
    assert "cases" not in result and "summary" not in result
    referenced = query(context, "get_candidate_result", result_id=result["result_id"])
    assert referenced == result
    assert query(context, "get_candidate_result", result_id="foreign")["error"]["code"] == "out_of_scope"


def test_evaluated_state_ids_cannot_cross_result_boundaries(context):
    first = query(context, "evaluate_predicate", predicate="0")
    second = query(context, "evaluate_predicate", predicate="rax > 0")
    states = query(context, "get_case", case_id="function:0", result_id=first["result_id"])
    state_id = states["states"]["items"][0]["state_id"]
    selected = query(context, "get_case", case_id="function:0", result_id=first["result_id"], state_id=state_id)
    assert selected["state"]["registers"]["rax"] == "-3"
    assert query(context, "get_case", case_id="function:0", result_id=second["result_id"],
                 state_id=state_id)["error"]["code"] == "out_of_scope"


def test_unavailable_result_capture_rejects_state_and_cursor(context):
    context._results["unavailable-result"] = {"cases": [{"case_id": "function:0", "capture": None}]}
    args = {"case_id": "function:0", "result_id": "unavailable-result"}
    unavailable = query(context, "get_case", **args)
    assert unavailable["ok"] and "states" not in unavailable and "note" in unavailable
    assert "zero_hits" not in unavailable
    prepared = query(context, "get_case", case_id="function:0")
    state_id = prepared["states"]["items"][0]["state_id"]
    assert query(context, "get_case", **args, state_id=state_id)["error"]["code"] == "out_of_scope"
    assert query(context, "get_case", **args, cursor="malformed")["error"]["code"] == "invalid_cursor"
    analysis = query(context, "get_function_analysis", procedure_id="procedure:0x1000", view="decompilation")
    assert query(context, "get_case", **args, cursor=analysis["next_cursor"])["error"]["code"] == "invalid_cursor"


def test_analysis_pagination_and_cursor_scope(context):
    first = query(context, "get_function_analysis", procedure_id="procedure:0x1000", view="decompilation")
    assert len(first["text"].encode()) <= 8192 and first["truncated"]
    pages = [first["text"]]
    current = first
    while current.get("next_cursor"):
        current = query(context, "get_function_analysis", procedure_id="procedure:0x1000",
                        view="decompilation", cursor=current["next_cursor"])
        assert current["ok"]
        pages.append(current["text"])
    assert "".join(pages) == "\n".join("  /* é */ step_" + str(i) + "();" for i in range(500))
    wrong = query(context, "get_function_analysis", procedure_id="procedure:0x1000",
                  view="instructions", cursor=first["next_cursor"])
    assert wrong["error"]["code"] == "invalid_cursor"


@pytest.mark.parametrize("expression", ["", "rax &&", "rax; return 1", "rip == 0", "0xff"])
def test_family_parser_rejects_invalid_candidates(context, expression):
    assert not query(context, "evaluate_predicate", predicate=expression)["ok"]
    with pytest.raises(ValueError):
        context.validate_proposal(proposal(context, predicate=expression))


@pytest.mark.parametrize("changes", [{"schema_version": True}, {"jump_if": "0"}, {"evidence_ids": ["system:999"]},
                                     {"predicate": "rax < 0", "decision": "abstain"}, {"reason": ""},
                                     {"evidence_ids": ["function:0", "function:0"]}])
def test_exact_proposal_fields(context, changes):
    with pytest.raises(ValueError):
        context.validate_proposal(proposal(context, **changes))


@pytest.mark.parametrize("patch_format,expression", [
    ("ERM generic", "rax != 0 && 10 / rax < 0"),
    ("ERM CWE-805", "(s->rax >= i->begin && s->rax < i->end) || (1 * s->rbx < i->end - i->begin)"),
])
def test_logical_candidate_tool_and_proposal_roundtrip(tmp_path, patch_format, expression):
    context = prepare_context(make_dataset(tmp_path / "dataset", patch_format=patch_format))
    assert query(context, "get_patch_context")["ok"]
    result = query(context, "evaluate_predicate", predicate=expression)
    assert result["ok"]
    parsed = context.validate_proposal(proposal(
        context, predicate=expression, evidence_ids=[result["result_id"]]))
    assert parsed["predicate"] == expression


def test_exact_json_and_result_evidence(context):
    result = query(context, "evaluate_predicate", predicate="rax < 0")
    assert context.validate_proposal(proposal(context, evidence_ids=[result["result_id"]]))["predicate"] == "rax < 0"
    assert context.validate_proposal(proposal(context, decision="abstain", predicate=None))["decision"] == "abstain"
    for value in ("```" + proposal(context), proposal(context) + " trailing", proposal(context)[:-1] + ',"reason":"duplicate"}'):
        with pytest.raises(ValueError):
            context.validate_proposal(value)
