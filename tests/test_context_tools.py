"""Real file-backed prepared datasets; no provider or native execution."""
import json
from pathlib import Path

import pytest
from binradar import binradar_taosc_predicates as predicates
from taosc_llm.context import canonical, digest, prepare_context
from taosc_llm.dataset import load_dataset


def make_dataset(root, *, count=2, patch_format="ERM generic"):
    root.mkdir(parents=True, exist_ok=True)
    workdir = root / "workdir"
    workdir.mkdir()
    payloads = {"config.env": b"BINARY=fixture\nTEST_CMD=./fixture @@\n", "fixture.orig": b"harmless fixture identity",
                "fixture.brcached": b"harmless cached identity", "patch-format": patch_format.encode(),
                "patch-location": b"1000", "patch-destination": b"1001"}
    artifacts = {}
    for name, data in payloads.items():
        path = workdir / name
        path.write_bytes(data)
        artifacts[name] = {"path": "workdir/" + name, "sha256": digest(data)}
    analysis = root / "instructions.txt"
    analysis.write_text("é" * 10000)
    capture = root / "state.brch"
    capture.write_bytes(predicates.CACHED_SNAPSHOT_HEADER.pack(predicates.CACHED_SNAPSHOT_MAGIC, 1, 0, 0, 0, 0)
                        + predicates.CACHED_SNAPSHOT_REGS.pack((1 << 64) - 3, *([0] * 15)))
    cases = []
    for index in range(count):
        cases.append({"id": f"function:{index}", "domain": "function", "input_path": None, "input_sha256": None,
                      "source": {"run": "/private/source-run", "case_id": index}, "observation": {},
                      "capture": {"path": "state.brch", "sha256": digest(capture.read_bytes()),
                                  "artifact_sha256": artifacts["fixture.brcached"]["sha256"], "branches": [0],
                                  "outcome": {}, "same_crash": None, "complete": True, "descriptor": "p0"}})
    case_path = root / "cases.jsonl"
    case_path.write_text("".join(json.dumps(c) + "\n" for c in cases))
    manifest = {"schema_version": 2, "binary": "fixture", "patch_format": patch_format,
                "patch": {"location": 4096, "destination": 4097, "address_domain": "elf-va"},
                "artifacts": artifacts, "sources": {"concrete_run": "/private/source-run", "mutation_run": None},
                "analysis": [{"function_id": "function:patch", "view": "instructions", "path": "instructions.txt",
                              "sha256": digest(analysis.read_bytes()), "availability": "available", "reason": None,
                              "complete": True, "backend": "fixture-static", "backend_version": "1"}],
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
    assert context.context_id == prepare_context(context.dataset).context_id
    assert "/private/source-run" not in context.initial_prompt()
    original = context.projection
    original["patch"]["location"] = 0
    assert int(context.projection["patch"]["location"], 16) == 4096
    context.dataset.artifact("fixture.orig").write_bytes(b"changed")
    with pytest.raises(ValueError):
        context.verify_artifacts()
    assert not query(context, "get_patch_context")["ok"]


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
    assert result["ok"] and result["valid_syntax"] and result["verified"] is False
    assert result["cases"]["total"] == 2
    referenced = query(context, "get_candidate_result", result_id=result["result_id"])
    assert referenced["cases"] == result["cases"]
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
    assert unavailable["ok"] and unavailable["availability"] == "unavailable"
    assert "zero_hits" not in unavailable
    prepared = query(context, "get_case", case_id="function:0")
    state_id = prepared["states"]["items"][0]["state_id"]
    assert query(context, "get_case", **args, state_id=state_id)["error"]["code"] == "out_of_scope"
    assert query(context, "get_case", **args, cursor="malformed")["error"]["code"] == "invalid_cursor"
    analysis = query(context, "get_function_analysis", function_id="function:patch", view="instructions")
    assert query(context, "get_case", **args, cursor=analysis["next_cursor"])["error"]["code"] == "invalid_cursor"


def test_analysis_pagination_and_cursor_scope(context):
    first = query(context, "get_function_analysis", function_id="function:patch", view="instructions")
    assert len(first["text"].encode()) <= 8192 and first["truncated"]
    second = query(context, "get_function_analysis", function_id="function:patch", view="instructions", cursor=first["next_cursor"])
    assert second["byte_offset"] == len(first["text"].encode())
    assert query(context, "list_cases", domain="all", cursor=first["next_cursor"])["error"]["code"] == "invalid_cursor"


def test_large_dataset_pages_not_global_cap(tmp_path):
    context = prepare_context(make_dataset(tmp_path / "large", count=1100))
    first = query(context, "list_cases", domain="all")
    assert first["total"] == 1100 and len(first["items"]) == 32
    second = query(context, "list_cases", domain="all", cursor=first["next_cursor"])
    assert second["items"][0]["id"] == "function:32"


@pytest.mark.parametrize("expression", ["", "rax && 1", "rax; return 1", "rip == 0", "0xff"])
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


def test_exact_json_and_result_evidence(context):
    result = query(context, "evaluate_predicate", predicate="rax < 0")
    assert context.validate_proposal(proposal(context, evidence_ids=[result["result_id"]]))["predicate"] == "rax < 0"
    assert context.validate_proposal(proposal(context, decision="abstain", predicate=None))["decision"] == "abstain"
    for value in ("```" + proposal(context), proposal(context) + " trailing", proposal(context)[:-1] + ',"reason":"duplicate"}'):
        with pytest.raises(ValueError):
            context.validate_proposal(value)
