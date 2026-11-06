"""Few examples preserve semantic filters without enumerating private reports."""
import json

import pytest

from taosc_llm.context import digest, prepare_context
from taosc_llm.dataset import canonical, load_dataset
from test_context_tools import make_dataset, proposal, query


def context_for(tmp_path, count=70):
    dataset = make_dataset(tmp_path / "dataset", count=count, concrete_run=None)
    cases = dataset.cases()
    for case in cases:
        case["capture"]["outcome"] = {"outcome": "normal"}
    raw = b"".join(canonical(case) + b"\n" for case in cases)
    (dataset.root / "cases.jsonl").write_bytes(raw)
    manifest = dataset.manifest
    manifest["cases"]["sha256"] = digest(raw)
    manifest.pop("dataset_id")
    manifest["dataset_id"] = digest(canonical(manifest))
    (dataset.root / "manifest.json").write_text(json.dumps(manifest))
    return prepare_context(load_dataset(dataset.root), run_dir=tmp_path / "run")


def test_search_returns_bounded_matching_examples_not_population(tmp_path):
    context = context_for(tmp_path)
    args = {"domain": "function", "filters": {"register": {
        "register": "rax", "op": "eq", "value": "-3", "hit": "any"}}}
    response = query(context, "list_cases", **args)
    assert response["ok"] and len(response["non_crash"]) == 3 and not response["crash"]
    assert "next_cursor" not in response and "items" not in response
    assert len(json.dumps(response).encode()) < 8192
    for example in response["non_crash"]:
        assert example["registers"]["hits"][0]["registers"]["rax"] == "-3"
    missing = query(context, "list_cases", domain="all", filters={"register": {
        "register": "rax", "op": "eq", "value": "99", "hit": "any"}})
    assert missing["crash"] == missing["non_crash"] == []


def test_search_similar_known_branch_pattern_excludes_reference(tmp_path):
    context = context_for(tmp_path, 4)
    response = query(context, "list_cases", domain="function",
                     same_as={"case_id": "function:2", "features": ["branch_pattern"]})
    assert {item["case_id"] for item in response["non_crash"]} == {"function:0", "function:1", "function:3"}
    missing = query(context, "list_cases", domain="all",
                    same_as={"case_id": "function:2", "features": ["mutation_shape"]})
    assert missing["error"]["code"] == "invalid_arguments"
    outside = query(context, "list_cases", domain="all",
                    same_as={"case_id": "function:99", "features": ["branch_pattern"]})
    assert outside["error"]["code"] == "out_of_scope"


@pytest.mark.parametrize("value", ["9223372036854775808", "-9223372036854775809", "0xff", "1.0"])
def test_register_filter_rejects_non_i64_values_even_without_matches(tmp_path, value):
    context = context_for(tmp_path, 0)
    result = query(context, "list_cases", domain="all", filters={"register": {
        "register": "rax", "op": "eq", "value": value, "hit": "any"}})
    assert result["error"]["code"] == "invalid_arguments"


def test_missing_candidate_state_cannot_match_baseline_register(tmp_path):
    context = context_for(tmp_path, 1)
    context._results["outcome-only"] = {"cases": [{"case_id": "function:0", "domain": "function",
        "status": "not_rejected", "reason": "observed-not-same-crash", "source": "executed",
        "outcome": {"outcome": "normal"}, "branches": None}]}
    result = query(context, "list_cases", domain="all", result_id="outcome-only", filters={"register": {
        "register": "rax", "op": "eq", "value": "-3", "hit": "any"}})
    assert result["ok"] and result["crash"] == result["non_crash"] == []
    detail = query(context, "get_case", case_id="function:0", result_id="outcome-only")
    assert detail["case"]["candidate"] == "normal"
    assert "activation" not in detail["case"] and "states" not in detail


def test_non_equivalent_capture_is_not_candidate_search_evidence(tmp_path):
    context = context_for(tmp_path, 1)
    context._results["mismatch"] = {"predicate": "rax < 0", "cases": [{
        "case_id": "function:0", "domain": "function", "status": "not_rejected",
        "outcome": {"outcome": "normal"}, "capture": context.dataset.case("function:0")["capture"]}]}
    result = query(context, "list_cases", domain="all", result_id="mismatch", filters={"register": {
        "register": "rax", "op": "eq", "value": "-3", "hit": "any"}})
    assert result["ok"] and result["crash"] == result["non_crash"] == []
    detail = query(context, "get_case", case_id="function:0", result_id="mismatch")
    assert "activation" not in detail["case"] and "states" not in detail


def test_feedback_finds_late_counterexample_without_success_or_missing_rows(tmp_path):
    dataset = make_dataset(tmp_path / "dataset", count=70, concrete_run=None)
    manifest = dict(dataset.manifest)
    manifest["oracles"] = {"mutation_reference": {"address": 4096, "source": "guest-signal", "image": None, "offset": None}}
    manifest.pop("dataset_id")
    manifest["dataset_id"] = digest(canonical(manifest))
    (dataset.root / "manifest.json").write_text(json.dumps(manifest))
    context = prepare_context(load_dataset(dataset.root), run_dir=tmp_path / "run")
    cases = []
    for index, prepared in enumerate(context.dataset.cases()):
        capture = dict(prepared["capture"])
        capture.update(outcome={"outcome": "normal"}, same_crash=False)
        case = {"case_id": prepared["id"], "domain": "function", "source": "offline",
                "status": "not_rejected", "reason": "observed-not-same-crash",
                "capture": capture, "branches": [0], "outcome": {"outcome": "normal"}}
        if index == 68:
            capture.update(outcome={"outcome": "crash"}, same_crash=True)
            case.update(status="reject_same_crash", reason="same-crash", outcome={"outcome": "target-crash"})
        elif index == 69:
            case.update(status="unavailable", reason="unsupported-external-state", capture=None,
                        branches=None, outcome={"outcome": "unavailable"})
        cases.append(case)
    context._results["many"] = {"predicate": "0", "status": "reject_same_crash", "cases": cases}
    result = query(context, "get_candidate_result", result_id="many")
    assert result["ok"] and result["missed_target_crashes"]["count"] == 1
    assert [case["case_id"] for case in result["missed_target_crashes"]["examples"]] == ["function:68"]
    assert "function:69" not in json.dumps(result)
    assert "function:0" not in json.dumps(result)
    assert "cases" not in result and "summary" not in result
    assert query(context, "list_cases", filters={"candidate_outcome": "other_crash"})["error"]["code"] == "invalid_arguments"


def test_initial_and_returned_static_evidence_ids_are_scoped(tmp_path):
    context = context_for(tmp_path, 1)
    inline = context.projection["analysis"]["windows"][0]["evidence_id"]
    assert context.validate_proposal(proposal(context, evidence_ids=[inline]))["evidence_ids"] == [inline]
    excerpt = query(context, "get_function_analysis", procedure_id="procedure:0x1000", view="instructions",
                    window={"address": "0x1010", "before": 2, "after": 3})
    assert [item["address"] for item in excerpt["instructions"]] == [hex(value) for value in range(0x100e, 0x1014)]
    assert context.validate_proposal(proposal(context, evidence_ids=[excerpt["evidence_id"]]))
    with pytest.raises(ValueError):
        context.validate_proposal(proposal(context, evidence_ids=["e9999"]))
    serialized = json.dumps(excerpt)
    assert "normalized_result" not in serialized and "/private/source-run" not in serialized
    assert len(excerpt["evidence_id"]) < 16
