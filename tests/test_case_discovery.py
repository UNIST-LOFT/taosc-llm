"""Case search and prioritization preserve rare evidence and exact query scope."""
import json

import pytest

from taosc_llm.context import prepare_context
from test_context_tools import make_dataset, proposal, query


def context_for(tmp_path, count=70):
    return prepare_context(make_dataset(tmp_path / "dataset", count=count, concrete_run=None),
                           run_dir=tmp_path / "run")


def test_query_cursor_cannot_change_filter_order_or_result(tmp_path):
    context = context_for(tmp_path)
    args = {"domain": "function", "order": "case_id", "filters": {"register": {
        "register": "rax", "op": "eq", "value": "-3", "hit": "any"}}}
    first = query(context, "list_cases", **args)
    assert first["ok"] and first["total"] == 70
    seen = [item["case_id"] for item in first["items"]]
    cursor = first["next_cursor"]
    while cursor:
        page = query(context, "list_cases", **args, cursor=cursor)
        assert page["query_id"] == first["query_id"]
        seen.extend(item["case_id"] for item in page["items"])
        cursor = page["next_cursor"]
    assert seen == [f"function:{index}" for index in range(70)]
    for changed in ({"order": "noteworthy"}, {"domain": "all"}, {"filters": {}}):
        response = query(context, "list_cases", **{**args, **changed}, cursor=first["next_cursor"])
        assert response["error"]["code"] == "invalid_cursor"
        assert "belongs to query" in response["error"]["message"]
        assert "requested query" in response["error"]["message"]


def test_search_similar_known_branch_pattern_excludes_reference(tmp_path):
    context = context_for(tmp_path, 4)
    response = query(context, "list_cases", domain="function", order="case_id",
                     same_as={"case_id": "function:2", "features": ["branch_pattern"]})
    assert [item["case_id"] for item in response["items"]] == ["function:0", "function:1", "function:3"]
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


def test_unknown_candidate_state_cannot_match_baseline_register(tmp_path):
    context = context_for(tmp_path, 1)
    context._results["outcome-only"] = {"cases": [{"case_id": "function:0", "domain": "function",
        "status": "not_rejected", "reason": "observed-not-same-crash", "source": "executed",
        "outcome": {"outcome": "normal"}, "branches": None}]}
    result = query(context, "list_cases", domain="all", result_id="outcome-only", filters={"register": {
        "register": "rax", "op": "eq", "value": "-3", "hit": "any"}})
    assert result["ok"] and result["total"] == 0
    detail = query(context, "get_case", case_id="function:0", result_id="outcome-only")
    assert detail["case"]["candidate"]["outcome"] == "normal"
    assert detail["case"]["activation"]["status"] == "unknown"
    assert detail["state_capture"]["status"] == "unavailable"


def test_non_equivalent_capture_is_not_candidate_search_evidence(tmp_path):
    context = context_for(tmp_path, 1)
    context._results["mismatch"] = {"predicate": "rax < 0", "cases": [{
        "case_id": "function:0", "domain": "function", "status": "not_rejected",
        "outcome": {"outcome": "normal"}, "capture": context.dataset.case("function:0")["capture"]}]}
    result = query(context, "list_cases", domain="all", result_id="mismatch", filters={"register": {
        "register": "rax", "op": "eq", "value": "-3", "hit": "any"}})
    assert result["ok"] and result["total"] == 0
    detail = query(context, "get_case", case_id="function:0", result_id="mismatch")
    assert detail["case"]["activation"]["status"] == "unknown"
    assert detail["case"]["candidate"]["capture"]["status"] == "invalid"
    assert detail["state_capture"]["status"] == "unavailable"


def test_prioritization_surfaces_late_counterexample_and_reason_group(tmp_path):
    from taosc_llm.context import digest
    from taosc_llm.dataset import canonical, load_dataset
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
    assert result["ok"] and result["status"] == "rejects_target"
    first = result["cases"]["items"]
    assert first[0]["case_id"] == "function:68"
    assert "function:69" in {item["case_id"] for item in first}
    assert result["cases"]["total"] == 70
    filtered = query(context, "list_cases", result_id="many", domain="function",
                     filters={"candidate_outcome": "unknown", "reason": "unsupported-external-state"})
    assert [item["case_id"] for item in filtered["items"]] == ["function:69"]


def test_initial_and_returned_static_evidence_ids_are_scoped(tmp_path):
    context = context_for(tmp_path, 1)
    inline = context.projection["analysis"]["windows"][0]["evidence_id"]
    assert context.validate_proposal(proposal(context, evidence_ids=[inline]))["evidence_ids"] == [inline]
    excerpt = query(context, "get_function_analysis", procedure_id="procedure:0x1000", view="instructions",
                    window={"address": "0x1010", "before": 2, "after": 3})
    assert [item["address"] for item in excerpt["instructions"]] == [hex(value) for value in range(0x100e, 0x1014)]
    assert context.validate_proposal(proposal(context, evidence_ids=[excerpt["evidence_id"]]))
    with pytest.raises(ValueError):
        context.validate_proposal(proposal(context, evidence_ids=["analysis:" + "0" * 64]))
    serialized = json.dumps(excerpt)
    assert "normalized_result" not in serialized and "/private/source-run" not in serialized
