"""Offline evidence/predicate boundaries; no native tools or providers invoked."""
import base64
import json
import shutil
import sys
from dataclasses import FrozenInstanceError

import pytest
from elftools.elf.elffile import ELFFile
from taosc_llm.context import digest, prepare_context


@pytest.fixture
def prepared(tmp_path):
    config = tmp_path / "config.env"
    config.write_text("BINARY=fixture\nPRIVATE_VALUE=do-not-project\n")
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    original = workdir / "fixture.orig"
    shutil.copyfile(sys.executable, original)
    with original.open("rb") as stream:
        entry = ELFFile(stream).header["e_entry"]
    for name in ("patch-location", "patch-destination"):
        (workdir / name).write_text(f"0x{entry:x}\n")
    evidence = {
        "schema_version": 1, "origin": "fixture", "original_sha256": digest(original.read_bytes()),
        "specification": "Negative signed return values use the error destination.",
        "destination_semantics": "Caller-selected fixture error return.",
        "functions": [{"function_id": "function:fixture", "view": "instructions", "text": "ret\n",
                       "source_ref": "opaque://not-a-file", "complete": False}],
        "observations": [
            {"evidence_id": "obs:negative", "domain": "system", "origin": "fixture",
             "source_ref": "/never/open/this", "outcome": {"label": "normal"},
             "hits": [{"state_id": "state:negative", "registers": {"rax": "-3", "rdi": "7"},
                       "availability": "available", "reason": None}]},
            {"evidence_id": "obs:zero", "domain": "function", "origin": "operator",
             "source_ref": "opaque:zero", "outcome": {"availability": "unavailable", "reason": "not recorded"}, "hits": []},
            {"evidence_id": "obs:missing", "domain": "system", "origin": "operator",
             "source_ref": "opaque:missing", "outcome": {},
             "hits": [{"state_id": "state:missing", "registers": {}, "availability": "unavailable", "reason": "capture missing"}]},
        ],
    }
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(evidence))
    return config, workdir, path, evidence


def context_from(prepared):
    return prepare_context(*prepared[:3])


def query(context, name, **args):
    return context.call_tool(name, {"context_id": context.context_id, **args})


def proposal(context, **changes):
    value = {"schema_version": 1, "context_id": context.context_id, "decision": "candidate", "jump_if": "rax < 0",
             "evidence_ids": ["obs:negative"], "assumptions": ["Caller specification is applicable."],
             "reason": "Consistent with supplied signed return convention; not execution-verified."}
    value.update(changes)
    return json.dumps(value)


def test_context_snapshot_identity_and_copy_isolation(prepared):
    context = context_from(prepared)
    again = context_from(prepared)
    assert again.context_id == context.context_id
    assert context.original_path != prepared[1] / "fixture.orig"
    assert context.original_path.read_bytes() == (prepared[1] / "fixture.orig").read_bytes()
    assert "do-not-project" not in context.initial_prompt()
    assert str(prepared[0]) not in context.initial_prompt()
    manifest = context.manifest
    manifest.pop("context_id")
    from taosc_llm.context import canonical
    assert digest(canonical(manifest)) == context.context_id
    projection = context.projection
    projection["patch"]["location"] = "0x0"
    assert context.projection["patch"]["location"] != "0x0"
    evidence = context.evidence
    evidence["observations"].clear()
    assert context.evidence["observations"]
    with pytest.raises(FrozenInstanceError):
        context.binary = "other"
    (prepared[1] / "patch-location").write_text("0x1\n")
    with pytest.raises(ValueError, match="artifact changed"):
        context.verify_artifacts()
    # Queries operate only on frozen bytes, even after caller files change.
    assert query(context, "get_patch_context")["ok"]


def test_exact_tools_scope_and_unknown_arguments(prepared):
    context = context_from(prepared)
    assert {tool["name"] for tool in context.tool_definitions()} == {
        "get_patch_context", "get_function_context", "list_observations", "get_observation", "check_predicate"}
    assert query(context, "bash")["error"]["code"] == "out_of_scope"
    assert query(context, "get_patch_context", path="/etc/passwd")["error"]["code"] == "invalid_arguments"
    assert context.call_tool("get_patch_context", {"context_id": "0" * 64})["error"]["code"] == "stale_context"
    assert query(context, "get_observation", evidence_id="heldout:1")["error"]["code"] == "out_of_scope"
    assert query(context, "get_function_context", function_id="function:fixture", view="decompilation")["error"]["code"] == "not_available"
    view = query(context, "get_function_context", function_id="function:fixture", view="instructions")
    assert view["source_refs"] == ["opaque://not-a-file"]
    assert view["complete"] is False


@pytest.mark.parametrize("expression,expected", [("rax < 0", 1), ("rax >= 0", 0), ("rax / 0", 2),
                                                  ("min64 / -1", 2), ("rax >> 64", 1), ("rdi == 7", 1)])
def test_canonical_signed_polarity_and_traps(prepared, expression, expected):
    context = context_from(prepared)
    result = query(context, "check_predicate", jump_if=expression, evidence_ids=["obs:negative"])
    assert result["ok"]
    assert result["evaluations"][0]["state_sequence"][0]["branch"] == expected
    assert "verified" not in result


def test_partial_registers_and_missing_vs_zero_hits(prepared):
    context = context_from(prepared)
    result = query(context, "get_observation", evidence_id="obs:negative")
    assert result["hits"]["items"][0]["registers"]["rbx"] is None
    assert result["origin"] == "caller-supplied"
    unavailable = query(context, "check_predicate", jump_if="rbx == 0", evidence_ids=["obs:negative"])
    state = unavailable["evaluations"][0]["state_sequence"][0]
    assert state["branch"] is None and state["availability"] == "unavailable"
    zero = query(context, "get_observation", evidence_id="obs:zero")
    missing = query(context, "get_observation", evidence_id="obs:missing")
    assert zero["zero_hits"] and zero["hits"]["total"] == "0"
    assert not missing["zero_hits"]
    assert missing["hits"]["items"][0]["availability"] == "unavailable"
    result = query(context, "check_predicate", jump_if="1", evidence_ids=["obs:missing"])
    assert result["evaluations"][0]["state_sequence"][0]["branch"] is None


@pytest.mark.parametrize("expression", ["", "rax && 1", "0xff", "rip == 0", "*(rax)", "rax; return 1", "rax <"])
def test_invalid_predicates(prepared, expression):
    context = context_from(prepared)
    assert query(context, "check_predicate", jump_if=expression)["ok"] is False
    with pytest.raises(ValueError):
        context.validate_proposal(proposal(context, jump_if=expression))


def test_ordered_pagination_and_opaque_cursors(prepared):
    config, workdir, path, evidence = prepared
    observation = evidence["observations"][0]
    observation["hits"] = [{"state_id": f"state:{i}", "registers": {"rax": str(i)},
                            "availability": "available", "reason": None} for i in range(70)]
    evidence["functions"][0]["text"] = "é" * 10000
    path.write_text(json.dumps(evidence))
    context = context_from(prepared)
    first = query(context, "get_observation", evidence_id="obs:negative")
    assert first["truncated"] and first["hits"]["omitted_after"] == "38"
    cursor = first["hits"]["next_cursor"]
    second = query(context, "get_observation", evidence_id="obs:negative", cursor=cursor)
    assert second["hits"]["items"][0]["state_id"] == "state:32"
    forged = base64.urlsafe_b64encode(b"[0,0,32]" + b"x" * 32).decode()
    assert query(context, "get_observation", evidence_id="obs:negative", cursor=forged)["error"]["code"] == "invalid_cursor"
    assert query(context, "get_observation", evidence_id="obs:missing", cursor=cursor)["error"]["code"] == "invalid_cursor"
    # A separate frozen instance cannot accept this run's cursor, even for identical evidence.
    assert query(context_from(prepared), "get_observation", evidence_id="obs:negative", cursor=cursor)["error"]["code"] == "invalid_cursor"
    function = query(context, "get_function_context", function_id="function:fixture", view="instructions")
    assert len(function["text"].encode()) <= 8192 and function["truncated"]
    checked = query(context, "check_predicate", jump_if="rax >= 0", evidence_ids=["obs:negative"])
    assert [h["hit_index"] for h in checked["evaluations"][0]["state_sequence"]] == [str(i) for i in range(70)]


@pytest.mark.parametrize("change", [
    {"schema_version": True}, {"context_id": "0" * 64}, {"decision": "other"}, {"extra": "no"},
    {"jump_if": " "}, {"decision": "abstain", "jump_if": "rax"},
    {"evidence_ids": ["heldout:secret"]}, {"evidence_ids": ["obs:negative", "obs:negative"]},
    {"assumptions": ["x" * 513]}, {"reason": ""}, {"reason": "x" * 2049},
])
def test_strict_final_proposal(prepared, change):
    context = context_from(prepared)
    with pytest.raises(ValueError):
        context.validate_proposal(proposal(context, **change))


def test_proposal_exact_json_and_abstention(prepared):
    context = context_from(prepared)
    valid = proposal(context)
    assert context.validate_proposal(valid)["jump_if"] == "rax < 0"
    assert context.validate_proposal(proposal(context, decision="abstain", jump_if=None))["decision"] == "abstain"
    for invalid in ("```json\n" + valid + "\n```", valid + " trailing", valid[:-1] + ',"reason":"duplicate"}',
                    valid.replace('"schema_version": 1', '"schema_version": NaN')):
        with pytest.raises(ValueError):
            context.validate_proposal(invalid)


@pytest.mark.parametrize("mutation", [
    lambda e: e.update(held_out=[]),
    lambda e: e["functions"][0].update(path="/etc/passwd"),
    lambda e: e["observations"][0]["hits"][0]["registers"].update(rip="0"),
    lambda e: e["observations"][0]["outcome"].update(held_out=True),
    lambda e: e.update(original_sha256="0" * 64),
    lambda e: e["observations"][0]["hits"][0]["registers"].update(rax=0),
])
def test_rejects_unbound_or_unknown_evidence_fields(prepared, mutation):
    mutation(prepared[3])
    prepared[2].write_text(json.dumps(prepared[3]))
    with pytest.raises(ValueError):
        context_from(prepared)


def test_uint64_bits_project_signed_without_fabricating_registers(prepared):
    prepared[3]["observations"][0]["hits"][0]["registers"]["rax"] = "18446744073709551615"
    prepared[2].write_text(json.dumps(prepared[3]))
    context = context_from(prepared)
    result = query(context, "get_observation", evidence_id="obs:negative")
    hit = result["hits"]["items"][0]
    assert hit["registers"]["rax"] == "-1"
    assert hit["registers"]["rbx"] is None
    assert hit["register_availability"]["rbx"]["availability"] == "unavailable"
    checked = query(context, "check_predicate", jump_if="rax < 0", evidence_ids=["obs:negative"])
    assert checked["evaluations"][0]["state_sequence"][0]["branch"] == 1


def test_frozen_artifact_tampering_is_detected(prepared):
    context = context_from(prepared)
    frozen_evidence = context.original_path.parent / "evidence.json"
    frozen_evidence.chmod(0o600)
    frozen_evidence.write_text("{}")
    with pytest.raises(ValueError, match="artifact changed"):
        context.verify_artifacts()
    with pytest.raises(ValueError, match="modified frozen artifact"):
        context_from(prepared)

