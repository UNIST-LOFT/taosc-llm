"""Refinement failures and exact host checks; no provider, target or fake verdict."""
import asyncio
import json

import pytest

from taosc_llm.context import prepare_context
from taosc_llm.provider import ProviderConfig
from taosc_llm import synthesis
from test_context_tools import make_dataset, proposal


def terminal(context, final, checked):
    return {"type": "turn_complete", "final_text": final, "host_inspected_context": True,
            "host_checked_predicates": checked}


@pytest.mark.parametrize("settled,status,delay,code,expected_attempts", [
    (True, 429, 2, "provider_rate_limited", 3),
    (False, 429, 2, "provider_rate_limited", 1),
    (True, 401, 2, "provider_rate_limited", 1),
    (True, 429, None, "provider_rate_limited", 1),
    (True, 429, True, "provider_rate_limited", 1),
    (True, 429, -1, "provider_rate_limited", 1),
    (True, 429, 31, "provider_rate_limited", 1),
    (True, 429, 2, "diagnostic_persistence_error", 1),
])
def test_retry_uses_terminal_settlement_and_existing_bounds(
        tmp_path, monkeypatch, settled, status, delay, code, expected_attempts):
    provider = ProviderConfig(api_key="offline-only", base_url="https://example.invalid/v1",
                              model="offline", timeout_seconds=30)
    journals = []
    delays = []
    async def fail(context, provider, command, run_id, journal):
        journals.append(journal.name)
        return {"type": "turn_failed", "remote_settled": settled, "http_status": status,
                "retry_after_seconds": delay, "error_code": code,
                "request_count": 1}
    async def sleep(seconds):
        delays.append(seconds)
    monkeypatch.setattr(synthesis, "run_adapter", fail)
    monkeypatch.setattr(synthesis.asyncio, "sleep", sleep)
    attempts = []
    with pytest.raises(RuntimeError, match="Pi operation failed"):
        asyncio.run(synthesis._model_round(None, provider, ["not-executed"], "offline", tmp_path, attempts))
    assert journals == [f"turn-{index + 1}.jsonl" for index in range(expected_attempts)]
    assert len(attempts) == expected_attempts
    assert delays == [delay] * (expected_attempts - 1)
    assert all(attempt["remote_settled"] is settled for attempt in attempts)


def test_exact_candidate_must_have_been_evaluated(tmp_path, monkeypatch):
    context = prepare_context(make_dataset(tmp_path / "dataset"), run_dir=tmp_path / "runs")
    provider = ProviderConfig(api_key="offline-only", base_url="https://example.invalid/v1", model="offline")
    monkeypatch.setattr(synthesis, "adapter_command", lambda _: ["not-executed"])
    async def model(current, *args):
        return terminal(current, proposal(current, predicate="rax < 0"), ["rax <= 0"])
    monkeypatch.setattr(synthesis, "_model_round", model)
    with pytest.raises(ValueError, match="exact predicate"):
        asyncio.run(synthesis.synthesize_context(context, provider, max_rounds=1))
    result = json.loads((context.run_dir / "run.json").read_text())
    assert result["status"] == "infrastructure_error"
    assert result["error_type"] == "ValueError"
    assert result["rounds"][0]["status"] == "parse_rejected"
    assert "exact predicate" in result["rounds"][0]["reason"]
    assert not (tmp_path / "runs" / "candidates").exists()
    assert result["verified"] is False


def test_parser_feedback_does_not_mask_real_build_failure(tmp_path, monkeypatch):
    context = prepare_context(make_dataset(tmp_path / "dataset"), run_dir=tmp_path / "runs")
    provider = ProviderConfig(api_key="offline-only", base_url="https://example.invalid/v1", model="offline")
    monkeypatch.setattr(synthesis, "adapter_command", lambda _: ["not-executed"])
    prompts = []
    async def model(current, *args):
        prompts.append(current.initial_prompt())
        if len(prompts) == 1:
            return terminal(current, proposal(current, predicate="rax &&"), [])
        latest = json.loads(current._feedback)[-1]
        if len(prompts) == 2:
            assert latest['error']['kind'] == 'parse_rejected'
            assert json.loads(latest['invalid_proposal'])['predicate'] == 'rax &&'
            return terminal(current, proposal(current), ["rax < 0"])
        pytest.fail("a real build failure must stop before another provider round")
    monkeypatch.setattr(synthesis, "_model_round", model)
    # The real builder rejects the fixture's deliberately non-ELF identity bytes
    # before any native tool/target runs; this is an execution failure, not quality.
    with pytest.raises((ValueError, RuntimeError, OSError)):
        asyncio.run(synthesis.synthesize_context(context, provider, max_rounds=3))
    result = json.loads((context.run_dir / "run.json").read_text())
    assert len(prompts) == 2
    assert [r["status"] for r in result["rounds"]] == ["parse_rejected", "build_failed"]
    assert result["rounds"][-1]["proposal"]["predicate"] == "rax < 0"
    assert result["status"] == "infrastructure_error" and result["verified"] is False
    assert result["binradar_verification"] == "not_run"
    assert "evaluation" not in result and "selected_round" not in result


@pytest.mark.parametrize("error,status", [(RuntimeError("intentional benign abort"), "infrastructure_error"),
                                         (asyncio.CancelledError(), "cancelled")])
def test_manual_failure_retains_unverified_run_record(tmp_path, monkeypatch, error, status):
    dataset = make_dataset(tmp_path / "dataset")
    async def abort_build(*args):
        raise error
    monkeypatch.setattr(synthesis, "build_candidate", abort_build)
    with pytest.raises(type(error)):
        synthesis.generate_manual(dataset, "0", output=tmp_path / "runs")
    record = tmp_path / "runs" / "run.json"
    result = json.loads(record.read_text())
    before = record.read_bytes()
    with pytest.raises(FileExistsError):
        synthesis.generate_manual(dataset, "0", output=tmp_path / "runs")
    assert record.read_bytes() == before
    assert result["run_directory"] == str(tmp_path / "runs")
    assert result["status"] == status and result["error_type"] == type(error).__name__
    assert result["verified"] is False and result["binradar_verification"] == "not_run"
    assert "build" not in result and "evaluation" not in result
    assert json.loads(record.with_name("context.json").read_text())["context_id"] == result["context_id"]


@pytest.mark.parametrize('mode', ['manual', 'provider', 'provider_entry'])
@pytest.mark.parametrize('occupied', ['run.json', 'context.json', 'legacy/run.json', 'symlink'])
def test_existing_output_is_rejected_without_execution_or_overwrite(tmp_path, monkeypatch, mode, occupied):
    dataset = make_dataset(tmp_path / 'dataset')
    output = tmp_path / 'result'
    output.mkdir()
    if occupied == 'symlink':
        original = tmp_path / 'original.json'
        original.write_bytes(b'preserve original result')
        marker = output / 'run.json'
        marker.symlink_to(original)
    else:
        marker = output / occupied
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_bytes(b'preserve original result')
    context = prepare_context(dataset, run_dir=output)

    def forbidden(*args, **kwargs):
        pytest.fail('occupied output must fail before execution or provider work')

    monkeypatch.setattr(synthesis, 'adapter_command', lambda _: ['not-executed'])
    monkeypatch.setattr(synthesis, 'build_candidate', forbidden)
    monkeypatch.setattr(synthesis, '_model_round', forbidden)
    monkeypatch.setattr(synthesis, 'poc_observation', forbidden)
    monkeypatch.setattr(synthesis, 'prepare_context', forbidden)
    monkeypatch.setattr(synthesis, 'load_provider', forbidden)
    with pytest.raises(FileExistsError):
        if mode == 'manual':
            synthesis.generate_manual(dataset, '0', output=output)
        elif mode == 'provider_entry':
            synthesis.generate_with_pi(dataset, tmp_path / 'provider.env', output=output)
        else:
            provider = ProviderConfig(api_key='offline-only', base_url='https://example.invalid/v1', model='offline')
            asyncio.run(synthesis.synthesize_context(context, provider))
    assert marker.read_bytes() == b'preserve original result'
    assert not (output / 'trials').exists() and not (output / 'build-workdir').exists()


def test_concurrent_output_claim_has_one_owner_and_preserves_cache(tmp_path):
    context = prepare_context(make_dataset(tmp_path / 'dataset'), run_dir=tmp_path / 'result')
    context.run_dir.chmod(0o755)
    cache = context.run_dir / 'cache'
    cache.mkdir()
    (cache / 'observation').write_bytes(b'preserve cached evidence')

    def claim(owner):
        try:
            synthesis._start_run(context, {'owner': owner})
        except FileExistsError:
            return None
        return owner

    async def race():
        return await asyncio.gather(*(asyncio.to_thread(claim, owner) for owner in range(16)))

    winners = [owner for owner in asyncio.run(race()) if owner is not None]
    assert len(winners) == 1
    record = context.run_dir / 'run.json'
    assert json.loads(record.read_text())['owner'] == winners[0]
    assert context.run_dir.stat().st_mode & 0o777 == 0o700
    assert record.stat().st_mode & 0o777 == 0o600
    assert (cache / 'observation').read_bytes() == b'preserve cached evidence'
    assert {entry.name for entry in context.run_dir.iterdir()} == {'run.json', 'cache'}


def test_cli_stdout_is_one_json_after_native_and_child_diagnostics(tmp_path):
    import subprocess
    import sys
    from pathlib import Path
    from taosc_llm import cli

    code = r'''import os, subprocess, sys
sys.path.insert(0, sys.argv[1])
from taosc_llm.cli import _run

def operation():
    print("python diagnostic")
    os.write(1, b"native diagnostic\n")
    subprocess.run([sys.executable, "-c", "print('child diagnostic')"], check=True)
    return {"status": "prepared", "verified": False}

raise SystemExit(_run("fixture", operation))
'''
    result = subprocess.run([sys.executable, "-I", "-c", code,
                             str(Path(cli.__file__).resolve().parent.parent)],
                            cwd=tmp_path, capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert json.loads(result.stdout) == {"status": "prepared", "verified": False}
    assert set(result.stderr.splitlines()) == {
        "python diagnostic", "native diagnostic", "child diagnostic"}


def test_manual_cli_rejects_provider_round_limit(tmp_path):
    from taosc_llm.cli import main
    with pytest.raises(SystemExit) as error:
        main(["--dataset", str(tmp_path), "--predicate", "0", "--max-rounds", "2"])
    assert error.value.code == 2


def test_blocking_tool_cancellation_waits_for_worker():
    import threading
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    def work():
        started.set()
        release.wait(5)
        finished.set()
    async def scenario():
        task = asyncio.create_task(synthesis._blocking(work))
        await asyncio.to_thread(started.wait, 5)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert finished.is_set()
    asyncio.run(scenario())


@pytest.mark.parametrize("outcome", ["not_rejected", "unavailable", "abstained"])
def test_feedback_follows_final_host_outcome_only(tmp_path, monkeypatch, outcome):
    context = prepare_context(make_dataset(tmp_path / "dataset"), run_dir=tmp_path / "runs")
    provider = ProviderConfig(api_key="offline-only", base_url="https://example.invalid/v1", model="offline")
    monkeypatch.setattr(synthesis, "adapter_command", lambda _: ["not-executed"])
    prompts = []
    settled = []

    async def model(current, provider, command, run_id, journal, *, on_complete):
        # First round is invalid; it must settle/release without a review call.
        first = not settled
        final = (proposal(current, predicate="rax &&") if first
                 else proposal(current, decision="abstain", predicate=None) if outcome == "abstained"
                 else proposal(current))
        response = terminal(current, final, ["rax < 0"])
        prompt = await on_complete(response)
        settled.append(final)
        prompts.append(prompt)
        if prompt is not None:
            assert outcome in prompt
            assert "private-host-path" not in prompt
            assert "raw-provider-secret" not in prompt
            response["session_feedback"] = {"type": "feedback_complete", "final_text": "# Review\nBounded evidence.",
                "remote_settled": True, "model_turns": 1, "tool_calls": 0,
                "request_count": 1, "usage": None}
        return response

    async def build(*args):
        return {"status": "built", "verified": False}

    def evaluate(*args, **kwargs):
        return {"status": outcome, "evaluation_mode": "host", "private_path": "private-host-path",
                "quality": {"status": "improved" if outcome == "not_rejected" else "incomplete",
                            "counts": {}, "reasons": []},
                "report_summary": {"domains": {}}, "cases": [{"case_id": "function:0", "source": "raw-provider-secret",
                    "report": {"case_id": "function:0", "domain": "function",
                               "candidate": {"outcome": "unknown"},
                               "activation": {"status": "unknown"}}}]}

    monkeypatch.setattr(synthesis, "run_adapter", model)
    monkeypatch.setattr(synthesis, "build_candidate", build)
    from taosc_llm import evaluation
    monkeypatch.setattr(evaluation, "evaluate_dataset", evaluate)
    result = asyncio.run(synthesis.synthesize_context(context, provider, max_rounds=2, session_feedback=True))
    assert result["status"] == outcome and result["verified"] is False
    assert prompts[0] is None and prompts[1] is not None
    path = context.run_dir / "session-feedback.md"
    assert path.read_text() == "# Review\nBounded evidence."
    assert path.stat().st_mode & 0o777 == 0o600
    assert "final_text" not in result["session_feedback"]
    assert all("session_feedback" not in attempt for attempt in result["attempts"])


def test_feedback_failure_is_separate_from_abstention(tmp_path, monkeypatch):
    context = prepare_context(make_dataset(tmp_path / "dataset"), run_dir=tmp_path / "runs")
    provider = ProviderConfig(api_key="offline-only", base_url="https://example.invalid/v1", model="offline")
    monkeypatch.setattr(synthesis, "adapter_command", lambda _: ["not-executed"])

    async def model(current, provider, command, run_id, journal, *, on_complete):
        response = terminal(current, proposal(current, decision="abstain", predicate=None), [])
        assert await on_complete(response) is not None
        response["session_feedback"] = {"type": "feedback_failed", "error_code": "timeout",
                                        "remote_settled": False, "request_count": 1}
        return response

    monkeypatch.setattr(synthesis, "run_adapter", model)
    result = asyncio.run(synthesis.synthesize_context(context, provider, session_feedback=True))
    assert result["status"] == "abstained"
    assert result["session_feedback"]["error_code"] == "timeout"
    assert not (context.run_dir / "session-feedback.md").exists()


def test_review_preparation_failure_preserves_frozen_verdict(tmp_path, monkeypatch):
    context = prepare_context(make_dataset(tmp_path / "dataset"), run_dir=tmp_path / "runs")
    provider = ProviderConfig(api_key="offline-only", base_url="https://example.invalid/v1", model="offline")
    monkeypatch.setattr(synthesis, "adapter_command", lambda _: ["not-executed"])

    def fail_review(*args):
        raise ValueError("evidence changed after final host result")

    async def model(current, provider, command, run_id, journal, *, on_complete):
        response = terminal(current, proposal(current, decision="abstain", predicate=None), [])
        assert await on_complete(response) is None
        return response

    monkeypatch.setattr(synthesis, "_review_prompt", fail_review)
    monkeypatch.setattr(synthesis, "run_adapter", model)
    result = asyncio.run(synthesis.synthesize_context(context, provider, session_feedback=True))
    assert result["status"] == "abstained" and result["verified"] is False
    assert result["session_feedback"]["error_code"] == "feedback_preparation_error"
    record = json.loads((context.run_dir / "run.json").read_text())
    assert record["status"] == "abstained"
    assert not (context.run_dir / "session-feedback.md").exists()


def test_manual_cli_rejects_session_feedback_before_preparing(tmp_path):
    from taosc_llm.cli import main
    output = tmp_path / "must-not-exist"
    with pytest.raises(SystemExit) as error:
        main(["--dataset", str(tmp_path), "--predicate", "0", "--session-feedback", "--output", str(output)])
    assert error.value.code == 2 and not output.exists()


def test_provider_preflight_precedes_prompt_and_survives_refinement(tmp_path, monkeypatch):
    context = prepare_context(make_dataset(tmp_path / "dataset"), run_dir=tmp_path / "runs")
    provider = ProviderConfig(api_key="offline-only", base_url="https://example.invalid/v1", model="offline")
    monkeypatch.setattr(synthesis, "adapter_command", lambda _: ["not-executed"])
    original_preflight = synthesis.poc_observation
    preflights = []
    rounds = []
    alias = None

    def preflight(dataset, *, cache_dir, execute):
        assert execute is True and not rounds
        preflights.append((dataset, cache_dir))
        # The fixture has no frozen POC: exercise the real unavailable observation,
        # not invented registers or a fake original/neutral outcome.
        return original_preflight(dataset, cache_dir=cache_dir, execute=False)

    async def model(current, *args):
        nonlocal alias
        assert len(preflights) == 1 and current._poc is not None
        rounds.append(current)
        if len(rounds) == 1:
            alias = current.reference("private-test-evidence")
            return terminal(current, proposal(current, predicate="rax &&"), [])
        assert current.reference("private-test-evidence") == alias
        assert current._poc == rounds[0]._poc
        return terminal(current, proposal(current, decision="abstain", predicate=None), [])

    monkeypatch.setattr(synthesis, "poc_observation", preflight)
    monkeypatch.setattr(synthesis, "_model_round", model)
    result = asyncio.run(synthesis.synthesize_context(context, provider, max_rounds=2))
    assert result["status"] == "abstained" and len(rounds) == 2
    assert preflights[0][1] == context.run_dir / "cache"
    run = context.run_dir
    assert json.loads((run / "poc.json").read_text()) == rounds[0]._poc
    assert json.loads((run / "context.json").read_text())["context_id"] == result["context_id"]
    assert result["context_provenance"] == context.audit
    assert result["run_directory"] == str(run)
    before = (run / 'run.json').read_bytes()
    with pytest.raises(FileExistsError):
        asyncio.run(synthesis.synthesize_context(context, provider))
    assert (run / 'run.json').read_bytes() == before
    assert len(preflights) == 1


def test_manual_mode_does_not_run_provider_preflight(tmp_path, monkeypatch):
    dataset = make_dataset(tmp_path / "dataset")

    def forbidden(*args, **kwargs):
        pytest.fail("manual generation must not run provider POC preflight")

    async def stop(*args):
        raise RuntimeError("stop before native build")

    monkeypatch.setattr(synthesis, "poc_observation", forbidden)
    monkeypatch.setattr(synthesis, "build_candidate", stop)
    with pytest.raises(RuntimeError, match="stop before native build"):
        synthesis.generate_manual(dataset, "0", output=tmp_path / "runs")


def test_refinement_uses_same_minimal_feedback_as_review(tmp_path, monkeypatch):
    context = prepare_context(make_dataset(tmp_path / "dataset"), run_dir=tmp_path / "runs")
    provider = ProviderConfig(api_key="offline-only", base_url="https://example.invalid/v1", model="offline")
    monkeypatch.setattr(synthesis, "adapter_command", lambda _: ["not-executed"])
    evaluated = {"status": "reject_same_crash", "evaluation_mode": "host",
                 "report_summary": {"audit_digest": "private-summary-digest"},
                 "cases": [{"case_id": "function:0", "report": {
                     "case_id": "function:0", "domain": "function",
                     "candidate": {"outcome": "target_crash"},
                     "activation": {"status": "not_fired"}}},
                    {"case_id": "function:1", "report": {
                     "case_id": "function:1", "domain": "function",
                     "candidate": {"outcome": "other_crash"},
                     "activation": {"status": "unknown"}}}]}
    calls = []

    async def model(current, *args):
        calls.append(current)
        if len(calls) == 1:
            return terminal(current, proposal(current), ["rax < 0"])
        feedback = json.loads(current._feedback)[0]
        assert feedback["feedback"]["missed_target_crashes"]["count"] == 1
        retrieved = current.call_tool("get_candidate_result", {
            "context_id": current.context_id, "result_id": feedback["result_id"]})
        assert retrieved["ok"] and retrieved["missed_target_crashes"]["count"] == 1
        assert feedback["result_id"].startswith("r") and len(feedback["result_id"]) < 10
        public = json.dumps(feedback)
        for forbidden in ("report_summary", "private-summary-digest", "case_results"):
            assert forbidden not in public
        return terminal(current, proposal(current, decision="abstain", predicate=None), [])

    async def build(*args):
        return {"status": "built", "verified": False}

    from taosc_llm import evaluation
    monkeypatch.setattr(synthesis, "_model_round", model)
    monkeypatch.setattr(synthesis, "build_candidate", build)
    monkeypatch.setattr(evaluation, "evaluate_dataset", lambda *args, **kwargs: evaluated)
    result = asyncio.run(synthesis.synthesize_context(context, provider, max_rounds=2))
    assert result["status"] == "reject_same_crash" and len(calls) == 2
    assert result["termination"] == "abstained" and result["selected_round"] == 1
    assert result["evaluation"] == evaluated
    # Full evaluator evidence remains in the private run, not the next model prompt.
    assert result["rounds"][0]["evaluation"] == evaluated


def quality_round(*, repaired=(), normals=(), branches=(), misses=(), missing=(), others=(), gaps=(),
                  predicate="rax < 0"):
    """Private classifier outputs at the refinement boundary, not fake captures."""
    rows = []
    for ids, facet in ((repaired, "improved"), (normals, "preserved_normal"),
                       (branches, "branch_regressions"), (misses, "target_misses"),
                       (missing, "unavailable"), (others, "other_crashes"), (gaps, "baseline_gaps")):
        for identifier in ids:
            normal = facet in ("preserved_normal", "branch_regressions")
            rows.append({"case_id": identifier, "report": {"quality": {
                "facets": [facet], "known_normal": normal, "observed_normal": normal, "reasons": []}}})
    from taosc_llm.evidence import summarize_quality
    return {"proposal": {"predicate": predicate},
            "evaluation": {"cases": rows, "quality": summarize_quality(row["report"] for row in rows)}}


@pytest.mark.parametrize("change,accepted,reason", [
    ({"repaired": ("target",), "normals": ("n1",), "branches": ("n2",)}, True, "quality-improved"),
    ({"repaired": (), "normals": ("n1", "n2")}, False, "preservation-failed"),
    ({"repaired": ("target",), "normals": ("n1",), "missing": ("n2",)}, False, "preservation-failed"),
    ({"repaired": ("target",), "normals": ("n1",), "misses": ("n2",)}, False, "preservation-failed"),
    ({"repaired": ("target",), "branches": ("n1", "n2")}, False, "no-quality-improvement"),
])
def test_incumbent_reduces_regressions_without_losing_repairs_or_evidence(change, accepted, reason):
    previous = quality_round(repaired=("target",), branches=("n1", "n2"))
    selected, diagnostic = synthesis._select_candidate(previous, quality_round(**change))
    assert selected is accepted
    assert diagnostic["reason"] == reason
    if change.get("missing"):
        assert diagnostic["lost_normal_evidence"] == {"count": 1, "case_ids": ["n2"]}
    if not change["repaired"]:
        assert diagnostic["lost_improvements"] == {"count": 1, "case_ids": ["target"]}


def test_nonreproducing_normal_branch_regression_cannot_be_hidden():
    previous = quality_round(branches=("mismatch",))
    previous["evaluation"]["cases"][0]["report"]["quality"]["known_normal"] = False
    selected, diagnostic = synthesis._select_candidate(previous, quality_round(missing=("mismatch",)))
    assert selected is False
    assert diagnostic["lost_normal_evidence"]["case_ids"] == ["mismatch"]


def test_other_crash_repair_outweighs_additional_normal_branch_changes():
    previous = quality_round(repaired=("target",), others=("other",), branches=("n1",), normals=("n2",))
    candidate = quality_round(repaired=("target", "other"), branches=("n1", "n2"))
    selected, diagnostic = synthesis._select_candidate(previous, candidate)
    assert selected is True and diagnostic["reason"] == "quality-improved"


def test_fewer_branch_changes_cannot_introduce_an_other_crash():
    previous = quality_round(repaired=("target",), missing=("unknown",), branches=("n1", "n2"))
    candidate = quality_round(repaired=("target",), others=("unknown",), normals=("n1", "n2"))
    selected, diagnostic = synthesis._select_candidate(previous, candidate)
    assert selected is False
    assert diagnostic["new_crash_failures"] == {"count": 1, "case_ids": ["unknown"]}


def test_fewer_branch_changes_cannot_replace_complete_evidence_with_a_gap():
    previous = quality_round(repaired=("target",), branches=("n1",), normals=("n2",))
    candidate = quality_round(repaired=("target",), normals=("n1",), gaps=("n2",))
    selected, diagnostic = synthesis._select_candidate(previous, candidate)
    assert selected is False and diagnostic["reason"] == "preservation-failed"


@pytest.mark.parametrize("candidate,repeated", [
    ({"normals": ("n2",), "branches": ("n1",), "predicate": "rax  < 0"}, True),
    ({"normals": ("n1",), "branches": ("n2",)}, False),
    ({"normals": ("n1", "n2")}, False),
    ({"normals": ("n2",), "branches": ("n1",), "predicate": "rax <= 0"}, False),
    ({"normals": ("n2",), "missing": ("n1",)}, False),
])
def test_stagnation_requires_same_predicate_and_unchanged_case_quality(candidate, repeated):
    previous = quality_round(repaired=("target",), normals=("n2",), branches=("n1",))
    current = quality_round(repaired=("target",), **candidate)
    # Fresh versus cached acquisition is not a change in observed quality.
    previous["evaluation"]["evaluation_mode"] = "host"
    current["evaluation"]["evaluation_mode"] = "offline"
    assert synthesis._repeated_result("ERM generic", previous, current) is repeated


def test_failed_build_breaks_consecutive_evaluated_result_streak():
    evaluated = quality_round(repaired=("target",), branches=("normal",))
    failed = {"proposal": evaluated["proposal"], "status": "build_failed"}
    assert synthesis._repeated_result("ERM generic", evaluated, failed) is False
    assert synthesis._repeated_result("ERM generic", failed, evaluated) is False


@pytest.mark.parametrize("ending,termination,round_count", [
    ("abstain", "abstained", 4),
    ("malformed", "round_limit", 4),
    ("worse", "round_limit", 4),
    ("repeat", "repeated_result", 3),
])
def test_provider_retains_crash_repair_before_minimizing_residual_branches(
        tmp_path, monkeypatch, ending, termination, round_count):
    context = prepare_context(make_dataset(tmp_path / "dataset"), run_dir=tmp_path / "runs")
    provider = ProviderConfig(api_key="offline-only", base_url="https://example.invalid/v1", model="offline")
    monkeypatch.setattr(synthesis, "adapter_command", lambda _: ["not-executed"])
    # Classifier boundary values exercise orchestration, not invented captures.
    initial = quality_round(repaired=("target",), misses=("other",), normals=("n1", "n2"))
    repaired = quality_round(repaired=("target", "other"), branches=("n1", "n2"), predicate="rax <= 0")
    worse = quality_round(repaired=("target",), misses=("other",), normals=("n1", "n2"),
                          predicate="rax < 1")
    predicates = ["rax < 0", "rax <= 0", "rax <= 0" if ending == "repeat" else "rax < 1", "rax < 2"]
    evaluated = [initial["evaluation"], repaired["evaluation"],
                 repaired["evaluation"] if ending == "repeat" else worse["evaluation"], worse["evaluation"]]
    model_calls = []
    build_calls = []

    async def model(current, *args):
        index = len(model_calls)
        model_calls.append(current)
        if index == 3 and ending == "abstain":
            return terminal(current, proposal(current, decision="abstain", predicate=None), [])
        predicate = "rax &&" if index == 3 and ending == "malformed" else predicates[index]
        return terminal(current, proposal(current, predicate=predicate), [predicate])

    async def build(dataset, predicate, directory):
        build_calls.append(predicate)
        return {"status": "built", "verified": False, "predicate": predicate}

    from taosc_llm import evaluation
    monkeypatch.setattr(synthesis, "_model_round", model)
    monkeypatch.setattr(synthesis, "build_candidate", build)
    monkeypatch.setattr(evaluation, "evaluate_dataset", lambda *args, **kwargs: evaluated.pop(0))
    monkeypatch.setattr(synthesis, "predicate_feedback", lambda dataset, value: {"quality": value["quality"]})
    result = asyncio.run(synthesis.synthesize_context(context, provider, max_rounds=4))
    assert result["status"] == "not_rejected" and result["termination"] == termination
    assert result["selected_round"] == 2 and result["proposal"]["predicate"] == "rax <= 0"
    assert result["quality"] == repaired["evaluation"]["quality"]
    assert result["quality"]["status"] == "improved_with_regressions"
    assert result["quality"]["counts"]["improved"] == 2
    assert result["quality"]["counts"]["branch_regressions"] == 2
    assert len(model_calls) == round_count and len(result["rounds"]) == round_count
    assert build_calls == predicates[:3 if ending in ("abstain", "malformed", "repeat") else 4]
    assert result["rounds"][1]["selection"]["accepted"] is True
    if ending != "repeat":
        assert result["rounds"][2]["selection"]["reason"] == "preservation-failed"
    assert result["build"]["predicate"] == "rax <= 0"
    assert result["verified"] is False and result["binradar_verification"] == "not_run"
    assert json.loads((context.run_dir / "run.json").read_text()) == result


@pytest.mark.parametrize("cases,status,quality", [
    ({"repaired": ("target",), "normals": ("normal",)}, "not_rejected", "improved"),
    ({"repaired": ("target",), "branches": ("normal",)}, "not_rejected", "improved_with_regressions"),
    ({"misses": ("target",)}, "rejected", "rejected"),
    ({"others": ("other",)}, "rejected", "rejected"),
    ({"missing": ("target",)}, "unavailable", "incomplete"),
    ({"normals": ("normal",)}, "unavailable", "unproven"),
])
def test_manual_completed_quality_is_reported_without_runtime_error(tmp_path, monkeypatch, cases, status, quality):
    dataset = make_dataset(tmp_path / "dataset")
    evaluated = quality_round(**cases)["evaluation"]

    async def build(*args):
        return {"status": "built", "verified": False}

    from taosc_llm import evaluation
    monkeypatch.setattr(synthesis, "build_candidate", build)
    monkeypatch.setattr(evaluation, "evaluate_dataset", lambda *args, **kwargs: evaluated)
    result = synthesis.generate_manual(dataset, "0", output=tmp_path / "runs")
    assert result["status"] == status and result["quality"]["status"] == quality
    assert result["evaluation"] == evaluated and "error_type" not in result
    assert result["verified"] is False and result["binradar_verification"] == "not_run"
    assert json.loads((tmp_path / "runs" / "run.json").read_text()) == result


@pytest.mark.parametrize("error", [ValueError("integrity failure"), RuntimeError("native build failed"),
                                    OSError("storage failure")])
def test_provider_build_failure_cannot_become_abstention_or_exhaustion(tmp_path, monkeypatch, error):
    context = prepare_context(make_dataset(tmp_path / "dataset"), run_dir=tmp_path / "runs")
    provider = ProviderConfig(api_key="offline-only", base_url="https://example.invalid/v1", model="offline")
    monkeypatch.setattr(synthesis, "adapter_command", lambda _: ["not-executed"])
    calls = []

    async def model(current, *args):
        calls.append(current)
        return terminal(current, proposal(current), ["rax < 0"])

    async def build(*args):
        raise error

    monkeypatch.setattr(synthesis, "_model_round", model)
    monkeypatch.setattr(synthesis, "build_candidate", build)
    with pytest.raises(type(error), match=str(error)):
        asyncio.run(synthesis.synthesize_context(context, provider, max_rounds=4))
    result = json.loads((context.run_dir / "run.json").read_text())
    assert len(calls) == 1 and result["status"] == "infrastructure_error"
    assert result["error_type"] == type(error).__name__
    assert result["rounds"][0]["status"] == "build_failed"
    assert "evaluation" not in result and "quality" not in result
    assert result["verified"] is False and result["binradar_verification"] == "not_run"


@pytest.mark.parametrize("phase", ["provider", "build"])
def test_real_failure_after_repair_is_not_masked_by_retained_incumbent(tmp_path, monkeypatch, phase):
    context = prepare_context(make_dataset(tmp_path / "dataset"), run_dir=tmp_path / "runs")
    provider = ProviderConfig(api_key="offline-only", base_url="https://example.invalid/v1", model="offline")
    monkeypatch.setattr(synthesis, "adapter_command", lambda _: ["not-executed"])
    evaluated = quality_round(repaired=("target",), branches=("normal",))["evaluation"]
    calls = []

    async def model(current, *args):
        calls.append(current)
        if len(calls) == 2 and phase == "provider":
            raise RuntimeError("provider request failed")
        predicate = "rax < 0" if len(calls) == 1 else "rax <= 0"
        return terminal(current, proposal(current, predicate=predicate), [predicate])

    async def build(dataset, predicate, directory):
        if len(calls) == 2:
            raise RuntimeError("native build failed")
        return {"status": "built", "verified": False, "predicate": predicate}

    from taosc_llm import evaluation
    monkeypatch.setattr(synthesis, "_model_round", model)
    monkeypatch.setattr(synthesis, "build_candidate", build)
    monkeypatch.setattr(evaluation, "evaluate_dataset", lambda *args, **kwargs: evaluated)
    monkeypatch.setattr(synthesis, "predicate_feedback", lambda dataset, value: {"quality": value["quality"]})
    with pytest.raises(RuntimeError, match="provider request failed" if phase == "provider" else "native build failed"):
        asyncio.run(synthesis.synthesize_context(context, provider, max_rounds=4))
    result = json.loads((context.run_dir / "run.json").read_text())
    assert result["status"] == "infrastructure_error" and result["error_type"] == "RuntimeError"
    assert len(calls) == 2 and result["selected_round"] == 1
    assert result["quality"]["status"] == "improved_with_regressions"
    assert result["evaluation"] == evaluated and result["build"]["predicate"] == "rax < 0"
    assert result["verified"] is False and result["binradar_verification"] == "not_run"


def test_replay_binding_fails_before_provider_or_original_execution(tmp_path, monkeypatch):
    context = prepare_context(make_dataset(tmp_path / "dataset"), run_dir=tmp_path / "result",
                              replay_socket=tmp_path / "unrelated.sock")
    provider = ProviderConfig(api_key="offline-only", base_url="https://example.invalid/v1", model="offline")
    monkeypatch.setattr(synthesis, "adapter_command", lambda _: ["not-executed"])

    def forbidden(*args, **kwargs):
        pytest.fail("invalid replay binding must fail before provider or target execution")

    monkeypatch.setattr(synthesis, "poc_observation", forbidden)
    monkeypatch.setattr(synthesis, "_model_round", forbidden)
    from taosc_llm.replay import ReplayError
    with pytest.raises(ReplayError):
        asyncio.run(synthesis.synthesize_context(context, provider))
    saved = json.loads((context.run_dir / "run.json").read_text())
    assert saved["status"] == "infrastructure_error" and saved["rounds"] == []




