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
    result = asyncio.run(synthesis.synthesize_context(context, provider, max_rounds=1))
    assert result["status"] == "refinement_exhausted"
    assert result["rounds"][0]["status"] == "parse_rejected"
    assert "exact predicate" in result["rounds"][0]["reason"]
    assert not (tmp_path / "runs" / result["run_id"] / "candidates").exists()
    assert result["verified"] is False


def test_parser_and_real_build_failure_are_feedback_then_abstention(tmp_path, monkeypatch):
    context = prepare_context(make_dataset(tmp_path / "dataset"), run_dir=tmp_path / "runs")
    provider = ProviderConfig(api_key="offline-only", base_url="https://example.invalid/v1", model="offline")
    monkeypatch.setattr(synthesis, "adapter_command", lambda _: ["not-executed"])
    prompts = []
    async def model(current, *args):
        prompts.append(current.initial_prompt())
        if len(prompts) == 1:
            return terminal(current, proposal(current, predicate="rax &&"), [])
        if len(prompts) == 2:
            assert 'rax &&' in prompts[-1] and 'parse_rejected' in prompts[-1]
            return terminal(current, proposal(current), ["rax < 0"])
        assert 'build_rejected' in prompts[-1] and 'rax < 0' in prompts[-1]
        return terminal(current, proposal(current, decision="abstain", predicate=None), [])
    monkeypatch.setattr(synthesis, "_model_round", model)
    # The real builder rejects the fixture's deliberately non-ELF identity bytes
    # before any native tool/target runs; this is actual build feedback, not a verdict.
    result = asyncio.run(synthesis.synthesize_context(context, provider, max_rounds=3))
    assert [r["status"] for r in result["rounds"]] == ["parse_rejected", "build_rejected", "abstained"]
    assert result["status"] == "abstained" and result["verified"] is False
    assert result["binradar_verification"] == "not_run"


@pytest.mark.parametrize("error,status", [(RuntimeError("intentional benign abort"), "infrastructure_error"),
                                         (asyncio.CancelledError(), "cancelled")])
def test_manual_failure_retains_unverified_run_record(tmp_path, monkeypatch, error, status):
    dataset = make_dataset(tmp_path / "dataset")
    async def abort_build(*args):
        raise error
    monkeypatch.setattr(synthesis, "_build", abort_build)
    with pytest.raises(type(error)):
        synthesis.generate_manual(dataset, "0", output=tmp_path / "runs")
    records = list((tmp_path / "runs").glob("*/run.json"))
    assert len(records) == 1
    result = json.loads(records[0].read_text())
    assert result["status"] == status and result["error_type"] == type(error).__name__
    assert result["verified"] is False and result["binradar_verification"] == "not_run"
    assert "build" not in result and "evaluation" not in result
    assert json.loads(records[0].with_name("context.json").read_text())["context_id"] == result["context_id"]


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


@pytest.mark.parametrize("outcome", ["not_rejected", "unavailable", "abstained", "refinement_exhausted"])
def test_feedback_follows_final_host_outcome_only(tmp_path, monkeypatch, outcome):
    context = prepare_context(make_dataset(tmp_path / "dataset"), run_dir=tmp_path / "runs")
    provider = ProviderConfig(api_key="offline-only", base_url="https://example.invalid/v1", model="offline")
    monkeypatch.setattr(synthesis, "adapter_command", lambda _: ["not-executed"])
    prompts = []
    settled = []

    async def model(current, provider, command, run_id, journal, *, on_complete):
        # First round is invalid; it must settle/release without a review call.
        first = not settled
        final = (proposal(current, predicate="rax &&") if first or outcome == "refinement_exhausted"
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
                "report_summary": {"domains": {}}, "cases": [{"case_id": "function:0", "source": "raw-provider-secret",
                    "report": {"case_id": "function:0", "domain": "function",
                               "candidate": {"outcome": "unknown"}}}]}

    monkeypatch.setattr(synthesis, "run_adapter", model)
    monkeypatch.setattr(synthesis, "_build", build)
    from taosc_llm import evaluation
    monkeypatch.setattr(evaluation, "evaluate_dataset", evaluate)
    result = asyncio.run(synthesis.synthesize_context(context, provider, max_rounds=2, session_feedback=True))
    assert result["status"] == outcome and result["verified"] is False
    assert prompts[0] is None and prompts[1] is not None
    path = context.run_dir / result["run_id"] / "session-feedback.md"
    assert path.read_text() == "# Review\nBounded evidence."
    assert path.stat().st_mode & 0o777 == 0o600
    assert "final_text" not in result["session_feedback"]
    assert all("session_feedback" not in attempt for attempt in result["attempts"])


def test_review_samples_noteworthy_cases_and_identifies_original_tools(tmp_path):
    import hashlib
    context = prepare_context(make_dataset(tmp_path / "dataset", count=12), run_dir=tmp_path / "runs")
    provider = ProviderConfig(api_key="offline-only", base_url="https://example.invalid/v1", model="offline")
    cases = [{"case_id": f"function:{index}", "report": {
        "case_id": f"function:{index}", "domain": "function",
        "candidate": {"outcome": "target_crash" if index == 11 else "unknown"},
        "activation": {"status": "fired" if index == 11 else "unknown"}}}
        for index in range(12)]
    evaluated = {"status": "reject_same_crash", "cases": cases, "report_summary": {"domains": {}}}
    prompt = synthesis._review_prompt(context, {"status": "refinement_exhausted"},
        {"round": 2, "status": "reject_same_crash", "evaluation": evaluated}, provider)
    payload = json.loads(prompt.split("Final host result:\n", 1)[1])
    assert payload["reports"][0]["case_id"] == "function:11"
    assert payload["reports"][0]["why_selected"] == "target_crash:fired"
    assert len(payload["reports"]) == 8 and payload["reports_omitted"] == 4
    assert payload["host_run_status"] == "refinement_exhausted"
    assert payload["evaluation_engine_status"] == "reject_same_crash"
    definitions = context.tool_definitions()
    assert payload["original_synthesis_tools"] == {
        "names": [tool["name"] for tool in definitions],
        "schema_sha256": hashlib.sha256(synthesis.canonical(definitions)).hexdigest()}
    assert synthesis._noteworthy_reports(context, evaluated) == payload["reports"]


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
    assert not (context.run_dir / result["run_id"] / "session-feedback.md").exists()


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
    record = json.loads((context.run_dir / result["run_id"] / "run.json").read_text())
    assert record["status"] == "abstained"
    assert not (context.run_dir / result["run_id"] / "session-feedback.md").exists()


def test_manual_cli_rejects_session_feedback_before_preparing(tmp_path):
    from taosc_llm.cli import main
    output = tmp_path / "must-not-exist"
    with pytest.raises(SystemExit) as error:
        main(["--dataset", str(tmp_path), "--predicate", "0", "--session-feedback", "--output", str(output)])
    assert error.value.code == 2 and not output.exists()


