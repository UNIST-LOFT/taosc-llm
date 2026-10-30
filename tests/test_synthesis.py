"""Refinement failures and exact host checks; no provider, target or fake verdict."""
import asyncio
import json
from types import SimpleNamespace

import pytest

from taosc_llm.context import prepare_context
from taosc_llm.provider import ProviderConfig
from taosc_llm import synthesis
from test_context_tools import make_dataset, proposal


def terminal(context, final, checked):
    return {"type": "turn_complete", "final_text": final, "host_inspected_context": True,
            "host_checked_predicates": checked}


def test_exact_candidate_must_have_been_evaluated(tmp_path, monkeypatch):
    context = prepare_context(make_dataset(tmp_path / "dataset"), run_dir=tmp_path / "runs")
    provider = ProviderConfig(api_key="offline-only", base_url="https://example.invalid/v1", model="offline")
    monkeypatch.setattr(synthesis, "adapter_command", lambda _: ["not-executed"])
    async def model(current, *args):
        return terminal(current, proposal(current, predicate="rax < 0"), ["rax <= 0"])
    monkeypatch.setattr(synthesis, "_model_round", model)
    result = asyncio.run(synthesis.synthesize_context(context, provider, SimpleNamespace(config=provider), max_rounds=1))
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
            return terminal(current, proposal(current, predicate="rax && 1"), [])
        if len(prompts) == 2:
            assert 'rax && 1' in prompts[-1] and 'parse_rejected' in prompts[-1]
            return terminal(current, proposal(current), ["rax < 0"])
        assert 'build_rejected' in prompts[-1] and 'rax < 0' in prompts[-1]
        return terminal(current, proposal(current, decision="abstain", predicate=None), [])
    monkeypatch.setattr(synthesis, "_model_round", model)
    # The real builder rejects the fixture's deliberately non-ELF identity bytes
    # before any native tool/target runs; this is actual build feedback, not a verdict.
    result = asyncio.run(synthesis.synthesize_context(context, provider, SimpleNamespace(config=provider), max_rounds=3))
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
