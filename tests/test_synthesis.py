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
        pytest.fail("a real publication failure must stop before another provider round")
    monkeypatch.setattr(synthesis, "_model_round", model)
    # A changed frozen runtime must remain fatal after recoverable parser feedback.
    original_publish = synthesis.publish_candidate
    def tampered(dataset, predicate):
        dataset.artifact('fixture.brcached').write_bytes(b'changed runtime')
        return original_publish(dataset, predicate)
    monkeypatch.setattr(synthesis, 'publish_candidate', tampered)
    with pytest.raises((ValueError, RuntimeError, OSError)):
        asyncio.run(synthesis.synthesize_context(context, provider, max_rounds=3))
    result = json.loads((context.run_dir / "run.json").read_text())
    assert len(prompts) == 2
    assert [r["status"] for r in result["rounds"]] == ["parse_rejected", "publication_failed"]
    assert result["rounds"][-1]["proposal"]["predicate"] == "rax < 0"
    assert result["status"] == "infrastructure_error" and result["verified"] is False
    assert result["binradar_verification"] == "not_run"
    assert "evaluation" not in result and "selected_round" not in result


@pytest.mark.parametrize("error,status", [(RuntimeError("intentional benign abort"), "infrastructure_error"),
                                         (asyncio.CancelledError(), "cancelled")])
def test_manual_failure_retains_unverified_run_record(tmp_path, monkeypatch, error, status):
    dataset = make_dataset(tmp_path / "dataset")
    def abort_build(*args):
        raise error
    monkeypatch.setattr(synthesis, "publish_candidate", abort_build)
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
    assert "candidate" not in result and "evaluation" not in result
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
    monkeypatch.setattr(synthesis, 'publish_candidate', forbidden)
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
    assert not (output / 'trials').exists() and not (output / 'candidate.json').exists()


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
            reviewed = json.loads(prompt[prompt.index('{'):])
            assert reviewed['host_run_status'] == outcome
            if outcome != 'abstained':
                assert reviewed['objective'] == reviewed['feedback']['objective']
                assert reviewed['objective']['candidate_known'] == (outcome == 'not_rejected')
                assert reviewed['objective']['candidate_target_crashes'] == 0
            assert "private-host-path" not in prompt
            assert "raw-provider-secret" not in prompt
            response["session_feedback"] = {"type": "feedback_complete", "final_text": "# Review\nBounded evidence.",
                "remote_settled": True, "model_turns": 1, "tool_calls": 0,
                "request_count": 1, "usage": None}
        return response

    def build(*args):
        return {"status": "published", "verified": False}

    def evaluate(*args, **kwargs):
        return {"status": outcome, "evaluation_mode": "host", "private_path": "private-host-path",
                "quality": {"status": "improved" if outcome == "not_rejected" else "incomplete",
                            "counts": {}, "reasons": []},
                "report_summary": {"domains": {}}, "cases": [{"case_id": "function:0", "source": "raw-provider-secret",
                    "report": {"case_id": "function:0", "domain": "function",
                               "candidate": {"outcome": "normal" if outcome == "not_rejected" else "unknown"},
                               "activation": {"status": "unknown"}}}]}

    monkeypatch.setattr(synthesis, "run_adapter", model)
    monkeypatch.setattr(synthesis, "publish_candidate", build)
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

    def stop(*args):
        raise RuntimeError("stop before publication")

    monkeypatch.setattr(synthesis, "poc_observation", forbidden)
    monkeypatch.setattr(synthesis, "publish_candidate", stop)
    with pytest.raises(RuntimeError, match="stop before publication"):
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

    def build(*args):
        return {"status": "published", "verified": False}

    from taosc_llm import evaluation
    monkeypatch.setattr(synthesis, "_model_round", model)
    monkeypatch.setattr(synthesis, "publish_candidate", build)
    monkeypatch.setattr(evaluation, "evaluate_dataset", lambda *args, **kwargs: evaluated)
    result = asyncio.run(synthesis.synthesize_context(context, provider, max_rounds=2))
    assert result["status"] == "reject_same_crash" and len(calls) == 2
    assert result["termination"] == "abstained" and result["selected_round"] == 1
    assert result["evaluation"] == evaluated
    # Full evaluator evidence remains in the private run, not the next model prompt.
    assert result["rounds"][0]["evaluation"] == evaluated


def quality_round(*, repaired=(), normals=(), branches=(), misses=(), missing=(), others=(), gaps=(),
                  predicate="rax < 0"):
    """Saved report boundary fixtures with actual outcomes, not quality-only scores."""
    from test_collection_metrics import case
    from taosc_llm.evidence import summarize_quality

    rows = []
    for ids, facet in ((repaired, "improved"), (normals, "preserved_normal"),
                       (branches, "branch_regressions"), (misses, "target_misses"),
                       (missing, "unavailable"), (others, "other_crashes"), (gaps, "baseline_gaps")):
        for identifier in ids:
            normal = facet in ("preserved_normal", "branch_regressions")
            row = case(int.from_bytes(identifier.encode(), 'big'),
                       original='normal' if normal else 'target_crash',
                       neutral='normal' if normal else 'target_crash',
                       outcome={'target_misses': 'target_crash', 'unavailable': 'unknown',
                                'other_crashes': 'other_crash'}.get(facet, 'normal'),
                       comparison='different' if facet == 'branch_regressions' else 'equal')
            if facet == 'baseline_gaps':
                row['report']['neutral_baseline']['compatible_control'] = False
            row['report']['quality'] = {
                'category': facet, 'facets': [facet], 'known_normal': normal,
                'observed_normal': normal, 'reasons': []}
            rows.append(row)
    return {"proposal": {"predicate": predicate},
            "evaluation": {"cases": rows, "quality": summarize_quality(row["report"] for row in rows)}}


@pytest.mark.parametrize('change,accepted,reason', [
    ({'repaired': ('target',), 'normals': ('n1',), 'branches': ('n2',)}, True,
     'branch-regressions-reduced'),
    ({'repaired': ('target',), 'normals': ('n1',), 'missing': ('n2',)}, True,
     'branch-regressions-reduced'),
    ({'repaired': ('target',), 'normals': ('n1',), 'misses': ('n2',)}, False,
     'target-crashes-increased'),
    ({'repaired': ('target',), 'branches': ('n1', 'n2')}, False,
     'no-objective-improvement'),
])
def test_selection_compares_target_then_shared_branch_outcomes(change, accepted, reason):
    previous = quality_round(repaired=('target',), branches=('n1', 'n2'))
    selected, comparison = synthesis._select_candidate(previous, quality_round(**change))
    assert selected is accepted and comparison['reason'] == reason


def test_ming_branch_regression_increase_cannot_win_by_losing_other_observations():
    previous = quality_round(repaired=('target',), normals=('n1', 'n2'), others=('f1', 'f2'))
    candidate = quality_round(repaired=('target',), branches=('n1', 'n2'), missing=('f1', 'f2'))
    selected, comparison = synthesis._select_candidate(previous, candidate)
    assert selected is False and comparison['reason'] == 'branch-regressions-increased'
    assert comparison['comparison'] == {
        'shared_known': 3, 'shared_branch_comparable': 2,
        'previous_target_crashes': 0, 'candidate_target_crashes': 0,
        'previous_branch_regressions': 0, 'candidate_branch_regressions': 2}


def test_true_target_repair_outranks_extra_branch_differences_and_other_crashes():
    previous = quality_round(misses=('target',), normals=('n1', 'n2'), repaired=('other',))
    candidate = quality_round(others=('target', 'other'), branches=('n1', 'n2'))
    selected, comparison = synthesis._select_candidate(previous, candidate)
    assert selected is True and comparison['reason'] == 'target-crashes-reduced'
    objective = synthesis.selection_objective(candidate['evaluation'])
    assert synthesis._objective_outcome(objective) == 'not_rejected'
    assert objective['candidate_target_crashes'] == 0 and objective['branch_regressions'] == 2


@pytest.mark.parametrize('remaining', ['missing', 'others', 'repaired'])
def test_gap_or_other_only_changes_do_not_win(remaining):
    previous = quality_round(branches=('n1',), others=('other',))
    candidate = quality_round(**{remaining: ('n1', 'other')})
    selected, comparison = synthesis._select_candidate(previous, candidate)
    assert selected is False and comparison['reason'] == 'no-objective-improvement'


def test_real_branch_improvement_with_unrelated_gaps_and_other_crash_is_not_vetoed():
    previous = quality_round(branches=('n1',), normals=('n2',), repaired=('target',))
    candidate = quality_round(normals=('n1',), missing=('n2',), others=('target',))
    selected, comparison = synthesis._select_candidate(previous, candidate)
    assert selected is True and comparison['reason'] == 'branch-regressions-reduced'
    assert comparison['comparison']['shared_branch_comparable'] == 1


def test_shared_target_repair_is_not_vetoed_by_an_unrelated_observation_gap():
    previous = quality_round(misses=('target',), normals=('unrelated',))
    candidate = quality_round(others=('target',), missing=('unrelated',))
    selected, comparison = synthesis._select_candidate(previous, candidate)
    assert selected is True and comparison['reason'] == 'target-crashes-reduced'
    assert comparison['comparison']['shared_known'] == 1
    assert comparison['comparison']['candidate_target_crashes'] == 0


def test_target_crash_can_move_between_cases_when_shared_target_count_improves():
    previous = quality_round(misses=('t1', 't2'), repaired=('t3',))
    candidate = quality_round(repaired=('t1', 't2'), misses=('t3',))
    selected, comparison = synthesis._select_candidate(previous, candidate)
    assert selected is True and comparison['reason'] == 'target-crashes-reduced'


def test_target_count_drop_from_observation_loss_is_not_improvement():
    previous = quality_round(misses=('target',), branches=('n1',))
    candidate = quality_round(missing=('target', 'n1'))
    selected, comparison = synthesis._select_candidate(previous, candidate)
    assert selected is False and comparison['reason'] == 'no-objective-improvement'


@pytest.mark.parametrize("candidate,repeated", [
    ({"normals": ("n2",), "branches": ("n1",), "predicate": "rax  < 0"}, True),
    ({"normals": ("n1",), "branches": ("n2",)}, False),
    ({"normals": ("n1", "n2")}, False),
    ({"normals": ("n2",), "branches": ("n1",), "predicate": "rax <= 0"}, False),
    ({"normals": ("n2",), "missing": ("n1",)}, False),
])
def test_stagnation_requires_same_predicate_and_unchanged_case_objective(candidate, repeated):
    previous = quality_round(repaired=("target",), normals=("n2",), branches=("n1",))
    current = quality_round(repaired=("target",), **candidate)
    # Fresh versus cached acquisition is not a change in observed quality.
    previous["evaluation"]["evaluation_mode"] = "host"
    current["evaluation"]["evaluation_mode"] = "offline"
    assert synthesis._repeated_result("ERM generic", previous, current) is repeated


def test_failed_build_breaks_consecutive_evaluated_result_streak():
    evaluated = quality_round(repaired=("target",), branches=("normal",))
    failed = {"proposal": evaluated["proposal"], "status": "publication_failed"}
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
        if index:
            update = json.loads(current._feedback)[-1]
            assert update['objective'] == update['feedback']['objective']
            expected = repaired if index >= 2 else initial
            assert update['incumbent']['objective'] == synthesis.selection_objective(expected['evaluation'])
        if index == 3 and ending == "abstain":
            return terminal(current, proposal(current, decision="abstain", predicate=None), [])
        predicate = "rax &&" if index == 3 and ending == "malformed" else predicates[index]
        return terminal(current, proposal(current, predicate=predicate), [predicate])

    def build(dataset, predicate):
        build_calls.append(predicate)
        return {"status": "published", "verified": False, "predicate": predicate}

    from taosc_llm import evaluation
    monkeypatch.setattr(synthesis, "_model_round", model)
    monkeypatch.setattr(synthesis, "publish_candidate", build)
    monkeypatch.setattr(evaluation, "evaluate_dataset", lambda *args, **kwargs: evaluated.pop(0))
    monkeypatch.setattr(synthesis, "predicate_feedback", lambda dataset, value: {
        "objective": synthesis.selection_objective(value)})
    result = asyncio.run(synthesis.synthesize_context(context, provider, max_rounds=4))
    assert result["status"] == "not_rejected" and result["termination"] == termination
    assert result["selected_round"] == 2 and result["proposal"]["predicate"] == "rax <= 0"
    assert result["quality"] == repaired["evaluation"]["quality"]
    assert result['objective'] == result['rounds'][1]['objective'] == synthesis.selection_objective(
        repaired['evaluation'])
    assert result['objective']['candidate_target_crashes'] == 0
    assert result['objective']['branch_regressions'] == 2
    assert result["quality"]["status"] == "improved_with_regressions"
    assert result["quality"]["counts"]["improved"] == 2
    assert result["quality"]["counts"]["branch_regressions"] == 2
    assert len(model_calls) == round_count and len(result["rounds"]) == round_count
    assert build_calls == predicates[:3 if ending in ("abstain", "malformed", "repeat") else 4]
    assert result["rounds"][1]["selection"]["accepted"] is True
    if ending != "repeat":
        assert result["rounds"][2]["selection"]["reason"] == "target-crashes-increased"
    assert result["candidate"]["predicate"] == "rax <= 0"
    assert result["verified"] is False and result["binradar_verification"] == "not_run"
    assert json.loads((context.run_dir / "run.json").read_text()) == result


@pytest.mark.parametrize("cases,status,quality", [
    ({"repaired": ("target",), "normals": ("normal",)}, "not_rejected", "improved"),
    ({"repaired": ("target",), "branches": ("normal",)}, "not_rejected", "improved_with_regressions"),
    ({"misses": ("target",)}, "reject_same_crash", "rejected"),
    ({"others": ("other",)}, "not_rejected", "rejected"),
    ({"missing": ("target",)}, "unavailable", "incomplete"),
    ({"normals": ("normal",)}, "not_rejected", "unproven"),
    ({}, "unavailable", "incomplete"),
])
def test_manual_completed_quality_is_reported_without_runtime_error(tmp_path, monkeypatch, cases, status, quality):
    dataset = make_dataset(tmp_path / "dataset")
    evaluated = quality_round(**cases)["evaluation"]

    def build(*args):
        return {"status": "published", "verified": False}

    from taosc_llm import evaluation
    monkeypatch.setattr(synthesis, "publish_candidate", build)
    monkeypatch.setattr(evaluation, "evaluate_dataset", lambda *args, **kwargs: evaluated)
    result = synthesis.generate_manual(dataset, "0", output=tmp_path / "runs")
    assert result["status"] == status and result["quality"]["status"] == quality
    assert result["evaluation"] == evaluated and "error_type" not in result
    assert result["verified"] is False and result["binradar_verification"] == "not_run"
    assert json.loads((tmp_path / "runs" / "run.json").read_text()) == result


@pytest.mark.parametrize("error", [ValueError("integrity failure"), RuntimeError("publication failed"),
                                    OSError("storage failure")])
def test_provider_build_failure_cannot_become_abstention_or_exhaustion(tmp_path, monkeypatch, error):
    context = prepare_context(make_dataset(tmp_path / "dataset"), run_dir=tmp_path / "runs")
    provider = ProviderConfig(api_key="offline-only", base_url="https://example.invalid/v1", model="offline")
    monkeypatch.setattr(synthesis, "adapter_command", lambda _: ["not-executed"])
    calls = []

    async def model(current, *args):
        calls.append(current)
        return terminal(current, proposal(current), ["rax < 0"])

    def build(*args):
        raise error

    monkeypatch.setattr(synthesis, "_model_round", model)
    monkeypatch.setattr(synthesis, "publish_candidate", build)
    with pytest.raises(type(error), match=str(error)):
        asyncio.run(synthesis.synthesize_context(context, provider, max_rounds=4))
    result = json.loads((context.run_dir / "run.json").read_text())
    assert len(calls) == 1 and result["status"] == "infrastructure_error"
    assert result["error_type"] == type(error).__name__
    assert result["rounds"][0]["status"] == "publication_failed"
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

    def build(dataset, predicate):
        if len(calls) == 2:
            raise RuntimeError("publication failed")
        return {"status": "published", "verified": False, "predicate": predicate}

    from taosc_llm import evaluation
    monkeypatch.setattr(synthesis, "_model_round", model)
    monkeypatch.setattr(synthesis, "publish_candidate", build)
    monkeypatch.setattr(evaluation, "evaluate_dataset", lambda *args, **kwargs: evaluated)
    monkeypatch.setattr(synthesis, "predicate_feedback", lambda dataset, value: {
        "objective": synthesis.selection_objective(value)})
    with pytest.raises(RuntimeError, match="provider request failed" if phase == "provider" else "publication failed"):
        asyncio.run(synthesis.synthesize_context(context, provider, max_rounds=4))
    result = json.loads((context.run_dir / "run.json").read_text())
    assert result["status"] == "infrastructure_error" and result["error_type"] == "RuntimeError"
    assert len(calls) == 2 and result["selected_round"] == 1
    assert result["quality"]["status"] == "improved_with_regressions"
    assert result["evaluation"] == evaluated and result["candidate"]["predicate"] == "rax < 0"
    assert result["verified"] is False and result["binradar_verification"] == "not_run"


@pytest.mark.parametrize('cases,minimum,status', [
    ({}, False, 'unavailable'),
    ({'missing': ('target',)}, False, 'unavailable'),
    ({'others': ('target',)}, True, 'not_rejected'),
    ({'repaired': ('target',), 'missing': ('unrelated',)}, True, 'not_rejected'),
    ({'gaps': ('target',)}, True, 'not_rejected'),
    ({'repaired': ('target',), 'branches': ('normal',)}, False, 'not_rejected'),
    ({'misses': ('target',)}, False, 'reject_same_crash'),
])
def test_provider_stop_uses_known_observed_objective_not_strict_quality(
        tmp_path, monkeypatch, cases, minimum, status):
    context = prepare_context(make_dataset(tmp_path / 'dataset'), run_dir=tmp_path / 'runs')
    provider = ProviderConfig(api_key='offline-only', base_url='https://example.invalid/v1', model='offline')
    evaluated = quality_round(**cases)['evaluation']
    for index, row in enumerate(evaluated['cases']):
        row.update(case_id=f'function:{index}', domain='function')
        row['report'].update(case_id=row['case_id'], domain='function')
        row['report']['original_baseline']['applicable'] = False
    # Even a forged legacy success must not turn missing observations into repair.
    if not evaluated['cases'] or cases.get('missing') and not cases.get('repaired'):
        evaluated['quality']['status'] = 'improved'
    calls = []

    async def model(current, *args):
        calls.append(current)
        if len(calls) == 1:
            return terminal(current, proposal(current), ['rax < 0'])
        return terminal(current, proposal(current, decision='abstain', predicate=None), [])

    def build(*args):
        return {'status': 'published', 'verified': False}

    from taosc_llm import evaluation
    monkeypatch.setattr(synthesis, 'adapter_command', lambda _: ['not-executed'])
    monkeypatch.setattr(synthesis, '_model_round', model)
    monkeypatch.setattr(synthesis, 'publish_candidate', build)
    monkeypatch.setattr(evaluation, 'evaluate_dataset', lambda *args, **kwargs: evaluated)
    result = asyncio.run(synthesis.synthesize_context(context, provider, max_rounds=2))
    assert result['status'] == status
    assert result['termination'] == ('observed_objective_minimum' if minimum else 'abstained')
    assert len(calls) == (1 if minimum else 2)
    assert result['selected_round'] == 1 and result['evaluation'] == evaluated
    assert result['objective'] == result['rounds'][0]['objective'] == synthesis.selection_objective(evaluated)
    assert result['verified'] is False and result['binradar_verification'] == 'not_run'


def test_repeated_result_ignores_other_crash_and_baseline_quality_penalties():
    previous = quality_round(repaired=('target',), branches=('n1',))
    current = quality_round(others=('target',), branches=('n1',), predicate='rax  < 0')
    assert previous['evaluation']['quality'] != current['evaluation']['quality']
    assert synthesis._repeated_result('ERM generic', previous, current) is True
    current['evaluation']['cases'][1]['report']['original_baseline']['outcome'] = 'unknown'
    assert synthesis._repeated_result('ERM generic', previous, current) is True


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




