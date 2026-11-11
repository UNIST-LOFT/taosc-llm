"""Consumer-visible collection of saved reports; no datasets, models or native runs."""
import csv
import hashlib
import io
import json

import pytest

from taosc_llm.collect_results import (
    RunSpec, collect_all, collect_run, discover_runs, main, write_output,
)


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def case(number=0, *, outcome="normal", baseline="target_crash", domain="system",
         capture="complete", original=None, comparison="different"):
    """Small saved-report schema, including authenticated normal-vector controls."""
    identity = f"{domain}:{number}"
    artifact = "a" * 64
    original = baseline if original is None else original
    report = {
        "case_id": identity, "domain": domain,
        "candidate": {"applicable": True, "outcome": outcome,
                      "artifact_sha256": artifact,
                      "capture": {"status": capture, "total_hits": 1}},
        "neutral_baseline": {"applicable": True, "outcome": baseline,
                             "artifact_sha256": artifact, "compatible_control": True,
                             "capture": {"status": "complete", "total_hits": 1}},
        "original_baseline": {"applicable": domain == "system", "outcome": original,
                              "artifact_sha256": "b" * 64,
                              "capture": {"status": "unavailable", "total_hits": None}},
        "oracle": {"domain": domain, "oracle_id": "qasan-main-v2",
                   "evaluation_artifact_sha256": artifact,
                   "target": {"address": "0x4012ed", "source": "qasan-main-v2"}},
        "activation": {"status": "fired", "repair_hits": 1, "trap_hits": 0},
        "branch_comparison": {"status": comparison, "basis": "actual_complete_vectors",
                              "neutral_hits": 1, "candidate_hits": 1,
                              "first_difference": 0, "neutral_branch": 0,
                              "candidate_branch": 1},
        "transition": {"original_paired": domain == "system", "neutral_paired": True},
        "quality": {"category": "other_crash", "facets": ["other_crashes"],
                    "known_normal": False, "observed_normal": False, "reasons": []},
    }
    return {"case_id": identity, "domain": domain, "report": report}


def evaluation(predicate="rax < 0", cases=None):
    return {"predicate": predicate, "descriptor": "c1p13", "status": "not_rejected",
            "verified": False, "cases": [case()] if cases is None else cases,
            "quality": {"status": "rejected"}}


def provider(root, *, selected=1, cases=None, lifecycle="finished", exit_code=0):
    report = evaluation(cases=cases)
    save(root / "result" / "candidates" / str(selected) / "evaluation.json", report)
    save(root / "run.json", {
        "schema_version": 1, "engine": "taosc-llm-run", "mode": "provider",
        "status": lifecycle, "exit_code": exit_code, "verified": False,
        "binradar_verification": "not_run", "result_directory": str(root / "result"),
        "synthesis": {"status": "unavailable", "selected_round": selected,
                      "termination": "round_limit", "quality": {"status": "rejected"},
                      "verified": False, "binradar_verification": "not_run"},
    })
    return root


def manual(root, *, cases=None):
    save(root / "run.json", {"schema_version": 2, "predicate": "rax < 0",
                            "status": "rejected", "verified": False,
                            "binradar_verification": "not_run",
                            "evaluation": evaluation(cases=cases)})
    return root


def collect(root):
    return collect_run(RunSpec(1, "package/subject", root))


def store(root, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode()
    digest = hashlib.sha256(raw).hexdigest()
    path = root / "payloads" / (digest + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return {"path": str(path.relative_to(root)), "sha256": digest}


def event(kind, data, seq=1):
    value = {"seq": seq, "prev": "", "kind": kind, "data": data}
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return {**value, "sha256": hashlib.sha256(raw).hexdigest()}


def no_llm(root, *, runner=False):
    reference = store(root, evaluation(cases=[case(), case(1, baseline="normal")]))
    result = {"schema_version": 1, "engine": "taosc-llm-no-llm", "predicate": "rax < 0",
              "evaluation": reference, "termination": "evaluation-budget-reached",
              "publication_status": "matched", "verified": False,
              "binradar_verification": "not_run",
              # Historical clause evidence need not be loaded to report the
              # saved selected evaluation. It is not used to reselect a patch.
              "clauses": [{"introduction": {"path": "payloads/" + "f" * 64 + ".json",
                                              "sha256": "f" * 64}}]}
    saved = store(root, result)
    if runner:
        save(root.parent / "run.json", {
            "engine": "taosc-llm-run", "mode": "no-llm", "status": "finished",
            "exit_code": 0, "result_directory": str(root),
            "synthesis": {"predicate": "rax < 0", "result_record": str(root / saved["path"]),
                          "publication_status": "matched", "verified": False,
                          "binradar_verification": "not_run"},
        })
    else:
        segments = root / "segments"
        segments.mkdir()
        final = event("result", {"result": saved})
        (segments / "00000001.jsonl").write_text(json.dumps(final) + "\n" + '{"torn":', encoding="utf-8")
        (segments / "00000002.jsonl").write_text(
            json.dumps(event("session_closed", {}, 2)) + "\n", encoding="utf-8")
    return reference


def test_selected_round_not_last_failed_candidate(tmp_path):
    root = provider(tmp_path / "run with spaces", selected=2,
                    cases=[case(outcome="other_crash")])
    save(root / "result" / "candidates" / "3" / "evaluation.json",
         evaluation("rax > 0", [case(outcome="target_crash")]))
    # Neither repeated synthesis report is needed on the compact-summary path.
    (root / "result" / "run.json").write_text("not JSON", encoding="utf-8")
    row = collect(root)
    assert row["collection_error"] is None
    assert row["selected_round"] == 2
    assert row["predicate"] == "rax < 0"
    assert row["target_status"] == "target_absent"
    assert row["target_fixed"] == 1
    assert row["candidate_other_crashes"] == 1
    assert row["legacy_quality"] == "rejected"
    assert row["evaluation_source"].endswith("candidates/2/evaluation.json")


def test_failed_provider_keeps_incumbent_without_outer_pointers(tmp_path):
    root = tmp_path / "failed"
    save(root / "run.json", {"engine": "taosc-llm-run", "mode": "provider",
                             "status": "failed", "exit_code": 1, "error": "provider failed"})
    save(root / "result" / "run.json", {
        "status": "infrastructure_error", "provider": {}, "rounds": [{"status": "build_failed"}],
        "selected_round": 1, "proposal": {"decision": "candidate", "predicate": "rax < 0"},
        "verified": False, "binradar_verification": "not_run"})
    save(root / "result" / "candidates" / "1" / "evaluation.json", evaluation())
    row = collect(root)
    assert row["collection_error"] is None
    assert (row["lifecycle"], row["exit_code"]) == ("failed", 1)
    assert row["run_error"] == "provider failed"
    assert row["target_status"] == "target_absent"
    assert main(["--run-dir", str(root), "--format", "json", "--output", str(tmp_path / "out.json")]) == 0


def test_manual_reports_use_target_only_outcomes_and_separate_branch_metric(tmp_path):
    root = manual(tmp_path / "manual", cases=[
        case(outcome="other_crash"),
        case(1, baseline="other_crash", outcome="other_crash"),
        case(2, baseline="normal"),
        case(3, domain="function", baseline="target_crash", outcome="normal",
             original="unknown", capture="unavailable"),
    ])
    row = collect(root)
    assert row["collection_error"] is None
    assert row["mode"] == "manual"
    assert row["lifecycle"] == "finished"
    assert row["target_status"] == "target_absent"
    assert row["target_fixed"] == 2
    assert row["candidate_other_crashes"] == 2
    assert row["branch_regressions"] == row["branch_comparable"] == 1
    assert row["function_target_fixed"] == 1
    assert row["candidate_capture_incomplete"] == 1
    assert row["legacy_quality"] == "rejected"


@pytest.mark.parametrize("runner", [False, True])
def test_no_llm_saved_references_are_read_only_and_select_final_evaluation(tmp_path, runner):
    root = tmp_path / "journal with spaces"
    journal = root / "result" if runner else root
    reference = no_llm(journal, runner=runner)
    before = {str(path): path.read_bytes() for path in root.rglob("*") if path.is_file()}
    row = collect(root)
    after = {str(path): path.read_bytes() for path in root.rglob("*") if path.is_file()}
    assert after == before
    assert row["collection_error"] is None
    assert row["mode"] == "no-llm"
    assert row["publication_status"] == "matched"
    assert row["verified"] is False
    assert row["binradar_verification"] == "not_run"
    assert row["target_fixed"] == 1
    assert row["target_status"] == "target_absent"
    assert row["branch_regressions"] == row["branch_comparable"] == 1
    assert row["evaluation_source"] == str(journal / reference["path"])
    assert not (journal / ".writer.lock").exists()


def test_no_llm_checksum_failure_is_reported_without_erasing_other_rows(tmp_path):
    bad = tmp_path / "bad"
    reference = no_llm(bad)
    (bad / reference["path"]).write_text("{}", encoding="utf-8")
    good = manual(tmp_path / "good")
    output = tmp_path / "results.json"
    code = main(["--run-dir", str(bad), "--run-dir", str(good),
                 "--format", "json", "--output", str(output)])
    data = json.loads(output.read_text())
    assert code == 1
    assert len(data["rows"]) == 2
    assert "checksum mismatch" in data["rows"][0]["collection_error"]
    assert data["rows"][1]["target_status"] == "target_absent"
    assert data["summary"]["collection_errors"] == 1


@pytest.mark.parametrize("reference", [
    {"path": "../outside.json", "sha256": "a" * 64},
    {"path": "payloads/" + "a" * 64 + ".json", "sha256": "b" * 64},
])
def test_no_llm_escaping_or_mismatched_payload_reference_is_error(tmp_path, reference):
    root = tmp_path / "journal"
    no_llm(root)
    result = {"engine": "taosc-llm-no-llm", "predicate": "rax < 0", "evaluation": reference}
    selected = store(root, result)
    save(root / "run.json", {**result, "result_record": str(root / selected["path"])})
    row = collect(root)
    assert row["collection_status"] == "collection_error"
    assert row["candidate_known"] is None


def test_archived_no_llm_reports_do_not_require_native_capture_files(tmp_path):
    root = tmp_path / "journal"
    raw = b"saved native capture bytes, never parsed by collection"
    digest = hashlib.sha256(raw).hexdigest()
    capture_path = root / "payloads" / (digest + ".brch")
    capture_path.parent.mkdir(parents=True)
    report = evaluation()
    report["cases"][0]["capture"] = {"path": str(capture_path), "sha256": digest}
    reference = store(root, report)
    save(root / "run.json", {"engine": "taosc-llm-no-llm", "predicate": "rax < 0",
                             "evaluation": reference, "termination": "evaluation-budget-reached"})
    row = collect(root)
    assert row["collection_status"] == "collected"
    assert row["target_status"] == "target_absent"
    assert row["target_fixed"] == 1
    assert not capture_path.exists()


def test_discovery_resolves_list_paths_preserves_spaces_and_sorts_numerically(tmp_path, monkeypatch):
    lists = tmp_path / "lists"
    subject = lists / "package with spaces" / "CVE-1"
    work = subject / "workdir"
    for name in ("taosc-llm-out-10", "taosc-llm-out-00002", "taosc-llm-out-1",
                 "taosc-llm-out-11.tmp", "taosc-llm-out-error", "other-20"):
        (work / "out" / name).mkdir(parents=True)
    exp = lists / "exp.list"
    exp.write_text("package with spaces/CVE-1\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    found = discover_runs(exp)
    assert [item.directory.name for item in found] == [
        "taosc-llm-out-1", "taosc-llm-out-00002", "taosc-llm-out-10"]
    assert all(item.subject == "package with spaces/CVE-1" for item in found)
    assert discover_runs(exp, runs="latest")[0].directory.name == "taosc-llm-out-10"


def test_latest_means_latest_run_not_latest_finished(tmp_path):
    subject = tmp_path / "subject"
    provider(subject / "workdir" / "out" / "taosc-llm-out-1")
    latest = provider(subject / "workdir" / "out" / "taosc-llm-out-2",
                      lifecycle="failed", exit_code=1)
    exp = tmp_path / "exp.list"
    exp.write_text("subject\n", encoding="utf-8")
    rows = collect_all(discover_runs(exp, runs="latest"))
    assert len(rows) == 1
    assert rows[0]["run_directory"] == str(latest)
    assert rows[0]["lifecycle"] == "failed"


def test_missing_workdirs_runs_and_single_formats_have_explicit_rows(tmp_path):
    (tmp_path / "empty" / "workdir").mkdir(parents=True)
    single = tmp_path / "single" / "workdir"
    single.mkdir(parents=True)
    (single / "patch-format").write_text("Single CWE-369\n", encoding="utf-8")
    exp = tmp_path / "exp.list"
    exp.write_text("missing\nempty\nsingle\n", encoding="utf-8")
    rows = collect_all(discover_runs(exp))
    assert [row["collection_status"] for row in rows] == ["missing_workdir", "missing_runs", "unsupported"]
    assert rows[0]["collection_error"] and rows[1]["collection_error"]
    assert rows[2]["collection_error"] is None
    assert all(row["target_status"] == "no_candidate" for row in rows)


def test_malformed_missing_selected_and_duplicate_cases_keep_other_runs(tmp_path):
    malformed = tmp_path / "malformed"
    malformed.mkdir()
    (malformed / "run.json").write_text("{", encoding="utf-8")
    missing = provider(tmp_path / "missing")
    (missing / "result" / "candidates" / "1" / "evaluation.json").unlink()
    duplicate = manual(tmp_path / "duplicate", cases=[case(), case()])
    good = manual(tmp_path / "good")
    specs = [RunSpec(i, path.name, path) for i, path in enumerate((malformed, missing, duplicate, good), 1)]
    rows = collect_all(specs)
    assert [row["collection_status"] for row in rows] == ["collection_error"] * 3 + ["collected"]
    assert rows[1]["target_status"] == "not_observed"
    assert "duplicate" in rows[2]["collection_error"]
    assert rows[3]["target_fixed"] == 1


def test_parallel_collection_has_identical_order_and_rows(tmp_path):
    roots = [manual(tmp_path / name, cases=[case(outcome=outcome)]) for name, outcome in (
        ("z", "target_crash"), ("a", "other_crash"), ("m", "normal"))]
    specs = [RunSpec(i, root.name, root) for i, root in enumerate(roots, 1)]
    assert collect_all(specs, jobs=2) == collect_all(specs, jobs=1)


@pytest.mark.parametrize("output_format,delimiter", [("csv", ","), ("tsv", "\t")])
def test_tabular_columns_are_stable_and_quote_special_paths(tmp_path, output_format, delimiter):
    root = manual(tmp_path / 'run "quoted", with spaces')
    row = collect(root)
    stream = io.StringIO()
    write_output(stream, output_format, [row], include_subject_id=False)
    reader = csv.DictReader(io.StringIO(stream.getvalue()), delimiter=delimiter)
    saved = list(reader)
    assert len(saved) == 1
    assert saved[0]["run_directory"] == str(root)
    assert saved[0]["target_status"] == "target_absent"


def test_explicit_output_avoids_default_logs_and_stdout_is_clean(tmp_path, capsys):
    root = manual(tmp_path / "saved")
    output = tmp_path / "explicit.json"
    absent_exp = tmp_path / "unused" / "exp.list"
    args = ["--exp", str(absent_exp), "--run-dir", str(root), "--format", "json"]
    assert main([*args, "--output", str(output)]) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert not (absent_exp.parent / "logs").exists()
    assert main([*args, "--output", "-"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["scope"] == "observed_cohort"
    assert data["summary"]["target_statuses"] == {"target_absent": 1}


def test_default_output_uses_exp_list_directory(tmp_path):
    root = manual(tmp_path / "saved")
    exp = tmp_path / "lists" / "exp.list"
    assert main(["--run-dir", str(root), "--exp", str(exp), "--format", "log"]) == 0
    files = list((exp.parent / "logs").glob("taosc-llm-results-*.log"))
    assert len(files) == 1


def test_mode_filter_keeps_unknown_errors_but_excludes_other_modes(tmp_path):
    one = manual(tmp_path / "manual")
    two = provider(tmp_path / "provider")
    missing = tmp_path / "missing"
    output = tmp_path / "filtered.json"
    assert main(["--run-dir", str(one), "--run-dir", str(two), "--run-dir", str(missing),
                 "--mode", "provider", "--format", "json", "--output", str(output)]) == 1
    rows = json.loads(output.read_text())["rows"]
    assert [row["mode"] for row in rows] == ["provider", "unknown"]


def test_recorded_no_candidate_and_unknown_evidence_are_not_failures(tmp_path):
    abstained = tmp_path / "abstained"
    save(abstained / "run.json", {"provider": {}, "rounds": [], "status": "abstained",
                                  "proposal": {"decision": "abstain"}, "verified": False,
                                  "binradar_verification": "not_run"})
    unknown = manual(tmp_path / "unknown", cases=[case(outcome="unknown")])
    output = tmp_path / "rows.json"
    assert main(["--run-dir", str(abstained), "--run-dir", str(unknown),
                 "--format", "json", "--output", str(output)]) == 0
    rows = json.loads(output.read_text())["rows"]
    assert [row["target_status"] for row in rows] == ["no_candidate", "not_observed"]
    assert rows[0]["candidate_total"] is None


def test_residual_target_is_data_not_collection_failure(tmp_path):
    root = provider(tmp_path / "target-remaining", cases=[case(outcome="target_crash")])
    output = tmp_path / "target.json"
    assert main(["--run-dir", str(root), "--format", "json", "--output", str(output)]) == 0
    row = json.loads(output.read_text())["rows"][0]
    assert row["target_status"] == "target_present"
    assert row["target_remaining"] == 1
    assert row["collection_error"] is None


def test_completed_runner_missing_synthesis_differs_from_intentional_dataset_stop(tmp_path):
    missing = tmp_path / "missing"
    stopped = tmp_path / "dataset-only"
    warmed = tmp_path / "warm-only"
    for root, stop in ((missing, "synthesis"), (stopped, "dataset"), (warmed, "warm")):
        save(root / "run.json", {"engine": "taosc-llm-run", "mode": "provider",
                                 "status": "finished", "exit_code": 0,
                                 "options": {"stop_after": stop}})
    assert collect(missing)["collection_status"] == "collection_error"
    row = collect(stopped)
    assert row["collection_error"] is None
    assert row["target_status"] == "no_candidate"
    assert row["candidate_total"] is None
    warm_row = collect(warmed)
    assert warm_row["collection_error"] is None
    assert warm_row["target_status"] == "no_candidate"


def test_missing_runner_record_keeps_recoverable_candidate_and_reports_lifecycle_gap(tmp_path):
    root = tmp_path / "missing-runner"
    manual(root / "result")
    row = collect(root)
    assert row["collection_status"] == "collection_error"
    assert "runner record not found" in row["collection_error"]
    assert row["lifecycle"] == "unknown"
    assert row["exit_code"] is None
    assert row["target_status"] == "target_absent"


def test_negative_jobs_is_usage_error():
    with pytest.raises(SystemExit) as raised:
        main(["--jobs", "-1"])
    assert raised.value.code == 2
