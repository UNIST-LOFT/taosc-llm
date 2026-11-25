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
    return collect_run(RunSpec("package/subject", root))


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


@pytest.mark.parametrize('mode', ['provider', 'manual'])
def test_historical_trapped_publication_keeps_raw_metrics_but_loses_final_admission(tmp_path, mode):
    trapped = case(outcome='normal')
    trapped['report']['activation'].update(status='trapped', repair_hits=1, trap_hits=1)
    root = (provider(tmp_path / 'run', cases=[trapped]) if mode == 'provider'
            else manual(tmp_path / 'run', cases=[trapped]))
    path = root / 'run.json'
    record = json.loads(path.read_text())
    (record['synthesis'] if mode == 'provider' else record)['publication_status'] = 'published'
    save(path, record)
    original = path.read_bytes()
    row = collect(root)
    assert row['collection_error'] is None
    assert row['final_admission'] == 'rejected-predicate-trap'
    assert row['target_status'] == 'no_candidate'
    assert row['publication_status'] == 'published'
    assert row['candidate_known'] == row['target_fixed'] == row['predicate_traps'] == 1
    assert path.read_bytes() == original


@pytest.mark.parametrize('runner', [False, True])
def test_rejected_provider_proposal_collects_diagnostics_not_a_final_candidate(tmp_path, runner):
    root = tmp_path / 'run'
    result_root = root / 'result' if runner else root
    trapped = case(outcome='unknown', capture='unavailable')
    trapped['report']['candidate']['reason'] = 'predicate-trap'
    result = {'schema_version': 2, 'provider': {}, 'rounds': [], 'status': 'no_candidate',
              'proposal': {'decision': 'candidate', 'predicate': 'rax < 0'},
              'evaluation': evaluation(cases=[trapped])}
    save(result_root / 'run.json', result)
    if runner:
        save(root / 'run.json', {'engine': 'taosc-llm-run', 'mode': 'provider',
                                'status': 'finished', 'exit_code': 0,
                                'result_directory': str(result_root),
                                'synthesis': {'status': 'no_candidate'}})
    row = collect(root)
    assert row['collection_error'] is None
    assert row['lifecycle'] == 'finished'
    assert row['target_status'] == 'no_candidate'
    assert row['final_admission'] == 'rejected-predicate-trap'
    assert row['predicate_traps'] == 1
    assert row['selected_round'] is None
    assert row['publication_status'] is None


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
    specs = [RunSpec(path.name, path) for path in (malformed, missing, duplicate, good)]
    rows = collect_all(specs)
    assert [row["collection_status"] for row in rows] == ["collection_error"] * 3 + ["collected"]
    assert rows[1]["target_status"] == "not_observed"
    assert "duplicate" in rows[2]["collection_error"]
    assert rows[3]["target_fixed"] == 1


def test_parallel_collection_has_identical_order_and_rows(tmp_path):
    roots = [manual(tmp_path / name, cases=[case(outcome=outcome)]) for name, outcome in (
        ("z", "target_crash"), ("a", "other_crash"), ("m", "normal"))]
    specs = [RunSpec(root.name, root) for root in roots]
    assert collect_all(specs, jobs=2) == collect_all(specs, jobs=1)


@pytest.mark.parametrize("output_format,delimiter", [("csv", ","), ("tsv", "\t")])
@pytest.mark.parametrize("verbose", ["full", "compact"])
def test_tabular_columns_are_stable_and_quote_special_paths(tmp_path, output_format, delimiter, verbose):
    root = manual(tmp_path / 'run "quoted", with spaces', cases=[
        case(0, outcome="target_crash"),
        case(1, outcome="target_crash", domain="function"),
        case(2, outcome="target_crash", domain="function"),
        case(3),
    ])
    row = collect(root)
    stream = io.StringIO()
    write_output(stream, output_format, [row], verbose=verbose)
    reader = csv.DictReader(io.StringIO(stream.getvalue()), delimiter=delimiter)
    full = list(reader)
    assert full[0]["subject"] == "package/subject"
    assert "subject_id" not in reader.fieldnames
    assert "subject_id" not in row
    if verbose == "compact":
        assert reader.fieldnames == [
            "subject", "mode", "predicate", "final_admission", "candidate_known", "candidate_normal",
            "system_candidate_target_crashes", "function_candidate_target_crashes",
            "branch_comparable", "branch_regressions",
        ]

    stream = io.StringIO()
    write_output(stream, output_format, [row], include_subject_id=False, verbose=verbose)
    reduced_reader = csv.DictReader(io.StringIO(stream.getvalue()), delimiter=delimiter)
    saved = list(reduced_reader)
    assert reduced_reader.fieldnames == [key for key in reader.fieldnames if key != "subject"]
    assert saved == [{key: value for key, value in full[0].items() if key != "subject"}]
    assert saved[0]["candidate_known"] == "4"
    assert saved[0]["system_candidate_target_crashes"] == "1"
    assert saved[0]["function_candidate_target_crashes"] == "2"
    if verbose == "full":
        assert saved[0]["candidate_target_crashes"] == "3"
        assert saved[0]["run_directory"] == str(root)
        assert saved[0]["target_status"] == "target_present"


@pytest.mark.parametrize("output_format", ["json", "log"])
@pytest.mark.parametrize("verbose", ["full", "compact"])
def test_subject_omission_preserves_results_without_numeric_ids(tmp_path, output_format, verbose):
    row = collect(manual(tmp_path / "saved"))
    full = io.StringIO()
    reduced = io.StringIO()
    write_output(full, output_format, [row], verbose=verbose)
    write_output(reduced, output_format, [row], include_subject_id=False, verbose=verbose)
    if output_format == "json":
        expected = json.loads(full.getvalue())
        assert "subject_id" not in expected["rows"][0]
        assert expected["rows"][0].pop("subject") == "package/subject"
        assert json.loads(reduced.getvalue()) == expected
    else:
        if verbose == "full":
            assert "\npackage/subject / saved\n" in full.getvalue()
            assert "\nsaved\n" in reduced.getvalue()
        else:
            assert "saved" not in full.getvalue()
            assert "  subject: \"package/subject\"" in full.getvalue()
        assert "subject_id:" not in full.getvalue()
        assert "package/subject" not in reduced.getvalue()
        assert "  subject:" not in reduced.getvalue()
        assert full.getvalue().split("\nSummary: ")[1] == reduced.getvalue().split("\nSummary: ")[1]


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


@pytest.mark.parametrize("verbose", ["full", "compact"])
def test_mode_filter_keeps_unknown_errors_but_excludes_other_modes(tmp_path, verbose):
    one = manual(tmp_path / "manual")
    two = provider(tmp_path / "provider")
    missing = tmp_path / "missing"
    output = tmp_path / "filtered.json"
    assert main(["--run-dir", str(one), "--run-dir", str(two), "--run-dir", str(missing),
                 "--mode", "provider", "--format", "json", "--verbose", verbose,
                 "--output", str(output)]) == 1
    rows = json.loads(output.read_text())["rows"]
    assert [row["mode"] for row in rows] == ["provider", "unknown"]


@pytest.mark.parametrize("verbose", ["full", "compact"])
def test_recorded_no_candidate_and_unknown_evidence_are_not_failures(tmp_path, verbose):
    abstained = tmp_path / "abstained"
    save(abstained / "run.json", {"provider": {}, "rounds": [], "status": "abstained",
                                  "proposal": {"decision": "abstain"}, "verified": False,
                                  "binradar_verification": "not_run"})
    unknown = manual(tmp_path / "unknown", cases=[case(outcome="unknown")])
    output = tmp_path / "rows.json"
    assert main(["--run-dir", str(abstained), "--run-dir", str(unknown),
                 "--format", "json", "--verbose", verbose, "--output", str(output)]) == 0
    rows = json.loads(output.read_text())["rows"]
    assert [row["candidate_known"] for row in rows] == [None, 0]
    for domain in ("system", "function"):
        assert [row[f"{domain}_candidate_target_crashes"] for row in rows] == [None, 0]
    if verbose == "full":
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


def selected_single(root):
    root.mkdir(parents=True)
    (root / "fixture.brpatched").write_bytes(b"fixed selected artifact")
    (root / "evaluation.json").write_text('{"status":"accepted","cases":[]}')
    (root / "patch-format").write_text("Single CWE-617")
    def reference(name):
        return {"path": name, "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest()}
    selected = {"schema_version": 1, "kind": "single-first-selection", "status": "selected",
                "selection": "single", "binary": "fixture", "patch_format": "Single CWE-617",
                "patch_location": "0x401000", "patch_destination": "0x401010",
                "evaluation": reference("evaluation.json"), "verified": False,
                "binradar_verification": "not_run"}
    selected["publication"] = {"kind": "single-patch", "status": "published",
                               "artifact": reference("fixture.brpatched"),
                               "verified": False, "binradar_verification": "not_run"}
    save(root / "patch-selection.json", selected)
    return selected


@pytest.mark.parametrize("lifecycle,status,verified,final", [
    ("finished", "verified", True, True), ("finished", "rejected", False, True),
    ("finished", "unavailable", False, True), ("failed", "failed", False, False),
    ("interrupted", "failed", False, False),
])
def test_fixed_single_collection_keeps_publication_separate_from_verification(
        tmp_path, lifecycle, status, verified, final):
    workdir = tmp_path / "selected"
    selected = selected_single(workdir)
    root = tmp_path / "run"
    save(root / "run.json", {"engine": "taosc-llm-run", "mode": "provider",
                            "status": lifecycle, "exit_code": 0 if lifecycle == "finished" else 1,
                            "error": "native failure" if lifecycle != "finished" else None,
                            "patch_selection": selected, "selection_workdir": str(workdir),
                            "publication": selected["publication"], "publication_status": "published",
                            "verified": verified, "binradar_verification": status,
                            "verification": {"status": status, "final_observed": final}})
    row = collect(root)
    assert row["collection_error"] is None
    assert row["mode"] == "single"
    assert row["predicate"] is None and row["publication_status"] == "published"
    assert row["artifact_kind"] == "single-patch" and row["patch_format"] == "Single CWE-617"
    assert row["artifact_path"] == str(workdir / "fixture.brpatched")
    assert row["artifact_sha256"] == selected["publication"]["artifact"]["sha256"]
    assert row["lifecycle"] == lifecycle and row["verified"] is verified
    assert row["binradar_verification"] == row["verification_status"] == status
    assert row["final_observed"] is final and row["final_admission"] == "fixed-artifact"
    assert row["target_status"] == "not_observed" and row["candidate_total"] is None
    assert row["evaluation_source"] == str(workdir / "evaluation.json")


@pytest.mark.parametrize("requested_mode", ["no-llm", "manual", "provider"])
@pytest.mark.parametrize("collected_mode", ["single", "no-llm", "manual", "provider"])
def test_single_runner_cli_filters_actual_artifact_not_requested_synthesis_mode(
        tmp_path, requested_mode, collected_mode):
    workdir = tmp_path / "selected"
    selected = selected_single(workdir)
    root = tmp_path / "run"
    record = {"engine": "taosc-llm-run", "mode": requested_mode,
              "status": "interrupted", "exit_code": 130,
              "patch_selection": selected, "selection_workdir": str(workdir),
              "publication": selected["publication"], "publication_status": "published",
              "verified": False, "binradar_verification": "failed",
              "verification": {"status": "failed", "final_observed": False}}
    save(root / "run.json", record)
    before = (root / "run.json").read_bytes()
    output = tmp_path / "collected.json"
    assert main(["--run-dir", str(root), "--mode", collected_mode,
                 "--format", "json", "--output", str(output)]) == 0
    rows = json.loads(output.read_text())["rows"]
    if collected_mode == "single":
        assert len(rows) == 1
        assert rows[0]["mode"] == "single" and rows[0]["selection"] == "single"
        assert rows[0]["lifecycle"] == "interrupted"
        assert rows[0]["verified"] is False and rows[0]["verification_status"] == "failed"
    else:
        assert rows == []
    assert (root / "run.json").read_bytes() == before


def test_selected_single_without_runner_is_not_an_unsupported_or_verified_run(tmp_path):
    subject_root = tmp_path / "subject"
    workdir = subject_root / "workdir-patch"
    selected_single(workdir)
    exp = tmp_path / "experiment.list"
    exp.write_text("subject\n")
    specs = discover_runs(exp, workdir="workdir-patch")
    assert len(specs) == 1 and specs[0].directory == workdir
    row = collect_all(specs)[0]
    assert row["collection_error"] is None and row["lifecycle"] == "selected"
    assert row["mode"] == "single" and row["publication_status"] == "published"
    assert row["verified"] is False and row["binradar_verification"] == "not_run"
    assert row["final_observed"] is False and row["predicate"] is None
    output = tmp_path / "collected.json"
    assert main(["--exp", str(exp), "--workdir", "workdir-patch", "--mode", "single",
                 "--format", "json", "--output", str(output)]) == 0
    assert json.loads(output.read_text())["rows"] == [row]


@pytest.mark.parametrize("name", ["fixture.brpatched", "evaluation.json"])
def test_collector_detects_changed_selected_single_evidence(tmp_path, name):
    selected_single(tmp_path / "selected")
    (tmp_path / "selected" / name).write_bytes(b"tampered")
    row = collect(tmp_path / "selected")
    assert row["collection_status"] == "collection_error"
    assert "checksum mismatch" in row["collection_error"]
    assert row["predicate"] is None and row["artifact_kind"] == "single-patch"
