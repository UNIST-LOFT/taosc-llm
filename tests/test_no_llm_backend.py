"""Persistent admission budgets cannot be replenished by process interruption."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import threading
from types import SimpleNamespace

import pytest

from taosc_llm import analysis, evaluation, poc
from taosc_llm.family import parse_candidate
from taosc_llm.preparation import prepare_dataset
from test_preparation import mutation_inputs, preparation_inputs

from taosc_llm.no_llm import backend as module
from taosc_llm.no_llm.backend import Backend
from taosc_llm.no_llm.journal import Journal
from taosc_llm.no_llm.model import SearchLimits, SearchStopped


@pytest.mark.parametrize("termination", [
    "observed-goals-met", "no-target-cases", "evidence-unavailable",
    "bounded-search-exhausted", "clause-budget-reached", "wall-time-reached",
    "evaluation-budget-reached", "interrupted",
])
def test_search_cli_completion_preserves_scoped_evidence(tmp_path, monkeypatch, capfd, termination):
    from taosc_llm.no_llm import cli, run
    result = {"termination": termination, "predicate": None, "coverage": "partial",
              "publication_status": "unavailable", "score": {
                  "target_failures": ["system:0"], "branch_regressions": ["system:1"]},
              "verified": False, "binradar_verification": "not_run"}
    monkeypatch.setattr(run, "synthesize", lambda *args, **kwargs: result)
    assert cli.main(["--dataset", str(tmp_path), "--output", str(tmp_path / "result")]) == (
        130 if termination == "interrupted" else 0)
    assert json.loads(capfd.readouterr().out) == result


@pytest.mark.parametrize("mode,status", [
    (mode, status) for mode in ("manual", "provider", "evaluate", "warm")
    for status in (("not_rejected", "reject_same_crash", "reject_predicate_trap", "unavailable")
                   if mode in ("evaluate", "warm") else
                   ("not_rejected", "reject_same_crash", "reject_predicate_trap", "no_candidate",
                    "rejected", "unavailable", "abstained", "refinement_exhausted"))
])
def test_public_cli_completed_results_do_not_encode_quality(tmp_path, monkeypatch, capfd, mode, status):
    from taosc_llm import cli, synthesis
    result = {"status": status, "predicate": None if mode == "warm" else "rax != 0",
              "quality": {"status": "unproven", "counts": {"target_remaining": 1, "other_crash": 1}},
              "verified": False, "binradar_verification": "not_run"}
    operation = lambda *args, **kwargs: result
    arguments = ["--dataset", str(tmp_path)]
    if mode in ("manual", "provider"):
        monkeypatch.setattr(synthesis, "generate_manual" if mode == "manual" else "generate_with_pi", operation)
        arguments += ["--predicate", "rax != 0"] if mode == "manual" else ["--provider-env", str(tmp_path / "provider.env")]
        entrypoint = cli.main
    else:
        monkeypatch.setattr(evaluation, "warm_dataset" if mode == "warm" else "evaluate_dataset", operation)
        arguments += ["--warm"] if mode == "warm" else ["--predicate", "rax != 0"]
        entrypoint = cli.evaluate_main
    assert entrypoint(arguments) == 0
    assert json.loads(capfd.readouterr().out) == result


@pytest.mark.parametrize("mode", ["no-llm", "manual", "provider", "evaluate"])
@pytest.mark.parametrize("error,expected", [
    (ValueError("invalid configuration"), 1), (RuntimeError("provider or build failed"), 1),
    (OSError("storage failed"), 1), (KeyboardInterrupt(), 130),
])
def test_public_cli_operational_failure_is_not_completion(tmp_path, monkeypatch, capfd, mode, error, expected):
    from taosc_llm import cli, synthesis
    from taosc_llm.no_llm import cli as search_cli, run
    def fail(*args, **kwargs):
        raise error
    arguments = ["--dataset", str(tmp_path)]
    if mode == "no-llm":
        monkeypatch.setattr(run, "synthesize", fail)
        entrypoint = search_cli.main
        arguments += ["--output", str(tmp_path / "result")]
    elif mode in ("manual", "provider"):
        monkeypatch.setattr(synthesis, "generate_manual" if mode == "manual" else "generate_with_pi", fail)
        entrypoint = cli.main
        arguments += ["--predicate", "rax != 0"] if mode == "manual" else ["--provider-env", str(tmp_path / "provider.env")]
    else:
        monkeypatch.setattr(evaluation, "evaluate_dataset", fail)
        entrypoint = cli.evaluate_main
        arguments += ["--predicate", "rax != 0"]
    assert entrypoint(arguments) == expected
    assert not capfd.readouterr().out


@pytest.mark.parametrize("status,expected", [("infrastructure_error", 1), ("refining", 1), ("cancelled", 130)])
def test_manual_cli_noncompleted_status_is_not_success(tmp_path, monkeypatch, capfd, status, expected):
    from taosc_llm import cli, synthesis
    result = {"status": status, "verified": False, "binradar_verification": "not_run"}
    monkeypatch.setattr(synthesis, "generate_manual", lambda *args, **kwargs: result)
    assert cli.main(["--dataset", str(tmp_path), "--predicate", "rax != 0"]) == expected
    assert json.loads(capfd.readouterr().out) == result


@pytest.mark.parametrize("entrypoint", ["search", "manual", "evaluate"])
def test_public_cli_invalid_arguments_remain_nonzero(tmp_path, entrypoint):
    from taosc_llm import cli
    from taosc_llm.no_llm import cli as search_cli
    operation = {"search": search_cli.main, "manual": cli.main, "evaluate": cli.evaluate_main}[entrypoint]
    with pytest.raises(SystemExit) as error:
        operation(["--dataset", str(tmp_path), "--unknown-option"])
    assert error.value.code == 2


def test_manual_cli_child_build_failure_is_fatal(tmp_path, monkeypatch, capfd):
    from taosc_llm import cli, synthesis
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(7, ["builder"])
    monkeypatch.setattr(synthesis, "generate_manual", fail)
    assert cli.main(["--dataset", str(tmp_path), "--predicate", "rax != 0"]) == 1
    assert not capfd.readouterr().out


@pytest.mark.parametrize("closed,expected", [(False, 25.0), (True, 5.0)])
def test_resume_charges_unclosed_interval_but_not_clean_downtime(tmp_path, monkeypatch, closed, expected):
    clock = {"wall": 100.0, "monotonic": 50.0}
    monkeypatch.setattr(module.time, "time", lambda: clock["wall"])
    monkeypatch.setattr(module.time, "monotonic", lambda: clock["monotonic"])
    limits = SearchLimits(timeout=20, max_evaluations=2)
    output = tmp_path / "search"
    with Journal(output, {"case": "budget"}) as journal:
        backend = Backend(SimpleNamespace(), journal, limits)
        backend.admit_evaluation()
        clock.update(wall=105.0, monotonic=55.0)
        backend.checkpoint_budget()
        if closed:
            journal.append("session_closed", {})
    clock.update(wall=125.0, monotonic=75.0)
    with Journal(output, {"case": "budget"}, resume=True) as journal:
        resumed = Backend(SimpleNamespace(), journal, limits)
        assert resumed.elapsed == expected
        assert resumed.evaluations == 1
        if closed:
            resumed.admit_evaluation()
            clock["monotonic"] += 15.0
        with pytest.raises(SearchStopped, match="wall-time"):
            resumed.admit_evaluation()
        assert resumed.evaluations == (2 if closed else 1)


@pytest.fixture
def prepared(tmp_path, monkeypatch, request):
    monkeypatch.delenv("TAOSC_LLM_REA", raising=False)
    monkeypatch.setattr(analysis.shutil, "which", lambda _: None)
    monkeypatch.setattr(evaluation, "execution_identity", lambda: {"qemu": "fixture"})
    family = getattr(request, "param", "ERM generic")
    config, work, concrete = preparation_inputs(tmp_path, family)
    mutation = mutation_inputs(tmp_path, work)
    dataset = prepare_dataset(config, work, concrete, mutation, output=tmp_path / "dataset")
    monkeypatch.setattr(poc, "poc_case", lambda _: None)
    return dataset


def offline_result(dataset, directory):
    with dataset.validation() as view:
        return evaluation._evaluate(view, None, "p0", case_ids=["function:2"], workers=1,
                                    execute=False, cache_dir=directory, include_poc=False)


@pytest.mark.parametrize("prepared", ["ERM generic", "ERM CWE-805"], indirect=True)
def test_repeated_captures_are_durable_without_rewriting_source(prepared, tmp_path):
    capture = prepared.case("function:2")["capture"]
    source = deepcopy(capture)
    result = {"cases": [{"capture": deepcopy(capture), "neutral_baseline": {"capture": capture},
                         "offline_reference": deepcopy(capture)} for _ in range(64)]}
    with Journal(tmp_path / "search", {"case": "repeated"}) as journal:
        backend = Backend(prepared, journal, SearchLimits())
        with prepared.validation() as view:
            preserved = backend._preserve(result, view)
        paths = {record[key]["path"] for record in preserved["cases"]
                 for key in ("capture", "offline_reference")}
        assert len(paths) == 1
        path = Path(paths.pop())
        assert path.parent == journal.directory / "payloads"
        assert path.read_bytes() == (prepared.root / capture["path"]).read_bytes()
        assert len(list((journal.directory / "payloads").glob("*.brch"))) == 1
        assert capture == source
        assert result["cases"][0]["capture"]["path"] == source["path"]
        assert preserved["cases"][0]["capture"]["branches"] == source["branches"]


@pytest.mark.parametrize("field,value", [
    ("descriptor", "c1p0"), ("patch_id", 7), ("artifact_sha256", "0" * 64),
    ("branches", [1]), ("sidecar", {"sha256": "0" * 64}),
])
def test_repeated_bytes_do_not_hide_different_capture_metadata(prepared, tmp_path, field, value):
    capture = prepared.case("function:2")["capture"]
    changed = deepcopy(capture)
    if field == "sidecar":
        changed[field].update(value)
    else:
        changed[field] = value
    with Journal(tmp_path / "search", {"case": "metadata"}) as journal:
        backend = Backend(prepared, journal, SearchLimits())
        with prepared.validation() as view:
            with pytest.raises(ValueError):
                backend._preserve({"cases": [{"capture": capture}, {"capture": changed}]}, view)
        assert not any(event["kind"] in ("baseline", "evaluation", "commit") for event in journal.events)


def test_equal_bytes_preserve_distinct_valid_representative_descriptors(prepared, tmp_path):
    capture = prepared.case("function:2")["capture"]
    other = {**capture, "descriptor": parse_candidate(prepared.patch_format, "rax != 0").descriptor}
    with Journal(tmp_path / "search", {"case": "distinct-descriptors"}) as journal:
        backend = Backend(prepared, journal, SearchLimits())
        with prepared.validation() as view:
            preserved = backend._preserve({"captures": [capture, other]}, view)
        first, second = preserved["captures"]
        assert first["path"] == second["path"]
        assert first["descriptor"] == "p0"
        assert second["descriptor"] == other["descriptor"] != first["descriptor"]
        with prepared.validation() as view:
            states = evaluation._snapshots(view, second)
            assert evaluation._vector(first["descriptor"], states, dataset=view) == [0]
            assert evaluation._vector(second["descriptor"], states, dataset=view) == [0]


@pytest.mark.parametrize("operation", ["load", "load_snapshots", "snapshots"])
def test_next_operation_reauthenticates_owned_capture(prepared, tmp_path, operation):
    result = offline_result(prepared, tmp_path / "cache")
    with Journal(tmp_path / "search", {"case": "corruption"}) as journal:
        backend = Backend(prepared, journal, SearchLimits())
        with prepared.validation() as view:
            preserved = backend._preserve(result, view)
        reference = journal.store(preserved)
        load = getattr(backend, operation)
        argument = preserved if operation == "snapshots" else reference
        restored = load(argument)
        if operation == "load":
            assert restored["cases"][0]["capture"]["branches"] == [0]
        else:
            assert restored["function:2"][0].branch == 0
        path = Path(preserved["cases"][0]["capture"]["path"])
        raw = path.read_bytes()
        path.chmod(0o600)
        path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        path.chmod(0o400)
        with pytest.raises(ValueError):
            load(argument)


@pytest.mark.parametrize("mirror", ["representative", "candidate", "observed", "missing", "offline", "length", "divergence"])
@pytest.mark.parametrize("operation", ["load", "load_snapshots", "snapshots"])
def test_all_journal_vector_mirrors_are_checked(prepared, tmp_path, mirror, operation):
    from taosc_llm.no_llm.score import Population

    result = offline_result(prepared, tmp_path / "cache")
    item = result["cases"][0]
    changed_descriptor = parse_candidate(prepared.patch_format, "1").descriptor
    if mirror == "representative":
        item["capture"] = {**item["capture"], "descriptor": changed_descriptor}
    elif mirror == "candidate":
        item["descriptor"] = changed_descriptor
    elif mirror == "observed":
        item["branches"] = [1]
    elif mirror == "missing":
        item["branches"] = None
    elif mirror == "length":
        item["capture"] = {**item["capture"], "branches": [0, 0]}
    elif mirror == "divergence":
        item["first_divergence"] = 0
    else:
        item["offline_branches"] = [1]
    with Journal(tmp_path / "search", {"case": "mirrors"}) as journal:
        backend = Backend(prepared, journal, SearchLimits())
        backend.population = Population({})
        reference = journal.store(result)
        with pytest.raises(ValueError):
            getattr(backend, operation)(result if operation == "snapshots" else reference)


@pytest.mark.parametrize("operation", ["baseline", "evaluate"])
def test_last_reserved_evaluation_can_finish_preservation(prepared, tmp_path, monkeypatch, operation):
    result = offline_result(prepared, tmp_path / "cache")
    monkeypatch.setattr(evaluation, "_evaluate", lambda *args, **kwargs: deepcopy(result))
    limits = SearchLimits(max_evaluations=1)
    with Journal(tmp_path / "search", {"case": "last-reservation"}) as journal:
        backend = Backend(prepared, journal, limits)
        if operation == "baseline":
            saved = backend.baseline()
        else:
            saved, reference = backend.evaluate("0")
            assert next(event["data"]["result"] for event in journal.events
                        if event["kind"] == "evaluation") == reference
        assert saved["cases"][0]["capture"]["complete"] is True
        assert backend.evaluations == 1
        with pytest.raises(SearchStopped, match="evaluation-budget"):
            backend.admit_evaluation()


def test_closed_session_restores_evidence_after_finalization_exceeds_search_timeout(prepared, tmp_path, monkeypatch):
    result = offline_result(prepared, tmp_path / "cache")
    clock = {"now": 0.0}
    monkeypatch.setattr(module.time, "monotonic", lambda: clock["now"])
    limits = SearchLimits(timeout=10, max_evaluations=1)
    output = tmp_path / "search"
    identity = {"case": "finished-over-budget"}
    with Journal(output, identity) as journal:
        backend = Backend(prepared, journal, limits)
        backend.admit_evaluation()
        with prepared.validation() as view:
            preserved = backend._preserve(result, view)
        reference = journal.store(preserved)
        journal.append("baseline", {"result": reference})
        clock["now"] = 11.0
        backend.checkpoint_budget()
        journal.append("session_closed", {})
    cancelled = threading.Event()
    with Journal(output, identity, resume=True) as journal:
        resumed = Backend(prepared, journal, limits, cancelled=cancelled)
        with pytest.raises(SearchStopped, match="wall-time"):
            resumed.load(reference)
        with resumed.restoration():
            assert resumed.baseline() == preserved
            assert resumed.load_snapshots(reference)["function:2"][0].branch == 0
            assert resumed.elapsed == 11.0
            with pytest.raises(SearchStopped, match="wall-time"):
                resumed.admit_evaluation()
        assert resumed.evaluations == 1
        with pytest.raises(SearchStopped, match="wall-time"):
            resumed.snapshots(preserved)
        cancelled.set()
        with resumed.restoration():
            with pytest.raises(SearchStopped, match="interrupted"):
                resumed.load_snapshots(reference)
        cancelled.clear()
        path = Path(preserved["cases"][0]["capture"]["path"])
        path.chmod(0o600)
        path.write_bytes(b"corrupt")
        with resumed.restoration():
            with pytest.raises(ValueError):
                resumed.load(reference)
        assert len([event for event in journal.events if event["kind"] == "baseline"]) == 1
        assert not any(event["kind"] in ("evaluation", "commit") for event in journal.events)


@pytest.mark.parametrize("stop", ["cancel", "wall"])
@pytest.mark.parametrize("operation", ["baseline", "evaluate"])
def test_evaluation_stops_new_execution_admission_after_budget(prepared, tmp_path, monkeypatch, stop, operation):
    clock = {"now": 0.0}
    monkeypatch.setattr(module.time, "monotonic", lambda: clock["now"])
    cancelled = threading.Event()
    executed = []
    capture = prepared.case("function:2")["capture"]

    def run(dataset, case, descriptor, directory):
        executed.append((case["id"], descriptor))
        if stop == "cancel":
            cancelled.set()
        else:
            clock["now"] = 10.0
        return {**capture, "path": str(prepared.root / capture["path"])}

    monkeypatch.setattr(evaluation, "execute_capture", run)
    with Journal(tmp_path / "search", {"case": "admission-cutoff"}) as journal:
        backend = Backend(prepared, journal, SearchLimits(timeout=10, max_evaluations=1), cancelled=cancelled)
        with pytest.raises(SearchStopped, match="interrupted" if stop == "cancel" else "wall-time"):
            backend.baseline() if operation == "baseline" else backend.evaluate("rax == 0")
        assert executed == [("system:0", "p0")]
        assert backend.evaluations == 1
        assert backend.baseline_ref is None and not backend.result_refs
        assert not any(event["kind"] in ("baseline", "evaluation", "commit") for event in journal.events)


@pytest.mark.parametrize("stop", ["cancel", "wall"])
@pytest.mark.parametrize("operation", ["baseline", "evaluate"])
def test_preservation_interruption_never_publishes_evaluation(prepared, tmp_path, monkeypatch, stop, operation):
    result = offline_result(prepared, tmp_path / "cache")
    monkeypatch.setattr(evaluation, "_evaluate", lambda *args, **kwargs: deepcopy(result))
    clock = {"now": 0.0}
    monkeypatch.setattr(module.time, "monotonic", lambda: clock["now"])
    cancelled = threading.Event()
    with Journal(tmp_path / "search", {"case": "stop-publication"}) as journal:
        backend = Backend(prepared, journal, SearchLimits(timeout=10, max_evaluations=1), cancelled=cancelled)
        store = journal.store_bytes

        def interrupt_after_durable_capture(data, suffix=".bin"):
            reference = store(data, suffix=suffix)
            if suffix == ".brch":
                if stop == "cancel":
                    cancelled.set()
                else:
                    clock["now"] = 10.0
            return reference

        monkeypatch.setattr(journal, "store_bytes", interrupt_after_durable_capture)
        with pytest.raises(SearchStopped, match="interrupted" if stop == "cancel" else "wall-time"):
            backend.baseline() if operation == "baseline" else backend.evaluate("0")
        assert backend.evaluations == 1
        assert backend.baseline_ref is None
        assert not backend.result_refs
        assert not any(event["kind"] in ("baseline", "evaluation", "commit") for event in journal.events)
        assert len(list((journal.directory / "payloads").glob("*.brch"))) == 1


@pytest.mark.parametrize("old_policy", [None, "allow-predicate-traps-v0"])
def test_session_identity_explicitly_rejects_older_final_admission_policy(prepared, tmp_path, monkeypatch, old_policy):
    from taosc_llm.no_llm.journal import JournalError

    monkeypatch.setattr(module, "execution_identity", lambda: {"qemu": "fixture"})
    identity = module.session_identity(prepared, SearchLimits(), workers=1, replay_socket=None)
    assert identity["final_admission_policy"] == "reject-known-predicate-traps-v1"
    old = deepcopy(identity)
    if old_policy is None:
        old.pop("final_admission_policy")
    else:
        old["final_admission_policy"] = old_policy
    output = tmp_path / "search"
    with Journal(output, old) as journal:
        journal.append("publication", {"publication_status": "published", "predicate": "1"})
    previous = {path: path.read_bytes() for path in output.rglob("*") if path.is_file()}
    with pytest.raises(JournalError, match="final admission policy changed; start a fresh output"):
        with Journal(output, identity, resume=True):
            pytest.fail("old-policy publication must not restore")
    assert all(path.read_bytes() == content for path, content in previous.items())


@pytest.mark.parametrize("reuse", [False, True])
@pytest.mark.parametrize("identity_mismatch", [False, True])
def test_run_authenticates_selected_evaluation_before_publication_or_reuse(tmp_path, monkeypatch, reuse, identity_mismatch):
    from contextlib import nullcontext
    from taosc_llm.no_llm import run

    dataset = SimpleNamespace(dataset_id="run-fixture")
    parsed = parse_candidate("ERM generic", "rax != 0")
    selected = {"dataset_id": dataset.dataset_id, "predicate": parsed.expression,
                "descriptor": parsed.descriptor, "cases": []}
    if identity_mismatch:
        selected["dataset_id"] = "different-dataset"
    result = {"predicate": parsed.expression, "evaluation": None,
              "termination": "bounded-search-exhausted", "score": {}}
    calls = []

    class StoredBackend:
        elapsed = evaluations = 0

        def __init__(self, dataset, journal, limits, **kwargs):
            self.journal = journal
            result["evaluation"] = journal.store(selected)
            if reuse:
                publication = journal.store({"candidate": {"status": "published"}})
                journal.append("publication", {"predicate": parsed.expression, "record": publication})

        def restoration(self):
            return nullcontext()

        def load(self, reference):
            calls.append("load")
            return self.journal.load(reference)

        def check_cancelled(self):
            pass

        def checkpoint_budget(self):
            pass

    def publish(dataset, predicate, *, evaluation, check):
        assert evaluation == selected
        calls.append("publish")
        return {"status": "published"}

    def validate(dataset, record, predicate, *, evaluation, check):
        assert evaluation == selected
        calls.append("validate")

    monkeypatch.setattr(run, "session_identity", lambda *args, **kwargs: {"case": "publication-order"})
    monkeypatch.setattr(run, "Backend", StoredBackend)
    monkeypatch.setattr(run, "SearchEngine", lambda backend: SimpleNamespace(run=lambda: deepcopy(result)))
    monkeypatch.setattr(run, "publish_candidate", publish)
    monkeypatch.setattr(run, "validate_publication", validate)
    if identity_mismatch:
        with pytest.raises(ValueError, match="selected evaluation identity mismatch"):
            run.synthesize(dataset, output=tmp_path / "search")
        assert calls == ["load"]
    else:
        actual = run.synthesize(dataset, output=tmp_path / "search")
        assert actual["publication_status"] == "published"
        assert calls == ["load", "validate" if reuse else "publish"]


def test_candidate_scoring_keeps_all_dataset_cases_outside_search_population(prepared, tmp_path, monkeypatch):
    from taosc_llm.no_llm.score import Population

    evaluate = evaluation._evaluate
    calls = []

    def offline(dataset, candidate, descriptor, **kwargs):
        calls.append(kwargs["case_ids"])
        kwargs["execute"] = False
        return evaluate(dataset, candidate, descriptor, **kwargs)

    monkeypatch.setattr(evaluation, "_evaluate", offline)
    with Journal(tmp_path / "search", {"case": "global-support"}) as journal:
        backend = Backend(prepared, journal, SearchLimits())
        backend.population = Population({})
        result, reference = backend.evaluate("0")
        assert {row["case_id"] for row in result["cases"]} == {case["id"] for case in prepared.cases()}
        assert next(event["data"]["result"] for event in journal.events
                    if event["kind"] == "evaluation") == reference
        assert backend.evaluate("0") == (result, reference)
        assert backend.evaluations == 1
        assert calls == [None]


def test_cached_descriptor_cannot_reuse_a_different_saved_evaluation(prepared, tmp_path):
    result = offline_result(prepared, tmp_path / "cache")
    directory = tmp_path / "search"
    identity = {"case": "descriptor-binding"}
    descriptor = parse_candidate(prepared.patch_format, "1").descriptor
    with Journal(directory, identity) as journal:
        reference = journal.store(result)
        journal.append("evaluation", {"descriptor": descriptor, "result": reference})
    with Journal(directory, identity, resume=True) as journal:
        backend = Backend(prepared, journal, SearchLimits())
        with pytest.raises(ValueError, match="journal evaluation identity mismatch"):
            backend.evaluate("1")
        assert backend.evaluations == 0


@pytest.mark.parametrize("corruption", ["dataset", "predicate", "case-descriptor", "report-outcome", "report-comparison"])
def test_saved_evaluation_authenticates_predicate_report_binding(prepared, tmp_path, corruption):
    result = offline_result(prepared, tmp_path / "cache")
    if corruption == "dataset":
        result["dataset_id"] = "different-dataset"
    elif corruption == "predicate":
        result["predicate"] = "1"
    elif corruption == "case-descriptor":
        result["cases"][0]["descriptor"] = parse_candidate(prepared.patch_format, "1").descriptor
    elif corruption == "report-outcome":
        candidate = result["cases"][0]["report"]["candidate"]
        candidate["outcome"] = "normal" if candidate["outcome"] == "target_crash" else "target_crash"
    else:
        result["cases"][0]["report"]["branch_comparison"]["status"] = "different"
    with Journal(tmp_path / "search", {"case": "report-binding", "corruption": corruption}) as journal:
        backend = Backend(prepared, journal, SearchLimits())
        with pytest.raises(ValueError):
            backend.load(journal.store(result))
