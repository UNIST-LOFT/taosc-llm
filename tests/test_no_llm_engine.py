"""Finite transition-system checks for search, independent of native execution.

The native/CLI smoke separately proves artifact execution. This oracle models
one patch visit with two disjoint crash intervals and a shared repair handler.
"""
from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace

import pytest

from binradar.binradar_taosc_predicates import CachedSnapshot, evaluate_cached_predicate
from taosc_llm.family import parse_candidate
from taosc_llm.no_llm.engine import SearchEngine
from taosc_llm.no_llm.journal import Journal
from taosc_llm.no_llm.model import SearchLimits, SearchStopped
from taosc_llm.collection_metrics import compare_selection, selection_case_sets, selection_objective


def observed_report(original, outcome, branch):
    return {
        "original_baseline": {"outcome": original, "applicable": True},
        "neutral_baseline": {"outcome": original, "compatible_control": True,
                             "artifact_sha256": "fixture", "capture": {"status": "complete", "total_hits": 1}},
        "candidate": {"outcome": outcome, "artifact_sha256": "fixture", "capture": {"status": "complete"}},
        "oracle": {"evaluation_artifact_sha256": "fixture"},
        "branch_comparison": {"basis": "actual_complete_vectors",
                              "status": "unavailable" if branch == 2 else "different" if branch else "equal"},
        "activation": {"status": "trapped" if branch == 2 else "fired" if branch else "not_fired"}}


class FiniteExecution:
    values = (-2, -1, 0, 1, 2)

    def __init__(self, journal, limits, *, interrupt_at=None):
        self.journal, self.limits = journal, limits
        self.dataset = SimpleNamespace(patch_format="ERM generic", dataset_id="finite-intervals")
        self.baseline_ref = journal.store(self._result("0"))
        self.evaluations = 0
        self.elapsed = 0
        self.interrupt_at = interrupt_at
        self.requests = []
        self.results = {}
        self.restoring = False

    @contextmanager
    def restoration(self):
        previous, self.restoring = self.restoring, True
        try:
            yield
        finally:
            self.restoring = previous

    def _result(self, source):
        candidate = parse_candidate("ERM generic", source)
        rows = []
        for index, value in enumerate(self.values):
            original = "target_crash" if abs(value) == 2 else "normal"
            state = CachedSnapshot(0, 0, (value & ((1 << 64) - 1),) + (0,) * 15)
            branch = evaluate_cached_predicate(candidate.parsed, [state])[0]
            outcome = "normal" if branch == 1 else original
            rows.append({"case_id": f"system:{index}", "domain": "system", "value": value, "branch": branch,
                         "report": observed_report(original, outcome, branch)})
        return {"cases": rows, "predicate": source, "descriptor": candidate.descriptor}

    def baseline(self):
        return self.load(self.baseline_ref)

    def load(self, ref):
        return self.journal.load(ref)

    def evaluate(self, source):
        self.requests.append(source)
        descriptor = parse_candidate("ERM generic", source).descriptor
        if descriptor not in self.results:
            self.check()
            self.evaluations += 1
            if self.evaluations == self.interrupt_at:
                raise KeyboardInterrupt
            self.results[descriptor] = self._result(source)
        return self.results[descriptor]

    def snapshots(self, result):
        return {row["case_id"]: [CachedSnapshot(0, row["branch"],
                (row["value"] & ((1 << 64) - 1),) + (0,) * 15)] for row in result["cases"]}

    def checkpoint_budget(self):
        pass

    def check_operation(self):
        pass

    def check(self):
        if self.evaluations >= self.limits.max_evaluations:
            raise SearchStopped("evaluation-budget-reached")


@pytest.fixture
def finite_grammar(monkeypatch):
    def install(*atoms):
        # Supply a closed vocabulary, including the new boundary proposal
        # source. Parsing, scheduling and whole-expression evaluation stay real;
        # boundary generation has separate case-based tests in test_no_llm_space.
        monkeypatch.setattr("taosc_llm.no_llm.space.atoms", lambda *args, **kwargs: atoms)
        monkeypatch.setattr("taosc_llm.no_llm.space._case_boundaries", lambda *args, **kwargs: ())
    return install


class PartitionExecution(FiniteExecution):
    # rax separates the first partition, rbx the complementary equal-size one.
    # rcx completes the latter with one regression; rdx completes the former
    # with two. The always-repair seed has three regressions.
    cases = (
        ((1, 1, 0, 0), "target_crash", True),
        ((1, 0, 1, 0), "target_crash", True),
        ((0, 1, 0, 1), "target_crash", True),
        ((0, 0, 1, 1), "target_crash", True),
        ((0, 0, 1, 0), "normal", True),
        ((0, 0, 0, 1), "normal", True),
        ((0, 0, 0, 1), "normal", True),
    )

    def __init__(self, journal, limits, *, interrupt_at=None):
        super().__init__(journal, limits, interrupt_at=interrupt_at)
        for event in journal.events:
            if event["kind"] == "finite_budget":
                self.evaluations = event["data"]["evaluations"]
            elif event["kind"] == "finite_evaluation":
                result = journal.load(event["data"]["result"])
                self.results[result["descriptor"]] = result
        self.elapsed = self.evaluations

    def _result(self, source):
        candidate = parse_candidate("ERM generic", source)
        rows = []
        for index, (values, original, repairable) in enumerate(self.cases):
            registers = tuple(value & ((1 << 64) - 1) for value in values) + (0,) * (16 - len(values))
            branch = evaluate_cached_predicate(candidate.parsed, [CachedSnapshot(0, 0, registers)])[0]
            rows.append({"case_id": f"system:{index}", "domain": "system",
                         "registers": list(registers), "branch": branch,
                         "report": observed_report(original, "normal" if branch == 1 and repairable else original, branch)})
        return {"cases": rows, "predicate": source, "descriptor": candidate.descriptor}

    def snapshots(self, result):
        return {row["case_id"]: [CachedSnapshot(0, row["branch"], tuple(row["registers"]))]
                for row in result["cases"]}

    def check_operation(self):
        if not self.restoring and self.interrupt_at is not None and self.evaluations >= self.interrupt_at:
            self.interrupt_at = None
            raise KeyboardInterrupt

    def check(self):
        self.check_operation()
        super().check()

    def evaluate(self, source):
        self.requests.append(source)
        descriptor = parse_candidate("ERM generic", source).descriptor
        if descriptor not in self.results:
            self.check()
            self.evaluations += 1
            self.elapsed = self.evaluations
            self.journal.append("finite_budget", {"evaluations": self.evaluations})
            self.results[descriptor] = self._result(source)
            self.journal.append("finite_evaluation", {"result": self.journal.store(self.results[descriptor])})
        return self.results[descriptor]


class PermanentlyUnrepairedExecution(PartitionExecution):
    cases = (
        ((-2,), "target_crash", True),
        ((-1,), "normal", True),
        ((0,), "normal", True),
        ((1,), "normal", True),
        ((2,), "target_crash", True),
        ((3,), "target_crash", False),
    )


def test_disjoint_crashes_get_separate_immutable_clause_owners(tmp_path):
    limits = SearchLimits(operand_depth=1, max_factors=1, max_atoms=512, beam_width=12)
    with Journal(tmp_path / "search", {"case": "intervals"}) as journal:
        result = SearchEngine(FiniteExecution(journal, limits)).run()
    assert result["termination"] == "observed-goals-met"
    assert result["score"]["branch_regressions"] == []
    assert result["score"]["covered"] == ["system:0", "system:4"]
    assert len(result["clauses"]) == 2
    assert sorted(clause["owners"] for clause in result["clauses"]) == [["system:0"], ["system:4"]]
    assert result["clauses"][1]["prefix"] == [result["clauses"][0]["factors"]]


@pytest.mark.parametrize("max_evaluations", [2, 64])
def test_full_repair_survives_lower_regression_partial_search(tmp_path, max_evaluations):
    # This bounded grammar can isolate the negative target, but cannot express
    # both disjoint intervals without the always-repair seed. The zero-regression
    # partial clause must not replace that proved full repair in the result.
    limits = SearchLimits(max_evaluations=max_evaluations, max_atoms=1,
                          max_factors=1, max_clauses=1, operand_depth=1)
    output = tmp_path / "search"
    identity = {"case": "crash-first", "limit": max_evaluations}
    with Journal(output, identity) as journal:
        backend = FiniteExecution(journal, limits)
        result = SearchEngine(backend).run()
        introductions = [journal.load(event["data"]["state"]) for event in journal.events
                         if event["kind"] == "commit" and event["data"]["operation"] == "introduce"]
        assert any(state["clauses"][0]["owners"] in (["system:0"], ["system:4"])
                   for state in introductions)
        assert result["clauses"][0]["owners"] == ["system:0", "system:4"]
    assert result["score"]["covered"] == ["system:0", "system:4"]
    assert result["score"]["target_failures"] == []
    assert result["score"]["branch_regressions"] == ["system:1", "system:2", "system:3"]
    before = {path: path.read_bytes() for path in (output / "segments").iterdir()}
    with Journal(output, identity, resume=True) as journal:
        backend = FiniteExecution(journal, limits)
        backend.evaluations = limits.max_evaluations
        resumed = SearchEngine(backend).run()
        assert backend.requests == []
        assert resumed["clauses"] == result["clauses"]
        assert resumed["score"] == result["score"]
    assert all(path.read_bytes() == contents for path, contents in before.items())


@pytest.mark.parametrize("max_evaluations", [2, 64])
def test_partial_archive_keeps_higher_coverage_with_permanent_residual(
        tmp_path, finite_grammar, max_evaluations):
    finite_grammar("rax < -1")
    limits = SearchLimits(max_evaluations=max_evaluations, max_clauses=1,
                          max_factors=1, operand_depth=1, beam_width=4)
    output = tmp_path / "search"
    identity = {"case": "partial-crash-first", "budget": max_evaluations}
    with Journal(output, identity) as journal:
        backend = PermanentlyUnrepairedExecution(journal, limits)
        engine = SearchEngine(backend)
        result = engine.run()
        assert result["score"]["covered"] == ["system:0", "system:4"]
        assert result["score"]["branch_regressions"] == ["system:1", "system:2", "system:3"]
        assert result["score"]["unresolved_targets"] == ["system:5"]
        assert result["score"]["target_failures"] == ["system:5"]
        assert result["clauses"][0]["owners"] == ["system:0", "system:4"]
        assert any(state["clauses"] and state["clauses"][0]["owners"] == ["system:0"]
                   for state in (journal.load(event["data"]["state"]) for event in journal.events
                                 if event["kind"] == "commit"))
        requests, spent = list(backend.requests), backend.evaluations
        assert engine.result()["score"] == result["score"]
        assert backend.requests == requests
    prior = {path: path.read_bytes() for path in (output / "segments").iterdir()}
    with Journal(output, identity, resume=True) as journal:
        backend = PermanentlyUnrepairedExecution(journal, limits)
        resumed = SearchEngine(backend).run()
        assert backend.requests == []
        assert backend.evaluations == spent
        assert resumed["clauses"] == result["clauses"]
        assert resumed["score"] == result["score"]
        assert resumed["termination"] == result["termination"]
    assert all(path.read_bytes() == contents for path, contents in prior.items())


@pytest.mark.parametrize("first_branch_can_finish", [False, True])
def test_equal_count_partitions_escape_stuck_or_full_first_decomposition(
        tmp_path, finite_grammar, first_branch_can_finish):
    atoms = ("rax == 1", "rbx == 1", "rcx == 1")
    if first_branch_can_finish:
        atoms += ("rdx == 1",)
    finite_grammar(*atoms)
    limits = SearchLimits(max_evaluations=128, max_clauses=2, max_factors=1,
                          operand_depth=1, beam_width=12)
    with Journal(tmp_path / "search", {"case": "partitions", "full": first_branch_can_finish}) as journal:
        backend = PartitionExecution(journal, limits)
        result = SearchEngine(backend).run()
        states = [journal.load(event["data"]["state"]) for event in journal.events
                  if event["kind"] == "commit"]
        assert any(state["clauses"] and state["clauses"][0]["owners"] == ["system:0", "system:1"]
                   for state in states)
        if first_branch_can_finish:
            assert any(all(row["report"]["candidate"]["outcome"] == "normal"
                           for row in evaluated["cases"][:4])
                       and [row["case_id"] for row in evaluated["cases"][4:] if row["branch"] == 1]
                       == ["system:5", "system:6"]
                       for evaluated in backend.results.values())
        # Actual execution of the initial always-repair expression is a valid
        # but worse answer, not a permanent all-target owner assignment.
        seed = next(value for value in backend.results.values()
                    if all(row["branch"] == 1 for row in value["cases"]))
        assert all(row["report"]["candidate"]["outcome"] == "normal" for row in seed["cases"])
        assert result["score"]["covered"] == ["system:0", "system:1", "system:2", "system:3"]
        assert result["score"]["branch_regressions"] == ["system:4"]
        assert result["score"]["unresolved_targets"] == []
        assert sorted(clause["owners"] for clause in result["clauses"]) == [
            ["system:0", "system:2"], ["system:1", "system:3"]]
        assert result["clauses"][1]["prefix"] == [result["clauses"][0]["factors"]]
        evaluated = backend.load(result["evaluation"])
        assert evaluated["predicate"] == result["predicate"]
        assert result["termination"] in {"bounded-search-exhausted", "evaluation-budget-reached"}


def test_scheduled_partitions_resume_without_rewriting_or_resetting_budget(tmp_path, finite_grammar):
    finite_grammar("rax == 1", "rbx == 1", "rcx == 1", "rdx == 1")
    limits = SearchLimits(max_evaluations=128, max_clauses=2, max_factors=1,
                          operand_depth=1, beam_width=12)
    with Journal(tmp_path / "continuous", {"case": "continuous-partitions"}) as journal:
        uninterrupted = SearchEngine(PartitionExecution(journal, limits)).run()
    output = tmp_path / "interrupted"
    identity = {"case": "resumed-partitions"}
    with Journal(output, identity) as journal:
        backend = PartitionExecution(journal, limits, interrupt_at=3)
        engine = SearchEngine(backend)
        interrupted = engine.run()
        assert interrupted["termination"] == "interrupted"
        assert engine.state["pending"]
        spent = backend.evaluations
    prior = {path: path.read_bytes() for path in (output / "segments").iterdir()}
    with Journal(output, identity, resume=True) as journal:
        backend = PartitionExecution(journal, limits)
        assert backend.evaluations == spent
        restored = SearchEngine(backend)
        assert restored.state["pending"]
        result = restored.run()
        assert result["score"] == uninterrupted["score"]
        assert result["predicate"] == uninterrupted["predicate"]
        assert result["clauses"] == uninterrupted["clauses"]
        assert result["termination"] == uninterrupted["termination"]
        assert result["budgets"]["evaluations"] == uninterrupted["budgets"]["evaluations"]
        assert backend.evaluations >= spent
    assert all(path.read_bytes() == contents for path, contents in prior.items())


def test_archived_result_checkpoint_requires_introduction_proof(tmp_path):
    limits = SearchLimits(max_evaluations=1, operand_depth=1)
    output = tmp_path / "search"
    identity = {"case": "full-repair-proof"}
    with Journal(output, identity) as journal:
        engine = SearchEngine(FiniteExecution(journal, limits))
        engine._start_draft("introduce", "system:0")
        engine._step_draft()
        engine.state["best_result"]["clauses"][0]["owners"] = ["system:0"]
        engine._save()
    with Journal(output, identity, resume=True) as journal:
        with pytest.raises(ValueError, match="introduction does not establish owners"):
            SearchEngine(FiniteExecution(journal, limits))


@pytest.mark.parametrize("location", ["archive", "pending"])
@pytest.mark.parametrize("corruption", ["none", "owners", "witnesses", "evaluation", "predicate", "program"])
def test_resume_authenticates_archive_and_scheduled_branch_proofs(tmp_path, location, corruption):
    limits = SearchLimits(max_evaluations=1, operand_depth=1)
    output = tmp_path / "search"
    identity = {"case": "forged-proof", "location": location, "corruption": corruption}
    with Journal(output, identity) as journal:
        backend = FiniteExecution(journal, limits)
        engine = SearchEngine(backend)
        engine._start_draft("introduce", "system:0")
        engine._step_draft()
        if location == "archive":
            saved = engine.state["best_result"]
        else:
            # This is a genuinely executed introduction with valid immutable
            # proofs, independent of whichever branch is currently scheduled.
            saved = engine._branch()
            saved.update(clauses=deepcopy(engine.state["best_result"]["clauses"]),
                         evaluation=engine.state["best_result"]["evaluation"], draft=None)
            engine.state["pending"].append(saved)
        if corruption == "owners":
            saved["clauses"][0]["owners"] = ["system:1"]
        elif corruption == "witnesses":
            saved["clauses"][0]["witnesses"] = {}
        elif corruption == "evaluation":
            saved["evaluation"] = backend.baseline_ref
        elif corruption == "predicate":
            if location == "archive":
                saved["predicate"] = "rax == 0"
            else:
                saved["clauses"][0]["factors"] = ["rax == 0"]
        elif corruption == "program":
            if location == "archive":
                saved["program"] = [["rax == 0"]]
            else:
                saved["clauses"] = []
        engine._save()
    with Journal(output, identity, resume=True) as journal:
        if corruption == "none":
            restored = SearchEngine(FiniteExecution(journal, limits))
            assert restored.state["best_result"]["clauses"][0]["owners"] == ["system:0", "system:4"]
            if location == "pending":
                assert restored.state["pending"][0]["clauses"][0]["owners"] == ["system:0", "system:4"]
        else:
            with pytest.raises(ValueError):
                SearchEngine(FiniteExecution(journal, limits))


@pytest.mark.parametrize("reason", ["unsupported-external-state", "timeout"])
@pytest.mark.parametrize("target_outcome", ["normal", "other_crash", "unknown"])
def test_ignored_normals_do_not_veto_evaluated_archive_or_resume(tmp_path, reason, target_outcome):
    class IgnoredExecution(FiniteExecution):
        def _result(self, source):
            result = super()._result(source)
            if source != "0":
                for row in result["cases"]:
                    report = row["report"]
                    if report["original_baseline"]["outcome"] == "normal":
                        report["candidate"].update(outcome="unknown", reason=reason, capture={"status": "unavailable"})
                        report["activation"]["status"] = "unknown"
                        report["branch_comparison"]["status"] = "unavailable"
                    else:
                        report["candidate"]["outcome"] = target_outcome
            return result

    limits = SearchLimits(max_evaluations=1, operand_depth=1)
    output = tmp_path / "search"
    identity = {"case": "ignored-archive", "reason": reason, "target": target_outcome}
    with Journal(output, identity) as journal:
        engine = SearchEngine(IgnoredExecution(journal, limits))
        result = engine.run()
        evidence = journal.load(result["evaluation"])
        assert result["predicate"] == evidence["predicate"]
        assert parse_candidate("ERM generic", result["predicate"]).expression == "(1)"
        assert result["objective"] == selection_objective(evidence)
        if target_outcome == "normal":
            assert result["clauses"][0]["owners"] == ["system:0", "system:4"]
        else:
            assert engine.state["clauses"] == []
            assert result["clauses"] == []
            assert result["score"]["covered"] == []
    prior = {path: path.read_bytes() for folder in ("segments", "payloads")
             for path in (output / folder).iterdir()}
    with Journal(output, identity, resume=True) as journal:
        backend = IgnoredExecution(journal, limits)
        backend.evaluations = 1
        restored = SearchEngine(backend)
        resumed = restored.run()
        assert backend.requests == []
        assert resumed["predicate"] == result["predicate"]
        assert resumed["evaluation"] == result["evaluation"]
        assert resumed["clauses"] == result["clauses"]
        assert resumed["objective"] == result["objective"]
    assert all(path.read_bytes() == data for path, data in prior.items())


def test_refinement_retains_real_owners_without_all_normal_evidence(tmp_path):
    atom = "rax * rax >= 4"

    class RefinementExecution(FiniteExecution):
        def _result(self, source):
            result = super()._result(source)
            if atom in source:
                report = result["cases"][1]["report"]
                report["candidate"].update(outcome="unknown", reason="timeout", capture={"status": "unavailable"})
                report["activation"]["status"] = "unknown"
                report["branch_comparison"]["status"] = "unavailable"
            return result

    limits = SearchLimits(operand_depth=1)
    output = tmp_path / "search"
    identity = {"case": "refinement-ignored-normal"}
    with Journal(output, identity) as journal:
        engine = SearchEngine(RefinementExecution(journal, limits))
        engine._start_draft("introduce", "system:0")
        engine._step_draft()
        engine._accept_introduction(engine.state["draft"]["best"])
        engine._start_draft("refine", "system:0", index=0)
        engine.state["draft"]["queue"] = [[atom]]
        engine._step_draft()
        assert engine.state["clauses"][0]["factors"] == [atom]
        assert engine._required() == {"system:0", "system:4"}
        assert engine.state["best_result"]["clauses"][0]["refinement"]
        engine._authenticate_best()
    with Journal(output, identity, resume=True) as journal:
        restored = SearchEngine(RefinementExecution(journal, limits))
        assert restored._required() == {"system:0", "system:4"}
        assert restored.best_score.regressions == set()
        assert restored.best_score.ignored == {"system:1": "timeout"}


def test_unknown_disappearance_does_not_improve_archive(tmp_path):
    limits = SearchLimits(operand_depth=1)
    with Journal(tmp_path / "search", {"case": "unknown-tie"}) as journal:
        backend = FiniteExecution(journal, limits)
        engine = SearchEngine(backend)
        engine._run(((),))
        first = deepcopy(engine.state["best_result"])
        candidate = backend._result("rax != 0")
        candidate["cases"][2]["report"]["candidate"].update(outcome="unknown", capture={"status": "unavailable"})
        candidate["cases"][2]["report"]["activation"]["status"] = "unknown"
        candidate["cases"][2]["report"]["branch_comparison"]["status"] = "unavailable"
        previous = selection_case_sets(engine.best_evaluation)
        after = selection_case_sets(candidate)
        assert compare_selection(previous, after)[0] is False
        score = type(engine.best_score).from_evaluation(engine.population, candidate)
        engine._archive((("rax != 0",),), candidate, score, journal.store(candidate))
        assert engine.state["best_result"] == first


def test_interrupted_search_resumes_without_rewriting_prior_evidence(tmp_path):
    limits = SearchLimits(operand_depth=1, max_factors=1, max_atoms=512)
    output = tmp_path / "search"
    identity = {"case": "resume-intervals"}
    with Journal(output, identity) as journal:
        interrupted = SearchEngine(FiniteExecution(journal, limits, interrupt_at=2)).run()
    assert interrupted["termination"] == "interrupted"
    prior = {path: path.read_bytes() for path in (output / "segments").iterdir()}
    with Journal(output, identity, resume=True) as journal:
        completed = SearchEngine(FiniteExecution(journal, limits)).run()
    assert completed["termination"] == "observed-goals-met"
    assert completed["score"]["branch_regressions"] == []
    assert all(path.read_bytes() == contents for path, contents in prior.items())


def test_resume_retains_uncommitted_capture_revision_and_atom_order(tmp_path):
    limits = SearchLimits(operand_depth=1, max_factors=1, max_atoms=512)
    output = tmp_path / "search"
    identity = {"case": "new-visit-state"}
    with Journal(output, identity) as journal:
        backend = FiniteExecution(journal, limits)
        engine = SearchEngine(backend)
        # A divergent real representative may expose a different later state.
        # It must survive restart even when that proposal never became incumbent.
        backend.values = (-19, -1, 0, 1, 23)
        engine._run((("rax < 0",),))
        engine._save()
        expected = engine.space.predict((("rax == 23",),))
        ordered_atoms = engine.space.atoms
        assert engine.state["clauses"] == []
    with Journal(output, identity, resume=True) as journal:
        restored = SearchEngine(FiniteExecution(journal, limits))
        assert restored.space.predict((("rax == 23",),)) == expected
        assert restored.space.atoms == ordered_atoms
        assert restored.state["clauses"] == []


class NoRepairExecution(FiniteExecution):
    def _result(self, source):
        result = super()._result(source)
        for row in result["cases"]:
            row["report"]["candidate"]["outcome"] = row["report"]["original_baseline"]["outcome"]
        return result


def test_budget_stop_has_no_fabricated_incumbent(tmp_path):
    limits = SearchLimits(max_evaluations=1, operand_depth=1)
    with Journal(tmp_path / "search", {"case": "budget"}) as journal:
        result = SearchEngine(NoRepairExecution(journal, limits)).run()
    assert result["termination"] == "evaluation-budget-reached"
    assert result["predicate"] is not None
    assert result["clauses"] == []
    assert result["score"]["target_failures"] == ["system:0", "system:4"]


class DeadlineExecution(FiniteExecution):
    cancelled = False

    def check_operation(self):
        if self.cancelled:
            raise SearchStopped("interrupted")
        if not self.restoring and self.elapsed >= self.limits.timeout:
            raise SearchStopped("wall-time-reached")

    def check(self):
        self.check_operation()
        super().check()


@pytest.mark.parametrize("boundary", ["wall", "evaluations"])
def test_budget_finalizes_only_proved_best_without_new_execution(tmp_path, boundary):
    limits = SearchLimits(max_evaluations=1, operand_depth=1)
    output = tmp_path / "search"
    identity = {"case": "proved-budget", "boundary": boundary}
    with Journal(output, identity) as journal:
        backend = DeadlineExecution(journal, limits)
        engine = SearchEngine(backend)
        engine._start_draft("introduce", "system:0")
        engine._step_draft()  # actual always-jump repairs, but three regressions
        assert engine.state["draft"]["best"] is not None
        assert engine.state["clauses"] == []
        if boundary == "wall":
            backend.elapsed = limits.timeout
        requests = list(backend.requests)
        result = engine.run()
        assert backend.requests == requests
        assert backend.evaluations == 1
    assert result["termination"] == ("wall-time-reached" if boundary == "wall" else "evaluation-budget-reached")
    assert result["score"]["covered"] == ["system:0", "system:4"]
    assert result["score"]["branch_regressions"] == ["system:1", "system:2", "system:3"]
    assert result["clauses"][0]["owners"] == ["system:0", "system:4"]
    assert result["verified"] is False
    with Journal(output, identity, resume=True) as journal:
        backend = DeadlineExecution(journal, limits)
        with backend.restoration():
            restored = SearchEngine(backend)
        assert restored.result()["clauses"] == result["clauses"]
        assert restored.result()["evaluation"] == result["evaluation"]


def test_cancellation_never_promotes_a_proved_draft(tmp_path):
    limits = SearchLimits(max_evaluations=1, operand_depth=1)
    with Journal(tmp_path / "search", {"case": "cancel-proved"}) as journal:
        backend = DeadlineExecution(journal, limits)
        engine = SearchEngine(backend)
        engine._start_draft("introduce", "system:0")
        engine._step_draft()
        assert engine.state["draft"]["best"] is not None
        backend.cancelled = True
        result = engine.run()
        assert result["termination"] == "interrupted"
        assert result["predicate"] is None
        assert engine.state["draft"]["best"] is not None
        assert not any(event["kind"] == "commit" for event in journal.events)


@pytest.mark.parametrize("corruption", ["owners", "witnesses", "evaluation"])
def test_budget_finalization_reauthenticates_archived_proof(tmp_path, corruption):
    limits = SearchLimits(max_evaluations=1, operand_depth=1)
    with Journal(tmp_path / "search", {"case": "invalid-best", "field": corruption}) as journal:
        backend = DeadlineExecution(journal, limits)
        engine = SearchEngine(backend)
        engine._start_draft("introduce", "system:0")
        engine._step_draft()
        saved = engine.state["best_result"]
        if corruption == "owners":
            saved["clauses"][0]["owners"] = ["system:1"]
        elif corruption == "witnesses":
            saved["clauses"][0]["witnesses"] = {}
        else:
            saved["evaluation"] = backend.baseline_ref
        requests = list(backend.requests)
        with pytest.raises(ValueError):
            engine.run()
        assert backend.requests == requests
        assert engine.state["clauses"] == []
        assert not any(event["kind"] == "commit" for event in journal.events)


def test_resume_finalizes_durable_best_without_execution(tmp_path):
    limits = SearchLimits(max_evaluations=1, operand_depth=1)
    output = tmp_path / "search"
    identity = {"case": "resume-proved-draft"}
    with Journal(output, identity) as journal:
        engine = SearchEngine(DeadlineExecution(journal, limits))
        engine._start_draft("introduce", "system:0")
        engine._step_draft()
        reference = engine.state["draft"]["best"]["evaluation"]
    with Journal(output, identity, resume=True) as journal:
        backend = DeadlineExecution(journal, limits)
        backend.evaluations = 1  # restored reserved evaluation in the host adapter
        engine = SearchEngine(backend)
        result = engine.run()
        assert result["termination"] == "evaluation-budget-reached"
        assert result["evaluation"] == reference
        assert result["clauses"][0]["owners"] == ["system:0", "system:4"]
        assert backend.requests == []


def test_cancellation_during_budget_revalidation_never_commits(tmp_path, monkeypatch):
    limits = SearchLimits(max_evaluations=1, operand_depth=1)
    with Journal(tmp_path / "search", {"case": "cancel-revalidation"}) as journal:
        backend = DeadlineExecution(journal, limits)
        engine = SearchEngine(backend)
        engine._start_draft("introduce", "system:0")
        engine._step_draft()
        load = backend.load

        def cancel_on_restore(reference):
            result = load(reference)
            if backend.restoring:
                backend.cancelled = True
            return result

        monkeypatch.setattr(backend, "load", cancel_on_restore)
        result = engine.run()
        assert result["termination"] == "interrupted"
        assert result["clauses"] == []
        assert not any(event["kind"] == "commit" for event in journal.events)


class UnavailableAnchorExecution(FiniteExecution):
    anchor_outcome = "unknown"

    def _result(self, source):
        result = super()._result(source)
        row = result["cases"][0]
        row.update(case_id="function:0", domain="function")
        if source != "0":
            row["report"]["candidate"] = {"outcome": self.anchor_outcome, "reason": "offline-divergence"}
        return result


@pytest.mark.parametrize("anchor_outcome", ["unknown", "target_crash"])
def test_unrepairable_first_anchor_does_not_veto_other_validated_repairs(tmp_path, anchor_outcome):
    limits = SearchLimits(max_evaluations=1, operand_depth=1)
    with Journal(tmp_path / "search", {"case": "unrepairable-anchor", "outcome": anchor_outcome}) as journal:
        backend = UnavailableAnchorExecution(journal, limits)
        backend.anchor_outcome = anchor_outcome
        engine = SearchEngine(backend)
        engine._start_draft("introduce", "function:0")
        draft = engine.state["draft"]
        assert engine._rank(("rax > 1",), draft) is not None
        result = engine.run()
    assert result["termination"] == "evaluation-budget-reached"
    assert result["clauses"][0]["owners"] == ["system:4"]
    assert result["score"]["covered"] == ["system:4"]
    assert result["score"]["unresolved_targets"] == ["function:0"]
    if anchor_outcome == "unknown":
        assert result["score"]["ignored"] == {"function:0": "offline-divergence"}
        assert result["score"]["coverage"] == "partial"
    else:
        assert result["score"]["target_failures"] == ["function:0"]
        assert result["score"]["ignored"] == {}
    assert result["score"]["domains"]["function"]["target_cases"] == 1


def test_budget_promotion_keeps_baseline_gaps_visible(tmp_path):
    limits = SearchLimits(max_evaluations=1, operand_depth=1)
    with Journal(tmp_path / "search", {"case": "gap-promotion"}) as journal:
        backend = FiniteExecution(journal, limits)
        baseline = backend.load(backend.baseline_ref)
        baseline["cases"][1]["report"]["original_baseline"]["outcome"] = "unknown"
        backend.baseline_ref = journal.store(baseline)
        result = SearchEngine(backend).run()
    assert result["clauses"]
    assert result["termination"] == "evaluation-budget-reached"
    assert result["population"]["system:1"]["label"] == "unknown"
    assert result["score"]["domains"]["system"]["baseline_gaps"] == 1
    assert result["score"]["coverage"] == "partial"


def test_exhausted_population_does_not_cycle_cached_evaluations(tmp_path):
    limits = SearchLimits(operand_depth=1, max_atoms=32, max_factors=2, beam_width=3)
    with Journal(tmp_path / "search", {"case": "exhaustion"}) as journal:
        backend = NoRepairExecution(journal, limits)
        result = SearchEngine(backend).run()
        assert result["termination"] == "bounded-search-exhausted"
        assert result["score"]["unresolved_targets"] == ["system:0", "system:4"]
        assert len(backend.requests) == backend.evaluations


def test_new_capture_revision_reopens_frontier_and_cached_capture_cannot_rewind_it(tmp_path):
    limits = SearchLimits(operand_depth=1, max_atoms=32, max_factors=1)
    output = tmp_path / "search"
    identity = {"case": "frontier-revision"}
    with Journal(output, identity) as journal:
        backend = NoRepairExecution(journal, limits)
        engine = SearchEngine(backend)
        engine._start_draft("introduce", "system:0")
        engine._run((("rax < 0",),))
        backend.values = (-19, -1, 0, 1, 23)
        engine._run((("rax > 0",),))
        assert engine.state["prediction_revision"] == 1
        engine._end_draft()
        assert engine.state["draft"] is not None
        assert engine.state["draft"]["prediction_revision"] == 1
        assert engine.state["blocked"] == []
        engine._run((("rax < 0",),))  # cached older descriptor
        assert engine.space.predict((("rax == 23",),))["system:4"] == (1,)
        assert engine.state["prediction_revision"] == 1
        engine._save()
    with Journal(output, identity, resume=True) as journal:
        restored = SearchEngine(NoRepairExecution(journal, limits))
        assert restored.state["prediction_revision"] == 1
        assert restored.space.predict((("rax == 23",),))["system:4"] == (1,)
        restored._end_draft()
        assert restored.state["draft"] is None
        assert restored.state["blocked"] == ["system:0", "system:4"]


class OutsideTrapExecution(FiniteExecution):
    trap_domain = "system"

    def _result(self, source):
        result = super()._result(source)
        branch = 0 if source == "0" else 2
        report = observed_report("other_crash", "other_crash", branch)
        if branch == 2:
            # The repair hit does not cancel a trap at a later visit.
            report["activation"].update(repair_hits=1, trap_hits=1)
        result["cases"].append({
            "case_id": self.trap_domain + ":99", "domain": self.trap_domain,
            "value": 9, "branch": branch, "branches": [0] if branch == 0 else [1, 2],
            "report": report})
        return result


@pytest.mark.parametrize("domain", ["system", "function"])
def test_all_unsafe_results_have_no_final_candidate_even_with_valid_working_owners(tmp_path, domain):
    limits = SearchLimits(max_evaluations=4, max_factors=1, operand_depth=1, beam_width=2)
    with Journal(tmp_path / "search", {"case": "all-trapped", "domain": domain}) as journal:
        class TrapExecution(OutsideTrapExecution):
            trap_domain = domain

        engine = SearchEngine(TrapExecution(journal, limits))
        engine._start_draft("introduce", "system:0")
        engine.state["draft"]["queue"] = [["rax < -1"]]
        engine._step_draft()
        result = engine.run()
        assert engine.population.cases[domain + ":99"]["label"] == "excluded"
        assert any(journal.load(event["data"]["state"])["clauses"]
                   for event in journal.events if event["kind"] == "commit")
        assert engine.state["best_result"] is None
        assert result["predicate"] is None
        assert result["program"] == result["clauses"] == []
        assert result["publication_status"] == "no_candidate"
        assert result["admission"]["status"] == "not_evaluated"


def test_unsafe_better_target_objective_preserves_eligible_incumbent(tmp_path):
    from taosc_llm.no_llm.score import Score

    with Journal(tmp_path / "search", {"case": "unsafe-better"}) as journal:
        engine = SearchEngine(FiniteExecution(journal, SearchLimits(operand_depth=1)))
        engine._run((("rax < -1",),))
        saved = deepcopy(engine.state["best_result"])
        unsafe = engine.backend._result("(1)")
        unsafe["cases"][1]["report"]["activation"]["status"] = "trapped"
        score = Score.from_evaluation(engine.population, unsafe)
        assert len(score.target_failures) < len(engine.best_score.target_failures)
        engine._archive(((),), unsafe, score, journal.store(unsafe))
        assert engine.state["best_result"] == saved
        assert engine.result()["evaluation"] == saved["evaluation"]


def test_new_incumbent_trap_evidence_revokes_final_selection(tmp_path):
    from taosc_llm.no_llm.score import Score

    with Journal(tmp_path / "search", {"case": "new-incumbent-trap"}) as journal:
        engine = SearchEngine(FiniteExecution(journal, SearchLimits(operand_depth=1)))
        _, evaluated, _ = engine._run((("rax < -1",),))
        unsafe = deepcopy(evaluated)
        unsafe["cases"][1]["report"]["activation"]["status"] = "trapped"
        engine._archive((("rax < -1",),), unsafe,
                        Score.from_evaluation(engine.population, unsafe), journal.store(unsafe))
        assert engine.state["best_result"] is None
        assert engine.best_sets is None
        assert engine.result()["predicate"] is None
        assert engine.result()["publication_status"] == "no_candidate"


@pytest.mark.parametrize("search_policy", ["balanced", "composed", "adaptive"])
def test_guard_first_search_retains_dangerous_atom_and_selects_eligible_composition(
        tmp_path, finite_grammar, search_policy):
    guard, dangerous = "rax != 0", "1 / rax != 0"
    finite_grammar(guard, dangerous)

    class DivisionExecution(PartitionExecution):
        cases = (((1,), "target_crash", True), ((0,), "normal", True), ((2,), "normal", True))

    limits = SearchLimits(max_evaluations=24, max_clauses=1, max_factors=2,
                          operand_depth=1, beam_width=4, search_policy=search_policy)
    with Journal(tmp_path / "search", {"case": "guarded-division"}) as journal:
        backend = DivisionExecution(journal, limits)
        engine = SearchEngine(backend)
        # Standalone danger and guard-after-danger are genuinely evaluated and
        # rejected, not removed from the atom pool or rewritten into safety.
        engine._run(((dangerous,),))
        engine._run(((dangerous, guard),))
        assert engine.state["best_result"] is None
        assert dangerous in engine.space.atoms
        result = engine.run()
        assert result["program"] == [[guard, dangerous]]
        assert result["score"]["covered"] == ["system:0"]
        assert result["score"]["branch_regressions"] == []
        assert result["score"]["selection"]["predicate_traps"] == []
        assert result["admission"]["status"] == "eligible"
        assert backend.evaluations <= limits.max_evaluations
        assert dangerous in engine.space.atoms


@pytest.mark.parametrize("stored_claim", ["eligible", "published"])
def test_resume_rechecks_saved_archive_evaluation_despite_eligible_scalars(tmp_path, stored_claim):
    output = tmp_path / "search"
    identity = {"case": "forged-final-admission", "claim": stored_claim}
    limits = SearchLimits(operand_depth=1)
    with Journal(output, identity) as journal:
        engine = SearchEngine(FiniteExecution(journal, limits))
        _, evaluated, _ = engine._run((("rax < -1",),))
        unsafe = deepcopy(evaluated)
        unsafe["cases"][1]["report"]["activation"]["status"] = "trapped"
        saved = engine.state["best_result"]
        saved.update(evaluation=journal.store(unsafe),
                     admission={"status": "eligible", "predicate_traps": 0, "trap_cases": []},
                     score={"selection": {"predicate_traps": []}}, publication_status=stored_claim)
        engine._save()
        journal.append("publication", {"predicate": saved["predicate"],
                                       "record": journal.store({"candidate": {"status": "published"}})})
    with Journal(output, identity, resume=True) as journal:
        with pytest.raises(ValueError, match="checkpoint archive rejected predicate trap"):
            SearchEngine(FiniteExecution(journal, limits))


def test_budget_promotion_cannot_replace_an_existing_owner(tmp_path):
    limits = SearchLimits(operand_depth=1)
    with Journal(tmp_path / "search", {"case": "owner-preservation"}) as journal:
        engine = SearchEngine(FiniteExecution(journal, limits))
        engine._start_draft("introduce", "system:0")
        draft = engine.state["draft"]
        draft["queue"] = [["rax < -1"]]
        engine._step_draft()
        assert engine._required() == frozenset({"system:0"})
        # This is a real repair of system:4, but not an owner-preserving global
        # introduction. Reusing its evidence cannot discharge system:0.
        score, result, reference = engine._run((("rax > 1",),))
        best = {"factors": ["rax > 1"], "evaluation": reference,
                "owners": ["system:4"], "witnesses": {"system:4": {"hit": 0, "prefix_branch": 0, "branch": 1}}}
        with pytest.raises(ValueError, match="does not establish owners"):
            with engine.backend.restoration():
                engine._accept_introduction(best)
        assert engine._required() == frozenset({"system:0"})


class EarlyNarrowingExecution(PartitionExecution):
    cases = (
        ((1, 1, 1), "target_crash", True),
        ((2, 2, 2), "target_crash", False),
        ((1, 0, 1), "normal", True),
        ((1, 1, 0), "normal", True),
    )
    residual_outcome = "target_crash"

    def _result(self, source):
        result = super()._result(source)
        if source != "0" and self.residual_outcome == "unknown":
            report = result["cases"][1]["report"]
            report["candidate"].update(outcome="unknown", reason="offline-divergence")
            report["activation"]["status"] = "unknown"
        return result


def seed_broad_owner(engine):
    # A proved branch with an immutable partial owner, rather than an offline
    # claim that union coverage or an unknown remaining target was repaired.
    engine._start_draft("introduce", "system:0")
    engine._step_draft()
    engine._accept_introduction(engine.state["draft"]["best"])
    assert engine._required() == {"system:0"}
    assert engine.score.regressions == {"system:2", "system:3"}


@pytest.mark.parametrize("search_policy", ["refine", "balanced", "composed", "adaptive"])
@pytest.mark.parametrize("residual_outcome", ["target_crash", "unknown"])
def test_early_narrowing_gets_budget_before_unresolvable_cover(
        tmp_path, finite_grammar, search_policy, residual_outcome):
    finite_grammar("rax == 1", "rbx == 1", "rcx == 1")
    limits = SearchLimits(search_policy=search_policy, max_evaluations=4,
                          max_factors=3, max_clauses=2, beam_width=1)
    with Journal(tmp_path / "early", {"case": "early-narrowing"}) as journal:
        backend = EarlyNarrowingExecution(journal, limits)
        backend.residual_outcome = residual_outcome
        engine = SearchEngine(backend)
        seed_broad_owner(engine)
        result = engine.run()
        refinements = [journal.load(event["data"]["state"]) for event in journal.events
                       if event["kind"] == "commit" and event["data"]["operation"] == "refine"]
        assert refinements
        assert result["score"]["covered"] == ["system:0"]
        assert result["score"]["unresolved_targets"] == ["system:1"]
        assert len(result["score"]["branch_regressions"]) < 2
        assert result["search_diagnostics"]["refine"] == 1
        assert backend.evaluations == 4
        # Refinement did not throw away or restart the pending cover queue.
        assert engine.state["draft"]["kind"] == "introduce"
        assert engine.state["draft"]["offset"] == 1
        assert engine.state["draft"]["seen"] == [[], ["rax == 1"]]
        assert engine._required() == {"system:0"}
        assert engine.state["cover_draft"] is None
        assert engine.state["early_draft"] is None
        assert engine.state["clauses"][0]["introduced_factors"] == []
        assert engine.state["clauses"][0]["prefix"] == []


@pytest.mark.parametrize("search_policy", ["refine", "balanced", "composed", "adaptive"])
def test_guided_interruption_restores_suspended_cover_and_exact_work_counts(
        tmp_path, finite_grammar, search_policy):
    finite_grammar("rax == 1", "rbx == 1", "rcx == 1")
    limits = SearchLimits(search_policy=search_policy, max_evaluations=8,
                          max_factors=3, max_clauses=2, beam_width=1)
    with Journal(tmp_path / "continuous", {"case": "continuous-guided"}) as journal:
        continuous_engine = SearchEngine(EarlyNarrowingExecution(journal, limits))
        seed_broad_owner(continuous_engine)
        continuous = continuous_engine.run()
    directory = tmp_path / "resumed"
    identity = {"case": "interrupted-guided"}
    with Journal(directory, identity) as journal:
        engine = SearchEngine(EarlyNarrowingExecution(journal, limits, interrupt_at=4))
        seed_broad_owner(engine)
        interrupted = engine.run()
        assert interrupted["termination"] == "interrupted"
        assert engine.state["cover_draft"] is not None
        assert engine.state["draft"]["kind"] == "refine"
        assert engine.state["work_counts"]["refine"] == 1
    prior = {path: path.read_bytes() for path in (directory / "segments").iterdir()}
    with Journal(directory, identity, resume=True) as journal:
        restored = SearchEngine(EarlyNarrowingExecution(journal, limits))
        result = restored.run()
        for key in ("predicate", "clauses", "score", "budgets", "search_diagnostics", "termination"):
            assert result[key] == continuous[key]
        assert restored.state["draft"] == continuous_engine.state["draft"]
        assert restored.state["early_draft"] == continuous_engine.state["early_draft"]
    assert all(path.read_bytes() == data for path, data in prior.items())


@pytest.mark.parametrize("search_policy", ["composed", "adaptive"])
def test_three_factor_preview_improves_before_broad_intermediates_use_budget(
        tmp_path, finite_grammar, search_policy):
    finite_grammar("rax == 1", "rbx == 1", "rcx == 1")

    class ThreeFactorExecution(PartitionExecution):
        cases = (
            ((1, 1, 1), "target_crash", True),
            ((0, 1, 1), "normal", True),
            ((1, 0, 1), "normal", True),
            ((1, 1, 0), "normal", True),
        )

    limits = SearchLimits(search_policy=search_policy, max_evaluations=2,
                          max_factors=3, max_clauses=1, beam_width=3)
    with Journal(tmp_path / "combination", {"case": "three-factor-preview"}) as journal:
        backend = ThreeFactorExecution(journal, limits)
        result = SearchEngine(backend).run()
        assert result["score"]["covered"] == ["system:0"]
        assert result["score"]["branch_regressions"] == []
        assert len(result["program"]) == 1
        assert len(result["program"][0]) == 3
        assert set(result["program"][0]) == {"rax == 1", "rbx == 1", "rcx == 1"}
        assert backend.evaluations == 2
        assert all(source.count("&&") == 2 for source in backend.requests[1:])
        assert 0 < result["search_diagnostics"]["lookahead_predictions"] <= 4 * limits.beam_width ** 2


def test_exhausted_early_refinement_is_not_reopened_by_cached_evidence(tmp_path, finite_grammar):
    finite_grammar("rax == 1")
    limits = SearchLimits(search_policy="balanced", max_factors=1,
                          max_clauses=2, beam_width=1)
    with Journal(tmp_path / "exhausted-early", {"case": "exhausted-early"}) as journal:
        backend = EarlyNarrowingExecution(journal, limits)
        engine = SearchEngine(backend)
        seed_broad_owner(engine)
        result = engine.run()
        assert result["termination"] == "bounded-search-exhausted"
        assert result["search_diagnostics"]["refine"] == 1
        assert engine.state["early_index"] == 1
        assert engine.state["draft"] is None
        assert engine.state["early_draft"] is None
        assert engine.state["cover_draft"] is None
        counts = deepcopy(engine.state["work_counts"])
        spent = backend.evaluations
        engine._run((("rax == 1",),))
        assert engine.state["prediction_revision"] == 0
        assert engine.state["early_index"] == 1
        assert engine.run()["search_diagnostics"] == result["search_diagnostics"]
        assert engine.state["work_counts"] == counts
        assert backend.evaluations == spent


@pytest.mark.parametrize("corruption", ["kind", "index", "attempt", "offset"])
def test_resume_rejects_forged_suspended_cover_work(tmp_path, finite_grammar, corruption):
    finite_grammar("rax == 1", "rbx == 1", "rcx == 1")
    limits = SearchLimits(search_policy="balanced", max_factors=3,
                          max_clauses=2, beam_width=1)
    directory = tmp_path / "forged-suspended"
    identity = {"case": "forged-suspended", "corruption": corruption}
    with Journal(directory, identity) as journal:
        engine = SearchEngine(EarlyNarrowingExecution(journal, limits, interrupt_at=4))
        seed_broad_owner(engine)
        assert engine.run()["termination"] == "interrupted"
        if corruption == "kind":
            engine.state["cover_draft"]["kind"] = "refine"
        elif corruption == "index":
            engine.state["draft"]["index"] = 1
        elif corruption == "attempt":
            engine.state["draft"]["attempt"] = "forged"
        else:
            engine.state["cover_draft"]["offset"] = 100
        engine._save()
    with Journal(directory, identity, resume=True) as journal:
        with pytest.raises(ValueError, match="checkpoint"):
            SearchEngine(EarlyNarrowingExecution(journal, limits))


class AdaptiveExecution(PartitionExecution):
    cases = tuple(((value,), "target_crash" if abs(value) == 2 else "normal", True)
                  for value in (-2, -1, 0, 1, 2))


@pytest.mark.parametrize("hide_normal", [False, True])
def test_adaptive_learns_only_unique_eligible_evidence_preserving_improvements(
        tmp_path, finite_grammar, hide_normal):
    atom = "rax * rax >= 4"
    finite_grammar(atom, "rax == 2", "rax == -2", "rax != 0", "rax >= 0")

    class LearningExecution(AdaptiveExecution):
        def _result(self, source):
            result = super()._result(source)
            if hide_normal and atom in source:
                report = result["cases"][1]["report"]
                report["candidate"].update(outcome="unknown", reason="timeout")
                report["activation"]["status"] = "unknown"
                report["branch_comparison"]["status"] = "unavailable"
            return result

    limits = SearchLimits(search_policy="adaptive", beam_width=4)
    directory = tmp_path / "learning"
    identity = {"case": "operator-learning", "hide-normal": hide_normal}
    ranks = {(factor,): (index, 0, 0, 0, (factor,)) for index, factor in enumerate(
        ("rax == 2", "rax == -2", "rax != 0", "rax >= 0", atom))}
    signatures = {factor: frozenset({index}) for index, factor in enumerate(ranks)}
    with Journal(directory, identity) as journal:
        backend = LearningExecution(journal, limits)
        engine = SearchEngine(backend)
        engine._run(((atom,),))
        engine._run(((atom,),))  # Real backend cache, not another learning trial.
        engine._run((("rax / rax != 0",),))  # Complete-predicate trap: never rewarded.
        stats = deepcopy(engine.state["operator_stats"])
        assert stats["arithmetic"] == {"trials": 1, "improvements": int(not hide_normal)}
        assert stats["division"] == {"trials": 1, "improvements": 0}
        assert len(engine.state["operator_evaluations"]) == 2
        chosen = engine._shortlist(ranks, signatures, 4)
        assert chosen[:3] == list(ranks)[:3]  # Exploration floor survives learning.
        assert ((atom,) in chosen) is (not hide_normal)
        engine._save()
        spent = backend.evaluations
    prior = {path: path.read_bytes() for path in (directory / "segments").iterdir()}
    with Journal(directory, identity, resume=True) as journal:
        backend = LearningExecution(journal, limits)
        restored = SearchEngine(backend)
        assert restored.state["operator_stats"] == stats
        assert restored._shortlist(ranks, signatures, 4) == chosen
        restored._run(((atom,),))
        assert backend.evaluations == spent
        assert restored.state["operator_stats"] == stats
        assert len(restored.state["operator_evaluations"]) == 2
    assert all(path.read_bytes() == data for path, data in prior.items())


@pytest.mark.parametrize("corruption", ["reward", "stats", "program", "before", "duplicate", "counter"])
def test_resume_authenticates_adaptive_rewards_and_counters(tmp_path, finite_grammar, corruption):
    atom = "rax * rax >= 4"
    finite_grammar(atom)
    limits = SearchLimits(search_policy="adaptive")
    directory = tmp_path / "forged-learning"
    identity = {"case": "forged-operator-learning", "corruption": corruption}
    with Journal(directory, identity) as journal:
        engine = SearchEngine(AdaptiveExecution(journal, limits))
        engine._run(((atom,),))
        row = engine.state["operator_evaluations"][0]
        if corruption == "reward":
            row["reward"] = False
        elif corruption == "stats":
            engine.state["operator_stats"]["arithmetic"]["improvements"] += 1
        elif corruption == "program":
            row["program"] = [["rax == 2"]]
        elif corruption == "before":
            row["before"] = row["evaluation"]
        elif corruption == "duplicate":
            engine.state["operator_evaluations"].append(deepcopy(row))
        else:
            engine.state["work_counts"]["refine"] = -1
        engine._save()
    with Journal(directory, identity, resume=True) as journal:
        with pytest.raises(ValueError, match="checkpoint.*(learning|counters)"):
            SearchEngine(AdaptiveExecution(journal, limits))
