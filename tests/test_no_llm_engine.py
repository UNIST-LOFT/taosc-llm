"""Finite transition-system checks for search, independent of native execution.

The native/CLI smoke separately proves artifact execution. This oracle models
one patch visit with two disjoint crash intervals and a shared repair handler.
"""
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from binradar.binradar_taosc_predicates import CachedSnapshot, evaluate_cached_predicate
from taosc_llm.family import parse_candidate
from taosc_llm.no_llm.engine import SearchEngine
from taosc_llm.no_llm.journal import Journal
from taosc_llm.no_llm.model import SearchLimits, SearchStopped


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
                         "report": {"original_baseline": {"outcome": original, "applicable": True},
                                    "neutral_baseline": {"outcome": original, "compatible_control": True,
                                                         "capture": {"status": "complete", "total_hits": 1}},
                                    "candidate": {"outcome": outcome},
                                    "activation": {"status": "trapped" if branch == 2 else "fired" if branch else "not_fired"}}})
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


@pytest.mark.parametrize("max_evaluations,termination", [
    (2, "evaluation-budget-reached"), (64, "clause-budget-reached"),
])
def test_full_repair_survives_lower_regression_partial_search(
        tmp_path, max_evaluations, termination):
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
        assert any(len(state["clauses"][0]["owners"]) == 1 for state in introductions)
        # The published alternative has its own identity; historical owners do
        # not silently change when another complete expression is selected.
        assert result["clauses"][0]["id"] > introductions[-1]["clauses"][0]["id"]
    assert result["termination"] == termination
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


def test_full_repair_checkpoint_requires_introduction_proof(tmp_path):
    limits = SearchLimits(max_evaluations=1, operand_depth=1)
    output = tmp_path / "search"
    identity = {"case": "full-repair-proof"}
    with Journal(output, identity) as journal:
        engine = SearchEngine(FiniteExecution(journal, limits))
        engine._start_draft("introduce", "system:0")
        engine._step_draft()
        engine.state["full_repair"]["clauses"][0]["owners"] = ["system:0"]
        engine._save()
    with Journal(output, identity, resume=True) as journal:
        with pytest.raises(ValueError, match="introduction does not establish owners"):
            SearchEngine(FiniteExecution(journal, limits))


def test_interrupted_draft_resumes_without_committing_partial_coverage(tmp_path):
    limits = SearchLimits(operand_depth=1, max_factors=1, max_atoms=512)
    output = tmp_path / "search"
    identity = {"case": "resume-intervals"}
    with Journal(output, identity) as journal:
        interrupted = SearchEngine(FiniteExecution(journal, limits, interrupt_at=2)).run()
    assert interrupted["termination"] == "interrupted"
    assert interrupted["clauses"] == []
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
    assert result["predicate"] is None
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
def test_budget_finalization_revalidates_saved_draft(tmp_path, corruption):
    limits = SearchLimits(max_evaluations=1, operand_depth=1)
    with Journal(tmp_path / "search", {"case": "invalid-best", "field": corruption}) as journal:
        backend = DeadlineExecution(journal, limits)
        engine = SearchEngine(backend)
        engine._start_draft("introduce", "system:0")
        engine._step_draft()
        best = engine.state["draft"]["best"]
        if corruption == "owners":
            best["owners"] = ["system:1"]
        elif corruption == "witnesses":
            best["witnesses"] = {}
        else:
            best["evaluation"] = backend.baseline_ref
        with pytest.raises(ValueError, match="does not establish owners"):
            engine.run()
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
    anchor_outcome = "unavailable"

    def _result(self, source):
        result = super()._result(source)
        row = result["cases"][0]
        row.update(case_id="function:0", domain="function")
        if source != "0":
            row["report"]["candidate"] = {"outcome": self.anchor_outcome, "reason": "offline-divergence"}
        return result


@pytest.mark.parametrize("anchor_outcome", ["unavailable", "target_crash"])
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
    if anchor_outcome == "unavailable":
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


def test_exhausted_population_uses_one_frontier_not_one_per_anchor(tmp_path):
    limits = SearchLimits(operand_depth=1, max_atoms=32, max_factors=2, beam_width=3)
    with Journal(tmp_path / "search", {"case": "one-frontier"}) as journal:
        backend = NoRepairExecution(journal, limits)
        engine = SearchEngine(backend)
        result = engine.run()
        assert result["termination"] == "bounded-search-exhausted"
        assert result["score"]["unresolved_targets"] == ["system:0", "system:4"]
        assert engine.state["blocked"] == ["system:0", "system:4"]
        assert len(backend.requests) == backend.evaluations
        frontiers = [journal.load(event["data"]["state"])["draft"]
                     for event in journal.events if event["kind"] == "checkpoint"]
        assert sum(draft is not None and draft["depth"] == 0 and not draft["seen"]
                   for draft in frontiers) == 1


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
