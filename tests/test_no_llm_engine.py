"""Finite transition-system checks for search, independent of native execution.

The native/CLI smoke separately proves artifact execution. This oracle models
one patch visit with two disjoint crash intervals and a shared repair handler.
"""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

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
        self.evaluations += 1
        if self.evaluations == self.interrupt_at:
            raise KeyboardInterrupt
        return self._result(source)

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
    assert [clause["owners"] for clause in result["clauses"]] == [["system:0"], ["system:4"]]
    assert result["clauses"][1]["prefix"] == [result["clauses"][0]["factors"]]


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


def test_budget_stop_has_no_fabricated_incumbent(tmp_path):
    limits = SearchLimits(max_evaluations=1, operand_depth=1)
    with Journal(tmp_path / "search", {"case": "budget"}) as journal:
        result = SearchEngine(FiniteExecution(journal, limits)).run()
    assert result["termination"] == "evaluation-budget-reached"
    assert result["predicate"] is None
    assert result["score"]["target_failures"] == ["system:0", "system:4"]
