from taosc_llm.no_llm.score import Population, Score, improves, new_owners, preserves


def row(key, baseline="target_crash", candidate="normal", activation="fired", *, hits=1, compatible=True):
    return {"case_id": key, "domain": "system", "report": {
        "original_baseline": {"outcome": baseline, "applicable": True},
        "neutral_baseline": {"outcome": baseline, "compatible_control": compatible,
                             "capture": {"status": "complete" if hits else "zero_hits", "total_hits": hits}},
        "candidate": {"outcome": candidate, "reason": "observed"},
        "activation": {"status": activation, "repair_hits": hits if activation == "fired" else 0}}}


def test_regression_is_case_level_branch_selection_not_crash_only():
    baseline = {"cases": [row("system:0", "normal", "normal", "not_fired"),
                           row("system:1"), row("system:2"), row("system:3")]}
    population = Population.from_evaluation(baseline)
    score = Score.from_evaluation(population, {"cases": [
        row("system:0", "normal", "normal", "fired", hits=97),
        row("system:1", candidate="target_crash"),
        row("system:2", candidate="other_crash"), row("system:3")]})
    assert score.regressions == {"system:0"}
    assert score.covered == {"system:3"}
    assert score.target_failures == {"system:1"}
    assert score.ignored == {"system:2": "other-crash"}


def test_no_hit_is_excluded_but_missing_capture_is_not_zero_hit():
    absent = row("system:2")
    absent["report"]["neutral_baseline"].update(compatible_control=False, capture={"status": "unavailable"})
    population = Population.from_evaluation({"cases": [row("system:0", hits=0), row("system:1"), absent]})
    assert population.cases["system:0"]["reason"] == "no-hit"
    assert population.crashes == {"system:1"}
    assert population.gaps == {"system:2"}


def test_target_after_normal_baseline_is_failure_and_nonfiring_normal_is_not_repair():
    population = Population.from_evaluation({"cases": [row("system:0", "normal"), row("system:1")]})
    score = Score.from_evaluation(population, {"cases": [row("system:0", "normal", "target_crash"),
                                                         row("system:1", activation="not_fired")]})
    assert score.target_failures == {"system:0"}
    assert score.covered == set()
    assert score.ignored["system:1"] == "normal-without-repair"


def test_trap_does_not_supply_a_valid_failure_or_repair_comparison():
    population = Population.from_evaluation({"cases": [row("system:0")]})
    score = Score.from_evaluation(population, {"cases": [
        row("system:0", candidate="target_crash", activation="trapped")]})
    assert not score.covered and not score.target_failures
    assert score.ignored == {"system:0": "candidate-trapped"}


def test_other_clause_cannot_pay_lost_local_ownership():
    owner = frozenset({"system:0"})
    local = Score(target_failures=owner)
    global_score = Score(covered=owner)
    assert not preserves(owner, local, owner, global_score)
    assert preserves(owner, global_score, owner, global_score)
    assert not new_owners(Score(ignored={"system:0": "unknown"}), global_score)
    assert new_owners(local, global_score) == owner


def test_ignored_normal_cannot_manufacture_regression_improvement():
    normal = frozenset({"system:0"})
    before = Score(regressions=normal, known_normals=normal)
    after = Score(ignored={"system:0": "other-crash"})
    assert not improves(before, after, old_cost=10, new_cost=1)
    assert improves(before, Score(known_normals=normal), old_cost=10, new_cost=10)


def test_unknown_original_and_changed_reachability_cannot_improve_population():
    unknown = row("system:0")
    unknown["report"]["original_baseline"]["outcome"] = "unknown"
    no_hit = row("system:1", hits=0)
    no_hit["original_patch_hits"] = 1
    changed_fault = row("system:2")
    changed_fault["report"]["neutral_baseline"]["outcome"] = "other_crash"
    mutation = row("function:3")
    mutation["domain"] = "function"
    mutation["report"]["original_baseline"] = {"applicable": False, "outcome": "unknown"}
    population = Population.from_evaluation({"cases": [unknown, no_hit, changed_fault, mutation]})
    assert population.gaps == {"system:0", "system:1", "system:2"}
    assert population.crashes == {"function:3"}
    assert population.cases["system:0"]["reason"] == "original-evidence-unavailable"
    assert population.cases["system:1"]["reason"] == "original-neutral-reachability-disagreement"


def test_original_neutral_disagreement_is_evidence_gap():
    value = row("system:0")
    value["report"]["neutral_baseline"]["outcome"] = "normal"
    population = Population.from_evaluation({"cases": [value]})
    assert not population.crashes
    assert population.gaps == {"system:0"}
    assert population.cases["system:0"]["reason"] == "original-neutral-disagreement"
