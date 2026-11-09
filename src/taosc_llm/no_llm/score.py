"""Case-level branch selection and immutable clause introduction obligations.

Only authenticated host reports enter this module. Offline branch predictions
are deliberately not accepted as repair outcomes.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Population:
    cases: dict[str, dict]

    @classmethod
    def from_evaluation(cls, evaluation: dict) -> "Population":
        cases = {}
        for item in evaluation["cases"]:
            identifier = item["case_id"]
            if identifier in cases:
                raise ValueError("duplicate baseline case")
            report = item["report"]
            neutral = report["neutral_baseline"]
            original = report["original_baseline"]
            capture = neutral.get("capture", {})
            label, reason = "unknown", "neutral-evidence-unavailable"
            if capture.get("status") == "zero_hits":
                if item.get("original_patch_hits", 0) > 0:
                    reason = "original-neutral-reachability-disagreement"
                else:
                    label, reason = "excluded", "no-hit"
            elif (neutral.get("compatible_control") is True
                  and capture.get("status") == "complete"):
                outcome = neutral.get("outcome")
                source = original.get("outcome") if original.get("applicable", True) else outcome
                if source == "other_crash":
                    label, reason = "excluded", "other-crash"
                elif source not in ("normal", "target_crash"):
                    reason = "original-evidence-unavailable"
                elif source != outcome:
                    reason = "original-neutral-disagreement"
                elif outcome in ("normal", "target_crash"):
                    label, reason = outcome, "admitted"
            cases[identifier] = {"domain": item["domain"], "label": label, "reason": reason}
        return cls(cases)

    @property
    def crashes(self) -> frozenset[str]:
        return frozenset(k for k, v in self.cases.items() if v["label"] == "target_crash")

    @property
    def normals(self) -> frozenset[str]:
        return frozenset(k for k, v in self.cases.items() if v["label"] == "normal")

    @property
    def active(self) -> frozenset[str]:
        return self.crashes | self.normals

    @property
    def gaps(self) -> frozenset[str]:
        return frozenset(k for k, v in self.cases.items() if v["label"] == "unknown")

    def to_dict(self) -> dict:
        return {key: self.cases[key] for key in sorted(self.cases)}


@dataclass(frozen=True)
class Score:
    covered: frozenset[str] = frozenset()
    regressions: frozenset[str] = frozenset()
    target_failures: frozenset[str] = frozenset()
    known_normals: frozenset[str] = frozenset()
    ignored: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_evaluation(cls, population: Population, evaluation: dict) -> "Score":
        covered, regressions, failures, known = set(), set(), set(), set()
        normals = population.normals
        active = population.crashes | normals
        ignored = {key: "candidate-not-evaluated" for key in active}
        seen = set()
        for item in evaluation["cases"]:
            key = item["case_id"]
            if key in seen:
                raise ValueError("duplicate candidate case")
            seen.add(key)
            if key not in active:
                continue
            report = item["report"]
            candidate = report["candidate"]
            outcome = candidate.get("outcome")
            activation = report.get("activation", {}).get("status")
            if activation == "trapped":
                ignored[key] = "candidate-trapped"
            elif outcome == "target_crash":
                failures.add(key)
                ignored.pop(key)
            elif outcome == "other_crash":
                ignored[key] = "other-crash"
            elif outcome != "normal":
                ignored[key] = candidate.get("reason", "outcome-unavailable")
            elif activation not in ("fired", "not_fired"):
                ignored[key] = "candidate-" + (activation or "unknown")
            elif key in normals:
                ignored.pop(key)
                known.add(key)
                if activation == "fired":
                    regressions.add(key)
            else:
                control = report["neutral_baseline"]
                if control.get("compatible_control") is not True or control.get("outcome") != "target_crash":
                    ignored[key] = "target-control-unavailable"
                elif activation == "fired":
                    ignored.pop(key)
                    covered.add(key)
                else:
                    ignored[key] = "normal-without-repair"
        return cls(frozenset(covered), frozenset(regressions), frozenset(failures),
                   frozenset(known), ignored)

    def to_dict(self) -> dict:
        return {"covered": sorted(self.covered), "branch_regressions": sorted(self.regressions),
                "target_failures": sorted(self.target_failures), "known_normals": sorted(self.known_normals),
                "ignored": dict(sorted(self.ignored.items()))}

    @classmethod
    def from_dict(cls, value: dict) -> "Score":
        return cls(*(frozenset(value[key]) for key in
                     ("covered", "branch_regressions", "target_failures", "known_normals")),
                   dict(value["ignored"]))

    def complete(self, population: Population) -> bool:
        return not population.gaps and not self.ignored and self.known_normals == population.normals

    def summary(self, population: Population) -> dict:
        domains = {}
        for domain in ("system", "function"):
            ids = {key for key, value in population.cases.items() if value["domain"] == domain}
            domains[domain] = {"target_cases": len(population.crashes & ids),
                               "normal_cases": len(population.normals & ids),
                               "covered": len(self.covered & ids),
                               "branch_regressions": len(self.regressions & ids),
                               "target_failures": len(self.target_failures & ids),
                               "ignored": len(set(self.ignored) & ids),
                               "baseline_gaps": len(population.gaps & ids),
                               "excluded": sum(population.cases[key]["label"] == "excluded" for key in ids)}
        return {**self.to_dict(), "domains": domains,
                "unresolved_targets": sorted(population.crashes - self.covered),
                "coverage": "complete" if self.complete(population) else "partial"}


def new_owners(before: Score, after: Score) -> frozenset[str]:
    """An unavailable-to-normal transition does not prove marginal repair."""
    return (after.covered - before.covered) & before.target_failures


def preserves(owners: frozenset[str], local: Score, required: frozenset[str], global_score: Score) -> bool:
    return owners <= local.covered and required <= global_score.covered


def improves(before: Score, after: Score, *, old_cost: int, new_cost: int) -> bool:
    """No credit for hiding a known normal behind ignored/unavailable evidence."""
    if not before.known_normals <= after.known_normals:
        return False
    if after.target_failures - before.target_failures:
        return False
    common = before.known_normals & after.known_normals
    old = len(before.regressions & common)
    new = len(after.regressions & common)
    return new < old or (new == old and new_cost < old_cost)
