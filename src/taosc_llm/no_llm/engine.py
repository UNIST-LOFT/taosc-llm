"""Bounded sequential covering and owner-preserving refinement.

The engine consumes a host execution adapter, not a Pi session. State checkpoints
contain draft frontiers separately from the last fully evaluated incumbent.
"""
from __future__ import annotations

import copy

from ..dataset import canonical
from ..family import parse_candidate
from .model import SearchStopped
from .score import Population, Score, improves, new_owners, preserves
from .space import Space, compose


def _clauses(records):
    return tuple(tuple(record["factors"]) for record in records)


def _cost(clauses):
    return sum(len(atom.encode("utf-8")) + 4 for clause in clauses for atom in clause) + len(clauses)


class SearchEngine:
    def __init__(self, backend):
        self.backend = backend
        self.journal = backend.journal
        self.limits = backend.limits
        self.family = backend.dataset.patch_format
        self.baseline = backend.baseline()
        self.population = Population.from_evaluation(self.baseline)
        backend.population = self.population
        self.state: dict = {"clauses": [], "evaluation": backend.baseline_ref, "phase": "cover",
                      "blocked": [], "refine_index": 0, "refine_progress": False,
                      "draft": None, "revision": 0, "termination": None,
                      "prediction_evidence": {}, "prediction_revision": 0,
                      "processed_evaluations": [], "atoms": []}
        for event in self.journal.events:
            if event["kind"] in ("checkpoint", "commit"):
                self.state = self.journal.load(event["data"]["state"])
        self.current = backend.load(self.state["evaluation"])
        self.score = Score.from_evaluation(self.population, self.current)
        snapshots = backend.snapshots(self.baseline)
        references = self.state["prediction_evidence"]
        if references:
            loaded = {}
            for case, reference in references.items():
                backend.check_operation()
                key = canonical(reference)
                if key not in loaded:
                    loaded[key] = backend.snapshots(backend.load(reference))
                if case not in loaded[key]:
                    raise ValueError("checkpoint prediction capture missing")
                snapshots[case] = loaded[key][case]
        else:
            references.update({case: backend.baseline_ref for case in snapshots})
        self.space = Space(self.family, snapshots, self.limits, check=backend.check_operation)
        if self.state["atoms"]:
            if set(self.state["atoms"]) != set(self.space.atoms):
                raise ValueError("checkpoint atom corpus mismatch")
            self.space.atoms = tuple(self.state["atoms"])
        self._validate_incumbent()

    def _validate_incumbent(self):
        """A durable checkpoint is not itself proof of ownership or execution."""
        required = set()
        ids = set()
        for clause in self.state["clauses"]:
            owners = frozenset(clause["owners"])
            if (not owners or not owners <= self.population.crashes or owners & required
                    or clause["id"] in ids):
                raise ValueError("invalid checkpoint clause ownership")
            ids.add(clause["id"])
            required.update(owners)
            prefix = tuple(tuple(row) for row in clause["prefix"])
            before = self.backend.load(clause["prefix_evaluation"])
            introduced = self.backend.load(clause["introduction"])
            def matches(result, program):
                if program:
                    expected = parse_candidate(self.family, compose(self.family, program)).descriptor
                    if result["descriptor"] != expected:
                        raise ValueError("checkpoint expression/evidence mismatch")
            matches(before, prefix)
            matches(introduced, prefix + (tuple(clause["introduced_factors"]),))
            if new_owners(Score.from_evaluation(self.population, before),
                          Score.from_evaluation(self.population, introduced)) != owners:
                raise ValueError("checkpoint introduction does not establish owners")
            if self._witnesses(prefix, clause["introduced_factors"], introduced, owners) != clause["witnesses"]:
                raise ValueError("checkpoint introduction witness mismatch")
            refinement = clause.get("refinement")
            if refinement is not None:
                local = self.backend.load(refinement["local_evaluation"])
                matches(local, prefix + (tuple(clause["factors"]),))
                if (not owners <= Score.from_evaluation(self.population, local).covered
                        or self._witnesses(prefix, clause["factors"], local, owners) != refinement["witnesses"]):
                    raise ValueError("checkpoint refinement lost local owners")
            elif clause["factors"] != clause["introduced_factors"]:
                raise ValueError("checkpoint has unproved refinement")
        if not required <= self.score.covered:
            raise ValueError("checkpoint incumbent lost global owners")
        if self.state["clauses"]:
            expected = parse_candidate(self.family, compose(self.family, _clauses(self.state["clauses"])))
            if self.current["descriptor"] != expected.descriptor:
                raise ValueError("checkpoint incumbent expression mismatch")

    def _save(self, *, commit=None):
        self.state["atoms"] = list(self.space.atoms)
        reference = self.journal.store(self.state)
        self.journal.append("commit" if commit else "checkpoint",
                            {"state": reference, **({"operation": commit} if commit else {})})
        self.backend.checkpoint_budget()

    def _required(self):
        return frozenset(owner for clause in self.state["clauses"] for owner in clause["owners"])

    def _run(self, clauses):
        expression = compose(self.family, clauses)
        if expression is None:
            return None
        try:
            parse_candidate(self.family, expression)
        except ValueError:
            return None
        result = self.backend.evaluate(expression)
        score = Score.from_evaluation(self.population, result)
        reference = self.journal.store(result)
        # At most one entry per admitted descriptor (bounded by the evaluation
        # budget). Reusing an old outcome must not roll prediction state back to
        # that descriptor's earlier capture or restart an exhausted frontier.
        if result["descriptor"] not in self.state["processed_evaluations"]:
            snapshots = self.backend.snapshots(result)
            revision = self.space.revision
            self.space.update(snapshots)
            if self.space.revision != revision:
                self.state["prediction_revision"] += 1
                self.state["blocked"] = []
            self.state["prediction_evidence"].update({case: reference for case in snapshots})
            self.state["processed_evaluations"].append(result["descriptor"])
        return score, result, reference

    def _witnesses(self, prefix, factors, result, owners):
        """A repair hit must exclude the frozen prefix's remaining safe path.

        For CWE this compares whole same-clamp trees, never per-clause reduced
        jump flags. One complete actual hit with prefix=0 and composed=1 is the
        marginal witness; real paired outcomes establish the case contribution.
        """
        from binradar.binradar_taosc_predicates import evaluate_cached_predicate, prepare_generic_environments
        prefix_source = compose(self.family, prefix)
        prefix_parsed = parse_candidate(self.family, prefix_source).parsed if prefix_source is not None else None
        full = parse_candidate(self.family, compose(self.family, prefix + (tuple(factors),))).parsed
        captures = self.backend.snapshots(result)
        witnesses, evaluated = {}, {}
        for key in owners:
            self.backend.check_operation()
            states = captures.get(key, ())
            if not states:
                return None
            if id(states) not in evaluated:
                environments = prepare_generic_environments(states)
                prior = (evaluate_cached_predicate(prefix_parsed, states, environments)
                         if prefix_parsed is not None else [0] * len(states))
                branches = evaluate_cached_predicate(full, states, environments)
                self.backend.check_operation()
                evaluated[id(states)] = next((index for index, (old, new, state)
                                              in enumerate(zip(prior, branches, states))
                                              if old == 0 and new == 1 and state.branch == 1), None)
            index = evaluated[id(states)]
            if index is None:
                return None
            witnesses[key] = {"hit": index, "prefix_branch": 0, "branch": 1}
        return witnesses

    def _predict(self, clauses):
        try:
            vectors = self.space.predict(clauses)
        except ValueError:
            return None
        fired = {key for key, vector in vectors.items() if 1 in vector and 2 not in vector}
        trapped = {key for key, vector in vectors.items() if 2 in vector}
        return fired, trapped

    def _rank(self, factors, draft):
        clauses = list(_clauses(self.state["clauses"]))
        if draft["kind"] == "introduce":
            clauses.append(tuple(factors))
            targets = self.population.crashes - self.score.covered
        else:
            clauses[draft["index"]] = tuple(factors)
            targets = self._required()
        prediction = self._predict(tuple(clauses))
        if prediction is None:
            return None
        fired, trapped = prediction
        # Introduction searches the unresolved population together. An anchor
        # with unavailable outcomes must not veto another case's actual repair.
        # Refinement still retains its immutable owners below.
        if not fired & targets:
            return None
        if not self._required() <= fired or trapped & self._required():
            return None
        false_positives = len(fired & self.population.normals)
        covered = len(fired & targets)
        return (false_positives, -covered, len(trapped), _cost((tuple(factors),)), tuple(factors))

    def _queue(self, draft):
        """Keep both no-error and no-reg beams; no truth-vector is an outcome."""
        pool = {}
        seen = {tuple(row) for row in draft["seen"]}
        for parent in draft["beam"]:
            for atom in self.space.atoms:
                self.backend.check()
                if atom in parent:
                    continue
                factors = tuple(parent) + (atom,)
                if len(factors) > self.limits.max_factors or factors in seen:
                    continue
                rank = self._rank(factors, draft)
                if rank is not None:
                    pool[factors] = rank
            if draft["kind"] == "refine":
                for index in range(len(parent)):
                    factors = tuple(parent[:index] + parent[index + 1:])
                    if factors in seen or not factors and self.family == "ERM CWE-805":
                        continue
                    rank = self._rank(factors, draft)
                    if rank is not None:
                        pool[factors] = rank
        if not pool:
            return []
        # Cover-preserving no-error candidates get their own slots, so a
        # zero-regression smaller target partition cannot erase that alternative.
        by_coverage = sorted(pool, key=lambda factors: (pool[factors][1], pool[factors][0], *pool[factors][2:]))
        by_regression = sorted(pool, key=pool.__getitem__)
        selected = []
        for index in range(self.limits.beam_width):
            for order in (by_coverage, by_regression):
                if index < len(order) and order[index] not in selected:
                    selected.append(order[index])
                if len(selected) >= self.limits.beam_width:
                    return [list(row) for row in selected]
        return [list(row) for row in selected]

    def _start_draft(self, kind, anchor, *, index=None):
        factors = list(self.state["clauses"][index]["factors"]) if kind == "refine" else []
        initial = [factors] if kind == "introduce" and self.family == "ERM generic" else []
        self.state["draft"] = {"kind": kind, "anchor": anchor, "index": index,
                               "beam": [factors], "queue": initial, "offset": 0, "depth": 0,
                               "seen": [], "best": None,
                               "prediction_revision": self.state["prediction_revision"]}
        self._save()

    def _accept_introduction(self, best):
        current = self.backend.load(best["evaluation"])
        score = Score.from_evaluation(self.population, current)
        prefix = _clauses(self.state["clauses"])
        expected = parse_candidate(self.family, compose(self.family, prefix + (tuple(best["factors"]),)))
        owners = new_owners(self.score, score)
        if (current["descriptor"] != expected.descriptor or not owners
                or owners != frozenset(best["owners"])
                or not self._required() <= score.covered
                or not self.score.known_normals <= score.known_normals
                or score.target_failures & self.population.normals):
            raise ValueError("draft introduction does not establish owners")
        witnesses = self._witnesses(prefix, best["factors"], current, owners)
        if witnesses is None or witnesses != best["witnesses"]:
            raise ValueError("draft introduction does not establish owners")
        self.backend.check_operation()
        self.state["clauses"].append({"id": self.state["revision"] + 1,
                                      "factors": best["factors"], "introduced_factors": best["factors"],
                                      "prefix": [list(row) for row in prefix],
                                      "prefix_evaluation": self.state["evaluation"],
                                      "owners": best["owners"], "introduction": best["evaluation"],
                                      "witnesses": best["witnesses"]})
        self.state["evaluation"] = best["evaluation"]
        self.current = current
        self.score = score
        self.state.update(draft=None, blocked=[], revision=self.state["revision"] + 1)
        self._save(commit="introduce")

    def _accept_refinement(self, draft, factors, result, reference, local_reference, witnesses):
        self.backend.check_operation()
        clause = self.state["clauses"][draft["index"]]
        clause["factors"] = list(factors)
        clause["refinement"] = {"evaluation": reference, "local_evaluation": local_reference,
                                "witnesses": witnesses}
        self.state["evaluation"] = reference
        self.current = result
        self.score = Score.from_evaluation(self.population, result)
        self.state.update(draft=None, refine_progress=True, revision=self.state["revision"] + 1)
        self._save(commit="refine")

    def _step_draft(self):
        draft = self.state["draft"]
        if draft["offset"] >= len(draft["queue"]):
            if draft["depth"] >= self.limits.max_factors:
                return self._end_draft()
            draft["queue"] = self._queue(draft)
            draft["offset"] = 0
            draft["depth"] += 1
            if not draft["queue"]:
                return self._end_draft()
            draft["beam"] = copy.deepcopy(draft["queue"])
            self._save()
        factors = draft["queue"][draft["offset"]]
        program = _clauses(self.state["clauses"])
        if draft["kind"] == "introduce":
            tested = self._run(program + (tuple(factors),))
            if tested is not None:
                score, result, reference = tested
                owners = new_owners(self.score, score)
                if (owners and self._required() <= score.covered
                        and self.score.known_normals <= score.known_normals
                        and not (score.target_failures & self.population.normals)):
                    witnesses = self._witnesses(program, factors, result, owners)
                    if witnesses is not None:
                        rank = (len(score.regressions), -len(owners), _cost((tuple(factors),)), tuple(factors))
                        old = draft["best"]
                        old_rank = (old["rank"][0], old["rank"][1], old["rank"][2], tuple(old["rank"][3])) if old else None
                        if old_rank is None or rank < old_rank:
                            draft["best"] = {"rank": list(rank), "factors": list(factors),
                                             "evaluation": reference, "owners": sorted(owners),
                                             "witnesses": witnesses}
                        if score.regressions <= self.score.regressions:
                            self._accept_introduction(draft["best"])
                            return
        else:
            clause = self.state["clauses"][draft["index"]]
            prefix = tuple(tuple(row) for row in clause["prefix"])
            local = self._run(prefix + (tuple(factors),))
            if local is not None and frozenset(clause["owners"]) <= local[0].covered:
                witnesses = self._witnesses(prefix, factors, local[1], clause["owners"])
                modified = list(program)
                modified[draft["index"]] = tuple(factors)
                tested = self._run(tuple(modified)) if witnesses is not None else None
                if tested is not None:
                    score, result, reference = tested
                    if (preserves(frozenset(clause["owners"]), local[0], self._required(), score)
                            and improves(self.score, score, old_cost=_cost(program), new_cost=_cost(modified))):
                        self._accept_refinement(draft, factors, result, reference, local[2], witnesses)
                        return
        draft["seen"].append(list(factors))
        draft["offset"] += 1
        self._save()

    def _end_draft(self):
        draft = self.state["draft"]
        if draft["kind"] == "introduce" and draft["best"] is not None:
            self._accept_introduction(draft["best"])
            return
        if draft["prediction_revision"] != self.state["prediction_revision"]:
            # New representative states can change the bounded shortlist. Once
            # every descriptor's evidence was consumed, cached outcomes cannot
            # cause another restart. Revision and consumption survive resume.
            self._start_draft(draft["kind"], draft["anchor"], index=draft["index"])
            return
        if draft["kind"] == "introduce":
            # Every unresolved target participated in this same bounded beam.
            # Repeating it for each anchor would only reload cached outcomes and
            # rebuild identical predictions, without adding search alternatives.
            self.state["blocked"] = sorted(self.population.crashes - self.score.covered)
        else:
            self.state["refine_index"] += 1
        self.state["draft"] = None
        self._save()

    def run(self):
        if not self.population.crashes:
            self.state["termination"] = "no-target-cases" if not self.population.gaps else "evidence-unavailable"
            self._save()
            return self.result()
        try:
            while True:
                if (self.population.crashes <= self.score.covered and not self.score.regressions
                        and not self.score.target_failures and self.score.complete(self.population)):
                    self.state["termination"] = "observed-goals-met"
                    self._save()
                    break
                self.backend.check()
                if self.state["draft"] is not None:
                    self._step_draft()
                    continue
                if self.state["phase"] == "cover":
                    outstanding = sorted(self.population.crashes - self.score.covered - set(self.state["blocked"]))
                    if outstanding and len(self.state["clauses"]) < self.limits.max_clauses:
                        self._start_draft("introduce", outstanding[0])
                    else:
                        self.state.update(phase="refine", refine_index=0, refine_progress=False)
                        self._save()
                elif self.state["refine_index"] < len(self.state["clauses"]):
                    index = self.state["refine_index"]
                    owner = self.state["clauses"][index]["owners"][0]
                    self._start_draft("refine", owner, index=index)
                elif (self.state["refine_progress"]
                      or (len(self.state["clauses"]) < self.limits.max_clauses
                          and self.population.crashes - self.score.covered - set(self.state["blocked"]))):
                    self.state.update(phase="cover", blocked=[])
                    self._save()
                else:
                    self.state["termination"] = ("evidence-unavailable" if self.score.ignored or self.population.gaps
                                                 else "clause-budget-reached" if len(self.state["clauses"]) >= self.limits.max_clauses
                                                 and self.population.crashes - self.score.covered
                                                 else "bounded-search-exhausted")
                    self._save()
                    break
        except SearchStopped as stop:
            reason = stop.reason
            draft = self.state["draft"]
            if (reason in ("wall-time-reached", "evaluation-budget-reached")
                    and draft is not None and draft["kind"] == "introduce" and draft["best"] is not None):
                try:
                    # Only authenticate/re-gate already completed evidence. The
                    # backend still forbids new evaluation admission, and polls
                    # cancellation throughout restoration and before commit.
                    with self.backend.restoration():
                        self._accept_introduction(draft["best"])
                except SearchStopped as interrupted:
                    reason = interrupted.reason
                except KeyboardInterrupt:
                    reason = "interrupted"
            self.state["termination"] = reason
            self._save()
        except KeyboardInterrupt:
            self.state["termination"] = "interrupted"
            self._save()
        return self.result()

    def result(self):
        clauses = _clauses(self.state["clauses"])
        return {"schema_version": 1, "engine": "taosc-llm-no-llm",
                "dataset_id": self.backend.dataset.dataset_id,
                "termination": self.state["termination"], "verified": False,
                "binradar_verification": "not_run", "run_directory": str(self.journal.directory),
                "predicate": compose(self.family, clauses) if clauses else None,
                "clauses": copy.deepcopy(self.state["clauses"]), "population": self.population.to_dict(),
                "evaluation": self.state["evaluation"], "score": self.score.summary(self.population),
                "budgets": {"elapsed": self.backend.elapsed, "evaluations": self.backend.evaluations},
                "limits": self.limits.to_dict()}
