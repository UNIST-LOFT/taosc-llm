"""Bounded diverse sequential covering and owner-preserving refinement.

The crash-first result archive is independent of round-robin working branches.
Checkpoints retain each branch's draft and immutable proofs, but share capture
revisions, visited work and execution budgets. Predictions only schedule work.
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
                      "processed_evaluations": [], "atoms": [], "best_result": None,
                      "pending": [], "visited_branches": {}, "visited_work": {},
                      "branch_prediction_revision": 0, "exhausted_revision": None,
                      "next_clause_id": 1}
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
        self._scores = {canonical(self.state["evaluation"]): self.score}
        self._validate_branch(self._branch(), self.current, self.score)
        if len(self.state["pending"]) >= self.limits.beam_width:
            raise ValueError("checkpoint exceeds branch beam")
        for branch in self.state["pending"]:
            evaluated = backend.load(branch["evaluation"])
            score = Score.from_evaluation(self.population, evaluated)
            self._scores[canonical(branch["evaluation"])] = score
            self._validate_branch(branch, evaluated, score)
        self.best_score = self.score
        saved = self.state["best_result"]
        if saved is not None:
            evaluated = backend.load(saved["evaluation"])
            self.best_score = Score.from_evaluation(self.population, evaluated)
            self._validate_incumbent(saved["clauses"], evaluated, self.best_score)
            self._scores[canonical(saved["evaluation"])] = self.best_score
        else:
            self.state["best_result"] = {"clauses": [], "evaluation": backend.baseline_ref}

    def _validate_incumbent(self, clauses, current, score):
        """A durable checkpoint is not itself proof of ownership or execution."""
        self.space.expression(_clauses(clauses))
        if not self.population.normals <= score.known_normals:
            raise ValueError("checkpoint lost required normal observations")
        if score.target_failures & self.population.normals:
            raise ValueError("checkpoint introduced a normal crash")
        required = set()
        ids = set()
        for clause in clauses:
            owners = frozenset(clause["owners"])
            if (not owners or not owners <= self.population.crashes or owners & required
                    or clause["id"] in ids):
                raise ValueError("invalid checkpoint clause ownership")
            ids.add(clause["id"])
            required.update(owners)
            prefix = tuple(tuple(row) for row in clause["prefix"])
            if len(prefix) != len(ids) - 1:
                raise ValueError("checkpoint introduction prefix length mismatch")
            before = self.backend.load(clause["prefix_evaluation"])
            introduced = self.backend.load(clause["introduction"])
            def matches(result, program):
                self.space.expression(program)
                expected = (parse_candidate(self.family, compose(self.family, program)).descriptor
                            if program else self.baseline["descriptor"])
                if result["descriptor"] != expected or not program and result != self.baseline:
                    raise ValueError("checkpoint expression/evidence mismatch")
            matches(before, prefix)
            matches(introduced, prefix + (tuple(clause["introduced_factors"]),))
            before_score = Score.from_evaluation(self.population, before)
            introduction_score = Score.from_evaluation(self.population, introduced)
            if (not self.population.normals <= before_score.known_normals
                    or not self.population.normals <= introduction_score.known_normals
                    or not (required - owners) <= before_score.covered
                    or not required <= introduction_score.covered
                    or new_owners(before_score, introduction_score) != owners):
                raise ValueError("checkpoint introduction does not establish owners")
            introduction_witnesses = self._witnesses(prefix, clause["introduced_factors"], introduced, owners)
            if introduction_witnesses is None or introduction_witnesses != clause["witnesses"]:
                raise ValueError("checkpoint introduction witness mismatch")
            refinement = clause.get("refinement")
            if refinement is not None:
                local = self.backend.load(refinement["local_evaluation"])
                global_result = self.backend.load(refinement["evaluation"])
                refined_program = tuple(tuple(row) for row in refinement["program"])
                matches(global_result, refined_program)
                global_score = Score.from_evaluation(self.population, global_result)
                historical_owners = frozenset(owner for row in clauses[:len(refined_program)] for owner in row["owners"])
                if (not len(ids) <= len(refined_program) <= len(clauses)
                        or refined_program[len(ids) - 1] != tuple(clause["factors"])
                        or frozenset(refinement["required"]) != historical_owners
                        or not historical_owners <= global_score.covered
                        or not self.population.normals <= global_score.known_normals):
                    raise ValueError("checkpoint refinement lost global owners or normal evidence")
                matches(local, prefix + (tuple(clause["factors"]),))
                local_witnesses = self._witnesses(prefix, clause["factors"], local, owners)
                if (not owners <= Score.from_evaluation(self.population, local).covered
                        or local_witnesses is None or local_witnesses != refinement["witnesses"]):
                    raise ValueError("checkpoint refinement lost local owners")
            elif clause["factors"] != clause["introduced_factors"]:
                raise ValueError("checkpoint has unproved refinement")
        if not required <= score.covered:
            raise ValueError("checkpoint incumbent lost global owners")
        if clauses:
            expected = parse_candidate(self.family, compose(self.family, _clauses(clauses)))
            if current["descriptor"] != expected.descriptor:
                raise ValueError("checkpoint incumbent expression mismatch")
        elif current != self.baseline:
            raise ValueError("checkpoint neutral expression mismatch")

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
        self._scores[canonical(reference)] = score
        # At most one entry per admitted descriptor (bounded by the evaluation
        # budget). Reusing an old outcome must not roll prediction state back to
        # that descriptor's earlier capture or restart an exhausted frontier.
        if result["descriptor"] not in self.state["processed_evaluations"]:
            snapshots = self.backend.snapshots(result)
            revision = self.space.revision
            self.space.update(snapshots)
            if self.space.revision != revision:
                self.state["prediction_revision"] += 1
                self.state.update(blocked=[], termination=None, exhausted_revision=None,
                                  branch_prediction_revision=self.state["prediction_revision"])
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

    def _predict(self, clauses, *, membership=False):
        try:
            vectors = self.space.predict(clauses)
        except ValueError:
            return None
        fired = {key for key, vector in vectors.items() if 1 in vector and 2 not in vector}
        trapped = {key for key, vector in vectors.items() if 2 in vector}
        if membership:
            # Preserve mixed-hit fire/trap distinctions as well as case IDs.
            signature = frozenset((key, branch) for key, vector in vectors.items() for branch in set(vector))
            return fired, trapped, signature
        return fired, trapped

    def _rank(self, factors, draft):
        proposal = self._proposal(factors, draft)
        return proposal[0] if proposal is not None else None

    def _proposal(self, factors, draft):
        clauses = list(_clauses(self.state["clauses"]))
        if draft["kind"] == "introduce":
            clauses.append(tuple(factors))
            targets = self.population.crashes - self.score.covered
        else:
            clauses[draft["index"]] = tuple(factors)
            targets = self._required()
        prediction = self._predict(tuple(clauses), membership=True)
        if prediction is None:
            return None
        fired, trapped, signature = prediction
        # Introduction searches the unresolved population together. An anchor
        # with unavailable outcomes must not veto another case's actual repair.
        # Refinement still retains its immutable owners below.
        if not fired & targets:
            return None
        if not self._required() <= fired or trapped & self._required():
            return None
        false_positives = len(fired & self.population.normals)
        covered = len(fired & targets)
        rank = (false_positives, -covered, len(trapped), _cost((tuple(factors),)), tuple(factors))
        return rank, signature

    def _queue(self, draft):
        """Keep coverage, regression and case-membership roles, not outcomes."""
        pool, signatures = {}, {}
        seen = {tuple(row) for row in draft["seen"]}
        for parent in draft["beam"]:
            for atom in self.space.atoms:
                self.backend.check()
                if atom in parent:
                    continue
                factors = tuple(parent) + (atom,)
                if len(factors) > self.limits.max_factors or factors in seen:
                    continue
                proposal = self._proposal(factors, draft)
                if proposal is not None:
                    pool[factors], signatures[factors] = proposal
            if draft["kind"] == "refine":
                for index in range(len(parent)):
                    factors = tuple(parent[:index] + parent[index + 1:])
                    if factors in seen or not factors and self.family == "ERM CWE-805":
                        continue
                    proposal = self._proposal(factors, draft)
                    if proposal is not None:
                        pool[factors], signatures[factors] = proposal
        selected = self._diverse(list(pool), pool, signatures, self.limits.beam_width)
        return [list(row) for row in selected]

    def _start_draft(self, kind, anchor, *, index=None):
        factors = list(self.state["clauses"][index]["factors"]) if kind == "refine" else []
        initial = [factors] if kind == "introduce" and self.family == "ERM generic" else []
        self.state["draft"] = {"kind": kind, "anchor": anchor, "index": index,
                               "beam": [factors], "queue": initial, "offset": 0, "depth": 0,
                               "seen": [], "best": None,
                               "prediction_revision": self.state["prediction_revision"]}
        self._save()

    def _introduction_record(self, best):
        identifier = self.state["next_clause_id"]
        self.state["next_clause_id"] += 1
        return {"id": identifier,
                "factors": best["factors"], "introduced_factors": best["factors"],
                "prefix": [list(row) for row in _clauses(self.state["clauses"])],
                "prefix_evaluation": self.state["evaluation"],
                "owners": best["owners"], "introduction": best["evaluation"],
                "witnesses": best["witnesses"]}

    _BRANCH_KEYS = ("clauses", "evaluation", "phase", "blocked", "refine_index",
                    "refine_progress", "draft", "branch_prediction_revision", "exhausted_revision")

    def _branch(self):
        return copy.deepcopy({key: self.state[key] for key in self._BRANCH_KEYS})

    def _branch_key(self, branch):
        # Different owner partitions are different decompositions, even when
        # they happen to repair equally many cases. IDs are allocation details.
        return canonical([(row["factors"], row["owners"], row["prefix"], row["introduced_factors"])
                          for row in branch["clauses"]]).decode("utf-8")

    def _validate_branch(self, branch, evaluated, score):
        self._validate_incumbent(branch["clauses"], evaluated, score)
        revision = self.state["prediction_revision"]
        if (branch["phase"] not in ("cover", "refine")
                or not 0 <= branch["branch_prediction_revision"] <= revision
                or branch["exhausted_revision"] is not None and not 0 <= branch["exhausted_revision"] <= revision
                or not 0 <= branch["refine_index"] <= len(branch["clauses"])):
            raise ValueError("invalid checkpoint branch schedule")
        draft = branch["draft"]
        if draft is None:
            return
        if (draft["kind"] not in ("introduce", "refine")
                or not 0 <= draft["offset"] <= len(draft["queue"])
                or not 0 <= draft["depth"] <= self.limits.max_factors
                or not 0 <= draft["prediction_revision"] <= revision
                or len(draft["queue"]) > self.limits.beam_width
                or len(draft["beam"]) > self.limits.beam_width
                or any(len(row) > self.limits.max_factors for row in draft["queue"] + draft["beam"])):
            raise ValueError("invalid checkpoint draft schedule")
        if draft["kind"] == "refine":
            if not isinstance(draft["index"], int) or not 0 <= draft["index"] < len(branch["clauses"]):
                raise ValueError("invalid checkpoint refinement index")
        elif draft["best"] is not None:
            best = draft["best"]
            candidate = self.backend.load(best["evaluation"])
            after = Score.from_evaluation(self.population, candidate)
            prefix = _clauses(branch["clauses"])
            expression = self.space.expression(prefix + (tuple(best["factors"]),))
            expected = parse_candidate(self.family, expression)
            required = frozenset(owner for row in branch["clauses"] for owner in row["owners"])
            owners = new_owners(score, after)
            witnesses = self._witnesses(prefix, best["factors"], candidate, owners) if owners else None
            if (candidate["descriptor"] != expected.descriptor or not owners
                    or owners != frozenset(best["owners"]) or not required <= after.covered
                    or not self.population.normals <= after.known_normals
                    or witnesses is None or witnesses != best["witnesses"]):
                raise ValueError("draft introduction does not establish owners")

    def _result_rank(self, clauses, score):
        program = _clauses(clauses)
        return (len(self.population.crashes - score.covered), len(score.regressions),
                _cost(program), compose(self.family, program) or "")

    def _remember_best(self, clauses, score, reference):
        if (not self.population.normals <= score.known_normals
                or score.target_failures & self.population.normals):
            return
        saved = self.state["best_result"]
        if saved is not None and self._result_rank(clauses, score) >= self._result_rank(saved["clauses"], self.best_score):
            return
        self.state["best_result"] = {"clauses": copy.deepcopy(clauses), "evaluation": reference}
        self.best_score = score

    def _branch_score(self, branch):
        key = canonical(branch["evaluation"])
        if key not in self._scores:
            self._scores[key] = Score.from_evaluation(self.population, self.backend.load(branch["evaluation"]))
        return self._scores[key]

    @staticmethod
    def _diverse(pool, ranks, signatures, width, *, initial=()):
        """Coverage, regression and farthest-membership turns; stable ties."""
        coverage = sorted(pool, key=lambda key: (ranks[key][1], ranks[key][0], *ranks[key][2:]))
        regression = sorted(pool, key=ranks.__getitem__)
        selected, represented = [], list(initial)
        for turn in range(min(width, len(pool))):
            remaining = [key for key in pool if key not in selected]
            novel = [key for key in remaining if signatures[key] not in represented]
            choices = novel or remaining
            if turn % 3 == 2:
                chosen = min(choices, key=lambda key: (
                    -min((len(signatures[key] ^ other) for other in represented), default=0), ranks[key]))
            else:
                order = coverage if turn % 3 == 0 else regression
                chosen = next(key for key in order if key in choices)
            selected.append(chosen)
            represented.append(signatures[chosen])
        return selected

    def _retain(self, branch, *, continuation=False):
        """Retain at most beam_width-1 alternatives without reordering survivors."""
        if self.limits.beam_width <= 1:
            return
        key = self._branch_key(branch)
        revision = self.state["prediction_revision"]
        if not continuation and self.state["visited_branches"].get(key, -1) >= revision:
            return
        pool = list(self.state["pending"])
        for index, old in enumerate(pool):
            if self._branch_key(old) == key:
                pool[index] = branch
                break
        else:
            pool.append(branch)
        width = self.limits.beam_width - 1
        if len(pool) > width:
            # A saved draft is the opportunity to try another first clause,
            # not merely a worse zero-coverage incumbent. Reserve one slot.
            drafts = [index for index, row in enumerate(pool) if row["draft"] is not None]
            keep = drafts[:1]
            ranks, signatures = {}, {}
            for index, row in enumerate(pool):
                score = self._branch_score(row)
                ranks[index] = (len(score.regressions), -len(score.covered),
                                _cost(_clauses(row["clauses"])), self._branch_key(row))
                signatures[index] = (frozenset(("repair", case) for case in score.covered)
                                     | frozenset(("regression", case) for case in score.regressions)
                                     | frozenset(("failure", case) for case in score.target_failures)
                                     | frozenset((reason, case) for case, reason in score.ignored.items()))
            choices = [index for index in range(len(pool)) if index not in keep]
            keep += self._diverse(choices, ranks, signatures, width - len(keep),
                                  initial=[signatures[index] for index in keep])
            pool = [row for index, row in enumerate(pool) if index in keep]
        self.state["pending"] = pool
        if not continuation:
            self.state["visited_branches"][key] = revision

    def _rotate(self):
        revision = self.state["prediction_revision"]
        pending = self.state["pending"]
        index = next((index for index, row in enumerate(pending)
                      if row["exhausted_revision"] is None or row["exhausted_revision"] < revision), None)
        if index is None:
            return self.state["exhausted_revision"] is None
        branch = pending[index]
        evaluated = self.backend.load(branch["evaluation"])
        score = Score.from_evaluation(self.population, evaluated)
        previous = self._branch()
        pending.pop(index)
        pending.append(previous)
        self.state.update(branch)
        self.current, self.score = evaluated, score
        if self.state["branch_prediction_revision"] < revision:
            self.state.update(blocked=[], branch_prediction_revision=revision)
            if self.state["exhausted_revision"] is not None:
                self.state.update(exhausted_revision=None, phase="cover", refine_index=0, refine_progress=False)
        self._save()
        return True

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
        if self.state["draft"] is not None:
            continuation = self._branch()
            continuation["draft"]["best"] = None
            self._retain(continuation, continuation=True)
        self.state["clauses"].append(self._introduction_record(best))
        self.state["evaluation"] = best["evaluation"]
        self.current = current
        self.score = score
        self._remember_best(self.state["clauses"], score, best["evaluation"])
        self.state.update(draft=None, blocked=[], phase="cover", exhausted_revision=None,
                          revision=self.state["revision"] + 1)
        self.state["visited_branches"][self._branch_key(self.state)] = self.state["prediction_revision"]
        self._save(commit="introduce")

    def _refined_records(self, draft, factors, reference, local_reference, witnesses):
        records = copy.deepcopy(self.state["clauses"])
        records[draft["index"]]["factors"] = list(factors)
        records[draft["index"]]["refinement"] = {
            "evaluation": reference, "local_evaluation": local_reference, "witnesses": witnesses,
            "program": [list(row) for row in _clauses(records)], "required": sorted(self._required())}
        return records

    def _accept_refinement(self, draft, factors, result, reference, local_reference, witnesses):
        self.backend.check_operation()
        self._retain(self._branch(), continuation=True)
        self.state["clauses"] = self._refined_records(draft, factors, reference, local_reference, witnesses)
        self.state["evaluation"] = reference
        self.current = result
        self.score = Score.from_evaluation(self.population, result)
        self._remember_best(self.state["clauses"], self.score, reference)
        self.state.update(draft=None, refine_progress=True, revision=self.state["revision"] + 1)
        self.state["visited_branches"][self._branch_key(self.state)] = self.state["prediction_revision"]
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
        work = canonical([self._branch_key(self.state), draft["kind"], draft["index"], factors]).decode("utf-8")
        if self.state["visited_work"].get(work, -1) >= self.state["prediction_revision"]:
            draft["seen"].append(list(factors))
            draft["offset"] += 1
            self._save()
            return
        if draft["kind"] == "introduce":
            tested = self._run(program + (tuple(factors),))
            if tested is not None:
                score, result, reference = tested
                owners = new_owners(self.score, score)
                if (owners and self._required() <= score.covered
                        and self.population.normals <= score.known_normals
                        and not (score.target_failures & self.population.normals)):
                    witnesses = self._witnesses(program, factors, result, owners)
                    if witnesses is not None:
                        rank = (len(score.regressions), -len(owners), _cost((tuple(factors),)), tuple(factors))
                        old = draft["best"]
                        old_rank = (old["rank"][0], old["rank"][1], old["rank"][2], tuple(old["rank"][3])) if old else None
                        candidate = {"rank": list(rank), "factors": list(factors),
                                     "evaluation": reference, "owners": sorted(owners),
                                     "witnesses": witnesses}
                        records = self.state["clauses"] + [self._introduction_record(candidate)]
                        self._remember_best(records, score, reference)
                        if old_rank is None or rank < old_rank:
                            draft["best"] = candidate
                        # Consume this operation before forking. Its continuation
                        # must never accept the same cached candidate again.
                        draft["seen"].append(list(factors))
                        draft["offset"] += 1
                        self.state["visited_work"][work] = self.state["prediction_revision"]
                        if score.regressions <= self.score.regressions:
                            self._accept_introduction(candidate)
                        else:
                            child = self._branch()
                            child.update(clauses=copy.deepcopy(records), evaluation=reference,
                                         draft=None, phase="cover", blocked=[], refine_index=0,
                                         refine_progress=False, exhausted_revision=None,
                                         branch_prediction_revision=self.state["prediction_revision"])
                            self._retain(child)
                            self._save()
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
                            and self.population.normals <= score.known_normals
                            and not score.target_failures & self.population.normals):
                        records = self._refined_records(draft, factors, reference, local[2], witnesses)
                        self._remember_best(records, score, reference)
                        if improves(self.score, score, old_cost=_cost(program), new_cost=_cost(modified)):
                            draft["seen"].append(list(factors))
                            draft["offset"] += 1
                            self.state["visited_work"][work] = self.state["prediction_revision"]
                            self._accept_refinement(draft, factors, result, reference, local[2], witnesses)
                            return
        self.state["visited_work"][work] = self.state["prediction_revision"]
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

    def _authenticate_best(self):
        saved = self.state["best_result"]
        evaluated = self.backend.load(saved["evaluation"])
        score = Score.from_evaluation(self.population, evaluated)
        self._validate_incumbent(saved["clauses"], evaluated, score)
        self.backend.check_operation()
        self.best_score = score

    def _exhaustion_reason(self):
        score = self.best_score
        if (self.population.crashes <= score.covered and not score.regressions
                and not score.target_failures and score.complete(self.population)):
            return "observed-goals-met"
        if score.ignored or self.population.gaps:
            return "evidence-unavailable"
        if len(self.state["clauses"]) >= self.limits.max_clauses and self.population.crashes - score.covered:
            return "clause-budget-reached"
        return "bounded-search-exhausted"

    def run(self):
        try:
            # A completed journal resumes as the same answer, not a fresh beam.
            # An interruption, unlike an exhausted frontier, can continue work.
            if self.state["termination"] not in (None, "interrupted"):
                with self.backend.restoration():
                    self._authenticate_best()
                return self.result()
            self.state["termination"] = None
            if not self.population.crashes:
                self.state["termination"] = "no-target-cases" if not self.population.gaps else "evidence-unavailable"
                self._save()
            while self.state["termination"] is None:
                self.backend.check()
                if self.state["exhausted_revision"] is not None:
                    if not self._rotate():
                        self.state["termination"] = self._exhaustion_reason()
                        self._save()
                    continue
                if self.state["draft"] is not None:
                    self._step_draft()
                    self._rotate()
                elif self.state["phase"] == "cover":
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
                    self.state["exhausted_revision"] = self.state["prediction_revision"]
                    self._save()
                    self._rotate()
        except SearchStopped as stop:
            self.state["termination"] = stop.reason
            self._save()
        except KeyboardInterrupt:
            self.state["termination"] = "interrupted"
            self._save()
        if self.state["termination"] != "interrupted":
            try:
                # Selection is read-only authentication. In particular it does
                # not commit a draft, discard pending work or admit execution.
                with self.backend.restoration():
                    self._authenticate_best()
            except (SearchStopped, KeyboardInterrupt):
                self.state["termination"] = "interrupted"
                self._save()
        return self.result()

    def result(self, *, interrupted=False):
        if interrupted or self.state["termination"] == "interrupted":
            selected, score = self.state, self.score
        else:
            selected, score = self.state["best_result"], self.best_score
        clauses = _clauses(selected["clauses"])
        return {"schema_version": 1, "engine": "taosc-llm-no-llm",
                "dataset_id": self.backend.dataset.dataset_id,
                "termination": self.state["termination"], "verified": False,
                "binradar_verification": "not_run", "run_directory": str(self.journal.directory),
                "predicate": compose(self.family, clauses) if clauses else None,
                "clauses": copy.deepcopy(selected["clauses"]), "population": self.population.to_dict(),
                "evaluation": selected["evaluation"], "score": score.summary(self.population),
                "budgets": {"elapsed": self.backend.elapsed, "evaluations": self.backend.evaluations},
                "limits": self.limits.to_dict()}
