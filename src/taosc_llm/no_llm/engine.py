"""Bounded diverse sequential covering and owner-preserving refinement.

The crash-first result archive is independent of round-robin working branches.
Checkpoints retain each branch's draft and immutable proofs, but share capture
revisions, visited work and execution budgets. Predictions only schedule work.
"""
from __future__ import annotations

import copy
import re
from hashlib import sha256
from typing import NamedTuple

from ..collection_metrics import candidate_admission, compare_selection, selection_objective
from ..dataset import canonical
from ..family import parse_candidate
from .model import SearchStopped
from .score import Population, Score, improves, new_owners, preserves
from .space import Clause, Space, compose


class _Ranking(NamedTuple):
    before: tuple[Clause, ...]
    after: tuple[Clause, ...]
    targets: int
    required: int
    normals: int


class _Evaluation(NamedTuple):
    score: Score
    result: dict
    reference: dict
    snapshots: dict | None


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
                      "next_clause_id": 1, "cover_draft": None, "early_draft": None,
                      "early_index": 0, "cover_opportunities": 0,
                      "operator_evaluations": [], "operator_stats": {},
                      "work_counts": {"introduce": 0, "refine": 0,
                                      "lookahead_predictions": 0}}
        # The journal authenticates history; only the last complete state is
        # needed to restore the frontier.
        for event in reversed(self.journal.events):
            if event["kind"] in ("checkpoint", "commit"):
                self.state = self.journal.load(event["data"]["state"])
                break
        self.current = (self.baseline if self.state["evaluation"] == backend.baseline_ref
                        else backend.load(self.state["evaluation"]))
        self.score = Score.from_evaluation(self.population, self.current)
        self.space = Space(self.family, self._restore_predictions(), self.limits, check=backend.check_operation,
                           crashes=self.population.crashes, normals=self.population.normals)
        if self.state["atoms"]:
            if set(self.state["atoms"]) != set(self.space.atoms):
                raise ValueError("checkpoint atom corpus mismatch")
            self.space.atoms = tuple(self.state["atoms"])
        self._scores = {canonical(self.state["evaluation"]): self.score}
        self._validate_branch(self.state, self.current, self.score)
        if len(self.state["pending"]) >= self.limits.beam_width:
            raise ValueError("checkpoint exceeds branch beam")
        for branch in self.state["pending"]:
            evaluated = backend.load(branch["evaluation"])
            score = Score.from_evaluation(self.population, evaluated)
            self._scores[canonical(branch["evaluation"])] = score
            self._validate_branch(branch, evaluated, score)
        self.best_score = Score.from_evaluation(self.population, self.baseline)
        self.best_evaluation = self.baseline
        self.best_sets = None
        if self.state["best_result"] is not None:
            self._authenticate_best()
        self._validate_learning()

    def _restore_predictions(self):
        snapshots = self.backend.snapshots(self.baseline)
        references = self.state["prediction_evidence"]
        if not references:
            references.update({case: self.backend.baseline_ref for case in snapshots})
            return snapshots
        # Keep the baseline fallback and read each distinct durable evaluation
        # only once for this capture reconstruction, never across operations.
        loaded = {canonical(self.backend.baseline_ref): dict(snapshots)}
        for case, reference in references.items():
            self.backend.check_operation()
            key = canonical(reference)
            if key not in loaded:
                loaded[key] = self.backend.load_snapshots(reference)
            if case not in loaded[key]:
                raise ValueError("checkpoint prediction capture missing")
            snapshots[case] = loaded[key][case]
        return snapshots

    @staticmethod
    def _operator_families(program):
        families = set()
        for clause in program:
            for atom in clause:
                if "i->" in atom:
                    family = "containment" if "i->begin &&" in atom else "size"
                elif re.search(r"[/%]", atom):
                    family = "division"
                elif "<<" in atom or ">>" in atom:
                    family = "shift"
                elif re.search(r"[&|^~]", atom):
                    family = "bitwise"
                elif re.search(r"[+*]|(?<=[\w)])\s*-", atom):
                    family = "arithmetic"
                else:
                    family = "comparison"
                families.add(family)
        return sorted(families or {"constant"})

    @staticmethod
    def _learning_reward(before, after, result):
        # Learning is deliberately stricter than the independent final archive:
        # never reward lost observations or newly hidden responsibility evidence.
        return (candidate_admission(result)["status"] == "eligible"
                and before.selection["known"] <= after.selection["known"]
                and before.selection["branch_comparable"] <= after.selection["branch_comparable"]
                and set(after.ignored) <= set(before.ignored)
                and compare_selection(before.selection, after.selection)[0])

    @staticmethod
    def _tally_operator(stats, families, reward):
        for family in families:
            row = stats.setdefault(family, {"trials": 0, "improvements": 0})
            row["trials"] += 1
            row["improvements"] += int(reward)

    def _learn(self, program, result, score, reference):
        if self.limits.search_policy != "adaptive":
            return
        if any(row["descriptor"] == result["descriptor"] for row in self.state["operator_evaluations"]):
            return
        families = self._operator_families(program)
        reward = self._learning_reward(self.score, score, result)
        self.state["operator_evaluations"].append({
            "descriptor": result["descriptor"], "program": [list(row) for row in program],
            "evaluation": reference, "before": self.state["evaluation"],
            "families": families, "reward": reward})
        self._tally_operator(self.state["operator_stats"], families, reward)

    def _validate_learning(self):
        stats, descriptors = {}, set()
        for row in self.state["operator_evaluations"]:
            self.backend.check_operation()
            result = self.backend.load(row["evaluation"])
            before = Score.from_evaluation(self.population, self.backend.load(row["before"]))
            after = Score.from_evaluation(self.population, result)
            program = tuple(tuple(clause) for clause in row["program"])
            expected = parse_candidate(self.family, self.space.expression(program))
            families = self._operator_families(program)
            reward = self._learning_reward(before, after, result)
            if (row["descriptor"] in descriptors or row["descriptor"] != result["descriptor"]
                    or expected.descriptor != result["descriptor"]
                    or row["families"] != families or row["reward"] is not reward):
                raise ValueError("checkpoint operator learning evidence mismatch")
            descriptors.add(row["descriptor"])
            self._tally_operator(stats, families, reward)
        if (stats != self.state["operator_stats"]
                or self.limits.search_policy != "adaptive" and stats
                or set(self.state["work_counts"]) != {"introduce", "refine", "lookahead_predictions"}
                or any(type(value) is not int or value < 0 for value in self.state["work_counts"].values())):
            raise ValueError("invalid checkpoint guided search counters")

    def _operator_priority(self, factors):
        stats = self.state["operator_stats"]
        # Integer arithmetic makes priority and ties reproducible on resume.
        return max((1024 * stats[family]["improvements"] // stats[family]["trials"]
                    for family in self._operator_families((factors,)) if family in stats), default=0)

    def _validate_archive(self, saved, evaluated, score):
        """Bind an evaluated program independently of optional search proofs."""
        program = tuple(tuple(row) for row in saved["program"])
        expression = self.space.expression(program)
        expected = parse_candidate(self.family, expression)
        if (evaluated["predicate"] != expected.expression
                or evaluated["descriptor"] != expected.descriptor
                or saved["predicate"] != expected.expression):
            raise ValueError("checkpoint archive expression/evidence mismatch")
        if saved["clauses"]:
            if _clauses(saved["clauses"]) != program:
                raise ValueError("checkpoint archive proof program mismatch")
            self._validate_incumbent(saved["clauses"], evaluated, score, saved["evaluation"])

    def _validate_incumbent(self, clauses, current, score, reference):
        """A durable checkpoint is not itself proof of ownership or execution."""
        def load(evidence):
            return current if evidence == reference else self.backend.load(evidence)

        self.space.expression(_clauses(clauses))
        required = set()
        ids = set()
        for clause in clauses:
            self.backend.check_operation()
            owners = frozenset(clause["owners"])
            if (not owners or not owners <= self.population.crashes or owners & required
                    or clause["id"] in ids):
                raise ValueError("invalid checkpoint clause ownership")
            ids.add(clause["id"])
            required.update(owners)
            prefix = tuple(tuple(row) for row in clause["prefix"])
            if len(prefix) != len(ids) - 1:
                raise ValueError("checkpoint introduction prefix length mismatch")
            before = load(clause["prefix_evaluation"])
            introduced = load(clause["introduction"])
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
            if (not (required - owners) <= before_score.covered
                    or not required <= introduction_score.covered
                    or new_owners(before_score, introduction_score) != owners):
                raise ValueError("checkpoint introduction does not establish owners")
            introduction_witnesses = self._witnesses(prefix, clause["introduced_factors"], introduced, owners)
            if introduction_witnesses is None or introduction_witnesses != clause["witnesses"]:
                raise ValueError("checkpoint introduction witness mismatch")
            refinement = clause.get("refinement")
            if refinement is not None:
                local = load(refinement["local_evaluation"])
                global_result = (local if refinement["evaluation"] == refinement["local_evaluation"]
                                 else load(refinement["evaluation"]))
                refined_program = tuple(tuple(row) for row in refinement["program"])
                matches(global_result, refined_program)
                global_score = Score.from_evaluation(self.population, global_result)
                historical_owners = frozenset(owner for row in clauses[:len(refined_program)] for owner in row["owners"])
                if (not len(ids) <= len(refined_program) <= len(clauses)
                        or refined_program[len(ids) - 1] != tuple(clause["factors"])
                        or frozenset(refinement["required"]) != historical_owners
                        or not historical_owners <= global_score.covered):
                    raise ValueError("checkpoint refinement lost global owners")
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
        result, reference = self.backend.evaluate(expression)
        score = Score.from_evaluation(self.population, result)
        self._scores[canonical(reference)] = score
        self._learn(clauses, result, score, reference)
        self._archive(clauses, result, score, reference)
        # At most one entry per admitted descriptor (bounded by the evaluation
        # budget). Reusing an old outcome must not roll prediction state back to
        # that descriptor's earlier capture or restart an exhausted frontier.
        snapshots = None
        if result["descriptor"] not in self.state["processed_evaluations"]:
            snapshots = self.backend.snapshots(result)
            revision = self.space.revision
            self.space.update(snapshots)
            if self.space.revision != revision:
                self.state["prediction_revision"] += 1
                self.state.update(blocked=[], termination=None, exhausted_revision=None,
                                  early_index=self._early_cursor(),
                                  branch_prediction_revision=self.state["prediction_revision"])
            self.state["prediction_evidence"].update({case: reference for case in snapshots})
            self.state["processed_evaluations"].append(result["descriptor"])
        return _Evaluation(score, result, reference, snapshots)

    def _witnesses(self, prefix, factors, result, owners, *, captures=None):
        """A repair hit must exclude the frozen prefix's remaining safe path.

        For CWE this compares whole same-clamp trees, never per-clause reduced
        jump flags. One complete actual hit with prefix=0 and composed=1 is the
        marginal witness; real paired outcomes establish the case contribution.
        """
        from binradar.binradar_taosc_predicates import evaluate_cached_predicate, prepare_generic_environments
        prefix_source = compose(self.family, prefix)
        prefix_parsed = parse_candidate(self.family, prefix_source).parsed if prefix_source is not None else None
        full = parse_candidate(self.family, compose(self.family, prefix + (tuple(factors),))).parsed
        if captures is None:
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

    def _ranking(self, draft):
        clauses = _clauses(self.state["clauses"])
        required = self.space.case_mask(self._required())
        normals = self.space.case_mask(self.population.normals)
        if draft["kind"] == "introduce":
            targets = self.space.case_mask(self.population.crashes - self.score.covered)
            return _Ranking(clauses, (), targets, required, normals)
        index = draft["index"]
        return _Ranking(clauses[:index], clauses[index + 1:], required, required, normals)

    def _rank(self, factors, draft):
        proposal = self._proposal(tuple(factors), self._ranking(draft))
        return proposal[0] if proposal is not None else None

    def _proposal(self, factors, ranking):
        try:
            fired, trapped, signature = self.space.branch_membership(ranking.before + (factors,) + ranking.after)
        except ValueError:
            return None
        # Introduction searches the unresolved population together. An anchor
        # with unavailable outcomes must not veto another case's actual repair.
        # Firing excludes any case with a trap, including mixed fire/trap traces.
        covered = fired & ranking.targets
        if not covered or ranking.required & ~fired:
            return None
        rank = ((fired & ranking.normals).bit_count(), -covered.bit_count(), trapped.bit_count(),
                _cost((factors,)), factors)
        return rank, signature

    def _queue(self, draft):
        """Keep coverage, regression and case-membership roles, not outcomes."""
        pool, signatures = {}, {}
        seen = {tuple(row) for row in draft["seen"]}
        ranking = self._ranking(draft)
        for row in draft["beam"]:
            parent = tuple(row)
            for atom in self.space.atoms:
                self.backend.check()
                if atom in parent:
                    continue
                factors = parent + (atom,)
                if len(factors) > self.limits.max_factors or factors in seen:
                    continue
                proposal = self._proposal(factors, ranking)
                if proposal is not None:
                    pool[factors], signatures[factors] = proposal
            if draft["kind"] == "refine":
                for index in range(len(parent)):
                    factors = parent[:index] + parent[index + 1:]
                    if factors in seen or not factors and self.family == "ERM CWE-805":
                        continue
                    proposal = self._proposal(factors, ranking)
                    if proposal is not None:
                        pool[factors], signatures[factors] = proposal
        if self.limits.search_policy in ("composed", "adaptive"):
            self._lookahead(pool, signatures, seen, ranking)
        selected = self._shortlist(pool, signatures, self.limits.beam_width)
        return [list(row) for row in selected]

    def _shortlist(self, ranks, signatures, width):
        pool = list(ranks)
        selected = self._diverse(pool, ranks, signatures, width, xor_size=int.bit_count)
        if self.limits.search_policy == "adaptive" and pool and width:
            # One exploitation slot in four; all other slots retain the original
            # coverage/regression/membership exploration roles. A width-one
            # beam receives the same floor over consecutive durable proposals.
            turn = sum(self.state["work_counts"][kind] for kind in ("introduce", "refine"))
            slots = range(3, len(selected), 4) if width >= 4 else ([len(selected) - 1] if turn % 4 == 3 else [])
            for slot in slots:
                choices = [row for row in pool if row not in selected or row == selected[slot]]
                selected[slot] = min(choices, key=lambda row: (-self._operator_priority(row), ranks[row]))
        return selected

    def _lookahead(self, pool, signatures, seen, ranking):
        """Predict at most four beam-squared ordered extensions, never atoms^3.

        Whole programs go through Space, including same-hit conjunctions and
        same-clamp CWE trees. Reverse extensions are separate proposals, not
        commutation: a guard before a dangerous factor may be the only safe one.
        Sample-equivalent expressions remain available on later rounds.
        """
        width = self.limits.beam_width
        seeds = self._shortlist(pool, signatures, width)
        leaves = list(dict.fromkeys(atom for row in seeds for atom in row))[:width]
        cap = min(3, self.limits.max_factors)
        predictions = 0
        for _ in range(2):
            extensions, memberships = {}, {}
            for seed in seeds:
                if len(seed) >= cap:
                    continue
                for atom in leaves:
                    if atom in seed:
                        continue
                    for factors in (seed + (atom,), (atom,) + seed):
                        self.backend.check()
                        if factors in seen or factors in pool or factors in extensions:
                            continue
                        predictions += 1
                        proposal = self._proposal(factors, ranking)
                        if proposal is not None:
                            extensions[factors], memberships[factors] = proposal
            seeds = self._shortlist(extensions, memberships, width)
            pool.update(extensions)
            signatures.update(memberships)
            if not seeds:
                break
        self.state["work_counts"]["lookahead_predictions"] += predictions

    def _start_draft(self, kind, anchor, *, index=None):
        factors = list(self.state["clauses"][index]["factors"]) if kind == "refine" else []
        initial = [factors] if kind == "introduce" and self.family == "ERM generic" else []
        self.state["draft"] = {"kind": kind, "anchor": anchor, "index": index,
                               "beam": [factors], "queue": initial, "offset": 0, "depth": 0,
                               "seen": [], "best": None, "attempt": None,
                               "prediction_revision": self.state["prediction_revision"]}
        self._save()

    def _early_cursor(self):
        draft = self.state["draft"] if self.state["cover_draft"] is not None else self.state["early_draft"]
        return draft["index"] if draft is not None else 0

    def _step_scheduled_draft(self):
        # A suspended cover draft is durable even if interruption lands during
        # local/global validation or immediately after the refinement commit.
        if self.state["cover_draft"] is not None:
            if self.state["draft"] is not None:
                self._step_draft()
            self.state["early_draft"] = self.state["draft"]
            self.state["draft"] = self.state["cover_draft"]
            self.state["cover_draft"] = None
            self._save()
            return
        draft = self.state["draft"]
        early = (draft["kind"] == "introduce" and self.score.regressions
                 and self.state["early_index"] < len(self.state["clauses"])
                 and self.limits.search_policy in ("refine", "balanced", "composed", "adaptive"))
        if early and draft["attempt"] is None and self.state["cover_opportunities"] % 4 == 3:
            self.state["cover_opportunities"] += 1
            self.state["cover_draft"] = draft
            self.state["draft"] = self.state["early_draft"]
            self.state["early_draft"] = None
            if self.state["draft"] is None:
                index = self.state["early_index"]
                self._start_draft("refine", self.state["clauses"][index]["owners"][0], index=index)
            else:
                self._save()
            self._step_scheduled_draft()
            return
        self._step_draft()

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
                    "refine_progress", "draft", "branch_prediction_revision", "exhausted_revision",
                    "cover_draft", "early_draft", "early_index", "cover_opportunities")

    def _branch(self):
        # Rotation transfers the schedule. Clause proof records are read-only;
        # introducing or refining a clause replaces the outer list.
        return {key: self.state[key] for key in self._BRANCH_KEYS}

    def _fork_branch(self):
        branch = self._branch()
        for key in ("draft", "cover_draft", "early_draft"):
            draft = branch[key]
            if draft is not None:
                # Queue/beam/best values are replaced, but seen grows in place.
                branch[key] = {**draft, "seen": list(draft["seen"])}
        return branch

    @staticmethod
    def _branch_identity(branch):
        # Different owner partitions are different decompositions, even when
        # they happen to repair equally many cases. IDs are allocation details.
        return canonical([(row["factors"], row["owners"], row["prefix"], row["introduced_factors"])
                          for row in branch["clauses"]])

    def _branch_key(self, branch):
        return sha256(self._branch_identity(branch)).hexdigest()

    def _work_key(self, branch, draft):
        return sha256(canonical([self._branch_key(branch), draft["kind"], draft["index"],
                                 draft["queue"][draft["offset"]]])).hexdigest()

    def _validate_branch(self, branch, evaluated, score):
        self._validate_incumbent(branch["clauses"], evaluated, score, branch["evaluation"])
        revision = self.state["prediction_revision"]
        if (branch["phase"] not in ("cover", "refine")
                or not 0 <= branch["branch_prediction_revision"] <= revision
                or branch["exhausted_revision"] is not None and not 0 <= branch["exhausted_revision"] <= revision
                or not 0 <= branch["refine_index"] <= len(branch["clauses"])
                or type(branch["early_index"]) is not int
                or not 0 <= branch["early_index"] <= len(branch["clauses"])
                or type(branch["cover_opportunities"]) is not int or branch["cover_opportunities"] < 0):
            raise ValueError("invalid checkpoint branch schedule")
        if (branch["cover_draft"] is not None
                and (branch["cover_draft"]["kind"] != "introduce"
                     or branch["draft"] is not None and branch["draft"]["kind"] != "refine"
                     or branch["early_draft"] is not None)
                or branch["early_draft"] is not None and branch["early_draft"]["kind"] != "refine"):
            raise ValueError("invalid checkpoint suspended draft schedule")
        for draft in (branch["draft"], branch["cover_draft"], branch["early_draft"]):
            if draft is not None:
                self._validate_draft(draft, branch, score, revision)

    def _validate_draft(self, draft, branch, score, revision):
        if (draft["kind"] not in ("introduce", "refine")
                or not 0 <= draft["offset"] <= len(draft["queue"])
                or not 0 <= draft["depth"] <= self.limits.max_factors
                or not 0 <= draft["prediction_revision"] <= revision
                or len(draft["queue"]) > self.limits.beam_width
                or len(draft["beam"]) > self.limits.beam_width
                or any(len(row) > self.limits.max_factors for row in draft["queue"] + draft["beam"])):
            raise ValueError("invalid checkpoint draft schedule")
        if draft["attempt"] is not None:
            if draft["offset"] >= len(draft["queue"]):
                raise ValueError("invalid checkpoint counted proposal")
            if draft["attempt"] != self._work_key(branch, draft):
                raise ValueError("checkpoint counted proposal mismatch")
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
                    or witnesses is None or witnesses != best["witnesses"]):
                raise ValueError("draft introduction does not establish owners")

    def _archive(self, program, result, score, reference):
        # Reject only final promotion: the evaluated draft and its ordered
        # factors still participate in ownership and bounded continuation work.
        if candidate_admission(result)["status"] != "eligible":
            if (self.state["best_result"] is not None
                    and self.best_evaluation["descriptor"] == result["descriptor"]):
                # New evidence for the incumbent cannot leave its older,
                # apparently eligible observation selected.
                self.state["best_result"] = None
                self.best_evaluation = self.baseline
                self.best_score = Score.from_evaluation(self.population, self.baseline)
                self.best_sets = None
            return
        after = score.selection
        accepted, _ = compare_selection(self.best_sets, after)
        if not accepted:
            return
        self.state["best_result"] = {
            "program": [list(row) for row in program], "predicate": result["predicate"],
            "clauses": [], "evaluation": reference}
        self.best_score, self.best_evaluation, self.best_sets = score, result, after

    def _remember_proofs(self, clauses, reference):
        """Attach established search proofs without changing observed selection."""
        saved = self.state["best_result"]
        if (saved is not None and saved["evaluation"] == reference
                and tuple(tuple(row) for row in saved["program"]) == _clauses(clauses)
                and not saved["clauses"]):
            saved["clauses"] = copy.deepcopy(clauses)

    def _branch_score(self, branch):
        key = canonical(branch["evaluation"])
        if key not in self._scores:
            self._scores[key] = Score.from_evaluation(self.population, self.backend.load(branch["evaluation"]))
        return self._scores[key]

    @staticmethod
    def _diverse(pool, ranks, signatures, width, *, initial=(), xor_size=len):
        """Coverage, regression and farthest-membership turns; stable ties."""
        coverage = sorted(pool, key=lambda key: (ranks[key][1], ranks[key][0], *ranks[key][2:]))
        regression = sorted(pool, key=ranks.__getitem__)
        selected, taken, represented = [], set(), set(initial)
        for turn in range(min(width, len(pool))):
            remaining = [key for key in pool if key not in taken]
            novel = [key for key in remaining if signatures[key] not in represented]
            choices = novel or remaining
            if turn % 3 == 2:
                chosen = min(choices, key=lambda key: (
                    -min((xor_size(signatures[key] ^ other) for other in represented), default=0), ranks[key]))
            else:
                order = coverage if turn % 3 == 0 else regression
                allowed = set(choices)
                chosen = next(key for key in order if key in allowed)
            selected.append(chosen)
            taken.add(chosen)
            represented.add(signatures[chosen])
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
                                _cost(_clauses(row["clauses"])), self._branch_identity(row))
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
            self.state.update(blocked=[], branch_prediction_revision=revision,
                              early_index=self._early_cursor())
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
                or not self._required() <= score.covered):
            raise ValueError("draft introduction does not establish owners")
        witnesses = self._witnesses(prefix, best["factors"], current, owners)
        if witnesses is None or witnesses != best["witnesses"]:
            raise ValueError("draft introduction does not establish owners")
        self._commit_introduction(best, current, score)

    def _commit_introduction(self, best, current, score):
        self.backend.check_operation()
        if self.state["draft"] is not None:
            continuation = self._fork_branch()
            continuation["draft"]["best"] = None
            self._retain(continuation, continuation=True)
        self.state["clauses"] = self.state["clauses"] + [self._introduction_record(best)]
        self.state["evaluation"] = best["evaluation"]
        self.current = current
        self.score = score
        self._remember_proofs(self.state["clauses"], best["evaluation"])
        self.state.update(draft=None, blocked=[], phase="cover", exhausted_revision=None,
                          early_draft=None, early_index=0,
                          revision=self.state["revision"] + 1)
        self.state["visited_branches"][self._branch_key(self.state)] = self.state["prediction_revision"]
        self._save(commit="introduce")

    def _refined_records(self, draft, factors, reference, local_reference, witnesses):
        records = list(self.state["clauses"])
        index = draft["index"]
        record = records[index] = {**records[index], "factors": list(factors)}
        record["refinement"] = {
            "evaluation": reference, "local_evaluation": local_reference, "witnesses": witnesses,
            "program": [list(row) for row in _clauses(records)], "required": sorted(self._required())}
        return records

    def _accept_refinement(self, draft, records, tested):
        self.backend.check_operation()
        self._retain(self._fork_branch(), continuation=True)
        self.state["clauses"] = records
        self.state["evaluation"] = tested.reference
        self.current = tested.result
        self.score = tested.score
        self._remember_proofs(records, tested.reference)
        if self.state["cover_draft"] is not None:
            # Its queue/offset are still useful, but an introduction proof is
            # relative to the old frozen prefix and cannot survive this commit.
            self.state["cover_draft"]["best"] = None
        self.state.update(draft=None, early_draft=None, early_index=draft["index"],
                          refine_progress=True, revision=self.state["revision"] + 1)
        self.state["visited_branches"][self._branch_key(self.state)] = self.state["prediction_revision"]
        self._save(commit="refine")

    def _try_refinement(self, draft, program, factors, work):
        index = draft["index"]
        clause = self.state["clauses"][index]
        prefix = tuple(tuple(row) for row in clause["prefix"])
        replacement = (tuple(factors),)
        local_program = prefix + replacement
        local = self._run(local_program)
        owners = frozenset(clause["owners"])
        if local is None or not owners <= local.score.covered:
            return False
        witnesses = self._witnesses(prefix, factors, local.result, clause["owners"], captures=local.snapshots)
        if witnesses is None:
            return False
        self.backend.check_operation()
        modified = program[:index] + replacement + program[index + 1:]
        tested = local if modified == local_program else self._run(modified)
        if tested is None or not preserves(owners, local.score, self._required(), tested.score):
            return False
        records = self._refined_records(draft, factors, tested.reference, local.reference, witnesses)
        self._remember_proofs(records, tested.reference)
        if not improves(self.score, tested.score, old_cost=_cost(program), new_cost=_cost(modified)):
            return False
        self._consume_proposal(draft, work)
        self._accept_refinement(draft, records, tested)
        return True

    def _consume_proposal(self, draft, work=None):
        if work is not None:
            self.state["visited_work"][work] = self.state["prediction_revision"]
        draft["seen"].append(list(draft["queue"][draft["offset"]]))
        draft["offset"] += 1
        draft["attempt"] = None

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
            draft["beam"] = draft["queue"]
            self._save()
        factors = draft["queue"][draft["offset"]]
        program = _clauses(self.state["clauses"])
        work = self._work_key(self.state, draft)
        if self.state["visited_work"].get(work, -1) >= self.state["prediction_revision"]:
            self._consume_proposal(draft)
            self._save()
            return
        if draft["attempt"] != work:
            draft["attempt"] = work
            self.state["work_counts"][draft["kind"]] += 1
            if draft["kind"] == "introduce":
                self.state["cover_opportunities"] += 1
            self._save()
        if draft["kind"] == "introduce":
            tested = self._run(program + (tuple(factors),))
            if tested is not None:
                score, result, reference, snapshots = tested
                owners = new_owners(self.score, score)
                if owners and self._required() <= score.covered:
                    witnesses = self._witnesses(program, factors, result, owners, captures=snapshots)
                    if witnesses is not None:
                        rank = (len(score.regressions), -len(owners), _cost((tuple(factors),)), tuple(factors))
                        old = draft["best"]
                        old_rank = (old["rank"][0], old["rank"][1], old["rank"][2], tuple(old["rank"][3])) if old else None
                        candidate = {"rank": list(rank), "factors": list(factors),
                                     "evaluation": reference, "owners": sorted(owners),
                                     "witnesses": witnesses}
                        records = self.state["clauses"] + [self._introduction_record(candidate)]
                        self._remember_proofs(records, reference)
                        if old_rank is None or rank < old_rank:
                            draft["best"] = candidate
                        # Consume this operation before forking. Its continuation
                        # must never accept the same cached candidate again.
                        self._consume_proposal(draft, work)
                        if score.regressions <= self.score.regressions:
                            self._commit_introduction(candidate, result, score)
                        else:
                            child = self._branch()
                            child.update(clauses=records, evaluation=reference,
                                         draft=None, phase="cover", blocked=[], refine_index=0,
                                         refine_progress=False, exhausted_revision=None,
                                         early_draft=None, early_index=0, cover_draft=None,
                                         branch_prediction_revision=self.state["prediction_revision"])
                            self._retain(child)
                            self._save()
                        return
        elif self._try_refinement(draft, program, factors, work):
            return
        self._consume_proposal(draft, work)
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
        elif self.state["cover_draft"] is not None:
            self.state["early_index"] = draft["index"] + 1
        else:
            self.state["refine_index"] += 1
            self.state["early_index"] = max(self.state["early_index"], self.state["refine_index"])
        self.state["draft"] = None
        self._save()

    def _authenticate_best(self):
        saved = self.state["best_result"]
        if saved is None:
            return
        evaluated = self.backend.load(saved["evaluation"])
        score = Score.from_evaluation(self.population, evaluated)
        self._validate_archive(saved, evaluated, score)
        if candidate_admission(evaluated)["status"] != "eligible":
            raise ValueError("checkpoint archive rejected predicate trap")
        self.backend.check_operation()
        self.best_score, self.best_evaluation = score, evaluated
        self.best_sets = score.selection
        self._scores[canonical(saved["evaluation"])] = score

    def _exhaustion_reason(self):
        score = self.best_score
        if (self.best_sets is not None
                and self.population.crashes <= score.covered and not score.regressions
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
                if self.state["draft"] is not None or self.state["cover_draft"] is not None:
                    self._step_scheduled_draft()
                    self._rotate()
                elif self.state["phase"] == "cover":
                    outstanding = sorted(self.population.crashes - self.score.covered - set(self.state["blocked"]))
                    if outstanding and len(self.state["clauses"]) < self.limits.max_clauses:
                        self._start_draft("introduce", outstanding[0])
                    else:
                        self.state.update(phase="refine", refine_index=self.state["early_index"],
                                          refine_progress=False)
                        self._save()
                elif self.state["refine_index"] < len(self.state["clauses"]):
                    index = self.state["refine_index"]
                    if self.state["early_draft"] is not None:
                        self.state["draft"] = self.state["early_draft"]
                        self.state["early_draft"] = None
                        self._save()
                    else:
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
            selected, score, evaluated = self.state, self.score, self.current
            program = _clauses(selected["clauses"])
            predicate = compose(self.family, program) if program else None
        elif self.state["best_result"] is not None:
            selected, score, evaluated = self.state["best_result"], self.best_score, self.best_evaluation
            program = tuple(tuple(row) for row in selected["program"])
            predicate = selected["predicate"]
        else:
            predicate = None
        if predicate is None or candidate_admission(evaluated)["status"] != "eligible":
            # A useful working branch may contain known traps outside its
            # owners. It is never a fallback final candidate.
            selected = {"clauses": [], "evaluation": self.backend.baseline_ref}
            score, evaluated = Score.from_evaluation(self.population, self.baseline), self.baseline
            program, predicate = (), None
        return {"schema_version": 1, "engine": "taosc-llm-no-llm",
                "dataset_id": self.backend.dataset.dataset_id,
                "termination": self.state["termination"], "verified": False,
                "binradar_verification": "not_run", "run_directory": str(self.journal.directory),
                "predicate": predicate, "program": [list(row) for row in program],
                "admission": candidate_admission(evaluated if predicate is not None else None),
                "publication_status": "not_published" if predicate is not None else "no_candidate",
                "clauses": copy.deepcopy(selected["clauses"]), "population": self.population.to_dict(),
                "evaluation": selected["evaluation"], "score": score.summary(self.population),
                "objective": selection_objective(evaluated if predicate is not None else None),
                "budgets": {"elapsed": self.backend.elapsed, "evaluations": self.backend.evaluations},
                "search_diagnostics": {**self.state["work_counts"],
                                       "evaluated_programs": len(self.state["processed_evaluations"]),
                                       "operator_stats": copy.deepcopy(self.state["operator_stats"])},
                "limits": self.limits.to_dict()}
