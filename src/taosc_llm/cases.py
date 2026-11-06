"""Deterministic, read-only discovery within a host-selected case population."""
from __future__ import annotations

import operator
import re

from binradar.binradar_taosc_predicates import REGISTER_TO_VAR, wrap64

from .evidence import project_case

COMPARISONS = {"eq": operator.eq, "ne": operator.ne, "lt": operator.lt,
               "le": operator.le, "gt": operator.gt, "ge": operator.ge}
SIMILAR_FEATURES = ("mutation_shape", "branch_pattern", "oracle", "candidate_outcome", "domain")


def case_order(case_id):
    domain, _, number = case_id.partition(":")
    return domain, int(number) if number.isdecimal() else -1, case_id


def resolve_case(dataset, case_id):
    """Resolve prepared cases and the one sanctioned frozen-POC input."""
    try:
        return dataset.case(case_id)
    except ValueError:
        from .poc import poc_case
        case = poc_case(dataset)
        if case is not None and case['id'] == case_id:
            return case
        raise ValueError('unknown scoped case id') from None


def case_records(dataset, evaluation=None):
    """A result admits only prepared cases or the authenticated frozen POC."""
    records = []
    if evaluation is None:
        items = ((case, None) for case in dataset.cases())
    else:
        items = ((resolve_case(dataset, item["case_id"]), item) for item in evaluation.get("cases", []))
    for case, evaluated in items:
        report = evaluated.get("report") if evaluated else None
        records.append({"case": case, "evaluated": evaluated, "dataset": dataset,
                        "report": report if report is not None else project_case(dataset, case, evaluated,
                            descriptor=(evaluation or {}).get("descriptor"), predicate=(evaluation or {}).get("predicate"))})
    return records


def _capture(record):
    evaluated = record["evaluated"]
    return (evaluated if evaluated is not None else record["case"]).get("capture")


def _states(dataset, record):
    if "states" not in record:
        from .evaluation import _snapshots
        capture = _capture(record)
        # Candidate states are evidence only after requested-vector authentication;
        # a valid representative capture alone does not establish equivalence.
        if record["evaluated"] is not None and record["report"]["activation"]["status"] == "unknown":
            record["states"] = None
            return None
        try:
            record["states"] = _snapshots(dataset, capture) if capture is not None else None
        except (ValueError, OSError, KeyError, TypeError):
            record["states"] = None
    return record["states"]


def _mutation(record):
    if "mutation" not in record:
        mutation = record["report"].get("mutation", {})
        if mutation.get("truncated") or any(write.get("value_truncated") for write in mutation.get("writes", [])):
            from .evidence import mutation_provenance
            mutation = mutation_provenance(record["dataset"], record["case"])
        record["mutation"] = mutation
    return record["mutation"]


def _feature(dataset, record, name):
    report = record["report"]
    if name == "mutation_shape":
        mutation = _mutation(record)
        writes = mutation.get("writes")
        if not isinstance(writes, list) or mutation.get("status") != "available":
            return None
        return tuple(tuple(write.get(k) for k in ("kind", "size", "value", "target_extent"))
                     for write in writes)
    if name == "branch_pattern":
        states = _states(dataset, record)
        return tuple(state.branch for state in states) if states is not None else None
    if name == "oracle":
        oracle = report.get("oracle", {})
        target = oracle.get("target")
        if target is None:
            return None
        return (oracle.get("oracle_id"), oracle.get("artifact_sha256"),
                tuple(target.get(k) for k in ("address", "source", "image", "offset")))
    if name == "candidate_outcome":
        outcome = report.get("candidate", {}).get("outcome", "unknown")
        return outcome if outcome != "unknown" else None
    if name == "domain":
        return report["domain"]
    raise ValueError("unknown similarity feature")


def _register_matches(dataset, record, request):
    value = request["value"]
    if not re.fullmatch(r"-?(?:0|[1-9][0-9]*)", value):
        raise ValueError("register comparison requires a signed decimal integer")
    integer = int(value)
    if not -(1 << 63) <= integer < (1 << 63):
        raise ValueError("register comparison is outside signed 64-bit range")
    hit = request["hit"]
    if hit == "first_divergence":
        evaluated = record["evaluated"] or {}
        index, reference = evaluated.get("first_divergence"), evaluated.get("offline_reference")
        if index is None or reference is None:
            return False
        from .evaluation import _snapshots
        try:
            states = _snapshots(dataset, reference)[index:index + 1]
        except (ValueError, OSError, KeyError, TypeError):
            return False
    else:
        states = _states(dataset, record)
        if states is not None and hit == "first":
            states = states[:1]
    if not states:
        return False
    compare = COMPARISONS[request["op"]]
    slot = REGISTER_TO_VAR[request["register"]]
    matches = (compare(wrap64(state.registers[slot]), integer) for state in states)
    return all(matches) if hit == "all" else any(matches)


def select_cases(dataset, records, domain="all", filters=None, same_as=None):
    """No arbitrary expression language or execution side effects in retrieval."""
    filters = filters or {}
    register = filters.get("register")
    # Validate even an empty population: invalid searches never succeed vacuously.
    if register:
        value = register["value"]
        if not re.fullmatch(r"-?(?:0|[1-9][0-9]*)", value) or not -(1 << 63) <= int(value) < (1 << 63):
            raise ValueError("register comparison requires a signed 64-bit decimal integer")
    reference = None
    features = {}
    if same_as:
        reference = next((r for r in records if r["report"]["case_id"] == same_as["case_id"]), None)
        if reference is None:
            raise KeyError("similarity case is outside this result")
        features = {name: _feature(dataset, reference, name) for name in same_as["features"]}
        missing = [name for name, value in features.items() if value is None]
        if missing:
            raise ValueError("similarity reference has no evidence for: " + ", ".join(missing))
    selected = []
    for record in records:
        report = record["report"]
        if domain != "all" and report["domain"] != domain:
            continue
        candidate = report.get("candidate", {})
        neutral = report.get("neutral_baseline", {})
        pairs = (("candidate_outcome", candidate.get("outcome", "unknown")),
                 ("baseline_outcome", neutral.get("outcome", "unknown")),
                 ("activation", report.get("activation", {}).get("status", "unknown")))
        if any(name in filters and filters[name] != actual for name, actual in pairs):
            continue
        if register and not _register_matches(dataset, record, register):
            continue
        mutation_filter = filters.get("mutation")
        if mutation_filter:
            writes = _mutation(record).get("writes", [])
            if not any(all(write.get(k) == value for k, value in mutation_filter.items()) for write in writes):
                continue
        if reference is not None:
            if record is reference or any(_feature(dataset, record, name) != value for name, value in features.items()):
                continue
        selected.append(record)
    return selected


def relevant_registers(dataset, record, predicate):
    """Bounded examples from actual captures, never guessed register semantics."""
    names = [name for name in REGISTER_TO_VAR if re.search(r"\b" + name + r"\b", predicate or "")]
    if not names:
        return None
    states = _states(dataset, record)
    if states is None:
        return None
    return {"basis": "candidate_capture" if record["evaluated"] is not None else "prepared_capture",
            "hits": [{"hit_index": index, "registers": {
                name: str(wrap64(state.registers[REGISTER_TO_VAR[name]])) for name in names}}
                     for index, state in enumerate(states[:2])],
            "total_hits": len(states), "truncated": len(states) > 2}
