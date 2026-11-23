"""Bounded predicate proposals and capture-only (never outcome) predictions.

Factor/clause order is semantic.  In particular CWE factors are SAFE leaves;
repair DNF is represented by its ordered safe CNF and evaluated at one clamp.
"""
from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable, Iterator
from typing import NamedTuple

from binradar import binradar_taosc_predicates as predicates

from ..family import parse_candidate
from .model import SearchLimits

Clause = tuple[str, ...]
_FORMATS = ("ERM generic", "ERM CWE-805")
_REGISTERS = tuple(predicates.REGISTER_TO_VAR)
_COMPARISONS = ("==", "!=", "<", ">=", ">", "<=")
_BINARY = ("+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>")
_MIN64 = -(1 << 63)
_MAX64 = (1 << 63) - 1


def _family(patch_format: str) -> None:
    if patch_format not in _FORMATS:
        raise ValueError(f"unsupported patch-format: {patch_format!r}")


def compose(patch_format: str, clauses: tuple[Clause, ...]) -> str | None:
    """Render ordered generic jump DNF or CWE safe CNF, without rewriting.

    Empty generic programs are neutral 0; an empty conjunction is true 1.
    CWE has neither Boolean constant in its closed source grammar: None is an
    internal-only seed, not a source string and not an executable candidate.
    """
    _family(patch_format)
    if patch_format == "ERM CWE-805":
        if not clauses or any(not clause for clause in clauses):
            return None
        inner, outer = " || ", " && "
    else:
        if not clauses:
            return "0"
        inner, outer = " && ", " || "
    blocks = []
    for clause in clauses:
        block = inner.join(f"({factor})" for factor in clause) if clause else "1"
        blocks.append(f"({block})")
    return outer.join(blocks)


def _round_robin(streams: list[Iterator[str]]) -> Iterator[str]:
    while streams:
        remaining = []
        for stream in streams:
            try:
                yield next(stream)
            except StopIteration:
                continue
            remaining.append(stream)
        streams = remaining


def _constants(observed: dict[int, None]) -> tuple[str, ...]:
    # The boundary pool is bounded independently of capture count. New captures
    # rebuild it; no full-state-equivalent predicate is permanently discarded.
    boundaries = ([min(observed), max(observed), *observed] if observed else [])
    neighbors = [neighbor for value in boundaries for neighbor in (value - 1, value + 1)
                 if _MIN64 <= neighbor <= _MAX64]
    fixed = ("0", "1", "-1", "min64", "max64", *predicates.CONSTANTS)
    evidence = iter(str(value) for value in dict.fromkeys([*boundaries, *neighbors]))
    return tuple(dict.fromkeys(_round_robin([evidence, iter(fixed)])))


def _thresholds(constants: tuple[tuple[str, ...], ...], indices: tuple[int, ...]) -> Iterator[str]:
    # Cover every comparison at an observed boundary before advancing it.
    for turn in range(max(map(len, constants))):
        for operator in _COMPARISONS:
            for index in indices:
                if turn < len(constants[index]):
                    yield f"{_REGISTERS[index]} {operator} {constants[index][turn]}"


def _relations() -> Iterator[str]:
    for distance in range(1, len(_REGISTERS)):
        for operator in _COMPARISONS:
            for index, register in enumerate(_REGISTERS):
                other = _REGISTERS[(index + distance) % len(_REGISTERS)]
                yield f"{register} {operator} {other}"


def _unary_operands() -> Iterator[str]:
    for turn in range(len(_COMPARISONS)):
        for operation in ("~", "-", "+"):
            for index, register in enumerate(_REGISTERS):
                operator = _COMPARISONS[(index + turn) % len(_COMPARISONS)]
                yield f"({operation}{register}) {operator} 0"


def _binary_operands(constants: tuple[tuple[str, ...], ...], depth: int) -> Iterator[str]:
    # Each turn covers all registers; rotate the operator by register so even
    # small budgets contain arithmetic, division/remainder traps, bitwise and
    # shifts.  Both register-register and register-constant forms participate.
    for turn in range(6 * len(_BINARY)):
        for index, register in enumerate(_REGISTERS):
            operation = _BINARY[(index + turn) % len(_BINARY)]
            other = _REGISTERS[(index + 1 + turn // 2) % len(_REGISTERS)]
            constant = constants[index][turn % len(constants[index])]
            right = other if turn % 2 == 0 else constant
            operand = f"({register} {operation} {right})"
            for level in range(2, depth):
                nested_op = _BINARY[(index + turn + level) % len(_BINARY)]
                operand = f"({operand} {nested_op} {constants[index][level % len(constants[index])]})"
            comparison = _COMPARISONS[(index + turn) % len(_COMPARISONS)]
            # Comparing against another register is useful for wrapping sums,
            # masks and differences, not just one-register zero thresholds.
            target = other if turn % 3 == 2 else "0"
            yield f"{operand} {comparison} {target}"


def _generic_atoms(snapshots: list[predicates.CachedSnapshot], depth: int, check=None) -> Iterator[str]:
    observed: list[dict[int, None]] = [{} for _ in _REGISTERS]
    varying_set = set()
    for turn, state in enumerate(snapshots):
        if check is not None and turn % 256 == 0:
            check()
        for index, value in enumerate(state.registers):
            if len(observed[index]) < 24:
                observed[index].setdefault(predicates.wrap64(value), None)
            if value != snapshots[0].registers[index]:
                varying_set.add(index)
        if len(varying_set) == len(_REGISTERS) and all(len(pool) == 24 for pool in observed):
            break
    constants = tuple(_constants(pool) for pool in observed)
    varying = tuple(index for index in range(len(_REGISTERS)) if index in varying_set)
    fixed = tuple(index for index in range(len(_REGISTERS)) if index not in varying_set)
    streams = [_thresholds(constants, varying), _thresholds(constants, fixed), _relations()]
    if depth >= 2:
        streams.extend([_unary_operands(), _binary_operands(constants, 2)])
    for level in range(3, depth + 1):
        streams.append(_binary_operands(constants, level))
    return _round_robin(streams)


def _pointer(cell: str) -> str:
    return f"{cell} >= i->begin && {cell} < i->end"


def _size(cell: str, scale: int) -> str:
    return f"{scale} * {cell} < i->end - i->begin"


def _register_pointers() -> Iterator[str]:
    for register in _REGISTERS:
        yield _pointer(f"s->{register}")


def _register_sizes() -> Iterator[str]:
    for scale in (1, 2, 4, 8):
        for register in _REGISTERS:
            yield _size(f"s->{register}", scale)


def _stack_pointers(extent: int) -> Iterator[str]:
    for index in range(min(extent // 8, 65536)):
        yield _pointer(f"((uint64_t *)s->rsp)[{index}]")


def _stack_sizes(extent: int, width: int) -> Iterator[str]:
    for index in range(min(extent // (width // 8), 65536)):
        for scale in (1, 2, 4, 8):
            yield _size(f"((uint{width}_t *)s->rsp)[{index}]", scale)


def atoms(patch_format: str, snapshots: list[predicates.CachedSnapshot],
          limits: SearchLimits, *, check=None) -> tuple[str, ...]:
    """Generate at most max_atoms valid, deterministic, syntactically distinct atoms.

    Generic operand_depth counts leaf operands as 1 (comparison is outside that
    budget).  CWE only emits closed typed leaves whose complete stack extent is
    present in EVERY supplied capture.  With no captures no stack is invented.
    """
    _family(patch_format)
    cwe = patch_format == "ERM CWE-805"
    extent = None
    for index, snapshot in enumerate(snapshots):
        if check is not None and index % 256 == 0:
            check()
        if snapshot.is_CWE805 != cwe:
            raise ValueError("snapshot family does not match patch-format")
        if cwe:
            extent = len(snapshot.stack) if extent is None else min(extent, len(snapshot.stack))
    if cwe:
        extent = extent or 0
        stream = _round_robin([_register_pointers(), _register_sizes(),
                               _stack_pointers(extent),
                               *(_stack_sizes(extent, width) for width in (8, 16, 32))])
    else:
        stream = _generic_atoms(snapshots, limits.operand_depth, check)
    result = []
    seen: set[str] = set()
    for expression in stream:
        if check is not None:
            check()
        # The parser also enforces runtime source/descriptor/depth bounds.
        candidate = parse_candidate(patch_format, expression)
        if candidate.descriptor in seen:
            continue
        seen.add(candidate.descriptor)
        result.append(candidate.expression)
        if len(result) >= limits.max_atoms:
            break
    return tuple(result)


def _case_boundaries(snapshots_by_case, crashes, normals, limit, flattened,
                     indices, environments, check=None) -> tuple[str, ...]:
    """Rank at most two signed envelopes per register using whole cases.

    Each envelope fires at least once in every captured target trace. Missing
    and empty traces supply neither an extremum nor a successful observation.
    Equivalent full outcome vectors share one revision-local proposal slot;
    ordinary enumeration still retains other spellings and operators.
    """
    if not limit:
        return ()
    lower, upper = None, None
    for case in sorted(crashes):
        if check is not None:
            check()
        rows = snapshots_by_case.get(case, ())
        if not rows:
            continue
        minima, maxima = [_MAX64] * len(_REGISTERS), [_MIN64] * len(_REGISTERS)
        for turn, row in enumerate(rows):
            if check is not None and turn % 256 == 0:
                check()
            for index, value in enumerate(row.registers):
                value = predicates.wrap64(value)
                minima[index] = min(minima[index], value)
                maxima[index] = max(maxima[index], value)
        if lower is None:
            lower, upper = maxima, minima
        else:
            lower = [min(left, right) for left, right in zip(lower, maxima)]
            upper = [max(left, right) for left, right in zip(upper, minima)]
    if lower is None:
        return ()

    # Preserve ordered hit outcomes for diversity, not only an any-hit bit. Two
    # atoms can activate identical case sets but refine differently at each hit.
    relevant = set()
    for case in sorted(crashes | normals):
        if check is not None:
            check()
        for turn, index in enumerate(indices.get(case, ())):
            if check is not None and turn % 256 == 0:
                check()
            relevant.add(index)
    relevant = sorted(relevant)
    ranked = []
    for index, register in enumerate(_REGISTERS):
        for operator, cutoff in (("<=", upper[index]), (">=", lower[index])):
            candidate = parse_candidate("ERM generic", f"{register} {operator} {cutoff}")
            outcomes = {}
            for turn, position in enumerate(relevant):
                if check is not None and turn % 256 == 0:
                    check()
                outcomes[position] = predicates.evaluate_cached_branch(
                    candidate.parsed, flattened[position], environments[position])
            activated_normals = 0
            for case in sorted(normals):
                if check is not None:
                    check()
                for turn, position in enumerate(indices.get(case, ())):
                    if check is not None and turn % 256 == 0:
                        check()
                    if outcomes[position] == 1:
                        activated_normals += 1
                        break
            rank = (activated_normals, len(candidate.expression.encode("utf-8")), candidate.expression)
            # The fixed case-to-state index vectors reconstruct every ordered
            # hit from these bytes, without duplicating shared capture traces.
            ranked.append((rank, bytes(outcomes.values()), candidate.expression))
    seen, result = set(), []
    for _, signature, expression in sorted(ranked):
        if signature not in seen:
            seen.add(signature)
            result.append(expression)
            if len(result) == limit:
                break
    return tuple(result)


class _CaseBranches(NamedTuple):
    fired: int
    trapped: int
    # One distinct bit per (case, branch 0/1/2) pair, including mixed traces.
    signature: int


class _Prediction(NamedTuple):
    ones: bytes
    traps: bytes
    cases: _CaseBranches


class Space:
    """Canonical capture evaluator with bounded revision-local bitset caches.

    Predictions, whether ordered vectors or case membership, establish no repair
    or ownership. For CWE the whole safe expression is evaluated jointly, never
    an OR of independently reduced per-allocation jump decisions.
    """

    def __init__(self, patch_format: str,
                 snapshots_by_case: dict[str, list[predicates.CachedSnapshot]],
                 limits: SearchLimits, *, crashes: frozenset[str] = frozenset(),
                 normals: frozenset[str] = frozenset(), check=None):
        _family(patch_format)
        self.patch_format = patch_format
        self.limits = limits
        self._crashes = crashes
        self._normals = normals
        self._guided = (patch_format == "ERM generic" and bool(crashes)
                        and limits.search_policy in ("boundaries", "balanced", "composed", "adaptive"))
        self._check = check
        self._snapshots: dict[str, tuple[predicates.CachedSnapshot, ...]] = {}
        self._cache: OrderedDict[tuple[Clause, ...], _Prediction] = OrderedDict()
        self._cache_limit = max(32, min(4096, limits.max_atoms + limits.beam_width * limits.max_clauses))
        self.atoms: tuple[str, ...] = ()
        self.revision = 0
        self.update(snapshots_by_case)

    def update(self, snapshots_by_case: dict[str, list[predicates.CachedSnapshot]]) -> None:
        """Add/replace cases; retain caches only for identical prediction inputs."""
        updated = dict(self._snapshots)
        changed = False
        for case, rows in snapshots_by_case.items():
            if self._check is not None:
                self._check()
            rows = tuple(rows)
            prior = updated.get(case)
            same = prior is not None and len(prior) == len(rows)
            if same:
                for index, (old, new) in enumerate(zip(prior, rows)):
                    if self._check is not None and index % 256 == 0:
                        self._check()
                    # Captured branch/id authenticate outcomes, but are not
                    # inputs to prediction. A new descriptor alone is not a
                    # new predictive frontier.
                    if (old.registers != new.registers or old.clamps != new.clamps
                            or old.stack != new.stack):
                        same = False
                        break
            if not same:
                updated[case] = rows
                changed = True
        if self.revision and not changed:
            return
        # Authenticated captures share frozen states. Evaluate each state object
        # once, while retaining every case's complete ordered index vector.
        flattened, positions, indices, captures = [], {}, {}, {}
        for case in sorted(updated):
            if self._check is not None:
                self._check()
            rows = updated[case]
            if id(rows) not in captures:
                selected = []
                for turn, state in enumerate(rows):
                    if self._check is not None and turn % 256 == 0:
                        self._check()
                    if id(state) not in positions:
                        positions[id(state)] = len(flattened)
                        flattened.append(state)
                    selected.append(positions[id(state)])
                captures[id(rows)] = tuple(selected)
            indices[case] = captures[id(rows)]
        # Keep an ordinal even for a known case without captures. Missing or
        # empty traces contribute no branch bits and cannot satisfy an owner.
        cases = sorted(updated.keys() | self._crashes | self._normals)
        case_bits, trace_cases = {}, {}
        nonempty_cases = 0
        for ordinal, case in enumerate(cases):
            if self._check is not None and ordinal % 256 == 0:
                self._check()
            bit = 1 << ordinal
            case_bits[case] = bit
            if trace := indices.get(case):
                group = id(trace)
                previous = trace_cases.get(group)
                trace_cases[group] = (bit if previous is None else previous[0] | bit), trace
                nonempty_cases |= bit
        state_cases = [0] * len(flattened)
        for mask, trace in trace_cases.values():
            for turn, position in enumerate(trace):
                if self._check is not None and turn % 256 == 0:
                    self._check()
                previous = state_cases[position]
                state_cases[position] = (previous | mask) if previous else mask
        environments = [] if self.patch_format == "ERM generic" else None
        if environments is not None:
            for start in range(0, len(flattened), 256):
                if self._check is not None:
                    self._check()
                environments.extend(predicates.prepare_generic_environments(flattened[start:start + 256]))
        generated = atoms(self.patch_format, flattened, self.limits, check=self._check)
        if self._guided:
            # A small cap must still admit ordinary grammar. Larger caps devote
            # at most 32 existing slots to case envelopes, never an extra pool.
            proposals = _case_boundaries(updated, self._crashes, self._normals,
                                         min(32, self.limits.max_atoms // 2),
                                         flattened, indices, environments, self._check)
            selected, seen = [], set()
            for atom in (*proposals, *generated):
                if self._check is not None:
                    self._check()
                descriptor = parse_candidate(self.patch_format, atom).descriptor
                if descriptor not in seen:
                    seen.add(descriptor)
                    selected.append(atom)
                    if len(selected) == self.limits.max_atoms:
                        break
            generated = tuple(selected)
            # Reconstruct from current evidence alone, including proposal rank,
            # so updates and a fresh resume agree and stale boundaries disappear.
            retained = ()
        else:
            available = set(generated)
            # Preserve the original unlabelled/baseline enumerator behavior.
            retained = tuple(atom for atom in self.atoms if atom in available)
        retained_set = set(retained)
        if self._check is not None:
            self._check()
        self.atoms = retained + tuple(atom for atom in generated if atom not in retained_set)
        self._snapshots = updated
        self._indices = indices
        self._case_bits = case_bits
        self._case_count = len(cases)
        self._state_cases = state_cases
        self._neutral_cases = self._pack_cases(nonempty_cases, 0, 0)
        self._true_cases = self._pack_cases(0, nonempty_cases, 0)
        self._flat = flattened
        self._environments = tuple(environments) if environments is not None else None
        self._cache.clear()
        self.revision += 1

    def expression(self, clauses: tuple[Clause, ...]) -> str | None:
        if len(clauses) > self.limits.max_clauses:
            raise ValueError("candidate exceeds max_clauses")
        if any(len(clause) > self.limits.max_factors for clause in clauses):
            raise ValueError("candidate exceeds max_factors")
        return compose(self.patch_format, clauses)

    def case_mask(self, cases: Iterable[str]) -> int:
        """Map case IDs to the same revision-local bits used by predictions."""
        mask = 0
        for index, case in enumerate(cases):
            if self._check is not None and index % 256 == 0:
                self._check()
            mask |= self._case_bits.get(case, 0)
        return mask

    def _pack_cases(self, zero: int, one: int, trap: int) -> _CaseBranches:
        signature = zero | (one << self._case_count) | (trap << (2 * self._case_count))
        return _CaseBranches(one & ~trap, trap, signature)

    def _prediction(self, clauses: tuple[Clause, ...]) -> _Prediction | None:
        if self._check is not None:
            self._check()
        cached = self._cache.get(clauses)
        if cached is not None:
            self._cache.move_to_end(clauses)
            return cached
        expression = self.expression(clauses)
        if not clauses or expression is None:
            return None
        candidate = parse_candidate(self.patch_format, expression)
        ones = bytearray((len(self._flat) + 7) // 8)
        traps = bytearray(len(ones))
        cases = [0, 0, 0]
        for index, snapshot in enumerate(self._flat):
            if self._check is not None and index % 256 == 0:
                self._check()
            environment = self._environments[index] if self._environments is not None else None
            branch = predicates.evaluate_cached_branch(candidate.parsed, snapshot, environment)
            cases[branch] |= self._state_cases[index]
            if branch == 1:
                ones[index // 8] |= 1 << (index % 8)
            elif branch == 2:
                traps[index // 8] |= 1 << (index % 8)
        prediction = _Prediction(bytes(ones), bytes(traps), self._pack_cases(*cases))
        self._cache[clauses] = prediction
        if len(self._cache) > self._cache_limit:
            self._cache.popitem(last=False)
        return prediction

    def branch_membership(self, clauses: tuple[Clause, ...]) -> _CaseBranches:
        """Return compact firing, trapping and branch membership for ranking."""
        prediction = self._prediction(clauses)
        if prediction is not None:
            return prediction.cases
        return self._true_cases if clauses else self._neutral_cases

    def predict(self, clauses: tuple[Clause, ...]) -> dict[str, tuple[int, ...]]:
        prediction = self._prediction(clauses)
        if prediction is None:
            # Empty program is neutral; CWE's unencodable true draft is only a
            # heuristic, not an executable candidate or outcome assertion.
            branch = int(bool(clauses))
            result, vectors = {}, {}
            for case, indices in self._indices.items():
                if self._check is not None:
                    self._check()
                if len(indices) not in vectors:
                    vectors[len(indices)] = (branch,) * len(indices)
                result[case] = vectors[len(indices)]
            return result
        ones, traps, _ = prediction
        result, vectors = {}, {}
        for case, indices in self._indices.items():
            if self._check is not None:
                self._check()
            if id(indices) not in vectors:
                branches = []
                for turn, index in enumerate(indices):
                    if self._check is not None and turn % 256 == 0:
                        self._check()
                    bit = 1 << (index % 8)
                    branches.append(2 if traps[index // 8] & bit else int(bool(ones[index // 8] & bit)))
                vectors[id(indices)] = tuple(branches)
            result[case] = vectors[id(indices)]
        return result
