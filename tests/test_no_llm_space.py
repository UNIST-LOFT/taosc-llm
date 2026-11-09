"""Search proposals preserve canonical family semantics and capture revisions."""
from dataclasses import replace

import pytest
from binradar import binradar_taosc_predicates as predicates

from taosc_llm.family import parse_candidate
from taosc_llm.no_llm.model import SearchLimits, SearchStopped
from taosc_llm.no_llm.space import Space, atoms, compose

GENERIC = "ERM generic"
CWE = "ERM CWE-805"
POINTER_A = "s->rax >= i->begin && s->rax < i->end"
POINTER_B = "s->rbx >= i->begin && s->rbx < i->end"


def snapshot(*, clamps=(), stack=b"", **registers):
    values = [0] * 16
    for name, value in registers.items():
        values[predicates.REGISTER_TO_VAR[name]] = value & ((1 << 64) - 1)
    return predicates.CachedSnapshot(0, 0, tuple(values), tuple(clamps), stack)


def test_generic_multiclause_discriminates_disjoint_repairs():
    space = Space(GENERIC, {
        "left-target": [snapshot(rax=-1, rbx=1)],
        "right-target": [snapshot(rax=11, rcx=2)],
        "normal": [snapshot(rax=-1, rbx=0), snapshot(rax=11, rcx=0), snapshot(rax=5)],
    }, SearchLimits())
    left = ("rax < 0", "rbx == 1")
    right = ("rax > 10", "rcx == 2")
    assert space.predict((left,))["right-target"] == (0,)
    assert space.predict((right,))["left-target"] == (0,)
    assert space.predict((left, right)) == {
        "left-target": (1,), "normal": (0, 0, 0), "right-target": (1,),
    }
    expression = compose(GENERIC, (left, right))
    assert expression.index("rax < 0") < expression.index("rbx == 1") < expression.index("rax > 10")


def test_neutral_program_and_internal_true_draft_are_distinct():
    generic = Space(GENERIC, {"case": [snapshot()]}, SearchLimits())
    cwe = Space(CWE, {"case": [snapshot(clamps=((100, 200),))]}, SearchLimits())
    assert compose(GENERIC, ()) == "0"
    assert parse_candidate(GENERIC, compose(GENERIC, ((),))).expression == "(1)"
    assert compose(CWE, ()) is None
    assert compose(CWE, ((),)) is None
    assert compose(CWE, ((POINTER_A,), ())) is None
    assert generic.predict(()) == cwe.predict(()) == {"case": (0,)}
    assert generic.predict(((),)) == cwe.predict(((),)) == {"case": (1,)}


def test_generic_signed_boundaries_and_trap_order():
    space = Space(GENERIC, {"case": [snapshot(rax=1 << 63), snapshot(rax=(1 << 63) - 1)]}, SearchLimits())
    assert space.predict((("rax < 0",),)) == {"case": (1, 0)}
    assert space.predict((("(rax + 1) < 0",),)) == {"case": (1, 1)}
    assert space.predict((("rax / -1",),)) == {"case": (2, 1)}
    assert space.predict((("rax % -1",),)) == {"case": (2, 0)}
    assert space.predict((("0", "rax / -1"),)) == {"case": (0, 0)}
    assert space.predict((("rax / -1", "0"),)) == {"case": (2, 0)}
    assert space.predict(((), ("rax / -1",))) == {"case": (1, 1)}
    # Do not algebraically collapse the late empty/true conjunction: the
    # earlier clause can trap before the true clause is visited.
    assert space.predict((("rax / -1",), ())) == {"case": (2, 1)}


def test_generic_bitwise_shift_predictions_use_signed_canonical_rules():
    row = snapshot(rax=-2, rbx=65)
    space = Space(GENERIC, {"case": [row]}, SearchLimits())
    for expression in ("(rax >> rbx) < 0", "(rax << 1) == -4", "(~rax & 1) != 0", "(rax ^ rbx) < 0"):
        parsed = parse_candidate(GENERIC, expression)
        assert space.predict(((expression,),))["case"] == (
            predicates.evaluate_cached_branch(parsed.parsed, row),)


def test_cwe_distinct_allocations_must_share_one_clamp_for_composition():
    row = snapshot(rax=110, rbx=310, clamps=((100, 200), (300, 400)))
    space = Space(CWE, {"case": [row]}, SearchLimits())
    assert space.predict(((POINTER_A,),)) == {"case": (0,)}
    assert space.predict(((POINTER_B,),)) == {"case": (0,)}
    # Each safe leaf matches a different allocation.  AND of the safe blocks
    # matches neither; OR-ing the independent jump results would be WRONG.
    assert space.predict(((POINTER_A,), (POINTER_B,))) == {"case": (1,)}
    # Two factors refine a single unsafe conjunction; dual safe OR stays safe.
    assert space.predict(((POINTER_A, POINTER_B),)) == {"case": (0,)}


def test_cwe_preserves_visited_overflow_order_and_clamp_scan_order():
    overflow = "8 * s->rbx < i->end - i->begin"
    row = snapshot(rax=110, rbx=(1 << 64) - 1, clamps=((100, 200),))
    space = Space(CWE, {"case": [row]}, SearchLimits())
    assert space.predict(((POINTER_A, overflow),)) == {"case": (0,)}
    assert space.predict(((overflow, POINTER_A),)) == {"case": (2,)}
    # AND short circuits on the current clamp before visiting later clamps.
    assert space.predict(((POINTER_A,), (overflow,))) == {"case": (2,)}
    space.update({"case": [replace(row, clamps=((100, 200), (300, 400)))]})
    assert space.predict(((POINTER_A, overflow),)) == {"case": (2,)}


def test_cwe_stack_atoms_use_complete_cells_in_every_capture():
    rows = [snapshot(clamps=((100, 200),), stack=bytes(32)),
            snapshot(clamps=((100, 200),), stack=bytes(7))]
    pool = atoms(CWE, rows, SearchLimits(max_atoms=512))
    assert any("uint8_t" in atom for atom in pool)
    assert any("uint16_t" in atom for atom in pool)
    assert any("uint32_t" in atom for atom in pool)
    assert not any("uint64_t" in atom for atom in pool)
    assert all(parse_candidate(CWE, atom).required_stack_bytes <= 7 for atom in pool)
    assert all(f"{scale} * s->rax" in " ".join(pool) for scale in (1, 2, 4, 8))
    assert not any("uint" in atom for atom in atoms(CWE, [], SearchLimits()))
    complete = atoms(CWE, [rows[0]], SearchLimits())
    assert any("((uint64_t *)s->rsp)[3]" in atom for atom in complete)


def test_stack_extent_is_checked_even_in_skipped_leaf():
    space = Space(CWE, {"case": [snapshot(rax=110, clamps=((100, 200),), stack=bytes(4))]}, SearchLimits())
    missing = "1 * ((uint32_t *)s->rsp)[1] < i->end - i->begin"
    with pytest.raises(ValueError, match="insufficient captured stack"):
        space.predict(((POINTER_A, missing),))


def test_atoms_are_deterministic_bounded_diverse_and_not_only_thresholds():
    rows = [snapshot(rax=-(1 << 63), rbx=73, rcx=12345), snapshot(rax=(1 << 63) - 1, rbx=74)]
    limits = SearchLimits(max_atoms=512)
    pool = atoms(GENERIC, rows, limits)
    assert pool == atoms(GENERIC, rows, limits)
    assert len(pool) == limits.max_atoms
    descriptors = [parse_candidate(GENERIC, atom).descriptor for atom in pool]
    assert len(set(descriptors)) == len(pool)
    for register in predicates.REGISTER_TO_VAR:
        assert any(register in atom.split() for atom in pool)
    for operation in ("+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>"):
        assert any(f" {operation} " in atom for atom in pool)
    assert any("rax" in atom and "rbx" in atom for atom in pool)
    assert any("-9223372036854775808" in atom for atom in pool)
    assert any("min64" in atom or "max64" in atom for atom in pool)
    assert all(len(atom.encode()) <= predicates.MAX_SOURCE_BYTES for atom in pool)
    assert len(atoms(GENERIC, rows, SearchLimits(max_atoms=7))) == 7


def test_operand_depth_bounds_expansion_and_allows_nested_operands():
    leaf = atoms(GENERIC, [], SearchLimits(max_atoms=256, operand_depth=1))
    assert not any(f" {operation} " in atom for atom in leaf for operation in _ARITHMETIC)
    nested = atoms(GENERIC, [], SearchLimits(max_atoms=512, operand_depth=3))
    assert any(atom.startswith("((") and any(f" {op} " in atom for op in _ARITHMETIC) for atom in nested)


_ARITHMETIC = ("+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>")


def test_prediction_cache_invalidates_on_replacement_and_new_captures():
    space = Space(GENERIC, {"a": [snapshot(rax=1, rbx=1)]}, SearchLimits())
    rax, rbx = (("rax == 1",),), (("rbx == 1",),)
    assert space.predict(rax) == space.predict(rbx) == {"a": (1,)}
    assert space.predict(rax) == {"a": (1,)}
    space.update({"a": [snapshot(rax=0, rbx=1)], "b": [snapshot(rax=1, rbx=0)]})
    assert space.predict(rax) == {"a": (0,), "b": (1,)}
    assert space.predict(rbx) == {"a": (1,), "b": (0,)}
    assert any("rax" in atom for atom in space.atoms)
    assert any("rbx" in atom for atom in space.atoms)


def test_capture_update_rebuilds_atom_boundaries_and_removes_invalid_stack_cells():
    limits = SearchLimits(max_atoms=512)
    generic = Space(GENERIC, {"case": [snapshot(rax=71)]}, limits)
    assert any("71" in atom for atom in generic.atoms)
    generic.update({"case": [snapshot(rax=83)]})
    assert any("83" in atom for atom in generic.atoms)
    cwe = Space(CWE, {"case": [snapshot(clamps=((1, 2),), stack=bytes(32))]}, limits)
    assert any(parse_candidate(CWE, atom).required_stack_bytes == 32 for atom in cwe.atoms)
    cwe.update({"shorter": [snapshot(clamps=((1, 2),), stack=bytes(3))]})
    assert all(parse_candidate(CWE, atom).required_stack_bytes <= 3 for atom in cwe.atoms)


def test_shared_capture_predictions_retain_order_length_and_traps():
    zero, two = snapshot(rax=0), snapshot(rax=2)
    rows = (zero, two, zero)
    space = Space(GENERIC, {"first": rows, "same": rows, "reverse": (two, zero),
                            "empty": ()}, SearchLimits())
    clauses = (("1 / rax",),)
    assert space.predict(clauses) == {"first": (2, 0, 2), "same": (2, 0, 2),
                                      "reverse": (0, 2), "empty": ()}
    space.update({"same": (two,)})
    assert space.predict(clauses) == {"first": (2, 0, 2), "same": (0,),
                                      "reverse": (0, 2), "empty": ()}


def test_cancelled_preprocessing_keeps_prior_capture_revision():
    polls = {"remaining": None}

    def check():
        if polls["remaining"] is not None:
            polls["remaining"] -= 1
            if polls["remaining"] == 0:
                raise SearchStopped("interrupted")

    space = Space(GENERIC, {"case": [snapshot(rax=1)]}, SearchLimits(), check=check)
    prior_atoms = space.atoms
    polls["remaining"] = 4
    with pytest.raises(SearchStopped, match="interrupted"):
        space.update({"case": [snapshot(rax=index) for index in range(600)]})
    polls["remaining"] = None
    assert space.atoms == prior_atoms
    assert space.predict((("rax == 1",),)) == {"case": (1,)}


def test_cancelled_prediction_never_caches_a_partial_vector():
    polls = {"remaining": None}

    def check():
        if polls["remaining"] is not None:
            polls["remaining"] -= 1
            if polls["remaining"] == 0:
                raise SearchStopped("wall-time-reached")

    rows = [snapshot(rax=index % 3) for index in range(600)]
    space = Space(GENERIC, {"case": rows}, SearchLimits(), check=check)
    clauses = (("1 / rax",),)
    polls["remaining"] = 3
    with pytest.raises(SearchStopped, match="wall-time"):
        space.predict(clauses)
    polls["remaining"] = None
    expected = tuple(predicates.evaluate_cached_predicate(parse_candidate(GENERIC, "1 / rax").parsed, rows))
    assert space.predict(clauses) == {"case": expected}
    assert len(expected) == 600 and set(expected) == {0, 1, 2}


def test_limits_and_family_mismatches_are_rejected():
    space = Space(GENERIC, {}, SearchLimits(max_clauses=1, max_factors=1))
    with pytest.raises(ValueError, match="max_clauses"):
        space.predict((("1",), ("0",)))
    with pytest.raises(ValueError, match="max_factors"):
        space.predict((("1", "0"),))
    with pytest.raises(ValueError, match="family"):
        atoms(CWE, [snapshot()], SearchLimits())
    with pytest.raises(ValueError, match="family"):
        atoms(GENERIC, [snapshot(clamps=((1, 2),))], SearchLimits())
    with pytest.raises(ValueError, match="unsupported"):
        compose("ERM CWE-823", ())
