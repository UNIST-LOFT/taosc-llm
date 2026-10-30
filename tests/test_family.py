"""Family parsing preserves the authoritative offline/native descriptor semantics."""

import pytest
from binradar import binradar_taosc_predicates as predicates
from taosc_llm.family import parse_candidate, grammar_contract


def test_generic_polarity_and_traps():
    candidate = parse_candidate("ERM generic", "  rax <= 0\n")
    assert candidate.expression == "rax <= 0"
    assert candidate.source_predicate == "(rax <= 0) == 0"
    assert candidate.required_stack_bytes == 0
    for value, branch in ((-1, 1), (0, 1), (1, 0)):
        assert predicates.eval_patch_str(candidate.descriptor, [value] + [0] * 15) == branch
    trapped = parse_candidate("ERM generic", "1 / rax")
    with pytest.raises(predicates.PredicateTrap):
        predicates.eval_patch_str(trapped.descriptor, [0] * 16)


@pytest.mark.parametrize("expression,descriptor,stack_bytes", [
    ("s->rax >= i->begin && s->rax < i->end", "c1p0", 0),
    ("((uint64_t *)s->rsp)[2] >= i->begin && ((uint64_t *)s->rsp)[2] < i->end", "c1s64i2", 24),
    ("4 * ((uint16_t *)s->rsp)[3] < i->end - i->begin", "c2s16i3q4", 8),
    ("8 * s->rdx < i->end - i->begin", "c2p3q8", 0),
])
def test_typed_candidate_roundtrip(expression, descriptor, stack_bytes):
    candidate = parse_candidate("ERM CWE-805", expression)
    assert candidate.source_predicate == expression
    assert candidate.descriptor == descriptor
    assert candidate.required_stack_bytes == stack_bytes
    assert predicates.parse_predicate_descriptor(descriptor) == candidate.parsed


def test_cwe805_pointer_clamps_and_size_overflow():
    pointer = parse_candidate("ERM CWE-805", "s->rax >= i->begin && s->rax < i->end")
    for value, branch in ((99, 1), (100, 0), (131, 0), (132, 1)):
        assert predicates.CWE805_branch_taken(pointer.parsed, [value] + [0] * 15, b"", [(100, 132)]) == branch
    size = parse_candidate("ERM CWE-805", "8 * s->rax < i->end - i->begin")
    assert predicates.CWE805_branch_taken(size.parsed, [(1 << 64) - 1] + [0] * 15, b"", [(100, 132)]) == 2
    stack = parse_candidate("ERM CWE-805", "1 * ((uint32_t *)s->rsp)[1] < i->end - i->begin")
    assert stack.required_stack_bytes == 8
    assert predicates.CWE805_branch_taken(stack.parsed, [0] * 16,
                                         b"\0" * 4 + (31).to_bytes(4, "little"), [(100, 132)]) == 0
    assert predicates.CWE805_branch_taken(stack.parsed, [0] * 16,
                                         b"\0" * 4 + (32).to_bytes(4, "little"), [(100, 132)]) == 1


@pytest.mark.parametrize("expression", [
    "rax != 0", "s->rax >= i->begin && s->rbx < i->end",
    "3 * s->rax < i->end - i->begin",
    "1 * ((uint64_t *)s->rsp)[0] < i->end - i->begin",
    "1 * ((uint32_t *)s->rsp)[65536] < i->end - i->begin",
    "s->rax >= i->begin && s->rax < i->end; return 1",
])
def test_cwe805_rejects_noncanonical_or_unrepresentable_predicates(expression):
    with pytest.raises(ValueError):
        parse_candidate("ERM CWE-805", expression)


@pytest.mark.parametrize("patch_format", ["", "Single CWE-805", "ERM CWE-823"])
def test_formats_are_explicit(patch_format):
    with pytest.raises(ValueError):
        parse_candidate(patch_format, "0")
    with pytest.raises(ValueError):
        grammar_contract(patch_format)
