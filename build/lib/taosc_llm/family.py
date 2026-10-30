"""Candidate grammar and lowering shared by synthesis, evaluation and builds."""

from __future__ import annotations

from dataclasses import dataclass

from binradar import binradar_taosc_predicates as predicates


@dataclass(frozen=True)
class Candidate:
    expression: str
    source_predicate: str
    descriptor: str
    parsed: predicates.ParsedPredicate
    family: predicates.PredicateFamily
    required_stack_bytes: int


def _family(patch_format: str) -> predicates.PredicateFamily:
    if patch_format not in ("ERM generic", "ERM CWE-805"):
        raise ValueError(f"unsupported patch-format: {patch_format!r}; require ERM generic or ERM CWE-805")
    return predicates.PATCH_FORMAT_TO_FAMILY[patch_format]


def parse_candidate(patch_format: str, expression: str) -> Candidate:
    """Lower a repair expression using BinRadar's existing family semantics."""
    family = _family(patch_format)
    if not isinstance(expression, str):
        raise ValueError("predicate must be a string")
    normalized = " ".join(expression.split())
    if family == predicates.PredicateFamily.GENERIC_ERM:
        predicates.predicate_to_patch_str(normalized)
        source = f"({normalized}) == 0"
        parsed = predicates.predicate_to_branch_patch_str(source)
    else:
        source = normalized
        parsed = predicates.parse_CWE805_predicate(source)
        # The native descriptor stores an unsigned 16-bit element index.
        # Reject truncation rather than evaluating a different stack cell.
        if isinstance(parsed.cell, predicates.StackCell) and parsed.cell.index > 65535:
            raise ValueError("CWE-805 stack cell index exceeds native descriptor capacity")
    return Candidate(normalized, source, predicates.predicate_descriptor(parsed),
                     parsed, family, predicates.predicate_stack_bytes(parsed))


def grammar_contract(patch_format: str) -> dict:
    """Describe the closed model grammar, not arbitrary compilable C."""
    family = _family(patch_format)
    common = {"patch_format": patch_format, "family": family.value,
              "registers": list(predicates.REGISTER_TO_VAR)}
    if family == predicates.PredicateFamily.GENERIC_ERM:
        return {**common,
                "semantics": "Repair when expression is nonzero; signed i64 BinRadar/Taosc arithmetic; traps are unavailable, never a repair.",
                "constants": {key: str(value) for key, value in predicates.CONSTANTS.items()},
                "operands": "lowercase registers, decimal integer literals, named constants only",
                "unary": ["+", "-", "~"],
                "precedence_low_to_high": ["|", "^", "&", "== !=", "< <= > >=", "<< >>", "+ -", "* / %"],
                "grouping": "parentheses; binary chains associate left"}
    return {**common,
            "semantics": "Safe clamp predicate: repair only when no tracked allocation clamp satisfies it. Checked size multiplication overflow is a trap, not a repair.",
            "pointer": "CELL >= i->begin && CELL < i->end (identical CELL occurrences)",
            "pointer_cells": ["s->REGISTER", "((uint64_t *)s->rsp)[INDEX]"],
            "size": "SCALE * CELL < i->end - i->begin",
            "size_cells": ["s->REGISTER", "((uint8_t *)s->rsp)[INDEX]", "((uint16_t *)s->rsp)[INDEX]", "((uint32_t *)s->rsp)[INDEX]"],
            "scales": [1, 2, 4, 8],
            "index": "decimal integer 0..65535; captured stack must include the complete cell",
            "syntax": "Canonical spacing as shown; no other C expressions or operators"}
