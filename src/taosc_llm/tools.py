"""Exactly five bounded, filesystem-free queries over a frozen context."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

import binradar.binradar_taosc_predicates as predicates

from .context import MAX_EXPRESSION, REGISTERS, canonical, keys, strict_json

PAGE_SIZE = 32
FUNCTION_PAGE_BYTES = 8192


class ToolError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def tool_definitions():
    context = {"type": "string", "minLength": 64, "maxLength": 64}
    identifier = {"type": "string", "minLength": 1, "maxLength": 160}
    cursor = {"type": "string", "minLength": 1, "maxLength": 2048}
    specs = [
        ("get_patch_context", "Read the frozen patch, grammar, caller provenance and evidence inventory.", {}, []),
        ("get_function_context", "Read one bounded page of an admitted caller-supplied function view.",
         {"function_id": identifier, "view": {"type": "string", "enum": ["instructions", "decompilation", "references"]}, "cursor": cursor}, ["function_id", "view"]),
        ("list_observations", "List ordered development observations and explicit domain counts.",
         {"domain": {"type": "string", "enum": ["system", "function", "all"]}, "cursor": cursor}, ["domain"]),
        ("get_observation", "Read caller provenance, outcome and ordered recorded-state pages; no replay.",
         {"evidence_id": identifier, "cursor": cursor}, ["evidence_id"]),
        ("check_predicate", "Canonical grammar validation and offline branches on available caller-recorded registers only; not execution or verification.",
         {"jump_if": {"type": "string", "minLength": 1, "maxLength": MAX_EXPRESSION},
          "evidence_ids": {"type": "array", "maxItems": 1024, "items": identifier}}, ["jump_if"]),
    ]
    return [{"name": name, "description": description,
             "parameters": {"type": "object", "properties": {"context_id": context, **properties},
                            "required": ["context_id", *required], "additionalProperties": False}}
            for name, description, properties, required in specs]


def _validate(value, schema):
    kind = schema["type"]
    expected = {"object": dict, "array": list, "string": str}[kind]
    if not isinstance(value, expected):
        raise ToolError("invalid_arguments", "argument type mismatch")
    if kind == "object":
        if set(value) - set(schema["properties"]) or set(schema["required"]) - set(value):
            raise ToolError("invalid_arguments", "missing or unknown argument")
        for key, item in value.items():
            _validate(item, schema["properties"][key])
    elif kind == "array":
        if len(value) > schema.get("maxItems", 1024):
            raise ToolError("resource_limit", "argument list too large")
        for item in value:
            _validate(item, schema["items"])
    else:
        if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", 4096):
            raise ToolError("invalid_arguments", "argument length mismatch")
        if "enum" in schema and value not in schema["enum"]:
            raise ToolError("invalid_arguments", "unsupported argument value")


def _cursor(context, scope, offset):
    payload = canonical([context.context_id, scope, str(offset)])
    signature = hmac.new(context._cursor_key, payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload + signature).decode("ascii")


def _offset(context, scope, cursor):
    if cursor is None:
        return 0
    try:
        data = base64.b64decode(cursor, altchars=b"-_", validate=True)
        payload, signature = data[:-32], data[-32:]
        expected = hmac.new(context._cursor_key, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError()
        identity, actual_scope, offset = json.loads(payload)
        if identity != context.context_id or actual_scope != scope or not offset.isdecimal():
            raise ValueError()
        return int(offset)
    except (ValueError, TypeError, UnicodeError):
        raise ToolError("invalid_cursor", "cursor is invalid for this context and query") from None


def _page(context, scope, records, cursor):
    offset = _offset(context, scope, cursor)
    if offset >= len(records) and offset != 0:
        raise ToolError("invalid_cursor", "cursor is outside this dataset")
    end = min(offset + PAGE_SIZE, len(records))
    return {"items": records[offset:end], "offset": str(offset), "total": str(len(records)),
            "omitted_before": str(offset), "omitted_after": str(len(records) - end),
            "truncated": end < len(records),
            "next_cursor": _cursor(context, scope, end) if end < len(records) else None}


def _observation(context, evidence_id):
    for observation in context.evidence["observations"]:
        if observation["evidence_id"] == evidence_id:
            return observation
    raise ToolError("out_of_scope", "observation is not admitted in this context")


def parse_predicate(expression):
    if not isinstance(expression, str) or not expression.strip() or len(expression.encode("utf-8")) > MAX_EXPRESSION:
        raise ToolError("invalid_predicate", "predicate is empty or exceeds the size bound")
    try:
        tokens = predicates.tokenize_generic(expression)
        ast = predicates.Parser(tokens).parse()
        # Same polarity adapter as builder.generate_patch; no second interpreter.
        descriptor = predicates.predicate_to_branch_patch_str(f"({expression}) == 0")
    except (ValueError, RecursionError):
        raise ToolError("invalid_predicate", "expression rejected by canonical predicate parser") from None
    references = set()
    def visit(node):
        if node[0] == "var":
            references.add(REGISTERS[node[1]])
        for child in node[1:]:
            if isinstance(child, tuple):
                visit(child)
    try:
        visit(ast)
    except RecursionError:
        raise ToolError("invalid_predicate", "predicate nesting exceeds host bound") from None
    return descriptor, sorted(references, key=REGISTERS.index)


def _check(context, args):
    descriptor, references = parse_predicate(args["jump_if"])
    selected = args.get("evidence_ids", [])
    if len(selected) != len(set(selected)):
        raise ToolError("invalid_arguments", "duplicate evidence ID")
    observations = [_observation(context, eid) for eid in selected]
    evaluations = []
    for observation in observations:
        states = []
        for index, hit in enumerate(observation["hits"]):
            missing = [name for name in references if hit["registers"].get(name) is None]
            branch, reason = None, hit["reason"]
            if hit["availability"] != "available":
                availability = "unavailable"
            elif missing:
                availability, reason = "unavailable", "referenced registers unavailable: " + ", ".join(missing)
            else:
                availability, reason = "available", None
                # Only unreferenced cells receive internal filler; never project it as evidence.
                environment = [predicates.wrap64(int(hit["registers"].get(name) or "0")) for name in REGISTERS]
                try:
                    branch = int(predicates.eval_patch_str(descriptor, environment) != 0)
                except predicates.PredicateTrap:
                    branch = 2
            states.append({"state_id": hit["state_id"], "hit_index": str(index), "availability": availability,
                           "reason": reason, "branch": branch})
        evaluations.append({"evidence_id": observation["evidence_id"], "source_ref": observation["source_ref"],
                            "hit_count": str(len(states)), "state_sequence": states,
                            "zero_hits": not states, "desired_action": "unknown"})
    return {"valid_syntax": True, "referenced_registers": references, "evaluations": evaluations,
            "evaluation_scope": "offline caller-recorded pre-branch states only; no execution or outcome prediction",
            "provenance": "caller-supplied, not authenticated snapshots"}


def call_tool(context, name: str, args: dict):
    base = {"context_id": context.context_id, "source_refs": [], "truncated": False}
    try:
        definitions = {definition["name"]: definition for definition in tool_definitions()}
        if name not in definitions:
            raise ToolError("out_of_scope", "tool is not allowed")
        if not isinstance(args, dict):
            raise ToolError("invalid_arguments", "arguments must be an object")
        if args.get("context_id") != context.context_id:
            raise ToolError("stale_context", "context ID does not match frozen context")
        _validate(args, definitions[name]["parameters"])
        if name == "get_patch_context":
            result = {"patch_context": context.projection, "availability": "available"}
        elif name == "check_predicate":
            result = _check(context, args)
            base["source_refs"] = [o["source_ref"] for o in result["evaluations"]]
        elif name == "list_observations":
            observations = context.evidence["observations"]
            summaries = [{"evidence_id": o["evidence_id"], "domain": o["domain"],
                          "origin": "caller-supplied", "caller_origin": o["origin"], "source_ref": o["source_ref"],
                          "outcome": o["outcome"], "hit_count": str(len(o["hits"])), "desired_action": "unknown"}
                         for o in observations if args["domain"] in ("all", o["domain"])]
            result = _page(context, "observations:" + args["domain"], summaries, args.get("cursor"))
            result["domain_counts"] = {d: str(sum(o["domain"] == d for o in observations)) for d in ("system", "function")}
            result["exclusions"] = {"availability": "not_authenticated", "reason": "only caller-admitted development records; no held-out import"}
            base["source_refs"] = [o["source_ref"] for o in result["items"]]
        elif name == "get_observation":
            observation = _observation(context, args["evidence_id"])
            result = {key: value for key, value in observation.items() if key not in ("hits", "origin")}
            result.update({"origin": "caller-supplied", "caller_origin": observation["origin"],
                           "authenticated_snapshot": False, "desired_action": "unknown", "zero_hits": not observation["hits"],
                           "hit_sequence_availability": "caller-supplied",
                           "outcome_availability": observation["outcome"].get("availability", "caller-supplied" if observation["outcome"] else "unavailable"),
                           "outcome_reason": observation["outcome"].get("reason", None if observation["outcome"] else "caller supplied no outcome")})
            hits = [{**hit, "hit_index": str(index),
                     "register_availability": {register: {
                         "availability": "available" if hit["availability"] == "available" and value is not None else "unavailable",
                         "reason": None if hit["availability"] == "available" and value is not None else (hit["reason"] or "register not supplied")}
                         for register, value in hit["registers"].items()}}
                    for index, hit in enumerate(observation["hits"])]
            result["hits"] = _page(context, "hits:" + args["evidence_id"], hits, args.get("cursor"))
            result["truncated"] = result["hits"]["truncated"]
            base["source_refs"] = [observation["source_ref"]]
        else:
            functions = context.evidence["functions"]
            if not any(f["function_id"] == args["function_id"] for f in functions):
                raise ToolError("out_of_scope", "function is not admitted in this context")
            function = next((f for f in functions if f["function_id"] == args["function_id"] and f["view"] == args["view"]), None)
            if function is None:
                raise ToolError("not_available", "requested function view is unavailable")
            scope = "function:" + args["function_id"] + ":" + args["view"]
            raw = function["text"].encode("utf-8")
            offset = _offset(context, scope, args.get("cursor"))
            if offset >= len(raw) and offset != 0:
                raise ToolError("invalid_cursor", "cursor outside function text")
            end = min(offset + FUNCTION_PAGE_BYTES, len(raw))
            while end < len(raw) and (raw[end] & 0xc0) == 0x80:
                end -= 1
            result = {"function_id": function["function_id"], "view": function["view"],
                      "text": raw[offset:end].decode("utf-8"), "source_ref": function["source_ref"],
                      "complete": function["complete"], "function_extent": "caller-asserted" if function["complete"] else "not_established",
                      "analysis_confidence": "caller-supplied, not independently authenticated",
                      "backend": "caller-prepared-evidence-v1", "backend_version": "1",
                      "availability": "available", "byte_offset": str(offset), "total_bytes": str(len(raw)),
                      "omitted_before": str(offset), "omitted_after": str(len(raw) - end), "truncated": end < len(raw),
                      "next_cursor": _cursor(context, scope, end) if end < len(raw) else None}
            base["source_refs"] = [function["source_ref"]]
        return {**base, "ok": True, **result}
    except ToolError as error:
        return {**base, "ok": False, "error": {"code": error.code, "message": str(error)}}
    except (ValueError, TypeError, RecursionError, OverflowError):
        return {**base, "ok": False, "error": {"code": "backend_error", "message": "bounded local evidence query failed"}}


def validate_proposal(context, value: str):
    """Return the exact validated final object, or raise ValueError (never repair it)."""
    if not isinstance(value, str) or len(value.encode("utf-8")) > 16384:
        raise ValueError("proposal exceeds size bound")
    try:
        proposal = keys(strict_json(value), {"schema_version", "context_id", "decision", "jump_if", "evidence_ids", "assumptions", "reason"})
        if type(proposal["schema_version"]) is not int or proposal["schema_version"] != 1:
            raise ValueError("invalid proposal schema")
        if proposal["context_id"] != context.context_id:
            raise ValueError("stale proposal context")
        if proposal["decision"] == "candidate":
            parse_predicate(proposal["jump_if"])
        elif proposal["decision"] != "abstain" or proposal["jump_if"] is not None:
            raise ValueError("invalid proposal decision or jump_if")
        evidence_ids = proposal["evidence_ids"]
        if not isinstance(evidence_ids, list) or len(evidence_ids) > 128 or any(not isinstance(eid, str) for eid in evidence_ids):
            raise ValueError("invalid proposal evidence IDs")
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("duplicate proposal evidence IDs")
        for eid in evidence_ids:
            _observation(context, eid)
        assumptions = proposal["assumptions"]
        if not isinstance(assumptions, list) or len(assumptions) > 16:
            raise ValueError("invalid proposal assumptions")
        if any(not isinstance(item, str) or not item.strip() or len(item.encode("utf-8")) > 512 for item in assumptions):
            raise ValueError("invalid proposal assumption")
        reason = proposal["reason"]
        if not isinstance(reason, str) or not reason.strip() or len(reason.encode("utf-8")) > 2048:
            raise ValueError("invalid proposal reason")
        return proposal
    except (ToolError, TypeError, RecursionError) as error:
        raise ValueError("invalid final proposal") from error
