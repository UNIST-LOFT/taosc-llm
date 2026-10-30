"""Bounded, ID-only prepared dataset tools. Native case policy belongs to host."""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
from pathlib import Path

from .context import MAX_EXPRESSION, canonical, digest, keys, strict_json

PAGE_SIZE = 32
FUNCTION_PAGE_BYTES = 8192


class ToolError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def tool_definitions():
    identifier = {"type": "string", "minLength": 1, "maxLength": 160}
    cursor = {"type": "string", "minLength": 1, "maxLength": 2048}
    predicate = {"type": "string", "minLength": 1, "maxLength": MAX_EXPRESSION}
    specs = [
        ("get_patch_context", "Read frozen family grammar, patch identity and inventory.", {}, []),
        ("get_function_analysis", "Read setup-owned static analysis, never execute REA.",
         {"function_id": identifier, "view": {"type": "string", "enum": ["function", "instructions", "decompilation", "references"]}, "cursor": cursor}, ["function_id", "view"]),
        ("list_cases", "List prepared cases without private paths.",
         {"domain": {"type": "string", "enum": ["system", "function", "all"]}, "cursor": cursor}, ["domain"]),
        ("get_case", "Read case/capture provenance and paged states; optional state_id reads bounded stack pages.", {"case_id": identifier, "result_id": identifier, "state_id": identifier, "cursor": cursor}, ["case_id"]),
        ("evaluate_predicate", "Evaluate complete captures offline only; never proof of repair.", {"predicate": predicate}, ["predicate"]),
        ("test_candidate", "Host-selected bounded concrete evaluation; function cases remain offline.", {"predicate": predicate}, ["predicate"]),
        ("get_candidate_result", "Read a bounded page of a prior evaluation by opaque result ID.", {"result_id": identifier, "cursor": cursor}, ["result_id"]),
    ]
    return [{"name": name, "description": description, "parameters": {
        "type": "object", "properties": {"context_id": {"type": "string", "minLength": 64, "maxLength": 64}, **props},
        "required": ["context_id", *required], "additionalProperties": False}}
        for name, description, props, required in specs]


def _validate(value, schema):
    kind = schema["type"]
    if not isinstance(value, {"object": dict, "string": str}[kind]):
        raise ToolError("invalid_arguments", "argument type mismatch")
    if kind == "object":
        if set(value) - set(schema["properties"]) or set(schema["required"]) - set(value):
            raise ToolError("invalid_arguments", "missing or unknown argument")
        for key, item in value.items():
            _validate(item, schema["properties"][key])
    elif not schema.get("minLength", 0) <= len(value.encode()) <= schema.get("maxLength", 4096) or ("enum" in schema and value not in schema["enum"]):
        raise ToolError("invalid_arguments", "invalid argument value")


def _cursor(context, scope, offset):
    payload = canonical([context.context_id, scope, offset])
    return base64.urlsafe_b64encode(payload + hmac.new(context._cursor_key, payload, hashlib.sha256).digest()).decode()


def _offset(context, scope, cursor):
    if cursor is None:
        return 0
    try:
        data = base64.b64decode(cursor, altchars=b"-_", validate=True)
        payload, signature = data[:-32], data[-32:]
        if not hmac.compare_digest(signature, hmac.new(context._cursor_key, payload, hashlib.sha256).digest()):
            raise ValueError()
        identity, actual, offset = json.loads(payload)
        if identity != context.context_id or actual != scope or type(offset) is not int or offset < 0:
            raise ValueError()
        return offset
    except (ValueError, TypeError, UnicodeError):
        raise ToolError("invalid_cursor", "cursor does not belong to this query") from None


def _page(context, scope, records, cursor):
    offset = _offset(context, scope, cursor)
    if offset >= len(records) and offset:
        raise ToolError("invalid_cursor", "cursor outside result")
    end = min(offset + PAGE_SIZE, len(records))
    return {"items": records[offset:end], "offset": offset, "total": len(records), "truncated": end < len(records),
            "next_cursor": _cursor(context, scope, end) if end < len(records) else None}


def _public(value):
    """Only explicit summary fields cross the model boundary; raw source/env never do."""
    allowed = ("id", "case_id", "domain", "status", "reason", "source", "same_crash", "complete", "descriptor", "sha256", "input_sha256", "first_divergence", "returncode", "signal", "verified", "candidate_id", "dataset_id", "predicate", "result_id", "outcome", "exit", "oracle", "concrete-oracle", "fault_valid", "concrete-fault-valid", "fault_addr", "fault-addr", "fault_source", "concrete-fault-source", "fault_image", "fault_offset", "patch-hit", "patch-func-hit")
    result = {k: v for k, v in value.items() if k in allowed and not isinstance(v, (dict, list))}
    if isinstance(result.get("source"), str) and result["source"] not in ("executed", "cache", "offline", "unavailable"):
        result.pop("source")
    for key in ("fault_addr", "fault-addr", "fault_offset"):
        if type(result.get(key)) is int:
            result[key] = str(result[key])
    for key in ("branches", "offline_branches"):
        if key in value:
            vector = value[key]
            if isinstance(vector, list):
                result[key] = vector[:256]
                result[key + "_total"] = len(vector)
                result[key + "_truncated"] = len(vector) > 256
    for key in ("capture", "observation", "outcome", "actual_outcome"):
        if isinstance(value.get(key), dict):
            result[key] = _public(value[key])
    return result


def _candidate(context, expression):
    from .family import parse_candidate
    if not isinstance(expression, str) or not expression.strip() or len(expression.encode()) > MAX_EXPRESSION:
        raise ToolError("invalid_predicate", "predicate exceeds expression bound")
    try:
        return parse_candidate(context.dataset.patch_format, expression)
    except (ValueError, RecursionError) as error:
        raise ToolError("invalid_predicate", "canonical family parser rejected predicate") from error


def _result(context, result_id, cursor=None):
    if result_id not in context._results:
        raise ToolError("out_of_scope", "unknown candidate result")
    result = context._results[result_id]
    return {**_public(result), "result_id": result_id, "summary": result.get("summary", {}),
            "cases": _page(context, "result:" + result_id, [_public(c) for c in result.get("cases", [])], cursor)}


def call_tool(context, name, args):
    base = {"context_id": context.context_id, "truncated": False}
    try:
        definitions = {item["name"]: item for item in tool_definitions()}
        if name not in definitions:
            raise ToolError("out_of_scope", "tool is not allowed")
        if not isinstance(args, dict):
            raise ToolError("invalid_arguments", "arguments must be an object")
        if args.get("context_id") != context.context_id:
            raise ToolError("stale_context", "context ID mismatch")
        _validate(args, definitions[name]["parameters"])
        context.verify_artifacts()
        if name == "get_patch_context":
            result = {"patch_context": context.projection}
        elif name == "list_cases":
            result = _page(context, "cases:" + args["domain"], [_public(c) for c in context.dataset.cases(args["domain"])], args.get("cursor"))
        elif name == "get_case":
            try:
                case = context.dataset.case(args["case_id"])
                result = {"case": _public(case)}
                capture = case.get("capture")
                result_id = args.get("result_id")
                if result_id is not None:
                    if result_id not in context._results:
                        raise ToolError("out_of_scope", "unknown candidate result")
                    evaluated = next((item for item in context._results[result_id].get("cases", [])
                                      if item["case_id"] == case["id"]), None)
                    if evaluated is None:
                        raise ToolError("out_of_scope", "case not present in candidate result")
                    capture = evaluated.get("capture")
                    result["evaluation"] = _public(evaluated)
                    result["result_id"] = result_id
                if capture is None:
                    if args.get("state_id") is not None:
                        raise ToolError("out_of_scope", "state does not belong to an available capture")
                    if args.get("cursor") is not None:
                        _offset(context, "states:" + case["id"] + ":" + (result_id or "prepared"), args["cursor"])
                        raise ToolError("invalid_cursor", "cursor outside unavailable capture")
                    result.update(availability="unavailable", reason="no complete committed capture")
                else:
                    import binradar.binradar_taosc_predicates as predicates
                    from .evaluation import _snapshots
                    states = _snapshots(context.dataset, capture)
                    state_id = args.get("state_id")
                    scope = case["id"] + ":" + (result_id or "prepared")
                    def project(index, state):
                        return {"state_id": scope + ":hit:" + str(index), "hit_index": index,
                                "branch": state.branch,
                                "registers": {name: str(predicates.wrap64(state.registers[position]))
                                              for name, position in predicates.REGISTER_TO_VAR.items()},
                                "clamps": [[str(begin), str(end)] for begin, end in state.clamps],
                                "stack_bytes": len(state.stack), "stack_sha256": digest(state.stack)}
                    if state_id is None:
                        result["states"] = _page(context, "states:" + scope,
                            [project(index, state) for index, state in enumerate(states)], args.get("cursor"))
                        result["zero_hits"] = not states
                    else:
                        prefix = scope + ":hit:"
                        if not state_id.startswith(prefix) or not state_id[len(prefix):].isdecimal():
                            raise ToolError("out_of_scope", "state does not belong to case")
                        index = int(state_id[len(prefix):])
                        if index >= len(states) or state_id != prefix + str(index):
                            raise ToolError("out_of_scope", "state does not belong to case")
                        state = states[index]
                        offset = _offset(context, "stack:" + state_id, args.get("cursor"))
                        if offset >= len(state.stack) and offset:
                            raise ToolError("invalid_cursor", "cursor outside captured stack")
                        end = min(offset + 4096, len(state.stack))
                        result["state"] = project(index, state)
                        result["stack"] = {"hex": state.stack[offset:end].hex(), "byte_offset": offset,
                            "total_bytes": len(state.stack), "truncated": end < len(state.stack),
                            "next_cursor": _cursor(context, "stack:" + state_id, end) if end < len(state.stack) else None}
            except ToolError:
                raise
            except ValueError:
                raise ToolError("out_of_scope", "unknown case ID or invalid capture") from None
        elif name in ("evaluate_predicate", "test_candidate"):
            from .evaluation import evaluate_dataset
            candidate = _candidate(context, args["predicate"])
            evaluation = evaluate_dataset(context.dataset, candidate.expression, workers=context.workers,
                                          execute=name == "test_candidate", cache_dir=context.run_dir / "cache")
            result_id = digest(canonical(evaluation))
            context._results[result_id] = evaluation
            result = {"valid_syntax": True, "checked_predicate": args["predicate"], **_result(context, result_id)}
        elif name == "get_candidate_result":
            result = _result(context, args["result_id"], args.get("cursor"))
        else:
            entries = context.dataset.manifest.get("analysis", [])
            entry = next((e for e in entries if e["function_id"] == args["function_id"] and e["view"] == args["view"]), None)
            if entry is None:
                raise ToolError("out_of_scope", "unknown analysis ID or view")
            if entry.get("availability") != "available":
                result = {k: entry.get(k) for k in ("function_id", "view", "availability", "reason", "backend", "backend_version")}
            else:
                path = (context.dataset.root / entry["path"]).resolve(strict=True)
                if not path.is_relative_to(context.dataset.root.resolve()):
                    raise ValueError("analysis path escapes dataset")
                offset = _offset(context, "analysis:" + args["function_id"] + ":" + args["view"], args.get("cursor"))
                with path.open("rb") as stream:
                    stream.seek(offset)
                    raw = stream.read(FUNCTION_PAGE_BYTES + 4)
                if not raw and offset:
                    raise ToolError("invalid_cursor", "cursor outside analysis")
                end = min(len(raw), FUNCTION_PAGE_BYTES)
                while end < len(raw) and raw[end] & 0xc0 == 0x80:
                    end -= 1
                size = path.stat().st_size
                result = {k: entry.get(k) for k in ("function_id", "view", "sha256", "availability", "complete", "backend", "backend_version")}
                result.update(text=raw[:end].decode(), byte_offset=offset, total_bytes=size, truncated=offset + end < size,
                              next_cursor=_cursor(context, "analysis:" + args["function_id"] + ":" + args["view"], offset + end) if offset + end < size else None)
        return {**base, "ok": True, **result}
    except ToolError as error:
        return {**base, "ok": False, "error": {"code": error.code, "message": str(error)}}
    except (ValueError, TypeError, KeyError, OSError, RecursionError):
        return {**base, "ok": False, "error": {"code": "backend_error", "message": "prepared dataset query failed"}}


def validate_proposal(context, value):
    if not isinstance(value, str) or len(value.encode()) > 16384:
        raise ValueError("proposal exceeds size bound")
    proposal = keys(strict_json(value), {"schema_version", "context_id", "decision", "predicate", "evidence_ids", "assumptions", "reason"})
    if type(proposal["schema_version"]) is not int or proposal["schema_version"] != 1 or proposal["context_id"] != context.context_id:
        raise ValueError("invalid proposal identity")
    if proposal["decision"] == "candidate":
        _candidate(context, proposal["predicate"])
    elif proposal["decision"] != "abstain" or proposal["predicate"] is not None:
        raise ValueError("invalid proposal decision")
    evidence = proposal["evidence_ids"]
    if not isinstance(evidence, list) or len(evidence) > 128 or any(not isinstance(e, str) for e in evidence) or len(set(evidence)) != len(evidence):
        raise ValueError("invalid evidence IDs")
    for eid in evidence:
        if eid not in context._results:
            context.dataset.case(eid)
    assumptions = proposal["assumptions"]
    if not isinstance(assumptions, list) or len(assumptions) > 16 or any(not isinstance(a, str) or not a.strip() or len(a.encode()) > 512 for a in assumptions):
        raise ValueError("invalid assumptions")
    if not isinstance(proposal["reason"], str) or not proposal["reason"].strip() or len(proposal["reason"].encode()) > 2048:
        raise ValueError("invalid reason")
    return proposal
