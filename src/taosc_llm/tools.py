"""Bounded prepared-evidence tools; execution and rejection remain host-owned."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

from .context import MAX_EXPRESSION, SynthesisContext, canonical, digest, keys, strict_json

PAGE_SIZE = 32
RESULT_PAGE_SIZE = 8
PROJECTION_VERSION = 1


class ToolError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def tool_definitions():
    from binradar.binradar_taosc_predicates import REGISTER_TO_VAR
    from .cases import ACTIVATIONS, COMPARISONS, OUTCOMES, SIMILAR_FEATURES

    def obj(properties, required=()):
        return {"type": "object", "properties": properties, "required": list(required), "additionalProperties": False}

    def choice(values):
        return {"type": "string", "enum": list(values)}

    identifier = {"type": "string", "minLength": 1, "maxLength": 160}
    cursor = {"type": "string", "minLength": 1, "maxLength": 4096}
    predicate = {"type": "string", "minLength": 1, "maxLength": MAX_EXPRESSION}
    register_filter = obj({"register": choice(REGISTER_TO_VAR), "op": choice(COMPARISONS),
        "value": {"type": "string", "minLength": 1, "maxLength": 20},
        "hit": choice(("first", "any", "all", "first_divergence"))}, ("register", "op", "value", "hit"))
    mutation_filter = obj({"kind": identifier, "size": {"type": "integer", "minimum": 1, "maximum": 1048576},
        "value": identifier, "target_extent": {"type": "integer", "minimum": 0, "maximum": 1048576}})
    filters = obj({"candidate_outcome": choice(OUTCOMES), "baseline_outcome": choice(OUTCOMES),
        "activation": choice(ACTIVATIONS), "reason": identifier, "warning": identifier,
        "transition": choice([a + "->" + b for a in OUTCOMES for b in OUTCOMES]),
        "register": register_filter, "mutation": mutation_filter})
    same_as = obj({"case_id": identifier, "features": {"type": "array", "minItems": 1,
        "maxItems": len(SIMILAR_FEATURES), "uniqueItems": True, "items": choice(SIMILAR_FEATURES)}}, ("case_id", "features"))
    specs = [
        ("get_patch_context", "Context and original-POC QASAN summary are already inline. Use view=poc_log only for paged diagnostic details; paths are normalized and this log does not define the target oracle.",
         {"view": choice(("context", "poc_log")), "cursor": cursor}, []),
        ("get_function_analysis", "Read a frozen procedure facet. Use listed procedure IDs and site windows. References require site=patch or destination bound to that procedure; they are exact-site xrefs, not procedure-wide. Never runs analysis.",
         {"procedure_id": identifier, "view": choice(("function", "instructions", "decompilation", "references")),
          "site": choice(("patch", "destination")), "window": obj({
              "address": {"type": "string", "minLength": 1, "maxLength": 20},
              "before": {"type": "integer", "minimum": 0, "maximum": 100},
              "after": {"type": "integer", "minimum": 0, "maximum": 100}}, ("address",)),
          "cursor": cursor}, ["procedure_id", "view"]),
        ("list_cases", "Search only the prepared/result population. Default order highlights counterexamples, control gaps and rare outcomes; same_as matches explicit known features.",
         {"domain": choice(("system", "function", "all")), "result_id": identifier, "filters": filters,
          "same_as": same_as, "order": choice(("noteworthy", "case_id")), "cursor": cursor}, ["domain"]),
        ("get_case", "Inspect separate baselines/candidate and ordered states. Missing candidate capture does not erase a known outcome.",
         {"case_id": identifier, "result_id": identifier, "state_id": identifier, "cursor": cursor}, ["case_id"]),
        ("evaluate_predicate", "Offline capture inference only. Inspect predicted divergence separately from actual activation; no target or replay execution.",
         {"predicate": predicate}, ["predicate"]),
        ("test_candidate", "Host evaluation and matched neutral controls. May execute concrete inputs and configured retained replay; never proof of repair.",
         {"predicate": predicate}, ["predicate"]),
        ("get_candidate_result", "Read outcome/control/activity summary and prioritized case pages from this session's result.",
         {"result_id": identifier, "cursor": cursor}, ["result_id"]),
    ]
    return [{"name": name, "description": description, "parameters": obj({
        "context_id": {"type": "string", "minLength": 64, "maxLength": 64}, **props}, ["context_id", *required])}
        for name, description, props, required in specs]


def _validate(value, schema):
    kind = schema["type"]
    if kind == "object":
        if not isinstance(value, dict) or set(value) - set(schema["properties"]) or set(schema.get("required", ())) - set(value):
            raise ToolError("invalid_arguments", "missing, unknown or invalid object argument")
        for key, item in value.items():
            _validate(item, schema["properties"][key])
    elif kind == "string":
        if (not isinstance(value, str) or not schema.get("minLength", 0) <= len(value.encode()) <= schema.get("maxLength", 4096)
                or ("enum" in schema and value not in schema["enum"])):
            raise ToolError("invalid_arguments", "invalid string argument")
    elif kind == "integer":
        if type(value) is not int or not schema.get("minimum", 0) <= value <= schema.get("maximum", 2**53 - 1):
            raise ToolError("invalid_arguments", "integer argument is outside its bounds")
    elif kind == "array":
        if not isinstance(value, list) or not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", 128):
            raise ToolError("invalid_arguments", "invalid array argument")
        for item in value:
            _validate(item, schema["items"])
        if schema.get("uniqueItems") and len({canonical(item) for item in value}) != len(value):
            raise ToolError("invalid_arguments", "array items must be unique")
    else:
        raise ToolError("invalid_arguments", "unsupported argument type")


def _cursor(context, scope, offset):
    payload = canonical([context.context_id, scope, offset])
    return base64.urlsafe_b64encode(payload + hmac.new(context._cursor_key, payload, hashlib.sha256).digest()).decode()


def _scope_description(scope):
    return canonical(scope).decode()[:768]


def _offset(context, scope, cursor):
    if cursor is None:
        return 0
    try:
        data = base64.b64decode(cursor, altchars=b"-_", validate=True)
        payload, signature = data[:-32], data[-32:]
        if not hmac.compare_digest(signature, hmac.new(context._cursor_key, payload, hashlib.sha256).digest()):
            raise ValueError()
        identity, actual, offset = json.loads(payload)
        if identity != context.context_id or type(offset) is not int or offset < 0:
            raise ValueError()
    except (ValueError, TypeError, UnicodeError):
        raise ToolError("invalid_cursor", "malformed cursor or cursor from another context") from None
    if actual != scope:
        raise ToolError("invalid_cursor", "cursor belongs to query " + _scope_description(actual)
                        + "; requested query " + _scope_description(scope))
    return offset


def _page(context, scope, records, cursor, *, size=PAGE_SIZE):
    offset = _offset(context, scope, cursor)
    if offset >= len(records) and offset:
        raise ToolError("invalid_cursor", "cursor outside result")
    end = min(offset + size, len(records))
    return {"items": records[offset:end], "offset": offset, "total": len(records),
            "query_id": digest(canonical(scope)), "truncated": end < len(records),
            "next_cursor": _cursor(context, scope, end) if end < len(records) else None}


def _candidate(dataset, expression):
    from .family import parse_candidate
    if not isinstance(expression, str) or not expression.strip() or len(expression.encode()) > MAX_EXPRESSION:
        raise ToolError("invalid_predicate", "predicate exceeds expression bound")
    try:
        return parse_candidate(dataset.patch_format, expression)
    except (ValueError, RecursionError) as error:
        raise ToolError("invalid_predicate", "canonical family parser rejected predicate") from error


def _known_result(context, result_id):
    if result_id not in context._results:
        raise ToolError("out_of_scope", "unknown candidate result; use a returned result_id")
    return context._results[result_id]


def _case_page(context, dataset, args, *, size=PAGE_SIZE):
    from .cases import case_records, public_cases, relevant_registers, select_cases
    evaluation = _known_result(context, args["result_id"]) if args.get("result_id") else None
    scope = {"view": "cases", "projection_version": PROJECTION_VERSION,
             "domain": args.get("domain", "all"), "result_id": args.get("result_id"),
             "filters": args.get("filters", {}), "same_as": args.get("same_as"),
             "order": args.get("order", "noteworthy")}
    # Authenticate scope before loading or searching any state pages.
    _offset(context, scope, args.get("cursor"))
    records = case_records(dataset, evaluation)
    try:
        selected = select_cases(dataset, records, scope["domain"], scope["filters"], scope["same_as"])
    except KeyError as error:
        raise ToolError("out_of_scope", str(error)) from None
    except ValueError as error:
        raise ToolError("invalid_arguments", str(error)) from None
    result = _page(context, scope, public_cases(selected, scope["order"]), args.get("cursor"), size=size)
    result["query"] = {"domain": scope["domain"], "order": scope["order"], "filters": scope["filters"]}
    if scope["result_id"]:
        result["query"]["result_id"] = scope["result_id"]
    if scope["same_as"]:
        result["query"]["same_as"] = scope["same_as"]
    if scope["filters"].get("register"):
        result["register_evidence"] = ("offline_reference_not_candidate_execution"
            if scope["filters"]["register"]["hit"] == "first_divergence"
            else "candidate_capture" if evaluation is not None else "prepared_capture")
    if evaluation is not None:
        lookup = {record["report"]["case_id"]: record for record in selected}
        result["items"] = [dict(item) for item in result["items"]]
        for item in result["items"]:
            registers = relevant_registers(dataset, lookup[item["case_id"]], evaluation.get("predicate"))
            if registers is not None:
                item["relevant_registers"] = registers
    return result


def _result(context, dataset, result_id, cursor=None):
    from .cases import case_records
    from .evidence import summarize_reports
    result = _known_result(context, result_id)
    summary = result.get("report_summary")
    if summary is None:
        summary = summarize_reports([item["report"] for item in case_records(dataset, result)])
    status = {"reject_same_crash": "rejects_target", "not_rejected": "observed", "unavailable": "unknown"}.get(result.get("status"), "unknown")
    return {"result_id": result_id, "predicate": result.get("predicate"), "status": status,
            "verified": False, "evaluation_mode": result.get("evaluation_mode", "historical"),
            "summary": summary, "cases": _case_page(context, dataset,
                {"result_id": result_id, "domain": "all", "order": "noteworthy", "cursor": cursor}, size=RESULT_PAGE_SIZE)}


def _case_detail(context, dataset, args):
    from binradar import binradar_taosc_predicates as predicates
    from .evaluation import _snapshots
    from .evidence import project_case
    try:
        case = dataset.case(args["case_id"])
    except ValueError:
        raise ToolError("out_of_scope", "unknown case_id; select a returned case") from None
    result_id = args.get("result_id")
    evaluated = None
    evaluation = _known_result(context, result_id) if result_id is not None else {}
    if result_id is not None:
        evaluated = next((item for item in evaluation.get("cases", [])
                          if item["case_id"] == case["id"]), None)
        if evaluated is None:
            raise ToolError("out_of_scope", "case not present in candidate result")
    result = {"case": evaluated.get("report") if evaluated and evaluated.get("report") is not None
              else project_case(dataset, case, evaluated, descriptor=evaluation.get("descriptor"),
                                predicate=evaluation.get("predicate")), "result_id": result_id}
    capture = (evaluated if evaluated is not None else case).get("capture")
    scope = case["id"] + ":" + (result_id or "prepared")
    state_id = args.get("state_id")
    candidate_unverified = result_id is not None and result["case"]["activation"]["status"] == "unknown"
    if capture is None or capture.get("complete") is not True or candidate_unverified:
        if state_id is not None:
            raise ToolError("out_of_scope", "state does not belong to an available capture")
        if args.get("cursor") is not None:
            _offset(context, "states:" + scope, args["cursor"])
            raise ToolError("invalid_cursor", "cursor outside unavailable capture")
        result["state_capture"] = {"status": "unavailable", "basis": "candidate" if result_id else "prepared",
                                   "reason": "candidate-capture-unverified" if candidate_unverified
                                             else "no-complete-capture"}
        return result
    try:
        states = _snapshots(dataset, capture)
    except (ValueError, OSError, KeyError, TypeError):
        raise ToolError("not_available", "capture failed identity/completeness validation") from None
    result["state_capture"] = {"status": "complete", "basis": "candidate" if result_id else "prepared",
                               "total_hits": len(states), "descriptor": capture["descriptor"]}

    def project(index):
        state = states[index]
        eid = scope + ":hit:" + str(index)
        context._evidence_ids.add(eid)
        return {"state_id": eid, "hit_index": index, "branch": state.branch,
                "registers": {name: str(predicates.wrap64(state.registers[position]))
                              for name, position in predicates.REGISTER_TO_VAR.items()},
                "clamps": [[str(begin), str(end)] for begin, end in state.clamps],
                "stack_bytes": len(state.stack), "stack_sha256": digest(state.stack)}

    if state_id is None:
        page = _page(context, "states:" + scope, range(len(states)), args.get("cursor"))
        page["items"] = [project(index) for index in page["items"]]
        result["states"] = page
        result["zero_hits"] = not states
        return result
    prefix = scope + ":hit:"
    if not state_id.startswith(prefix) or not state_id[len(prefix):].isdecimal():
        raise ToolError("out_of_scope", "state does not belong to case/result")
    index = int(state_id[len(prefix):])
    if index >= len(states) or state_id != prefix + str(index):
        raise ToolError("out_of_scope", "state does not belong to case/result")
    state = states[index]
    offset = _offset(context, "stack:" + state_id, args.get("cursor"))
    if offset >= len(state.stack) and offset:
        raise ToolError("invalid_cursor", "cursor outside captured stack")
    end = min(offset + 4096, len(state.stack))
    result["state"] = project(index)
    result["stack"] = {"hex": state.stack[offset:end].hex(), "byte_offset": offset,
        "total_bytes": len(state.stack), "truncated": end < len(state.stack),
        "next_cursor": _cursor(context, "stack:" + state_id, end) if end < len(state.stack) else None}
    return result


def _analysis(context, dataset, args):
    from .analysis import analysis_view
    scope = {"query": "analysis", "projection_version": PROJECTION_VERSION,
             **{key: args.get(key) for key in ("procedure_id", "view", "site", "window")}}
    offset = _offset(context, scope, args.get("cursor"))
    try:
        result = analysis_view(dataset, args["procedure_id"], args["view"], site=args.get("site"),
                               window=args.get("window"), offset=offset)
    except ValueError as error:
        raise ToolError("out_of_scope", str(error)) from None
    next_offset = result.pop("next_offset", None)
    result["next_cursor"] = _cursor(context, scope, next_offset) if next_offset is not None else None
    result["query_id"] = digest(canonical(scope))
    if result.get("evidence_id"):
        context._evidence_ids.add(result["evidence_id"])
    return result


def _poc_log(context, dataset, args):
    from .analysis import _page_text
    from .evidence import poc_log
    log = poc_log(dataset)
    scope = {"view": "poc_log", "projection_version": PROJECTION_VERSION,
             "log_sha256": log["source"]["log_sha256"]}
    offset = _offset(context, scope, args.get("cursor"))
    text, extent, total, next_offset = _page_text(log.pop("text"), offset)
    log.update(text=text, range=extent, total_bytes=total)
    if log["source"]["log_sha256"] is not None:
        log["evidence_id"] = "poc-log:" + digest(canonical([dataset.dataset_id, log]))
        context._evidence_ids.add(log["evidence_id"])
    return {"poc_log": log, "query_id": digest(canonical(scope)),
            "truncated": next_offset is not None or log["source_truncated"],
            "next_cursor": _cursor(context, scope, next_offset) if next_offset is not None else None}


def call_tool(context: SynthesisContext, name, args):
    base = {"context_id": context.context_id, "dataset_id": context.dataset.dataset_id, "truncated": False}
    try:
        definitions = {item["name"]: item for item in tool_definitions()}
        if name not in definitions:
            raise ToolError("out_of_scope", "tool is not allowed")
        if not isinstance(args, dict):
            raise ToolError("invalid_arguments", "arguments must be an object")
        if args.get("context_id") != context.context_id:
            raise ToolError("stale_context", "context ID mismatch")
        _validate(args, definitions[name]["parameters"])
        with context.dataset.validation() as dataset:
            if name == "get_patch_context":
                if args.get("view", "context") == "poc_log":
                    result = _poc_log(context, dataset, args)
                elif "cursor" in args:
                    raise ToolError("invalid_arguments", "cursor is only valid for view=poc_log")
                else:
                    result = {"patch_context": context.projection}
            elif name == "get_function_analysis":
                result = _analysis(context, dataset, args)
            elif name == "list_cases":
                result = _case_page(context, dataset, args)
            elif name == "get_case":
                result = _case_detail(context, dataset, args)
            elif name == "get_candidate_result":
                result = _result(context, dataset, args["result_id"], args.get("cursor"))
            else:
                from .evaluation import evaluate_dataset
                candidate = _candidate(dataset, args["predicate"])
                evaluation = evaluate_dataset(dataset, candidate.expression, workers=context.workers,
                    execute=name == "test_candidate", cache_dir=context.cache_dir or context.run_dir / "cache",
                    replay_socket=context.replay_socket if name == "test_candidate" else None)
                result_id = digest(canonical(evaluation))
                context._results[result_id] = evaluation
                result = {"valid_syntax": True, "checked_predicate": args["predicate"],
                          **_result(context, dataset, result_id)}
        return {**base, "ok": True, **result}
    except ToolError as error:
        return {**base, "ok": False, "error": {"code": error.code, "message": str(error)}}
    except (ValueError, TypeError, KeyError, OSError, RecursionError):
        return {**base, "ok": False, "error": {"code": "backend_error", "message": "prepared dataset query failed"}}


def validate_proposal(context: SynthesisContext, value):
    if not isinstance(value, str) or len(value.encode()) > 16384:
        raise ValueError("proposal exceeds size bound")
    proposal = keys(strict_json(value), {"schema_version", "context_id", "decision", "predicate", "evidence_ids", "assumptions", "reason"})
    if type(proposal["schema_version"]) is not int or proposal["schema_version"] != 1 or proposal["context_id"] != context.context_id:
        raise ValueError("invalid proposal identity")
    if proposal["decision"] == "candidate":
        _candidate(context.dataset, proposal["predicate"])
    elif proposal["decision"] != "abstain" or proposal["predicate"] is not None:
        raise ValueError("invalid proposal decision")
    evidence = proposal["evidence_ids"]
    if not isinstance(evidence, list) or len(evidence) > 128 or any(not isinstance(e, str) for e in evidence) or len(set(evidence)) != len(evidence):
        raise ValueError("invalid evidence IDs")
    for eid in evidence:
        if eid not in context._results and eid not in context._evidence_ids:
            context.dataset.case(eid)
    assumptions = proposal["assumptions"]
    if not isinstance(assumptions, list) or len(assumptions) > 16 or any(not isinstance(a, str) or not a.strip() or len(a.encode()) > 512 for a in assumptions):
        raise ValueError("invalid assumptions")
    if not isinstance(proposal["reason"], str) or not proposal["reason"].strip() or len(proposal["reason"].encode()) > 2048:
        raise ValueError("invalid reason")
    return proposal
