"""Compact model tools over complete, authenticated host evidence."""
from __future__ import annotations

import secrets

from .context import MAX_EXPRESSION, SynthesisContext, canonical, digest, keys, strict_json

STATE_PAGE_SIZE = 3


class ToolError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def tool_definitions():
    from binradar.binradar_taosc_predicates import REGISTER_TO_VAR
    from .analysis import FUNCTION_FACETS
    from .cases import COMPARISONS, SIMILAR_FEATURES

    def obj(properties, required=()):
        return {"type": "object", "properties": properties, "required": list(required), "additionalProperties": False}

    def choice(values):
        return {"type": "string", "enum": list(values)}

    identifier = {"type": "string", "minLength": 1, "maxLength": 160}
    cursor = {"type": "string", "minLength": 1, "maxLength": 64}
    predicate = {"type": "string", "minLength": 1, "maxLength": MAX_EXPRESSION}
    register_filter = obj({"register": choice(REGISTER_TO_VAR), "op": choice(COMPARISONS),
        "value": {"type": "string", "minLength": 1, "maxLength": 20},
        "hit": choice(("first", "any", "all", "first_divergence"))}, ("register", "op", "value", "hit"))
    mutation_filter = obj({"kind": identifier, "size": {"type": "integer", "minimum": 1, "maximum": 1048576},
        "value": identifier, "target_extent": {"type": "integer", "minimum": 0, "maximum": 1048576}})
    outcomes = ("target_crash", "normal")
    filters = obj({"candidate_outcome": {**choice(outcomes), "description": "Requires result_id; actual candidate outcome, not offline prediction."},
        "baseline_outcome": {**choice(outcomes), "description": "Authenticated same-case neutral p0 outcome on the prepared/cached artifact; not the original POC outcome. Unknown evidence does not match."},
        "activation": {**choice(("fired", "not_fired", "zero_hits", "trapped")), "description": "Requires result_id; authenticated actual candidate capture only."},
        "register": register_filter, "mutation": mutation_filter})
    same_as = obj({"case_id": {**identifier, "description": "Reference case in the selected prepared/result population; excluded from matches."},
        "features": {"type": "array", "minItems": 1, "description": "Explicit feature names only; unknown reference evidence is an error. candidate_outcome requires result_id.",
        "maxItems": len(SIMILAR_FEATURES), "uniqueItems": True, "items": choice(SIMILAR_FEATURES)}}, ("case_id", "features"))
    specs = [
        ("get_patch_context", "Context is already inline. Request poc_log only for detailed POC diagnostics.",
         {"view": choice(("context", "poc_log")), "cursor": cursor}, []),
        ("get_function_analysis", "Read a frozen procedure using its canonical procedure_id from context.analysis.procedures, not a role or address. view=function lists available facets; select facet there for local CFG or value flow. Instruction windows count instructions. view=references requires site=patch or destination.",
         {"procedure_id": {**identifier, "description": "Exact procedure_id returned in context.analysis.procedures (for example procedure:0x1000)."}, "view": choice(("function", "instructions", "decompilation", "references")),
          "facet": {**choice(FUNCTION_FACETS), "description": "Only with view=function; omit to inspect availability first."}, "address": {"type": "string", "minLength": 1, "maxLength": 20},
          "site": choice(("patch", "destination")), "window": obj({
              "address": {"type": "string", "minLength": 1, "maxLength": 20},
              "before": {"type": "integer", "minimum": 0, "maximum": 100},
              "after": {"type": "integer", "minimum": 0, "maximum": 100}}, ("address",)),
          "cursor": cursor}, ["procedure_id", "view"]),
        ("list_cases", "Up to three target-crash and three normal examples, not an exhaustive listing. Candidate-outcome/activation filters and candidate_outcome similarity require a returned result_id. baseline_outcome means the same-case neutral p0 outcome, not original POC. same_as uses explicit known features and excludes its reference case.",
         {"domain": choice(("system", "function", "all")), "result_id": identifier,
          "filters": filters, "same_as": same_as}, []),
        ("get_case", "Inspect one case and its captured registers; state_id reads captured stack bytes.",
         {"case_id": identifier, "result_id": identifier, "state_id": identifier, "cursor": cursor}, ["case_id"]),
        ("evaluate_predicate", "Check existing captures only; return missed target crashes and regressions. Does not execute.",
         {"predicate": predicate}, ["predicate"]),
        ("test_candidate", "Host evaluation, including execution when needed; return missed target crashes and regressions.",
         {"predicate": predicate}, ["predicate"]),
        ("get_candidate_result", "Retrieve concise failure feedback for a returned result.",
         {"result_id": identifier}, ["result_id"]),
    ]
    return [{"name": name, "description": description, "parameters": obj({
        "context_id": {"type": "string", "minLength": 1, "maxLength": 64}, **props}, ["context_id", *required])}
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
    token = "p-" + secrets.token_urlsafe(12)
    context._cursors[token] = (canonical(scope), offset)
    return token


def _offset(context, scope, cursor):
    if cursor is None:
        return 0
    record = context._cursors.get(cursor)
    if record is None:
        raise ToolError("invalid_cursor", "cursor was not issued in this context")
    if record[0] != canonical(scope):
        raise ToolError("invalid_cursor", "cursor belongs to another query")
    return record[1]


def _page(context, scope, records, cursor):
    offset = _offset(context, scope, cursor)
    if offset >= len(records) and offset:
        raise ToolError("invalid_cursor", "cursor outside result")
    end = min(offset + STATE_PAGE_SIZE, len(records))
    result = {"items": records[offset:end], "offset": offset, "total": len(records)}
    if end < len(records):
        result["next_cursor"] = _cursor(context, scope, end)
    return result


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
        raise ToolError("out_of_scope", "use a returned result_id")
    return context._results[result_id]


def _case_examples(context, dataset, args):
    from .cases import case_records, select_cases
    from .presentation import sample_cases
    evaluation = _known_result(context, args["result_id"]) if args.get("result_id") else None
    if evaluation is None:
        candidate_filters = set(args.get("filters", {})) & {"candidate_outcome", "activation"}
        candidate_similarity = "candidate_outcome" in args.get("same_as", {}).get("features", [])
        if candidate_filters or candidate_similarity:
            raise ToolError("invalid_arguments", "candidate_outcome and activation require result_id; "
                            "call evaluate_predicate or test_candidate, then use its returned result_id")
    try:
        records = select_cases(dataset, case_records(dataset, evaluation), args.get("domain", "all"),
                               args.get("filters", {}), args.get("same_as"))
    except KeyError as error:
        raise ToolError("out_of_scope", str(error)) from None
    except ValueError as error:
        raise ToolError("invalid_arguments", str(error)) from None
    result = sample_cases(dataset, records, predicate=(evaluation or {}).get("predicate"))
    for examples in result.values():
        for example in examples:
            context._evidence_ids.add(example["case_id"])
    return result


def _result(context, dataset, result_id):
    from .presentation import feedback
    result = _known_result(context, result_id)
    return {"result_id": result_id, "predicate": result.get("predicate"),
            "mode": result.get("evaluation_mode", "recorded"), **feedback(dataset, result)}


def _resolve_case(dataset, case_id):
    from .cases import resolve_case
    try:
        return resolve_case(dataset, case_id)
    except ValueError:
        raise ToolError("out_of_scope", "use a returned case_id") from None


def _case_detail(context, dataset, args):
    from binradar import binradar_taosc_predicates as predicates
    from .evaluation import _snapshots
    from .evidence import project_case
    from .presentation import compact_case
    case = _resolve_case(dataset, args["case_id"])
    result_id = args.get("result_id")
    evaluation = _known_result(context, result_id) if result_id else {}
    evaluated = None
    if result_id:
        evaluated = next((item for item in evaluation.get("cases", []) if item["case_id"] == case["id"]), None)
        if evaluated is None:
            raise ToolError("out_of_scope", "case is not in that result")
    elif context._poc and case["id"] == (context._poc.get("case") or {}).get("id"):
        case = {**case, "capture": (context._poc.get("neutral") or {}).get("capture"),
                "observation": context._poc.get("original", {}).get("outcome") or case.get("observation", {})}
    report = (evaluated.get("report") if evaluated else None) or project_case(
        dataset, case, evaluated, descriptor=evaluation.get("descriptor"), predicate=evaluation.get("predicate"))
    result = {"case": compact_case(dataset, report, predicate=evaluation.get("predicate"))}
    capture = (evaluated if evaluated is not None else case).get("capture")
    scope = case["id"] + ":" + (result_id or "neutral")
    state_id = args.get("state_id")
    if capture is None or capture.get("complete") is not True or (result_id and report["activation"]["status"] == "unknown"):
        if state_id is not None:
            raise ToolError("out_of_scope", "state is not captured for this observation")
        if args.get("cursor") is not None:
            _offset(context, "states:" + scope, args["cursor"])
            raise ToolError("invalid_cursor", "no state continuation")
        result["note"] = "No captured registers for this observation."
        return result
    try:
        states = _snapshots(dataset, capture)
    except (ValueError, OSError, KeyError, TypeError):
        raise ToolError("not_available", "capture failed validation") from None
    result["basis"] = "candidate_capture" if result_id else "neutral_capture"

    def project(index):
        state = states[index]
        eid = scope + ":hit:" + str(index)
        context._evidence_ids.add(eid)
        value = {"state_id": eid, "hit_index": index, "branch": state.branch,
                 "registers": {name: str(predicates.wrap64(state.registers[position]))
                               for name, position in predicates.REGISTER_TO_VAR.items()}}
        if state.clamps:
            value["clamps"] = [[str(begin), str(end)] for begin, end in state.clamps]
        if state.stack:
            value["stack_bytes"] = len(state.stack)
        return value

    if state_id is None:
        page = _page(context, "states:" + scope, range(len(states)), args.get("cursor"))
        page["items"] = [project(index) for index in page["items"]]
        result["states"] = page
        return result
    prefix = scope + ":hit:"
    if not state_id.startswith(prefix) or not state_id[len(prefix):].isdecimal():
        raise ToolError("out_of_scope", "state does not belong to this observation")
    index = int(state_id[len(prefix):])
    if index >= len(states) or state_id != prefix + str(index):
        raise ToolError("out_of_scope", "state does not belong to this observation")
    state = states[index]
    offset = _offset(context, "stack:" + state_id, args.get("cursor"))
    if offset >= len(state.stack) and offset:
        raise ToolError("invalid_cursor", "cursor outside captured stack")
    end = min(offset + 4096, len(state.stack))
    result["state"] = project(index)
    result["stack"] = {"hex": state.stack[offset:end].hex(), "byte_offset": offset, "total_bytes": len(state.stack)}
    if end < len(state.stack):
        result["stack"]["next_cursor"] = _cursor(context, "stack:" + state_id, end)
    return result


def _analysis(context, dataset, args):
    from .analysis import analysis_view
    scope = {key: args.get(key) for key in ("procedure_id", "view", "site", "window", "facet", "address")}
    offset = _offset(context, scope, args.get("cursor"))
    try:
        result = analysis_view(dataset, args["procedure_id"], args["view"], site=args.get("site"),
                               window=args.get("window"), facet=args.get("facet"), address=args.get("address"), offset=offset)
    except ValueError as error:
        raise ToolError("out_of_scope", str(error)) from None
    next_offset = result.pop("next_offset", None)
    if next_offset is not None:
        result["next_cursor"] = _cursor(context, scope, next_offset)
    return context.expose_evidence(result)


def _poc_log(context, dataset, args):
    from .analysis import _page_text
    from .evidence import poc_log
    log = poc_log(dataset)
    scope = {"view": "poc_log"}
    offset = _offset(context, scope, args.get("cursor"))
    text, extent, total, next_offset = _page_text(log["text"], offset)
    if not text:
        return {"note": "No saved POC log text." if not log["source_truncated"] else "POC log exceeds the bounded excerpt."}
    result = {"text": text, "range": extent, "total_bytes": total,
              "evidence_id": context.reference("poc-log:" + digest(canonical([log["source"], extent, text])))}
    if next_offset is not None:
        result["next_cursor"] = _cursor(context, scope, next_offset)
    if log["source_truncated"]:
        result["note"] = "Source excerpt limited to 1 MiB; remaining source is omitted."
    return result


def call_tool(context: SynthesisContext, name, args, *, operation_check=None):
    base = {"context_id": context.context_id}
    try:
        if operation_check is not None:
            operation_check()
        definitions = {item["name"]: item for item in tool_definitions()}
        if name not in definitions:
            raise ToolError("out_of_scope", "tool is not allowed")
        if not isinstance(args, dict):
            raise ToolError("invalid_arguments", "arguments must be an object")
        if args.get("context_id") != context.context_id:
            raise ToolError("stale_context", "context ID mismatch")
        _validate(args, definitions[name]["parameters"])
        if name in ("evaluate_predicate", "test_candidate"):
            # A rejected expression cannot read evidence, publish a result or
            # execute a target. Successful parsing grants no trust: below we
            # still authenticate the whole dataset and parse its bound family.
            _candidate(context.dataset, args["predicate"])
        scope = (context.dataset.validation() if operation_check is None
                 else context.dataset.validation(check=operation_check))
        with scope as dataset:
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
                result = _case_examples(context, dataset, args)
            elif name == "get_case":
                result = _case_detail(context, dataset, args)
            elif name == "get_candidate_result":
                result = _result(context, dataset, args["result_id"])
            else:
                from .evaluation import evaluate_dataset
                candidate = _candidate(dataset, args["predicate"])
                evaluation = evaluate_dataset(dataset, candidate.expression, workers=context.workers,
                    execute=name == "test_candidate", cache_dir=context.cache_dir or context.run_dir / "cache",
                    replay_socket=context.replay_socket if name == "test_candidate" else None,
                    operation_check=operation_check)
                if operation_check is not None:
                    operation_check()
                result_id = context.reference(digest(canonical(evaluation)), kind="r")
                context._results[result_id] = evaluation
                result = _result(context, dataset, result_id)
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
