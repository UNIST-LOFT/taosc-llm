"""Host-selected local REA static views; never a model-accessible analysis service."""
from __future__ import annotations

import hashlib
import os
import re
import shutil
from pathlib import Path

from ._rea import ReaSession
from .dataset import canonical, read_json, sha256

_OPERATIONS = {"resolve": "resolve_containing_procedure", "function": "analyze_function",
               "instructions": "read_function_instructions", "references": "xrefs"}


def _unavailable(value) -> str | None:
    if isinstance(value, dict):
        if value.get("truncated") is True or value.get("complete") is False:
            return str(value.get("reason") or "backend reports incomplete analysis")
        if value.get("available") is False or value.get("availability") in ("unavailable", "unsupported") or value.get("status") in ("unavailable", "error", "unsupported", "incomplete", "partial") or value.get("success") is False or value.get("ok") is False:
            return str(value.get("reason") or value.get("error") or value.get("status") or "backend unavailable")
    return None


def _coverage(payload, view):
    """A partial relationship is a limitation, not failure of sibling facets."""
    data = payload.get("data", {}) if isinstance(payload, dict) else {}
    value = data.get("normalized_result")
    facets = value.get("facet_availability", {}) if isinstance(value, dict) else {}
    facets = {name: {"available": facet.get("available") is True,
                     **({"reason": str(facet["reason"])[:512]} if facet.get("reason") else {})}
              for name, facet in facets.items() if isinstance(facet, dict)}
    limitations = []

    def visit(node, path="result"):
        if len(limitations) >= 16:
            return
        if isinstance(node, dict):
            reason = _unavailable(node)
            if reason:
                item = f"{path}: {reason}"[:512]
                if item not in limitations:
                    limitations.append(item)
            for key, child in node.items():
                if isinstance(child, (dict, list)):
                    visit(child, f"{path}.{key}")
        elif isinstance(node, list):
            for index, child in enumerate(node):
                if isinstance(child, (dict, list)):
                    visit(child, f"{path}[{index}]")
                if len(limitations) >= 16:
                    break

    visit(value)
    if isinstance(value, dict):
        for item in value.get("limitations", []):
            if isinstance(item, str) and item[:512] not in limitations:
                limitations.append(item[:512])
    reason = _unavailable(payload) or _unavailable(data)
    if reason is None and view == "decompilation":
        facet = facets.get("pseudocode", {})
        if (facet.get("available") is not True or not isinstance(value, dict)
                or not isinstance(value.get("pseudocode"), str) or not value["pseudocode"].strip()):
            reason = facet.get("reason") or "REA pseudocode unavailable"
    elif reason is None and view == "function":
        # Dossiers with at least one explicitly admitted facet remain usable.
        if not isinstance(value, dict):
            reason = "REA function dossier unavailable"
        elif facets:
            if not any(facet["available"] for facet in facets.values()):
                reason = "REA function facets unavailable"
        else:
            reason = _unavailable(value)
    elif reason is None:
        reason = _unavailable(value)
        if reason is None and view == "instructions" and (
                not isinstance(value, dict) or not isinstance(value.get("instructions"), list)):
            reason = "REA decoded instruction inventory unavailable"
        if reason is None and view == "references" and not (
                isinstance(value, list) or isinstance(value, dict) and isinstance(value.get("references"), list)):
            reason = "REA exact-address references unavailable"
    complete = reason is None and not limitations and all(facet["available"] for facet in facets.values())
    return reason, complete, facets, limitations[:16]


def _backend_version(value):
    if isinstance(value, dict):
        provider = value.get("provider")
        if isinstance(provider, dict) and isinstance(provider.get("version"), str):
            return provider["version"]
        for key in ("backend_version", "backendVersion", "provider_version", "providerVersion"):
            if isinstance(value.get(key), str):
                return value[key]
        for child in value.values():
            version = _backend_version(child)
            if version is not None:
                return version
    elif isinstance(value, list):
        for child in value:
            version = _backend_version(child)
            if version is not None:
                return version
    return None


def _static_identity(payload, artifact_hash: str, address: int, command: str, provider: str) -> str | None:
    """Validate original REA Evidence; never rewrite its bound query parameters."""
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        return _unavailable(payload) or "REA static evidence envelope unavailable"
    data = payload.get("data")
    if not isinstance(data, dict):
        return "REA static evidence data unavailable"
    subject, backend, parameters = (data.get(key) for key in ("subject", "provider", "parameters"))
    if (not isinstance(subject, dict) or not isinstance(subject.get("digest"), dict)
            or subject["digest"].get("sha256") != artifact_hash):
        return "REA static evidence artifact identity mismatch"
    if not isinstance(backend, dict) or backend.get("id") != provider:
        return "REA static evidence provider identity mismatch"
    parameter = "address" if command in ("resolve", "references") else "procedure"
    if (data.get("operation") != _OPERATIONS[command] or not isinstance(parameters, dict)
            or parameters.get(parameter) != hex(address)):
        return "REA static evidence operation/address identity mismatch"
    if data.get("normalized_result") is None:
        return "REA normalized static evidence unavailable"
    return None


def _resolve(payload: dict, digest: str, address: int, provider: str) -> tuple[int | None, dict, str | None]:
    extent = {"start": address, "end": None, "address_domain": "elf-va", "confidence": "unavailable"}
    reason = _static_identity(payload, digest, address, "resolve", provider) or _unavailable(payload)
    if reason:
        return None, extent, reason
    value = payload["data"]["normalized_result"]
    if (not isinstance(value, dict) or value.get("found") is not True
            or value.get("query_address") != hex(address)):
        return None, extent, "REA did not resolve the requested containing function"
    procedure = value.get("procedure")
    if not isinstance(procedure, dict):
        return None, extent, "REA containing function identity unavailable"
    if (_unavailable(value) or _unavailable(procedure)
            or _unavailable(procedure.get("body"))):
        return None, extent, "REA containing function body is incomplete or unavailable"
    try:
        entry = int(procedure["address"], 16)
        body = procedure["body"]
        ranges = [(int(item["start"], 16), int(item["end"], 16)) for item in body["ranges"]]
        if (body.get("available") is not True or not ranges or entry <= 0
                or any(start < 0 or end < start or end >= 2**64 for start, end in ranges)
                or not any(start <= address <= end for start, end in ranges)
                or not any(start <= entry <= end for start, end in ranges)):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        return None, extent, "REA containing function has no complete, matching body ranges"
    extent = {"start": min(start for start, _ in ranges), "end": max(end for _, end in ranges) + 1,
              "ranges": [{"start": start, "end": end + 1} for start, end in ranges],
              "entry": entry, "address_domain": "elf-va", "confidence": "ghidra-function-body"}
    return entry, extent, None


def prepare_analysis(root: Path, binary: Path, addresses: dict[str, int], *,
                     rea: str | None, provider: str, timeout: int = 900,
                     query_timeout: int = 120) -> list[dict]:
    if provider != "ghidra":
        raise ValueError("static preparation currently supports only the explicit ghidra provider")
    if any(type(value) is not int or not 1 <= value <= 2147483 for value in (timeout, query_timeout)):
        raise ValueError("static analysis timeouts must be 1..2147483 integer seconds")
    root, binary = root.resolve(), binary.resolve()
    executable = rea or os.environ.get("TAOSC_LLM_REA") or shutil.which("rea")
    if executable:
        executable = str(Path(executable).absolute()) if os.path.sep in executable else shutil.which(executable)
    cache = root / "analysis-cache"
    cache.mkdir()
    (root / "analysis").mkdir()
    environment = {key: os.environ[key] for key in ("PATH", "JAVA_HOME", "GHIDRA_INSTALL_DIR", "LANG") if key in os.environ}
    environment.update({"HOME": str(cache), "XDG_CACHE_HOME": str(cache / "cache"),
                        "XDG_CONFIG_HOME": str(cache / "config"), "XDG_DATA_HOME": str(cache / "data"),
                        "REA_ANALYSIS_PROVIDER": provider,
                        "REA_GHIDRA_STARTUP_TIMEOUT_MS": str(timeout * 1000),
                        # Leave transport/dossier time after the native decompiler's own deadline.
                        "REA_GHIDRA_DECOMPILE_TIMEOUT_SECONDS": str(max(1, query_timeout * 3 // 4))})
    artifact_hash = sha256(binary)
    records: list[dict] = []
    resolutions: dict[str, tuple[dict, int | None, dict, str | None]] = {}
    observations: dict[tuple[str, int], tuple[dict, str]] = {}
    rea_version = None

    def publish(function_id, view, payload, reason, analysis_address, reused_from=None):
        resolution, _entry, extent, _resolution_reason = resolutions[function_id]
        version = _backend_version(payload)
        command = "function" if view == "decompilation" else view
        _facet_reason, complete, facets, limitations = _coverage(payload, view)
        record = {"function_id": function_id, "view": view,
                  "path": f"analysis/{function_id}-{view}.json",
                  "availability": "unavailable" if reason else "available", "reason": reason,
                  "complete": reason is None and complete, "facets": facets, "limitations": limitations,
                  "backend": provider, "backend_version": version,
                  "backend_version_availability": "available" if version else "unavailable",
                  "rea_version": rea_version, "artifact_sha256": artifact_hash,
                  "range": extent, "requested_address": addresses[function_id],
                  "analysis_address": analysis_address,
                  "provenance": {"operation": _OPERATIONS[command], "provider": provider, "local_static": True}}
        if reused_from is not None:
            record["reused_from"] = reused_from
        output = {"metadata": record, "resolution": resolution, "evidence": payload}
        if view == "decompilation":
            record["provenance"]["facet"] = "pseudocode"
            output["value"] = payload["data"]["normalized_result"].get("pseudocode") if reason is None else None
        path = root / record["path"]
        path.write_bytes(canonical(output) + b"\n")
        record["sha256"] = sha256(path)
        records.append(record)

    def collect(session: ReaSession | None):
        # Resolve actual Ghidra bodies, including stripped/non-contiguous functions.
        # A selected destination is an entry point, not proof of a safe error handler.
        for function_id, address in addresses.items():
            payload = session.query(_OPERATIONS["resolve"], address) if session else {"ok": False, "error": failure}
            entry, extent, reason = _resolve(payload, artifact_hash, address, provider)
            resolutions[function_id] = (payload, entry, extent, reason)
        # Preserve cheap listing/address facts before any bounded decompilation.
        for view in ("instructions", "references", "function", "decompilation"):
            for function_id, address in addresses.items():
                _resolution, entry, _extent, resolution_reason = resolutions[function_id]
                command = "function" if view == "decompilation" else view
                analysis_address = address if view == "references" else entry
                reused_from = None
                payload: dict | None
                if analysis_address is None:
                    payload, reason = None, resolution_reason
                else:
                    key = (command, analysis_address)
                    if key in observations:
                        payload, source = observations[key]
                        if source != function_id:
                            reused_from = source
                    else:
                        payload = session.query(_OPERATIONS[command], analysis_address) if session else {"ok": False, "error": failure}
                        observations[key] = (payload, function_id)
                    reason = _static_identity(payload, artifact_hash, analysis_address, command, provider)
                    if reason is None:
                        reason, _complete, _facets, _limitations = _coverage(payload, view)
                publish(function_id, view, payload, reason, analysis_address, reused_from)

    try:
        failure = "REA executable unavailable"
        if executable:
            session = ReaSession(executable, binary, artifact_hash, environment, cache, timeout, query_timeout)
            try:
                session.__enter__()
            except (OSError, EOFError, ValueError) as exc:
                failure = f"REA static initialization unavailable: {exc}"
            else:
                try:
                    rea_version = session.version
                    collect(session)
                finally:
                    session.close()
                return records
        collect(None)
        return records
    finally:
        # Incidental REA caches are not evidence. Completed views are already frozen.
        shutil.rmtree(cache)


_VIEWS = ("function", "instructions", "decompilation", "references")
_PAGE_BYTES = 8192
_PAGE_RECORDS = 120


def _frozen(dataset):
    """Re-interpret authenticated frozen observations, never their old coarse status."""
    procedures = {}
    digest = dataset.manifest["artifacts"][dataset.binary + ".orig"]["sha256"]
    addresses = {"patch": dataset.manifest["patch"]["location"],
                 "destination": dataset.manifest["patch"]["destination"]}
    sites = {role: {"address": hex(address), "procedure_id": None,
                    "limitation": "frozen containing procedure unavailable"} for role, address in addresses.items()}
    for record in dataset.manifest.get("analysis", []):
        role, view = record.get("function_id"), record.get("view")
        if role not in addresses or view not in _VIEWS:
            continue
        address = addresses[role]
        if record.get("artifact_sha256") != digest or record.get("requested_address") != address:
            raise ValueError("frozen static record artifact/site identity mismatch")
        output = read_json(dataset._verify(record))
        entry, extent, reason = _resolve(output.get("resolution"), digest, address, record.get("backend"))
        if reason:
            sites[role]["limitation"] = reason[:512]
            continue
        if record.get("range") != extent:
            raise ValueError("frozen static procedure body identity mismatch")
        procedure_id = f"procedure:{hex(entry)}"
        sites[role] = {"address": hex(address), "procedure_id": procedure_id}
        procedure = procedures.setdefault(procedure_id, {"entry": entry, "extent": extent,
                                                       "views": {}, "references": {}, "roles": []})
        if procedure["extent"] != extent:
            raise ValueError("conflicting frozen procedure bodies")
        if role not in procedure["roles"]:
            procedure["roles"].append(role)
        query_address = address if view == "references" else entry
        if record.get("analysis_address") != query_address:
            raise ValueError("frozen static query address identity mismatch")
        payload = output.get("evidence")
        reason = _static_identity(payload, digest, query_address,
                                 "function" if view == "decompilation" else view, record.get("backend"))
        coverage_reason, complete, facets, limitations = _coverage(payload, view)
        reason = reason or coverage_reason
        observation = {"value": payload["data"]["normalized_result"] if reason is None else None,
                       "reason": reason, "complete": complete and reason is None,
                       "facets": facets, "limitations": limitations}
        if view == "references":
            procedure["references"][role] = observation
        else:
            procedure["views"].setdefault(view, observation)
    return procedures, sites


def _public_procedure(procedure_id, procedure):
    views = procedure["views"]
    function = views.get("function", {})
    value = function.get("value") or {}
    identity = value.get("procedure", {}) if isinstance(value, dict) else {}
    result = {"procedure_id": procedure_id, "entry": hex(procedure["entry"]),
              "body_ranges": [{"start": hex(item["start"]), "end": hex(item["end"])}
                              for item in procedure["extent"]["ranges"]],
              "range_end": "exclusive", "decompilation_address_mapping": "unavailable",
              "instruction_window_semantics": "decoded instructions within one body range; not a CFG or reaching-definition proof",
              "available_views": [view for view in _VIEWS
                  if (any(not item["reason"] for item in procedure["references"].values()) if view == "references"
                      else view in views and not views[view]["reason"])],
              "facets": function.get("facets", {}),
              "limitations": function.get("limitations", []),
              "unavailable_views": {view: item["reason"][:512] for view, item in views.items() if item["reason"]}}
    for key in ("name", "signature"):
        if isinstance(identity.get(key), str):
            result[key] = identity[key][:1024]
    return result


def _instruction_rows(procedure):
    observation = procedure["views"].get("instructions", {})
    value = observation.get("value")
    source = value.get("instructions", []) if isinstance(value, dict) else []
    dossier = procedure["views"].get("function", {}).get("value") or {}
    names = {}
    if isinstance(dossier, dict) and dossier.get("facet_availability", {}).get("strings_names", {}).get("available") is not False:
        for item in dossier.get("referenced_names", []):
            if isinstance(item, dict) and isinstance(item.get("source_address"), str):
                names.setdefault(item["source_address"], []).append(
                    {key: item[key] for key in ("address", "value") if isinstance(item.get(key), str)})
    call_targets = {}
    if isinstance(dossier, dict) and dossier.get("facet_availability", {}).get("references", {}).get("available") is not False:
        for reference in dossier.get("outgoing_references", []):
            if not isinstance(reference, dict) or not isinstance(reference.get("kind"), dict) or reference["kind"].get("call") is not True:
                continue
            source_address = reference.get("source_address")
            target_procedure = reference.get("target_procedure")
            target_procedure = target_procedure if isinstance(target_procedure, dict) else {}
            target_address = reference.get("target_address") or target_procedure.get("address")
            if not isinstance(source_address, str) or not isinstance(target_address, str):
                continue
            try:
                source_address = hex(int(source_address, 16))
            except ValueError:
                continue
            target = {"address": target_address[:256]}
            if len(target_address) > 256:
                target["label_truncated"] = True
            name = target_procedure.get("name")
            if isinstance(name, str):
                target["name"] = name[:256]
                if len(name) > 256:
                    target["label_truncated"] = True
            classification = target_procedure.get("classification", {})
            if isinstance(classification, dict):
                for key in ("thunk", "external"):
                    if type(classification.get(key)) is bool:
                        target[key] = classification[key]
                if isinstance(classification.get("thunk_target"), str):
                    target["thunk_target"] = classification["thunk_target"][:256]
                    if len(classification["thunk_target"]) > 256:
                        target["label_truncated"] = True
            targets = call_targets.setdefault(source_address, [])
            if target not in targets:
                targets.append(target)
    rows = []
    for item in source:
        if isinstance(item, str):
            match = re.fullmatch(r"\s*(0x[0-9a-fA-F]+):\s*(.*)", item)
            if not match:
                raise ValueError("malformed frozen instruction: expected address and decoded text")
            address, text = int(match[1], 16), match[2]
        elif isinstance(item, dict) and isinstance(item.get("address"), str):
            try:
                address = int(item["address"], 0)
            except ValueError as exc:
                raise ValueError("malformed frozen instruction address") from exc
            text = item.get("text") or item.get("assembly")
        else:
            raise ValueError("malformed frozen instruction record")
        if not isinstance(text, str) or not text.strip():
            raise ValueError("malformed frozen instruction: decoded text unavailable")
        body = next((index for index, extent in enumerate(procedure["extent"]["ranges"])
                     if extent["start"] <= address < extent["end"]), None)
        if body is None:
            raise ValueError("frozen instruction lies outside resolved procedure body")
        row = {"address": hex(address), "text": text, "body_range": body}
        if hex(address) in names:
            row["referenced_names"] = names[hex(address)]
        if hex(address) in call_targets:
            targets = call_targets[hex(address)]
            row["call_targets"] = targets[:8]
            row["call_targets_truncated"] = len(targets) > 8
        rows.append(row)
    rows.sort(key=lambda item: int(item["address"], 16))
    if len({row["address"] for row in rows}) != len(rows):
        raise ValueError("duplicate frozen instruction address")
    return rows


def _window(procedure, sites, site, window):
    if site is not None and site not in procedure["roles"]:
        raise ValueError("site must belong to procedure; valid sites: " + ", ".join(procedure["roles"]))
    if window is not None and (not isinstance(window, dict) or set(window) - {"address", "before", "after"}):
        raise ValueError("window must contain address and optional before/after instruction counts")
    window = window or {}
    before, after = window.get("before", 20), window.get("after", 20)
    if any(type(count) is not int or not 0 <= count <= 100 for count in (before, after)):
        raise ValueError("window before/after must be integer instruction counts in 0..100")
    role = site or ("patch" if "patch" in procedure["roles"] else procedure["roles"][0])
    address = window.get("address", sites[role]["address"])
    if not isinstance(address, str) or not re.fullmatch(r"(?:0x[0-9a-fA-F]+|[0-9]+)", address):
        raise ValueError("window address must be a hexadecimal or decimal address string")
    address = int(address, 16 if address.startswith("0x") else 10)
    rows = _instruction_rows(procedure)
    index = next((index for index, row in enumerate(rows) if int(row["address"], 16) == address), None)
    if index is None:
        choices = ", ".join(row["address"] for row in rows[:8]) or "none"
        raise ValueError(f"address must identify an exact frozen instruction in this body; examples: {choices}")
    body = rows[index]["body_range"]
    start, end = max(0, index - before), min(len(rows), index + after + 1)
    while start < index and rows[start]["body_range"] != body:
        start += 1
    while end > index + 1 and rows[end - 1]["body_range"] != body:
        end -= 1
    return rows, start, end, {"address": hex(address), "before": before, "after": after}


def _page_records(records, offset):
    if offset > len(records) or offset == len(records) and offset:
        raise ValueError("offset outside static view")
    end, size = offset, 0
    while end < len(records) and end - offset < _PAGE_RECORDS:
        count = len(canonical(records[end]))
        if size + count > _PAGE_BYTES:
            break
        size += count
        end += 1
    if end == offset and end < len(records):
        raise ValueError("single frozen static record exceeds bounded page size")
    return records[offset:end], {"start": offset, "end": end, "unit": "records"}, len(records), end if end < len(records) else None


def _page_text(text, offset):
    raw = text.encode("utf-8")
    if offset > len(raw) or offset == len(raw) and offset or offset < len(raw) and raw[offset] & 0xc0 == 0x80:
        raise ValueError("offset outside pseudocode or not on a UTF-8 character boundary")
    end = min(len(raw), offset + _PAGE_BYTES)
    while end < len(raw) and raw[end] & 0xc0 == 0x80:
        end -= 1
    chunk = raw[offset:end]
    lines = chunk.splitlines(keepends=True)
    if len(lines) > 120:
        end = offset + sum(len(line) for line in lines[:120])
    elif end < len(raw) and len(lines) > 1 and not lines[-1].endswith((b"\n", b"\r")):
        end -= len(lines[-1])
    return raw[offset:end].decode("utf-8"), {"start": offset, "end": end, "unit": "utf8_bytes",
            "start_line": raw[:offset].count(b"\n") + 1,
            "end_line": raw[:end].count(b"\n") + (0 if end and raw[end - 1] == 10 else 1)}, len(raw), end if end < len(raw) else None


def _compact_reference(item):
    if isinstance(item, str):
        return {"source_address": item}
    if not isinstance(item, dict):
        return None
    result = {key: item[key] for key in ("source_address", "target_address", "from", "to", "address", "type")
              if isinstance(item.get(key), (str, int))}
    kind = item.get("kind")
    if isinstance(kind, dict):
        result["kind"] = {key: kind[key] for key in ("type", "call", "jump", "conditional", "indirect", "computed", "data") if key in kind}
    for key in ("source_procedure", "target_procedure"):
        value = item.get(key)
        if isinstance(value, dict):
            result[key] = {field: value[field] for field in ("address", "name") if isinstance(value.get(field), str)}
    return result


def _function_records(value):
    """Project individual facts once; never page serialized REA dossiers."""
    records = []
    availability = value.get("facet_availability", {})
    owners = {"basic_blocks": "cfg", "referenced_names": "strings_names", "referenced_strings": "strings_names",
              "unresolved_calls": "callees", "incoming_references": "references", "outgoing_references": "references"}
    for facet in ("callees", "callers", "basic_blocks", "comments", "referenced_names", "referenced_strings", "unresolved_calls",
                  "incoming_references", "outgoing_references"):
        if availability.get(owners.get(facet, facet), {}).get("available") is False:
            continue
        for item in value.get(facet, []):
            if facet in ("incoming_references", "outgoing_references"):
                reference = _compact_reference(item)
                if reference is not None:
                    records.append({"facet": facet, **reference})
                continue
            if isinstance(item, str):
                record = {"facet": facet, "text": item}
            elif isinstance(item, dict):
                record = {"facet": facet, **{key: item[key] for key in
                    ("address", "source_address", "target_address", "name", "signature", "start", "end", "successors", "value", "text", "comment", "reason")
                    if key in item and isinstance(item[key], (str, int, list))}}
            else:
                continue
            records.append(record)
    return records


def _view(dataset, procedures, sites, procedure_id, view, site, window, offset):
    if not isinstance(procedure_id, str) or procedure_id not in procedures:
        raise ValueError("unknown procedure_id; valid choices: " + (", ".join(list(procedures)[:8]) or "none"))
    if view not in _VIEWS:
        raise ValueError("view must be one of: " + ", ".join(_VIEWS))
    if type(offset) is not int or offset < 0:
        raise ValueError("offset must be a nonnegative integer")
    procedure = procedures[procedure_id]
    if site is not None and site not in procedure["roles"]:
        raise ValueError("site must belong to procedure; valid sites: " + ", ".join(procedure["roles"]))
    if window is not None and view != "instructions":
        raise ValueError("window is only supported for instructions")
    if view == "references" and site is None:
        raise ValueError("references requires site; valid sites: " + ", ".join(procedure["roles"]))
    observation = (procedure["references"].get(site) if view == "references" else procedure["views"].get(view)) or {
        "reason": "frozen view unavailable", "complete": False, "limitations": []}
    result = {"procedure_id": procedure_id, "view": view, "availability": "unavailable" if observation["reason"] else "available",
              "complete": observation["complete"], "limitations": observation["limitations"]}
    if site is not None:
        result["site"] = site
    if observation["reason"]:
        if offset:
            raise ValueError("unavailable view has no continuation")
        result.update(reason=observation["reason"][:512], range={"start": 0, "end": 0, "unit": "records"}, total=0, next_offset=None)
    elif view == "decompilation":
        text = observation["value"]["pseudocode"]
        result["text"], result["range"], result["total"], result["next_offset"] = _page_text(text, offset)
        result["address_mapping"] = "unavailable"
        result["total_lines"] = len(text.splitlines())
    else:
        if view == "instructions":
            rows, start, end, normalized_window = _window(procedure, sites, site, window)
            result["window"] = normalized_window
            result["instruction_range"] = {"start": start, "end": end, "total": len(rows)}
            records, key = rows[start:end], "instructions"
        elif view == "references":
            value = observation["value"]
            source = value if isinstance(value, list) else value.get("references", [])
            records, key = [row for item in source if (row := _compact_reference(item)) is not None], "references"
            result["address"] = sites[site]["address"]
        else:
            result["procedure"] = _public_procedure(procedure_id, procedure)
            result["facets"] = observation["facets"]
            records, key = _function_records(observation["value"]), "records"
        result[key], result["range"], result["total"], result["next_offset"] = _page_records(records, offset)
    result["truncated"] = result["next_offset"] is not None
    scope = {"dataset_id": dataset.dataset_id, "procedure_id": procedure_id, "view": view,
             "site": site, "window": result.get("window"), "range": result["range"]}
    result["evidence_id"] = "analysis:" + hashlib.sha256(canonical(scope)).hexdigest()
    return result


def analysis_view(dataset, procedure_id, view, *, site=None, window=None, offset=0):
    """Read bounded, authenticated static facts; offset is host cursor state only."""
    with dataset.validation() as validated:
        procedures, sites = _frozen(validated)
        return _view(validated, procedures, sites, procedure_id, view, site, window, offset)


def analysis_inventory(dataset):
    """Canonical procedures, distinct sites and compact initial evidence slices."""
    with dataset.validation() as validated:
        procedures, sites = _frozen(validated)
        result = {"procedures": [_public_procedure(key, value) for key, value in procedures.items()],
                  "sites": sites, "same_procedure": bool(sites.get("patch", {}).get("procedure_id")) and
                  sites.get("patch", {}).get("procedure_id") == sites.get("destination", {}).get("procedure_id"),
                  "windows": [], "references": {}}
        for procedure_id, procedure in procedures.items():
            windows = []
            if procedure["views"].get("instructions", {}).get("value") is not None:
                # Inventory may omit an unresolved site window, never corrupt rows.
                _instruction_rows(procedure)
            for role in procedure["roles"]:
                result["references"][role] = _view(validated, procedures, sites, procedure_id, "references", role, None, 0)
                if procedure["views"].get("instructions", {}).get("reason") is not None:
                    continue
                try:
                    rows, start, end, _normalized = _window(procedure, sites, role, None)
                except ValueError as exc:
                    sites[role]["instruction_limitation"] = str(exc)[:512]
                    continue
                windows.append((start, end, role))
            merged = []
            for start, end, role in sorted(windows):
                if merged and start < merged[-1][1] and rows[start]["body_range"] == rows[merged[-1][0]]["body_range"]:
                    merged[-1][1] = max(end, merged[-1][1])
                    merged[-1][2].append(role)
                else:
                    merged.append([start, end, [role]])
            for start, end, roles in merged:
                anchor = next(index for index in range(start, end) if rows[index]["address"] == sites[roles[0]]["address"])
                page = _view(validated, procedures, sites, procedure_id, "instructions", None,
                             {"address": rows[anchor]["address"], "before": anchor - start, "after": end - anchor - 1}, 0)
                page["sites"] = roles
                result["windows"].append(page)
        return result
