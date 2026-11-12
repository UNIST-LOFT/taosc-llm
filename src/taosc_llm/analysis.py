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
    # Destination zero selects exit(128), not code at virtual address zero.
    addresses = {role: address for role, address in addresses.items()
                 if role != "destination" or address != 0}
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
FUNCTION_FACETS = ("callees", "callers", "cfg", "strings", "references", "native_api", "value_flow")
_PAGE_BYTES = 8192
_PAGE_RECORDS = 120


def _frozen(dataset):
    """Re-interpret authenticated frozen observations, never their old coarse status."""
    procedures = {}
    digest = dataset.manifest["artifacts"][dataset.binary + ".orig"]["sha256"]
    addresses = {"patch": dataset.manifest["patch"]["location"],
                 "destination": dataset.manifest["patch"]["destination"]}
    termination = addresses["destination"] == 0
    if termination:
        del addresses["destination"]
    sites = {role: {"address": hex(address), "procedure_id": None,
                    "limitation": "frozen containing procedure unavailable"} for role, address in addresses.items()}
    if termination:
        sites["destination"] = {"procedure_id": None,
            "note": "Selected repair exits with status 128; destination 0 is a termination sentinel, not an executable address."}
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
              "range_end": "exclusive",
              "available_views": [view for view in _VIEWS
                  if (any(not item["reason"] for item in procedure["references"].values()) if view == "references"
                      else view in views and not views[view]["reason"])],
              "available_facets": _available_facets(value)}
    if isinstance(identity.get("name"), str):
        result["name"] = identity["name"][:256]
    if function.get("limitations") or any(item["reason"] for item in views.values()):
        result["note"] = "Some frozen static evidence is missing or partial; available views and facets remain usable."
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
    end, size = offset, 2  # Include the JSON array delimiters and separators.
    while end < len(records) and end - offset < _PAGE_RECORDS:
        count = len(canonical(records[end])) + (1 if end > offset else 0)
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


_FACET_FIELDS = {
    "callees": ("callees", "unresolved_calls"), "callers": ("callers",),
    "cfg": ("basic_blocks",), "strings": ("referenced_names", "referenced_strings"),
    "references": ("incoming_references", "outgoing_references"),
}


def _facet_status(value, facet):
    owner = "strings_names" if facet == "strings" else facet
    availability = value.get("facet_availability", {}).get(owner, {})
    if availability.get("available") is False:
        return False, str(availability.get("reason") or "requested frozen facet unavailable")[:256]
    if facet in ("native_api", "value_flow"):
        native = value.get("native_api" if facet == "native_api" else "native_value_flow")
        if not isinstance(native, dict) or native.get("available") is not True:
            return False, "requested native facet was not saved or is unavailable"
    elif not any(isinstance(value.get(key), list) for key in _FACET_FIELDS[facet]):
        return availability.get("available") is True, "requested facet was not saved"
    return True, None


def _available_facets(value):
    return [facet for facet in FUNCTION_FACETS if _facet_status(value, facet)[0]]


def _bounded_fact(value, depth=0):
    """Bound individual saved facts as well as pages; never copy a raw dossier."""
    if isinstance(value, str):
        return value.encode("utf-8")[:256].decode("utf-8", errors="ignore")
    if value is None or type(value) in (int, bool, float):
        return value
    if depth >= 4:
        return {"truncated": True}
    if isinstance(value, list):
        return [_bounded_fact(item, depth + 1) for item in value[:16]]
    if isinstance(value, dict):
        result = {key: _bounded_fact(item, depth + 1) for key, item in value.items()
                  if isinstance(key, str) and not isinstance(item, (dict, list))}
        for key, item in value.items():
            if isinstance(key, str) and isinstance(item, (dict, list)):
                result[key] = _bounded_fact(item, depth + 1)
                if isinstance(item, list) and len(item) > 16:
                    result[key + "_truncated"] = True
            elif isinstance(item, str) and len(item.encode("utf-8")) > 256:
                result["labels_truncated"] = True
        return result
    return None


def _local_address(procedure, sites, site, address):
    if address is None:
        role = site or ("patch" if "patch" in procedure["roles"] else procedure["roles"][0])
        address = sites[role]["address"]
    if not isinstance(address, str) or not re.fullmatch(r"(?:0x[0-9a-fA-F]+|[0-9]+)", address):
        raise ValueError("address must be a hexadecimal or decimal address string")
    number = int(address, 16 if address.startswith("0x") else 10)
    if not any(item["start"] <= number < item["end"] for item in procedure["extent"]["ranges"]):
        raise ValueError("address must be inside the frozen procedure body")
    return hex(number)


def _address_number(value):
    try:
        return int(value, 16 if value.startswith("0x") else 10) if isinstance(value, str) else None
    except ValueError:
        return None


def _block_extent(block, procedure):
    if not isinstance(block, dict):
        return None
    start, end = _address_number(block.get("start")), _address_number(block.get("end"))
    if start is None or end is None or start >= end:
        return None
    if not any(item["start"] <= start < end <= item["end"] for item in procedure["extent"]["ranges"]):
        return None
    return start, end


def _cfg_records(value, procedure, address):
    blocks = [(block, extent) for block in value.get("basic_blocks", [])
              if (extent := _block_extent(block, procedure)) is not None]
    number = int(address, 16)
    local = [(block, extent) for block, extent in blocks if extent[0] <= number < extent[1]]
    if len(local) != 1:
        return [], "No unique saved basic block contains this address."
    block, extent = local[0]
    records = [{"relation": "block", "start": hex(extent[0]), "end": hex(extent[1])}]
    for predecessor, bounds in blocks:
        if any(_address_number(target) == extent[0] for target in predecessor.get("successors", [])):
            records.append({"relation": "predecessor", "start": hex(bounds[0]), "end": hex(bounds[1])})
    for target in block.get("successors", []):
        destination = _address_number(target)
        if destination is None:
            continue
        record = {"relation": "successor", "address": hex(destination)}
        target_blocks = [bounds for _item, bounds in blocks if bounds[0] == destination]
        if len(target_blocks) == 1:
            record.update(start=hex(target_blocks[0][0]), end=hex(target_blocks[0][1]))
        else:
            record["saved_block"] = False
        records.append(record)
    note = None
    if len(blocks) != len(value.get("basic_blocks", [])):
        note = "Some saved blocks have missing or out-of-body bounds; only body-confined blocks are shown."
    return records, note


def _flow_records(value, address):
    flow = value["native_value_flow"]
    operations = [item for item in flow.get("operations", []) if isinstance(item, dict)
                  and _address_number(item.get("address")) == int(address, 16) and isinstance(item.get("id"), str)]
    ids = {item["id"] for item in operations}
    records = []

    def operand(item):
        if not isinstance(item, dict):
            return None
        result = {key: item[key] for key in ("kind", "location", "size_bytes", "constant_hex") if key in item}
        for key, text in result.copy().items():
            if isinstance(text, str) and len(text.encode("utf-8")) > 64:
                result[key] = text.encode("utf-8")[:64].decode("utf-8", errors="ignore")
                result["labels_truncated"] = True
        return result

    for item in operations:
        record = {key: item[key] for key in ("id", "address", "sequence", "opcode", "is_dead", "block_membership") if key in item}
        if isinstance(item.get("inputs"), list):
            record["inputs"] = [operand(node) for node in item["inputs"][:16]]
            if len(item["inputs"]) > 16:
                record["inputs_truncated"] = True
        if "output" in item:
            record["output"] = operand(item["output"])
        records.append({"kind": "operation", **_bounded_fact(record)})
    for key, match in (("def_use", lambda item: item.get("definition") in ids or item.get("use") in ids),
                       ("effects", lambda item: item.get("operation") in ids),
                       ("parameter_uses", lambda item: item.get("use") in ids)):
        fields = {"def_use": ("definition", "use", "input_index"),
                  "effects": ("kind", "operation", "operand_input", "value_input"),
                  "parameter_uses": ("use", "ordinal", "input_index")}[key]
        for item in flow.get(key, []):
            if isinstance(item, dict) and match(item):
                record = _bounded_fact({field: item[field] for field in fields if field in item})
                # Effect kind describes the native effect, not the enclosing record type.
                if key == "effects" and "kind" in record:
                    record["effect"] = record.pop("kind")
                records.append({"kind": key, **record})
    note = ("Address-local decompiler-derived high p-code and incident def-use only; incomplete data-flow evidence, "
            "not runtime behavior or a reaching-definition proof. is_dead is the saved AST flag; block_membership is separate.")
    if flow.get("truncated") or any(flow.get(key, 0) for key in
            ("known_omitted_edges", "known_omitted_inputs", "omitted_operations_lower_bound")):
        note += " The saved source also reports omissions."
    if not operations:
        note += " No operations were saved at this address."
    return records, note


def _native_api_records(value):
    api = value["native_api"]
    signature = {key: api[key] for key in ("calling_convention", "signature_source") if key in api}
    if api.get("signature_source") == "default":
        signature["confidence"] = "low"
    records = [{"kind": "signature", **_bounded_fact(signature)}] if signature else []
    for key in ("parameters", "return_type"):
        source = api.get(key, []) if key == "parameters" else [api.get(key)]
        for item in source:
            if isinstance(item, dict):
                records.append({"kind": "parameter" if key == "parameters" else "return_type",
                    **_bounded_fact({field: item[field] for field in
                    ("name", "ordinal", "data_type", "size_bytes", "storage", "confidence") if field in item})})
    return records, ("Recovered decompiler API observations, not authoritative ABI or source declarations; "
                     "a default signature source (including saved __stdcall) is low-confidence.")


def _function_records(value, facet, procedure, address):
    """Select one saved facet, never page unrelated dossier sections."""
    if facet == "cfg":
        return _cfg_records(value, procedure, address)
    if facet == "value_flow":
        return _flow_records(value, address)
    if facet == "native_api":
        return _native_api_records(value)
    if facet in ("callees", "callers") and address is not None:
        outgoing = facet == "callees"
        field = "outgoing_references" if outgoing else "incoming_references"
        coordinate = "source_address" if outgoing else "target_address"
        if not isinstance(value.get(field), list) or value.get("facet_availability", {}).get("references", {}).get("available") is False:
            return [], "Address-local calls require saved reference evidence, which is missing."
        records = []
        for item in value[field]:
            if (isinstance(item, dict) and isinstance(item.get("kind"), dict) and item["kind"].get("call") is True
                    and _address_number(item.get(coordinate)) == int(address, 16)):
                reference = _compact_reference(item)
                if reference is not None:
                    records.append(_bounded_fact(reference))
        return records, None
    records = []
    partial = False
    for field in _FACET_FIELDS[facet]:
        source = value.get(field, [])
        partial |= any(_unavailable(item) or isinstance(item, dict) and
                       _unavailable(item.get("relationship_coverage")) for item in source)
        for item in source:
            if address is not None:
                coordinates = (("source_address", "from") if field == "outgoing_references" else
                               ("target_address", "to") if field == "incoming_references" else
                               ("source_address", "address"))
                if not isinstance(item, dict) or not any(
                        _address_number(item.get(key)) == int(address, 16) for key in coordinates):
                    continue
            if facet == "references":
                reference = _compact_reference(item)
                if reference is not None:
                    records.append({"direction": "incoming" if field == "incoming_references" else "outgoing",
                                    **_bounded_fact(reference)})
            elif isinstance(item, str):
                records.append(_bounded_fact({"text": item}))
            elif isinstance(item, dict):
                record = _bounded_fact({key: item[key] for key in
                    ("address", "source_address", "target_address", "name", "value", "text", "reason") if key in item})
                if field == "unresolved_calls":
                    record["unresolved"] = True
                records.append(record)
    return records, "Selected relationships are partial; unresolved edges may be missing." if partial else None


def _view(dataset, procedures, sites, procedure_id, view, site, window, offset, facet=None, address=None):
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
    if (facet is not None or address is not None) and view != "function":
        raise ValueError("facet/address are only supported for function; use window.address for instructions")
    if facet is not None and facet not in FUNCTION_FACETS:
        raise ValueError("facet must be one of: " + ", ".join(FUNCTION_FACETS))
    if address is not None and facet is None:
        raise ValueError("address requires a function facet")
    if facet == "native_api" and address is not None:
        raise ValueError("native_api is procedure-wide and does not accept address")
    if address is not None or facet in ("cfg", "value_flow"):
        address = _local_address(procedure, sites, site, address)
    if view == "references" and site is None:
        raise ValueError("references requires site; valid sites: " + ", ".join(procedure["roles"]))
    observation = (procedure["references"].get(site) if view == "references" else procedure["views"].get(view)) or {
        "reason": "frozen view unavailable", "complete": False, "limitations": []}
    reason = observation["reason"]
    partial_source = None
    if not reason and facet is not None:
        available, facet_reason = _facet_status(observation["value"], facet)
        if not available:
            reason = facet_reason
        else:
            partial_source = _unavailable(observation["value"])
    result = {"procedure_id": procedure_id, "view": view, "availability": "unavailable" if reason else "available",
              "complete": observation["complete"] if facet is None else not bool(reason)}
    if site is not None:
        result["site"] = site
    if facet is not None:
        result["facet"] = facet
    if address is not None:
        result["address"] = address
    if not reason and view in ("instructions", "references") and observation["limitations"]:
        result["note"] = "Saved static evidence is partial; missing records are not proof of absence."
    if reason:
        if offset:
            raise ValueError("unavailable view has no continuation")
        result.update(note=str(reason)[:256], range={"start": 0, "end": 0, "unit": "records"}, total=0, next_offset=None)
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
            body = procedure["extent"]["ranges"][rows[start]["body_range"]]
            result["body_range"] = {"start": hex(body["start"]), "end": hex(body["end"]), "range_end": "exclusive"}
            records = [{key: value for key, value in row.items() if key != "body_range"} for row in rows[start:end]]
            key = "instructions"
        elif view == "references":
            value = observation["value"]
            source = value if isinstance(value, list) else value.get("references", [])
            records, key = [row for item in source if (row := _compact_reference(item)) is not None], "references"
            result["address"] = sites[site]["address"]
        elif facet is None:
            result["procedure"] = _public_procedure(procedure_id, procedure)
            records, key = [], "records"
        else:
            records, note = _function_records(observation["value"], facet, procedure, address)
            key = "records"
            if facet == "cfg":
                result["range_end"] = "exclusive"
            if partial_source:
                note = (note + " " if note else "") + "Saved dossier is partial; selected facts may omit records."
            if note:
                result["note"] = note
                if facet != "native_api" or partial_source or _unavailable(observation["value"].get("native_api")):
                    result["complete"] = False
        result[key], result["range"], result["total"], result["next_offset"] = _page_records(records, offset)
    result["truncated"] = result["next_offset"] is not None
    scope = {"dataset_id": dataset.dataset_id, "procedure_id": procedure_id, "view": view,
             "site": site, "window": result.get("window"), "range": result["range"]}
    if facet is not None:
        scope.update(facet=facet, address=address)
    result["evidence_id"] = "analysis:" + hashlib.sha256(canonical(scope)).hexdigest()
    return result


def analysis_view(dataset, procedure_id, view, *, site=None, window=None, offset=0, facet=None, address=None):
    """Read bounded, authenticated frozen facts; no backend execution or pseudocode address inference."""
    with dataset.validation() as validated:
        procedures, sites = _frozen(validated)
        return _view(validated, procedures, sites, procedure_id, view, site, window, offset, facet, address)


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
