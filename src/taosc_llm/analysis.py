"""Host-selected local REA static views; never a model-accessible analysis service."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from ._rea import ReaSession
from .dataset import canonical, sha256

_OPERATIONS = {"resolve": "resolve_containing_procedure", "function": "analyze_function",
               "instructions": "read_function_instructions", "references": "xrefs"}


def _unavailable(value) -> str | None:
    if isinstance(value, dict):
        if value.get("truncated") is True or value.get("complete") is False:
            return str(value.get("reason") or "backend reports incomplete analysis")
        if value.get("available") is False or value.get("availability") in ("unavailable", "unsupported") or value.get("status") in ("unavailable", "error", "unsupported", "incomplete", "partial") or value.get("success") is False or value.get("ok") is False:
            return str(value.get("reason") or value.get("error") or value.get("status") or "backend unavailable")
        for child in value.values():
            result = _unavailable(child)
            if result:
                return result
    elif isinstance(value, list):
        for child in value:
            result = _unavailable(child)
            if result:
                return result
    return None


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
        record = {"function_id": function_id, "view": view,
                  "path": f"analysis/{function_id}-{view}.json",
                  "availability": "unavailable" if reason else "available", "reason": reason,
                  "complete": reason is None, "backend": provider, "backend_version": version,
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
                    if reason is None and view == "decompilation":
                        value = payload["data"]["normalized_result"]
                        facet = value.get("facet_availability", {}).get("pseudocode", {}) if isinstance(value, dict) else {}
                        if facet.get("available") is not True or not isinstance(value.get("pseudocode"), str) or not value["pseudocode"].strip():
                            reason = str(facet.get("reason") or "REA pseudocode unavailable")
                    elif reason is None:
                        reason = _unavailable(payload)
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
