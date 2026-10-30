"""Host-selected local REA static views; never a generic command/MCP adapter."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from elftools.elf.elffile import ELFFile

from .dataset import canonical, sha256


def _function_range(binary: Path, address: int) -> dict:
    with binary.open("rb") as stream:
        elf = ELFFile(stream)
        matches = []
        for section in elf.iter_sections():
            if section["sh_type"] not in ("SHT_SYMTAB", "SHT_DYNSYM"):
                continue
            for symbol in section.iter_symbols():
                start, size = int(symbol["st_value"]), int(symbol["st_size"])
                if symbol["st_info"]["type"] == "STT_FUNC" and size and start <= address < start + size:
                    matches.append((start, start + size))
        unique = set(matches)
        if len(unique) == 1:
            start, end = unique.pop()
            return {"start": start, "end": end, "address_domain": "elf-va", "confidence": "elf-symbol"}
    return {"start": address, "end": None, "address_domain": "elf-va", "confidence": "unavailable"}


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
    """Validate the REA CLI evidence envelope, not incidental cache contents."""
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        return "REA static evidence envelope unavailable"
    data = payload.get("data")
    if not isinstance(data, dict):
        return "REA static evidence data unavailable"
    operations = {"function": "analyze_function", "instructions": "read_function_instructions",
                  "decompile": "procedure_pseudo_code", "xrefs": "xrefs"}
    subject, backend, parameters = (data.get(key) for key in ("subject", "provider", "parameters"))
    if (not isinstance(subject, dict) or not isinstance(subject.get("digest"), dict)
            or subject["digest"].get("sha256") != artifact_hash):
        return "REA static evidence artifact identity mismatch"
    if not isinstance(backend, dict) or backend.get("id") != provider:
        return "REA static evidence provider identity mismatch"
    parameter = "address" if command == "xrefs" else "procedure"
    if (data.get("operation") != operations[command] or not isinstance(parameters, dict)
            or parameters.get(parameter) != hex(address)):
        return "REA static evidence operation/address identity mismatch"
    if data.get("normalized_result") is None:
        return "REA normalized static evidence unavailable"
    return None


def prepare_analysis(root: Path, binary: Path, addresses: dict[str, int], *,
                     rea: str | None, provider: str) -> list[dict]:
    if provider != "ghidra":
        raise ValueError("static preparation currently supports only the explicit ghidra provider")
    executable = rea or os.environ.get("TAOSC_LLM_REA") or shutil.which("rea")
    prefix = [executable] if executable else []
    environment = {key: os.environ[key] for key in ("PATH", "JAVA_HOME", "GHIDRA_INSTALL_DIR", "LANG") if key in os.environ}
    cache = root / "analysis-cache"
    cache.mkdir()
    environment.update({"HOME": str(cache), "XDG_CACHE_HOME": str(cache / "cache"),
                        "XDG_CONFIG_HOME": str(cache / "config"), "XDG_DATA_HOME": str(cache / "data")})
    rea_version = None
    if prefix:
        try:
            probe = subprocess.run([*prefix, "--help"], env=environment, capture_output=True, text=True, timeout=30)
            match = re.search(r"rea@([0-9][^\s]*)", probe.stdout)
            rea_version = match[1] if match else None
        except (OSError, subprocess.TimeoutExpired):
            pass
    directory = root / "analysis"
    directory.mkdir()
    records = []
    artifact_hash = sha256(binary)
    for function_id, address in addresses.items():
        extent = _function_range(binary, address)
        for view, command in (("function", "function"), ("instructions", "instructions"),
                              ("decompilation", "decompile"), ("references", "xrefs")):
            argv = [*prefix, command, str(binary), hex(address), "--provider", provider, "--format", "json", "--full-output"] if prefix else []
            reason, payload = None, None
            if not prefix:
                reason = "REA executable unavailable"
            else:
                try:
                    completed = subprocess.run(argv, env=environment, cwd=cache, capture_output=True,
                                               text=True, timeout=180)
                    if completed.returncode:
                        try:
                            payload = json.loads(completed.stdout)
                        except ValueError:
                            pass
                        error = payload.get("error") if isinstance(payload, dict) else None
                        message = error.get("message") if isinstance(error, dict) else None
                        detail = message if isinstance(message, str) else completed.stderr.strip()
                        reason = f"REA exited {completed.returncode}: {detail}"
                    else:
                        payload = json.loads(completed.stdout)
                        reason = (_unavailable(payload) or
                                  _static_identity(payload, artifact_hash, address, command, provider))
                except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
                    reason = f"REA static view unavailable: {exc}"
            record = {"function_id": function_id, "view": view,
                      "path": f"analysis/{function_id}-{view}.json",
                      "availability": "unavailable" if reason else "available", "reason": reason,
                      "complete": reason is None, "backend": provider,
                      "backend_version": _backend_version(payload),
                      "backend_version_availability": "available" if _backend_version(payload) else "unavailable",
                      "rea_version": rea_version, "artifact_sha256": artifact_hash,
                      "range": extent, "requested_address": address,
                      "provenance": {"command": command, "provider": provider, "local_static": True}}
            output = {"metadata": record, "evidence": payload}
            path = root / record["path"]
            path.write_bytes(canonical(output) + b"\n")
            record["sha256"] = sha256(path)
            records.append(record)
    # REA's incidental cache is not evidence and must not leak mutable source paths.
    shutil.rmtree(cache)
    return records
