"""Private host-only REA stdio session; no model-selected tools or network endpoint."""
from __future__ import annotations

import json
import os
import selectors
import signal
import subprocess
import time
from pathlib import Path

_PROTOCOL = "2025-11-25"
_MAX_FRAME = 10 * 1024 * 1024
_CLEANUP_TIMEOUT = 45
_OPERATIONS = frozenset(("resolve_containing_procedure", "read_function_instructions",
                         "analyze_function", "xrefs"))


class ReaSession:
    def __init__(self, executable: str, binary: Path, digest: str, environment: dict[str, str],
                 directory: Path, timeout: int, query_timeout: int):
        self.executable, self.binary, self.digest = executable, binary, digest
        self.environment, self.directory = environment, directory
        self.timeout, self.query_timeout = timeout, query_timeout
        self.process = None
        self.version = None
        self.failure = None
        self._sequence = 0
        self._pending = None
        self._buffer = bytearray()
        self._selector = selectors.DefaultSelector()
        self._stderr = None
        self._cold = True

    def __enter__(self):
        try:
            self._stderr = (self.directory / "rea-stderr.log").open("wb")
            self.process = subprocess.Popen(
                [self.executable, "--mcp"], cwd=self.directory, env=self.environment,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self._stderr,
                start_new_session=True)
            assert self.process.stdout is not None
            self._selector.register(self.process.stdout, selectors.EVENT_READ)
            initialized = self._rpc("initialize", {
                "protocolVersion": _PROTOCOL, "capabilities": {},
                "clientInfo": {"name": "taosc-static-analysis", "version": "1"}}, 30)
            if initialized.get("protocolVersion") != _PROTOCOL:
                raise ValueError("REA negotiated an unsupported stdio protocol")
            self.version = initialized.get("serverInfo", {}).get("version")
            self._send({"method": "notifications/initialized"})
            opened = self._tool("open_binary", {"path": str(self.binary), "provider_id": "ghidra"},
                                self.timeout + self.query_timeout)
            if (opened.get("ok") is not True or not isinstance(opened.get("data"), dict)
                    or opened["data"].get("result", {}).get("sha256") != self.digest):
                raise ValueError("REA open failed or returned a different artifact: " + str(opened))
            return self
        except BaseException:
            self.close()
            raise

    def _send(self, message: dict) -> None:
        assert self.process is not None and self.process.stdin is not None
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", **message}, separators=(",", ":")).encode() + b"\n")
        self.process.stdin.flush()

    def _receive(self, identifier: int, timeout: int) -> dict:
        assert self.process is not None and self.process.stdout is not None
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"REA request exceeded {timeout} seconds")
            end = self._buffer.find(b"\n")
            if end > _MAX_FRAME:
                raise ValueError("REA response exceeds the 10 MiB frame bound")
            if end >= 0:
                line = bytes(self._buffer[:end])
                del self._buffer[:end + 1]
                message = json.loads(line)
                if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                    raise ValueError("invalid REA stdio frame")
                if message.get("id") != identifier:
                    # Notifications and late replies to a cancelled request are not results.
                    continue
                if "error" in message:
                    raise ValueError("REA protocol error: " + str(message["error"]))
                result = message.get("result")
                if not isinstance(result, dict):
                    raise ValueError("REA response has no result object")
                return result
            if len(self._buffer) > _MAX_FRAME:
                raise ValueError("REA response exceeds the 10 MiB frame bound")
            if not self._selector.select(remaining):
                raise TimeoutError(f"REA request exceeded {timeout} seconds")
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                raise EOFError("REA exited before completing its response")
            self._buffer.extend(chunk)

    def _rpc(self, method: str, params: dict, timeout: int) -> dict:
        self._sequence += 1
        self._pending = self._sequence
        self._send({"id": self._sequence, "method": method, "params": params})
        result = self._receive(self._sequence, timeout)
        self._pending = None
        return result

    def _tool(self, name: str, arguments: dict, timeout: int) -> dict:
        result = self._rpc("tools/call", {"name": name, "arguments": arguments}, timeout)
        if result.get("isError") is True:
            texts = [part["text"] for part in result.get("content", [])
                     if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str)]
            return {"ok": False, "error": "\n".join(texts) or "REA tool failed without diagnostics"}
        data = result.get("structuredContent")
        if not isinstance(data, dict):
            raise ValueError("REA tool returned no structured evidence")
        # Keep the original Evidence intact; this is the same outer shape as the CLI.
        return {"ok": True, "data": data}

    def query(self, operation: str, address: int) -> dict:
        if operation not in _OPERATIONS:
            raise ValueError("static operation is not permitted")
        if self.failure is not None:
            return {"ok": False, "error": self.failure}
        parameter = "address" if operation in ("resolve_containing_procedure", "xrefs") else "procedure"
        arguments = {parameter: hex(address)}
        if operation == "analyze_function":
            arguments["detail"] = "complete"
        cold, self._cold = self._cold, False
        try:
            result = self._tool(operation, arguments,
                                self.query_timeout + (self.timeout if cold else 0))
            if cold and result.get("ok") is not True:
                self.failure = "REA initial analysis failed: " + str(result.get("error"))
            return result
        except (OSError, EOFError, ValueError) as exc:
            # An active cancellation retires the native session. Never restart a
            # cold import for each remaining view after losing this session.
            self.failure = str(exc)
            return {"ok": False, "error": self.failure}

    def close(self) -> None:
        process = self.process
        try:
            if process is None:
                return
            if process.poll() is None:
                if self._pending is not None:
                    try:
                        self._send({"method": "notifications/cancelled", "params": {
                            "requestId": self._pending, "reason": "Host static-analysis request ended"}})
                    except (OSError, ValueError):
                        pass
                elif self.failure is None:
                    try:
                        closed = self._tool("close_binary", {}, _CLEANUP_TIMEOUT)
                        if closed.get("ok") is not True:
                            self.failure = "REA close failed: " + str(closed.get("error"))
                    except (OSError, EOFError, ValueError) as exc:
                        self.failure = "REA close failed: " + str(exc)
                # EOF aborts pending work and awaits REA's OWNED process cleanup.
                # Java is detached: killing only this process group is insufficient.
                if process.stdin is not None:
                    try:
                        process.stdin.close()
                    except OSError:
                        pass
                    process.stdin = None
                try:
                    process.communicate(timeout=_CLEANUP_TIMEOUT)
                except subprocess.TimeoutExpired:
                    process.send_signal(signal.SIGTERM)
                    try:
                        process.communicate(timeout=_CLEANUP_TIMEOUT)
                    except subprocess.TimeoutExpired as exc:
                        raise RuntimeError(
                            f"REA cleanup did not settle; owner PID {process.pid} requires intervention") from exc
            if process.returncode not in (0, None):
                raise RuntimeError(f"REA exited with {process.returncode}; native cleanup was not confirmed")
        finally:
            self._selector.close()
            if self._stderr is not None:
                self._stderr.close()
            if process is not None and process.returncode is not None:
                if process.stdin is not None:
                    process.stdin.close()
                if process.stdout is not None:
                    process.stdout.close()

    def __exit__(self, exc_type, exc, traceback):
        self.close()
