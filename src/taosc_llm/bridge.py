"""One Pi operation: bounded JSONL, separate credentials, explicit settlement."""

import asyncio
import json
import os
import re
import shutil
import signal
import sys
import uuid
from importlib.resources import files
from pathlib import Path
from tempfile import TemporaryDirectory

from .context import SynthesisContext, strict_json
from .provider import ProviderConfig, native_environment

MAX_FRAME = 4 * 1024 * 1024


class AdapterError(RuntimeError):
    pass


def adapter_command(sdk_root: Path | None = None) -> list[str]:
    root = sdk_root or os.environ.get("TAOSC_LLM_PI_SDK_ROOT")
    if root is None:
        raise AdapterError("provide --pi-sdk-root or install the Guix package")
    root = Path(root).resolve(strict=True)
    for name in ("pi-coding-agent", "pi-ai"):
        path = root / "node_modules" / "@earendil-works" / name / "package.json"
        try:
            metadata = json.loads(path.read_text())
        except (OSError, ValueError):
            raise AdapterError("pinned Pi SDK installation is unavailable") from None
        if metadata.get("name") != "@earendil-works/" + name or metadata.get("version") != "1.4.0":
            raise AdapterError("Pi SDK 1.4.0 is required")
    node = shutil.which(os.environ.get("TAOSC_LLM_NODE", "node"))
    if node is None:
        raise AdapterError("Node >=22.19 is required")
    return [node, str(files("taosc_llm").joinpath("pi/adapter.mjs")),
            "--sdk-root", str(root)]


async def _kill(process) -> None:
    if process.returncode is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    await process.wait()


async def run_adapter(context: SynthesisContext, provider: ProviderConfig,
                      command: list[str], run_id: str, journal: Path,
                      settlement: dict[str, bool]) -> dict:
    """Caller must retain its quota reservation until this coroutine finishes.

    settlement is pessimistic once a worker exists. A valid final frame followed
    by worker exit is the only normal release path. Cancellation may drain that
    proof, otherwise leaves the reservation quarantined for explicit recovery.
    """
    process = None
    terminal = None
    seen = set()
    inspected = False
    checked = set()
    request_id = uuid.uuid4().hex
    read_fd, write_fd = os.pipe()
    settlement["remote_settled"] = True  # no worker/request exists yet
    key_bytes = json.dumps({"api_key": provider.api_key}).encode()
    if len(key_bytes) > 65536:
        os.close(read_fd)
        os.close(write_fd)
        raise AdapterError("provider credential exceeds transport bound")

    def encode(frame):
        payload = json.dumps(frame, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        if provider.api_key in payload or len(payload.encode()) > MAX_FRAME:
            raise AdapterError("unsafe or oversized adapter payload")
        return (payload + "\n").encode()

    with TemporaryDirectory(prefix="taosc-llm-pi-") as private, journal.open("x", encoding="utf-8") as log:
        os.chmod(journal, 0o600)
        envelope = {"protocol_version": 1, "run_id": run_id}

        def record(direction, frame):
            log.write(json.dumps({"direction": direction, "frame": frame}, ensure_ascii=True) + "\n")
            log.flush()

        async def send(frame):
            assert process is not None and process.stdin is not None
            payload = encode(frame)
            process.stdin.write(payload)
            await process.stdin.drain()
            record("host", frame)

        def receive(line):
            if not line or len(line) > MAX_FRAME + 1 or not line.endswith(b"\n"):
                raise AdapterError("missing or oversized adapter frame")
            # Raw SDK diagnostics are never persisted; protocol is the sole channel.
            if provider.api_key.encode() in line:
                raise AdapterError("credential detected in adapter output")
            try:
                frame = strict_json(line.decode("utf-8"))
            except (ValueError, UnicodeError, RecursionError):
                raise AdapterError("invalid adapter JSON") from None
            if (not isinstance(frame, dict) or frame.get("protocol_version") != 1
                    or frame.get("run_id") != run_id or not isinstance(frame.get("request_id"), str)):
                raise AdapterError("invalid adapter envelope")
            return frame

        def final(frame):
            common = {"protocol_version", "run_id", "request_id", "type", "remote_settled", "request_count"}
            fields = ({"final_text", "tool_calls", "model_turns", "usage", "active_tools", "provider_metadata"}
                      if frame["type"] == "turn_complete"
                      else {"error_code", "retry_after_seconds", "http_status"})
            if (set(frame) != common | fields or frame["request_id"] != request_id
                    or type(frame["remote_settled"]) is not bool
                    or type(frame["request_count"]) is not int or frame["request_count"] < 0):
                raise AdapterError("invalid adapter terminal frame")
            if frame["type"] == "turn_complete":
                if (not isinstance(frame["final_text"], str) or not frame["remote_settled"]
                        or set(frame["active_tools"]) != {item["name"] for item in context.tool_definitions()}):
                    raise AdapterError("unsettled or unisolated adapter completion")
            elif not isinstance(frame["error_code"], str) or not re.fullmatch(r"[a-z_]+", frame["error_code"]):
                raise AdapterError("invalid adapter failure code")
            return frame

        async def conversation():
            nonlocal inspected
            assert process is not None and process.stdout is not None
            while True:
                frame = receive(await process.stdout.readline())
                if frame["type"] in ("turn_complete", "turn_failed"):
                    result = final(frame)
                    record("adapter", frame)
                    await process.wait()
                    if process.returncode != (0 if frame["type"] == "turn_complete" else 1):
                        raise AdapterError("adapter exit disagrees with terminal frame")
                    settlement["remote_settled"] = frame["remote_settled"]
                    result["host_inspected_context"] = inspected
                    result["host_checked_predicates"] = sorted(checked)
                    return result
                if (frame["type"] != "tool_request" or set(frame) != {
                        *envelope, "request_id", "type", "context_id", "tool", "arguments"}
                        or frame["request_id"] in seen or frame["context_id"] != context.context_id):
                    raise AdapterError("invalid or repeated adapter tool request")
                seen.add(frame["request_id"])
                if len(seen) > provider.max_tool_calls:
                    raise AdapterError("adapter tool limit exceeded")
                record("adapter", frame)
                # One host tool at a time. Cancellation does not abandon a native
                # worker: drain it before releasing the provider reservation; the
                # evaluator owns bounded process-group execution and worker limits.
                task = asyncio.create_task(asyncio.to_thread(context.call_tool, frame["tool"], frame["arguments"]))
                try:
                    result = await asyncio.shield(task)
                except asyncio.CancelledError:
                    await task
                    raise
                if result.get("ok"):
                    if frame["tool"] in ("evaluate_predicate", "test_candidate") and result.get("valid_syntax"):
                        checked.add(frame["arguments"]["predicate"])
                    elif frame["tool"] not in ("evaluate_predicate", "test_candidate", "get_candidate_result"):
                        inspected = True
                await send({**envelope, "type": "tool_result", "request_id": frame["request_id"], "result": result})

        async def cancel_and_drain():
            nonlocal terminal
            assert process is not None and process.stdout is not None
            try:
                await send({**envelope, "type": "cancel", "request_id": uuid.uuid4().hex})
                # Do not service more model work after cancellation.
                while True:
                    frame = receive(await process.stdout.readline())
                    if frame["type"] in ("turn_complete", "turn_failed"):
                        terminal = final(frame)
                        record("adapter", frame)
                        await process.wait()
                        settlement["remote_settled"] = terminal["remote_settled"]
                        return
            except (OSError, ValueError, AdapterError):
                return

        try:
            environment = native_environment()
            environment.pop("E9TOOL", None)
            environment.pop("E9COMPILE", None)
            environment.update(HOME=private, TMPDIR=private, LC_ALL="C.UTF-8")
            process = await asyncio.create_subprocess_exec(
                sys.executable, "-I", "-S", str(files("taosc_llm").joinpath("_exec.py")),
                *command, "--credential-fd", str(read_fd), cwd=private, env=environment,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                # Never forward provider/SDK stderr into logs or terminal.
                stderr=asyncio.subprocess.DEVNULL, pass_fds=(read_fd,),
                start_new_session=True, limit=MAX_FRAME + 1)
            settlement["remote_settled"] = False
            os.close(read_fd)
            read_fd = -1
            with os.fdopen(write_fd, "wb") as pipe:
                write_fd = -1
                pipe.write(key_bytes)
            await send({**envelope, "type": "start_turn", "request_id": request_id,
                        "provider": provider.public_dict(), "context_id": context.context_id,
                        "system_prompt": context.system_prompt(), "user_prompt": context.initial_prompt(),
                        "tools": context.tool_definitions(), "private_dir": private})
            terminal = await asyncio.wait_for(conversation(), timeout=provider.timeout_seconds + 20)
            return terminal
        except BaseException:
            if process is not None and process.returncode is None:
                try:
                    await asyncio.wait_for(cancel_and_drain(), timeout=15)
                except (TimeoutError, asyncio.CancelledError, OSError, ValueError):
                    pass
            raise
        finally:
            if read_fd >= 0:
                os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)
            if process is not None:
                await _kill(process)
