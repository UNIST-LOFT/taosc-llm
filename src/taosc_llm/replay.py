"""Trusted-host bridge to a resident BinRadar replay server.

The sandboxed model never sees this socket or its path.  Only the host
evaluator submits one canonical family predicate at a time; the native parent
owns the snapshot, retained mutation plans and cross-request result cache.

This is an explicit host option (``--replay``).  Without it, function
(mutation) cases stay offline and rejection-only.  Concrete ``system`` cases
always use their existing capture/cache/execution path and never the live
mutation snapshot.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import select
import socket
import stat
import sys
import time
from pathlib import Path

SOCKET_NAME = "replay.sock"
STATUS_TIMEOUT = 10.0
# Per-response inactivity, not a whole-batch deadline.  The resident server
# bounds each child attempt itself; this only detects a dead or stuck peer.
RESPONSE_TIMEOUT = 2100.0
ADMISSION_TIMEOUT = 2100.0
RESPONSE_LIMIT = 16 * 1024 * 1024
WAIT_INTERVAL = 0.25
STATES = ("starting", "generating", "ready", "evaluating", "stopping")
SOURCES = ("cache", "executed")
OUTCOMES = ("normal", "target-crash", "other-crash", "unavailable")
REASONS = (
    "unknown-mutation",
    "invalid-descriptor",
    "unsupported-external-state",
    "cancelled",
    "timeout",
    "incomplete-observation",
)
BUSY = "busy"


class ReplayError(ValueError):
    """The resident service is unavailable or violated its wire contract."""


def _reject_extra(value: dict, allowed: set, what: str) -> None:
    extra = set(value) - allowed
    if extra:
        raise ReplayError(f"{what} has unexpected field(s): "
                          f"{', '.join(sorted(extra))}")


def _integer(value, *, positive: bool, what: str) -> int:
    if type(value) is not int or value < (1 if positive else 0):
        raise ReplayError(
            f"{what} must be a {'positive' if positive else 'nonnegative'} integer")
    return value


def validate_status(value: dict) -> dict:
    if not isinstance(value, dict):
        raise ReplayError("replay status is not an object")
    _reject_extra(value, {"state", "generation_stop", "remaining_plans",
                          "retained_mutations"}, "replay status")
    if value.get("state") not in STATES:
        raise ReplayError(f"replay status has unknown state {value.get('state')!r}")
    stop = value.get("generation_stop")
    if stop is not None and not isinstance(stop, str):
        raise ReplayError("replay status generation_stop must be a string or null")
    remaining = value.get("remaining_plans")
    if remaining is not None:
        _integer(remaining, positive=False, what="remaining_plans")
    _integer(value.get("retained_mutations"), positive=False,
             what="retained_mutations")
    return value


def _read_objects(socket_path: Path, payload: dict, *,
                  timeout: float, operation_check=None) -> list[dict]:
    """One newline-delimited request/response exchange on its own connection."""
    if operation_check is not None:
        operation_check()
    connection = None
    try:
        endpoint = socket_path.resolve(strict=True)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(timeout)
        connection.connect(str(endpoint))
    except (OSError, RuntimeError) as exc:
        if connection is not None:
            connection.close()
        raise ReplayError(
            f"replay socket unavailable: {socket_path}: {exc}") from exc
    try:
        if operation_check is not None:
            operation_check()
        try:
            connection.sendall(
                json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
        except OSError as exc:
            raise ReplayError(
                f"replay request failed: {socket_path}: {exc}") from exc
        data = bytearray()
        objects: list[dict] = []
        received = 0
        last_activity = time.monotonic()
        while True:
            if operation_check is not None:
                # Callback exceptions deliberately escape protocol-error wrapping.
                # Closing this request cancels only its batch, not the resident.
                operation_check()
                remaining = timeout - (time.monotonic() - last_activity)
                if remaining <= 0:
                    raise ReplayError(f"replay response timed out after {timeout:g}s: {socket_path}")
                try:
                    readable, _, _ = select.select([connection], [], [], min(WAIT_INTERVAL, remaining))
                except OSError as exc:
                    raise ReplayError(f"replay response failed: {socket_path}: {exc}") from exc
                if not readable:
                    continue
            try:
                chunk = connection.recv(65536)
            except TimeoutError as exc:
                raise ReplayError(
                    f"replay response timed out after {timeout:g}s: "
                    f"{socket_path}") from exc
            except OSError as exc:
                raise ReplayError(
                    f"replay response failed: {socket_path}: {exc}") from exc
            if not chunk:
                break
            last_activity = time.monotonic()
            data.extend(chunk)
            received += len(chunk)
            if received > RESPONSE_LIMIT:
                raise ReplayError(
                    f"replay response exceeds {RESPONSE_LIMIT} bytes")
            while b"\n" in data:
                line, _, remainder = bytes(data).partition(b"\n")
                data[:] = remainder
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ReplayError("replay server returned malformed JSON") from exc
                if not isinstance(value, dict):
                    raise ReplayError("replay server returned a non-object")
                objects.append(value)
        if data.strip():
            raise ReplayError("replay response ended without a newline")
        return objects
    finally:
        connection.close()


def status(socket_path, *, timeout: float = STATUS_TIMEOUT, operation_check=None) -> dict:
    objects = _read_objects(Path(socket_path), {"op": "status"}, timeout=timeout,
                            operation_check=operation_check)
    if len(objects) != 1:
        raise ReplayError("replay status must return exactly one object")
    if "error" in objects[0]:
        raise ReplayError(f"replay status failed: {objects[0]['error']}")
    return validate_status(objects[0])


def shutdown(socket_path, *, timeout: float = STATUS_TIMEOUT) -> dict:
    objects = _read_objects(Path(socket_path), {"op": "shutdown"}, timeout=timeout)
    if len(objects) != 1 or objects[0] != {"accepted": True}:
        raise ReplayError("replay shutdown was not acknowledged")
    return {"accepted": True}


def _process_alive(pid: int) -> bool:
    """A zombie launcher must not look alive while its server is gone."""
    try:
        data = Path(f"/proc/{int(pid)}/stat").read_bytes()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    end = data.rfind(b")")
    return end >= 0 and data[end + 2:end + 3] != b"Z"


def wait_ready(socket_path, *, timeout: float, pid: int | None = None,
               interval: float = WAIT_INTERVAL) -> dict:
    """Block until ready; timeout zero waits indefinitely, not past launcher death."""
    if timeout < 0:
        raise ValueError("readiness timeout must be nonnegative")
    deadline = time.monotonic() + timeout if timeout else None
    last_error: Exception | None = None
    while True:
        if pid is not None and not _process_alive(pid):
            raise ReplayError(f"replay server process {pid} exited before ready")
        remaining = None if deadline is None else deadline - time.monotonic()
        if remaining is not None and remaining <= 0:
            detail = f": {last_error}" if last_error is not None else ""
            raise TimeoutError(
                f"replay server did not reach ready within {timeout:g}s{detail}")
        try:
            value = status(socket_path, timeout=STATUS_TIMEOUT if remaining is None
                           else min(STATUS_TIMEOUT, remaining))
        except ReplayError as exc:
            last_error = exc
        else:
            if value["state"] == "ready":
                return value
            if value["state"] == "stopping":
                raise ReplayError("replay server is stopping")
            last_error = None
        if deadline is not None and time.monotonic() >= deadline:
            detail = f": {last_error}" if last_error is not None else ""
            raise TimeoutError(
                f"replay server did not reach ready within {timeout:g}s{detail}")
        time.sleep(interval if deadline is None else
                   min(interval, max(0.0, deadline - time.monotonic())))


def dataset_socket(dataset) -> Path:
    """Return the socket of the dataset's frozen ``--binradar-run``."""
    source = (dataset.manifest.get("sources") or {}).get("binradar_run")
    if not source:
        raise ReplayError(
            "dataset has no binradar run; prepare it with "
            "taosc-llm-setup --binradar-run")
    return Path(source).expanduser().absolute() / SOCKET_NAME


def retained_cases(dataset) -> list[dict]:
    """Select the native committed-useful subset without losing offline evidence.

    Native snapshot_modify_memory fails before publishing a valid exit when a
    plan cannot apply, and generation discards patch-zero site misses before
    committing captures. Consequently the imported committed mutation pairs
    already guarantee applied/site-observed. snapshot_replay_commit_plan further
    keeps only normal exits or authenticated target crashes; other crashes are
    valid frozen evidence, but have no retained plan.
    """
    return [case for case in dataset.cases("function")
            if (case.get("capture") or {}).get("outcome", {}).get("outcome") == "normal"
            or (case.get("capture") or {}).get("same_crash") is True]


def validate_dataset(dataset, socket_path, *, operation_check=None) -> tuple[Path, list[dict], dict]:
    """Bind the live service to the frozen dataset before any predicate runs.

    The dataset records the exact mutation run it imported, so a socket from a
    different generation is a mismatch, not an interchangeable endpoint.
    """
    expected = dataset_socket(dataset)
    actual = Path(socket_path).expanduser().absolute()
    if actual.resolve() != expected.resolve():
        raise ReplayError(
            f"replay socket {actual} is not the dataset's binradar run "
            f"({expected})")
    cases = retained_cases(dataset)
    info = status(actual, operation_check=operation_check)
    if info["state"] not in ("ready", "evaluating"):
        raise ReplayError(
            f"replay server is not ready (state={info['state']}); wait for "
            "generation to finish")
    if info["retained_mutations"] != len(cases):
        raise ReplayError(
            f"replay server retains {info['retained_mutations']} mutations but "
            f"the dataset froze {len(cases)} useful function cases")
    return actual, cases, info


def _validate_row(value: dict) -> dict:
    _reject_extra(value, {"mutation", "patch", "source", "outcome", "reason", "capture"},
                  "replay case")
    mutation = _integer(value.get("mutation"), positive=True, what="case mutation")
    if _integer(value.get("patch"), positive=True, what="case patch") != 1:
        raise ReplayError(f"replay case {mutation} answers another patch id")
    if value.get("source") not in SOURCES:
        raise ReplayError(f"replay case {mutation} has unknown source")
    outcome = value.get("outcome")
    if outcome not in OUTCOMES:
        raise ReplayError(f"replay case {mutation} has unknown outcome")
    reason = value.get("reason")
    if outcome == "unavailable":
        if reason not in REASONS:
            raise ReplayError(
                f"replay case {mutation} is unavailable without a known reason")
    elif reason is not None:
        raise ReplayError(
            f"replay case {mutation} carries a reason for an available outcome")
    return value


def _validate_done(value: dict) -> dict:
    _reject_extra(value, {"done", "cases", "unavailable", "patches", "mutations",
                          "coverage"}, "replay terminal row")
    if value.get("done") is not True:
        raise ReplayError("replay terminal row is not done=true")
    for name in ("cases", "unavailable", "patches", "mutations"):
        _integer(value.get(name), positive=name in ("patches", "mutations"),
                 what=f"terminal {name}")
    if value["coverage"] not in ("complete", "partial"):
        raise ReplayError("replay terminal row has unknown coverage")
    expected = "complete" if value["unavailable"] == 0 else "partial"
    if value["coverage"] != expected:
        raise ReplayError(
            "replay terminal coverage disagrees with its unavailable count")
    return value


def _capture(dataset, row: dict, candidate) -> dict | None:
    """Authenticate the native-owned representative, not the caller's selector."""
    from binradar.binradar_taosc_predicates import parse_cached_snapshots
    from .evaluation import _capture_metadata, _memo, _validated_snapshots, _vector

    identity = row.get("capture")
    if row["outcome"] == "unavailable":
        if identity is not None:
            raise ReplayError("unavailable replay case carries candidate state")
        return None
    fields = {"mutation", "path", "sha256", "descriptor", "patch_id", "reuse"}
    if not isinstance(identity, dict) or set(identity) != fields:
        raise ReplayError("available replay case has no complete capture identity")
    if type(identity["mutation"]) is not int or identity["mutation"] != row["mutation"]:
        raise ReplayError("replay capture belongs to another mutation")
    if type(identity["patch_id"]) is not int or identity["patch_id"] not in (0, 1):
        raise ReplayError("replay capture has an unknown selector")
    reuse = identity["reuse"]
    if reuse not in ("fresh", "exact-descriptor", "full-vector-equivalent") or \
            (row["source"] == "executed") != (reuse == "fresh"):
        raise ReplayError("replay capture has inconsistent reuse provenance")
    descriptor = identity["descriptor"]
    digest = identity["sha256"]
    if reuse == "fresh" and (identity["patch_id"] != 1 or descriptor != candidate.descriptor):
        raise ReplayError("replay fresh capture does not identify the executed predicate")
    if not isinstance(descriptor, str) or not descriptor or \
            len(descriptor.encode("utf-8")) > 4095:
        raise ReplayError("replay capture descriptor is invalid")
    if not isinstance(digest, str) or len(digest) != 64 or \
            any(c not in "0123456789abcdef" for c in digest):
        raise ReplayError("replay capture digest is invalid")
    raw_path = identity["path"]
    if not isinstance(raw_path, str) or len(raw_path.encode("utf-8")) > 8192:
        raise ReplayError("replay capture path is invalid")
    try:
        run = dataset_socket(dataset).parent.resolve(strict=True)
        root = (run / "replay").resolve(strict=True)
        path = Path(raw_path)
        if not path.is_absolute() or root.parent != run or \
                not path.resolve(strict=True).is_relative_to(root):
            raise ReplayError("replay capture is outside the frozen run replay directory")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 64 * 1024 * 1024:
                raise ReplayError("replay capture has invalid type or size")
            payload = stream.read(64 * 1024 * 1024 + 1)
        if len(payload) != info.st_size or hashlib.sha256(payload).hexdigest() != digest:
            raise ReplayError("replay capture hash mismatch")
        # Preserve the native-owned path/type/size/hash checks above, then
        # share these already authenticated bytes and the native parse with
        # validation, evidence projection and journal preservation.
        cache_key = (str(path), digest)
        _memo(dataset, 'record-bytes', cache_key, lambda: payload)
        def parse():
            states, error = parse_cached_snapshots(payload)
            if error:
                raise ValueError(error)
            return tuple(states)
        snapshots = _memo(dataset, 'parsed-brch', digest, parse)
        branches = [state.branch for state in snapshots]
        if not branches or any(branch not in (0, 1) for branch in branches):
            raise ValueError("replay-capture-incomplete-or-trapped")
        metadata = _capture_metadata(dataset)
        capture = {"path": str(path), "sha256": digest,
                   "artifact_sha256": metadata.artifact_sha256,
                   "descriptor": descriptor, "branches": branches,
                   "complete": True, "patch_id": identity["patch_id"],
                   "outcome": {"outcome": row["outcome"]},
                   "same_crash": row["outcome"] == "target-crash"}
        snapshots = _validated_snapshots(dataset, capture, metadata)
        if _vector(descriptor, snapshots, dataset=dataset) != branches or \
                _vector(candidate.descriptor, snapshots, dataset=dataset) != branches:
            raise ValueError("replay-capture-vector-mismatch")
        return capture
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        raise ReplayError(f"replay capture authentication failed: {exc}") from exc


def _case_result(dataset, row: dict, candidate) -> dict:
    capture = _capture(dataset, row, candidate)
    mutation = row["mutation"]
    outcome = row["outcome"]
    if outcome == "target-crash":
        # Only the selected artifact's committed attempt-1 reference produces
        # target-crash; another crash is not that reference.
        status, reason = "reject_same_crash", "same-crash"
    elif outcome in ("normal", "other-crash"):
        status, reason = "not_rejected", "observed-not-same-crash"
    else:
        status, reason = "unavailable", row["reason"]
    return {
        "case_id": f"function:{mutation}",
        "domain": "function",
        "descriptor": candidate.descriptor,
        "source": row["source"],
        "status": status,
        "reason": reason,
        "branches": capture["branches"] if capture is not None else None,
        "capture": capture,
        "reuse": row["capture"]["reuse"] if capture is not None else None,
        "offline_branches": None,
        "first_divergence": None,
        "outcome": {"outcome": outcome},
        "verified": False,
    }


def _exchange(path: Path, source_predicate: str, *,
              admission_timeout: float, response_timeout: float,
              operation_check=None) -> list[dict]:
    deadline = time.monotonic() + admission_timeout
    request = {"op": "evaluate",
               "patches": [{"id": 1, "predicate": source_predicate}]}
    while True:
        # ``busy`` is an admission-time refusal: no child ran and nothing was
        # streamed.  Another host evaluation (for example a debugging
        # ``taosc-llm-evaluate``) may own the snapshot for a while, so retry
        # until this bounded admission deadline.
        if operation_check is not None:
            operation_check()
        if time.monotonic() >= deadline:
            raise ReplayError(
                f"timed out after {admission_timeout:g}s waiting for the "
                "replay evaluation owner")
        objects = _read_objects(path, request, timeout=response_timeout,
                                operation_check=operation_check)
        if len(objects) == 1 and objects[0].get("error") == BUSY:
            time.sleep(min(WAIT_INTERVAL, max(0.0, deadline - time.monotonic())))
            continue
        return objects


def evaluate_replay(dataset, candidate, *, socket_path=None,
                    admission_timeout: float = ADMISSION_TIMEOUT,
                    response_timeout: float = RESPONSE_TIMEOUT,
                    operation_check=None) -> dict:
    """Evaluate one candidate over every retained mutation in the live snapshot."""
    scope = (dataset.validation() if operation_check is None
             else dataset.validation(check=operation_check))
    with scope as validated:
        return _evaluate_replay(validated, candidate, socket_path=socket_path,
                                admission_timeout=admission_timeout,
                                response_timeout=response_timeout,
                                operation_check=operation_check)


def _evaluate_replay(dataset, candidate, *, socket_path, admission_timeout,
                     response_timeout, operation_check=None):
    path, cases, _info = validate_dataset(
        dataset, dataset_socket(dataset) if socket_path is None else socket_path,
        operation_check=operation_check)
    if not cases:
        return {
            "cases": [], "status": "unavailable",
            "summary": {"total": 0, "reject_same_crash": 0,
                        "not_rejected": 0, "unavailable": 0},
            "replay": {"socket": str(path), "coverage": "empty",
                       "mutations": 0, "unavailable": 0},
        }
    objects = _exchange(path, candidate.source_predicate,
                        admission_timeout=admission_timeout,
                        response_timeout=response_timeout,
                        operation_check=operation_check)
    rows: list[dict] = []
    terminal: dict | None = None
    for value in objects:
        if operation_check is not None:
            operation_check()
        if "error" in value:
            if rows:
                raise ReplayError(
                    "replay server failed after streaming cases: "
                    + str(value["error"]))
            _reject_extra(value, {"error"}, "replay error")
            raise ReplayError(f"replay server rejected the batch: {value['error']}")
        if "done" in value:
            if terminal is not None:
                raise ReplayError("replay server sent two terminal rows")
            terminal = _validate_done(value)
            continue
        if terminal is not None:
            raise ReplayError("replay server sent a case after its terminal row")
        rows.append(_validate_row(value))
    if terminal is None:
        raise ReplayError("replay server closed the batch without a terminal row")
    expected = {int(case["id"].split(":", 1)[1]) for case in cases}
    observed = [row["mutation"] for row in rows]
    if len(observed) != len(cases) or set(observed) != expected:
        raise ReplayError("replay mutation set does not match the frozen dataset")
    if terminal["cases"] != len(rows) or terminal["patches"] != 1 or \
            terminal["mutations"] != len(cases) or \
            terminal["unavailable"] != sum(row["outcome"] == "unavailable" for row in rows):
        raise ReplayError("replay terminal counts disagree with streamed cases")
    by_mutation = {row["mutation"]: row for row in rows}
    results = []
    for case in cases:
        if operation_check is not None:
            operation_check()
        results.append(_case_result(dataset, by_mutation[int(case["id"].split(":", 1)[1])], candidate))
    counts = {status: sum(item["status"] == status for item in results)
              for status in ("reject_same_crash", "not_rejected", "unavailable")}
    status = ("reject_same_crash" if counts["reject_same_crash"] else
              "unavailable" if counts["unavailable"] else "not_rejected")
    return {
        "cases": results,
        "status": status,
        "summary": {"total": len(results), **counts},
        "replay": {
            "socket": str(path),
            "coverage": terminal["coverage"],
            "mutations": terminal["mutations"],
            "unavailable": terminal["unavailable"],
        },
    }


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m taosc_llm.replay",
        description="Debug the trusted-host bridge to a resident BinRadar "
                    "replay server.",
    )
    parser.add_argument("operation", choices=("status", "wait", "evaluate", "shutdown"))
    endpoint = parser.add_mutually_exclusive_group(required=True)
    endpoint.add_argument("--socket", type=Path)
    endpoint.add_argument("--dataset", type=Path)
    parser.add_argument("--predicate")
    parser.add_argument("--timeout", type=float, default=ADMISSION_TIMEOUT,
                        help="seconds to wait (wait: 0 means unlimited; default: %(default)g)")
    parser.add_argument("--pid", type=int,
                        help="launcher pid; a dead process fails wait early")
    args = parser.parse_args(argv)
    if args.dataset is None and args.operation == "evaluate":
        parser.error("--dataset is required to bind predicates to frozen cases")
    if args.operation == "evaluate" and args.predicate is None:
        parser.error("evaluate requires --predicate")

    def execute():
        path = args.socket
        dataset = None
        if args.dataset is not None:
            from .dataset import load_dataset
            dataset = load_dataset(args.dataset)
            path = dataset_socket(dataset)
        if args.operation == "status":
            return status(path)
        if args.operation == "shutdown":
            return shutdown(path)
        if args.operation == "wait":
            return wait_ready(path, timeout=args.timeout, pid=args.pid)
        from .family import parse_candidate
        assert dataset is not None
        return evaluate_replay(dataset, parse_candidate(
            dataset.patch_format, args.predicate))

    try:
        print(json.dumps(execute(), allow_nan=False))
        return 0
    except (OSError, ReplayError, TimeoutError, ValueError) as error:
        print(f"taosc-llm replay: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(_main())
