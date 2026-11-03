"""Trusted-host replay bridge: wire, dataset binding and host-only option."""
import json
import os
import socket
import threading
from pathlib import Path

import pytest

from taosc_llm import evaluation, replay
from taosc_llm.family import parse_candidate

from test_context_tools import make_dataset


class FakeServer:
    """Minimal newline-JSON replay peer; records every request it answers.

    ``status`` is answered from ``status_value`` so an evaluation script only
    has to describe the batch itself.  A scripted status response can still be
    queued first when a test exercises state transitions.
    """

    def __init__(self, path: Path, responses, *, status_value=None,
                 mutations=2, scripted_status=False):
        self.path = path
        self.responses = list(responses)
        # ``scripted_status`` makes status consume the response script, so a
        # test can observe starting -> ready transitions.
        self.status_value = None if scripted_status else (
            status_value if status_value is not None else {
                "state": "ready", "generation_stop": "exhausted",
                "remaining_plans": 0, "retained_mutations": mutations})
        self.requests = []
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()

    def start(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            self.path.unlink()
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.bind(str(self.path))
        self._socket.listen(4)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        self._ready.wait(5)
        return self

    def _serve(self):
        listener = self._socket
        assert listener is not None
        self._ready.set()
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            with connection:
                data = bytearray()
                while b"\n" not in data:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    data.extend(chunk)
                if not data.strip():
                    continue
                request = json.loads(bytes(data).split(b"\n", 1)[0])
                self.requests.append(request)
                if request.get("op") == "status" and self.status_value is not None:
                    response = [self.status_value]
                else:
                    response = (self.responses.pop(0) if self.responses else
                                [{"error": "no more scripted responses"}])
                for item in response:
                    connection.sendall(json.dumps(item).encode() + b"\n")

    def close(self):
        listener = self._socket
        if listener is not None:
            try:
                listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            listener.close()
            self._socket = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None


@pytest.fixture
def run_dir(tmp_path):
    directory = tmp_path / "binradar-run"
    directory.mkdir()
    return directory


@pytest.fixture
def dataset(tmp_path, run_dir):
    # The real importer names function cases after the retained attempt ID;
    # attempt 1 is the unmutated baseline, so the fixture uses 2 and 3.
    base = make_dataset(tmp_path / "dataset", binradar_run=run_dir)
    rows_by_id = {row["id"]: dict(row) for row in base.cases()}
    first, second = (rows_by_id[f"function:{index}"] for index in range(2))
    first["id"], second["id"] = "function:2", "function:3"
    return rewrite_cases(base, [first, second])


def rows(mutations=(2, 3), *, patch=1, outcome="normal", reason=None):
    return [{"mutation": mutation, "patch": patch, "source": "executed",
             "outcome": outcome, "reason": reason} for mutation in mutations]


def done(mutations=2, *, unavailable=0, patches=1):
    return {"done": True, "cases": mutations, "unavailable": unavailable,
            "patches": patches, "mutations": mutations,
            "coverage": "complete" if unavailable == 0 else "partial"}


def serve(run_dir, responses, **kwargs):
    return FakeServer(run_dir / replay.SOCKET_NAME, responses, **kwargs).start()


def status_requests(server):
    return [request for request in server.requests if request.get("op") == "status"]


def evaluate_requests(server):
    return [request for request in server.requests if request.get("op") == "evaluate"]


def rewrite_cases(dataset, rows):
    """Replace the frozen case index with a new, consistently hashed revision."""
    from taosc_llm.dataset import canonical as dataset_canonical
    from taosc_llm.context import digest
    path = dataset.root / "cases.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    manifest = dict(dataset.manifest)
    manifest["cases"] = {"path": "cases.jsonl", "sha256": digest(path.read_bytes())}
    manifest.pop("dataset_id", None)
    manifest["dataset_id"] = digest(dataset_canonical(manifest))
    (dataset.root / "manifest.json").write_text(json.dumps(manifest))
    from taosc_llm.dataset import load_dataset
    return load_dataset(dataset.root)


def test_dataset_without_binradar_run_cannot_replay(tmp_path):
    dataset = make_dataset(tmp_path / "dataset")
    with pytest.raises(replay.ReplayError, match="no binradar run"):
        replay.dataset_socket(dataset)


def test_socket_must_be_the_datasets_own_run(run_dir):
    dataset = make_dataset(run_dir.parent / "dataset", binradar_run=run_dir)
    other = run_dir.parent / "other-run"
    other.mkdir()
    with pytest.raises(replay.ReplayError, match="not the dataset's binradar run"):
        replay.validate_dataset(dataset, other / replay.SOCKET_NAME)


def test_retained_mutations_must_match_frozen_cases(run_dir):
    dataset = make_dataset(run_dir.parent / "dataset", binradar_run=run_dir)
    server = serve(run_dir, [], mutations=1)
    try:
        with pytest.raises(replay.ReplayError, match="retains 1 mutations"):
            replay.validate_dataset(dataset, run_dir / replay.SOCKET_NAME)
    finally:
        server.close()


def test_generating_state_is_not_replayable(run_dir):
    dataset = make_dataset(run_dir.parent / "dataset", binradar_run=run_dir)
    server = serve(run_dir, [], status_value={
        "state": "generating", "generation_stop": None,
        "remaining_plans": 4, "retained_mutations": 0})
    try:
        with pytest.raises(replay.ReplayError, match="not ready"):
            replay.validate_dataset(dataset, run_dir / replay.SOCKET_NAME)
    finally:
        server.close()


def test_wait_ready_uses_status_only(run_dir):
    statuses = [
        {"state": "starting", "generation_stop": None,
         "remaining_plans": None, "retained_mutations": 0},
        {"state": "ready", "generation_stop": "exhausted",
         "remaining_plans": 0, "retained_mutations": 2},
    ]
    server = serve(run_dir, [[statuses[0]], [statuses[1]]], scripted_status=True)
    try:
        ready = replay.wait_ready(run_dir / replay.SOCKET_NAME, timeout=5,
                                  interval=0.01)
    finally:
        server.close()
    assert ready["retained_mutations"] == 2
    assert server.requests == [{"op": "status"}, {"op": "status"}]


def test_wait_ready_reports_dead_launcher(tmp_path):
    import subprocess
    import sys
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()
    path = tmp_path / "replay.sock"
    with pytest.raises(replay.ReplayError, match="exited before ready"):
        replay.wait_ready(path, timeout=5, pid=dead.pid, interval=0.01)


@pytest.mark.parametrize("outcome,source,status,reason", [
    ("normal", "executed", "not_rejected", "observed-not-same-crash"),
    ("target-crash", "executed", "reject_same_crash", "same-crash"),
    ("other-crash", "cache", "not_rejected", "observed-not-same-crash"),
    ("unavailable", "executed", "unavailable", "unsupported-external-state"),
])
def test_outcome_mapping_matches_the_existing_evaluation_vocabulary(
        run_dir, dataset, outcome, source, status, reason):
    server = serve(run_dir, [[
        {"mutation": 2, "patch": 1, "source": source, "outcome": outcome,
         "reason": "unsupported-external-state" if outcome == "unavailable" else None},
        {"mutation": 3, "patch": 1, "source": source, "outcome": outcome,
         "reason": "unsupported-external-state" if outcome == "unavailable" else None},
        done(unavailable=2 if outcome == "unavailable" else 0),
    ]])
    try:
        result = replay.evaluate_replay(dataset, parse_candidate("ERM generic", "rax <= 0"))
    finally:
        server.close()
    assert [case["status"] for case in result["cases"]] == [status, status]
    assert {case["reason"] for case in result["cases"]} == {reason}
    assert result["status"] == status
    assert status_requests(server) == [{"op": "status"}]
    assert evaluate_requests(server)[0]["patches"] == [
        {"id": 1, "predicate": "(rax <= 0) == 0"}]


def test_busy_is_retried_without_losing_the_batch(run_dir, dataset):
    server = serve(run_dir, [
        [{"error": "busy"}],
        rows() + [done()],
    ])
    try:
        result = replay.evaluate_replay(dataset, parse_candidate("ERM generic", "1"),
                                        admission_timeout=5)
    finally:
        server.close()
    assert len(evaluate_requests(server)) == 2
    assert [case["status"] for case in result["cases"]] == ["not_rejected"] * 2


def test_busy_past_the_admission_deadline_is_an_error(run_dir, dataset):
    server = serve(run_dir, [[{"error": "busy"}]])
    try:
        with pytest.raises(replay.ReplayError, match="waiting for the replay"):
            replay.evaluate_replay(dataset, parse_candidate("ERM generic", "1"),
                                   admission_timeout=0.05)
    finally:
        server.close()


@pytest.mark.parametrize("responses,match", [
    (rows() + [done(), {"mutation": 4, "patch": 1, "source": "executed",
                        "outcome": "normal", "reason": None}],
     "after its terminal row"),
    (rows(), "without a terminal row"),
    (rows() + [done(mutations=3)], "counts disagree"),
    ([{"mutation": 2, "patch": 1, "source": "executed", "outcome": "normal",
       "reason": "timeout"}, done(unavailable=0)], "reason for an available outcome"),
    ([{"mutation": 2, "patch": 1, "source": "executed", "outcome": "unavailable",
       "reason": None}, done(unavailable=1)], "without a known reason"),
    ([{"mutation": 2, "patch": 2, "source": "executed", "outcome": "normal",
       "reason": None}, done()], "another patch id"),
])
def test_malformed_or_incomplete_replay_batches_are_rejected(
        run_dir, dataset, responses, match):
    server = serve(run_dir, [responses])
    try:
        with pytest.raises(replay.ReplayError, match=match):
            replay.evaluate_replay(dataset, parse_candidate("ERM generic", "1"))
    finally:
        server.close()


def test_missing_terminal_row_after_streamed_cases_is_not_completion(run_dir, dataset):
    server = serve(run_dir, [rows()])
    try:
        with pytest.raises(replay.ReplayError, match="without a terminal row"):
            replay.evaluate_replay(dataset, parse_candidate("ERM generic", "1"))
    finally:
        server.close()


def test_replay_socket_never_appears_in_the_model_projection(run_dir, dataset):
    from taosc_llm.context import prepare_context
    plain = prepare_context(dataset)
    live = prepare_context(dataset, replay_socket=run_dir / replay.SOCKET_NAME)
    assert str(run_dir) not in live.initial_prompt()
    assert live.projection["policy"] != plain.projection["policy"]
    assert live.context_id != plain.context_id


def test_evaluation_keeps_concrete_cases_on_their_own_path(run_dir, dataset, tmp_path, monkeypatch):
    # Give the dataset a concrete case and a function case with no capture.
    manifest_path = dataset.workdir / "brpatches.json"
    manifest_path.write_text('{"version":1,"kind":"generic-erm","predicates":[]}')
    from taosc_llm.context import digest
    base_manifest = {**dataset.manifest, "artifacts": {
        **dataset.manifest["artifacts"],
        "brpatches.json": {"path": "workdir/brpatches.json",
                           "sha256": digest(manifest_path.read_bytes())}}}
    from taosc_llm.dataset import canonical as dataset_canonical
    base_manifest.pop("dataset_id", None)
    base_manifest["dataset_id"] = digest(dataset_canonical(base_manifest))
    (dataset.root / "manifest.json").write_text(json.dumps(base_manifest))
    from taosc_llm.dataset import load_dataset
    dataset = load_dataset(dataset.root)
    cases = {row["id"]: dict(row) for row in dataset.cases()}
    concrete = {**cases["function:2"], "id": "system:0", "domain": "system",
                "source": {"case_id": 0, "filename": "input"}}
    mutation = {**cases["function:3"], "id": "function:2"}
    dataset = rewrite_cases(dataset, [concrete, mutation])
    executed = []

    def run(ds, case, descriptor, directory):
        executed.append(case["id"])
        raise evaluation.ExecutionUnavailable("fixture-concrete-unavailable")

    monkeypatch.setattr(evaluation, "execute_capture", run)
    server = serve(run_dir, [rows((2,)) + [done(mutations=1)]], mutations=1)
    try:
        result = evaluation.evaluate_dataset(
            dataset, "rax <= 0", cache_dir=tmp_path / "cache",
            replay_socket=run_dir / replay.SOCKET_NAME)
    finally:
        server.close()
    assert executed == ["system:0"]
    assert {case["case_id"]: case["source"] for case in result["cases"]} == {
        "system:0": "unavailable", "function:2": "executed"}
    assert result["replay"]["mutations"] == 1


def test_evaluation_without_replay_keeps_function_cases_offline(run_dir, dataset,
                                                                 tmp_path, monkeypatch):
    rows_by_id = {row["id"]: dict(row) for row in dataset.cases()}
    dataset = rewrite_cases(dataset, [rows_by_id["function:2"]])
    monkeypatch.setattr(evaluation, "execute_capture",
                        lambda *a: pytest.fail("offline function case executed"))
    result = evaluation.evaluate_dataset(dataset, "1",
                                         cache_dir=tmp_path / "cache")
    assert result["status"] == "unavailable"
    assert result["cases"][0]["source"] != "executed"


def test_tool_exposes_replay_only_through_host_context(run_dir, dataset):
    from taosc_llm.context import prepare_context
    server = serve(run_dir, [rows() + [done()]])
    try:
        context = prepare_context(dataset, run_dir=run_dir.parent / "run",
                                  replay_socket=run_dir / replay.SOCKET_NAME)
        result = context.call_tool("test_candidate", {
            "context_id": context.context_id, "predicate": "1"})
    finally:
        server.close()
    assert result["ok"] is True and result["verified"] is False
    assert result["cases"]["total"] == 2
    # A tool caller cannot pass an endpoint, execute flag or path.
    for args in ({"context_id": context.context_id, "predicate": "1",
                  "replay_socket": str(run_dir / replay.SOCKET_NAME)},
                 {"context_id": context.context_id, "predicate": "1", "execute": True}):
        denied = context.call_tool("test_candidate", args)
        assert denied["ok"] is False and denied["error"]["code"] == "invalid_arguments"

def test_model_tool_shares_live_bridge_and_never_sees_the_endpoint(run_dir, dataset):
    """The Pi-facing tool reaches the same snapshot the host configured."""
    from taosc_llm.context import prepare_context
    server = serve(run_dir, [rows() + [done()]])
    try:
        context = prepare_context(dataset, run_dir=run_dir.parent / "run",
                                  replay_socket=run_dir / replay.SOCKET_NAME,
                                  cache_dir=run_dir.parent / "cache")
        result = context.call_tool("test_candidate", {
            "context_id": context.context_id, "predicate": "rax <= 0"})
    finally:
        server.close()
    assert result["ok"] is True
    assert result["verified"] is False
    assert evaluate_requests(server)[0]["patches"] == [
        {"id": 1, "predicate": "(rax <= 0) == 0"}]
    # Projection, prompt, and the tool result carry no endpoint or cache path.
    for text in (context.initial_prompt(), json.dumps(result),
                 json.dumps(context.projection)):
        assert str(run_dir) not in text
        assert str(run_dir.parent / "cache") not in text


def test_host_cache_dir_is_shared_by_tool_and_cli(dataset, run_dir, tmp_path):
    from taosc_llm.context import prepare_context
    shared = tmp_path / "shared-cache"
    context = prepare_context(dataset, run_dir=tmp_path / "run",
                              cache_dir=shared)
    assert context.cache_dir == shared
    assert context.replay_socket is None
    assert str(shared) not in context.initial_prompt()
