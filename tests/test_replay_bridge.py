"""Trusted-host replay bridge: wire, dataset binding and host-only option."""
import json
import os
import socket
import tempfile
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
                 mutations=2, scripted_status=False, patch_format="ERM generic",
                 capture_root=None):
        self.patch_format = patch_format
        self.capture_root = Path(capture_root) if capture_root is not None else path.parent
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
        self._directory = None

    def start(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists() or self.path.is_symlink():
            self.path.unlink()
        # Match BinRadar's public-link/private-socket contract even when Guix
        # gives pytest a long TMPDIR and parametrized test directory.
        self._directory = tempfile.TemporaryDirectory(prefix="br-peer-", dir="/tmp")
        try:
            endpoint = Path(self._directory.name) / "replay.sock"
            self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._socket.bind(str(endpoint))
            self._socket.listen(4)
            self.path.symlink_to(endpoint)
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()
            self._ready.wait(5)
            return self
        except BaseException:
            self.close()
            raise

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
                    if request.get("op") == "evaluate" and "mutation" in item and "capture" not in item:
                        item = {**item, "capture": self._capture(request, item)}
                    connection.sendall(json.dumps(item).encode() + b"\n")

    def _capture(self, request, row):
        if row["outcome"] == "unavailable":
            return None
        from binradar import binradar_taosc_predicates as predicates
        from binradar.binradar_replay import lower_predicate
        import hashlib
        cwe = self.patch_format == "ERM CWE-805"
        descriptor = lower_predicate("CWE805-erm" if cwe else "generic-erm",
                                     request["patches"][0]["predicate"])
        registers = predicates.CACHED_SNAPSHOT_REGS.pack(150 if cwe else (1 << 64) - 3, *([0] * 15))
        clamps = (100).to_bytes(8, "little") + (200).to_bytes(8, "little") + b"\0" * (predicates.CACHED_SNAPSHOT_CLAMPS.size - 16)
        def state(branch):
            return (predicates.CACHED_SNAPSHOT_HEADER.pack(
                predicates.CACHED_SNAPSHOT_MAGIC, 1, 1, branch, 0, 2 if cwe else 0)
                + (clamps if cwe else b"")
                + registers)
        snapshots, error = predicates.parse_cached_snapshots(state(0))
        assert error is None
        branch = predicates.evaluate_cached_predicate(
            predicates.parse_predicate_descriptor(descriptor), snapshots)[0]
        assert branch in (0, 1)
        payload = state(branch)
        directory = self.capture_root / "replay"
        directory.mkdir(exist_ok=True)
        path = directory / f"capture-{row['mutation']}.brch"
        path.write_bytes(payload)
        return {"mutation": row["mutation"], "path": str(path),
                "sha256": hashlib.sha256(payload).hexdigest(), "descriptor": descriptor,
                "patch_id": 1, "reuse": "fresh" if row["source"] == "executed" else "exact-descriptor"}

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
        if self._directory is not None:
            endpoint = Path(self._directory.name) / "replay.sock"
            if self.path.is_symlink() and self.path.readlink() == endpoint:
                self.path.unlink()
            self._directory.cleanup()
            self._directory = None


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
    for case in (first, second):
        case["observation"] = {"outcome": "normal"}
        case["capture"] = {**case["capture"], "outcome": {"outcome": "normal"}}
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


def test_retained_mutations_must_match_frozen_cases(run_dir, dataset):
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


@pytest.mark.parametrize("timeout", [0, 5])
def test_wait_ready_uses_status_only(run_dir, timeout):
    statuses = [
        {"state": "starting", "generation_stop": None,
         "remaining_plans": None, "retained_mutations": 0},
        {"state": "ready", "generation_stop": "exhausted",
         "remaining_plans": 0, "retained_mutations": 2},
    ]
    server = serve(run_dir, [[statuses[0]], [statuses[1]]], scripted_status=True)
    try:
        ready = replay.wait_ready(run_dir / replay.SOCKET_NAME, timeout=timeout,
                                  interval=0.01)
    finally:
        server.close()
    assert ready["retained_mutations"] == 2
    assert server.requests == [{"op": "status"}, {"op": "status"}]


@pytest.mark.parametrize("timeout", [0, 5])
def test_wait_ready_reports_dead_launcher(tmp_path, timeout):
    import subprocess
    import sys
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()
    path = tmp_path / "replay.sock"
    with pytest.raises(replay.ReplayError, match="exited before ready"):
        replay.wait_ready(path, timeout=timeout, pid=dead.pid, interval=0.01)


def test_wait_ready_positive_timeout_bounds_status_request(tmp_path, monkeypatch):
    clock = [0.0]
    observed_timeouts = []
    monkeypatch.setattr(replay.time, "monotonic", lambda: clock[0])
    def sleep(delay):
        clock[0] += delay
    def generating(path, *, timeout):
        observed_timeouts.append(timeout)
        clock[0] += timeout
        raise replay.ReplayError("peer stalled")
    monkeypatch.setattr(replay.time, "sleep", sleep)
    monkeypatch.setattr(replay, "status", generating)
    with pytest.raises(TimeoutError, match="within 0.1s"):
        replay.wait_ready(tmp_path / "missing", timeout=0.1)
    assert observed_timeouts == [0.1]
    assert clock[0] == 0.1


def test_unlimited_wait_fails_on_stopping(run_dir):
    server = serve(run_dir, [], status_value={
        "state": "stopping", "generation_stop": "shutdown",
        "remaining_plans": 0, "retained_mutations": 0})
    try:
        with pytest.raises(replay.ReplayError, match="stopping"):
            replay.wait_ready(run_dir / replay.SOCKET_NAME, timeout=0)
    finally:
        server.close()
    assert len(status_requests(server)) == 1


def test_wait_cli_zero_waits_until_ready(run_dir, capsys):
    server = serve(run_dir, [
        [{"state": "generating", "generation_stop": None,
          "remaining_plans": 1, "retained_mutations": 0}],
        [{"state": "ready", "generation_stop": "exhausted",
          "remaining_plans": 0, "retained_mutations": 2}],
    ], scripted_status=True)
    try:
        assert replay._main(["wait", "--socket", str(server.path), "--timeout", "0"]) == 0
    finally:
        server.close()
    assert json.loads(capsys.readouterr().out)["state"] == "ready"
    assert len(status_requests(server)) == 2


@pytest.mark.parametrize("leaf", ["long-run-" + "x" * 110, "é" * 60])
def test_long_published_socket_supports_all_operations(dataset, tmp_path, leaf):
    target = tmp_path / leaf
    target.mkdir()
    public = target / replay.SOCKET_NAME
    base = make_dataset(tmp_path / "published-dataset", binradar_run=target)
    bound = rewrite_cases(base, dataset.cases("function"))
    with tempfile.TemporaryDirectory(prefix="replay-peer-", dir="/tmp") as short:
        server = FakeServer(Path(short) / replay.SOCKET_NAME,
                            [rows() + [done()], [{"accepted": True}]], capture_root=target).start()
        public.symlink_to(server.path)
        try:
            assert replay.status(public)["state"] == "ready"
            assert replay.wait_ready(public, timeout=5)["state"] == "ready"
            result = replay.evaluate_replay(bound, parse_candidate("ERM generic", "1"))
            assert replay.shutdown(public) == {"accepted": True}
        finally:
            server.close()
        assert len(os.fsencode(str(public))) > 107
        assert result["replay"]["socket"] == str(public)
        assert len(status_requests(server)) == 3
        assert len(evaluate_requests(server)) == 1
        assert server.requests[-1] == {"op": "shutdown"}


@pytest.mark.parametrize("dangling", [False, True])
def test_wait_retries_until_public_endpoint_is_available(tmp_path, monkeypatch, dangling):
    public = tmp_path / ("long-run-" + "x" * 110) / replay.SOCKET_NAME
    public.parent.mkdir()
    sleeps = []
    with tempfile.TemporaryDirectory(prefix="replay-peer-", dir="/tmp") as short:
        endpoint = Path(short) / replay.SOCKET_NAME
        if dangling:
            public.symlink_to(endpoint)
        server = FakeServer(endpoint, [])
        def publish(delay):
            sleeps.append(delay)
            server.start()
            if not dangling:
                public.symlink_to(endpoint)
        monkeypatch.setattr(replay.time, "sleep", publish)
        try:
            assert replay.wait_ready(public, timeout=5, interval=0.01)["state"] == "ready"
        finally:
            server.close()
        assert sleeps == [0.01]
        assert server.requests == [{"op": "status"}]


@pytest.mark.parametrize("kind", ["missing", "dangling", "loop"])
def test_unavailable_endpoint_does_not_allocate_a_socket(tmp_path, monkeypatch, kind):
    public = tmp_path / replay.SOCKET_NAME
    if kind == "dangling":
        public.symlink_to(tmp_path / "missing")
    elif kind == "loop":
        public.symlink_to(public)
    def unexpected_socket(*args, **kwargs):
        pytest.fail("unresolved endpoints must not allocate a socket")
    monkeypatch.setattr(replay.socket, "socket", unexpected_socket)
    with pytest.raises(replay.ReplayError, match="replay socket unavailable"):
        replay.status(public)


def test_failed_connect_closes_its_socket(tmp_path, monkeypatch):
    # An existing non-socket endpoint resolves but cannot accept a connection.
    public = tmp_path / replay.SOCKET_NAME
    public.touch()
    sockets = []
    socket_factory = socket.socket
    def tracked_socket(*args, **kwargs):
        connection = socket_factory(*args, **kwargs)
        sockets.append(connection)
        return connection
    monkeypatch.setattr(replay.socket, "socket", tracked_socket)
    with pytest.raises(replay.ReplayError, match="replay socket unavailable"):
        replay.status(public)
    assert len(sockets) == 1
    assert sockets[0].fileno() == -1


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


@pytest.mark.parametrize("patch_format,expression", [
    ("ERM generic", "rax != 0 && 10 / rax > 1"),
    ("ERM CWE-805", "(s->rax >= i->begin && s->rax < i->end) && (1 * s->rbx < i->end - i->begin)"),
])
def test_logical_replay_preserves_shared_safe_source(run_dir, tmp_path, patch_format, expression):
    base = make_dataset(tmp_path / "logical-dataset", patch_format=patch_format,
                        binradar_run=run_dir)
    cases = []
    for index, original in enumerate(base.cases("function"), 2):
        case = dict(original)
        case["id"] = f"function:{index}"
        case["observation"] = {"outcome": "normal"}
        case["capture"] = {**case["capture"], "outcome": {"outcome": "normal"}}
        cases.append(case)
    dataset = rewrite_cases(base, cases)
    candidate = parse_candidate(patch_format, expression)
    server = serve(run_dir, [rows() + [done()]], patch_format=patch_format)
    try:
        result = replay.evaluate_replay(dataset, candidate)
    finally:
        server.close()
    assert all(case["verified"] is False for case in result["cases"])
    assert evaluate_requests(server)[0]["patches"] == [
        {"id": 1, "predicate": candidate.source_predicate}]
    assert candidate.source_predicate == (f"({expression}) == 0"
                                           if patch_format == "ERM generic" else expression)


def test_busy_is_retried_without_losing_the_batch(run_dir, dataset):
    server = serve(run_dir, [
        [{"error": "busy"}],
        rows() + [done()],
    ], status_value={"state": "evaluating", "generation_stop": "exhausted",
                     "remaining_plans": 0, "retained_mutations": 2})
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
    assert result["ok"] is True
    private = context._results[result["result_id"]]
    assert private["verified"] is False
    assert len(private["cases"]) == 2
    assert "cases" not in result
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
    assert context._results[result["result_id"]]["verified"] is False
    assert "cases" not in result
    assert evaluate_requests(server)[0]["patches"] == [
        {"id": 1, "predicate": "(rax <= 0) == 0"}]
    # Projection, prompt, and the tool result carry no endpoint or cache path.
    for text in (context.initial_prompt(), json.dumps(result),
                 json.dumps(context.projection)):
        assert str(run_dir) not in text
        assert str(run_dir.parent / "cache") not in text


@pytest.mark.parametrize("through_tool", [False, True])
def test_offline_evaluation_never_contacts_configured_bridge(
        dataset, run_dir, tmp_path, monkeypatch, through_tool):
    monkeypatch.setattr(replay, "status", lambda *a, **k: pytest.fail("offline socket access"))
    monkeypatch.setattr(evaluation, "execute_capture",
                        lambda *a, **k: pytest.fail("offline target execution"))
    if through_tool:
        from taosc_llm.context import prepare_context
        context = prepare_context(dataset, run_dir=tmp_path / "run",
                                  replay_socket=run_dir / replay.SOCKET_NAME)
        result = context.call_tool("evaluate_predicate", {
            "context_id": context.context_id, "predicate": "1"})
        assert result["ok"] is True
        assert len(context._results[result["result_id"]]["cases"]) == 2
        assert "cases" not in result
    else:
        result = evaluation.evaluate_dataset(
            dataset, "1", execute=False, cache_dir=tmp_path / "cache",
            replay_socket=run_dir / replay.SOCKET_NAME)
        assert "replay" not in result
        assert len(result["cases"]) == 2


@pytest.mark.parametrize("selected", [None, ["function:3"], ["function:2", "function:3"]])
@pytest.mark.parametrize("target_crash", [False, True])
@pytest.mark.parametrize("predicate", ["0", "1"])
def test_nonretained_crashes_remain_selected_offline_evidence(
        dataset, run_dir, tmp_path, selected, target_crash, predicate):
    first, second = dataset.cases("function")
    crash = {"outcome": "crash", "fault_valid": True}
    if target_crash:
        first = {**first, "observation": crash,
                 "capture": {**first["capture"], "outcome": crash, "same_crash": True}}
    second = {**second, "observation": crash,
              "capture": {**second["capture"], "outcome": crash, "same_crash": False}}
    dataset = rewrite_cases(dataset, [first, second])
    server = serve(run_dir, [rows((2,)) + [done(1)]], mutations=1)
    try:
        result = evaluation.evaluate_dataset(
            dataset, predicate, case_ids=selected, cache_dir=tmp_path / "cache",
            replay_socket=run_dir / replay.SOCKET_NAME)
    finally:
        server.close()
    expected = selected or ["function:2", "function:3"]
    assert [case["case_id"] for case in result["cases"]] == expected
    by_id = {case["case_id"]: case for case in result["cases"]}
    if predicate == "0":
        assert by_id["function:3"]["source"] == "offline"
        assert by_id["function:3"]["status"] == "not_rejected"
    else:
        assert by_id["function:3"]["source"] == "unavailable"
        assert by_id["function:3"]["status"] == "unavailable"
        assert by_id["function:3"]["reason"] == "branch-divergence"
    assert result["summary"]["total"] == len(expected)
    assert result["replay"]["mutations"] == 1


def test_normal_and_target_crash_replay_but_other_crash_stays_offline(dataset, run_dir, tmp_path):
    normal, other = dataset.cases("function")
    crash = {"outcome": "crash", "fault_valid": True}
    other = {**other, "observation": crash,
             "capture": {**other["capture"], "outcome": crash, "same_crash": False}}
    target = {**normal, "id": "function:4", "observation": crash,
              "capture": {**normal["capture"], "outcome": crash, "same_crash": True}}
    dataset = rewrite_cases(dataset, [normal, other, target])
    server = serve(run_dir, [rows((2,)) + rows((4,), outcome="target-crash") + [done()]], mutations=2)
    try:
        result = evaluation.evaluate_dataset(
            dataset, "0", cache_dir=tmp_path / "cache",
            replay_socket=run_dir / replay.SOCKET_NAME)
    finally:
        server.close()
    assert [(case["case_id"], case["source"]) for case in result["cases"]] == [
        ("function:2", "executed"), ("function:3", "offline"), ("function:4", "executed")]
    assert result["summary"]["total"] == 3
    assert result["replay"]["mutations"] == 2


def test_zero_retained_keeps_offline_cases_and_empty_live_coverage(dataset, run_dir, tmp_path):
    cases = [{**case, "capture": {**case["capture"],
              "outcome": {"outcome": "crash"}, "same_crash": False}}
             for case in dataset.cases("function")]
    dataset = rewrite_cases(dataset, cases)
    server = serve(run_dir, [], mutations=0)
    try:
        result = evaluation.evaluate_dataset(
            dataset, "0", cache_dir=tmp_path / "cache",
            replay_socket=run_dir / replay.SOCKET_NAME)
    finally:
        server.close()
    assert evaluate_requests(server) == []
    assert result["replay"]["coverage"] == "empty"
    assert result["replay"]["mutations"] == 0
    assert result["summary"]["total"] == 2
    assert all(case["source"] == "offline" for case in result["cases"])


@pytest.mark.parametrize("mutations", [(2, 2), (2, 4), (2,), (2, 3, 4)])
def test_replay_requires_exact_retained_ids(dataset, run_dir, mutations):
    server = serve(run_dir, [rows(mutations) + [done(len(mutations))]])
    try:
        with pytest.raises(replay.ReplayError, match="mutation set"):
            replay.evaluate_replay(dataset, parse_candidate("ERM generic", "1"))
    finally:
        server.close()


def capture_row(dataset, run_dir, *, branches=(1, 1), selector=1,
                descriptor=None, reuse="fresh", mutation=2):
    from binradar import binradar_taosc_predicates as predicates
    import hashlib
    cwe = dataset.patch_format == "ERM CWE-805"
    if descriptor is None:
        descriptor = parse_candidate(dataset.patch_format,
            "s->rbx >= i->begin && s->rbx < i->end" if cwe else "rax < 0").descriptor
    payload = b"".join(
        predicates.CACHED_SNAPSHOT_HEADER.pack(
            predicates.CACHED_SNAPSHOT_MAGIC, 1, selector, branch, 0, 2 if cwe else 0)
        + ((100).to_bytes(8, "little") + (200).to_bytes(8, "little")
           + b"\0" * (predicates.CACHED_SNAPSHOT_CLAMPS.size - 16) if cwe else b"")
        + predicates.CACHED_SNAPSHOT_REGS.pack(150 if cwe else (1 << 64) - 3, *([0] * 15))
        for branch in branches)
    directory = run_dir / "replay"
    directory.mkdir(exist_ok=True)
    path = directory / f"capture-{mutation}.brch"
    path.write_bytes(payload)
    return {"mutation": mutation, "patch": 1,
            "source": "executed" if reuse == "fresh" else "cache",
            "outcome": "normal", "reason": None,
            "capture": {"mutation": mutation, "path": str(path),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "descriptor": descriptor, "patch_id": selector, "reuse": reuse}}


@pytest.mark.parametrize("patch_format", ["ERM generic", "ERM CWE-805"])
@pytest.mark.parametrize("reuse", ["fresh", "exact-descriptor", "full-vector-equivalent"])
def test_complete_replay_capture_is_available_to_standard_state_reader(
        tmp_path, run_dir, patch_format, reuse):
    dataset = make_dataset(tmp_path / "states", patch_format=patch_format, binradar_run=run_dir)
    candidate = parse_candidate(patch_format,
        "s->rbx >= i->begin && s->rbx < i->end" if patch_format == "ERM CWE-805" else "rax < 0")
    row = capture_row(dataset, run_dir, reuse=reuse, descriptor=candidate.descriptor)
    result = replay._case_result(dataset, row, candidate)
    assert result["branches"] == [1, 1]
    assert result["capture"]["artifact_sha256"] == dataset.manifest["artifacts"]["fixture.brcached"]["sha256"]
    states = evaluation._snapshots(dataset, result["capture"])
    assert len(states) == 2 and all(state.patch_id == 1 for state in states)
    assert result["reuse"] == reuse


@pytest.mark.parametrize("patch_format", ["ERM generic", "ERM CWE-805"])
def test_vector_reuse_keeps_neutral_descriptor_and_original_selector(tmp_path, run_dir, patch_format):
    dataset = make_dataset(tmp_path / "states", patch_format=patch_format, binradar_run=run_dir)
    candidate = parse_candidate(patch_format,
        "s->rax >= i->begin && s->rax < i->end" if patch_format == "ERM CWE-805" else "rax > 0")
    row = capture_row(dataset, run_dir, branches=(0, 0), selector=0,
                      descriptor="p0", reuse="full-vector-equivalent")
    result = replay._case_result(dataset, row, candidate)
    assert result["capture"]["descriptor"] == "p0"
    assert result["capture"]["patch_id"] == 0
    assert result["branches"] == [0, 0]
    assert all(state.patch_id == 0 for state in evaluation._snapshots(dataset, result["capture"]))


@pytest.mark.parametrize("failure", ["mutation", "selector", "hash", "path", "symlink", "descriptor", "trap", "candidate"])
def test_replay_capture_identity_failures_cannot_become_success(dataset, run_dir, tmp_path, failure):
    candidate = parse_candidate("ERM generic", "rax < 0")
    row = capture_row(dataset, run_dir,
                      branches=(1, 2) if failure == "trap" else (1, 1))
    if failure == "mutation":
        row["capture"]["mutation"] = 3
    elif failure == "selector":
        row["capture"]["patch_id"] = 0
    elif failure == "hash":
        row["capture"]["sha256"] = "0" * 64
    elif failure == "path":
        outside = tmp_path / "outside.brch"
        outside.write_bytes(Path(row["capture"]["path"]).read_bytes())
        row["capture"]["path"] = str(outside)
    elif failure == "symlink":
        original = Path(row["capture"]["path"])
        target = original.with_name("real-capture.brch")
        original.rename(target)
        original.symlink_to(target)
    elif failure == "descriptor":
        row["capture"]["descriptor"] = "p0"
    elif failure == "candidate":
        candidate = parse_candidate("ERM generic", "rax > 0")
    with pytest.raises(replay.ReplayError):
        replay._case_result(dataset, row, candidate)


def test_replay_authenticates_frozen_artifact_before_contact(dataset, monkeypatch):
    dataset.artifact("fixture.brcached").write_bytes(b"changed artifact")
    monkeypatch.setattr(replay, "status", lambda *a, **k: pytest.fail("unauthenticated replay contact"))
    with pytest.raises(ValueError, match="hash mismatch"):
        replay.evaluate_replay(dataset, parse_candidate("ERM generic", "rax < 0"))


def test_unknown_replay_activity_is_not_a_zero_hit_vector(dataset):
    result = replay._case_result(dataset,
        {"mutation": 2, "source": "executed", "outcome": "unavailable",
         "reason": "unsupported-external-state", "capture": None},
        parse_candidate("ERM generic", "rax < 0"))
    assert result["branches"] is None and result["capture"] is None
    assert result["status"] == "unavailable"



def test_host_cache_dir_is_shared_by_tool_and_cli(dataset, run_dir, tmp_path):
    from taosc_llm.context import prepare_context
    shared = tmp_path / "shared-cache"
    context = prepare_context(dataset, run_dir=tmp_path / "run",
                              cache_dir=shared)
    assert context.cache_dir == shared
    assert context.replay_socket is None
    assert str(shared) not in context.initial_prompt()
