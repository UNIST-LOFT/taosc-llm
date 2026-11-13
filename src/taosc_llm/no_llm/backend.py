"""Authenticated execution adapter; no model, prompt, or provider state."""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import time

from .. import evaluation
from ..dataset import PreparedDataset, canonical, sha256
from ..execution import execution_identity
from ..family import parse_candidate
from .model import SearchLimits, SearchStopped


def session_identity(dataset: PreparedDataset, limits: SearchLimits, *, workers: int,
                     replay_socket: Path | None) -> dict:
    dataset.verify_artifacts()
    sources = Path(__file__).parent
    implementation = sorted(sources.glob("*.py")) + [sources.parent / name for name in (
        "dataset.py", "evaluation.py", "evidence.py", "family.py", "poc.py", "replay.py",
        "publication.py", "native.py")]
    return {"schema_version": 1, "engine": "taosc-llm-no-llm",
            "dataset_id": dataset.dataset_id, "manifest": dataset.manifest,
            "environment": dataset.execution_environment(), "runtime": execution_identity(),
            "implementation": {str(path.relative_to(sources.parent)): sha256(path)
                               for path in implementation},
            "limits": limits.to_dict(), "workers": workers,
            "replay_socket": str(Path(replay_socket).absolute()) if replay_socket is not None else None}


class Backend:
    def __init__(self, dataset, journal, limits, *, workers=1, cache_dir=None, replay_socket=None, cancelled=None):
        if type(workers) is not int or not 1 <= workers <= 32:
            raise ValueError("execution workers must be in 1..32")
        self.dataset, self.journal, self.limits = dataset, journal, limits
        self.workers = workers
        self.cancelled = cancelled
        self.cache_dir = Path(cache_dir) if cache_dir is not None else journal.directory / "cache"
        self.socket = Path(replay_socket).absolute() if replay_socket is not None else None
        self.started = time.monotonic()
        self.spent = 0.0
        self.evaluations = 0
        self.result_refs = {}
        self.baseline_ref = None
        self.population = None
        self._restoring = False
        self._bound_socket = None
        unsettled_since = None
        for event in journal.events:
            data = event["data"]
            if event["kind"] == "budget":
                self.spent = max(self.spent, data["elapsed"])
                self.evaluations = max(self.evaluations, data["evaluations"])
                unsettled_since = data["wall_time"]
            elif event["kind"] == "session_closed":
                unsettled_since = None
            elif event["kind"] == "evaluation":
                self.result_refs[data["descriptor"]] = data["result"]
            elif event["kind"] == "baseline":
                self.baseline_ref = data["result"]
            elif event["kind"] == "replay_bound":
                self._bound_socket = data
        if unsettled_since is not None:
            # SIGKILL cannot report its exact stop time. Charge the unclosed
            # interval (including downtime) rather than replenish its budget.
            self.spent += max(0.0, time.time() - unsettled_since)
        self.checkpoint_budget()
        self._connect_policy()

    def _connect_policy(self):
        if self.socket is None:
            return
        from ..replay import dataset_socket
        expected = dataset_socket(self.dataset)
        if self.socket.resolve() != expected.resolve():
            raise ValueError("replay endpoint does not belong to this dataset")
        try:
            real = self.socket.resolve(strict=True)
            info = real.stat()
        except FileNotFoundError:
            self.socket = None
            self.journal.append("replay_unavailable", {"reason": "endpoint-missing"})
            return
        bound = {"path": str(real), "device": info.st_dev, "inode": info.st_ino}
        if self._bound_socket is not None and self._bound_socket != bound:
            raise ValueError("replay endpoint replaced; old mutation IDs cannot be rebound")
        if self._bound_socket is None:
            self.journal.append("replay_bound", bound)
            self._bound_socket = bound

    @property
    def elapsed(self):
        return self.spent + time.monotonic() - self.started

    def checkpoint_budget(self):
        self.journal.append("budget", {"elapsed": self.elapsed, "evaluations": self.evaluations,
                                       "wall_time": time.time()})

    def check_cancelled(self):
        if self.cancelled is not None and self.cancelled.is_set():
            raise SearchStopped("interrupted")

    @contextmanager
    def restoration(self):
        """Authenticate saved evidence even when finalization exhausted time.

        This permits no new evaluation admission and never replenishes a budget.
        The engine may re-gate and commit an already fully evaluated draft at a
        budget boundary. Cancellation and complete capture validation still apply.
        """
        previous = self._restoring
        self._restoring = self.baseline_ref is not None
        try:
            yield
        finally:
            self._restoring = previous

    def check_operation(self):
        """Bound admitted work without rejecting the final allowed evaluation."""
        self.check_cancelled()
        if not self._restoring and self.elapsed >= self.limits.timeout:
            raise SearchStopped("wall-time-reached")

    def check(self):
        self.check_cancelled()
        # Read-only restoration must never admit new work past the deadline.
        if self.elapsed >= self.limits.timeout:
            raise SearchStopped("wall-time-reached")
        if self.evaluations >= self.limits.max_evaluations:
            raise SearchStopped("evaluation-budget-reached")

    def admit_evaluation(self):
        self.check()
        self.evaluations += 1
        self.checkpoint_budget()

    def _preserve(self, result, dataset):
        # Identity authentication and content storage have different keys. Equal
        # bytes never excuse a different selector/descriptor/provenance binding.
        captures, objects, stored = {}, {}, {}

        def visit(value):
            self.check_operation()
            if isinstance(value, dict):
                if value.get("complete") is True and all(k in value for k in
                        ("path", "sha256", "descriptor", "artifact_sha256")):
                    if id(value) in objects:
                        return objects[id(value)]
                    key = canonical(value)
                    if key not in captures:
                        raw = dataset.capture_bytes(value)
                        self.check_operation()
                        digest = value["sha256"]
                        if digest not in stored:
                            stored[digest] = self.journal.store_bytes(raw, suffix=".brch")
                        captures[key] = str(self.journal.directory / stored[digest]["path"])
                    preserved = {**value, "path": captures[key]}
                    objects[id(value)] = preserved
                    return preserved
                children = {key: (visit(child) if key not in ("branches", "offline_branches")
                                  and isinstance(child, (dict, list)) else child)
                            for key, child in value.items()}
                return children if any(children[key] is not child for key, child in value.items()) else value
            if isinstance(value, list):
                children = [visit(child) if isinstance(child, (dict, list)) else child for child in value]
                return children if any(a is not b for a, b in zip(children, value)) else value
            return value

        preserved = visit(result)
        self.check_operation()
        return preserved

    def _validate_result(self, dataset, result):
        """Retain all actual, representative and offline full-vector mirrors."""
        for item in result["cases"]:
            self.check_operation()
            for record in (item, item.get("neutral_baseline", {})):
                capture = record.get("capture")
                if capture and capture.get("complete") is True:
                    states = evaluation._snapshots(dataset, capture)
                    actual = capture["branches"]
                    if evaluation._vector(capture["descriptor"], states, dataset=dataset) != actual:
                        raise ValueError("journal representative evaluator mismatch")
                    if ((record.get("status") != "unavailable" or record.get("branches") is not None)
                            and record.get("branches") != actual):
                        raise ValueError("journal observed vector mismatch")
                    if (record.get("status") != "unavailable"
                            and evaluation._vector(record["descriptor"], states, dataset=dataset) != actual):
                        raise ValueError("journal candidate vector mismatch")
                reference = record.get("offline_reference")
                if reference and reference.get("complete") is True:
                    states = evaluation._snapshots(dataset, reference)
                    actual = reference["branches"]
                    if evaluation._vector(reference["descriptor"], states, dataset=dataset) != actual:
                        raise ValueError("journal offline representative evaluator mismatch")
                    predicted = evaluation._vector(record["descriptor"], states, dataset=dataset)
                    divergence = next((index for index, (a, b) in enumerate(zip(predicted, actual))
                                       if a != b), None)
                    if (record.get("offline_branches") != predicted
                            or record.get("first_divergence") != divergence):
                        raise ValueError("journal offline vector mismatch")
        self.check_operation()

    def load(self, reference):
        self.check_operation()
        result = self.journal.load(reference)
        with self.dataset.validation(check=self.check_operation) as dataset:
            self._validate_result(dataset, result)
        return result

    def baseline(self):
        if self.baseline_ref is not None:
            return self.load(self.baseline_ref)
        from ..poc import poc_case
        from ..execution import execute_original
        from ..evidence import _project_case
        self.check()
        with self.dataset.validation(check=self.check_operation) as dataset:
            cases = {case["id"]: case for case in dataset.cases()}
            poc = poc_case(dataset)
            if poc is not None:
                cases.setdefault(poc["id"], poc)
            missing = [case for case in cases.values()
                       if case["domain"] == "system" and not case.get("observation")]
            self.admit_evaluation()
            originals = {}
            for case in missing:
                self.check_operation()
                record = execute_original(dataset, case, self.cache_dir / "originals")
                if record["artifact_sha256"] != dataset.manifest["artifacts"][dataset.binary + ".orig"]["sha256"]:
                    raise ValueError("original baseline artifact mismatch")
                originals[case["id"]] = record
            result = evaluation._evaluate(dataset, None, "p0", case_ids=None, workers=self.workers,
                                          execute=True, cache_dir=self.cache_dir,
                                          operation_check=self.check_operation)
            for item in result["cases"]:
                self.check_operation()
                case = cases[item["case_id"]]
                if case["id"] in originals:
                    record = originals[case["id"]]
                    case = {**case, "observation": record["outcome"]}
                    item["report"] = _project_case(dataset, case, item, descriptor="p0")
                    item["original_observation"] = record
                    hits = record.get("patch_hits")
                else:
                    hits = (case.get("observation") or {}).get("patch-hit")
                if type(hits) is int:
                    item["original_patch_hits"] = hits
            result = self._preserve(result, dataset)
            reference = self.journal.store(result)
            self.check_operation()
            self.journal.append("baseline", {"result": reference})
            self.baseline_ref = reference
        self.checkpoint_budget()
        return result

    def evaluate(self, source: str):
        candidate = parse_candidate(self.dataset.patch_format, source)
        if candidate.descriptor in self.result_refs:
            return self.load(self.result_refs[candidate.descriptor])
        self.check()
        ids = sorted(self.population.active) if self.population is not None else None
        with self.dataset.validation(check=self.check_operation) as dataset:
            if self.socket is not None:
                self._connect_policy()
            self.admit_evaluation()
            from ..poc import poc_case
            poc = poc_case(dataset)
            include_poc = poc is not None and (ids is None or poc["id"] in ids)
            result = evaluation._evaluate(dataset, candidate, candidate.descriptor,
                                          case_ids=ids, workers=self.workers, execute=True,
                                          cache_dir=self.cache_dir, replay_socket=self.socket,
                                          include_poc=include_poc,
                                          operation_check=self.check_operation)
            result = self._preserve(result, dataset)
            reference = self.journal.store(result)
            self.check_operation()
            self.journal.append("evaluation", {"descriptor": candidate.descriptor, "result": reference})
            self.result_refs[candidate.descriptor] = reference
        self.checkpoint_budget()
        return result

    def snapshots(self, result):
        output = {}
        active = self.population.active if self.population is not None else None
        with self.dataset.validation(check=self.check_operation) as dataset:
            self._validate_result(dataset, result)
            for item in result["cases"]:
                self.check_operation()
                if active is not None and item["case_id"] not in active:
                    continue
                capture = item.get("capture")
                if not capture or capture.get("complete") is not True:
                    capture = item.get("neutral_baseline", {}).get("capture")
                if capture and capture.get("complete") is True:
                    states = evaluation._snapshots(dataset, capture)
                    if states:
                        output[item["case_id"]] = states
        return output
