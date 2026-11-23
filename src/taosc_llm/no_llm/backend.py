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
        "publication.py", "native.py", "collection_metrics.py")]
    return {"schema_version": 1, "engine": "taosc-llm-no-llm",
            "final_admission_policy": "reject-known-predicate-traps-v1",
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
        No working draft is promoted. Cancellation and complete capture
        validation still apply.
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

    def _validate_result(self, dataset, result, *, snapshots=None):
        """Authenticate every report/vector, optionally collecting prediction states."""
        from ..evidence import _project_case
        from ..poc import poc_case
        descriptor = result["descriptor"]
        if (result["dataset_id"] != dataset.dataset_id
                or (descriptor == "p0" and result["predicate"] is not None)
                or (descriptor != "p0" and parse_candidate(dataset.patch_format, result["predicate"]).descriptor != descriptor)):
            raise ValueError("journal evaluation identity mismatch")
        metadata = evaluation._capture_metadata(dataset)
        poc = poc_case(dataset)
        active = self.population.active if snapshots is not None and self.population is not None else None
        seen = set()
        for item in result["cases"]:
            self.check_operation()
            identifier = item["case_id"]
            if identifier in seen or item["descriptor"] != descriptor:
                raise ValueError("journal case predicate identity mismatch")
            seen.add(identifier)
            case = poc if poc is not None and identifier == poc["id"] else dataset.case(identifier)
            if "original_observation" in item:
                case = {**case, "observation": item["original_observation"]["outcome"]}
            if item["report"] != _project_case(dataset, case, item, metadata=metadata, descriptor=descriptor):
                raise ValueError("journal case report mismatch")
            selected = None
            for record in (item, item.get("neutral_baseline", {})):
                capture = record.get("capture")
                if capture and capture.get("complete") is True:
                    states = evaluation._validated_snapshots(dataset, capture, metadata)
                    actual, representative = capture["branches"], capture["descriptor"]
                    if evaluation._vector(representative, states, dataset=dataset) != actual:
                        raise ValueError("journal representative evaluator mismatch")
                    if ((record.get("status") != "unavailable" or record.get("branches") is not None)
                            and record.get("branches") != actual):
                        raise ValueError("journal observed vector mismatch")
                    if (record.get("status") != "unavailable" and record["descriptor"] != representative
                            and evaluation._vector(record["descriptor"], states, dataset=dataset) != actual):
                        raise ValueError("journal candidate vector mismatch")
                    # A complete candidate capture wins even when it has zero hits.
                    if selected is None:
                        selected = states
                reference = record.get("offline_reference")
                if reference and reference.get("complete") is True:
                    states = evaluation._validated_snapshots(dataset, reference, metadata)
                    actual, representative = reference["branches"], reference["descriptor"]
                    if evaluation._vector(representative, states, dataset=dataset) != actual:
                        raise ValueError("journal offline representative evaluator mismatch")
                    if record["descriptor"] == representative:
                        predicted, divergence = actual, None
                    else:
                        predicted = evaluation._vector(record["descriptor"], states, dataset=dataset)
                        divergence = next((index for index, (a, b) in enumerate(zip(predicted, actual))
                                           if a != b), None)
                    if (record.get("offline_branches") != predicted
                            or record.get("first_divergence") != divergence):
                        raise ValueError("journal offline vector mismatch")
            if snapshots is not None and selected and (active is None or identifier in active):
                snapshots[identifier] = selected
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

    def evaluate(self, source: str) -> tuple[dict, dict]:
        candidate = parse_candidate(self.dataset.patch_format, source)
        if candidate.descriptor in self.result_refs:
            reference = self.result_refs[candidate.descriptor]
            result = self.load(reference)
            if result["descriptor"] != candidate.descriptor:
                raise ValueError("journal evaluation identity mismatch")
            return result, reference.copy()
        self.check()
        with self.dataset.validation(check=self.check_operation) as dataset:
            if self.socket is not None:
                self._connect_policy()
            self.admit_evaluation()
            result = evaluation._evaluate(dataset, candidate, candidate.descriptor,
                                          case_ids=None, workers=self.workers, execute=True,
                                          cache_dir=self.cache_dir, replay_socket=self.socket,
                                          operation_check=self.check_operation)
            result = self._preserve(result, dataset)
            reference = self.journal.store(result)
            self.check_operation()
            self.journal.append("evaluation", {"descriptor": candidate.descriptor, "result": reference})
            self.result_refs[candidate.descriptor] = reference
        self.checkpoint_budget()
        return result, reference.copy()

    def load_snapshots(self, reference):
        """Load and authenticate a saved result, returning only prediction states."""
        self.check_operation()
        return self.snapshots(self.journal.load(reference))

    def snapshots(self, result):
        output = {}
        with self.dataset.validation(check=self.check_operation) as dataset:
            self._validate_result(dataset, result, snapshots=output)
        return output
