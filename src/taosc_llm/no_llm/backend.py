"""Authenticated execution adapter; no model, prompt, or provider state."""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import time

from .. import evaluation
from ..dataset import PreparedDataset, sha256
from ..execution import execution_identity
from ..family import parse_candidate
from .model import SearchLimits, SearchStopped


def session_identity(dataset: PreparedDataset, limits: SearchLimits, *, workers: int,
                     replay_socket: Path | None) -> dict:
    dataset.verify_artifacts()
    sources = Path(__file__).parent
    implementation = sorted(sources.glob("*.py")) + [sources.parent / name for name in (
        "dataset.py", "evaluation.py", "evidence.py", "family.py", "poc.py", "replay.py",
        "builder.py", "publication.py", "native.py", "runtime.c")]
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
        self.executions_reserved = 0
        self.result_refs = {}
        self.baseline_ref = None
        self.population = None
        self._bound_socket = None
        unsettled_since = None
        for event in journal.events:
            data = event["data"]
            if event["kind"] == "budget":
                self.spent = max(self.spent, data["elapsed"])
                self.evaluations = max(self.evaluations, data["evaluations"])
                self.executions_reserved = max(self.executions_reserved, data["executions_reserved"])
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
                                       "executions_reserved": self.executions_reserved,
                                       "wall_time": time.time()})

    def check_cancelled(self):
        if self.cancelled is not None and self.cancelled.is_set():
            raise SearchStopped("interrupted")

    def check(self):
        self.check_cancelled()
        if self.elapsed >= self.limits.timeout:
            raise SearchStopped("wall-time-reached")
        if self.evaluations >= self.limits.max_evaluations:
            raise SearchStopped("evaluation-budget-reached")

    def reserve(self, maximum_executions: int):
        self.check()
        if self.executions_reserved + maximum_executions > self.limits.max_executions:
            raise SearchStopped("execution-budget-reached")
        self.evaluations += 1
        self.executions_reserved += maximum_executions
        # Charge the whole bounded operation before admitting any target work.
        self.checkpoint_budget()

    def _preserve(self, result):
        result = copy.deepcopy(result)
        def visit(value):
            if isinstance(value, dict):
                if value.get("complete") is True and all(k in value for k in ("path", "sha256", "descriptor", "artifact_sha256")):
                    evaluation._snapshots(self.dataset, value)
                    path = Path(value["path"])
                    if not path.is_absolute():
                        path = self.dataset.root / path
                    raw = path.read_bytes()
                    if hashlib.sha256(raw).hexdigest() != value["sha256"]:
                        raise ValueError("capture changed during journal publication")
                    ref = self.journal.store_bytes(raw, suffix=".brch")
                    value["path"] = str(self.journal.directory / ref["path"])
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)
        visit(result)
        return result

    def load(self, reference):
        result = self.journal.load(reference)
        self.dataset.verify_artifacts()
        for item in result["cases"]:
            for record in (item, item.get("neutral_baseline", {})):
                capture = record.get("capture")
                if capture and capture.get("complete") is True:
                    states = evaluation._snapshots(self.dataset, capture)
                    if evaluation._vector(capture["descriptor"], states) != capture["branches"]:
                        raise ValueError("journal representative evaluator mismatch")
                    if (record.get("status") != "unavailable"
                            and evaluation._vector(record["descriptor"], states) != capture["branches"]):
                        raise ValueError("journal candidate vector mismatch")
        return result

    def baseline(self):
        if self.baseline_ref is not None:
            return self.load(self.baseline_ref)
        from ..poc import poc_case
        from ..execution import execute_original
        from ..evidence import _project_case
        cases = {case["id"]: case for case in self.dataset.cases()}
        poc = poc_case(self.dataset)
        if poc is not None:
            cases.setdefault(poc["id"], poc)
        missing = [case for case in cases.values()
                   if case["domain"] == "system" and not case.get("observation")]
        self.reserve(sum(case["domain"] == "system" for case in cases.values()) + len(missing))
        with self.dataset.validation() as dataset:
            originals = {}
            for case in missing:
                record = execute_original(dataset, case, self.cache_dir / "originals")
                if record["artifact_sha256"] != dataset.manifest["artifacts"][dataset.binary + ".orig"]["sha256"]:
                    raise ValueError("original baseline artifact mismatch")
                originals[case["id"]] = record
            result = evaluation._evaluate(dataset, None, "p0", case_ids=None, workers=self.workers,
                                          execute=True, cache_dir=self.cache_dir)
            for item in result["cases"]:
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
        self.check_cancelled()
        result = self._preserve(result)
        self.baseline_ref = self.journal.store(result)
        self.journal.append("baseline", {"result": self.baseline_ref})
        self.checkpoint_budget()
        return result

    def evaluate(self, source: str):
        candidate = parse_candidate(self.dataset.patch_format, source)
        if candidate.descriptor in self.result_refs:
            return self.load(self.result_refs[candidate.descriptor])
        ids = sorted(self.population.active) if self.population is not None else None
        count = len(ids) if ids is not None else len(self.dataset.cases()) + 1
        # A bridge evaluates its whole retained function inventory before the
        # existing API filters rows. Reserve that population as well.
        if self.socket is not None:
            self._connect_policy()
            count = max(count, len(self.dataset.cases()))
        self.reserve(2 * count)
        from ..poc import poc_case
        poc = poc_case(self.dataset)
        include_poc = poc is not None and (ids is None or poc["id"] in ids)
        result = evaluation.evaluate_dataset(self.dataset, source, case_ids=ids, workers=self.workers,
                                             execute=True, cache_dir=self.cache_dir,
                                             replay_socket=self.socket, include_poc=include_poc)
        self.check_cancelled()
        result = self._preserve(result)
        reference = self.journal.store(result)
        self.journal.append("evaluation", {"descriptor": candidate.descriptor, "result": reference})
        self.result_refs[candidate.descriptor] = reference
        self.checkpoint_budget()
        return result

    def snapshots(self, result):
        output = {}
        for item in result["cases"]:
            if self.population is not None and item["case_id"] not in self.population.active:
                continue
            capture = item.get("capture")
            if not capture or capture.get("complete") is not True:
                capture = item.get("neutral_baseline", {}).get("capture")
            if capture and capture.get("complete") is True:
                states = evaluation._snapshots(self.dataset, capture)
                if states:
                    output[item["case_id"]] = states
        return output
