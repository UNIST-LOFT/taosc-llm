"""Provider-free search session ownership and final artifact publication."""
from __future__ import annotations

import asyncio
import os
from pathlib import Path

from ..dataset import load_dataset, sha256
from .backend import Backend, session_identity
from .engine import SearchEngine
from .journal import Journal, _directory
from .model import SearchLimits, SearchStopped


async def _build(backend, operation):
    task = asyncio.create_task(operation)
    try:
        while not task.done():
            backend.check_cancelled()
            await asyncio.wait({task}, timeout=0.1)
        backend.check_cancelled()
        return await task
    except BaseException:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        raise


def _durable_build(build, root):
    for path in build["artifacts"].values():
        with Path(path).open("rb") as stream:
            os.fsync(stream.fileno())
    directories = set()
    for path in build["artifacts"].values():
        directory = Path(path).parent
        while directory != root:
            if root not in directory.parents:
                raise ValueError("candidate artifact escapes journal")
            directories.add(directory)
            directory = directory.parent
    directories.add(root)
    for directory in sorted(directories, key=lambda path: len(path.parts), reverse=True):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _existing_publication(journal, predicate):
    for event in reversed(journal.events):
        if event["kind"] != "publication" or event["data"]["predicate"] != predicate:
            continue
        record = journal.load(event["data"]["record"])
        for name, digest in record["build"]["artifact_hashes"].items():
            path = Path(record["build"]["artifacts"][name])
            if (path.resolve() != path or journal.directory not in path.parents
                    or not path.is_file() or sha256(path) != digest):
                raise ValueError("published candidate artifact changed")
        return record
    return None


def synthesize(dataset, *, output: Path, limits: SearchLimits | None = None,
               execution_workers: int = 1, cache_dir: Path | None = None,
               replay_socket: Path | None = None, resume: bool = False, cancelled=None) -> dict:
    """Synthesize without a model; no signal handlers or global cwd changes.

    Search budgets persist across resumes. A completed result remains empirical
    branch-selection evidence and never acquires a BinRadar FINAL verdict.
    """
    dataset = load_dataset(dataset) if isinstance(dataset, (str, Path)) else dataset
    limits = limits or SearchLimits()
    identity = session_identity(dataset, limits, workers=execution_workers, replay_socket=replay_socket)
    with Journal(Path(output), identity, resume=resume) as journal:
        backend = Backend(dataset, journal, limits, workers=execution_workers,
                          cache_dir=cache_dir, replay_socket=replay_socket, cancelled=cancelled)
        engine = None
        try:
            # Restoring an incumbent is read-only authentication, not renewed
            # search admission. Publication can legitimately finish after the
            # search deadline; its completed evidence must survive resume.
            with backend.restoration():
                engine = SearchEngine(backend)
            result = engine.run()
            backend.check_cancelled()
            if result["predicate"] is not None and result["termination"] != "interrupted":
                publication = _existing_publication(journal, result["predicate"])
                if publication is None:
                    from ..publication import build_candidate, verify_built_candidate
                    backend.checkpoint_budget()
                    parent = journal.directory / "candidates" / f"candidate-{len(journal.events):08d}"
                    descriptor = _directory(parent, create=True)
                    os.close(descriptor)
                    directory = parent / "build-workdir"
                    build = asyncio.run(_build(backend, build_candidate(dataset, result["predicate"], directory)))
                    verification = verify_built_candidate(dataset, build, engine.current, workers=execution_workers)
                    backend.check_cancelled()
                    _durable_build(build, journal.directory)
                    publication = {"build": build, "artifact_execution": verification}
                    reference = journal.store(publication)
                    kind = "publication" if verification["status"] == "matched" else "publication_incomplete"
                    journal.append(kind, {"predicate": result["predicate"], "record": reference})
                result.update(publication)
                result["publication_status"] = publication["artifact_execution"]["status"]
        except (SearchStopped, KeyboardInterrupt) as stop:
            reason = "interrupted" if isinstance(stop, KeyboardInterrupt) else stop.reason
            if engine is not None:
                result = engine.result()
                result["termination"] = reason
            else:
                result = {"schema_version": 1, "engine": "taosc-llm-no-llm",
                          "dataset_id": dataset.dataset_id, "predicate": None, "clauses": [],
                          "termination": reason, "coverage": "partial", "verified": False,
                          "binradar_verification": "not_run", "run_directory": str(journal.directory)}
            journal.append("stopped", {"reason": reason})
        except BaseException as error:
            try:
                journal.append("failed", {"error_type": type(error).__name__})
                backend.checkpoint_budget()
            except (OSError, ValueError, RuntimeError) as journal_error:
                raise error from journal_error
            raise
        backend.checkpoint_budget()
        result["budgets"] = {"elapsed": backend.elapsed, "evaluations": backend.evaluations}
        result["limits"] = limits.to_dict()
        result["coverage"] = result.get("score", {}).get("coverage", "partial")
        reference = journal.store(result)
        journal.append("result", {"result": reference})
        journal.append("session_closed", {})
        return {**result, "result_record": str(journal.directory / reference["path"])}
