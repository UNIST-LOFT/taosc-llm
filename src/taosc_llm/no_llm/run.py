"""Provider-free search session ownership and final artifact publication."""
from __future__ import annotations

from pathlib import Path

from ..dataset import load_dataset
from ..publication import publish_candidate, validate_publication
from .backend import Backend, session_identity
from .engine import SearchEngine
from .journal import Journal
from .model import SearchLimits, SearchStopped


def _existing_publication(journal, dataset, predicate, *, check=None):
    for event in reversed(journal.events):
        if event["kind"] != "publication" or event["data"]["predicate"] != predicate:
            continue
        record = journal.load(event["data"]["record"])
        validate_publication(dataset, record['candidate'], predicate, check=check)
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
                publication = _existing_publication(journal, dataset, result["predicate"],
                                                    check=backend.check_cancelled)
                if publication is None:
                    backend.checkpoint_budget()
                    with backend.restoration():
                        selected = backend.load(result["evaluation"])
                    if (selected['dataset_id'] != dataset.dataset_id
                            or selected['predicate'] != result['predicate']):
                        raise ValueError('selected evaluation identity mismatch')
                    candidate = publish_candidate(dataset, result["predicate"], check=backend.check_cancelled)
                    backend.check_cancelled()
                    publication = {"candidate": candidate}
                    reference = journal.store(publication)
                    journal.append("publication", {"predicate": result["predicate"], "record": reference})
                result.update(publication)
                result["publication_status"] = publication["candidate"]["status"]
        except (SearchStopped, KeyboardInterrupt) as stop:
            reason = "interrupted" if isinstance(stop, KeyboardInterrupt) else stop.reason
            if engine is not None:
                result = engine.result(interrupted=reason == "interrupted")
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
