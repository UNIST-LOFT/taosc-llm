"""The taosc-llm-no-llm entrypoint; intentionally no provider options."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import sys
from threading import Event, Thread

from .model import SearchLimits


@contextmanager
def _diagnostics():
    sys.stdout.flush()
    saved = os.dup(1)
    try:
        os.dup2(2, 1)
        yield
    finally:
        sys.stdout.flush()
        os.dup2(saved, 1)
        os.close(saved)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="taosc-llm-no-llm",
        description="Bounded ERM branch-selection synthesis without a model; not FINAL verification.")
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="private result directory; existing sessions require --resume")
    parser.add_argument("--resume", action="store_true", help="resume this identity-bound append-only search journal")
    parser.add_argument("--execution-workers", type=int, default=1)
    parser.add_argument("--cache-dir", type=Path)
    parser.add_argument("--replay-socket", type=Path, help="explicit endpoint of the dataset's existing mutation server")
    defaults = SearchLimits()
    parser.add_argument("--timeout", type=float, default=defaults.timeout, help="persistent search-time budget in seconds")
    for name in ("max_evaluations", "max_atoms", "beam_width", "max_clauses", "max_factors", "operand_depth"):
        parser.add_argument("--" + name.replace("_", "-"), type=int, default=getattr(defaults, name))
    args = parser.parse_args(argv)
    try:
        limits = SearchLimits(**{name: getattr(args, name) for name in defaults.to_dict()})
        if not 1 <= args.execution_workers <= 32:
            raise ValueError("execution workers must be in 1..32")
    except ValueError as error:
        parser.error(str(error))

    cancelled, wake = Event(), Event()
    def interrupt(signum, frame):
        # Never raise through a journal write/fsync or re-enter registry locks.
        cancelled.set()
        wake.set()

    def drain():
        wake.wait()
        if cancelled.is_set():
            from binradar.binradar_runtime import PROCESS_REGISTRY
            PROCESS_REGISTRY.stop_all()

    watcher = Thread(target=drain, name="search-cancellation", daemon=True)
    previous = {number: signal.signal(number, interrupt) for number in (signal.SIGINT, signal.SIGTERM)}
    watcher.start()
    try:
        from .run import synthesize
        with _diagnostics():
            result = synthesize(args.dataset, output=args.output, limits=limits,
                                execution_workers=args.execution_workers, cache_dir=args.cache_dir,
                                replay_socket=args.replay_socket, resume=args.resume, cancelled=cancelled)
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        if result["termination"] == "interrupted":
            return 130
        return 0
    except KeyboardInterrupt:
        print("taosc-llm-no-llm: interrupted before search admission", file=sys.stderr)
        return 130
    except (ValueError, OSError, RuntimeError) as error:
        print(f"taosc-llm-no-llm: {error}", file=sys.stderr)
        return 130 if cancelled.is_set() else 1
    finally:
        wake.set()
        watcher.join(timeout=15)
        for number, handler in previous.items():
            signal.signal(number, handler)
