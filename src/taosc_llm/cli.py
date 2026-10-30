"""Prepare datasets, evaluate ERM candidates, and run isolated Pi refinement."""

import argparse
import json
import os
import subprocess
import sys
from contextlib import contextmanager, redirect_stdout
from pathlib import Path


def _positive(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


@contextmanager
def _diagnostics_to_stderr():
    """Reserve CLI stdout for JSON, including inherited native/child output."""
    sys.stdout.flush()
    saved = os.dup(1)
    try:
        os.dup2(2, 1)
        with redirect_stdout(sys.stderr):
            yield
    finally:
        os.dup2(saved, 1)
        os.close(saved)


def _run(label: str, operation) -> int:
    try:
        with _diagnostics_to_stderr():
            result = operation()
        print(json.dumps(result, allow_nan=False))
        status = result.get("status")
        if status == "reject_same_crash":
            return 2
        if status == "unavailable":
            return 3
        return 0 if status in ("prepared", "built", "abstained", "not_rejected", "warmed") else 1
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"{label}: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(f"{label}: cancelled; unresolved provider requests remain quarantined", file=sys.stderr)
        return 130


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["recover-quota"]:
        parser = argparse.ArgumentParser(prog="taosc-llm recover-quota")
        parser.add_argument("--confirm-provider-settled", action="store_true", required=True)
        parser.parse_args(arguments[1:])
        def recover():
            from .admission import recover_reservations
            return {"status": "prepared", "cleared_reservations":
                    recover_reservations(confirm_provider_settled=True)}
        return _run("taosc-llm", recover)

    parser = argparse.ArgumentParser(
        prog="taosc-llm",
        description="Synthesize or build an ERM predicate from a prepared dataset; not final repair verification.",
    )
    parser.add_argument("--dataset", type=Path, required=True, help="prepared directory or manifest.json")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--predicate", help="manual family-specific predicate, evaluated before building")
    mode.add_argument("--provider-env", type=Path, help="explicit provider file; enables isolated Pi refinement")
    parser.add_argument("--output", type=Path, help="private synthesis run root")
    parser.add_argument("--execution-workers", type=_positive, default=1, help="concrete workers, independent of provider quota")
    parser.add_argument("--max-rounds", type=_positive, help="maximum proposal/build/refinement rounds (provider mode; default: 4)")
    parser.add_argument("--pi-sdk-root", type=Path, help="pinned SDK project; Guix supplies its own default")
    parser.add_argument("--base-url")
    parser.add_argument("--model")
    parser.add_argument("--max-in-flight", type=int, help="provider cap; Ollama permits 1..3")
    parser.add_argument("--workers", type=_positive, help="model-session worker capacity, not execution workers")
    args = parser.parse_args(arguments)
    if args.predicate is not None and any(value is not None for value in (
            args.pi_sdk_root, args.base_url, args.model, args.max_in_flight, args.workers, args.max_rounds)):
        parser.error("provider options require --provider-env")

    def execute():
        if args.predicate is not None:
            from .synthesis import generate_manual
            return generate_manual(args.dataset, args.predicate,
                                   execution_workers=args.execution_workers, output=args.output)
        from .synthesis import generate_with_pi
        return generate_with_pi(args.dataset, args.provider_env,
                                sdk_root=args.pi_sdk_root, base_url=args.base_url, model=args.model,
                                max_in_flight=args.max_in_flight, workers=args.workers,
                                execution_workers=args.execution_workers, max_rounds=4 if args.max_rounds is None else args.max_rounds,
                                output=args.output)
    return _run("taosc-llm", execute)


def setup_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="taosc-llm-setup",
        description="Freeze Taosc artifacts and admitted generation evidence; prepare static analysis without an LLM.",
    )
    parser.add_argument("--config", "-c", type=Path, required=True, metavar="config.env")
    parser.add_argument("--workdir", "-w", type=Path, required=True)
    parser.add_argument("--concrete-run", type=Path, required=True, help="explicit run containing minimized inputs and original observations")
    parser.add_argument("--binradar-run", type=Path, help="explicit BinRadar run containing committed patch-zero mutation evidence")
    parser.add_argument("--output", type=Path, help="prepared dataset output root")
    parser.add_argument("--rea", help="explicit local REA executable; never a shell command")
    parser.add_argument("--analysis-provider", default="ghidra", help="local static analysis backend")
    args = parser.parse_args(argv)

    def execute():
        from .preparation import prepare_dataset
        dataset = prepare_dataset(args.config, args.workdir, args.concrete_run, args.binradar_run,
                                  output=args.output, rea=args.rea, analysis_provider=args.analysis_provider)
        return {"status": "prepared", "dataset_id": dataset.dataset_id,
                "dataset": str(dataset.root), "manifest": str(dataset.root / "manifest.json"),
                "patch_format": dataset.patch_format, "verified": False}
    return _run("taosc-llm-setup", execute)


def evaluate_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="taosc-llm-evaluate",
        description="Reuse complete captures or execute concrete cases; mutation evidence is offline, rejection-only.",
    )
    parser.add_argument("--dataset", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--predicate", help="family-specific candidate expression")
    mode.add_argument("--warm", action="store_true", help="capture neutral concrete executions without a candidate")
    parser.add_argument("--case", dest="case_ids", action="append", help="scoped case ID; repeat to select development cases")
    parser.add_argument("--workers", type=_positive, default=1)
    parser.add_argument("--offline", action="store_true", help="never execute a target")
    parser.add_argument("--cache-dir", type=Path, help="private evaluator cache; does not modify source producer files")
    args = parser.parse_args(argv)
    if args.warm and (args.offline or args.case_ids):
        parser.error("--warm captures the dataset's concrete cases; it cannot be combined with --offline or --case")

    def execute():
        from .evaluation import evaluate_dataset, warm_dataset
        if args.warm:
            return warm_dataset(args.dataset, workers=args.workers, cache_dir=args.cache_dir)
        return evaluate_dataset(args.dataset, args.predicate, case_ids=args.case_ids,
                                workers=args.workers, execute=not args.offline, cache_dir=args.cache_dir)
    return _run("taosc-llm-evaluate", execute)
