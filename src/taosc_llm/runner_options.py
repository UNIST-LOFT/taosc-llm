"""Validated runner options and exclusive, non-destructive run allocation."""
from __future__ import annotations

import argparse
import math
import os
import re
from pathlib import Path

from .no_llm.model import SearchLimits


def _positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def _seconds(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise argparse.ArgumentTypeError("must be nonnegative finite seconds")
    return number


def _positive_seconds(value: str) -> float:
    number = _seconds(value)
    if number == 0:
        raise argparse.ArgumentTypeError("must be positive finite seconds")
    return number


def _prefix(value: str) -> str:
    if not value or value in (".", "..") or "/" in value or "\\" in value or "\x00" in value:
        raise argparse.ArgumentTypeError("must be a nonempty simple basename")
    return value


def _run_id(value: str) -> str:
    if value not in ("n", "l") and re.fullmatch(r"[0-9]+", value) is None:
        raise argparse.ArgumentTypeError("must be n, l, or a decimal run number")
    if value not in ("n", "l"):
        try:
            int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("run number is too large") from exc
    return value


def _absolute(value: str | Path, base: Path) -> Path:
    path = Path(value).expanduser()
    return Path(os.path.abspath(path if path.is_absolute() else base / path))


def parse_args(argv=None) -> argparse.Namespace:
    """Validate all option combinations without creating or changing files."""
    parser = argparse.ArgumentParser(
        prog="taosc-llm-run", allow_abbrev=False,
        description="Run generation, dataset preparation and bounded synthesis in a private run directory.",
    )
    parser.add_argument("--mode", choices=("no-llm", "manual", "provider"), default="no-llm")
    parser.add_argument("--subject", type=Path)
    parser.add_argument("--workdir", type=Path, default=Path("workdir-0.1.24"))
    path_options = {
        "dataset": "existing immutable dataset; skip preparation and generation",
        "concrete-run": "completed concrete producer to reuse read-only; omitted: generate",
        "binradar-run": "committed mutation producer to reuse read-only; omitted: generate",
        "replay-socket": "explicit caller-owned resident endpoint; reused mutations default to offline",
        "output": "exact fresh run directory (never replace); conflicts with run-prefix/run-id",
    }
    for name, help_text in path_options.items():
        parser.add_argument(f"--{name}", type=Path, help=help_text)
    parser.add_argument("--concrete-only", action="store_true")
    parser.add_argument("--stop-after", choices=("generation", "dataset", "warm", "synthesis"), default="synthesis")
    parser.add_argument("--run-prefix", type=_prefix,
                        help="default taosc-llm-no-llm-out (no-llm), otherwise taosc-llm-out")
    parser.add_argument("--run-id", type=_run_id,
                        help="n=new (default), decimal=exact numbered run, l=latest with --resume")
    parser.add_argument("--resume", action="store_true",
                        help="resume an initialized no-llm search, never regenerate evidence or snapshots")
    parser.add_argument("--predicate")
    parser.add_argument("--provider-env", type=Path)
    parser.add_argument("--pi-sdk-root", type=Path)
    parser.add_argument("--max-rounds", type=_positive_int)
    parser.add_argument("--session-feedback", action="store_true")
    parser.add_argument("--rea")
    parser.add_argument("--analysis-timeout", type=_positive_int, default=900)
    parser.add_argument("--analysis-query-timeout", type=_positive_int, default=120)
    parser.add_argument("--execution-workers", type=_positive_int, default=4)
    parser.add_argument("--generation-timeout", type=int, default=7200,
                        help="native per-phase seconds; 0 means unlimited")
    for name in ("ready-timeout", "stage-timeout"):
        parser.add_argument(f"--{name}", type=_seconds, default=7200.0)
    parser.add_argument("--graceful-timeout", type=_positive_seconds, default=10.0)
    parser.add_argument("--search-timeout", type=_positive_seconds)
    limits = SearchLimits()
    search_names = ("max_evaluations", "max_executions", "max_atoms", "beam_width", "max_clauses", "max_factors", "operand_depth")
    for name in search_names:
        parser.add_argument("--" + name.replace("_", "-"), type=_positive_int)
    args = parser.parse_args(argv)

    if args.output is not None and (args.run_prefix is not None or args.run_id is not None):
        parser.error("--output conflicts with explicitly supplied --run-prefix/--run-id")
    if args.dataset is not None:
        if args.concrete_run is not None or args.binradar_run is not None or args.concrete_only:
            parser.error("--dataset conflicts with --concrete-run, --binradar-run and --concrete-only")
        if args.stop_after in ("generation", "dataset"):
            parser.error("--dataset requires --stop-after warm or synthesis")
    if args.concrete_only and args.binradar_run is not None:
        parser.error("--concrete-only conflicts with --binradar-run")
    if args.replay_socket is not None and (args.concrete_only or (args.binradar_run is None and args.dataset is None and not args.resume)):
        parser.error("--replay-socket requires externally reused --binradar-run, --dataset or --resume, without --concrete-only")
    if args.predicate is not None and args.mode != "manual":
        parser.error("--predicate requires --mode manual")
    if args.mode != "provider" and any((args.provider_env is not None, args.pi_sdk_root is not None, args.max_rounds is not None, args.session_feedback)):
        parser.error("--provider-env, --pi-sdk-root, --max-rounds and --session-feedback require --mode provider")
    if args.mode != "no-llm" and (args.search_timeout is not None or any(getattr(args, name) is not None for name in search_names)):
        parser.error("search options require --mode no-llm")
    if args.stop_after == "synthesis":
        if args.mode == "manual" and args.predicate is None:
            parser.error("manual synthesis requires --predicate")
        if args.mode == "provider" and args.provider_env is None:
            parser.error("provider synthesis requires explicit --provider-env")
    if args.max_rounds is not None and args.max_rounds > 16:
        parser.error("--max-rounds must be between 1 and 16")
    if args.execution_workers > 32:
        parser.error("--execution-workers must be between 1 and 32")
    if args.generation_timeout < 0:
        parser.error("--generation-timeout must be nonnegative whole seconds")
    if max(args.analysis_timeout, args.analysis_query_timeout) > 2147483:
        parser.error("analysis timeouts must not exceed 2147483 seconds")
    if args.run_id == "l" and not args.resume:
        parser.error("--run-id l requires --resume")
    if args.resume:
        if args.concrete_run is not None or args.binradar_run is not None or args.concrete_only:
            parser.error("--resume conflicts with --concrete-run, --binradar-run and --concrete-only")
        if args.mode != "no-llm" or args.stop_after != "synthesis":
            parser.error("--resume requires no-llm synthesis")
        if args.output is None and args.run_id in (None, "n"):
            parser.error("--resume requires --output or a non-n --run-id")

    for name in search_names:
        if getattr(args, name) is None:
            setattr(args, name, getattr(limits, name))
    if args.search_timeout is None:
        args.search_timeout = limits.timeout
    try:
        SearchLimits(timeout=args.search_timeout, **{name: getattr(args, name) for name in search_names})
    except ValueError as exc:
        parser.error(str(exc))
    if args.max_rounds is None and args.mode == "provider":
        args.max_rounds = 4
    if args.run_prefix is None:
        args.run_prefix = "taosc-llm-no-llm-out" if args.mode == "no-llm" else "taosc-llm-out"
    if args.run_id is None:
        args.run_id = "n"
    args.cwd = Path(os.getcwd())
    args.subject = _absolute(args.subject if args.subject is not None else args.cwd, args.cwd)
    args.workdir = _absolute(args.workdir, args.subject)
    for name in ("dataset", "concrete_run", "binradar_run", "replay_socket", "output", "provider_env", "pi_sdk_root"):
        value = getattr(args, name)
        if value is not None:
            setattr(args, name, _absolute(value, args.cwd))
    if args.rea is not None and "/" in args.rea:
        args.rea = str(_absolute(args.rea, args.cwd))
    return args


def output_base(args: argparse.Namespace) -> Path:
    """Return the allocation parent, independent of later working-directory changes."""
    return args.cwd if args.dataset is not None else args.workdir / "out"


def _numbered(base: Path, prefix: str):
    pattern = re.compile(re.escape(prefix) + r"-([0-9]+)\Z")
    for path in base.iterdir():
        match = pattern.fullmatch(path.name)
        if match is not None:
            yield int(match[1]), path


def _resume_directory(path: Path) -> Path:
    if path.is_symlink():
        raise FileExistsError(f"refusing symlink run directory: {path}")
    if not path.exists():
        raise FileNotFoundError(f"run directory does not exist: {path}")
    if not path.is_dir():
        raise NotADirectoryError(f"run path is not a directory: {path}")
    return path


def allocate_run(args: argparse.Namespace) -> Path:
    """Reserve a new 0700 root atomically, or select an existing resume root."""
    if args.output is not None:
        path = args.output
    else:
        base = output_base(args)
        if args.run_id == "l":
            directories = ((number, path) for number, path in _numbered(base, args.run_prefix)
                           if not path.is_symlink() and path.is_dir())
            latest = max(directories, key=lambda item: (item[0], item[1].name), default=None)
            if latest is None:
                raise FileNotFoundError(f"no numbered run directories in {base}")
            return _resume_directory(latest[1])
        if args.run_id == "n":
            base.mkdir(parents=True, exist_ok=True)
            number = max((number for number, _ in _numbered(base, args.run_prefix)), default=-1) + 1
            while True:
                path = base / f"{args.run_prefix}-{number:05d}"
                try:
                    path.mkdir(mode=0o700)
                    return path
                except FileExistsError:
                    if not os.path.lexists(path):
                        raise
                    number += 1
        path = base / f"{args.run_prefix}-{int(args.run_id):05d}"
    if args.resume:
        return _resume_directory(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir(mode=0o700)
    return path
