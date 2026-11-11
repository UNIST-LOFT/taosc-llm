"""Collect saved, selected Taosc results without loading datasets or running targets.

The target counters describe only the observed cohort, not universal repair or
FINAL verification. Producer lifecycle and legacy quality are separate facts.
"""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import TextIO

from .collection_metrics import METRIC_FIELDS, collect_metrics


ROW_FIELDS = (
    "subject", "run", "run_directory", "mode", "lifecycle",
    "exit_code", "run_error", "synthesis_status", "selected_round", "predicate",
    "termination", "legacy_quality", "publication_status", "verified",
    "binradar_verification", "evaluation_source", "collection_status", "collection_error",
)
COLUMNS = ROW_FIELDS + METRIC_FIELDS
_MODES = ("provider", "manual", "no-llm")
_PAYLOAD = re.compile(r"payloads/([0-9a-f]{64})\.([A-Za-z0-9][A-Za-z0-9._-]{0,31})")


@dataclass(frozen=True)
class RunSpec:
    subject: str
    directory: Path
    problem: str | None = None
    detail: str | None = None


def _pairs(items):
    value = {}
    for key, child in items:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = child
    return value


def _decode(raw: bytes, source: Path) -> dict:
    def invalid(value):
        raise ValueError(f"invalid JSON constant: {value}")
    value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=invalid)
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {source}")
    return value


def _read_json(path: Path) -> dict:
    return _decode(path.read_bytes(), path)


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def load_experiment_list(exp_file: str | Path) -> tuple[Path, list[Path], list[str]]:
    """Resolve whole-line paths (including spaces) relative to the list itself."""
    path = Path(exp_file).absolute()
    entries = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
               if line.strip()]
    directories = [Path(os.path.abspath(path.parent / entry)) for entry in entries]
    return path.parent, directories, entries


def discover_runs(exp_file: str | Path, *, workdir: str = "workdir",
                  run_prefix: str = "taosc-llm-out", runs: str = "all") -> list[RunSpec]:
    """Discover exact prefix-numeric directories, sorting numerically then by name."""
    _, subjects, labels = load_experiment_list(exp_file)
    pattern = re.compile(re.escape(run_prefix) + r"-([0-9]+)")
    found = []
    seen = set()
    for subject, label in zip(subjects, labels):
        directory = subject / workdir
        try:
            if not directory.is_dir():
                found.append(RunSpec(label, directory, "missing_workdir",
                                     f"workdir not found: {directory}"))
                continue
            patch_format = directory / "patch-format"
            if patch_format.is_file():
                value = patch_format.read_text(encoding="utf-8").strip()
                if value.startswith("Single "):
                    found.append(RunSpec(label, directory, "unsupported",
                                         f"unsupported patch format: {value}"))
                    continue
            output = directory / "out"
            candidates = []
            if output.is_dir():
                for child in output.iterdir():
                    match = pattern.fullmatch(child.name)
                    if match and child.is_dir():
                        candidates.append((int(match[1]), child.name, child))
            candidates.sort()
            if runs == "latest":
                candidates = candidates[-1:]
            if not candidates:
                found.append(RunSpec(label, output, "missing_runs",
                                     f"no {run_prefix}-NUMERIC run directories: {output}"))
            for _, _, child in candidates:
                identity = child.resolve()
                if identity not in seen:
                    seen.add(identity)
                    found.append(RunSpec(label, child))
        except (OSError, ValueError, UnicodeError) as error:
            found.append(RunSpec(label, directory, "collection_error",
                                 f"{type(error).__name__}: {error}"))
    return found


def _path(value: object, base: Path) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("saved path must be a nonempty string")
    return Path(value) if Path(value).is_absolute() else base / value


def _compact(record: dict) -> dict:
    """Discard repeated round evaluations before opening the selected report."""
    keys = ("engine", "mode", "status", "exit_code", "error", "predicate", "termination",
            "selected_round", "quality", "publication_status", "verified",
            "binradar_verification", "result_record", "result_directory", "synthesis_result")
    result = {key: record[key] for key in keys if key in record}
    proposal = record.get("proposal")
    if isinstance(proposal, dict) and proposal.get("decision") == "candidate":
        result["predicate"] = proposal.get("predicate")
    # Provider reports have a separately saved selected candidate. Manual
    # reports are inline; no-LLM reports contain a content-addressed reference.
    if "selected_round" not in record and "evaluation" in record:
        result["evaluation"] = record["evaluation"]
    if "provider" in record or "rounds" in record:
        result["mode"] = "provider"
    return result


def _payload_path(root: Path, reference: dict) -> Path:
    if not isinstance(reference, dict):
        raise ValueError("invalid journal payload reference")
    name, digest = reference.get("path"), reference.get("sha256")
    if isinstance(name, str) and Path(name).is_absolute():
        try:
            name = str(Path(name).relative_to(root))
        except ValueError as exc:
            raise ValueError("escaping journal payload reference") from exc
    match = _PAYLOAD.fullmatch(name) if isinstance(name, str) else None
    if not match or match[1] != digest:
        raise ValueError("invalid journal payload path or checksum")
    path = root / name
    if (root.is_symlink() or (root / "payloads").is_symlink() or path.is_symlink()
            or not stat.S_ISREG(path.stat().st_mode)):
        raise ValueError(f"unsafe journal payload: {path}")
    return path


def _load_payload(root: Path, reference: dict) -> tuple[dict, Path]:
    path = _payload_path(root, reference)
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != reference["sha256"]:
        raise ValueError(f"journal payload checksum mismatch: {path}")
    return _decode(raw, path), path


def _result_reference(root: Path, result_path: Path) -> dict:
    try:
        relative = str(result_path.relative_to(root))
    except ValueError as exc:
        raise ValueError("result_record is outside the saved journal") from exc
    match = _PAYLOAD.fullmatch(relative)
    if not match or match[2] != "json":
        raise ValueError("result_record is not a content-addressed JSON payload")
    return {"path": relative, "sha256": match[1]}


def _journal_result(root: Path) -> tuple[dict, Path]:
    """Find the last saved result event without opening a live Journal."""
    segments = root / "segments"
    if segments.is_symlink():
        raise ValueError("unsafe journal segments directory")
    paths = sorted((p for p in segments.iterdir()
                    if re.fullmatch(r"[0-9]{8}\.jsonl", p.name)), reverse=True)
    for path in paths:
        selected = None
        if path.is_symlink():
            raise ValueError(f"unsafe journal segment: {path}")
        with path.open("rb") as stream:
            for line in stream:
                if not line.endswith(b"\n"):
                    break  # An uncommitted torn tail is not a final result.
                event = _decode(line, path)
                if event.get("kind") != "result":
                    continue
                unsigned = {key: value for key, value in event.items() if key != "sha256"}
                if hashlib.sha256(_canonical(unsigned)).hexdigest() != event.get("sha256"):
                    raise ValueError(f"journal result event checksum mismatch: {path}")
                data = event.get("data")
                if not isinstance(data, dict) or not isinstance(data.get("result"), dict):
                    raise ValueError(f"malformed journal result event: {path}")
                selected = data["result"]
        if selected is not None:
            return _load_payload(root, selected)
    raise ValueError(f"no saved final result in journal: {root}")


def _mode(record: dict) -> str:
    if record.get("engine") == "taosc-llm-no-llm":
        return "no-llm"
    if record.get("mode") in _MODES:
        return record["mode"]
    if "provider" in record or "rounds" in record:
        return "provider"
    return "manual" if "predicate" in record else "unknown"


def _apply_metadata(row: dict, summary: dict) -> None:
    row["synthesis_status"] = summary.get("status")
    for key in ("selected_round", "predicate", "termination", "publication_status",
                "verified", "binradar_verification"):
        if key in summary:
            row[key] = summary[key]
    quality = summary.get("quality")
    if quality is not None:
        row["legacy_quality"] = quality.get("status") if isinstance(quality, dict) else quality


def _collect_selected(row: dict, summary: dict, result_root: Path) -> None:
    _apply_metadata(row, summary)
    evaluation = None
    source = None
    if row["mode"] == "no-llm":
        if summary.get("result_record") is not None:
            path = _path(summary["result_record"], result_root)
            summary, _ = _load_payload(result_root, _result_reference(result_root, path))
            if summary.get("engine") != "taosc-llm-no-llm":
                raise ValueError("result_record does not identify a no-LLM result")
            _apply_metadata(row, summary)
        if row["predicate"] is not None:
            evaluation, source = _load_payload(result_root, summary.get("evaluation"))
    elif row["mode"] == "provider":
        selected = summary.get("selected_round")
        if selected is not None:
            if type(selected) is not int or selected < 1:
                raise ValueError("selected_round must be a positive integer")
            source = result_root / "candidates" / str(selected) / "evaluation.json"
            evaluation = _read_json(source)
            predicate = evaluation.get("predicate")
            if not isinstance(predicate, str) or not predicate:
                raise ValueError("selected candidate evaluation has no predicate")
            if row["predicate"] is not None and row["predicate"] != predicate:
                raise ValueError("selected predicate disagrees with its saved evaluation")
            row["predicate"] = predicate
        elif row["predicate"] is not None:
            raise ValueError("provider candidate has no saved selected_round")
    else:
        evaluation = summary.get("evaluation")
        if evaluation is not None:
            if not isinstance(evaluation, dict):
                raise ValueError("manual evaluation must be an object")
            source = result_root / "run.json"
            if row["predicate"] is None:
                row["predicate"] = evaluation.get("predicate")
        elif row["predicate"] is not None and row["lifecycle"] not in (
                "failed", "interrupted", "timed-out", "running", "prepared",
                "infrastructure_error", "cancelled"):
            raise ValueError("selected manual candidate is missing its evaluation")
    if row["predicate"] is not None and (not isinstance(row["predicate"], str)
                                          or not row["predicate"].strip()):
        raise ValueError("selected predicate must be a nonempty string or null")
    if evaluation is not None and row["predicate"] is None:
        raise ValueError("saved selected evaluation has no predicate")
    if evaluation is not None and evaluation.get("predicate") != row["predicate"]:
        raise ValueError("selected predicate disagrees with its saved evaluation")
    row["evaluation_source"] = str(source) if source is not None else None
    row.update(collect_metrics(evaluation, candidate_present=row["predicate"] is not None))
    if evaluation is not None and row["legacy_quality"] is None:
        quality = evaluation.get("quality")
        if isinstance(quality, dict):
            row["legacy_quality"] = quality.get("status")


def collect_run(spec: RunSpec) -> dict:
    """Reduce one selected evaluation to scalars; failures cannot erase other rows."""
    row = dict.fromkeys(COLUMNS)
    row.update(subject=spec.subject, run=spec.directory.name,
               run_directory=str(spec.directory), mode="unknown", lifecycle="unknown",
               collection_status="collected", collection_error=None)
    row.update(collect_metrics(None, candidate_present=False))
    if spec.problem is not None:
        row["collection_status"] = spec.problem
        if spec.problem == "unsupported":
            row["lifecycle"] = "unsupported"
            row["run_error"] = spec.detail
        else:
            row["collection_error"] = spec.detail
        return row
    try:
        root = spec.directory
        record_path = root / "run.json"
        if record_path.is_file():
            record = _read_json(record_path)
            runner = record.get("engine") == "taosc-llm-run"
            row.update(mode=_mode(record), lifecycle=record.get("status", "unknown"),
                       exit_code=record.get("exit_code"), run_error=record.get("error"))
            _apply_metadata(row, record)
            if runner:
                result_root = _path(record["result_directory"], root) if record.get("result_directory") else root / "result"
                summary = record.get("synthesis")
                if summary is not None and not isinstance(summary, dict):
                    raise ValueError("runner synthesis summary must be an object")
                # Compact provider summary names exactly the retained candidate;
                # do not read either giant repeated synthesis report on this path.
                if row["mode"] == "provider" and summary is not None:
                    pass
                elif row["mode"] == "no-llm" and summary is not None and summary.get("result_record"):
                    pass
                elif (result_root / "run.json").is_file():
                    summary = _compact(_read_json(result_root / "run.json"))
                elif record.get("synthesis_result"):
                    summary = _compact(_read_json(_path(record["synthesis_result"], root)))
                elif (result_root / "segments").is_dir():
                    summary, _ = _journal_result(result_root)
                elif summary is None:
                    # Generation/dataset/warm stops and operational failures can have
                    # no synthesis at all. A completed synthesis requires its
                    # saved result, not an invented no-candidate success.
                    options = record.get("options") or {}
                    if not isinstance(options, dict):
                        raise ValueError("runner options must be an object")
                    if (row["lifecycle"] == "finished"
                            and options.get("stop_after") not in ("generation", "dataset", "warm")):
                        raise ValueError("completed runner is missing saved synthesis evidence")
                    summary = {}
                else:
                    raise ValueError("saved selected synthesis evidence is missing")
                del record
            else:
                summary, result_root = _compact(record), root
                status = record.get("status")
                if row["mode"] == "no-llm":
                    row["lifecycle"] = "interrupted" if record.get("termination") == "interrupted" else "recorded"
                elif status in ("not_rejected", "reject_same_crash", "rejected", "unavailable",
                                "abstained", "refinement_exhausted", "built"):
                    row["lifecycle"] = "finished"
                elif status == "infrastructure_error":
                    row["lifecycle"] = "failed"
                elif status == "cancelled":
                    row["lifecycle"] = "interrupted"
                elif status in ("prepared", "refining"):
                    row["lifecycle"] = "running"
                del record
        elif (root / "segments").is_dir():
            summary, _ = _journal_result(root)
            result_root = root
            row.update(mode="no-llm", lifecycle="recorded")
        elif (root / "result" / "run.json").is_file():
            # Preserve a recoverable candidate but report the missing runner
            # lifecycle instead of inventing a completed experiment.
            result_root = root / "result"
            summary = _compact(_read_json(result_root / "run.json"))
            row["mode"] = _mode(summary)
            row["collection_status"] = "collection_error"
            row["collection_error"] = f"runner record not found: {record_path}"
        else:
            raise FileNotFoundError(f"saved run record not found: {record_path}")
        if row["mode"] == "unknown":
            row["mode"] = _mode(summary)
        if row["mode"] == "unknown":
            raise ValueError("unrecognized saved synthesis layout or mode")
        _collect_selected(row, summary, result_root)
    except Exception as error:
        row.update(collection_status="collection_error",
                   collection_error=f"{type(error).__name__}: {error}")
        row.update(collect_metrics(None, candidate_present=(row["predicate"] is not None
                                                          or row["selected_round"] is not None)))
    return row


def collect_all(specs: list[RunSpec], jobs: int = 1) -> list[dict]:
    """Keep input order and only retain reduced rows, never full evaluations.

    jobs=0 uses up to one process per CPU/run. The default of one bounds memory
    to one evaluation; explicitly parallel workers each load one run at a time.
    """
    workers = jobs if jobs else min(os.cpu_count() or 1, len(specs))
    if workers <= 1 or len(specs) <= 1:
        return [collect_run(spec) for spec in specs]
    with ProcessPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(collect_run, specs, chunksize=1))


def summarize(rows: list[dict]) -> dict:
    return {"runs": len(rows),
            "collection_errors": sum(row["collection_error"] is not None for row in rows),
            "collection_statuses": dict(sorted(Counter(row["collection_status"] for row in rows).items())),
            "lifecycles": dict(sorted(Counter(row["lifecycle"] for row in rows).items())),
            "target_statuses": dict(sorted(Counter(row["target_status"] for row in rows).items()))}


def write_output(stream: TextIO, output_format: str, rows: list[dict], *,
                 include_subject_id: bool = True) -> None:
    fields = tuple(key for key in COLUMNS if include_subject_id or key != "subject")
    summary = summarize(rows)
    if output_format in ("csv", "tsv"):
        writer = csv.DictWriter(stream, fieldnames=fields,
                                delimiter="\t" if output_format == "tsv" else ",",
                                extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    elif output_format == "json":
        json.dump({"schema_version": 1, "scope": "observed_cohort",
                   "rows": [{key: row[key] for key in fields} for row in rows],
                   "summary": summary}, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")
    else:
        stream.write("Observed-cohort target results; not universal repair or FINAL verification.\n")
        for row in rows:
            label = f"{row['subject']} / {row['run']}" if include_subject_id else row["run"]
            stream.write(f"\n{label}\n")
            for key in fields:
                stream.write(f"  {key}: {json.dumps(row[key], ensure_ascii=False)}\n")
        stream.write("\nSummary: " + json.dumps(summary, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exp", default="exp.list", help="experiment list; paths are relative to this file")
    parser.add_argument("--workdir", default="workdir")
    parser.add_argument("--run-prefix", default="taosc-llm-out")
    parser.add_argument("--runs", choices=("all", "latest"), default="latest",
                        help="latest means highest numeric run, including failed runs")
    parser.add_argument("--mode", choices=("all", *_MODES), default="all")
    parser.add_argument("--format", choices=("log", "csv", "tsv", "json"), default="log")
    parser.add_argument("--output", help="output path, or - for stdout; default: exp-list-dir/logs/taosc-llm-results-TIMESTAMP.ext")
    parser.add_argument("--jobs", type=int, default=1,
                        help="collection processes (default 1; 0 = CPU/run count; each loads one report)")
    parser.add_argument("-n", "--no-subject-id", action="store_true",
                        help="omit the textual subject column for side-by-side spreadsheet comparison")
    parser.add_argument("--run-dir", action="append", default=[],
                        help="saved run directory, repeatable; bypass experiment discovery")
    args = parser.parse_args(argv)
    if args.jobs < 0:
        parser.error("--jobs must be nonnegative")
    if not args.run_prefix or "/" in args.run_prefix:
        parser.error("--run-prefix must be a nonempty directory-name prefix")
    try:
        if args.run_dir:
            specs = []
            seen = set()
            for value in args.run_dir:
                path = Path(value).absolute()
                if path.resolve() in seen:
                    continue
                seen.add(path.resolve())
                specs.append(RunSpec(str(path), path))
        else:
            specs = discover_runs(args.exp, workdir=args.workdir,
                                  run_prefix=args.run_prefix, runs=args.runs)
        rows = collect_all(specs, args.jobs)
        if args.mode != "all":
            # Unknown/missing evidence must not disappear under a mode filter.
            rows = [row for row in rows if row["mode"] in (args.mode, "unknown")]
        output = args.output
        if output is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
            output = str(Path(args.exp).absolute().parent / "logs" /
                         f"taosc-llm-results-{timestamp}.{args.format}")
        if output == "-":
            write_output(sys.stdout, args.format, rows, include_subject_id=not args.no_subject_id)
        else:
            path = Path(output)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("w", encoding="utf-8", newline="") as stream:
                write_output(stream, args.format, rows, include_subject_id=not args.no_subject_id)
            print(f"Results written to: {path}", file=sys.stderr)
        return 1 if any(row["collection_error"] is not None for row in rows) else 0
    except (OSError, ValueError, RuntimeError) as error:
        print(f"taosc-llm-collect-results: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
