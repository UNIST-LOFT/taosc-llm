"""Supervise explicit evidence producers and scoped Taosc synthesis, never FINAL."""

from __future__ import annotations

import fcntl
import json
import os
import shutil
import sys
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path

from .runner_options import allocate_run, parse_args
from .runner_process import RunnerInterrupted, RunnerTimeout, Supervisor

_SEARCH_OPTIONS = ("search_timeout", "max_evaluations", "max_executions", "max_atoms",
                   "beam_width", "max_clauses", "max_factors", "operand_depth")


class StageFailure(RuntimeError):
    """A required stage failed; its private logs retain the actual diagnostic."""


@contextmanager
def _directory_lock(path: Path, *, nofollow: bool = True):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if nofollow:
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError(f"another runner owns {path}") from error
        yield descriptor
    finally:
        os.close(descriptor)


def _read_json(path: Path) -> dict:
    with path.open() as stream:
        result = json.load(stream)
    if not isinstance(result, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return result


def _save(root: Path, record: dict) -> None:
    """Publish only complete summaries; search's own immutable journal is separate."""
    temporary = root / ".run.json.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(record, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, root / "run.json")
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _options(args) -> dict:
    return {key: str(value) if isinstance(value, Path) else value
            for key, value in vars(args).items() if not key.startswith("_")}


def _preflight(args) -> str | None:
    """Validate before reserving output or touching caller-owned producer data."""
    if args.resume:
        return None
    if args.dataset is not None:
        manifest = args.dataset / "manifest.json" if args.dataset.is_dir() else args.dataset
        if not manifest.is_file():
            raise ValueError(f"prepared dataset manifest not found: {manifest}")
    else:
        if not args.subject.is_dir() or not args.workdir.is_dir():
            raise ValueError("--subject and --workdir must identify an existing prepared subject")
        if not (args.concrete_only and args.stop_after == "generation"):
            format_path = args.workdir / "patch-format"
            if not os.path.lexists(format_path):
                format_path = args.subject / "patch-format"
            patch_format = format_path.read_text().strip()
            if not patch_format:
                raise ValueError(f"patch-format is empty: {format_path}")
            if patch_format not in ("ERM generic", "ERM CWE-805"):
                return f"unsupported patch-format: {patch_format} ({format_path})"
        if not (args.workdir / "patch-location").is_file():
            raise ValueError(f"{args.workdir} has no patch-location; prepare Taosc artifacts first")
        if not (args.subject / "config.env").is_file():
            raise ValueError(f"subject config.env not found: {args.subject}")
        if args.concrete_run is not None:
            manifest = args.concrete_run / "minimizer.sbsv"
            if not manifest.is_file() or not manifest.stat().st_size:
                raise ValueError(f"--concrete-run requires a completed nonempty {manifest}")
        if args.binradar_run is not None and not (args.binradar_run / "binradar.br").is_file():
            raise ValueError(f"--binradar-run has no committed binradar.br: {args.binradar_run}")
        if args.replay_socket is not None:
            expected = args.binradar_run / "replay.sock"
            if args.replay_socket.resolve() != expected.resolve():
                raise ValueError("--replay-socket must belong to --binradar-run")
    if args.mode == "provider" and args.stop_after == "synthesis":
        if not args.provider_env.is_file():
            raise ValueError(f"provider environment file not found: {args.provider_env}")
    return None


def _resume_record(root: Path, args) -> dict:
    path = root / "run.json"
    if path.is_symlink():
        raise ValueError("runner summary must not be a symlink")
    record = _read_json(path)
    if (record.get("schema_version") != 1 or record.get("engine") != "taosc-llm-run"
            or record.get("mode") != "no-llm"):
        raise ValueError("--resume requires a taosc-llm-run no-llm session")
    if not (root / "result" / "identity.json").is_file():
        raise ValueError("search was not initialized; reuse the prepared dataset in a fresh run")
    saved = record.get("options")
    if (not isinstance(saved, dict) or not isinstance(record.get("dataset"), str)
            or any(name not in saved for name in ("execution_workers", *_SEARCH_OPTIONS))):
        raise ValueError("runner resume metadata is incomplete")
    for name in ("execution_workers", *_SEARCH_OPTIONS):
        if getattr(args, name) != saved[name]:
            raise ValueError(f"resume must preserve --{name.replace('_', '-')}")
    dataset = Path(record["dataset"])
    if args.dataset is not None:
        actual = args.dataset.parent if args.dataset.name == "manifest.json" else args.dataset
        expected = dataset.parent if dataset.name == "manifest.json" else dataset
        if actual.resolve() != expected.resolve():
            raise ValueError("resume must preserve the recorded dataset")
    args.dataset = dataset
    saved_socket = record.get("replay_socket")
    if args.replay_socket is not None and str(args.replay_socket) != saved_socket:
        raise ValueError("resume must preserve the recorded replay socket")
    args.replay_socket = Path(saved_socket) if saved_socket else None
    # No source setup, generator restart or new snapshot can restore old replay identity.
    return record


def _python(module: str, *arguments) -> list[str]:
    return [sys.executable, "-u", "-m", module, *map(str, arguments)]


def _cli(entry: str, *arguments) -> list[str]:
    # The entrypoint is a host literal, never a caller-supplied Python fragment.
    return [sys.executable, "-u", "-c",
            f"from taosc_llm.cli import {entry}; raise SystemExit({entry}())", *map(str, arguments)]


class Experiment:
    def __init__(self, args, root: Path, record: dict, supervisor: Supervisor):
        self.args, self.root, self.record, self.supervisor = args, root, record, supervisor
        self.concrete_job = self.resident_job = None
        self.shutting_down = False
        attempts = record.setdefault("attempts", [])
        self.log = root / "logs" / f"attempt-{len(attempts):05d}"
        self.log.mkdir(mode=0o700, parents=True)
        self.attempt: dict = {"started_at": time.time(), "logs": str(self.log), "stages": []}
        attempts.append(self.attempt)
        record.update(status="running", exit_code=None)
        for key in ("error", "cleanup_error", "synthesis", "synthesis_result"):
            record.pop(key, None)
        self.persist()

    def persist(self):
        self.record["updated_at"] = time.time()
        _save(self.root, self.record)

    def _start(self, name, command, *, cwd=None, structured=True):
        self.supervisor.check()
        print(f"[{name}] logs: {self.log / name}", file=sys.stderr, flush=True)
        stdout = self.log / (name + (".json" if structured else ".log"))
        stderr = self.log / (name + ".stderr.log") if structured else stdout
        stage = {"name": name, "started_at": time.time(), "stdout": str(stdout),
                 "stderr": str(stderr), "status": "running"}
        self.attempt["stages"].append(stage)
        self.persist()
        job = self.supervisor.start(command, cwd=cwd, stdout=stdout, stderr=stderr, name=name)
        stage["pid"] = job.pid
        self.persist()
        return job

    def _finish(self, job, code):
        stage = next(item for item in reversed(self.attempt["stages"]) if item["name"] == job.name)
        if stage["status"] == "running":
            stage.update(exit_code=code, ended_at=time.time(), status="finished")
            self.persist()
        return code

    def health(self):
        self.supervisor.check()
        if self.concrete_job is not None:
            code = self.concrete_job.poll()
            if code is not None:
                self._finish(self.concrete_job, code)
                self.concrete_job = None
                if code != 0:
                    raise StageFailure(f"concrete producer failed (exit {code}); see {self.log}")
        if self.resident_job is not None and not self.shutting_down:
            code = self.resident_job.poll()
            if code is not None:
                self._finish(self.resident_job, code)
                raise StageFailure(f"resident producer exited before shutdown (exit {code}); see {self.log}")

    def stage(self, name, command, *, accepted=(0,), timeout=None, cwd=None, structured=True):
        job = self._start(name, command, cwd=cwd, structured=structured)
        code = self.supervisor.wait(job, timeout=self.args.stage_timeout if timeout is None else timeout,
                                    tick=self.health)
        self._finish(job, code)
        self.health()
        if code not in accepted:
            raise StageFailure(f"{name} failed (exit {code}); see {self.log}")
        return code

    def resolve_rea(self) -> str:
        rea = self.args.rea or os.environ.get("TAOSC_LLM_REA")
        if not rea:
            package = Path(__file__).absolute().parents[2]
            recipe = package / "static-runtime.scm"
            if not recipe.is_file() or not shutil.which("guix"):
                raise ValueError("pass --rea or set TAOSC_LLM_REA; no installed pinned REA runtime available")
            self.stage("resolve-rea", ["guix", "package", f"--profile={package / '.guix-rea'}",
                                      f"--install-from-file={recipe}"], structured=False)
            rea = str(package / ".guix-rea" / "bin" / "rea")
        executable = shutil.which(rea)
        if executable is None:
            raise ValueError(f"REA executable not found: {rea}")
        return os.path.abspath(executable)

    def prepare(self) -> Path | None:
        args = self.args
        concrete = args.concrete_run or self.root / "concrete"
        mutation = None if args.concrete_only else args.binradar_run or self.root / "binradar"
        self.record["sources"] = {"concrete_run": str(concrete),
                                  "binradar_run": str(mutation) if mutation else None,
                                  "owns_concrete": args.concrete_run is None,
                                  "owns_binradar": mutation is not None and args.binradar_run is None}
        rea = self.resolve_rea() if args.stop_after != "generation" else None
        if args.concrete_run is None:
            self.stage("prepare-concrete", _python("binradar.binradar_setup", "--generate-concrete",
                                                   "-c", args.subject, "-w", args.workdir), structured=False)
        # A concrete-only search still needs .brcached. Never rewrite a supplied
        # mutation run's artifact/environment identity, nor concrete reuse metadata.
        if args.binradar_run is None and (mutation is not None or args.stop_after != "generation"):
            self.stage("prepare-cached", _python("binradar.binradar_setup", "--generate-binradar",
                                                 "-c", args.subject, "-w", args.workdir), structured=False)
        if args.concrete_run is None:
            self.concrete_job = self._start("concrete", _python(
                "binradar.cli", "-w", args.workdir, "--output", concrete,
                "--generate-concrete", "--timeout", args.generation_timeout),
                cwd=args.subject, structured=False)
        if mutation is not None and args.binradar_run is None:
            self.resident_job = self._start("binradar", _python(
                "binradar.cli", "-w", args.workdir, "--output", mutation,
                "--generate-binradar", "--replay-server", "--timeout", args.generation_timeout),
                cwd=args.subject, structured=False)
            args.replay_socket = mutation / "replay.sock"
        self.record["replay_socket"] = str(args.replay_socket) if args.replay_socket else None
        self.persist()
        if args.replay_socket is not None:
            command = _python("taosc_llm.replay", "wait", "--socket", args.replay_socket,
                              "--timeout", args.ready_timeout)
            if self.resident_job is not None:
                command.extend(("--pid", str(self.resident_job.pid)))
            self.stage("ready", command, timeout=args.ready_timeout)
        if self.concrete_job is not None:
            job = self.concrete_job
            code = self.supervisor.wait(job, timeout=args.stage_timeout, tick=self.health)
            self._finish(job, code)
            self.health()
        manifest = concrete / "minimizer.sbsv"
        if not manifest.is_file() or not manifest.stat().st_size:
            raise StageFailure(f"concrete run has no admitted producer manifest: {manifest}")
        self.health()
        if args.stop_after == "generation":
            return None
        dataset = self.root / "dataset"
        command = _cli("setup_main", "--config", args.subject / "config.env", "--workdir", args.workdir,
                       "--concrete-run", concrete, "--output", dataset, "--rea", rea,
                       "--analysis-timeout", args.analysis_timeout,
                       "--analysis-query-timeout", args.analysis_query_timeout)
        if mutation is not None:
            command.extend(("--binradar-run", str(mutation)))
        self.stage("dataset", command)
        return dataset

    def synthesize(self, dataset: Path) -> int:
        args = self.args
        command = _python("taosc_llm.no_llm" if args.mode == "no-llm" else "taosc_llm",
                          "--dataset", dataset, "--output", self.root / "result",
                          "--cache-dir", self.root / "cache", "--execution-workers", args.execution_workers)
        if args.replay_socket is not None:
            command.extend(("--replay-socket", str(args.replay_socket)))
        if args.mode == "no-llm":
            for name in _SEARCH_OPTIONS:
                flag = "--timeout" if name == "search_timeout" else "--" + name.replace("_", "-")
                command.extend((flag, str(getattr(args, name))))
            if args.resume:
                command.append("--resume")
        elif args.mode == "manual":
            command.extend(("--predicate", args.predicate))
        else:
            command.extend(("--provider-env", str(args.provider_env), "--max-rounds", str(args.max_rounds)))
            if args.pi_sdk_root is not None:
                command.extend(("--pi-sdk-root", str(args.pi_sdk_root)))
            if args.session_feedback:
                command.append("--session-feedback")
        code = self.stage("synthesis", command, accepted=(0, 2, 3))
        output = self.log / "synthesis.json"
        result = _read_json(output)
        self.record["synthesis_result"] = str(output)
        self.record["result_directory"] = str(self.root / "result")
        self.record["synthesis"] = {key: result[key] for key in (
            "status", "termination", "coverage", "predicate", "publication_status", "budgets", "result_record")
                                   if key in result}
        return code

    def execute(self) -> int:
        args = self.args
        dataset = args.dataset if args.dataset is not None else self.prepare()
        if dataset is None:
            return 0
        self.record["dataset"] = str(dataset)
        self.record["replay_socket"] = str(args.replay_socket) if args.replay_socket else None
        self.persist()
        if args.stop_after == "dataset":
            return 0
        if not args.resume:
            code = self.stage("warm", _cli("evaluate_main", "--dataset", dataset, "--warm",
                                           "--workers", args.execution_workers, "--cache-dir", self.root / "cache"),
                              accepted=(0, 2, 3))
            if args.stop_after == "warm":
                return code
        return self.synthesize(dataset)

    def shutdown(self):
        """Only the producer launched by this invocation is ours to shut down."""
        if self.resident_job is None or self.supervisor.interrupted:
            return
        self.shutting_down = True
        self.stage("shutdown", _python("taosc_llm.replay", "shutdown", "--socket", self.args.replay_socket),
                   timeout=min(self.args.graceful_timeout, 5))
        code = self.supervisor.wait(self.resident_job, timeout=self.args.graceful_timeout)
        self._finish(self.resident_job, code)
        if code != 0:
            raise StageFailure(f"resident shutdown exited {code}; see {self.log}")
        self.resident_job = None


def _execute(args, root, record, *, held_fds=()) -> int:
    experiment = None
    code = 1
    try:
        with ExitStack() as lifetime:
            if args.dataset is None and not args.resume:
                # Hold the inode lock until every owned producer is reaped,
                # including cleanup after exceptions and interruption.
                descriptor = lifetime.enter_context(_directory_lock(args.workdir, nofollow=False))
                held_fds = (*held_fds, descriptor)
            supervisor = lifetime.enter_context(Supervisor(args.graceful_timeout, held_fds=held_fds))
            experiment = Experiment(args, root, record, supervisor)
            try:
                code = experiment.execute()
            finally:
                prior_error = sys.exc_info()[0] is not None
                try:
                    experiment.shutdown()
                except (OSError, ValueError, RuntimeError) as error:
                    if not prior_error:
                        raise
                    print(f"[cleanup] {error}", file=sys.stderr)
        record["status"] = "finished" if code == 0 else "scoped-result"
    except RunnerInterrupted as error:
        code = error.exit_code
        record.update(status="interrupted", error=str(error))
    except RunnerTimeout as error:
        code = 124
        record.update(status="timed-out", error=str(error))
    except (OSError, ValueError, RuntimeError) as error:
        code = 1
        record.update(status="failed", error=str(error))
    except KeyboardInterrupt:
        code = 130
        record.update(status="interrupted", error="interrupted")
    record["exit_code"] = code
    record["updated_at"] = time.time()
    if experiment is not None:
        if experiment.supervisor.cleanup_error:
            record["cleanup_error"] = experiment.supervisor.cleanup_error
        experiment.attempt.update(ended_at=time.time(), exit_code=code, status=record["status"])
        for key in ("error", "cleanup_error"):
            if key in record:
                experiment.attempt[key] = record[key]
        for stage in experiment.attempt["stages"]:
            if stage["status"] == "running":
                stage.update(status=record["status"], ended_at=time.time())
    _save(root, record)
    return code


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        skipped = _preflight(args)
        if skipped:
            print(json.dumps({"engine": "taosc-llm-run", "status": "skipped", "reason": skipped,
                              "verified": False, "binradar_verification": "not_run"}))
            return 0
        root = allocate_run(args)
        with _directory_lock(root) as run_lock:
            record = _resume_record(root, args) if args.resume else {
                "schema_version": 1, "engine": "taosc-llm-run", "mode": args.mode,
                "run_directory": str(root), "options": _options(args), "created_at": time.time(),
                "verified": False, "binradar_verification": "not_run"}
            code = _execute(args, root, record, held_fds=(run_lock,))
            print(json.dumps(record, sort_keys=True))
            return code
    except (OSError, ValueError, RuntimeError) as error:
        print(f"taosc-llm-run: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
