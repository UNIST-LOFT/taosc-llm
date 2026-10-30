"""Settled Pi rounds, isolated family builds and actual host evaluation feedback."""
import asyncio
import hashlib
import json
import os
import shutil
import sys
import uuid
from pathlib import Path
from tempfile import NamedTemporaryFile

from .admission import QuotaOwner
from .bridge import adapter_command, run_adapter
from .context import SynthesisContext, canonical, prepare_context
from .provider import ProviderConfig, load_provider, native_environment


def write_record(path: Path, value: object) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with NamedTemporaryFile(mode="wb", dir=path.parent, delete=False) as temporary:
        name = Path(temporary.name)
        try:
            temporary.write(canonical(value))
            temporary.flush()
            os.fsync(temporary.fileno())
        except BaseException:
            name.unlink(missing_ok=True)
            raise
    try:
        name.replace(path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        name.unlink(missing_ok=True)


async def _blocking(function, *args, **kwargs):
    """Do not orphan bounded host/native work on cancellation."""
    task = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        await task
        raise


async def _build(context: SynthesisContext, proposal: dict, candidate: Path) -> dict:
    import binradar
    from binradar import paths
    context.verify_artifacts()
    candidate.mkdir(mode=0o700, parents=True)
    dataset = context.dataset
    # Resolve only frozen metadata. No source run or arbitrary environment is copied.
    for name in (dataset.binary + ".orig", "patch-location", "patch-destination", "patch-format"):
        shutil.copyfile(dataset.artifact(name), candidate / name)
    if dataset.patch_format == "ERM CWE-805":
        shutil.copyfile(dataset.artifact("stack-size"), candidate / "stack-size")
        trace = candidate / "trace"
        trace.mkdir()
        for allocator in ("malloc", "calloc", "realloc"):
            for suffix in ("calls", "returns"):
                name = f"trace/{allocator}.{suffix}"
                if name in dataset.manifest["artifacts"]:
                    shutil.copyfile(dataset.artifact(name), candidate / name)
    original = candidate / (dataset.binary + ".orig")
    original.chmod(0o500)
    expected = hashlib.sha256(context.original_path.read_bytes()).hexdigest()
    config = candidate / "config.env"
    config.write_text(f"BINARY={dataset.binary}\n")
    environment = native_environment()
    environment.update(E9TOOL=paths.e9tool(), E9COMPILE=paths.e9compile())
    roots = list(dict.fromkeys([str(Path(__file__).resolve().parent.parent),
                              str(Path(binradar.__file__).resolve().parent.parent),
                              *(str(Path(p).resolve()) for p in sys.path if p and Path(p).is_absolute())]))
    bootstrap = ("import json,sys;from pathlib import Path;sys.path[:0]=json.loads(sys.argv[1]);"
                 "from taosc_llm.builder import generate_patch;from taosc_llm.native import build_command;"
                 "print(json.dumps(generate_patch(Path(sys.argv[2]),Path(sys.argv[3]),sys.argv[4],native_runner=build_command)))")
    process = await asyncio.create_subprocess_exec(sys.executable, "-I", "-c", bootstrap, json.dumps(roots),
        str(config), str(candidate), proposal["predicate"], cwd=candidate, env=environment,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=1800)
    except BaseException:
        from .bridge import _kill
        await _kill(process)
        raise
    (candidate.parent / "build.log").write_bytes(stderr[:65536])
    if process.returncode or len(stdout) > 1024 * 1024:
        raise RuntimeError("isolated candidate build failed; see private build.log")
    result = json.loads(stdout)
    if result.get("status") != "built" or result.get("verified") is not False:
        raise RuntimeError("unexpected native build result")
    context.verify_artifacts()
    if hashlib.sha256(original.read_bytes()).hexdigest() != expected:
        raise ValueError("build changed frozen original copy")
    result["original_sha256"] = expected
    result["artifact_hashes"] = {name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                                 for name, path in result["artifacts"].items()}
    result["native_isolation"] = "linux-landlock-seccomp"
    return result


async def _model_round(context, provider, owner, command, run_id, trials, attempts):
    async with owner.reserve() as reservation:
        settlement = {"remote_settled": True}
        try:
            for attempt in range(3):
                terminal = await run_adapter(context, provider, command, run_id,
                    trials / f"turn-{attempt + 1}.jsonl", settlement)
                attempts.append({k: v for k, v in terminal.items() if k != "final_text"})
                if terminal["type"] == "turn_complete":
                    return terminal
                delay = terminal.get("retry_after_seconds")
                if (terminal.get("http_status") != 429 or not settlement["remote_settled"] or attempt == 2
                        or not isinstance(delay, (int, float)) or isinstance(delay, bool)
                        or not 0 <= delay <= provider.timeout_seconds):
                    raise RuntimeError("Pi operation failed: " + terminal["error_code"])
                await asyncio.sleep(delay)
        finally:
            if settlement["remote_settled"]:
                reservation.settle()
    raise RuntimeError("Pi retry policy exhausted")


async def synthesize_context(context: SynthesisContext, provider: ProviderConfig,
                             owner: QuotaOwner, *, sdk_root: Path | None = None,
                             max_rounds: int = 4) -> dict:
    if owner.config != provider:
        raise ValueError("provider must match quota owner")
    if type(max_rounds) is not int or not 1 <= max_rounds <= 16:
        raise ValueError("max_rounds must be between 1 and 16")
    command = adapter_command(sdk_root)
    context.verify_artifacts()
    run_id = uuid.uuid4().hex
    run_dir = context.run_dir / run_id
    run_dir.mkdir(mode=0o700, parents=True)
    result = {"schema_version": 2, "run_id": run_id, "context_id": context.context_id,
              "dataset_id": context.dataset.dataset_id, "run_directory": str(run_dir),
              "status": "prepared", "verified": False, "provider": provider.public_dict(),
              "binradar_verification": "not_run", "attempts": [], "rounds": []}
    feedback = []
    prior_results = {}
    write_record(run_dir / "context.json", context.projection)
    try:
        for index in range(max_rounds):
            trials = run_dir / "trials" / str(index + 1)
            trials.mkdir(mode=0o700, parents=True)
            current = prepare_context(context.dataset, run_dir=run_dir, workers=context.workers, feedback=feedback)
            current._results.update(prior_results)
            terminal = await _model_round(current, provider, owner, command, run_id, trials, result["attempts"])
            prior_results.update(current._results)
            (trials / "final.txt").write_text(terminal["final_text"])
            round_result: dict = {"round": index + 1, "final_text": terminal["final_text"]}
            result["rounds"].append(round_result)
            try:
                proposal = current.validate_proposal(terminal["final_text"])
                if proposal["decision"] == "candidate" and (not terminal["host_inspected_context"]
                        or proposal["predicate"] not in terminal["host_checked_predicates"]):
                    raise ValueError("candidate requires context inspection and exact predicate evaluation")
            except ValueError as error:
                round_result.update(status="parse_rejected", reason=str(error))
            else:
                round_result["proposal"] = proposal
                result["proposal"] = proposal
                if proposal["decision"] == "abstain":
                    round_result["status"] = result["status"] = "abstained"
                    write_record(run_dir / "run.json", result)
                    return result
                candidate = run_dir / "candidates" / str(index + 1) / "build-workdir"
                try:
                    build = await _build(current, proposal, candidate)
                except (ValueError, RuntimeError, OSError) as error:
                    round_result.update(status="build_rejected", reason=str(error))
                else:
                    round_result["build"] = build
                    write_record(candidate.parent / "build-result.json", build)
                    from .evaluation import evaluate_dataset
                    evaluation = await _blocking(evaluate_dataset, current.dataset, proposal["predicate"],
                        workers=current.workers, execute=True, cache_dir=current.run_dir / "cache")
                    write_record(candidate.parent / "evaluation.json", evaluation)
                    result_id = hashlib.sha256(canonical(evaluation)).hexdigest()
                    prior_results[result_id] = evaluation
                    round_result["result_id"] = result_id
                    round_result["evaluation"] = evaluation
                    round_result["status"] = evaluation["status"]
                    if evaluation["status"] != "reject_same_crash":
                        result.update(status=evaluation["status"], build=build, evaluation=evaluation)
                        write_record(run_dir / "run.json", result)
                        return result
            # Preserve exact candidate/settled output and actual results, not a fabricated verifier verdict.
            from .tools import _public
            feedback.append({"round": index + 1, "final_text": terminal["final_text"],
                             "status": round_result["status"], "reason": round_result.get("reason"),
                             "evaluation": _public(round_result["evaluation"]) if "evaluation" in round_result else None,
                             "case_results": [_public(c) for c in round_result.get("evaluation", {}).get("cases", [])][:32],
                             "result_id": round_result.get("result_id"),
                             "candidate_reference": "candidate:" + str(index + 1)})
            result["status"] = "refinement_exhausted" if index + 1 == max_rounds else "refining"
            write_record(run_dir / "run.json", result)
        return result
    except BaseException as error:
        result["status"] = "cancelled" if isinstance(error, (KeyboardInterrupt, asyncio.CancelledError)) else "infrastructure_error"
        result["error_type"] = type(error).__name__
        write_record(run_dir / "run.json", result)
        raise


def generate_manual(dataset: Path, predicate: str, *, execution_workers=1, output: Path | None = None) -> dict:
    """Build and evaluate a host-provided family predicate without any model call."""
    from .family import parse_candidate
    context = prepare_context(dataset, run_dir=output, workers=execution_workers)
    parsed = parse_candidate(context.dataset.patch_format, predicate)
    run_dir = context.run_dir / uuid.uuid4().hex
    run_dir.mkdir(mode=0o700)

    async def generate():
        from .evaluation import evaluate_dataset
        result = {"schema_version": 2, "dataset_id": context.dataset.dataset_id,
                  "context_id": context.context_id, "predicate": parsed.expression,
                  "run_directory": str(run_dir), "status": "prepared", "verified": False,
                  "binradar_verification": "not_run"}
        write_record(run_dir / "context.json", context.projection)
        write_record(run_dir / "run.json", result)
        try:
            result["build"] = await _build(context, {"predicate": parsed.expression}, run_dir / "build-workdir")
            result["evaluation"] = await _blocking(evaluate_dataset, context.dataset, parsed.expression,
                workers=context.workers, execute=True, cache_dir=context.run_dir / "cache")
            result["status"] = result["evaluation"]["status"]
        except BaseException as error:
            result["status"] = "cancelled" if isinstance(error, (KeyboardInterrupt, asyncio.CancelledError)) else "infrastructure_error"
            result["error_type"] = type(error).__name__
            write_record(run_dir / "run.json", result)
            raise
        write_record(run_dir / "run.json", result)
        return result
    return asyncio.run(generate())


def generate_with_pi(dataset: Path, provider_file: Path, *, sdk_root=None, base_url=None,
                     model=None, max_in_flight=None, workers=None, execution_workers=1,
                     max_rounds=4, output: Path | None = None) -> dict:
    provider = load_provider(provider_file, base_url=base_url, model=model,
                             max_in_flight=max_in_flight, workers=workers)
    context = prepare_context(dataset, run_dir=output, workers=execution_workers)
    with QuotaOwner(provider) as owner:
        return asyncio.run(synthesize_context(context, provider, owner, sdk_root=sdk_root, max_rounds=max_rounds))
