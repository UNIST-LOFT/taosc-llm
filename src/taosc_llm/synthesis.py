"""Immutable-context proposal, then isolated native build; no repair verdict."""

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
    """Publish one complete private record, not a partially written success."""
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


async def _build(context: SynthesisContext, proposal: dict, candidate: Path) -> dict:
    import binradar
    from binradar import paths

    context.verify_artifacts()
    candidate.mkdir(mode=0o700, parents=True)
    original = candidate / f"{context.binary}.orig"
    shutil.copyfile(context.original_path, original)
    original.chmod(0o500)
    if hashlib.sha256(original.read_bytes()).hexdigest() != context.manifest["artifacts"]["original_sha256"]:
        raise ValueError("candidate original does not match frozen context")
    config = candidate / "config.env"
    # No provider/target environment or unrelated workdir files are copied.
    config.write_text(f"BINARY={context.binary}\n", encoding="utf-8")
    patch = context.manifest["patch"]
    (candidate / "patch-location").write_text(f"{int(patch['location'], 16):x}\n")
    (candidate / "patch-destination").write_text(f"{int(patch['destination'], 16):x}\n")
    (candidate / "patch-format").write_text("ERM generic\n")
    environment = native_environment()
    environment.update(E9TOOL=paths.e9tool(), E9COMPILE=paths.e9compile())
    # Guix dependencies occupy separate site-packages roots. Preserve this
    # trusted runtime's resolved import roots, never its environment or cwd.
    # The fresh worker still contains no provider credential.
    import_roots = list(dict.fromkeys([
        str(Path(__file__).resolve().parent.parent),
        str(Path(binradar.__file__).resolve().parent.parent),
        *(str(Path(path).resolve()) for path in sys.path if path and Path(path).is_absolute()),
    ]))
    bootstrap = ("import json,sys; sys.path[:0]=json.loads(sys.argv[1]); "
                 "from taosc_llm.cli import main; raise SystemExit(main(sys.argv[2:]))")
    argv = [sys.executable, "-I", "-c", bootstrap, json.dumps(import_roots),
            "--config", str(config), "--workdir", str(candidate),
            "--predicate", proposal["jump_if"], "--isolate-native"]
    process = await asyncio.create_subprocess_exec(*argv, cwd=candidate, env=environment,
                                                  stdout=asyncio.subprocess.PIPE,
                                                  stderr=asyncio.subprocess.PIPE,
                                                  start_new_session=True)
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=1800)
    except BaseException:
        from .bridge import _kill
        await _kill(process)
        raise
    (candidate.parent / "build.log").write_bytes(stderr[:65536])
    if process.returncode:
        raise RuntimeError("isolated candidate build failed; see build.log")
    result = json.loads(stdout)
    if result.get("status") != "built" or result.get("verified") is not False:
        raise RuntimeError("unexpected native builder result")
    context.verify_artifacts()
    if hashlib.sha256(original.read_bytes()).hexdigest() != context.manifest["artifacts"]["original_sha256"]:
        raise ValueError("native build changed its original input")
    result["original_sha256"] = context.manifest["artifacts"]["original_sha256"]
    result["artifact_hashes"] = {name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                                 for name, path in result["artifacts"].items()}
    result["native_isolation"] = "linux-landlock-seccomp"
    return result


async def synthesize_context(context: SynthesisContext, provider: ProviderConfig,
                             owner: QuotaOwner, *, sdk_root: Path | None = None) -> dict:
    """May be gathered across prepared contexts under ONE shared QuotaOwner."""
    if owner.config != provider:
        raise ValueError("provider must match quota owner")
    command = adapter_command(sdk_root)
    context.verify_artifacts()
    root = context.workdir / "taosc-llm" / "runs"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex
    run_dir = root / run_id
    run_dir.mkdir(mode=0o700)
    trials = run_dir / "trials"
    trials.mkdir(mode=0o700)
    result = {"schema_version": 1, "run_id": run_id, "context_id": context.context_id,
              "run_directory": str(run_dir), "status": "prepared", "verified": False,
              "provider": provider.public_dict(), "capability_scope": "client bounds; no advertised maximum claim",
              "binradar_verification": "not_run", "attempts": []}
    # Store only the disclosed projection, not arbitrary config contents.
    write_record(run_dir / "context.json", context.projection)
    write_record(run_dir / "run.json", result)
    try:
        async with owner.reserve() as reservation:
            result.update(status="model_running", reservation_id=reservation.identifier)
            write_record(run_dir / "run.json", result)
            settlement = {"remote_settled": True}
            try:
                # Only 429 is retried, sequentially and within the same reservation.
                # There is no second Pi/provider retry loop or financial budget.
                for attempt in range(3):
                    terminal = await run_adapter(context, provider, command, run_id,
                                                 trials / f"{attempt + 1}.jsonl", settlement)
                    summary = {key: value for key, value in terminal.items() if key != "final_text"}
                    result["attempts"].append(summary)
                    write_record(run_dir / "run.json", result)
                    if terminal["type"] == "turn_complete":
                        break
                    delay = terminal.get("retry_after_seconds")
                    if (terminal.get("http_status") != 429 or not settlement["remote_settled"]
                            or attempt == 2 or not isinstance(delay, (int, float))
                            or isinstance(delay, bool) or not 0 <= delay <= provider.timeout_seconds):
                        raise RuntimeError("Pi operation failed: " + terminal["error_code"])
                    await asyncio.sleep(delay)
                else:
                    raise RuntimeError("Pi retry policy exhausted")
            finally:
                if settlement["remote_settled"]:
                    reservation.settle()
        # No model/provider process or quota reservation remains during native work.
        (trials / "final.txt").write_text(terminal["final_text"], encoding="utf-8")
        try:
            proposal = context.validate_proposal(terminal["final_text"])
            if proposal["decision"] == "candidate" and (
                    not terminal["host_inspected_context"]
                    or proposal["jump_if"] not in terminal["host_checked_predicates"]):
                raise ValueError("candidate requires context inspection and exact predicate check")
        except ValueError as error:
            result["proposal_error"] = str(error)
            result["status"] = "parse_rejected"
            write_record(run_dir / "run.json", result)
            return result
        result["proposal"] = proposal
        write_record(trials / "proposal.json", proposal)
        if proposal["decision"] == "abstain":
            result["status"] = "abstained"
        else:
            result["status"] = "proposed"
            write_record(run_dir / "run.json", result)
            candidate = run_dir / "candidates" / "1" / "build-workdir"
            result["build"] = await _build(context, proposal, candidate)
            write_record(candidate.parent / "build-result.json", result["build"])
            result["status"] = "built"
        write_record(run_dir / "run.json", result)
        return result
    except BaseException as error:
        result["status"] = "cancelled" if isinstance(error, (KeyboardInterrupt, asyncio.CancelledError)) else "infrastructure_error"
        result["error_type"] = type(error).__name__
        write_record(run_dir / "run.json", result)
        raise


def generate_with_pi(config: Path, workdir: Path, evidence: Path, provider_file: Path,
                     *, sdk_root: Path | None = None, base_url=None, model=None,
                     max_in_flight=None, workers=None) -> dict:
    provider = load_provider(provider_file, base_url=base_url, model=model,
                             max_in_flight=max_in_flight, workers=workers)
    context = prepare_context(config, workdir, evidence)
    with QuotaOwner(provider) as owner:
        return asyncio.run(synthesize_context(context, provider, owner, sdk_root=sdk_root))
