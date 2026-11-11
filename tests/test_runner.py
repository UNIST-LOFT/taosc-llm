"""Public runner admission, evidence ownership and immutable resume boundaries."""

import json
import socket
import sys
import tempfile
from pathlib import Path

import pytest

from taosc_llm.runner import _directory_lock, main


@pytest.fixture
def child_contract(tmp_path, monkeypatch):
    from taosc_llm import runner
    warm = {"status": "reject_same_crash", "predicate": None, "verified": False,
            "quality": {"status": "rejected"}, "summary": {"reject_same_crash": 1}}
    synthesis = {"schema_version": 1, "engine": "taosc-llm-no-llm",
                 "termination": "evidence-unavailable", "predicate": None, "coverage": "partial",
                 "publication_status": "unavailable", "verified": False,
                 "binradar_verification": "not_run", "score": {"target_failures": ["system:0"]},
                 "population": {"unresolved": ["system:0"]}}
    contract = {"warm": warm, "synthesis": synthesis, "warm_code": 0, "synthesis_code": 0}
    def command(stage):
        payload = contract[stage]
        text = json.dumps(payload) if not isinstance(payload, str) else payload
        return [sys.executable, "-c", f"print({text!r}); raise SystemExit({contract[stage + '_code']})"]
    monkeypatch.setattr(runner, "_preflight", lambda args: None)
    monkeypatch.setattr(runner, "_cli", lambda entry, *args: command("warm"))
    monkeypatch.setattr(runner, "_python", lambda module, *args: command("synthesis"))
    contract["arguments"] = ["--dataset", str(tmp_path / "dataset"), "--output", str(tmp_path / "run")]
    return contract


@pytest.mark.parametrize("mode", ["no-llm", "manual", "provider"])
@pytest.mark.parametrize("outcome", ["residual", "no-candidate", "bounded-stop"])
def test_runner_records_completed_scoped_outcomes_without_quality_exit(
        tmp_path, capsys, child_contract, mode, outcome):
    result = child_contract["synthesis"]
    if mode != "no-llm":
        result.update(status={"residual": "rejected", "no-candidate": "abstained",
                              "bounded-stop": "refinement_exhausted"}[outcome],
                      quality={"status": "unproven", "counts": {"other_crash": 1}})
    else:
        result["termination"] = {"residual": "bounded-search-exhausted", "no-candidate": "no-target-cases",
                                 "bounded-stop": "wall-time-reached"}[outcome]
    arguments = child_contract["arguments"] + ["--mode", mode]
    if mode == "manual":
        arguments += ["--predicate", "rax != 0"]
    elif mode == "provider":
        arguments += ["--provider-env", str(tmp_path / "provider.env")]
    assert main(arguments) == 0
    record = json.loads(capsys.readouterr().out)
    assert record["status"] == "finished" and record["exit_code"] == 0
    assert record["attempts"][-1]["status"] == "finished"
    assert record["warm"]["status"] == "reject_same_crash"
    assert record["warm"]["quality"]["status"] == "rejected"
    assert record["synthesis"]["score"] == result["score"]
    assert record["synthesis"]["publication_status"] == "unavailable"
    assert record["synthesis"]["verified"] is False
    assert record["synthesis"]["binradar_verification"] == "not_run"
    assert json.loads(Path(record["synthesis_result"]).read_text()) == result
    assert json.loads((tmp_path / "run" / "run.json").read_text()) == record


@pytest.mark.parametrize("stage", ["warm", "synthesis"])
@pytest.mark.parametrize("code,expected,status", [
    (1, 1, "failed"), (2, 1, "failed"), (3, 1, "failed"), (130, 130, "interrupted"),
])
def test_runner_requires_current_child_exit_contract(capsys, child_contract, stage, code, expected, status):
    child_contract[stage + "_code"] = code
    assert main(child_contract["arguments"]) == expected
    record = json.loads(capsys.readouterr().out)
    assert record["status"] == status and record["exit_code"] == expected
    assert record["attempts"][-1]["stages"][-1]["exit_code"] == code
    assert "synthesis" not in record


@pytest.mark.parametrize("stage", ["warm", "synthesis"])
@pytest.mark.parametrize("invalid", ["empty", "malformed", "verified", "nonterminal"])
def test_runner_zero_exit_does_not_establish_scoped_completion(capsys, child_contract, stage, invalid):
    result = child_contract[stage]
    if invalid == "empty":
        child_contract[stage] = {}
    elif invalid == "malformed":
        child_contract[stage] = "not json"
    elif invalid == "verified":
        result["verified"] = True
    elif stage == "warm":
        result["status"] = "infrastructure_error"
    else:
        result["termination"] = "interrupted"
    assert main(child_contract["arguments"]) == 1
    record = json.loads(capsys.readouterr().out)
    assert record["status"] == "failed"
    assert "synthesis" not in record


@pytest.mark.parametrize("status", ["prepared", "refining", "infrastructure_error", "cancelled"])
def test_runner_zero_provider_exit_requires_completed_status(tmp_path, capsys, child_contract, status):
    child_contract["synthesis"].update(status=status)
    assert main(child_contract["arguments"] + [
        "--mode", "provider", "--provider-env", str(tmp_path / "provider.env")]) == 1
    record = json.loads(capsys.readouterr().out)
    assert record["status"] == "failed"
    assert "synthesis" not in record


@pytest.mark.parametrize("status", ["reject_same_crash", "not_rejected", "unavailable"])
def test_runner_warm_boundary_is_completed_evaluation(capsys, child_contract, status):
    child_contract["warm"]["status"] = status
    assert main(child_contract["arguments"] + ["--stop-after", "warm"]) == 0
    record = json.loads(capsys.readouterr().out)
    assert record["status"] == "finished"
    assert record["warm"] == child_contract["warm"]
    assert "synthesis" not in record
    assert [stage["name"] for stage in record["attempts"][-1]["stages"]] == ["warm"]


def subject(tmp_path, patch_format="ERM generic"):
    directory = tmp_path / "subject"
    workdir = directory / "prepared"
    workdir.mkdir(parents=True)
    (directory / "config.env").write_text("BINARY=fixture\nTEST_CMD=@@\nPOC_INPUT=poc/input\nPOC_DIR=poc\n")
    (directory / "poc").mkdir()
    (directory / "poc/input").write_bytes(b"fixture")
    (workdir / "patch-location").write_text("401000\n")
    (workdir / "patch-destination").write_text("401010\n")
    if patch_format is not None:
        (workdir / "patch-format").write_text(patch_format)
    return directory, workdir


def arguments(directory, workdir, output):
    return ["--subject", str(directory), "--workdir", str(workdir), "--output", str(output)]


@pytest.mark.parametrize("patch_format", ["Single CWE-805", "unknown", "  ERM CWE-119 \n"])
def test_unsupported_family_skips_before_dependencies_or_output(tmp_path, monkeypatch, capsys, patch_format):
    directory, workdir = subject(tmp_path, patch_format)
    (workdir / "patch-location").unlink()
    output = tmp_path / "result"
    monkeypatch.setenv("PATH", "")
    monkeypatch.delenv("TAOSC_LLM_REA", raising=False)
    code = main(arguments(directory, workdir, output))
    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "skipped" and not result["verified"]
    assert not output.exists()


@pytest.mark.parametrize("format_kind", ["empty", "missing", "directory", "dangling"])
def test_invalid_workdir_metadata_never_falls_back_or_allocates(tmp_path, capsys, format_kind):
    directory, workdir = subject(tmp_path, None)
    (directory / "patch-format").write_text("ERM generic")
    path = workdir / "patch-format"
    if format_kind == "empty":
        path.write_text(" \n\t")
    elif format_kind == "directory":
        path.mkdir()
    elif format_kind == "dangling":
        path.symlink_to("absent")
    else:
        (directory / "patch-format").unlink()
    output = tmp_path / "result"
    assert main(arguments(directory, workdir, output)) == 1
    assert not output.exists()
    assert "taosc-llm-run:" in capsys.readouterr().err


def test_completed_concrete_reuse_preserves_source_and_needs_no_runtime(tmp_path, monkeypatch, capsys):
    directory, workdir = subject(tmp_path, "Single CWE-805")
    concrete = tmp_path / "concrete"
    concrete.mkdir()
    manifest = concrete / "minimizer.sbsv"
    manifest.write_bytes(b"completed producer evidence\n")
    before = manifest.stat()
    output = tmp_path / "result"
    monkeypatch.setenv("PATH", "")
    monkeypatch.delenv("TAOSC_LLM_REA", raising=False)
    args = arguments(directory, workdir, output) + [
        "--concrete-only", "--stop-after", "generation", "--concrete-run", str(concrete)]
    assert main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["sources"]["concrete_run"] == str(concrete)
    assert not result["sources"]["owns_concrete"]
    assert "dataset" not in result and not (output / "dataset").exists()
    assert not (output / "concrete").exists() and not (output / "binradar").exists()
    after = manifest.stat()
    assert (before.st_ino, before.st_mtime_ns, before.st_size) == (after.st_ino, after.st_mtime_ns, after.st_size)
    assert manifest.read_bytes() == b"completed producer evidence\n"
    saved = (output / "run.json").read_bytes()
    assert main(args) == 1
    assert (output / "run.json").read_bytes() == saved


def test_reused_mutation_endpoint_and_outputs_are_not_owned(tmp_path, capsys):
    directory, workdir = subject(tmp_path)
    concrete, mutation = tmp_path / "concrete", tmp_path / "mutation"
    concrete.mkdir()
    mutation.mkdir()
    (concrete / "minimizer.sbsv").write_text("retained evidence")
    (mutation / "binradar.br").write_bytes(b"retained mutations")
    endpoint = mutation / "replay.sock"
    output = tmp_path / "result"
    # No explicit --replay-socket: reuse is offline and must not contact, signal,
    # shut down or unlink this caller-owned endpoint.
    with tempfile.TemporaryDirectory(prefix="runner-peer-", dir="/tmp") as short, socket.socket(socket.AF_UNIX) as external:
        actual = Path(short) / "socket"
        external.bind(str(actual))
        endpoint.symlink_to(actual)
        external.listen()
        before = endpoint.lstat()
        assert main(arguments(directory, workdir, output) + [
            "--concrete-run", str(concrete), "--binradar-run", str(mutation),
            "--stop-after", "generation"]) == 0
        result = json.loads(capsys.readouterr().out)
        assert not result["sources"]["owns_binradar"]
        assert result["replay_socket"] is None
        assert endpoint.lstat().st_ino == before.st_ino
        assert (mutation / "binradar.br").read_bytes() == b"retained mutations"
        with socket.socket(socket.AF_UNIX) as client:
            client.connect(str(endpoint.resolve()))
            accepted, _ = external.accept()
            accepted.close()


def test_workdir_has_one_runner_owner_without_lock_file_mutation(tmp_path, capsys):
    directory, workdir = subject(tmp_path)
    concrete = tmp_path / "concrete"
    concrete.mkdir()
    (concrete / "minimizer.sbsv").write_text("retained")
    before = {path.name: path.read_bytes() for path in workdir.iterdir()}
    output = tmp_path / "result"
    with _directory_lock(workdir):
        assert main(arguments(directory, workdir, output) + [
            "--concrete-only", "--stop-after", "generation", "--concrete-run", str(concrete)]) == 1
    result = json.loads(capsys.readouterr().out)
    assert "another runner owns" in result["error"]
    assert {path.name: path.read_bytes() for path in workdir.iterdir()} == before


def test_resume_refuses_uninitialized_search_without_rewriting_run(tmp_path, capsys):
    output = tmp_path / "result"
    output.mkdir()
    record = {"schema_version": 1, "engine": "taosc-llm-run", "mode": "no-llm", "status": "interrupted"}
    summary = output / "run.json"
    summary.write_text(json.dumps(record))
    before = summary.read_bytes()
    assert main(["--output", str(output), "--resume"]) == 1
    assert "search was not initialized" in capsys.readouterr().err
    assert summary.read_bytes() == before
    assert not (output / "logs").exists()


@pytest.mark.parametrize("field,value", [
    ("patch-location", "0"), ("patch-destination", "0"),
    ("patch-destination", "10000000000000000"), ("patch-destination", "not-an-address"),
])
def test_invalid_address_fails_before_generation_or_output(tmp_path, capsys, field, value):
    directory, workdir = subject(tmp_path)
    (workdir / field).write_text(value)
    before = {path.name: path.read_bytes() for path in workdir.iterdir()}
    output = tmp_path / "result"
    assert main(arguments(directory, workdir, output)) == 1
    assert field in capsys.readouterr().err
    assert not output.exists()
    assert {path.name: path.read_bytes() for path in workdir.iterdir()} == before


def test_invalid_native_timeout_fails_before_generation(tmp_path, capsys):
    directory, workdir = subject(tmp_path)
    config = directory / "config.env"
    config.write_text(config.read_text() + "BINRADAR_QEMU_EXEC_TIMEOUT=nan\n")
    output = tmp_path / "result"
    assert main(arguments(directory, workdir, output)) == 1
    assert "BINRADAR_QEMU_EXEC_TIMEOUT" in capsys.readouterr().err
    assert not output.exists()


def test_invalid_provider_configuration_is_private_and_early(tmp_path, capsys):
    directory, workdir = subject(tmp_path)
    provider = tmp_path / "provider.env"
    secret = "private-fixture-secret-never-log"
    provider.write_text(f"OPENAI_API_KEY={secret}\nOPENAI_BASE_URL=http://unsafe.example/v1\nOPENAI_MODEL=x\n")
    output = tmp_path / "result"
    assert main(arguments(directory, workdir, output) + [
        "--mode", "provider", "--provider-env", str(provider)]) == 1
    diagnostic = capsys.readouterr()
    assert secret not in diagnostic.out + diagnostic.err
    assert "base_url" in diagnostic.err
    assert not output.exists()


def test_missing_sdk_fails_before_producers(tmp_path, monkeypatch, capsys):
    directory, workdir = subject(tmp_path)
    provider = tmp_path / "provider.env"
    provider.write_text("OPENAI_API_KEY=fixture-secret\nOPENAI_BASE_URL=https://ollama.com/v1\n"
                        "OPENAI_MODEL=deepseek-v4.1-flash:1017\n")
    monkeypatch.delenv("TAOSC_LLM_PI_SDK_ROOT", raising=False)
    output = tmp_path / "result"
    assert main(arguments(directory, workdir, output) + [
        "--mode", "provider", "--provider-env", str(provider)]) == 1
    assert "--pi-sdk-root" in capsys.readouterr().err
    assert not output.exists()


def test_missing_external_replay_fails_before_output(tmp_path, capsys):
    directory, workdir = subject(tmp_path)
    concrete, mutation = tmp_path / "concrete", tmp_path / "mutation"
    concrete.mkdir()
    mutation.mkdir()
    (concrete / "minimizer.sbsv").write_text("retained")
    (mutation / "binradar.br").write_bytes(b"retained")
    output = tmp_path / "result"
    assert main(arguments(directory, workdir, output) + [
        "--concrete-run", str(concrete), "--binradar-run", str(mutation),
        "--replay-socket", str(mutation / "replay.sock"), "--stop-after", "generation"]) == 1
    assert "replay" in capsys.readouterr().err
    assert not output.exists()


def test_invalid_manual_predicate_fails_before_producers(tmp_path, capsys):
    directory, workdir = subject(tmp_path)
    output = tmp_path / "result"
    assert main(arguments(directory, workdir, output) + ["--mode", "manual", "--predicate", "rax ==="]) == 1
    assert not output.exists()
    assert "taosc-llm-run:" in capsys.readouterr().err
