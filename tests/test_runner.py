"""Public runner admission, evidence ownership and immutable resume boundaries."""

import json
import socket
import tempfile
from pathlib import Path

import pytest

from taosc_llm.runner import _directory_lock, main


def subject(tmp_path, patch_format="ERM generic"):
    directory = tmp_path / "subject"
    workdir = directory / "prepared"
    workdir.mkdir(parents=True)
    (directory / "config.env").write_text("BINARY=fixture\n")
    (workdir / "patch-location").write_text("401000\n")
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
