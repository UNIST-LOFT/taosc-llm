"""Consumer-visible validation and transactional publication guarantees."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile
from taosc_llm.builder import generate_patch

OUTPUTS = (
    "predicates",
    "fixture.patched",
    "fixture.patched.json",
    "fixture.patched.e9map.json",
    "fixture.brpatched",
    "fixture.brpatched.json",
    "fixture.brpatched.e9map.json",
    "brpatches.inc",
    "brpatch.c",
    "binradar.env",
)


def prepared_workdir(tmp_path: Path) -> tuple[Path, Path]:
    config = tmp_path / "config.env"
    config.write_text("BINARY=fixture\n")
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    original = workdir / "fixture.orig"
    shutil.copyfile(sys.executable, original)
    with original.open("rb") as stream:
        entry = ELFFile(stream).header["e_entry"]
    for name in ("patch-location", "patch-destination"):
        (workdir / name).write_text(f"0x{entry:x}\n")
    (workdir / "patch-format").write_text("ERM generic\n")
    for name in OUTPUTS:
        (workdir / name).write_bytes(f"previous {name}\n".encode())
    return config, workdir


def snapshot(workdir: Path) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in workdir.iterdir() if path.is_file()}


@pytest.mark.parametrize(
    "invalid",
    [
        "unsupported_family",
        "missing_format",
        "zero_destination",
        "missing_allocator",
        "missing_location",
        "malformed_destination",
        "empty_location",
        "missing_binary_setting",
        "missing_original",
        "malformed_guard",
    ],
)
def test_invalid_inputs_preserve_previous_artifacts(tmp_path, monkeypatch, invalid):
    config, workdir = prepared_workdir(tmp_path)
    guard = "rax <= 0"
    if invalid == "unsupported_family":
        (workdir / "patch-format").write_text("Single CWE-805\n")
    elif invalid == "missing_format":
        (workdir / "patch-format").unlink()
    elif invalid == "zero_destination":
        (workdir / "patch-destination").write_text("0\n")
    elif invalid == "missing_allocator":
        (workdir / "patch-format").write_text("ERM CWE-805\n")
        guard = "1 * s->rax < i->end - i->begin"
    elif invalid == "missing_location":
        (workdir / "patch-location").unlink()
    elif invalid == "malformed_destination":
        (workdir / "patch-destination").write_text("0x401000\n0x401010\n")
    elif invalid == "empty_location":
        (workdir / "patch-location").write_text("\n")
    elif invalid == "missing_binary_setting":
        config.write_text("OTHER=value\n")
    elif invalid == "missing_original":
        (workdir / "fixture.orig").unlink()
    elif invalid == "malformed_guard":
        guard = "rax <= 0; return 1"
    before = snapshot(workdir)
    config_before = config.read_bytes()

    def unexpected_native_process(*args, **kwargs):
        pytest.fail("invalid input must fail before invoking native tools")

    monkeypatch.setattr(subprocess, "Popen", unexpected_native_process)
    with pytest.raises((ValueError, OSError)):
        generate_patch(config, workdir, guard)

    assert snapshot(workdir) == before
    assert config.read_bytes() == config_before


@pytest.mark.parametrize("stack_size", ["7", "-1", "1048577", "unknown"])
def test_cwe805_stack_bounds_preserve_previous_artifacts(tmp_path, stack_size):
    config, workdir = prepared_workdir(tmp_path)
    (workdir / "patch-format").write_text("ERM CWE-805\n")
    (workdir / "stack-size").write_text(stack_size + "\n")
    trace = workdir / "trace"
    trace.mkdir()
    address = (workdir / "patch-location").read_text().strip().removeprefix("0x")
    (trace / "malloc.calls").write_text(f"0 {address}\n1 {address}\n")
    (trace / "malloc.returns").write_text(address + "\n")
    before = snapshot(workdir)

    def forbidden_runner(command, stage):
        pytest.fail("invalid stack access must be rejected before native work")

    with pytest.raises(ValueError):
        generate_patch(config, workdir,
                       "1 * ((uint32_t *)s->rsp)[1] < i->end - i->begin",
                       native_runner=forbidden_runner)
    assert snapshot(workdir) == before


def test_native_failure_preserves_previous_artifacts(tmp_path, monkeypatch):
    config, workdir = prepared_workdir(tmp_path)
    failing_tool = tmp_path / "fail-native"
    failing_tool.write_text(f"#!{sys.executable}\nraise SystemExit(47)\n")
    failing_tool.chmod(0o755)
    monkeypatch.setenv("E9TOOL", str(failing_tool))
    monkeypatch.setenv("E9COMPILE", str(failing_tool))
    before = snapshot(workdir)

    with pytest.raises((RuntimeError, subprocess.CalledProcessError)):
        generate_patch(config, workdir, "rax <= 0")

    assert snapshot(workdir) == before
