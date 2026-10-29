"""Real E9 proof on a harmless return-code fixture, not a vulnerable benchmark."""

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile
from taosc_llm.builder import generate_patch
from taosc_llm.context import prepare_context
from taosc_llm.fixture import prepare_fixture
from taosc_llm.native import run_native
from taosc_llm.synthesis import _build

ASSEMBLY = """\
.text
.globl main
.type main, @function
main:
    push %rbp
    mov %rsp, %rbp
    movslq %edi, %rax
    sub $2, %rax
.globl patch_site
patch_site:
    mov $17, %eax
    leave
    ret
.globl error_handler
error_handler:
    mov $23, %eax
    leave
    ret
.size main, .-main
.section .note.GNU-stack,"",@progbits
"""


def require_native_tools() -> str:
    for name in ("E9TOOL", "E9COMPILE"):
        value = os.environ.get(name)
        if not value or shutil.which(value) is None:
            pytest.skip(
                "real native integration requires explicit executable E9TOOL and E9COMPILE"
            )
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.skip("real native integration requires gcc")
    return gcc


def symbol_addresses(binary: Path) -> dict[str, int]:
    with binary.open("rb") as stream:
        symbols = ELFFile(stream).get_section_by_name(".symtab")
        assert symbols is not None, "gcc fixture must retain its symbol table"
        return {
            name: symbols.get_symbol_by_name(name)[0]["st_value"]
            for name in ("patch_site", "error_handler")
        }


def returncode(binary: Path, argument_count: int, patch_id: str | None) -> int:
    env = os.environ.copy()
    for name in ("PATCH_ID", "PATCH_FD", "PATCH_CACHED_FD"):
        env.pop(name, None)
    if patch_id is not None:
        env["PATCH_ID"] = patch_id
    return subprocess.run(
        [str(binary), *(["argument"] * argument_count)],
        env=env,
        cwd=binary.parent,
        capture_output=True,
        timeout=5,
        check=False,
    ).returncode


@pytest.mark.parametrize("link_mode", ["-no-pie", "-pie"])
def test_real_fixed_and_selected_patch_semantics(tmp_path, link_mode):
    gcc = require_native_tools()
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    source = tmp_path / "fixture.S"
    source.write_text(ASSEMBLY)
    original = workdir / "fixture.orig"
    subprocess.run(
        [gcc, link_mode, str(source), "-o", str(original)],
        capture_output=True,
        timeout=30,
        check=True,
    )
    original_bytes = original.read_bytes()
    addresses = symbol_addresses(original)
    (workdir / "patch-location").write_text(f"0x{addresses['patch_site']:x}\n")
    (workdir / "patch-destination").write_text(f"0x{addresses['error_handler']:x}\n")
    # The absent patch-format is a supported prepared-workdir input.
    config = tmp_path / "config.env"
    config.write_text("BINARY=fixture\n")
    result = generate_patch(config, workdir, "rax <= 0")

    assert result["status"] == "built"
    assert result["verified"] is False
    assert result["binradar_activation"] == {"PATCH_ID": "1"}
    assert original.read_bytes() == original_bytes
    assert not (workdir / "binradar.env").exists()
    artifacts = {Path(value) for value in result["artifacts"].values()}
    for suffix in ("patched", "brpatched"):
        binary = workdir / f"fixture.{suffix}"
        assert binary in artifacts
        assert binary.is_absolute()
        metadata = json.loads(Path(str(binary) + ".e9map.json").read_text())
        assert metadata["artifact-sha256"] == hashlib.sha256(binary.read_bytes()).hexdigest()
        assert metadata["original-sha256"] == hashlib.sha256(original_bytes).hexdigest()

    # argc is 1, 2, 3: signed rax at patch_site is -1, 0, +1.
    for argument_count, repaired in ((0, 23), (1, 23), (2, 17)):
        assert returncode(original, argument_count, None) == 17
        fixed = workdir / "fixture.patched"
        assert returncode(fixed, argument_count, None) == repaired
        assert returncode(fixed, argument_count, "0") == repaired
        selected = workdir / "fixture.brpatched"
        assert returncode(selected, argument_count, None) == 17
        assert returncode(selected, argument_count, "0") == 17
        assert returncode(selected, argument_count, "1") == repaired

    assert original.read_bytes() == original_bytes


def test_fresh_build_worker_preserves_runtime_dependency_closure(tmp_path):
    require_native_tools()
    prepared = prepare_fixture(tmp_path / "caller")
    context = prepare_context(prepared["config"], prepared["workdir"], prepared["context"])
    built = asyncio.run(_build(context, {"jump_if": "rax <= 0"}, tmp_path / "candidate"))
    scratch = tmp_path / "execution"
    scratch.mkdir()
    fixed = built["artifacts"]["fixture.patched"]
    # This crosses the fresh Python process and real native build boundaries.
    # Guix must resolve dependencies outside the interpreter's own site-packages.
    for value, expected in (("-1", 23), ("1", 17)):
        result = run_native([fixed, value], scratch, timeout=5, check=False)
        assert result.returncode == expected
