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
    (workdir / "patch-format").write_text("ERM generic\n")
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


CWE805_ASSEMBLY = """\
.text
.globl main
.type main, @function
main:
    push %rbp
    mov %rsp, %rbp
    sub $32, %rsp
    mov %edi, (%rsp)
.globl allocator_entry
allocator_entry:
    mov $32, %edi
.globl malloc_site
malloc_site:
    call malloc@PLT
.globl malloc_return
malloc_return:
    mov (%rsp), %edx
    sub $1, %edx
    add %rdx, %rax
    mov %rax, 8(%rsp)
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


@pytest.mark.parametrize("link_mode", ["-no-pie", "-pie"])
@pytest.mark.parametrize("predicate,safe_count,repair_count", [
    ("s->rax >= i->begin && s->rax < i->end", 0, 32),
    ("((uint64_t *)s->rsp)[1] >= i->begin && ((uint64_t *)s->rsp)[1] < i->end", 0, 32),
    ("1 * s->rdx < i->end - i->begin", 0, 32),
    ("1 * ((uint32_t *)s->rsp)[0] < i->end - i->begin", 0, 31),
])
def test_real_cwe805_clamps_and_typed_cells(tmp_path, link_mode, predicate, safe_count, repair_count):
    gcc = require_native_tools()
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    source = tmp_path / "fixture.S"
    source.write_text(CWE805_ASSEMBLY)
    original = workdir / "fixture.orig"
    subprocess.run([gcc, link_mode, str(source), "-o", str(original)],
                   capture_output=True, timeout=30, check=True)
    original_bytes = original.read_bytes()
    with original.open("rb") as stream:
        symbols = ELFFile(stream).get_section_by_name(".symtab")
        addresses = {name: symbols.get_symbol_by_name(name)[0]["st_value"]
                     for name in ("patch_site", "error_handler", "allocator_entry", "malloc_site", "malloc_return")}
    (workdir / "patch-location").write_text(f"{addresses['patch_site']:x}\n")
    (workdir / "patch-destination").write_text(f"{addresses['error_handler']:x}\n")
    (workdir / "patch-format").write_text("ERM CWE-805\n")
    (workdir / "stack-size").write_text("32\n")
    trace = workdir / "trace"
    trace.mkdir()
    (trace / "malloc.calls").write_text(f"0 {addresses['malloc_site']:x}\n1 {addresses['allocator_entry']:x}\n")
    (trace / "malloc.returns").write_text(f"{addresses['malloc_return']:x}\n")
    config = tmp_path / "config.env"
    config.write_text("BINARY=fixture\n")
    result = generate_patch(config, workdir, predicate)
    assert result["patch_format"] == "ERM CWE-805"
    for count, expected in ((safe_count, 17), (repair_count, 23)):
        assert returncode(original, count, None) == 17
        for selector in (None, "0", "1", "123456"):
            assert returncode(workdir / "fixture.patched", count, selector) == expected
        for selector in (None, "0"):
            assert returncode(workdir / "fixture.brpatched", count, selector) == 17
        assert returncode(workdir / "fixture.brpatched", count, "1") == expected
    for suffix in ("patched", "brpatched"):
        binary = workdir / f"fixture.{suffix}"
        metadata = json.loads(Path(str(binary) + ".e9map.json").read_text())
        assert metadata["artifact-sha256"] == hashlib.sha256(binary.read_bytes()).hexdigest()
        assert metadata["original-sha256"] == hashlib.sha256(original_bytes).hexdigest()
    assert original.read_bytes() == original_bytes


@pytest.mark.parametrize("predicate", ["1 / rax", "1 % rax"])
def test_real_fixed_and_selected_traps_follow_original(tmp_path, predicate):
    gcc = require_native_tools()
    source = tmp_path / "fixture.S"
    source.write_text(ASSEMBLY)
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    original = workdir / "fixture.orig"
    subprocess.run([gcc, "-no-pie", str(source), "-o", str(original)],
                   capture_output=True, timeout=30, check=True)
    addresses = symbol_addresses(original)
    (workdir / "patch-location").write_text(f"{addresses['patch_site']:x}\n")
    (workdir / "patch-destination").write_text(f"{addresses['error_handler']:x}\n")
    (workdir / "patch-format").write_text("ERM generic\n")
    config = tmp_path / "config.env"
    config.write_text("BINARY=fixture\n")
    generate_patch(config, workdir, predicate)
    for suffix in ("patched", "brpatched"):
        assert returncode(workdir / f"fixture.{suffix}", 1, "1") == 17


def test_fresh_build_worker_preserves_runtime_dependency_closure(tmp_path):
    require_native_tools()
    prepared = prepare_fixture(tmp_path / "caller")
    context = prepare_context(prepared["dataset"])
    built = asyncio.run(_build(context, {"predicate": "rax <= 0"}, tmp_path / "candidate"))
    scratch = tmp_path / "execution"
    scratch.mkdir()
    fixed = built["artifacts"]["fixture.patched"]
    # This crosses the fresh Python process and real native build boundaries.
    # Guix must resolve dependencies outside the interpreter's own site-packages.
    for value, expected in (("-1", 23), ("1", 17)):
        result = run_native([fixed, value], scratch, timeout=5, check=False)
        assert result.returncode == expected
