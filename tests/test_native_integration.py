"""Real E9 proof on a harmless return-code fixture, not a vulnerable benchmark."""

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

from binradar import binradar_setup, paths
from binradar.binradar_taosc_predicates import (
    PredicateFamily, parse_allocator_trace, parse_cached_snapshots,
)

import pytest
from elftools.elf.elffile import ELFFile
from taosc_llm.builder import generate_patch
from taosc_llm.dataset import load_dataset
from taosc_llm.fixture import prepare_fixture
from taosc_llm.native import run_native
from taosc_llm.publication import build_candidate, verify_built_candidate
from taosc_llm.evaluation import evaluate_dataset

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


def assert_native_action(binary, argument_count, patch_id, expected, branch, *,
                         descriptor=None, runtime_id=None):
    env = os.environ.copy()
    for name in ("PATCH_ID", "PATCH_FD", "PATCH_CACHED_FD", "TAOSC_PRED",
                 "BINRADAR_PATCH_SHM_KEY"):
        env.pop(name, None)
    if patch_id is not None:
        env["PATCH_ID"] = patch_id
    if descriptor is not None:
        env["TAOSC_PRED"] = descriptor
        env["BRCACHE_STACK_SIZE"] = "32"
    with tempfile.TemporaryFile() as text, tempfile.TemporaryFile() as raw:
        env["PATCH_FD"] = str(text.fileno())
        env["PATCH_CACHED_FD"] = str(raw.fileno())
        result = subprocess.run(
            [str(binary), *(["argument"] * argument_count)], env=env,
            cwd=binary.parent, pass_fds=(text.fileno(), raw.fileno()),
            capture_output=True, timeout=5, check=False)
        assert result.returncode == expected, result.stderr.decode(errors="replace")
        text.seek(0)
        selected_id = runtime_id if runtime_id is not None else int(patch_id or "0")
        assert text.read().decode().splitlines() == [
            f"[patch] [id {selected_id}] [br {branch}] [v 0]"]
        if descriptor is not None:
            raw.seek(0)
            snapshots, error = parse_cached_snapshots(raw.read())
            assert error is None
            assert [state.patch_id for state in snapshots] == [selected_id]
            assert [state.branch for state in snapshots] == [branch]


def build_cached_fixture(workdir, family):
    location = int((workdir / "patch-location").read_text().strip(), 16)
    settings = {"BINARY": "fixture", "PATCH_LOC": f"0x{location:x}"}
    metadata = binradar_setup.build_cached_binary(
        workdir, workdir, settings, family,
        parse_allocator_trace(workdir / "trace") if family == PredicateFamily.CWE805_ERM else None,
        persist_metadata=False)
    return metadata


@pytest.mark.parametrize("destination_zero", [False, True])
@pytest.mark.parametrize("link_mode", ["-no-pie", "-pie"])
@pytest.mark.parametrize("predicate", [
    "rax <= 0",
    "rax == 0 || (rax < 0 && 10 / rax < 0)",
    "rax <= 0 && (1 || 1 / 0)",
])
def test_real_fixed_and_selected_patch_semantics(tmp_path, link_mode, predicate, destination_zero):
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
    destination = 0 if destination_zero else addresses['error_handler']
    (workdir / "patch-destination").write_text(f"{destination:x}\n")
    (workdir / "patch-format").write_text("ERM generic\n")
    config = tmp_path / "config.env"
    config.write_text("BINARY=fixture\n")
    result = generate_patch(config, workdir, predicate)

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

    if destination_zero:
        build_cached_fixture(workdir, PredicateFamily.GENERIC_ERM)
    # argc is 1, 2, 3: signed rax at patch_site is -1, 0, +1.
    for argument_count, branch in ((0, 1), (1, 1), (2, 0)):
        repaired = (128 if destination_zero else 23) if branch else 17
        assert returncode(original, argument_count, None) == 17
        for selector in (None, "0", "1", "123456"):
            assert_native_action(workdir / "fixture.patched", argument_count,
                                 selector, repaired, branch, runtime_id=1)
        for selector in (None, "0"):
            assert_native_action(workdir / "fixture.brpatched", argument_count,
                                 selector, 17, 0)
        assert_native_action(workdir / "fixture.brpatched", argument_count,
                             "1", repaired, branch)
        if destination_zero:
            for descriptor, expected, taken in (("p0", 17, 0),
                                                 (result['descriptor'], repaired, branch)):
                assert_native_action(workdir / "fixture.brcached", argument_count,
                                     "0", expected, taken, descriptor=descriptor)

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


@pytest.mark.parametrize("destination_zero", [False, True])
@pytest.mark.parametrize("link_mode", ["-no-pie", "-pie"])
@pytest.mark.parametrize("predicate,safe_count,repair_count,repair_branch", [
    ("s->rax >= i->begin && s->rax < i->end", 0, 32, 1),
    ("((uint64_t *)s->rsp)[1] >= i->begin && ((uint64_t *)s->rsp)[1] < i->end", 0, 32, 1),
    ("1 * s->rdx < i->end - i->begin", 0, 32, 1),
    ("1 * ((uint32_t *)s->rsp)[0] < i->end - i->begin", 0, 31, 1),
    ("(s->rax >= i->begin && s->rax < i->end) && (1 * s->rdx < i->end - i->begin)", 0, 32, 1),
    ("(s->rax >= i->begin && s->rax < i->end) || (1 * ((uint32_t *)s->rsp)[0] < i->end - i->begin)", 0, 32, 1),
    ("8 * s->rdx < i->end - i->begin", 0, 2, 2),
])
def test_real_cwe805_clamps_and_typed_cells(tmp_path, link_mode, predicate, safe_count, repair_count, repair_branch, destination_zero):
    gcc = require_native_tools()
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    source = tmp_path / "fixture.S"
    assembly = CWE805_ASSEMBLY
    if repair_branch == 2:
        # argc=3 supplies a size whose checked scale overflows uint64.
        assembly = assembly.replace(
            "    add %rdx, %rax",
            "    cmp $2, %edx\n    jne 1f\n"
            "    movabs $0x2000000000000000, %rdx\n1:\n    add %rdx, %rax")
    source.write_text(assembly)
    original = workdir / "fixture.orig"
    subprocess.run([gcc, link_mode, str(source), "-o", str(original)],
                   capture_output=True, timeout=30, check=True)
    original_bytes = original.read_bytes()
    with original.open("rb") as stream:
        symbols = ELFFile(stream).get_section_by_name(".symtab")
        addresses = {name: symbols.get_symbol_by_name(name)[0]["st_value"]
                     for name in ("patch_site", "error_handler", "allocator_entry", "malloc_site", "malloc_return")}
    (workdir / "patch-location").write_text(f"{addresses['patch_site']:x}\n")
    destination = 0 if destination_zero else addresses['error_handler']
    (workdir / "patch-destination").write_text(f"{destination:x}\n")
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
    if destination_zero:
        build_cached_fixture(workdir, PredicateFamily.CWE805_ERM)
    for count, branch in ((safe_count, 0), (repair_count, repair_branch)):
        expected = (128 if destination_zero else 23) if branch == 1 else 17
        assert returncode(original, count, None) == 17
        for selector in (None, "0", "1", "123456"):
            assert_native_action(workdir / "fixture.patched", count, selector,
                                 expected, branch, runtime_id=1)
        for selector in (None, "0"):
            assert_native_action(workdir / "fixture.brpatched", count, selector, 17, 0)
        assert_native_action(workdir / "fixture.brpatched", count, "1", expected, branch)
        if destination_zero:
            for descriptor, status, taken in (("p0", 17, 0),
                                               (result['descriptor'], expected, branch)):
                assert_native_action(workdir / "fixture.brcached", count, "0",
                                     status, taken, descriptor=descriptor)
    for suffix in ("patched", "brpatched"):
        binary = workdir / f"fixture.{suffix}"
        metadata = json.loads(Path(str(binary) + ".e9map.json").read_text())
        assert metadata["artifact-sha256"] == hashlib.sha256(binary.read_bytes()).hexdigest()
        assert metadata["original-sha256"] == hashlib.sha256(original_bytes).hexdigest()
    assert original.read_bytes() == original_bytes


@pytest.mark.parametrize("destination_zero", [False, True])
@pytest.mark.parametrize("link_mode", ["-no-pie", "-pie"])
@pytest.mark.parametrize("predicate", ["1 / rax", "1 % rax"])
def test_real_fixed_and_selected_traps_follow_original(tmp_path, predicate, link_mode, destination_zero):
    gcc = require_native_tools()
    source = tmp_path / "fixture.S"
    source.write_text(ASSEMBLY)
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    original = workdir / "fixture.orig"
    subprocess.run([gcc, link_mode, str(source), "-o", str(original)],
                   capture_output=True, timeout=30, check=True)
    addresses = symbol_addresses(original)
    (workdir / "patch-location").write_text(f"{addresses['patch_site']:x}\n")
    destination = 0 if destination_zero else addresses['error_handler']
    (workdir / "patch-destination").write_text(f"{destination:x}\n")
    (workdir / "patch-format").write_text("ERM generic\n")
    config = tmp_path / "config.env"
    config.write_text("BINARY=fixture\n")
    result = generate_patch(config, workdir, predicate)
    for suffix in ("patched", "brpatched"):
        assert_native_action(workdir / f"fixture.{suffix}", 1, "1", 17, 2)
    if destination_zero:
        build_cached_fixture(workdir, PredicateFamily.GENERIC_ERM)
        assert_native_action(workdir / "fixture.brcached", 1, "0", 17, 2,
                             descriptor=result['descriptor'])


def test_real_cached_zero_runs_through_execution_worker(tmp_path):
    from binradar import binradar_utils
    from taosc_llm.execution import execute_capture, sha256

    gcc = require_native_tools()
    qemu = Path(paths.QASAN_QEMU_BIN)
    if not qemu.is_file() or not qemu.with_name('libqasan.so').is_file():
        pytest.skip('real execution worker requires QASAN and its sibling library')
    workdir = tmp_path / 'workdir'
    workdir.mkdir()
    source = tmp_path / 'fixture.S'
    source.write_text(ASSEMBLY)
    original = workdir / 'fixture.orig'
    subprocess.run([gcc, '-no-pie', str(source), '-o', str(original)],
                   capture_output=True, timeout=30, check=True)
    location = symbol_addresses(original)['patch_site']
    (workdir / 'patch-location').write_text(f'{location:x}\n')
    (workdir / 'patch-destination').write_text('0\n')
    (workdir / 'patch-format').write_text('ERM generic\n')
    config = tmp_path / 'config.env'
    config.write_text('BINARY=fixture\n')
    built = generate_patch(config, workdir, 'rax <= 0')
    metadata = build_cached_fixture(workdir, PredicateFamily.GENERIC_ERM)
    settings = {'BINARY': 'fixture', 'PATCH_LOC': f'0x{location:x}',
                'TEST_CMD': '@@', 'BINRADAR_PATCH_KIND': 'generic-erm',
                'BINRADAR_QEMU_EXEC_TIMEOUT': '5'}
    binradar_utils.set_e9_metadata(settings, 'brcached',
                                  metadata.exclude_ranges_str(), metadata.relocated_calls_str())
    manifest = {'patch': {'location': location, 'destination': 0}, 'artifacts': {
        name: {'sha256': sha256(workdir / name)} for name in (
            'fixture.orig', 'fixture.brcached', 'fixture.brcached.json',
            'fixture.brcached.e9map.json')}}
    dataset = SimpleNamespace(root=tmp_path, workdir=workdir, binary='fixture',
                              patch_format='ERM generic', manifest=manifest,
                              artifact=lambda name: workdir / name,
                              execution_environment=lambda: dict(settings))
    input_file = tmp_path / 'input'
    input_file.write_bytes(b'harmless input')
    case = {'input_path': 'input', 'input_sha256': sha256(input_file)}
    for descriptor, arguments, branch in (('p0', '@@', 0),
                                         (built['descriptor'], '@@', 1),
                                         (built['descriptor'], '@@ normal', 0)):
        settings['TEST_CMD'] = arguments
        result = execute_capture(dataset, case, descriptor, tmp_path / 'capture')
        assert result['complete'], result
        assert result['branches'] == [branch]
        assert result['outcome']['outcome'] == 'normal'
        snapshots, error = parse_cached_snapshots(Path(result['path']).read_bytes())
        assert error is None and [state.branch for state in snapshots] == [branch]


def test_fresh_build_worker_preserves_runtime_dependency_closure(tmp_path):
    require_native_tools()
    prepared = prepare_fixture(tmp_path / "caller")
    dataset = load_dataset(prepared["dataset"])
    original = dataset.artifact('fixture.orig')
    original_bytes = original.read_bytes()
    built = asyncio.run(build_candidate(dataset, "rax <= 0", tmp_path / "candidate"))
    scratch = tmp_path / "execution"
    scratch.mkdir()
    fixed = built["artifacts"]["fixture.patched"]
    # This crosses the fresh Python process and real native build boundaries.
    # Guix must resolve dependencies outside the interpreter's own site-packages.
    for value, expected in (("-1", 23), ("1", 17)):
        result = run_native([fixed, value], scratch, timeout=5, check=False)
        assert result.returncode == expected
    evaluation = evaluate_dataset(dataset, 'rax <= 0',
                                  cache_dir=tmp_path / 'evaluation-cache', workers=2)
    replay = verify_built_candidate(dataset, built, evaluation, workers=2)
    assert replay['status'] == 'matched'
    assert replay['summary']['matched'] == len(evaluation['cases']) > 0
    assert all(set(case['observations']) == {'fixed', 'selectable_id0', 'selectable_id1'}
               for case in replay['cases'])
    assert original.read_bytes() == original_bytes
    assert replay['verified'] is False and replay['binradar_verification'] == 'not_run'
