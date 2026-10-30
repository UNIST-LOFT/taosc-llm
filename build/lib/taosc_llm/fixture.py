"""Opt-in setup/evaluate/Pi smoke using a harmless intentional-abort fixture."""

import argparse
import hashlib
import json
import shutil
import signal
import subprocess
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from .cli import _diagnostics_to_stderr
from .native import run_native
from .synthesis import generate_with_pi, write_record

ASSEMBLY = """\
.text
.globl route
.type route, @function
route:
    push %rbp
    mov %rsp, %rbp
    mov %rdi, %rax
.globl patch_site
patch_site:
    cmp $0, %rax
    jg positive
    leave
    jmp abort@PLT
positive:
    mov $17, %eax
    leave
    ret
.globl error_handler
error_handler:
    mov $23, %eax
    leave
    ret
.size route, .-route
.section .note.GNU-stack,"",@progbits
"""
C_SOURCE = """\
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern int route(long value);
int main(int argc, char **argv) {
    char buffer[64];
    const char *text;
    if (argc == 3 && strcmp(argv[1], "--file") == 0) {
        FILE *input = fopen(argv[2], "r");
        if (!input) return 97;
        char *line = fgets(buffer, sizeof(buffer), input);
        fclose(input);
        if (!line) return 98;
        text = buffer;
    } else if (argc == 2) text = argv[1];
    else return 97;
    char *end;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno || (*end && *end != '\\n') || end == text) return 98;
    return route(value);
}
"""
DEVELOPMENT_VALUES = (-7, 0, 5)
HELD_OUT_VALUES = (-(1 << 63), -2, -1, 1, 7, (1 << 63) - 1)


def prepare_fixture(directory: Path, *, pie: bool = False, rea: str | None = None) -> dict[str, Path]:
    """Produce actual original observations and a neutral executable, not claimed states."""
    from binradar import binradar_config, binradar_minimizer, binradar_setup, binradar_verifier
    from .preparation import prepare_dataset

    directory = Path(directory).absolute()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    gcc = shutil.which("gcc")
    if gcc is None:
        raise RuntimeError("fixture requires gcc")
    workdir = directory / "workdir"
    workdir.mkdir(mode=0o700)
    (directory / "route.S").write_text(ASSEMBLY)
    (directory / "main.c").write_text(C_SOURCE)
    original = workdir / "fixture.orig"
    run_native([gcc, "-pie" if pie else "-no-pie", "-O0", "-g0",
                str(directory / "main.c"), str(directory / "route.S"), "-o", str(original)], directory)
    with original.open("rb") as stream:
        symbols = ELFFile(stream).get_section_by_name(".symtab")
        if not isinstance(symbols, SymbolTableSection):
            raise RuntimeError("fixture has no symbols")
        addresses = {}
        for name in ("patch_site", "error_handler"):
            matches = symbols.get_symbol_by_name(name)
            if not matches:
                raise RuntimeError("fixture patch symbol is absent")
            addresses[name] = matches[0]["st_value"]
    (workdir / "patch-location").write_text(f"{addresses['patch_site']:x}\n")
    (workdir / "patch-destination").write_text(f"{addresses['error_handler']:x}\n")
    (workdir / "patch-format").write_text("ERM generic\n")
    (workdir / "poc").mkdir()
    (workdir / "poc/input").write_text("-7\n")
    config = directory / "config.env"
    config.write_text('BINARY=fixture\nTEST_CMD="--file @@"\nPOC_INPUT=poc/input\nPOC_DIR=poc\nBINRADAR_QEMU_EXEC_TIMEOUT=10\n')
    # Only this fixed, non-vulnerable source is executed by the fixture producer.
    binradar_setup._generate_concrete(directory, workdir)
    binradar_setup._generate_binradar(directory, workdir)
    environment = binradar_setup.load_env(workdir / "generate-concrete.env")
    runner = binradar_verifier.BinRadarQemuRunner.from_env(str(workdir), environment)
    probe = runner.test_with_original(str(workdir / "poc/input"), verbose=False)
    if probe is None or not probe.patch_hit() or probe.exit_info != "crash":
        raise RuntimeError("intentional-abort fixture did not produce its actual original crash observation")
    concrete_run = directory / "concrete-run"
    concrete_run.mkdir()
    file_trace = runner.test_with_file_trace(str(workdir / "poc/input"), probe.patch_func_entry)
    if file_trace is None:
        raise RuntimeError("fixture file-trace observation unavailable")
    (concrete_run / "probe-results.sbsv").write_text(
        "[probe-info] " + probe.serialize() + "\n[file-trace] "
        + file_trace.serialize_file_trace_result() + "\n")
    corpus = directory / "development"
    corpus.mkdir()
    for index, value in enumerate(DEVELOPMENT_VALUES):
        (corpus / str(index)).write_text(str(value) + "\n")
    minimizer = binradar_minimizer.BinRadarMinimizer(
        str(workdir), str(concrete_run), probe, [str(corpus)], environment,
        min_file_age=0, baseline=binradar_config.ConcreteBaseline.ORIGINAL)
    minimizer.load_testcases()
    minimizer.run_testcases(timeout=120)
    dataset = prepare_dataset(config, workdir, concrete_run, None,
                              output=directory / "dataset", rea=rea)
    if len(dataset.cases("system")) != len(DEVELOPMENT_VALUES):
        raise RuntimeError("fixture minimizer did not retain every reached development input")
    write_record(directory / "fixture.json", {
        "schema_version": 2, "oracle": "intentional-abort-route-v2",
        "original_sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
        "dataset_id": dataset.dataset_id, "pie": pie,
        "scope": "Actual original observations; no mutation capture or functional specification supplied to model",
    })
    return {"config": config, "workdir": workdir, "concrete_run": concrete_run, "dataset": dataset.root}


def verify_fixture(directory: Path, result: dict) -> dict:
    if "build" not in result:
        raise ValueError("fixture verification requires a built candidate")
    directory = Path(directory).resolve(strict=True)
    manifest = json.loads((directory / "fixture.json").read_text())
    original = directory / "workdir/fixture.orig"
    if hashlib.sha256(original.read_bytes()).hexdigest() != manifest["original_sha256"]:
        raise ValueError("fixture original changed")
    build = result["build"]
    for name, expected in build["artifact_hashes"].items():
        if hashlib.sha256(Path(build["artifacts"][name]).read_bytes()).hexdigest() != expected:
            raise ValueError("built fixture artifact changed")
    candidate = Path(build["artifacts"]["fixture.patched"]).parent
    scratch = directory / "verification-scratch"
    scratch.mkdir(mode=0o700, exist_ok=True)
    cases = []
    for partition, values in (("development", DEVELOPMENT_VALUES), ("held-out", HELD_OUT_VALUES)):
        for value in values:
            repaired = 23 if value <= 0 else 17
            baseline = -signal.SIGABRT if value <= 0 else 17
            modes = (("original", original, None, baseline),
                     ("fixed", candidate / "fixture.patched", None, repaired),
                     ("fixed-selector-ignored", candidate / "fixture.patched", "0", repaired),
                     ("selectable-default", candidate / "fixture.brpatched", None, baseline),
                     ("selectable-original", candidate / "fixture.brpatched", "0", baseline),
                     ("selectable-candidate", candidate / "fixture.brpatched", "1", repaired))
            for mode, binary, selector, expected in modes:
                actual = run_native([str(binary), str(value)], scratch, timeout=5, check=False,
                                    extra_env={} if selector is None else {"PATCH_ID": selector},
                                    self_signals=True).returncode
                cases.append({"partition": partition, "input": str(value), "mode": mode,
                              "expected_returncode": expected, "actual_returncode": actual,
                              "passed": actual == expected})
    verification = {"schema_version": 2, "oracle": manifest["oracle"], "context_id": result["context_id"],
                    "status": "passed" if all(case["passed"] for case in cases) else "failed",
                    "scope": "Finite harmless fixture checks, not general correctness or BinRadar phase verification",
                    "artifact_hashes": build["artifact_hashes"], "cases": cases}
    write_record(candidate.parent / "verification.json", verification)
    return verification


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True, help="new private fixture directory")
    parser.add_argument("--pie", action="store_true")
    parser.add_argument("--rea", help="explicit local REA executable")
    parser.add_argument("--provider-env", type=Path, help="opt in to a real model request and fixture replay")
    parser.add_argument("--pi-sdk-root", type=Path)
    args = parser.parse_args(argv)
    try:
        with _diagnostics_to_stderr():
            prepared = prepare_fixture(args.directory, pie=args.pie, rea=args.rea)
            if args.provider_env is None:
                result: dict = {"status": "prepared", **{name: str(path) for name, path in prepared.items()}}
            else:
                result = generate_with_pi(prepared["dataset"], args.provider_env, sdk_root=args.pi_sdk_root)
                if "build" in result:
                    result["fixture_verification"] = verify_fixture(args.directory, result)
                    write_record(Path(result["run_directory"]) / "run.json", result)
        print(json.dumps(result))
        return 0 if args.provider_env is None or result.get("fixture_verification", {}).get("status") == "passed" else 1
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"taosc-llm-fixture: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("taosc-llm-fixture: cancelled; unresolved model requests stay quarantined", file=sys.stderr)
        return 130
