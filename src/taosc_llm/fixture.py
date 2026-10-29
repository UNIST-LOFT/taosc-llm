"""Opt-in Pi/build/replay smoke on a harmless, fixed signed-value specification."""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

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
#include <stdlib.h>
extern int route(long value);
int main(int argc, char **argv) {
    if (argc != 2) return 97;
    char *end;
    errno = 0;
    long value = strtol(argv[1], &end, 10);
    if (errno || *end || end == argv[1]) return 98;
    return route(value);
}
"""
DEVELOPMENT_VALUES = (-7, 0, 5)
# Never copied into the model context, summaries, or tool results.
HELD_OUT_VALUES = (-(1 << 63), -2, -1, 1, 7, (1 << 63) - 1)


def prepare_fixture(directory: Path, *, pie: bool = False) -> dict[str, Path]:
    directory = Path(directory).absolute()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    gcc = shutil.which("gcc")
    objdump = shutil.which("objdump")
    if gcc is None or objdump is None:
        raise RuntimeError("fixture requires gcc and objdump")
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
    config = directory / "config.env"
    config.write_text("BINARY=fixture\n")
    disassembly = run_native([objdump, "--disassemble=route", str(original)], directory).stdout.decode()
    # File paths are not part of the model's static context.
    disassembly = disassembly.replace(str(original), "fixture.orig")
    observations = []
    for index, value in enumerate(DEVELOPMENT_VALUES):
        actual = run_native([str(original), str(value)], directory, check=False, timeout=5).returncode
        if actual != 17:
            raise RuntimeError("original fixture disagrees with its baseline")
        observations.append({
            "evidence_id": f"obs:fixture:{index}", "domain": "system",
            "origin": "fixture execution; register values derived from the fixed ABI and instruction prefix, not captured",
            "source_ref": f"signed-route-v1:development:{index}",
            "outcome": {"label": "fixture-functional-example", "returncode": str(actual),
                        "expected_returncode": str(23 if value <= 0 else 17),
                        "availability": "available", "reason": None},
            "hits": [{"state_id": f"state:fixture:{index}:0", "registers": {"rax": str(value), "rdi": str(value)},
                      "availability": "available", "reason": None}],
        })
    observations.append({
        "evidence_id": "obs:fixture:unavailable", "domain": "function",
        "origin": "synthetic unavailable-state example, not an execution or a BinRadar mutation",
        "source_ref": "signed-route-v1:availability-example",
        "outcome": {"label": "unknown", "availability": "unavailable", "reason": "no execution supplied"},
        "hits": [{"state_id": "state:fixture:unavailable", "registers": {},
                  "availability": "unavailable", "reason": "synthetic missing-state example"}],
    })
    evidence = {
        "schema_version": 1, "origin": "fixture",
        "original_sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
        "specification": (
            "Harmless signed-route-v1 functional fixture. Input is a signed 64-bit integer. "
            "For every input <= 0 the specified result is return code 23; for every positive input it is 17. "
            "At patch_site, RAX and RDI equal the input because route copies RDI into RAX immediately before the site. "
            "Other register values are unknown. The original always returns 17. "
            "Choose a general guard respecting the specification, not an enumeration of example values. "
            "Register observations are source-derived fixture data, not authenticated snapshots."),
        "destination_semantics": "error_handler returns 23 using the same live stack frame; original path returns 17",
        "functions": [{"function_id": "function:route", "view": "instructions", "text": disassembly,
                       "source_ref": "host-objdump:route:bound-to-original-sha256", "complete": True}],
        "observations": observations,
    }
    context_file = directory / "evidence.json"
    write_record(context_file, evidence)
    write_record(directory / "fixture.json", {"schema_version": 1, "oracle": "signed-route-v1",
                                               "original_sha256": evidence["original_sha256"], "pie": pie})
    return {"config": config, "workdir": workdir, "context": context_file}


def verify_fixture(directory: Path, result: dict) -> dict:
    if result.get("status") != "built":
        raise ValueError("fixture verification requires a built candidate")
    directory = Path(directory).resolve(strict=True)
    manifest = json.loads((directory / "fixture.json").read_text())
    original = directory / "workdir" / "fixture.orig"
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
            modes = (("original", original, None, 17),
                     ("fixed", candidate / "fixture.patched", None, repaired),
                     ("fixed-selector-ignored", candidate / "fixture.patched", "0", repaired),
                     ("selectable-default", candidate / "fixture.brpatched", None, 17),
                     ("selectable-original", candidate / "fixture.brpatched", "0", 17),
                     ("selectable-candidate", candidate / "fixture.brpatched", "1", repaired))
            for mode, binary, selector, expected in modes:
                actual = run_native([str(binary), str(value)], scratch, timeout=5, check=False,
                                    extra_env={} if selector is None else {"PATCH_ID": selector}).returncode
                cases.append({"partition": partition, "input": str(value), "mode": mode,
                              "expected_returncode": expected, "actual_returncode": actual,
                              "passed": actual == expected})
    verification = {"schema_version": 1, "oracle": "signed-route-v1", "context_id": result["context_id"],
                    "status": "passed" if all(case["passed"] for case in cases) else "failed",
                    "scope": "finite harmless fixture cases, not general correctness or BinRadar verification",
                    "artifact_hashes": build["artifact_hashes"], "cases": cases}
    write_record(candidate.parent / "verification.json", verification)
    return verification


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True, help="new private fixture directory (must not exist)")
    parser.add_argument("--pie", action="store_true")
    parser.add_argument("--provider-env", type=Path, help="opt in to a real model request and fixture replay")
    parser.add_argument("--pi-sdk-root", type=Path)
    args = parser.parse_args(argv)
    result: dict = {}
    try:
        with redirect_stdout(sys.stderr):
            prepared = prepare_fixture(args.directory, pie=args.pie)
            if args.provider_env is None:
                result = {"status": "prepared", **{name: str(path) for name, path in prepared.items()}}
            else:
                result = generate_with_pi(prepared["config"], prepared["workdir"], prepared["context"],
                                          args.provider_env, sdk_root=args.pi_sdk_root)
                if result["status"] == "built":
                    result["fixture_verification"] = verify_fixture(args.directory, result)
                    write_record(Path(result["run_directory"]) / "run.json", result)
        print(json.dumps(result))
        if args.provider_env is None:
            return 0
        return 0 if result.get("fixture_verification", {}).get("status") == "passed" else 1
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"taosc-llm-fixture: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("taosc-llm-fixture: cancelled; unresolved model requests stay quarantined", file=sys.stderr)
        return 130
