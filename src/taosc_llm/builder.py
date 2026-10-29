"""Build one manual generic predicate; discovering or verifying it is separate."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from contextlib import redirect_stdout
from importlib.resources import files
from pathlib import Path
from tempfile import TemporaryDirectory

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

import binradar.binradar_taosc_predicates as predicates
from binradar import binradar_setup, paths


def _address(path: Path) -> int:
    text = path.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]{1,16}", text):
        raise ValueError(f"{path}: expected exactly one hexadecimal ELF address")
    address = int(text, 16)
    if not address:
        raise ValueError(f"{path}: address 0 is not a supported jump destination/site")
    return address


def _check_original(original: Path, location: int, destination: int) -> None:
    try:
        with original.open("rb") as stream:
            elf = ELFFile(stream)
            if (elf.elfclass != 64 or elf["e_machine"] != "EM_X86_64"
                    or elf["e_type"] not in ("ET_EXEC", "ET_DYN")):
                raise ValueError(f"{original}: expected an x86-64 executable ELF")
            executable = [
                (segment["p_vaddr"], segment["p_vaddr"] + segment["p_filesz"])
                for segment in elf.iter_segments()
                if segment["p_type"] == "PT_LOAD" and segment["p_flags"] & 1
            ]
            for name, address in (("patch-location", location),
                                  ("patch-destination", destination)):
                if not any(start <= address < end for start, end in executable):
                    raise ValueError(f"{name}: 0x{address:x} is outside executable ELF bytes")
    except ELFError as error:
        raise ValueError(f"{original}: invalid ELF: {error}") from error


def _run(command: list[str], stage: Path) -> None:
    # stdout is reserved for the CLI's JSON result, including native diagnostics.
    subprocess.run(command, cwd=stage, stdout=sys.stderr, check=True, timeout=300)


def _instrument(stage: Path, binary: str, suffix: str,
                location: int, action: str) -> None:
    original = stage / f"{binary}.orig"
    output = stage / f"{binary}.{suffix}"
    metadata = Path(f"{output}.json")
    spec = predicates.InstrumentationSpec(((f"0x{location:x}", action),))
    _run(predicates.e9tool_command(spec, metadata, original, fmt="json"), stage)
    _run(predicates.e9tool_command(spec, output, original), stage)
    # Sidecars are extracted from this exact binary/JSON pair, never copied
    # between the fixed and selector-based artifacts.
    with redirect_stdout(sys.stderr):
        binradar_setup.extract_e9_runtime_metadata(
            output, metadata, original, location)


def generate_patch(config: Path, workdir: Path, predicate: str) -> dict[str, object]:
    """Compile ``if (predicate != 0) goto destination`` at a prepared location.

    Existing candidates are replaced only after both builds and metadata checks
    succeed. No target executions or correctness verdicts occur here. A caller
    must not build concurrently with another producer/verifier in this workdir.
    """
    config = Path(config).resolve(strict=True)
    workdir = Path(workdir).resolve(strict=True)
    if not workdir.is_dir():
        raise ValueError(f"{workdir}: workdir must be a directory")
    env = binradar_setup.load_env(config)
    binary = env.get("BINARY", "")
    if not binary or Path(binary).name != binary or binary in (".", ".."):
        raise ValueError(f"{config}: BINARY must be a nonempty executable basename")
    format_file = workdir / "patch-format"
    if format_file.exists() and format_file.read_text(encoding="utf-8").strip() != "ERM generic":
        raise ValueError("only ERM generic is supported; prepare a separate generic workdir")
    location = _address(workdir / "patch-location")
    destination = _address(workdir / "patch-destination")
    original = workdir / f"{binary}.orig"
    # Whitespace is insignificant in the expression grammar. Keep the persisted
    # candidate on one physical line, as required by Taosc/BinRadar readers.
    jump_if = " ".join(predicate.split())
    predicates.predicate_to_patch_str(jump_if)
    safe_predicate = f"({jump_if}) == 0"
    branch = predicates.predicate_to_branch_patch_str(safe_predicate)
    _check_original(original, location, destination)
    if not paths.BRPATCH_SOURCE.is_file():
        raise FileNotFoundError(
            f"BinRadar native runtime missing: {paths.BRPATCH_SOURCE}; "
            "use the Guix package or a complete BinRadar source checkout")

    names = [
        "patch-format", "predicates", "brpatches.json", "brpatches.inc", "brpatch.c",
        "taosc-llm-runtime.c", "taosc-llm-selector.c", "predicate.h",
        *(f"{binary}.{suffix}{extension}"
          for suffix in ("patched", "brpatched")
          for extension in ("", ".json", ".e9map.json")),
    ]
    # Stage on the same filesystem. Validation/native failures do not replace
    # prior artifacts; publication is per-file, not a multi-file transaction.
    with TemporaryDirectory(prefix=".taosc-llm-", dir=workdir) as temporary:
        stage = Path(temporary)
        shutil.copy2(original, stage / original.name)
        shutil.copyfile(paths.BRPATCH_SOURCE, stage / "brpatch.c")
        (stage / "patch-format").write_text("ERM generic\n", encoding="utf-8")
        (stage / "predicates").write_text(safe_predicate + "\n", encoding="utf-8")
        # This table is deliberately just one validated candidate plus id0.
        # No source expression is interpolated into C.
        (stage / "brpatches.inc").write_text(
            f"case 1: return {json.dumps(branch)};\ndefault: return \"p0\";\n",
            encoding="utf-8")
        predicates.write_runtime_predicates(
            stage / "brpatches.json", predicates.PredicateFamily.GENERIC_ERM,
            [predicates.PredicateRecord(1, 1, safe_predicate, branch)])
        (stage / "predicate.h").write_text(
            f"#define TAOSC_LLM_BRANCH {json.dumps(branch)}\n"
            # STATE.rip is the matching instruction's runtime address. A static
            # ELF destination alone is not a valid process address for PIE.
            f"#define TAOSC_DEST ((uintptr_t)state->rip + 0x{destination:x} - 0x{location:x})\n",
            encoding="utf-8")
        (stage / "taosc-llm-runtime.c").write_bytes(
            files("taosc_llm").joinpath("runtime.c").read_bytes())
        (stage / "taosc-llm-selector.c").write_text(
            '#include "predicate.h"\n#include "brpatch.c"\n', encoding="utf-8")
        compiler = paths.e9compile()
        _run([compiler, "taosc-llm-selector.c"], stage)
        _instrument(stage, binary, "brpatched", location,
                    "if dest(state)@taosc-llm-selector goto")
        _run([compiler, "taosc-llm-runtime.c"], stage)
        _instrument(stage, binary, "patched", location,
                    "if llm_dest(state)@taosc-llm-runtime goto")
        # Check the complete set before publishing, including the exact E9 maps.
        for name in names:
            if not (stage / name).is_file():
                raise RuntimeError(f"patch build did not produce {name}")
        for name in names:
            (stage / name).replace(workdir / name)

    return {
        "status": "built",
        "verified": False,
        "binary": binary,
        "patch_location": f"0x{location:x}",
        "patch_destination": f"0x{destination:x}",
        "jump_if": jump_if,
        "artifacts": {name: str(workdir / name) for name in names},
        "binradar_activation": {"PATCH_ID": "1"},
    }
