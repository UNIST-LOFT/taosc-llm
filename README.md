# taosc-llm

Build one manually supplied binary guard from prepared Taosc metadata. This is
an executable backend for a future LLM proposer, **not an LLM synthesizer or a
repair verifier**. No Pi/REA service, model credentials or network inference is
used.

## Run from the checkout

From the repository root:

```sh
uv run --project utils/taosc-llm taosc-llm \
  --config /path/to/config.env \
  --workdir /path/to/prepared-workdir \
  --predicate 'rax == 0'
```

`python -m taosc_llm` has the same CLI. The local uv source uses the main
checkout's `binradar` package; it is not fetched from PyPI. Python 3.10+ is
required. Runtime paths come from `binradar.paths`; a Python-only BinRadar wheel
without its native resources is insufficient.

Required inputs:

```text
config.env                  BINARY="example"; other keys are not executed
prepared-workdir/
  example.orig              original x86-64 ELF executable
  patch-location            one hexadecimal ELF virtual address
  patch-destination         one nonzero hexadecimal ELF virtual address
  patch-format              optional; if present, must be ERM generic
```

Addresses may have a `0x` prefix. They must belong to executable file-backed
segments. Use the selected `patch-destination`, not the list of unselected
`destinations`. The caller remains responsible for a valid instruction site and
an error handler compatible with that site's stack/register state. The original,
config and address files are not changed or executed. PIE and non-PIE x86-64
ELF executables are supported: jump destinations use E9's saved runtime `rip`
plus the static location-to-destination delta, rather than an unrelocated ELF
constant.

`--predicate` uses BinRadar's existing generic register-expression grammar:
signed 64-bit arithmetic, bitwise operators and comparisons over the sixteen
x86-64 general-purpose registers. It is not arbitrary C or Python; stack,
memory dereferences, calls and allocator-clamp predicates are not accepted.
**Nonzero means jump to the error handler.** For example `rax == 0` jumps when
`rax` is zero. Taosc's `predicates` file instead describes the safe condition,
so the backend persists `(rax == 0) == 0` and lowers it through the existing
BinRadar parser. It never inserts source expressions into generated C.

## Artifacts and integration

A successful invocation writes these files in the workdir:

| Artifact | Meaning |
|---|---|
| `<binary>.patched` | Fixed candidate; independent of `PATCH_ID` |
| `<binary>.brpatched` | BinRadar selector: unset/0 follows original, 1 enables the candidate |
| `<binary>.{patched,brpatched}.json` | Each artifact's own E9 command stream, not a single JSON document |
| `<binary>.{patched,brpatched}.e9map.json` | Exact binary-bound relocation metadata |
| `patch-format`, `predicates`, `brpatches.json` | Generic family, safe-condition source, runtime id-1 descriptor |
| `brpatch.c`, `brpatches.inc`, `predicate.h`, `taosc-llm-*.c` | Reproducible native evaluator/adapter inputs |

Build/metadata errors leave previous artifacts intact. Outputs are staged in the
workdir and published only after both builds succeed; final renames are per-file,
not an atomic directory transaction. Do not share a workdir with a running build
or verifier. A failed/interrupted publication has no success result and must not
be consumed. Successful builds replace earlier candidate artifacts.

Stdout contains one JSON object with `status: "built"`, `verified: false`,
`jump_if`, the addresses, absolute artifact paths and
`binradar_activation: {"PATCH_ID": "1"}`. Diagnostics go to stderr; failures
exit nonzero without success JSON. Each native compile/rewrite command has a
300-second deadline. No POC, target or BinRadar campaign runs during generation.

```python
from pathlib import Path
from taosc_llm.builder import generate_patch

result = generate_patch(Path("config.env"), Path("workdir"), "rax == 0")
# Hand the candidate to verification; `built` is not a correctness verdict.
```

Taosc can call the CLI as a subprocess and consume its JSON/exit status. This
package does not depend on Taosc, avoiding `taosc -> taosc-llm -> taosc` cycles.
Existing `taosc-fix`/`taosc-refine` scripts are not changed to invoke it.

Before normal BinRadar verification, rerun `binradar-setup setup` for the new
candidate. This backend does **not** update `binradar.env`, prior filters, cached
artifacts or completed runs; never reuse those as evidence for a newly built
predicate. Two existing setup boundaries matter:

- Keep `patch-destination` in Taosc's **unprefixed hex** format when handing this
  same workdir to BinRadar: its current generic builder prepends `0x`, even
  though taosc-llm itself accepts either spelling without changing the file.
- Current BinRadar generic setup rebuilds with a literal `TAOSC_DEST`, not this
  backend's runtime-relative adapter. The PIE build/execution proof here does
  **not** cover that subsequent rebuild; PIE verification through normal setup
  needs a BinRadar-side change. The backend does not change BinRadar code.

Arithmetic traps follow the original path and report `br=2`, matching BinRadar's
evaluator; they do not establish that a candidate is valid.

## Guix

The local recipe uses the current checkout for the Python parser and native
predicate resources while retaining Loftix's pinned native dependency closure:

```sh
guix build -L utils/loftix -f utils/taosc-llm/guix.scm
guix shell -L utils/loftix -f utils/taosc-llm/guix.scm -- \
  taosc-llm -c /path/to/config.env -w /path/to/workdir --predicate 'rax == 0'
```

It is a local development package, not a published Loftix channel release.
Source selection is an explicit allowlist of packaging metadata, Python source,
tests and `runtime.c`. In particular, `.env`, model credentials, workdirs,
virtualenvs, build outputs and caches must never enter the world-readable Guix
store. Adding packaged data requires extending that allowlist deliberately.
Python modules and `runtime.c` ship in the wheel; original binaries, workdirs,
model runtimes and native tool binaries do not. BinRadar/E9 supply native resources separately.
Outside Guix, `E9TOOL` and `E9COMPILE` may point to individual executables; absent
these overrides, BinRadar resolves `e9patch@1.0.1` through Guix. `--help` does not
resolve native tools.

## Verification

```sh
# Set executable paths to enable the real native integration tests.
E9TOOL=/path/to/e9tool E9COMPILE=/path/to/e9compile \
  uv run --project utils/taosc-llm python -m pytest utils/taosc-llm/tests
```

The native tests compile and execute a harmless return-code fixture in PIE and
non-PIE modes; no vulnerable benchmark is used. Without explicit E9 executables
or GCC those tests skip. The Guix recipe supplies these tools for its check
phase. Failure-injection scripts use the running Python's absolute interpreter:
`/bin/sh` is not available inside the Guix build sandbox.
See [the maintained Taosc contract](../../agent-docs/TAOSC.md) for the broader
workflow and remaining stage boundaries.
