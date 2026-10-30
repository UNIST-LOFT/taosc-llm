# taosc-llm

Prepare immutable BinRadar evidence, evaluate an ERM predicate, and build a manual
or isolated Pi-driven candidate. Only explicit `ERM generic` and `ERM CWE-805`
families are supported. This is a standalone backend: existing `taosc-fix` and
`taosc-refine` orchestration is unchanged. Candidate evaluation is rejection-only,
not final BinRadar verification or proof of repair.

## Setup: import explicit producer runs

```sh
uv run --project utils/taosc-llm taosc-llm-setup \
  --config /path/to/config.env --workdir /path/to/prepared-workdir \
  --concrete-run /path/to/concrete-run \
  --output /path/to/new-dataset --rea /path/to/rea
```

Optionally add `--mutation-run /path/to/mutation-run` for committed patch-zero
mutation evidence. Setup does not call an LLM or generate fresh mutation tests.
`--analysis-provider` defaults to `ghidra`; REA/Ghidra are local static analysis
backends, not model-accessible services. Setup freezes function, instruction,
decompilation and reference views with availability/provenance records.

Required workdir inputs:

```text
<BINARY>.orig                  little-endian x86-64 ELF
<BINARY>.brcached               existing cached-state executable
<BINARY>.brcached.json          its E9 command stream
<BINARY>.brcached.e9map.json     exact artifact/original-bound instruction map
brpatches.json
patch-format                   exactly ERM generic or ERM CWE-805
patch-location                 one nonzero hexadecimal ELF virtual address
patch-destination              one selected nonzero hexadecimal ELF virtual address
generate-concrete.env
```

`config.env` is loaded as data, not executed. It must supply `BINARY` and an
invocation/POC consistent with generation metadata; the POC must resolve locally.
Address files accept an optional `0x` prefix and must identify executable,
file-backed original ELF ranges. The caller owns instruction boundaries and
handler/frame compatibility. CWE-805 additionally requires complete allocator
traces under `trace/` and `stack-size`. Mutation import also requires
`generate-binradar.env` and artifact-bound capture context plus committed evidence.

The concrete run supplies `minimizer.sbsv` original-only baseline v1 observations
and matching hashed inputs under `minimized/`; incomplete or replaced producer
rows are not admitted. Optional `probe-results.sbsv` supplies original reference
observations. Do not invent runtime states or substitute caller-written evidence
JSON. See the [evidence contract](../../agent-docs/taosc-llm/PROMPTS_AND_EVIDENCE.md)
for capture identities and the system/function domain distinction.

Setup publishes a schema-2 dataset containing `manifest.json`, `cases.jsonl`,
frozen workdir artifacts, input bytes, source records and static analysis. A new
explicit output directory is required; existing revisions are not overwritten.
Without `--output`, revisions live under `workdir/taosc-llm-datasets/<dataset-id>`.
Later commands accept either the dataset directory or its `manifest.json`.

## Evaluate, warm, and offline operation

```sh
uv run --project utils/taosc-llm taosc-llm-evaluate \
  --dataset /path/to/new-dataset --warm --workers 4
uv run --project utils/taosc-llm taosc-llm-evaluate \
  --dataset /path/to/new-dataset --predicate 'rax <= 0' --workers 4
uv run --project utils/taosc-llm taosc-llm-evaluate \
  --dataset /path/to/new-dataset --predicate 'rax <= 0' --offline
```

`--warm` collects neutral `p0` concrete observations, including empty-manifest
cases; it does not test a repair. It cannot be combined with `--offline` or
`--case`. For predicate evaluation, repeat `--case system:ID` or
`--case function:ID` to select prepared cases. `--cache-dir` selects private
host-owned cache storage; the default is `~/.cache/taosc-llm`. Producer files are
never modified.

Reuse requires a complete, identity-bound capture, a valid evaluator mirror of
its recorded descriptor, and an **equal full ordered branch vector** for the
candidate. Missing, incomplete, mismatched or divergent concrete captures trigger
candidate execution unless `--offline` is set. Each host worker owns copied
artifacts, input, environment, cwd and runner. Offline missing/divergent evidence
is `unavailable`, not an inferred successful execution. Mutation/function cases
are always **OFFLINE, rejection-only**: no fresh mutation phase is run. A same-
crash observation can reject a candidate; changed branches cannot establish its
new outcome. Predicate traps (branch 2), missing stacks and missing oracle data
are unavailable, never repair success.

Concrete workers are bounded to 1–32 (`--workers` here, `--execution-workers` in
synthesis). They are separate from provider session workers and the provider cap.
A supplied PIE `.brcached` cannot currently execute a nonneutral descriptor:
literal-destination relocation is unproven, so that path explicitly reports
`unavailable`. This is distinct from the fixed/selectable builder's PIE support.

## Manual and Pi synthesis

```sh
uv run --project utils/taosc-llm taosc-llm \
  --dataset /path/to/new-dataset --predicate 'rax <= 0' \
  --output /path/to/manual-runs --execution-workers 4
uv run --project utils/taosc-llm taosc-llm \
  --dataset /path/to/new-dataset --provider-env /absolute/path/to/provider.env \
  --pi-sdk-root utils/taosc-llm/thirdparty/pi \
  --output /path/to/model-runs --execution-workers 4 --max-rounds 4
```

`python -m taosc_llm` is the synthesis CLI. Manual mode loads no provider and
makes no model request; it uses the same mandatory native isolation and
candidate-owned outputs as model mode. There is no manual unsandboxed CLI switch.
Both paths build and evaluate the family-specific candidate. Generic predicates
are signed-i64 register expressions: **nonzero means jump to the selected repair
destination**. The builder lowers the safe condition `(expression) == 0` through
BinRadar's parser, never interpolating model text as C. CWE-805 instead accepts
the existing closed pointer/size safe-clamp grammar; it is not generic C or an
arbitrary memory-expression interface. Inspect the dataset's family grammar.

Pi SDK 1.4.0 receives exactly seven restricted host tools:
`get_patch_context`, `get_function_analysis`, `list_cases`, `get_case`,
`evaluate_predicate`, `test_candidate`, and `get_candidate_result`.
`evaluate_predicate` is offline; `test_candidate` requests bounded host-controlled
concrete evaluation. No shell, arbitrary file access, debugger, built-in tools,
extensions, MCP, REA invocation or subagents are exposed. REA views were frozen at
setup. Candidate proposals require context inspection and evaluation of the exact
expression. Strict response parsing, native builds and actual evaluation feedback
feed bounded refinement rounds (`--max-rounds` 1–16, default 4, provider-only);
manual mode rejects provider options instead of ignoring them. Abstention stops
without a candidate. No final BinRadar verification is run.

Provider routing, credential-file syntax, isolated SDK setup, the unchanged
Ollama cap of three, session `--workers`, nonsecret overrides and durable quota
recovery are specified in [PROVIDER_AND_PI.md](../../agent-docs/taosc-llm/PROVIDER_AND_PI.md).
Use an explicit provider file; no home credentials, ambient provider defaults or
fallback models are discovered. Guix supplies its SDK root automatically.

### Results and artifacts

Stdout contains one JSON result; diagnostics go to stderr. Common CLI exits:

| Exit | Meaning |
|---|---|
| 0 | `prepared`, `built`, `abstained`, `not_rejected` (or `warmed` if returned); not repair success |
| 2 | `reject_same_crash` |
| 3 | `unavailable` |
| 1 | Other terminal failure, including exhausted refinement or infrastructure/parser/build error |
| 130 | Interrupted; unresolved provider operations remain quarantined |

`--warm` currently returns the ordinary evaluation status, not a guaranteed
`warmed` status. Rejection takes precedence over unavailable cases; absent any
rejection, any unavailable case (or no cases) makes the aggregate unavailable.
`not_rejected` only means admitted observations did not reject this candidate.
`unavailable` is not evidence of improvement. Synthesis results retain
`verified=false` and `binradar_verification=not_run` even when a build exists.

Synthesis uses a private context/run root (temporary by default, or `--output`).
Model runs contain `run.json`, `context.json`, `trials/<round>/` journals/final text,
and `candidates/<round>/build-workdir/`, `build-result.json`, `evaluation.json`.
Manual runs place `build-workdir/` and `run.json` in their own unique run directory.
Source workdir candidate outputs are not overwritten.

| Built artifact | Meaning |
|---|---|
| `<BINARY>.patched` | Fixed candidate; independent of `PATCH_ID` |
| `<BINARY>.brpatched` | Unset/0 selects original; 1 selects candidate |
| `<BINARY>.{patched,brpatched}.json` | Separate E9 command streams |
| `<BINARY>.{patched,brpatched}.e9map.json` | Exact binary-bound relocation metadata |
| `patch-format`, `predicates`, `brpatches.json`, native inputs | Family, lowered safe condition, descriptor and build sources |

Consume a complete result and matching artifact hashes, not partial files.
The low-level builder publishes per-file, not as an atomic directory transaction;
do not share a candidate directory with another build/verifier. Fixed/selectable
PIE support does not prove subsequent ordinary BinRadar literal-destination
rebuilds are PIE-compatible.

```python
from pathlib import Path
from taosc_llm.preparation import prepare_dataset
from taosc_llm.evaluation import evaluate_dataset, warm_dataset
from taosc_llm.synthesis import generate_manual, generate_with_pi

dataset = prepare_dataset(Path("config.env"), Path("workdir"),
                          Path("concrete-run"), None,
                          output=Path("new-dataset"), rea="/path/to/rea")
neutral = warm_dataset(dataset, workers=4)
checked = evaluate_dataset(dataset, "rax <= 0", workers=4, execute=False)
manual = generate_manual(dataset.root, "rax <= 0", execution_workers=4)
proposed = generate_with_pi(dataset.root, Path("provider.env"),
                           sdk_root=Path("utils/taosc-llm/thirdparty/pi"),
                           execution_workers=4, max_rounds=4)
```

## Native isolation and harmless fixture

Native builds and execution require Linux x86-64 Landlock + seccomp, private
writable scratch, bounded resources and no networking. Isolation failure is
fatal: no unsandboxed fallback. Credentials use a separate inherited pipe to
Node and are absent from prompts, protocol journals, argv and native environments.
QASAN admits only its own `/proc/PID/maps` and `/proc/sys/vm/mmap_min_addr`;
`environ`, `mem`, other proc entries and private files remain denied. System trees
remain readable; Landlock ABI 1 does not hide all path metadata. This is not a VM.

For checkout development install the pinned SDK once (Node >=22.19):

```sh
npm --prefix utils/taosc-llm/thirdparty/pi ci --ignore-scripts --no-audit --no-fund
uv run --project utils/taosc-llm taosc-llm-fixture \
  --directory /tmp/taosc-llm-example --rea /path/to/rea
```

The directory must not exist. Add `--provider-env /absolute/path/to/provider.env`
and `--pi-sdk-root utils/taosc-llm/thirdparty/pi` to opt into a real model request
and finite fixture replay. Add `--pie` for the PIE fixture, subject to the cached
execution limitation above. The fixed source has an **intentional abort**, not a
vulnerability: original signed inputs <=0 abort, positives return 17; the fixture
repair route returns 23. It produces real original observations and a schema-2
dataset, not asserted register JSON. Development values are -7, 0 and 5; six
signed boundary inputs remain held out from the model. Replay checks original,
fixed and selectable behavior; any fixture `passed` verdict is finite fixture
scope only, not final BinRadar verification. Historical fixture results are not
acceptance evidence for this cutover. Exercised package/build/smoke results and
remaining gates are recorded in the
[integration reference](../../agent-docs/taosc-llm/IMPLEMENTATION_PLAN.md#packaging-and-acceptance-evidence).

## Packaging and Guix

```sh
guix build -L utils/loftix -f utils/taosc-llm/guix.scm
guix shell -L utils/loftix -f utils/taosc-llm/guix.scm -- \
  taosc-llm-fixture --directory /tmp/taosc-llm-guix-example
```

The local recipe uses checkout BinRadar Python/resources and Loftix native tools,
with Node 26.12.1, REA 6.8.0 (149 nonoptional locked archives), Ghidra 12.1,
OpenJDK 21's full JDK, and the Pi SDK/AI 1.4.0 locktree. Runtime never runs npm;
SDK extraction does not run lifecycle hooks. Official binary license notices
are preserved. This is not a published Loftix release. The integration reference
records actual package-build and installed-smoke results separately from live
provider acceptance and final BinRadar verification.

Four installed wrappers are `taosc-llm`, `taosc-llm-setup`,
`taosc-llm-evaluate`, and `taosc-llm-fixture`. Source allowlists and the wheel
exclude real `.env` files, credentials, workdirs, node_modules and caches. The
wheel ships Python, `runtime.c`, prompts and adapter, not the SDK/native closure.
Python 3.10+ and BinRadar native resources are required; the local uv project uses
the checkout BinRadar package. E9 overrides are `E9TOOL`/`E9COMPILE`; otherwise
BinRadar resolves `e9patch@1.0.1`. Help does not require credentials/native discovery.
See the [maintained reference](../../agent-docs/taosc-llm/README.md) for contracts
and validation limits. Future Taosc orchestration remains a separate integration.
