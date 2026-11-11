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

Optionally add `--binradar-run /path/to/binradar-run` for committed patch-zero
mutation evidence from a `--generate-binradar` run. Setup does not call an LLM
or generate fresh mutation tests.
`--analysis-provider` defaults to `ghidra`; REA/Ghidra are local static analysis
backends, not model-accessible services. Setup keeps one private REA stdio session
for the binary, rather than importing it for every view. It resolves both selected
addresses to actual Ghidra function bodies (including stripped binaries). If they
share a function, function/instruction/decompilation work is reused; exact-address
references remain separate. A destination is a selected repair entry point, not
an assertion that its function is a safe error handler.

`--analysis-timeout SECONDS` controls initial Ghidra import/analysis (default
**900**). `--analysis-query-timeout SECONDS` controls each subsequent query
(default **120**). Both accept positive whole seconds, at most 2147483. The first
native query gets both budgets because opening REA does not necessarily start
Ghidra. Native decompilation gets 75% of the query budget (at least one second),
leaving time to return its unavailable-facet diagnostics. For larger subjects:

```sh
# Add to the setup command; these are not provider/LLM timeouts.
--analysis-timeout 1800 --analysis-query-timeout 240
```

Instructions and address references are frozen before the function dossier;
pseudocode is extracted from that same dossier without a second decompile.
Timeout cancellation retires the session, awaits REA's detached-backend cleanup,
and leaves completed views intact; it does not repeat cold startup for each
missing view. Model context lists each canonical procedure once, binds patch and
destination as site roles, and supplies bounded instruction windows and exact-site
references. Available facets survive unrelated partial dossier relationships;
limitations remain explicit. Decompilation pages contain actual pseudocode (up to
120 lines/8192 UTF-8 bytes), never the raw dossier. `prepared`
means dataset publication, not that all static views succeeded. Inspect
`manifest.json`'s `analysis` entries before relying on that context.

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
host-owned cache storage; the default is `~/.cache/taosc-llm`. A relative cache
directory is resolved before each worker starts, because the sandbox launcher
runs with the scratch directory as its cwd. Producer files are never modified.

Reuse requires a complete, identity-bound capture, a valid evaluator mirror of
its recorded descriptor, and an **equal full ordered branch vector** for the
candidate. Missing, incomplete, mismatched or divergent concrete captures trigger
candidate execution unless `--offline` is set. Each host worker owns copied
artifacts, input, environment, cwd and runner. Offline missing/divergent evidence
is `unavailable`, not an inferred successful execution.

### Live function evaluation (trusted-host replay bridge)

Function (`--binradar-run`) cases are **offline by default**. An explicit
trusted-host option evaluates them against the dataset's own resident
`--generate-binradar --replay-server` snapshot:

```sh
uv run --project utils/taosc-llm taosc-llm-evaluate \
  --dataset /path/to/new-dataset --predicate 'rax <= 0' \
  --replay-socket workdir/out/br-gen-bin/replay.sock \
  --cache-dir workdir/out/taosc-llm-cache --workers 4
uv run --project utils/taosc-llm taosc-llm \
  --dataset /path/to/new-dataset --provider-env /abs/provider.env \
  --output /path/to/model-result --execution-workers 4 \
  --replay-socket workdir/out/br-gen-bin/replay.sock \
  --cache-dir workdir/out/taosc-llm-cache
```

- The socket must identify the dataset's own `--binradar-run` endpoint. Canonical
  paths are compared for identity. BinRadar publishes `<run>/replay.sock` as a
  symlink to its short private `/tmp` socket; the common client transport resolves
  that link before every connection. A missing or dangling endpoint remains
  unavailable, not ready. Pass the public path even when it exceeds 107 bytes;
  do not pass it directly to a raw `socket.connect()` without resolving it.
- The service must report `ready` or `evaluating`. Its `retained_mutations` and
  returned IDs must match the frozen **useful subset**: normal observations or
  authenticated target crashes, certified timeout-free by canonical v4 iteration
  flag `TIMEOUT_EXCLUDED`. Deadline-killed attempts are excluded even when crash
  provenance was salvaged. Unflagged old mutation runs/prepared function datasets
  require regeneration; never retrofit flags or reuse their candidate caches.
  System-only datasets are unaffected. Other committed crashes remain offline
  evidence; they are not missing native plans. Offline divergence remains
  unavailable. Synthesis checks replay binding before original execution or any
  provider request.
- Concrete `system:*` cases keep their existing capture/cache/worker path and
  never use the mutation snapshot.
- The model never sees the socket, and no tool schema accepts a path, endpoint or
  execution switch. `test_candidate` gains live function cases only because the
  host configured the bridge; `evaluate_predicate` stays offline. The Python
  API's `execute=False` also prohibits all socket access, even with a configured
  endpoint; the CLI rejects `--offline` combined with `--replay-socket`.
- Per-case target-oracle diagnostics keep the existing vocabulary: `target-crash` (the artifact's
  committed attempt-1 oracle) is `reject_same_crash`; `normal` and `other-crash`
  are `not_rejected`; cancellation, timeout, trap, unsupported external state and
  incomplete observation are `unavailable`. Every result keeps
  `verified=false`; nothing is FINAL verification.
- `busy` is retried within a bounded admission window so a debugging CLI
  evaluation can finish first. Any other protocol error aborts the batch.

Debug the wire directly, without building a candidate:

```sh
uv run --project utils/taosc-llm python -m taosc_llm.replay status   --socket <run>/replay.sock
uv run --project utils/taosc-llm python -m taosc_llm.replay wait     --socket <run>/replay.sock --pid <launcher-pid> --timeout 7200
uv run --project utils/taosc-llm python -m taosc_llm.replay evaluate --dataset <dataset> --predicate 'rax <= 0'
uv run --project utils/taosc-llm python -m taosc_llm.replay shutdown --socket <run>/replay.sock
```

`wait --timeout 0` waits indefinitely, but a dead launcher or stopping server
still fails. A positive timeout bounds the entire wait, including status calls.

The server's own acceptance boundaries (fresh-target/multiwrite replay, large
capture sets, measured cost) are unchanged; see the
[replay plan](../../agent-docs/memo/BINRADAR_REPLAY_SERVER_PLAN.md).

Concrete workers are bounded to 1–32 (`--workers` here, `--execution-workers` in
synthesis). They do not limit LLM concurrency; external orchestration owns any
account-wide provider limits.
A supplied PIE `.brcached` cannot currently execute a nonneutral descriptor:
literal-destination relocation is unproven, so that path explicitly reports
`unavailable`. This is distinct from the fixed/selectable builder's PIE support.

## Non-LLM branch-selection synthesis

```sh
uv run --project utils/taosc-llm taosc-llm-no-llm \
  --dataset DATASET --output NEW_RESULT --execution-workers 4
# Optional existing, dataset-bound mutation server:
uv run --project utils/taosc-llm taosc-llm-no-llm \
  --dataset DATASET --output NEW_RESULT --replay-socket RUN/replay.sock
# Repeat the original limits/execution policy when resuming:
uv run --project utils/taosc-llm taosc-llm-no-llm \
  --dataset DATASET --output EXISTING_RESULT --execution-workers 4 --resume
```

`python -m taosc_llm.no_llm` is equivalent. This host-only path imports no
provider, model context or Pi loop; it accepts no provider/model/session-review
options. It consumes the same prepared dataset, canonical family parser,
full-vector evaluator, optional explicit replay bridge and isolated builder.
It neither prepares a dataset nor invokes REA, starts a replay server or runs
BinRadar FINAL. The wheel/Guix closure still includes the existing Pi tools.
The reusable library entry is `taosc_llm.no_llm.run.synthesize(dataset,
output=..., limits=SearchLimits(...), execution_workers=..., cache_dir=...,
replay_socket=..., resume=...)`; `SearchEngine` accepts the host execution backend,
not CLI arguments or a model session.

The objective is **case-level branch selection**, separate from existing model
feedback. A reached normal case selecting repair is a regression even if it
exits normally. A target case is covered only with a compatible target-crashing
neutral control, an actual normal candidate outcome and a complete vector with
repair selected. Other-location crashes, traps, unknown/missing observations and
normal-without-repair supply no coverage. Original/neutral outcome or reachability
disagreement remains a baseline gap, not an excluded target. A POC absent from
the producer inventory receives separate original and neutral observations.
Known baseline no-hit cases are excluded; missing captures are never zero hits.
Concrete and mutation domains retain their distinct oracles and counts.

Search uses ordered generic repair DNF; CWE-805 uses its ordered dual safe CNF
against one same clamp. No new runtime grammar or independently reduced clamp
OR is introduced. Bounded atom/beam exploration shortlists candidates using
captured values; only actual execution or equal complete-vector reuse establishes
coverage. Each branch considers all unresolved targets: an unavailable anchor
cannot veto another case’s actual repair. A bounded, deterministic frontier gives
work to high-coverage, low-regression and different case-membership alternatives.
Early clause acceptance preserves alternative draft continuations, so a locally
stuck or full-repair decomposition is not the only path. Identical prediction
states preserve caches; only genuine new evidence reopens exhausted work.
Each branch keeps immutable clause-introduction owners, prefix evaluations and
decisive-hit witnesses. Refinement preserves both local obligations without later
clauses and that branch’s global owners; selecting a different branch never
transfers ownership. Losing normal evidence or crashing an admitted normal is
not an improvement.

An independent best-result archive ranks eligible, actually evaluated programs
by unresolved target count, then branch regression count, expression cost and
stable expression. This retains better partial repairs as well as full repairs,
even if the working branch has fewer regressions. The archive does not force an
always-repair seed to own every target in the exploratory branches. Normal/budget
termination reauthenticates the selected program’s evaluation and ownership
proofs without new execution or overwriting the working frontier. Artifact
publication compares against that selected evaluation, not the active branch.
Cancellation never promotes a draft.

| Search option | Finite default | Bound |
|---|---:|---|
| `--timeout` | 3600 seconds | Positive finite admission budget |
| `--max-evaluations` | 256 | Positive; includes baseline admission |
| `--max-atoms` | 1024 | 1–65536 |
| `--beam-width` | 12 | 1–256 |
| `--max-clauses` | 12 | 1–128 |
| `--max-factors` | 6 | 1–128 |
| `--operand-depth` | 2 | 1–4; generic leaves have depth 1 |

Canonical source/descriptor/depth and stack bounds override search bounds.
There is no target-execution count limit or corpus-size reservation. Target work
is bounded by the persistent search timeout and existing native per-child caps.
The evaluation-count cap still charges baseline/candidate operations before
admission and persists across interruption. In-flight evaluation drains under
existing per-execution limits. Finalization is separate from search admission,
remains cancellable under native limits, and may finish after the search deadline;
it does not reset spent search time. A time/evaluation-budget stop selects the
already evaluated best-result archive after reauthenticating its evidence, owners
and marginal witnesses; it does not commit a draft or admit new evaluation.
Cancellation never promotes a draft; positive branch regressions remain visible. Search stop reasons
distinguish goals, budgets, bounded exhaustion,
interruption and evidence gaps; no global optimum or out-of-corpus repair is
claimed. `coverage=complete` means complete observations, not all targets repaired.

The output is a private, single-writer schema-1 session: immutable `identity.json`,
`segments/*.jsonl`, content-addressed `payloads/`, private `cache/`, and new
`candidates/` directories. Stdout is one JSON result; diagnostics go to stderr.
`result_record` names the immutable summary payload; journal events are the source
of truth. Resume never overwrites old segments/payloads or interprets manual/Pi
`run.json`. Checksums, chains and transitive evidence references are checked;
a torn final record remains on disk, while complete corruption is fatal.
Directory/file locks, restrictive permissions, symlink rejection and fsync ordering
protect publication. The best-result archive, active and pending branches,
scheduling order, capture revision, atom order, owner proofs and spent budgets
are restored. Different dataset/artifact/oracle,
implementation, limits, workers or replay policy refuses resume. SIGINT/TERM
stop admission and drain registered children. SIGKILL cannot report its stop time:
the interval since the last durable budget timestamp, including downtime, is
conservatively charged; cleanly closed sessions do not charge downtime.
The removed `--max-executions` option is rejected by both entrypoints, not silently
ignored. Older count-reservation sessions are not migrated: implementation and
limit identity changes require a fresh output, though immutable datasets and
completed producers can still be reused.

A missing old replay server allows offline/concrete continuation; an endpoint
replacement cannot rebind old mutation IDs. BRCH is not a process checkpoint.
An interrupted build is retried in a new candidate directory. Only a completed
`publication` event authenticates fully checked artifacts; incomplete attempts
are recorded separately. Final verification compares fixed and selectable id1
against candidate outcomes/full vectors and selectable id0 against neutral controls.
The fixed artifact honors `PATCH_FD` for logging but never lets `PATCH_ID` or SHM
disable its guard. `publication_status=matched` is local artifact parity only;
function mutations cannot be transferred to newly built artifacts and leave
publication partial. Every result retains `verified=false` and
`binradar_verification=not_run`.

Exit status: **0** for every completed search outcome, including remaining
crashes/regressions, no candidate, exhausted budget/grammar and partial evidence
or publication; **130** interrupted; **1** input/storage/engine/build failure.
Invalid CLI usage remains nonzero. Judge repair from `score`, `termination`,
`coverage`, `publication_status` and the artifacts, never process exit alone.
A built-artifact branch mismatch is still an error, not partial success.
Acceptance and remaining representative-corpus/live-replay gates are recorded in
the [implementation record](../../agent-docs/taosc-llm/memo/patch-synthesizer/README.md).

## Manual and Pi synthesis

```sh
uv run --project utils/taosc-llm taosc-llm \
  --dataset /path/to/new-dataset --predicate 'rax <= 0' \
  --output /path/to/manual-result --execution-workers 4
uv run --project utils/taosc-llm taosc-llm \
  --dataset /path/to/new-dataset --provider-env /absolute/path/to/provider.env \
  --pi-sdk-root utils/taosc-llm/thirdparty/pi \
  --output /path/to/model-result --execution-workers 4 --max-rounds 4
```

`python -m taosc_llm` is the synthesis CLI. Manual mode loads no provider and
makes no model request; it uses the same mandatory native isolation and
candidate-owned outputs as model mode. There is no manual unsandboxed CLI switch.
Both paths build and evaluate the family-specific candidate. Generic predicates
are signed-i64 register expressions: **nonzero means jump to the selected repair
destination**. The builder lowers the safe condition `(expression) == 0` through
BinRadar's parser, never interpolating model text as C. CWE-805 instead accepts
the closed pointer/size safe-clamp grammar; it is not generic C or an arbitrary
memory-expression interface. Both families support parentheses and logical
`&&`/`||`, with `&&` binding tighter and left-to-right short circuit. Generic
logical results are exactly 0/1; bitwise `&`/`|` remain eager. For example,
`rax != 0 && 10 / rax > 1` skips division at zero. Visited arithmetic traps stay
branch 2, never repair success.

CWE atoms compose against one **same allocation clamp** before existential
reduction, in raw clamp order 255→0. All leaves, including skipped ones, must fit
the captured stack. Source is bounded to 4096 UTF-8 bytes; the final lowered
descriptor to 4095 bytes and depth 256. Inspect the dataset's family grammar.
Rebuild all components and regenerate workdirs/datasets together; no additional
language version, capability metadata or compatibility check is used.

Pi SDK 1.4.0 receives exactly seven restricted host tools:
`get_patch_context`, `get_function_analysis`, `list_cases`, `get_case`,
`evaluate_predicate`, `test_candidate`, and `get_candidate_result`.
`evaluate_predicate` is offline; `test_candidate` requests bounded host-controlled
evaluation of concrete cases and, when the trusted host configured a replay
bridge, of loaded function cases as well. No shell, arbitrary file access, debugger, built-in tools,
extensions, MCP, REA invocation or subagents are exposed. REA views were frozen at
setup. Inline context satisfies context availability; `get_patch_context` is optional.
Initial context includes the original POC's sanitized invocation, input size,
observed outcome and neutral patch-site register example. Before the first provider
prompt, the host reuses authenticated evidence or actually collects missing original
and neutral observations. A POC absent from prepared cases is still included in
candidate evaluation. No values are invented; neutral registers are labeled separately
from the original artifact. Saved QASAN diagnostics are summarized inline; deeper
frames/allocation/free histories require bounded `get_patch_context(view="poc_log")`
pages. Neither saved-log addresses nor site values replace the configured target
oracle. See [POC evidence](../../agent-docs/taosc-llm/PROMPTS_AND_EVIDENCE.md#original-poc-diagnostic-summary).
Candidate proposals require evaluation of the exact expression. Context and
`list_cases` show at most three crash/three normal examples. Evaluation feedback
separates missed targets, normal→target/other-crash regressions, and normal→normal
complete-vector branch regressions. Each group has counts and at most three
examples. Quality feedback also exposes bounded other-crash, unavailable,
original/neutral-gap and unproven-repair examples; none counts as success. Optional register/mutation filters and similarity
select more small examples, never an exhaustive case page. Hashes/audit metadata
stay private; model IDs are short scoped handles. Static `function` views default
to available facets; select a facet/address for local CFG/value-flow evidence. Strict response parsing, native builds and actual evaluation feedback
feed bounded refinement rounds (`--max-rounds` 1–16, default 4, provider-only);
manual mode rejects provider options instead of ignoring them. The primary goal
is blocking all crashes without missing or unproven evidence. The secondary goal
is minimizing authenticated normal→normal branch-vector differences, not rejecting
an otherwise established repair merely because differences remain.
`evaluation.quality.status=improved` ends immediately as `not_rejected` with
`termination=quality_met`. `improved_with_regressions` also maps to `not_rejected`
and exit 0, but continues refinement while the budget and new candidates permit.
Neither verdict proves general equivalence or a global minimum.

The selected incumbent must retain all established repairs and observed normal
executions, and cannot add a newly crashing case (target, other or normal→crash).
Among admissible proposals, fewer crashing cases, fewer unresolved cases, fewer
branch regressions, then more repairs determine selection in that order; ties
retain the incumbent. This prevents losing evidence from masquerading as
improvement. `selected_round` binds the retained proposal/build/evaluation even
if later attempts are worse.

Each new round receives the full validated prior proposal, including rationale
and assumptions, bounded host results, the incumbent and remaining round budget.
Previously admitted result IDs remain inspectable. Two consecutive evaluated
rounds with the same canonical predicate and unchanged aggregate and case-level
quality stop with `termination=repeated_result`; matching counts alone do not
suffice. Otherwise the configured limit (default four rounds) ends with
`termination=round_limit`. Both retain the incumbent's actual quality and report
residual branches normally; crashes and evidence gaps do not become success.
Without an evaluated candidate a valid abstention stops without a candidate;
a later abstention retains an already evaluated incumbent. Invalid model
proposals can receive bounded corrective feedback, but an unrecovered final
parse error with no incumbent remains an error. Build/storage/integrity and
provider failures propagate; they are not `refinement_exhausted` outcomes.
No final BinRadar verification is run.

Provider routing, credential-file syntax, isolated SDK setup, per-operation
bounds and externally managed scheduling are specified in
[PROVIDER_AND_PI.md](../../agent-docs/taosc-llm/PROVIDER_AND_PI.md).
There is no global provider lock, call counter or recovery command. Separate CLI
invocations may run concurrently; each invocation still processes one context
sequentially. Remove obsolete `TAOSC_LLM_MAX_IN_FLIGHT`/`TAOSC_LLM_WORKERS` fields
from provider files. Provider `--max-in-flight`/`--workers` are also removed;
evaluator `--workers` and synthesis `--execution-workers` remain supported.
Use an explicit provider file; no home credentials, ambient provider defaults or
fallback models are discovered. To request reasoning effort, add
`TAOSC_LLM_REASONING_EFFORT=high` to that file. Exact accepted values and the
omitted/default behavior are in the [provider configuration contract](../../agent-docs/taosc-llm/PROVIDER_AND_PI.md#explicit-configuration);
this is not a CLI option or an ambient environment override. Guix supplies its
SDK root automatically.

### Evaluate the original session after its result

Add `--session-feedback` to provider synthesis (or `taosc-llm-run --mode provider`):

```sh
uv run --project utils/taosc-llm taosc-llm \
  --dataset /path/to/new-dataset --provider-env /absolute/path/to/provider.env \
  --pi-sdk-root utils/taosc-llm/thirdparty/pi \
  --output /path/to/model-result --session-feedback
```

After the final host result is persisted, the **same live Pi SDK session** receives
that result and a tool-free review request. It evaluates its prompts, tool calls,
evidence interpretation and workflow; it cannot change the candidate or host verdict.
The final run directory contains private `session-feedback.md`, with separate
status/usage/request/settlement metadata in `run.json.session_feedback`. Review gets
one model response, at most `min(TAOSC_LLM_MAX_TOKENS, 4096)` output tokens,
and a fresh configured timeout, not another synthesis loop. The request asks for
at most 600 words/eight bullets and reviews the retained candidate, not an
unselected last attempt. Failure is recorded separately and leaves the settled result intact. Manual mode
rejects the flag. It is disabled by default and consumes an additional provider
request when used; this self-review is not independent correctness verification.

This preserves the original custom tool history unlike `pi --session` reopening,
which does not restore the taosc host. See the [review lifecycle and limits](../../agent-docs/taosc-llm/PROVIDER_AND_PI.md#optional-post-result-session-feedback).

### Results and artifacts

Stdout contains one JSON result; diagnostics go to stderr. Common CLI exits:

| Exit | Meaning |
|---|---|
| 0 | Completed setup/evaluation/synthesis, including abstention, no candidate, remaining crashes/regressions, evidence gaps and bounded exhaustion; never repair or FINAL proof |
| 1 | Input, provider/API, unrecovered parser, storage, engine or build failure |
| 2 | Invalid CLI arguments, not candidate quality |
| 130 | Interrupted; local cleanup does not prove remote provider completion |

`evaluation.status` remains the target-only diagnostic: any same-target crash
rejects, otherwise a nonempty case set is `not_rejected`, including unavailable
cases; an empty set is `unavailable`. Do not aggregate this field as repair
success. The separate `evaluation.quality` carries status, orthogonal counts and
reasons. Original-target/neutral-normal disagreement is `baseline_gaps`, not an
improvement. Other crashes, unavailable evidence and unproven repair remain
separate from `improved`/`preserved_normal`; facet counts can overlap.
Candidate quality remains in the result, independent of CLI exit status. A
completed all-unavailable or rejected candidate exits 0 without changing its
quality or evidence. `--warm` is acquisition rather than candidate assessment;
its JSON status is not guaranteed to be `warmed`, and its completed outcomes
also exit 0.
Full private `report_summary` retains actual firing, paired transitions, capture
gaps and oracle warnings; offline predictions are not actual activity. See the
[quality classification contract](../../agent-docs/taosc-llm/PROMPTS_AND_EVIDENCE.md#capture-and-outcome-interpretation)
for exact eligibility and bounded model-facing failure evidence.
With `--replay-socket`, a result also carries a `replay` block (endpoint,
coverage, mutation count, unavailable count). The endpoint never enters the
model projection or a tool result, and it is not a patch field.
`unavailable` is not evidence of improvement. Synthesis results retain
`verified=false` and `binradar_verification=not_run` even when a build exists.

`--output` is the exact private result directory, not a parent for UUID directories.
Without it, synthesis allocates one temporary directory. Model results go directly
into `run.json` (including private `context_provenance`), `context.json`, private
preflight `poc.json`, `trials/<round>/` journals/final text, and
`candidates/<round>/build-workdir/`, `build-result.json`, `evaluation.json`.
Optional review writes `session-feedback.md` in that same root. Manual results use
`build-workdir/`, `build.log`, `context.json` and `run.json` directly under `--output`.
Protocol `run_id` remains metadata; use returned `run_directory`, never append
`run_id` to locate files.

Choose an unused output directory for every invocation. New/empty directories are
accepted, as is a directory containing only a real `cache/` initialized by context
preparation. Existing results, unrelated content and legacy UUID subdirectories
are rejected before context preparation can change caches. Atomic exclusive
`run.json` creation admits only one concurrent owner; failed/interrupted runs are
not automatically resumed. The root is private mode 0700. Keep reusable caches
outside the result via `--cache-dir`, or use the default `<output>/cache`.
Previous outputs and source workdir candidate artifacts are not overwritten.

For `taosc-llm-run --mode provider`, model output is:

```text
taosc-llm-out-00000/result/
  run.json
  context.json
  poc.json
  session-feedback.md          # only with successful --session-feedback
  trials/
  candidates/
```

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
                           execution_workers=4, max_rounds=4, session_feedback=True)
```

### Inspecting model sessions

New Pi synthesis attempts automatically retain these private files under
`<run-directory>/trials/<round>/`; no additional option is needed:

| File | Contents |
|---|---|
| `turn-<attempt>.jsonl` | Host protocol: initial prompts, tool requests/results, terminal status/final text |
| `turn-<attempt>.pi.jsonl` | Native Pi session: system/user messages, intermediate assistant text/thinking when returned, tool calls/results, final response, SDK usage and unmodified SDK errors |
| `turn-<attempt>.errors/events.jsonl` | Lazily created unredacted HTTP response metadata, body-end status and full Node exception diagnostics |
| `turn-<attempt>.errors/request-<index>.body` | Exact HTTP non-2xx payload bytes seen by fetch, including blocked redirects; index is the attempt's 1-based guarded request count |
| `final.txt` | Final assistant text of the successfully settled attempt in that round |

Use the pinned Pi 1.4.0 CLI to export a native capture without changing it. From
the repository root, with Node >=22.19 (or `TAOSC_LLM_NODE` set):

```sh
SESSION=/absolute/path/to/run/trials/1/turn-1.pi.jsonl
"${TAOSC_LLM_NODE:-node}" \
  utils/taosc-llm/thirdparty/pi/node_modules/@earendil-works/pi-coding-agent/dist/bundle/cli.js \
  --export "$SESSION" "$SESSION.html"
```

Open the HTML in a browser; `Toggle thinking` and `Toggle tools` control details.
Pi 1.4.0's HTML transcript does not render the system prompt sections, although
its tree lists `[system]`; those sections and `toolsAdded` remain in the native
JSONL's system message. A normal Pi session viewer does not restore taosc's
custom host tools or resume synthesis.

Native and diagnostic files are created exclusively with mode 0600; error
directories use exclusive mode 0700, refusing existing directories and symlinks.
Completed native records remain on failure/cancellation; unfinished streaming text
is not guaranteed. **SDK errors and raw response files are unredacted and may
contain the configured API key or other secrets.** This is the explicit
user-approved retention policy: no error clipping, masking or credential-based
record dropping. Keep captures, diagnostics and exported HTML private; do not
publish them or feed them back to model tools/native workers.

HTTP body EOF records `complete:true`; interruption/cancellation retains received
bytes with `complete:false`. SIGKILL may omit the end row, and deadlines still
bound execution: capture cannot promise bytes never received. Node fetch's
normal decompression/header normalization apply; this is not raw TCP capture.
Redirects remain blocked, success wire bodies need not be logged, and private raw
files do not travel through bounded, sanitized stdout protocol frames. Diagnostic
creation/write failure terminates with `diagnostic_persistence_error`.

SDK zero cost fields are not real billing. Existing host journals are not converted
into native sessions; no old-results migration or deletion is performed. See the
[native persistence contract](../../agent-docs/taosc-llm/PROVIDER_AND_PI.md#native-pi-session-artifacts)
and the single authoritative
[raw error schema and privacy contract](../../agent-docs/taosc-llm/PROVIDER_AND_PI.md#raw-error-artifacts-authoritative-persistence-contract).

## Result collection

`taosc-llm-collect-results` reads saved provider/manual/no-LLM results without
loading a dataset, running a target/model, or contacting a replay server. The
checkout launcher is `collect-results.py` in this package; the module entry is
`python -m taosc_llm.collect_results`. No native tools or credentials are needed.

```sh
uv run --project utils/taosc-llm taosc-llm-collect-results \
  --exp benchmarks/loftix/exp.list --workdir workdir-0.1.24-new \
  --run-prefix taosc-llm-out --mode provider \
  --format csv --output /tmp/taosc-llm-results.csv
```

For no-LLM use its workdir and `--run-prefix taosc-llm-no-llm-out --mode no-llm`.
Alternatively, repeat `--run-dir SAVED_RUN` to collect exact runner directories,
standalone provider/manual outputs, or standalone no-LLM journals. This bypasses
experiment discovery and does not select a new candidate.

### Independent result axes

Collection deliberately does **not** use the producer's stricter `quality` or
no-LLM `score` to classify a patch. Its primary objective is **only the designated
target crash**, not eliminating every other crash or proving complete evidence.

| `target_status` | Meaning |
|---|---|
| `target_present` | At least one observed candidate reproduces the target crash. |
| `target_absent` | At least one candidate outcome is observed and none reproduces the target; normal and other-crash outcomes both qualify. |
| `not_observed` | A candidate exists but no outcome is classified; never counted as target removal. |
| `no_candidate` | No selected predicate was produced. |

These labels describe the **observed cohort**, not universal repair or causal
attribution. Unknown cases do not turn `target_absent` into an incomplete patch,
but remain explicitly counted. Baseline gaps, other crashes and branch differences
never reject a patch in this collector. Existing synthesis/selection algorithms,
model feedback, stored strict quality and exit policies are unchanged.

| Axis | Important fields / interpretation |
|---|---|
| Target outcomes | `candidate_known`, `candidate_unknown`, `candidate_target_crashes`; `candidate_other_crashes` is informational only. |
| Target transitions | `target_baselines = target_fixed + target_remaining + target_unobserved`. System cases use the applicable original; function cases use the neutral when the original is inapplicable. Unknown originals never borrow neutral outcomes. Target→normal **or other crash** counts as `target_fixed`, even with a known original/neutral mismatch; this is an observed transition, not proof that the predicate caused it. |
| Regression | `branch_regressions / branch_comparable` counts authenticated normal→normal complete-vector differences. `new_target_failures` compares compatible neutral-normal→candidate-target, not an instrumentation-induced original/neutral change. No other-crash penalty or automatic cross-run ranking is added. |
| Comparison limits | `branch_comparison_unavailable` is all cases outside that normal→normal denominator, including inapplicable transitions. It is not a count of crashing cases. `candidate_capture_incomplete` can coexist with a known normal/crash outcome. |
| Baseline diagnostics | `baseline_gaps` records unavailable/incompatible source/control/oracle evidence; known original/neutral disagreements are separately `original_neutral_mismatches`. Neither vetoes observed target transitions or an independently valid neutral branch comparison. These are recomputed diagnostics, not copies of the legacy quality facets. |
| Execution / storage | `lifecycle`, `exit_code`, `run_error` describe the producer. `collection_status`/`collection_error` describe reading its results. `legacy_quality`, publication and verification fields remain separately visible. |

Every metric is also emitted with `system_` and `function_` prefixes. Missing
evaluations have null/blank counters, not invented zeros. An existing empty
case inventory has zero counters but never `target_absent`. Regression counts
must be read with their comparable denominator: losing evidence is not progress.

### Discovery, output and recovery

- Defaults follow the BinRadar collector's experiment-list convention:
  `--exp exp.list`, `--workdir workdir`, `--run-prefix taosc-llm-out`, `--format log`.
  List entries resolve relative to the list file, including paths with spaces.
- `--runs latest` is the CLI default; `--runs all` includes every run.
  Only exact `PREFIX-NUMERIC` directories are read,
  in numeric order. `--runs latest` means the highest run number, **including
  failed/interrupted runs**, not the latest successful run. `--mode` filters the
  collected rows afterward; unknown/error rows remain visible.
- `--jobs 1` bounds memory to one selected evaluation. Explicit `--jobs N` uses
  ordered processes; `0` selects CPU/run count and may consume substantial memory.
  `--format log|csv|tsv|json` and `--output -` are supported.
  CSV/TSV have one row per run; JSON includes rows and separate summary counters.
- `subject` contains the experiment-list identifier, e.g. `binutils/CVE-2017-14745`.
  No numeric `subject_id` is generated. `-n/--no-subject-id` omits that textual
  `subject` column/key (and the subject in log headings), allowing subsequent
  experiments to be pasted to the right in a spreadsheet. Other columns, row
  order and recorded artifact paths are unchanged; use matching subject/run
  selections when comparing experiments side by side.
- Default output is `<exp-list-dir>/logs/taosc-llm-results-UTC-TIMESTAMP.<format>`.
  Explicit output never creates that default directory. Stdout output contains
  only the requested format; diagnostics go to stderr.
- Compact runner metadata selects the saved round, not the last attempted round.
  A failed provider run can retain a usable partial candidate under `result/`;
  its metrics are collected without changing the failed lifecycle. Deliberate
  generation/dataset/warm stops have no candidate. Unsupported `Single` formats
  get explicit rows; missing workdirs/runs and corrupt/missing required result
  records get collection-error rows rather than silently disappearing.
- No-LLM result/evaluation payload references and result events are checksum
  checked read-only. Collection never opens a live `Journal`, resumes search,
  loads historical branches, or rereads native capture files. It reports saved
  observations, not a new capture/binary integrity or execution verification.
- Collector exit **0** means readable results were collected, even for failed
  producer runs, target misses, regression, unknown evidence or abstention.
  Exit **1** means collection/input/output errors (other rows are retained when
  possible); invalid CLI usage exits **2**.

Provider evaluations still describe the cached descriptor, not execution of the
new fixed/selectable binaries. No-LLM `publication_status=matched` is saved local
artifact parity, not FINAL. The collector never promotes either into verification.

Validation: collector I/O tests pass (26 tests), including numeric-ID removal and
textual subject omission in all four formats. The checkout CLI was also exercised
against a saved journal with the default, `-n`, and `--no-subject-id` outputs in
each format. Pass a real journal directory to `--run-dir`: symlinked journal aliases
are rejected as `unsafe journal payload` by the existing containment check.
An isolated wheel-only installation was exercised from an external cwd, including the installed CLI,
checkout launcher, module entry and sequential/spawn-process equality on eight
saved provider/no-LLM scenarios. These included target→other crash, residual target,
baseline disagreement, failed-provider incumbent, abstention and legacy journals.
Use isolated `uv build --wheel`; the root development venv need not contain
setuptools. These checks do not rerun subjects, models or FINAL.

## Experiment runner

`taosc-llm-run` is the installed Python orchestrator; `python -m taosc_llm.runner`
is equivalent. It replaces the Bash example, not production `taosc-fix` or FINAL.
Default mode is `no-llm`; provider calls require explicit mode and credentials.

```sh
# Fresh concrete + resident producers, immutable dataset, warm, then search.
uv run --project utils/taosc-llm taosc-llm-run \
  --subject SUBJECT --workdir workdir-0.1.24 --generation-timeout 600

# Concrete-only experiment; no resident server or mutation import.
uv run --project utils/taosc-llm taosc-llm-run \
  --subject SUBJECT --workdir workdir-0.1.24 --concrete-only

# Completed producer reuse; mutations default to offline observations.
uv run --project utils/taosc-llm taosc-llm-run \
  --subject SUBJECT --workdir workdir-0.1.24 \
  --concrete-run OLD/concrete --binradar-run OLD/binradar
# Add --replay-socket OLD/binradar/replay.sock only for that same live generation.

# Prepared dataset: no native preparation, producers or REA invocation.
uv run --project utils/taosc-llm taosc-llm-run \
  --dataset DATASET --output NEW_RUN --search-timeout 900

# Explicit alternative modes; same generation/reuse options apply.
uv run --project utils/taosc-llm taosc-llm-run \
  --dataset DATASET --mode manual --predicate 'rax <= 0'
uv run --project utils/taosc-llm taosc-llm-run \
  --dataset DATASET --mode provider --provider-env /abs/provider.env
```

`--subject` defaults to cwd; `--workdir` defaults to `workdir-0.1.24` relative to
subject. Absolute workdirs are accepted; other supplied paths are relative to
invocation cwd. Lexical symlink parents are preserved. Workdir `patch-format`
wins, with subject fallback only when absent. Only `ERM generic`/`ERM CWE-805`
proceed; other nonempty values emit JSON `status=skipped`, exit 0, and allocate
nothing. Missing/invalid metadata is an error. Only concrete-only generation
without synthesis bypasses the family check. Before reserving output or starting
producers, the runner checks positive 64-bit patch addresses, subject/POC settings,
native timeout values, CWE allocator/stack metadata, and manual predicate grammar.
A supplied dataset is authenticated. Provider synthesis parses only the explicit
provider file and performs a credential-free Node/Pi import/ABI check (30-second
supervised cap); missing SDK, incompatible Node and malformed local configuration
fail here, not after generation. This is offline admission, not proof of remote
credentials/model availability. An explicit REA path must resolve before generation.
An explicit external replay endpoint must already answer as ready/evaluating;
dataset reuse also checks its frozen mutation binding before warming. Omit the
socket for offline reuse rather than naming a dead endpoint.

### Run directory selection

| Option | Meaning |
|---|---|
| omitted | `<workdir>/out/taosc-llm-no-llm-out-00000` for no-llm; `taosc-llm-out-00000` otherwise. Dataset-only runs allocate under invocation cwd. |
| `--run-prefix PREFIX` | Simple basename replacing the mode prefix; allocate above the largest numeric suffix without filling gaps. |
| `--run-id n` | New numbered root (default), atomic mode-0700 reservation; at least five digits. |
| `--run-id NUMBER` | Exact numbered root, created only if absent or selected with explicit `--resume`. |
| `--run-id l --resume` | Latest existing numbered directory; never implicit continuation. |
| `--output DIR` | Exact root; conflicts with explicitly supplied prefix/id. Unlike BinRadar's destructive output option, never replaces existing results. |

```text
<run>/
  run.json                       # atomic runner summary and attempt history
  logs/attempt-00000/             # stage stdout JSON and stderr/combined logs
  concrete/                      # only if generated by this runner
  binradar/                      # only if generated by this runner
  dataset/                       # only if prepared by this runner
  cache/                         # shared warm/synthesis evidence cache
  result/                        # existing manual/Pi or no-LLM result contract
```

The runner summary copies synthesis `quality` and `selected_round`, so batch
accounting can distinguish improved candidates, regressions and evidence gaps
without treating a built artifact or target-only non-rejection as success.

A supplied `--concrete-run` is read-only and suppresses concrete setup/generation.
A supplied `--binradar-run` suppresses cached/mutation setup and generation; its
snapshot is never restarted. Missing inputs generate under this run, never fixed
shared `br-gen-*` leaves. `--concrete-only` disables mutation import/generation,
but cached artifacts are still prepared for evaluation. Reusing concrete alone
can therefore update the workdir's cached artifacts, not the original-only
producer or its generation metadata. A workdir inode lock remains held through
cleanup; cooperating runners cannot mutate that workdir concurrently. External
tools must also respect its ownership.

After a native resident/audit fix, rebuild the tracer and start a fresh numbered
run. A completed `--concrete-run OLD/concrete` can be reused, but omit
`--binradar-run`, `--dataset`, `--replay-socket` and `--resume` to regenerate
mutations and create a new resident/dataset. Old capture files cannot recreate
the parent or change previously recorded replay eligibility. An already-running
resident keeps the old executable; a rebuild does not update it. Wait for its
owner to finish or stop it through that owner's normal cleanup before reusing
the workdir. Neither runner resume nor GNU Parallel `--resume-failed` refreshes
frozen evidence when the command still selects old mutation/dataset inputs.

`--stop-after generation|dataset|warm|synthesis` defaults to synthesis.
`--concrete-only --stop-after generation` collects concrete inputs without REA
or synthesis credentials. Dataset-only mode accepts warm/synthesis stages.
Preparation-only stages require no provider file or manual predicate.

### Lifetime and time budgets

Generated producers run concurrently after setup. Readiness uses the actual
replay status protocol, including startup/PROBE. Concrete generation must finish
and publish a nonempty manifest before freezing. Producer failure is monitored
during foreground work. Only the generated resident is automatically attached
and shut down. Reused mutations require explicit `--replay-socket` for live
execution; caller-owned runs/servers are never signalled, restarted or shut down.

| Option | Default | Scope |
|---|---:|---|
| `--generation-timeout` | 7200 s | Native per-phase integer budget; 0 explicitly unlimited. |
| `--forkserver-child-timeout` | subject/default | Optional native per-child cap, passed to owned producers; native phase/attempt clamping still applies. |
| `--binradar-representative-budget` | subject/default | Optional cap on actual mutation-generation representative replies; 0 unlimited. Requires owned mutation generation. |
| `--ready-timeout` | 0 | Optional external wall cap covering startup/PROBE/generation until ready. 0 adds no outer deadline. |
| `--concrete-timeout` | 0 | Optional external concrete wall cap **from launch**, including PROBE and MINIMIZER drain; monitored even while waiting for ready. |
| `--stage-timeout` | 0 | Optional external wall cap per setup/dataset/warm/synthesis stage; does not bound producer completion. |
| `--graceful-timeout` | 10 s | Grace before TERM/KILL escalation; positive. |
| `--search-timeout` | 3600 s | Persistent no-LLM search admission budget, not whole-program wall time. |

The default external watchdogs are disabled deliberately, not the native budgets:
PROBE precedes the generation clock, and concrete MINIMIZER has a shared native
`T + 600` drain budget plus an in-flight QASAN execution and cleanup. A second
7200-second whole-process timeout truncated both policies. Provider synthesis
likewise has per-operation budgets and optional review, not one 7200-second total.
Set explicit external caps when an overall wall bound is required; they are hard
supervisor limits and may intentionally stop before native completion. A stuck
stage outside its own native/tool deadlines otherwise has no runner wall cap.
Readiness has one watchdog owner (the supervisor), not racing client/parent timers.
Changing `--generation-timeout` does not change no-LLM search or provider budgets.

`--execution-workers` defaults to 4 (1–32). No-LLM atom/beam/clause/factor/depth
and evaluation/execution limits match its direct CLI. Explicit search options
are rejected in other modes. Provider-only options are `--pi-sdk-root`,
`--max-rounds` (1–16, default 4), and `--session-feedback`. Analysis defaults
remain 900 s import / 120 s query.

Every subprocess has an owned session. A per-job Linux subreaper guardian also
retains descendants that call `setsid` or outlive the launcher; pidfds prevent
PID-reuse mis-signalling. Ctrl-C marks cancellation and drains processes with
bounded INT→TERM→KILL escalation; a second signal requests immediate KILL.
Guardians also clean up on parent-channel loss. Handlers are restored and logs
retained. Unkillable survivors are reported as cleanup errors, never success.
Linux pidfds/subreapers are required; there is no unsafe group-number fallback.

Stdout is one runner JSON summary; stderr is progress. `run.json` references the
actual synthesis JSON and preserves its scoped result, including score/quality,
residual targets/regressions and publication status. Exit 0 means a completed
requested stage or explicit skip. Warm and synthesis children must return the
current zero-exit completed-result contract; old quality-derived 2/3 codes are
not silently accepted. Zero without a valid terminal result is also an error.
Operational warm/producer/build errors still stop the pipeline: a required
resident that cannot establish its baseline is not a completed search outcome.
Exit 124 means the runner killed an over-limit stage, not a cooperative search stop;
130/143 mean SIGINT/SIGTERM; 1 means operational failure. Argparse errors use 2.
Inspect status and synthesis evidence, not exit 0 alone. No path runs FINAL.
Existing no-LLM live-mutation artifact-publication limits are unchanged.

### Resume and CLI cutover

```sh
# Repeat the original search limits and worker policy.
uv run --project utils/taosc-llm taosc-llm-run \
  --output EXISTING_RUN --resume --search-timeout 900
```

Resume requires an initialized no-LLM search. It uses the recorded dataset,
cache and result, adds a fresh attempt log directory, and never repeats setup,
generation or warm. The engine checks code/runtime, budget and snapshot identity.
A lost resident remains unavailable; a replacement generation cannot restore its
identity. Interruption before search initialization requires a fresh run, optionally
reusing completed producers/dataset. Manual/Pi session resume is not introduced.

Removed options have no aliases: `--no-llm --predicate` becomes
`--mode manual --predicate`; `--skip-concrete` becomes `--concrete-run DIR`;
`--only-concrete` becomes `--concrete-only --stop-after generation`; `--outdir`
becomes non-destructive run selection; ambiguous `--timeout` becomes separate
budgets. No implicit `.env` file is loaded.

REA selection is `--rea`, then `TAOSC_LLM_REA`, then the checkout's pinned
`static-runtime.scm` installed into `.guix-rea`. Custom executables must supply
Java/Ghidra. Guix supplies the pinned runtime; a wheel without a checkout recipe
needs an explicit runtime. Resolution failure retains diagnostics without
starting or replacing producers.

## Native isolation and harmless fixture

Native builds and execution require Linux x86-64 Landlock + seccomp, private
writable scratch, bounded resources and no networking. Isolation failure is
fatal: no unsandboxed fallback. Credentials use a separate inherited pipe to
Node, not prompts, protocol journals, argv or native-worker environments. The
bridge's known-key protocol checks remain enabled. Private native Pi captures and
raw error artifacts may nevertheless retain provider/SDK-echoed keys unredacted;
that diagnostic retention does not grant model/tool or native-worker access.
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

REA alone, including Java/Ghidra, can be built from the repository root:

```sh
guix build -f utils/taosc-llm/static-runtime.scm

# Optional manual equivalent of taosc-llm-run's checkout runtime selection:
guix package --profile=utils/taosc-llm/.guix-rea \
  --install-from-file=utils/taosc-llm/static-runtime.scm
utils/taosc-llm/.guix-rea/bin/rea --version
```

`taosc-llm-rea` is the package's name; `rea-runtime` is its file-local Scheme
binding. Neither becomes a searchable package merely by loading `guix.scm` with
`-f`. Do not append `taosc-llm-rea` to a `guix build -f ...` command: that requests
an additional registry lookup, which reports `unknown package` here. The
standalone `static-runtime.scm` returns the REA package directly. The local
profile supplies GC roots and repeatable updates; unlike `guix build --root`, it
does not fail when the link already exists. It does not modify the user's global
Guix profile.

Full application:

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

Seven installed wrappers are `taosc-llm`, `taosc-llm-run`, `taosc-llm-no-llm`,
`taosc-llm-setup`, `taosc-llm-evaluate`, `taosc-llm-fixture`, and
`taosc-llm-collect-results`. Source allowlists and the wheel
exclude real `.env` files, credentials, workdirs, node_modules and caches. The
wheel ships Python, `runtime.c`, prompts and adapter, not the SDK/native closure.
Python 3.10+ is required; setup/evaluation/synthesis also require BinRadar native
resources. The read-only collector uses only the standard library. The local uv
project uses the checkout BinRadar package. E9 overrides are `E9TOOL`/`E9COMPILE`; otherwise
BinRadar resolves `e9patch@1.0.1`. Help does not require credentials/native discovery.
See the [maintained reference](../../agent-docs/taosc-llm/README.md) for contracts
and validation limits. Future Taosc orchestration remains a separate integration.
