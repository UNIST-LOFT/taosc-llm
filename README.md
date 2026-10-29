# taosc-llm

Synthesize one generic binary guard with an isolated Pi SDK session, or build a
manually supplied predicate. The live path uses an explicitly selected provider
file and caller-prepared evidence; it is **not a BinRadar evidence importer or
repair verifier**. Existing Taosc scripts do not yet invoke this package.

## Live harmless fixture

From the repository root, prepare the pinned development SDK once (Node >=22.19):

```sh
npm --prefix utils/taosc-llm/thirdparty/pi ci --ignore-scripts --no-audit --no-fund
uv run --project utils/taosc-llm taosc-llm-fixture \
  --directory /tmp/taosc-llm-example \
  --provider-env utils/taosc-llm/.env \
  --pi-sdk-root utils/taosc-llm/thirdparty/pi
```

The directory must not exist. Omit `--provider-env` to prepare inputs without a
model request. Add `--pie` to exercise PIE. The fixture has no vulnerability:
a signed input <=0 must return 23; positive inputs must return 17. Register data
is explicitly source-derived, not an authenticated runtime snapshot. Six ordinary
boundary inputs are held out from the model. The host checks original, fixed,
fixed-with-selector, and selectable unset/0/1 behavior: 54 executions per run.
`fixture_verification.status=passed` applies only to these cases; top-level
`verified=false` and `binradar_verification=not_run` remain unchanged.

The real Ollama smoke exercised streaming, custom tools, final JSON, native
compilation and all 54 checks. This does not establish provider maximum context,
model determinism, exhaustive correctness or research-subject repair quality.

## Prepared target and evidence

```sh
uv run --project utils/taosc-llm taosc-llm \
  --config /path/to/config.env --workdir /path/to/prepared-workdir \
  --provider-env utils/taosc-llm/.env --context /path/to/evidence.json \
  --pi-sdk-root utils/taosc-llm/thirdparty/pi
```

`python -m taosc_llm` has the same CLI. The local uv source uses the main checkout's
BinRadar package, not PyPI. Python 3.10+ is required. Runtime resources come from
`binradar.paths`; a Python-only wheel without native resources is insufficient.
Guix supplies the SDK/root and Node automatically; outside Guix select the SDK
root explicitly. No global Pi installation or home credentials are discovered.

Required target inputs:

```text
config.env                  BINARY="example"; other keys are not executed
prepared-workdir/
  example.orig              original x86-64 ELF executable
  patch-location            one hexadecimal ELF virtual address
  patch-destination         one nonzero hexadecimal ELF virtual address
  patch-format              optional; if present, must be ERM generic
```

Addresses can have a `0x` prefix and must belong to executable file-backed
segments. Use the selected destination, not the list of possible `destinations`.
The caller owns valid instruction boundaries and handler/frame compatibility.
PIE and non-PIE are supported using E9's saved runtime `rip` plus the static
location-to-destination delta. Target generation does not execute the target.

Evidence JSON is a strict, bounded caller-prepared format, **not raw
`--generate-binradar` output**. Its exact fields, limits and provenance rules are
in [the evidence contract](../../agent-docs/taosc-llm/PROMPTS_AND_EVIDENCE.md).
The fixture's generated `evidence.json` is a runnable example. System/function
records remain distinct; unknown registers remain unavailable. A supplied source
reference is an opaque string, never a path the model can open. Only admitted
development data should be included: selected projections are sent to the cloud.

The host freezes hashes and inputs under `workdir/taosc-llm/contexts/<digest>/`.
One run under `workdir/taosc-llm/runs/<id>/` contains `run.json`, `context.json`,
`trials/<attempt>.jsonl`, the final proposal, and candidate-owned
`candidates/1/build-workdir/` plus build results. The original workdir's existing
candidate outputs are not overwritten. A candidate requires context inspection,
a successful check of the exact proposed expression, and final strict JSON/parser
validation. Abstention and rejected responses produce no candidate.

## Provider configuration and recovery

The provider file is loaded explicitly as data, never sourced. Supported syntax:
blank lines, whole-line `#` comments, and `KEY=value`; matching quotes are removed
literally. No interpolation, `export`, executable substitutions or inline-comment
processing. Required fields are `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_MODEL`.
The existing `.env.example` remains the public template; do not put a key in argv.

Default `ollama-dev` policy requires `https://ollama.com/v1` and exact model
`deepseek-v4.1-flash:1017`. `TAOSC_LLM_MAX_IN_FLIGHT` defaults to 3 and must be 1–3;
`TAOSC_LLM_WORKERS` defaults to 3 and bounds simultaneous model sessions.
Explicit nonsecret CLI overrides are `--base-url`, `--model`, `--max-in-flight`,
`--workers`. Ambient provider variables, Pi defaults and fallback models are ignored.

Other optional fields: `TAOSC_LLM_CONTEXT_WINDOW=32768`, `TAOSC_LLM_MAX_TOKENS=8192`,
`TAOSC_LLM_TIMEOUT_SECONDS=600`, `TAOSC_LLM_MAX_TURNS=16`,
`TAOSC_LLM_MAX_TOOL_CALLS=64`. Sizes are **client bounds, not advertised maxima**;
pricing is unknown. An explicit `TAOSC_LLM_PROFILE=openai-compatible` permits a
different HTTPS chat endpoint/model and provider cap 0, still with finite workers.
It cannot bypass Ollama's cap. Other providers require their own live admission.

One coordinator owns a private lock and durable reservations in the account's
passwd-home `.local/state/taosc-llm/quota`, independent of `HOME`, workdir or key
rotation. Another coordinator fails rather than multiplying the cap. Python users
can share one `QuotaOwner` across asynchronous `synthesize_context` calls; the CLI
runs one context at a time. This local owner cannot account for another host/user
or unrelated client using the same cloud account: stop or coordinate those clients.

A reservation covers the whole Pi operation, including tool continuations and
bounded 429 retry-after handling. Truncated streams, timeout and uncertain aborts
remain quarantined across process restarts. They are **not** automatically freed
by a timer. Only after independently establishing that all remote work has stopped:

```sh
taosc-llm recover-quota --confirm-provider-settled
```

This flag is an operator assertion, not a remote cancellation API. Do not use it
merely because a local process exited. Auth failures and unsupported responses
are redacted errors, never another-model fallback.

## Restricted tools and native execution

Pi 1.4.0 receives exactly `get_patch_context`, `get_function_context`,
`list_observations`, `get_observation`, `check_predicate`. No built-in tools,
extensions, MCP/REA, shell, arbitrary files, debugger or target execution. Evidence
and function views are frozen data; no REA process is required. The existing
BinRadar parser/evaluator owns syntax, signed-i64 behavior and trap reporting.

Credentials travel to Node through a separate inherited pipe. They are absent
from protocol journals, prompts, argv and native child environments. Native model-
selected builds and fixture executions use Linux x86-64 Landlock + seccomp, private
writable scratch, bounded resources and no networking. Private files and `/proc`
reads are denied. If isolation cannot start, the operation fails; there is no
unsandboxed fallback. Runtime/system trees remain readable, and Landlock ABI 1
does not hide all path metadata: this is not a VM or a generic hostile-kernel gate.

## Manual predicate path and artifacts

```sh
uv run --project utils/taosc-llm taosc-llm \
  --config /path/to/config.env --workdir /path/to/prepared-workdir \
  --predicate 'rax == 0'
```

Manual mode does not load credentials or call a model. Add `--isolate-native` to
use the same native sandbox; without it the previous manual execution policy is
preserved. Its outputs are published directly in the supplied workdir.

`--predicate` accepts signed-i64 register expressions, not arbitrary C/Python,
stack/memory dereferences, calls or allocator-clamp predicates. **Nonzero means
jump.** For `rax == 0`, the safe-condition file contains `(rax == 0) == 0`, lowered
through BinRadar's parser; model text is never interpolated into generated C.
Arithmetic traps follow original flow and report branch 2, not success.

| Artifact | Meaning |
|---|---|
| `<binary>.patched` | Fixed candidate, independent of `PATCH_ID` |
| `<binary>.brpatched` | Selector: unset/0 original; 1 candidate |
| `<binary>.{patched,brpatched}.json` | Each binary's E9 command stream |
| `<binary>.{patched,brpatched}.e9map.json` | Exact binary-bound relocation metadata |
| `patch-format`, `predicates`, `brpatches.json` | Generic family, safe condition, id-1 descriptor |
| `brpatch.c`, `brpatches.inc`, `predicate.h`, `taosc-llm-*.c` | Native evaluator/adapter inputs |

Builds stage both artifacts before publishing, but final renames are per-file,
not an atomic directory transaction. Consume only a complete success record and
matching hashes, never partial files. Do not share a manual workdir with a build
or verifier. Native commands have 300-second deadlines. Successful build JSON
contains `status=built`, `verified=false` and artifact paths; LLM runs wrap this
under `build` and add context/proposal/attempt records. Diagnostics go to stderr.

```python
from pathlib import Path
from taosc_llm.builder import generate_patch
from taosc_llm.synthesis import generate_with_pi

manual = generate_patch(Path("config.env"), Path("workdir"), "rax == 0")
# Live call: explicit provider file and caller-prepared development evidence.
proposed = generate_with_pi(Path("config.env"), Path("workdir"),
                           Path("evidence.json"), Path("provider.env"),
                           sdk_root=Path("thirdparty/pi"))
```

Taosc can consume CLI JSON/exit status without a `taosc -> taosc-llm -> taosc`
cycle. Authenticated BinRadar concrete/mutation import and verifier handoff are
still P2/P3. Rerun fresh BinRadar setup before verification; this package does not
refresh `binradar.env`, filters, cached artifacts or prior results. Existing
BinRadar generic setup prepends `0x` to destination metadata and rebuilds with a
literal destination: retain unprefixed hex for that handoff. This backend's PIE
proof does **not** prove the subsequent BinRadar rebuild is PIE-compatible.

## Guix and offline checks

```sh
guix build -L utils/loftix -f utils/taosc-llm/guix.scm
guix shell -L utils/loftix -f utils/taosc-llm/guix.scm -- \
  taosc-llm-fixture --directory /tmp/taosc-llm-guix-example \
  --provider-env /absolute/path/to/provider.env
```

The local recipe uses checkout BinRadar Python/resources with Loftix's native
closure. It packages exact Pi SDK/AI 1.4.0, lockfile-pinned registry tarballs, a
channel-selected compatible Node, prompts and adapter; runtime never runs npm.
The SDK package extracts verified tarballs without lifecycle hooks. Outside Guix,
run the same pinned `npm ci --ignore-scripts`; do not use `latest` or a global Pi.

Source allowlists exclude real `.env`, credentials, workdirs, node_modules and
npm caches. The wheel includes Python, `runtime.c`, prompts and adapter, but not
the SDK/native tools. E9 executables can be selected with `E9TOOL`/`E9COMPILE`;
otherwise BinRadar resolves `e9patch@1.0.1`. `--help` needs neither auth nor native
tool discovery. This is a local recipe, not a published Loftix release.

```sh
E9TOOL=/path/to/e9tool E9COMPILE=/path/to/e9compile \
TAOSC_LLM_PI_SDK_ROOT=/absolute/path/to/utils/taosc-llm/thirdparty/pi \
  uv run --project utils/taosc-llm python -m pytest utils/taosc-llm/tests
```

Tests exercise native PIE/non-PIE behavior, strict evidence/proposal boundaries,
private state/crash recovery, concurrent admission, and the actual SDK with fake
HTTP streams for tool continuation, auth/429, redirect, truncation and cancellation.
No real credentials or provider requests enter package tests. SDK/native tests
skip only when their explicit dependencies are absent; Guix supplies them.
See [the maintained design and remaining gates](../../agent-docs/taosc-llm/README.md).
