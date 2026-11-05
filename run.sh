#!/usr/bin/env bash
# Debug example only: concurrent concrete/resident generation, immutable dataset,
# cache warm, then manual/provider synthesis. Scoped results are never FINAL.
set -euo pipefail

# Preserve the user's lexical paths, including symlinked directories.
absolute_path() { realpath --canonicalize-missing --no-symlinks -- "$1"; }
allocate_runs() {
  local out=$1
  mkdir -p -- "$out"
  RUNS=$(mktemp -d -- "$out/runs-debug-XXXXXXXXXX")
  LOG=$RUNS/logs
  CONCRETE_RUN=$out/br-gen-con
  MUTATION_RUN=$out/br-gen-bin
  MUTATION_SOCKET=$MUTATION_RUN/replay.sock
}

# Own each job's process group so cleanup still reaches descendants after its
# launcher exits, and forced termination does not depend on uv's signal forwarding.
start_job() {
  setsid "$@" &
  STARTED_PID=$!
  OWNED_PIDS+=("$STARTED_PID")
}
retire_job() {
  local pid=$1 index
  # Keep a group while forwarded descendants survive its leader, but do not
  # retain completed identities throughout a potentially unlimited generation.
  if ! kill -0 -- "-$pid" 2>/dev/null; then
    for index in "${!OWNED_PIDS[@]}"; do
      if [ "${OWNED_PIDS[$index]}" = "$pid" ]; then unset 'OWNED_PIDS[index]'; fi
    done
  fi
}
producer_health() {
  local status
  if [ -n "$CONCRETE_PID" ] && ! kill -0 "$CONCRETE_PID" 2>/dev/null; then
    if wait "$CONCRETE_PID"; then status=0; else status=$?; fi
    retire_job "$CONCRETE_PID"
    CONCRETE_PID=
    if [ "$status" -ne 0 ]; then
      echo "concrete generation failed (exit $status); see $LOG/concrete.log" >&2
      return 1
    fi
  fi
  if [ -n "$MUTATION_PID" ] && ! kill -0 "$MUTATION_PID" 2>/dev/null; then
    if wait "$MUTATION_PID"; then status=0; else status=$?; fi
    retire_job "$MUTATION_PID"
    MUTATION_PID=
    echo "resident mutation generation exited before shutdown (exit $status); see $LOG/mutation.log" >&2
    return 1
  fi
}
wait_job() {
  local pid=$1 status
  while kill -0 "$pid" 2>/dev/null; do
    producer_health || return 1
    sleep 0.1
  done
  producer_health || return 1
  if wait "$pid"; then status=0; else status=$?; fi
  retire_job "$pid"
  return "$status"
}
run_uv() {
  local project=$1
  shift
  start_job uv run --project "$project" "$@"
  wait_job "$STARTED_PID"
}
owned_groups_alive() {
  local pid
  for pid in "${OWNED_PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null || kill -0 -- "-$pid" 2>/dev/null; then return 0; fi
  done
  return 1
}
cleanup() {
  local status=$? pid attempt
  trap - EXIT
  # Do not let a second signal interrupt bounded cleanup or replace its status.
  trap '' INT TERM
  if [ -n "$MUTATION_PID" ] && [ -S "$MUTATION_SOCKET" ]; then
    # uv itself may still be forwarding: bound both the helper and its children.
    start_job timeout --kill-after=1 3 uv run --project "$TAOSC_LLM" \
      python -m taosc_llm.replay shutdown --socket "$MUTATION_SOCKET" >/dev/null 2>&1
    for ((attempt=0; attempt<40; attempt++)); do
      kill -0 "$STARTED_PID" 2>/dev/null || break
      sleep 0.1
    done
  fi
  for pid in "${OWNED_PIDS[@]}"; do
    kill -TERM -- "-$pid" 2>/dev/null || true
    kill -TERM "$pid" 2>/dev/null || true
  done
  for ((attempt=0; attempt<30; attempt++)); do
    owned_groups_alive || break
    sleep 0.1
  done
  for pid in "${OWNED_PIDS[@]}"; do
    kill -KILL -- "-$pid" 2>/dev/null || true
    kill -KILL "$pid" 2>/dev/null || true
  done
  # Never make an unbounded final wait, including after SIGKILL (D-state exists).
  for ((attempt=0; attempt<10; attempt++)); do
    owned_groups_alive || break
    sleep 0.1
  done
  for pid in "${OWNED_PIDS[@]}"; do
    if ! kill -0 "$pid" 2>/dev/null; then wait "$pid" 2>/dev/null || true; fi
  done
  if [ "$status" -ne 0 ] && [ -n "$LOG" ]; then echo "logs kept for diagnosis: $LOG" >&2; fi
  exit "$status"
}

default_rea() {
  if [ -n "${TAOSC_LLM_REA:-}" ]; then printf '%s' "$TAOSC_LLM_REA"; return; fi
  if ! command -v guix >/dev/null 2>&1; then
    echo "Guix is required for the pinned REA runtime; pass --rea PATH or set TAOSC_LLM_REA to override" >&2
    return 1
  fi
  # Resolve this checkout's recipe, never a store hash ordering or an ambient shim.
  # A project-local profile supplies atomic updates and GC roots across runs.
  guix package --profile="$TAOSC_LLM/.guix-rea" \
    --install-from-file="$TAOSC_LLM/static-runtime.scm" >&2 || return
  printf '%s/.guix-rea/bin/rea\n' "$TAOSC_LLM"
}

main() {
  REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd) # binradar repo
  TAOSC_LLM=$REPO/utils/taosc-llm # taosc-llm repo
  SUBJECT=$REPO/benchmarks/loftix/binutils/CVE-2017-14745 # subject directory with config.env
  WORKDIR_NAME=workdir-0.1.24
  OUTDIR= TIMEOUT=7200 READY_TIMEOUT=0 PROVIDER_ENV=$TAOSC_LLM/.env PREDICATE= NO_LLM=0 REA=
  SKIP_CONCRETE=0 ONLY_CONCRETE=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --subject|--workdir|--outdir|--timeout|--ready-timeout|--provider-env|--predicate|--rea)
        [ $# -ge 2 ] || { echo "missing value for $1" >&2; return 2; }
        case "$1" in
          --subject) SUBJECT=$2 ;; --workdir) WORKDIR_NAME=$2 ;; --outdir) OUTDIR=$2 ;;
          --timeout) TIMEOUT=$2 ;; --ready-timeout) READY_TIMEOUT=$2 ;;
          --provider-env) PROVIDER_ENV=$2 ;; --predicate) PREDICATE=$2 ;; --rea) REA=$2 ;;
        esac
        shift 2 ;;
      --no-llm) NO_LLM=1; shift ;;
      --skip-concrete) SKIP_CONCRETE=1; shift ;;
      --only-concrete) ONLY_CONCRETE=1; shift ;;
      -h|--help)
        cat <<'HELP'
Usage: run.sh [--subject DIR] [--workdir NAME] [--outdir DIR]
              [--timeout SECONDS] [--ready-timeout SECONDS]
              [--skip-concrete | --only-concrete]
              [--provider-env FILE | --no-llm --predicate PREDICATE] [--rea PATH]
Debug example: requires a prepared workdir. By default Guix builds/resolves the
pinned REA runtime, including Java and Ghidra, at utils/taosc-llm/.guix-rea.
--rea PATH overrides TAOSC_LLM_REA; either bypasses automatic Guix resolution.
Custom REA executables must supply their own Java/Ghidra environment.
--skip-concrete reuses br-gen-con under the selected output base; it must already
have a nonempty minimizer.sbsv. Concrete setup and generation are skipped.
--only-concrete runs concrete setup/generation only: no REA, replay or Taosc.
These two flags are mutually exclusive; omitted means run the full pipeline.
Resident modes admit only ERM generic/ERM CWE-805: other nonempty patch formats
print [skip] and exit 0 before preparation; missing/empty metadata exits 2.
--timeout controls native generation only (default 7200; 0 means unlimited).
--ready-timeout bounds the whole readiness wait, including PROBE (default 0:
unlimited). A failed producer always ends the wait promptly.
Warm/synthesis exits 2/3 are scoped rejection/unavailable results, never FINAL.
HELP
        return 0 ;;
      *) echo "unknown option: $1" >&2; return 2 ;;
    esac
  done
  if [ "$SKIP_CONCRETE" -eq 1 ] && [ "$ONLY_CONCRETE" -eq 1 ]; then
    echo "--skip-concrete and --only-concrete are mutually exclusive" >&2; return 2
  fi
  [[ "$READY_TIMEOUT" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
    echo "--ready-timeout must be nonnegative seconds" >&2; return 2;
  }
  SUBJECT=$(absolute_path "$SUBJECT")
  WORKDIR=$SUBJECT/$WORKDIR_NAME
  [ -d "$SUBJECT" ] || { echo "subject directory not found: $SUBJECT" >&2; return 2; }
  if [ "$ONLY_CONCRETE" -eq 0 ]; then
    # Match generation setup: workdir metadata wins; only absence permits fallback.
    local format_file=$WORKDIR/patch-format patch_format
    if [ ! -e "$format_file" ]; then format_file=$SUBJECT/patch-format; fi
    [ -f "$format_file" ] || {
      echo "patch-format file not found: $format_file" >&2; return 2;
    }
    if ! patch_format=$(cat -- "$format_file"); then return 2; fi
    # Trim surrounding whitespace, not internal whitespace or extra lines.
    patch_format="${patch_format#"${patch_format%%[![:space:]]*}"}"
    patch_format="${patch_format%"${patch_format##*[![:space:]]}"}"
    [ -n "$patch_format" ] || {
      echo "patch-format is empty: $format_file" >&2; return 2;
    }
    case "$patch_format" in
      'ERM generic'|'ERM CWE-805') ;;
      *) printf '[skip] unsupported patch-format: %s (%s)\n' "$patch_format" "$format_file"; return 0 ;;
    esac
  fi
  [ -f "$WORKDIR/patch-location" ] || {
    echo "$WORKDIR has no patch-location; run taosc-fix (or taosc-fix-prepare) first" >&2; return 2;
  }
  OUTDIR=$(absolute_path "${OUTDIR:-$WORKDIR/out}")
  if [ "$SKIP_CONCRETE" -eq 1 ] && [ ! -s "$OUTDIR/br-gen-con/minimizer.sbsv" ]; then
    echo "--skip-concrete requires an existing nonempty $OUTDIR/br-gen-con/minimizer.sbsv" >&2
    return 2
  fi
  if [ "$ONLY_CONCRETE" -eq 0 ]; then
    if [ -z "$REA" ]; then REA=$(default_rea); fi
    [ -n "$REA" ] || { echo "REA not found; pass --rea PATH or set TAOSC_LLM_REA" >&2; return 2; }
    if [[ "$REA" == */* ]]; then REA=$(absolute_path "$REA"); fi
    if [ -n "$PROVIDER_ENV" ]; then PROVIDER_ENV=$(absolute_path "$PROVIDER_ENV"); fi
    printf 'REA runtime: %s\n' "$REA"
    if [ "$NO_LLM" -eq 1 ]; then
      [ -n "$PREDICATE" ] || { echo "--no-llm needs --predicate" >&2; return 2; }
    elif [ -z "$PROVIDER_ENV" ]; then
      echo "model mode needs --provider-env; use --no-llm for the manual predicate path" >&2; return 2
    fi
  fi
  OWNED_PIDS=() CONCRETE_PID= MUTATION_PID= MUTATION_SOCKET= LOG=
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  allocate_runs "$OUTDIR"
  mkdir -p -- "$LOG"
  printf 'producer outputs:\n  concrete     %s\n' "$CONCRETE_RUN"
  if [ "$ONLY_CONCRETE" -eq 0 ]; then printf '  mutation     %s\n' "$MUTATION_RUN"; fi
  printf 'artifact root: %s\n' "$RUNS"

  echo "== preparing selected generation environments =="
  if [ "$SKIP_CONCRETE" -eq 0 ]; then
    run_uv "$REPO" binradar-setup --generate-concrete -c "$SUBJECT" -w "$WORKDIR"
  else
    echo "== reusing concrete output: $CONCRETE_RUN =="
  fi
  if [ "$ONLY_CONCRETE" -eq 0 ]; then
    run_uv "$REPO" binradar-setup --generate-binradar -c "$SUBJECT" -w "$WORKDIR"
  fi

  # The subshell immediately execs setsid; the owned PID is the new group leader.
  if [ "$SKIP_CONCRETE" -eq 0 ]; then
    echo "== starting concrete generation =="
    (
      cd "$SUBJECT"
      exec setsid uv run --project "$REPO" binradar -w "$WORKDIR_NAME" --output "$CONCRETE_RUN" \
        --generate-concrete --timeout "$TIMEOUT"
    ) >"$LOG/concrete.log" 2>&1 &
    CONCRETE_PID=$!; OWNED_PIDS+=("$CONCRETE_PID")
  fi
  if [ "$ONLY_CONCRETE" -eq 0 ]; then
    echo "== starting resident mutation generation =="
    (
      cd "$SUBJECT"
      exec setsid uv run --project "$REPO" binradar -w "$WORKDIR_NAME" --output "$MUTATION_RUN" \
        --generate-binradar --replay-server --timeout "$TIMEOUT"
    ) >"$LOG/mutation.log" 2>&1 &
    MUTATION_PID=$!; OWNED_PIDS+=("$MUTATION_PID")

    echo "== waiting for the resident server to report ready =="
    # Readiness includes directory creation, PROBE, generation and handshake.
    run_uv "$TAOSC_LLM" python -m taosc_llm.replay wait \
      --socket "$MUTATION_SOCKET" --pid "$MUTATION_PID" --timeout "$READY_TIMEOUT" >"$LOG/status.json"
    cat "$LOG/status.json"
  fi
  if [ "$SKIP_CONCRETE" -eq 0 ]; then echo "== waiting for concrete generation =="; fi
  while [ -n "$CONCRETE_PID" ]; do producer_health; sleep 0.1; done
  producer_health
  [ -s "$CONCRETE_RUN/minimizer.sbsv" ] || {
    echo "concrete run $CONCRETE_RUN has no minimizer.sbsv; dataset setup would fail" >&2; return 1;
  }

  if [ "$ONLY_CONCRETE" -eq 1 ]; then
    printf 'artifacts:\n  run root     %s\n  concrete     %s\n  logs         %s\n' \
      "$RUNS" "$CONCRETE_RUN" "$LOG"
    return 0
  fi

  DATASET=$RUNS/dataset RESULT=$RUNS/taosc-llm-result CACHE=$RUNS/taosc-llm-cache
  mkdir -p -- "$CACHE"
  echo "== freezing the dataset (concrete run + live mutation run) =="
  run_uv "$TAOSC_LLM" taosc-llm-setup -c "$SUBJECT/config.env" -w "$WORKDIR" \
    --concrete-run "$CONCRETE_RUN" --binradar-run "$MUTATION_RUN" \
    --rea "$REA" --output "$DATASET" >"$LOG/setup.json"
  cat "$LOG/setup.json"
  echo "== warming the shared evaluation cache =="
  local warm_status synthesis_status
  if run_uv "$TAOSC_LLM" taosc-llm-evaluate --dataset "$DATASET" \
    --warm --workers 4 --cache-dir "$CACHE" >"$LOG/warm.json"; then warm_status=0; else warm_status=$?; fi
  case "$warm_status" in
    0|2|3) echo "warm exit $warm_status (neutral p0; see $LOG/warm.json)" ;;
    *) echo "cache warm failed with exit $warm_status" >&2; return 1 ;;
  esac
  echo "== candidate synthesis =="
  local mode_args=()
  if [ "$NO_LLM" -eq 1 ]; then mode_args=(--predicate "$PREDICATE"); else
    mode_args=(--provider-env "$PROVIDER_ENV" --pi-sdk-root "$TAOSC_LLM/thirdparty/pi" --max-rounds 4)
  fi
  if run_uv "$TAOSC_LLM" taosc-llm --dataset "$DATASET" "${mode_args[@]}" \
    --execution-workers 4 --output "$RESULT" --replay-socket "$MUTATION_SOCKET" \
    --cache-dir "$CACHE" >"$LOG/synthesis.json"; then synthesis_status=0; else synthesis_status=$?; fi
  cat "$LOG/synthesis.json"
  case "$synthesis_status" in
    0|2|3) echo "synthesis exit $synthesis_status (rejection-only; never FINAL)" ;;
    *) echo "synthesis failed with exit $synthesis_status" >&2; return 1 ;;
  esac

  producer_health
  echo "== shutting the resident server down =="
  # From here the resident's exit is expected, but shutdown itself stays bounded.
  local resident_pid=$MUTATION_PID attempt
  MUTATION_PID=
  run_uv "$TAOSC_LLM" timeout --kill-after=1 5 python -m taosc_llm.replay shutdown --socket "$MUTATION_SOCKET"
  for ((attempt=0; attempt<50; attempt++)); do
    kill -0 "$resident_pid" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$resident_pid" 2>/dev/null; then echo "resident shutdown did not finish" >&2; return 1; fi
  wait "$resident_pid"
  retire_job "$resident_pid"
  printf 'artifacts:\n  run root     %s\n  dataset      %s\n  result       %s\n  cache        %s\n  logs         %s\n' \
    "$RUNS" "$DATASET" "$RESULT" "$CACHE" "$LOG"
}

# Sourcing is only for focused helper regressions, not an orchestration API.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
