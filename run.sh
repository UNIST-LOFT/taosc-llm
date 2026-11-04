#!/usr/bin/env bash
# Debug example only: concurrent concrete/resident generation, immutable dataset,
# cache warm, then manual/provider synthesis. Scoped results are never FINAL.
set -euo pipefail

# Keep lexical aliases: resolving a short symlink can exceed sockaddr_un's limit.
absolute_path() { realpath --canonicalize-missing --no-symlinks -- "$1"; }
socket_path_fits() {
  local LC_ALL=C path=$1
  [ "${#path}" -le 107 ]
}
allocate_runs() {
  local out=$1 producer_base=$1
  mkdir -p -- "$out"
  RUNS=$(mktemp -d -- "$out/runs-debug-XXXXXXXXXX")
  LOG=$RUNS/logs
  if ! socket_path_fits "$out/br-gen-bin/replay.sock"; then
    echo "note: output socket path exceeds 107 bytes; using a temporary /tmp alias" >&2
    OUTPUT_ALIAS=$(mktemp -d -- /tmp/binradar-debug-XXXXXXXXXX)
    ln -s -- "$out" "$OUTPUT_ALIAS/out"
    producer_base=$OUTPUT_ALIAS/out
  fi
  CONCRETE_RUN=$producer_base/br-gen-con
  MUTATION_RUN=$producer_base/br-gen-bin
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
  # Only remove our symlink and its owned parent, never the physical outputs.
  if [ -n "$OUTPUT_ALIAS" ]; then
    rm -f -- "$OUTPUT_ALIAS/out"
    rmdir -- "$OUTPUT_ALIAS"
  fi
  if [ "$status" -ne 0 ] && [ -n "$LOG" ]; then echo "logs kept for diagnosis: $LOG" >&2; fi
  exit "$status"
}

default_rea() {
  if [ -n "${TAOSC_LLM_REA:-}" ]; then printf '%s' "$TAOSC_LLM_REA"; return; fi
  local candidate
  candidate=$(ls -d /gnu/store/*-taosc-llm-rea-*/bin/rea 2>/dev/null | sort | tail -1) || true
  if [ -n "$candidate" ] && "$candidate" --version >/dev/null 2>&1; then
    printf '%s' "$candidate"; return
  fi
  candidate=$(command -v rea || true)
  if [ -n "$candidate" ] && "$candidate" --version >/dev/null 2>&1; then printf '%s' "$candidate"; fi
}

main() {
  REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
  TAOSC_LLM=$REPO/utils/taosc-llm
  SUBJECT=$REPO/benchmarks/loftix/binutils/CVE-2017-14745
  WORKDIR_NAME=workdir-0.1.24
  OUTDIR= TIMEOUT=7200 READY_TIMEOUT=0 PROVIDER_ENV=$TAOSC_LLM/.env PREDICATE= NO_LLM=0 REA=
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
      -h|--help)
        cat <<'HELP'
Usage: run.sh [--subject DIR] [--workdir NAME] [--outdir DIR]
              [--timeout SECONDS] [--ready-timeout SECONDS]
              [--provider-env FILE | --no-llm --predicate PREDICATE] [--rea PATH]
Debug example: requires a prepared workdir, REA, JAVA_HOME and GHIDRA_INSTALL_DIR.
--timeout controls native generation only (default 7200; 0 means unlimited).
--ready-timeout bounds the whole readiness wait, including PROBE (default 0:
unlimited). A failed producer always ends the wait promptly.
Warm/synthesis exits 2/3 are scoped rejection/unavailable results, never FINAL.
HELP
        return 0 ;;
      *) echo "unknown option: $1" >&2; return 2 ;;
    esac
  done
  [[ "$READY_TIMEOUT" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
    echo "--ready-timeout must be nonnegative seconds" >&2; return 2;
  }
  SUBJECT=$(absolute_path "$SUBJECT")
  WORKDIR=$SUBJECT/$WORKDIR_NAME
  [ -d "$SUBJECT" ] || { echo "subject directory not found: $SUBJECT" >&2; return 2; }
  [ -f "$WORKDIR/patch-location" ] || {
    echo "$WORKDIR has no patch-location; run taosc-fix (or taosc-fix-prepare) first" >&2; return 2;
  }
  if [ -z "$REA" ]; then REA=$(default_rea); fi
  [ -n "$REA" ] || { echo "REA not found; pass --rea PATH or set TAOSC_LLM_REA" >&2; return 2; }
  if [[ "$REA" == */* ]]; then REA=$(absolute_path "$REA"); fi
  if [ -n "$PROVIDER_ENV" ]; then PROVIDER_ENV=$(absolute_path "$PROVIDER_ENV"); fi
  if [ -z "${JAVA_HOME:-}" ] || [ -z "${GHIDRA_INSTALL_DIR:-}" ]; then
    echo "note: checkout static analysis needs JAVA_HOME/GHIDRA_INSTALL_DIR (Guix wrappers supply both)" >&2
  fi
  if [ "$NO_LLM" -eq 1 ]; then
    [ -n "$PREDICATE" ] || { echo "--no-llm needs --predicate" >&2; return 2; }
  elif [ -z "$PROVIDER_ENV" ]; then
    echo "model mode needs --provider-env; use --no-llm for the manual predicate path" >&2; return 2
  fi
  OUTDIR=$(absolute_path "${OUTDIR:-$WORKDIR/out}")
  OWNED_PIDS=() CONCRETE_PID= MUTATION_PID= MUTATION_SOCKET= OUTPUT_ALIAS= LOG=
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  allocate_runs "$OUTDIR"
  DATASET=$RUNS/dataset RESULT=$RUNS/taosc-llm-result CACHE=$RUNS/taosc-llm-cache
  mkdir -p -- "$LOG" "$CACHE"
  printf 'producer outputs:\n  concrete     %s\n  mutation     %s\nartifact root: %s\n' \
    "$OUTDIR/br-gen-con" "$OUTDIR/br-gen-bin" "$RUNS"

  echo "== preparing both generation environments =="
  run_uv "$REPO" binradar-setup --generate-concrete -c "$SUBJECT" -w "$WORKDIR"
  run_uv "$REPO" binradar-setup --generate-binradar -c "$SUBJECT" -w "$WORKDIR"

  echo "== starting concrete generation and resident mutation generation =="
  # The subshell immediately execs setsid; the owned PID is the new group leader.
  (
    cd "$SUBJECT"
    exec setsid uv run --project "$REPO" binradar -w "$WORKDIR_NAME" --output "$CONCRETE_RUN" \
      --generate-concrete --timeout "$TIMEOUT"
  ) >"$LOG/concrete.log" 2>&1 &
  CONCRETE_PID=$!; OWNED_PIDS+=("$CONCRETE_PID")
  (
    cd "$SUBJECT"
    exec setsid uv run --project "$REPO" binradar -w "$WORKDIR_NAME" --output "$MUTATION_RUN" \
      --generate-binradar --replay-server --timeout "$TIMEOUT"
  ) >"$LOG/mutation.log" 2>&1 &
  MUTATION_PID=$!; OWNED_PIDS+=("$MUTATION_PID")

  echo "== waiting for the resident server to report ready =="
  # Start immediately: the explicit readiness policy includes directory creation,
  # PROBE, generation and handshake. Native generation timeout is independent.
  run_uv "$TAOSC_LLM" python -m taosc_llm.replay wait \
    --socket "$MUTATION_SOCKET" --pid "$MUTATION_PID" --timeout "$READY_TIMEOUT" >"$LOG/status.json"
  cat "$LOG/status.json"
  echo "== waiting for concrete generation =="
  while [ -n "$CONCRETE_PID" ]; do producer_health; sleep 0.1; done
  producer_health
  [ -s "$CONCRETE_RUN/minimizer.sbsv" ] || {
    echo "concrete run $CONCRETE_RUN has no minimizer.sbsv; dataset setup would fail" >&2; return 1;
  }

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
