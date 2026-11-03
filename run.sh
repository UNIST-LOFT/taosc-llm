#!/usr/bin/env bash
#
# Debug example: run both BinRadar generation modes concurrently and drive
# taosc-llm against them.
#
#   1. binradar --generate-concrete        (original-only input corpus)
#   2. binradar --generate-binradar --replay-server
#   3. taosc-llm-setup / taosc-llm-evaluate / taosc-llm
#
# The two generation runs are independent producers.  They share the prepared
# workdir (that is where patch-location/patch-format/patch-destination live)
# but write different run directories, so they may run at the same time.
#
# Usage:
#   utils/taosc-llm/run.sh [--subject DIR] [--workdir NAME] [--outdir DIR]
#                          [--timeout SECONDS] [--provider-env FILE]
#                          [--predicate PREDICATE] [--rea PATH]
#                          [--no-llm]
#
# Environment:
#   TAOSC_LLM_REA         REA binary (default: `rea` from PATH)
#   JAVA_HOME             JDK required by REA/Ghidra
#   GHIDRA_INSTALL_DIR    Ghidra install root required by REA
#
# The Guix-built taosc-llm wrappers set JAVA_HOME/GHIDRA_INSTALL_DIR
# themselves.  A checkout `uv run` does not, so export them (or use the Guix
# package) before taosc-llm-setup runs.
#
# What it demonstrates, in order:
#   * concrete and mutation generation start together;
#   * the replay socket is polled with `status` (never inferred from logs), and
#     a dead launcher fails the wait instead of hanging;
#   * taosc-llm-setup freezes the concrete run and the live mutation run;
#   * taosc-llm-evaluate --warm fills the concrete cache once, then the
#     candidate evaluation reuses it;
#   * taosc-llm gets `--replay-socket` + `--cache-dir`, so function cases are
#     evaluated by the resident snapshot and concrete cases by the trusted
#     host worker.  Neither socket nor cache path is a model tool argument.
#
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TAOSC_LLM=$REPO/utils/taosc-llm
SUBJECT=$REPO/benchmarks/loftix/binutils/CVE-2017-14745
WORKDIR_NAME=workdir-0.1.24
OUTDIR=""
TIMEOUT=7200
PROVIDER_ENV=""
PREDICATE=""
NO_LLM=0
# Prefer an explicit path, then the Guix-built REA, then PATH.  A mise shim
# named `rea` can exist without a selected version and exits nonzero, so a
# bare `command -v rea` is not proof that the binary runs.
default_rea() {
  if [ -n "${TAOSC_LLM_REA:-}" ]; then
    printf '%s' "$TAOSC_LLM_REA"
    return
  fi
  local candidate
  candidate=$(ls -d /gnu/store/*-taosc-llm-rea-*/bin/rea 2>/dev/null | sort | tail -1)
  if [ -n "$candidate" ] && "$candidate" --version >/dev/null 2>&1; then
    printf '%s' "$candidate"
    return
  fi
  candidate=$(command -v rea || true)
  if [ -n "$candidate" ] && "$candidate" --version >/dev/null 2>&1; then
    printf '%s' "$candidate"
  fi
}
REA=$(default_rea)
STAMP=debug-$(date +%Y%m%d-%H%M%S)
CONCRETE_PREFIX=br-gen-con
MUTATION_PREFIX=br-gen-bin
# ``br-gen-bin-00000/replay.sock`` is 29 bytes, the widest deterministic suffix.
SOCKET_SUFFIX=/br-gen-bin-00000/replay.sock
MAX_SOCKET_PATH=107

while [ $# -gt 0 ]; do
  case "$1" in
    --subject) SUBJECT=$2; shift 2 ;;
    --workdir) WORKDIR_NAME=$2; shift 2 ;;
    --outdir) OUTDIR=$2; shift 2 ;;
    --timeout) TIMEOUT=$2; shift 2 ;;
    --provider-env) PROVIDER_ENV=$2; shift 2 ;;
    --predicate) PREDICATE=$2; shift 2 ;;
    --rea) REA=$2; shift 2 ;;
    --no-llm) NO_LLM=1; shift ;;
    -h|--help) sed -n '2,40p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

WORKDIR=$SUBJECT/$WORKDIR_NAME
[ -d "$SUBJECT" ] || { echo "subject directory not found: $SUBJECT" >&2; exit 2; }
[ -f "$WORKDIR/patch-location" ] || {
  echo "$WORKDIR has no patch-location; run taosc-fix (or taosc-fix-prepare) first" >&2
  exit 2
}
[ -n "$REA" ] || { echo "REA not found; pass --rea PATH or set TAOSC_LLM_REA" >&2; exit 2; }
if [ -z "${JAVA_HOME:-}" ] || [ -z "${GHIDRA_INSTALL_DIR:-}" ]; then
  echo "note: JAVA_HOME/GHIDRA_INSTALL_DIR are not both set; static analysis needs them" >&2
  echo "      (the Guix taosc-llm wrapper supplies both; a checkout run must export them)" >&2
fi
if [ "$NO_LLM" -eq 1 ]; then
  [ -n "$PREDICATE" ] || { echo "--no-llm needs --predicate" >&2; exit 2; }
elif [ -z "$PROVIDER_ENV" ]; then
  echo "model mode needs --provider-env; use --no-llm for the manual predicate path" >&2
  exit 2
fi

# A fresh run root keeps run ids deterministic (0) for the whole example and
# avoids reusing another operator's in-flight run directories.
if [ -z "$OUTDIR" ]; then
  OUTDIR=$WORKDIR/out
fi
RUNS=$OUTDIR/runs-$STAMP
if [ $(( ${#RUNS} + ${#SOCKET_SUFFIX} )) -gt "$MAX_SOCKET_PATH" ]; then
  SHORT=/tmp/binradar-debug-$STAMP
  echo "note: $RUNS$SOCKET_SUFFIX exceeds the ${MAX_SOCKET_PATH}-byte Unix socket" >&2
  echo "      limit; using $SHORT instead (override with --outdir on a short path)" >&2
  RUNS=$SHORT
fi
[ $(( ${#RUNS} + ${#SOCKET_SUFFIX} )) -le "$MAX_SOCKET_PATH" ] || {
  echo "output path still exceeds the Unix socket limit: $RUNS" >&2
  exit 2
}

LOG=$RUNS/logs
CONCRETE_RUN=$RUNS/$CONCRETE_PREFIX-00000
MUTATION_RUN=$RUNS/$MUTATION_PREFIX-00000
MUTATION_SOCKET=$MUTATION_RUN/replay.sock
DATASET=$RUNS/dataset
RESULT=$RUNS/taosc-llm-result
CACHE=$RUNS/taosc-llm-cache
mkdir -p "$LOG" "$CACHE"

CONCRETE_PID=
MUTATION_PID=
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  # Ask the resident server to shut down before signalling anything: that path
  # reaps the snapshot parent, solver and child and removes the socket.
  if [ -n "$MUTATION_PID" ] && kill -0 "$MUTATION_PID" 2>/dev/null; then
    if [ -S "$MUTATION_SOCKET" ]; then
      uv run --project "$TAOSC_LLM" python -m taosc_llm.replay shutdown \
        --socket "$MUTATION_SOCKET" >/dev/null 2>&1 || true
    fi
    for _ in $(seq 1 40); do
      kill -0 "$MUTATION_PID" 2>/dev/null || break
      sleep 0.5
    done
    kill -TERM "$MUTATION_PID" 2>/dev/null || true
  fi
  [ -n "$CONCRETE_PID" ] && kill -TERM "$CONCRETE_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  if [ "$status" -ne 0 ]; then
    echo "logs kept for diagnosis: $LOG" >&2
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

run_uv() { uv run --project "$1" "${@:2}"; }

# Background a generation in THIS shell so `wait "$pid"` sees it.  A command
# substitution would background it in a subshell, and the returned pid would
# no longer be a child of the orchestration shell.
STARTED_PID=
start_generation() {
  local prefix=$1 log=$2
  shift 2
  (
    cd "$SUBJECT"
    exec uv run --project "$REPO" binradar -w "$WORKDIR_NAME" -o "$RUNS" \
      "$@" --run-prefix "$prefix"
  ) >"$log" 2>&1 &
  STARTED_PID=$!
}

echo "== preparing both generation environments =="
run_uv "$REPO" binradar-setup --generate-concrete -c "$SUBJECT" -w "$WORKDIR"
run_uv "$REPO" binradar-setup --generate-binradar -c "$SUBJECT" -w "$WORKDIR"

echo "== starting concrete generation and resident mutation generation =="
start_generation "$CONCRETE_PREFIX" "$LOG/concrete.log" \
  --generate-concrete --timeout "$TIMEOUT"
CONCRETE_PID=$STARTED_PID
start_generation "$MUTATION_PREFIX" "$LOG/mutation.log" \
  --generate-binradar --replay-server --timeout "$TIMEOUT"
MUTATION_PID=$STARTED_PID

for _ in $(seq 1 600); do
  [ -d "$MUTATION_RUN" ] && break
  kill -0 "$MUTATION_PID" 2>/dev/null || break
  sleep 0.1
done
[ -d "$MUTATION_RUN" ] || {
  echo "mutation generation did not create $MUTATION_RUN; tail $LOG/mutation.log" >&2
  exit 1
}

echo "== waiting for the resident server to report ready =="
# `status` is the only completion signal; a closed socket or a log line is not.
# A dead launcher pid fails immediately instead of waiting out the timeout.
# The generation deadline bounds new attempts, but the in-flight child and its
# cleanup may finish just after it, so allow a bounded grace on top.
WAIT_TIMEOUT=$((TIMEOUT + 300))
run_uv "$TAOSC_LLM" python -m taosc_llm.replay wait \
  --socket "$MUTATION_SOCKET" --pid "$MUTATION_PID" --timeout "$WAIT_TIMEOUT" \
  | tee "$LOG/status.json"

echo "== waiting for concrete generation =="
if ! wait "$CONCRETE_PID"; then
  CONCRETE_PID=
  echo "concrete generation failed; last log lines:" >&2
  tail -5 "$LOG/concrete.log" >&2 || true
  exit 1
fi
CONCRETE_PID=
[ -d "$CONCRETE_RUN" ] || { echo "concrete generation produced no run" >&2; exit 1; }
[ -s "$CONCRETE_RUN/minimizer.sbsv" ] || {
  echo "concrete run $CONCRETE_RUN has no minimizer.sbsv; dataset setup would fail" >&2
  exit 1
}

echo "== freezing the dataset (concrete run + live mutation run) =="
[ ! -e "$DATASET" ] || { echo "dataset path already exists: $DATASET" >&2; exit 1; }
run_uv "$TAOSC_LLM" taosc-llm-setup -c "$SUBJECT/config.env" -w "$WORKDIR" \
  --concrete-run "$CONCRETE_RUN" \
  --binradar-run "$MUTATION_RUN" \
  --rea "$REA" \
  --output "$DATASET" | tee "$LOG/setup.json"

# Warm once so later candidate evaluations reuse real concrete captures.  The
# cache directory is explicit and shared with synthesis below.
echo "== warming the shared evaluation cache =="
# Warm evaluates neutral p0, so reproducing the original crash is a normal
# result and exits 2; unavailable exits 3.  Only an actual failure exits 1.
set +e
run_uv "$TAOSC_LLM" taosc-llm-evaluate --dataset "$DATASET" \
  --warm --workers 4 --cache-dir "$CACHE" >"$LOG/warm.json"
warm_status=$?
set -e
case "$warm_status" in
  0|2|3) echo "warm exit $warm_status (neutral p0; see $LOG/warm.json)" ;;
  *) echo "cache warm failed with exit $warm_status" >&2; exit 1 ;;
esac

echo "== candidate synthesis =="
# Synthesis exits 2 for reject_same_crash and 3 for unavailable: both are
# scoped rejection-only results, not orchestration failures.  Capture and
# report them instead of aborting before the resident server is shut down.
set +e
if [ "$NO_LLM" -eq 1 ]; then
  run_uv "$TAOSC_LLM" taosc-llm --dataset "$DATASET" --predicate "$PREDICATE" \
    --execution-workers 4 --output "$RESULT" \
    --replay-socket "$MUTATION_SOCKET" --cache-dir "$CACHE" \
    | tee "$LOG/synthesis.json"
  synthesis_status=${PIPESTATUS[0]}
else
  run_uv "$TAOSC_LLM" taosc-llm --dataset "$DATASET" \
    --provider-env "$PROVIDER_ENV" \
    --pi-sdk-root "$TAOSC_LLM/thirdparty/pi" \
    --execution-workers 4 --max-rounds 4 --output "$RESULT" \
    --replay-socket "$MUTATION_SOCKET" --cache-dir "$CACHE" \
    | tee "$LOG/synthesis.json"
  synthesis_status=${PIPESTATUS[0]}
fi
set -e
case "$synthesis_status" in
  0|2|3) echo "synthesis exit $synthesis_status (rejection-only; never FINAL)" ;;
  *) echo "synthesis failed with exit $synthesis_status" >&2; exit 1 ;;
esac

echo "== shutting the resident server down =="
run_uv "$TAOSC_LLM" python -m taosc_llm.replay shutdown --socket "$MUTATION_SOCKET"
wait "$MUTATION_PID"
MUTATION_PID=

echo "artifacts:"
echo "  run root     $RUNS"
echo "  dataset      $DATASET"
echo "  result       $RESULT"
echo "  cache        $CACHE"
echo "  logs         $LOG"
