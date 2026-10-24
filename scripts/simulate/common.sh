#!/usr/bin/env bash
# Shared helpers for the attack simulations. Sourced, not executed.
# shellcheck disable=SC2034  # variables here are used by the sourcing scripts

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_DIR="${ENV_DIR:-$ROOT_DIR/environments/account-baseline}"
EVIDENCE_DIR="${EVIDENCE_DIR:-$ROOT_DIR/docs/evidence}"

for bin in aws jq terraform; do
  command -v "$bin" >/dev/null || { echo "missing dependency: $bin" >&2; exit 2; }
done

tf_raw()  { terraform -chdir="$ENV_DIR" output -raw "$1"; }
tf_json() { terraform -chdir="$ENV_DIR" output -json "$1"; }

AWS_REGION="$(tf_raw aws_region)"
NAME_PREFIX="$(tf_raw trail_name)"
NAME_PREFIX="${NAME_PREFIX%-trail}"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
export AWS_REGION AWS_PAGER=""

# start_evidence <name>: tee all further output into docs/evidence/<name>-<ts>.txt
start_evidence() {
  mkdir -p "$EVIDENCE_DIR"
  EVIDENCE_FILE="$EVIDENCE_DIR/$1-$(date -u +%Y%m%dT%H%M%SZ).txt"
  exec > >(tee "$EVIDENCE_FILE") 2>&1
  echo "Simulation: $1"
  echo "Account $ACCOUNT_ID, region $AWS_REGION, started $(date -u '+%Y-%m-%d %H:%M:%SZ')"
  echo "Caller: $(aws sts get-caller-identity --query Arn --output text)"
  echo "------------------------------------------------------------------------"
}

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

# wait_until <timeout-seconds> <command...>: polls every 10 s until the command
# succeeds. Prints elapsed seconds on success; returns 1 on timeout.
wait_until() {
  local timeout="$1"; shift
  local start elapsed
  start="$(date +%s)"
  while true; do
    if "$@"; then
      elapsed=$(( $(date +%s) - start ))
      log "condition met after ${elapsed}s"
      LAST_ELAPSED="$elapsed"
      return 0
    fi
    elapsed=$(( $(date +%s) - start ))
    if (( elapsed >= timeout )); then
      log "TIMEOUT after ${timeout}s"
      return 1
    fi
    sleep 10
  done
}
