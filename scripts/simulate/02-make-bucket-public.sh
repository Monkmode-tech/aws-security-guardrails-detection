#!/usr/bin/env bash
#
# Simulation 2 - someone removes S3 Block Public Access from a bucket.
#
# Expected:
#   - block_public_s3 Lambda re-applies all four settings (typically 1-3 minutes)
#   - "[AUTO-REMEDIATED] Public access blocked" email on the critical channel
#   - the account-level public access block kept the bucket private throughout
#
# ATT&CK: T1530 Data from Cloud Storage
#
set -euo pipefail
# shellcheck source=scripts/simulate/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
start_evidence "sim-02-make-bucket-public"

BUCKET="sim-public-${ACCOUNT_ID}-$(date +%s)"
cleanup() {
  log "cleaning up"
  aws s3api delete-bucket --bucket "$BUCKET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ "$AWS_REGION" == "us-east-1" ]]; then
  aws s3api create-bucket --bucket "$BUCKET" >/dev/null
else
  aws s3api create-bucket --bucket "$BUCKET" \
    --create-bucket-configuration "LocationConstraint=$AWS_REGION" >/dev/null
fi
log "created test bucket $BUCKET"

log "ATTACK: deleting the bucket's public access block"
aws s3api delete-public-access-block --bucket "$BUCKET"

fully_blocked() {
  local cfg
  cfg="$(aws s3api get-public-access-block --bucket "$BUCKET" \
    --query PublicAccessBlockConfiguration --output json 2>/dev/null)" || return 1
  jq -e 'all(.[]; . == true) and length == 4' <<<"$cfg" >/dev/null
}

log "waiting for auto-remediation (up to 10 minutes)..."
if wait_until 600 fully_blocked; then
  echo "------------------------------------------------------------------------"
  echo "RESULT: PASS - Block Public Access restored ${LAST_ELAPSED}s after it was removed"
  echo "Account-level block (stayed on throughout):"
  aws s3control get-public-access-block --account-id "$ACCOUNT_ID" \
    --query PublicAccessBlockConfiguration --output table || true
else
  echo "RESULT: FAIL - check the ${NAME_PREFIX}-block-public-s3 logs"
  exit 1
fi
