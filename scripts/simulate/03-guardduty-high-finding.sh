#!/usr/bin/env bash
#
# Simulation 3 - GuardDuty reports cryptocurrency mining on an EC2 instance.
#
# Uses GuardDuty's built-in sample findings (no real malware, no real instance).
#
# Expected:
#   - critical-channel email "GuardDuty finding (severity 8...)" from EventBridge
#   - isolate_ec2 Lambda runs and reports "not_found" (sample findings reference
#     an instance that does not exist) - proving the containment path is wired
#     end to end. Unit tests cover the actual isolation logic.
#
# ATT&CK: T1496 Resource Hijacking
#
set -euo pipefail
# shellcheck source=scripts/simulate/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
start_evidence "sim-03-guardduty-high-finding"

DETECTOR_ID="$(tf_raw guardduty_detector_id)"
FUNCTION="$(tf_json remediation_functions | jq -r '.isolate_ec2')"
START_MS=$(( $(date +%s) * 1000 ))

log "generating sample finding CryptoCurrency:EC2/BitcoinTool.B!DNS on detector $DETECTOR_ID"
aws guardduty create-sample-findings --detector-id "$DETECTOR_ID" \
  --finding-types 'CryptoCurrency:EC2/BitcoinTool.B!DNS'

lambda_handled() {
  local hits
  hits="$(aws logs filter-log-events --log-group-name "/aws/lambda/$FUNCTION" \
    --start-time "$START_MS" --filter-pattern '"not_found"' \
    --query 'length(events)' --output text 2>/dev/null)" || return 1
  [[ "$hits" != "0" && "$hits" != "None" ]]
}

log "waiting for $FUNCTION to process the finding (up to 15 minutes)..."
if wait_until 900 lambda_handled; then
  echo "------------------------------------------------------------------------"
  echo "RESULT: PASS - finding routed to the containment Lambda ${LAST_ELAPSED}s after creation"
  echo "Check your inbox for the critical GuardDuty alert and the Lambda's report."
else
  echo "RESULT: FAIL - no invocation seen; check the EventBridge rule ${NAME_PREFIX}-isolate-ec2"
  exit 1
fi
