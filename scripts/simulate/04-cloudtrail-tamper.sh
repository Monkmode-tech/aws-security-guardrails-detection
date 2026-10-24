#!/usr/bin/env bash
#
# Simulation 4 - an attacker tries to blind the defenders by stopping CloudTrail.
#
# Stops the trail for a few seconds and restarts it. The StopLogging call is
# itself recorded, so the cloudtrail-config-changes detection (CIS / Security
# Hub CloudWatch.5) must fire.
#
# Expected:
#   - alarm <prefix>-cloudtrail-config-changes goes to ALARM (typically 5-10 min,
#     CloudTrail -> CloudWatch Logs delivery plus the 5-minute alarm period)
#   - email on the critical channel
#
# ATT&CK: T1562.008 Impair Defenses: Disable or Modify Cloud Logs
#
set -euo pipefail
# shellcheck source=scripts/simulate/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
start_evidence "sim-04-cloudtrail-tamper"

TRAIL="$(tf_raw trail_name)"
ALARM="$(tf_json detection_alarms | jq -r '."cloudtrail-config-changes"')"

restart() { aws cloudtrail start-logging --name "$TRAIL" || true; }
trap restart EXIT

log "ATTACK: stopping trail $TRAIL"
aws cloudtrail stop-logging --name "$TRAIL"
sleep 5
log "restoring logging"
aws cloudtrail start-logging --name "$TRAIL"
aws cloudtrail get-trail-status --name "$TRAIL" --query '{IsLogging:IsLogging}' --output table

in_alarm() {
  [[ "$(aws cloudwatch describe-alarms --alarm-names "$ALARM" \
    --query 'MetricAlarms[0].StateValue' --output text)" == "ALARM" ]]
}

log "waiting for alarm $ALARM (up to 20 minutes)..."
if wait_until 1200 in_alarm; then
  echo "------------------------------------------------------------------------"
  echo "RESULT: PASS - tampering detected; alarm fired ${LAST_ELAPSED}s after StopLogging"
  aws cloudwatch describe-alarm-history --alarm-name "$ALARM" --history-item-type StateUpdate \
    --max-items 1 --query 'AlarmHistoryItems[0].[Timestamp,HistorySummary]' --output text
else
  echo "RESULT: FAIL - alarm did not fire; check the metric filter on the trail log group"
  exit 1
fi
