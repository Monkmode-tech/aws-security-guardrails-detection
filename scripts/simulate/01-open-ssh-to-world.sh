#!/usr/bin/env bash
#
# Simulation 1 - a developer opens SSH (22/tcp) to the entire internet.
#
# Creates a throwaway VPC and security group, adds the risky rule, and measures
# how long the revoke_public_ingress Lambda takes to remove it.
#
# Expected:
#   - rule revoked automatically (typically within 1-3 minutes)
#   - group tagged SecurityAutoRemediated=<time>
#   - "[AUTO-REMEDIATED] World-open ingress revoked" email on the critical channel
#   - security-group-changes / vpc-changes alarms on the change channel
#
# ATT&CK: T1133 External Remote Services, T1562.007 Disable or Modify Cloud Firewall
#
set -euo pipefail
# shellcheck source=scripts/simulate/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
start_evidence "sim-01-open-ssh-to-world"

VPC_ID=""
SG_ID=""
cleanup() {
  log "cleaning up"
  if [[ -n "$SG_ID" ]]; then aws ec2 delete-security-group --group-id "$SG_ID" || true; fi
  if [[ -n "$VPC_ID" ]]; then aws ec2 delete-vpc --vpc-id "$VPC_ID" || true; fi
}
trap cleanup EXIT

VPC_ID="$(aws ec2 create-vpc --cidr-block 10.250.0.0/16 \
  --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=simulation-01}]' \
  --query Vpc.VpcId --output text)"
SG_ID="$(aws ec2 create-security-group --group-name simulation-open-ssh \
  --description "Simulation 01 - temporary" --vpc-id "$VPC_ID" --query GroupId --output text)"
log "created test group $SG_ID in $VPC_ID"

log "ATTACK: authorizing 22/tcp from 0.0.0.0/0"
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
  --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null

world_rule_gone() {
  local open
  open="$(aws ec2 describe-security-group-rules --filters "Name=group-id,Values=$SG_ID" \
    --query "length(SecurityGroupRules[?CidrIpv4=='0.0.0.0/0' && IsEgress==\`false\`])" --output text)"
  [[ "$open" == "0" ]]
}

log "waiting for auto-remediation (up to 10 minutes)..."
if wait_until 600 world_rule_gone; then
  tag="$(aws ec2 describe-security-groups --group-ids "$SG_ID" \
    --query "SecurityGroups[0].Tags[?Key=='SecurityAutoRemediated'].Value | [0]" --output text)"
  echo "------------------------------------------------------------------------"
  echo "RESULT: PASS - world-open SSH revoked ${LAST_ELAPSED}s after it was created"
  echo "        group tag SecurityAutoRemediated=$tag"
else
  echo "RESULT: FAIL - rule still open; check the ${NAME_PREFIX}-revoke-public-ingress logs"
  exit 1
fi
