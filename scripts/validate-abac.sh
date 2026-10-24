#!/usr/bin/env bash
#
# validate-abac.sh - prove the attribute-based access model works on live AWS.
#
# Assumes each record role in turn and attempts real S3 operations, comparing
# the outcome with the expected access matrix from docs/abac-design.md.
# The final case shows that even the account administrator cannot read
# patient records, because the PHI key only lets the record roles decrypt.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_DIR="${ENV_DIR:-$ROOT_DIR/environments/account-baseline}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/docs/evidence}"
REPORT="$OUT_DIR/abac-validation-$(date -u +%Y%m%dT%H%M%SZ).txt"

for bin in aws jq terraform; do
  command -v "$bin" >/dev/null || { echo "missing dependency: $bin" >&2; exit 2; }
done

REGION="$(terraform -chdir="$ENV_DIR" output -raw aws_region)"
BUCKET="$(terraform -chdir="$ENV_DIR" output -raw records_bucket)"
ROLES_JSON="$(terraform -chdir="$ENV_DIR" output -json record_role_arns)"
export AWS_REGION="$REGION" AWS_PAGER=""

mkdir -p "$OUT_DIR"
exec > >(tee "$REPORT") 2>&1

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
echo '{"note":"synthetic demo record - no real patient data"}' > "$WORK/record.json"

# run_as <role|admin> <command...> - run an AWS CLI command as that role.
# Temporary credentials are cached per role in the scratch directory.
run_as() {
  local who="$1"; shift
  if [[ "$who" == "admin" ]]; then
    "$@"
    return
  fi
  local cache="$WORK/creds-$who.json"
  if [[ ! -s "$cache" ]]; then
    aws sts assume-role --role-arn "$(jq -r --arg r "$who" '.[$r]' <<<"$ROLES_JSON")" \
      --role-session-name "abac-test-$who" --query Credentials --output json > "$cache"
  fi
  env -u AWS_PROFILE -u AWS_DEFAULT_PROFILE \
    AWS_ACCESS_KEY_ID="$(jq -r .AccessKeyId "$cache")" \
    AWS_SECRET_ACCESS_KEY="$(jq -r .SecretAccessKey "$cache")" \
    AWS_SESSION_TOKEN="$(jq -r .SessionToken "$cache")" \
    "$@"
}

put() {
  local args=(s3api put-object --bucket "$BUCKET" --key "$2" --body "$WORK/record.json")
  if [[ -n "$3" ]]; then args+=(--tagging "$3"); fi
  run_as "$1" aws "${args[@]}"
}

get() { run_as "$1" aws s3api get-object --bucket "$BUCKET" --key "$2" "$WORK/out.json"; }

PASS=0
FAIL=0
printf '%-4s %-22s %-6s %-48s %-8s %-8s %s\n' "#" "Principal" "Action" "Object" "Expect" "Actual" "Result"

case_() {
  local n="$1" who="$2" action="$3" key="$4" tags="$5" expect="$6" actual
  actual="DENY"
  if [[ "$action" == "PUT" ]]; then
    if put "$who" "$key" "$tags" >/dev/null 2>&1; then actual="ALLOW"; fi
  else
    if get "$who" "$key" >/dev/null 2>&1; then actual="ALLOW"; fi
  fi
  local result="PASS"
  if [[ "$actual" == "$expect" ]]; then PASS=$((PASS + 1)); else result="FAIL"; FAIL=$((FAIL + 1)); fi
  printf '%-4s %-22s %-6s %-48s %-8s %-8s %s\n' "$n" "$who" "$action" "$key" "$expect" "$actual" "$result"
}

CLIN="clinical/patient-001/visit-note.json"
BILL="billing/patient-001/claim.json"

case_ 1  physician-cardiology PUT "$CLIN"                               "data-class=clinical&ward=cardiology" ALLOW
case_ 2  physician-cardiology PUT "clinical/patient-002/visit-note.json" "data-class=clinical&ward=oncology"   DENY
case_ 3  physician-cardiology PUT "clinical/patient-003/visit-note.json" ""                                    DENY
case_ 4  nurse-cardiology     GET "$CLIN"                               ""                                    ALLOW
case_ 5  nurse-cardiology     PUT "clinical/patient-004/visit-note.json" "data-class=clinical&ward=cardiology" DENY
case_ 6  nurse-oncology       GET "$CLIN"                               ""                                    DENY
case_ 7  billing-specialist   PUT "$BILL"                               "data-class=billing"                  ALLOW
case_ 8  billing-specialist   GET "$BILL"                               ""                                    ALLOW
case_ 9  billing-specialist   GET "$CLIN"                               ""                                    DENY
case_ 10 physician-cardiology GET "$BILL"                               ""                                    DENY
case_ 11 admin                GET "$CLIN"                               ""                                    DENY

echo
echo "Result: $PASS passed, $FAIL failed (bucket $BUCKET)"
echo "Report saved to ${REPORT#"$ROOT_DIR"/}"
[[ "$FAIL" -eq 0 ]]
