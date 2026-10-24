# Runbook

Requires the AWS CLI v2 (SSO profile), Terraform >= 1.10 and `jq`. The remote
state bucket comes from `bootstrap/` in
[aws-secure-three-tier-platform](https://github.com/Monkmode-tech/aws-secure-three-tier-platform).

## 1. Before you deploy

GuardDuty, Security Hub and the AWS Config recorder are **one per region per
account**. If you ever enabled them by hand in `us-east-2`, either disable them
first or import them:

```bash
terraform import module.threat_detection.aws_guardduty_detector.this <detector-id>
terraform import module.threat_detection.aws_securityhub_account.this <account-id>
```

## 2. Deploy

```bash
cd environments/account-baseline
cp backend.hcl.example backend.hcl            # set your state bucket
cp terraform.tfvars.example terraform.tfvars  # set your emails; keep remediation_dry_run = true
terraform init -backend-config=backend.hcl
terraform apply                               # about 5-10 minutes
```

Then:

1. **Confirm the SNS subscription emails** (one per channel). Nothing is delivered until you do.
2. Expect a burst of Security Hub findings over the first day as the new account
   is scanned. That is why only CRITICAL pages you at first.
3. Review findings in Security Hub. Fixing them is good practice and good evidence.

## 3. Turn remediation on

Leave `remediation_dry_run = true` for a day. Dry-run alerts tell you exactly
what each Lambda *would* have changed. When you are comfortable:

```hcl
remediation_dry_run = false
```

and `terraform apply` again.

## 4. Run the attack simulations

Each script is self-contained, cleans up after itself, and writes a timestamped
report to `docs/evidence/`.

```bash
./scripts/simulate/01-open-ssh-to-world.sh     # expect PASS in ~1-3 min
./scripts/simulate/02-make-bucket-public.sh    # expect PASS in ~1-3 min
./scripts/simulate/03-guardduty-high-finding.sh
./scripts/simulate/04-cloudtrail-tamper.sh     # expect alarm in ~5-10 min
```

Also sign in once as the root user (then sign out) to fire `root-account-usage`,
and screenshot the alert email.

## 5. Validate attribute-based access

```bash
./scripts/validate-abac.sh                     # expect 11/11 PASS
```

## 6. Threat hunting

CloudWatch console → Logs Insights → **Saved queries** → `secbase/hunt/...`,
select the trail log group, and run. Try *console-logins* after your root
sign-in and *world-open-security-group-ingress* after simulation 01.

## 7. Operating it

| Event | What to do |
|-------|------------|
| Critical email | Follow the matching playbook in `docs/incident-response-playbooks.md` |
| `*-errors` or `*-dlq` alarm | A remediation failed. Check `/aws/lambda/<function>` logs, fix, and redrive the DLQ message |
| Change-channel emails | Skim daily; they are expected when you deploy other projects |
| Monthly | Review Security Hub score and Config compliance; rotate nothing manually (keys auto-rotate) |

## 8. Teardown

```bash
terraform -chdir=environments/account-baseline destroy
```

Both KMS keys enter a 7-day pending-deletion window. Data encrypted under the
PHI key becomes unreadable after that, which is the intended behaviour for
crypto-shredding demo data.
