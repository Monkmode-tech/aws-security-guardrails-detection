# Cost

Unlike the application projects, this baseline is meant to **stay on**: it
protects the account while the other portfolio projects come and go.

> Pricing is usage-based and changes over time. Use the
> [AWS Pricing Calculator](https://calculator.aws/) and Cost Explorer for real numbers.

| Service | How it is billed | Expected in a quiet personal account |
|---------|------------------|--------------------------------------|
| CloudTrail | First copy of management events is free; S3 storage | Cents |
| CloudWatch Logs | Ingestion + storage of trail events (90-day retention) | Low; grows with activity |
| CloudWatch alarms | Per alarm per month (about 20 alarms) | About $2 |
| GuardDuty | 30-day free trial, then per volume of events analysed | Low |
| Security Hub | 30-day free trial, then per security check | Low to moderate |
| AWS Config | Per configuration item recorded + per rule evaluation | Low with the curated resource list |
| Lambda, EventBridge, SNS, SQS | Per invocation / message | Effectively free at this volume |
| KMS | 2 customer-managed keys | About $2 |

Expect **a few dollars a month** once free trials end. The $50 account budget
from the bootstrap stage covers this with room for the application projects.

## Levers

| Variable | Default | Effect |
|----------|---------|--------|
| `config_record_all_resources` | `false` | Curated resource list instead of everything |
| `config_recording_frequency` (module) | `CONTINUOUS` | `DAILY` reduces configuration items |
| `guardduty_features` (module) | malware/EKS off | Paid add-ons stay off unless needed |
| `securityhub_standards` (module) | FSBP + CIS | Fewer standards = fewer checks |

If you need to pause spend completely, `terraform destroy` removes everything
(state and settings are recreated identically on the next apply).
