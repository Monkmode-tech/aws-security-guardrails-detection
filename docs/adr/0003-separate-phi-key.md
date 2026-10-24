# ADR 0003: A separate KMS key for patient records that admins cannot use

**Status:** Accepted

## Context

By default a KMS key policy grants the account root full access, so any
administrator with broad IAM permissions can decrypt anything. For protected
health information that violates separation of duties and the HIPAA *minimum
necessary* principle.

## Decision

The PHI key policy grants the account:

- **Administration** actions (rotate, disable, tag, schedule deletion), so the
  key can still be managed and recovered; but
- **Data** actions (`Decrypt`, `GenerateDataKey`) only to the four record roles,
  and only when called through S3 in this region.

## Consequences

- An administrator can read bucket metadata but receives `AccessDenied` reading
  a record (validated by `validate-abac.sh` case 11).
- Deleting the record roles makes the data unreadable until roles with the same
  names are recreated; destroying the key crypto-shreds the data.
- Break-glass access in production would be a separate, heavily monitored role
  added to the key policy.
