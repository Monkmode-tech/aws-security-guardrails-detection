# Attribute-based access control for patient records

## Background

In CLCS 605 (Unit 2, *Cloud IAM and Data Security Design*) I designed access
controls for a healthcare organization moving its patient-management system to
the cloud under HIPAA: role-based access for physicians, nurses, billing
specialists, coordinators and pharmacists, refined by attributes such as
department, plus MFA and encryption. This module implements the core of that
design on AWS.

## Why ABAC instead of one policy per role

With role-based policies, every new ward or department means new roles and new
policies. With ABAC there is **one policy**; access is decided by comparing
attributes:

- **Principal tags** on the role: `job-function` (physician, nurse, billing) and `ward`
- **Object tags** on each record: `data-class` (clinical, billing) and `ward`

Adding an oncology physician is just a new role with `job-function=physician,
ward=oncology`. No policy changes.

## Access matrix

| Role | Clinical, own ward | Clinical, other ward | Create clinical | Billing records |
|------|--------------------|----------------------|-----------------|-----------------|
| physician-cardiology | Read | No | Yes, own ward only | No |
| nurse-cardiology | Read | No | No | No |
| nurse-oncology | Read (oncology) | No | No | No |
| billing-specialist | No | No | No | Read and write |
| Account administrator | **No** (cannot decrypt) | **No** | n/a | **No** |

This enforces HIPAA's *minimum necessary* standard: each workforce role sees
only what its job requires.

## Layers of enforcement

1. **IAM ABAC policy** (`aws_iam_policy.abac`): principal tags must match object tags.
2. **Bucket policy**: every upload must carry a `data-class` tag; TLS required.
3. **PHI KMS key policy**: administrators can manage the key (rotate, disable,
   schedule deletion) but only the four record roles can use it to decrypt, and
   only through S3. An administrator with full S3 permissions still gets
   `AccessDenied` reading a record. That is separation of duties.
4. **Detection**: CloudTrail records every access attempt; repeated denials show
   up in the *access-denied-by-principal* hunting query.

## Verification

`scripts/validate-abac.sh` assumes each role and runs 11 real S3 operations
against the expected matrix, including the administrator-cannot-read case,
and saves a PASS/FAIL table to `docs/evidence/`.

## Production differences

- People would reach these roles through IAM Identity Center permission sets with
  session tags from the identity provider (e.g., Entra ID department attribute),
  not by assuming roles directly.
- `require_mfa = true` for IAM-user-based access.
- S3 Object Lock (compliance mode) on the records bucket for retention requirements.
