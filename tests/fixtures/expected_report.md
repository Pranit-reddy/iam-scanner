# IAM Misconfiguration Scan Report

| | |
|---|---|
| **Account** | `123456789012` |
| **Region(s)** | us-east-1 |
| **Generated** | 2026-09-26 12:00:00 UTC |
| **Benchmark** | CIS AWS Foundations Benchmark v3.0.0 |

## Summary

| Critical | High | Medium | Low |
|---|---|---|---|
| 1 | 1 | 1 | 0 |

**3 findings** from 5 checks: 1 passed, 1 errored.

## Findings

| # | Severity | Finding | Resource | CIS control(s) |
|---|---|---|---|---|
| 1 | Critical | [Customer-managed policy grants full \*:\* admin access](#1-customer-managed-policy-grants-full--admin-access) | `arn:aws:iam::123456789012:policy/sandbox-wildcard-policy` | 1.16 |
| 2 | High | [Security group allows SSH (22) from 0.0.0.0/0](#2-security-group-allows-ssh-22-from-00000) | `sg-0123456789abcdef0` | 5.2 |
| 3 | Medium | [Access key unused for 120 days and not rotated in 200 days](#3-access-key-unused-for-120-days-and-not-rotated-in-200-days) | `arn:aws:iam::123456789012:user/sandbox-stale-key-user` | 1.12, 1.14 |

## Details

### 1. Customer-managed policy grants full \*:\* admin access

- **Severity:** Critical
- **Resource:** `arn:aws:iam::123456789012:policy/sandbox-wildcard-policy` (AWS::IAM::ManagedPolicy, global)
- **Check:** `iam_wildcard_policy`

Policy sandbox-wildcard-policy allows "Action": "\*" on "Resource": "\*" and is attached to 1 principal.

**CIS controls**

- **1.16**: Ensure IAM policies that allow full "\*:\*" administrative privileges are not attached

**Evidence**

```json
{
  "attached_to": [
    "role/sandbox-admin-role"
  ],
  "statement": {
    "Action": "*",
    "Effect": "Allow",
    "Resource": "*"
  }
}
```

**Remediation**

_1.16: Ensure IAM policies that allow full "\*:\*" administrative privileges are not attached_

Find where the policy is attached:

`aws iam list-entities-for-policy --policy-arn <policy-arn>`

Detach it from each user, group and role, e.g.:

`aws iam detach-user-policy --user-name <user> --policy-arn <policy-arn>`

`aws iam detach-group-policy --group-name <group> --policy-arn <policy-arn>`

`aws iam detach-role-policy --role-name <role> --policy-arn <policy-arn>`

Replace it with a policy scoped to the specific actions and resources the principal needs. IAM Access Analyzer can generate one from CloudTrail activity.

---

### 2. Security group allows SSH (22) from 0.0.0.0/0

- **Severity:** High
- **Resource:** `sg-0123456789abcdef0` (AWS::EC2::SecurityGroup, us-east-1)
- **Check:** `ec2_open_security_group`

Security group sandbox-open-sg allows inbound TCP 22 from anywhere on the internet.

**CIS controls**

- **5.2**: Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports

**Evidence**

```json
{
  "cidr": "0.0.0.0/0",
  "from_port": 22,
  "protocol": "tcp",
  "to_port": 22
}
```

**Remediation**

_5.2: Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports_

Remove the rule:

`aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port <port> --cidr 0.0.0.0/0`

If admin access is needed, allow it only from a known CIDR (e.g. a corporate VPN range), or better, use AWS Systems Manager Session Manager and open no inbound admin ports at all.

---

### 3. Access key unused for 120 days and not rotated in 200 days

- **Severity:** Medium
- **Resource:** `arn:aws:iam::123456789012:user/sandbox-stale-key-user` (AWS::IAM::User, global)
- **Check:** `iam_stale_access_keys`

Access key AKIAEXAMPLE1 on user sandbox-stale-key-user is active, was last used 120 days ago and was created 200 days ago.

**CIS controls**

- **1.12**: Ensure credentials unused for 45 days or greater are disabled
- **1.14**: Ensure access keys are rotated every 90 days or less

**Evidence**

```json
{
  "access_key_id": "AKIAEXAMPLE1",
  "created": "2026-03-10T00:00:00+00:00",
  "last_used": "2026-05-29T00:00:00+00:00",
  "status": "Active"
}
```

**Remediation**

_1.12: Ensure credentials unused for 45 days or greater are disabled_

Check the IAM credential report for `password_last_used` and `access_key_N_last_used_date` older than 45 days.

Deactivate the unused access key:

`aws iam update-access-key --user-name <user> --access-key-id <key-id> --status Inactive`

Remove an unused console password:

`aws iam delete-login-profile --user-name <user>`

Delete the key once you confirm nothing depends on it:

`aws iam delete-access-key --user-name <user> --access-key-id <key-id>`

_1.14: Ensure access keys are rotated every 90 days or less_

1. Create a new key: `aws iam create-access-key --user-name <user>`

2. Update every application or tool that uses the old key.

3. Deactivate the old key: `aws iam update-access-key --user-name <user> --access-key-id <old-key-id> --status Inactive`

4. After confirming nothing broke, delete it: `aws iam delete-access-key --user-name <user> --access-key-id <old-key-id>`

Prefer IAM roles or IAM Identity Center (short-lived credentials) over long-lived access keys where possible.

## Check status

### Passed

- `iam_user_mfa`

### Errored

- `s3_public_bucket`: An error occurred (AccessDenied) when calling the ListBuckets operation: Access Denied
