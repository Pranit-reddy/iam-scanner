> **Note:** Generated with `--key-max-age-days 0 --key-unused-days 0` to force the key-based findings to appear immediately for demonstration purposes. This also flags the scanning user's own recent key (`IAMTest1`, finding 5), which is expected at these thresholds.

# IAM Misconfiguration Scan Report

| | |
|---|---|
| **Account** | `123456789012` |
| **Region(s)** | us-east-1 |
| **Generated** | 2026-09-27 00:12:15 UTC |
| **Benchmark** | CIS AWS Foundations Benchmark v3.0.0 |

## Summary

| Critical | High | Medium | Low |
|---|---|---|---|
| 2 | 2 | 2 | 0 |

**6 findings** from 6 checks: 1 passed, 0 errored.

## Findings

| # | Severity | Finding | Resource | CIS control(s) |
|---|---|---|---|---|
| 1 | Critical | [Customer-managed policy grants full \*:\* admin access](#1-customer-managed-policy-grants-full--admin-access) | `arn:aws:iam::123456789012:policy/iam-scanner-sandbox-wildcard-policy` | 1.16 |
| 2 | Critical | [S3 bucket is publicly accessible via its bucket policy](#2-s3-bucket-is-publicly-accessible-via-its-bucket-policy) | `arn:aws:s3:::iam-scanner-sandbox-public-123456789012` | 2.1.4 |
| 3 | High | [Security group allows SSH (22), RDP (3389) from the internet](#3-security-group-allows-ssh-22-rdp-3389-from-the-internet) | `sg-0a420b13ffac24c79` | 5.2 |
| 4 | High | [IAM user has console access without MFA](#4-iam-user-has-console-access-without-mfa) | `arn:aws:iam::123456789012:user/iam-scanner-sandbox-no-mfa-user` | 1.10 |
| 5 | Medium | [Access key unused for 0 days and not rotated in 0 days](#5-access-key-unused-for-0-days-and-not-rotated-in-0-days) | `arn:aws:iam::123456789012:user/IAMTest1` | 1.12, 1.14 |
| 6 | Medium | [Access key never used and not rotated in 0 days](#6-access-key-never-used-and-not-rotated-in-0-days) | `arn:aws:iam::123456789012:user/iam-scanner-sandbox-stale-key-user` | 1.12, 1.14 |

## Details

### 1. Customer-managed policy grants full \*:\* admin access

- **Severity:** Critical
- **Resource:** `arn:aws:iam::123456789012:policy/iam-scanner-sandbox-wildcard-policy` (AWS::IAM::ManagedPolicy, global)
- **Check:** `iam_wildcard_policy`

Policy iam-scanner-sandbox-wildcard-policy allows "Action": "\*" on "Resource": "\*" and is attached to 1 principal.

**CIS controls**

- **1.16**: Ensure IAM policies that allow full "\*:\*" administrative privileges are not attached

**Evidence**

```json
{
  "attached_to": [
    "group/iam-scanner-sandbox-wildcard-admins"
  ],
  "policy_name": "iam-scanner-sandbox-wildcard-policy",
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

### 2. S3 bucket is publicly accessible via its bucket policy

- **Severity:** Critical
- **Resource:** `arn:aws:s3:::iam-scanner-sandbox-public-123456789012` (AWS::S3::Bucket, us-east-1)
- **Check:** `s3_public_bucket`

Bucket iam-scanner-sandbox-public-123456789012 has a bucket policy that allows anyone (Principal "\*") access, and Block Public Access does not restrict it at the bucket or account level.

**CIS controls**

- **2.1.4**: Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'

**Evidence**

```json
{
  "account_block_public_access": {
    "BlockPublicAcls": false,
    "BlockPublicPolicy": false,
    "IgnorePublicAcls": false,
    "RestrictPublicBuckets": false
  },
  "bucket_block_public_access": {
    "BlockPublicAcls": false,
    "BlockPublicPolicy": false,
    "IgnorePublicAcls": false,
    "RestrictPublicBuckets": false
  },
  "parser_is_public": true,
  "policy_status_is_public": true,
  "public_statements": [
    {
      "Action": "s3:GetObject",
      "Effect": "Allow",
      "Principal": "*",
      "Resource": "arn:aws:s3:::iam-scanner-sandbox-public-123456789012/*",
      "Sid": "PublicReadGetObject"
    }
  ],
  "verdict_discrepancy": null
}
```

**Remediation**

_2.1.4: Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'_

Console: S3 → select the bucket → Permissions → Block public access (bucket settings) → Edit → check 'Block all public access' → Save.

CLI:

`aws s3api put-public-access-block --bucket <bucket> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`

Also remove any `"Principal": "*"` statements from the bucket policy, and enable Block Public Access at the account level: `aws s3control put-public-access-block --account-id <account-id> ...`

---

### 3. Security group allows SSH (22), RDP (3389) from the internet

- **Severity:** High
- **Resource:** `sg-0a420b13ffac24c79` (AWS::EC2::SecurityGroup, us-east-1)
- **Check:** `ec2_open_security_group`

Security group iam-scanner-sandbox-open-sg in vpc-08ac5bcba04d31100 allows inbound SSH (22), RDP (3389) from 0.0.0.0/0.

**CIS controls**

- **5.2**: Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports

**Evidence**

```json
{
  "group_name": "iam-scanner-sandbox-open-sg",
  "open_rules": [
    {
      "admin_ports": [
        22
      ],
      "cidr": "0.0.0.0/0",
      "from_port": 22,
      "protocol": "tcp",
      "to_port": 22
    },
    {
      "admin_ports": [
        3389
      ],
      "cidr": "0.0.0.0/0",
      "from_port": 3389,
      "protocol": "tcp",
      "to_port": 3389
    }
  ],
  "vpc_id": "vpc-08ac5bcba04d31100"
}
```

**Remediation**

_5.2: Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports_

Remove the rule:

`aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port <port> --cidr 0.0.0.0/0`

If admin access is needed, allow it only from a known CIDR (e.g. a corporate VPN range), or better, use AWS Systems Manager Session Manager and open no inbound admin ports at all.

---

### 4. IAM user has console access without MFA

- **Severity:** High
- **Resource:** `arn:aws:iam::123456789012:user/iam-scanner-sandbox-no-mfa-user` (AWS::IAM::User, global)
- **Check:** `iam_user_mfa`

User iam-scanner-sandbox-no-mfa-user can sign in to the AWS console with a password, but has no active MFA device.

**CIS controls**

- **1.10**: Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password

**Evidence**

```json
{
  "mfa_active": "false",
  "password_enabled": "true",
  "password_last_used": "no_information",
  "user": "iam-scanner-sandbox-no-mfa-user"
}
```

**Remediation**

_1.10: Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password_

Console: IAM → Users → select the user → Security credentials → Multi-factor authentication (MFA) → Assign MFA device, and follow the prompts.

If the user does not need console access, remove the password instead:

`aws iam delete-login-profile --user-name <user>`

To enforce MFA, attach a policy that denies all actions except MFA self-management when `aws:MultiFactorAuthPresent` is false.

---

### 5. Access key unused for 0 days and not rotated in 0 days

- **Severity:** Medium
- **Resource:** `arn:aws:iam::123456789012:user/IAMTest1` (AWS::IAM::User, global)
- **Check:** `iam_stale_access_keys`

Access key AKIAI44QH8DHBEXAMPLE on user IAMTest1 is active, was last used 0 days ago and was created 0 days ago (limits: unused ≥ 0 days, age > 0 days).

**CIS controls**

- **1.12**: Ensure credentials unused for 45 days or greater are disabled
- **1.14**: Ensure access keys are rotated every 90 days or less

**Evidence**

```json
{
  "access_key_id": "AKIAI44QH8DHBEXAMPLE",
  "age_days": 0,
  "created": "2026-09-26T21:25:14+00:00",
  "key_slot": 1,
  "last_used": "2026-09-26T23:42:00+00:00",
  "thresholds": {
    "key_max_age_days": 0,
    "key_unused_days": 0
  },
  "unused_days": 0,
  "user": "IAMTest1"
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

---

### 6. Access key never used and not rotated in 0 days

- **Severity:** Medium
- **Resource:** `arn:aws:iam::123456789012:user/iam-scanner-sandbox-stale-key-user` (AWS::IAM::User, global)
- **Check:** `iam_stale_access_keys`

Access key AKIAIOSFODNN7EXAMPLE on user iam-scanner-sandbox-stale-key-user is active, has never been used and was created 0 days ago (limits: unused ≥ 0 days, age > 0 days).

**CIS controls**

- **1.12**: Ensure credentials unused for 45 days or greater are disabled
- **1.14**: Ensure access keys are rotated every 90 days or less

**Evidence**

```json
{
  "access_key_id": "AKIAIOSFODNN7EXAMPLE",
  "age_days": 0,
  "created": "2026-09-26T23:06:13+00:00",
  "key_slot": 1,
  "last_used": null,
  "thresholds": {
    "key_max_age_days": 0,
    "key_unused_days": 0
  },
  "unused_days": 0,
  "user": "iam-scanner-sandbox-stale-key-user"
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

- `iam_root_mfa`

### Errored

_None._
