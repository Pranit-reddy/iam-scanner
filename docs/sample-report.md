# IAM Misconfiguration Scan Report

| | |
|---|---|
| **Account** | `123456789012` |
| **Region(s)** | us-east-1 |
| **Generated** | 2026-09-27 00:18:25 UTC |
| **Benchmark** | CIS AWS Foundations Benchmark v3.0.0 |

## Summary

| Critical | High | Medium | Low |
|---|---|---|---|
| 2 | 2 | 0 | 0 |

**4 findings** from 6 checks: 2 passed, 0 errored.

## Findings

| # | Severity | Finding | Resource | CIS control(s) |
|---|---|---|---|---|
| 1 | Critical | [Customer-managed policy grants full \*:\* admin access](#1-customer-managed-policy-grants-full--admin-access) | `arn:aws:iam::123456789012:policy/iam-scanner-sandbox-wildcard-policy` | 1.16 |
| 2 | Critical | [S3 bucket is publicly accessible via its bucket policy](#2-s3-bucket-is-publicly-accessible-via-its-bucket-policy) | `arn:aws:s3:::iam-scanner-sandbox-public-123456789012` | 2.1.4 |
| 3 | High | [Security group allows SSH (22), RDP (3389) from the internet](#3-security-group-allows-ssh-22-rdp-3389-from-the-internet) | `sg-0a420b13ffac24c79` | 5.2 |
| 4 | High | [IAM user has console access without MFA](#4-iam-user-has-console-access-without-mfa) | `arn:aws:iam::123456789012:user/iam-scanner-sandbox-no-mfa-user` | 1.10 |

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

## Check status

### Passed

- `iam_root_mfa`
- `iam_stale_access_keys`

### Errored

_None._
