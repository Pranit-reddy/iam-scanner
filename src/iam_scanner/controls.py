"""CIS AWS Foundations Benchmark v3.0.0 control catalogue.

Remediation text lives here only; checks reference controls by ID via `Finding.cis_controls`.
"""

from __future__ import annotations

from dataclasses import dataclass

from iam_scanner import CIS_BENCHMARK_VERSION


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    rationale: str
    remediation: str


_CONTROLS = [
    Control(
        id="1.5",
        title="Ensure MFA is enabled for the 'root' user account",
        rationale=(
            "The root user has unrestricted access to every resource in the account, and "
            "IAM policies cannot limit it. MFA means a leaked root password alone is not "
            "enough to take over the account."
        ),
        remediation=(
            "Sign in to the console as the root user (with the account email address) → "
            "account menu → Security credentials → Multi-factor authentication (MFA) → "
            "Assign MFA device, and follow the prompts.\n"
            "Prefer a hardware security key (CIS 1.6 recommends hardware MFA for root), "
            "and store recovery details somewhere safe.\n"
            "For member accounts in AWS Organizations, consider centralized root access "
            "management, which removes root credentials from member accounts entirely."
        ),
    ),
    Control(
        id="1.10",
        title=(
            "Ensure multi-factor authentication (MFA) is enabled for all IAM users "
            "that have a console password"
        ),
        rationale=(
            "MFA adds a second factor on top of the password. A leaked or guessed console "
            "password alone is then not enough to sign in to the account."
        ),
        remediation=(
            "Console: IAM → Users → select the user → Security credentials → "
            "Multi-factor authentication (MFA) → Assign MFA device, and follow the prompts.\n"
            "If the user does not need console access, remove the password instead:\n"
            "`aws iam delete-login-profile --user-name <user>`\n"
            "To enforce MFA, attach a policy that denies all actions except MFA "
            "self-management when `aws:MultiFactorAuthPresent` is false."
        ),
    ),
    Control(
        id="1.12",
        title="Ensure credentials unused for 45 days or greater are disabled",
        rationale=(
            "Unused passwords and access keys are attack surface with no business value. "
            "Disabling them limits what a stolen or forgotten credential can be used for."
        ),
        remediation=(
            "Check the IAM credential report for `password_last_used` and "
            "`access_key_N_last_used_date` older than 45 days.\n"
            "Deactivate the unused access key:\n"
            "`aws iam update-access-key --user-name <user> --access-key-id <key-id> "
            "--status Inactive`\n"
            "Remove an unused console password:\n"
            "`aws iam delete-login-profile --user-name <user>`\n"
            "Delete the key once you confirm nothing depends on it:\n"
            "`aws iam delete-access-key --user-name <user> --access-key-id <key-id>`"
        ),
    ),
    Control(
        id="1.14",
        title="Ensure access keys are rotated every 90 days or less",
        rationale=(
            "Rotating access keys shortens the window in which a leaked key can be used "
            "and ensures that old keys stop working."
        ),
        remediation=(
            "1. Create a new key: `aws iam create-access-key --user-name <user>`\n"
            "2. Update every application or tool that uses the old key.\n"
            "3. Deactivate the old key: `aws iam update-access-key --user-name <user> "
            "--access-key-id <old-key-id> --status Inactive`\n"
            "4. After confirming nothing broke, delete it: `aws iam delete-access-key "
            "--user-name <user> --access-key-id <old-key-id>`\n"
            "Prefer IAM roles or IAM Identity Center (short-lived credentials) over "
            "long-lived access keys where possible."
        ),
    ),
    Control(
        id="1.16",
        title=(
            'Ensure IAM policies that allow full "*:*" administrative privileges are not attached'
        ),
        rationale=(
            "Least privilege limits the damage a compromised identity can do. A policy with "
            '`"Action": "*"` on `"Resource": "*"` grants full control of the account.'
        ),
        remediation=(
            "Find where the policy is attached:\n"
            "`aws iam list-entities-for-policy --policy-arn <policy-arn>`\n"
            "Detach it from each user, group and role, e.g.:\n"
            "`aws iam detach-user-policy --user-name <user> --policy-arn <policy-arn>`\n"
            "`aws iam detach-group-policy --group-name <group> --policy-arn <policy-arn>`\n"
            "`aws iam detach-role-policy --role-name <role> --policy-arn <policy-arn>`\n"
            "Replace it with a policy scoped to the specific actions and resources the "
            "principal needs. IAM Access Analyzer can generate one from CloudTrail activity."
        ),
    ),
    Control(
        id="2.1.4",
        title=(
            "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'"
        ),
        rationale=(
            "Block Public Access overrides bucket policies and ACLs that would grant public "
            "access, which prevents data from being exposed by an accidental "
            "misconfiguration."
        ),
        remediation=(
            "Console: S3 → select the bucket → Permissions → Block public access "
            "(bucket settings) → Edit → check 'Block all public access' → Save.\n"
            "CLI:\n"
            "`aws s3api put-public-access-block --bucket <bucket> "
            "--public-access-block-configuration "
            "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,"
            "RestrictPublicBuckets=true`\n"
            'Also remove any `"Principal": "*"` statements from the bucket policy, and '
            "enable Block Public Access at the account level: "
            "`aws s3control put-public-access-block --account-id <account-id> ...`"
        ),
    ),
    Control(
        id="5.2",
        title=(
            "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server "
            "administration ports"
        ),
        rationale=(
            "Exposing administration ports such as SSH (22) and RDP (3389) to the whole "
            "internet invites brute-force and exploit attempts against the instances "
            "behind the group."
        ),
        remediation=(
            "Remove the rule:\n"
            "`aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp "
            "--port <port> --cidr 0.0.0.0/0`\n"
            "If admin access is needed, allow it only from a known CIDR (e.g. a corporate "
            "VPN range), or better, use AWS Systems Manager Session Manager and open no "
            "inbound admin ports at all."
        ),
    ),
    Control(
        id="5.3",
        title=(
            "Ensure no security groups allow ingress from ::/0 to remote server "
            "administration ports"
        ),
        rationale=(
            "The IPv6 equivalent of 5.2: `::/0` exposes SSH (22) and RDP (3389) to every "
            "IPv6 address on the internet, and is easy to miss when only IPv4 rules are "
            "reviewed."
        ),
        remediation=(
            "Remove the rule:\n"
            "`aws ec2 revoke-security-group-ingress --group-id <sg-id> --ip-permissions "
            "IpProtocol=tcp,FromPort=<port>,ToPort=<port>,Ipv6Ranges=[{CidrIpv6=::/0}]`\n"
            "If admin access is needed, allow it only from a known IPv6 prefix, or use AWS "
            "Systems Manager Session Manager and open no inbound admin ports at all."
        ),
    ),
]

CONTROLS: dict[str, Control] = {c.id: c for c in _CONTROLS}
BENCHMARK = f"CIS AWS Foundations Benchmark v{CIS_BENCHMARK_VERSION}"


def get_control(control_id: str) -> Control:
    """Return the control with this ID. Raises KeyError for an unknown ID."""
    return CONTROLS[control_id]
