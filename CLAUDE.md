# CLAUDE.md

A Python scanner that finds AWS IAM and resource misconfigurations and maps each finding to a **CIS AWS Foundations Benchmark v3.0.0** control. It also includes Terraform for a sandbox that is **vulnerable on purpose**, which the scanner is tested against. This is a security portfolio project, so clarity and reproducibility matter more than breadth.

## Layout
```
iam-scanner/
├── README.md
├── pyproject.toml
├── .gitignore                 # tfstate, .terraform/, *.tfvars, reports/
├── infra/                     # vulnerable sandbox (Terraform only)
│   ├── README.md              # warning, preconditions, apply/destroy steps
│   ├── versions.tf            # terraform + aws provider pins
│   ├── providers.tf           # region, allowed_account_ids, default_tags
│   ├── variables.tf
│   ├── s3.tf                  # public bucket
│   ├── iam_users.tf           # no-MFA console user; user with unused access key
│   ├── iam_policy.tf          # wildcard policy + attachment
│   ├── network.tf             # security group open to 0.0.0.0/0
│   └── outputs.tf
├── src/iam_scanner/           # the scanner (run with `python -m iam_scanner`)
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                 # --profile, --region, --output, thresholds, --checks
│   ├── models.py              # Finding dataclass, ordered Severity enum
│   ├── controls.py            # CIS catalogue: control ID → title, rationale, remediation
│   ├── aws.py                 # boto3 session factory + cached credential report
│   ├── checks/
│   │   ├── __init__.py        # check registry + run_all()
│   │   └── <one module per check>.py
│   └── report/
│       └── markdown.py        # findings → Markdown report
├── tests/
│   ├── conftest.py            # moto fixtures, fake AWS credentials
│   ├── checks/                # mirrors src/iam_scanner/checks/
│   ├── test_report.py         # golden-file test
│   └── fixtures/              # expected_report.md, etc.
└── docs/
    └── sample-report.md       # real output from a live sandbox scan
```

**Terraform vs. boto3:** all sandbox infrastructure is provisioned with Terraform in `infra/`. boto3 is used **only** by the scanner in `src/iam_scanner/`. Don't add boto3 provisioning or setup scripts.

## The `Finding` dataclass
Every check returns `list[Finding]`, where `Finding` (in `models.py`) has exactly these fields:

| Field | Type | Meaning |
|---|---|---|
| `check_id` | `str` | Name of the check module that produced it, e.g. `iam_wildcard_policy` |
| `resource_type` | `str` | AWS resource kind, e.g. `AWS::IAM::User`, `AWS::S3::Bucket` |
| `resource_id` | `str` | ARN, or a name/ID when there is no ARN (e.g. a security group ID) |
| `region` | `str` | Region scanned, or `global` for IAM |
| `severity` | `Severity` | Ordered enum: `CRITICAL` > `HIGH` > `MEDIUM` > `LOW` |
| `title` | `str` | Short one-line summary |
| `description` | `str` | What is wrong with *this* resource |
| `cis_controls` | `list[str]` | CIS v3.0.0 control IDs, e.g. `["1.12", "1.14"]` |
| `evidence` | `dict` | The raw facts behind the finding, e.g. `{"port": 22, "cidr": "0.0.0.0/0"}` |

There's no remediation field; remediation comes from `controls.py` by control ID. Changing these fields means updating every check, the report renderer and the golden-file fixture in the same change.

## Scanner conventions
- **Check signature:** `def check(ctx: ScanContext) -> list[Finding]`. A check is a pure function over the AWS API. It gets its clients from `ctx.session`, never by calling `boto3.client()` directly, so moto and profiles work.
- **One check per module**, named after the misconfiguration (e.g. `iam_wildcard_policy.py`). The module name is the `check_id`.
- **Every finding lists one or more CIS control IDs** in `cis_controls`. Each ID must exist in `controls.py`.
- **Remediation text lives only in `controls.py`.** Checks set `description` (what is wrong with *this* resource) and `evidence` (the raw facts, e.g. port and CIDR). They never set remediation.
- **Thresholds come from `ScanContext`** (e.g. key age and unused days), never hardcoded. The defaults follow CIS (45 days unused, 90 days rotation). The live demo lowers them because Terraform can't create an old access key.
- **Credential report:** checks that need `password_enabled`, `mfa_active` or access-key dates read the cached report from `ctx`. They don't call `generate_credential_report` themselves.
- **Errors don't crash the scan.** A check that hits `AccessDenied` or another `ClientError` returns an error result, and the report lists it under "errored checks".
- **Adding a check:** add the control to `controls.py`, write the check module, register it, and add tests. Update the mapping table in `README.md` too.

## CIS mapping (v3.0.0; don't mix versions)
| Check | Control(s) | Severity |
|---|---|---|
| `s3_public_bucket` | 2.1.4 | Critical |
| `iam_wildcard_policy` | 1.16 | Critical |
| `iam_root_mfa` | 1.5 | Critical |
| `iam_user_mfa` | 1.10 (console users only) | High |
| `ec2_open_security_group` | 5.2 (0.0.0.0/0 → 22/3389), 5.3 (::/0 → 22/3389) | High |
| `iam_stale_access_keys` | 1.12, 1.14 | Medium |

**`s3_public_bucket` decision rule:**
- **Not public** if `RestrictPublicBuckets` is on at the bucket *or* account level. `BlockPublicPolicy` alone doesn't count, because it only blocks *new* public policies.
- **Otherwise public** if either of two verdicts says so:
  - the scanner's parser, which counts an `Allow` statement with a `"*"` principal and no `Condition`;
  - AWS's `GetBucketPolicyStatus` `IsPublic`.
- When the two disagree, the bucket is still flagged, and `evidence.verdict_discrepancy` explains the disagreement.
- moto doesn't implement `IsPublic`, so tests that cover the cross-check replace `_policy_status_is_public` with a fake answer (monkeypatch).
- ACL-based public access is not checked (yet).

## Report format
Header (account, region, timestamp, CIS version, severity counts) → summary table sorted Critical → Low → one section per finding (description → severity → control → evidence → remediation) → passed checks and errored checks. The format is locked by a golden-file test (`tests/fixtures/expected_report.md`). If you change the format on purpose, update that fixture in the same change.

## Testing
- `pytest` must pass with **no AWS credentials**. Use moto's `mock_aws` with fake credentials set in `tests/conftest.py`.
- Each check needs at least one **vulnerable case** (finding produced) and one **compliant case** (no finding).
- For time-based logic, use fixed timestamps or frozen time. Never depend on the real clock.
- Lint with `ruff` (`ruff check` and `ruff format`). CI runs ruff and pytest only, with no AWS access.

## Terraform / sandbox rules
- **Never run `terraform apply` or `terraform destroy` without the user's explicit confirmation.** They create or delete real, publicly exposed resources.
- Use only a dedicated sandbox AWS account. Pin it with the `allowed_account_ids` provider setting.
- Tag every resource `Project=iam-scanner-sandbox` (set in `default_tags`).
- Make the S3 bucket public with a **bucket policy** (`Principal: "*"`), not ACLs. Account-level Block Public Access is a documented manual precondition and is not managed in Terraform.
- The no-MFA user needs an `aws_iam_user_login_profile`, because CIS 1.10 only covers console users.
- Never attach the wildcard policy to a principal that has usable credentials. Launch no instances into the open security group. Keep the bucket empty or put only harmless placeholder content in it.
- Terraform state holds the access-key secret. Never commit `*.tfstate*`, `.terraform/` or `*.tfvars`. Mark any key output `sensitive`.

## Style
- Python ≥ 3.11, with type hints on public functions.
- Prefer the standard library and boto3. Ask before adding a runtime dependency.
- Keep checks small and readable. Reviewers of this portfolio should understand each one at a glance.
