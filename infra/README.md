# Vulnerable sandbox (Terraform)

> ⚠️ **This creates insecure resources on purpose.** Deploy it only to a dedicated,
> disposable AWS account with nothing else in it, and run `terraform destroy` when you're done.

## What it creates

| # | Resource | Misconfiguration | CIS v3.0.0 | Why it's contained |
|---|---|---|---|---|
| 1 | S3 bucket `…-public-<account-id>` | Public-read bucket policy, bucket-level Block Public Access off | 2.1.4 | Holds only a placeholder `README.txt` |
| 2 | IAM user `…-no-mfa-user` | Console password, no MFA | 1.10 | No policies attached; password never output |
| 3 | IAM user `…-stale-key-user` | Active access key | 1.12, 1.14 | No policies attached, so the key can do nothing |
| 4 | Policy `…-wildcard-policy` | `Action: *` on `Resource: *` | 1.16 | Attached only to an empty group |
| 5 | Security group `…-open-sg` | SSH (22) and RDP (3389) from 0.0.0.0/0 | 5.2 | Own VPC with no subnets, no internet gateway and no instances |

Every taggable resource is tagged `Project=iam-scanner-sandbox`.

## Precondition: account-level S3 Block Public Access must be off

With account-level Block Public Access on, AWS rejects the public bucket policy and
`terraform apply` fails on `aws_s3_bucket_policy.public_read`. This setting is **not**
managed by Terraform on purpose, so the account's own guardrail is never changed by accident.

**Check it:**
```bash
aws s3control get-public-access-block --account-id <account-id>
```
- `NoSuchPublicAccessBlockConfiguration` error: nothing is configured at account level, so you're good.
- All four flags `false`: you're good.
- Any flag `true`: disable it (next step).

**Disable it (sandbox account only):**
```bash
aws s3control delete-public-access-block --account-id <account-id>
```
Console alternative: S3 → *Block Public Access settings for this account* → Edit →
uncheck *Block all public access* → Save.

**Turn it back on after `terraform destroy`:**
```bash
aws s3control put-public-access-block --account-id <account-id> \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

## Usage

```bash
cd infra
terraform init
terraform plan  -var allowed_account_id=<account-id> -out sandbox.tfplan
terraform apply sandbox.tfplan
terraform output

# when finished
terraform destroy -var allowed_account_id=<account-id>
```

`allowed_account_id` is required, and the AWS provider refuses to run against any other account.

**State contains secrets.** The access key secret and the generated console password
are stored in `terraform.tfstate`. It is gitignored along with `.terraform/` and `*.tfvars`.
Never commit it. `.terraform.lock.hcl` *should* be committed.
