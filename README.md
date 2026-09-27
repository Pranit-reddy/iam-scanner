# iam-scanner

A Python scanner that finds AWS IAM and resource misconfigurations and maps each finding to a
**CIS AWS Foundations Benchmark v3.0.0** control. It produces a Markdown report
(finding → severity → control → remediation).

The repo also includes Terraform (`infra/`) for a sandbox AWS environment that is
**vulnerable on purpose**, so the scanner can be demonstrated end to end.

> ⚠️ Deploy `infra/` only to a dedicated, disposable AWS account. It creates a public
> S3 bucket and other insecure resources.

## Status
Work in progress. The skeleton is in place; checks, report and infra are coming.

## Development
Requires Python 3.11+.
```bash
python3 -m venv .venv && source .venv/bin/activate   # or: uv venv --python 3.12
pip install -e ".[dev]"                              # or: uv pip install -e ".[dev]"
pytest
```
Tests use [moto](https://github.com/getmoto/moto) and need no AWS credentials.
