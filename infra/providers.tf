provider "aws" {
  region = var.region

  # Refuse to run against any account other than the sandbox.
  allowed_account_ids = [var.allowed_account_id]

  default_tags {
    tags = {
      Project   = "iam-scanner-sandbox"
      Purpose   = "intentionally-vulnerable"
      ManagedBy = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}
