# Resource names/IDs, for cross-checking against the scanner's report.

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "region" {
  value = var.region
}

output "public_bucket_name" {
  value = aws_s3_bucket.public.id
}

output "no_mfa_user_name" {
  value = aws_iam_user.no_mfa.name
}

output "stale_key_user_name" {
  value = aws_iam_user.stale_key.name
}

output "stale_access_key_id" {
  value     = aws_iam_access_key.stale_key.id
  sensitive = true # show with: terraform output -raw stale_access_key_id
}

output "wildcard_policy_arn" {
  value = aws_iam_policy.wildcard.arn
}

output "wildcard_group_name" {
  value = aws_iam_group.wildcard_admins.name
}

output "open_security_group_id" {
  value = aws_security_group.open_admin.id
}

output "vpc_id" {
  value = aws_vpc.sandbox.id
}
