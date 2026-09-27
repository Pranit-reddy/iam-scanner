variable "allowed_account_id" {
  description = "The dedicated sandbox AWS account ID. Terraform refuses to run against any other account."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.allowed_account_id))
    error_message = "allowed_account_id must be a 12-digit AWS account ID."
  }
}

variable "region" {
  description = "Region for regional resources (S3 bucket, VPC, security group)."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for every resource name, so sandbox resources are easy to spot."
  type        = string
  default     = "iam-scanner-sandbox"
}
