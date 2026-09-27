# Misconfiguration #1: public S3 bucket (CIS 2.1.4).
#
# Public via a bucket policy, not ACLs: new buckets default to BucketOwnerEnforced,
# which disables ACLs. Requires account-level Block Public Access to be off (see README).

resource "aws_s3_bucket" "public" {
  bucket        = "${var.name_prefix}-public-${data.aws_caller_identity.current.account_id}"
  force_destroy = true # lets `terraform destroy` remove the placeholder object
}

resource "aws_s3_bucket_public_access_block" "public" {
  bucket = aws_s3_bucket.public.id

  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_read" {
  bucket = aws_s3_bucket.public.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicReadGetObject"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.public.arn}/*"
    }]
  })

  # The policy is rejected while bucket-level Block Public Access is still on.
  depends_on = [aws_s3_bucket_public_access_block.public]
}

resource "aws_s3_object" "placeholder" {
  bucket       = aws_s3_bucket.public.id
  key          = "README.txt"
  content      = "Harmless placeholder in an intentionally public sandbox bucket (iam-scanner). No real data.\n"
  content_type = "text/plain"
}
