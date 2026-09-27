# Misconfiguration #4: customer-managed policy granting full "*:*" admin (CIS 1.16).
#
# Attached to a group with no members, so it counts as "attached" for CIS 1.16
# while no principal can actually use it.

resource "aws_iam_policy" "wildcard" {
  name        = "${var.name_prefix}-wildcard-policy"
  description = "INTENTIONALLY INSECURE: full admin for iam-scanner testing. Attached to an empty group."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_group" "wildcard_admins" {
  name = "${var.name_prefix}-wildcard-admins"
}

resource "aws_iam_group_policy_attachment" "wildcard" {
  group      = aws_iam_group.wildcard_admins.name
  policy_arn = aws_iam_policy.wildcard.arn
}
