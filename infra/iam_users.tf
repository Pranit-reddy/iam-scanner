# Misconfiguration #2: console user without MFA (CIS 1.10).
# CIS 1.10 only applies to users with a console password, hence the login profile.

resource "aws_iam_user" "no_mfa" {
  name          = "${var.name_prefix}-no-mfa-user"
  force_destroy = true # also removes the login profile on destroy
}

resource "aws_iam_user_login_profile" "no_mfa" {
  user                    = aws_iam_user.no_mfa.name
  password_length         = 24
  password_reset_required = true

  # The generated password is never output. The user has no policies attached.
  lifecycle {
    ignore_changes = [password_length, password_reset_required]
  }
}

# Misconfiguration #3: user with an unused access key (CIS 1.12, 1.14).
# The key is brand new, so the live demo lowers the scanner's age thresholds.
# The user has no policies attached, so the key cannot do anything useful.

resource "aws_iam_user" "stale_key" {
  name          = "${var.name_prefix}-stale-key-user"
  force_destroy = true # also removes the access key on destroy
}

resource "aws_iam_access_key" "stale_key" {
  user = aws_iam_user.stale_key.name
  # The secret ends up in Terraform state, which is why *.tfstate is gitignored.
}
