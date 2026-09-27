# Misconfiguration #5: security group open to 0.0.0.0/0 on admin ports (CIS 5.2).
#
# Lives in its own VPC with no subnets and no internet gateway, and no instance
# uses it, so nothing is actually exposed.

resource "aws_vpc" "sandbox" {
  cidr_block = "10.99.0.0/16"

  tags = {
    Name = "${var.name_prefix}-vpc"
  }
}

resource "aws_security_group" "open_admin" {
  name        = "${var.name_prefix}-open-sg"
  description = "INTENTIONALLY INSECURE: SSH/RDP from anywhere, for iam-scanner testing"
  vpc_id      = aws_vpc.sandbox.id

  tags = {
    Name = "${var.name_prefix}-open-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "ssh_anywhere" {
  security_group_id = aws_security_group.open_admin.id
  description       = "SSH from anywhere (intentionally insecure)"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "rdp_anywhere" {
  security_group_id = aws_security_group.open_admin.id
  description       = "RDP from anywhere (intentionally insecure)"
  ip_protocol       = "tcp"
  from_port         = 3389
  to_port           = 3389
  cidr_ipv4         = "0.0.0.0/0"
}
