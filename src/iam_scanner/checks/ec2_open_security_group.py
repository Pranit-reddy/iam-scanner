"""CIS 5.2 / 5.3: security groups allowing 0.0.0.0/0 or ::/0 to remote admin ports."""

from __future__ import annotations

from typing import Any

from iam_scanner.aws import ScanContext
from iam_scanner.models import Finding, Severity

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
# World CIDR → CIS control (5.2 is IPv4, 5.3 is IPv6).
WORLD_CIDRS = {"0.0.0.0/0": "5.2", "::/0": "5.3"}
_ALL_PROTOCOLS = "-1"
_TCP = {"tcp", "6"}


def check(ctx: ScanContext) -> list[Finding]:
    findings = []
    for region in ctx.regions:
        ec2 = ctx.client("ec2", region)
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for group in page["SecurityGroups"]:
                open_rules = _open_admin_rules(group["IpPermissions"])
                if open_rules:
                    findings.append(_finding(group, region, open_rules))
    return findings


def _open_admin_rules(permissions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rules = []
    for perm in permissions:
        ports = _exposed_admin_ports(perm)
        if not ports:
            continue
        cidrs = [r["CidrIp"] for r in perm.get("IpRanges", [])]
        cidrs += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])]
        for cidr in cidrs:
            if cidr in WORLD_CIDRS:
                rules.append(
                    {
                        "protocol": perm["IpProtocol"],
                        "from_port": perm.get("FromPort"),
                        "to_port": perm.get("ToPort"),
                        "cidr": cidr,
                        "admin_ports": ports,
                    }
                )
    return rules


def _exposed_admin_ports(perm: dict[str, Any]) -> list[int]:
    protocol = perm["IpProtocol"]
    if protocol == _ALL_PROTOCOLS:
        return list(ADMIN_PORTS)
    if protocol not in _TCP:
        return []
    low, high = perm["FromPort"], perm["ToPort"]
    return [p for p in ADMIN_PORTS if low <= p <= high]


def _label(port: int) -> str:
    return f"{ADMIN_PORTS[port]} ({port})"


def _finding(group: dict[str, Any], region: str, open_rules: list[dict[str, Any]]) -> Finding:
    ports = [_label(p) for p in sorted({p for r in open_rules for p in r["admin_ports"]})]
    cidrs = sorted({r["cidr"] for r in open_rules})
    return Finding(
        check_id=__name__.rsplit(".", 1)[-1],
        resource_type="AWS::EC2::SecurityGroup",
        resource_id=group["GroupId"],
        region=region,
        severity=Severity.HIGH,
        title=f"Security group allows {', '.join(ports)} from the internet",
        description=(
            f"Security group {group['GroupName']} in {group.get('VpcId', 'EC2-Classic')} allows "
            f"inbound {', '.join(ports)} from {' and '.join(cidrs)}."
        ),
        cis_controls=sorted({WORLD_CIDRS[c] for c in cidrs}),
        evidence={
            "group_name": group["GroupName"],
            "vpc_id": group.get("VpcId"),
            "open_rules": open_rules,
        },
    )
