from iam_scanner.checks.ec2_open_security_group import check
from iam_scanner.models import Severity


def _sg(ec2, name, *permissions):
    group_id = ec2.create_security_group(GroupName=name, Description=name)["GroupId"]
    if permissions:
        ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=list(permissions))
    return group_id


def _tcp(port, cidr=None, cidr6=None, to_port=None):
    perm = {"IpProtocol": "tcp", "FromPort": port, "ToPort": to_port or port}
    if cidr:
        perm["IpRanges"] = [{"CidrIp": cidr}]
    if cidr6:
        perm["Ipv6Ranges"] = [{"CidrIpv6": cidr6}]
    return perm


def _findings_for(ctx, group_id):
    return [f for f in check(ctx) if f.resource_id == group_id]


def test_flags_ssh_and_rdp_open_to_world_in_one_finding(ctx):
    ec2 = ctx.client("ec2")
    group_id = _sg(ec2, "open", _tcp(22, "0.0.0.0/0"), _tcp(3389, "0.0.0.0/0"))

    findings = _findings_for(ctx, group_id)

    assert len(findings) == 1
    f = findings[0]
    assert f.resource_type == "AWS::EC2::SecurityGroup"
    assert f.region == "us-east-1"
    assert f.severity is Severity.HIGH
    assert f.cis_controls == ["5.2"]
    assert {(r["from_port"], r["to_port"], r["cidr"]) for r in f.evidence["open_rules"]} == {
        (22, 22, "0.0.0.0/0"),
        (3389, 3389, "0.0.0.0/0"),
    }


def test_ipv6_world_maps_to_cis_5_3(ctx):
    group_id = _sg(ctx.client("ec2"), "open6", _tcp(3389, cidr6="::/0"))
    [f] = _findings_for(ctx, group_id)
    assert f.cis_controls == ["5.3"]


def test_flags_all_traffic_rule(ctx):
    all_traffic = {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    group_id = _sg(ctx.client("ec2"), "all", all_traffic)
    [f] = _findings_for(ctx, group_id)
    assert f.evidence["open_rules"][0]["admin_ports"] == [22, 3389]
    assert f.title == "Security group allows SSH (22), RDP (3389) from the internet"


def test_flags_port_range_covering_ssh(ctx):
    group_id = _sg(ctx.client("ec2"), "range", _tcp(20, "0.0.0.0/0", to_port=25))
    assert len(_findings_for(ctx, group_id)) == 1


def test_ignores_admin_port_restricted_to_specific_cidr(ctx):
    group_id = _sg(ctx.client("ec2"), "restricted", _tcp(22, "10.0.0.0/8"))
    assert _findings_for(ctx, group_id) == []


def test_ignores_non_admin_port_open_to_world(ctx):
    group_id = _sg(ctx.client("ec2"), "web", _tcp(443, "0.0.0.0/0", cidr6="::/0"))
    assert _findings_for(ctx, group_id) == []
