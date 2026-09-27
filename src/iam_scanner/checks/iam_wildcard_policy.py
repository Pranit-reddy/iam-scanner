"""CIS 1.16: customer-managed policies granting full "*:*" admin that are attached."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import unquote

from iam_scanner.aws import ScanContext
from iam_scanner.models import Finding, Severity


def check(ctx: ScanContext) -> list[Finding]:
    iam = ctx.client("iam")
    findings = []
    for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
        for policy in page["Policies"]:
            if policy["AttachmentCount"] == 0:
                continue
            document = iam.get_policy_version(
                PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
            )["PolicyVersion"]["Document"]
            statement = _full_admin_statement(document)
            if statement is None:
                continue
            attached_to = _attached_entities(iam, policy["Arn"])
            findings.append(
                Finding(
                    check_id=__name__.rsplit(".", 1)[-1],
                    resource_type="AWS::IAM::ManagedPolicy",
                    resource_id=policy["Arn"],
                    region="global",
                    severity=Severity.CRITICAL,
                    title="Customer-managed policy grants full *:* admin access",
                    description=(
                        f'Policy {policy["PolicyName"]} allows "Action": "*" on "Resource": "*" '
                        f"and is attached to {len(attached_to)} "
                        f"{'principal' if len(attached_to) == 1 else 'principals'}."
                    ),
                    cis_controls=["1.16"],
                    evidence={
                        "policy_name": policy["PolicyName"],
                        "attached_to": attached_to,
                        "statement": statement,
                    },
                )
            )
    return findings


def _full_admin_statement(document: Any) -> dict | None:
    """Return the first Allow statement with Action "*" and Resource "*", if any."""
    if isinstance(document, str):  # the raw API returns URL-encoded JSON
        document = json.loads(unquote(document))
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if (
            stmt.get("Effect") == "Allow"
            and _has_star(stmt.get("Action"))
            and _has_star(stmt.get("Resource"))
        ):
            return stmt
    return None


def _has_star(value: str | list[str] | None) -> bool:
    return value == "*" or (isinstance(value, list) and "*" in value)


def _attached_entities(iam: Any, policy_arn: str) -> list[str]:
    entities = []
    for page in iam.get_paginator("list_entities_for_policy").paginate(PolicyArn=policy_arn):
        entities += [f"group/{g['GroupName']}" for g in page["PolicyGroups"]]
        entities += [f"user/{u['UserName']}" for u in page["PolicyUsers"]]
        entities += [f"role/{r['RoleName']}" for r in page["PolicyRoles"]]
    return sorted(entities)
