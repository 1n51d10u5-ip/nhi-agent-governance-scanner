"""
Identity Inventory Engine
--------------------------

Enumerates every IAM user, role, and access key in an AWS account,
classifies as human/service/ai-agent, writes a structured
JSON registry to data/identity_registry.json.

"""

import boto3
import json
import datetime
from pathlib import Path

# ---- Configuration -------------------------------------------------

# Naming conventions used to auto-classify identities. Adjust these to
# match your tagging/naming scheme for identities in account.

AI_AGENT_MARKERS = ["agent", "crewai", "bedrock-agent", "llm"]
SERVICE_MARKERS = ["svc-", "service-", "-role", "lambda", "ci-", "deploy"]

OUTPUT_PATH = Path(__file__).parent.parent / "data" / "identity_registry.json"


def classify_identity(name: str, entity_type: str) -> str:
    """Best-effort classification: human / service / ai-agent.

    Real-world version of this would also check tags (e.g. a
    'Purpose: ai-agent' resource tag) rather than relying on naming
    conventions alone -- naming is a fine v1 heuristic, not a
    production control.
    """
    lower = name.lower()
    if any(marker in lower for marker in AI_AGENT_MARKERS):
        return "ai-agent"
    if entity_type == "role" or any(marker in lower for marker in SERVICE_MARKERS):
        return "service"
    return "human"


def get_attached_policy_actions(iam_client, entity_type: str, entity_name: str) -> list:
    """Return the list of distinct Action strings across all policies
    (managed + inline) attached to a user or role."""
    actions = set()

    if entity_type == "user":
        attached = iam_client.list_attached_user_policies(UserName=entity_name)["AttachedPolicies"]
        inline_names = iam_client.list_user_policies(UserName=entity_name)["PolicyNames"]
        get_inline = lambda name: iam_client.get_user_policy(UserName=entity_name, PolicyName=name)
    else:  # role
        attached = iam_client.list_attached_role_policies(RoleName=entity_name)["AttachedPolicies"]
        inline_names = iam_client.list_role_policies(RoleName=entity_name)["PolicyNames"]
        get_inline = lambda name: iam_client.get_role_policy(RoleName=entity_name, PolicyName=name)

    # Managed policies: fetch the default version's document
    for policy in attached:
        try:
            policy_arn = policy["PolicyArn"]
            version_id = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
            doc = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
            statements = doc["PolicyVersion"]["Document"].get("Statement", [])
            actions.update(_extract_actions(statements))
        except Exception as e:
            print(f"  [warn] could not read managed policy {policy.get('PolicyName')}: {e}")

    # Inline policies
    for name in inline_names:
        try:
            doc = get_inline(name)
            statements = doc["PolicyDocument"].get("Statement", [])
            actions.update(_extract_actions(statements))
        except Exception as e:
            print(f"  [warn] could not read inline policy {name}: {e}")

    return sorted(actions)


def _extract_actions(statements) -> set:
    if isinstance(statements, dict):
        statements = [statements]
    actions = set()
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        act = stmt.get("Action", [])
        if isinstance(act, str):
            act = [act]
        actions.update(act)
    return actions


def inventory_users(iam_client) -> list:
    identities = []
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            name = user["UserName"]
            print(f"Inventorying user: {name}")

            # Access keys + last-used info
            keys = iam_client.list_access_keys(UserName=name)["AccessKeyMetadata"]
            key_info = []
            for k in keys:
                last_used = iam_client.get_access_key_last_used(AccessKeyId=k["AccessKeyId"])
                key_info.append({
                    "access_key_id": k["AccessKeyId"],
                    "status": k["Status"],
                    "created": k["CreateDate"].isoformat(),
                    "last_used": last_used["AccessKeyLastUsed"].get("LastUsedDate", None) and
                                 last_used["AccessKeyLastUsed"]["LastUsedDate"].isoformat(),
                    "last_used_service": last_used["AccessKeyLastUsed"].get("ServiceName"),
                })

            actions = get_attached_policy_actions(iam_client, "user", name)

            identities.append({
                "identity_id": user["UserId"],
                "name": name,
                "arn": user["Arn"],
                "entity_type": "user",
                "classification": classify_identity(name, "user"),
                "created": user["CreateDate"].isoformat(),
                "access_keys": key_info,
                "granted_actions": actions,
            })
    return identities


def inventory_roles(iam_client) -> list:
    identities = []
    paginator = iam_client.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page["Roles"]:
            name = role["RoleName"]

            # Skip AWS service-linked roles -- noisy and not actionable
            if name.startswith("AWSServiceRoleFor"):
                continue

            print(f"Inventorying role: {name}")
            actions = get_attached_policy_actions(iam_client, "role", name)

            identities.append({
                "identity_id": role["RoleId"],
                "name": name,
                "arn": role["Arn"],
                "entity_type": "role",
                "classification": classify_identity(name, "role"),
                "created": role["CreateDate"].isoformat(),
                "trust_policy": role.get("AssumeRolePolicyDocument", {}),
                "granted_actions": actions,
            })
    return identities


def main():
    iam = boto3.client("iam")

    print("=== Starting identity inventory ===")
    users = inventory_users(iam)
    roles = inventory_roles(iam)

    registry = {
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "identity_count": len(users) + len(roles),
        "identities": users + roles,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(registry, f, indent=2, default=str)

    print(f"\n=== Done. {registry['identity_count']} identities written to {OUTPUT_PATH} ===")

    # Quick breakdown by classification
    by_class = {}
    for i in registry["identities"]:
        by_class[i["classification"]] = by_class.get(i["classification"], 0) + 1
    print("Breakdown:", by_class)


if __name__ == "__main__":
    main()
