"""
Least-Privilege Diff & Risk Scoring Engine
--------------------------------------------

Reads data/identity_registry.json (from inventory.py), pulls CloudTrail
activity for each identity over a lookback window, diffs granted vs.
actually-used actions, and computes a risk score that WEIGHTS BY ACTION
TYPE rather than raw action count.

Why not raw count: a broad AWS-managed policy like ReadOnlyAccess grants
~2,900 actions to a completely benign reporting role. Counting actions
alone would rank it identically to a genuinely dangerous role with the
same count from e.g. PowerUserAccess. What matters is the *kind* of
action granted (read vs. data-exposing read vs. write vs. admin/IAM),
whether it's actually used, and who holds it -- the same grant carries
more real risk on an AI agent (no judgment, manipulable via its inputs)
than on a human or a well-audited service role.

Setup:
    Run inventory.py first to generate data/identity_registry.json

Run:
    python src/risk_scoring.py --days 7
"""

import boto3
import json
import argparse
import datetime
from pathlib import Path
from collections import defaultdict

REGISTRY_PATH = Path(__file__).parent.parent / "data" / "identity_registry.json"
OUTPUT_PATH = Path(__file__).parent.parent / "data" / "risk_report.json"

# ---- Action risk tiers ----------------------------------------------
# Tune these keyword lists as you learn more -- this is a heuristic
# classifier, same spirit as the naming-convention identity classifier
# from Week 1. A production version would use AWS's own IAM Access
# Analyzer action-risk data instead of keyword matching.

CRITICAL_KEYWORDS = ["iam:", "sts:AssumeRole", "kms:", "organizations:"]
WRITE_KEYWORDS = ["Delete", "Put", "Create", "Attach", "Detach", "Update",
                  "Modify", "Terminate", "Revoke", "PassRole", "Remove"]

# Reads that return actual data CONTENT, not just resource metadata/names.
# ReadOnlyAccess grants both kinds indiscriminately -- an identity that can
# list bucket names is a very different risk than one that can read every
# object inside them. This matters most for AI agents: the realistic attack
# path isn't "the agent goes rogue," it's a poisoned tool response or a
# prompt-injected instruction tricking the agent into reading and then
# leaking data it technically has permission to read (OWASP LLM Top 10:
# excessive agency + sensitive information disclosure).
DATA_EXPOSURE_KEYWORDS = ["GetObject", "GetSecretValue", "Decrypt", "GetItem",
                          "Query", "Scan", "GetRecords", "Download",
                          "GetParameter", "GetSnapshotData", "SelectObjectContent"]

TIER_WEIGHT = {"critical": 10, "write": 3, "data-read": 4, "read": 1}

# Same granted permission carries different real-world risk depending on
# who holds it. A human with ReadOnlyAccess has judgment and accountability;
# an AI agent with the same grant has neither -- it reads whatever its
# inputs tell it to. This multiplier is a judgment call, not a hard science;
# tune it as you get more comfortable with the tradeoffs.
IDENTITY_RISK_MULTIPLIER = {"ai-agent": 1.5, "service": 1.2, "human": 1.0}


def classify_action_tier(action: str) -> str:
    if action == "*" or any(action.startswith(k) for k in CRITICAL_KEYWORDS):
        return "critical"
    verb = action.split(":")[-1]
    if any(verb.startswith(w) for w in WRITE_KEYWORDS):
        return "write"
    if any(verb.startswith(k) for k in DATA_EXPOSURE_KEYWORDS):
        return "data-read"
    return "read"


def get_actual_actions(cloudtrail, arn_fragment: str, days: int) -> set:
    """Pull CloudTrail events and return the set of actions
    (service:EventName) actually performed by anything whose
    userIdentity.arn contains arn_fragment (role/user name)."""
    end_time = datetime.datetime.utcnow()
    start_time = end_time - datetime.timedelta(days=days)

    actual = set()
    paginator = cloudtrail.get_paginator("lookup_events")
    try:
        for page in paginator.paginate(StartTime=start_time, EndTime=end_time):
            for event in page["Events"]:
                raw = json.loads(event["CloudTrailEvent"])
                user_identity = raw.get("userIdentity", {})
                arn = user_identity.get("arn", "") or ""
                if arn_fragment not in arn:
                    continue
                source = raw.get("eventSource", "").replace(".amazonaws.com", "")
                name = raw.get("eventName", "")
                actual.add(f"{source}:{name}")
    except Exception as e:
        print(f"  [warn] CloudTrail lookup failed for {arn_fragment}: {e}")

    return actual


def score_identity(identity: dict, actual_actions: set) -> dict:
    granted = set(identity["granted_actions"])
    unused = granted - actual_actions

    tier_counts = defaultdict(int)
    unused_tier_counts = defaultdict(int)
    for action in granted:
        tier = classify_action_tier(action)
        tier_counts[tier] += 1
        if action in unused:
            unused_tier_counts[tier] += 1

    # Risk score: weighted sum of GRANTED critical/write/data-read actions,
    # plus a penalty for unused ones (unused dangerous permissions are pure
    # liability -- no benefit, all risk). Plain "read" (List*/Describe*)
    # contributes to the base score but is excluded from the unused penalty
    # and the high-risk-unused report -- an unused ListBuckets isn't worth
    # flagging.
    base_score = sum(tier_counts[t] * TIER_WEIGHT[t] for t in tier_counts)
    unused_penalty = sum(unused_tier_counts[t] * TIER_WEIGHT[t] * 1.5
                          for t in unused_tier_counts if t != "read")

    # Cross-account / broad trust bumps risk further (role hijack blast radius)
    trust_penalty = 0
    trust_policy = identity.get("trust_policy")
    if trust_policy:
        trust_str = json.dumps(trust_policy)
        if '"AWS": "*"' in trust_str or '"Principal": "*"' in trust_str:
            trust_penalty = 100

    multiplier = IDENTITY_RISK_MULTIPLIER.get(identity["classification"], 1.0)
    # Trust penalty reflects the trust policy itself, not the holder's
    # nature, so it's added after the multiplier rather than scaled by it.
    total_score = round((base_score + unused_penalty) * multiplier + trust_penalty, 1)

    return {
        "name": identity["name"],
        "classification": identity["classification"],
        "identity_risk_multiplier": multiplier,
        "granted_action_count": len(granted),
        "granted_tier_breakdown": dict(tier_counts),
        "unused_action_count": len(unused),
        "unused_high_risk_actions": sorted(
            a for a in unused if classify_action_tier(a) != "read"
        )[:15],  # cap for readability
        "cross_account_trust_flag": trust_penalty > 0,
        "risk_score": total_score,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=7,
                         help="CloudTrail lookback window in days")
    args = parser.parse_args()

    with open(REGISTRY_PATH) as f:
        registry = json.load(f)

    cloudtrail = boto3.client("cloudtrail")

    results = []
    for identity in registry["identities"]:
        print(f"Scoring {identity['name']} ({identity['classification']})...")
        actual = get_actual_actions(cloudtrail, identity["name"], args.days)
        results.append(score_identity(identity, actual))

    results.sort(key=lambda r: r["risk_score"], reverse=True)

    report = {
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "lookback_days": args.days,
        "identities": results,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n=== Risk report written to {OUTPUT_PATH} ===\n")
    print(f"{'Name':<20} {'Class':<10} {'Score':<8} {'Unused (high-risk)'}")
    for r in results:
        high_risk_unused = len(r["unused_high_risk_actions"])
        print(f"{r['name']:<20} {r['classification']:<10} {r['risk_score']:<8} {high_risk_unused}")


if __name__ == "__main__":
    main()
