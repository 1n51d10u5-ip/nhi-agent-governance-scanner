# NHI & AI Agent Access Governance Scanner

A cloud security tool that inventories non-human identities (service accounts,
access keys, AI agents) in an AWS account, flags excessive/unused permissions,
scores blast radius, and detects behavioral anomalies in AI agent activity.

## Status: Part 2 — Least-Privilege Diff & Risk Scoring

## Setup

1. Create an AWS sandbox account (free tier is enough). **Never point this at
   a production account.**
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Configure AWS credentials for the sandbox account:
   ```
   aws configure
   ```
   (or set `AWS_PROFILE` to a profile pointed at the sandbox account)

## Seeding test identities (do this before running the scanner)

Create a handful of IAM users/roles by hand or script, with varied and
deliberately imperfect permissions, e.g.:

- 2-3 "human" users with sensible, scoped permissions
- 2-3 "service" roles (name them with `svc-` or `-role` so the classifier
  picks them up), one with an unused admin policy attached
- 1-2 "ai-agent" identities (name them with `agent` or `crewai` in the name)
  representing the CrewAI agent you'll wire up in Week 3

Naming conventions drive the v1 classifier in `inventory.py` — see
`AI_AGENT_MARKERS` / `SERVICE_MARKERS` at the top of the file. Adjust them to
match whatever convention you pick, or swap in a tag-based check later.

## Run

```
python src/inventory.py
```

This writes `data/identity_registry.json` — every IAM user and role, tagged
by classification, with access key metadata and the full list of actions
their attached policies grant.

## Part 2: Risk scoring

Run after `inventory.py`:

```
python src/risk_scoring.py --days 7
```

This pulls CloudTrail activity, diffs it against each identity's granted
actions, and computes a risk score. Key design decision: the score weights
by **action risk tier** (critical / write / read), not raw action count —
a broad managed policy like `ReadOnlyAccess` grants ~2,900 actions to a
completely benign role, so counting alone is a meaningless signal. See the
`CRITICAL_KEYWORDS` / `WRITE_KEYWORDS` heuristics in `risk_scoring.py`.

Output: `data/risk_report.json`, ranked highest-risk-first.

## Next up (Part 3)

- Deploy a CrewAI agent with its own IAM identity and tool scope
- Log every tool call the agent makes
- Build behavioral anomaly detection (scope creep, burst rate, privilege
  escalation), mapped to OWASP Agentic AI Top 10 / MITRE ATT&CK-ATLAS
