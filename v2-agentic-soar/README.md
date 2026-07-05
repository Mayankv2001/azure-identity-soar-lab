# Version 2.0 — Agentic AI SOAR & graph correlation

V2 aligns the lab with 2026 Microsoft security-engineering patterns across four
components. The through-line: **the AI reasons; humans approve; audited playbooks
act; and security infrastructure is code.**

| # | Component | Was (V1) | Now (V2) | Artefacts |
|---|-----------|----------|----------|-----------|
| 1 | Agentic AI over static SOAR | Static Logic App playbooks | Security Copilot custom agent + MCP grounding | [copilot/](copilot/), [mcp/](mcp/) |
| 2 | CI/CD identity threat detection | Identity-only attack path | Workload-identity credential-bridging KQL | [detections/](detections/) |
| 3 | Graph-powered correlation | Time-window joins | Typed property graph + reachability | [`src/graph_correlation.py`](../src/graph_correlation.py) |
| 4 | Detection-as-code (shift-left) | Azure DevOps pipeline | GitHub Actions (OIDC) + Bicep | [`.github/workflows/deploy-detections.yml`](../.github/workflows/deploy-detections.yml), [infra/](infra/) |

## 1. Agentic AI over static SOAR

A Microsoft Security Copilot custom agent replaces the *triage and decision* stage
of the static playbooks. It runs the
[MFA-fatigue triage promptbook](copilot/mfa-fatigue-triage.promptbook.md),
grounded by the `identity-soar-mcp` server
([schema](mcp/identity-soar-mcp-schema.json),
[design](mcp/mcp-server-design.md)), which exposes read tools (sign-in timeline,
unified identity risk score, graph correlation, MFA-fatigue check) and **one
proposal-only tool**. The agent holds no write role: it proposes a containment
plan; a human approves; a separate audited Logic App acts. Full flow in
[copilot/agent-design.md](copilot/agent-design.md).

## 2. CI/CD identity threat detection — credential bridging

[DET-CICD-001](detections/DET-CICD-001-workload-identity-credential-bridging.kql)
detects a compromised GitHub Actions pipeline that authenticates via an OIDC
federated credential and "bridges" that token into Azure — either extracting Key
Vault secrets at abnormal volume or escalating privilege via
`roleAssignments/write` — within a short window, escalating when the federated
subject is off the approved allow-list. Mapped to T1552.007, T1550.001,
T1098.001/.003. Ships **disabled** pending tenant validation.

## 3. Graph-powered correlation

[`src/graph_correlation.py`](../src/graph_correlation.py) (runnable, tested)
builds a typed property graph of identities, service principals, resource groups,
NSGs, VMs and IPs, and correlates by **graph reachability** rather than time
proximity. The demonstration: in CP-INC-2001 the NSG rule that opens RDP to the
internet is written by the service principal `sp-infra-deploy`, not by the victim
`chris.walker@contoso.com`. A caller-keyed time-window join therefore **misses**
the exposure; the graph recovers the full path through the bridge edge:

```
chris.walker --added_credential_to--> sp-infra-deploy --modified--> nsg-prod-dc-mgmt --exposed_to_internet--> vm-dc-mgmt-01
```

Run it: `python3 src/graph_correlation.py --demo` — it prints both the (empty)
time-window result and the graph path so the difference is concrete.

## 4. Detection-as-code (shift-left)

[`.github/workflows/deploy-detections.yml`](../.github/workflows/deploy-detections.yml)
validates KQL/YAML/Bicep and runs the tests on every PR, then deploys analytics
rules to Sentinel on merge to main through an approval-gated GitHub environment.
It authenticates with **OIDC / workload identity federation — no stored
secrets** (the secure counterpart to the attack DET-CICD-001 detects), and the
Bicep ([infra/deploy-v2.bicep](infra/deploy-v2.bicep)) deploys the CI/CD rule and
its watchlist, rules disabled by default.

## Honest scope

The graph-correlation engine is real, runnable, and covered by tests. The Copilot
agent, the MCP server, and the live deployment are **designs and templates** —
they compile and validate offline but are conceptual until wired to a tenant with
Microsoft Security Copilot enabled. Nothing here is production-ready or
auto-enabled; every state-changing action remains human-approved.
