# identity-soar-mcp — server design

Conceptual Model Context Protocol server that grounds the Security Copilot custom
agent in real Sentinel, Entra ID Protection, and repo detection context. Schema:
[identity-soar-mcp-schema.json](identity-soar-mcp-schema.json).

## Why MCP

Security Copilot needs *grounded* context to reason instead of hallucinate. MCP
is the open protocol that exposes that context as typed **tools** (callable
functions with JSON-Schema inputs), **resources** (documents the model can read),
and **prompts** (reusable promptbooks). Rather than baking Sentinel API calls into
the agent, the MCP server is the single, auditable, least-privilege boundary
between the model and the security estate.

## Tool taxonomy (read vs propose)

The defining design choice: **read tools are auto-executable; there is exactly one
state-adjacent tool, and it only proposes.**

| Tool | Kind | Backing data |
|------|------|--------------|
| `get_signin_timeline` | read | Sentinel `SigninLogs` |
| `get_unified_identity_risk_score` | read | Entra ID Protection + Sentinel UEBA (`InvestigationPriority`) |
| `get_correlated_incident_graph` | read | graph correlation (see `src/graph_correlation.py`) |
| `check_mfa_fatigue_pattern` | read | Sentinel `SigninLogs` (DET-001 logic) |
| `propose_containment_action` | **proposal only** | detection + playbook automation matrix |

`propose_containment_action` returns a plan object with `requiresHumanApproval:
true` and never mutates state. Execution happens in a separate, audited Logic App
after a human approves — the same automate-vs-approve boundary the rest of the
repo enforces.

## Runtime and identity

- The server runs as an **Azure managed / federated workload identity** — no
  stored client secret (the same posture whose *absence* DET-CICD-001 hunts for).
- **Least privilege:** Microsoft Sentinel Reader + Security Reader for the read
  tools. The server holds **no write role**, so even a fully compromised agent
  cannot disable a user or change a network through it.
- **Data minimisation:** tools return typed entities and aggregates, never raw log
  bodies, secrets, or tokens.
- **Untrusted input:** telemetry strings are data, never instructions
  (prompt-injection defence), consistent with `docs/RESPONSIBLE_AI.md`.

## How the agent uses it

The [MFA-fatigue promptbook](../copilot/mfa-fatigue-triage.promptbook.md) calls
these tools in sequence (signature → risk → timeline → graph → disposition →
proposed plan → briefing). The [agent design](../copilot/agent-design.md) shows
the end-to-end flow, including the human approval gate before any Logic App acts.

## Honest scope

This is a schema and a design. The graph-correlation tool has a **runnable
implementation** in the repo (`src/graph_correlation.py`); the Sentinel/Entra
read tools and the Copilot agent are conceptual until wired to a tenant with
Security Copilot enabled and the MCP server hosted.
