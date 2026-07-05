# Declarative Agent — design

V2 described a generic "custom agent" with a single custom MCP server. V3 moves to
a **Declarative Agent** (the first-party Microsoft 365 / Security Copilot agent
format) that leans on native servers and keeps only the irreducible custom piece.

## What changed from V2

| Concern | V2 (generic agent) | V3 (declarative agent) |
|---------|--------------------|------------------------|
| Agent definition | Prose design | [manifest.json](manifest.json) - versioned declarative manifest |
| Read-side grounding | Custom MCP tools (sign-in, risk, graph) | **Native Microsoft Sentinel MCP server** (`get_incident`, `run_kql_query`, `get_entity_graph`, `get_identity_risk_score`) |
| Custom code surface | Whole MCP server | **One** function: `proposeContainmentAction` ([plugin](soar-containment-plugin.json)) |
| Graph queries | Custom Python engine | Native `make-graph` / `graph-match` via the Sentinel MCP server |

The design principle: **own the minimum.** Everything the platform now does
natively (incident retrieval, KQL graph, identity risk) is delegated to the
first-party Sentinel MCP server. The only thing that stays custom is the
proposal-only containment logic, because the automate-vs-approve policy is
organisation-specific.

## Two MCP servers, two trust levels

1. **`microsoft-sentinel` (native, read-only)** — Entra ID OAuth, least privilege
   (Sentinel Reader + Security Reader). `allowed_tools` is explicitly scoped to
   read/query tools.
2. **`identity-soar-containment` (custom, propose-only)** — federated workload
   identity holding **no Azure write role**. `allowed_tools` is a single function
   that returns a plan and never mutates state.

Because the agent is only ever handed read tools and a proposal tool, no prompt -
adversarial or otherwise - can make it disable a user or change a network. The
human approval gate and the audited execution playbook are unchanged from V2.

## Honest scope

These are valid, schema-referenced manifests, not a deployed agent. They compile
and validate offline; wiring them requires a tenant with Microsoft Security
Copilot and the native Sentinel MCP server enabled. The responsible-AI boundary
(propose, don't act) is enforced structurally by the `allowed_tools` scoping, not
just by instruction text.
