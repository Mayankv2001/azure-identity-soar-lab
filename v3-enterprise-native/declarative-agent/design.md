# Declarative Agent — design

V2 described a generic "custom agent" with a single custom MCP server. V3 moves to
a declarative manifest that leans on native servers and keeps only the
irreducible custom piece.

## Which Copilot: Security Copilot, not M365 Copilot

This agent and its MCP plugin are built for **Microsoft Security Copilot** - the
standalone SOC portal (securitycopilot.microsoft.com) used by SOC analysts and
DRIs - **not** a generic **Microsoft 365 Copilot** declarative agent that a
knowledge worker invokes in Teams, Word or Outlook. The distinction matters:

| | Microsoft Security Copilot | Microsoft 365 Copilot declarative agent |
|---|----------------------------|------------------------------------------|
| Surface | Standalone SOC portal, embedded in Defender/Sentinel | Teams / Word / Outlook / M365 chat |
| Persona | SOC analyst, DRI, threat hunter | Knowledge worker |
| Grounding | Security graph, incidents, hunting, threat intel | Graph connectors, SharePoint, web |
| Purpose | Investigate and respond to incidents | Productivity and content |

The extensibility models are **converging** - both increasingly use the same
building blocks (declarative manifests, MCP servers and plugins), which is why
this manifest reuses the declarative-agent schema and the `target_platform` field
names the intended runtime explicitly. But the **audience and runtime are the
Security Operations Center**, not end-user productivity, and the plugin's tools,
grounding and guardrails are designed for that persona.

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
