# Version 3.0 — Enterprise native (aligning with Microsoft's 2026 roadmap)

V2 proved the concepts with custom code. V3 does what a senior engineer does next:
**retires the custom implementations for first-party Microsoft capabilities**,
keeping only the irreducible org-specific logic. Less code to own, on the
supported path, ready for the platform's deprecation schedule.

| Deliverable | Was (custom / legacy) | Now (native) | Artefact |
|-------------|-----------------------|--------------|----------|
| Graph correlation | Python `AttackGraph` engine | KQL `make-graph` / `graph-match` | [graph/attack-path-make-graph.kql](graph/attack-path-make-graph.kql) |
| Agent | Generic custom agent + full custom MCP | Declarative Agent + native Sentinel MCP; custom MCP only for `propose` | [declarative-agent/](declarative-agent/) |
| Ingestion | Legacy Data Collector API | DCE + DCR + Logs Ingestion API | [ingestion/](ingestion/) |

## 1. Sentinel native graph (KQL)

[attack-path-make-graph.kql](graph/attack-path-make-graph.kql) reproduces the V2
Python graph engine's result using KQL's native graph operators - normalise
heterogeneous telemetry into a typed edge list, `make-graph`, then `graph-match`
the 3-hop path `User -[added_credential_to]-> SP -[modified]-> NSG
-[exposed_to_internet]-> VM`. It runs inside Log Analytics with no external
compute, and it still recovers the path a caller-keyed time-window join misses.
`src/graph_correlation.py` is now marked **deprecated** in favour of this.

## 2. Declarative Agent

[manifest.json](declarative-agent/manifest.json) is a versioned Declarative Agent
that declares two MCP servers: the **native Microsoft Sentinel MCP server** (read
tools: incident, KQL graph, identity risk) and a **custom MCP plugin scoped to a
single proposal-only function**
([soar-containment-plugin.json](declarative-agent/soar-containment-plugin.json)).
The agent is handed read tools and one proposal tool - structurally it cannot
change tenant state. Design: [declarative-agent/design.md](declarative-agent/design.md).

## 3. DCR ingestion (Bicep)

[dcr-logs-ingestion.bicep](ingestion/dcr-logs-ingestion.bicep) provisions a DCE +
DCR + custom table so telemetry is ingested through the **Logs Ingestion API**
(Entra ID token, keyless), replacing the retiring Data Collector API. Details:
[ingestion/README.md](ingestion/README.md).

---

## Aligning with Microsoft's 2026 roadmap

> The mark of a mature security platform build is not how much custom code it
> contains - it is how little. V3 deliberately deletes custom scaffolding the
> platform now provides natively, so the lab ages *with* Microsoft's roadmap
> instead of against it.

**From Python to Sentinel Graph.** My V2 attack-path engine was a custom Python
graph built on time-adjacent joins glued together in application code. That is
technical debt: it lives outside the data plane, it has to be hosted and
maintained, and it duplicates a capability the platform now ships. KQL's native
`make-graph` / `graph-match` operators express the same identity-to-infrastructure
path *inside* Log Analytics - no external compute, no glue code, and it composes
with every other analytics rule. I keep the Python version only as a readable
reference; the native KQL is the go-forward.

**From generic agents to Declarative Agents.** A hand-rolled agent wrapping a
bespoke MCP server means I own the whole surface - retrieval, grounding, auth,
and the reasoning loop. The Declarative Agent format lets me declare the
**first-party Microsoft Sentinel MCP server** for everything the platform does
natively (incident retrieval, KQL graph, unified identity risk) and reduce my
custom footprint to the one thing that is genuinely organisation-specific: the
proposal-only containment plugin. Less bespoke auth to secure, less to break on
an update, and the responsible-AI boundary (propose, never act) is enforced by
`allowed_tools` scoping, not just prose.

**From legacy APIs to DCRs / CCF.** Ingesting synthetic telemetry through the
legacy Log Analytics Data Collector API would have shipped a lab that is already
on a deprecation clock, and gated on a shared workspace key. Moving to a **Data
Collection Rule + Data Collection Endpoint on the Logs Ingestion API** puts the
lab on the supported path: keyless Entra ID auth with a least-privilege publisher
role, schema-on-write with an ingestion-time transform for cost and quality
control, and the same pattern the **Codeless Connector Framework (CCF)** uses to
build data connectors declaratively rather than in code. Future-proofed, not
just working today.

The theme across all three: **delete the custom thing when the platform grows a
native one.** That is how you keep an enterprise security estate cheap to run and
easy to trust.

## Honest scope

The KQL, manifests and Bicep are valid and validate offline (`az bicep build`,
JSON-schema-referenced). They are **native-aligned designs**, not a live
deployment - wiring them needs a tenant with Sentinel graph, Security Copilot, and
the DCR pipeline enabled. Nothing here is auto-enabled, and every state-changing
action remains human-approved.
