# AI-Assisted Azure Identity Threat Detection & SOAR Lab

A runnable Microsoft Sentinel-style cloud security lab using synthetic Entra
ID, audit, and privileged-access telemetry to demonstrate detection
engineering, incident correlation, SOAR design, AI-assisted triage, and SecOps
metrics.

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![Tests 55 passing](https://img.shields.io/badge/tests-55%20passing-success)
![Offline first](https://img.shields.io/badge/mode-offline--first-success)
![MITRE ATT&CK mapped](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red)
![License MIT](https://img.shields.io/badge/license-MIT-green)

A role-aligned security engineering portfolio project. Everything is synthetic
and runs offline - it mirrors Microsoft Sentinel and Azure concepts and does not
require, or claim, a production Sentinel deployment.

**No time to run it?** Every artefact from a full demo run is committed under
[demo-output/](demo-output/) - start with the
[correlation timeline](demo-output/sample_incident_timeline.md), which shows
how twelve alerts became eight incidents and why each one matters.

## Quick review for hiring managers

**a. Review without running.** Read [docs/PROJECT_OVERVIEW.md](docs/PROJECT_OVERVIEW.md)
for orientation, then open the committed sample outputs - no setup required:
[sample_incident_timeline.md](demo-output/sample_incident_timeline.md) (identity
lab) and
[control_plane_timeline.md](modules/datacenter-control-plane/demo-output/control_plane_timeline.md)
(control-plane module).

**b. Run locally.** Python 3.9+; the demos are standard-library only:

```bash
python3 src/main.py --demo
python3 modules/datacenter-control-plane/src/main.py --demo
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt && python3 -m pytest -q
```

**c. Best artefacts to open.** The
[Attack-Path Graph](security-engineering/attack-path-graph.md) (attack-path
thinking as a diagram), the
[Analyst Incident Packet](security-engineering/incident-packet/) (a realistic
handover packet), and the
[Detection Quality Scorecard](security-engineering/detection-quality-scorecard.md)
(honest self-assessment of every detection).

**d. Honest lab-vs-production boundary.** This is a synthetic, offline lab that
mirrors Microsoft Sentinel and Azure concepts. The KQL is written against common
Sentinel table names and the IaC/policy files are illustrative - none of it has
been deployed to a production tenant. My production experience is in identity and
privileged-access security; this project demonstrates how I extend that thinking
into cloud security engineering, and it does not claim production Azure-scale
operations experience.

## Why I built this

My production background is in identity and privileged-access security (IAM/PAM),
including investigating identity security signals, incident triage, and building
automation around privileged access. I built this project to express that
judgement in a cloud security engineering context: to show how identity attacks
translate into detection engineering, correlation, SOAR, responsible AI, and the
operational-excellence discipline (SLAs, honest metrics, false-positive tuning)
that a mature security operations team runs on. It is offline-first so it runs on
any machine with Python, and it draws a clear line throughout between what is
production experience and what is demonstrated in this lab.

## The problem it models

- **Identity compromise becomes cloud infrastructure risk.** A single phished
  password plus MFA fatigue becomes a Global Administrator, a backdoored
  service principal, and a weakened Conditional Access policy - the lab's two
  showcase incidents replay exactly that identity-to-cloud attack path.
- **SOC teams need fidelity, not volume.** Detections must be correlated into
  investigable incidents, scored explainably, tuned against false positives,
  and measured (MTTD, MTTR, SLA adherence) - or they are just noise.
- **AI can help, within boundaries.** Summarisation and triage guidance are
  real toil reducers, but high-risk response must remain human-approved and
  model input must be treated as attacker-influenceable data.

## Key capabilities

- Deterministic synthetic telemetry generation (Entra ID sign-in and audit
  logs, CyberArk EPV events, identity/asset inventory - seed 42, 7 days)
- Seven detections, each in three synchronised forms: Sentinel-ready KQL,
  detection-as-code YAML, and a tested Python mirror with identical thresholds
- MITRE ATT&CK mapping per rule, with coverage computed as a report table
- Explainable severity scoring (base + auditable context modifiers)
- Incident correlation (user + time window) - multi-stage attacks become one
  investigation, not three pages
- SOAR playbook designs with explicit automation-vs-approval boundaries
- AI-assisted triage briefings with documented security boundaries
- A false-positive tuning story: a narrow tuning rule removed the seeded
  false-positive class entirely (see the honest note below - this demonstrates
  a tuning method, not a real-world zero-false-positive claim)
- MTTD / MTTR / SLA-adherence / FP-rate metrics computed from the incident
  lifecycle
- Azure DevOps validation pipeline (validate, test, package, approval-gated
  deploy)
- Fully local demo; documented optional path to a real Sentinel workspace

## Architecture

```mermaid
flowchart LR
    A["Synthetic telemetry"] --> B["KQL / YAML detections"]
    B --> C["Python detection mirror"]
    C --> D["Alerts"]
    D --> E["Correlation"]
    E --> F["Incidents"]
    F --> G["AI triage"]
    G --> H["SOAR playbooks"]
    F --> I["Metrics / reporting"]
    I --> J["Production-readiness controls"]
```

Detections are written as KQL and version-controlled YAML, mirrored as a tested
Python engine, and shipped through an Azure DevOps pipeline (validate, test,
package, approval-gated deploy) - see
[Detection-as-code and CI](#detection-as-code-and-ci) below. The
[production-readiness controls](production-readiness/README.md) wrap the whole
flow with the operational discipline (tuning, change approval, RBAC, cost, DRI)
that a real deployment would require.

## Demo in 5 minutes

```bash
git clone https://github.com/Mayankv2001/azure-identity-soar-lab.git
cd azure-identity-soar-lab
python3 src/main.py --demo
```

No dependencies needed - the pipeline is Python standard library only.
Expected output:

- **7 of 7 detections fire** over the 7-day window: 345 sign-in events in,
  **12 alerts** out (7 Critical, 2 High, 3 Medium)
- **8 incidents** after correlation - 4 true positives, 1 false positive,
  3 posture findings
- **Showcase incident INC-1003:** MFA fatigue burst plus two impossible-travel
  alerts against one victim, merged into a single Critical incident
- **Showcase incident INC-1004:** compromised service-desk account adds a
  service principal credential, self-elevates to Global Administrator, then
  disables a Conditional Access policy - three detections in 30 minutes,
  correctly correlated into one Critical incident
- **Metrics:** MTTD 1.4 h, MTTR 12.7 h, SLA adherence 93.8% (one honest
  breach). A narrow tuning rule (v1.1.0) removed the seeded false-positive
  class entirely - this demonstrates the tuning *method* on a fixed,
  deterministic dataset, not a claim of zero false positives in a real, noisy
  environment.

Tests and validation (dev dependencies only):

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 -m pytest -q        # 55 tests across labs, deployment artifacts and production-readiness layer
```

## Detection coverage

| ID | Scenario | Data source | MITRE technique | Severity | Response idea |
|----|----------|-------------|-----------------|----------|---------------|
| DET-001 | MFA fatigue / push bombing | SigninLogs | T1621 | High -> Critical on post-burst approval | Revoke sessions, reset credential + MFA re-registration (PB-04/PB-05) |
| DET-002 | Impossible travel | SigninLogs | T1078.004 | Medium (context-escalated) | Attribute the second IP; revoke sessions if unexplained (PB-04) |
| DET-003 | Conditional Access policy modified/deleted | AuditLogs | T1556.009 | High -> Critical for unauthorised actor | Revert policy; treat actor as compromised (PB-06) |
| DET-004 | Service principal credential added | AuditLogs | T1098.001 | High -> Critical for high-privilege app | Remove the new credential; audit SP sign-ins |
| DET-005 | Privileged role/group addition | AuditLogs | T1098.003, T1098.007 | High -> Critical on self-elevation | Remove membership; suspend actor pending review (PB-06) |
| DET-006 | CyberArk checkout anomaly | CyberArk_EPV_CL (custom) | T1078.002 | Medium -> Critical for Tier-0 safe | Force check-in, rotate credentials, review PSM recordings |
| DET-007 | Stale/orphaned privileged account | Identity watchlist | T1078 | Low/Medium posture (High if orphaned) | Disable or convert to PIM-eligible with expiry |

Each detection is three synchronised artefacts - `detections/DET-00X-*.kql`
(KQL written against common Sentinel table names), `detections/DET-00X-*.yaml` (the analytics
rule as reviewable code: severity, MITRE, entity mappings, SLA, known false
positives, tuning exclusions) and a mirrored function in
`src/detection_engine.py`. A CI test fails if any of the three drifts.

## Read the outputs without running anything

Committed, deterministic artefacts from a real demo run:

| Artefact | What it shows |
|----------|---------------|
| [sample_incident_timeline.md](demo-output/sample_incident_timeline.md) | **Best artefact to review first** - every alert chronologically, its incident, why it matters, recommended next action |
| [sample_daily_report.md](demo-output/sample_daily_report.md) | The daily SecOps report: volumes, MTTD/MTTR, SLA breaches, tuning impact, MITRE coverage |
| [sample_ai_triage_summary.md](demo-output/sample_ai_triage_summary.md) | AI briefing for the MFA-fatigue incident (offline deterministic mode) |
| [sample_alerts.json](demo-output/sample_alerts.json) / [sample_incidents.json](demo-output/sample_incidents.json) | Raw alert and incident objects with severity reasoning |
| [sample_metrics.json](demo-output/sample_metrics.json) | Machine-readable metrics snapshot |

Regenerate any time with `python3 src/export_demo_outputs.py`.

## Detection-as-code and CI

[.azure-pipelines/validate-detections.yml](.azure-pipelines/validate-detections.yml)
runs four stages on every change to `detections/`, `src/` or `tests/`:
**Validate** (every rule has KQL + YAML + engine implementation; schemas and
MITRE formats checked), **Test** (full pytest suite plus an end-to-end demo
smoke run), **Package** (rules published as a deployable artifact), **Deploy**
(an approval-gated Sentinel deployment path: a deployment job against a
manual-approval environment; without a subscription it documents the exact
`az sentinel alert-rule create` path and stays green).

## SOAR playbooks

Six Logic App-style designs in [playbooks/](playbooks/): enrich, notify DRI,
open ticket, revoke sessions, require password reset, disable user. The
automation boundary is a three-question framework - blast radius,
reversibility, confidence
([playbooks/soar-response-design.md](playbooks/soar-response-design.md)).
Session revocation runs unattended at Critical severity; anything that can
lock a human out waits for DRI approval.

## Responsible AI

- AI is used for **alert summarisation and triage guidance only**.
- It receives **minimised aggregates of synthetic telemetry** - never raw
  evidence, never secrets, and in any real adaptation, never customer data.
- **No automatic destructive actions.** Account disablement, session
  revocation, role removal, network/firewall changes and service principal
  credential rotation all require human approval through the playbooks.
- Telemetry-derived text is wrapped in untrusted-input delimiters
  (prompt-injection defence); AI output is **advisory, not authoritative**.
- Offline deterministic mode is the default - no key, no network. Every prompt
  and briefing is persisted for audit.

Full write-up: [docs/RESPONSIBLE_AI.md](docs/RESPONSIBLE_AI.md).

## What it demonstrates

- **Microsoft Sentinel and KQL:** seven analytics rules modelled on the
  scheduled-rule schema, written against common Sentinel table names
  (`SigninLogs`, `AuditLogs`, custom `CyberArk_EPV_CL`), with the KQL nuances
  documented (tumbling vs sliding windows, join cost, watchlist lookups).
- **MITRE ATT&CK:** mapped per rule and computed as a coverage table across
  six tactics - gaps visible, not vibes.
- **Identity-to-cloud attack path thinking:** the showcase incidents replay how
  one phished helpdesk account becomes tenant-wide compromise.
- **SOAR / Logic Apps:** blast radius, reversibility, confidence - the
  three-question framework that decides what runs unattended.
- **Azure DevOps:** detections ship like code - validated, tested, packaged
  and deployed through an approval gate.
- **Incident response and DRI:** correlation into single investigations,
  severity-driven SLA clocks, a first-15-minutes runbook, blameless RCA
  ([docs/DRI_RUNBOOK.md](docs/DRI_RUNBOOK.md)).
- **False-positive reduction:** disposition data feeds narrow, versioned,
  tested exclusions - a narrow tuning rule removed the seeded false-positive
  class with zero lost true positives (deterministic lab tuning method, not a
  real-world zero-false-positive claim).
- **Operational metrics:** MTTD, MTTR and SLA adherence computed from the
  incident lifecycle, with the one breach displayed rather than buried.
- **Responsible AI:** the AI briefs, the human decides, the playbook acts.

## Known limitations

Stated honestly, because a security engineer should be able to describe the
boundaries of their own system:

- This is **offline-first and Sentinel-style**, not a production deployment.
  **Mode B** is the documented CI/CD promotion pattern (how detections would
  reach a workspace). **Mode C** is an optional live lab deployment path that
  *was* run in a personal/test Azure subscription (workspace, Sentinel
  onboarding, and the disabled `[LAB] DET-001` rule) - a lab, not production.
- All telemetry is **synthetic** and shaped for clarity; real environments are
  noisier and the thresholds here would need baselining and tuning.
- The detections are **educational reference implementations** - production
  use would add UEBA-style baselining (especially DET-006), token-theft
  coverage, and ingestion-cost engineering.
- The AI component defaults to a deterministic offline template; the Azure
  OpenAI mode is optional and untested at scale.
- **Reaching production** would still require real telemetry, tuning against
  real noise, an RBAC review, a cost review, change approval, and ongoing
  operations - the controls documented in the
  [production-readiness layer](production-readiness/README.md).

## Safe to share

This repository contains **no real employer data, no internal logs, no
secrets, no customer information, and no proprietary architecture**. Every
identity, IP address and event is fictional and generated by
`src/generate_logs.py` (documentation IP ranges, contoso.com personas,
fixed seed). It is safe to read, run, fork and discuss publicly.

## Repository structure

```
azure-identity-soar-lab/
├── README.md                          ├── LICENSE   ├── requirements.txt
├── .azure-pipelines/
│   └── validate-detections.yml        CI: validate -> test -> package -> gated deploy
├── data/                              committed synthetic telemetry (regenerable)
├── demo-output/                       committed sample run artefacts (see table above)
├── detections/                        7 x KQL + 7 x YAML analytics rules
├── docs/
│   ├── PROJECT_OVERVIEW.md            what it is, how to run it, limitations
│   ├── DEMO_SCRIPT.md                 technical demo walkthrough
│   ├── DATACENTER_CONTROL_PLANE_TALK_TRACK.md  module explainer
│   ├── DRI_RUNBOOK.md                 on-call / SLA / RCA model
│   └── RESPONSIBLE_AI.md              AI safety boundaries
├── playbooks/
│   ├── soar-response-design.md        6 playbooks + automation-vs-approval matrix
│   └── logic-app-pseudocode.json
├── src/
│   ├── main.py                        entry point (--demo)
│   ├── generate_logs.py               deterministic telemetry generator
│   ├── detection_engine.py            7 detections + severity model
│   ├── incident_builder.py            correlation, triage, SLA lifecycle
│   ├── ai_assistant.py                bounded AI briefings (offline / Azure OpenAI)
│   ├── reporting.py                   daily operations report
│   └── export_demo_outputs.py         regenerates demo-output/
├── modules/datacenter-control-plane/  advanced extension: identity-to-cloud attack path (8 detections)
├── security-engineering/              detection scorecard, purple-team pack, attack-path graph, incident packet
├── production-readiness/              lab-vs-production operations layer (telemetry, connectors, IR, tuning, RBAC, cost, DRI, maintenance) + scorecard
├── infra/sentinel/                    Mode C Bicep: lab Log Analytics + Sentinel + disabled [LAB] DET-001 rule
├── scripts/sentinel/                  Mode C deploy / validate / verify scripts (personal/test subscription only)
└── tests/                             55 tests across labs, deployment artifacts and production-readiness
```

## Mode B: deploying to Azure (documented path)

The lab is designed to port: KQL targets production table schemas, YAML rules
mirror the scheduled-analytics-rule contract, and watchlist lookups
(`CAPolicyAdmins`, `HighPrivilegeApps`, `PrivilegedIdentities`) replace the
lab's JSON reference data. Deployment order: Log Analytics workspace + Sentinel
onboarding, data connectors (Entra ID sign-in/audit, CyberArk via AMA or the
Logs Ingestion API), watchlists, then analytics rules via the pipeline's deploy
stage and playbooks as Logic Apps.

## Optional live Sentinel deployment path (Mode C, lab only)

Offline mode is the default. **Mode C** is an optional path that deploys into a
real Microsoft Sentinel workspace using Bicep and Azure CLI - in a
**personal/test subscription only**. This path *was* run as a lab: a Log
Analytics workspace, Sentinel onboarding, and the custom scheduled analytics rule
**`[LAB] DET-001 MFA Fatigue`** were deployed, with the **rule disabled by
default** and **no destructive automation**. That is a lab deployment - **not
production**.

- Deploys a lab Log Analytics workspace (30-day retention), Sentinel onboarding,
  and a sample scheduled analytics rule (DET-001), **disabled by default**.
- Optional, off by default: a non-destructive tagging automation rule and a
  disabled Logic App playbook skeleton.
- **No destructive playbooks, no secrets, no tenant/subscription IDs** in the
  repo. Not production-ready - the rules require tenant-specific tuning, cost
  review, and change-control approval first (see the
  [production-readiness layer](production-readiness/README.md) and its
  [scorecard](production-readiness/reports/PRODUCTION_READINESS_SCORECARD.md)).

Details: [docs/LIVE_SENTINEL_DEPLOYMENT_PATH.md](docs/LIVE_SENTINEL_DEPLOYMENT_PATH.md)
| Infrastructure: [infra/sentinel/](infra/sentinel/)

## Advanced extension: Datacenter Control Plane Attack Path Lab

A second module, [modules/datacenter-control-plane/](modules/datacenter-control-plane/),
follows the attacker past the identity plane and into Azure infrastructure -
the seam where cloud security engineering actually operates.

**What it demonstrates:** one correlated attack chain from a risky sign-in ->
MFA fatigue -> ticketless privileged-role activation -> credential added to a
high-privilege service principal -> Owner granted on a synthetic cloud-management
resource group -> an NSG rule opening RDP to `0.0.0.0/0` on a reachable
management jumpbox. Eight KQL-mirrored detections across Entra ID, Azure
Activity and Defender telemetry are correlated by identity, service principal
and resource scope into **one Critical incident with an explainable
blast-radius score (100/100)**, followed by approval-gated containment and an
RCA that recommends the Azure Policy which would have prevented the exposure.

**Why it matters:** cloud security engineering is more than alert-watching. This
module shows identity-to-cloud attack-path thinking, detection engineering as
code, Azure networking/RBAC/NSG reasoning, IaC (Bicep + Azure Policy), and SOAR
with strict automate-vs-approve boundaries for destructive network changes.

**How to run it:**

```bash
python3 modules/datacenter-control-plane/src/main.py --demo
```

**Best artefact to review:**
[modules/datacenter-control-plane/demo-output/control_plane_timeline.md](modules/datacenter-control-plane/demo-output/control_plane_timeline.md)
- the full chain chronologically with the blast-radius breakdown and response
flow. Module explainer:
[docs/DATACENTER_CONTROL_PLANE_TALK_TRACK.md](docs/DATACENTER_CONTROL_PLANE_TALK_TRACK.md).
Full detail: [module README](modules/datacenter-control-plane/README.md).

## Security Engineering Excellence Layer

A professional layer wrapping both labs that demonstrates detection-engineering
maturity, purple-team thinking, prevention (not just detection), incident-response
readiness and operational metrics. All under [security-engineering/](security-engineering/).

| Artefact | What it shows |
|----------|---------------|
| [Detection Quality Scorecard](security-engineering/detection-quality-scorecard.md) | All 15 detections scored 0-100 on transparent criteria (avg 91.8) - regenerated by [score_detections.py](security-engineering/score_detections.py), stdlib only |
| [Purple-Team Validation Pack](security-engineering/purple-team-validation.md) | Every detection mapped to a safe, simulation-based adversary behaviour with its benign look-alike |
| [Attack-Path Graph](security-engineering/attack-path-graph.md) | The control-plane incident as a graph - identity to management-endpoint, with the earliest break point |
| [Analyst Incident Packet](security-engineering/incident-packet/) | A realistic handover packet for CP-INC-2001: brief, timeline, entities, containment, RCA, exec summary |
| [Prevention Controls](security-engineering/prevention-controls.md) | Eight preventive controls with policy-as-code - stopping attacks, not just detecting them |
| [KQL Test Harness](security-engineering/kql-test-harness.md) | How each KQL rule is validated before production, plus the detection promotion checklist |
| [Executive Risk Report](security-engineering/executive-risk-report.md) | One-page, non-technical leadership summary of the risk and the plan |
| [90-Day Roadmap](security-engineering/90-day-roadmap.md) | How this work maps to adding value in a first 30/60/90 days |

**Honest framing:** my production strength is identity and privileged-access
automation. This layer shows how I think about cloud security engineering,
detection maturity, responsible automation and identity-to-infrastructure risk -
on synthetic data, mirroring Sentinel and Azure concepts, without claiming
production deployment.

## Production Readiness & Operations Layer

The gap between a lab Sentinel deployment and a production security operations
capability is not more detections - it is the operating controls around them.
[production-readiness/](production-readiness/) documents that gap honestly, using
**no real company or customer data**: telemetry maturity and source mappings,
data-connector runbooks, an incident-response operating model, a detection-tuning
and promotion workflow, change approval, RBAC least-privilege review, Sentinel
cost governance, a DRI/on-call model, playbook validation, and ongoing
maintenance/ownership.

It scores the project against ten production-readiness dimensions and is candid
about the result: **55/100 - "Production candidate"**, strong on documentation
and lab design, not production-ready because no real enterprise telemetry or
tuning exists yet. See
[production-readiness/README.md](production-readiness/README.md) and the
[production readiness scorecard](production-readiness/reports/PRODUCTION_READINESS_SCORECARD.md).

## Version 2.0: Agentic AI SOAR & graph correlation

[v2-agentic-soar/](v2-agentic-soar/) aligns the lab with 2026 patterns: a
Microsoft Security Copilot custom agent with an MCP grounding server (replacing
static playbooks - AI proposes, humans approve), a workload-identity
**credential-bridging** detection for compromised GitHub Actions pipelines, a
runnable **graph-powered correlation** engine
([src/graph_correlation.py](src/graph_correlation.py)) that recovers an
identity-to-infrastructure attack path a time-window join misses, and a
shift-left **GitHub Actions (OIDC, no secrets) + Bicep** detection-as-code
pipeline. Details: [v2-agentic-soar/README.md](v2-agentic-soar/README.md).

## License

MIT - see [LICENSE](LICENSE).
