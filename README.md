# AI-Assisted Azure Identity Threat Detection & SOAR Lab

A runnable Microsoft Sentinel-style cloud security lab using synthetic Entra ID, audit, and privileged-access telemetry to demonstrate detection engineering, incident correlation, SOAR design, AI-assisted triage, and SecOps metrics.

A role-aligned security engineering portfolio project. Everything is synthetic and runs offline—it mirrors Microsoft Sentinel and Azure concepts and does not require, or claim, a production Sentinel deployment.

> **No time to run it?** Every artifact from a full demo run is committed under `demo-output/`—start with the **correlation timeline**, which shows how twelve alerts became eight incidents and why each one matters.

---

## Quick Review for Hiring Managers

* **Review without running:** Read `docs/PROJECT_OVERVIEW.md` for orientation, then open the committed sample outputs (no setup required): `sample_incident_timeline.md` (identity lab) and `control_plane_timeline.md` (control-plane module).
* **Run locally:** The demos run on Python 3.9+ and rely entirely on the standard library:
    ```bash
    python3 src/main.py --demo
    python3 modules/datacenter-control-plane/src/main.py --demo
    python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt && python3 -m pytest -q
    ```
* **Best artifacts to inspect:** The **Attack-Path Graph** (attack-path thinking as a diagram), the **Analyst Incident Packet** (a realistic operational handover packet), and the **Detection Quality Scorecard** (honest self-assessment of every detection).
* **Honest lab-vs-production boundary:** This is a synthetic, offline lab that mirrors Microsoft Sentinel and Azure concepts. The KQL is written against common Sentinel table names and the IaC/policy files are illustrative—none of it has been deployed to a production tenant. My production experience is in identity and privileged-access security; this project demonstrates how I extend that thinking into cloud security engineering, and it does not claim production Azure-scale operations experience.

---

## Why I Built This

My production background is in identity and privileged-access security (IAM/PAM), including investigating identity security signals, incident triage, and building automation around privileged access. I built this project to express that judgment in a cloud security engineering context: to show how identity attacks translate into detection engineering, correlation, SOAR, responsible AI, and the operational-excellence discipline (SLAs, honest metrics, false-positive tuning) that a mature security operations team runs on. It is offline-first so it runs on any machine with Python, and it draws a clear line throughout between what is production experience and what is demonstrated in this lab.

### The Problem It Models
* **Identity compromise becomes cloud infrastructure risk:** A single phished password plus MFA fatigue becomes a Global Administrator, a backdoored service principal, and a weakened Conditional Access policy—the lab's two showcase incidents replay exactly that identity-to-cloud attack path.
* **SOC teams need fidelity, not volume:** Detections must be correlated into investigable incidents, scored explainably, tuned against false positives, and measured (MTTD, MTTR, SLA adherence)—or they are just noise.
* **AI can help, within boundaries:** Summarization and triage guidance are real toil reducers, but high-risk response must remain human-approved and model input must be treated as attacker-influenceable data.

---

## Architecture & Capabilities

Detections are written as KQL and version-controlled YAML, mirrored as a tested Python engine, and shipped through a validation pipeline—see *Detection-as-Code* below. The production-readiness controls wrap the whole flow with the operational discipline (tuning, change approval, RBAC, cost, DRI) that a real deployment would require.

### Key Capabilities
* Deterministic synthetic telemetry generation (Entra ID sign-in/audit logs, CyberArk EPV events, identity/asset watchlists).
* 15 detections across modules, each synchronised as Sentinel-ready KQL, detection-as-code YAML, and a tested Python mirror.
* Explainable severity scoring (base + auditable context modifiers).
* Incident correlation mapping user + asset reachability instead of brittle time windows.
* SOAR playbook designs with explicit automation-vs-approval boundaries.

---

## Detection Coverage

| ID | Scenario | Data Source | MITRE Technique | Severity | Response Action |
|---|---|---|---|---|---|
| **DET-001** | MFA fatigue / push bombing | SigninLogs | T1621 | High $\rightarrow$ Critical | Revoke sessions, reset credentials via PB-04/05 |
| **DET-002** | Impossible travel | SigninLogs | T1078.004 | Medium | Attribute second IP; isolate if unexplained |
| **DET-003** | Conditional Access modified | AuditLogs | T1556.009 | High $\rightarrow$ Critical | Revert policy via PB-06; triage actor |
| **DET-004** | Service Principal cred added | AuditLogs | T1098.001 | High $\rightarrow$ Critical | Remove new credential; audit SP sign-ins |
| **DET-005** | Privileged role/group addition | AuditLogs | T1098.003 | High $\rightarrow$ Critical | Remove membership; suspend actor via PB-06 |
| **DET-006** | CyberArk checkout anomaly | CyberArk_EPV_CL | T1078.002 | Medium $\rightarrow$ Critical | Force check-in, rotate credentials, review PSM |
| **DET-007** | Stale privileged account | Identity Watchlist | T1078 | Low/Medium | Posture finding: disable or convert to PIM |

---

## Committed Demo Artifacts

If you prefer to review outputs directly without executing code, the following deterministic files are available in the repository:

| Artifact | Location | Operational Value |
|---|---|---|
| **Incident Timeline** | `demo-output/sample_incident_timeline.md` | Chronological walkthrough of alerts, incidents, and root cause analysis. |
| **Daily SecOps Report** | `demo-output/sample_daily_report.md` | Executive metrics: volumes, MTTD/MTTR, SLA breaches, and MITRE heatmap. |
| **AI Triage Summary** | `demo-output/sample_ai_triage_summary.md` | Bounded LLM triage briefing generated for the showcase MFA fatigue event. |
| **Raw Incident Context** | `demo-output/sample_incidents.json` | Underlying machine-readable incident objects with auditable context modifiers. |

---

## Advanced Extension: Datacenter Control Plane Attack Path Lab

Located under `modules/datacenter-control-plane/`, this secondary module follows the attacker past the identity plane and directly into Azure infrastructure—the exact seam where cloud security engineering operates.

* **What it demonstrates:** One correlated attack chain tracking a risky sign-in $\rightarrow$ MFA fatigue $\rightarrow$ ticketless privileged-role activation $\rightarrow$ credential added to a high-privilege service principal $\rightarrow$ Owner role granted on a core resource group $\rightarrow$ an NSG rule opening RDP to `0.0.0.0/0` on a management jumpbox.
* **Why it matters:** Cloud security engineering is more than alert watching. This module models cross-plane entity correlation into a single Critical incident with an explainable blast-radius score (100/100) and provides a blameless post-mortem recommending the specific Azure Policy that blocks the root configuration flaw.

---

## Aligning with Microsoft's 2026 Roadmap

The `v3-enterprise-native/` layer implements an enterprise polish, retiring custom code in favor of first-party Microsoft capabilities. The guiding principle: **delete the custom component the moment the platform grows a native equivalent.**

* **From Python to Sentinel Graph:** The custom Python attack-graph engine is deprecated in favor of native KQL `make-graph` / `graph-match` operators. This maps the cross-plane identity-to-infrastructure path entirely inside Log Analytics with zero external compute footprint.
* **Sentinel Graph vs. Defender XDR Unified Graph:** With Microsoft Sentinel and Microsoft Defender XDR now merged into the Unified Security Operations Platform, `make-graph` is reserved for our custom lab telemetry (e.g., CyberArk safe checks, custom asset logs). For standard Microsoft identities, the architecture natively offloads to the **Microsoft Defender XDR Identity Graph** and Advanced Hunting tables (`IdentityInfo`, `IdentityDirectoryEvents`) to minimize query overhead.
* **From Generic Agents to Security Copilot MCP Plugins:** The generic automation scripts are replaced by a **Microsoft Security Copilot MCP Server** design. By targeting the standalone SOC portal (`securitycopilot.microsoft.com`) and strictly structuring tool permissions via the manifest, the AI is granted read-only access to risk data and a single proposal-only tool (`propose_containment_action`). The boundary is enforced by application architecture, not prompt prose.
* **From Legacy Ingestion to DCRs & CCF:** Telemetry ingestion bypasses the deprecated HTTP Data Collector API. The lab implements a Bicep-deployed **Data Collection Endpoint (DCE)** and **Data Collection Rule (DCR)** using keyless Entra ID Workload Identity federation, perfectly aligning with the architecture of the Codeless Connector Framework.

---

## Repository Architecture

```text
azure-identity-soar-lab/
├── .azure-pipelines/
│   └── validate-detections.yml        CI/CD: validate -> test -> package -> gated deploy
├── data/                              Committed synthetic telemetry (seed 42, 7 days)
├── demo-output/                       Committed sample run artifacts (timelines, metrics)
├── detections/                        15 x Production-ready KQL & YAML analytics rules
├── playbooks/                         Logic App pseudocode and automate-vs-approve matrices
├── src/                               Core simulation, incident building, and metrics engines
├── modules/datacenter-control-plane/  Identity-to-infrastructure attack path module
├── security-engineering/              Scorecards, purple-team plays, and prevention policies
└── production-readiness/              Ops framework (Cost governance, DRI runbooks, RBAC)
```

---

## License

Released under the [MIT License](LICENSE).
