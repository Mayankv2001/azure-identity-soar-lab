# Sentinel RBAC Matrix

Least-privilege role → capability → persona mapping for the detection estate.
Read alongside [RBAC_REVIEW_MODEL.md](RBAC_REVIEW_MODEL.md) (the governance model)
and [sample-rbac-assignments.json](sample-rbac-assignments.json) (the concrete
fictional assignments).

> **Honest lab framing.** Fictional, illustrative model for a synthetic
> offline-first lab. No production tenant, no real GUIDs/subscriptions/secrets.
> Personas are `@contoso.com`; scopes are placeholders (`sub-lab` or the all-zero
> GUID `00000000-0000-0000-0000-000000000000`). The roles referenced are the
> real Microsoft built-in roles a production deployment *would* use — mapped here
> so the least-privilege reasoning is explicit and reviewable.

---

## 1. Roles in use (least-privilege built-ins)

Prefer built-in roles over custom ones; prefer narrow scope over broad. All
Sentinel/workspace roles are assigned at **workspace scope**, never subscription
or tenant scope, unless a genuine platform need is documented.

| # | Role | Plane | Scope in this model | Why this role (least-privilege intent) |
|---|------|-------|---------------------|----------------------------------------|
| R1 | **Microsoft Sentinel Reader** | Sentinel (workspace) | Workspace | Read incidents, rules, workbooks, hunting queries — the floor for any analyst |
| R2 | **Microsoft Sentinel Responder** | Sentinel (workspace) | Workspace | R1 + manage incidents (assign/status/comment) and run playbooks; **cannot author rules** |
| R3 | **Microsoft Sentinel Contributor** | Sentinel (workspace) | Workspace | R2 + create/edit analytics rules, workbooks, automation rules; for detection authoring & rollback |
| R4 | **Logic App Contributor** | Azure Resource (playbook RG) | Playbook resource group | Create/update/enable Logic App playbooks (deploy-time only); **excludes** rights to run destructive actions unattended |
| R5 | **Log Analytics Reader** | Data (workspace) | Workspace | Read underlying tables (`SigninLogs`, `AuditLogs`, `CyberArk_EPV_CL`) for hunting/investigation |
| R6 | **Security Reader** | Entra/Defender | Directory (read-only) | Cross-service posture read (e.g. Conditional Access state during DET-003) — granted only where needed, not by default |
| R7 | **Security Admin** | Entra/Defender | Directory (scoped) | Manage security config/connectors/policy state; platform ownership, **not** day-to-day triage |
| R8 | **Automation / Deployment identity** | Azure Resource | Workspace + playbook RG | Non-interactive CI principal: R3 + R4 at workspace/RG scope only; the **only** principal that writes rules to the workspace |
| R9 | **Owner (break-glass only)** | Azure Resource | Workspace | Emergency full control of the estate; held by a disabled break-glass account only (see model §5) |

Notes:

- **R3 vs R2 vs R1** is the core least-privilege gradient: read (R1) → respond
  (R2) → author (R3). Analysts stop at R1/R2; only engineers and the automation
  identity reach R3.
- **R4 (Logic App Contributor)** is a *deploy-time* capability, deliberately
  separate from *running* a playbook (which is governed by the Sentinel
  Responder role plus the run-time approval gate). Being able to build a playbook
  is not the same as being allowed to fire a destructive one.
- **R6/R7** live on the Entra/Defender plane, not the workspace — they are kept
  minimal because they are the broadest-reach roles in the set.
- **R9 (Owner)** exists in exactly one place and is normally unusable (disabled
  account). It is never assigned to a working human.

---

## 2. Role → capability matrix

Legend: **✅ granted**, **⛔ denied**, **⚠️ gated** (allowed but only through an
approval or pipeline gate).

| Capability | R1 Sentinel Reader | R2 Sentinel Responder | R3 Sentinel Contributor | R4 Logic App Contributor | R5 Log Analytics Reader | R6 Security Reader | R7 Security Admin | R8 Deploy identity | R9 Owner (break-glass) |
|------------|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Read incidents / rules / workbooks | ✅ | ✅ | ✅ | ⛔ | ⛔ | ⛔ | ✅ | ✅ | ✅ |
| Read raw log tables (KQL hunting) | ⛔ | ⛔ | ⛔ | ⛔ | ✅ | ⛔ | ⛔ | ⛔ | ✅ |
| Manage incidents (assign/status/comment) | ⛔ | ✅ | ✅ | ⛔ | ⛔ | ⛔ | ⛔ | ⛔ | ✅ |
| Run non-destructive playbooks (enrich/notify) | ⛔ | ✅ | ✅ | ⛔ | ⛔ | ⛔ | ⛔ | ⛔ | ✅ |
| Run session-revocation playbook (Critical) | ⛔ | ✅ | ✅ | ⛔ | ⛔ | ⛔ | ⛔ | ⛔ | ✅ |
| Run destructive playbooks (disable user / reset / role removal) | ⛔ | ⚠️ | ⚠️ | ⛔ | ⛔ | ⛔ | ⛔ | ⛔ | ⚠️ |
| Author / edit analytics rules | ⛔ | ⛔ | ✅ | ⛔ | ⛔ | ⛔ | ⛔ | ⚠️ | ✅ |
| Deploy rules to the workspace | ⛔ | ⛔ | ⚠️ | ⛔ | ⛔ | ⛔ | ⛔ | ⚠️ | ⚠️ |
| Create / edit Logic App playbooks | ⛔ | ⛔ | ⚠️ | ✅ | ⛔ | ⛔ | ⛔ | ✅ | ✅ |
| Approve playbook *changes* (governance gate) | ⛔ | ⛔ | ⛔ | ⛔ | ⛔ | ⛔ | ✅ | ⛔ | ⛔ |
| Read cross-service security posture (CA, Defender) | ⛔ | ⛔ | ⛔ | ⛔ | ⛔ | ✅ | ✅ | ⛔ | ⛔ |
| Configure connectors / platform / policy | ⛔ | ⛔ | ⛔ | ⛔ | ⛔ | ⛔ | ✅ | ⛔ | ✅ |
| Manage RBAC assignments | ⛔ | ⛔ | ⛔ | ⛔ | ⛔ | ⛔ | ⛔ | ⛔ | ✅ |

Reading the ⚠️ cells:

- **Destructive playbook runs** are ⚠️ for R2/R3/R9: the role *can* trigger them,
  but each one pauses for a named approver at run time (DRI, escalating to SecOps
  Manager for Tier-0). The role is necessary but not sufficient.
- **Author / deploy** is ✅ author but ⚠️ deploy for R3: engineers author freely,
  but shipping to the workspace goes through the pipeline's approval-gated deploy
  stage.
- **Deploy identity (R8)** authoring is ⚠️: it does not *write* rules by hand — it
  applies rule definitions produced and reviewed upstream, only from the gated
  `Deploy` stage. It is the *executor*, not the *author*.
- **Break-glass (R9)** can do everything, including manage RBAC — which is exactly
  why the account is disabled by default and every use is a paging + RCA event.

---

## 3. Capability → persona (who actually holds what)

| Capability | Persona(s) who hold it | Role granting it |
|------------|------------------------|------------------|
| Read incidents & logs | Wei Zhang (Analyst) | R1 + R5 |
| Triage & escalate incidents | Wei Zhang (Analyst) | R1 |
| Manage incidents + run response playbooks | Omar Haddad (DRI/Responder) | R2 |
| Approve destructive playbook *runs* | Omar Haddad (DRI) → Hana Kovac (Mgr) for Tier-0 | run-time gate (not a standing role) |
| Author & code-review detections | Raj Menon (Detection Eng Lead) | R3 |
| Build / edit playbooks | Raj Menon (Detection Eng Lead) | R4 |
| Deploy rules & playbooks to workspace | `svc-sentinel-deploy` (automation) | R8 |
| Approve playbook *changes* (governance) | Hana Kovac (SecOps Manager) | pipeline approval gate + R7-adjacent sign-off |
| Cross-service posture read | Raj Menon / Omar Haddad (as needed) | R6 (scoped, on request) |
| Platform / connector / policy config | Elena Petrova (Security Admin) | R7 |
| Emergency full access | `break-glass-01` (normally disabled) | R9 |

Cross-checks against separation of duties (model §4):

- **Author ≠ deployer:** Raj (R3) authors; `svc-sentinel-deploy` (R8) deploys.
- **Author ≠ change approver:** Raj authors; Hana approves the change.
- **Incident raiser ≠ destructive-run approver:** Wei/Omar raise; a *different*
  person approves the account-impacting playbook.
- **No human holds Owner:** R9 sits only on the disabled break-glass account.
- **Deploy identity is workspace-bound:** R8 never has subscription/tenant scope.

---

## 4. Scope discipline

| Persona | Assigned scope (placeholder) | Why not broader |
|---------|------------------------------|-----------------|
| Wei Zhang (Analyst) | Workspace | Reader needs the workspace, nothing above it |
| Omar Haddad (Responder) | Workspace + playbook RG | Runs playbooks in the RG; no subscription rights |
| Raj Menon (Detection Eng) | Workspace + playbook RG | Author/rollback in one estate; not a subscription contributor |
| Elena Petrova (Security Admin) | Directory (scoped) | Platform config is directory-plane; kept off the data plane |
| `svc-sentinel-deploy` | Workspace + playbook RG | CI writes exactly two things; scope creep is a review finding |
| `break-glass-01` | Workspace (all-zero GUID placeholder) | Emergency control of the *estate*, never of the cloud |

Nobody in this matrix is assigned at **subscription**, **management-group** or
**tenant** scope. Where a subscription-level placeholder is shown in the sample
assignments it is `sub-lab` (a stand-in string) or the all-zero GUID, never a
real subscription ID — because there is no real subscription.
