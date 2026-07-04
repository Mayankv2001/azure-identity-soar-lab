# Sentinel RBAC & Review Model

How access to the detection estate *would* be governed if this lab were promoted
into a real Microsoft Sentinel workspace. This is the human side of production
readiness: who is allowed to deploy a detection, who signs off a response
playbook, who can actually revoke a session or disable an account, and who may
only read.

> **Honest lab framing.** This repository is a synthetic, offline-first lab that
> mirrors Microsoft Sentinel and Azure concepts; nothing here is deployed to a
> production tenant. The roles, personas and assignments in this document are
> **fictional and illustrative**. Every identity is a `@contoso.com` persona, and
> every scope is a placeholder (`sub-lab` or the all-zero GUID
> `00000000-0000-0000-0000-000000000000`). There are **no real GUIDs, tenant
> IDs, subscription IDs, secrets or employer data** anywhere in this layer. The
> model is written the way I would propose it to a security operations team, not
> as a record of a live deployment.

Companion files:

- [SENTINEL_RBAC_MATRIX.md](SENTINEL_RBAC_MATRIX.md) — roles vs capabilities vs
  who holds each one.
- [LEAST_PRIVILEGE_REVIEW_CHECKLIST.md](LEAST_PRIVILEGE_REVIEW_CHECKLIST.md) —
  the checklist a reviewer runs each quarter.
- [sample-rbac-assignments.json](sample-rbac-assignments.json) — machine-readable
  fictional assignments with justifications and review-due dates.

This model aligns with the DRI/on-call structure in
[../../docs/DRI_RUNBOOK.md](../../docs/DRI_RUNBOOK.md) and the automation-vs-approval
boundaries in [../../playbooks/soar-response-design.md](../../playbooks/soar-response-design.md).

---

## 1. Principles

The whole model rests on five rules, in priority order:

1. **Least privilege by default.** Every persona gets the narrowest built-in role
   that lets them do their job, scoped as tightly as possible. New access starts
   at *read-only* and is widened only with a written justification.
2. **Separation of duties.** The person who *writes and deploys* a detection is
   not the same person who *approves the destructive response* it triggers, and
   neither is the *automation identity* that ships to the workspace. No single
   human holds deploy + approve + break-glass.
3. **Scope over role.** Prefer a powerful role at a *narrow* scope (one resource
   group / one workspace) over a weak role at a broad scope (a subscription).
   Nobody is assigned at management-group or tenant scope in this model.
4. **Human-in-the-loop for destructive actions.** Session revocation runs
   unattended only at Critical severity; anything that can lock a person out
   (disable user, remove role, rotate credentials) waits for a named approver.
   RBAC enforces that only Responders can *run* those playbooks and only
   Approvers can *authorise* the account-impacting ones.
5. **Everything is reviewable and time-bound.** Standing privileged access is
   reviewed quarterly; any elevation above read is expected to carry an expiry,
   ideally through Privileged Identity Management (PIM) eligibility rather than a
   permanent assignment.

---

## 2. Personas (all fictional, all `@contoso.com`)

These are **security-team** personas, deliberately distinct from the synthetic
*actors and victims* that appear in the lab's telemetry (Priya Sharma, Chris
Walker, etc.). Nobody below appears in a sign-in or audit log — they are the
people who *operate the detection estate*.

| Persona | Email | Function | Primary Sentinel role |
|---------|-------|----------|-----------------------|
| Ravi Menon | `ravi.menon@contoso.com` | Detection Engineering Lead | Sentinel Contributor (rule authoring & deploy path owner) |
| Hana Kovac | `hana.kovac@contoso.com` | SecOps Manager / Approver | Sentinel Reader + Approver (change & response sign-off) |
| Omar Haddad | `omar.haddad@contoso.com` | Senior SOC Analyst / DRI | Microsoft Sentinel Responder |
| Wei Zhang | `wei.zhang@contoso.com` | SOC Analyst (Tier 1 triage) | Microsoft Sentinel Reader + Log Analytics Reader |
| Elena Petrova | `elena.petrova@contoso.com` | Security / Sentinel platform admin | Security Admin (platform config, not day-to-day triage) |
| Deployment identity | `svc-sentinel-deploy@contoso.com` | CI/CD automation (non-interactive) | Sentinel Contributor + Logic App Contributor, workspace-scoped |
| Break-glass account | `break-glass-01@contoso.com` | Emergency access only | Owner at workspace scope, **normally disabled** |

The Detection Engineering Lead (Raj) and the SecOps Manager (Hana) are
intentionally two different people so that authoring and approval never collapse
into one identity.

---

## 3. Who does what

### 3.1 Who deploys detection rules

- **Authoring** happens as code. Every analytics rule is a `*.kql` + `*.yaml`
  pair reviewed like any other change through the Azure DevOps pipeline
  (`.azure-pipelines/validate-detections.yml`): validate → test → package →
  approval-gated deploy.
- **The human who merges is not the identity that deploys.** A detection engineer
  (Ravi Menon, `ravi.menon@contoso.com`) authors and code-reviews the rule; the
  **deployment identity** (`svc-sentinel-deploy@contoso.com`) is the only
  principal that writes analytics rules into the workspace, and only from the
  pipeline's approval-gated `Deploy` stage.
- Raj holds **Microsoft Sentinel Contributor** scoped to the lab workspace so he
  can hotfix or roll back a rule in an incident — but routine changes still go
  through the pipeline, and that standing Contributor assignment is a review
  item every quarter (candidate for PIM-eligible instead of permanent).
- Nobody deploys a detection with interactive Owner or Contributor at
  subscription scope. The deployment identity's write ability is bounded to the
  workspace and its playbooks, nothing else.

### 3.2 Who approves playbooks

Two distinct approvals, and neither is the author:

1. **Change approval** — before a new or modified playbook (Logic App) ships, the
   **SecOps Manager (Hana Kovac, `hana.kovac@contoso.com`)** approves the
   pipeline's manual approval gate. This is a governance sign-off on *what the
   automation is allowed to do*.
2. **Run-time approval** — when a *destructive* playbook is triggered by an
   incident (disable user, require password reset, remove role, rotate SP
   credential), it pauses for a named approver. Per the SOAR design, that
   approver is the on-call **DRI/Responder** for reversibility-checked actions,
   escalating to the **SecOps Manager** for anything that can lock out a human or
   touches a Tier-0 asset.

Session revocation at Critical severity is the one action that runs unattended —
it is reversible and high-confidence — but the RBAC still requires the triggering
principal to hold the Responder role.

### 3.3 Who runs response actions

- The **DRI/Responder (Omar Haddad, `omar.haddad@contoso.com`)** holds
  **Microsoft Sentinel Responder**, which allows incident management (assign,
  change status, add comments) and running playbooks — but **not** authoring or
  editing analytics rules.
- Responders can *trigger* containment playbooks; the destructive ones still
  hit the run-time approval gate above. This means "can run a response" and "can
  approve an irreversible response" are separated even within the response team.
- Tier 1 analysts (Wei Zhang) are **Readers**: they triage, comment and escalate,
  but cannot run response actions or change incident ownership on their own.

### 3.4 Who reads logs

- **Log Analytics Reader** on the workspace grants read access to the underlying
  tables (`SigninLogs`, `AuditLogs`, custom `CyberArk_EPV_CL`, etc.) for hunting
  and investigation.
- **Microsoft Sentinel Reader** grants read of incidents, analytics rules,
  workbooks and hunting queries.
- Analysts get both; the deployment identity gets neither beyond what it needs to
  write rules; the break-glass account is not used for routine reading.
- **Security Reader** (Azure AD/Entra level) is granted separately and only where
  someone genuinely needs cross-service security posture read (e.g. reviewing
  Conditional Access state during a DET-003 investigation) — it is not handed out
  as a default.

---

## 4. Separation of duties (the SoD matrix)

The controlling rule: **no single persona holds two of {Deploy, Approve,
Break-glass} for the same estate.**

| Duty | Held by | Explicitly *not* also held by |
|------|---------|-------------------------------|
| Author & code-review detections | Ravi Menon (Detection Eng Lead) | — |
| Deploy detections to workspace | `svc-sentinel-deploy` (automation, gated) | any interactive analyst |
| Approve playbook *changes* | Hana Kovac (SecOps Manager) | the playbook's author |
| Approve destructive *runs* | DRI/Responder → SecOps Manager for Tier-0 | the analyst who raised the incident |
| Run response playbooks | Omar Haddad (Responder) | Tier 1 Readers |
| Read incidents & logs | all analysts | — (read is the floor, not a privilege) |
| Platform / connector config | Elena Petrova (Security Admin) | detection authors, analysts |
| Emergency full access | `break-glass-01` (normally disabled) | everyone, day-to-day |

Two concrete SoD guarantees this produces:

- The engineer who writes DET-005 (privileged-role-addition detection) cannot
  quietly ship it to production alone — the deployment identity and an approval
  gate stand between the merge and the workspace.
- The analyst who raises an incident cannot self-approve the *disable-user*
  playbook against the suspected identity — approval routes to a different person
  (DRI, then SecOps Manager for Tier-0).

---

## 5. Emergency break-glass access

Real operations sometimes need to bypass the normal path — the automation
identity is broken, the approver is unreachable, and a Critical incident is live.
That is what break-glass is for, and it is designed to be *painful to use and
impossible to hide*.

- **Account:** `break-glass-01@contoso.com` — a dedicated, named-for-purpose
  emergency account, **not** a person's day-to-day identity.
- **State:** normally **disabled**. It is enabled only for the duration of a
  declared emergency and disabled again immediately after.
- **Credentials:** a long, randomly generated password stored offline in a sealed
  secret (a physical or vaulted split-knowledge secret), *not* in the repo, not
  in a password manager shared with the team. This lab contains **no
  credentials of any kind** — the account is described, never provisioned here.
- **Access:** Owner at **workspace scope only** (all-zero GUID placeholder in the
  sample assignments) — never subscription or tenant Owner. Break-glass buys you
  full control of the *detection estate*, not the cloud.
- **MFA / exclusions:** excluded from Conditional Access policies that could lock
  it out during an outage (the classic break-glass exclusion), but that exclusion
  is itself a monitored, reviewed control — DET-003 (Conditional Access policy
  modified) would fire if someone tampered with it.
- **Alerting:** any *enable* or *sign-in* of the break-glass account raises a
  Critical alert to the SecOps Manager and platform admin immediately. Using it
  is a paging event, by design.
- **Post-use:** every break-glass use triggers a mandatory blameless RCA within
  five business days (per the DRI runbook), a credential rotation, and a
  re-disable. "Why did the normal path fail?" is the first RCA question.

Break-glass is the *only* place Owner-level access exists in this model, it is
held by no human by default, and it cannot be used silently.

---

## 6. Periodic access reviews

Standing access decays into risk if nobody re-justifies it. The cadence:

| Review | Frequency | Owner | What it checks |
|--------|-----------|-------|----------------|
| Privileged access review | Quarterly | SecOps Manager (Hana) | Every assignment above Reader still has a live business justification and an owner; stale grants removed |
| Break-glass attestation | Quarterly | Security Admin (Elena) | Account still disabled, credential unbroken/rotated on schedule, exclusions still correct, no un-RCA'd uses |
| Automation identity review | Quarterly | Detection Eng Lead (Raj) | `svc-sentinel-deploy` scope is still workspace-bound; no scope creep; credentials rotated; least role still sufficient |
| Joiner/mover/leaver | On event | Line manager + SecOps Manager | Access granted on join, re-scoped on role change, **fully revoked on leave** — same day |
| Full recertification | Annually | SecOps Manager + Security Admin | End-to-end attestation of the entire matrix against the SoD rules in §4 |

Each review is driven by the checklist in
[LEAST_PRIVILEGE_REVIEW_CHECKLIST.md](LEAST_PRIVILEGE_REVIEW_CHECKLIST.md) and
recorded against the `review_due` dates in
[sample-rbac-assignments.json](sample-rbac-assignments.json). An assignment past
its `review_due` with no attestation is treated as an exception and removed until
re-justified — the default answer to "should this access still exist?" is *no*
unless someone actively says yes.

Reviews feed the same continuous-improvement loop as detection tuning: the
weekly operations review surfaces expiring access alongside expiring detection
exceptions, so access hygiene is not a once-a-quarter fire drill but a standing
line item.

---

## 7. How I would describe this honestly

> "The lab is offline-first, so there is no live RBAC to show. What I documented
> instead is the access model I would propose before any of these detections went
> near a real workspace: least-privilege built-in roles, separation between the
> engineer who ships a detection and the manager who approves the response it
> triggers, a disabled break-glass account that cannot be used silently, and
> quarterly access reviews with hard expiry dates. It draws the same lab-vs-
> production line as the rest of the project — it shows how I think about who
> should hold which key, not a claim that I run this in production."
