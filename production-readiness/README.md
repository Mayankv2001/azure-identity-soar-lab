# Production Readiness & Operations Layer

This layer answers a fair and pointed question a hiring manager should ask of any
security portfolio project:

> *"This runs beautifully as a lab. What would it actually take to run in
> production - and does the author know the difference?"*

Everything above this folder demonstrates detection engineering, correlation,
SOAR design, responsible AI and SecOps metrics on **synthetic, offline data**.
That work is deliberately clean: a fixed seed, deterministic telemetry, no
tenant, no billing, no on-call pager going off at 02:00. Production is none of
those things. This layer exists to make the gap between the two **explicit,
honest and reviewable** rather than glossed over.

## What makes a Sentinel lab different from production

A lab and a production Microsoft Sentinel deployment share the same *concepts* -
analytics rules, incidents, playbooks, KQL, watchlists - but almost none of the
same *operational reality*. The differences are not cosmetic; they are where most
real security programmes succeed or fail.

| Dimension | This lab | Real production Sentinel |
|-----------|----------|--------------------------|
| Telemetry | Synthetic, seed 42, 7 days, shaped for clarity | Real, noisy, high-volume, adversarial, never-stops |
| Data arrival | A committed JSON file | Live data connectors that break, lag, and change schema |
| Detections | Fire cleanly against fixtures | Need baselining, tuning and false-positive review per tenant |
| Incidents | 8 deterministic, well-behaved | Unbounded, ambiguous, overlapping, sometimes wrong |
| Response | Playbooks documented and mocked | Playbooks that *actually* revoke sessions and disable accounts |
| People | One author | A rota, a DRI, an escalation chain, a change board |
| Money | Free (runs on a laptop) | Log Analytics ingestion and retention are billable and can surprise you |
| Failure | A red test | A missed breach, a locked-out executive, a blown budget |

The lab proves the **engineering thinking**. Production demands an **operations
discipline** on top of it: cost control, RBAC review, change approval, on-call
ownership, playbook sign-off and continuous tuning. This folder documents that
discipline as a set of lab-safe artefacts, so the maturity is visible without
ever pretending the lab has been productionised.

## Why this layer exists

Three reasons, in order of importance:

1. **Honesty.** The whole repository draws a hard line between production
   experience and lab demonstration. A "production readiness" section that
   *claimed* production readiness would break that line. Instead, this layer
   catalogues exactly what is missing and what a real deployment would require -
   which is itself the useful, senior signal.
2. **Completeness of thinking.** Good detection engineering that ignores cost,
   RBAC, change control and on-call is not production-grade, no matter how good
   the KQL is. This layer shows the whole picture, not just the fun part.
3. **A safe rehearsal.** Every operational process here - the change ticket, the
   RBAC review, the tuning workflow, the cost model, the incident-response
   runbook - is written as a *template you could pick up and use in a real
   tenant*, with fictional data standing in for the real thing.

## How each production gap is represented safely

Every gap below is represented by a **real, committed artefact** in this
repository - a template, a checklist, a worked example or a model - never by a
live connection to any real system. Nothing here is wired to a tenant, a
subscription, a billing account or a pager. The middle column of the table below
links to the actual file that stands in for each production requirement.

| Production requirement | Lab-safe artifact in this repo | What real production would require |
|------------------------|--------------------------------|------------------------------------|
| **Real telemetry** | [telemetry/](telemetry/SYNTHETIC_TO_REAL_TELEMETRY_MAPPING.md) | Live Entra ID sign-in/audit and CyberArk data ingested into a real Log Analytics workspace, with volume, latency and schema drift all monitored - and thresholds re-baselined against that real, noisy data before any rule is trusted. |
| **Data connectors** | [connectors/](connectors/CONNECTOR_RUNBOOK.md) | Configured, authenticated and health-monitored connectors (Entra ID via the built-in connector, CyberArk via AMA or the Logs Ingestion API), with connector failure alerting and a documented owner for each feed. |
| **Incident response process** | [incident-response/](incident-response/INCIDENT_RESPONSE_OPERATING_MODEL.md) | A staffed IR process: triage SLAs, containment authority, comms tree, evidence handling, and post-incident review, exercised through real tabletop drills - not just a runbook that reads well. |
| **Detection tuning** | [tuning/](tuning/DETECTION_TUNING_PROCESS.md) | A continuous tuning loop fed by real analyst dispositions: versioned, tested exclusions reviewed against live false positives, with true-positive regression guarded on every change. |
| **Change approval** | [change-approval/](change-approval/CHANGE_APPROVAL_MODEL.md) | A real change-management gate: every rule, playbook and policy change raised as a ticket, peer-reviewed, risk-assessed, approved by an accountable owner, and reversible - with an audit trail. |
| **RBAC review** | [rbac/](rbac/RBAC_REVIEW_MODEL.md) | Least-privilege Azure RBAC over the workspace, Sentinel, playbooks and automation identities, reviewed on a schedule, with break-glass accounts and just-in-time (PIM) elevation for administrative roles. |
| **Cost monitoring** | [cost-management/](cost-management/SENTINEL_COST_MODEL.md) | Active monitoring of Log Analytics ingestion and retention spend, with budgets, alerts, commitment-tier decisions, and per-table cost attribution so a noisy connector cannot quietly blow the budget. |
| **DRI / on-call** | [on-call/](on-call/DRI_ROTATION_MODEL.md) | A real on-call rotation with paging, acknowledge/resolve SLAs, escalation paths, handover notes and a Directly Responsible Individual accountable for each live incident end-to-end. |
| **Playbook approval** | [playbook-validation/](playbook-validation/PLAYBOOK_APPROVAL_PROCESS.md) | Human sign-off on every destructive automation (disable user, revoke sessions, rotate credentials), gated by a blast-radius / reversibility / confidence review before a playbook is allowed to run unattended at any severity. |
| **Ongoing maintenance** | [maintenance/](maintenance/MAINTENANCE_OPERATING_MODEL.md) | Scheduled detection-estate maintenance: re-scoring rules, retiring dead detections, updating MITRE mappings, re-baselining after environment change, and owning the drift that a real tenant produces every week. |

## What is simulated versus what needs a real tenant

Being precise about this is the whole point of the layer.

**Simulated here (safe to read, run, fork and discuss):**

- All telemetry, identities, IP addresses and incidents - synthetic, fictional
  `@contoso.com` personas, documentation IP ranges, fixed seed.
- Every operational *process* - change tickets, RBAC reviews, tuning proposals,
  cost models and IR runbooks are realistic **templates and worked examples**,
  populated with lab data.
- The detection-as-code pipeline, which validates, tests and packages rules and
  documents (but does not perform) an approval-gated Sentinel deployment.

**Needs a real tenant to become real (documented, not done):**

- Actual data-connector configuration and live ingestion.
- Real Azure RBAC assignments, PIM eligibility and break-glass accounts.
- Real Azure Cost Management budgets, alerts and commitment tiers.
- Playbooks with live permissions that can actually change identity or network
  state.
- A staffed on-call rotation and a functioning change-approval board.

The optional, lab-only live path
([docs/LIVE_SENTINEL_DEPLOYMENT_PATH.md](../docs/LIVE_SENTINEL_DEPLOYMENT_PATH.md)
and [infra/sentinel/](../infra/sentinel/)) shows how the first steps of that
transition would be made **in a personal/test subscription only** - never an
employer tenant - with the sample rule shipped disabled by default.

## What must be reviewed before any production use

Before a single artefact in this repository is pointed at a real environment, a
security team would need to:

1. **Re-baseline every threshold** against that tenant's real telemetry - the
   lab thresholds are illustrative and would be noisy or blind in production.
2. **Review cost** - model ingestion and retention spend and set budgets and
   alerts *before* connecting high-volume sources.
3. **Review RBAC** - apply least privilege to the workspace, Sentinel,
   playbooks and automation identities, and gate admin roles behind PIM.
4. **Approve through change control** - every rule, playbook and policy change
   goes through the change-approval gate, peer-reviewed and reversible.
5. **Sign off playbooks** - no destructive automation runs unattended until its
   blast radius, reversibility and confidence have been reviewed and approved.
6. **Stand up on-call** - a real DRI rotation with paging and escalation must
   exist before detections are trusted to page a human.

## Sub-folders in this layer

- [telemetry/](telemetry/) - telemetry maturity model and synthetic-to-real source mappings with required fields per detection
- [connectors/](connectors/) - data-connector runbooks, validation checklist and a health-dashboard spec
- [incident-response/](incident-response/) - production IR process: SLAs, containment authority, comms and post-incident review
- [tuning/](tuning/) - continuous false-positive tuning loop: disposition-driven, versioned, tested exclusions
- [change-approval/](change-approval/) - change-management gate and ticket templates for rule, playbook and policy changes
- [rbac/](rbac/) - least-privilege RBAC model, PIM elevation and break-glass, with a periodic access-review checklist
- [cost-management/](cost-management/) - Log Analytics ingestion/retention cost model, budgets and alerting approach
- [on-call/](on-call/) - DRI rotation, escalation matrix, handover template and a CP-INC-2001 page simulation
- [playbook-validation/](playbook-validation/) - playbook approval process, test plan and automation safety checklist
- [maintenance/](maintenance/) - detection owner register, monthly/quarterly reviews and deprecation process
- [checklists/](checklists/) - consolidated pre-production and go-live approval checklists
- [reports/](reports/) - the [production readiness scorecard](reports/PRODUCTION_READINESS_SCORECARD.md) (55/100) and gap-closure roadmap

---

**Honest note.** Nothing in this folder is production-ready, and no real data is
used anywhere in it. Every process here is a template or worked example running
on synthetic, fictional data; every artefact makes the lab-versus-production
boundary explicit rather than hiding it. This layer demonstrates that the author
understands what production operations *require* - it does not claim to have
delivered them. Treat it as a readiness map, not a readiness certificate.
