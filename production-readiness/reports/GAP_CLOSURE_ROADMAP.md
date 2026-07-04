# Gap-closure roadmap

How the project would move from **55 / 100 (Production candidate)** toward
production readiness. Honest split between what can be done now (in a lab) and
what genuinely requires a real enterprise tenant, real telemetry, and a real
team.

## What requires a real enterprise tenant (cannot be closed in this repo)

These gaps are not closeable with synthetic data by design - they are the honest
reason the project is not, and does not claim to be, production-ready:

- **Real telemetry and connectors** - detections tuned against real environment
  noise; ingestion health measured against live volume.
- **Rules tuned against real noise** - promotion states advanced with evidence
  from audit-mode runs on real data.
- **Real cost governance** - budgets, alerts, and retention set against actual
  ingestion volume.
- **Real RBAC** - least-privilege roles applied to real identities, separation of
  duties enforced, access reviews and break-glass audited.
- **Operating cadence** - the monthly/quarterly reviews, the staffed on-call
  rotation, and change control running with real approvers.

## What can be strengthened now (in the lab)

| Priority | Action | Closes / lifts |
|----------|--------|----------------|
| 1 | Wire more detections into the Mode C Bicep (currently only DET-001), still disabled | Detection maturity, Connector readiness |
| 2 | Add token-theft and post-exposure behavioural detections (top MITRE gaps) | Detection maturity |
| 3 | Build lab Logic Apps for the enrichment + notify playbooks (non-destructive) and lab-test them | Automation safety |
| 4 | Add a synthetic ingestion-cost simulation to the cost model | Cost governance |
| 5 | Run the CP-INC-2001 page simulation as a recorded tabletop | DRI / on-call, IR readiness |
| 6 | Expand regression tests as new detections/tuning land | Detection maturity, Maintenance |

## Sequenced closure (if this were a real programme)

**First 30 days** - connect a subset of real sources in audit mode; validate
schemas/fields; measure baseline ingestion and cost. Lifts Telemetry and
Connector readiness.

**Days 31-60** - run detections in audit mode against real telemetry; open a
tuning backlog from real false positives; apply least-privilege RBAC to the real
identities; stand up the health dashboard. Lifts Detection maturity, RBAC, and
Connector readiness.

**Days 61-90** - operate the change board and monthly review on real changes;
staff and paging-integrate the on-call rotation; run a real incident through the
IR model and measure MTTD/MTTR; set real cost budgets and alerts. Lifts IR
readiness, Change control, DRI/on-call, and Cost governance.

## The honest target

Even after all of the above, no dimension is claimed at "production-ready"
without a period of real operation and a formal go-live approval (see
[../checklists/GO_LIVE_APPROVAL_CHECKLIST.md](../checklists/GO_LIVE_APPROVAL_CHECKLIST.md)).
The roadmap raises the score by *operating* the controls this layer documents -
it does not shortcut the requirement for real telemetry, tuning, and time.
