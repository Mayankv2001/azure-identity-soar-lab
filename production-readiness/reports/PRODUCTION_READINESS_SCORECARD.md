# Production readiness scorecard

An honest self-assessment of this project against ten production-readiness
dimensions. Machine-readable source:
[production-readiness-scorecard.json](production-readiness-scorecard.json).

**Overall: 55 / 100 — Production candidate.** The project is strong on
documentation, detection-as-code, and lab design, and it deploys a real (lab)
Sentinel workspace with a disabled analytics rule. It is **not production-ready**:
there is no real enterprise telemetry, no rules tuned against real environment
noise, and no operating cadence running yet. This scorecard is deliberate about
that line - a security engineer should be able to state the limits of their own
system.

## Bands

| Score | Band |
|-------|------|
| 0-25 | Not started |
| 26-50 | Lab-defined |
| 51-75 | Production candidate |
| 76-100 | Production-ready after tenant validation |

No dimension is scored in the top band, because reaching it requires validation
against a real tenant's telemetry, cost, and operations.

## Scores

| # | Dimension | Score | Band | Evidence |
|---|-----------|-------|------|----------|
| 1 | Telemetry readiness | 55 | Production candidate | [telemetry/](../telemetry/) |
| 2 | Connector readiness | 45 | Lab-defined | [connectors/](../connectors/) |
| 3 | Detection maturity | 65 | Production candidate | [tuning/](../tuning/) |
| 4 | Incident response readiness | 60 | Production candidate | [incident-response/](../incident-response/) |
| 5 | Automation safety | 70 | Production candidate | [playbook-validation/](../playbook-validation/) |
| 6 | Change control | 55 | Production candidate | [change-approval/](../change-approval/) |
| 7 | RBAC / least privilege | 50 | Lab-defined | [rbac/](../rbac/) |
| 8 | Cost governance | 45 | Lab-defined | [cost-management/](../cost-management/) |
| 9 | DRI / on-call model | 55 | Production candidate | [on-call/](../on-call/) |
| 10 | Maintenance / ownership | 50 | Lab-defined | [maintenance/](../maintenance/) |
| | **Overall (mean)** | **55.0** | **Production candidate** | this layer |

## Per-dimension detail

### 1. Telemetry readiness — 55 (Production candidate)
- **Reason:** synthetic-to-real mappings, required-field analysis, and an
  ingestion inventory exist for all eight source types; no real ingestion yet.
- **Gap to close:** connect real sources, validate schemas/fields against live
  volume.

### 2. Connector readiness — 45 (Lab-defined)
- **Reason:** connector runbooks, validation checklist, and a health-dashboard
  spec are documented; no connectors are live.
- **Gap to close:** deploy and validate connectors; measure freshness/latency.

### 3. Detection maturity — 65 (Production candidate)
- **Reason:** 15 detections as code with MITRE mapping and a quality scorecard
  (avg 91.8/100 metadata); none tuned against real noise; all at Draft/Simulated.
- **Gap to close:** run in audit mode on real telemetry; tune; advance promotion
  states with evidence.

### 4. Incident response readiness — 60 (Production candidate)
- **Reason:** full IR operating model, severity model, comms templates, RCA
  process, and lifecycle states, exercised via the CP-INC-2001 tabletop.
- **Gap to close:** run real incidents; measure MTTD/MTTR; refine from PIRs.

### 5. Automation safety — 70 (Production candidate)
- **Reason:** strong automate-vs-approve guardrails, approval process, test plan,
  and safety checklist; the one live Logic App is disabled with no secrets.
- **Gap to close:** build/lab-test real Logic Apps with approval gates; approve
  before enabling.

### 6. Change control — 55 (Production candidate)
- **Reason:** change-approval model, risk matrix, sample record, rollback
  template; detection-as-code pipeline enforces review/test.
- **Gap to close:** operate change control on real changes with real approvers.

### 7. RBAC / least privilege — 50 (Lab-defined)
- **Reason:** least-privilege matrix, review model, checklist, and fictional
  sample assignments; no real assignments or access reviews.
- **Gap to close:** apply least-privilege roles; enforce separation of duties;
  run access reviews and audit break-glass.

### 8. Cost governance — 45 (Lab-defined)
- **Reason:** cost model, ingestion budget, retention policy, and monitoring
  queries with illustrative numbers; no real ingestion to govern.
- **Gap to close:** measure real ingestion; set budgets/alerts; apply retention;
  run cost reviews.

### 9. DRI / on-call model — 55 (Production candidate)
- **Reason:** rotation model, escalation matrix, handover template, and a
  CP-INC-2001 page simulation; rota not staffed or paging-integrated.
- **Gap to close:** staff the rotation; integrate paging; run real on-call and
  recurring simulations.

### 10. Maintenance / ownership — 50 (Lab-defined)
- **Reason:** owner register, monthly/quarterly cadences, and a deprecation
  process; the cadence is not yet running on real data.
- **Gap to close:** run the reviews; keep the register live; operate
  versioning/deprecation on real rules.

## What this scorecard is honest about

The project scores strongly where the work is *thinking and engineering*
(detection maturity, automation safety, IR readiness) and lower where the work
requires a *real environment* (connectors, cost, RBAC operating on real
identities). That pattern is the truth: I can demonstrate how production would
work; I have not operated it at enterprise scale. Closing the gap is the subject
of the [gap-closure roadmap](GAP_CLOSURE_ROADMAP.md).
