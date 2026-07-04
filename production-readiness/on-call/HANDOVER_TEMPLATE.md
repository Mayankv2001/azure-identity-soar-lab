# Shift handover template

Lab-safe, synthetic. Copy this at the end of every on-call shift so the incoming
DRI starts warm. Follow-the-sun handover between the two notional regions in
[sample-oncall-schedule.json](sample-oncall-schedule.json).

---

## Handover: <date> <outgoing region> -> <incoming region>

**Outgoing DRI:** <persona@contoso.com>  |  **Incoming DRI:** <persona@contoso.com>

### 1. Open incidents

| Incident | Severity | Status | Owner | Next action | Waiting on |
|----------|----------|--------|-------|-------------|------------|
| INC-... | P... | investigating/contained | <persona> | ... | ... |

### 2. Approvals in flight

Any containment action queued for approval (revoke sessions, NSG revert, SP
credential rotation, role removal, VM isolation, disable user) - who needs to
approve, and by when.

### 3. Tuning changes in progress

Rules mid-promotion or with an open false-positive review (see
[../tuning/TUNING_BACKLOG_SAMPLE.md](../tuning/TUNING_BACKLOG_SAMPLE.md)). Note any
rule that is temporarily suppressed and why.

### 4. Noisy detections to watch

Detections generating above-baseline volume this shift, with the benign cause if
known. Flag anything that could mask a real incident.

### 5. Expiring exceptions / break-glass

Any tuning exclusion, RBAC exception, or break-glass access that expires soon
(see [../rbac/RBAC_REVIEW_MODEL.md](../rbac/RBAC_REVIEW_MODEL.md)).

### 6. Connector / ingestion health

Any data connector with delayed or missing ingestion (see
[../connectors/CONNECTOR_HEALTH_DASHBOARD_SPEC.md](../connectors/CONNECTOR_HEALTH_DASHBOARD_SPEC.md)).
A blind detection is worse than a noisy one.

### 7. Anything the next DRI must not be surprised by

Free text: scheduled changes, maintenance windows, planned pen-tests, known
degradations.

---

**Handover acknowledged by incoming DRI:** yes / no  |  **Time:** <utc>

A handover is not complete until the incoming DRI has acknowledged it. Open
threads must be owned, not left to evaporate between shifts.
