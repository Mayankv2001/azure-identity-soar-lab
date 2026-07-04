# Maintenance operating model

Lab-safe, synthetic. How the detection estate, playbooks, connectors, and cost
controls would be kept healthy over time. Personas are fictional (`@contoso.com`).
Nothing here is a running cadence yet - it is the documented model, scored under
**Maintenance / ownership** in the
[production readiness scorecard](../reports/PRODUCTION_READINESS_SCORECARD.md).

## Detection owner model

Every detection has a single accountable owner. Owners are engineers, not a
generic team inbox - so there is always someone to ask "is this rule still
earning its alerts?". See [RULE_OWNER_REGISTER.md](RULE_OWNER_REGISTER.md).

| Detection group | Owner (persona) |
|-----------------|-----------------|
| Identity detections (DET-001..007) | ravi.menon@contoso.com (Detection Engineering) |
| Control-plane detections (CP-DET-001..008) | amara.okafor@contoso.com (SecOps Lead) |
| Connectors / ingestion | priya.sharma@contoso.com (Cloud Platform) |
| Playbooks / automation | amara.okafor@contoso.com |

## Review cadence

| Activity | Frequency | Artefact |
|----------|-----------|----------|
| False-positive review | Monthly | [MONTHLY_DETECTION_REVIEW.md](MONTHLY_DETECTION_REVIEW.md) |
| MITRE coverage review | Quarterly | [QUARTERLY_CONTROL_REVIEW.md](QUARTERLY_CONTROL_REVIEW.md) |
| Rule versioning check | Per change | detection-as-code pipeline |
| Rule deprecation | As needed | [DEPRECATION_PROCESS.md](DEPRECATION_PROCESS.md) |
| Dependency review | Quarterly | connector + watchlist dependencies |
| Connector health review | Weekly | [../connectors/CONNECTOR_HEALTH_DASHBOARD_SPEC.md](../connectors/CONNECTOR_HEALTH_DASHBOARD_SPEC.md) |
| Playbook credential review | Quarterly | [../playbook-validation/AUTOMATION_SAFETY_CHECKLIST.md](../playbook-validation/AUTOMATION_SAFETY_CHECKLIST.md) |
| Cost review | Monthly | [../cost-management/SENTINEL_COST_MODEL.md](../cost-management/SENTINEL_COST_MODEL.md) |
| Documentation review | Quarterly | this layer |

## What each review protects

- **Monthly FP review** keeps the signal clean - noise spent is attention the
  real incident will need.
- **Quarterly MITRE review** keeps coverage honest - gaps become the next
  detections to build (see the security-engineering coverage tables).
- **Connector health review** keeps detections from going *blind* - a rule over a
  dead connector is worse than no rule, because it implies coverage that is not
  there.
- **Playbook credential review** keeps automation from becoming an attack surface
  - stale or over-scoped automation identities are removed.
- **Cost review** keeps ingestion within budget so the platform stays affordable.

## Versioning and dependencies

- Every rule carries a semantic version; changes ship through the
  detection-as-code pipeline with a version bump and a test update.
- Dependencies (a rule depends on a watchlist, a connector, a custom table) are
  tracked so that retiring a source triggers a review of the rules that use it.

## The through-line

Maintenance is what separates a detection *project* from a detection *estate*:
owned, reviewed on a cadence, versioned, and retired deliberately. This model
documents that discipline; operating it on real telemetry is the gap that a real
tenant and a real team would close.
