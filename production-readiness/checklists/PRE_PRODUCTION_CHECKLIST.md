# Pre-production checklist

Lab-safe, synthetic. A consolidated checklist, grouped by the ten
production-readiness dimensions, of what must be true before any detection from
this repo is enabled in a real tenant. Each item links to the artefact that
defines it. **This repo has not completed this checklist** - it is the map, not a
sign-off.

## 1. Telemetry readiness
- [ ] Real log sources connected and mapped to the required Sentinel tables
      ([../telemetry/SYNTHETIC_TO_REAL_TELEMETRY_MAPPING.md](../telemetry/SYNTHETIC_TO_REAL_TELEMETRY_MAPPING.md))
- [ ] Required fields validated present for every detection in scope
- [ ] Telemetry gaps assessed against detection quality

## 2. Connector readiness
- [ ] Connectors deployed and validated
      ([../connectors/CONNECTOR_VALIDATION_CHECKLIST.md](../connectors/CONNECTOR_VALIDATION_CHECKLIST.md))
- [ ] Ingestion freshness, volume, and latency within SLA
- [ ] Connector health dashboard live
      ([../connectors/CONNECTOR_HEALTH_DASHBOARD_SPEC.md](../connectors/CONNECTOR_HEALTH_DASHBOARD_SPEC.md))

## 3. Detection maturity
- [ ] Rule run in audit mode against real telemetry
- [ ] False positives reviewed and tuned
      ([../tuning/DETECTION_TUNING_PROCESS.md](../tuning/DETECTION_TUNING_PROCESS.md))
- [ ] Promotion gates passed
      ([../tuning/DETECTION_PROMOTION_GATES.md](../tuning/DETECTION_PROMOTION_GATES.md))
- [ ] Regression tests protect true positives

## 4. Incident response readiness
- [ ] IR operating model and severity model adopted
      ([../incident-response/INCIDENT_RESPONSE_OPERATING_MODEL.md](../incident-response/INCIDENT_RESPONSE_OPERATING_MODEL.md))
- [ ] RCA process and evidence checklist in place
      ([../incident-response/RCA_PROCESS.md](../incident-response/RCA_PROCESS.md))

## 5. Automation safety
- [ ] Playbooks lab-tested with correct automation levels
      ([../playbook-validation/PLAYBOOK_TEST_PLAN.md](../playbook-validation/PLAYBOOK_TEST_PLAN.md))
- [ ] Safety checklist passed for every destructive action
      ([../playbook-validation/AUTOMATION_SAFETY_CHECKLIST.md](../playbook-validation/AUTOMATION_SAFETY_CHECKLIST.md))
- [ ] No secrets in any workflow; playbooks ship disabled

## 6. Change control
- [ ] Change record raised with test evidence and rollback
      ([../change-approval/CHANGE_APPROVAL_MODEL.md](../change-approval/CHANGE_APPROVAL_MODEL.md))
- [ ] Approver(s) for the affected system signed off

## 7. RBAC / least privilege
- [ ] Least-privilege roles applied per the matrix
      ([../rbac/SENTINEL_RBAC_MATRIX.md](../rbac/SENTINEL_RBAC_MATRIX.md))
- [ ] Separation of duties enforced; break-glass audited

## 8. Cost governance
- [ ] Ingestion budget and alerts set
      ([../cost-management/INGESTION_BUDGET.md](../cost-management/INGESTION_BUDGET.md))
- [ ] Retention tiers applied
      ([../cost-management/RETENTION_POLICY.md](../cost-management/RETENTION_POLICY.md))

## 9. DRI / on-call model
- [ ] Rotation staffed and paging-integrated with SLAs
      ([../on-call/DRI_ROTATION_MODEL.md](../on-call/DRI_ROTATION_MODEL.md))
- [ ] Escalation matrix and handover in use
      ([../on-call/ESCALATION_MATRIX.md](../on-call/ESCALATION_MATRIX.md))

## 10. Maintenance / ownership
- [ ] Named owner registered for every rule
      ([../maintenance/RULE_OWNER_REGISTER.md](../maintenance/RULE_OWNER_REGISTER.md))
- [ ] Monthly/quarterly reviews scheduled and running
- [ ] Deprecation process available
      ([../maintenance/DEPRECATION_PROCESS.md](../maintenance/DEPRECATION_PROCESS.md))

When every box above is genuinely ticked against a real tenant, proceed to the
[go-live approval checklist](GO_LIVE_APPROVAL_CHECKLIST.md).
