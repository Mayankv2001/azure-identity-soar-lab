# Quarterly control review

Lab-safe, synthetic. Agenda and checklist for the quarterly review of the whole
control estate - detections, coverage, connectors, automation, RBAC, and cost.
Owned by the SecOps Lead (amara.okafor@contoso.com).

## Purpose

The monthly review keeps detections clean; the quarterly review keeps the
*strategy* honest - are we covering the threats that matter, at a cost we can
sustain, with access that stays least-privilege?

## Agenda (90 minutes)

1. **MITRE ATT&CK coverage (25 min)** - review the coverage matrix across both
   labs. Which tactics/techniques fire nowhere? Prioritise the top gaps
   (token theft, exfiltration, post-exposure behaviour) as next-quarter work.
2. **Detection portfolio health (15 min)** - promotion-state distribution, rule
   age, deprecations, and whether any rule has drifted from its intent.
3. **Connector and telemetry review (15 min)** - ingestion completeness, schema
   drift, new sources needed
   ([../telemetry/LOG_SOURCE_COVERAGE_MATRIX.md](../telemetry/LOG_SOURCE_COVERAGE_MATRIX.md)).
4. **Automation and playbook review (10 min)** - playbook credential hygiene,
   automation-level correctness, any near-misses
   ([../playbook-validation/AUTOMATION_SAFETY_CHECKLIST.md](../playbook-validation/AUTOMATION_SAFETY_CHECKLIST.md)).
5. **RBAC / access review (15 min)** - least-privilege review, stale assignments,
   break-glass usage
   ([../rbac/LEAST_PRIVILEGE_REVIEW_CHECKLIST.md](../rbac/LEAST_PRIVILEGE_REVIEW_CHECKLIST.md)).
6. **Cost governance (10 min)** - ingestion vs budget, noisy tables, retention
   ([../cost-management/SENTINEL_COST_MODEL.md](../cost-management/SENTINEL_COST_MODEL.md)).

## Checklist

- [ ] MITRE coverage matrix refreshed; top gaps have owners and target quarter
- [ ] Deprecated rules removed with tests; no orphaned dependencies
- [ ] Telemetry gaps identified; new connectors proposed with cost impact
- [ ] Playbook automation identities reviewed; stale/over-scoped ones removed
- [ ] RBAC assignments reviewed against
      [../rbac/SENTINEL_RBAC_MATRIX.md](../rbac/SENTINEL_RBAC_MATRIX.md); break-glass
      usage audited
- [ ] Ingestion within budget; retention tiers still appropriate
- [ ] Production-readiness scorecard re-scored if capabilities changed

## Output

A quarterly control review report: coverage deltas, decisions, and a prioritised
backlog for the next quarter. This is where the
[gap-closure roadmap](../reports/GAP_CLOSURE_ROADMAP.md) gets updated.
