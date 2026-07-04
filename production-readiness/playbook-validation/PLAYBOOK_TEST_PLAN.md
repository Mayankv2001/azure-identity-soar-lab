# Playbook test plan

Lab-safe, synthetic. Test cases for each SOAR playbook, with the automation level
of the primary action marked. All testing is against synthetic/lab resources -
never real accounts, tenants, or networks.

Automation levels: **automatic** / **approval required** / **manual only**.

## Enrichment playbook (automation: automatic)

| Test | Input | Expected result |
|------|-------|-----------------|
| E1 | Incident with account + IP entities | Identity privilege, PIM eligibility, asset criticality, exposure attached; blast-radius computed |
| E2 | Incident with a service principal entity | SP privilege tier and owner attached |
| E3 | Read-only guarantee | No state change to any asset; only comments/tags written |

## Notification playbook (automation: automatic)

| Test | Input | Expected result |
|------|-------|-----------------|
| N1 | P1 incident created | Adaptive card to SOC channel + page to primary DRI |
| N2 | P3 incident | Channel notification only, no page |
| N3 | No secrets in payload | Notification contains no credentials or tokens |

## Session revocation playbook (automation: automatic at Critical, else approval required)

| Test | Input | Expected result |
|------|-------|-----------------|
| S1 | Critical identity-compromise incident | Sessions/refresh tokens revoked unattended; action logged |
| S2 | High (non-critical) incident | Approval card issued; no revocation until approved |
| S3 | Reversibility | Legitimate user can re-authenticate with MFA; no lasting lockout |

## Credential rotation playbook (automation: approval required)

| Test | Input | Expected result |
|------|-------|-----------------|
| C1 | SP credential-added incident (DET-004/CP-DET-004) | Approval gate to app owner; attacker credential removed on approval |
| C2 | Service-account guard | Rotation on a service account routes to owner, does not run blind |
| C3 | Snapshot | Prior credential metadata captured before removal for audit/rollback |

## NSG rollback playbook (automation: approval required)

| Test | Input | Expected result |
|------|-------|-----------------|
| R1 | Public NSG rule (CP-DET-006/007) | Snapshot current rule; approval gate to network on-call; revert on approval |
| R2 | Legitimate public endpoint | If tagged/approved, no auto-revert; flagged for human review |
| R3 | Rollback | Snapshotted rule can be re-applied if the change was legitimate |

## VM isolation playbook (automation: approval required)

| Test | Input | Expected result |
|------|-------|-----------------|
| V1 | Exposed VM with inbound attempt (CP-DET-007) | Approval gate to workload owner; JIT-lock/isolate on approval |
| V2 | No inbound activity | Prefer JIT/Bastion restriction over full isolation |
| V3 | Restore | Normal network config restored once the VM is confirmed clean |

## Exit criteria

A playbook is test-passed only when: every action behaves at its declared
automation level, every destructive action snapshots and gates, no secrets appear
in any payload or log, and rollback is demonstrated. Results are recorded in
[sample-playbook-test-results.json](sample-playbook-test-results.json).
