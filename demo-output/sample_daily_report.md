# Daily security operations report

Reporting window: 2026-06-24 to 2026-06-30 (simulation clock 2026-07-01T00:00Z)

## Headline numbers

- Alerts raised: **12** (7 Critical, 2 High, 3 Medium)
- Incidents opened: **8**
- MTTD (mean time to acknowledge): **1.4 h**
- MTTR (mean time to resolve): **12.7 h**
- SLA adherence: **93.8%** (1 breach(es))
- Incident false-positive rate: **12.5%** (INC-1005)

## Alert volume by detection

| Detection | Name | Alerts | Base severity |
|-----------|------|--------|---------------|
| DET-001 | MFA Fatigue (Push Bombing) | 1 | High |
| DET-002 | Impossible Travel Sign-in | 4 | Medium |
| DET-003 | Conditional Access Policy Modified or Deleted | 1 | High |
| DET-004 | New Credential Added to Service Principal | 1 | High |
| DET-005 | Account Added to Privileged Role or Group | 1 | High |
| DET-006 | Anomalous CyberArk Privileged Credential Checkout | 1 | Medium |
| DET-007 | Stale or Orphaned Privileged Account | 3 | Low |

## Incidents

| Incident | Severity | Primary identity | Disposition | Ack | Resolve | SLA |
|----------|----------|------------------|-------------|-----|---------|-----|
| INC-1001 | High | daniel.wright@contoso.com | true positive | 19 min | 5.5 h | ack met, resolve met |
| INC-1002 | Critical | mark.taylor@contoso.com | true positive | 11 min | 2.6 h | ack met, resolve met |
| INC-1003 | Critical | amelia.chen@contoso.com | true positive | 7 min | 2.5 h | ack met, resolve met |
| INC-1004 | Critical | jordan.lee@contoso.com | true positive | 7 min | 2.2 h | ack met, resolve met |
| INC-1005 | Medium | sofia.russo@contoso.com | false positive | 4.4 h | 5.2 h | ack BREACH, resolve met |
| INC-1006 | Medium | karen.mills@contoso.com | posture finding | 2.9 h | 50.3 h | ack met, resolve met |
| INC-1007 | Medium | old.admin@contoso.com | posture finding | 2.6 h | 28.0 h | ack met, resolve met |
| INC-1008 | High | svc-backup-legacy@contoso.com | posture finding | 24 min | 5.6 h | ack met, resolve met |

### SLA breaches

- INC-1005: acknowledge took 4.4 h against a 4.0 h target (Medium)

## Tuning impact (rule v1.1.0 exclusions applied)

| Detection | Alerts before | Alerts after | Change |
|-----------|---------------|--------------|--------|
| DET-002 | 4 | 3 | -1 |

The DET-002 v1.1.0 exclusion (corporate VPN egress range 198.51.100.0/24) removes the benign impossible-travel alert while keeping both true positives - a false-positive reduction with no loss of detection coverage.

## MITRE ATT&CK coverage

| Tactic | DET-001 | DET-002 | DET-003 | DET-004 | DET-005 | DET-006 | DET-007 |
|--------|----|----|----|----|----|----|----|
| InitialAccess |  | X |  |  |  |  | X |
| CredentialAccess | X |  |  |  |  |  |  |
| PrivilegeEscalation |  |  |  | X | X | X |  |
| Persistence |  |  | X | X | X |  |  |
| DefenseEvasion |  | X | X |  |  |  |  |
| LateralMovement |  |  |  |  |  | X |  |

## Top risky identities

- amelia.chen@contoso.com (cumulative severity score 12)
- jordan.lee@contoso.com (cumulative severity score 12)
- mark.taylor@contoso.com (cumulative severity score 4)
- daniel.wright@contoso.com (cumulative severity score 3)
- svc-backup-legacy@contoso.com (cumulative severity score 3)

## Recommended actions

1. Promote the DET-002 VPN egress exclusion from proposal to production (v1.1.0).
2. Disable or lifecycle the three stale privileged accounts flagged by DET-007.
3. Enforce ticket validation on Tier-0 CyberArk safes (root cause of INC involving the domain-admins safe).
4. Require PIM-eligible assignment for Global Administrator (standing assignment enabled the DET-005 self-elevation).
5. Review acknowledgement staffing for Medium alerts - the single SLA breach was a false positive that sat in the queue.
