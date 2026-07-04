# Escalation matrix

Lab-safe, synthetic. Who gets paged next when an incident is not acknowledged or
grows in scope. Personas are fictional (`@contoso.com`).

## Time-based escalation (unacknowledged)

| Severity | 0 min | +15 min | +30 min | +60 min |
|----------|-------|---------|---------|---------|
| P1 / Critical | Primary DRI | Secondary DRI | Incident Commander | SecOps Lead |
| P2 / High | Primary DRI | Secondary DRI | SecOps Lead | - |
| P3 / Medium | Channel notify | Primary DRI (business hours) | - | - |
| P4 / Low | Queue | Daily review | - | - |

Escalation is automatic on the clock - the person who did not acknowledge is not
blamed; the next responder simply picks it up. The escalation event itself is
logged on the incident timeline.

## Scope-based escalation (incident grows)

| Condition | Add / escalate to |
|-----------|-------------------|
| Second distinct detection correlates on the same entity | Incident Commander |
| Tier-0 asset in scope (Global Administrator, domain-admins safe, rg-prod-dc-mgmt, vm-dc-mgmt-01) | IC + SecOps Lead |
| Public internet exposure created (CP-DET-006/007) | Network on-call + IC |
| Confirmed account takeover | Identity platform owner + IC |
| Customer/business impact plausible | Communications owner + SecOps Lead |
| Suspected insider | SecOps Lead + HR/legal channel |

## Cross-team escalation contacts (fictional)

| Team | Persona | When |
|------|---------|------|
| Network engineering | felix.nguyen@contoso.com | NSG/firewall changes, exposure containment |
| Identity platform | (identity on-call) | Conditional Access, PIM, SP credentials |
| Cloud platform | priya.sharma@contoso.com | RBAC, resource groups, Azure Policy, workspace |
| Detection engineering | ravi.menon@contoso.com | Rule misfires, tuning, flooding |
| Incident Commander | daniel.wright@contoso.com | Any P1/P2 needing coordination |

## Decision rule (one line)

Escalate when the incident **outgrows the current owner** - either in time
(unacknowledged) or in blast radius (Tier-0, exposure, takeover). The matrix
above pre-decides those calls so nobody has to improvise at 03:00.
