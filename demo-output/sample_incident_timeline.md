# Correlation timeline - how twelve alerts became eight incidents

The single best artefact to walk through in an interview: every alert in
chronological order, which incident it correlated into, and why it matters.
All data is synthetic (generator seed 42, simulation clock 2026-07-01T00:00Z).

| Time (UTC) | Detection | Incident | Entity | Severity | Alert summary | Why it matters | Recommended next action |
|------------|-----------|----------|--------|----------|---------------|----------------|--------------------------|
| 2026-06-28T00:05:00Z | DET-002 | INC-1001 | daniel.wright@contoso.com | High | Impossible Travel Sign-in (2 events) | Either token/session abuse from attacker infrastructure or VPN egress - attribution decides. | Attribute the second IP (VPN? proxy?); revoke sessions if unexplained. |
| 2026-06-28T16:05:00Z | DET-006 | INC-1002 | mark.taylor@contoso.com | Critical | Anomalous CyberArk Privileged Credential Checkout (5 events) | Ticketless bulk checkout of Tier-0 credentials is how harvesting looks in a PAM system. | Force check-in, rotate credentials, pull PSM session recordings. |
| 2026-06-29T05:22:28Z | DET-002 | INC-1003 | amelia.chen@contoso.com | Critical | Impossible Travel Sign-in (2 events) | Either token/session abuse from attacker infrastructure or VPN egress - attribution decides. | Attribute the second IP (VPN? proxy?); revoke sessions if unexplained. |
| 2026-06-29T11:15:00Z | DET-001 | INC-1003 | amelia.chen@contoso.com | Critical | MFA Fatigue (Push Bombing) (8 events) | A valid password is already in attacker hands; the approval is the takeover moment. | Revoke sessions, reset credentials, re-register MFA (PB-04/PB-05). |
| 2026-06-29T11:31:40Z | DET-002 | INC-1003 | amelia.chen@contoso.com | Critical | Impossible Travel Sign-in (2 events) | Either token/session abuse from attacker infrastructure or VPN egress - attribution decides. | Attribute the second IP (VPN? proxy?); revoke sessions if unexplained. |
| 2026-06-29T13:05:00Z | DET-004 | INC-1004 | jordan.lee@contoso.com -> sp-automation-graph | Critical | New Credential Added to Service Principal (1 event) | Service principal persistence survives password resets and MFA - quiet, durable access. | Remove the added credential; audit the service principal's sign-ins. |
| 2026-06-29T13:20:00Z | DET-005 | INC-1004 | jordan.lee@contoso.com | Critical | Account Added to Privileged Role or Group (1 event) | Self-elevation to Global Administrator is near-certain account takeover, not admin error. | Remove the membership; suspend the actor pending investigation (PB-06). |
| 2026-06-29T13:35:00Z | DET-003 | INC-1004 | jordan.lee@contoso.com | Critical | Conditional Access Policy Modified or Deleted (1 event) | The authentication control plane itself was weakened - classic post-takeover defence evasion. | Revert the policy; treat the actor account as compromised. |
| 2026-06-29T23:40:00Z | DET-002 | INC-1005 | sofia.russo@contoso.com | Medium | Impossible Travel Sign-in (2 events) | Either token/session abuse from attacker infrastructure or VPN egress - attribution decides. | Attribute the second IP (VPN? proxy?); revoke sessions if unexplained. |
| 2026-07-01T00:00:00Z | DET-007 | INC-1007 | old.admin@contoso.com | Medium | Stale or Orphaned Privileged Account (1 event) | Dormant privileged accounts are standing attack surface nobody would miss being used. | Confirm ownership, then disable or convert to PIM-eligible with expiry. |
| 2026-07-01T00:00:00Z | DET-007 | INC-1006 | karen.mills@contoso.com | Medium | Stale or Orphaned Privileged Account (1 event) | Dormant privileged accounts are standing attack surface nobody would miss being used. | Confirm ownership, then disable or convert to PIM-eligible with expiry. |
| 2026-07-01T00:00:00Z | DET-007 | INC-1008 | svc-backup-legacy@contoso.com | High | Stale or Orphaned Privileged Account (1 event) | Dormant privileged accounts are standing attack surface nobody would miss being used. | Confirm ownership, then disable or convert to PIM-eligible with expiry. |

## Correlation spotlight: the two multi-stage incidents

### INC-1003: MFA fatigue plus impossible travel against one victim

Severity **Critical** - Correlated identity attack (3 detections) - amelia.chen@contoso.com

- `2026-06-29T05:22:28Z` **AL-002-0002** Impossible Travel Sign-in (Critical) - privileged identity involved (+1); activity outside business hours (+1); high-risk sign-in in evidence (+1)
- `2026-06-29T11:15:00Z` **AL-001-0001** MFA Fatigue (Push Bombing) (Critical) - privileged identity involved (+1); activity outside business hours (+1); high-risk sign-in in evidence (+1); detection escalation: user approved MFA immediately after the prompt burst (+1)
- `2026-06-29T11:31:40Z` **AL-002-0003** Impossible Travel Sign-in (Critical) - privileged identity involved (+1); activity outside business hours (+1); high-risk sign-in in evidence (+1)

Correlation rule: alerts for the same user within a 60-minute window merge into one incident, so the analyst works 3 signals as a single investigation instead of 3 separate pages.

### INC-1004: Persistence, privilege escalation and defence evasion by one compromised actor

Severity **Critical** - Correlated identity attack (3 detections) - jordan.lee@contoso.com

- `2026-06-29T13:05:00Z` **AL-004-0001** New Credential Added to Service Principal (Critical) - privileged identity involved (+1); activity outside business hours (+1); detection escalation: target service principal is classified high-privilege (+1)
- `2026-06-29T13:20:00Z` **AL-005-0001** Account Added to Privileged Role or Group (Critical) - privileged identity involved (+1); activity outside business hours (+1); detection escalation: actor granted the privilege to their own account (+1)
- `2026-06-29T13:35:00Z` **AL-003-0001** Conditional Access Policy Modified or Deleted (Critical) - privileged identity involved (+1); activity outside business hours (+1); detection escalation: actor holds no Conditional Access management role (+1)

Correlation rule: alerts for the same user within a 60-minute window merge into one incident, so the analyst works 3 signals as a single investigation instead of 3 separate pages.
