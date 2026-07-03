# Root cause analysis - CP-INC-2001

Synthetic. Blameless RCA - focus on the controls that failed, not the person who
clicked. Written as a template a DRI would complete within five business days.

## Summary

A compromised Cloud Operations identity was walked from a phished login to an
internet-exposed datacenter management endpoint in under two hours. Eight
detections correlated into one Critical incident (blast radius 100/100).
Contained without confirmed data loss (synthetic).

## Timeline reference

See [TIMELINE.md](TIMELINE.md). First malicious event 09:00; correlated Critical
incident 10:40; sessions revoked 10:43; full containment ~11:20.

## Root causes (controls that failed)

1. **Phishing-vulnerable MFA.** Push-approval MFA allowed the fatigue attack to
   succeed. *Fix:* phishing-resistant methods (FIDO2/passkeys) and risk-based
   Conditional Access for Cloud Operations.
2. **Standing Contributor on the service principal.** sp-infra-deploy held broad
   standing rights, so one added secret unlocked control-plane changes.
   *Fix:* least-privilege scoping, managed identities, short-lived credentials.
3. **Ticketless PIM activation.** Application Administrator activated with no
   linked change record. *Fix:* require justification/ticket binding and
   approval on protected-role activation.
4. **No policy denying public management exposure.** The NSG rule opening RDP to
   0.0.0.0/0 was accepted at write time. *Fix:* Azure Policy denying internet-wide
   inbound on management ports (this is the earliest break point in the graph).

## RCA questions to work through

- Which single control, if present, would have broken the chain earliest?
  (Answer in this scenario: the deny-public-management-exposure policy.)
- Why did the chain run for 100 minutes before a Critical incident fired - should
  correlation escalate sooner when stage 4 chains with stage 1/2?
- Was the service principal's standing Contributor ever justified, or is it
  historical debt?
- How many other Cloud Operations identities have the same standing-privilege +
  push-MFA combination?
- Did any successful inbound login reach the exposed endpoint?

## Detection performance

- Seven of seven telemetry stages detected and correlated into one incident.
- Gap: no follow-on detection for the actual post-exposure RDP brute-force -
  add a behavioural rule on the management port.
- Gap: correlation severity should reach Critical at stage 4-5, not stage 7-8.

## Prevention recommendations (advisory - require approval to apply)

| Recommendation | Control type | Owner |
|----------------|--------------|-------|
| Deny public inbound on management ports | Azure Policy | Cloud Security |
| Phishing-resistant MFA for Cloud Operations | Conditional Access | Identity |
| Least-privilege + managed identity for sp-infra-deploy | RBAC / IaC | Cloud Engineering |
| Ticket-bound, approval-gated PIM activation | PIM config | Identity governance |
| Alert-volume canary on new public NSG rules | Detection tuning | Detection engineering |

## Action items

| # | Action | Owner | Due |
|---|--------|-------|-----|
| 1 | Deploy deny-public-management-exposure policy (Audit then Deny) | Cloud Security | 2 weeks |
| 2 | Migrate Cloud Operations to phishing-resistant MFA | Identity | 4 weeks |
| 3 | Re-scope sp-infra-deploy to least privilege | Cloud Engineering | 3 weeks |
| 4 | Add correlation-severity escalation at stage 4 | Detection engineering | 2 weeks |
| 5 | Access review of standing privilege across Cloud Operations | Identity governance | 4 weeks |

Each action feeds back into the labs as a versioned detection or policy change -
closing the loop from incident to control improvement.
