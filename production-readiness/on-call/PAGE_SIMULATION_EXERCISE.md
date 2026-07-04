# Page simulation exercise - CP-INC-2001

A tabletop walkthrough of a single page, using the synthetic control-plane
incident **CP-INC-2001** from the Datacenter Control Plane Attack Path Lab. All
people and data are fictional. This is a training exercise, not a record of a
real incident.

## The scenario (recap)

A compromised Cloud Operations identity (chris.walker@contoso.com) is walked from
a risky sign-in through MFA fatigue, a ticketless privileged-role activation, a
credential added to the high-privilege service principal sp-infra-deploy, an
Owner grant on the synthetic cloud-management resource group rg-prod-dc-mgmt, and
finally an NSG rule opening RDP to `0.0.0.0/0` on the reachable management jumpbox
vm-dc-mgmt-01. Eight detections correlate into one Critical incident with a
blast-radius score of 100/100.

## The page

```
[PAGE] P1 CP-INC-2001 - Identity-to-control-plane attack chain
Entity: chris.walker@contoso.com  |  Blast radius: 100/100
Detections: CP-DET-001..007 correlated (CP-DET-008)
Exposure: vm-dc-mgmt-01 RDP reachable from internet
```

## What a good first response looks like (minute by minute)

**00:00 - Acknowledge.** Primary DRI (lena.novak@contoso.com) acknowledges within
the 15-minute P1 SLA. Acknowledgement stops the escalation timer.

**00:02 - Read the enrichment, not the raw logs.** Open the PB-01/CP-PB-03
enrichment: is the identity privileged (yes), is a high-privilege SP in scope
(yes, sp-infra-deploy), is anything exposed (yes, RDP to the internet). The
blast-radius breakdown already says why this is 100/100.

**00:04 - Cheapest reversible containment first.** Session revocation for
chris.walker is automatic at Critical (CP-PB-04) - confirm it fired. No approval
needed; the user simply re-authenticates.

**00:06 - Declare and pull in help.** This is Tier-0 (rg-prod-dc-mgmt, a
management jumpbox), so escalate to the Incident Commander
(daniel.wright@contoso.com) and page network on-call
(felix.nguyen@contoso.com) for the NSG revert.

**00:10 - Approval-gated containment, least destructive first.** DRI/IC approve,
in order: revert the NSG rule (CP-PB-05, snapshot first), remove the
attacker-added SP credential and rotate (CP-PB-06), remove the Owner assignment
and deactivate the PIM role (CP-PB-07), JIT-lock/isolate the VM if any inbound
login is found (CP-PB-08), and disable the user if takeover is confirmed
(CP-PB-09).

**00:15 - First communication.** Communications owner (grace.kim@contoso.com)
posts the initial stakeholder note using
[../incident-response/COMMUNICATION_TEMPLATES.md](../incident-response/COMMUNICATION_TEMPLATES.md).

**00:20 - Verify eviction, don't assume it.** Confirm no new tokens for
chris.walker, no remaining SP credentials, no successful RDP login, and no
internet-wide management rule left on the NSG.

**Post-incident - RCA task.** Once contained, open the blameless RCA (CP-PB-10)
using [../incident-response/RCA_PROCESS.md](../incident-response/RCA_PROCESS.md).
The root cause is a failed control (no Azure Policy denying public management
exposure; push-approval MFA; standing SP privilege), not the person.

## Decision checkpoints exercised

| Checkpoint | Good answer |
|------------|-------------|
| Wake someone up? | Yes - P1, Tier-0, active exposure |
| Automate or approve the NSG revert? | Approve - network change, blast radius, snapshot first |
| Disable the user immediately? | Not first - revoke sessions (reversible) before disable (approval) |
| Who else? | IC + network on-call + identity platform |
| When is it over? | When eviction is *verified*, not when it goes quiet |

## Facilitator notes

Run this as a 20-minute tabletop. Score the responder on: acknowledged in SLA,
enriched before acting, took reversible containment first, escalated Tier-0
correctly, communicated on cadence, and verified eviction. The learning goal is
the *sequence and the guardrails*, not speed alone.
