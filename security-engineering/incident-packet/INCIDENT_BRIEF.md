# Incident brief - CP-INC-2001

> Synthetic incident from the Datacenter Control Plane Attack Path Lab. All
> identities, resources and events are fictional. This packet is written the way
> a real incident handover packet reads.

| Field | Value |
|-------|-------|
| Incident ID | CP-INC-2001 |
| Title | Identity-to-control-plane attack chain - chris.walker@contoso.com |
| Severity | Critical |
| Blast radius | 100 / 100 |
| Status | Contained (synthetic) |
| Detection | CP-DET-008 (correlated chain) over 7 stage detections |
| Window (UTC) | 2026-06-30 09:00 to 10:40 |

## What happened

A compromised Cloud Operations identity was used to walk from an initial
foothold all the way to an internet-exposed datacenter management endpoint, in
under two hours. Eight detections fired across Entra ID sign-in and audit logs,
Azure Activity, and NSG telemetry, plus a Microsoft Defender for Cloud signal.
Rather than eight disconnected alerts, the correlation engine linked them by
shared identity, service principal and resource scope into a single Critical
incident.

The chain:

1. **09:00** - high-risk sign-in for `chris.walker@contoso.com` from an unusual
   country (Latvia), succeeding.
2. **09:02-09:11** - five failed strong-auth prompts followed by an approval
   (MFA fatigue - the takeover moment).
3. **09:25** - Application Administrator activated via PIM with no change ticket.
4. **09:40** - a client secret added to the high-privilege service principal
   `sp-infra-deploy`.
5. **10:05** - `sp-infra-deploy` granted **Owner** on resource group
   `rg-prod-dc-mgmt`.
6. **10:20** - an NSG rule opened RDP (3389) to `0.0.0.0/0` on
   `nsg-prod-dc-mgmt`.
7. **10:20** - the management endpoint of `vm-dc-mgmt-01` (which has a public IP)
   became reachable from the internet.
8. **10:40** - Defender for Cloud flagged unusual inbound traffic to the
   management port.

## Why it matters

This is the identity-to-infrastructure attack path in miniature. Each step alone
is a medium-interest event a busy SOC might close. Together they are an attacker
converting one phished login into standing infrastructure access and an exposed
management plane on a **critical** datacenter host - the exact class of incident
where correlation, not triage volume, is the difference between catching it at
stage 2 and reading about it in a breach report.

## Immediate priorities for the receiving DRI

1. Confirm the account is contained (sessions revoked) and the NSG rule reverted.
2. Verify whether the exposed RDP endpoint received any successful inbound login.
3. Remove the attacker-added SP credential and the Owner assignment.
4. Preserve evidence before rotating (see ENTITY_SUMMARY and CONTAINMENT_PLAN).

Related documents in this packet: [TIMELINE](TIMELINE.md),
[ENTITY_SUMMARY](ENTITY_SUMMARY.md), [CONTAINMENT_PLAN](CONTAINMENT_PLAN.md),
[RCA_TEMPLATE](RCA_TEMPLATE.md), [EXECUTIVE_SUMMARY](EXECUTIVE_SUMMARY.md).
