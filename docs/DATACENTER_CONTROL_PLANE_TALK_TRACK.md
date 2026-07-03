# Datacenter Control Plane module - explainer

A plain-language explanation of the Datacenter Control Plane Attack Path module:
what it models, why it matters, and how it connects identity, cloud, networking
and automation. The single best artefact to open alongside this is
[modules/datacenter-control-plane/demo-output/control_plane_timeline.md](../modules/datacenter-control-plane/demo-output/control_plane_timeline.md).

## In one paragraph

The parent lab stops at the identity plane. This module follows the attacker
across the bridge into Azure infrastructure. It replays one chain: a risky
sign-in from an unusual country, MFA fatigue until the user approves, a
ticketless privileged-role activation, a credential added to a high-privilege
service principal, that principal granted Owner on a synthetic cloud-management
resource group, and finally an NSG rule opening RDP to the whole internet on a
reachable management jumpbox. Eight detections fire across Entra ID, Azure
Activity and Defender-style telemetry - and instead of eight disconnected
alerts, a correlation engine links them by identity, service principal and
resource scope into one Critical incident with a blast-radius score of 100/100.
The module then runs the response lifecycle: enrich, approval-gated containment,
and an RCA that recommends the Azure Policy which would have prevented the
exposure in the first place.

## Why this matters

Cloud security engineering is more than watching alerts. The incidents that end
up in post-mortems usually start with an identity - a phished credential, an
over-privileged service principal, an MFA bypass - and end at infrastructure.
This module makes that path explicit and shows the engineering that contains it:
correlation, blast-radius scoring, approval-gated response, and prevention.

The chain is deliberately realistic. Every stage is a separate telemetry event
in a separate log source. Individually each one is a medium-interest signal that
a busy team might close. The value is in the correlation: when three or more
distinct stages line up on a shared entity within a short window, the engine
raises a single Critical incident. That is the difference between "eight alerts
in a queue" and "someone is walking from a phished login to an exposed
management port right now".

## The blast-radius score

The score is explainable, not a black box - five weighted factors: whether a
privileged identity is involved, whether a high-privilege service principal is in
scope, whether anything was exposed to the internet, whether the assets are
critical, and how many resources are affected. A reviewer sees exactly why an
incident is scored 100 out of 100.

## Automation boundaries

Because these actions touch networks and RBAC, the response boundaries are
strict. Enrichment and session revocation can be automatic - they are reversible.
But reverting an NSG rule, rotating a service principal credential, or isolating a
VM all require human approval, because a wrong network change causes a second
outage. Detection is also paired with prevention: an Azure Policy in the module's
`iac/` folder denies the exact public management exposure the detection catches.

## How it connects identity, cloud, networking and automation

It starts in identity (sign-in, MFA, privileged roles), crosses into cloud RBAC
(service principal credentials, resource-group Owner grants), lands in networking
(an NSG rule opening a management port to the internet), and it is all wired
together by automation - the correlation engine, the approval-gated playbooks,
and the Azure Policy that prevents the exposure next time.

## Honest scope

Everything here is synthetic and runs offline. The KQL is written against common
Sentinel table names, and the Bicep and Azure Policy files are illustrative -
none of it has been deployed to a production tenant. My production strength is
identity and privileged-access security; this module demonstrates how I reason
about identity-driven cloud infrastructure risk. See
[RESPONSIBLE_AUTOMATION.md](../modules/datacenter-control-plane/RESPONSIBLE_AUTOMATION.md)
for the automation boundaries and
[the module README](../modules/datacenter-control-plane/README.md) for full
detail.
