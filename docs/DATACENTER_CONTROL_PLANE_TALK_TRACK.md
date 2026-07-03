# Datacenter Control Plane Attack Path Lab - talk track

How to present the advanced extension in an interview. Natural, honest, and
tied to the hiring manager's post. The single best artefact to open is
[modules/datacenter-control-plane/demo-output/control_plane_timeline.md](../modules/datacenter-control-plane/demo-output/control_plane_timeline.md).

## 60-second explanation

"The parent lab stops at the identity plane. This extension follows the
attacker across the bridge into Azure infrastructure. It replays one chain:
a risky sign-in from an unusual country, MFA fatigue until the user approves, a
ticketless privileged-role activation, a credential added to a high-privilege
service principal, that principal granted Owner on the datacenter-management
resource group, and finally an NSG rule opening RDP to the whole internet on a
reachable management jumpbox. Eight detections fire across Entra ID, Azure
Activity and Defender telemetry - and instead of eight disconnected alerts, a
correlation engine links them by identity, service principal and resource
scope into one Critical incident with a blast-radius score of 100 out of 100.
Then it runs the response lifecycle: enrich, DRI-approved containment, and an
RCA that recommends the Azure Policy which would have prevented the exposure in
the first place."

## 2-minute explanation

"I built this because the role isn't 'watch alerts all day' - it's cloud
security engineering where identity compromise becomes infrastructure risk, and
that's exactly the seam I wanted to show I understand.

The chain is deliberately realistic. Every stage is a separate telemetry event
in a separate log source: sign-in logs, audit logs, Azure Activity, NSG
changes, a Defender alert. Individually each one is a medium-interest signal
that a busy SOC might close. The value is in the correlation: my engine links
alerts that share an identity, a service principal, or a resource scope within
a four-hour window, and when three or more distinct attack stages line up it
raises a single Critical incident. That's the difference between 'eight alerts
in a queue' and 'someone is walking from a phished login to an exposed
management port right now.'

The blast-radius score is the part I'm most pleased with. It's explainable, not
a black box - five weighted factors: is a privileged identity involved, is a
high-privilege service principal in scope, was anything exposed to the
internet, are the assets critical, how many resources are affected. The DRI
sees *why* it's a hundred out of a hundred.

On response, I was careful about automation boundaries because these actions
touch networks and RBAC. Enrichment and session revocation can be automatic -
they're reversible. But reverting an NSG rule, rotating a service principal
credential, isolating a VM - those all require human approval, because a wrong
network change causes a second outage. And I paired detection with prevention:
there's an Azure Policy in the IaC folder that denies the exact public
management exposure the detection catches.

It's a synthetic, offline lab - I'm honest that I haven't run this at
production scale - but every KQL query targets real Sentinel table schemas, so
the thinking ports directly."

## How it maps to the hiring manager's post

| Their words | This extension |
|-------------|----------------|
| "not a watch-alerts-all-day role" | The point is correlation and response engineering, not alert triage |
| Azure administration and cloud engineering | Azure Activity, RBAC, NSG, VM exposure modelled end to end |
| cloud security and identity security | The whole thesis: identity compromise -> infrastructure exposure |
| Sentinel and security operations | KQL detections on real table schemas, correlation, incident lifecycle |
| detection engineering and incident response | 8 detections as code + a blast-radius-scored incident with an RCA |
| Infrastructure as Code | Bicep + Azure Policy under `iac/`, detection paired with prevention |
| automation using Python, KQL, Logic Apps | Python engine, KQL rules, 10 Logic App-style playbooks |
| Azure networking, firewalls, hybrid | NSG rule analysis, public-exposure detection, deny policy |
| large-scale critical infrastructure security | Datacenter-management assets as the crown jewels in the model |
| builders who automate or eliminate manual processes | Correlation replaces manual alert-stitching; RCA feeds tuning |

## "Why did you build this extension?"

"Because when I looked at the role honestly, my parent lab proved I can do
identity detection - but the job is bigger than identity. It's about what
happens when a compromised identity reaches the Azure control plane, and I
wanted to show I think in attack paths, not isolated alerts. I also wanted to
prove I can reason about the response side where it gets dangerous - network and
RBAC changes that can cause outages - and show the discipline of gating those
behind human approval. It's the most role-specific thing I could build to
demonstrate how I'd approach the actual work."

## Being honest about lab versus production

- Say: "synthetic, offline lab that mirrors Sentinel and Azure concepts."
- Say: "the KQL targets real table schemas, and the Bicep and Azure Policy are
  illustrative - I haven't run them at production scale."
- Say: "my production strength is identity and privileged access security. I
  built this extension to show how I think about identity-driven cloud
  infrastructure risk and to prepare for this role."
- Don't claim production Azure infrastructure operations experience. The
  credibility comes from the quality of the thinking, not an inflated CV.

## How it demonstrates a builder mindset

The manager asked for builders who automate or eliminate manual processes.
Stitching eight alerts across five log sources into one incident is exactly the
manual toil a busy analyst does in their head under pressure - and gets wrong.
I built the engine that does it deterministically, scores the blast radius, and
hands the DRI a ready-to-action incident. Then the RCA closes the loop by
turning the incident into a versioned policy and detection change. That's the
build-to-eliminate-toil pattern, applied to the control plane.

## How it connects identity, cloud, networking and automation

This is the one-sentence version: "It starts in identity (sign-in, MFA,
privileged roles), crosses into cloud RBAC (service principal credentials,
resource-group Owner grants), lands in networking (an NSG rule opening a
management port to the internet), and it's all wired together by automation -
the correlation engine, the approval-gated playbooks, and the Azure Policy that
prevents the exposure next time." That sentence is the whole role in miniature,
which is exactly why I built it.
