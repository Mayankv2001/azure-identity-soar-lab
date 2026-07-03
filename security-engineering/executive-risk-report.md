# Executive risk report - identity-to-cloud control-plane exposure

One page for leadership. Based on the synthetic labs in this repository. No real
environment data.

## Risk summary

The highest-impact cloud security incidents do not start at the firewall - they
start with an identity. A single compromised login can be walked, in under two
hours, into standing infrastructure access and an internet-exposed management
server. This repository demonstrates that path end to end and shows the
detection, response and prevention that contain it.

## Why identity-to-control-plane attacks matter

- **Identity is the new perimeter.** Attackers do not break in; they log in.
  Phished credentials plus a defeated MFA prompt are enough to begin.
- **The blast radius compounds.** Each step - privileged role, service principal
  credential, resource-group ownership, an open firewall rule - widens access,
  ending at critical infrastructure.
- **Speed outpaces manual triage.** The demonstrated chain ran in ~100 minutes.
  Watching individual alerts does not catch it; correlating them into one
  incident does.

## Business impact (if this were real)

- Exposure of a datacenter management host to the internet.
- Durable attacker persistence via a service principal credential that survives
  password resets.
- Potential lateral movement into the workloads that host depends on.
- Regulatory, availability and trust consequences disproportionate to the single
  account that was compromised.

## Current detection coverage

- **15 detections** across identity, audit, Azure Activity, NSG and Defender
  telemetry, all mapped to MITRE ATT&CK.
- **Average detection maturity 91.8/100** on a transparent scorecard - strong
  candidates that require tenant-specific tuning before deployment.
- **Full-chain correlation:** eight signals collapse into one Critical incident
  with an explainable blast-radius score.

## Response maturity

- Automated enrichment, notification and session revocation (reversible actions).
- Human-approved containment for anything that changes a network or permission
  (irreversible-in-practice actions), preventing self-inflicted outages.
- Every incident produces a handover packet and a blameless RCA that feeds
  control improvements.

## Prevention gaps (the honest part)

- No enforced policy yet denying public exposure of management ports - the single
  highest-leverage missing control.
- Push-approval MFA still permitted for operations staff - the weakness the chain
  exploits first.
- Standing broad privilege on automation service principals - historical debt
  that widens blast radius.

## Key metrics

| Metric | Current (synthetic) | Target |
|--------|---------------------|--------|
| Detection coverage (MITRE tactics) | 6 tactics across 15 rules | Expand to token-theft, exfiltration |
| Detection maturity (avg) | 91.8 / 100 | Maintain >85 as rules are added |
| Time to correlated Critical incident | ~100 min | < 30 min (escalate at stage 4) |
| High-risk actions requiring approval | 100% | Maintain 100% |
| Preventive policies enforced | 0 of 8 documented | 8 of 8 (Audit then Deny) |

## Recommended next actions

1. Deploy the deny-public-management-exposure policy (Audit, then Deny).
2. Move operations and admin roles to phishing-resistant MFA.
3. Re-scope high-privilege service principals to least privilege / managed identity.
4. Escalate correlation severity earlier in the chain (stage 4, not stage 7).

## What success looks like in 90 days

Management servers cannot be exposed to the internet by policy; operations staff
use phishing-resistant sign-in; the time from first suspicious event to a
connected high-priority incident drops below 30 minutes; and every incident ends
in a versioned control improvement rather than just a closed ticket.
