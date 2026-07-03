# Entity summary - CP-INC-2001

Synthetic. The entities involved in the chain, what each one is, and its role in
the incident.

## Affected identity

| Attribute | Value |
|-----------|-------|
| UPN | chris.walker@contoso.com |
| Role | Cloud Operations Engineer |
| Privilege | Standing Contributor on sub-prod-dc; PIM-eligible for Application Administrator |
| MFA | Registered (push) - phishing-vulnerable |
| Compromise vector | Valid password + MFA fatigue approval |
| Status | Sessions revoked; pending password reset and phishing-resistant MFA |

This is the pivot. A single Cloud Operations identity with standing Contributor
plus PIM eligibility is enough to reach the control plane once its MFA is
defeated.

## Affected service principal

| Attribute | Value |
|-----------|-------|
| Name | sp-infra-deploy |
| Privilege tier | High (Contributor on sub-prod-dc) |
| Owner | chris.walker@contoso.com |
| Abuse | Attacker added a client secret, then used it to grant Owner and open the NSG |
| Why it matters | SP credentials survive user password resets and MFA - durable persistence |
| Status | Attacker credential removed; remaining secrets rotated |

## Affected resource group

| Attribute | Value |
|-----------|-------|
| Name | rg-prod-dc-mgmt |
| Criticality | Critical (datacenter management tooling) |
| Abuse | sp-infra-deploy granted Owner with no change ticket |
| Status | Owner assignment removed |

## Affected NSG / firewall

| Attribute | Value |
|-----------|-------|
| Name | nsg-prod-dc-mgmt |
| Change | New Allow rule allow-rdp-temp: TCP 3389 from 0.0.0.0/0 |
| Criticality | Critical (protects the management jumpbox) |
| Status | Rule reverted (snapshot preserved for evidence) |

## Affected VM / management endpoint

| Attribute | Value |
|-----------|-------|
| Name | vm-dc-mgmt-01 |
| Role | Datacenter management jumpbox |
| Public IP | 203.0.113.200 |
| Exposure | RDP reachable from the internet for ~20 minutes |
| Status | Endpoint JIT-locked; under review for successful inbound logins |

## Entity relationship (why correlation worked)

The correlation engine linked all eight alerts because they share a small set of
entities within a four-hour window:

- **chris.walker@contoso.com** ties stages 1-5 (sign-in, MFA, role, SP credential, RG grant).
- **sp-infra-deploy** ties stages 4-6 (credential, RG Owner, NSG change).
- **rg-prod-dc-mgmt / nsg-prod-dc-mgmt / vm-dc-mgmt-01** tie stages 5-7.

No single shared entity spans the whole chain - but the overlapping entity sets
do, which is exactly why entity-plus-time-window correlation beats
correlate-by-user-only.

## Blast radius (why 100/100)

| Factor | Points | Reason |
|--------|--------|--------|
| Identity privilege | 25 | Privileged identity with PIM eligibility |
| Service principal permissions | 25 | High-privilege SP in scope |
| Public exposure | 20 | Management port reachable from the internet |
| Asset criticality | 20 | Critical datacenter-management assets |
| Affected resources | 10 | Multiple distinct resources |
| **Total** | **100** | **Critical** |
