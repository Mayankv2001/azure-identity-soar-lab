# Control plane attack timeline - CP-INC-2001

**Identity-to-control-plane attack chain - chris.walker@contoso.com**  |  severity Critical  |  blast radius 100/100 (Critical)

All data is synthetic (generator seed 77, simulation clock 2026-07-01T00:00Z).

## Stages 1-8: detection telemetry

| Time (UTC) | Stage | Detection | Entity | Severity | Why it matters |
|------------|-------|-----------|--------|----------|----------------|
| 2026-06-30T09:00:00Z | 1 | CP-DET-001 Risky sign-in from unusual location | chris.walker@contoso.com | High | Foreign high-risk sign-in - the entry point of the chain. |
| 2026-06-30T09:02:00Z | 2 | CP-DET-002 MFA fatigue leading to approval | chris.walker@contoso.com | Critical | The approval after the deny burst is the account-takeover moment. |
| 2026-06-30T09:11:00Z | 1 | CP-DET-001 Risky sign-in from unusual location | chris.walker@contoso.com | High | Foreign high-risk sign-in - the entry point of the chain. |
| 2026-06-30T09:25:00Z | 3 | CP-DET-003 Privileged role activation without change record | chris.walker@contoso.com | High | Privileged role activated with no change record - escalation begins. |
| 2026-06-30T09:40:00Z | 4 | CP-DET-004 Credential added to high-privilege service principal | chris.walker@contoso.com | Critical | Credential on a high-privilege SP survives user password resets. |
| 2026-06-30T10:05:00Z | 5 | CP-DET-005 Subscription or resource group permission change | chris.walker@contoso.com | High | The SP is granted Owner on the datacenter-management group. |
| 2026-06-30T10:20:00Z | 6 | CP-DET-006 NSG or firewall rule opened to the internet | sp-infra-deploy | Critical | A management port is opened to the entire internet. |
| 2026-06-30T10:20:00Z | 7 | CP-DET-007 VM management endpoint exposed to the internet | sp-infra-deploy | Critical | A reachable jumpbox management endpoint is now internet-facing. |
| 2026-06-30T10:40:00Z | 8 | Defender: Traffic from unusual locations to a management port | vm-dc-mgmt-01, 203.0.113.200 | High | Platform signal confirms the exposure is being probed. |

## Blast-radius scoring

| Factor | Points | Reason |
|--------|--------|--------|
| identity_privilege | 25 | compromised identity holds or can activate privileged roles |
| service_principal_permissions | 25 | high-privilege service principal in scope |
| public_exposure | 20 | management surface reachable from the internet |
| asset_criticality | 20 | critical datacenter-management assets in scope |
| affected_resources | 10 | 4 distinct resources affected |
| **Total** | **100/100** | **Critical** |

## Stages 9-11: response flow

### 9. SOAR enrichment  _(automatic)_

Enrich every entity: identity privilege and PIM eligibility, service principal permissions, resource criticality, and current public exposure. Attach the blast-radius score to the incident.

### 10. DRI review and approved containment  _(human approval required)_

On-call DRI reviews the enriched chain and approves containment in least-destructive order: revoke sessions (auto at Critical), revert the NSG rule, rotate the service principal credential, remove the Owner assignment, deactivate the PIM role, contain the user.

### 11. RCA and hardening  _(manual)_

Blameless RCA: identify the control that failed (standing Contributor on the SP, ticketless PIM activation, no Azure Policy denying public management exposure) and ship the fixes as detection tuning and policy.

## Correlation logic

Alerts were linked because they share entities (chris.walker@contoso.com, rg-prod-dc-mgmt, sp-infra-deploy) within a four-hour window. Because three or more distinct attack stages were present, the engine raised the correlated chain detection CP-DET-008 as a single Critical incident rather than eight disconnected alerts.
