# Synthetic → Real Telemetry Mapping

Part of the [Production Readiness & Operations Layer](../). This is the crosswalk
a detection engineer would use to move a rule off this lab's synthetic fixtures
and onto real Microsoft Sentinel telemetry: for each synthetic source, the real
Sentinel source it stands in for, which detections consume it, the fields that
**must** be present for the rule to work, and the concrete risk if a field is
missing or unmapped.

> **These are MAPPINGS, not live connections.** Nothing in this repo is connected
> to a tenant. The generator ([`src/generate_logs.py`](../../src/generate_logs.py))
> produces rows shaped to match the real column names below, so the KQL and the
> Python mirror can be written against the production schema — but no data
> connector exists, no `_GetWatchlist()` resolves against a live watchlist, and
> the "real/Sentinel source" column describes where the data *would* come from,
> not where it comes from today. This document is the plan for Level 1+ of the
> [Telemetry Maturity Model](TELEMETRY_MATURITY_MODEL.md); it is not evidence that
> the move has happened.

## How to read the table

- **Synthetic source** — what the generator emits in this lab.
- **Real / Sentinel source** — the production table and connector it models.
- **Used by detection** — the rule(s) that break if this source is absent
  (see the [Log Source Coverage Matrix](LOG_SOURCE_COVERAGE_MATRIX.md)).
- **Required fields** — the columns the rule logic actually reads. If a real
  tenant does not populate one of these, the mapping is incomplete.
- **Risk if missing** — what goes wrong when the source or a required field is
  absent: a false negative (silent miss), a false positive (noise), or a
  correlation/enrichment failure.

## Sign-in telemetry

| Synthetic source | Real / Sentinel source | Used by detection | Required fields | Risk if missing |
|------------------|------------------------|-------------------|-----------------|-----------------|
| Generated Entra sign-in events | `SigninLogs` (Entra ID sign-in connector) | DET-001, DET-002, CP-DET-001, CP-DET-002 | `UserPrincipalName`, `TimeGenerated`, `ResultType`, `AuthenticationRequirement` / MFA result, `IPAddress`, `Location` (country), `AppDisplayName`, `DeviceDetail` | Missing table → total false negative on MFA fatigue, impossible travel and risky sign-in (4 detections blind). Missing `ResultType`/MFA fields → cannot distinguish a denied push from an approved one, breaking DET-001 and CP-DET-002. Missing `Location`/`IPAddress` → DET-002 impossible-travel cannot compute distance/velocity. |

## Directory audit telemetry

| Synthetic source | Real / Sentinel source | Used by detection | Required fields | Risk if missing |
|------------------|------------------------|-------------------|-----------------|-----------------|
| Generated Entra audit events | `AuditLogs` (Entra ID audit connector) | DET-003, DET-004, DET-005, CP-DET-003, CP-DET-004 | `OperationName`, `TimeGenerated`, `InitiatedBy` (actor UPN / app), `TargetResources`, `ActivityDisplayName`, `Result` | Missing table → 5 detections blind, including the CA-policy-tamper (DET-003) and privileged-role-addition (DET-005) rules that anchor the identity-to-cloud chain. Missing `InitiatedBy` → cannot attribute the change to an actor, so self-elevation detection and the "unauthorised actor" severity escalation both fail. Missing `TargetResources` → cannot tell *which* policy/app/role changed, collapsing precision into noise. |

## Azure control-plane telemetry

| Synthetic source | Real / Sentinel source | Used by detection | Required fields | Risk if missing |
|------------------|------------------------|-------------------|-----------------|-----------------|
| Generated Azure Resource Manager activity | `AzureActivity` (Azure Activity connector) | CP-DET-005, CP-DET-006, CP-DET-007 | `OperationNameValue`, `TimeGenerated`, `Caller`, `ResourceGroup` / `_ResourceId`, `ActivityStatusValue`, `Properties` (rule/permission detail) | Missing table → the entire control-plane side of the attack path is invisible: NSG-opened-to-internet (`CP-DET-006`), permission change (`CP-DET-005`) and management-endpoint exposure (`CP-DET-007`) all go dark. Missing `OperationNameValue` → cannot match the specific `Microsoft.Network/.../securityRules/write` operation, so the public-rule detection silently under-fires. Missing `Caller` → no actor attribution for the correlated chain. |

## Defender / analytics alert telemetry

| Synthetic source | Real / Sentinel source | Used by detection | Required fields | Risk if missing |
|------------------|------------------------|-------------------|-----------------|-----------------|
| Generated detection alerts (this lab's own rule output) | `SecurityAlert` (Microsoft 365 Defender / Defender for Cloud connectors, and Sentinel's own analytics-rule alerts) | CP-DET-008 (correlation) | `AlertName`, `TimeGenerated`, `Entities` (user / SP / resource), `AlertSeverity`, `SystemAlertId` | Missing table → the correlated identity-to-control-plane chain (`CP-DET-008`, the 100/100 blast-radius showcase) cannot assemble; the attack degrades into eight isolated alerts with no single incident. Missing `Entities` → correlation cannot join alerts by user/SP/resource, which is the whole mechanism. This rule is only as complete as the upstream alerts feeding `SecurityAlert`. |

## NSG / firewall telemetry

| Synthetic source | Real / Sentinel source | Used by detection | Required fields | Risk if missing |
|------------------|------------------------|-------------------|-----------------|-----------------|
| Generated network-rule change events | `AzureActivity` for the rule-write control-plane event; NSG flow / firewall logs (`AzureNetworkAnalytics_CL`, `AzureDiagnostics`, or `CommonSecurityLog` for third-party firewalls) for the data-plane confirmation | CP-DET-006, CP-DET-007 | Control-plane: `OperationNameValue == Microsoft.Network/networkSecurityGroups/securityRules/write`, `Properties` (source prefix, destination port, access). Data-plane (optional enrichment): source/destination IP, port, action, allow/deny | This lab detects the **control-plane write** (the rule *being opened* to `0.0.0.0/0`) via `AzureActivity`, which is the earliest signal. Missing that → no detection that a management port was exposed. Flow/firewall logs are a real-world *enrichment* (was the open port actually reached?); missing them → the detection still fires but loses the "confirmed traffic" evidence a real investigation wants. Note the lab does not scrape or model third-party firewall payloads — only the ARM control-plane event is generated. |

## CyberArk privileged-access telemetry

| Synthetic source | Real / Sentinel source | Used by detection | Required fields | Risk if missing |
|------------------|------------------------|-------------------|-----------------|-----------------|
| Generated CyberArk EPV events | `CyberArk_EPV_CL` (custom log — AMA / Logs Ingestion API; **no first-party connector**) | DET-006 | `Username`, `TimeGenerated`, `SafeName`, `Action` (checkout / retrieve), `RequestReason`, `SourceAddress` | Missing custom log → the privileged-credential-checkout anomaly (DET-006) is impossible; there is no first-party fallback for CyberArk, so this is the highest-effort source to make real. Missing `SafeName` → cannot apply the Tier-0-safe severity escalation. Missing `RequestReason` → loses the "checkout without justification" signal. As the scorecard notes, DET-006 would most need real baselining before deployment. |

## Identity watchlists (reference-data mapping)

| Synthetic source | Real / Sentinel source | Used by detection | Required fields | Risk if missing |
|------------------|------------------------|-------------------|-----------------|-----------------|
| `data/` JSON reference files | Sentinel watchlists populated from the identity systems of record: `_GetWatchlist('CAPolicyAdmins')`, `_GetWatchlist('HighPrivilegeApps')`, `_GetWatchlist('PrivilegedIdentities')`, `_GetWatchlist('IdentityBaseline')`, `_GetWatchlist('HighPrivilegeServicePrincipals')` | DET-003 (CAPolicyAdmins), DET-004 (HighPrivilegeApps), DET-007 (PrivilegedIdentities), CP-DET-001 (IdentityBaseline), CP-DET-004 (HighPrivilegeServicePrincipals) | Watchlist key column (e.g. `UserPrincipalName`, `AppId`, `ServicePrincipalId`) plus the classification field the rule joins on (privilege tier, baseline country) | A **stale or empty watchlist fails silently**: the join returns nothing, so authorised-actor allow-lists and high-privilege escalations quietly stop matching. This is a false-negative *and* a false-positive risk at once — DET-003 can't tell an authorised CA admin from an attacker; DET-004 can't escalate on a genuinely high-privilege app. Watchlist freshness is a coverage dependency equal to any log source. |

## Asset / CMDB watchlists (reference-data mapping)

| Synthetic source | Real / Sentinel source | Used by detection | Required fields | Risk if missing |
|------------------|------------------------|-------------------|-----------------|-----------------|
| `data/` JSON reference files | Sentinel watchlists populated from the asset register / CMDB and the alert store: `_GetWatchlist('AssetInventory')`, `_GetWatchlist('ControlPlaneAlerts')` | CP-DET-007 (AssetInventory), CP-DET-008 (ControlPlaneAlerts) | `AssetInventory`: resource id / hostname, tier / criticality, "is management endpoint" flag. `ControlPlaneAlerts`: alert id, entity keys used for correlation | Missing/stale `AssetInventory` → `CP-DET-007` cannot tell that an exposed NSG fronts a *management* endpoint, dropping the severity from Critical to noise and losing the blast-radius reasoning. Missing `ControlPlaneAlerts` → `CP-DET-008` loses the scoped set of alerts it correlates, degrading the single-incident showcase back into scattered alerts. CMDB feeds are a genuine "Not yet" source — they need an external system integration, not a connector toggle. |

## The through-line

Two failure modes dominate this mapping and are worth stating plainly:

1. **A missing raw source is a loud, obvious false negative** — a whole family of
   detections goes dark, and you notice because the queue goes quiet.
2. **A stale or unmapped field / watchlist is a quiet, dangerous one** — the rule
   still runs, still "passes", but joins against nothing, so it neither escalates
   real threats nor allow-lists authorised actors. This is the harder failure to
   catch, and it is exactly why the [maturity model](TELEMETRY_MATURITY_MODEL.md)
   requires a *sampled-real* pass (Level 1) that asserts every required field is
   present before a rule is ever scheduled.

Neither failure mode can be discovered from synthetic data alone — which is the
honest reason this repo sits at Level 0 and this document is a plan rather than a
report.

---

*Synthetic lab artefact. All telemetry is generated offline; no production
Sentinel workspace, data connector, or real log source is involved. Table and
field names mirror the real Sentinel schema so the mapping is realistic, but no
data flows. Personas are fictional `@contoso.com` identities. See the
[repository README](../../README.md) for the full lab-vs-production boundary.*
