# Connector Runbook

Operational runbook for the data connectors this detection estate depends on. It
is written for the person who has to answer "is this connector actually healthy,
and if not, what do I do?" — not for a first-time installer.

**Honest lab framing.** This is a synthetic, offline-first lab that mirrors
Microsoft Sentinel and Azure concepts. None of these connectors is deployed to a
production tenant. Every persona, table name and validation query below is
written against **common Sentinel table schemas** so the runbook ports cleanly if
the lab is ever promoted (see `docs/LIVE_SENTINEL_DEPLOYMENT_PATH.md`, Mode C),
but the permissions, owners and SLAs are illustrative reference values, not a
record of a live deployment. Every identity is a fictional `@contoso.com` persona;
no real emails, GUIDs, subscription IDs or secrets appear anywhere in this repo.

All KQL in this runbook is **read-only and safe** — validation and health queries
only. Nothing here mutates data, changes configuration, or triggers a response.

## How to use this runbook

Each connector below is documented with a fixed set of fields so you can compare
them at a glance:

- **Purpose** — what telemetry it brings in and which detections rely on it.
- **Required permissions** — the least-privilege roles/scopes to configure and
  run it. Grant the minimum; review under `production-readiness/rbac/`.
- **Validation KQL** — a safe, read-only query to prove the connector is
  delivering usable data. Run it in the Log Analytics query window.
- **Expected table** — where the data lands.
- **Expected minimum fields** — the columns a detection cannot run without. If
  any are missing or empty, treat the connector as degraded even if rows exist.
- **Failure symptoms** — what a broken or degraded connector looks like.
- **Owner** — the accountable persona/team for this connector.
- **Operational check frequency** — how often health is actively confirmed
  (in addition to the automated health dashboard in
  `CONNECTOR_HEALTH_DASHBOARD_SPEC.md`).

Detection IDs (`DET-00X`, `CP-DET-00X`) refer to the analytics rules under
`detections/` and `modules/datacenter-control-plane/detections/`. Watchlist
names (`PrivilegedIdentities`, `HighPrivilegeApps`, etc.) match the
`_GetWatchlist(...)` lookups those rules already use.

**Timezone note.** The SOC operates on Australia/Sydney time (UTC+10 in this
environment). `TimeGenerated` is stored in UTC; freshness queries below reason in
UTC and convert only where a human-readable local time is needed.

---

## Connector inventory (quick reference)

| # | Connector | Primary table | Owner (persona / team) | Check frequency |
|---|-----------|---------------|------------------------|-----------------|
| 1 | Entra ID sign-in logs | `SigninLogs` | Priya Sharma — Identity Detection Engineering | Daily |
| 2 | Entra ID audit logs | `AuditLogs` | Priya Sharma — Identity Detection Engineering | Daily |
| 3 | Azure Activity | `AzureActivity` | Dana Iyer — Cloud Security Engineering | Daily |
| 4 | Defender for Cloud / Defender alerts | `SecurityAlert` | Dana Iyer — Cloud Security Engineering | Daily |
| 5 | NSG / firewall logs | `AzureActivity` (rule writes) + `AzureNetworkAnalytics_CL` (flow, optional) | Dana Iyer — Cloud Security Engineering | Daily |
| 6 | CyberArk (custom table / Logs Ingestion API) | `CyberArk_EPV_CL` | Liam O'Connor — Identity Detection Engineering | Twice daily |
| 7 | Watchlists (privileged identities, apps, assets, admin groups) | Watchlist store (`_GetWatchlist`) | Priya Sharma / Dana Iyer — shared | Weekly + on change |

---

## 1. Entra ID sign-in logs

**Purpose.** Interactive and non-interactive sign-in events for the tenant. This
is the highest-value identity stream in the estate: it powers MFA-fatigue
detection (DET-001 / CP-DET-002), impossible-travel (DET-002), risky sign-in
(CP-DET-001), and provides the sign-in context every downstream identity
investigation reads first.

**Required permissions.**
- To configure the connector: **Security Administrator** or **Global Administrator**
  on the Entra tenant (connector enablement is a tenant-level action), plus
  **Microsoft Sentinel Contributor** on the target workspace.
- Diagnostic settings for `SignInLogs` (and `NonInteractiveUserSignInLogs` if
  used) must be routed to the Log Analytics workspace.
- To run validation queries: **Microsoft Sentinel Reader** or **Log Analytics
  Reader** on the workspace. No write permission is needed for anything in this
  runbook.

**Validation KQL** (safe, read-only):
```kql
// Freshness + volume + core-field completeness for sign-in logs, last 24h
SigninLogs
| where TimeGenerated > ago(24h)
| summarize
    Rows            = count(),
    LastReceivedUtc = max(TimeGenerated),
    MinsSinceLast   = datetime_diff('minute', now(), max(TimeGenerated)),
    NullUser        = countif(isempty(UserPrincipalName)),
    NullIp          = countif(isempty(IPAddress)),
    NullResult      = countif(isempty(ResultType))
```

**Expected table.** `SigninLogs`.

**Expected minimum fields.** `TimeGenerated`, `UserPrincipalName`, `IPAddress`,
`ResultType`, `AuthenticationRequirement` (or `AuthenticationDetails`),
`Location` / `LocationDetails`, `AppDisplayName`. DET-001 needs the result and
timestamp columns to count push prompts; DET-002 needs `IPAddress` and
`LocationDetails` to reason about geography.

**Failure symptoms.**
- `Rows = 0` over a 24h window in a tenant that normally has sign-ins → connector
  disabled, diagnostic setting removed, or workspace key rotated.
- `MinsSinceLast` climbing well past normal ingestion latency (see the latency
  target in `CONNECTOR_VALIDATION_CHECKLIST.md`) → ingestion backlog or pipeline
  stall.
- `NullIp` / `NullUser` non-zero and rising → schema drift or a partial log
  category (e.g. only non-interactive sign-ins routed) that silently starves
  DET-002.

**Owner.** Priya Sharma (`priya.sharma@contoso.com`) — Identity Detection
Engineering.

**Operational check frequency.** Daily (dashboard tile + the weekly operations
review confirms trend, per `docs/DRI_RUNBOOK.md`).

---

## 2. Entra ID audit logs

**Purpose.** Directory-change events: policy edits, credential additions, role
and group membership changes. This stream powers the control-plane-relevant
identity detections — Conditional Access policy modified/deleted (DET-003),
service-principal credential added (DET-004 / CP-DET-004), privileged role or
group addition (DET-005 / CP-DET-003). Without it, an attacker's
persistence-and-escalation actions are invisible.

**Required permissions.**
- To configure: **Security Administrator** / **Global Administrator** on the
  tenant + **Microsoft Sentinel Contributor** on the workspace. Diagnostic
  setting for the `AuditLogs` category must route to the workspace.
- To run validation queries: **Microsoft Sentinel Reader** / **Log Analytics
  Reader**.

**Validation KQL** (safe, read-only):
```kql
// Freshness + category coverage for audit logs, last 24h
AuditLogs
| where TimeGenerated > ago(24h)
| summarize
    Rows            = count(),
    LastReceivedUtc = max(TimeGenerated),
    MinsSinceLast   = datetime_diff('minute', now(), max(TimeGenerated)),
    Categories      = dcount(Category),
    NullActor       = countif(isempty(tostring(InitiatedBy)))
  by Category
| sort by Rows desc
```

**Expected table.** `AuditLogs`.

**Expected minimum fields.** `TimeGenerated`, `OperationName`, `Category`,
`ActivityDisplayName`, `InitiatedBy` (actor UPN / app id), `TargetResources`,
`Result`. DET-003 keys on policy `OperationName`; DET-004 reads
`TargetResources` for the credential change; DET-005 reads the role/group
target and the initiating actor.

**Failure symptoms.**
- `Rows = 0` while sign-in logs still flow → the audit category specifically was
  dropped from the diagnostic setting (a common single-category regression).
- Only one or two `Categories` present when the tenant normally shows several →
  partial routing; the missing category may be exactly the one a detection needs
  (e.g. `RoleManagement` for DET-005).
- `NullActor` rising → schema drift in `InitiatedBy`, which breaks actor
  attribution and the "unauthorised actor" severity escalation in DET-003/005.

**Owner.** Priya Sharma (`priya.sharma@contoso.com`) — Identity Detection
Engineering.

**Operational check frequency.** Daily.

---

## 3. Azure Activity

**Purpose.** The Azure Resource Manager control-plane log: who did what to which
resource. It powers the infrastructure detections in the control-plane module —
subscription/resource-group permission change (CP-DET-005), NSG rule opened to
the internet (CP-DET-006), and VM management endpoint exposed (CP-DET-007). This
is the seam where an identity compromise becomes infrastructure risk.

**Required permissions.**
- To configure: **Owner** or **Contributor** at the subscription (or management
  group) scope to create the diagnostic setting that exports Activity logs, plus
  **Microsoft Sentinel Contributor** on the workspace. In practice this is done
  once per subscription via the Azure Activity connector.
- To run validation queries: **Microsoft Sentinel Reader** / **Log Analytics
  Reader**.

**Validation KQL** (safe, read-only):
```kql
// Freshness + presence of the network-rule operation CP-DET-006/007 depend on
AzureActivity
| where TimeGenerated > ago(24h)
| summarize
    Rows            = count(),
    LastReceivedUtc = max(TimeGenerated),
    MinsSinceLast   = datetime_diff('minute', now(), max(TimeGenerated)),
    NetworkRuleOps  = countif(OperationNameValue ==
        "Microsoft.Network/networkSecurityGroups/securityRules/write"),
    DistinctCallers = dcount(Caller)
```

**Expected table.** `AzureActivity`.

**Expected minimum fields.** `TimeGenerated`, `OperationNameValue`,
`ActivityStatusValue`, `Caller`, `CallerIpAddress`, `_ResourceId`, `Properties`.
CP-DET-006 parses `Properties.sourceAddressPrefix` / `Properties.access`;
CP-DET-005 keys on the role-assignment write operation and `Caller`.

**Failure symptoms.**
- `Rows = 0` → subscription diagnostic setting removed or the connector
  disconnected; the entire control-plane detection set goes dark.
- `NetworkRuleOps = 0` over a period where NSG changes are known to have
  happened → the operation name or `Properties` shape has drifted, silently
  blinding CP-DET-006/007 (see the schema-drift tile in the dashboard spec).
- Sudden drop in `DistinctCallers` to near-zero → only management-plane noise is
  arriving and user/service-principal actions are being filtered upstream.

**Owner.** Dana Iyer (`dana.iyer@contoso.com`) — Cloud Security Engineering.

**Operational check frequency.** Daily.

---

## 4. Defender for Cloud / Defender alerts

**Purpose.** Product-generated security alerts from Microsoft Defender for Cloud
and the Defender suite, surfaced into Sentinel via the `SecurityAlert` table.
These are used as **corroborating signal**: the correlated identity-to-control-
plane chain (CP-DET-008) unions `SecurityAlert` rows (alert names starting
`CP-DET-00`) with the lab's own detections so a Defender finding and a custom
analytic reinforce one incident rather than fragmenting into two.

**Required permissions.**
- To configure: **Security Administrator** on the workspace/tenant and
  **Microsoft Sentinel Contributor** to enable the Microsoft Defender for Cloud
  (and Microsoft 365 Defender / Defender XDR) connectors. Defender for Cloud must
  be enabled on the subscription with alert export to the workspace.
- To run validation queries: **Microsoft Sentinel Reader** / **Log Analytics
  Reader**.

**Validation KQL** (safe, read-only):
```kql
// Freshness + provider spread for Defender alerts, last 24h
SecurityAlert
| where TimeGenerated > ago(24h)
| summarize
    Rows            = count(),
    LastReceivedUtc = max(TimeGenerated),
    MinsSinceLast   = datetime_diff('minute', now(), max(TimeGenerated)),
    Providers       = make_set(ProductName, 10),
    NullSeverity    = countif(isempty(AlertSeverity))
```

**Expected table.** `SecurityAlert`.

**Expected minimum fields.** `TimeGenerated`, `AlertName`, `AlertSeverity`,
`ProductName`, `Entities`, `SystemAlertId`. CP-DET-008 keys on `AlertName`
prefixes; entity mapping into an incident needs `Entities`.

**Failure symptoms.**
- `Rows = 0` while other connectors flow → alert export from Defender for Cloud
  turned off, or the Defender connector disconnected. Corroboration for
  CP-DET-008 disappears but the custom chain still fires, so this fails quietly.
- `Providers` shrinks (e.g. Defender for Cloud drops out but Defender for
  Identity remains) → partial coverage; note which product stopped.
- `NullSeverity` rising → schema drift that breaks any severity-weighted
  correlation.

**Owner.** Dana Iyer (`dana.iyer@contoso.com`) — Cloud Security Engineering.

**Operational check frequency.** Daily.

---

## 5. NSG / firewall logs

**Purpose.** Network-layer control-plane and (optionally) flow telemetry.
Two distinct signals live here and are deliberately kept separate:

1. **Rule-change events** — an NSG security-rule create/update arrives as an
   **`AzureActivity`** control-plane write
   (`Microsoft.Network/networkSecurityGroups/securityRules/write`). This is what
   CP-DET-006 (internet-open allow rule) and CP-DET-007 (reachable management
   endpoint) actually query. It is the authoritative "someone opened the
   firewall" signal.
2. **Flow logs** — NSG flow logs / traffic analytics (`AzureNetworkAnalytics_CL`)
   are an **optional enrichment** for confirming a rule change was actually
   exercised by traffic. No detection depends on flow logs today; they are listed
   so the runbook is honest about what is and is not required.

**Required permissions.**
- Rule-change events: covered by the **Azure Activity** connector (see §3) — no
  separate connector.
- Flow logs (optional): **Network Contributor** at the relevant scope to enable
  NSG flow logs, a storage account for flow-log staging, and the Traffic
  Analytics workspace binding. **Microsoft Sentinel Contributor** on the
  workspace. This is only needed if flow-level confirmation is added later.
- To run validation queries: **Microsoft Sentinel Reader** / **Log Analytics
  Reader**.

**Validation KQL** (safe, read-only):
```kql
// Rule-change signal (the one detections depend on), last 7d.
// Uses 7d because NSG rule changes are rare — a 24h window can be legitimately empty.
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue ==
    "Microsoft.Network/networkSecurityGroups/securityRules/write"
| summarize
    RuleWrites      = count(),
    LastRuleWrite   = max(TimeGenerated),
    DistinctNsgs    = dcount(tostring(_ResourceId)),
    DistinctCallers = dcount(Caller)
```

**Expected table.** `AzureActivity` (rule-change events).
`AzureNetworkAnalytics_CL` if the optional flow-log enrichment is enabled.

**Expected minimum fields.** From `AzureActivity`: `TimeGenerated`,
`OperationNameValue`, `ActivityStatusValue`, `Caller`, `_ResourceId`,
`Properties` (with `sourceAddressPrefix`, `access`, `destinationPortRange`,
`nsgName`, `rule`).

**Failure symptoms.**
- The §3 Azure Activity validation shows healthy rows but `RuleWrites` here is
  persistently `0` **and** you know NSG changes occurred → the `Properties`
  shape or operation name has drifted; CP-DET-006/007 are blind. This is the
  most dangerous NSG failure because it is silent — no error, just no alerts.
- A legitimate empty result is **expected and normal** in quiet weeks; do not
  page on `RuleWrites = 0` alone. Correlate with a known change window before
  declaring a failure (this is why the query uses a 7-day window).
- If flow logs are enabled and `AzureNetworkAnalytics_CL` stops while
  `AzureActivity` continues → flow-log pipeline (storage/Traffic Analytics)
  broke; enrichment only, non-blocking.

**Owner.** Dana Iyer (`dana.iyer@contoso.com`) — Cloud Security Engineering.

**Operational check frequency.** Daily (rule-change presence), reconciled weekly
against the change record so an empty week is confirmed benign, not a fault.

---

## 6. CyberArk (custom table / Logs Ingestion API)

**Purpose.** Privileged-credential checkout and PSM session telemetry from
CyberArk EPV/PSM, landing in the custom table `CyberArk_EPV_CL`. It powers
DET-006 (anomalous privileged credential checkout): ticketless checkout bursts,
quiet-hours checkouts, and Tier-0-safe escalation. This is the bridge between the
PAM estate and the Sentinel detection layer.

**Ingestion path.** Two supported, non-scraping paths (per the repo's no-HTML-
scrape rule):
1. **AMA + syslog/CEF** — CyberArk forwards CEF over syslog to an Azure Monitor
   Agent collector; classic custom-log columns carry the `_s` string suffix
   (e.g. `EventType_s`, `TicketId_s`), which is exactly what DET-006's KQL reads.
2. **Logs Ingestion API** — CyberArk (or a small forwarder) POSTs JSON to a Data
   Collection Endpoint bound to a Data Collection Rule, which writes to
   `CyberArk_EPV_CL`. Preferred for structured control over the schema.

**Required permissions.**
- Logs Ingestion API path: a Data Collection Endpoint + Data Collection Rule on
  the workspace; the sending identity (a dedicated service principal / managed
  identity — **no secrets in the repo**) needs the **Monitoring Metrics
  Publisher** role on the DCR. **Microsoft Sentinel Contributor** to wire the
  table into analytics.
- AMA/syslog path: agent install permission on the collector host and a DCR that
  maps the CEF stream to `CyberArk_EPV_CL`.
- To run validation queries: **Microsoft Sentinel Reader** / **Log Analytics
  Reader**.
- The publishing credential is stored in a secret store (Key Vault) and never
  committed. Rotation is tracked under `production-readiness/rbac/`.

**Validation KQL** (safe, read-only):
```kql
// Freshness + schema-suffix + ticket-completeness for CyberArk events, last 24h
CyberArk_EPV_CL
| where TimeGenerated > ago(24h)
| summarize
    Rows            = count(),
    LastReceivedUtc = max(TimeGenerated),
    MinsSinceLast   = datetime_diff('minute', now(), max(TimeGenerated)),
    Checkouts       = countif(EventType_s == "PasswordCheckout"),
    NullUser        = countif(isempty(Username_s)),
    NullSafe        = countif(isempty(SafeName_s))
```

**Expected table.** `CyberArk_EPV_CL`.

**Expected minimum fields.** `TimeGenerated`, `EventType_s`, `Username_s`,
`SafeName_s`, `AccountName_s`, `TicketId_s`. DET-006 counts `PasswordCheckout`
events per user/window, groups by `SafeName_s`, and escalates when a safe
matches the Tier-0 domain-admins safe. Missing `SafeName_s` breaks the
Critical-escalation path.

**Failure symptoms.**
- `Rows = 0` → forwarder down, DCR misconfigured, or (Logs Ingestion API path)
  the publisher credential expired. CyberArk is a low-volume, high-value stream,
  so silence is easy to miss — the health dashboard's last-received tile is the
  primary guard.
- Rows present but `EventType_s` empty / renamed (e.g. a CyberArk version change
  altered the CEF mapping) → schema drift; DET-006 counts nothing even though
  data flows. Classic "green connector, dead detection".
- `NullSafe` rising → the safe field mapping broke; Tier-0 escalation silently
  degrades to Medium.

**Owner.** Liam O'Connor (`liam.oconnor@contoso.com`) — Identity Detection
Engineering (PAM liaison).

**Operational check frequency.** Twice daily. CyberArk is low-volume and
business-critical, so a longer gap between checks risks a multi-hour blind spot
on privileged access; the tighter cadence is deliberate.

---

## 7. Watchlists (privileged identities, high-privilege apps, assets, approved admin groups)

**Purpose.** Reference data the detections enrich against, surfaced through
`_GetWatchlist(...)`. These are not a streaming connector — they are curated
lookup tables — but they are treated as connectors here because a stale or empty
watchlist silently degrades detection quality just like a dead log feed. The
watchlists in use:

| Watchlist | What it holds | Consumed by |
|-----------|---------------|-------------|
| `PrivilegedIdentities` | Privileged users/accounts and their tier | DET-005, DET-007, identity enrichment |
| `HighPrivilegeApps` | High-privilege application registrations | DET-004 severity escalation |
| `HighPrivilegeServicePrincipals` | Sensitive service principals | CP-DET-004 |
| `CAPolicyAdmins` | Approved actors allowed to change CA policy | DET-003 authorised-actor check |
| `AssetInventory` | Asset/VM inventory incl. public-IP + NSG binding | CP-DET-007 reachability |
| `IdentityBaseline` | Baseline sign-in context for identities | CP-DET-001 |
| `ControlPlaneAlerts` | Control-plane alert reference set | CP-DET-008 correlation |

An **approved admin groups** watchlist (a curated `CAPolicyAdmins`-style list of
sanctioned privileged groups) is the authorisation backbone: it is what turns
"a role was added" into "a role was added by someone **not** on the approved
list", which is the difference between noise and an incident.

**Required permissions.**
- To create/update a watchlist: **Microsoft Sentinel Contributor** on the
  workspace (watchlist authoring is a Sentinel-scoped write).
- To read via `_GetWatchlist` in analytics/validation: **Microsoft Sentinel
  Reader** / **Log Analytics Reader**.
- Watchlist source data is curated and reviewed by the owning team; changes go
  through the process under `production-readiness/change-approval/`. No secrets
  or real identities — contents are fictional `@contoso.com` personas and
  synthetic asset records.

**Validation KQL** (safe, read-only):
```kql
// Confirm each critical watchlist is present and non-empty
union isfuzzy=true
    (_GetWatchlist('PrivilegedIdentities')          | summarize Rows = count() | extend Watchlist = 'PrivilegedIdentities'),
    (_GetWatchlist('HighPrivilegeApps')             | summarize Rows = count() | extend Watchlist = 'HighPrivilegeApps'),
    (_GetWatchlist('HighPrivilegeServicePrincipals')| summarize Rows = count() | extend Watchlist = 'HighPrivilegeServicePrincipals'),
    (_GetWatchlist('CAPolicyAdmins')                | summarize Rows = count() | extend Watchlist = 'CAPolicyAdmins'),
    (_GetWatchlist('AssetInventory')                | summarize Rows = count() | extend Watchlist = 'AssetInventory')
| project Watchlist, Rows
| sort by Watchlist asc
```

**Expected table.** Watchlist store, accessed via `_GetWatchlist('<Name>')`.

**Expected minimum fields.** Each watchlist must resolve (function does not
error) and return `Rows > 0`. `PrivilegedIdentities` needs a UPN/identity key and
tier column; `AssetInventory` needs `Type`, `Name`, `Nsg`, `PublicIp` (CP-DET-007
joins on `Nsg` and filters on `PublicIp`); `CAPolicyAdmins` needs the approved-
actor key DET-003 compares against.

**Failure symptoms.**
- `_GetWatchlist('X')` errors → the watchlist was deleted or renamed; any rule
  referencing it fails to run (a hard, visible failure — better than silent).
- `Rows = 0` for a watchlist that should be populated → someone uploaded an empty
  or malformed CSV. DET-003 then treats **every** actor as unapproved (false-
  positive storm) or **no** actor as unapproved (false negatives), depending on
  how the join is written. Either way, degraded.
- Stale contents (e.g. `PrivilegedIdentities` not updated after a
  joiner/mover/leaver change) → correct rule, wrong reference; DET-007 misses a
  newly-orphaned account, or DET-005 mis-scores. This is why watchlists are
  reviewed on a cadence, not just when they break.

**Owner.** Shared: Priya Sharma (`priya.sharma@contoso.com`, identity
watchlists — `PrivilegedIdentities`, `HighPrivilegeApps`, `CAPolicyAdmins`,
`IdentityBaseline`) and Dana Iyer (`dana.iyer@contoso.com`, infrastructure
watchlists — `AssetInventory`, `HighPrivilegeServicePrincipals`,
`ControlPlaneAlerts`) — with a single named reviewer per watchlist recorded in
the change-approval log.

**Operational check frequency.** Weekly presence/row-count check, **plus** a
re-review on every privileged-access or asset change (event-driven), because a
watchlist's danger is staleness, not just absence.

---

## Cross-connector operating notes

- **Green connector, dead detection.** The recurring theme across connectors 3–7
  is that a connector can look healthy (rows arriving) while a specific field or
  operation a detection depends on has drifted. Row-count freshness is necessary
  but not sufficient — the validation checklist and the schema-drift dashboard
  tile exist precisely to catch this class.
- **Least privilege everywhere.** Every validation query in this runbook runs
  under a Reader role. Configuration roles (Contributor/Owner/Security Admin) are
  granted for enablement and then reviewed down under
  `production-readiness/rbac/`. No runbook step requires a write role.
- **No secrets, ever.** Ingestion credentials (CyberArk publisher, DCR keys) live
  in a secret store and are referenced, never committed. This repo contains no
  real subscription IDs, tenant IDs, client secrets, tokens, or real emails.
- **Escalation.** A connector confirmed down is treated as a detection-coverage
  incident: the owning persona is paged per the severity of the detections it
  starves (a `SigninLogs` or `AzureActivity` outage is Critical coverage loss),
  following the SLA matrix in `docs/DRI_RUNBOOK.md`.
- **Related artefacts.** Validate a connector before trusting it with
  `CONNECTOR_VALIDATION_CHECKLIST.md`; monitor them continuously with
  `CONNECTOR_HEALTH_DASHBOARD_SPEC.md`.
