# Log Source Coverage Matrix

Part of the [Production Readiness & Operations Layer](../). This matrix answers a
question every SOC lead asks of a detection catalogue: *for each log source, which
detections depend on it, and what is our coverage status?* It is the inventory
that makes coverage gaps visible instead of assumed.

> **Coverage status is honest about the lab boundary.** Every source below is at
> **Synthetic** status: the detections are written against real Microsoft
> Sentinel table names and column shapes, but the rows are generated offline by
> [`src/generate_logs.py`](../../src/generate_logs.py) and the watchlists are JSON
> reference files, not live `_GetWatchlist()` lookups. "Available in tenant" and
> "Not yet" are included as *target* states so the path to real ingestion is
> explicit — see the
> [Telemetry Maturity Model](TELEMETRY_MATURITY_MODEL.md) for what moving between
> them entails.

## Status legend

| Status | Meaning |
|--------|---------|
| **Synthetic** | Modelled by the generator; the rule's KQL targets the real table but no live data flows. **This is where every source in this repo sits.** |
| Available in tenant | The source exists in a typical Entra ID / Azure / Defender tenant and a connector *could* be enabled — no work has been done here, it is the natural next step. |
| Not yet | The source needs bespoke onboarding (custom log ingestion, a watchlist populated from an external system of record) before it can be used at all. |

The **Available in tenant** and **Not yet** columns describe the *effort class* of
turning a synthetic source real; the **live status in this repo is Synthetic for
all rows**.

## Primary log sources

| Log source (Sentinel table) | Detections that use it | Effort to make real | Coverage status (this repo) |
|-----------------------------|------------------------|---------------------|-----------------------------|
| `SigninLogs` | DET-001, DET-002, CP-DET-001, CP-DET-002 | Available in tenant (Entra ID sign-in connector) | Synthetic |
| `AuditLogs` | DET-003, DET-004, DET-005, CP-DET-003, CP-DET-004 | Available in tenant (Entra ID audit connector) | Synthetic |
| `AzureActivity` | CP-DET-005, CP-DET-006, CP-DET-007 | Available in tenant (Azure Activity connector) | Synthetic |
| `SecurityAlert` (Defender / analytics alert store) | CP-DET-008 (correlation input) | Available in tenant (Microsoft 365 Defender / Defender for Cloud connectors) | Synthetic |
| `CyberArk_EPV_CL` (custom log) | DET-006 | Not yet (custom ingestion via AMA / Logs Ingestion API) | Synthetic |

## Watchlists (reference data as a "source")

Watchlists are consumed exactly like a log source in the KQL (`_GetWatchlist(...)`)
and are just as much a coverage dependency — a detection with a stale or empty
watchlist silently under-fires. In this repo they are JSON files under
[`data/`](../../data/); making them real means populating them from the actual
identity / asset systems of record.

| Watchlist | Detections that use it | Real system of record | Coverage status (this repo) |
|-----------|------------------------|-----------------------|-----------------------------|
| `CAPolicyAdmins` | DET-003 | Entra ID role assignments (CA policy admins) | Synthetic |
| `HighPrivilegeApps` | DET-004 | App registration / enterprise app inventory | Synthetic |
| `PrivilegedIdentities` | DET-007 | PIM / privileged identity register | Synthetic |
| `IdentityBaseline` | CP-DET-001 | Sign-in baseline (country / device history) | Synthetic |
| `HighPrivilegeServicePrincipals` | CP-DET-004 | Service principal / workload identity inventory | Synthetic |
| `AssetInventory` | CP-DET-007 | CMDB / asset register (management endpoints) | Not yet — needs CMDB feed |
| `ControlPlaneAlerts` | CP-DET-008 | Sentinel's own `SecurityAlert` store (correlation) | Synthetic |

## Coverage read-out

- **All 15 detections** are covered by **at least one** modelled source — there is
  no detection in this catalogue with an unmapped input. That is the coverage
  claim the matrix supports, and it is a *logic* coverage claim, not a *data*
  coverage claim.
- **Sign-in and audit telemetry carry the identity plane.** `SigninLogs` and
  `AuditLogs` together back **9 of 15** detections and are the highest-value
  connectors to make real first — they are standard Entra ID connectors, so this
  is the lowest-friction move to Level 1/2 in the maturity model.
- **`AzureActivity` carries the control plane.** Three of the eight control-plane
  detections (`CP-DET-005/006/007`) depend on it; without it, the
  identity-to-cloud attack path this project showcases is invisible from the
  control-plane side.
- **`CyberArk_EPV_CL` is the one true "Not yet" log source.** It is a custom log,
  so unlike the first-party tables it cannot be turned on with a connector toggle
  — it needs an ingestion pipeline (AMA or the Logs Ingestion API). DET-006 is
  therefore the detection furthest from real telemetry, which matches the
  [Detection Quality Scorecard](../../security-engineering/detection-quality-scorecard.md)
  note that DET-006 would most need UEBA-style baselining in production.
- **`CP-DET-008` is a correlation-of-detections rule**, not a raw-log rule: its
  input is `SecurityAlert` (the alerts the other rules raise) plus the
  `ControlPlaneAlerts` watchlist. It is therefore only as mature as its *least*
  mature upstream detection — a coverage dependency worth stating explicitly.
- **Two watchlists need an external feed** to become real: `AssetInventory`
  (a CMDB) and, in effect, every watchlist that mirrors a live system of record.
  These are the "Not yet" reference sources.

## What this matrix is *not*

It is not evidence of ingestion. No source here is live. The matrix maps
**detection → source dependency** and states the honest coverage status
(Synthetic) for each; the per-field mapping needed to actually connect a source is
in [`SYNTHETIC_TO_REAL_TELEMETRY_MAPPING.md`](SYNTHETIC_TO_REAL_TELEMETRY_MAPPING.md),
and the illustrative owners and notional volumes are in
[`sample-ingestion-inventory.json`](sample-ingestion-inventory.json).

---

*Synthetic lab artefact. All telemetry is generated offline; no production
Sentinel workspace, data connector, or real log source is involved. Personas are
fictional `@contoso.com` identities. See the
[repository README](../../README.md) for the full lab-vs-production boundary.*
