# Microsoft Sentinel Cost Model (Lab, Illustrative)

> **Lab framing.** This project is an offline-first, synthetic Microsoft
> Sentinel-style lab. Nothing here has been deployed to a production tenant, and
> **every dollar and gigabyte figure on this page is illustrative** - chosen to
> reason about cost behaviour, not measured from a real bill. My production
> background is identity and privileged-access security; this document shows how
> I would think about Sentinel ingestion economics as a cloud security
> engineer, using Australian pricing conventions (AUD, GST-exclusive list
> pricing) as the frame of reference.
>
> Real numbers depend on your commitment tier, region, retention choices, and
> the mix of analytics vs. auxiliary/basic logs. Always confirm current pricing
> in the Azure pricing calculator for **Australia East** before committing to a
> budget.

## 1. Why Sentinel cost matters

Microsoft Sentinel is billed primarily on **data ingested and retained**, not on
the number of detections you run. That inverts the intuition a lot of engineers
start with: writing one more analytics rule is essentially free, but onboarding
one more chatty data source can quietly double the monthly bill. Cost is
therefore a **detection-engineering decision**, not just a finance one.

Three cost drivers dominate:

1. **Ingestion volume (GB/day)** - the single largest lever. Priced per GB, so a
   noisy connector is a recurring tax, not a one-off.
2. **Retention beyond the included period** - the first 90 days of analytics-tier
   data are included with Sentinel; anything kept longer is billed per
   GB/month, and archive tier is cheaper again.
3. **Feature add-ons** - UEBA, some ML analytics, and certain data connectors
   carry their own ingestion or compute footprint.

The failure mode I want to avoid is the classic one: a debug connector or a
verbose firewall feed gets switched on "temporarily", nobody watches the daily
volume, and three weeks later the workspace has blown its commitment tier and
the bill has tripled. This document exists so that does not happen silently.

### The one honest line

Detection quality and cost quality are the same discipline. A rule that fires on
a low-value, high-volume table is expensive twice - once to ingest the data and
again in analyst time to triage the noise. The 15 detections in this lab
(average score 91.8/100, per the
[detection quality scorecard](../../security-engineering/detection-quality-scorecard.md))
deliberately sit on **high-signal identity and control-plane tables**, which is
also the cheapest place for them to live.

## 2. Ingestion volume - the primary lever

The lab's detections read from a small, deliberate set of tables. An illustrative
production-shaped estimate for a **mid-size Australian enterprise** (roughly
2,000-5,000 identities) might look like this. Numbers are made up for reasoning;
they are not from any real tenant.

| Table | Purpose in this lab | Illustrative volume | Signal density | Cost posture |
|-------|---------------------|---------------------|----------------|--------------|
| `SigninLogs` | DET-001/002, CP-DET-001/002 | ~3.0 GB/day | High | Keep - core identity signal |
| `AuditLogs` | DET-003/004/005, CP-DET-003/004 | ~1.2 GB/day | High | Keep - core identity signal |
| `AzureActivity` | CP-DET-005/006/007 | ~2.5 GB/day | Medium-high | Keep, but filter noisy operations |
| `CyberArk_EPV_CL` (custom) | DET-006 | ~0.4 GB/day | High | Keep - Tier-0 privileged signal |
| Watchlists (`CAPolicyAdmins`, `HighPrivilegeApps`, `PrivilegedIdentities`) | DET-005/007 lookups | negligible | Reference | Keep - tiny, high-value |
| `SecurityEvent` (illustrative, not used by lab rules) | Windows security events | ~8-15 GB/day | Low-medium | **Filter hard** - largest noise risk |
| `Syslog` / firewall (illustrative) | Network telemetry | ~6-20 GB/day | Low per-event | **Filter / basic tier** |

The pattern to internalise: the tables the lab actually detects on
(`SigninLogs`, `AuditLogs`, `AzureActivity`, `CyberArk_EPV_CL`) are a **minority
of the volume** but the **majority of the security value**. The tables that
blow budgets (`SecurityEvent`, `Syslog`, raw firewall) are mostly noise unless
carefully filtered.

### Volume-reduction techniques (in priority order)

1. **Don't ingest what you won't query.** The cheapest gigabyte is the one you
   never collect. Every connector should map to at least one detection, hunt,
   or compliance requirement.
2. **Filter at the collection tier.** Data Collection Rules (DCRs) can drop or
   project columns before ingestion - e.g. strip verbose Windows event IDs you
   never detect on, or `AzureActivity` read-only operations.
3. **Use the right table tier.** High-value analytics data belongs in the
   Analytics tier; high-volume, rarely-queried data (raw network flows,
   verbose app logs) belongs in the **Basic/Auxiliary tier**, which is
   materially cheaper to ingest but query-limited.
4. **Transform, don't hoard.** Summarise where you can - a per-minute
   aggregate of a chatty source is far smaller than the raw stream.

## 3. Retention - included, extended, and archive

Retention is the second lever and it is easy to get wrong by leaving the default
everywhere.

- **Analytics tier, included:** the first 90 days of interactive retention is
  included with Sentinel at no extra retention charge (you still pay to ingest).
- **Analytics tier, extended:** days 91+ up to the interactive maximum (currently
  up to ~2 years, region permitting) are billed per GB/month.
- **Archive tier:** long-tail retention (up to ~7-12 years depending on the
  configuration) at a much lower per-GB/month rate, but data must be
  **rehydrated** or **searched** before normal KQL analytics run over it.

The lab's own workspace is deliberately provisioned at **30-day retention**
(`infra/sentinel/modules/log-analytics-workspace.bicep`, `retentionInDays: 30`,
with `immediatePurgeDataOn30Days: true`) precisely because it is a lab and cost
control beats history there. A production workspace would use the tiered policy
in [RETENTION_POLICY.md](./RETENTION_POLICY.md) instead of one flat number.

### Table-level retention

The important production capability is **per-table retention**, not one
workspace-wide setting. Sentinel/Log Analytics lets each table carry its own
interactive-retention and total-retention values. This is where real money is
saved:

- Keep **`SigninLogs` and `AuditLogs`** interactively for longer (identity
  investigations reach back weeks) but archive the tail.
- Keep **high-volume, low-per-event tables** interactively for the shortest
  window that still supports triage, then archive or drop.
- Keep **watchlists** effectively forever - they are tiny reference data.

The concrete per-table matrix lives in
[RETENTION_POLICY.md](./RETENTION_POLICY.md); the point here is that flat
retention is a cost anti-pattern and the platform gives you a per-table knob.

## 4. Noisy sources - identify and tame

"Noisy" is not the same as "high-volume". A noisy source is one whose **cost per
unit of security value is poor** - it generates a lot of ingestion for few
actionable detections.

Warning signs I would watch for:

- A single table is a large share of daily GB but appears in **zero** analytics
  rules or hunting queries.
- A connector was enabled for a proof-of-concept and never turned off.
- Verbose diagnostic/debug logging left at `Verbose`/`Informational` in
  production.
- Duplicate ingestion - the same events arriving via two connectors.

Taming, in order of preference: **turn it off**, then **filter it at the DCR**,
then **move it to the Basic/Auxiliary tier**, then (only if genuinely needed for
analytics) accept the cost and document why. The
[cost monitoring queries](./COST_MONITORING_QUERIES.kql) include a "top noisy
tables" query and a "tables with volume but no detections" starting point to
find these.

## 5. Watchlists - cheap by design

Watchlists (`CAPolicyAdmins`, `HighPrivilegeApps`, `PrivilegedIdentities` in this
lab) are **reference data, not telemetry**. They are small, human-curated lookup
tables that enrich detections without adding a measurable ingestion footprint.
They are one of the best cost-per-value tools available:

- A watchlist lookup lets a detection be **precise** (e.g. DET-005 only escalates
  when the target is a protected role/group), which reduces false positives and
  therefore analyst cost.
- They cost effectively nothing to store.
- They avoid ingesting bulky context that would otherwise have to live in a
  telemetry table.

Cost guidance: prefer a watchlist over ingesting a large enrichment feed whenever
the enrichment set is small and slow-changing. Keep watchlists version-controlled
and reviewed - a stale privileged-identity watchlist is a detection-quality bug,
not just a cost one.

## 6. Archive strategy

The archive tier is the pressure-release valve for compliance-driven retention
without paying analytics-tier rates for years of cold data.

Illustrative approach:

- **Hot / interactive (Analytics tier):** the window an analyst needs for live
  investigation and correlation. For identity tables, illustratively 90 days.
- **Warm / extended interactive:** where an investigation *might* need to reach
  but rarely does - illustratively to 180 days for `SigninLogs`/`AuditLogs`.
- **Cold / archive:** compliance and forensic retention beyond that -
  illustratively to 1-2 years for identity tables, longer only if a regulator
  or contract requires it.

Two operational rules:

1. **Archive is not free and not instant.** Rehydration/search over archived data
   is a deliberate, billable action - budget for it in incident response, don't
   assume "we can always look it back up" is zero-cost.
2. **Archive only what has a retention requirement.** Archiving noise just moves
   the cost, it does not remove it. Filter first, then archive what remains.

## 7. Daily cost review

Cost control is an operational habit, not a one-off design. The discipline that
keeps a Sentinel workspace inside budget is a **short daily review**, ideally
folded into the same SecOps stand-up that reviews incidents (see the daily
operations report pattern in
[docs/DRI_RUNBOOK.md](../../docs/DRI_RUNBOOK.md)).

A five-minute daily cost check:

1. Yesterday's **total ingestion (GB)** vs. the running 7-day average.
2. **Per-table** volume - did any table jump more than ~25%?
3. Any **new table** that appeared and wasn't expected?
4. Are we tracking toward the **daily cap / commitment tier** or over it?
5. Any **cost alert** fired overnight?

The queries in [COST_MONITORING_QUERIES.kql](./COST_MONITORING_QUERIES.kql) map
one-to-one onto that checklist, and the illustrative dashboard in
[sample-cost-dashboard.json](./sample-cost-dashboard.json) renders them as tiles
so the review can be done at a glance.

## 8. Cost alerts

Reviews catch drift; alerts catch spikes. Two complementary layers:

- **Platform layer (Azure Cost Management / budgets):** an Azure Budget on the
  Sentinel + Log Analytics resource group with alert thresholds at, illustratively,
  50% / 80% / 100% of the monthly forecast. This is the financial backstop and it
  is provider-native.
- **Data layer (KQL scheduled query):** a scheduled analytics/summary rule over
  the `Usage` table that fires when daily ingestion for the workspace, or for a
  specific table, exceeds a threshold - e.g. total ingestion > 25% above the
  trailing 7-day average, or any single table crossing its per-table budget from
  [INGESTION_BUDGET.md](./INGESTION_BUDGET.md).

Additionally, a **daily ingestion cap** on the workspace is the hard safety net:
it stops ingestion (with configurable exclusions) once the cap is hit, converting
a runaway-cost incident into a data-completeness decision you make deliberately.
For a lab, the cap should be low. For production, set it above expected peak with
alerting well below it, so the cap is the last line, not the first.

The concrete thresholds and triggers are defined in
[INGESTION_BUDGET.md](./INGESTION_BUDGET.md).

## 9. Lab cleanup plan

Because this is a lab, the most important cost control is **turning it off when
you are done**. Leaving a Log Analytics workspace and Sentinel running in a
personal/test subscription is the number-one way to get a surprise bill.

Cleanup checklist (consistent with
[docs/LIVE_SENTINEL_DEPLOYMENT_PATH.md](../../docs/LIVE_SENTINEL_DEPLOYMENT_PATH.md)
section 10):

1. **Keep analytics rules disabled** unless actively testing - a disabled rule
   ingests nothing and runs nothing.
2. **Keep retention at the 30-day lab default** with `immediatePurgeDataOn30Days`
   enabled, so cold data does not accumulate.
3. **Delete the resource group** when finished:

   ```bash
   az group delete --name "$RESOURCE_GROUP" --yes --no-wait
   ```

   This removes the workspace, Sentinel, and every rule in one action.
4. **Confirm the workspace is gone**, remembering the soft-delete window - a
   soft-deleted workspace can still incur charges and blocks name reuse until it
   is purged.
5. **Never point lab collection at a real tenant** - synthetic, personal/test
   subscription only. That is a security control first and a cost control second.

## 10. Summary

- Sentinel cost is driven by **ingestion and retention**, so cost engineering is
  detection engineering.
- The lab's detections live on **high-signal, lower-volume identity and
  control-plane tables** - the cheapest and most valuable place to be.
- Use **per-table retention** and the **archive tier**, not one flat number.
- Prefer **watchlists** over ingesting bulky enrichment.
- Run a **daily cost review**, back it with **budget + KQL alerts and a daily
  cap**, and for the lab, **delete the resource group when done**.

All figures on this page are illustrative and Australian-priced by convention;
confirm current Australia East pricing before building a real budget.
