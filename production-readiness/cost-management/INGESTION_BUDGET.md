# Ingestion Budget (Illustrative)

> **Illustrative only.** Every gigabyte, dollar, and threshold on this page is a
> made-up planning figure for an offline Sentinel-style lab, not a measurement
> from a real workspace. Amounts are expressed in AUD (GST-exclusive list
> pricing) by convention; the real per-GB rate depends on your commitment tier
> and region - confirm current **Australia East** pricing in the Azure pricing
> calculator before using any of this for a real budget.

This document turns the [cost model](./SENTINEL_COST_MODEL.md) into a concrete,
per-table budget with alert thresholds. It is the reference the
[cost monitoring queries](./COST_MONITORING_QUERIES.kql) and the
[sample dashboard](./sample-cost-dashboard.json) check against.

## 1. Assumptions

| Assumption | Illustrative value |
|------------|--------------------|
| Region | Australia East |
| Pricing model | Pay-as-you-go (Analytics tier), for planning |
| Illustrative Analytics ingestion rate | ~A$4.00 per GB |
| Illustrative Basic/Auxiliary ingestion rate | ~A$0.90 per GB |
| Included interactive retention | 90 days (Analytics tier) |
| Environment size modelled | Mid-size AU enterprise, ~2,000-5,000 identities |
| Billing period | Calendar month (~30.4 days) |

These are round planning numbers chosen to make the arithmetic legible, not
current list prices.

## 2. Per-table daily budget

Each table gets a **target** (expected steady-state), a **soft threshold**
(warn), and a **hard threshold** (alert / investigate). Thresholds are expressed
as GB/day. The lab's detections read only the first four telemetry tables plus
watchlists; the remaining rows are illustrative production sources shown so the
budget models a realistic mix.

| Table | Tier | Target GB/day | Soft (warn) | Hard (alert) | Notes |
|-------|------|---------------|-------------|--------------|-------|
| `SigninLogs` | Analytics | 3.0 | 3.8 | 4.5 | Core identity signal (DET-001/002, CP-DET-001/002). Keep. |
| `AuditLogs` | Analytics | 1.2 | 1.6 | 2.0 | Core identity signal (DET-003/004/005, CP-DET-003/004). Keep. |
| `AzureActivity` | Analytics | 2.5 | 3.2 | 4.0 | Control-plane (CP-DET-005/006/007). Filter read-only ops at the DCR. |
| `CyberArk_EPV_CL` | Analytics | 0.4 | 0.6 | 0.8 | Tier-0 privileged signal (DET-006). Keep. |
| Watchlists | Reference | ~0 | n/a | n/a | Tiny lookup data (`CAPolicyAdmins`, `HighPrivilegeApps`, `PrivilegedIdentities`). |
| `SecurityEvent` | Analytics/Basic | 8.0 | 11.0 | 14.0 | Illustrative, not used by lab rules. Biggest noise risk - filter hard. |
| `Syslog` | Basic/Auxiliary | 6.0 | 9.0 | 12.0 | Illustrative network telemetry. Prefer Basic tier. |
| **Workspace total** | mixed | **~21.1** | **26.0** | **30.0** | Sum + headroom; also governed by the daily cap below. |

Notes on reading the table:

- **Target** is what "normal" looks like; sustained operation near target is
  healthy.
- **Soft threshold** is roughly target +25-35%. Crossing it should raise a
  low-severity notice in the daily review, not page anyone.
- **Hard threshold** is roughly target +50% (or the point where the table would
  breach its share of the workspace budget). Crossing it should raise an alert
  and an investigation.

## 3. Monthly cost envelope (illustrative)

Using the assumptions above and the analytics-tier tables only for the identity
lab's own footprint:

| Table | Target GB/day | GB/month (~30.4) | Illustrative A$/month |
|-------|---------------|------------------|-----------------------|
| `SigninLogs` | 3.0 | 91.2 | ~365 |
| `AuditLogs` | 1.2 | 36.5 | ~146 |
| `AzureActivity` | 2.5 | 76.0 | ~304 |
| `CyberArk_EPV_CL` | 0.4 | 12.2 | ~49 |
| **Lab-core subtotal** | **7.1** | **215.9** | **~864** |

Adding the illustrative production noise sources (`SecurityEvent`, `Syslog`) at
their targets would roughly triple the bill - which is exactly the point of the
budget: the security-valuable core is the cheap part, and the volume tables are
where governance pays for itself. Moving `Syslog` to the Basic tier alone saves
roughly A$560/month at target in this illustration.

> These A$ figures are arithmetic on illustrative rates, not a quote. A real
> environment on a commitment tier would pay a different (usually lower) blended
> rate.

## 4. Daily ingestion cap

A workspace-level **daily cap** is the hard safety net that turns a runaway-cost
event into a deliberate data-completeness decision.

| Environment | Illustrative daily cap | Rationale |
|-------------|------------------------|-----------|
| This lab | **1 GB/day** | Synthetic data is tiny; a low cap makes runaway ingestion impossible. |
| Illustrative production | **30 GB/day** | Above expected peak (~26 GB soft), with KQL alerts well below it. |

The cap should always sit **above** the workspace hard threshold so alerts fire
first and the cap is the last line of defence, never the routine control.

## 5. Alert triggers

Two layers, matching the [cost model](./SENTINEL_COST_MODEL.md#8-cost-alerts).

### Layer A - Azure Budget (financial backstop)

An Azure Budget scoped to the Sentinel + Log Analytics resource group:

| Threshold | % of monthly forecast | Action |
|-----------|-----------------------|--------|
| Info | 50% | Email owner (Cloud Security Engineering) |
| Warn | 80% | Email owner + note in daily review |
| Critical | 100% | Email owner + escalate to review commitment tier / caps |

### Layer B - KQL scheduled alerts (data backstop)

Scheduled summary/analytics rules over the `Usage` table (see
[COST_MONITORING_QUERIES.kql](./COST_MONITORING_QUERIES.kql)):

| Alert | Trigger | Severity | Suggested cadence |
|-------|---------|----------|-------------------|
| Workspace daily spike | Yesterday's total ingestion > 25% above trailing 7-day average | Medium | Daily |
| Per-table hard breach | Any table exceeds its **Hard (alert)** GB/day from section 2 | Medium | Daily |
| Unexpected new table | A table appears that is not in the budget list | Low | Daily |
| Approaching daily cap | Running-day ingestion > 80% of the daily cap | High | Hourly |
| Table with volume, no detection | Table in top-N by volume but referenced by no analytics rule | Low | Weekly |

### Ownership and routing

- **Owner:** Cloud Security Engineering (consistent with the detection-rule
  owners in this repo).
- **Routing:** cost alerts go to the same DRI queue as security alerts but at
  lower default severity - a cost spike is operational, not an incident, unless
  it correlates with a security event (an ingestion spike *can* be an
  exfiltration/log-flooding signal, so a sustained unexplained spike is worth a
  security glance, not just a finance one).

## 6. How the budget is reviewed and revised

- **Daily:** the five-minute review in
  [SENTINEL_COST_MODEL.md](./SENTINEL_COST_MODEL.md#7-daily-cost-review) checks
  actuals against these thresholds.
- **Monthly:** compare actual GB/month per table to the targets here; adjust
  targets that have drifted for legitimate reasons (org growth, new connector
  with a documented detection justification).
- **On change:** any new data connector must arrive with (a) at least one
  detection/hunt/compliance justification and (b) a target/soft/hard row added
  to section 2 **before** it is enabled. No connector goes live without a budget
  line.

## 7. Honest caveats

- These are planning figures for a synthetic lab; real ingestion is spikier and
  correlated with business events (month-end, incidents, onboarding waves).
- The A$ rates are illustrative round numbers, not current list pricing.
- A production budget would also account for UEBA, ML analytics, cross-workspace
  queries, and export/rehydration costs, which this simplified model omits.
- The single most reliable cost control for this lab remains **deleting the
  resource group when finished** - see the cleanup plan in the cost model.
