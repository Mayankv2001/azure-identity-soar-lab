# Connector Health Dashboard — Specification

A specification for a single-pane connector-health view: at a glance, is every
data source this detection estate depends on alive, fresh, correctly shaped, and
on time? The runbook (`CONNECTOR_RUNBOOK.md`) tells you what each connector is and
how to fix it; the validation checklist (`CONNECTOR_VALIDATION_CHECKLIST.md`)
gates reliance at onboarding. This dashboard is the **continuous** view that
catches a connector going dark between those checks.

**Honest lab framing.** This is a design specification for a synthetic, offline-
first lab that mirrors Microsoft Sentinel and Azure Monitor Workbook concepts. The
dashboard is **not deployed**; the KQL below is illustrative and written against
common Sentinel table schemas so it would port to a real workspace (Mode C, lab
subscription only). Thresholds are sensible reference values to baseline per
tenant, not measured production figures. All KQL is **read-only and safe** —
purely observational, nothing mutates data or triggers a response. All personas
are fictional `@contoso.com` identities; no secrets, real emails, GUIDs or
subscription IDs appear.

---

## Intended platform and audience

- **Platform.** An Azure Monitor Workbook (or Sentinel Workbook) over the Log
  Analytics workspace. Equivalent tiles could be built in a Grafana/Log Analytics
  panel; the KQL is the portable part.
- **Primary audience.** The DRI on shift and the connector owners (Priya Sharma —
  Identity Detection Engineering; Dana Iyer — Cloud Security Engineering; Liam
  O'Connor — PAM liaison). It is also the first artefact opened at the weekly
  operations review (`docs/DRI_RUNBOOK.md`).
- **Refresh.** Auto-refresh every 15 minutes. The freshness and failed-connector
  tiles are the ones the DRI glances at first.

## Layout at a glance

```
┌───────────────────────────────────────────────────────────────────────┐
│  Row 0:  [ Failed / stale connectors — RED banner if any ]              │
├───────────────────────────────┬───────────────────────────────────────┤
│  Tile 1  Last-received per     │  Tile 2  Daily volume trend            │
│          table (freshness)     │          (per table, 14 days)          │
├───────────────────────────────┼───────────────────────────────────────┤
│  Tile 3  Schema-drift          │  Tile 4  Ingestion latency (p50/p95)   │
│          (load-bearing fields) │                                        │
├───────────────────────────────┴───────────────────────────────────────┤
│  Tile 5  Failed connectors — detail table (drill-down)                  │
└───────────────────────────────────────────────────────────────────────┘
```

Tiles are ordered by triage value: freshness first (is it alive?), then volume
(is it sane?), then schema and latency (is it usable and on time?), with the
failed-connector detail as the drill-down.

## Colour semantics (consistent across every tile)

| State | Meaning | Colour |
|-------|---------|--------|
| Healthy | Within SLA / baseline | Green |
| Warning | Approaching threshold or benign-but-notable deviation | Amber |
| Failed | SLA breached / feed dark / drift confirmed | Red |
| Unknown | No data to evaluate (new connector, or table absent) | Grey |

Use Australian spelling in all tile labels (e.g. "colour", "behaviour",
"utilisation") and AUD if any cost figure is ever surfaced.

---

## Shared source list

Every tile evaluates the same connector set. Define it once (conceptually) and
reuse:

| Connector | Table evaluated | Freshness SLA | Owner |
|-----------|-----------------|---------------|-------|
| Entra sign-in | `SigninLogs` | 60 min | Priya Sharma |
| Entra audit | `AuditLogs` | 60 min | Priya Sharma |
| Azure Activity | `AzureActivity` | 120 min | Dana Iyer |
| Defender alerts | `SecurityAlert` | 120 min | Dana Iyer |
| CyberArk | `CyberArk_EPV_CL` | 180 min | Liam O'Connor |
| Watchlists | `_GetWatchlist(...)` | presence-based | Priya Sharma / Dana Iyer |

NSG rule-change health is read through `AzureActivity` (it is an operation within
that table), so it is covered by the `AzureActivity` row plus the schema-drift
tile, rather than a separate freshness row — an NSG-quiet week is normal and must
not paint the board red.

---

## Tile 1 — Last-received time per table (freshness)

**Purpose.** The heartbeat. One row per connector, showing minutes since the last
event and a green/amber/red state against that connector's freshness SLA. This is
the tile that answers "did anything just go dark?".

**Visual.** A status grid (one row per connector), red-first sort so failures rise
to the top.

**Sample KQL** (safe, read-only):
```kql
let Sources = datatable(Connector:string, TableName:string, FreshnessSlaMin:long)
[
    "Entra sign-in",   "SigninLogs",        60,
    "Entra audit",     "AuditLogs",         60,
    "Azure Activity",  "AzureActivity",     120,
    "Defender alerts", "SecurityAlert",     120,
    "CyberArk",        "CyberArk_EPV_CL",   180
];
let lastSeen =
    union isfuzzy=true
        (SigninLogs      | where TimeGenerated > ago(3d) | summarize Last = max(TimeGenerated) | extend TableName = "SigninLogs"),
        (AuditLogs       | where TimeGenerated > ago(3d) | summarize Last = max(TimeGenerated) | extend TableName = "AuditLogs"),
        (AzureActivity   | where TimeGenerated > ago(3d) | summarize Last = max(TimeGenerated) | extend TableName = "AzureActivity"),
        (SecurityAlert   | where TimeGenerated > ago(3d) | summarize Last = max(TimeGenerated) | extend TableName = "SecurityAlert"),
        (CyberArk_EPV_CL | where TimeGenerated > ago(3d) | summarize Last = max(TimeGenerated) | extend TableName = "CyberArk_EPV_CL");
Sources
| join kind=leftouter lastSeen on TableName
| extend MinsSinceLast = iff(isnull(Last), real(null),
                             todouble(datetime_diff('minute', now(), Last)))
| extend State = case(
    isnull(Last),                                  "Unknown",
    MinsSinceLast <= FreshnessSlaMin,              "Healthy",
    MinsSinceLast <= FreshnessSlaMin * 2,          "Warning",
                                                   "Failed")
| project Connector, TableName, LastReceivedUtc = Last, MinsSinceLast,
          FreshnessSlaMin, State
| sort by State asc, MinsSinceLast desc
```

**Thresholds.** Healthy ≤ SLA; Warning between 1× and 2× SLA; Failed beyond 2×
SLA; Unknown when the table returns no rows in 3 days.

---

## Tile 2 — Daily volume trend (per table, 14 days)

**Purpose.** Spot slow bleeds and spikes a single freshness check misses — a feed
that halves over a week, or a duplication loop doubling ingestion (and cost).

**Visual.** Multi-series time chart (one line per connector), 14-day daily bins,
with a faint band for each series' own trailing baseline.

**Sample KQL** (safe, read-only):
```kql
union isfuzzy=true
    (SigninLogs      | extend TableName = "SigninLogs"),
    (AuditLogs       | extend TableName = "AuditLogs"),
    (AzureActivity   | extend TableName = "AzureActivity"),
    (SecurityAlert   | extend TableName = "SecurityAlert"),
    (CyberArk_EPV_CL | extend TableName = "CyberArk_EPV_CL")
| where TimeGenerated > ago(14d)
| summarize Rows = count() by TableName, Day = bin(TimeGenerated, 1d)
| sort by Day asc
```

**Companion band check** (drives amber/red on the tile — deviation vs each
series' own 7-day average):
```kql
let today =
    union isfuzzy=true
        (SigninLogs | extend TableName = "SigninLogs"),
        (AuditLogs  | extend TableName = "AuditLogs"),
        (AzureActivity | extend TableName = "AzureActivity"),
        (SecurityAlert | extend TableName = "SecurityAlert"),
        (CyberArk_EPV_CL | extend TableName = "CyberArk_EPV_CL")
    | where TimeGenerated > ago(1d)
    | summarize Recent = count() by TableName;
let base =
    union isfuzzy=true
        (SigninLogs | extend TableName = "SigninLogs"),
        (AuditLogs  | extend TableName = "AuditLogs"),
        (AzureActivity | extend TableName = "AzureActivity"),
        (SecurityAlert | extend TableName = "SecurityAlert"),
        (CyberArk_EPV_CL | extend TableName = "CyberArk_EPV_CL")
    | where TimeGenerated between (ago(8d) .. ago(1d))
    | summarize Total = count() by TableName, bin(TimeGenerated, 1d)
    | summarize DailyAvg = avg(Total) by TableName;
today
| join kind=inner base on TableName
| extend RatioPct = round(100.0 * Recent / DailyAvg, 1)
| extend State = case(
    RatioPct between (40.0 .. 250.0), "Healthy",
    RatioPct between (25.0 .. 400.0), "Warning",
                                      "Failed")
| project TableName, Recent, DailyAvg = round(DailyAvg, 0), RatioPct, State
| sort by RatioPct asc
```

**Thresholds.** Healthy 40–250% of the trailing daily average; Warning 25–400%;
Failed outside that. A spike can be a real event storm — the tile prompts
investigation, it does not auto-conclude a fault.

---

## Tile 3 — Schema-drift (load-bearing fields)

**Purpose.** Catch the "green connector, dead detection" failure: rows arriving,
but a field a detection depends on has been renamed, dropped, or turned into
nulls. Freshness and volume both look fine while the detection quietly stops
matching.

**Visual.** A grid, one row per (table, load-bearing field), showing the
null/empty rate over 24h and its state.

**Sample KQL** (safe, read-only — one representative field per critical table):
```kql
let signin =
    SigninLogs | where TimeGenerated > ago(24h)
    | summarize Rows = count(), Bad = countif(isempty(IPAddress))
    | extend TableName = "SigninLogs", Field = "IPAddress";
let audit =
    AuditLogs | where TimeGenerated > ago(24h)
    | summarize Rows = count(), Bad = countif(isempty(tostring(InitiatedBy)))
    | extend TableName = "AuditLogs", Field = "InitiatedBy";
let activity =
    AzureActivity | where TimeGenerated > ago(24h)
    | summarize Rows = count(), Bad = countif(isempty(tostring(Properties)))
    | extend TableName = "AzureActivity", Field = "Properties";
let alerts =
    SecurityAlert | where TimeGenerated > ago(24h)
    | summarize Rows = count(), Bad = countif(isempty(AlertSeverity))
    | extend TableName = "SecurityAlert", Field = "AlertSeverity";
let cyberark =
    CyberArk_EPV_CL | where TimeGenerated > ago(24h)
    | summarize Rows = count(), Bad = countif(isempty(SafeName_s))
    | extend TableName = "CyberArk_EPV_CL", Field = "SafeName_s";
union signin, audit, activity, alerts, cyberark
| extend PctBad = iff(Rows == 0, real(null), round(100.0 * Bad / Rows, 2))
| extend State = case(
    Rows == 0,          "Unknown",
    PctBad < 2.0,       "Healthy",
    PctBad < 10.0,      "Warning",
                        "Failed")
| project TableName, Field, Rows, PctBad, State
| sort by State asc, PctBad desc
```

**Thresholds.** Healthy < 2% empty on the load-bearing field; Warning 2–10%;
Failed ≥ 10% (or the field/operation absent entirely). Extend the union with more
fields as detections are added — keep it aligned with the "expected minimum
fields" tables in the runbook.

---

## Tile 4 — Ingestion latency (p50 / p95)

**Purpose.** Show end-to-end delay between an event happening and it being
queryable, so scheduled rules with short look-backs don't silently skip
late-arriving data.

**Visual.** A bar/heat grid, one row per connector, showing p50 and p95 latency
in minutes against the stream's target.

**Sample KQL** (safe, read-only — uses `ingestion_time()`):
```kql
let lat = (T:string) {
    union isfuzzy=true
        (SigninLogs      | where TableName1 == "" | project TimeGenerated), // placeholder, replaced per-table below
        (SigninLogs      | take 0)
};
union isfuzzy=true
    (SigninLogs      | where TimeGenerated > ago(24h) | extend TableName = "SigninLogs"),
    (AuditLogs       | where TimeGenerated > ago(24h) | extend TableName = "AuditLogs"),
    (AzureActivity   | where TimeGenerated > ago(24h) | extend TableName = "AzureActivity"),
    (SecurityAlert   | where TimeGenerated > ago(24h) | extend TableName = "SecurityAlert"),
    (CyberArk_EPV_CL | where TimeGenerated > ago(24h) | extend TableName = "CyberArk_EPV_CL")
| extend LatencySec = datetime_diff('second', ingestion_time(), TimeGenerated)
| where LatencySec >= 0
| summarize
    p50Min = round(percentile(LatencySec, 50) / 60.0, 1),
    p95Min = round(percentile(LatencySec, 95) / 60.0, 1)
  by TableName
| extend Targetp95Min = case(
    TableName in ("SigninLogs", "AuditLogs"),        15.0,
    TableName in ("AzureActivity", "SecurityAlert"), 30.0,
    TableName == "CyberArk_EPV_CL",                  30.0,
                                                     30.0)
| extend State = case(
    p95Min <= Targetp95Min,        "Healthy",
    p95Min <= Targetp95Min * 2,    "Warning",
                                   "Failed")
| project TableName, p50Min, p95Min, Targetp95Min, State
| sort by p95Min desc
```

> The `lat` helper above is illustrative scaffolding only; the working query is
> the `union` block. Keep the union explicit (no dynamic table names) so the
> query stays safe and reviewable.

**Thresholds.** Healthy p95 within target (15 min identity, 30 min control-plane
/ product alerts); Warning up to 2× target; Failed beyond. If a stream sits in
Warning, widen the dependent rule's look-back window and record it, so rule
config and observed latency stay consistent (cross-reference Gate 5 of the
validation checklist).

---

## Tile 5 — Failed connectors (detail / drill-down)

**Purpose.** The DRI's action list. When Row 0's banner is red, this table says
exactly which connector, why, since when, and who owns it — enough to act without
opening five other tiles.

**Visual.** A red-highlighted detail table, one row per currently-failing
connector, with an owner column for direct escalation.

**Sample KQL** (safe, read-only — reuses the Tile 1 logic and keeps only failures):
```kql
let Sources = datatable(Connector:string, TableName:string, FreshnessSlaMin:long, Owner:string)
[
    "Entra sign-in",   "SigninLogs",        60,  "Priya Sharma (Identity Detection Eng.)",
    "Entra audit",     "AuditLogs",         60,  "Priya Sharma (Identity Detection Eng.)",
    "Azure Activity",  "AzureActivity",     120, "Dana Iyer (Cloud Security Eng.)",
    "Defender alerts", "SecurityAlert",     120, "Dana Iyer (Cloud Security Eng.)",
    "CyberArk",        "CyberArk_EPV_CL",   180, "Liam O'Connor (PAM liaison)"
];
let lastSeen =
    union isfuzzy=true
        (SigninLogs      | where TimeGenerated > ago(3d) | summarize Last = max(TimeGenerated) | extend TableName = "SigninLogs"),
        (AuditLogs       | where TimeGenerated > ago(3d) | summarize Last = max(TimeGenerated) | extend TableName = "AuditLogs"),
        (AzureActivity   | where TimeGenerated > ago(3d) | summarize Last = max(TimeGenerated) | extend TableName = "AzureActivity"),
        (SecurityAlert   | where TimeGenerated > ago(3d) | summarize Last = max(TimeGenerated) | extend TableName = "SecurityAlert"),
        (CyberArk_EPV_CL | where TimeGenerated > ago(3d) | summarize Last = max(TimeGenerated) | extend TableName = "CyberArk_EPV_CL");
Sources
| join kind=leftouter lastSeen on TableName
| extend MinsSinceLast = iff(isnull(Last), real(null),
                             todouble(datetime_diff('minute', now(), Last)))
| extend State = case(
    isnull(Last),                         "Failed (no data 3d)",
    MinsSinceLast > FreshnessSlaMin * 2,  "Failed (stale)",
    MinsSinceLast > FreshnessSlaMin,      "Warning",
                                          "Healthy")
| where State startswith "Failed" or State == "Warning"
| project Connector, TableName, LastReceivedUtc = Last, MinsSinceLast,
          FreshnessSlaMin, State, Owner
| sort by State asc, MinsSinceLast desc
```

**Behaviour.** Empty table = board is green (the good state). Any row here is a
detection-coverage incident: page the named owner per the `docs/DRI_RUNBOOK.md`
SLA matrix, and treat the detections that depend on that connector as uncovered
until it recovers.

---

## Row 0 — Failed / stale connectors banner

**Purpose.** A single, unmissable indicator at the very top: is anything down
right now? It is a count, not a chart, so a glance is enough.

**Sample KQL** (safe, read-only — reuses Tile 5's result, counted):
```kql
// Wrap the Tile 5 query as `FailedConnectors`, then:
FailedConnectors
| where State startswith "Failed"
| summarize FailedCount = count()
| extend Banner = iff(FailedCount == 0,
                      "All connectors healthy",
                      strcat(FailedCount, " connector(s) FAILED — see Tile 5"))
```

**Behaviour.** Green with "All connectors healthy" when the count is zero; red
banner with the count otherwise. This is the first pixel the DRI reads.

---

## Operating the dashboard

- **Cadence.** Auto-refresh 15 min; the DRI glances at Row 0 and Tile 1 each
  shift start; connector owners own their rows. Reviewed in full at the weekly
  operations review alongside SLA breaches and MITRE coverage deltas.
- **From tile to action.** A red tile maps to a runbook section
  (`CONNECTOR_RUNBOOK.md` §1–7) for the fix, and a failing connector is
  re-cleared through `CONNECTOR_VALIDATION_CHECKLIST.md` before its detections
  are trusted again.
- **Safety.** Every query here is read-only and observational. The dashboard
  never triggers a response — response stays human-approved through the SOAR
  playbooks, consistent with the estate's automate-vs-approve boundary.
- **Honesty.** If a connector is down, the board says so and the dependent
  detections are marked uncovered. A dashboard that hides a blind spot is worse
  than no dashboard — the point of this one is that coverage gaps are visible,
  not buried.
