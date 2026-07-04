# Connector Validation Checklist

A go/no-go checklist to run **before you rely on a connector** — at onboarding, and
again whenever a detection that depends on it is promoted, re-tuned, or starts
behaving oddly. A connector is not "done" when data appears; it is done when
freshness, volume, schema, field completeness, latency and access have all been
confirmed against a defined threshold.

**Honest lab framing.** This is a synthetic, offline-first lab mirroring Microsoft
Sentinel concepts; no connector here is deployed to a production tenant. The
thresholds below are illustrative reference values a real SOC would baseline
per-tenant — they are a sensible starting point, not measured production figures.
All KQL is **read-only and safe**. All identities are fictional `@contoso.com`
personas. No secrets, real emails, GUIDs or subscription IDs appear anywhere.

Use it with the per-connector detail in `CONNECTOR_RUNBOOK.md` and the continuous
view in `CONNECTOR_HEALTH_DASHBOARD_SPEC.md`.

---

## How to score a connector

Run the seven gates below in order. Record a **Pass / Fail / N/A** for each, with
the observed value. A connector is **cleared for reliance only when every
applicable gate passes.** A single Fail blocks reliance until remediated or an
explicit, time-boxed exception is recorded in
`production-readiness/change-approval/`.

| Gate | Question it answers | Blocking? |
|------|---------------------|-----------|
| 1. Freshness | Is data still arriving *now*? | Yes |
| 2. Volume | Is the amount of data sane vs baseline? | Yes |
| 3. Schema | Are the expected columns present and typed? | Yes |
| 4. Field completeness | Are the *load-bearing* fields populated, not just present? | Yes |
| 5. Latency | Is end-to-end delay within the detection's tolerance? | Yes |
| 6. RBAC | Least privilege to read; no over-grant to configure? | Yes |
| 7. Detection wiring | Does the dependent rule actually fire on a known-good input? | Yes |

Set the connector-specific inputs once, then reuse them:

```kql
// --- Edit these two lines per connector, then run the gate queries below ---
let TableName   = "SigninLogs";     // e.g. AuditLogs, AzureActivity, SecurityAlert, CyberArk_EPV_CL
let FreshnessSLA = 60m;             // max acceptable minutes since last row (see per-connector table)
```

> The gate queries below are written explicitly per table for clarity and safety
> (no dynamic table names, nothing that could mutate data). Swap in the table you
> are validating.

---

## Gate 1 — Freshness

**Definition.** Time since the most recent `TimeGenerated` is within the
connector's freshness SLA. This is the single most important gate: a stale
connector is a silent blind spot.

**Threshold (illustrative, baseline per tenant):**

| Connector | Table | Freshness SLA | Rationale |
|-----------|-------|---------------|-----------|
| Entra sign-in | `SigninLogs` | ≤ 60 min | High-volume, near-real-time expected |
| Entra audit | `AuditLogs` | ≤ 60 min | High-volume directory changes |
| Azure Activity | `AzureActivity` | ≤ 120 min | ARM control-plane, slightly higher latency |
| Defender alerts | `SecurityAlert` | ≤ 120 min | Product-generated, batched |
| NSG rule writes | `AzureActivity` | event-driven | Empty is normal; check *last known* write, not "recent" |
| CyberArk | `CyberArk_EPV_CL` | ≤ 180 min | Low-volume; longer gaps tolerated but watched twice daily |
| Watchlists | `_GetWatchlist(...)` | N/A (not time-series) | Use Gate 2/3 instead |

**Check (example — sign-in):**
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| summarize LastReceivedUtc = max(TimeGenerated)
| extend MinsSinceLast = datetime_diff('minute', now(), LastReceivedUtc)
| extend FreshnessGate = iff(MinsSinceLast <= 60, "PASS", "FAIL")
```

**Pass:** `FreshnessGate == "PASS"`.
**Fail action:** Treat as a coverage incident; check diagnostic settings /
connector state / publisher credential per the runbook, and page the owning
persona.

---

## Gate 2 — Volume

**Definition.** Row count over a representative window is within a sane band of
the connector's own recent baseline — neither collapsed (feed dying) nor
exploding (loop, duplication, or an actual event storm worth knowing about).

**Threshold.** Compare the last 24h against the trailing 7-day daily average;
alert outside roughly **40%–250%** of baseline. Bands are per-tenant; the point
is *relative* deviation, not an absolute number.

**Check (example — audit):**
```kql
let recent =
    AuditLogs | where TimeGenerated > ago(24h) | count | project Recent = Count;
let baseline =
    AuditLogs
    | where TimeGenerated between (ago(8d) .. ago(1d))
    | summarize Total = count() by bin(TimeGenerated, 1d)
    | summarize DailyAvg = avg(Total);
recent
| extend DailyAvg = toscalar(baseline)
| extend RatioPct = round(100.0 * Recent / DailyAvg, 1)
| extend VolumeGate = iff(RatioPct between (40.0 .. 250.0), "PASS", "REVIEW")
```

**Pass:** `VolumeGate == "PASS"`.
**Review (not auto-fail):** Volume outside the band is a prompt to investigate,
not always a fault — a genuine event storm is real signal. Confirm cause before
clearing or escalating.

---

## Gate 3 — Schema

**Definition.** The columns the dependent detections read exist, with the
expected names and types. Catches the "green connector, dead detection" class
where data flows but a field was renamed or dropped.

**Check (example — Azure Activity, confirming the NSG operation shape):**
```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue ==
    "Microsoft.Network/networkSecurityGroups/securityRules/write"
| extend SourcePrefix = tostring(Properties.sourceAddressPrefix),
         Access       = tostring(Properties.access)
| summarize
    Rows          = count(),
    HasSourcePfx  = countif(isnotempty(SourcePrefix)),
    HasAccess     = countif(isnotempty(Access))
| extend SchemaGate = iff(Rows == 0 or (HasSourcePfx > 0 and HasAccess > 0),
                          "PASS", "FAIL")
```

**Expected minimum columns per table** (must exist and be non-degenerate):

| Table | Load-bearing columns |
|-------|----------------------|
| `SigninLogs` | `TimeGenerated`, `UserPrincipalName`, `IPAddress`, `ResultType`, `LocationDetails`, `AppDisplayName` |
| `AuditLogs` | `TimeGenerated`, `OperationName`, `Category`, `InitiatedBy`, `TargetResources`, `Result` |
| `AzureActivity` | `TimeGenerated`, `OperationNameValue`, `ActivityStatusValue`, `Caller`, `_ResourceId`, `Properties` |
| `SecurityAlert` | `TimeGenerated`, `AlertName`, `AlertSeverity`, `ProductName`, `Entities` |
| `CyberArk_EPV_CL` | `TimeGenerated`, `EventType_s`, `Username_s`, `SafeName_s`, `AccountName_s`, `TicketId_s` |
| Watchlists | Resolve via `_GetWatchlist(...)` and expose their key column(s) |

**Pass:** all listed columns present and correctly typed.
**Fail action:** Flag schema drift; freeze reliance on the affected detection and
open a tuning/fix item — the rule may need a parser update.

---

## Gate 4 — Field completeness

**Definition.** The load-bearing fields are actually **populated**, not merely
present as empty columns. A column of nulls passes Gate 3 but fails a detection.

**Threshold.** Null/empty rate on each load-bearing field below **2%** over 24h
(tune per tenant; some fields are legitimately sparse and marked N/A).

**Check (example — sign-in):**
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| summarize
    Rows        = count(),
    NullUser    = countif(isempty(UserPrincipalName)),
    NullIp      = countif(isempty(IPAddress)),
    NullResult  = countif(isempty(ResultType))
| extend
    PctNullUser = round(100.0 * NullUser / Rows, 2),
    PctNullIp   = round(100.0 * NullIp   / Rows, 2)
| extend CompletenessGate =
    iff(PctNullUser < 2.0 and PctNullIp < 2.0, "PASS", "FAIL")
```

**Pass:** every load-bearing field under the null-rate threshold.
**Fail action:** Identify which upstream category/mapping is incomplete (e.g.
only non-interactive sign-ins routed → sparse `IPAddress`); fix routing before
relying on the detection.

---

## Gate 5 — Latency

**Definition.** End-to-end delay from event occurrence to queryable in the
workspace — the gap between the event's own timestamp and its ingestion time.
Distinct from freshness (which only asks "did anything arrive recently"). A
scheduled analytics rule with a 5-minute look-back will miss events that land 20
minutes late even if the connector looks "fresh".

**Threshold.** p95 ingestion latency within the dependent rule's look-back
window, with margin. Illustrative target: **p95 ≤ 15 min** for identity streams,
**≤ 30 min** for control-plane/product-alert streams.

**Check (example — audit, using the ingestion-time function):**
```kql
AuditLogs
| where TimeGenerated > ago(24h)
| extend LatencySec = datetime_diff('second', ingestion_time(), TimeGenerated)
| summarize
    p50 = percentile(LatencySec, 50),
    p95 = percentile(LatencySec, 95),
    p99 = percentile(LatencySec, 99)
| extend LatencyGate = iff(p95 <= 900, "PASS", "REVIEW")   // 900s = 15 min
```

**Pass:** `p95` within the target for the stream.
**Review action:** If p95 exceeds the rule's look-back, widen the rule's window
or lengthen its bin — otherwise late-arriving events are silently skipped. Record
the chosen window so freshness and rule config stay consistent.

---

## Gate 6 — RBAC

**Definition.** Access is least-privilege in both directions: the identities that
**read** the connector's data hold only Reader-level roles, and the elevated
roles used to **configure** it were granted for enablement and then reviewed
down.

**Checklist (manual, cross-checked against `production-readiness/rbac/`):**

- [ ] Validation/analytics readers hold **Microsoft Sentinel Reader** or **Log
      Analytics Reader** — not Contributor. No runbook query needs write.
- [ ] Connector configuration roles (Security Admin, subscription
      Contributor/Owner, Sentinel Contributor) are **assigned to named owners
      only**, time-boxed or reviewed, not standing broad grants.
- [ ] Ingestion publisher identities (CyberArk Logs Ingestion API service
      principal / managed identity) hold **only** `Monitoring Metrics Publisher`
      on the specific DCR — nothing wider.
- [ ] Ingestion secrets live in a secret store (Key Vault), are referenced not
      committed, and have a rotation owner recorded. **No secret is in the repo.**
- [ ] Watchlist authoring is limited to the owning persona(s) via **Sentinel
      Contributor**; everyone else reads via `_GetWatchlist`.

**Pass:** every box ticked.
**Fail action:** Raise an RBAC finding; over-grants are remediated before the
connector is cleared, because an over-privileged reader is itself an attack path.

---

## Gate 7 — Detection wiring (end-to-end proof)

**Definition.** The connector isn't just delivering data — the **dependent
detection actually fires** on a known-good input and stays silent on a benign
look-alike. This is the difference between "the pipe is connected" and "the
alarm works".

**How (safe, in-lab):**
- Run the offline mirror first — `python3 src/main.py --demo` — which
  deterministically drives every detection over the synthetic dataset and is the
  authoritative functional test.
- In a live workspace (Mode C, lab subscription only), validate against the
  purple-team pack (`security-engineering/purple-team-validation.md`): each
  detection has a safe, simulation-based positive case and its benign twin.
- Confirm with a read-only KQL that the rule's own logic returns the expected
  row on the seeded positive and nothing on the benign case. Never generate real
  malicious activity or run attack tooling — the whole design is safe synthetic
  demonstration.

**Check (example — CyberArk / DET-006 positive shape, read-only):**
```kql
CyberArk_EPV_CL
| where TimeGenerated > ago(1d)
| where EventType_s == "PasswordCheckout" and isempty(TicketId_s)
| summarize Checkouts = count() by Username_s, Window = bin(TimeGenerated, 1h)
| where Checkouts >= 4          // the burst threshold DET-006 uses
| project Username_s, Window, Checkouts
```
A seeded ticketless burst should surface here; a clean day should return nothing.

**Pass:** dependent rule fires on the positive, is silent on the benign twin.
**Fail action:** The connector data is fine but the rule is mis-wired
(wrong field, wrong threshold) — route to detection tuning, not connector ops.

---

## Sign-off record

Record the outcome so reliance is auditable. Store completed checklists alongside
the change-approval record for the detection that depends on the connector.

| Field | Value |
|-------|-------|
| Connector | _e.g. Entra ID sign-in logs_ |
| Table | _e.g. `SigninLogs`_ |
| Validated by | _named persona, e.g. Priya Sharma (`priya.sharma@contoso.com`)_ |
| Date (Australia/Sydney) | _YYYY-MM-DD_ |
| Gate 1 Freshness | Pass / Fail — observed value |
| Gate 2 Volume | Pass / Review — ratio vs baseline |
| Gate 3 Schema | Pass / Fail — missing columns, if any |
| Gate 4 Field completeness | Pass / Fail — worst null rate |
| Gate 5 Latency | Pass / Review — p95 |
| Gate 6 RBAC | Pass / Fail — over-grants found |
| Gate 7 Detection wiring | Pass / Fail — rule(s) exercised |
| Overall | **Cleared / Blocked** |
| Exception (if any) | change-approval reference + expiry |

**Cleared** means: every applicable gate passed, or a Fail has a signed,
time-boxed exception recorded in `production-readiness/change-approval/`. Until
then the connector is **Blocked** and the dependent detections are treated as
uncovered — stated plainly, because pretending a blind detection is live is worse
than admitting it is down.
