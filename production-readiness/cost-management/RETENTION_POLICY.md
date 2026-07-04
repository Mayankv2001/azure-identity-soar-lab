# Retention Policy (Illustrative)

> **Illustrative only.** This is a lab planning document for an offline
> Sentinel-style project. The retention values below are examples for reasoning
> about the cost/investigation trade-off, not a policy applied to any real
> tenant. The lab's own workspace is provisioned at a flat **30-day** retention
> (`infra/sentinel/modules/log-analytics-workspace.bicep`) for cost safety; the
> tiered policy here is what a **production** workspace would use instead.
> Confirm current retention limits and pricing for **Australia East** before
> adopting any of this.

## 1. Retention tiers

Microsoft Sentinel / Log Analytics separates retention into two mechanisms, and
using both correctly is where cost is controlled without losing
investigability.

| Tier | What it is | Query behaviour | Cost posture |
|------|------------|-----------------|--------------|
| **Interactive (Analytics tier)** | Hot, immediately queryable data | Full KQL, joins, analytics rules, workbooks | First 90 days included with Sentinel; days 91+ billed per GB/month |
| **Archive** | Cold, low-cost long-term storage | Requires **search job** or **rehydration** before normal KQL | Much lower per GB/month; rehydration/search billed per use |

The design rule:

- **Interactive retention** = the window where you need data *live* for
  correlation, hunting, and analytics rules to run. This is what makes a
  detection able to look back N days.
- **Archive retention** = the tail beyond that, kept only because a
  regulator, contract, or forensic policy requires it. Cheap to store,
  deliberate (and billable) to read.
- **Total retention** = interactive + archive, per table.

Two cost facts that drive the whole policy:

1. **Analytics rules and interactive KQL only see interactive-tier data.** If a
   detection needs to look back 30 days, that table needs >= 30 days
   *interactive*, not just total. Setting interactive too short silently breaks
   look-back detections.
2. **Archive is not instant.** Reading archived data needs a search job or
   rehydration and costs money and time - so archive is for compliance and
   cold forensics, not day-to-day triage.

## 2. Per-table retention matrix (illustrative)

Flat retention is a cost anti-pattern. This matrix sets interactive and total
retention per table, sized to how far back each is genuinely investigated. The
first four telemetry tables (plus watchlists) are what the lab's 15 detections
actually use; the rest are illustrative production sources.

| Table | Tier used | Interactive (hot) | Archive (cold) | Total retention | Why |
|-------|-----------|-------------------|----------------|-----------------|-----|
| `SigninLogs` | Analytics | 90 days | +275 days | ~1 year | Identity investigations reach back weeks; 1yr covers most audit needs |
| `AuditLogs` | Analytics | 90 days | +275 days | ~1 year | Directory/role changes need a long, queryable audit trail |
| `AzureActivity` | Analytics | 90 days | +640 days | ~2 years | Control-plane forensics + common compliance windows |
| `CyberArk_EPV_CL` | Analytics | 90 days | +640 days | ~2 years | Tier-0 privileged access - keep the audit trail long |
| Watchlists (`CAPolicyAdmins`, `HighPrivilegeApps`, `PrivilegedIdentities`) | Reference | effectively permanent | n/a | permanent | Tiny, high-value lookup data - version-controlled, not telemetry |
| `SecurityEvent` (illustrative) | Analytics/Basic | 30 days | +155 days | ~6 months | High volume, low per-event value - short hot window, modest archive |
| `Syslog` / firewall (illustrative) | Basic/Auxiliary | 30 days | +60 days | ~90 days | Very high volume - Basic tier, minimal retention unless a rule needs more |

Reading the matrix:

- **Identity and privileged tables** (`SigninLogs`, `AuditLogs`,
  `CyberArk_EPV_CL`) get the **longest hot window** because that is where
  investigations actually reach back - and they are lower-volume, so the cost of
  keeping them hot is affordable.
- **High-volume network/host tables** get the **shortest hot window** and lean on
  the Basic tier and short archive, because their cost-per-value is poor and
  they are rarely queried at 90-day depth.
- **Watchlists** are reference data and effectively permanent - they cost
  nothing and losing them breaks detection precision.

## 3. Interactive-retention floors set by detections

Interactive retention must never be shorter than the longest look-back any live
detection needs on that table, or the detection silently degrades. From the
lab's rules:

| Table | Longest look-back in lab rules | Interactive floor required |
|-------|--------------------------------|----------------------------|
| `SigninLogs` | Impossible-travel / burst windows (minutes to hours) | Comfortably covered by 90 days |
| `AuditLogs` | Role/CA/SP change correlation (hours) | Comfortably covered by 90 days |
| `AzureActivity` | Correlated chain window (CP-DET-008, ~4h) | Comfortably covered by 90 days |
| Watchlist-backed | DET-007 stale-account (60d), DET-006 (window) | Watchlist is reference; the 60d look-back reads recent sign-in state, covered by 90 days |

The 90-day interactive floor on the identity tables leaves generous headroom
above every rule's look-back window, which is deliberate - it lets an analyst
manually reach back further than any single rule during an investigation.

## 4. Archive strategy

- **Archive only what has a retention requirement.** Archiving noise just relocates
  the cost. Filter at the DCR first (see the cost model), then archive what
  survives.
- **Rehydrate/search deliberately.** Reaching into archive during an incident is
  a billable, planned action - budget analyst time and cost for it rather than
  assuming "we can always look it up" is free.
- **Prefer search jobs over full rehydration** where the platform supports it -
  a targeted search job over archived data is usually cheaper than rehydrating a
  whole time range into the interactive tier.

## 5. Governance

- **Owner:** Cloud Security Engineering (consistent with the detection-rule
  owners in this repo).
- **Review cadence:** retention settings reviewed quarterly, and whenever a new
  data connector is onboarded (a new table must arrive with an explicit
  interactive/archive/total decision - no table inherits a flat default
  silently).
- **Change control:** any reduction in retention on identity or privileged tables
  goes through change review, because shortening retention can quietly remove an
  investigation's evidence and weaken a look-back detection.
- **Compliance alignment:** total-retention values on `AzureActivity` and
  `CyberArk_EPV_CL` should be reconciled against the organisation's actual audit
  and regulatory obligations before adoption - the ~2-year figures here are
  illustrative, not a legal recommendation.

## 6. Lab vs. production

| Setting | This lab (offline / test) | Illustrative production |
|---------|---------------------------|-------------------------|
| Retention model | Flat 30 days, `immediatePurgeDataOn30Days: true` | Per-table interactive + archive matrix (section 2) |
| Rationale | Cost safety; synthetic data has no audit value | Investigation depth + compliance, balanced against per-GB cost |
| Cleanup | Delete the resource group when finished | Lifecycle-managed, reviewed quarterly |

The lab keeps it flat and short on purpose. The point of this document is to show
the **production reasoning** - per-table tiers, interactive floors driven by
detections, and archive reserved for genuine compliance need - without applying
any of it to a real tenant.

## 7. Honest caveats

- Retention maximums, the size of the included interactive window, and archive
  behaviour are platform features that change over time - verify current limits
  for Australia East before adopting these numbers.
- The day counts here are illustrative planning figures, not measured or
  legally-derived requirements.
- Real retention design must be reconciled with the organisation's data-residency,
  privacy, and records-management obligations, which are out of scope for a lab.
