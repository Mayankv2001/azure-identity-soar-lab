# Tuning Backlog (Sample)

A small, illustrative tuning backlog for the detections in this lab. It shows the
shape a real detection-engineering team's backlog takes: each row is a rule, an
observed symptom, the narrowest proposed change, the promotion state the change
sits in, and the named owner accountable for it.

> Illustrative and synthetic. Every persona is fictional (`@contoso.com`) and no
> rule here is production approved — the states below are lab/candidate states,
> not claims of a live production estate. This backlog is the standing output of
> the weekly noise roll-up ([noise-review-sample.json](noise-review-sample.json))
> and the monthly owner review described in
> [DETECTION_TUNING_PROCESS.md](DETECTION_TUNING_PROCESS.md#monthly-owner-review).

## Owners

| Persona | Team | Detections owned |
|---------|------|------------------|
| priya.raman@contoso.com | Identity Detection Engineering | DET-001 … DET-007 |
| diego.santos@contoso.com | Cloud Security Engineering | CP-DET-001 … CP-DET-008 |

## Backlog

| ID | Rule | Symptom | Proposed change | State | Owner |
|----|------|---------|-----------------|-------|-------|
| TB-01 | DET-002 Impossible Travel | Corporate VPN egress nodes in different cities read as >900 km/h travel (3/6 alerts in 2026-W26 were benign). | Scoped `both_endpoints_in_cidr` exclusion on the VPN range `198.51.100.0/24`; bump to v1.1.0; add paired negative + positive regression tests. **Done** in the lab as the reference tuning example. | Simulated (re-validated after change) | priya.raman@contoso.com |
| TB-02 | DET-001 MFA Fatigue | Legitimate multi-device re-registration during a laptop refresh generates a burst of prompts that resembles push bombing. | Add an exclusion for prompt bursts correlated with an approved device-enrolment change record; keep escalation to Critical on any *approved* prompt after a burst. | Draft (evidence gathering) | priya.raman@contoso.com |
| TB-03 | DET-004 Service Principal Credential Added | Approved DevOps pipeline rotates an SP secret on schedule and fires the rule (`approved_pipeline_rotation`). | Exclude credential-add events whose actor SP is on the `ApprovedRotationPipelines` watchlist; keep firing for human-added credentials on high-privilege apps. | Audit-only (FP review against real data) | priya.raman@contoso.com |
| TB-04 | DET-005 Privileged Role/Group Addition | Change-window role activations with a linked change record fire alongside genuine self-elevation. | Suppress only when a matching approved change record is correlated within the window; retain Critical escalation on self-elevation with no change record. | Draft (needs change-record join design) | priya.raman@contoso.com |
| TB-05 | DET-006 CyberArk Checkout Anomaly | No baseline yet for per-user checkout cadence, so first-week volume is noisy for high-frequency operators. | Add UEBA-style per-user baselining before enablement; hold at Audit-only until a 30-day baseline exists. Documented known limitation. | Audit-only (baselining) | priya.raman@contoso.com |
| TB-06 | DET-007 Stale/Orphaned Privileged Account | Low-severity posture findings crowd the queue when run daily against a large watchlist. | Move to a weekly cadence and route to a posture backlog rather than the paging queue; keep High severity only for truly orphaned (no owner) accounts. | Limited enablement (cadence change) | priya.raman@contoso.com |
| TB-07 | CP-DET-003 Privileged Role Activation Without Change Record | Emergency break-glass activations legitimately have no change record and fire as ticketless. | Exclude activations by the break-glass accounts on the `BreakGlassIdentities` watchlist; alert instead via a separate low-noise break-glass-usage rule. | Draft (needs break-glass watchlist) | diego.santos@contoso.com |
| TB-08 | CP-DET-006 NSG/Firewall Rule Opened to Internet | Approved short-lived maintenance windows open a management port to a specific admin CIDR and fire as an internet exposure. | Distinguish `0.0.0.0/0` (keep Critical) from a narrow approved admin CIDR opened during a linked change window (downgrade + auto-close-on-expiry check). | Audit-only (real-data volume check) | diego.santos@contoso.com |
| TB-09 | CP-DET-004 Credential Added to High-Privilege Service Principal | Same `approved_pipeline_rotation` benign cause as TB-03, on the control-plane side. | Share the `ApprovedRotationPipelines` watchlist exclusion with DET-004; keep Critical for any interactive/human actor. | Draft (share watchlist with TB-03) | diego.santos@contoso.com |
| TB-10 | CP-DET-001 Risky Sign-in From Unusual Location | Travelling executives and a new regional office trip the "unusual country" logic during onboarding weeks. | Feed an allow-list of expected travel countries from the HR travel calendar / new-site list; retain firing for genuinely unexpected geographies. | Draft (data-source dependency) | diego.santos@contoso.com |

## How to read this backlog

- **State reflects the promotion state** in
  [DETECTION_PROMOTION_GATES.md](DETECTION_PROMOTION_GATES.md), not a generic
  "todo/doing/done". A row moves right only when its gate passes, and can move
  back on a failed gate or a regression.
- **Every proposed change is the narrowest safe form.** No row proposes disabling
  a rule or a broad user/host suppression — each targets a specific benign cause
  with a scoped exclusion, watchlist, or cadence change, and (per the tuning
  process) will carry a paired true-positive regression test before it merges.
- **Shared benign causes are shared once.** TB-03 and TB-09 are the same
  `approved_pipeline_rotation` cause across the two labs and are tuned with one
  shared watchlist, not two divergent exclusions — a small example of keeping the
  estate coherent.
- **The backlog is owned.** Each row has a single accountable owner who carries it
  through the monthly review until it is closed or promoted.

Only **TB-01** is realised in code today (the DET-002 v1.1.0 exclusion); the rest
are illustrative next steps that demonstrate how noise data becomes a prioritised,
owned, honestly-scoped tuning plan.
