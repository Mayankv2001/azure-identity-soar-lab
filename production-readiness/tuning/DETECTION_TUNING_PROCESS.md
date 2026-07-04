# Detection Tuning Process

How a detection moves from an idea to a production-approved analytics rule in
this lab's model, how false positives are labelled and fed back into the rule,
how tuning changes are proposed and reviewed, and how true positives are
protected so tuning never quietly blinds a working detection.

> **Honest framing.** This is a synthetic, offline lab that mirrors Microsoft
> Sentinel and Azure concepts. **None of the 15 detections in this repository is
> production approved.** Every rule is a *candidate* that still requires
> tenant-specific baselining, false-positive review against real telemetry, and
> a documented deployment approval before it earns the "production" label. See
> the [Detection Quality Scorecard](../../security-engineering/detection-quality-scorecard.md):
> its top band is deliberately named "production *candidate*", not "production
> ready". This document describes the discipline that would move a candidate the
> rest of the way — it does not assert that any rule has already made the trip.

## Where this fits

This process extends, rather than replaces, two existing artefacts:

- The **[detection promotion checklist](../../security-engineering/kql-test-harness.md#detection-promotion-checklist)**
  in the KQL Test Harness — the eight-step Dev → Post-deployment monitoring
  lifecycle. The promotion *states* below are that checklist expressed as
  explicit, named stages with an owner and an exit gate each.
- The **[gates](DETECTION_PROMOTION_GATES.md)** each state must pass — the
  companion document that lists exactly what must be true to leave a state.

The tuning artefacts that feed this process live alongside it:
[FALSE_POSITIVE_REVIEW_TEMPLATE.md](FALSE_POSITIVE_REVIEW_TEMPLATE.md),
[TUNING_BACKLOG_SAMPLE.md](TUNING_BACKLOG_SAMPLE.md), and the machine-readable
[noise-review-sample.json](noise-review-sample.json).

## Promotion states

A detection is always in exactly one state. Movement is one state at a time,
forward only, and every transition is recorded in the pull request that carries
the change. A rule can be sent *back* a state at any time if a gate fails or a
regression appears — demotion is a normal, healthy outcome, not a failure.

```
Draft ──▶ Simulated ──▶ Audit-only ──▶ Limited enablement ──▶ Production candidate ──▶ Production approved
  ▲           │              │                  │                       │
  └───────────┴──────────────┴──────────────────┴───────────────────────┘
                        demotion on failed gate or regression
```

| # | State | What it means | Alerts visible to analysts? | Exit gate (summary) |
|---|-------|---------------|------------------------------|---------------------|
| 1 | **Draft** | KQL and its Python mirror authored; thresholds documented in the query header; a benign look-alike identified. | No | Peer review of logic, MITRE mapping and FP guidance. |
| 2 | **Simulated** | Positive and negative samples run in a staging workspace (or the offline Python mirror). Expected alert count confirmed. | No (staging only) | Simulation evidence attached: exact positive/negative counts, scan volume, run time. |
| 3 | **Audit-only** | Deployed to production data **disabled from paging** — it writes to a shadow table / audit stream but raises no analyst-facing alert. Used to observe true volume against real telemetry. | No (recorded, not paged) | False-positive review against a real historical window; benign firings quantified and tuned. |
| 4 | **Limited enablement** | Enabled for a narrow scope — one business unit, one region, or a canary user population — with an explicit rollback switch. | Yes, for the scoped population | Scoped precision acceptable; rollback plan tested; on-call briefed. |
| 5 | **Production candidate** | Enabled tenant-wide but under heightened monitoring, with an alert-volume canary that pages if it floods the queue. | Yes, tenant-wide | Post-deployment monitoring window clean; owner sign-off; no open regression. |
| 6 | **Production approved** | Steady-state, owned, on the monthly review cycle. Only a rule that has cleared every prior gate reaches here. | Yes, tenant-wide | (Steady state — subject to monthly owner review and change control for any edit.) |

**Current repository status:** every detection in `detections/` and
`modules/datacenter-control-plane/detections/` sits at **Draft/Simulated** —
authored, peer-reviewable, and validated against synthetic positives and
negatives by the pytest suite. States 3–6 require a real tenant and are
documented here as the production path, not claimed as done.

## How false positives are labelled

A false positive is not "an alert the analyst did not like". It is a specific,
recorded disposition with a benign root cause. Labelling is deliberately
structured so the data can drive tuning rather than opinion.

Every closed alert receives exactly one **disposition**:

| Disposition | Meaning | Feeds tuning? |
|-------------|---------|---------------|
| `true_positive` | Real malicious or policy-violating activity. | No — protected (see below). |
| `benign_positive` | The activity genuinely happened but is authorised (e.g. an approved admin action). The rule was *right* to fire; the environment context makes it benign. | Sometimes — via scoped exclusion, never suppression of the technique. |
| `false_positive` | The rule fired on activity that does not match its intent (e.g. VPN egress read as impossible travel). | Yes — this is the primary tuning input. |
| `indeterminate` | Insufficient evidence to decide. | No — escalate or gather more telemetry. |

For every `false_positive` and `benign_positive`, the analyst records a
**benign cause** in controlled language so the same cause can be counted across
weeks. The recurring causes in this lab's model are, for example:

- `corp_vpn_egress` — two corporate VPN/SASE nodes in different cities read as
  impossible travel (the seeded DET-002 case, incident INC-1005).
- `mobile_carrier_nat` — carrier NAT geolocating far from the user.
- `approved_pipeline_rotation` — a DevOps pipeline rotating a service principal
  secret on schedule, seen by DET-004 / CP-DET-004.
- `scheduled_admin_change` — a change-window role activation with a linked
  change record, seen by DET-005 / CP-DET-003.

The labelled dispositions are aggregated weekly per rule — see
[noise-review-sample.json](noise-review-sample.json) for the shape
(`{rule, week, alert_count, fp_count, benign_cause, action}`). That weekly roll-up
is what makes a rule's *precision* and *false-positive rate* visible, and it is
the raw material for the [tuning backlog](TUNING_BACKLOG_SAMPLE.md).

## How tuning changes are proposed

Tuning is a code change, not a console click. It follows the same
detection-as-code path as any rule edit, because an exclusion is part of the
detection's logic and must be reviewable, testable and revertible.

1. **Evidence first.** A tuning change starts from labelled data — at least one
   week of dispositions showing a recurring benign cause — not from a single
   noisy shift. The evidence is captured on a
   [False-Positive Review](FALSE_POSITIVE_REVIEW_TEMPLATE.md) form.
2. **Propose the narrowest change.** The proposed exclusion is scoped as tightly
   as the benign cause allows: a specific CIDR pair, a named service principal, a
   specific change-record correlation — never a blanket "suppress this rule for
   this user". The DET-002 v1.1.0 exclusion is the reference example: a
   `both_endpoints_in_cidr` guard on the single corporate VPN egress range
   (`198.51.100.0/24`), not a mute on impossible travel.
3. **Version the rule.** The YAML `version` is bumped (semantic) and the
   `description` records *why* the exclusion exists and which incident/evidence
   justified it. DET-002 carries exactly this: "Version 1.1.0 adds an exclusion
   for pairs where both IP addresses sit inside the corporate VPN egress range,
   after triage confirmed…".
4. **Add a regression test that the exclusion is safe.** Before merge, add a
   negative test proving the benign cause no longer fires **and** a positive test
   proving the malicious variant of the same shape still fires (see next section).
5. **Peer review and gate.** The change enters the promotion pipeline at the
   state appropriate to its risk. A pure exclusion on a Production-approved rule
   still goes through peer review, simulation, and — where the change is
   material — a fresh false-positive review window before re-approval. It does
   not silently ship.

Broad suppression, disabling a rule to stop noise, or widening a threshold
without evidence are explicitly **not** tuning — they are outages waiting to be
discovered. The process is designed to make the narrow, tested, versioned path
the path of least resistance.

## How true positives are protected (regression tests)

The failure mode that tuning must guard against is a well-meaning exclusion that
also swallows a real attack. Every exclusion is therefore paired with a
**true-positive regression test** that would fail if the exclusion ever grew too
wide.

The mechanism already exists in this repo and is the backbone of the guarantee:

- Each detection is three synchronised artefacts — KQL, YAML, and a Python mirror
  in `src/detection_engine.py` — and the pytest suite asserts a matched
  **positive** and **negative** sample for every rule (see
  [kql-test-cases.json](../../security-engineering/kql-test-cases.json), one case
  per detection, all 15). A tuning change that broke a positive assertion fails
  CI and cannot merge.
- When an exclusion is added, the review requires a **paired test**:
  - a *negative* case reproducing the exact benign cause (must now stay silent),
    and
  - a *positive* case that is the malicious twin of that benign cause — same
    surface shape, hostile intent — which **must still alert**.

  For DET-002, that pairing is: two IPs both inside `198.51.100.0/24` →
  silent (benign VPN); two IPs implying >900 km/h where at least one is *outside*
  the VPN range → still fires (real impossible travel). The exclusion removed the
  seeded false-positive class with **zero lost true positives**, and the test
  suite is what makes "zero lost" a checkable claim rather than a hope.
- The paired positive test becomes a permanent **regression guard**. If a future
  tuning change widened the VPN CIDR, or added a second exclusion that
  overlapped the attack path, the positive assertion would fail and block the
  merge. True positives are protected by making their disappearance a build
  failure.

This is the honest boundary worth stating plainly: in this deterministic lab the
tuning method demonstrably loses no true positives on a fixed dataset. In a real,
noisy tenant the same *method* applies, but the guarantee is only ever as good as
the regression cases you write — which is why the process makes the paired test a
merge requirement, not a suggestion.

## Monthly owner review

Every detection has a named owner (see the
[tuning backlog](TUNING_BACKLOG_SAMPLE.md) owner column and the YAML `owner`
field on the control-plane rules). Once a month, each owner reviews their rules
against a fixed agenda:

1. **Precision and volume.** Read the weekly noise roll-up
   ([noise-review-sample.json](noise-review-sample.json) shape) for each owned
   rule. Any rule whose false-positive rate is trending up, or whose alert volume
   spiked, gets a backlog item.
2. **Open tuning backlog.** Walk the [tuning backlog](TUNING_BACKLOG_SAMPLE.md)
   for owned rules — confirm state, owner, and that nothing has stalled.
3. **Exclusion audit.** Re-justify every active exclusion. An exclusion whose
   benign cause no longer occurs (e.g. the VPN range was retired) is *removed*,
   because a stale exclusion is an unmonitored blind spot. Removing it is itself a
   versioned, tested change.
4. **Regression health.** Confirm every excluded rule still carries its paired
   positive regression test and that the suite is green.
5. **Promotion movement.** Decide whether any candidate has earned the next
   promotion state, or whether any production rule needs demotion pending a fix.

The output of the monthly review is a short written note per owner — what
changed, what is proposed, what is blocked — mirroring the "written map of noisy
detections and recurring root causes" deliverable in the
[90-day roadmap](../../security-engineering/90-day-roadmap.md). The review is the
routine that keeps the estate honest between incidents: it is where quiet drift
gets caught before it becomes either noise or a blind spot.

## Summary of guarantees

- No detection is production approved by author's assertion; each earns the label
  by clearing every gate.
- Every false positive is a labelled disposition with a controlled benign cause,
  aggregated weekly to drive tuning by data, not opinion.
- Every tuning change is a narrow, versioned, peer-reviewed, tested code change —
  never a broad suppression or a silent console edit.
- Every exclusion ships with a paired true-positive regression test, so tuning
  cannot blind a working detection without failing the build.
- Every rule has a named owner and a monthly review that re-justifies its
  exclusions and re-checks its precision.
