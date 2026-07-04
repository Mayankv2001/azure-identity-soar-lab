# Detection Promotion Gates

The exit gates a detection must pass to leave each promotion state. Each gate is
a checklist with a named accountable role; a state is not "done" until every
item in its gate is true and recorded in the pull request that carries the
change.

This is the companion to the
[Detection Tuning Process](DETECTION_TUNING_PROCESS.md), which describes the
states and the tuning flow, and it is the explicit, gate-by-gate form of the
eight-step
[detection promotion checklist](../../security-engineering/kql-test-harness.md#detection-promotion-checklist)
in the KQL Test Harness.

> **Honest framing.** No detection in this repository has cleared these gates to
> Production approved. Every rule is a candidate at Draft/Simulated maturity on
> synthetic data; gates 3–6 require a real tenant and are documented as the
> production path. The [Detection Quality Scorecard](../../security-engineering/detection-quality-scorecard.md)
> measures detection-as-code *metadata quality*, not clearance through these
> gates.

## Roles referenced

The lab uses role-based owners rather than named individuals for the rules
themselves (`owner: Identity Detection Engineering`,
`owner: Cloud Security Engineering` in the detection YAML). Where a gate needs an
accountable person, these fictional `@contoso.com` personas are used
consistently across the tuning artefacts:

| Role | Persona | Owns |
|------|---------|------|
| Detection author | `priya.raman@contoso.com` | Identity Detection Engineering rules (DET-00x) |
| Detection author | `diego.santos@contoso.com` | Cloud Security Engineering rules (CP-DET-00x) |
| Peer reviewer | a second engineer on the owning team | Independent logic / MITRE / FP review |
| Approver | `security-operations@contoso.com` (change-approval group) | Deployment approval gate |
| On-call DRI | rotating, per the paging matrix | Post-deployment monitoring, rollback trigger |

## Gate 1 — leaving Draft (to Simulated)

**Owner: detection author, checked by peer reviewer.**

- [ ] KQL authored against the correct Sentinel table(s); thresholds and window
      semantics documented in the query header.
- [ ] Python mirror in `src/detection_engine.py` implements identical thresholds
      (detection-as-code contract).
- [ ] YAML complete: `severity`, MITRE `techniques`, `entity_mappings`, `sla`,
      `tuning.known_false_positives`, `owner`.
- [ ] At least one benign look-alike identified and written into
      `tuning.known_false_positives`.
- [ ] **Peer review** by a second engineer: logic, MITRE mapping and
      false-positive guidance reviewed and approved in the PR.

**Gate fails if:** the three artefacts disagree (CI drift check), MITRE mapping is
malformed, or no benign look-alike is documented.

## Gate 2 — leaving Simulated (to Audit-only)

**Owner: detection author, evidence reviewed by peer reviewer.**

- [ ] **Simulation run** of the positive and negative samples in a staging
      workspace (or the offline Python mirror for lab rules).
- [ ] Expected alert count confirmed exactly — positives fire, negatives stay
      silent (matches [kql-test-cases.json](../../security-engineering/kql-test-cases.json)).
- [ ] **Test-case evidence attached** to the PR: positive/negative results plus
      query performance (scan volume, run time), so a regression is visible later.
- [ ] Query cost within budget for the intended run frequency (no unbounded
      joins or full-table scans left un-noted).

**Gate fails if:** any negative sample fires, the alert count differs from the
expectation, or query cost is unacceptable at the declared `query_frequency`.

## Gate 3 — leaving Audit-only (to Limited enablement)

**Owner: detection author, with the owning team.** This is the first gate that
requires **real data**.

- [ ] Rule has run **audit-only against real historical telemetry** for a defined
      window (writing to a shadow stream, paging no one).
- [ ] **False-positive review completed** against that real window: benign
      firings quantified per cause on a
      [False-Positive Review](FALSE_POSITIVE_REVIEW_TEMPLATE.md) form, and rolled
      up in the weekly [noise-review](noise-review-sample.json) shape.
- [ ] Any exclusion added to handle a real benign cause is **narrow, versioned,
      and paired with a true-positive regression test** (per the tuning process).
- [ ] Observed real-data volume is within the queue's tolerance — the rule will
      not flood analysts when it starts paging.

**Gate fails if:** the false-positive rate against real data is above the agreed
threshold and cannot be tuned narrowly, or an exclusion is proposed without a
paired regression test.

## Gate 4 — leaving Limited enablement (to Production candidate)

**Owner: owning team, with on-call DRI briefed.**

- [ ] Rule enabled for a **narrow scope** (one BU / region / canary population)
      with alerts reaching analysts for that scope only.
- [ ] Scoped **precision is acceptable** over the limited-enablement window —
      measured, not assumed.
- [ ] **Rollback plan defined and tested**: the exact mechanism to disable or
      revert (version pin, `status: Disabled` flip, feature flag) has been
      exercised at least once, and the time-to-rollback is known.
- [ ] **On-call DRI briefed**: the paging matrix, the rule's intent, and its
      rollback switch are in the runbook before it can page anyone.

**Gate fails if:** scoped precision is poor, or the rollback path is
theoretical rather than tested.

## Gate 5 — leaving Production candidate (to Production approved)

**Owner: approver (`security-operations@contoso.com`), on owner recommendation.**

- [ ] **Deployment approval** recorded through the approval-gated pipeline stage
      (the Azure DevOps deploy stage in both labs runs against a manual-approval
      environment).
- [ ] **Post-deployment monitoring** window completed clean: alert volume and
      precision watched for the first N days tenant-wide.
- [ ] **Alert-volume canary armed**: an automatic guard pages if the rule's
      volume spikes beyond baseline, so a silent flood cannot persist.
- [ ] **No open regression** and no open high-severity tuning backlog item for
      the rule.
- [ ] **Owner sign-off** that the rule is ready for steady-state ownership and the
      monthly review cycle.

**Gate fails if:** the monitoring window shows a volume spike or precision drop,
the canary is not in place, or any regression is open.

## Gate 6 — staying Production approved (steady-state gates)

**Owner: named rule owner, on the monthly cycle.**

Production approved is not a finish line; it is a maintained state with its own
recurring gate. To *remain* approved a rule must, each month:

- [ ] Pass the **monthly owner review** (precision, volume, backlog, exclusion
      audit, regression health — per the tuning process).
- [ ] Have **every active exclusion re-justified**; stale exclusions removed via a
      versioned, tested change.
- [ ] Keep its **paired true-positive regression tests green**.

Any material edit to an approved rule (a new exclusion, a threshold change) is a
**change-controlled** modification: it re-enters the gates at the state
appropriate to its risk — at minimum peer review (Gate 1) and simulation
(Gate 2), and a fresh false-positive review (Gate 3) if it touches detection
scope. Approved status is never a licence to edit silently.

## Demotion

Any gate can be run in reverse. A production rule that starts flooding the queue,
loses precision, or is found to swallow a true positive is **demoted** — typically
to Audit-only or Limited enablement — while it is re-tuned, then re-promoted
through the gates. Demotion is a routine operational tool, and the rollback plan
proven at Gate 4 is what makes it fast and safe.

## Gate-to-checklist mapping

For reviewers cross-referencing the original checklist:

| Promotion gate | KQL Test Harness checklist step(s) |
|----------------|-------------------------------------|
| Gate 1 (Draft → Simulated) | 1 Dev, 2 Peer review |
| Gate 2 (Simulated → Audit-only) | 3 Simulation validation, 4 Test-case evidence |
| Gate 3 (Audit-only → Limited) | 5 False-positive review |
| Gate 4 (Limited → Candidate) | 6 Rollback plan |
| Gate 5 (Candidate → Approved) | 7 Deployment approval, 8 Post-deployment monitoring |
| Gate 6 (steady state) | Monthly owner review (this process) |
