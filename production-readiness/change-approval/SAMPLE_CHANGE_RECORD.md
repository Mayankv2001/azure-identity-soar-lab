# Sample Change Record — CHG-2026-0142

Part of the **Production Readiness & Operations Layer** for the AI-Assisted
Azure Identity Threat Detection & SOAR Lab.

> **Fictional worked example.** This is a filled-in change record for a
> synthetic change, using fictional `@contoso.com` personas and lab detection
> IDs. It exists to show the *shape and rigour* of a change record — not to
> document a real deployment. Nothing here was applied to a production tenant.
> No secrets, real emails, subscription IDs or GUIDs appear. It scores as
> **Medium risk** under the [Change Risk Matrix](CHANGE_RISK_MATRIX.md) and
> follows the analytics-rule path in the
> [Change Approval Model](CHANGE_APPROVAL_MODEL.md).

## 1. Summary

| Field | Value |
|-------|-------|
| Change ID | CHG-2026-0142 |
| Title | Re-enable `DET-002` Impossible Travel after v1.1.0 false-positive tuning |
| Change type | Analytics rule (enable previously-disabled rule) |
| Risk level | **Medium** (likelihood 2 x impact 2 — see §4) |
| Requester | `sofia.russo@contoso.com` (detection engineering) |
| Reviewer / approver | `priya.sharma@contoso.com` (detection reviewer); `dana.iyer@contoso.com` (SOC DRI, informed) |
| Related ticket | JIRA SOC-2026-0142 |
| Related incident | INC-1005 (the seeded false positive that drove the tuning) |
| Change window | Business hours, Wed 2026-07-08 10:00–11:00 AEST |
| Status | **Closed — succeeded** |

## 2. Background and intent

`DET-002` (Impossible Travel Sign-in) was **disabled** on 2026-06-24 after it
produced a repeatable false-positive class: a legitimate user whose corporate
VPN egress flips between two Australian regions read as impossible travel
between sign-ins minutes apart. That false positive is INC-1005 in the sample
run — closed with a reason, fed to tuning rather than the bin, exactly as the
[DRI Runbook](../../docs/DRI_RUNBOOK.md) prescribes.

The intent of this change is to **re-enable `DET-002` with a narrow, versioned
tuning exclusion (v1.1.0)** that removes the VPN-egress false-positive class
**without dropping any true positives** — restoring impossible-travel coverage
that the estate has been blind to for two weeks.

**Scope of the change:**

- `detections/DET-002-impossible-travel.kql` — add the tuning exclusion clause.
- `detections/DET-002-impossible-travel.yaml` — bump `version` to `1.1.0`, add
  the exclusion to the structured `tuning` block, note INC-1005 as the driver.
- `src/detection_engine.py` — mirror the same exclusion in the Python engine so
  the three forms stay in lockstep.
- Set the rule state to **enabled**.

**Out of scope:** severity, entity mappings, and the core detection logic are
unchanged. This is a tuning-and-enable change, not a rewrite.

## 3. The change (before / after)

**Exclusion added (v1.1.0):** suppress an impossible-travel pair when *both*
sign-ins originate from the organisation's known corporate VPN egress ranges
(documentation IP ranges in the lab) **and** both succeeded with satisfied MFA —
the benign VPN-region-flip pattern. Any leg outside the VPN egress set, or any
MFA anomaly, still fires.

| | Before | After (v1.1.0) |
|---|--------|----------------|
| Rule state | Disabled | Enabled |
| Version | 1.0.0 | 1.1.0 |
| Tuning block | (none) | 1 exclusion: corp-VPN-egress + MFA-satisfied pair |
| Alerts on deterministic dataset | 3 (2 true, 1 false = INC-1005) | 2 (2 true, 0 false) |

The exclusion is **narrow and conjunctive** — it requires the VPN-egress
condition *and* the MFA-satisfied condition together, so it cannot silently
swallow a real impossible-travel event that happens to touch a VPN range.

## 4. Risk assessment

Scored with the [Change Risk Matrix](CHANGE_RISK_MATRIX.md):

- **Likelihood: 2 (Possible).** Impossible travel is a behavioural detection and
  exclusions can over-suppress; however the change is tested on the
  deterministic dataset and the exclusion is conjunctive and narrow.
- **Impact: 2 (Significant).** A bad exclusion could drop a true positive, but
  the change is fully reversible through the pipeline and does not touch access,
  network, or automated destructive response.
- **Result: Medium.** Approval path: detection reviewer approves; SOC DRI is
  informed because re-enabling a rule changes response volume.

The scope condition that would raise this to High — disabling a Critical
detection or widening an exclusion that could drop true positives — does **not**
apply: this change *adds* coverage and demonstrably drops zero true positives.

## 5. Test evidence (attached before deployment)

All evidence was produced and attached to the record **before** the change
window, per the approval model's "evidence over assertion" rule.

1. **Full test suite green.**
   `python3 -m pytest -q` → **37 passed**, including the detection-as-code
   contract test that fails if the KQL, YAML and Python engine drift apart —
   proving the three synchronised forms of `DET-002` still match after the edit.

2. **Before/after alert count on the deterministic dataset.**
   `python3 src/main.py --demo` re-run with the tuned rule enabled:
   - Before tuning (v1.0.0): 3 `DET-002` alerts — 2 true positives, 1 false
     positive (INC-1005).
   - After tuning (v1.1.0): **2 `DET-002` alerts — 2 true positives, 0 false
     positives.**
   - **True positives lost: 0.** This meets the standard set by the original
     DET-002 tuning story (narrow, versioned, tested, zero true positives lost
     on the fixed dataset).

3. **KQL validated per the harness.**
   The edited KQL passes the checks in the
   [KQL Test Harness](../../security-engineering/kql-test-harness.md)
   (schema/table names, MITRE format, expected-output contract).

4. **Scorecard re-run — no metadata regression.**
   `python3 security-engineering/score_detections.py` → `DET-002` holds its
   score (87/100) with the structured `tuning` block now richer; the 15-detection
   average remains 91.8/100. No detection regressed.

> **Honesty note on the metrics.** The zero-false-positive result is a
> demonstration of the *tuning method* on a fixed, deterministic dataset. It is
> **not** a claim of zero false positives in a real, noisy tenant — real
> impossible-travel tuning needs baselining against live VPN egress data before
> the same confidence would hold.

## 6. Rollback plan

Follows the analytics-rule instance of the
[Rollback Plan Template](ROLLBACK_PLAN_TEMPLATE.md).

- **Trigger:** any `DET-002` true-positive miss observed in the bake window, or
  the false-positive rate not improving as expected, or the contract test
  failing post-deploy.
- **Steps:**
  1. Revert `DET-002` to the committed v1.0.0 rule through the pipeline (KQL,
     YAML and engine reverted together).
  2. Re-run the detection-as-code contract test to confirm the three forms match
     again.
  3. Return the rule to its prior **disabled** state if the false positive
     recurs, restoring the pre-change position (coverage off, but no noise).
- **Verification:** `python3 -m pytest -q` green; `--demo` alert counts match
  the v1.0.0 baseline (3 alerts). Rollback verified reversible in seconds — the
  change is code, not configuration drift.
- **Owner during rollback:** the SOC DRI on shift (`dana.iyer@contoso.com`).

## 7. Post-change monitoring (bake window)

Per the approval model, a re-enabled rule is bake-monitored until the next
weekly operations review.

| Check | Frequency | Threshold that triggers rollback |
|-------|-----------|-----------------------------------|
| `DET-002` alert volume vs. baseline | Daily (daily report) | Sustained spike suggesting the exclusion missed a live FP pattern |
| False-positive disposition on `DET-002` | Daily | Any recurrence of the INC-1005 VPN-egress class |
| True-positive coverage | On any impossible-travel incident | A confirmed impossible-travel event that the exclusion suppressed |
| SLA adherence for `DET-002` incidents | Weekly review | New SLA breach attributable to the change |

Bake window: **7 days**, closing at the 2026-07-15 weekly operations review.

## 8. Approvals and timeline

| Timestamp (AEST) | Actor | Action |
|------------------|-------|--------|
| 2026-07-07 15:20 | `sofia.russo@contoso.com` | Raised CHG-2026-0142; attached test evidence (§5) |
| 2026-07-07 16:05 | `priya.sharma@contoso.com` | Reviewed diff + evidence; **approved** (Medium risk, evidence complete) |
| 2026-07-07 16:30 | `dana.iyer@contoso.com` | Acknowledged as SOC DRI; will own the bake window |
| 2026-07-08 10:15 | `sofia.russo@contoso.com` | Deployed via pipeline; rule enabled at v1.1.0 |
| 2026-07-08 10:25 | `sofia.russo@contoso.com` | Post-deploy contract test green; `--demo` shows 2/0 alerts |
| 2026-07-15 14:00 | `dana.iyer@contoso.com` | Bake window clean; **change closed — succeeded** |

## 9. Outcome

`DET-002` re-enabled at v1.1.0. Impossible-travel coverage restored; the
INC-1005 false-positive class did not recur during the bake window; no true
positives lost. The tuning exclusion is now the committed, versioned baseline
for the detection. Change closed at the weekly review with no rollback required.

## Related documents

- [Change Approval Model](CHANGE_APPROVAL_MODEL.md) — the analytics-rule change
  type
- [Change Risk Matrix](CHANGE_RISK_MATRIX.md) — the Medium-risk scoring
- [Rollback Plan Template](ROLLBACK_PLAN_TEMPLATE.md) — the rollback structure
  used in §6
- [DRI Runbook](../../docs/DRI_RUNBOOK.md) — false positives feed tuning; weekly
  review
