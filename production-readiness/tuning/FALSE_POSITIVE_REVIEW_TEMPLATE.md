# False-Positive Review Template

A single form to record one false-positive (or benign-positive) finding, the
benign cause behind it, the exclusion proposed to handle it, the scope of that
exclusion, the test evidence that the exclusion is safe, and the approver who
signed it off.

Copy the template below into a new file per review (suggested name
`FP-REVIEW-<rule>-<yyyy-mm>.md`). One form per benign cause per rule — if a rule
has two distinct benign causes, that is two forms and two narrowly-scoped
exclusions, never one broad one.

> This form is the evidence artefact for **Gate 3** in
> [DETECTION_PROMOTION_GATES.md](DETECTION_PROMOTION_GATES.md) and the input to a
> tuning change described in
> [DETECTION_TUNING_PROCESS.md](DETECTION_TUNING_PROCESS.md#how-tuning-changes-are-proposed).
> All personas and data below are fictional (`@contoso.com`, documentation IP
> ranges); this is a synthetic lab and no rule here is production approved.

---

## Template

```markdown
# False-Positive Review — <RULE ID> <rule name>

| Field | Value |
|-------|-------|
| Review ID | FP-REVIEW-<rule>-<yyyy-mm> |
| Rule | <DET-00x / CP-DET-00x> — <name> |
| Rule version reviewed | <semver, e.g. 1.0.0> |
| Rule owner | <team> (<persona@contoso.com>) |
| Reviewer | <persona@contoso.com> |
| Date | <yyyy-mm-dd> |
| Promotion state | <Audit-only / Limited enablement / Production candidate / Production approved> |

## 1. Evidence window
- Data window reviewed: <yyyy-mm-dd> to <yyyy-mm-dd> (<N> days)
- Alerts in window: <alert_count>
- Dispositioned false_positive / benign_positive: <fp_count>
- False-positive rate for the window: <fp_count / alert_count as %>
- Source of the roll-up: <link to weekly noise-review row, see noise-review-sample.json>

## 2. Benign cause
- Controlled cause label: <corp_vpn_egress | mobile_carrier_nat | approved_pipeline_rotation | scheduled_admin_change | new_cause_here>
- Plain description: <what benign thing actually happened, and why the rule read it as hostile>
- Recurring? <yes/no — how many distinct occurrences across the window>
- Evidence: <example alert IDs, entities involved (fictional), the field values that triggered the match>

## 3. Proposed exclusion
- Change type: <scoped exclusion | context modifier | threshold note — NOT broad suppression>
- Exact predicate:
      field: <field>
      op: <both_endpoints_in_cidr | equals | in_watchlist | correlated_with_change_record>
      values: [ <narrow value(s)> ]
- Why this is the narrowest safe form: <what wider option was rejected and why>
- New rule version after change: <semver bump, e.g. 1.0.0 -> 1.1.0>
- Description text to add to the YAML `description`: <one honest sentence citing this review>

## 4. Scope
- Entities affected by the exclusion: <exactly which sign-ins / SPs / actions become silent>
- Entities explicitly NOT affected: <the malicious variant that must still fire>
- Blast radius of getting this wrong: <what a real attack using this benign shape would look like, and confirmation the exclusion does not cover it>

## 5. Test evidence (regression guard)
- Negative test added: <name> — reproduces the benign cause, asserts SILENT.
- Positive (true-positive) test added/confirmed: <name> — malicious twin of the same
  shape, asserts STILL FIRES.
- Test suite result after change: <pass/fail> (`python3 -m pytest -q`)
- True positives lost by this change: <must be 0 — the positive test proves it>

## 6. Approval
| Role | Persona | Decision | Date |
|------|---------|----------|------|
| Peer reviewer | <persona@contoso.com> | <approve/changes-requested> | <yyyy-mm-dd> |
| Rule owner | <persona@contoso.com> | <approve/reject> | <yyyy-mm-dd> |
| Deployment approver | security-operations@contoso.com | <approve/hold> | <yyyy-mm-dd> |

## 7. Outcome
- Merged in PR: <#id>
- New rule state after change: <state>
- Follow-up (monthly review): <re-justify this exclusion on <yyyy-mm>; remove if benign cause no longer occurs>
```

---

## Worked example (illustrative)

The reference tuning change in this lab — the DET-002 VPN-egress exclusion —
filled in on this form. It is illustrative and synthetic; DET-002 remains a
candidate, not a production-approved rule.

```markdown
# False-Positive Review — DET-002 Impossible Travel Sign-in

| Field | Value |
|-------|-------|
| Review ID | FP-REVIEW-DET-002-2026-06 |
| Rule | DET-002 — Impossible Travel Sign-in |
| Rule version reviewed | 1.0.0 |
| Rule owner | Identity Detection Engineering (priya.raman@contoso.com) |
| Reviewer | diego.santos@contoso.com |
| Date | 2026-06-30 |
| Promotion state | Audit-only |

## 1. Evidence window
- Data window reviewed: 2026-06-23 to 2026-06-29 (7 days)
- Alerts in window: 6
- Dispositioned false_positive / benign_positive: 3
- False-positive rate for the window: 50%
- Source of the roll-up: noise-review-sample.json, DET-002 / 2026-W26 row

## 2. Benign cause
- Controlled cause label: corp_vpn_egress
- Plain description: Two successful sign-ins for the same user came from the
  corporate VPN/SASE egress nodes in different cities within minutes, implying a
  travel speed above 900 km/h. The user never moved; only the VPN exit did.
- Recurring? yes — 3 distinct user-days across the window, all inside the VPN range.
- Evidence: alert pairs where both IPAddress values sat inside 198.51.100.0/24
  (documentation range); tied to sample incident INC-1005.

## 3. Proposed exclusion
- Change type: scoped exclusion
- Exact predicate:
      field: IPAddress
      op: both_endpoints_in_cidr
      values: [ 198.51.100.0/24 ]
- Why this is the narrowest safe form: excludes only pairs where BOTH endpoints
  are inside the single corporate VPN egress range. A pair with one endpoint
  outside the range still fires. Rejected wider option: suppressing impossible
  travel for VPN users entirely (would blind real token-theft from a VPN user).
- New rule version after change: 1.0.0 -> 1.1.0
- Description text to add: "Version 1.1.0 adds an exclusion for pairs where both
  IP addresses sit inside the corporate VPN egress range, after triage confirmed
  that VPN nodes in different cities were the sole source of false positives."

## 4. Scope
- Entities affected: sign-in pairs with both IPs in 198.51.100.0/24.
- Entities explicitly NOT affected: any pair with at least one IP outside the VPN
  range — i.e. genuine impossible travel from an attacker's own infrastructure.
- Blast radius of getting this wrong: a real attacker would have to source BOTH
  legs from inside the corporate VPN egress to be masked — an implausible and
  separately-detected precondition.

## 5. Test evidence (regression guard)
- Negative test added: both-IPs-in-VPN-range pair asserts SILENT.
- Positive test confirmed: >900 km/h pair with one IP outside the VPN range
  asserts STILL FIRES.
- Test suite result after change: pass (python3 -m pytest -q)
- True positives lost by this change: 0.

## 6. Approval
| Role | Persona | Decision | Date |
|------|---------|----------|------|
| Peer reviewer | diego.santos@contoso.com | approve | 2026-06-30 |
| Rule owner | priya.raman@contoso.com | approve | 2026-06-30 |
| Deployment approver | security-operations@contoso.com | approve | 2026-07-01 |

## 7. Outcome
- Merged in PR: (illustrative)
- New rule state after change: Audit-only (re-validated), exclusion live in v1.1.0
- Follow-up (monthly review): re-justify the 198.51.100.0/24 exclusion on 2026-07;
  remove if the VPN egress range is retired.
```

The point the worked example makes: the exclusion removed the seeded
false-positive class **with zero lost true positives**, and section 5 is the
evidence that "zero lost" is a checkable claim, not a hope — exactly the
regression-guard discipline required by the
[tuning process](DETECTION_TUNING_PROCESS.md#how-true-positives-are-protected-regression-tests).
