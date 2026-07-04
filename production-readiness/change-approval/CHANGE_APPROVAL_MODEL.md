# Change Approval Model

Part of the **Production Readiness & Operations Layer** for the AI-Assisted
Azure Identity Threat Detection & SOAR Lab.

> **Honest lab framing.** This is a synthetic, offline-first lab that mirrors
> Microsoft Sentinel and Azure concepts; nothing here is deployed to a
> production tenant. This document describes the change-control *discipline* I
> would run a detection-and-response estate under, expressed against the lab's
> own detections (`DET-001`..`DET-007`, `CP-DET-001`..`CP-DET-008`), playbooks
> (`PB-01`..`PB-06`) and policy-as-code controls. All identities are fictional
> `@contoso.com` personas; no real emails, GUIDs, subscription IDs or secrets
> appear anywhere. Treat it as the process a mature SecOps team applies *before*
> any of these candidates earns a place in a live workspace.

## 1. Why change control exists here

Every artefact in this repository is a **candidate that requires
tenant-specific baselining, tuning and a deployment approval before it goes
live** (see the [Detection Quality Scorecard](../../security-engineering/detection-quality-scorecard.md),
15 detections, average 91.8/100). Change control is the gate that converts a
scored candidate into an operating control without breaking the estate or the
humans who depend on it.

The model rests on three principles, consistent with the lab's SOAR design:

- **Blast radius first.** The wider the effect of a change, the more approval
  and evidence it needs — the same instinct the playbooks use to decide what
  runs unattended.
- **Reversibility is a feature.** No change ships without a written, tested
  rollback. If it cannot be rolled back cleanly, that constraint is stated up
  front and factored into the risk level.
- **Evidence over assertion.** "It works" is a test result and a reviewer's
  signature, not an opinion. Test evidence is attached to the change record,
  not remembered.

## 2. Roles

| Role | Persona (fictional) | Responsibility |
|------|---------------------|----------------|
| Change requester | any engineer | Raises the change record, attaches test evidence, writes the rollback plan |
| Detection-engineering reviewer | `priya.sharma@contoso.com` | Reviews analytics-rule and detection-as-code changes for correctness and drift |
| SOC DRI / on-call | `dana.iyer@contoso.com` | Approves response-affecting changes; owns the change during any monitored bake window |
| Platform / identity owner | `noah.patel@contoso.com` | Approves RBAC, PIM and identity-plane changes |
| Cloud infrastructure owner | `grace.kim@contoso.com` | Approves firewall/NSG and Azure Policy changes affecting the network or subscription |
| Change advisory (high-risk) | DRI + platform owner + one peer | Two-person review for High and Critical-risk changes |

Roles are functions, not headcount — one person can hold several in a small
team, but a requester may **never** be the sole approver of their own change.
Break-glass identities are exempt from approval only through a documented,
monitored exception (see the
[require-approval-privileged-role](../../security-engineering/policy-as-code/require-approval-privileged-role.md)
control) and every break-glass use generates its own after-the-fact change
record.

## 3. Risk levels

Risk level is assigned from the [Change Risk Matrix](CHANGE_RISK_MATRIX.md)
(likelihood x impact) and drives the whole approval path.

| Risk level | Meaning | Approval | Change window |
|------------|---------|----------|---------------|
| **Low** | Self-contained, easily reversible, no production-response effect | One peer review | Any time |
| **Medium** | Affects detection fidelity or a scoped control; reversible with effort | Detection reviewer *or* DRI | Business hours |
| **High** | Can suppress detection, change automated response, or alter access/network posture | Two-person review (owner + DRI) | Scheduled window, announced |
| **Critical** | Can lock users out, open network exposure, or grant standing privilege at scale | Change advisory review + explicit go/no-go | Scheduled window, rollback rehearsed |

## 4. Change types

Each change type below states its **default risk level**, **approval required**,
**test evidence required**, **rollback plan**, and **post-change monitoring**.
The default risk level is the starting point; the matrix can raise it based on
scope (for example, a Deny-mode Azure Policy at subscription scope is Critical
even though an Audit-mode version of the same policy is Medium).

### 4.1 Analytics rule change (Sentinel scheduled rule / detection-as-code)

Enabling, disabling, or editing a detection — threshold, query logic, severity,
entity mappings, or a tuning exclusion. Covers `DET-001`..`DET-007` and
`CP-DET-001`..`CP-DET-008` in their three synchronised forms (KQL, YAML,
Python mirror).

- **Default risk level:** Medium. *Raised to High* when the change can suppress
  a Critical detection (disabling a rule, widening a tuning exclusion, or
  raising a threshold enough to miss the seeded showcase incidents).
- **Approval required:** Detection-engineering reviewer for Medium; add the SOC
  DRI for High (a detection change is a response change — silence has blast
  radius).
- **Test evidence required:**
  - `python3 -m pytest -q` green, including the detection-as-code contract test
    that fails if KQL / YAML / engine drift apart.
  - For a tuning exclusion: a before/after alert count on the deterministic
    dataset showing the targeted false-positive class removed **and zero true
    positives lost** (the standard set by the DET-002 v1.1.0 tuning story).
  - For a new/edited rule: KQL validated per the
    [KQL Test Harness](../../security-engineering/kql-test-harness.md) and a
    scorecard re-run (`score_detections.py`) confirming no metadata regression.
- **Rollback plan:** Revert the rule to the previous committed version through
  the pipeline (rules ship like code); re-run the contract test to confirm the
  three forms match again. See the analytics-rule instance in the
  [Rollback Plan Template](ROLLBACK_PLAN_TEMPLATE.md).
- **Post-change monitoring:** Watch alert volume and false-positive rate for the
  affected detection in the daily report for one full review cycle (see the
  weekly operations review in the [DRI Runbook](../../docs/DRI_RUNBOOK.md)).
  A re-enabled rule is bake-monitored: alert-count delta and any new SLA breach
  are checked daily until the next weekly review.

### 4.2 SOAR playbook change (Logic App design)

Changing a playbook's trigger, logic, automation level, or approver — `PB-01`
enrich, `PB-02` notify DRI, `PB-03` open ticket, `PB-04` revoke sessions,
`PB-05` password reset, `PB-06` disable user.

- **Default risk level:** High for any change to `PB-04`/`PB-05`/`PB-06`
  (they touch sessions, credentials, and accounts). Medium for `PB-01`/`PB-02`/
  `PB-03` (enrich, notify, ticket — informational, easily reversed).
- **Approval required:** SOC DRI always; add the platform/identity owner for any
  change that would move an action from *approval-required* to *full-auto*.
  Promoting a destructive action to unattended is a Critical-risk change and
  goes to change advisory review.
- **Test evidence required:**
  - The automation-vs-approval decision re-checked against the three-question
    framework (blast radius, reversibility, confidence) from
    [soar-response-design.md](../../playbooks/soar-response-design.md), with the
    answer recorded on the change.
  - A dry-run against synthetic incidents showing the approval card still fires
    for actions that must stay human-gated, and that no destructive step runs
    without an approve/reject record (actor + timestamp).
- **Rollback plan:** Restore the previous playbook design; the DRI confirms the
  approval gate is back in place before the change is closed.
- **Post-change monitoring:** For one week, spot-check that every
  approval-required action produced an audit record and that no full-auto
  action fired outside its intended trigger.

### 4.3 Firewall / NSG response change

A network security group or firewall rule changed as containment or hardening —
for example reverting the CP-INC-2001 rule that opened RDP (3389) to
`0.0.0.0/0` on `nsg-prod-dc-mgmt`, or adding a deny rule.

- **Default risk level:** High. *Critical* when the rule governs a management
  endpoint (SSH/RDP/WinRM: 22/3389/5985/5986) or a production-tier subnet — a
  wrong change can either expose a jumpbox or sever a legitimate access path.
- **Approval required:** Cloud infrastructure owner **and** SOC DRI. Emergency
  containment (closing an active exposure) may be executed first under the
  DRI's authority and ratified with a change record immediately after — the
  bias is toward closing exposure fast, then documenting.
- **Test evidence required:**
  - The exact rule delta (priority, direction, access, source prefix,
    destination port) captured before and after.
  - Confirmation the change matches the intent of the
    [deny-public-management-ports](../../security-engineering/policy-as-code/deny-public-management-ports.json)
    control and does not break a documented legitimate access path.
  - A reachability check: the management port is closed from the internet and
    still reachable from the approved administrative source only.
- **Rollback plan:** Re-apply the prior rule set from the captured before-state.
  Because a network change can lock out responders, the rollback rule set is
  written down *before* the change is applied, not reconstructed afterward.
- **Post-change monitoring:** Watch `CP-DET-006` (NSG/firewall opened to
  internet) and Defender-for-Cloud inbound signals for 24 hours; confirm no
  legitimate service alarmed on the tightened rule.

### 4.4 RBAC assignment change

Granting, changing, or removing an Azure role assignment or a privileged
directory role — for example removing the attacker-added **Owner** grant on
`rg-prod-dc-mgmt`, or provisioning a new administrator.

- **Default risk level:** High. *Critical* for any assignment at subscription
  scope, any Owner/Global Administrator/Privileged Role Administrator grant, or
  any change to a break-glass account.
- **Approval required:** Platform/identity owner. Standing privileged access is
  disfavoured entirely: new privileged access should be PIM-eligible with an
  expiry and an approval flow, per
  [require-approval-privileged-role](../../security-engineering/policy-as-code/require-approval-privileged-role.md),
  rather than a permanent assignment.
- **Test evidence required:**
  - Least-privilege justification: the specific role and scope, and why a
    narrower role or a time-bound PIM-eligible assignment does not suffice.
  - The change ticket reference bound to the assignment (the same
    `require_ticket_information` binding the PIM control enforces).
  - Confirmation `DET-005` / `CP-DET-003` (privileged role change without a
    change record) will *not* fire falsely — i.e. this legitimate change is
    correlated to its ticket.
- **Rollback plan:** Remove the assignment (or restore the prior one) and revoke
  active sessions for the affected principal so a removed grant cannot be used
  from a cached token — mirrors `PB-04`.
- **Post-change monitoring:** Confirm the assignment appears in the next access
  review; watch `DET-007` (stale/orphaned privileged account) so a temporary
  grant that was meant to expire does not quietly become permanent.

### 4.5 Azure Policy change

Adding, editing, or changing the effect of an Azure Policy or PIM configuration
control — for example moving `deny-public-management-ports` from `Audit` to
`Deny`, or tightening
[require-workload-identity-rotation](../../security-engineering/policy-as-code/require-workload-identity-rotation.md).

- **Default risk level:** Medium in `Audit` mode (observes, does not block).
  *Critical* in `Deny` mode at management-group or subscription scope — a Deny
  policy can block legitimate deployments estate-wide.
- **Approval required:** Cloud infrastructure owner for Audit; change advisory
  review (owner + DRI + peer) for any Deny-mode promotion.
- **Test evidence required:**
  - The policy first run in **Audit / report-only** with the compliance result
    captured: what would have been denied, and confirmation none of it is a
    legitimate pattern. This is the mandatory Audit-before-Deny step called out
    in every policy-as-code file in the repo.
  - Confirmation break-glass and documented exceptions are excluded before Deny
    is enabled.
- **Rollback plan:** Set the effect parameter back to `Audit` (or `Disabled`);
  because effect is parameterised, rollback is a parameter change, not a
  redeploy. Any resources blocked during the incident window are re-checked.
- **Post-change monitoring:** Track the policy compliance dashboard and the
  paired detection (`CP-DET-006` for the network policy) for one week; a Deny
  policy that starts blocking legitimate change is rolled back to Audit and the
  scope narrowed.

## 5. The change lifecycle

```
Request  ->  Assess risk        ->  Review / approve     ->  Test evidence
(record)     (Risk Matrix)          (per risk level)         (attached, green)
             |
             v
Deploy   ->  Post-change monitor ->  Close (or Rollback)
(windowed)   (bake period)           (record outcome + RCA if rolled back)
```

- **Request** creates the change record (see the
  [Sample Change Record](SAMPLE_CHANGE_RECORD.md) for the shape).
- **Assess** picks the risk level from the matrix; scope can raise the default.
- **Review** matches the approval path to the risk level; the requester cannot
  self-approve.
- **Test evidence** is attached before deployment, never promised for later.
- **Deploy** happens in the allowed window for the risk level.
- **Monitor** runs the bake period; the DRI owns the change until it clears.
- **Close** records the outcome. A rollback is a normal, non-punitive outcome
  and triggers a blameless RCA per the [DRI Runbook](../../docs/DRI_RUNBOOK.md).

## 6. What this deliberately does not do

Consistent with the repository's safety posture:

- **No auto-publish, no auto-apply.** No detection, playbook, policy or access
  change goes live without a human approval on the record.
- **No standing destructive automation.** Account disablement, session
  revocation, credential rotation and network/firewall changes stay
  human-approved through the playbooks.
- **No secrets or real identifiers.** Change records carry ticket references and
  fictional personas — never credentials, subscription IDs, or tenant GUIDs.

## Related documents

- [Change Risk Matrix](CHANGE_RISK_MATRIX.md) — likelihood x impact scoring
- [Sample Change Record](SAMPLE_CHANGE_RECORD.md) — a filled example
- [Rollback Plan Template](ROLLBACK_PLAN_TEMPLATE.md) — reusable rollback
- [DRI Runbook](../../docs/DRI_RUNBOOK.md) — SLA matrix, RCA, weekly review
- [SOAR Response Design](../../playbooks/soar-response-design.md) — the
  three-question automation framework
- [Detection Quality Scorecard](../../security-engineering/detection-quality-scorecard.md)
  — the candidate maturity these changes promote from
