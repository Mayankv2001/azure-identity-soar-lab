# Rollback Plan Template

Part of the **Production Readiness & Operations Layer** for the AI-Assisted
Azure Identity Threat Detection & SOAR Lab.

> **Honest lab framing.** Synthetic, offline-first lab mirroring Microsoft
> Sentinel and Azure concepts; nothing here is deployed to a production tenant.
> This is a reusable template referenced by the
> [Change Approval Model](CHANGE_APPROVAL_MODEL.md): **no change ships without a
> written, tested rollback plan.** Copy the template in §2, fill it in, and
> attach it to the change record before deployment. All personas are fictional
> `@contoso.com` accounts; no secrets or real identifiers.

## 1. Principles

- **Write it before you deploy, not while you are rolling back.** A network or
  access change can lock out the very responders who would fix it — the rollback
  state (prior NSG rules, prior role assignment) is captured *before* the change
  is applied.
- **Reversibility is designed in.** Detections and playbooks ship like code
  (revert a commit through the pipeline); Azure Policy effects are parameterised
  (`Deny` → `Audit` → `Disabled`) so rollback is a parameter flip, not a
  redeploy.
- **A rollback is a normal outcome, not a failure.** It triggers a blameless RCA
  per the [DRI Runbook](../../docs/DRI_RUNBOOK.md), not blame.
- **Verify, do not assume.** Every rollback ends with an explicit verification
  step that proves the estate is back to the pre-change position.

## 2. Template (copy this block)

```markdown
### Rollback plan — <CHG-ID> <title>

**Change type:** <analytics rule | SOAR playbook | firewall/NSG | RBAC | Azure Policy>
**Risk level:** <Low | Medium | High | Critical>
**Rollback owner:** <persona / on-call DRI on shift>
**Pre-change state captured:** <where the before-state is recorded — commit SHA,
  exported rule set, prior role assignment, prior policy effect>

**Trigger — roll back if any of these is observed:**
- <specific, observable condition 1 — e.g. true-positive miss, exposure detected,
  legitimate access blocked, contract test fails post-deploy>
- <condition 2>
- <time-boxed condition — e.g. not verified healthy within the bake window>

**Steps (least-destructive first):**
1. <exact action, with the command / pipeline step / portal path>
2. <...>
3. <restore prior state from the captured before-state>

**Verification — rollback is complete only when all pass:**
- [ ] <automated check — e.g. `pytest -q` green, `--demo` counts match baseline>
- [ ] <state check — e.g. rule disabled, NSG rule reverted, assignment removed>
- [ ] <reachability / behaviour check — e.g. management port closed from internet>

**Communications:**
- Announce in: <incident/SOC channel>
- Notify: <approvers + affected owners>
- Record on: <change record + incident timeline>
- Post-rollback: schedule blameless RCA (DRI, within 5 business days)

**Estimated rollback time:** <seconds | minutes | requires helpdesk round-trip>
```

## 3. Field guidance

- **Trigger** must be *observable*, not a feeling. "Alert volume spikes above
  baseline for the affected detection", "a legitimate deployment is blocked by
  the Deny policy", "the management port is reachable from the internet" — each
  is something a monitor or a person can point at.
- **Steps** are ordered least-destructive first, matching the incident triage
  discipline. Restoring the captured before-state is the last resort, not the
  first reflex.
- **Verification** is not optional. A rollback with no green verification is an
  open change, not a closed one.
- **Communications** answer the DRI-runbook three questions — what we know, what
  we have done, what is next — and always land on the change record.

## 4. Pre-filled instances per change type

Short, ready-to-adapt rollbacks for each change type in the approval model.

### 4.1 Analytics rule (`DET-00X` / `CP-DET-00X`)

- **Trigger:** true-positive miss in the bake window, false-positive rate not
  improving, or the detection-as-code contract test failing post-deploy.
- **Steps:** (1) revert the rule to the previous committed version through the
  pipeline (KQL + YAML + Python engine together); (2) re-run the contract test;
  (3) if a false positive recurs, return the rule to its prior disabled state.
- **Verification:** `python3 -m pytest -q` green; `python3 src/main.py --demo`
  alert counts match the pre-change baseline; scorecard shows no regression.
- **Rollback time:** seconds (it is code).
- *Worked example:* §6 of the [Sample Change Record](SAMPLE_CHANGE_RECORD.md).

### 4.2 SOAR playbook (`PB-01`..`PB-06`)

- **Trigger:** an approval-required action fired without an approve/reject
  record, a full-auto action fired outside its trigger, or the approval card
  stopped appearing for a human-gated step.
- **Steps:** (1) restore the previous playbook design; (2) confirm the approval
  gate is back for every destructive action (`PB-04`/`PB-05`/`PB-06`); (3) if a
  promotion-to-full-auto caused the issue, revert the automation level to
  approval-required.
- **Verification:** a dry-run against synthetic incidents shows the approval card
  fires and no destructive step runs unattended; every action produces an audit
  record (actor + timestamp).
- **Rollback time:** minutes.

### 4.3 Firewall / NSG response

- **Trigger:** a legitimate service loses connectivity, or (for a rule that was
  meant to *close* exposure) `CP-DET-006` / Defender still shows the port open.
- **Steps:** (1) re-apply the prior rule set from the **before-state captured
  before the change** (priority, direction, access, source prefix, destination
  port); (2) confirm the intended access path is restored; (3) re-verify the
  security intent (management port not open to the internet).
- **Verification:** reachability check — port closed from the internet, still
  reachable from the approved administrative source; no legitimate service
  alarming.
- **Rollback time:** minutes — *but* because a network change can lock out
  responders, the before-state is captured up front and the rollback rule set is
  written down before the change is applied.

### 4.4 RBAC assignment

- **Trigger:** over-broad access discovered, the wrong principal granted, or a
  temporary grant that should have expired still active (`DET-007`).
- **Steps:** (1) remove the assignment (or restore the prior one from the
  captured before-state); (2) revoke active sessions for the affected principal
  so a removed grant cannot be used from a cached token (mirrors `PB-04`);
  (3) confirm the change appears in the next access review.
- **Verification:** the assignment is gone / restored as intended; no active
  session retains the revoked privilege; `DET-005` / `CP-DET-003` are correlated
  to the rollback ticket and do not fire falsely.
- **Rollback time:** minutes, plus session propagation.

### 4.5 Azure Policy

- **Trigger:** a Deny policy blocks a legitimate deployment, or the compliance
  result diverges from the Audit-run expectation.
- **Steps:** (1) set the policy effect parameter back to `Audit` (or `Disabled`)
  — a parameter change, not a redeploy; (2) re-check any resources blocked during
  the window; (3) narrow the scope before re-attempting `Deny`.
- **Verification:** the policy no longer blocks; compliance dashboard reflects
  the reverted effect; paired detection (e.g. `CP-DET-006`) still watching.
- **Rollback time:** seconds (parameter flip).

## 5. When rollback is not clean

Some changes cannot be reversed to the exact prior state, and the plan must say
so up front rather than pretend otherwise:

- **Disable-user (`PB-06`) rollback** re-enables the account, but sessions and
  tokens must be re-established — the user is not seamlessly back where they
  were. This is exactly why `PB-06` is approval-required, never full-auto.
- **Credential rotation** cannot un-rotate a secret; rollback means re-issuing
  and re-distributing, not restoring the old value (and the old value should
  stay dead).
- **A management-port exposure** that was open for a window cannot be made
  "un-exposed" — rollback closes it, but the RCA must assess whether anything
  reached it while it was open (the CP-INC-2001 receiving-DRI priority).

For these, the change is rated higher on the [Change Risk Matrix](CHANGE_RISK_MATRIX.md)
(impact 3), gets change-advisory approval, and the rollback plan states the
residual, irreversible effect explicitly.

## Related documents

- [Change Approval Model](CHANGE_APPROVAL_MODEL.md) — where rollback plans are
  required per change type
- [Change Risk Matrix](CHANGE_RISK_MATRIX.md) — how reversibility feeds the
  impact score
- [Sample Change Record](SAMPLE_CHANGE_RECORD.md) — a filled rollback plan in
  context
- [DRI Runbook](../../docs/DRI_RUNBOOK.md) — blameless RCA after a rollback
