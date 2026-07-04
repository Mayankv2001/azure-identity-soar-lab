# Playbook approval process

Lab-safe, synthetic. How a SOAR playbook moves from design to approved-for-use,
and why destructive automation is gated behind human approval. Consistent with
the repo's SOAR design
([../../playbooks/soar-response-design.md](../../playbooks/soar-response-design.md)
and
[../../modules/datacenter-control-plane/RESPONSIBLE_AUTOMATION.md](../../modules/datacenter-control-plane/RESPONSIBLE_AUTOMATION.md)).

## The principle

**Automate what is reversible and low-blast-radius; gate anything that can break
a service or lock out responders. AI advises, humans decide, playbooks act.**

The automation level of every action is one of:

- **automatic** - runs unattended (enrichment, notification, ticketing, session
  revocation at Critical severity);
- **approval required** - a named approver signs off before it runs (NSG revert,
  service principal credential rotation, privileged-role removal, VM isolation,
  disable user, password reset);
- **manual only** - a human performs it directly (RCA authoring, evidence
  handling).

## Why destructive automation needs approval

- **Blast radius is unbounded** in a way an identity session revocation is not. A
  wrong NSG revert can sever a legitimate public endpoint; isolating the wrong VM
  can take a management plane offline during the very incident you are containing.
- **Confidence is not correctness.** A high-confidence detection can still be
  wrong; an automatic destructive response on a false positive creates a second
  incident.
- **Accountability.** A human approves every state change, so there is always a
  named owner for the action - not a model, not a rule.

## Approval workflow (design -> approved)

1. **Design** - author the playbook outline (trigger, actions, connectors,
   automation level per action, rollback).
2. **Safety review** - run the
   [AUTOMATION_SAFETY_CHECKLIST.md](AUTOMATION_SAFETY_CHECKLIST.md). Any
   destructive action must snapshot prior state and route to an owner-approver.
3. **Lab test** - execute against synthetic/lab resources only; capture results
   in [sample-playbook-test-results.json](sample-playbook-test-results.json) per
   the [PLAYBOOK_TEST_PLAN.md](PLAYBOOK_TEST_PLAN.md).
4. **Peer + approver review** - detection engineering peer review, plus the
   accountable approver for the affected system (network on-call for NSG,
   application owner for SP credentials, identity for roles).
5. **Change record** - raise a change per
   [../change-approval/CHANGE_APPROVAL_MODEL.md](../change-approval/CHANGE_APPROVAL_MODEL.md);
   attach test evidence and rollback plan.
6. **Enable disabled / off by default** - playbooks ship disabled; enabling is a
   deliberate, approved change. Nothing auto-enables.
7. **Post-execution review** - after any live run, review the run logs (below).

## How to review logs after playbook execution

- Confirm the Logic App run history shows the expected actions and outcomes.
- Confirm the incident timeline records the action, the approver, and the
  timestamp.
- Confirm the snapshot artefact (prior NSG rule, prior role assignment) was
  captured for rollback.
- Confirm no unexpected side effects (extra API calls, unintended scope).

## How to roll back failed automation

- Every destructive playbook snapshots prior state first, so rollback re-applies
  the snapshot (see
  [../change-approval/ROLLBACK_PLAN_TEMPLATE.md](../change-approval/ROLLBACK_PLAN_TEMPLATE.md)).
- If a run half-completed, treat it as an incident: stop the workflow, restore
  from snapshot, verify, and RCA why the guard rails let it through.

## Honest scope

These are playbook *designs and a validation process*, not deployed, credentialed
Logic Apps. The one Logic App in the live path (Mode C) is deployed **disabled**,
with no connectors and no secrets. This capability is scored under **Automation
safety** in the
[production readiness scorecard](../reports/PRODUCTION_READINESS_SCORECARD.md).
