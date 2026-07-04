# Go-live approval checklist

Lab-safe, synthetic. The final sign-off before a detection or playbook is enabled
in a real production tenant. It is deliberately short and deliberately hard - a
single gate with named human approvers.

> **This repository has NOT completed this checklist.** It is provided to show
> what a responsible go-live gate looks like, and to make explicit that nothing
> in this repo is production-approved.

## Preconditions

- [ ] The [pre-production checklist](PRE_PRODUCTION_CHECKLIST.md) is fully ticked
      against the target tenant (not a lab).
- [ ] The rule/playbook has run in audit mode long enough to characterise its
      real-world false-positive rate.
- [ ] The [production readiness scorecard](../reports/PRODUCTION_READINESS_SCORECARD.md)
      has been re-scored against the real environment.

## Evidence bundle (attached to the change record)

- [ ] Audit-mode alert and false-positive history
- [ ] Tuning changes made, versioned and tested
- [ ] Rollback plan, tested
      ([../change-approval/ROLLBACK_PLAN_TEMPLATE.md](../change-approval/ROLLBACK_PLAN_TEMPLATE.md))
- [ ] Post-deployment monitoring plan (canary / alert-volume watch)
- [ ] RBAC review confirming least privilege for anyone who can change or run it

## Named approvals

| Approval | Role | Signed | Date |
|----------|------|--------|------|
| Detection owner | Detection Engineering | | |
| Security owner | SecOps Lead | | |
| Affected-system owner | Network / Identity / Cloud Platform (as applicable) | | |
| Change approver | Security Manager | | |

## Go / no-go

- [ ] **Go** - all preconditions met, evidence attached, all approvals signed,
      rollback tested, monitoring ready.
- [ ] **No-go** - record the blocking item and the owner to close it.

## After go-live

- [ ] Monitor per the post-deployment plan for the agreed window.
- [ ] Move the rule's promotion state to **Production approved** only after the
      monitoring window passes clean
      ([../tuning/DETECTION_PROMOTION_GATES.md](../tuning/DETECTION_PROMOTION_GATES.md)).
- [ ] Update the [rule owner register](../maintenance/RULE_OWNER_REGISTER.md).

The point of this gate is that "production approved" is earned by evidence and
signed by named humans - never assumed, never automatic.
