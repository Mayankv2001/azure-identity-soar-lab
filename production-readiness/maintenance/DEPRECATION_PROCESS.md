# Detection deprecation process

Lab-safe, synthetic. How a detection is retired. Retiring a rule is a change like
any other - reviewed, tested, and reversible - not a silent delete.

## When to deprecate a rule

- It stopped earning its alert volume (all noise, no true positives over N review
  cycles).
- It is superseded by a better rule (broader, more precise, or lower cost).
- Its data source is being retired (a connector or custom table is going away).
- Its technique is now covered by a platform capability (e.g. an Entra ID
  Protection or Defender detection) that makes the custom rule redundant.

## Process

1. **Propose** - the rule owner raises a deprecation with evidence: alert/FP
   history, superseding rule (if any), and dependency impact.
2. **Impact review** - which incidents, playbooks, or reports depend on this
   rule? Check the dependency notes in
   [MAINTENANCE_OPERATING_MODEL.md](MAINTENANCE_OPERATING_MODEL.md).
3. **Notice period** - move the rule to **disabled/audit-only** for one review
   cycle rather than deleting it immediately. Confirm nothing breaks and no
   coverage gap opens.
4. **Change record** - raise a change per
   [../change-approval/CHANGE_APPROVAL_MODEL.md](../change-approval/CHANGE_APPROVAL_MODEL.md);
   attach the evidence and the rollback (re-enable) plan.
5. **Archive, don't erase** - keep the KQL, YAML, and version history in the repo
   under an archived/deprecated marker so the reasoning is auditable and the rule
   can be revived.
6. **Remove tests deliberately** - remove or mark the rule's regression tests so
   the suite stays green, and record why in the commit.
7. **Update the registers** - remove the rule from the
   [rule owner register](RULE_OWNER_REGISTER.md), the MITRE coverage matrix, and
   the scorecard evidence if relevant.

## Rollback

Because the rule is disabled (not deleted) for a notice period and archived (not
erased) afterwards, revival is: re-enable, re-add tests, version bump. A
deprecation that cannot be reversed within a cycle was done too fast.

## Honest note

No repo detection is being deprecated today. This documents the discipline so
that retiring a rule is as controlled as shipping one.
