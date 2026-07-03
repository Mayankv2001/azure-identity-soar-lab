# Control: require approval for privileged role activation

**Illustrative concept - requires environment-specific configuration and testing.**

Privileged role activation is governed in Microsoft Entra Privileged Identity
Management (PIM), not by Azure Policy. This file documents the intended
configuration as code-adjacent settings so it can be reviewed and versioned like
any other control.

Counters: **CP-DET-003 / DET-005** (privileged role activation without a change
record).

## Intended PIM configuration (per protected role)

```yaml
role: Application Administrator      # repeat for Global Administrator, Privileged Role Administrator
activation:
  maximum_duration_hours: 4
  require_justification: true
  require_ticket_information: true   # binds activation to a change record
  require_approval: true
  approvers:
    - group: sg-pim-approvers
  require_mfa_on_activation: true
  require_conditional_access_context: true
notifications:
  on_activation: [security-operations@contoso.com]
```

## How it breaks the attack chain

In CP-INC-2001 the attacker activated Application Administrator with no ticket.
With `require_approval` and `require_ticket_information` enforced, that activation
would either be blocked pending approval or immediately visible to an approver -
turning a silent escalation into a decision point.

## Validation before production

1. Enable in report-only where available; measure activation friction.
2. Confirm break-glass accounts have a documented, monitored exception.
3. Confirm approver coverage across time zones (no single point of delay).
4. Pair with DET-005/CP-DET-003 so any bypass still detects.
