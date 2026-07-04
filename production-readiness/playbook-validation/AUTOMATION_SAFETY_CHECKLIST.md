# Automation safety checklist

Lab-safe, synthetic. Run this before any playbook action is enabled. Every
destructive action must pass every relevant item. Derived from the repo's
three-question automation framework: **blast radius, reversibility, confidence.**

## Per-action safety gate

- [ ] **Blast radius assessed** - who/what else is affected if this runs on the
      wrong target? (identity session = tiny; NSG/RBAC/VM = large)
- [ ] **Reversibility known** - can it be undone in seconds (session revoke) or
      does it need a helpdesk round-trip / snapshot restore?
- [ ] **Confidence appropriate** - is the triggering signal deterministic
      (self-elevation, secret added) or behavioural (travel, checkout pattern)?
- [ ] **Automation level correct** - automatic only if reversible AND
      low-blast-radius AND high-confidence; otherwise approval required.
- [ ] **Snapshot before change** - destructive actions capture prior state (NSG
      rule, role assignment, credential metadata) for rollback.
- [ ] **Named approver** - the approver owns the affected system (network on-call,
      app owner, identity, workload owner), not just the SOC.
- [ ] **Audit trail** - action, approver, and timestamp are written to the
      incident timeline.
- [ ] **Kill switch** - the playbook can be disabled instantly, and ships
      disabled by default.
- [ ] **No secrets** - no credentials, tokens, or keys in the workflow, its
      parameters, or its logs.
- [ ] **No AI-triggered action** - AI output is advisory only; there is no path
      from a model to a state-changing call.
- [ ] **Rollback tested** - the rollback path has been exercised in the lab.
- [ ] **Post-run review defined** - who checks the run logs afterwards, and what
      they confirm.

## Classification quick reference

| Action | Automation level | Why |
|--------|------------------|-----|
| Enrich alert | automatic | read-only |
| Notify DRI / open ticket | automatic | no blast radius |
| Revoke sessions | automatic (Critical) / approval (else) | reversible; user re-authenticates |
| Require password reset | approval required | breaks service-account integrations |
| Revert NSG / firewall rule | approval required | can sever a legitimate endpoint |
| Rotate SP credential | approval required | can break dependent automation |
| Remove privileged role | approval required | can remove legitimate access |
| Isolate VM / restrict endpoint | approval required | service impact on a critical host |
| Disable user | approval required | highest blast radius; can lock out responders |
| Author RCA | manual only | human judgement |

## The one rule that overrides all others

If you cannot answer "how do I undo this" **before** the action runs, it does not
run automatically. Full stop.
