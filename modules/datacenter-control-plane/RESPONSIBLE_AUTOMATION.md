# Responsible automation

This module can recommend and, in a real tenant, execute response actions
against identity, RBAC and network controls. Those are exactly the actions that
cause self-inflicted outages when automated carelessly. This document is the
boundary policy.

## What can be automated safely

- **Enrichment and notification.** Read-only lookups (identity privilege, PIM
  eligibility, SP permissions, asset criticality, current public exposure) and
  paging the DRI. No blast radius, and speed is pure upside.
- **Ticketing.** Creating and updating the auditable work item.
- **Session revocation - at Critical severity only.** It is fully reversible:
  the legitimate user simply re-authenticates. The worst case is thirty
  seconds of friction against hours of attacker dwell time.

## What needs human approval

Everything that changes the state of an asset or a permission:

- reverting or deleting NSG / firewall rules;
- removing or rotating service principal credentials;
- removing privileged role or RBAC assignments;
- isolating a VM or restricting a management endpoint;
- disabling or containing a user account.

Each of these routes to an approver who **owns the affected system** (network
on-call, application owner, workload owner, or the SOC DRI), and each snapshots
current state first so the action is reversible.

## Why network and security-control changes need strong guardrails

The blast radius of a network change is unbounded in a way an identity action
is not. An over-broad NSG revert can cut a production service; isolating the
wrong VM can take a management plane offline mid-incident. A wrong containment
action does not just fail to help - it creates a second incident and erodes the
trust that lets security act quickly next time. The guardrails (snapshot,
owner-approval, audit) exist to keep automation a force multiplier rather than a
new source of outages.

## Why AI output must be advisory only

The AI layer in the parent lab summarises and recommends; it does not act.
Applied here that rule is even stricter, because the actions in scope are
destructive and irreversible-in-practice. Three reasons:

1. **Attacker-influenced input.** Telemetry contains attacker-controlled
   strings; a model that could trigger a network change on that input is a
   remote-control primitive for the attacker.
2. **Confidence is not correctness.** A fluent, wrong recommendation to isolate
   a critical host must never become an automatic isolation.
3. **Accountability.** A human approves every state change, so there is always a
   named owner for every action - not a model.

The AI briefs, the human decides, the playbook acts.

## How every recommendation and action is audited

- Every detection alert, correlation decision and blast-radius score is written
  to `demo-output/` (in production, to the incident record and the workspace).
- Every playbook records the action, the approver, and the timestamp on the
  incident timeline.
- State-changing playbooks snapshot the prior configuration before acting, so
  the audit trail also contains the rollback artefact.
- The RCA task (CP-PB-10) links each hardening action back to the root cause,
  closing the loop from incident to versioned control change.
