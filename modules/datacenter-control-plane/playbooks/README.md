# Control-plane SOAR playbooks

Ten playbook designs covering the response half of the attack chain (stages
9-11: enrich, contain, RCA). Machine-readable outlines are in
[control_plane_playbooks.json](control_plane_playbooks.json). The design
principle is the same as the parent lab: **automate what is reversible and
low-blast-radius; gate anything that can break a service or lock out
responders.**

## Automation classification

| Playbook | Action | Classification | Why |
|----------|--------|----------------|-----|
| CP-PB-01 | Notify DRI / on-call | automatic | No blast radius; speed matters |
| CP-PB-02 | Open incident ticket | automatic | Audit trail; no state change to assets |
| CP-PB-03 | Enrich alert + blast radius | automatic | Read-only; every incident needs context |
| CP-PB-04 | Revoke sessions | automatic (at Critical) | Reversible - user re-authenticates |
| CP-PB-05 | Revert NSG / firewall rule | human approval required | Could sever a legitimate public endpoint |
| CP-PB-06 | Remove / rotate SP credential | human approval required | Can break integrations that depend on the SP |
| CP-PB-07 | Remove privileged role assignment | human approval required | Could remove legitimately granted access |
| CP-PB-08 | Isolate VM / restrict endpoint | human approval required | Service impact on a critical management host |
| CP-PB-09 | Disable or contain user | human approval required | Highest blast radius; wrong target locks out responders |
| CP-PB-10 | Create RCA task | manual only | Human judgement and narrative required |

## Why network and security-control changes need the strongest guardrails

Reverting an NSG rule or isolating a VM is not like revoking a session. A
session revocation self-heals - the legitimate user signs back in. A network
change can:

- sever a genuine public endpoint that a business service depends on;
- take a critical management host offline during the exact incident you are
  trying to contain;
- create a second outage that the organisation blames on security, which
  teaches teams to route around you.

So every network or RBAC change in these playbooks: **snapshots current state
first** (so it is reversible), **routes to an approver who owns the affected
system** (network on-call, workload owner, application owner), and **records
the approval with actor and timestamp**. The playbook makes the safe path the
default path.

## DRI / on-call flow

1. CP-DET-008 raises the chain incident -> CP-PB-01 pages the primary DRI with
   the blast-radius card, CP-PB-02 opens the ticket, CP-PB-03 enriches.
2. CP-PB-04 revokes sessions automatically (Critical) - the one containment
   cheap enough to run unattended.
3. The DRI reviews the enriched chain and approves containment in
   least-destructive order: revert NSG (CP-PB-05), rotate SP credential
   (CP-PB-06), remove role assignment (CP-PB-07), restrict endpoint (CP-PB-08),
   contain user (CP-PB-09).
4. After eviction is confirmed, CP-PB-10 opens the blameless RCA task, which
   feeds versioned detection and Azure Policy changes.
