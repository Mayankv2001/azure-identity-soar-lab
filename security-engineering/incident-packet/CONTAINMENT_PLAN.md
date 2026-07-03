# Containment plan - CP-INC-2001

Synthetic. Ordered least-destructive first, with each action's approval class.
The principle: automate the reversible, gate the blast radius, preserve evidence
before you rotate.

## Immediate actions (automatic - already applied by SOAR)

| # | Action | Playbook | Why safe to automate |
|---|--------|----------|----------------------|
| 1 | Page the DRI, open the ticket | CP-PB-01/02 | No asset state change |
| 2 | Enrich entities + compute blast radius | CP-PB-03 | Read-only |
| 3 | Revoke chris.walker sessions and tokens | CP-PB-04 | Reversible - user re-authenticates |

## Approval-gated actions (human approval required)

Perform in this order. Each snapshots current state before acting.

| # | Action | Playbook | Approver | Rollback |
|---|--------|----------|----------|----------|
| 4 | Revert NSG rule allow-rdp-temp | CP-PB-05 | DRI + network on-call | Re-apply snapshot if legitimate |
| 5 | Remove attacker SP credential; rotate remaining | CP-PB-06 | DRI + app owner | Owner re-issues from key vault |
| 6 | Remove Owner on rg-prod-dc-mgmt; deactivate PIM role | CP-PB-07 | DRI | Re-grant via PIM if legitimate |
| 7 | JIT-lock / isolate vm-dc-mgmt-01 if login found | CP-PB-08 | DRI + workload owner | Restore config once clean |
| 8 | Disable chris.walker if takeover confirmed | CP-PB-09 | DRI (manager notified) | Re-enable after eviction |

## Evidence to collect before rotating

Rotating credentials and reverting rules destroys state - capture it first:

- The added SP credential's key id and creation timestamp (before removal).
- The NSG rule definition (before revert) - already snapshotted by CP-PB-05.
- Sign-in and audit logs for chris.walker and sp-infra-deploy for the window.
- Defender for Cloud alert details and any inbound connection logs on
  vm-dc-mgmt-01's RDP port.
- The PIM activation record and the role-assignment write event.

## Verification (attacker actually evicted, not just quiet)

- Confirm no new tokens issued for chris.walker after session revocation.
- Confirm sp-infra-deploy has no remaining unexpected credentials.
- Confirm no successful interactive login landed on vm-dc-mgmt-01.
- Confirm the NSG no longer contains any internet-wide management rule.
- Re-run the detections against the post-containment window and confirm silence.

## What must not be automated here

Every action from #4 onward touches a network control, an RBAC assignment or a
critical host. A wrong automatic revert could sever a legitimate service or take
the management plane offline during response. Human approval on these is not
bureaucracy - it is the control that keeps containment from becoming a second
outage. See [RESPONSIBLE_AUTOMATION.md](../../modules/datacenter-control-plane/RESPONSIBLE_AUTOMATION.md).
