# DRI / on-call rotation model

Lab-safe, synthetic operating model for a Directly Responsible Individual (DRI)
on-call rotation covering the detections in this repository. All people are
fictional personas (`@contoso.com`). Nothing here reflects a real roster, a real
employer, or a live paging integration.

## Roles

| Role | Purpose | Who (persona) |
|------|---------|---------------|
| Primary DRI | First responder; owns the incident until resolved or handed over | lena.novak@contoso.com |
| Secondary DRI | Backstop if primary does not acknowledge; second pair of hands on majors | tom.becker@contoso.com |
| Escalation contact | Detection/engineering escalation for tuning and rule behaviour | ravi.menon@contoso.com |
| Incident Commander (IC) | Runs coordination on P1/P2 majors; owns comms and decisions | daniel.wright@contoso.com |
| Communications owner | Drafts and sends stakeholder/exec updates during a major | grace.kim@contoso.com |
| SecOps Lead | Accountable owner of the detection estate and the rota itself | amara.okafor@contoso.com |

The DRI model's core principle: **one owner at any moment.** Fixing is a team
sport; owning is singular. The primary DRI holds the incident end to end for
their shift - triage, containment decisions, communication, and the hand-off.

## Rotation

- Weekly rotation, handover at the Monday operations stand-up.
- Primary and secondary never the same person in the same week.
- Follow-the-sun handover between two notional regions (Australia/Sydney and a
  Europe timezone) so there is always a waking primary. See
  [HANDOVER_TEMPLATE.md](HANDOVER_TEMPLATE.md) and
  [sample-oncall-schedule.json](sample-oncall-schedule.json).
- Rota is published two weeks ahead; swaps are recorded, not verbal.

## Acknowledgement SLAs (aligned to the incident severity model)

| Severity | Acknowledge | Paging behaviour |
|----------|-------------|------------------|
| P1 / Critical | 15 minutes | Page primary immediately; auto-escalate to secondary at 15 min |
| P2 / High | 30 minutes | Page primary; secondary notified |
| P3 / Medium | 4 hours | Channel notification; business-hours follow-up |
| P4 / Low | 24 hours | Queue for daily review |

These mirror the SLAs in
[../incident-response/SEVERITY_MODEL.md](../incident-response/SEVERITY_MODEL.md)
and the DRI runbook at [../../docs/DRI_RUNBOOK.md](../../docs/DRI_RUNBOOK.md).

## When to wake someone up

Page a human out of hours only when the answer to any of these is yes:

- A **P1** incident is open (identity-to-control-plane chain, Tier-0 asset,
  confirmed account takeover, or public exposure of a management surface).
- A **P2** is unacknowledged past its SLA.
- A detection is **flooding the queue** and risks masking a real incident.
- A containment action needs **approval** and the DRI cannot reach the approver.

Do **not** wake anyone for: a single posture finding (DET-007), a Medium alert
inside SLA, or a known-benign pattern already logged for tuning.

## When to escalate to other teams

| Trigger | Escalate to |
|---------|-------------|
| NSG/firewall revert, public exposure (CP-DET-006/007) | Network on-call (felix.nguyen@contoso.com) |
| Conditional Access / privileged role / SP credential (DET-003/004/005, CP-DET-003/004) | Identity platform owner |
| Resource-group ownership / Azure Policy / workspace | Cloud Platform Engineer (priya.sharma@contoso.com) |
| Suspected insider | SecOps Lead + HR/legal channel - do not confront the user |
| Tier-0 assets (domain-admins safe, Global Administrator, rg-prod-dc-mgmt) | IC + SecOps Lead immediately |

## Honest scope

This is a documented operating model, not a staffed, paging-integrated rotation.
It maps directly to how the repo's detections and the CP-INC-2001 scenario would
be worked, and it is scored under **DRI / on-call model** in the
[production readiness scorecard](../reports/PRODUCTION_READINESS_SCORECARD.md)
as a *documented, not-yet-operating* capability.
