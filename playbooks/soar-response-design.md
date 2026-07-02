# SOAR response design

Six Logic App-style playbooks respond to incidents raised by the seven
detections. The design principle: **automate enrichment and containment that is
cheap to reverse; require a human for anything with blast radius.** AI output
never triggers an action - it advises the analyst who does.

Machine-readable outlines for all six playbooks live in
[logic-app-pseudocode.json](logic-app-pseudocode.json).

## Playbook catalogue

| Playbook | Trigger | Automation level | Approver | Used by |
|----------|---------|------------------|----------|---------|
| PB-01 Enrich alert | Sentinel incident created | Full-auto | none | all detections |
| PB-02 Notify DRI / on-call | Incident severity High or Critical | Full-auto | none | all detections |
| PB-03 Open ticket | Sentinel incident created | Full-auto | none | all detections |
| PB-04 Revoke sessions | Identity-compromise incidents | Full-auto for Critical, else approval | SOC DRI | DET-001, DET-002, DET-003, DET-005 |
| PB-05 Require password reset | Confirmed credential compromise | Approval required | SOC DRI | DET-001, DET-002 |
| PB-06 Disable user | Confirmed account takeover | Approval required | SOC DRI + user's manager notified | DET-001, DET-003, DET-004, DET-005, DET-006 |

## Automation vs approval decision matrix

Three questions decide the automation level of any response action:

| Question | Full-auto if... | Approval if... |
|----------|-----------------|----------------|
| **Blast radius** - who else is affected? | Only the attacker's session (enrich, notify, ticket, revoke) | Business processes stop (disable user, disable service principal) |
| **Reversibility** - how hard to undo? | Seconds to undo, self-healing (user just signs in again) | Requires helpdesk round-trip or breaks automation (password reset on a service account) |
| **Confidence** - how sure is the detection? | Deterministic signal (self-elevation, secret added off-hours) at Critical severity | Behavioural signal that has a plausible benign explanation (travel, checkout patterns) |

Worked examples:

- **Revoke sessions** is full-auto at Critical severity: worst case, a legitimate
  user re-authenticates - thirty seconds of friction against hours of attacker
  dwell time. At High and below it queues for one-click approval.
- **Disable user** always needs a human. Disabling the wrong account (say, the
  service-desk analyst whose identity the attacker borrowed) can lock out the
  very people responding, so the DRI confirms identity context first.
- **Password reset** always needs a human: forced resets on service accounts can
  break integrations, and resets during an active MFA-fatigue attack must be
  paired with MFA re-registration or the attacker simply prompts again.

## DRI / on-call notification flow

1. Sentinel incident created or severity raised to High/Critical.
2. PB-02 posts an adaptive card to the SOC Teams channel: incident id, title,
   severity, entities, top three triage steps, deep link to the incident.
3. Critical incidents additionally page the on-call DRI (PagerDuty/Opsgenie
   webhook) with a 15-minute acknowledgement SLA (see docs/DRI_RUNBOOK.md).
4. No acknowledgement within SLA escalates to the secondary on-call and the
   team lead; the escalation itself is logged on the incident timeline.
5. Every approval-required action arrives as a Teams approval card to the DRI -
   approve/reject is recorded with actor and timestamp for audit.

## Rollback notes

| Playbook | Rollback |
|----------|----------|
| PB-04 Revoke sessions | None needed - user re-authenticates. |
| PB-05 Password reset | Helpdesk-assisted reset with identity verification. |
| PB-06 Disable user | Re-enable the account; sessions and tokens must be re-established. |
| PB-01/02/03 | Informational only - close ticket / mark notification as false alarm. |
