# DRI / on-call runbook

How the Directly Responsible Individual model works for this detection estate.
Written the way I would want to receive it at 02:00: what fires, how fast I must
move, who I wake up, and what I write down afterwards.

## Severity and SLA matrix

| Severity | Acknowledge | Resolve | Paging behaviour |
|----------|-------------|---------|------------------|
| Critical | 15 minutes | 4 hours | Page primary DRI immediately; auto-escalate at 15 min |
| High | 30 minutes | 8 hours | Teams channel + DRI mention |
| Medium | 4 hours | 72 hours | Teams channel, business hours follow-up |
| Low | 24 hours | 7 days | Queue for daily review |

These are the same values enforced in code (src/incident_builder.py,
SLA_MATRIX) and reported daily (output/daily_security_report.md) - the SLA you
are paged on is the SLA the metrics measure.

## On-call rotation

- Primary and secondary DRI, weekly rotation, handover at Monday stand-up.
- Handover includes: open incidents, tuning changes in flight, noisy detections
  to watch, and any expiring exceptions.
- The DRI owns the incident end-to-end during their shift: triage, containment
  decisions (playbook approvals), communication, and the handoff note. Fixing
  is a team sport; owning is singular - that is the point of the model.

## First 15 minutes of a Critical incident

1. Acknowledge the page (stops the escalation timer).
2. Open the incident and the PB-01 enrichment comment: who is the identity, is
   it privileged, which safes/apps are in scope.
3. Read the AI triage briefing (output/ai/) - treat it as a well-prepared
   colleague's first take, then verify against the evidence.
4. Approve or reject queued containment cards (revoke sessions is usually
   already done at Critical; disable-user waits for you).
5. Work the incident's triage checklist top to bottom; it is ordered
   least-destructive first.
6. Post a one-line status to the SOC channel every 30 minutes until contained.

## Escalation paths

| Situation | Escalate to |
|-----------|-------------|
| No ack in 15 min (Critical) | Secondary DRI, then team lead (automated) |
| Tier-0 assets involved (domain admins safe, Global Administrator) | Team lead + identity platform owner immediately |
| Suspected insider | Team lead + HR/legal channel - do not confront the user |
| Business-critical service account containment | Application owner before disabling |

## Communications

- Single incident channel per Critical incident; the DRI posts updates, nobody
  else speculates in it.
- Status updates answer three questions: what do we know, what have we done,
  what is next (with a time).
- False positives are closed with the reason recorded - they feed tuning, not
  the bin (see INC-1005 in the sample run, which became the DET-002 v1.1.0
  exclusion).

## After the incident: RCA

Blameless, written by the DRI within five business days, reviewed at the weekly
operations review. Template:

1. Timeline (detection -> acknowledgement -> containment -> resolution, with
   timestamps; compare against SLA).
2. Root cause - the control that failed or was missing, not the person.
3. Detection performance - did the right rule fire, at the right severity, fast
   enough? Any coverage gap exposed?
4. Response performance - which manual steps should become playbook steps?
5. Actions - owner and due date each; tuning proposals become versioned rule
   changes through the pipeline (detection-as-code, reviewed like any code).

## Weekly operations review

Standing agenda driven by the daily report metrics: SLA breaches (each one gets
a why), false-positive rate by detection, tuning changes shipped, MITRE
coverage deltas, and the top risky identities list for the identity platform
team. Continuous improvement is the deliverable; the metrics are just evidence.
