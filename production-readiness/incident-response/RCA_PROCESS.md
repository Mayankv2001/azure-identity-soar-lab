# Root Cause Analysis Process (Blameless)

> **Synthetic lab document.** The worked values reference the fictional incident
> **CP-INC-2001** — `@contoso.com` personas, `TEST-NET` IP ranges, synthetic
> resources. Nothing here has run against a production tenant. This is the RCA
> discipline I would run for the detection estate in these labs, written to
> production standard. It is consistent with the RCA guidance already in
> [`docs/DRI_RUNBOOK.md`](../../docs/DRI_RUNBOOK.md) and the completed template in
> [`security-engineering/incident-packet/RCA_TEMPLATE.md`](../../security-engineering/incident-packet/RCA_TEMPLATE.md).

## Purpose and principles

An RCA exists to make the **next** incident less likely or less severe. It is not a
performance review, a courtroom, or a formality attached to closure. Two principles
govern everything below.

1. **Blameless.** We analyse the **control that failed or was missing**, never the
   person who clicked. "chris.walker approved an MFA prompt" is not a root cause;
   "push-approval MFA allowed a fatigue attack to succeed, and no risk-based
   Conditional Access blocked the foreign high-risk sign-in" is. People operate
   inside the controls we give them; if the outcome was bad, the controls were
   insufficient. Blame kills the honest reporting that RCAs depend on.
2. **Root cause = failed control.** Every root cause must name a control that, had
   it been present and working, would have broken the chain. This is what makes an
   RCA actionable: each failed control becomes an owned, dated action that feeds
   back into the labs as a versioned detection or policy change — closing the loop
   from incident to control improvement.

## When and who

- **Trigger:** every P1 and P2 gets an RCA. P3/P4 get a lightweight note if there
  is a control lesson; otherwise they feed tuning metrics directly.
- **Author:** the DRI who owned the incident.
- **Deadline:** written within **five business days** of resolution.
- **Review:** at the weekly operations review, alongside the daily-report metrics
  (SLA breaches, false-positive rate by detection, MITRE coverage deltas).
- **Output:** a completed RCA (template below) plus action items with owners and
  due dates that are tracked to done.

## The five questions an RCA must answer

1. **What happened?** A factual timeline, detection → acknowledgement → containment
   → resolution, with timestamps compared against SLA.
2. **What was the root cause?** The control(s) that failed or were missing.
3. **What contributed?** Conditions that made it worse or slower but were not the
   root cause (contributing factors).
4. **Did detection and response perform?** Did the right rule fire, at the right
   severity, fast enough? Which manual steps should become playbook steps?
5. **What are we changing?** Actions with a single owner and a due date each.

---

## RCA template

Copy this block for each incident. The bracketed values show the shape using
CP-INC-2001; replace them with your incident's facts.

```markdown
# Root Cause Analysis — [CP-INC-2001]

**Incident:** [Identity-to-control-plane attack chain (synthetic)]
**Severity:** [P1 / Critical]   **Blast radius:** [100 / 100]
**DRI / author:** [amelia.chen@contoso.com]
**Resolved:** [2026-06-30 12:30 UTC]   **RCA due:** [2026-07-07]
**Status:** [Draft / In review / Complete]

## 1. Summary
[A compromised privileged Cloud Operations identity was walked from a phished
sign-in to an internet-exposed datacenter management endpoint in under two hours.
Eight detections correlated into one Critical incident. Contained without
confirmed data loss (synthetic).]

## 2. Timeline (UTC — compare against SLA)
| Time | Event | Source |
|------|-------|--------|
| [09:00] | [First malicious event: high-risk sign-in from Latvia succeeds] | [CP-DET-001] |
| [09:11] | [MFA-fatigue approval — account takeover] | [CP-DET-002] |
| [09:25] | [Ticketless PIM activation of Application Administrator] | [CP-DET-003] |
| [09:40] | [Client secret added to sp-infra-deploy] | [CP-DET-004] |
| [10:05] | [sp-infra-deploy granted Owner on rg-prod-dc-mgmt] | [CP-DET-005] |
| [10:20] | [NSG rule opens RDP 3389 to 0.0.0.0/0; endpoint internet-reachable] | [CP-DET-006/007] |
| [10:40] | [Correlated Critical incident raised; Defender confirms probing] | [CP-DET-008] |
| [10:41] | [DRI paged and acknowledged] | [SOAR] |
| [10:43] | [Sessions revoked (automatic)] | [CP-PB-04] |
| [11:20] | [Full containment applied] | [DRI + on-calls] |
| [12:30] | [Resolved and verified] | [DRI] |

**SLA check:** [Ack target 15 min — met (1 min). Resolve target 4 h — met
(1h49m). Note: 100 min elapsed between first stage and the correlated incident.]

## 3. Root cause(s) — controls that failed
[Ordered by earliest break point in the attack graph.]
1. [**No policy denying public management-port exposure.** The NSG rule opening
   RDP to 0.0.0.0/0 was accepted at write time. This is the earliest single
   control that, if present, would have broken the chain.]
2. [**Standing Contributor on sp-infra-deploy.** Broad standing rights meant one
   added secret unlocked control-plane changes.]
3. [**Ticketless PIM activation.** Application Administrator activated with no
   linked change record.]
4. [**Phishing-vulnerable push MFA.** Fatigue attack succeeded; no risk-based
   Conditional Access blocked the foreign high-risk sign-in.]

## 4. Contributing factors (made it worse/slower, not the root cause)
- [Correlation reached Critical only at stage 7–8; the earlier single-stage
  alerts were individually sub-Critical, so the chain ran ~100 minutes before a
  P1 fired.]
- [No follow-on behavioural detection for post-exposure RDP brute-force.]
- [Historical debt: it was unclear whether the SP's standing Contributor was ever
  justified.]

## 5. Detection & response performance
- **Detection:** [7 of 7 telemetry stages detected and correlated into one
  incident. Gap: correlation severity should reach Critical at stage 4–5.]
- **Response:** [Least-destructive-first ordering held; evidence preserved before
  rotation. Candidate for playbook promotion: the JIT-lock decision on the exposed
  host was manual and should become a gated card.]

## 6. Action items
| # | Action | Type | Owner | Due |
|---|--------|------|-------|-----|
| 1 | [Deploy deny-public-management-exposure policy (Audit → Deny)] | [Azure Policy] | [Cloud Security] | [2 weeks] |
| 2 | [Migrate Cloud Operations to phishing-resistant MFA] | [Conditional Access] | [Identity] | [4 weeks] |
| 3 | [Re-scope sp-infra-deploy to least privilege / managed identity] | [RBAC / IaC] | [Cloud Engineering] | [3 weeks] |
| 4 | [Raise correlation severity at stage 4] | [Detection tuning] | [Detection engineering] | [2 weeks] |
| 5 | [Access review of standing privilege across Cloud Operations] | [Governance] | [Identity governance] | [4 weeks] |

## 7. Loop-back
[Each action becomes a versioned detection or policy change through the
detection-as-code pipeline, reviewed like any code. Reference the resulting
commit/PR here when shipped.]
```

---

## Evidence-collection checklist

Evidence is collected **before** eradication and recovery, because rotating
credentials and reverting rules **destroys state**. The rule is: *capture first,
then rotate.* This checklist runs during CONTAIN, before any gated action that
mutates state. It aligns with the evidence section of
[`CONTAINMENT_PLAN.md`](../../security-engineering/incident-packet/CONTAINMENT_PLAN.md).

### Identity evidence
- [ ] Sign-in logs for the affected UPN across the full incident window (auth
      method, risk level, source IP/country, session ids).
- [ ] Audit logs for the identity (role activations, consent grants, directory
      changes).
- [ ] The PIM activation record — who/what/when and **whether a ticket was
      linked** (its absence is itself evidence).
- [ ] Confirmation of which sessions/tokens existed *before* revocation (so you can
      later confirm none reissued).

### Service-principal evidence
- [ ] The attacker-added credential's **key id and creation timestamp**, captured
      **before removal** (once removed, this is gone).
- [ ] The full current credential list on the SP (to distinguish attacker secrets
      from legitimate ones before rotation).
- [ ] The RBAC write event granting Owner (actor, target scope, timestamp).

### Network / exposure evidence
- [ ] The offending NSG/firewall **rule definition before revert** (the snapshot
      captured by the containment playbook — verify it exists).
- [ ] Any inbound-connection logs on the exposed management port for the exposure
      window — this answers *did anyone actually get in.*
- [ ] The affected host's public-IP/exposure configuration at time of incident.

### Platform / detection evidence
- [ ] The Defender for Cloud (or equivalent) alert details in full.
- [ ] The correlated incident record and each contributing detection's raw output.
- [ ] The blast-radius score decomposition as computed at incident time.

### Chain-of-custody hygiene (even in a lab)
- [ ] Record **who** collected each item and **when** (UTC).
- [ ] Store evidence read-only; work from copies.
- [ ] Note anything you could **not** collect and why — gaps are findings too.
- [ ] Timestamp the transition from "evidence captured" to "eradication started",
      so the RCA timeline shows capture preceded rotation.

---

## Anti-patterns this process exists to prevent

- **Naming a person as the root cause.** If your root cause is a human action, keep
  asking "what control should have caught or prevented that?" until you reach a
  control.
- **Closing without an RCA task.** Closure requires the learning loop to be *open*,
  even if the full document lands within five days.
- **Rotating before capturing.** Destroying the attacker-added key before recording
  its id and timestamp loses the single best artefact of what the attacker did.
- **Action items without an owner or a date.** An unowned, undated action is a wish,
  not a fix — and it will not survive to the next weekly review.
- **Treating a false positive as noise.** A false-positive close is an RCA-lite
  signal that tunes a detection (as INC-1005 became the DET-002 v1.1.0 exclusion).
