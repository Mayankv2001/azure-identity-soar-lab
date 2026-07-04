# Incident Response Operating Model

> **Scope and honesty note.** This is the operating model for the *synthetic*
> Azure Identity Threat Detection & SOAR Lab. Every incident, identity, resource
> and timestamp referenced here is fictional (all personas are `@contoso.com`;
> all IP addresses are `TEST-NET` documentation ranges). Nothing in this document
> has run against a production Microsoft tenant. It is written the way a real
> operating model reads because the point of the portfolio is to show the
> *discipline*, not to claim production Azure-scale operations experience. My
> production background is in identity and privileged-access security; this
> document expresses how I would run response for the detection estate in these
> labs.

The operating model answers four questions a SecOps team must be able to answer
on its worst day: **who owns this, how fast must we move, who do we wake up, and
what do we write down afterwards.** It is deliberately consistent with the values
already enforced in code (`src/incident_builder.py`, `SLA_MATRIX`) and reported
daily (`output/daily_security_report.md`) — the SLA you are paged on is the SLA
the metrics measure. It also plugs directly into the Directly Responsible
Individual model in [`docs/DRI_RUNBOOK.md`](../../docs/DRI_RUNBOOK.md) and the
worked control-plane incident **CP-INC-2001**.

---

## 1. The lifecycle

Every incident moves through six operational states. The canonical machine-readable
definition — entry criteria, exit criteria, owning role and SLA per state — lives
in [`INCIDENT_LIFECYCLE_STATES.json`](./INCIDENT_LIFECYCLE_STATES.json); this
section is the human narrative.

```
  ALERT ──▶ TRIAGE ──▶ CONTAIN ──▶ ERADICATE ──▶ RECOVER ──▶ CLOSE
    │          │           │            │             │          │
 detection  is it real  stop the    remove the    return to   RCA +
  fires    & how bad?    bleeding    foothold      known-good  learning
```

The states are gates, not a suggestion. You do not eradicate before you contain,
and you do not close before the RCA exists. The lifecycle is intentionally
**reversible under evidence**: if eradication uncovers a second foothold, you drop
back to CONTAIN rather than pushing forward to RECOVER.

### ALERT

A detection fires. In this estate that is a Sentinel-style analytics rule
(`DET-00x`, `CP-DET-00x`) producing an alert, or the correlation engine linking
several alerts into one incident (`CP-DET-008`). SOAR performs only **read-only,
reversible, no-approval-needed** automation here: page the DRI, open the ticket,
and enrich the entities. Nothing that changes asset state happens without a human
past this line — with the single, deliberate exception of session revocation at
Critical, which is reversible (the user simply re-authenticates).

**Exit:** an accountable DRI has acknowledged the page and the incident has an ID.

### TRIAGE

The DRI decides: is this real, and how bad. They read the enrichment comment (who
is the identity, is it privileged, what is in scope), read the AI triage briefing
(`output/ai/`) as a well-prepared colleague's *first take* — then verify it against
the evidence, because model input is attacker-influenceable data — and assign a
severity from the [Severity Model](./SEVERITY_MODEL.md). For CP-INC-2001 triage is
short: a privileged identity, a high-privilege service principal, and an
internet-exposed management port is an unambiguous P1.

**Exit:** severity is set, the incident is confirmed real (or closed as a false
positive with a recorded reason that feeds tuning), and a containment plan exists.

### CONTAIN

Stop the bleeding without becoming a second outage. Containment is ordered
**least-destructive first** and every approval-gated action snapshots state before
acting (see [`CONTAINMENT_PLAN.md`](../../security-engineering/incident-packet/CONTAINMENT_PLAN.md)).
For CP-INC-2001 the order is: revoke sessions (auto at Critical) → revert the NSG
rule → remove/rotate the service-principal credential → remove the Owner
assignment and deactivate the PIM role → JIT-lock the exposed VM → disable the
user if takeover is confirmed. The blast radius is capped before the root cause is
fully understood; that is the entire purpose of this state.

**Exit:** the attacker can no longer act — no new tokens issued, no live exposed
surface, no usable added credential.

### ERADICATE

Remove the foothold, not just the symptom. Rotate every credential the attacker
touched or could have touched, remove attacker-created objects (the added client
secret, the Owner grant, the temporary NSG rule), and hunt for persistence you
have not yet seen. The guiding question: *if I re-enabled everything right now,
could they walk back in?* If yes, you are not done.

**Exit:** all attacker-introduced access, credentials and configuration are gone
and confirmed gone.

### RECOVER

Return affected services to a known-good state and verify the environment is
genuinely clean, not just quiet. Re-run the detections against the
post-containment window and confirm silence; confirm no successful interactive
login landed on the exposed endpoint; restore the user with phishing-resistant MFA
and a password reset. Recovery is a verification state as much as a restoration
state — "quiet" is not the same as "evicted".

**Exit:** services restored, verification checks all pass, business owner
confirms normal operation.

### CLOSE

The incident is closed only when the blameless RCA task exists and the immediate
verification is complete. The full RCA is written within **five business days**
(see [`RCA_PROCESS.md`](./RCA_PROCESS.md)); closure does not wait for every action
item to ship, but it does wait for the *learning loop to be opened* — the root
cause named, the failed control identified, and owners/dates assigned.

**Exit:** RCA task raised, resolution note issued, action items owned and dated.

---

## 2. The DRI: who owns this

The response model is built on a single **Directly Responsible Individual** per
incident. The DRI is not necessarily the person who fixes each thing — fixing is a
team sport, drawing on identity, networking and platform on-call — but ownership
is **singular**. That is the whole point of the model: at 02:00 there is exactly
one person accountable for the incident end-to-end.

**The DRI owns:**

| Responsibility | What it means in practice |
|----------------|---------------------------|
| Triage decision | Sets severity, confirms real vs. false positive, owns the call |
| Containment approvals | Approves/rejects each gated playbook card; owns the blast-radius call |
| Sequencing | Enforces least-destructive-first ordering; preserves evidence before rotating |
| Communications | Posts every status update in the incident channel; nobody else speculates there |
| Escalation | Decides when to wake the specialist on-calls and leadership |
| Hand-off | Writes the hand-off note if the incident crosses a shift boundary |
| RCA ownership | Raises and writes the blameless RCA within five business days |

**The DRI explicitly does *not* own:** unilaterally deciding on legal/HR action
for a suspected insider (escalate, do not confront), or absorbing blame — the RCA
is blameless by design and targets failed controls, not the person who clicked.

On-call is a primary + secondary DRI, weekly rotation, handover at Monday
stand-up. Handover carries: open incidents, tuning changes in flight, noisy
detections to watch, and any expiring exceptions.

---

## 3. Escalation model

Escalation is **time-based** (the SLA clock forces it) and **scope-based** (the
nature of the assets forces it). Both fire independently.

### Time-based (automatic)

| Trigger | Escalates to | Mechanism |
|---------|--------------|-----------|
| No ack within 15 min (P1/Critical) | Secondary DRI, then team lead | Automated paging escalation |
| No ack within 30 min (P2/High) | DRI mention in SOC channel, then secondary | Automated |
| Resolve SLA at 75% elapsed | Team lead notified (P1/P2) | Automated warning |
| Resolve SLA breached | Team lead + recorded breach reason for weekly review | Automated + manual note |

### Scope-based (judgement, immediate)

| Situation | Escalate to | Why |
|-----------|-------------|-----|
| Tier-0 asset in scope (Global Administrator, domain-admin equivalents) | Team lead + identity platform owner, immediately | Blast radius is tenant-wide |
| High-privilege service principal abused (e.g. `sp-infra-deploy` in CP-INC-2001) | App owner + Cloud Engineering on-call | SP credentials survive user resets — durable persistence |
| Internet-exposed management plane (NSG/firewall opened to `0.0.0.0/0`) | Network on-call, immediately | Live exposure of a critical host |
| Suspected insider | Team lead + HR/legal channel — **do not confront the user** | Preserves evidence and process |
| Business-critical service account containment | Application owner *before* disabling | Avoids a self-inflicted outage |

For CP-INC-2001, three scope triggers fire at once (privileged identity,
high-privilege SP, internet-exposed management port) — which is exactly why it is
a P1 with a paged DRI, an engaged network on-call, and an engaged app owner within
the first half hour.

---

## 4. Communications cadence

One incident, one channel. The DRI posts; nobody else speculates in it. Every
status update answers three questions and nothing else: **what do we know, what
have we done, what is next (with a time).**

| Severity | Internal cadence | Stakeholder/exec update |
|----------|------------------|-------------------------|
| P1 (Critical) | Status in incident channel every **30 minutes** until contained | Exec update at declaration, at containment, and at resolution |
| P2 (High) | Status every **60 minutes** until contained | Exec update at containment and resolution if scope warrants |
| P3 (Medium) | Status at triage, containment and close | Summary in weekly operations review |
| P4 (Low) | Status at close | Rolled into weekly metrics |

The reusable message shells — initial notification, status update, exec update,
resolution note — live in [`COMMUNICATION_TEMPLATES.md`](./COMMUNICATION_TEMPLATES.md),
all with fictional placeholders only. False positives are closed with the reason
recorded so they feed tuning rather than the bin.

---

## 5. First-15-minutes checklist (Critical / P1)

Do these in order. It is written for the person who just got paged at 02:00.

1. **Acknowledge the page.** This stops the auto-escalation timer and tells the
   team an owner exists.
2. **Open the incident and the enrichment comment.** Who is the identity, is it
   privileged, which service principals / resource groups / hosts are in scope.
3. **Read the AI triage briefing** (`output/ai/`) as a first take — then verify it
   against the raw evidence before acting on it.
4. **Confirm the automatic containment already applied.** At Critical, session
   revocation is usually done; confirm it and confirm no new tokens issued.
5. **Set the severity** from the [Severity Model](./SEVERITY_MODEL.md) and, if P1,
   trigger the scope-based escalations that apply (network on-call, app owner,
   identity platform owner).
6. **Post the initial notification** to the incident channel using the template.
7. **Approve or reject the top queued containment card.** Start least-destructive:
   for CP-INC-2001 that is reverting the internet-facing NSG rule.

If you cannot complete these in 15 minutes, that itself is a signal — pull in the
secondary DRI rather than working alone.

---

## 6. First-30-minutes checklist (Critical / P1)

By the 30-minute mark, containment should be *in progress with the right people
engaged*, not merely acknowledged.

1. **Work the containment plan top to bottom**, least-destructive first, snapshotting
   state before each gated action (revert NSG → remove/rotate SP credential →
   remove Owner grant + deactivate PIM role → JIT-lock exposed host).
2. **Preserve evidence before you rotate anything** — added credential key id and
   timestamp, NSG rule definition, sign-in/audit logs for the window, Defender
   alert details, PIM activation record. Rotating destroys state; capture first.
3. **Confirm specialist on-calls are engaged** and each owns their action (network
   on the NSG, app owner on the SP, identity on the account and MFA).
4. **Answer the exposure question:** did any successful inbound login reach the
   exposed endpoint? This changes whether you are containing or breach-responding.
5. **Post the first 30-minute status update** (what we know / done / next + time)
   and, for P1, issue the first exec update.
6. **Open the RCA task now** — do not wait for close. A stub with the timeline
   started is enough; it will be completed within five business days.

---

## 7. Hand-off to specialist teams

The DRI stays the single owner, but the work is done with named specialist
on-calls. Each hand-off is explicit — what you are handing them, what you need
back, and what they must *not* do without you.

### To the networking team

- **Trigger:** any NSG/firewall change opening a management port to the internet,
  or any action that could sever legitimate traffic.
- **Hand them:** the offending rule definition, the affected NSG/host, the
  snapshot of prior state.
- **Need back:** the rule reverted, confirmation the management surface is no longer
  internet-reachable, and any inbound-connection logs on the exposed port.
- **Guardrail:** revert is approval-gated (DRI + network on-call together) — a wrong
  automatic revert could take the management plane offline during response.

### To the identity team

- **Trigger:** compromised identity, privileged-role abuse, MFA-fatigue takeover,
  or any Tier-0 identity in scope.
- **Hand them:** the affected UPN, its privilege and PIM eligibility, the sign-in
  and audit trail for the window.
- **Need back:** sessions confirmed revoked (no new tokens), password reset queued,
  phishing-resistant MFA enforced, and a read on how many peer identities share the
  same standing-privilege + push-MFA weakness.
- **Guardrail:** for a suspected insider, HR/legal path only — do not confront.

### To the platform / cloud-engineering team

- **Trigger:** service-principal credential abuse, RBAC changes (Owner/Contributor
  grants), or containment of a business-critical workload identity.
- **Hand them:** the SP name and privilege tier, the attacker-added credential
  details, the RBAC assignment to unwind, the affected resource group/subscription.
- **Need back:** attacker credential removed and remaining secrets rotated from key
  vault, the Owner assignment removed, and confirmation the SP is scoped back to
  least privilege as a follow-up action.
- **Guardrail:** contain a business-critical service account only after the
  application owner is engaged — avoid a self-inflicted outage.

Each hand-off closes back to the DRI, who confirms the exit criteria for the
current lifecycle state are met before advancing the incident.

---

## 8. How this connects to the rest of the repo

- **Severity and SLA** → [`SEVERITY_MODEL.md`](./SEVERITY_MODEL.md) and the
  `SLA_MATRIX` in `src/incident_builder.py`.
- **Lifecycle state machine** → [`INCIDENT_LIFECYCLE_STATES.json`](./INCIDENT_LIFECYCLE_STATES.json).
- **Communications** → [`COMMUNICATION_TEMPLATES.md`](./COMMUNICATION_TEMPLATES.md).
- **Learning loop** → [`RCA_PROCESS.md`](./RCA_PROCESS.md).
- **Worked incident** → the CP-INC-2001 packet under
  [`security-engineering/incident-packet/`](../../security-engineering/incident-packet/)
  and the control-plane module's
  [`RESPONSIBLE_AUTOMATION.md`](../../modules/datacenter-control-plane/RESPONSIBLE_AUTOMATION.md).

The operating model is deliberately boring where it should be boring (SLAs,
ordering, ownership) and explicit where it must be (what is automated, what is
gated, what must never be automated). That boundary — automate the reversible,
gate the blast radius, preserve evidence before you rotate — is the operating
model's single most important idea.
