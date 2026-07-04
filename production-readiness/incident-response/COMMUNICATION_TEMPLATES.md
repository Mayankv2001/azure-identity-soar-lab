# Incident Communication Templates

> **Synthetic lab document.** Every name, address, identifier and IP below is
> fictional — `@contoso.com` personas, `TEST-NET` documentation IP ranges,
> bracketed `[PLACEHOLDER]` fields. Nothing here has been sent from, or about, a
> production tenant. These are the reusable message shells I would use to run
> communications for the detection estate in these labs.

Good incident communication is disciplined, not eloquent. Every message answers
the same three questions and no more — **what do we know, what have we done, what
is next (with a time)** — so a reader can absorb it in ten seconds at 02:00. The
cadence that governs *when* to send each template is in the
[Incident Response Operating Model](./INCIDENT_RESPONSE_OPERATING_MODEL.md#4-communications-cadence).

**Rules for using these templates:**

- One incident, one channel. The DRI posts; nobody else speculates there.
- Fill **every** `[BRACKETED]` field. If you do not yet know a value, write
  `[unknown — investigating]` rather than leaving it blank or guessing.
- State facts and confirmed actions. Do not attribute, speculate on intent, or
  name a suspected insider — for insider cases follow the HR/legal path and keep
  it out of the incident channel entirely.
- All times are UTC with the local equivalent in brackets (this lab's local zone
  is `Australia/Sydney`, UTC+10). Always give a *next update time*, never "soon".

The worked example values throughout use **CP-INC-2001** so the shape is concrete.

---

## Template 1 — Initial notification

Sent when the incident is declared, into the incident channel. Short by design.

```
[SECURITY INCIDENT — DECLARED]

Incident ID:   [CP-INC-2001]
Severity:      [P1 / Critical]
DRI (owner):   [amelia.chen@contoso.com]
Declared:      [2026-06-30 10:41 UTC / 20:41 AEST]
Channel:       [#inc-cp-2001]

What we know:
  [A correlated identity-to-control-plane attack chain has been detected. A
   privileged Cloud Operations identity ([chris.walker@contoso.com]) shows an
   MFA-fatigue takeover, a ticketless PIM activation, a credential added to a
   high-privilege service principal ([sp-infra-deploy]), an Owner grant on
   [rg-prod-dc-mgmt], and an NSG rule exposing RDP to the internet on
   [vm-dc-mgmt-01].]

What we have done:
  [Sessions for the affected identity revoked automatically. DRI paged and
   engaged. Network on-call and application owner being engaged now.]

What is next:
  [Reverting the internet-facing NSG rule (least-destructive first), then
   removing/rotating the service-principal credential. Evidence preserved before
   any rotation.]

Next update by: [11:11 UTC / 21:11 AEST]
```

---

## Template 2 — Status update (internal)

Posted on the cadence for the severity (P1 every 30 min, P2 every 60 min) until
contained. This is the workhorse message.

```
[STATUS UPDATE — #[n]]

Incident ID:   [CP-INC-2001]     Severity: [P1 / Critical]
Lifecycle:     [CONTAIN]         DRI: [amelia.chen@contoso.com]
As at:         [2026-06-30 11:10 UTC / 21:10 AEST]

What we know now (delta since last update):
  [Confirmed no successful interactive RDP login reached [vm-dc-mgmt-01] during
   the ~20-minute exposure window. Attacker-added client secret on
   [sp-infra-deploy] identified (key id [kid-xxxx], created [09:40 UTC]).]

What we have done since last update:
  [NSG rule [allow-rdp-temp] reverted (prior state snapshotted). Attacker SP
   credential removed and remaining secrets rotated from key vault. Owner
   assignment on [rg-prod-dc-mgmt] removed; PIM role deactivated.]

What is next:
  [JIT-lock [vm-dc-mgmt-01] pending final login-log review. Password reset and
   phishing-resistant MFA for [chris.walker@contoso.com]. Open the blameless RCA
   task.]

Blockers / help needed:
  [None] / [Need [workload-owner@contoso.com] to confirm the JIT-lock window.]

Next update by: [11:40 UTC / 21:40 AEST]
```

For a **false-positive close**, use this same template with the lifecycle set to
`CLOSE` and a "Reason closed" line recording the benign cause, so the closure feeds
tuning:

```
Reason closed (false positive):
  [Impossible-travel alert [INC-XXXX] on [jordan.lee@contoso.com] explained by a
   corporate VPN egress in [City]. Feeding to tuning as a [DET-002] exclusion
   candidate.]
```

---

## Template 3 — Executive / stakeholder update

Sent to leadership and affected business owners at declaration, containment and
resolution for a P1 (and at containment/resolution for a P2 if scope warrants).
Business-impact framing, no jargon, no raw log detail.

```
[EXECUTIVE UPDATE]

Incident:      [CP-INC-2001] — [Identity-to-control-plane attack chain (synthetic lab)]
Severity:      [P1 / Critical]
Current state: [Contained — recovery and verification in progress]
As at:         [2026-06-30 11:25 UTC / 21:25 AEST]
Owner (DRI):   [amelia.chen@contoso.com]
Prepared for:  [security-leadership@contoso.com]

Plain-English summary:
  [A privileged staff account was taken over and used to briefly expose a
   critical datacenter management server to the internet. Our detections
   correlated the activity into a single high-severity incident and we contained
   it before any confirmed successful intrusion into the exposed server.]

Business impact:
  [No confirmed data loss. No confirmed successful login to the exposed server.
   One critical management host was internet-reachable for approximately 20
   minutes and has been secured.]

What we have done:
  [Cut off the attacker's access, closed the internet exposure, removed the
   attacker's persistence (a service-principal credential and an ownership
   grant), and preserved evidence for the investigation.]

What happens next:
  [Restore the affected account with stronger, phishing-resistant sign-in;
   verify the environment is clean; and run a blameless review to fix the
   underlying control gaps (target: within 5 business days).]

Decisions / support needed from you:
  [None at this time.] / [Approval to enforce phishing-resistant MFA for the
   Cloud Operations team ahead of the standard change window.]

Next executive update: [at resolution, or by [13:00 UTC / 23:00 AEST]].
```

---

## Template 4 — Resolution note

Issued when the incident moves to CLOSE — verification complete and the RCA task
raised. This is the record the weekly operations review reads from.

```
[INCIDENT RESOLVED]

Incident ID:   [CP-INC-2001]
Severity:      [P1 / Critical]
DRI (owner):   [amelia.chen@contoso.com]
Declared:      [2026-06-30 10:41 UTC / 20:41 AEST]
Contained:     [2026-06-30 11:20 UTC / 21:20 AEST]
Resolved:      [2026-06-30 12:30 UTC / 22:30 AEST]

SLA outcome:
  Acknowledge: [met — paged 10:40, acked 10:41 (target 15 min)]
  Resolve:     [met — 1h49m from declaration (target 4 h)]

Summary of what happened:
  [A compromised privileged Cloud Operations identity was walked from a phished
   sign-in to an internet-exposed datacenter management endpoint in under two
   hours. Eight detections correlated into one Critical incident (blast radius
   100/100). Contained without confirmed data loss (synthetic).]

Root cause (control that failed):
  [Provisional — confirmed in RCA: no policy denying public management-port
   exposure; standing Contributor on [sp-infra-deploy]; ticketless PIM
   activation; phishing-vulnerable push MFA.]

Actions taken to resolve:
  [Sessions revoked; NSG rule reverted; SP credential removed and secrets
   rotated; Owner grant removed and PIM role deactivated; host JIT-locked;
   account reset with phishing-resistant MFA.]

Verification:
  [No new tokens issued post-revocation; no successful inbound login to the
   exposed host; no residual unexpected SP credentials; detections re-run over
   the post-containment window returned silent.]

Follow-up:
  Blameless RCA: [raised — [CP-INC-2001 RCA], due [2026-07-07], owner
                  [amelia.chen@contoso.com]]
  Open action items: [5 — see RCA_PROCESS.md, owners and dates assigned]

This incident is now CLOSED. Post-incident learning continues via the RCA.
```

---

## Placeholder legend

| Placeholder | Fill with | Fictional example used above |
|-------------|-----------|------------------------------|
| `[Incident ID]` | The assigned incident identifier | `CP-INC-2001` |
| `[Severity]` | `P1/P2/P3/P4` and the detection band | `P1 / Critical` |
| `[DRI (owner)]` | The single accountable owner | `amelia.chen@contoso.com` |
| `[affected identity]` | The compromised/abused UPN | `chris.walker@contoso.com` |
| `[service principal]` | The abused SP name | `sp-infra-deploy` |
| `[resource / host / NSG]` | Affected resources | `rg-prod-dc-mgmt`, `vm-dc-mgmt-01`, `nsg-prod-dc-mgmt` |
| `[IP]` | A documentation IP only | `203.0.113.200` (TEST-NET) |
| `[channel]` | The single incident channel | `#inc-cp-2001` |
| `[distribution list]` | The recipient group | `security-leadership@contoso.com` |
| `[timestamp]` | UTC + local (Australia/Sydney) | `2026-06-30 10:41 UTC / 20:41 AEST` |

**Never** substitute a real person, a real email address, a real tenant/GUID, a
real IP, or any secret into these templates when using this repository as a
portfolio artefact. The placeholders exist precisely so the shells are safe to
publish.
