# Severity Model (P1–P4)

> **Synthetic lab document.** All incidents, identities, service principals,
> resources and IP addresses below are fictional (`@contoso.com` personas,
> `TEST-NET` documentation IP ranges). Nothing here has run in a production
> tenant. This is the classification instrument I would use to run the detection
> estate in these labs, written to production standard.

Severity answers one question: **how fast, and how many people.** It drives the
SLA clock, the paging behaviour and the escalation scope in the
[Incident Response Operating Model](./INCIDENT_RESPONSE_OPERATING_MODEL.md). It is
deliberately aligned to the same four-band model enforced in code
(`src/incident_builder.py`, `SLA_MATRIX`) and reported daily
(`output/daily_security_report.md`), so the label an analyst assigns is the label
the metrics measure.

The internal detection severities in this lab are `Critical / High / Medium / Low`.
For the operating model we present them as **P1 / P2 / P3 / P4** — the mapping is
one-to-one, and both names appear together throughout so there is never ambiguity.

---

## The matrix

| Priority | Detection severity | Acknowledge | Resolve | Paging behaviour |
|----------|--------------------|-------------|---------|------------------|
| **P1** | Critical | 15 minutes | 4 hours | Page primary DRI immediately; auto-escalate to secondary + team lead at 15 min |
| **P2** | High | 30 minutes | 8 hours | SOC channel + DRI mention; secondary at 30 min |
| **P3** | Medium | 4 hours | 72 hours | SOC channel, business-hours follow-up |
| **P4** | Low | 24 hours | 7 days | Queue for daily review |

These are the exact values in `SLA_MATRIX`. If you change one here, you change it
there — the two must never drift.

---

## How to classify: the three dimensions

Severity is a judgement across three axes, taking the **highest** that applies. A
single Critical-tier factor is enough to make an incident P1; you do not average
the dimensions down.

1. **Privilege / identity blast radius.** How powerful is the compromised or
   abused principal? A Tier-0 identity (Global Administrator, domain-admin
   equivalent) or a high-privilege service principal is Critical-tier on its own.
2. **Reach / exposure.** Can the attacker act on infrastructure, and is anything
   reachable from the internet? An internet-exposed management plane on a critical
   host is Critical-tier.
3. **Confirmation and progression.** Is this a confirmed active chain, a single
   suspicious event, or an anomaly awaiting review? A correlated multi-stage chain
   escalates severity regardless of any single stage's individual score.

The correlation engine already encodes dimension 3: because three or more distinct
attack stages sharing entities within a four-hour window were present, it raised
the correlated-chain detection (`CP-DET-008`) as a **single Critical incident**
rather than eight sub-Critical alerts. Correlation is what turns a pile of
medium-interest events into one P1.

---

## P1 — Critical

**Definition.** A confirmed or high-confidence active attack that involves a
privileged identity **or** a high-privilege service principal **or** an
internet-exposed critical asset — especially any chain linking identity compromise
to infrastructure control. Tenant-wide or control-plane blast radius. Ack 15 min,
resolve 4 h, primary DRI paged immediately.

### Canonical P1 example — CP-INC-2001 (identity-to-control-plane chain)

This is the reference P1 for the whole estate. A compromised Cloud Operations
identity was walked from a phished login to an internet-exposed datacenter
management endpoint in under two hours. **Blast radius 100/100.** Eight detections
correlated into one Critical incident (`CP-DET-008`).

| Time (UTC, 2026-06-30) | Stage | Detection | Entity | What made it Critical |
|------------------------|-------|-----------|--------|-----------------------|
| 09:00 | 1 | CP-DET-001 | `chris.walker@contoso.com` | High-risk sign-in from an unusual country (Latvia) succeeds |
| 09:11 | 2 | CP-DET-002 | `chris.walker@contoso.com` | MFA-fatigue approval after five denies — account takeover |
| 09:25 | 3 | CP-DET-003 | `chris.walker@contoso.com` | Application Administrator activated via PIM, **no change ticket** |
| 09:40 | 4 | CP-DET-004 | `sp-infra-deploy` | Client secret added to a **high-privilege service principal** |
| 10:05 | 5 | CP-DET-005 | `rg-prod-dc-mgmt` | SP granted **Owner** on the datacenter management resource group |
| 10:20 | 6 | CP-DET-006 | `nsg-prod-dc-mgmt` | NSG rule opens RDP 3389 to **`0.0.0.0/0`** |
| 10:20 | 7 | CP-DET-007 | `vm-dc-mgmt-01` | Management endpoint (public IP `203.0.113.200`) reachable from the internet |
| 10:40 | 8 | Defender for Cloud | `vm-dc-mgmt-01` | Unusual inbound traffic to the management port confirmed |

**Why this is unambiguously P1 — all three dimensions max out:**

- **Privilege:** a privileged, PIM-eligible identity *and* a high-privilege service
  principal (`sp-infra-deploy`, Contributor on `sub-prod-dc`) whose credentials
  survive user password resets — durable persistence.
- **Reach/exposure:** a critical datacenter management port opened to the entire
  internet on a reachable jumpbox.
- **Confirmation/progression:** seven correlated telemetry stages plus a platform
  (Defender) confirmation — this is a confirmed active chain, not a lone anomaly.

The blast-radius score decomposes exactly as the incident packet records:

| Factor | Points | Reason |
|--------|--------|--------|
| Identity privilege | 25 | Privileged identity with PIM eligibility |
| Service principal permissions | 25 | High-privilege SP in scope |
| Public exposure | 20 | Management port reachable from the internet |
| Asset criticality | 20 | Critical datacenter-management assets |
| Affected resources | 10 | Multiple distinct resources |
| **Total** | **100 / 100** | **Critical** |

**Response signature:** paged DRI within 15 minutes; network on-call, app owner and
identity platform owner engaged inside 30 minutes; session revocation automatic;
every downstream containment action approval-gated and snapshotted. Full worked
detail in [`security-engineering/incident-packet/`](../../security-engineering/incident-packet/).

### Other P1 examples

- A Global Administrator role granted to an unexpected account, confirmed not to be
  a legitimate change.
- Conditional Access policy that enforces MFA for admins deleted or weakened by a
  non-change-managed actor (`DET-003`) *while* a privileged sign-in anomaly is live.
- A high-privilege service-principal credential added and immediately used to make
  control-plane RBAC changes (`DET-004` chaining into resource changes).

---

## P2 — High

**Definition.** A serious single-stage event against a privileged or sensitive
principal that is **not yet** a confirmed multi-stage chain, or a chain confined to
identities without infrastructure reach. Real risk, but the blast radius is bounded
or unconfirmed. Ack 30 min, resolve 8 h.

**Examples:**

- **MFA fatigue / push bombing** against a privileged user (`DET-001`) with no
  subsequent successful approval yet observed — the takeover has not landed.
- **Account added to a privileged role or group** (`DET-005`) where the actor is
  known but the change is unverified against a ticket.
- **New credential added to a service principal** (`DET-004`) that is *not*
  high-privilege, or where no downstream abuse has been seen.
- A single `CP-DET-00x` stage firing in isolation — e.g. a ticketless PIM
  activation (`CP-DET-003`) with no accompanying sign-in anomaly or SP change.

A P2 becomes a P1 the moment it correlates with a second stage that adds privilege,
persistence or exposure.

---

## P3 — Medium

**Definition.** A suspicious event that plausibly has a benign explanation and
needs analyst review, not immediate paging. Bounded blast radius, no privileged
infrastructure reach. Ack 4 h, resolve 72 h, business-hours follow-up.

**Examples:**

- **Impossible-travel sign-in** (`DET-002`) for a standard user — frequently a VPN,
  a corporate proxy or a mislocated IP; the canonical false-positive-to-tuning case
  in this lab (INC-1005 → the DET-002 v1.1.0 exclusion).
- **Anomalous CyberArk privileged credential checkout** (`DET-006`) that is unusual
  by hour or volume but within the user's normal safe scope.
- A single risky sign-in for a non-privileged identity with no follow-on activity.

---

## P4 — Low

**Definition.** A hygiene, posture or long-horizon-risk finding with no active
attacker. It matters for the estate's health but nobody is being attacked right
now. Ack 24 h, resolve 7 days, daily-review queue.

**Examples:**

- **Stale or orphaned privileged account** (`DET-007`) — a standing risk to remove,
  not an incident in progress.
- A detection that fired but self-resolved as expected benign behaviour, kept for
  trend and tuning signal.
- Configuration drift flagged for review (e.g. a tag/ownership gap) with no security
  event attached.

---

## Reclassification rules

- **Escalate immediately** when a lower-severity incident correlates with a new
  stage that adds privilege, persistence or internet exposure. Chaining always wins
  — that is the CP-INC-2001 lesson: individually sub-Critical stages became one P1.
- **De-escalate only with a recorded reason** and never below the point where
  evidence has been preserved. A false positive is closed with its reason logged so
  it feeds tuning, not the bin.
- **The RCA may recommend a severity-timing change** — CP-INC-2001's own RCA flags
  that correlation should reach Critical at stage 4–5, not stage 7–8. Severity
  classification is itself a tunable control.

---

## One-line rule of thumb

> **P1** = privilege *and/or* infrastructure reach, active and confirmed (page now).
> **P2** = serious single stage, bounded or unconfirmed (30-minute ack).
> **P3** = suspicious, plausibly benign, analyst review (business hours).
> **P4** = posture/hygiene, no active attacker (daily queue).

When in doubt between two bands, classify **up**, engage the DRI, and let triage
de-escalate with a recorded reason. Under-paging a P1 is the expensive mistake.
