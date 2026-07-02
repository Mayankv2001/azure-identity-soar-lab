# Five-minute demo script

Timed walkthrough for screen-sharing the lab in an interview. Practise it twice;
the timings assume the demo has already been run once so everything is warm.

## Before the call

- Terminal open in the repo root, font large, `python3 src/main.py --demo` ready.
- README.md open in the browser (architecture diagram visible).
- output/daily_security_report.md and output/ai/INC-1003-summary.md in tabs.

## 0:00 - 0:45 | Frame it (README architecture diagram on screen)

> "This is a detection engineering lab I built specifically to prepare for this
> role. It simulates the identity attacks I already investigate in my IAM/PAM
> job - but expressed in Microsoft's stack: KQL detections modelled on Sentinel
> analytics rules, SOAR playbooks, an AI triage assistant with explicit safety
> boundaries, and the operational metrics a SOC is held to. Everything is
> detection-as-code with an approval-gated pipeline. Let me show you a run."

## 0:45 - 2:00 | Run it live (terminal)

Run `python3 src/main.py --demo`. While it scrolls, narrate the numbers:

> "Seven days of synthetic telemetry - 345 sign-ins, audit logs, CyberArk
> events, all seeded and deterministic so the tests are exact. All seven
> detections fire: twelve alerts, correlated into eight incidents. Two things
> worth pausing on. INC-1004: one compromised service-desk account adds a
> credential to a high-privilege service principal, elevates itself to Global
> Administrator, then disables the MFA policy - three detections, thirty
> minutes, correctly correlated into one Critical incident. And the tuning
> line: rule v1.1.0 suppresses exactly one alert - a VPN false positive -
> keeping both true positives."

## 2:00 - 3:00 | One detection in depth (detections/DET-001-mfa-fatigue.kql + .yaml)

> "Each detection exists three times, deliberately. The KQL targets the real
> SigninLogs schema - ResultType 500121, five denials in ten minutes, and the
> Critical escalation is the approval that follows within thirty minutes,
> because that is the moment the user gave in. The YAML is the analytics rule
> as code - severity, MITRE mapping, entity mappings, SLA, and known false
> positives are part of the rule's contract, reviewed in pull requests. The
> Python mirror means the logic has seventeen tests in CI before it ever
> reaches a workspace."

## 3:00 - 4:00 | AI briefing + metrics (the two browser tabs)

> "Every incident gets an AI triage briefing - executive summary, likely cause,
> containment, RCA questions, and false-positive checks so the analyst
> challenges the alert rather than trusting it. The boundaries matter more than
> the feature: the model gets minimised aggregates, never raw logs; telemetry
> is delimited as untrusted input against prompt injection; and no AI output
> can trigger an action - humans approve anything with blast radius.
> The daily report is the operations layer: MTTD 1.4 hours, SLA adherence 93.8
> per cent - with the one breach shown, because a metrics page that never
> shows a breach is a metrics page nobody checked - false-positive rate 12.5
> per cent before tuning, zero after, and MITRE coverage as a computed table."

## 4:00 - 5:00 | Close with the transfer argument

> "The judgement in these detections is my day job - I investigate MFA fatigue,
> privileged self-elevation and anomalous CyberArk checkouts across Entra ID,
> AD, CyberArk and SailPoint, and I have automated PAM lifecycle work that
> saves about a hundred engineer-hours a month. What I built this week is the
> Microsoft-native expression of that judgement. That is also my answer on
> growth mindset: I find the gap, I build until it closes, and I am explicit
> about what is production experience versus what is lab-demonstrated. The
> next step is the Mode B deployment - and frankly, doing that at scale is
> what excites me about this role."

## Microsoft values, if asked directly

- **Growth mindset:** the whole lab exists because I audited my own gap and closed it in a week.
- **Customer obsession:** SLAs and honest metrics are customer promises; the runbook optimises for the person being protected, not the dashboard.
- **Accountability:** DRI model throughout; one named owner per incident; the SLA breach is displayed, not buried.
- **Integrity:** MY_REAL_EXPERIENCE_MAPPING.md separates production experience from lab work explicitly.
- **Respect and collaboration:** playbooks notify managers and application owners before disruptive actions; RCAs are blameless.

## Fallback if live demo is impossible

Screenshots of the demo output, the daily report and the AI briefing are enough -
the script above works unchanged; open output/ artefacts from the sample run
instead of executing.
