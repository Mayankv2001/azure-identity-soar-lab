# Demo walkthrough

A short, self-guided walkthrough of what the labs do and what to look at. It
takes about five minutes to run and read through. Everything is synthetic and
runs offline.

## 1. Run the identity lab

```bash
python3 src/main.py --demo
```

This generates seven days of synthetic Entra ID sign-in, audit and CyberArk
telemetry, runs the seven detections, correlates alerts into incidents, produces
an AI triage briefing (offline deterministic mode), and writes a daily security
operations report.

Expected: seven detections fire, 12 alerts, 8 incidents. Two showcase incidents
are worth reading in the output:

- **INC-1003** - an MFA-fatigue burst plus two impossible-travel alerts against
  one user, merged into a single Critical incident.
- **INC-1004** - a compromised service-desk account adds a service principal
  credential, self-elevates to Global Administrator, then disables a Conditional
  Access policy: three detections in 30 minutes, correlated into one Critical
  incident.

Headline metrics: MTTD 1.4 h, MTTR 12.7 h, SLA adherence 93.8% (one deliberate
breach kept visible). The v1.1.0 tuning change removed the seeded VPN
false-positive class through a narrow tuning rule - this demonstrates the
tuning method on a fixed, deterministic dataset, not a real-world
zero-false-positive claim.

## 2. Run the control-plane module

```bash
python3 modules/datacenter-control-plane/src/main.py --demo
```

This follows a compromised identity across the Azure control plane: risky
sign-in, MFA fatigue, ticketless privileged-role activation, a credential added
to a high-privilege service principal, an Owner grant on a synthetic
cloud-management resource group, and an NSG rule opening RDP to the internet on
a reachable management jumpbox. Eight detections correlate into one Critical
incident with an explainable blast-radius score of 100/100.

## 3. Read the key artefacts (no run required)

- Identity timeline:
  [demo-output/sample_incident_timeline.md](../demo-output/sample_incident_timeline.md)
- Control-plane timeline:
  [modules/datacenter-control-plane/demo-output/control_plane_timeline.md](../modules/datacenter-control-plane/demo-output/control_plane_timeline.md)
- Attack-path graph:
  [security-engineering/attack-path-graph.md](../security-engineering/attack-path-graph.md)
- Analyst incident packet:
  [security-engineering/incident-packet/](../security-engineering/incident-packet/)
- Detection quality scorecard:
  [security-engineering/detection-quality-scorecard.md](../security-engineering/detection-quality-scorecard.md)

## 4. Run the tests

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 -m pytest -q
```

37 tests cover detection logic, severity scoring, correlation, the
detection-as-code contract, and the security-engineering artefacts.

## What to take away

The point of the demo is not the individual alerts - it is the engineering
around them: detections expressed as code in three synchronised forms, alerts
correlated into investigable incidents, responses gated by blast radius, AI kept
advisory, and every claim backed by a metric or a test. The
[responsible automation boundaries](../modules/datacenter-control-plane/RESPONSIBLE_AUTOMATION.md)
are the part worth dwelling on: reversible actions automate, network and RBAC
changes require human approval, and AI never triggers an action.
