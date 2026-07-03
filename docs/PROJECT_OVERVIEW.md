# Project overview

A single-page orientation to this repository - what it is, the problem it models,
how to run it, what each part demonstrates, its limitations, and why it is safe
to share.

## What this project is

A role-aligned security engineering portfolio project built around Microsoft
Sentinel and Azure security concepts. It is a runnable, offline lab using
synthetic telemetry - it mirrors how a Sentinel-based detection and response
capability works without requiring, or claiming, a production deployment.

It has three parts:

1. **Identity Threat Detection & SOAR Lab** (the parent lab) - detection
   engineering, incident correlation, AI-assisted triage, SOAR design and
   operational metrics for identity attacks.
2. **Datacenter Control Plane Attack Path Lab** (`modules/datacenter-control-plane/`)
   - follows a compromised identity across the Azure control plane to an exposed
   management endpoint, with correlation and blast-radius scoring.
3. **Security Engineering Excellence Layer** (`security-engineering/`) - the
   professional wrapper: a detection quality scorecard, purple-team validation,
   an attack-path graph, an analyst incident packet, prevention controls, a KQL
   test harness, and an executive risk report.

## The problem it models

- **Identity compromise becomes cloud infrastructure risk.** Serious cloud
  incidents usually start with an identity - a phished credential, an
  over-privileged service principal, an MFA bypass - and end at infrastructure.
  The labs replay that path end to end.
- **Security operations need fidelity, not volume.** Detections have to be
  correlated into investigable incidents, scored explainably, tuned against false
  positives, and measured (MTTD, MTTR, SLA adherence) - otherwise they are noise.
- **AI can help, within boundaries.** Summarisation and triage guidance reduce
  toil, but high-risk response must remain human-approved and model input must be
  treated as attacker-influenceable data.

## How to run it

Python 3.9+ is all that is required for the demos (standard library only).

```bash
# Identity lab
python3 src/main.py --demo

# Control-plane module
python3 modules/datacenter-control-plane/src/main.py --demo

# Tests and detection-as-code validation (dev dependencies)
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 -m pytest -q

# Regenerate the security-engineering artefacts
python3 security-engineering/score_detections.py
python3 security-engineering/render_attack_graph.py
```

Every demo writes committed sample outputs, so the project can also be reviewed
without running anything - start with the timelines under `demo-output/` and
`modules/datacenter-control-plane/demo-output/`.

## What each module demonstrates

| Area | Where | What it shows |
|------|-------|---------------|
| Detection engineering (KQL + detection-as-code) | `detections/`, `modules/.../detections/` | 15 detections, each as KQL, YAML rule and a tested Python mirror |
| MITRE ATT&CK mapping | every rule + coverage tables | Techniques mapped and coverage computed, not asserted |
| Incident correlation | `src/incident_builder.py`, `modules/.../correlation_engine.py` | Multi-stage attacks become one investigation with a blast-radius score |
| SOAR design | `playbooks/`, `modules/.../playbooks/` | Automate-vs-approve boundaries by blast radius, reversibility, confidence |
| Responsible AI | `src/ai_assistant.py`, `docs/RESPONSIBLE_AI.md` | Advisory-only AI, data minimisation, prompt-injection defence |
| Operational metrics | `src/reporting.py` | MTTD, MTTR, SLA adherence, false-positive rate |
| Detection-as-code CI | `.azure-pipelines/` | Validate, test, package, approval-gated deployment path |
| Prevention / policy-as-code | `security-engineering/policy-as-code/`, `modules/.../iac/` | Preventive controls, illustrative Bicep and Azure Policy |

## Limitations

- This is a **local simulation** - Sentinel-style, not a production Sentinel
  deployment. The Azure deployment path is documented and illustrative, not run.
- All telemetry is **synthetic** and shaped for clarity; real environments are
  noisier, and the thresholds here would need baselining and tuning.
- The detections are **reference implementations** - production use would add
  behavioural baselining, broader coverage (e.g. token theft), and
  ingestion-cost engineering.
- The metrics (including the 12.5% to 0% false-positive figure) are computed on a
  fixed, deterministic dataset. They demonstrate the method, not real-world
  numbers.
- The AI component defaults to a deterministic offline template; the optional
  Azure OpenAI mode is untested at scale.

## Safe to share

This repository contains no real employer data, no internal logs, no secrets, and
no customer information. Every identity, IP address and resource is fictional and
generated deterministically (documentation IP ranges, contoso.com personas). It
is safe to read, run, fork and discuss publicly.

## Honest positioning

My production experience is in identity and privileged-access security (IAM/PAM).
This project demonstrates how I extend that judgement into cloud security
engineering - detection maturity, responsible automation, and
identity-to-infrastructure risk. It is not a claim of production Azure-scale
infrastructure operations experience.
