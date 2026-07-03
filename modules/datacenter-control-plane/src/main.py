"""Datacenter Control Plane Attack Path Lab - entry point.

Runs the full offline pipeline: generate telemetry, run detections, correlate
into incidents, score blast radius, then write the alert/incident/timeline/
RCA/metrics artefacts to demo-output/.

    python3 modules/datacenter-control-plane/src/main.py --demo
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import correlation_engine as engine
import generate_telemetry

MODULE_ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = MODULE_ROOT / "demo-output"

# Stage labels for the eleven-step chain (1-8 telemetry, 9-11 response).
STAGE_LABEL = {
    1: "Suspicious sign-in from unusual location",
    2: "MFA fatigue leading to approval",
    3: "Privileged role activation",
    4: "Service principal credential added",
    5: "Subscription / resource group permission change",
    6: "NSG / firewall opened to the internet",
    7: "VM management endpoint exposed",
    8: "Defender / Sentinel-style alert generated",
}

RESPONSE_STEPS = [
    ("9. SOAR enrichment", "automatic",
     "Enrich every entity: identity privilege and PIM eligibility, service "
     "principal permissions, resource criticality, and current public exposure. "
     "Attach the blast-radius score to the incident."),
    ("10. DRI review and approved containment", "human approval required",
     "On-call DRI reviews the enriched chain and approves containment in "
     "least-destructive order: revoke sessions (auto at Critical), revert the "
     "NSG rule, rotate the service principal credential, remove the Owner "
     "assignment, deactivate the PIM role, contain the user."),
    ("11. RCA and hardening", "manual",
     "Blameless RCA: identify the control that failed (standing Contributor on "
     "the SP, ticketless PIM activation, no Azure Policy denying public "
     "management exposure) and ship the fixes as detection tuning and policy."),
]


def build_timeline(incident, data) -> str:
    lines = [
        f"# Control plane attack timeline - {incident['incident_id']}",
        "",
        f"**{incident['title']}**  |  severity {incident['severity']}  |  "
        f"blast radius {incident['blast_radius']['score']}/100 "
        f"({incident['blast_radius']['label']})",
        "",
        "All data is synthetic (generator seed 77, simulation clock 2026-07-01T00:00Z).",
        "",
        "## Stages 1-8: detection telemetry",
        "",
        "| Time (UTC) | Stage | Detection | Entity | Severity | Why it matters |",
        "|------------|-------|-----------|--------|----------|----------------|",
    ]
    why = {
        "CP-DET-001": "Foreign high-risk sign-in - the entry point of the chain.",
        "CP-DET-002": "The approval after the deny burst is the account-takeover moment.",
        "CP-DET-003": "Privileged role activated with no change record - escalation begins.",
        "CP-DET-004": "Credential on a high-privilege SP survives user password resets.",
        "CP-DET-005": "The SP is granted Owner on the datacenter-management group.",
        "CP-DET-006": "A management port is opened to the entire internet.",
        "CP-DET-007": "A reachable jumpbox management endpoint is now internet-facing.",
    }
    for alert in sorted(incident["alerts"], key=lambda a: a["window_start"]):
        lines.append(
            f"| {alert['window_start']} | {alert['stage']} | "
            f"{alert['detection_id']} {alert['detection_name']} | {alert['entity']} "
            f"| {alert['severity']} | {why.get(alert['detection_id'], '')} |")
    for signal in incident["defender_signals"]:
        lines.append(
            f"| {signal['TimeGenerated']} | 8 | Defender: {signal['AlertName']} "
            f"| {', '.join(signal['Entities'])} | {signal['Severity']} "
            f"| Platform signal confirms the exposure is being probed. |")

    lines += ["", "## Blast-radius scoring", "",
              "| Factor | Points | Reason |", "|--------|--------|--------|"]
    for factor in incident["blast_radius"]["factors"]:
        lines.append(f"| {factor['factor']} | {factor['points']} | {factor['reason']} |")
    lines.append(f"| **Total** | **{incident['blast_radius']['score']}/100** "
                 f"| **{incident['blast_radius']['label']}** |")

    lines += ["", "## Stages 9-11: response flow", ""]
    for title, classification, detail in RESPONSE_STEPS:
        lines += [f"### {title}  _({classification})_", "", detail, ""]

    lines += ["## Correlation logic", "",
              "Alerts were linked because they share entities "
              f"({', '.join(e for e in incident['entities'] if '@' in e or e.startswith('sp-') or e.startswith('rg-'))}) "
              "within a four-hour window. Because three or more distinct attack "
              "stages were present, the engine raised the correlated chain "
              "detection CP-DET-008 as a single Critical incident rather than "
              "eight disconnected alerts.", ""]
    return "\n".join(lines)


def build_rca(incident, data) -> str:
    return "\n".join([
        f"# Root cause analysis - {incident['incident_id']}",
        "",
        "Blameless RCA for the synthetic control-plane attack chain. Focus is on "
        "the controls that failed, not the person who clicked.",
        "",
        "## What happened",
        "",
        f"A high-risk sign-in for {incident['alerts'][0]['entity']} from an "
        "unusual country was followed by an MFA-fatigue approval, a ticketless "
        "privileged-role activation, a credential added to a high-privilege "
        "service principal, an Owner grant on a synthetic cloud-management "
        "resource group, and an NSG rule opening RDP to the internet on a reachable "
        "management jumpbox. Eight detections correlated into one Critical "
        f"incident with a blast-radius score of "
        f"{incident['blast_radius']['score']}/100.",
        "",
        "## Root causes (controls that failed)",
        "",
        "1. **Standing Contributor on sp-infra-deploy.** The service principal "
        "held broad standing rights, so a single added secret unlocked "
        "control-plane changes. Fix: least-privilege scoping and managed "
        "identities where possible.",
        "2. **Ticketless PIM activation.** Application Administrator activated "
        "with no linked change record. Fix: require justification/ticket "
        "binding and approval on protected-role activation.",
        "3. **No policy denying public management exposure.** An NSG rule "
        "exposing RDP to 0.0.0.0/0 was accepted. Fix: Azure Policy to deny or "
        "audit internet-wide inbound on management ports (see iac/).",
        "4. **Phishing-vulnerable MFA.** MFA fatigue succeeded. Fix: "
        "phishing-resistant methods and risk-based Conditional Access.",
        "",
        "## Hardening recommendations (advisory - require human approval to apply)",
        "",
        "- Convert sp-infra-deploy to least-privilege, scoped, short-lived credentials.",
        "- Enforce ticket-bound, approval-gated PIM activation for protected roles.",
        "- Deploy Azure Policy denying public inbound on management ports across the subscription.",
        "- Add alert-volume canaries so a new public NSG rule pages before it is exploited.",
        "- Feed each root cause back as a versioned detection or policy change.",
        "",
        "## Detection performance",
        "",
        f"- Stages detected: {len(incident['stages_observed'])} of 7 telemetry stages, "
        "correlated into one incident.",
        "- Time from first stage to correlated Critical incident: "
        f"{incident['window_start']} -> {incident['window_end']}.",
        "- Gap to close next: no detection yet for the actual RDP brute-force "
        "post-exposure; add a follow-on behavioural rule.",
        "",
    ])


def build_metrics(alerts, incidents, data) -> dict:
    chain = [i for i in incidents if i["is_chain"]]
    return {
        "reporting_window": "2026-06-27 to 2026-06-30 (simulation clock 2026-07-01T00:00Z)",
        "telemetry_events": {
            "signin": len(data["entra_signin_logs"]),
            "audit": len(data["entra_audit_logs"]),
            "activity": len(data["azure_activity_logs"]),
            "nsg": len(data["network_security_group_logs"]),
            "defender": len(data["defender_alerts"]),
        },
        "alert_count": len(alerts),
        "alerts_by_detection": {d: sum(1 for a in alerts if a["detection_id"] == d)
                                for d in sorted({a["detection_id"] for a in alerts})},
        "incident_count": len(incidents),
        "correlated_chain_incidents": len(chain),
        "max_blast_radius": max((i["blast_radius"]["score"] for i in incidents), default=0),
        "chain_stages_detected": chain[0]["stages_observed"] if chain else [],
        "mitre_techniques_covered": sorted({t for a in alerts for t in a["mitre_techniques"]}),
    }


def run_demo() -> dict:
    print("=" * 68)
    print("  Datacenter Control Plane Attack Path Lab - demo")
    print("=" * 68)
    generate_telemetry.main()
    data = engine.load_data()

    alerts = engine.run_detections(data)
    print(f"\ndetections: {len(alerts)} alerts")
    for alert in alerts:
        print(f"  {alert['alert_id']}  {alert['severity']:<9} stage {alert['stage']}  "
              f"{alert['detection_name']}")

    incidents = engine.correlate(alerts, data)
    print(f"\ncorrelation: {len(incidents)} incident(s)")
    for incident in incidents:
        tag = "CHAIN" if incident["is_chain"] else "single"
        print(f"  {incident['incident_id']}  {incident['severity']:<9} {tag:<6}  "
              f"blast {incident['blast_radius']['score']}/100  {incident['title']}")

    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    _write(DEMO_DIR / "control_plane_alerts.json",
           json.dumps(alerts, indent=2) + "\n")
    _write(DEMO_DIR / "control_plane_incidents.json",
           json.dumps(incidents, indent=2) + "\n")
    top = max(incidents, key=lambda i: i["blast_radius"]["score"])
    _write(DEMO_DIR / "control_plane_timeline.md", build_timeline(top, data))
    _write(DEMO_DIR / "control_plane_rca.md", build_rca(top, data))
    metrics = build_metrics(alerts, incidents, data)
    _write(DEMO_DIR / "control_plane_metrics.json", json.dumps(metrics, indent=2) + "\n")

    print(f"\ntop incident: {top['incident_id']} "
          f"(blast radius {top['blast_radius']['score']}/100, "
          f"{len(top['stages_observed'])} stages correlated)")
    print("wrote demo-output/: alerts, incidents, timeline, rca, metrics")
    return {"alerts": alerts, "incidents": incidents, "metrics": metrics}


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Datacenter Control Plane Attack Path Lab")
    parser.add_argument("--demo", action="store_true", help="run the full pipeline")
    args = parser.parse_args()
    if args.demo:
        run_demo()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
