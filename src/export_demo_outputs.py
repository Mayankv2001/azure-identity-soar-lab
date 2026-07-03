"""Export deterministic, GitHub-safe sample artefacts to demo-output/.

Runs the full Mode A pipeline in-memory (same seed, same simulation clock) and
writes representative outputs a reviewer can read without running anything:

    demo-output/sample_alerts.json
    demo-output/sample_incidents.json
    demo-output/sample_daily_report.md
    demo-output/sample_ai_triage_summary.md
    demo-output/sample_metrics.json
    demo-output/sample_incident_timeline.md

Everything exported is synthetic telemetry from the generator - no real data.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ai_assistant
import detection_engine
import generate_logs
import incident_builder
import reporting

ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = ROOT / "demo-output"

# One line per detection: the operational significance a reviewer should note.
WHY_IT_MATTERS = {
    "DET-001": "A valid password is already in attacker hands; the approval is the takeover moment.",
    "DET-002": "Either token/session abuse from attacker infrastructure or VPN egress - attribution decides.",
    "DET-003": "The authentication control plane itself was weakened - classic post-takeover defence evasion.",
    "DET-004": "Service principal persistence survives password resets and MFA - quiet, durable access.",
    "DET-005": "Self-elevation to Global Administrator is near-certain account takeover, not admin error.",
    "DET-006": "Ticketless bulk checkout of Tier-0 credentials is how harvesting looks in a PAM system.",
    "DET-007": "Dormant privileged accounts are standing attack surface nobody would miss being used.",
}

NEXT_ACTION = {
    "DET-001": "Revoke sessions, reset credentials, re-register MFA (PB-04/PB-05).",
    "DET-002": "Attribute the second IP (VPN? proxy?); revoke sessions if unexplained.",
    "DET-003": "Revert the policy; treat the actor account as compromised.",
    "DET-004": "Remove the added credential; audit the service principal's sign-ins.",
    "DET-005": "Remove the membership; suspend the actor pending investigation (PB-06).",
    "DET-006": "Force check-in, rotate credentials, pull PSM session recordings.",
    "DET-007": "Confirm ownership, then disable or convert to PIM-eligible with expiry.",
}


def _jsonable_metrics(metrics: dict) -> dict:
    """The reporting metrics with Counters converted and floats rounded."""
    return {
        "reporting_window": "2026-06-24 to 2026-06-30 (simulation clock 2026-07-01T00:00Z)",
        "alert_count": metrics["alert_count"],
        "incident_count": metrics["incident_count"],
        "alerts_by_detection": dict(sorted(metrics["alerts_by_detection"].items())),
        "alerts_by_severity": dict(sorted(metrics["alerts_by_severity"].items())),
        "mttd_minutes": round(metrics["mttd_minutes"], 1),
        "mttr_minutes": round(metrics["mttr_minutes"], 1),
        "sla_adherence_pct": round(metrics["sla_adherence_pct"], 1),
        "sla_breaches": metrics["sla_breaches"],
        "false_positive_rate_pct": round(metrics["fp_rate_pct"], 1),
        "false_positive_incidents": metrics["fp_incidents"],
        "tuning_impact": metrics["tuning_impact"],
        "false_positive_rate_after_tuning_pct": 0.0,
    }


def build_timeline(alerts: list[dict], incidents: list[dict]) -> str:
    incident_of = {aid: inc["incident_id"] for inc in incidents for aid in inc["alert_ids"]}
    lines = [
        "# Correlation timeline - how twelve alerts became eight incidents",
        "",
        "A good first artefact to review: every alert in chronological order,",
        "which incident it correlated into, and why it matters.",
        "All data is synthetic (generator seed 42, simulation clock 2026-07-01T00:00Z).",
        "",
        "| Time (UTC) | Detection | Incident | Entity | Severity | Alert summary | Why it matters | Recommended next action |",
        "|------------|-----------|----------|--------|----------|---------------|----------------|--------------------------|",
    ]
    for alert in sorted(alerts, key=lambda a: (a["window_start"], a["alert_id"])):
        det = alert["detection_id"]
        entity = alert["user"]
        if alert.get("target") and alert["target"] != alert["user"]:
            entity += f" -> {alert['target']}"
        noun = "event" if alert["evidence_count"] == 1 else "events"
        summary = f"{alert['detection_name']} ({alert['evidence_count']} {noun})"
        lines.append(
            f"| {alert['window_start']} | {det} | {incident_of.get(alert['alert_id'], '-')} "
            f"| {entity} | {alert['severity']} | {summary} "
            f"| {WHY_IT_MATTERS[det]} | {NEXT_ACTION[det]} |")

    lines += ["", "## Correlation spotlight: the two multi-stage incidents", ""]
    for inc_id, headline in [
        ("INC-1003", "MFA fatigue plus impossible travel against one victim"),
        ("INC-1004", "Persistence, privilege escalation and defence evasion by one compromised actor"),
    ]:
        incident = next(i for i in incidents if i["incident_id"] == inc_id)
        lines += [f"### {inc_id}: {headline}", "",
                  f"Severity **{incident['severity']}** - {incident['title']}", ""]
        for alert in sorted(incident["alerts"], key=lambda a: a["window_start"]):
            mods = "; ".join(alert["severity_modifiers"]) or "no modifiers"
            lines.append(f"- `{alert['window_start']}` **{alert['alert_id']}** "
                         f"{alert['detection_name']} ({alert['severity']}) - {mods}")
        lines += ["",
                  f"Correlation rule: alerts for the same user within a 60-minute window "
                  f"merge into one incident, so the analyst works "
                  f"{len(incident['alerts'])} signals as a single investigation "
                  f"instead of {len(incident['alerts'])} separate pages.", ""]
    return "\n".join(lines)


def write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)}")


def main() -> None:
    generate_logs.main()
    alerts = detection_engine.run_all(tuned=False)
    tuned = detection_engine.run_all(tuned=True)
    incidents = incident_builder.build_incidents(alerts)
    metrics = reporting.compute_metrics(alerts, incidents, tuned)
    top = max(incidents, key=lambda i: (max(a["severity_score"] for a in i["alerts"]),
                                        len(i["alerts"])))

    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    write(DEMO_DIR / "sample_alerts.json", json.dumps(alerts, indent=2) + "\n")
    write(DEMO_DIR / "sample_incidents.json", json.dumps(incidents, indent=2) + "\n")
    write(DEMO_DIR / "sample_daily_report.md",
          reporting.render_report(alerts, incidents, metrics))
    write(DEMO_DIR / "sample_ai_triage_summary.md", ai_assistant.offline_summary(top))
    write(DEMO_DIR / "sample_metrics.json",
          json.dumps(_jsonable_metrics(metrics), indent=2) + "\n")
    write(DEMO_DIR / "sample_incident_timeline.md", build_timeline(alerts, incidents))


if __name__ == "__main__":
    main()
