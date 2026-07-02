"""Correlate alerts into incidents, attach triage guidance and simulate the
operational lifecycle (acknowledge/resolve timestamps, dispositions) so the
reporting layer can compute MTTD, MTTR, SLA adherence and false-positive rate.

Correlation rule: alerts for the same user whose evidence windows overlap or sit
within 60 minutes of each other are merged into one incident - so a multi-stage
attack (for example persistence + privilege escalation + defence evasion by one
actor) is handled as a single investigation, the way Microsoft Sentinel groups
related alerts.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from detection_engine import parse_ts

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "output"

CORRELATION_GAP = timedelta(minutes=60)
SEED = 42

# Ack / resolve targets in minutes, per severity.
SLA_MATRIX = {
    "Critical": {"ack_minutes": 15, "resolve_minutes": 240},
    "High": {"ack_minutes": 30, "resolve_minutes": 480},
    "Medium": {"ack_minutes": 240, "resolve_minutes": 4320},
    "Low": {"ack_minutes": 1440, "resolve_minutes": 10080},
}

TRIAGE_STEPS = {
    "DET-001": [
        "Contact the user out-of-band and confirm whether they approved the final MFA prompt.",
        "Revoke refresh tokens and active sessions for the account (Microsoft Entra ID > user > Revoke sessions).",
        "Reset the password and re-register MFA; remove unfamiliar authenticator methods and devices.",
        "Search sign-in logs for the same source IP across other users (password spray from shared infrastructure).",
        "Review mailbox rules and OAuth consent grants created after the approved sign-in.",
        "Block the source IP and confirm risk-based Conditional Access covers this scenario.",
        "Record root cause: how was a valid password obtained (phishing, reuse, infostealer)?",
    ],
    "DET-002": [
        "Compare device, browser and application fingerprints of both sign-ins against the user's baseline.",
        "Check whether either IP address belongs to corporate VPN egress or a known cloud proxy.",
        "Confirm actual travel with the user or their manager.",
        "If unexplained, revoke sessions, reset credentials and flag the account in Microsoft Entra ID Protection.",
        "Hunt for follow-on activity from the foreign IP (mailbox rules, mass downloads, consent grants).",
        "If VPN egress is confirmed, record the incident as benign and raise a tuning exclusion for the range.",
    ],
    "DET-003": [
        "Diff the Conditional Access policy change and identify which controls were weakened.",
        "Validate the change against change tickets and CAB approval records.",
        "Confirm the actor holds an authorised policy-management role.",
        "If unauthorised, revert the policy immediately and treat the actor account as compromised.",
        "Review all other administrative actions from the same actor and IP in the surrounding hour.",
        "Verify break-glass exclusions and alerting on policy state changes.",
    ],
    "DET-004": [
        "Identify the service principal's API permissions and owners; classify the blast radius.",
        "Validate the credential addition against approved change records.",
        "If unauthorised, remove the new secret or certificate immediately.",
        "Review the service principal's sign-in activity for any use of the new credential.",
        "Rotate remaining credentials and audit application role assignments.",
        "Investigate the actor account for compromise and revoke its sessions.",
    ],
    "DET-005": [
        "Confirm the role or group addition against an approved access request (PIM/JIT expected).",
        "Treat self-elevation (actor granted the privilege to their own account) as a critical signal.",
        "Remove the membership if it was not approved; prefer PIM-eligible over permanent assignment.",
        "Review the actor's authentication trail around the time of the grant.",
        "Audit all actions performed by the elevated account since the grant.",
        "Verify detection coverage for every protected role and privileged group.",
    ],
    "DET-006": [
        "Check for a change ticket or incident record justifying the checkouts; note that none was supplied.",
        "Contact the user and their manager to verify the stated reason.",
        "Review CyberArk PSM session recordings for each checked-out account.",
        "Inspect target systems for logons and changes during the checkout window.",
        "Force check-in and rotate the checked-out credentials.",
        "If unverified, suspend the user's safe access pending investigation (insider or compromise).",
        "Record root cause: why does policy permit ticketless checkout on a Tier-0 safe?",
    ],
    "DET-007": [
        "Identify the business owner of the account; confirm whether it is still required.",
        "Check for authentication attempts across cloud and on-premises in the last 90 days.",
        "Disable the account or strip privileged roles and groups (disable-then-delete lifecycle).",
        "For service accounts, map dependencies before disabling and plan credential rotation.",
        "Convert any remaining need to a PIM-eligible assignment with an expiry date.",
        "Feed the gap back into the joiner-mover-leaver process as a root-cause action.",
    ],
}


def _alert_summary(alert: dict) -> dict:
    return {k: alert[k] for k in (
        "alert_id", "detection_id", "detection_name", "severity", "severity_score",
        "severity_modifiers", "mitre_tactics", "mitre_techniques", "user", "target",
        "ips", "window_start", "window_end", "evidence_count", "scenario_tags")}


def _disposition(alerts: list[dict]) -> str:
    tags = {t for a in alerts for t in a["scenario_tags"]}
    if tags <= {"benign", "vpn_travel_fp"}:
        return "false_positive"
    if tags == {"stale_privileged"}:
        return "posture_finding"
    return "true_positive"


def _title(alerts: list[dict]) -> str:
    user = alerts[0]["user"]
    if len(alerts) == 1:
        return f"{alerts[0]['detection_name']} - {user}"
    return f"Correlated identity attack ({len(alerts)} detections) - {user}"


def _lifecycle(rng: random.Random, severity: str, disposition: str) -> tuple[int, int]:
    """Simulated minutes-to-acknowledge and minutes-to-resolve. The false
    positive deliberately breaches its acknowledgement SLA - one realistic
    breach keeps the SLA-adherence metric honest."""
    if disposition == "false_positive":
        return 265, 310
    if severity == "Critical":
        return rng.randint(6, 12), rng.randint(120, 200)
    if severity == "High":
        return rng.randint(18, 26), rng.randint(330, 450)
    if severity == "Medium":
        return rng.randint(90, 200), rng.randint(1500, 3400)
    return rng.randint(300, 900), rng.randint(3000, 8000)


def build_incidents(alerts: list[dict]) -> list[dict]:
    by_user: dict[str, list[dict]] = {}
    for alert in alerts:
        by_user.setdefault(alert["user"], []).append(alert)

    groups: list[list[dict]] = []
    for user in sorted(by_user):
        user_alerts = sorted(by_user[user], key=lambda a: a["window_start"])
        current = [user_alerts[0]]
        current_end = parse_ts(user_alerts[0]["window_end"])
        for alert in user_alerts[1:]:
            if parse_ts(alert["window_start"]) <= current_end + CORRELATION_GAP:
                current.append(alert)
                current_end = max(current_end, parse_ts(alert["window_end"]))
            else:
                groups.append(current)
                current = [alert]
                current_end = parse_ts(alert["window_end"])
        groups.append(current)

    # Incident creation time = the moment the first correlated rule would fire.
    groups.sort(key=lambda g: min(a["window_end"] for a in g))
    rng = random.Random(SEED)
    incidents = []
    for index, group in enumerate(groups):
        created = min(parse_ts(a["window_end"]) for a in group)
        severity = max(group, key=lambda a: a["severity_score"])["severity"]
        disposition = _disposition(group)
        ack_minutes, resolve_minutes = _lifecycle(rng, severity, disposition)
        steps, seen = [], set()
        for alert in sorted(group, key=lambda a: a["window_start"]):
            for step in TRIAGE_STEPS[alert["detection_id"]]:
                if step not in seen:
                    seen.add(step)
                    steps.append(step)
        incidents.append({
            "incident_id": f"INC-{1001 + index}",
            "title": _title(group),
            "severity": severity,
            "user": group[0]["user"],
            "ips": sorted({ip for a in group for ip in a["ips"]}),
            "alert_ids": [a["alert_id"] for a in group],
            "alerts": [_alert_summary(a) for a in group],
            "mitre_tactics": sorted({t for a in group for t in a["mitre_tactics"]}),
            "mitre_techniques": sorted({t for a in group for t in a["mitre_techniques"]}),
            "created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "acknowledged_at": (created + timedelta(minutes=ack_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "resolved_at": (created + timedelta(minutes=resolve_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ack_minutes": ack_minutes,
            "resolve_minutes": resolve_minutes,
            "status": "resolved",
            "disposition": disposition,
            "triage_steps": steps,
        })
    return incidents


def write_incident_markdown(incident: dict, directory: Path) -> Path:
    lines = [
        f"# {incident['incident_id']}: {incident['title']}",
        "",
        f"- **Severity:** {incident['severity']}",
        f"- **Status:** {incident['status']} ({incident['disposition'].replace('_', ' ')})",
        f"- **Primary identity:** {incident['user']}",
        f"- **Source IPs:** {', '.join(incident['ips']) or 'n/a'}",
        f"- **Created:** {incident['created_at']}  |  **Acknowledged:** {incident['acknowledged_at']}"
        f"  |  **Resolved:** {incident['resolved_at']}",
        f"- **MITRE ATT&CK:** {', '.join(incident['mitre_techniques'])}"
        f" ({', '.join(incident['mitre_tactics'])})",
        "",
        "## Correlated alerts",
        "",
        "| Alert | Detection | Severity | Window (UTC) | Evidence |",
        "|-------|-----------|----------|--------------|----------|",
    ]
    for alert in incident["alerts"]:
        lines.append(
            f"| {alert['alert_id']} | {alert['detection_name']} | {alert['severity']} "
            f"| {alert['window_start']} - {alert['window_end']} | {alert['evidence_count']} events |")
    lines += ["", "## Severity reasoning", ""]
    for alert in incident["alerts"]:
        mods = "; ".join(alert["severity_modifiers"]) or "no modifiers"
        lines.append(f"- {alert['alert_id']}: base {alert['detection_id']} severity, {mods}")
    lines += ["", "## Triage checklist", ""]
    lines += [f"{i}. {step}" for i, step in enumerate(incident["triage_steps"], 1)]
    lines.append("")
    path = directory / f"{incident['incident_id']}.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def main() -> None:
    alerts_path = OUTPUT_DIR / "alerts.json"
    if not alerts_path.exists():
        raise SystemExit("output/alerts.json not found - run: python3 src/detection_engine.py")
    alerts = json.loads(alerts_path.read_text(encoding="utf-8"))
    incidents = build_incidents(alerts)

    out_path = OUTPUT_DIR / "incidents.json"
    out_path.write_text(json.dumps(incidents, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out_path.relative_to(ROOT)} ({len(incidents)} incidents)")

    inc_dir = OUTPUT_DIR / "incidents"
    inc_dir.mkdir(parents=True, exist_ok=True)
    for incident in incidents:
        path = write_incident_markdown(incident, inc_dir)
        print(f"  {incident['incident_id']}  {incident['severity']:<8}  "
              f"{incident['disposition']:<15} {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
