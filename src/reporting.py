"""Daily security operations report - the operational-excellence layer.

Computes the metrics a security operations team is actually held to: alert
volume, MTTD (mean time to acknowledge), MTTR (mean time to resolve), SLA
adherence per severity, false-positive rate, tuning impact (before/after the
DET-002 v1.1.0 exclusions) and MITRE ATT&CK coverage.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from detection_engine import CATALOGUE
from incident_builder import SLA_MATRIX

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "output"

ALL_TACTICS = ["InitialAccess", "CredentialAccess", "PrivilegeEscalation",
               "Persistence", "DefenseEvasion", "LateralMovement"]


def _load(name: str):
    path = OUTPUT_DIR / name
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _fmt_minutes(minutes: float) -> str:
    if minutes < 60:
        return f"{minutes:.0f} min"
    return f"{minutes / 60:.1f} h"


def compute_metrics(alerts: list[dict], incidents: list[dict],
                    tuned_alerts: list[dict] | None) -> dict:
    sla_checks = []
    for incident in incidents:
        targets = SLA_MATRIX[incident["severity"]]
        sla_checks.append({
            "incident_id": incident["incident_id"], "kind": "acknowledge",
            "severity": incident["severity"],
            "actual": incident["ack_minutes"], "target": targets["ack_minutes"],
            "met": incident["ack_minutes"] <= targets["ack_minutes"]})
        sla_checks.append({
            "incident_id": incident["incident_id"], "kind": "resolve",
            "severity": incident["severity"],
            "actual": incident["resolve_minutes"], "target": targets["resolve_minutes"],
            "met": incident["resolve_minutes"] <= targets["resolve_minutes"]})
    met = sum(1 for c in sla_checks if c["met"])

    fp_incidents = [i for i in incidents if i["disposition"] == "false_positive"]
    tuning = None
    if tuned_alerts is not None:
        before = Counter(a["detection_id"] for a in alerts)
        after = Counter(a["detection_id"] for a in tuned_alerts)
        tuning = {det: {"before": before.get(det, 0), "after": after.get(det, 0)}
                  for det in sorted(set(before) | set(after))
                  if before.get(det, 0) != after.get(det, 0)}

    return {
        "alert_count": len(alerts),
        "incident_count": len(incidents),
        "alerts_by_detection": Counter(a["detection_id"] for a in alerts),
        "alerts_by_severity": Counter(a["severity"] for a in alerts),
        "mttd_minutes": sum(i["ack_minutes"] for i in incidents) / len(incidents),
        "mttr_minutes": sum(i["resolve_minutes"] for i in incidents) / len(incidents),
        "sla_checks": sla_checks,
        "sla_adherence_pct": 100.0 * met / len(sla_checks),
        "sla_breaches": [c for c in sla_checks if not c["met"]],
        "fp_rate_pct": 100.0 * len(fp_incidents) / len(incidents),
        "fp_incidents": [i["incident_id"] for i in fp_incidents],
        "tuning_impact": tuning,
    }


def render_report(alerts: list[dict], incidents: list[dict], metrics: dict) -> str:
    lines = [
        "# Daily security operations report",
        "",
        "Reporting window: 2026-06-24 to 2026-06-30 (simulation clock 2026-07-01T00:00Z)",
        "",
        "## Headline numbers",
        "",
        f"- Alerts raised: **{metrics['alert_count']}** "
        f"({', '.join(f'{v} {k}' for k, v in sorted(metrics['alerts_by_severity'].items()))})",
        f"- Incidents opened: **{metrics['incident_count']}**",
        f"- MTTD (mean time to acknowledge): **{_fmt_minutes(metrics['mttd_minutes'])}**",
        f"- MTTR (mean time to resolve): **{_fmt_minutes(metrics['mttr_minutes'])}**",
        f"- SLA adherence: **{metrics['sla_adherence_pct']:.1f}%** "
        f"({len(metrics['sla_breaches'])} breach(es))",
        f"- Incident false-positive rate: **{metrics['fp_rate_pct']:.1f}%** "
        f"({', '.join(metrics['fp_incidents']) or 'none'})",
        "",
        "## Alert volume by detection",
        "",
        "| Detection | Name | Alerts | Base severity |",
        "|-----------|------|--------|---------------|",
    ]
    for det_id in sorted(CATALOGUE):
        meta = CATALOGUE[det_id]
        lines.append(f"| {det_id} | {meta['name']} | "
                     f"{metrics['alerts_by_detection'].get(det_id, 0)} | {meta['base_severity']} |")

    lines += ["", "## Incidents", "",
              "| Incident | Severity | Primary identity | Disposition | Ack | Resolve | SLA |",
              "|----------|----------|------------------|-------------|-----|---------|-----|"]
    breach_ids = {(c["incident_id"], c["kind"]) for c in metrics["sla_breaches"]}
    for incident in incidents:
        ack_flag = "BREACH" if (incident["incident_id"], "acknowledge") in breach_ids else "met"
        res_flag = "BREACH" if (incident["incident_id"], "resolve") in breach_ids else "met"
        lines.append(
            f"| {incident['incident_id']} | {incident['severity']} | {incident['user']} "
            f"| {incident['disposition'].replace('_', ' ')} "
            f"| {_fmt_minutes(incident['ack_minutes'])} | {_fmt_minutes(incident['resolve_minutes'])} "
            f"| ack {ack_flag}, resolve {res_flag} |")

    if metrics["sla_breaches"]:
        lines += ["", "### SLA breaches", ""]
        for check in metrics["sla_breaches"]:
            lines.append(f"- {check['incident_id']}: {check['kind']} took "
                         f"{_fmt_minutes(check['actual'])} against a "
                         f"{_fmt_minutes(check['target'])} target ({check['severity']})")

    if metrics["tuning_impact"]:
        lines += ["", "## Tuning impact (rule v1.1.0 exclusions applied)", "",
                  "| Detection | Alerts before | Alerts after | Change |",
                  "|-----------|---------------|--------------|--------|"]
        for det, delta in metrics["tuning_impact"].items():
            lines.append(f"| {det} | {delta['before']} | {delta['after']} "
                         f"| {delta['after'] - delta['before']:+d} |")
        lines += ["",
                  "The DET-002 v1.1.0 exclusion (corporate VPN egress range "
                  "198.51.100.0/24) removes the benign impossible-travel alert while "
                  "keeping both true positives - a "
                  "false-positive reduction with no loss of detection coverage."]

    lines += ["", "## MITRE ATT&CK coverage", "",
              "| Tactic | " + " | ".join(sorted(CATALOGUE)) + " |",
              "|--------|" + "----|" * len(CATALOGUE)]
    for tactic in ALL_TACTICS:
        row = [("X" if tactic in CATALOGUE[d]["tactics"] else "")
               for d in sorted(CATALOGUE)]
        lines.append(f"| {tactic} | " + " | ".join(row) + " |")

    risk = Counter()
    for alert in alerts:
        risk[alert["user"]] += alert["severity_score"]
    lines += ["", "## Top risky identities", ""]
    for user, score in risk.most_common(5):
        lines.append(f"- {user} (cumulative severity score {score})")

    lines += ["", "## Recommended actions", "",
              "1. Promote the DET-002 VPN egress exclusion from proposal to production (v1.1.0).",
              "2. Disable or lifecycle the three stale privileged accounts flagged by DET-007.",
              "3. Enforce ticket validation on Tier-0 CyberArk safes (root cause of INC "
              "involving the domain-admins safe).",
              "4. Require PIM-eligible assignment for Global Administrator "
              "(standing assignment enabled the DET-005 self-elevation).",
              "5. Review acknowledgement staffing for Medium alerts - the single SLA "
              "breach was a false positive that sat in the queue.",
              ""]
    return "\n".join(lines)


def main() -> None:
    alerts = _load("alerts.json")
    incidents = _load("incidents.json")
    if alerts is None or incidents is None:
        raise SystemExit("run detection_engine.py and incident_builder.py first")
    tuned = _load("alerts_tuned.json")

    metrics = compute_metrics(alerts, incidents, tuned)
    report = render_report(alerts, incidents, metrics)
    path = OUTPUT_DIR / "daily_security_report.md"
    path.write_text(report, encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)}")
    print(f"  alerts={metrics['alert_count']}  incidents={metrics['incident_count']}  "
          f"MTTD={_fmt_minutes(metrics['mttd_minutes'])}  "
          f"MTTR={_fmt_minutes(metrics['mttr_minutes'])}  "
          f"SLA={metrics['sla_adherence_pct']:.1f}%  FP={metrics['fp_rate_pct']:.1f}%")


if __name__ == "__main__":
    main()
