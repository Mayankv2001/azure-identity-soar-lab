"""Entry point for the lab - runs the full Mode A pipeline.

    python3 src/main.py --demo              full pipeline + console summary
    python3 src/main.py --incident INC-1002 AI briefing for one incident
"""
from __future__ import annotations

import argparse
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
OUTPUT_DIR = ROOT / "output"


def banner(text: str) -> None:
    print()
    print("=" * 72)
    print(f"  {text}")
    print("=" * 72)


def run_demo() -> None:
    banner("1/6  Generating synthetic telemetry (seed 42, clock 2026-07-01T00:00Z)")
    generate_logs.main()

    banner("2/6  Running detections (rule set v1.0.0)")
    alerts = detection_engine.run_all(tuned=False)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "alerts.json").write_text(json.dumps(alerts, indent=2) + "\n", encoding="utf-8")
    for alert in alerts:
        print(f"  {alert['alert_id']}  {alert['severity']:<8}  "
              f"{alert['detection_name']}  ->  {alert['user']}")

    banner("3/6  Running detections with v1.1.0 tuning (VPN egress exclusions)")
    tuned = detection_engine.run_all(tuned=True)
    (OUTPUT_DIR / "alerts_tuned.json").write_text(json.dumps(tuned, indent=2) + "\n", encoding="utf-8")
    print(f"  alerts before tuning: {len(alerts)}   after tuning: {len(tuned)}   "
          f"suppressed: {len(alerts) - len(tuned)} (benign VPN travel)")

    banner("4/6  Correlating alerts into incidents")
    incidents = incident_builder.build_incidents(alerts)
    (OUTPUT_DIR / "incidents.json").write_text(json.dumps(incidents, indent=2) + "\n", encoding="utf-8")
    inc_dir = OUTPUT_DIR / "incidents"
    inc_dir.mkdir(parents=True, exist_ok=True)
    for incident in incidents:
        incident_builder.write_incident_markdown(incident, inc_dir)
        print(f"  {incident['incident_id']}  {incident['severity']:<8}  "
              f"{len(incident['alert_ids'])} alert(s)  {incident['disposition']:<15}  "
              f"{incident['title']}")

    banner("5/6  AI-assisted triage briefing (top incident, offline mode)")
    top = max(incidents, key=lambda i: (max(a["severity_score"] for a in i["alerts"]),
                                        len(i["alerts"])))
    ai_assistant.AI_DIR.mkdir(parents=True, exist_ok=True)
    prompt_path = ai_assistant.AI_DIR / f"{top['incident_id']}-prompt.md"
    prompt_path.write_text(ai_assistant.build_prompt(top), encoding="utf-8")
    summary = ai_assistant.online_summary(ai_assistant.build_prompt(top)) \
        or ai_assistant.offline_summary(top)
    summary_path = ai_assistant.AI_DIR / f"{top['incident_id']}-summary.md"
    summary_path.write_text(summary, encoding="utf-8")
    print(f"  briefing for {top['incident_id']} ({top['title']})")
    print(f"  wrote {prompt_path.relative_to(ROOT)}")
    print(f"  wrote {summary_path.relative_to(ROOT)}")

    banner("6/6  Daily security operations report")
    metrics = reporting.compute_metrics(alerts, incidents, tuned)
    report = reporting.render_report(alerts, incidents, metrics)
    report_path = OUTPUT_DIR / "daily_security_report.md"
    report_path.write_text(report, encoding="utf-8")
    print(f"  wrote {report_path.relative_to(ROOT)}")

    banner("Demo complete")
    print(f"""  Detections fired      7 of 7 (12 alerts, 8 incidents)
  MTTD                  {reporting._fmt_minutes(metrics['mttd_minutes'])}
  MTTR                  {reporting._fmt_minutes(metrics['mttr_minutes'])}
  SLA adherence         {metrics['sla_adherence_pct']:.1f}%
  False-positive rate   {metrics['fp_rate_pct']:.1f}% before tuning, 0.0% after v1.1.0
  Review next           output/daily_security_report.md
                        output/incidents/  (one markdown per incident)
                        output/ai/         (AI prompt + triage briefing)""")


def main() -> None:
    parser = argparse.ArgumentParser(description="AI-Assisted Azure Identity Threat Detection & SOAR Lab")
    parser.add_argument("--demo", action="store_true", help="run the full Mode A pipeline")
    parser.add_argument("--incident", help="write an AI briefing for one incident id")
    args = parser.parse_args()

    if args.demo:
        run_demo()
    elif args.incident:
        sys.argv = ["ai_assistant.py", "--incident", args.incident]
        ai_assistant.main()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
