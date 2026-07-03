"""Tests for the Security Engineering Excellence Layer.

Assert that every required artefact exists, that generated JSON is complete and
covers every detection, and that the attack-path graph and KQL test cases are
internally consistent. These run in the repo-root pytest suite.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SE = ROOT / "security-engineering"

# The 15 detection ids across both labs.
PARENT_IDS = {f"DET-00{i}" for i in range(1, 8)}
MODULE_IDS = {f"CP-DET-00{i}" for i in range(1, 9)}
ALL_IDS = PARENT_IDS | MODULE_IDS


def test_all_required_artifacts_exist():
    required = [
        "detection-quality-scorecard.md", "detection-quality-scorecard.json",
        "score_detections.py", "purple-team-validation.md", "atomic-scenarios.json",
        "attack-path-graph.md", "attack-path-graph.json", "render_attack_graph.py",
        "prevention-controls.md", "kql-test-harness.md", "kql-test-cases.json",
        "executive-risk-report.md", "90-day-roadmap.md",
    ]
    missing = [name for name in required if not (SE / name).exists()]
    assert not missing, f"missing security-engineering artefacts: {missing}"
    # Public-facing orientation doc for reviewers.
    assert (ROOT / "docs" / "PROJECT_OVERVIEW.md").exists()


def test_incident_packet_files_exist():
    packet = SE / "incident-packet"
    for name in ("INCIDENT_BRIEF.md", "TIMELINE.md", "ENTITY_SUMMARY.md",
                 "CONTAINMENT_PLAN.md", "RCA_TEMPLATE.md", "EXECUTIVE_SUMMARY.md"):
        path = packet / name
        assert path.exists() and path.stat().st_size > 0, name


def test_scorecard_json_covers_all_detections():
    data = json.loads((SE / "detection-quality-scorecard.json").read_text(encoding="utf-8"))
    scored = {d["id"] for d in data["detections"]}
    assert scored == ALL_IDS, f"scorecard mismatch: {ALL_IDS ^ scored}"
    for det in data["detections"]:
        assert 0 <= det["score"] <= 100
        assert det["maturity"]
        # honesty guard: no detection is labelled bare "production ready"
        assert "production ready" not in det["maturity"].lower()
    assert data["summary"]["detection_count"] == len(ALL_IDS)


def test_scorecard_is_reproducible():
    """Re-running the generator must produce the committed JSON (deterministic)."""
    before = (SE / "detection-quality-scorecard.json").read_text(encoding="utf-8")
    subprocess.run([sys.executable, str(SE / "score_detections.py")], check=True,
                   cwd=ROOT, capture_output=True)
    after = (SE / "detection-quality-scorecard.json").read_text(encoding="utf-8")
    assert before == after, "scorecard JSON drifted from score_detections.py output"


def test_attack_path_graph_has_required_nodes_and_edges():
    graph = json.loads((SE / "attack-path-graph.json").read_text(encoding="utf-8"))
    node_types = {n["type"] for n in graph["nodes"]}
    required_types = {
        "user_identity", "mfa_event", "privileged_role", "service_principal",
        "resource_group", "nsg_rule", "vm_management_endpoint", "incident",
        "soar_playbook", "azure_policy",
    }
    assert required_types <= node_types, f"missing node types: {required_types - node_types}"
    kinds = {e["kind"] for e in graph["edges"]}
    assert {"attack", "detection", "response", "prevention"} <= kinds
    # every edge references real nodes
    node_ids = {n["id"] for n in graph["nodes"]}
    for edge in graph["edges"]:
        assert edge["from"] in node_ids and edge["to"] in node_ids
    assert graph["earliest_break_point"]["node"] in node_ids


def test_kql_test_cases_cover_every_detection():
    data = json.loads((SE / "kql-test-cases.json").read_text(encoding="utf-8"))
    covered = {d["detection"] for d in data["detections"]}
    assert covered == ALL_IDS, f"kql test-case mismatch: {ALL_IDS ^ covered}"
    for case in data["detections"]:
        for field in ("positive_sample", "negative_sample", "expected_alert_count",
                      "false_positive_case", "regression_case", "tuning_variable",
                      "approval_checklist"):
            assert field in case, f"{case['detection']} missing {field}"


def test_atomic_scenarios_have_required_fields_and_safety_note():
    data = json.loads((SE / "atomic-scenarios.json").read_text(encoding="utf-8"))
    assert "synthetic telemetry only" in data["safety_note"].lower()
    assert len(data["scenarios"]) >= 10
    for scenario in data["scenarios"]:
        for field in ("scenario", "objective", "mitre_technique", "expected_telemetry",
                      "expected_detection", "expected_analyst_question",
                      "expected_containment", "false_positive_scenario",
                      "validation_method"):
            assert field in scenario, f"scenario missing {field}"


def test_policy_as_code_files_present():
    pac = SE / "policy-as-code"
    assert pac.is_dir()
    json_policies = list(pac.glob("*.json"))
    assert len(json_policies) >= 3
    for path in json_policies:
        json.loads(path.read_text(encoding="utf-8"))  # must be valid JSON
