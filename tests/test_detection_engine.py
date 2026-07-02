"""Tests for the detection engine, severity model, correlation, metrics and the
detection-as-code contract (every YAML rule matches its KQL file and its local
Python implementation). These are the same checks the Azure DevOps pipeline runs."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import detection_engine as engine          # noqa: E402
import generate_logs                       # noqa: E402
import incident_builder                    # noqa: E402
import reporting                           # noqa: E402

DETECTIONS_DIR = ROOT / "detections"
REQUIRED_ALERT_KEYS = {
    "alert_id", "detection_id", "detection_name", "mitre_tactics", "mitre_techniques",
    "user", "ips", "window_start", "window_end", "evidence_count", "evidence",
    "base_severity", "severity", "severity_score", "severity_modifiers", "scenario_tags",
}
REQUIRED_RULE_KEYS = {
    "id", "name", "version", "kind", "severity", "status", "description",
    "data_sources", "tactics", "techniques", "query_file", "query_frequency",
    "query_period", "trigger_operator", "trigger_threshold", "entity_mappings",
    "local_detection", "tuning", "sla", "references",
}


@pytest.fixture(scope="session", autouse=True)
def regenerate_data():
    """Data generation is deterministic - regenerating guarantees the committed
    sample data and the tested data are identical."""
    generate_logs.main()


@pytest.fixture(scope="session")
def alerts():
    return engine.run_all(tuned=False)


@pytest.fixture(scope="session")
def tuned_alerts():
    return engine.run_all(tuned=True)


@pytest.fixture(scope="session")
def incidents(alerts):
    return incident_builder.build_incidents(alerts)


# --- Generator ------------------------------------------------------------------

def test_generator_is_deterministic(tmp_path):
    first = (ROOT / "data" / "sample_signin_logs.json").read_bytes()
    generate_logs.main()
    second = (ROOT / "data" / "sample_signin_logs.json").read_bytes()
    assert first == second


# --- Detections -----------------------------------------------------------------

def test_all_seven_detections_fire(alerts):
    fired = {a["detection_id"] for a in alerts}
    assert fired == set(engine.CATALOGUE), f"missing: {set(engine.CATALOGUE) - fired}"


def test_alert_schema(alerts):
    for alert in alerts:
        assert REQUIRED_ALERT_KEYS <= set(alert), alert["alert_id"]
        assert alert["severity"] in engine.SEV_NUM
        assert alert["evidence_count"] == len(alert["evidence"])


def test_mfa_fatigue_escalates_to_critical(alerts):
    mfa = [a for a in alerts if a["detection_id"] == "DET-001"]
    assert len(mfa) == 1
    assert mfa[0]["severity"] == "Critical"
    assert any("approved MFA" in m for m in mfa[0]["severity_modifiers"])
    # burst of 7 denials plus the fatal approval
    assert mfa[0]["evidence_count"] == 8


def test_impossible_travel_true_positive_and_vpn_false_positive(alerts):
    travel = [a for a in alerts if a["detection_id"] == "DET-002"]
    users = {a["user"] for a in travel}
    assert "daniel.wright@contoso.com" in users        # true positive
    assert "sofia.russo@contoso.com" in users          # deliberate VPN false positive
    sofia = next(a for a in travel if a["user"] == "sofia.russo@contoso.com")
    assert sofia["scenario_tags"] == ["vpn_travel_fp"]


def test_tuning_suppresses_only_the_vpn_false_positive(alerts, tuned_alerts):
    before = {a["alert_id"]: a for a in alerts}
    after_users = {a["user"] for a in tuned_alerts if a["detection_id"] == "DET-002"}
    assert "sofia.russo@contoso.com" not in after_users
    assert "daniel.wright@contoso.com" in after_users
    assert len(alerts) - len(tuned_alerts) == 1
    assert any(a["scenario_tags"] == ["vpn_travel_fp"] for a in before.values())


def test_ca_policy_change_flags_unauthorised_actor(alerts):
    ca = [a for a in alerts if a["detection_id"] == "DET-003"]
    assert len(ca) == 1
    assert ca[0]["user"] == "jordan.lee@contoso.com"
    assert ca[0]["severity"] == "Critical"
    assert any("Conditional Access management role" in m for m in ca[0]["severity_modifiers"])


def test_sp_credential_added_is_critical_for_high_tier_target(alerts):
    sp = [a for a in alerts if a["detection_id"] == "DET-004"]
    assert len(sp) == 1
    assert sp[0]["target"] == "sp-automation-graph"
    assert sp[0]["severity"] == "Critical"


def test_priv_role_addition_detects_self_elevation(alerts):
    priv = [a for a in alerts if a["detection_id"] == "DET-005"]
    assert len(priv) == 1
    assert priv[0]["user"] == priv[0]["target"] == "jordan.lee@contoso.com"
    assert any("own account" in m for m in priv[0]["severity_modifiers"])


def test_cyberark_anomaly_offhours_no_ticket(alerts):
    cyber = [a for a in alerts if a["detection_id"] == "DET-006"]
    assert len(cyber) == 1
    assert cyber[0]["user"] == "mark.taylor@contoso.com"
    assert cyber[0]["evidence_count"] == 5
    assert all(e["TicketId"] is None for e in cyber[0]["evidence"])


def test_stale_privileged_accounts(alerts):
    stale = [a for a in alerts if a["detection_id"] == "DET-007"]
    assert {a["user"] for a in stale} == {
        "old.admin@contoso.com", "karen.mills@contoso.com", "svc-backup-legacy@contoso.com"}
    orphaned = next(a for a in stale if a["user"] == "svc-backup-legacy@contoso.com")
    assert orphaned["severity"] == "High"  # orphaned service account escalates


# --- Severity model ---------------------------------------------------------------

def test_severity_modifiers_accumulate_and_cap():
    score, label, mods = engine.apply_modifiers(
        "Medium", privileged=True, off_hours=True, high_risk=False, escalation=False)
    assert (score, label) == (4, "Critical")
    score, label, mods = engine.apply_modifiers(
        "High", privileged=True, off_hours=True, high_risk=True,
        escalation=True, escalation_reason="test")
    assert (score, label) == (4, "Critical")      # capped, never above 4
    assert len(mods) == 4
    score, label, mods = engine.apply_modifiers(
        "Low", privileged=False, off_hours=False, high_risk=False, escalation=False)
    assert (score, label, mods) == (1, "Low", [])


# --- Correlation and metrics -------------------------------------------------------

def test_multistage_attack_correlates_into_one_incident(incidents):
    jordan = [i for i in incidents if i["user"] == "jordan.lee@contoso.com"]
    assert len(jordan) == 1
    assert {a["detection_id"] for a in jordan[0]["alerts"]} == {"DET-003", "DET-004", "DET-005"}
    assert jordan[0]["severity"] == "Critical"


def test_incident_counts_and_dispositions(incidents):
    assert len(incidents) == 8
    dispositions = [i["disposition"] for i in incidents]
    assert dispositions.count("false_positive") == 1
    assert dispositions.count("posture_finding") == 3
    assert dispositions.count("true_positive") == 4


def test_metrics(alerts, tuned_alerts, incidents):
    metrics = reporting.compute_metrics(alerts, incidents, tuned_alerts)
    assert 90.0 <= metrics["sla_adherence_pct"] < 100.0
    assert len(metrics["sla_breaches"]) == 1
    assert metrics["fp_rate_pct"] == pytest.approx(12.5)
    assert metrics["tuning_impact"] == {"DET-002": {"before": 4, "after": 3}}


# --- Detection-as-code contract ------------------------------------------------------

def _rule_files():
    files = sorted(DETECTIONS_DIR.glob("DET-*.yaml"))
    assert len(files) == 7, "expected exactly seven YAML rules"
    return files


def test_every_catalogue_entry_has_kql_yaml_and_code():
    engine_source = (ROOT / "src" / "detection_engine.py").read_text(encoding="utf-8")
    yaml_ids = {yaml.safe_load(f.read_text(encoding="utf-8"))["id"] for f in _rule_files()}
    kql_ids = {f.name.split("-", 3)[0] + "-" + f.name.split("-", 3)[1]
               for f in DETECTIONS_DIR.glob("DET-*.kql")}
    for det_id, meta in engine.CATALOGUE.items():
        assert det_id in yaml_ids, f"{det_id} missing a YAML rule"
        assert det_id in kql_ids, f"{det_id} missing a KQL file"
        assert f"def {meta['function']}(" in engine_source


def test_yaml_rules_are_valid():
    for path in _rule_files():
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        missing = REQUIRED_RULE_KEYS - set(rule)
        assert not missing, f"{path.name}: missing keys {missing}"
        assert path.name.startswith(rule["id"]), f"{path.name}: id/filename mismatch"
        assert rule["severity"] in ("Low", "Medium", "High", "Critical")
        assert rule["kind"] == "Scheduled"
        for technique in rule["techniques"]:
            assert re.fullmatch(r"T\d{4}(\.\d{3})?", technique), \
                f"{path.name}: bad technique id {technique}"
        for tactic in rule["tactics"]:
            assert re.fullmatch(r"[A-Z][A-Za-z]+", tactic), \
                f"{path.name}: tactics must be PascalCase, got {tactic}"
        query_path = (path.parent / rule["query_file"]).resolve()
        assert query_path.exists() and query_path.stat().st_size > 0, \
            f"{path.name}: query_file {rule['query_file']} missing or empty"
        # rule metadata matches the engine catalogue
        meta = engine.CATALOGUE[rule["id"]]
        assert rule["local_detection"] == meta["function"]
        assert rule["tactics"] == meta["tactics"]
        assert rule["techniques"] == meta["techniques"]
        assert rule["severity"] == meta["base_severity"]
