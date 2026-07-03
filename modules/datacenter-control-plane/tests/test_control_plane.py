"""Tests for the Datacenter Control Plane Attack Path Lab.

Covers the attack-chain correlation, blast-radius scoring, the deliberate
benign cases (internal NSG change, low-privilege SP credential), detection
metadata completeness, and that the demo artefacts are produced.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest
import yaml

MODULE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MODULE_ROOT / "src"))

import correlation_engine as engine   # noqa: E402
import generate_telemetry             # noqa: E402
import main as module_main            # noqa: E402

DETECTIONS_DIR = MODULE_ROOT / "detections"
PLAYBOOKS_DIR = MODULE_ROOT / "playbooks"
DEMO_DIR = MODULE_ROOT / "demo-output"

REQUIRED_RULE_KEYS = {
    "id", "title", "description", "severity", "data_source", "tactics",
    "techniques", "false_positive_guidance", "response_guidance", "owner",
    "version", "test_expectation", "local_detection",
}
APPROVAL_CLASSES = {"automatic", "human approval required", "manual only"}


@pytest.fixture(scope="session", autouse=True)
def regenerate():
    generate_telemetry.main()


@pytest.fixture(scope="session")
def data():
    return engine.load_data()


@pytest.fixture(scope="session")
def alerts(data):
    return engine.run_detections(data)


@pytest.fixture(scope="session")
def incidents(alerts, data):
    return engine.correlate(alerts, data)


# --- Attack chain ------------------------------------------------------------

def test_attack_chain_produces_one_critical_correlated_incident(incidents):
    chains = [i for i in incidents if i["is_chain"]]
    assert len(chains) == 1
    chain = chains[0]
    assert chain["severity"] == "Critical"
    assert chain["chain_detection"] == "CP-DET-008"
    # all seven telemetry stages correlated
    assert set(chain["stages_observed"]) == {1, 2, 3, 4, 5, 6, 7}
    assert chain["blast_radius"]["score"] >= 80
    assert chain["blast_radius"]["label"] == "Critical"


def test_chain_links_identity_sp_and_resource_group(incidents):
    chain = next(i for i in incidents if i["is_chain"])
    entities = set(chain["entities"])
    assert "chris.walker@contoso.com" in entities
    assert "sp-infra-deploy" in entities
    assert any("rg-prod-dc-mgmt" in e for e in entities)


def test_all_eight_detections_represented(alerts, incidents):
    fired = {a["detection_id"] for a in alerts}
    # seven telemetry detections fire as alerts...
    for det in ("CP-DET-001", "CP-DET-002", "CP-DET-003", "CP-DET-004",
                "CP-DET-005", "CP-DET-006", "CP-DET-007"):
        assert det in fired, f"{det} did not fire"
    # ...and CP-DET-008 is the correlated chain incident
    assert any(i["chain_detection"] == "CP-DET-008" for i in incidents)


# --- Benign cases (must NOT alert) -------------------------------------------

def test_benign_internal_nsg_change_does_not_trigger_public_exposure(alerts):
    nsg_alerts = [a for a in alerts if a["detection_id"] in ("CP-DET-006", "CP-DET-007")]
    for alert in nsg_alerts:
        for event in alert["evidence"]:
            assert event["SourceAddressPrefix"] in engine.PUBLIC_PREFIXES
            assert event["NsgName"] != "nsg-prod-app"  # the benign internal change


def test_sp_credential_alerts_only_for_high_privilege_sp(alerts, data):
    sp_alerts = [a for a in alerts if a["detection_id"] == "CP-DET-004"]
    assert len(sp_alerts) == 1
    target = sp_alerts[0]["resources"][0]
    assert data["asset_by_id"][target]["privilege_tier"] == "high"
    # the low-privilege SP credential add exists in telemetry but must not alert
    assert all("sp-monitoring-reader" not in a["resources"] for a in sp_alerts)


def test_priv_role_activation_requires_missing_change_ticket(alerts):
    role_alerts = [a for a in alerts if a["detection_id"] == "CP-DET-003"]
    assert len(role_alerts) == 1
    assert role_alerts[0]["evidence"][0]["Detail"]["change_ticket"] is None


# --- Blast radius ------------------------------------------------------------

def test_blast_radius_factors_are_explainable(incidents):
    chain = next(i for i in incidents if i["is_chain"])
    factors = {f["factor"] for f in chain["blast_radius"]["factors"]}
    assert factors == {"identity_privilege", "service_principal_permissions",
                       "public_exposure", "asset_criticality", "affected_resources"}
    assert chain["blast_radius"]["score"] == sum(
        f["points"] for f in chain["blast_radius"]["factors"])


# --- Demo artefacts ----------------------------------------------------------

def test_demo_writes_all_artefacts():
    module_main.run_demo()
    for name in ("control_plane_alerts.json", "control_plane_incidents.json",
                 "control_plane_timeline.md", "control_plane_rca.md",
                 "control_plane_metrics.json"):
        path = DEMO_DIR / name
        assert path.exists() and path.stat().st_size > 0, name


def test_timeline_and_rca_have_content():
    timeline = (DEMO_DIR / "control_plane_timeline.md").read_text(encoding="utf-8")
    rca = (DEMO_DIR / "control_plane_rca.md").read_text(encoding="utf-8")
    assert "blast radius" in timeline.lower()
    assert "response flow" in timeline.lower()
    assert "root cause" in rca.lower()
    assert "hardening" in rca.lower()


# --- Detection-as-code metadata ---------------------------------------------

def _rule_files():
    files = sorted(DETECTIONS_DIR.glob("CP-DET-*.yaml"))
    assert len(files) == 8, "expected eight YAML detection rules"
    return files


def test_every_detection_has_mitre_and_response_guidance():
    for path in _rule_files():
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        missing = REQUIRED_RULE_KEYS - set(rule)
        assert not missing, f"{path.name}: missing {missing}"
        assert rule["techniques"], f"{path.name}: no MITRE techniques"
        for technique in rule["techniques"]:
            assert re.fullmatch(r"T\d{4}(\.\d{3})?", technique), \
                f"{path.name}: bad technique {technique}"
        assert rule["response_guidance"].strip(), f"{path.name}: no response guidance"
        assert rule["owner"].strip()


def test_every_detection_has_a_kql_file():
    for path in _rule_files():
        kql = path.with_suffix(".kql")
        assert kql.exists() and kql.stat().st_size > 0, f"missing KQL for {path.name}"


def test_every_playbook_action_has_approval_classification():
    playbook = json.loads((PLAYBOOKS_DIR / "control_plane_playbooks.json")
                          .read_text(encoding="utf-8"))
    assert len(playbook["playbooks"]) >= 9
    for pb in playbook["playbooks"]:
        assert pb["automation_level"] in APPROVAL_CLASSES, \
            f"{pb['playbook_id']}: bad automation_level {pb['automation_level']}"
