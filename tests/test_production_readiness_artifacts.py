"""Tests for the Production Readiness & Operations Layer.

Assert the artefacts exist, the JSON is valid, the scorecard has all ten
dimensions, the root README links the layer, and nothing contains secrets, real
Azure identifiers, or non-fictional email addresses.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PR = ROOT / "production-readiness"

GUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
ALLOWED_EMAIL_DOMAINS = ("@contoso.com", "@example.com")
SECRET_TOKENS = ("client_secret", "access_token", "refresh_token",
                 "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY")
REQUIRED_FOLDERS = [
    "telemetry", "connectors", "incident-response", "tuning", "change-approval",
    "rbac", "cost-management", "on-call", "playbook-validation", "maintenance",
    "checklists", "reports",
]


def test_layer_readme_and_folders_exist():
    assert (PR / "README.md").exists()
    for folder in REQUIRED_FOLDERS:
        assert (PR / folder).is_dir(), f"missing folder: {folder}"


def test_key_artifacts_exist():
    for rel in [
        "reports/PRODUCTION_READINESS_SCORECARD.md",
        "reports/production-readiness-scorecard.json",
        "reports/GAP_CLOSURE_ROADMAP.md",
        "connectors/CONNECTOR_VALIDATION_CHECKLIST.md",
        "connectors/CONNECTOR_RUNBOOK.md",
        "incident-response/INCIDENT_RESPONSE_OPERATING_MODEL.md",
        "rbac/SENTINEL_RBAC_MATRIX.md",
        "cost-management/SENTINEL_COST_MODEL.md",
        "playbook-validation/PLAYBOOK_APPROVAL_PROCESS.md",
        "maintenance/MAINTENANCE_OPERATING_MODEL.md",
        "telemetry/SYNTHETIC_TO_REAL_TELEMETRY_MAPPING.md",
        "tuning/DETECTION_TUNING_PROCESS.md",
        "change-approval/CHANGE_APPROVAL_MODEL.md",
        "on-call/DRI_ROTATION_MODEL.md",
        "checklists/PRE_PRODUCTION_CHECKLIST.md",
    ]:
        path = PR / rel
        assert path.exists() and path.stat().st_size > 0, f"missing/empty: {rel}"


def test_all_json_valid():
    for path in PR.rglob("*.json"):
        json.loads(path.read_text(encoding="utf-8"))  # raises on invalid JSON


def test_scorecard_has_all_ten_dimensions():
    data = json.loads((PR / "reports" / "production-readiness-scorecard.json")
                      .read_text(encoding="utf-8"))
    dims = data["dimensions"]
    assert len(dims) == 10, f"expected 10 dimensions, got {len(dims)}"
    assert sorted(d["id"] for d in dims) == list(range(1, 11))
    for d in dims:
        assert 0 <= d["score"] <= 100
        assert d["reason"] and d["gap_to_close"] and d["evidence"]
    # Overall score present and consistent with the mean (honesty guard).
    assert "overall_score" in data["summary"]
    mean = sum(d["score"] for d in dims) / len(dims)
    assert abs(data["summary"]["overall_score"] - mean) < 0.5
    # Honest framing: not production-ready.
    assert "not production-ready" in data["summary"]["honest_note"].lower()


def test_scorecard_md_names_all_ten_dimensions():
    md = (PR / "reports" / "PRODUCTION_READINESS_SCORECARD.md").read_text(encoding="utf-8")
    for dimension in ["Telemetry readiness", "Connector readiness", "Detection maturity",
                      "Incident response readiness", "Automation safety", "Change control",
                      "RBAC / least privilege", "Cost governance", "DRI / on-call model",
                      "Maintenance / ownership"]:
        assert dimension in md, f"scorecard.md missing dimension: {dimension}"


def test_root_readme_links_the_layer():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "production-readiness/README.md" in readme
    assert "Production Readiness" in readme


def test_no_secrets_no_real_ids_no_real_emails():
    for path in PR.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        lowered = text.lower()
        for token in SECRET_TOKENS:
            assert token.lower() not in lowered, f"{path}: contains '{token}'"
        # No real GUID (only the all-zero placeholder is allowed).
        for m in GUID_RE.findall(text):
            assert m == "00000000-0000-0000-0000-000000000000", \
                f"{path}: unexpected GUID {m}"
        # Every email must be a fictional domain.
        for email in EMAIL_RE.findall(text):
            assert email.endswith(ALLOWED_EMAIL_DOMAINS), \
                f"{path}: non-fictional email {email}"
