"""Tests for the optional Mode C live Sentinel deployment artefacts.

These assert the files exist, contain no secrets or real Azure identifiers, and
carry the required safety guard rails. They do NOT deploy anything to Azure.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INFRA = ROOT / "infra" / "sentinel"
SCRIPTS = ROOT / "scripts" / "sentinel"
DEPLOY_DOC = ROOT / "docs" / "LIVE_SENTINEL_DEPLOYMENT_PATH.md"
DEPLOY_SCRIPT = SCRIPTS / "deploy_sentinel_lab.sh"

# A 36-char GUID that is NOT the all-zero placeholder.
GUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
SECRET_TOKENS = ("client_secret", "access_token", "refresh_token",
                 "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY")


def test_required_files_exist():
    for path in [
        DEPLOY_DOC,
        INFRA / "main.bicep",
        INFRA / "parameters.example.json",
        INFRA / "README.md",
        INFRA / "modules" / "log-analytics-workspace.bicep",
        INFRA / "modules" / "sentinel-onboarding.bicep",
        INFRA / "modules" / "analytics-rule.bicep",
        INFRA / "modules" / "automation-rule.bicep",
        INFRA / "modules" / "playbook-logic-app.bicep",
        DEPLOY_SCRIPT,
        SCRIPTS / "validate_sentinel_templates.sh",
        SCRIPTS / "deploy_sentinel_lab.sh.example",
        SCRIPTS / "destroy_sentinel_lab.sh.example",
        SCRIPTS / "test_sentinel_deployment.sh.example",
    ]:
        assert path.exists() and path.stat().st_size > 0, f"missing: {path}"


def _sentinel_files():
    for base in (INFRA, SCRIPTS):
        for path in base.rglob("*"):
            if path.is_file():
                yield path


def test_no_secrets_or_real_azure_ids():
    for path in _sentinel_files():
        text = path.read_text(encoding="utf-8")
        lowered = text.lower()
        for token in SECRET_TOKENS:
            assert token.lower() not in lowered, f"{path.name}: contains '{token}'"
        # No real-looking GUIDs assigned to subscriptionId / tenantId.
        for line in text.splitlines():
            if ("subscriptionid" in line.lower() or "tenantid" in line.lower()) \
                    and GUID_RE.search(line) \
                    and "00000000-0000-0000-0000-000000000000" not in line:
                raise AssertionError(f"{path.name}: possible real Azure id -> {line.strip()}")


def test_no_bare_guids_in_parameter_or_json_files():
    """The example parameters and any JSON must not carry a real GUID."""
    for path in INFRA.rglob("*.json"):
        for line in path.read_text(encoding="utf-8").splitlines():
            found = GUID_RE.search(line)
            if found and "00000000-0000-0000-0000-000000000000" not in line:
                raise AssertionError(f"{path.name}: unexpected GUID -> {line.strip()}")


def test_readme_links_to_live_deployment_doc():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/LIVE_SENTINEL_DEPLOYMENT_PATH.md" in readme
    assert "infra/sentinel/" in readme


def test_analytics_rule_references_signinlogs():
    rule = (INFRA / "modules" / "analytics-rule.bicep").read_text(encoding="utf-8")
    assert "SigninLogs" in rule
    # Ships disabled by default for tenant safety.
    assert "param enableRule bool = false" in rule


def test_deploy_script_has_cost_warning_and_confirmation_guard():
    script = DEPLOY_SCRIPT.read_text(encoding="utf-8")
    assert "COST" in script.upper(), "deploy script must warn about cost"
    assert "I_UNDERSTAND_THIS_CREATES_AZURE_RESOURCES" in script
    assert "set -euo pipefail" in script
    # It must show the active subscription before deploying.
    assert "az account show" in script


def test_playbook_is_disabled_and_non_destructive():
    playbook = (INFRA / "modules" / "playbook-logic-app.bicep").read_text(encoding="utf-8")
    # Off by default.
    assert "state: 'Disabled'" in playbook
    # No API connections and no secrets means no way to authenticate a
    # destructive action against Entra ID / network / etc.
    assert "$connections" not in playbook
    assert "api/connections" not in playbook.lower()
    # The workflow body should only use benign action/trigger types. If any
    # destructive verb appears, it must be inside a // comment (the safety note),
    # never in a code/string line.
    for line in playbook.splitlines():
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        for verb in ("revoke", "rotate", "firewall", "accountenabled"):
            assert verb not in line.lower(), \
                f"playbook has non-comment '{verb}': {stripped}"


def test_default_deployment_is_lab_scoped():
    main = (INFRA / "main.bicep").read_text(encoding="utf-8")
    assert "param environmentName string = 'lab'" in main
    assert "param enableAnalyticsRule bool = false" in main
    assert "param deployAutomationRules bool = false" in main
    assert "param deployPlaybook bool = false" in main
