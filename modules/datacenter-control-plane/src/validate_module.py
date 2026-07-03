"""Detection-as-code validator for the control-plane module (CI gate).

Checks, exiting non-zero with a clear report on any failure:
- every YAML detection has the required keys, a MITRE mapping and response
  guidance;
- each detection id matches its filename and has a paired KQL file;
- every playbook action carries a valid approval classification.

Requires PyYAML.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML is required: pip install pyyaml")
    sys.exit(2)

MODULE_ROOT = Path(__file__).resolve().parents[1]
DETECTIONS_DIR = MODULE_ROOT / "detections"
PLAYBOOKS = MODULE_ROOT / "playbooks" / "control_plane_playbooks.json"

REQUIRED_KEYS = {
    "id", "title", "description", "severity", "data_source", "tactics",
    "techniques", "false_positive_guidance", "response_guidance", "owner",
    "version", "test_expectation", "local_detection",
}
APPROVAL_CLASSES = {"automatic", "human approval required", "manual only"}
SEVERITIES = {"Low", "Medium", "High", "Critical"}


def validate() -> list[str]:
    failures: list[str] = []

    rule_files = sorted(DETECTIONS_DIR.glob("CP-DET-*.yaml"))
    if len(rule_files) != 8:
        failures.append(f"expected 8 detection rules, found {len(rule_files)}")

    for path in rule_files:
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        missing = REQUIRED_KEYS - set(rule)
        if missing:
            failures.append(f"{path.name}: missing keys {sorted(missing)}")
            continue
        if not path.name.startswith(rule["id"]):
            failures.append(f"{path.name}: id '{rule['id']}' does not match filename")
        if rule["severity"] not in SEVERITIES:
            failures.append(f"{path.name}: bad severity '{rule['severity']}'")
        if not rule["techniques"]:
            failures.append(f"{path.name}: no MITRE techniques")
        for technique in rule["techniques"]:
            if not re.fullmatch(r"T\d{4}(\.\d{3})?", str(technique)):
                failures.append(f"{path.name}: bad technique id '{technique}'")
        if not str(rule["response_guidance"]).strip():
            failures.append(f"{path.name}: empty response guidance")
        if not str(rule["owner"]).strip():
            failures.append(f"{path.name}: empty owner")
        kql = path.with_suffix(".kql")
        if not (kql.exists() and kql.stat().st_size > 0):
            failures.append(f"{path.name}: missing or empty KQL file {kql.name}")

    if not PLAYBOOKS.exists():
        failures.append(f"missing playbook file {PLAYBOOKS.name}")
    else:
        playbook = json.loads(PLAYBOOKS.read_text(encoding="utf-8"))
        for pb in playbook.get("playbooks", []):
            level = pb.get("automation_level")
            if level not in APPROVAL_CLASSES:
                failures.append(
                    f"playbook {pb.get('playbook_id')}: automation_level "
                    f"'{level}' is not one of {sorted(APPROVAL_CLASSES)}")
    return failures


def main() -> None:
    failures = validate()
    if failures:
        print("Control-plane module validation FAILED:")
        for failure in failures:
            print(f"  - {failure}")
        sys.exit(1)
    print("Control-plane module validation passed: 8 detections, MITRE + "
          "response guidance present, playbook approval classes valid.")


if __name__ == "__main__":
    main()
