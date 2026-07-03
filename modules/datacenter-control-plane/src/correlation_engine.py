"""Detection and correlation engine for the Datacenter Control Plane Attack
Path Lab.

Runs eight KQL-mirrored detections over the synthetic telemetry, links related
alerts by identity, service principal, resource scope and time window, scores
blast radius, and emits the incident timeline, RCA and metrics artefacts.

Python standard library only. Detection logic mirrors the KQL in
../detections/ with identical thresholds.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = MODULE_ROOT / "data"
DEMO_DIR = MODULE_ROOT / "demo-output"

LOCAL_UTC_OFFSET = timedelta(hours=10)
CORRELATION_WINDOW = timedelta(hours=4)
MFA_BURST_THRESHOLD = 5
MFA_BURST_WINDOW = timedelta(minutes=10)
MFA_APPROVAL_FOLLOWUP = timedelta(minutes=30)
MANAGEMENT_PORTS = {"22", "3389", "5985", "5986"}
PROTECTED_ROLES = {"Global Administrator", "Privileged Role Administrator",
                   "Application Administrator"}
PUBLIC_PREFIXES = {"0.0.0.0/0", "*", "Internet"}

CATALOGUE = {
    "CP-DET-001": {"name": "Risky sign-in from unusual location",
                   "severity": "High", "stage": 1,
                   "tactics": ["InitialAccess"], "techniques": ["T1078.004"]},
    "CP-DET-002": {"name": "MFA fatigue leading to approval",
                   "severity": "Critical", "stage": 2,
                   "tactics": ["CredentialAccess"], "techniques": ["T1621"]},
    "CP-DET-003": {"name": "Privileged role activation without change record",
                   "severity": "High", "stage": 3,
                   "tactics": ["PrivilegeEscalation"], "techniques": ["T1098.003"]},
    "CP-DET-004": {"name": "Credential added to high-privilege service principal",
                   "severity": "Critical", "stage": 4,
                   "tactics": ["Persistence"], "techniques": ["T1098.001"]},
    "CP-DET-005": {"name": "Subscription or resource group permission change",
                   "severity": "High", "stage": 5,
                   "tactics": ["PrivilegeEscalation"], "techniques": ["T1098.003"]},
    "CP-DET-006": {"name": "NSG or firewall rule opened to the internet",
                   "severity": "Critical", "stage": 6,
                   "tactics": ["DefenseEvasion"], "techniques": ["T1562.007"]},
    "CP-DET-007": {"name": "VM management endpoint exposed to the internet",
                   "severity": "Critical", "stage": 7,
                   "tactics": ["InitialAccess"], "techniques": ["T1133"]},
    "CP-DET-008": {"name": "Correlated identity-to-control-plane attack chain",
                   "severity": "Critical", "stage": 8,
                   "tactics": ["InitialAccess", "CredentialAccess",
                               "PrivilegeEscalation", "Persistence",
                               "DefenseEvasion"],
                   "techniques": ["T1078.004", "T1621", "T1098.001",
                                  "T1098.003", "T1562.007", "T1133"]},
}

SEV_NUM = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def parse_ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def load_data() -> dict:
    data = {}
    for name in ("entra_signin_logs", "entra_audit_logs", "azure_activity_logs",
                 "network_security_group_logs", "defender_alerts",
                 "identity_inventory", "asset_inventory"):
        data[name] = json.loads((DATA_DIR / f"{name}.json").read_text(encoding="utf-8"))
    data["identity_by_upn"] = {i["upn"]: i for i in data["identity_inventory"]}
    data["asset_by_id"] = {a["asset_id"]: a for a in data["asset_inventory"]}
    return data


def _alert(det_id, entity, evidence, *, resources=None) -> dict:
    meta = CATALOGUE[det_id]
    stamps = sorted(e["TimeGenerated"] for e in evidence)
    return {"detection_id": det_id, "detection_name": meta["name"],
            "severity": meta["severity"], "stage": meta["stage"],
            "mitre_tactics": meta["tactics"], "mitre_techniques": meta["techniques"],
            "entity": entity, "resources": sorted(resources or []),
            "window_start": stamps[0], "window_end": stamps[-1],
            "evidence_count": len(evidence), "evidence": evidence,
            "scenario_tags": sorted({e.get("SimScenario", "") for e in evidence})}


# --- Detections -------------------------------------------------------------------

def detect_risky_signin(data) -> list[dict]:
    """CP-DET-001: successful sign-in with high risk from a country that is not
    the user's usual country."""
    alerts = []
    for event in data["entra_signin_logs"]:
        if event["ResultType"] != 0 or event["RiskLevelDuringSignIn"] != "high":
            continue
        ident = data["identity_by_upn"].get(event["UserPrincipalName"], {})
        if event["Country"] == ident.get("usual_country"):
            continue
        alerts.append(_alert("CP-DET-001", event["UserPrincipalName"], [event]))
    return alerts


def detect_mfa_fatigue(data) -> list[dict]:
    """CP-DET-002: >=5 failed strong-auth events for one user within 10 minutes,
    followed by an approval within 30 minutes."""
    by_user: dict[str, list[dict]] = {}
    for event in data["entra_signin_logs"]:
        if event["ResultType"] == 500121:
            by_user.setdefault(event["UserPrincipalName"], []).append(event)
    alerts = []
    for user, events in sorted(by_user.items()):
        events.sort(key=lambda e: e["TimeGenerated"])
        times = [parse_ts(e["TimeGenerated"]) for e in events]
        flagged: set[int] = set()
        left = 0
        for right in range(len(events)):
            while times[right] - times[left] > MFA_BURST_WINDOW:
                left += 1
            if right - left + 1 >= MFA_BURST_THRESHOLD:
                flagged.update(range(left, right + 1))
        if not flagged:
            continue
        burst = [events[i] for i in sorted(flagged)]
        burst_end = parse_ts(burst[-1]["TimeGenerated"])
        approvals = [e for e in data["entra_signin_logs"]
                     if e["UserPrincipalName"] == user and e["ResultType"] == 0
                     and e["MfaResult"] == "approved"
                     and burst_end < parse_ts(e["TimeGenerated"]) <= burst_end + MFA_APPROVAL_FOLLOWUP]
        if approvals:  # this rule requires the approval - the takeover moment
            alerts.append(_alert("CP-DET-002", user, burst + approvals))
    return alerts


def detect_priv_role_activation(data) -> list[dict]:
    """CP-DET-003: protected-role activation or addition with no linked change
    record."""
    alerts = []
    for event in data["entra_audit_logs"]:
        if "role" not in {k.lower() for k in event["Detail"]}:
            continue
        if not event["OperationName"].startswith(("Add member to role",)):
            continue
        role = event["Detail"].get("role", "")
        if role not in PROTECTED_ROLES:
            continue
        if event["Detail"].get("change_ticket"):
            continue
        alerts.append(_alert("CP-DET-003", event["ActorUPN"], [event]))
    return alerts


def detect_sp_credential_added(data) -> list[dict]:
    """CP-DET-004: credential added to a service principal classified
    high-privilege in the asset inventory. Low-tier principals do not alert."""
    alerts = []
    for event in data["entra_audit_logs"]:
        if event["OperationName"] != "Add service principal credentials":
            continue
        asset = data["asset_by_id"].get(event["TargetName"], {})
        if asset.get("privilege_tier") != "high":
            continue
        alerts.append(_alert("CP-DET-004", event["ActorUPN"], [event],
                             resources=[event["TargetName"]]))
    return alerts


def detect_permission_change(data) -> list[dict]:
    """CP-DET-005: role assignment written at subscription or resource group
    scope with no linked change record."""
    alerts = []
    for event in data["azure_activity_logs"]:
        if event["OperationNameValue"] != "Microsoft.Authorization/roleAssignments/write":
            continue
        if event["Properties"].get("change_ticket"):
            continue
        alerts.append(_alert("CP-DET-005", event["Caller"], [event],
                             resources=[event["Scope"],
                                        event["Properties"].get("principal", "")]))
    return alerts


def detect_nsg_public_rule(data) -> list[dict]:
    """CP-DET-006: NSG allow rule created or updated with an internet-wide
    source prefix. Internal source ranges never alert."""
    alerts = []
    for event in data["network_security_group_logs"]:
        if event["Access"] != "Allow":
            continue
        if event["SourceAddressPrefix"] not in PUBLIC_PREFIXES:
            continue
        alerts.append(_alert("CP-DET-006", event["Actor"], [event],
                             resources=[event["NsgName"]]))
    return alerts


def detect_mgmt_endpoint_exposed(data) -> list[dict]:
    """CP-DET-007: an internet-open NSG rule on a management port, where the NSG
    protects a VM that has a public IP - the endpoint is actually reachable."""
    alerts = []
    for event in data["network_security_group_logs"]:
        if event["Access"] != "Allow":
            continue
        if event["SourceAddressPrefix"] not in PUBLIC_PREFIXES:
            continue
        if event["DestinationPortRange"] not in MANAGEMENT_PORTS:
            continue
        nsg = data["asset_by_id"].get(event["NsgName"], {})
        exposed = [vm for vm in nsg.get("protects", [])
                   if data["asset_by_id"].get(vm, {}).get("public_ip")]
        if not exposed:
            continue
        alerts.append(_alert("CP-DET-007", event["Actor"], [event], resources=exposed))
    return alerts


def run_detections(data) -> list[dict]:
    alerts = []
    for func in (detect_risky_signin, detect_mfa_fatigue, detect_priv_role_activation,
                 detect_sp_credential_added, detect_permission_change,
                 detect_nsg_public_rule, detect_mgmt_endpoint_exposed):
        alerts.extend(func(data))
    alerts.sort(key=lambda a: (a["window_start"], a["detection_id"]))
    for index, alert in enumerate(alerts, 1):
        alert["alert_id"] = f"CP-AL-{index:04d}"
    return alerts


# --- Correlation and blast radius ---------------------------------------------------

def _entities_of(alert, data) -> set[str]:
    """Identity, service principal and resource entities an alert touches -
    the keys correlation links on."""
    entities = {alert["entity"]}
    entities.update(alert["resources"])
    for event in alert["evidence"]:
        for key in ("UserPrincipalName", "ActorUPN", "Caller", "Actor",
                    "TargetName", "NsgName"):
            if event.get(key):
                entities.add(event[key])
        if event.get("Scope"):
            entities.add(event["Scope"].split("/resourceGroups/")[-1])
        if event.get("Properties", {}).get("principal"):
            entities.add(event["Properties"]["principal"])
    entities.discard("")
    return entities


def correlate(alerts, data) -> list[dict]:
    """Link alerts sharing an entity within the correlation window
    (transitively), then emit the chain incident CP-DET-008 when three or more
    distinct attack stages are present."""
    groups: list[dict] = []
    for alert in sorted(alerts, key=lambda a: a["window_start"]):
        entities = _entities_of(alert, data)
        start = parse_ts(alert["window_start"])
        placed = None
        for group in groups:
            if entities & group["entities"] and \
                    start - group["latest"] <= CORRELATION_WINDOW:
                group["alerts"].append(alert)
                group["entities"] |= entities
                group["latest"] = max(group["latest"], parse_ts(alert["window_end"]))
                placed = group
                break
        if not placed:
            groups.append({"alerts": [alert], "entities": entities,
                           "latest": parse_ts(alert["window_end"])})

    incidents = []
    for index, group in enumerate(sorted(groups, key=lambda g: g["alerts"][0]["window_start"]), 1):
        alerts_in = group["alerts"]
        stages = sorted({a["stage"] for a in alerts_in})
        is_chain = len(stages) >= 3
        det_meta = CATALOGUE["CP-DET-008"]
        defender_hits = [d for d in data["defender_alerts"]
                         if set(d["Entities"]) & group["entities"]
                         and d["Severity"] not in ("Informational",)]
        severity = "Critical" if is_chain else max(
            alerts_in, key=lambda a: SEV_NUM[a["severity"]])["severity"]
        incident = {
            "incident_id": f"CP-INC-{2000 + index}",
            "title": (f"Identity-to-control-plane attack chain - {alerts_in[0]['entity']}"
                      if is_chain else
                      f"{alerts_in[0]['detection_name']} - {alerts_in[0]['entity']}"),
            "is_chain": is_chain,
            "chain_detection": "CP-DET-008" if is_chain else None,
            "severity": severity,
            "stages_observed": stages,
            "entities": sorted(group["entities"]),
            "alert_ids": [a["alert_id"] for a in alerts_in],
            "alerts": alerts_in,
            "defender_signals": defender_hits,
            "mitre_techniques": (det_meta["techniques"] if is_chain else
                                 sorted({t for a in alerts_in for t in a["mitre_techniques"]})),
            "window_start": alerts_in[0]["window_start"],
            "window_end": max(a["window_end"] for a in alerts_in),
        }
        incident["blast_radius"] = blast_radius(incident, data)
        incidents.append(incident)
    return incidents


def blast_radius(incident, data) -> dict:
    """Explainable 0-100 blast-radius score across five weighted factors."""
    factors = []

    identities = [data["identity_by_upn"][e] for e in incident["entities"]
                  if e in data["identity_by_upn"]]
    priv = any(i["is_privileged"] or i["pim_eligible_roles"] for i in identities)
    factors.append(("identity_privilege",
                    25 if priv else 5,
                    "compromised identity holds or can activate privileged roles"
                    if priv else "no privileged identity involved"))

    sps = [data["asset_by_id"][e] for e in incident["entities"]
           if data["asset_by_id"].get(e, {}).get("type") == "service_principal"]
    high_sp = any(sp["privilege_tier"] == "high" for sp in sps)
    factors.append(("service_principal_permissions",
                    25 if high_sp else (10 if sps else 0),
                    "high-privilege service principal in scope" if high_sp else
                    ("only low-privilege service principals" if sps else
                     "no service principal involved")))

    public = any(a["detection_id"] in ("CP-DET-006", "CP-DET-007")
                 for a in incident["alerts"])
    factors.append(("public_exposure", 20 if public else 0,
                    "management surface reachable from the internet" if public
                    else "no public exposure created"))

    touched = [data["asset_by_id"][e] for e in incident["entities"]
               if e in data["asset_by_id"]]
    critical = any(a.get("criticality") == "critical" for a in touched)
    factors.append(("asset_criticality",
                    20 if critical else (10 if touched else 0),
                    "critical datacenter-management assets in scope" if critical
                    else ("non-critical assets only" if touched else "no assets touched")))

    resources = {r for a in incident["alerts"] for r in a["resources"]}
    factors.append(("affected_resources", min(len(resources) * 3, 10),
                    f"{len(resources)} distinct resources affected"))

    score = sum(value for _, value, _ in factors)
    label = ("Critical" if score >= 80 else "High" if score >= 60 else
             "Medium" if score >= 40 else "Low")
    return {"score": score, "label": label,
            "factors": [{"factor": f, "points": v, "reason": r}
                        for f, v, r in factors]}
