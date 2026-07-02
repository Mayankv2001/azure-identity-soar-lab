"""Local detection engine - runs the seven KQL-mirrored detections offline.

Each detection function implements exactly the same logic and thresholds as its
Sentinel KQL counterpart in detections/DET-00X-*.kql, so the lab demonstrates the
detection lifecycle without needing a tenant. Severity is scored with a simple,
explainable model: base severity per detection plus contextual modifiers.
"""
from __future__ import annotations

import argparse
import json
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
OUTPUT_DIR = ROOT / "output"

SIM_NOW = datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)
LOCAL_UTC_OFFSET = timedelta(hours=10)  # Australia/Sydney (fixed offset for the sim)
BUSINESS_HOURS = (8, 18)                # local

SEV_NUM = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
NUM_SEV = {v: k for k, v in SEV_NUM.items()}

# Thresholds shared with the KQL rules.
MFA_BURST_THRESHOLD = 5
MFA_BURST_WINDOW = timedelta(minutes=10)
MFA_APPROVAL_FOLLOWUP = timedelta(minutes=30)
TRAVEL_SPEED_KMH = 900
VPN_EGRESS_PREFIX = "198.51.100."       # corporate VPN range 198.51.100.0/24
CYBERARK_BURST_THRESHOLD = 4
CYBERARK_BURST_WINDOW = timedelta(minutes=60)
CYBERARK_QUIET_HOURS = (0, 5)           # local 00:00-04:59
STALE_DAYS = 60
PRIVILEGED_ROLES = {"Global Administrator", "Privileged Role Administrator"}
PRIVILEGED_GROUPS = {"sg-prod-domain-admins"}
CA_AUTHORISED_ROLES = {"Conditional Access Administrator", "Global Administrator"}
CA_OPERATIONS = {"Update conditional access policy", "Delete conditional access policy"}

CATALOGUE = {
    "DET-001": {
        "name": "MFA Fatigue (Push Bombing)",
        "base_severity": "High",
        "tactics": ["CredentialAccess"],
        "techniques": ["T1621"],
        "function": "detect_mfa_fatigue",
    },
    "DET-002": {
        "name": "Impossible Travel Sign-in",
        "base_severity": "Medium",
        "tactics": ["InitialAccess", "DefenseEvasion"],
        "techniques": ["T1078.004"],
        "function": "detect_impossible_travel",
    },
    "DET-003": {
        "name": "Conditional Access Policy Modified or Deleted",
        "base_severity": "High",
        "tactics": ["DefenseEvasion", "Persistence"],
        "techniques": ["T1556.009"],
        "function": "detect_ca_policy_change",
    },
    "DET-004": {
        "name": "New Credential Added to Service Principal",
        "base_severity": "High",
        "tactics": ["Persistence", "PrivilegeEscalation"],
        "techniques": ["T1098.001"],
        "function": "detect_sp_credential_added",
    },
    "DET-005": {
        "name": "Account Added to Privileged Role or Group",
        "base_severity": "High",
        "tactics": ["PrivilegeEscalation", "Persistence"],
        "techniques": ["T1098.003", "T1098.007"],
        "function": "detect_priv_role_addition",
    },
    "DET-006": {
        "name": "Anomalous CyberArk Privileged Credential Checkout",
        "base_severity": "Medium",
        "tactics": ["PrivilegeEscalation", "LateralMovement"],
        "techniques": ["T1078.002"],
        "function": "detect_cyberark_anomaly",
    },
    "DET-007": {
        "name": "Stale or Orphaned Privileged Account",
        "base_severity": "Low",
        "tactics": ["InitialAccess"],
        "techniques": ["T1078"],
        "function": "detect_stale_privileged",
    },
}


# --- Shared helpers -------------------------------------------------------------

def parse_ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def is_off_hours(when: datetime) -> bool:
    local = when + LOCAL_UTC_OFFSET
    return not (BUSINESS_HOURS[0] <= local.hour < BUSINESS_HOURS[1])


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * radius * math.asin(math.sqrt(a))


def load_data() -> dict:
    data = {}
    for key, filename in [("signin", "sample_signin_logs.json"),
                          ("audit", "sample_audit_logs.json"),
                          ("cyberark", "sample_cyberark_epv.json"),
                          ("identities", "identities.json"),
                          ("assets", "assets.json")]:
        with open(DATA_DIR / filename, encoding="utf-8") as fh:
            data[key] = json.load(fh)
    data["identity_by_upn"] = {i["upn"]: i for i in data["identities"]}
    data["asset_by_name"] = {a["display_name"]: a for a in data["assets"]}
    return data


def apply_modifiers(base_severity: str, *, privileged: bool, off_hours: bool,
                    high_risk: bool, escalation: bool,
                    escalation_reason: str = "") -> tuple[int, str, list[str]]:
    """Explainable severity scoring: base + context, capped at Critical."""
    score = SEV_NUM[base_severity]
    modifiers = []
    if privileged:
        score += 1
        modifiers.append("privileged identity involved (+1)")
    if off_hours:
        score += 1
        modifiers.append("activity outside business hours (+1)")
    if high_risk:
        score += 1
        modifiers.append("high-risk sign-in in evidence (+1)")
    if escalation:
        score += 1
        modifiers.append(f"detection escalation: {escalation_reason} (+1)")
    score = min(score, 4)
    return score, NUM_SEV[score], modifiers


def _group_by_user(events: list[dict], key: str) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for event in events:
        grouped.setdefault(event[key], []).append(event)
    for evs in grouped.values():
        evs.sort(key=lambda e: e["TimeGenerated"])
    return grouped


# --- Detections -----------------------------------------------------------------

def detect_mfa_fatigue(data: dict, tuned: bool) -> list[dict]:
    """DET-001: >=5 denied/timed-out MFA prompts for one user inside a rolling
    10-minute window; escalates if an approved MFA sign-in follows within 30 min."""
    findings = []
    denials = [e for e in data["signin"] if e["MfaResult"] in ("denied", "timeout")]
    for user, events in sorted(_group_by_user(denials, "UserPrincipalName").items()):
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
        approvals = [
            e for e in data["signin"]
            if e["UserPrincipalName"] == user and e["ResultType"] == 0
            and e["MfaResult"] == "approved"
            and burst_end < parse_ts(e["TimeGenerated"]) <= burst_end + MFA_APPROVAL_FOLLOWUP
        ]
        findings.append({
            "detection_id": "DET-001",
            "user": user,
            "evidence": burst + approvals,
            "escalation": bool(approvals),
            "escalation_reason": "user approved MFA immediately after the prompt burst",
        })
    return findings


def detect_impossible_travel(data: dict, tuned: bool) -> list[dict]:
    """DET-002: consecutive successful sign-ins whose implied travel speed
    exceeds 900 km/h. v1.1.0 tuning suppresses pairs where both IPs are inside
    the corporate VPN egress range."""
    successes = [e for e in data["signin"] if e["ResultType"] == 0]
    grouped = _group_by_user(successes, "UserPrincipalName")
    violations: dict[tuple[str, str], list[dict]] = {}
    for user, events in sorted(grouped.items()):
        for prev, curr in zip(events, events[1:]):
            km = haversine_km(prev["Latitude"], prev["Longitude"],
                              curr["Latitude"], curr["Longitude"])
            seconds = (parse_ts(curr["TimeGenerated"]) - parse_ts(prev["TimeGenerated"])).total_seconds()
            hours = max(seconds, 60) / 3600.0
            if km / hours <= TRAVEL_SPEED_KMH:
                continue
            if tuned and prev["IPAddress"].startswith(VPN_EGRESS_PREFIX) \
                    and curr["IPAddress"].startswith(VPN_EGRESS_PREFIX):
                continue
            key = (user, curr["TimeGenerated"][:10])  # one alert per user per UTC day
            violations.setdefault(key, [])
            for event in (prev, curr):
                if event not in violations[key]:
                    violations[key].append(event)
    return [
        {"detection_id": "DET-002", "user": user, "evidence": evidence,
         "escalation": False, "escalation_reason": ""}
        for (user, _day), evidence in sorted(violations.items())
    ]


def detect_ca_policy_change(data: dict, tuned: bool) -> list[dict]:
    """DET-003: every Conditional Access policy modification is review-worthy;
    escalates when the actor holds no policy-management role."""
    findings = []
    for event in data["audit"]:
        if event["OperationName"] not in CA_OPERATIONS:
            continue
        actor = data["identity_by_upn"].get(event["ActorUPN"], {})
        authorised = bool(set(actor.get("entra_roles", [])) & CA_AUTHORISED_ROLES)
        findings.append({
            "detection_id": "DET-003",
            "user": event["ActorUPN"],
            "evidence": [event],
            "escalation": not authorised,
            "escalation_reason": "actor holds no Conditional Access management role",
        })
    return findings


def detect_sp_credential_added(data: dict, tuned: bool) -> list[dict]:
    """DET-004: any credential added to a service principal; escalates when the
    target principal is classified high-privilege in the asset inventory."""
    findings = []
    for event in data["audit"]:
        if event["OperationName"] != "Add service principal credentials":
            continue
        asset = data["asset_by_name"].get(event["TargetName"], {})
        findings.append({
            "detection_id": "DET-004",
            "user": event["ActorUPN"],
            "target": event["TargetName"],
            "evidence": [event],
            "escalation": asset.get("privilege_tier") == "high",
            "escalation_reason": "target service principal is classified high-privilege",
        })
    return findings


def detect_priv_role_addition(data: dict, tuned: bool) -> list[dict]:
    """DET-005: membership added to a privileged directory role or privileged
    group; escalates on self-elevation."""
    findings = []
    for event in data["audit"]:
        if event["OperationName"] not in ("Add member to role", "Add member to group"):
            continue
        granted = {p["newValue"] for p in event["ModifiedProperties"]
                   if p["name"] in ("Role.DisplayName", "Group.DisplayName")}
        if not (granted & PRIVILEGED_ROLES or granted & PRIVILEGED_GROUPS):
            continue
        findings.append({
            "detection_id": "DET-005",
            "user": event["ActorUPN"],
            "target": event["TargetName"],
            "evidence": [event],
            "escalation": event["ActorUPN"] == event["TargetName"],
            "escalation_reason": "actor granted the privilege to their own account",
        })
    return findings


def detect_cyberark_anomaly(data: dict, tuned: bool) -> list[dict]:
    """DET-006: >=4 no-ticket privileged checkouts within 60 minutes, or any
    no-ticket checkout between 00:00 and 05:00 local; escalates on the
    domain-admins safe."""
    checkouts = [e for e in data["cyberark"]
                 if e["EventType"] == "PasswordCheckout" and not e["TicketId"]]
    findings = []
    for user, events in sorted(_group_by_user(checkouts, "Username").items()):
        times = [parse_ts(e["TimeGenerated"]) for e in events]
        flagged: set[int] = set()
        left = 0
        for right in range(len(events)):
            while times[right] - times[left] > CYBERARK_BURST_WINDOW:
                left += 1
            if right - left + 1 >= CYBERARK_BURST_THRESHOLD:
                flagged.update(range(left, right + 1))
        for idx, when in enumerate(times):
            local_hour = (when + LOCAL_UTC_OFFSET).hour
            if CYBERARK_QUIET_HOURS[0] <= local_hour <= CYBERARK_QUIET_HOURS[1] - 1:
                flagged.add(idx)
        if not flagged:
            continue
        evidence = [events[i] for i in sorted(flagged)]
        findings.append({
            "detection_id": "DET-006",
            "user": user,
            "evidence": evidence,
            "escalation": any(e["SafeName"] == "AZ-PROD-DomainAdmins" for e in evidence),
            "escalation_reason": "checkout targeted the production domain-admins safe",
        })
    return findings


def detect_stale_privileged(data: dict, tuned: bool) -> list[dict]:
    """DET-007 (posture): enabled privileged accounts with no sign-in for 60+
    days, or never used; orphaned privileged service accounts escalate."""
    findings = []
    cutoff = SIM_NOW - timedelta(days=STALE_DAYS)
    for ident in data["identities"]:
        if not (ident["is_privileged"] and ident["account_enabled"]):
            continue
        last = parse_ts(ident["last_signin"]) if ident["last_signin"] else None
        if last is not None and last >= cutoff:
            continue
        orphaned = ident["is_service_account"] and not ident["manager_upn"]
        findings.append({
            "detection_id": "DET-007",
            "user": ident["upn"],
            "evidence": [ident],
            "escalation": orphaned,
            "escalation_reason": "orphaned privileged service account (no owner)",
        })
    return findings


# --- Alert assembly ---------------------------------------------------------------

def _evidence_window(evidence: list[dict]) -> tuple[str, str]:
    stamps = sorted(e["TimeGenerated"] for e in evidence if "TimeGenerated" in e)
    if stamps:
        return stamps[0], stamps[-1]
    return SIM_NOW.strftime("%Y-%m-%dT%H:%M:%SZ"), SIM_NOW.strftime("%Y-%m-%dT%H:%M:%SZ")


def _finalise(findings: list[dict], data: dict) -> list[dict]:
    alerts = []
    counters: dict[str, int] = {}
    findings.sort(key=lambda f: (f["detection_id"], _evidence_window(f["evidence"])[0]))
    for finding in findings:
        det_id = finding["detection_id"]
        meta = CATALOGUE[det_id]
        counters[det_id] = counters.get(det_id, 0) + 1
        window_start, window_end = _evidence_window(finding["evidence"])
        evidence = finding["evidence"]

        involved = {finding["user"], finding.get("target", "")}
        privileged = any(data["identity_by_upn"].get(u, {}).get("is_privileged")
                         for u in involved if u)
        off_hours = any(is_off_hours(parse_ts(e["TimeGenerated"]))
                        for e in evidence if "TimeGenerated" in e)
        high_risk = any(e.get("RiskLevelDuringSignIn") == "high" for e in evidence)
        score, severity, modifiers = apply_modifiers(
            meta["base_severity"], privileged=privileged, off_hours=off_hours,
            high_risk=high_risk, escalation=finding["escalation"],
            escalation_reason=finding["escalation_reason"])

        ips = sorted({ip for e in evidence
                      for ip in [e.get("IPAddress"), e.get("ActorIPAddress"), e.get("SourceIP")]
                      if ip})
        scenario_tags = sorted({e.get("SimScenario", "stale_privileged") for e in evidence})
        alerts.append({
            "alert_id": f"AL-{det_id.split('-')[1]}-{counters[det_id]:04d}",
            "detection_id": det_id,
            "detection_name": meta["name"],
            "mitre_tactics": meta["tactics"],
            "mitre_techniques": meta["techniques"],
            "user": finding["user"],
            "target": finding.get("target"),
            "ips": ips,
            "window_start": window_start,
            "window_end": window_end,
            "evidence_count": len(evidence),
            "evidence": evidence,
            "base_severity": meta["base_severity"],
            "severity": severity,
            "severity_score": score,
            "severity_modifiers": modifiers,
            "scenario_tags": scenario_tags,
        })
    alerts.sort(key=lambda a: (a["window_start"], a["alert_id"]))
    return alerts


def run_all(tuned: bool = False) -> list[dict]:
    data = load_data()
    findings = []
    for det_id in sorted(CATALOGUE):
        func = globals()[CATALOGUE[det_id]["function"]]
        findings.extend(func(data, tuned))
    return _finalise(findings, data)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the seven local detections.")
    parser.add_argument("--tuned", action="store_true",
                        help="apply the v1.1.0 tuning exclusions (VPN egress range)")
    args = parser.parse_args()

    alerts = run_all(tuned=args.tuned)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUTPUT_DIR / ("alerts_tuned.json" if args.tuned else "alerts.json")
    out_path.write_text(json.dumps(alerts, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out_path.relative_to(ROOT)} ({len(alerts)} alerts)")
    for alert in alerts:
        print(f"  {alert['alert_id']}  {alert['severity']:<8}  "
              f"{alert['detection_name']}  ->  {alert['user']}")


if __name__ == "__main__":
    main()
