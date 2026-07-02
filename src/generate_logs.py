"""Generate deterministic synthetic identity telemetry for the lab.

Produces seven days of Microsoft Entra ID sign-in logs, Entra ID audit logs and
CyberArk EPV events (plus an identity/asset inventory) containing seven embedded
attack scenarios amongst realistic benign noise. Output is byte-identical on every
run (fixed seed, fixed simulation clock) so detections and tests are reproducible.

All identities, IP addresses and events are fictional. IPs use documentation
ranges (203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24).
"""
from __future__ import annotations

import json
import random
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"

SEED = 42
SIM_NOW = datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)
LOCAL_UTC_OFFSET = timedelta(hours=10)  # Australia/Sydney (fixed offset for the sim)

CITIES = {
    "Sydney": ("AU", -33.8688, 151.2093),
    "Melbourne": ("AU", -37.8136, 144.9631),
    "Brisbane": ("AU", -27.4698, 153.0251),
    "Frankfurt": ("DE", 50.1109, 8.6821),
    "Amsterdam": ("NL", 52.3676, 4.9041),
    "Singapore": ("SG", 1.3521, 103.8198),
}

APPS = ["Microsoft 365", "Azure Portal", "Microsoft Teams", "Outlook Web", "SharePoint Online"]
DEVICE_OS = ["Windows 11", "macOS 14", "iOS 17"]
BROWSERS = ["Edge 126", "Chrome 126", "Safari 17"]

# --- Identity inventory -------------------------------------------------------

IDENTITIES = [
    {"upn": "amelia.chen@contoso.com", "user_id": "u-1001", "display_name": "Amelia Chen",
     "department": "IT Security", "title": "Identity Engineer",
     "entra_roles": ["Conditional Access Administrator"], "groups": ["sg-identity-team"],
     "is_privileged": True, "is_service_account": False, "mfa_registered": True,
     "account_enabled": True, "manager_upn": "priya.sharma@contoso.com",
     "created_date": "2023-02-14", "last_signin": "2026-06-30T06:45:00Z",
     "usual_city": "Sydney", "usual_ip": "203.0.113.21"},
    {"upn": "daniel.wright@contoso.com", "user_id": "u-1002", "display_name": "Daniel Wright",
     "department": "Finance", "title": "Financial Analyst",
     "entra_roles": [], "groups": ["sg-finance"],
     "is_privileged": False, "is_service_account": False, "mfa_registered": True,
     "account_enabled": True, "manager_upn": "grace.kim@contoso.com",
     "created_date": "2022-08-01", "last_signin": "2026-06-30T05:10:00Z",
     "usual_city": "Sydney", "usual_ip": "203.0.113.34"},
    {"upn": "priya.sharma@contoso.com", "user_id": "u-1003", "display_name": "Priya Sharma",
     "department": "IT Operations", "title": "Senior Cloud Administrator",
     "entra_roles": ["Global Administrator"], "groups": ["sg-cloud-ops"],
     "is_privileged": True, "is_service_account": False, "mfa_registered": True,
     "account_enabled": True, "manager_upn": None,
     "created_date": "2021-05-20", "last_signin": "2026-06-30T07:02:00Z",
     "usual_city": "Sydney", "usual_ip": "203.0.113.40"},
    {"upn": "jordan.lee@contoso.com", "user_id": "u-1004", "display_name": "Jordan Lee",
     "department": "IT Support", "title": "Service Desk Analyst",
     "entra_roles": ["Helpdesk Administrator"], "groups": ["sg-service-desk"],
     "is_privileged": True, "is_service_account": False, "mfa_registered": True,
     "account_enabled": True, "manager_upn": "priya.sharma@contoso.com",
     "created_date": "2024-01-09", "last_signin": "2026-06-30T06:20:00Z",
     "usual_city": "Sydney", "usual_ip": "203.0.113.55"},
    {"upn": "mark.taylor@contoso.com", "user_id": "u-1005", "display_name": "Mark Taylor",
     "department": "Data Platform", "title": "Database Administrator",
     "entra_roles": [], "groups": ["sg-prod-dba"],
     "is_privileged": True, "is_service_account": False, "mfa_registered": True,
     "account_enabled": True, "manager_upn": "priya.sharma@contoso.com",
     "created_date": "2022-03-11", "last_signin": "2026-06-30T05:55:00Z",
     "usual_city": "Sydney", "usual_ip": "203.0.113.60"},
    {"upn": "sofia.russo@contoso.com", "user_id": "u-1006", "display_name": "Sofia Russo",
     "department": "Sales", "title": "Sales Manager",
     "entra_roles": [], "groups": ["sg-sales"],
     "is_privileged": False, "is_service_account": False, "mfa_registered": True,
     "account_enabled": True, "manager_upn": "grace.kim@contoso.com",
     "created_date": "2023-06-30", "last_signin": "2026-06-30T00:15:00Z",
     "usual_city": "Melbourne", "usual_ip": "203.0.113.71"},
    {"upn": "liam.oconnor@contoso.com", "user_id": "u-1007", "display_name": "Liam O'Connor",
     "department": "Network Engineering", "title": "Network Engineer",
     "entra_roles": [], "groups": ["sg-network"],
     "is_privileged": False, "is_service_account": False, "mfa_registered": True,
     "account_enabled": True, "manager_upn": "priya.sharma@contoso.com",
     "created_date": "2022-11-02", "last_signin": "2026-06-30T06:30:00Z",
     "usual_city": "Brisbane", "usual_ip": "203.0.113.82"},
    {"upn": "grace.kim@contoso.com", "user_id": "u-1008", "display_name": "Grace Kim",
     "department": "Human Resources", "title": "HR Business Partner",
     "entra_roles": [], "groups": ["sg-hr"],
     "is_privileged": False, "is_service_account": False, "mfa_registered": True,
     "account_enabled": True, "manager_upn": None,
     "created_date": "2021-09-15", "last_signin": "2026-06-30T04:50:00Z",
     "usual_city": "Sydney", "usual_ip": "203.0.113.90"},
    {"upn": "noah.patel@contoso.com", "user_id": "u-1009", "display_name": "Noah Patel",
     "department": "Engineering", "title": "Software Engineer",
     "entra_roles": [], "groups": ["sg-engineering"],
     "is_privileged": False, "is_service_account": False, "mfa_registered": True,
     "account_enabled": True, "manager_upn": "priya.sharma@contoso.com",
     "created_date": "2023-10-23", "last_signin": "2026-06-30T06:58:00Z",
     "usual_city": "Melbourne", "usual_ip": "203.0.113.95"},
    # Stale / orphaned privileged accounts (no live traffic in the log window).
    {"upn": "old.admin@contoso.com", "user_id": "u-1010", "display_name": "Legacy Administrator",
     "department": "IT Operations", "title": "Systems Administrator (legacy)",
     "entra_roles": ["Exchange Administrator"], "groups": ["sg-cloud-ops"],
     "is_privileged": True, "is_service_account": False, "mfa_registered": False,
     "account_enabled": True, "manager_upn": "priya.sharma@contoso.com",
     "created_date": "2019-04-02", "last_signin": "2026-03-02T04:11:00Z",
     "usual_city": "Sydney", "usual_ip": "203.0.113.11"},
    {"upn": "karen.mills@contoso.com", "user_id": "u-1011", "display_name": "Karen Mills",
     "department": "IT Security", "title": "Contractor - Identity Project",
     "entra_roles": ["User Administrator"], "groups": ["sg-identity-team"],
     "is_privileged": True, "is_service_account": False, "mfa_registered": False,
     "account_enabled": True, "manager_upn": "amelia.chen@contoso.com",
     "created_date": "2025-12-10", "last_signin": None,
     "usual_city": "Sydney", "usual_ip": "203.0.113.12"},
    {"upn": "svc-backup-legacy@contoso.com", "user_id": "u-1012", "display_name": "svc-backup-legacy",
     "department": "IT Operations", "title": "Service Account - Legacy Backup",
     "entra_roles": [], "groups": ["sg-prod-domain-admins"],
     "is_privileged": True, "is_service_account": True, "mfa_registered": False,
     "account_enabled": True, "manager_upn": None,
     "created_date": "2020-07-19", "last_signin": "2026-01-15T13:40:00Z",
     "usual_city": "Sydney", "usual_ip": "203.0.113.13"},
]

ASSETS = [
    {"sp_id": "sp-9001", "display_name": "sp-automation-graph", "privilege_tier": "high",
     "owner_upn": "priya.sharma@contoso.com",
     "purpose": "Graph API automation - holds Directory.ReadWrite.All"},
    {"sp_id": "sp-9002", "display_name": "sp-billing-reader", "privilege_tier": "low",
     "owner_upn": "grace.kim@contoso.com", "purpose": "Read-only billing exports"},
    {"sp_id": "sp-9003", "display_name": "sp-devops-deploy", "privilege_tier": "medium",
     "owner_upn": "noah.patel@contoso.com", "purpose": "Azure DevOps deployment principal"},
]

# Users that produce day-to-day benign traffic (stale accounts deliberately absent).
BENIGN_TRAFFIC_UPNS = [i["upn"] for i in IDENTITIES if i["user_id"] <= "u-1009"]

# Local dates on which a scenario replaces a user's normal activity.
QUIET_DAYS = {
    ("daniel.wright@contoso.com", date(2026, 6, 28)),
    ("sofia.russo@contoso.com", date(2026, 6, 30)),
}

CYBERARK_BENIGN_USERS = ["mark.taylor@contoso.com", "priya.sharma@contoso.com",
                         "liam.oconnor@contoso.com"]
CYBERARK_SAFES = {
    "AZ-PROD-SQL": ["svc-sql-prod", "sql-sa-prod01"],
    "AZ-DEV-General": ["dev-local-admin", "svc-dev-deploy"],
    "AZ-PROD-NetworkDevices": ["net-ro-audit", "net-rw-core01"],
}


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def det_uuid(rng: random.Random) -> str:
    return str(uuid.UUID(int=rng.getrandbits(128)))


def identity(upn: str) -> dict:
    return next(i for i in IDENTITIES if i["upn"] == upn)


def signin_event(rng: random.Random, when: datetime, upn: str, city: str, ip: str, *,
                 result_type: int = 0, mfa_result: str | None = None,
                 auth_requirement: str = "singleFactorAuthentication",
                 risk: str = "none", ca_status: str = "notApplied",
                 scenario: str = "benign", app: str | None = None,
                 description: str = "Success") -> dict:
    country, lat, lon = CITIES[city]
    return {
        "TimeGenerated": iso(when),
        "UserPrincipalName": upn,
        "UserId": identity(upn)["user_id"],
        "AppDisplayName": app or rng.choice(APPS),
        "IPAddress": ip,
        "City": city,
        "Country": country,
        "Latitude": lat,
        "Longitude": lon,
        "DeviceOS": rng.choice(DEVICE_OS),
        "DeviceBrowser": rng.choice(BROWSERS),
        "AuthenticationRequirement": auth_requirement,
        "MfaResult": mfa_result,
        "ResultType": result_type,
        "ResultDescription": description,
        "RiskLevelDuringSignIn": risk,
        "ConditionalAccessStatus": ca_status,
        "CorrelationId": det_uuid(rng),
        "SimScenario": scenario,
    }


def audit_event(rng: random.Random, when: datetime, operation: str, category: str,
                actor_upn: str, actor_ip: str, target_type: str, target_name: str,
                target_id: str, modified: list, scenario: str = "benign") -> dict:
    return {
        "TimeGenerated": iso(when),
        "OperationName": operation,
        "Category": category,
        "ActorUPN": actor_upn,
        "ActorIPAddress": actor_ip,
        "TargetType": target_type,
        "TargetName": target_name,
        "TargetId": target_id,
        "ModifiedProperties": modified,
        "Result": "success",
        "CorrelationId": det_uuid(rng),
        "SimScenario": scenario,
    }


def cyberark_event(rng: random.Random, when: datetime, event_type: str, upn: str,
                   safe: str, account: str, target: str, source_ip: str,
                   ticket: str | None, reason: str, scenario: str = "benign") -> dict:
    return {
        "TimeGenerated": iso(when),
        "EventType": event_type,
        "Username": upn,
        "SafeName": safe,
        "AccountName": account,
        "TargetSystem": target,
        "SourceIP": source_ip,
        "TicketId": ticket,
        "Reason": reason,
        "SimScenario": scenario,
    }


# --- Benign background noise --------------------------------------------------

def benign_signins(rng: random.Random) -> list[dict]:
    events = []
    for day in range(24, 31):  # local dates 2026-06-24 .. 2026-06-30
        local_date = date(2026, 6, day)
        local_midnight = datetime(2026, 6, day, tzinfo=timezone.utc)  # treated as local
        for upn in BENIGN_TRAFFIC_UPNS:
            if (upn, local_date) in QUIET_DAYS:
                continue
            ident = identity(upn)
            city, ip = ident["usual_city"], ident["usual_ip"]
            mfa_blip_used = False
            for _ in range(rng.randint(4, 7)):
                local_time = local_midnight + timedelta(hours=rng.uniform(8.5, 17.5))
                when = local_time - LOCAL_UTC_OFFSET
                roll = rng.random()
                if roll < 0.04:  # occasional wrong password
                    events.append(signin_event(
                        rng, when, upn, city, ip, result_type=50126,
                        description="Invalid username or password",
                        risk="none", scenario="benign"))
                elif roll < 0.07 and not mfa_blip_used:
                    # a single missed MFA prompt followed by an approval - never a burst
                    mfa_blip_used = True
                    events.append(signin_event(
                        rng, when, upn, city, ip, result_type=500121,
                        mfa_result="timeout",
                        auth_requirement="multiFactorAuthentication",
                        ca_status="failure",
                        description="MFA denied; user did not respond to the request",
                        scenario="benign"))
                    events.append(signin_event(
                        rng, when + timedelta(minutes=rng.randint(2, 4)), upn, city, ip,
                        mfa_result="approved",
                        auth_requirement="multiFactorAuthentication",
                        ca_status="success", scenario="benign"))
                elif roll < 0.50:
                    events.append(signin_event(
                        rng, when, upn, city, ip, mfa_result="approved",
                        auth_requirement="multiFactorAuthentication",
                        ca_status="success",
                        risk="low" if rng.random() < 0.06 else "none",
                        scenario="benign"))
                else:
                    events.append(signin_event(
                        rng, when, upn, city, ip,
                        risk="low" if rng.random() < 0.06 else "none",
                        scenario="benign"))
    return events


def benign_audit(rng: random.Random) -> list[dict]:
    events = []
    targets = [u for u in BENIGN_TRAFFIC_UPNS if u != "jordan.lee@contoso.com"]
    for day in range(24, 31):
        local_midnight = datetime(2026, 6, day, tzinfo=timezone.utc)
        for n in range(2):
            when = local_midnight + timedelta(hours=rng.uniform(9, 17)) - LOCAL_UTC_OFFSET
            actor = "priya.sharma@contoso.com" if n == 0 else "jordan.lee@contoso.com"
            actor_ip = identity(actor)["usual_ip"]
            target = rng.choice(targets)
            kind = rng.choice(["group", "profile", "reset"])
            if kind == "group":
                group = rng.choice(["sg-social-club", "sg-project-phoenix"])
                events.append(audit_event(
                    rng, when, "Add member to group", "GroupManagement", actor, actor_ip,
                    "User", target, identity(target)["user_id"],
                    [{"name": "Group.DisplayName", "oldValue": None, "newValue": group}]))
            elif kind == "profile":
                events.append(audit_event(
                    rng, when, "Update user", "UserManagement", actor, actor_ip,
                    "User", target, identity(target)["user_id"],
                    [{"name": "TelephoneNumber", "oldValue": "redacted", "newValue": "redacted"}]))
            else:
                events.append(audit_event(
                    rng, when, "Reset password (by admin)", "UserManagement", actor, actor_ip,
                    "User", target, identity(target)["user_id"],
                    [{"name": "Password", "oldValue": None, "newValue": None}]))
    return events


def benign_cyberark(rng: random.Random) -> list[dict]:
    events = []
    safes = list(CYBERARK_SAFES)
    for day in range(24, 31):
        local_midnight = datetime(2026, 6, day, tzinfo=timezone.utc)
        for upn in CYBERARK_BENIGN_USERS:
            ip = identity(upn)["usual_ip"]
            for _ in range(rng.randint(2, 3)):
                safe = rng.choice(safes)
                account = rng.choice(CYBERARK_SAFES[safe])
                out_at = local_midnight + timedelta(hours=rng.uniform(9, 16)) - LOCAL_UTC_OFFSET
                ticket = f"CHG{rng.randint(100000, 999999)}"
                reason = rng.choice(["scheduled maintenance", "patch deployment",
                                     "performance investigation", "backup verification"])
                target = f"{account}.prod.contoso.local"
                events.append(cyberark_event(rng, out_at, "PasswordCheckout", upn, safe,
                                             account, target, ip, ticket, reason))
                events.append(cyberark_event(rng, out_at + timedelta(minutes=rng.randint(30, 70)),
                                             "PasswordCheckin", upn, safe, account, target,
                                             ip, ticket, reason))
    return events


# --- Attack scenarios -----------------------------------------------------------

def scenario_mfa_fatigue(rng: random.Random) -> list[dict]:
    """DET-001. 2026-06-29 21:15 local: push-bombing burst against Amelia Chen
    from an unfamiliar Amsterdam IP; she finally approves 16 minutes in."""
    upn = "amelia.chen@contoso.com"
    attacker_ip = "192.0.2.199"
    base = datetime(2026, 6, 29, 11, 15, 0, tzinfo=timezone.utc)  # 21:15 AEST
    offsets = [0, 67, 131, 202, 275, 349, 412]
    results = ["denied", "denied", "timeout", "denied", "denied", "timeout", "denied"]
    events = [
        signin_event(rng, base + timedelta(seconds=s), upn, "Amsterdam", attacker_ip,
                     result_type=500121, mfa_result=m,
                     auth_requirement="multiFactorAuthentication", ca_status="failure",
                     risk="medium", app="Azure Portal",
                     description="MFA denied; user declined or did not respond",
                     scenario="mfa_fatigue")
        for s, m in zip(offsets, results)
    ]
    events.append(signin_event(
        rng, base + timedelta(seconds=1000), upn, "Amsterdam", attacker_ip,
        mfa_result="approved", auth_requirement="multiFactorAuthentication",
        ca_status="success", risk="high", app="Azure Portal",
        description="Success", scenario="mfa_fatigue"))
    return events


def scenario_impossible_travel(rng: random.Random) -> list[dict]:
    """DET-002 (true positive). Daniel Wright signs in from Sydney, then a
    high-risk single-factor sign-in from Frankfurt 65 minutes later."""
    upn = "daniel.wright@contoso.com"
    return [
        signin_event(rng, datetime(2026, 6, 28, 0, 5, 0, tzinfo=timezone.utc),
                     upn, "Sydney", "203.0.113.34", mfa_result="approved",
                     auth_requirement="multiFactorAuthentication", ca_status="success",
                     scenario="impossible_travel"),
        signin_event(rng, datetime(2026, 6, 28, 1, 10, 0, tzinfo=timezone.utc),
                     upn, "Frankfurt", "192.0.2.44", risk="high",
                     ca_status="notApplied", app="Outlook Web",
                     scenario="impossible_travel"),
    ]


def scenario_vpn_travel_fp(rng: random.Random) -> list[dict]:
    """DET-002 (deliberate false positive). Sofia Russo works through the
    corporate VPN; egress nodes in Sydney then Singapore within 35 minutes.
    Both IPs sit in the documented VPN range 198.51.100.0/24 - the v1.1.0
    tuning exclusion suppresses this pair."""
    upn = "sofia.russo@contoso.com"
    return [
        signin_event(rng, datetime(2026, 6, 29, 23, 40, 0, tzinfo=timezone.utc),
                     upn, "Sydney", "198.51.100.10", mfa_result="approved",
                     auth_requirement="multiFactorAuthentication", ca_status="success",
                     scenario="vpn_travel_fp"),
        signin_event(rng, datetime(2026, 6, 30, 0, 15, 0, tzinfo=timezone.utc),
                     upn, "Singapore", "198.51.100.77", mfa_result="approved",
                     auth_requirement="multiFactorAuthentication", ca_status="success",
                     scenario="vpn_travel_fp"),
    ]


def scenario_audit_chain(rng: random.Random) -> list[dict]:
    """DET-004 / DET-005 / DET-003. A compromised service-desk account
    (Jordan Lee) establishes persistence on a high-privilege service principal,
    elevates itself to Global Administrator, then weakens Conditional Access -
    all within 30 minutes, late at night, from the same attacker IP."""
    actor = "jordan.lee@contoso.com"
    attacker_ip = "192.0.2.199"
    return [
        audit_event(rng, datetime(2026, 6, 29, 13, 5, 0, tzinfo=timezone.utc),
                    "Add service principal credentials", "ApplicationManagement",
                    actor, attacker_ip, "ServicePrincipal", "sp-automation-graph", "sp-9001",
                    [{"name": "KeyDescription", "oldValue": None,
                      "newValue": "client secret added (expires 2028-06-29)"}],
                    scenario="sp_credential_added"),
        audit_event(rng, datetime(2026, 6, 29, 13, 20, 0, tzinfo=timezone.utc),
                    "Add member to role", "RoleManagement",
                    actor, attacker_ip, "User", actor, "u-1004",
                    [{"name": "Role.DisplayName", "oldValue": None,
                      "newValue": "Global Administrator"}],
                    scenario="priv_group_add"),
        audit_event(rng, datetime(2026, 6, 29, 13, 35, 0, tzinfo=timezone.utc),
                    "Update conditional access policy", "Policy",
                    actor, attacker_ip, "Policy", "CA004 - Require MFA for admin roles", "pol-ca004",
                    [{"name": "PolicyState", "oldValue": "enabled",
                      "newValue": "disabled"}],
                    scenario="ca_policy_change"),
    ]


def scenario_cyberark_anomaly(rng: random.Random) -> list[dict]:
    """DET-006. Mark Taylor checks out five privileged credentials from the
    domain-admins safe at 02:00 local with no change ticket."""
    upn = "mark.taylor@contoso.com"
    base = datetime(2026, 6, 28, 16, 5, 0, tzinfo=timezone.utc)  # 02:05 AEST 29 June
    minutes = [0, 9, 17, 28, 40]
    accounts = ["da-admin01", "da-admin02", "da-admin03", "svc-sql-prod", "da-admin01"]
    return [
        cyberark_event(rng, base + timedelta(minutes=m), "PasswordCheckout", upn,
                       "AZ-PROD-DomainAdmins", acct, f"{acct}.prod.contoso.local",
                       "203.0.113.60", None, "emergency maintenance - approved verbally",
                       scenario="cyberark_anomaly")
        for m, acct in zip(minutes, accounts)
    ]


# --- Output ---------------------------------------------------------------------

def write_json(path: Path, records: list) -> None:
    """One record per line inside a valid JSON array - diff-friendly."""
    path.parent.mkdir(parents=True, exist_ok=True)
    body = ",\n".join(json.dumps(r, separators=(", ", ": ")) for r in records)
    path.write_text("[\n" + body + "\n]\n", encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)} ({len(records)} records)")


def main() -> None:
    rng = random.Random(SEED)

    signins = benign_signins(rng)
    signins += scenario_mfa_fatigue(rng)
    signins += scenario_impossible_travel(rng)
    signins += scenario_vpn_travel_fp(rng)
    signins.sort(key=lambda e: e["TimeGenerated"])

    audits = benign_audit(rng) + scenario_audit_chain(rng)
    audits.sort(key=lambda e: e["TimeGenerated"])

    cyberark = benign_cyberark(rng) + scenario_cyberark_anomaly(rng)
    cyberark.sort(key=lambda e: e["TimeGenerated"])

    write_json(DATA_DIR / "sample_signin_logs.json", signins)
    write_json(DATA_DIR / "sample_audit_logs.json", audits)
    write_json(DATA_DIR / "sample_cyberark_epv.json", cyberark)
    write_json(DATA_DIR / "identities.json", IDENTITIES)
    write_json(DATA_DIR / "assets.json", ASSETS)


if __name__ == "__main__":
    main()
