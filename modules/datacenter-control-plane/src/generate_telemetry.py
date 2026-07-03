"""Generate deterministic synthetic telemetry for the Datacenter Control Plane
Attack Path Lab.

Produces one complete identity-to-control-plane attack chain amongst benign
noise, across five telemetry sources plus identity/asset inventories. All
identities, IPs and resources are fictional (documentation IP ranges,
contoso.com personas). Output is byte-identical on every run (fixed seed,
fixed simulation clock).

The chain (2026-06-30, UTC):
  09:00  risky sign-in for chris.walker from an unusual country
  09:02+ MFA fatigue burst (5 failed strong-auth), approval at 09:11
  09:25  PIM activation of Application Administrator (no linked ticket)
  09:40  credential added to high-privilege service principal sp-infra-deploy
  10:05  sp-infra-deploy granted Owner on rg-prod-dc-mgmt
  10:20  NSG rule opened: 3389 from 0.0.0.0/0 on nsg-prod-dc-mgmt
  10:20+ management endpoint of vm-dc-mgmt-01 exposed to the internet
  10:40  Defender-style alert on unusual traffic to the management port
"""
from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = MODULE_ROOT / "data"

SEED = 77
SIM_NOW = datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)
LOCAL_UTC_OFFSET = timedelta(hours=10)

IDENTITIES = [
    {"upn": "chris.walker@contoso.com", "user_id": "u-2001", "display_name": "Chris Walker",
     "department": "Cloud Operations", "title": "Cloud Operations Engineer",
     "is_privileged": True, "pim_eligible_roles": ["Application Administrator"],
     "azure_rbac": [{"role": "Contributor", "scope": "/subscriptions/sub-prod-dc"}],
     "usual_country": "AU", "usual_city": "Sydney", "usual_ip": "203.0.113.150",
     "account_enabled": True, "mfa_registered": True},
    {"upn": "dana.iyer@contoso.com", "user_id": "u-2002", "display_name": "Dana Iyer",
     "department": "Site Reliability", "title": "Site Reliability Engineer",
     "is_privileged": False, "pim_eligible_roles": [],
     "azure_rbac": [{"role": "Reader", "scope": "/subscriptions/sub-prod-dc"}],
     "usual_country": "AU", "usual_city": "Melbourne", "usual_ip": "203.0.113.151",
     "account_enabled": True, "mfa_registered": True},
    {"upn": "felix.nguyen@contoso.com", "user_id": "u-2003", "display_name": "Felix Nguyen",
     "department": "Network Engineering", "title": "Network Engineer",
     "is_privileged": True, "pim_eligible_roles": [],
     "azure_rbac": [{"role": "Network Contributor", "scope": "/subscriptions/sub-prod-dc"}],
     "usual_country": "AU", "usual_city": "Sydney", "usual_ip": "203.0.113.152",
     "account_enabled": True, "mfa_registered": True},
]

ASSETS = [
    {"asset_id": "sub-prod-dc", "type": "subscription",
     "name": "Production - Datacenter Operations", "criticality": "high",
     "owner_team": "Cloud Operations"},
    {"asset_id": "rg-prod-dc-mgmt", "type": "resource_group",
     "name": "rg-prod-dc-mgmt", "subscription": "sub-prod-dc", "criticality": "critical",
     "purpose": "Datacenter management tooling", "owner_team": "Cloud Operations"},
    {"asset_id": "vm-dc-mgmt-01", "type": "virtual_machine",
     "name": "vm-dc-mgmt-01", "resource_group": "rg-prod-dc-mgmt",
     "criticality": "critical", "purpose": "Management jumpbox",
     "public_ip": "203.0.113.200", "nsg": "nsg-prod-dc-mgmt",
     "management_ports": [3389]},
    {"asset_id": "vm-app-01", "type": "virtual_machine",
     "name": "vm-app-01", "resource_group": "rg-prod-app", "criticality": "medium",
     "purpose": "Application server", "public_ip": None, "nsg": "nsg-prod-app",
     "management_ports": [22]},
    {"asset_id": "nsg-prod-dc-mgmt", "type": "network_security_group",
     "name": "nsg-prod-dc-mgmt", "resource_group": "rg-prod-dc-mgmt",
     "criticality": "critical", "protects": ["vm-dc-mgmt-01"]},
    {"asset_id": "nsg-prod-app", "type": "network_security_group",
     "name": "nsg-prod-app", "resource_group": "rg-prod-app",
     "criticality": "medium", "protects": ["vm-app-01"]},
    {"asset_id": "sp-infra-deploy", "type": "service_principal",
     "name": "sp-infra-deploy", "privilege_tier": "high",
     "azure_rbac": [{"role": "Contributor", "scope": "/subscriptions/sub-prod-dc"}],
     "owner_upn": "chris.walker@contoso.com",
     "purpose": "Infrastructure deployment automation"},
    {"asset_id": "sp-monitoring-reader", "type": "service_principal",
     "name": "sp-monitoring-reader", "privilege_tier": "low",
     "azure_rbac": [{"role": "Monitoring Reader", "scope": "/subscriptions/sub-prod-dc"}],
     "owner_upn": "dana.iyer@contoso.com",
     "purpose": "Read-only monitoring exports"},
]

ATTACKER_IP = "192.0.2.77"
ATTACKER_CITY, ATTACKER_COUNTRY = "Riga", "LV"


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def det_uuid(rng: random.Random) -> str:
    return str(uuid.UUID(int=rng.getrandbits(128)))


def signin(rng, when, upn, city, country, ip, *, result_type=0, mfa_result=None,
           risk="none", scenario="benign") -> dict:
    return {"TimeGenerated": iso(when), "UserPrincipalName": upn,
            "AppDisplayName": rng.choice(["Azure Portal", "Microsoft 365", "Azure CLI"]),
            "IPAddress": ip, "City": city, "Country": country,
            "ResultType": result_type, "MfaResult": mfa_result,
            "RiskLevelDuringSignIn": risk, "CorrelationId": det_uuid(rng),
            "SimScenario": scenario}


def audit(rng, when, operation, actor, actor_ip, target, detail, scenario="benign") -> dict:
    return {"TimeGenerated": iso(when), "OperationName": operation,
            "ActorUPN": actor, "ActorIPAddress": actor_ip, "TargetName": target,
            "Detail": detail, "Result": "success",
            "CorrelationId": det_uuid(rng), "SimScenario": scenario}


def activity(rng, when, operation, caller, caller_ip, scope, properties, scenario="benign") -> dict:
    return {"TimeGenerated": iso(when), "OperationNameValue": operation,
            "Caller": caller, "CallerIpAddress": caller_ip, "Scope": scope,
            "Properties": properties, "ActivityStatusValue": "Success",
            "CorrelationId": det_uuid(rng), "SimScenario": scenario}


def nsg_event(rng, when, nsg, rule, port, source_prefix, access, actor, ticket,
              scenario="benign") -> dict:
    return {"TimeGenerated": iso(when), "NsgName": nsg, "RuleName": rule,
            "Direction": "Inbound", "Access": access, "Protocol": "TCP",
            "DestinationPortRange": str(port), "SourceAddressPrefix": source_prefix,
            "Actor": actor, "ChangeTicket": ticket,
            "CorrelationId": det_uuid(rng), "SimScenario": scenario}


def build() -> dict:
    rng = random.Random(SEED)
    day = datetime(2026, 6, 30, tzinfo=timezone.utc)

    # --- Benign background --------------------------------------------------
    signins, audits, activities, nsg_logs = [], [], [], []
    for offset in range(3, 0, -1):  # 2026-06-27 .. 2026-06-29 local workdays
        base = datetime(2026, 6, 30 - offset, tzinfo=timezone.utc)
        for ident in IDENTITIES:
            for _ in range(rng.randint(3, 5)):
                when = base + timedelta(hours=rng.uniform(8.5, 17.5)) - LOCAL_UTC_OFFSET
                signins.append(signin(
                    rng, when, ident["upn"], ident["usual_city"],
                    ident["usual_country"], ident["usual_ip"],
                    mfa_result="approved" if rng.random() < 0.5 else None,
                    risk="low" if rng.random() < 0.05 else "none"))

    # Benign morning sign-ins on attack day too.
    for ident in IDENTITIES:
        when = day + timedelta(hours=rng.uniform(8.5, 9.5)) - LOCAL_UTC_OFFSET
        signins.append(signin(rng, when, ident["upn"], ident["usual_city"],
                              ident["usual_country"], ident["usual_ip"],
                              mfa_result="approved"))

    # Benign audit: dana added to a normal project group; credential added to a
    # LOW-privilege service principal (must NOT alert - test expectation).
    audits.append(audit(rng, datetime(2026, 6, 29, 1, 10, tzinfo=timezone.utc),
                        "Add member to group", "felix.nguyen@contoso.com",
                        "203.0.113.152", "dana.iyer@contoso.com",
                        {"group": "sg-project-atlas"}))
    audits.append(audit(rng, datetime(2026, 6, 29, 2, 0, tzinfo=timezone.utc),
                        "Add service principal credentials", "dana.iyer@contoso.com",
                        "203.0.113.151", "sp-monitoring-reader",
                        {"key": "client secret rotated ahead of expiry",
                         "change_ticket": "CHG778201"}))

    # Benign activity: ticketed internal NSG change by the network engineer
    # (must NOT trigger the public-exposure detections - test expectation).
    activities.append(activity(rng, datetime(2026, 6, 29, 3, 30, tzinfo=timezone.utc),
                               "Microsoft.Network/networkSecurityGroups/securityRules/write",
                               "felix.nguyen@contoso.com", "203.0.113.152",
                               "/subscriptions/sub-prod-dc/resourceGroups/rg-prod-app",
                               {"rule": "allow-https-internal", "change_ticket": "CHG778190"}))
    nsg_logs.append(nsg_event(rng, datetime(2026, 6, 29, 3, 30, tzinfo=timezone.utc),
                              "nsg-prod-app", "allow-https-internal", 443,
                              "10.0.0.0/8", "Allow", "felix.nguyen@contoso.com",
                              "CHG778190"))
    activities.append(activity(rng, datetime(2026, 6, 28, 5, 0, tzinfo=timezone.utc),
                               "Microsoft.Resources/deployments/write",
                               "sp-infra-deploy", "203.0.113.150",
                               "/subscriptions/sub-prod-dc/resourceGroups/rg-prod-app",
                               {"deployment": "app-release-241", "change_ticket": "CHG778102"}))

    # --- The attack chain (all tagged, one actor) ----------------------------
    chain = "control_plane_chain"
    victim = "chris.walker@contoso.com"

    # Stage 1: risky sign-in from unusual country.
    signins.append(signin(rng, day + timedelta(hours=9), victim, ATTACKER_CITY,
                          ATTACKER_COUNTRY, ATTACKER_IP, risk="high",
                          scenario=chain))
    # Stage 2: MFA fatigue - five failed strong-auth events, then an approval.
    for minutes in (2, 3, 5, 7, 9):
        signins.append(signin(rng, day + timedelta(hours=9, minutes=minutes),
                              victim, ATTACKER_CITY, ATTACKER_COUNTRY, ATTACKER_IP,
                              result_type=500121, mfa_result="denied", risk="high",
                              scenario=chain))
    signins.append(signin(rng, day + timedelta(hours=9, minutes=11), victim,
                          ATTACKER_CITY, ATTACKER_COUNTRY, ATTACKER_IP,
                          mfa_result="approved", risk="high", scenario=chain))

    # Stage 3: PIM activation of a protected role, no linked change ticket.
    audits.append(audit(rng, day + timedelta(hours=9, minutes=25),
                        "Add member to role completed (PIM activation)",
                        victim, ATTACKER_IP, victim,
                        {"role": "Application Administrator", "change_ticket": None},
                        scenario=chain))
    # Stage 4: credential added to the HIGH-privilege service principal.
    audits.append(audit(rng, day + timedelta(hours=9, minutes=40),
                        "Add service principal credentials", victim, ATTACKER_IP,
                        "sp-infra-deploy",
                        {"key": "client secret added (expires 2028-06-30)",
                         "change_ticket": None},
                        scenario=chain))
    # Stage 5: role assignment write - the SP is granted Owner on the
    # datacenter-management resource group.
    activities.append(activity(rng, day + timedelta(hours=10, minutes=5),
                               "Microsoft.Authorization/roleAssignments/write",
                               victim, ATTACKER_IP,
                               "/subscriptions/sub-prod-dc/resourceGroups/rg-prod-dc-mgmt",
                               {"principal": "sp-infra-deploy", "role": "Owner",
                                "change_ticket": None},
                               scenario=chain))
    # Stage 6: NSG rule opened to the internet - by the SP, with its new secret.
    activities.append(activity(rng, day + timedelta(hours=10, minutes=20),
                               "Microsoft.Network/networkSecurityGroups/securityRules/write",
                               "sp-infra-deploy", ATTACKER_IP,
                               "/subscriptions/sub-prod-dc/resourceGroups/rg-prod-dc-mgmt",
                               {"rule": "allow-rdp-temp", "change_ticket": None},
                               scenario=chain))
    nsg_logs.append(nsg_event(rng, day + timedelta(hours=10, minutes=20),
                              "nsg-prod-dc-mgmt", "allow-rdp-temp", 3389,
                              "0.0.0.0/0", "Allow", "sp-infra-deploy", None,
                              scenario=chain))

    # Stage 8 input: a Defender-style alert fires on the exposed endpoint.
    defender = [
        {"TimeGenerated": iso(day + timedelta(hours=10, minutes=40)),
         "AlertName": "Traffic from unusual locations to a management port",
         "Product": "Microsoft Defender for Cloud", "Severity": "High",
         "Entities": ["vm-dc-mgmt-01", "203.0.113.200"],
         "Description": "Inbound RDP traffic from previously unseen source ranges "
                        "was detected shortly after the management port became "
                        "reachable from the internet.",
         "SimScenario": chain},
        {"TimeGenerated": iso(datetime(2026, 6, 28, 4, 15, tzinfo=timezone.utc)),
         "AlertName": "Antimalware signature update completed",
         "Product": "Microsoft Defender for Cloud", "Severity": "Informational",
         "Entities": ["vm-app-01"],
         "Description": "Routine platform hygiene event included as benign noise.",
         "SimScenario": "benign"},
    ]

    for records in (signins, audits, activities, nsg_logs, defender):
        records.sort(key=lambda e: e["TimeGenerated"])

    return {"entra_signin_logs": signins, "entra_audit_logs": audits,
            "azure_activity_logs": activities,
            "network_security_group_logs": nsg_logs,
            "defender_alerts": defender,
            "identity_inventory": IDENTITIES, "asset_inventory": ASSETS}


def write_json(path: Path, records) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = ",\n".join(json.dumps(r, separators=(", ", ": ")) for r in records)
    path.write_text("[\n" + body + "\n]\n", encoding="utf-8")
    print(f"wrote {path.relative_to(MODULE_ROOT.parents[1])} ({len(records)} records)")


def main() -> None:
    data = build()
    for name, records in data.items():
        write_json(DATA_DIR / f"{name}.json", records)


if __name__ == "__main__":
    main()
