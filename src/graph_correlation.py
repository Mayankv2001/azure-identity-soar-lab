"""Graph-powered correlation engine (V2.0).

DEPRECATED (V3.0): superseded by native KQL graph semantics in
v3-enterprise-native/graph/attack-path-make-graph.kql, which expresses the same
identity-to-infrastructure path using make-graph / graph-match inside Log
Analytics (no external compute). This module is retained as a readable reference
implementation and remains runnable/tested; new work should target the native
KQL. See v3-enterprise-native/README.md ("From Python to Sentinel Graph").

Simulates Microsoft Sentinel's modern graph-based context. Where the classic
incident_builder.py correlates alerts by shared user within a time window, this
builds a typed property graph of entities (identities, service principals,
resource groups, NSGs, VMs, IPs) and relationships (authenticated_from,
added_credential_to, granted_owner_on, modified, exposed_to_internet, protects),
then correlates by *reachability over the graph* rather than by time proximity.

Why it matters (the demonstration): in the CP-INC-2001 chain the NSG rule that
opens RDP to the internet is written by the service principal `sp-infra-deploy`,
NOT by the victim identity `chris.walker@contoso.com`. A per-user, time-window
join keyed on the caller therefore NEVER links the victim's risky sign-in to the
NSG change - the caller fields simply do not match. The graph links them through
the bridge edge:

    chris.walker --added_credential_to--> sp-infra-deploy --modified--> nsg-prod-dc-mgmt --exposed_to_internet--> vm-dc-mgmt-01

This module runs offline against the committed control-plane telemetry and prints
both the naive time-window result and the graph result so the difference is
concrete. Python standard library only.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CP_DATA = ROOT / "modules" / "datacenter-control-plane" / "data"
OUTPUT_DIR = ROOT / "output"

# Relationship types that an attacker traverses forward through the control plane.
ATTACK_EDGE_TYPES = {
    "added_credential_to", "activated_role", "granted_owner_on", "modified",
    "exposed_to_internet", "authenticated_from",
}
# Node privilege weighting for the graph blast-radius score.
NODE_WEIGHT = {"identity": 2, "service_principal": 3, "resource_group": 3,
               "nsg": 3, "vm": 4, "ip": 1}


def parse_ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


class PropertyGraph:
    """Minimal typed property graph with directed, timestamped relationships."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict] = {}
        self.out: dict[str, list[dict]] = defaultdict(list)
        self.in_: dict[str, list[dict]] = defaultdict(list)

    def add_node(self, node_id: str, node_type: str, **props) -> None:
        node = self.nodes.setdefault(node_id, {"id": node_id, "type": node_type,
                                               "props": {}, "anomaly": False})
        node["type"] = node_type
        node["props"].update(props)

    def flag_anomaly(self, node_id: str, reason: str) -> None:
        if node_id in self.nodes:
            self.nodes[node_id]["anomaly"] = True
            self.nodes[node_id]["props"].setdefault("anomaly_reasons", []).append(reason)

    def add_edge(self, src: str, dst: str, rel: str, ts: str | None = None, **props) -> None:
        edge = {"src": src, "dst": dst, "rel": rel, "ts": ts, "props": props}
        self.out[src].append(edge)
        self.in_[dst].append(edge)

    def neighbours(self, node_id: str):
        """Traverse both directions along attack-relevant edges. Forward edges
        model attacker progression; reverse edges let us reach the actor that
        performed an action (e.g. which identity added the SP credential)."""
        for edge in self.out.get(node_id, []):
            if edge["rel"] in ATTACK_EDGE_TYPES:
                yield edge, edge["dst"]
        for edge in self.in_.get(node_id, []):
            if edge["rel"] in ATTACK_EDGE_TYPES:
                yield edge, edge["src"]


# --- Graph construction from telemetry -----------------------------------------

def load_telemetry() -> dict:
    def _load(name: str):
        path = CP_DATA / f"{name}.json"
        if not path.exists():  # regenerate deterministically if absent
            import sys
            sys.path.insert(0, str(CP_DATA.parent / "src"))
            import generate_telemetry  # noqa
            generate_telemetry.main()
        return json.loads(path.read_text(encoding="utf-8"))

    return {
        "signin": _load("entra_signin_logs"),
        "audit": _load("entra_audit_logs"),
        "activity": _load("azure_activity_logs"),
        "nsg": _load("network_security_group_logs"),
        "assets": _load("asset_inventory"),
    }


def build_graph(data: dict) -> PropertyGraph:
    g = PropertyGraph()
    asset_by_id = {a["asset_id"]: a for a in data["assets"]}

    # Seed asset nodes and structural relationships (NSG protects VM).
    for asset in data["assets"]:
        g.add_node(asset["asset_id"], asset["type"], **{
            k: asset[k] for k in ("criticality", "privilege_tier", "public_ip")
            if k in asset})
    for asset in data["assets"]:
        if asset["type"] == "network_security_group":
            for vm in asset.get("protects", []):
                g.add_edge(asset["asset_id"], vm, "protects")

    # Sign-ins: identity authenticated_from ip; flag high-risk as an anomaly.
    for e in data["signin"]:
        upn, ip = e["UserPrincipalName"], e["IPAddress"]
        g.add_node(upn, "identity")
        g.add_node(ip, "ip", country=e.get("Country"))
        g.add_edge(upn, ip, "authenticated_from", e["TimeGenerated"],
                   risk=e.get("RiskLevelDuringSignIn"), mfa=e.get("MfaResult"))
        if e.get("RiskLevelDuringSignIn") == "high" and e["ResultType"] == 0:
            g.flag_anomaly(upn, f"high-risk sign-in from {e['City']} ({ip})")

    # Audit: credential added to a service principal; privileged role activation.
    for e in data["audit"]:
        actor = e["ActorUPN"]
        g.add_node(actor, "identity")
        if e["OperationName"] == "Add service principal credentials":
            sp = e["TargetName"]
            tier = asset_by_id.get(sp, {}).get("privilege_tier", "unknown")
            g.add_node(sp, "service_principal", privilege_tier=tier)
            g.add_edge(actor, sp, "added_credential_to", e["TimeGenerated"],
                       ticket=e["Detail"].get("change_ticket"))
        elif e["OperationName"].startswith("Add member to role"):
            role = e["Detail"].get("role")
            g.add_edge(actor, e["TargetName"], "activated_role", e["TimeGenerated"], role=role)

    # Azure Activity: role assignment (Owner grant) and NSG rule writes by a caller.
    for e in data["activity"]:
        caller, scope = e["Caller"], e["Scope"]
        rg = scope.split("/resourceGroups/")[-1]
        g.add_node(rg, "resource_group", criticality=asset_by_id.get(rg, {}).get("criticality"))
        op = e["OperationNameValue"]
        if op == "Microsoft.Authorization/roleAssignments/write":
            principal = e["Properties"].get("principal", caller)
            g.add_node(principal, "service_principal")
            g.add_edge(principal, rg, "granted_owner_on", e["TimeGenerated"],
                       role=e["Properties"].get("role"), by=caller)
        elif op == "Microsoft.Network/networkSecurityGroups/securityRules/write":
            # The caller (often a service principal) modifies the NSG.
            g.add_node(caller, "service_principal"
                       if caller in asset_by_id and asset_by_id[caller]["type"] == "service_principal"
                       else g.nodes.get(caller, {}).get("type", "identity"))

    # NSG telemetry: who opened what to the internet, and against which NSG.
    for e in data["nsg"]:
        nsg, actor = e["NsgName"], e["Actor"]
        g.add_node(nsg, "network_security_group",
                   criticality=asset_by_id.get(nsg, {}).get("criticality"))
        if actor not in g.nodes:
            g.add_node(actor, "service_principal")
        g.add_edge(actor, nsg, "modified", e["TimeGenerated"],
                   rule=e["RuleName"], port=e["DestinationPortRange"],
                   source=e["SourceAddressPrefix"], access=e["Access"])
        if e["Access"] == "Allow" and e["SourceAddressPrefix"] in ("0.0.0.0/0", "*", "Internet"):
            for edge in g.out.get(nsg, []):
                if edge["rel"] == "protects":
                    g.add_edge(nsg, edge["dst"], "exposed_to_internet", e["TimeGenerated"],
                               port=e["DestinationPortRange"])
    return g


# --- Correlation ---------------------------------------------------------------

def correlate_by_graph(g: PropertyGraph, seed: str, max_hops: int = 6) -> dict:
    """BFS from an anomalous seed node across attack-relevant edges, collecting the
    connected subgraph and the path to any internet-exposure node."""
    visited = {seed}
    parent: dict[str, tuple[str, dict]] = {}
    order = [seed]
    q = deque([(seed, 0)])
    exposure_node = None
    while q:
        node, depth = q.popleft()
        if depth >= max_hops:
            continue
        for edge, nxt in g.neighbours(node):
            if nxt not in visited:
                visited.add(nxt)
                parent[nxt] = (node, edge)
                order.append(nxt)
                q.append((nxt, depth + 1))
                if edge["rel"] == "exposed_to_internet" or g.nodes[nxt]["type"] == "vm":
                    exposure_node = nxt

    # Reconstruct the attack path seed -> exposure.
    path = []
    if exposure_node:
        cur = exposure_node
        while cur in parent:
            prev, edge = parent[cur]
            path.append((prev, edge["rel"], cur))
            cur = prev
        path.reverse()

    subgraph_types = {g.nodes[n]["type"] for n in visited}
    score = min(100, sum(NODE_WEIGHT.get(g.nodes[n]["type"], 1) for n in visited) * 6)
    return {
        "seed": seed,
        "connected_entities": sorted(visited),
        "entity_types": sorted(subgraph_types),
        "attack_path": [f"{s} --{r}--> {d}" for s, r, d in path],
        "reaches_internet_exposure": exposure_node is not None,
        "graph_blast_radius": score,
    }


def correlate_by_time_window(data: dict, seed_upn: str, window_minutes: int = 60) -> dict:
    """Baseline: classic per-actor time-window correlation. Groups events whose
    caller/actor equals the seed identity within the window. This is what the V1
    engine does - and it is exactly why the NSG change is missed."""
    seed_events = [e for e in data["signin"] if e["UserPrincipalName"] == seed_upn]
    if not seed_events:
        return {"seed": seed_upn, "correlated_events": [], "reaches_nsg_change": False}
    t0 = min(parse_ts(e["TimeGenerated"]) for e in seed_events)
    horizon = t0 + timedelta(hours=8)
    correlated = []
    for e in data["audit"]:
        if e["ActorUPN"] == seed_upn and t0 <= parse_ts(e["TimeGenerated"]) <= horizon:
            correlated.append(f"audit:{e['OperationName']}")
    for e in data["activity"]:
        if e["Caller"] == seed_upn and t0 <= parse_ts(e["TimeGenerated"]) <= horizon:
            correlated.append(f"activity:{e['OperationNameValue']}")
    for e in data["nsg"]:
        if e["Actor"] == seed_upn and t0 <= parse_ts(e["TimeGenerated"]) <= horizon:
            correlated.append(f"nsg:{e['RuleName']}")
    reaches_nsg = any(c.startswith("nsg:") for c in correlated)
    return {"seed": seed_upn, "window_minutes": window_minutes,
            "correlated_events": correlated, "reaches_nsg_change": reaches_nsg}


def run(seed: str = "chris.walker@contoso.com") -> dict:
    data = load_telemetry()
    g = build_graph(data)
    graph_result = correlate_by_graph(g, seed)
    time_result = correlate_by_time_window(data, seed)
    return {
        "incident_id": "CP-INC-2001-GRAPH",
        "seed_anomaly": seed,
        "graph_correlation": graph_result,
        "time_window_correlation": time_result,
        "why_graph_wins": (
            "The NSG change was performed by the service principal sp-infra-deploy, "
            "not by " + seed + ". A caller-keyed time-window join never links the "
            "risky sign-in to the NSG change (the caller fields differ). The graph "
            "connects them through the added_credential_to bridge edge, recovering "
            "the full identity-to-infrastructure attack path."),
        "graph_stats": {"nodes": len(g.nodes),
                        "edges": sum(len(v) for v in g.out.values())},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Graph-powered correlation (V2.0)")
    parser.add_argument("--seed", default="chris.walker@contoso.com")
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args()

    result = run(args.seed)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUTPUT_DIR / "graph_correlation.json"
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    gr = result["graph_correlation"]
    tw = result["time_window_correlation"]
    print("=" * 70)
    print("  Graph-powered correlation (V2.0) -", result["seed_anomaly"])
    print("=" * 70)
    print(f"graph: {result['graph_stats']['nodes']} nodes, "
          f"{result['graph_stats']['edges']} edges")
    print(f"\n[TIME-WINDOW baseline] correlated events for {tw['seed']}:")
    for e in tw["correlated_events"]:
        print(f"  - {e}")
    print(f"  reaches the NSG change?  {tw['reaches_nsg_change']}   "
          "<- the exposure is MISSED (different caller)")
    print(f"\n[GRAPH correlation] connected {len(gr['connected_entities'])} entities "
          f"({', '.join(gr['entity_types'])})")
    print("  attack path:")
    for hop in gr["attack_path"]:
        print(f"    {hop}")
    print(f"  reaches internet exposure?  {gr['reaches_internet_exposure']}   "
          f"blast radius {gr['graph_blast_radius']}/100")
    print(f"\nwrote {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
