"""Render the attack-path graph JSON into a Mermaid diagram in
security-engineering/attack-path-graph.md.

Stdlib only. Keeps the human-readable diagram in sync with the machine-readable
graph, so the JSON stays the single source of truth.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GRAPH_JSON = ROOT / "security-engineering" / "attack-path-graph.json"
OUTPUT_MD = ROOT / "security-engineering" / "attack-path-graph.md"

# Mermaid class styling per node kind.
CLASS_STYLE = {
    "attack": "fill:#3b1f1f,stroke:#e06666,color:#f5f5f5",
    "detection": "fill:#1f2a3b,stroke:#6fa8dc,color:#f5f5f5",
    "response": "fill:#1f3b2a,stroke:#93c47d,color:#f5f5f5",
    "prevention": "fill:#2a1f3b,stroke:#b58cd6,color:#f5f5f5",
}
EDGE_STYLE = {
    "attack": "-->",
    "detection": "-.->",
    "response": "==>",
    "prevention": "-.->",
}


def render_mermaid(graph: dict) -> str:
    lines = ["```mermaid", "flowchart TD"]
    for node in graph["nodes"]:
        safe = node["label"].replace('"', "'")
        lines.append(f'    {node["id"]}["{safe}"]:::{node["kind"]}')
    lines.append("")
    for edge in graph["edges"]:
        arrow = EDGE_STYLE.get(edge["kind"], "-->")
        lines.append(f'    {edge["from"]} {arrow}|{edge["relation"]}| {edge["to"]}')
    lines.append("")
    for kind, style in CLASS_STYLE.items():
        lines.append(f"    classDef {kind} {style}")
    lines.append("```")
    return "\n".join(lines)


def render_markdown(graph: dict) -> str:
    attack_nodes = [n for n in graph["nodes"] if n["kind"] == "attack"]
    path = " -> ".join(n["label"].split(" ")[0] for n in attack_nodes)
    breakpoint_node = next(n for n in graph["nodes"]
                           if n["id"] == graph["earliest_break_point"]["node"])
    lines = [
        "# Attack Path Graph",
        "",
        "The datacenter control-plane scenario (incident **"
        f"{graph['incident']}**) as a graph, not a list of alerts. This is the "
        "artefact that shows attack-path reasoning: how a single compromised "
        "identity walks across identity, RBAC and networking boundaries, where "
        "the detections observe it, and where a single control breaks the chain.",
        "",
        "Machine-readable source: [attack-path-graph.json](attack-path-graph.json). "
        "Regenerate this diagram with `python3 security-engineering/render_attack_graph.py`.",
        "",
        "## The graph",
        "",
        render_mermaid(graph),
        "",
        "Legend: red = attacker moves, blue (dotted) = detection triggers, "
        "green (bold) = response containment, purple (dotted) = prevention control.",
        "",
        "## Attacker path",
        "",
        f"`{path}`",
        "",
        "Each hop is a real telemetry event in the lab; together they are one "
        "incident. Reading it as a path rather than seven alerts is the whole "
        "point - it is the difference between triaging noise and seeing an "
        "attacker walk toward the crown jewels.",
        "",
        "## Nodes",
        "",
        "| Node | Type | Role in the story |",
        "|------|------|-------------------|",
    ]
    role = {
        "attack": "attacker-controlled step",
        "detection": "where the chain is seen",
        "response": "how it is contained",
        "prevention": "how it is stopped next time",
    }
    for node in graph["nodes"]:
        lines.append(f"| {node['label']} | {node['type']} | {role[node['kind']]} |")

    lines += [
        "",
        "## Edges",
        "",
        "| From | Relation | To |",
        "|------|----------|----|",
    ]
    label = {n["id"]: n["label"] for n in graph["nodes"]}
    for edge in graph["edges"]:
        lines.append(f"| {label[edge['from']]} | {edge['relation']} | {label[edge['to']]} |")

    lines += [
        "",
        "## Earliest break point",
        "",
        f"**{breakpoint_node['label']}** - "
        + graph["earliest_break_point"]["explanation"],
        "",
        "This is the analytical payoff of drawing the graph: it makes the "
        "highest-leverage control obvious. The chain has seven attacker edges, "
        "but the prevention control severs the last and most damaging one before "
        "it happens - which is why the RCA recommends deploying it, not just "
        "adding another detection.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    graph = json.loads(GRAPH_JSON.read_text(encoding="utf-8"))
    OUTPUT_MD.write_text(render_markdown(graph), encoding="utf-8")
    print(f"wrote {OUTPUT_MD.relative_to(ROOT)} "
          f"({len(graph['nodes'])} nodes, {len(graph['edges'])} edges)")


if __name__ == "__main__":
    main()
