"""Detection Quality Scorecard generator.

Parses every detection YAML across both labs and scores each 0-100 against a
transparent eleven-criterion rubric, then writes
security-engineering/detection-quality-scorecard.json.

Stdlib only - a small targeted reader handles the detection YAML subset, so this
runs with a bare `python3` (no PyYAML, no virtualenv). The rubric is deliberate
about honesty: the top band is labelled "requires tenant-specific tuning", never
"production ready".
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "security-engineering" / "detection-quality-scorecard.json"
DETECTION_DIRS = [
    ("Identity Threat Detection & SOAR Lab", ROOT / "detections"),
    ("Datacenter Control Plane Attack Path Lab",
     ROOT / "modules" / "datacenter-control-plane" / "detections"),
]
TEST_FILES = [
    ROOT / "tests" / "test_detections.py",
    ROOT / "tests" / "test_severity.py",
    ROOT / "modules" / "datacenter-control-plane" / "tests" / "test_control_plane.py",
]

# Rubric: (key, label, weight). Weights sum to 100.
RUBRIC = [
    ("mitre_mapping", "MITRE ATT&CK mapping", 14),
    ("data_source", "Data source listed", 8),
    ("severity_rationale", "Severity + rationale", 6),
    ("version", "Version", 5),
    ("owner", "Named owner", 7),
    ("false_positive_guidance", "False-positive guidance", 12),
    ("response_guidance", "Response guidance", 12),
    ("test_coverage", "Automated test coverage", 12),
    ("tuning_notes", "Tuning notes", 10),
    ("known_limitations", "Known limitations", 8),
    ("expected_output", "Expected output contract", 6),
]

BANDS = [
    (85, "Production candidate (strong) - requires tenant-specific tuning"),
    (66, "Production candidate - requires tenant-specific tuning"),
    (41, "Developing"),
    (0, "Experimental"),
]


def _top_blocks(text: str) -> dict[str, str]:
    """Split a simple YAML doc into {top-level-key: block-text}. Handles inline
    scalars, block scalars (>- / |) and indented list/mapping blocks."""
    blocks: dict[str, str] = {}
    current, buf = None, []
    for line in text.splitlines():
        if re.match(r"^[A-Za-z_][\w-]*:", line):
            if current is not None:
                blocks[current] = "\n".join(buf)
            key, _, inline = line.partition(":")
            current, buf = key.strip(), [inline.strip()]
        elif current is not None:
            buf.append(line)
    if current is not None:
        blocks[current] = "\n".join(buf)
    return blocks


def _present(block: str | None) -> bool:
    if block is None:
        return False
    stripped = block.strip()
    return stripped not in ("", ">-", "|", "[]", "null", "None", "{}")


def _list_items(block: str | None) -> int:
    if not block:
        return 0
    return len(re.findall(r"^\s*-\s+\S", block, flags=re.MULTILINE))


def load_detection(path: str, blocks: dict[str, str]) -> dict:
    det_id = blocks.get("id", "").strip()
    title = blocks.get("title", "").strip() or blocks.get("name", "").strip()
    return {
        "id": det_id,
        "title": title,
        "severity": blocks.get("severity", "").strip(),
        "version": blocks.get("version", "").strip(),
        "local_detection": blocks.get("local_detection", "").strip(),
        "blocks": blocks,
    }


def _test_covered(det: dict) -> bool:
    needles = [n for n in (det["id"], det["local_detection"]) if n]
    for test_file in TEST_FILES:
        if not test_file.exists():
            continue
        content = test_file.read_text(encoding="utf-8")
        if any(n in content for n in needles):
            return True
    return False


def score(det: dict) -> dict:
    b = det["blocks"]
    tuning_block = b.get("tuning")
    has_fp = _present(b.get("false_positive_guidance")) or (
        tuning_block is not None and "known_false_positives" in tuning_block
        and _list_items(tuning_block) > 0)

    checks = {
        "mitre_mapping": _list_items(b.get("techniques")) > 0,
        "data_source": _present(b.get("data_source")) or _present(b.get("data_sources")),
        "severity_rationale": _present(b.get("severity")) and _present(b.get("description")),
        "version": _present(b.get("version")),
        "owner": _present(b.get("owner")),
        "false_positive_guidance": has_fp,
        "response_guidance": _present(b.get("response_guidance")) or _present(b.get("sla")),
        "test_coverage": _test_covered(det),
        "tuning_notes": (tuning_block is not None and _list_items(tuning_block) > 0)
        or _present(b.get("false_positive_guidance")),
        "known_limitations": has_fp or _present(b.get("references")),
        "expected_output": _present(b.get("test_expectation"))
        or _present(b.get("entity_mappings")),
    }
    # Partial credit: response guidance is full for an explicit field, half for
    # SLA-only; tuning is full for a structured block, partial for prose FP notes.
    breakdown = {}
    total = 0
    for key, label, weight in RUBRIC:
        earned = weight if checks[key] else 0
        if key == "response_guidance" and checks[key] and not _present(b.get("response_guidance")):
            earned = round(weight * 0.5)
        if key == "tuning_notes" and checks[key] and not (
                tuning_block is not None and _list_items(tuning_block) > 0):
            earned = round(weight * 0.6)
        breakdown[key] = {"label": label, "max": weight, "earned": earned}
        total += earned

    band = next(name for threshold, name in BANDS if total >= threshold)
    return {"score": total, "maturity": band, "criteria": breakdown}


def main() -> None:
    detections = []
    for lab_name, directory in DETECTION_DIRS:
        for path in sorted(directory.glob("*.yaml")):
            blocks = _top_blocks(path.read_text(encoding="utf-8"))
            det = load_detection(str(path), blocks)
            if not det["id"]:
                continue
            result = score(det)
            detections.append({
                "lab": lab_name,
                "id": det["id"],
                "title": det["title"],
                "severity": det["severity"],
                "version": det["version"],
                "file": str(path.relative_to(ROOT)),
                "score": result["score"],
                "maturity": result["maturity"],
                "criteria": result["criteria"],
            })

    detections.sort(key=lambda d: d["id"])
    scores = [d["score"] for d in detections]
    summary = {
        "rubric": [{"key": k, "label": l, "weight": w} for k, l, w in RUBRIC],
        "maturity_bands": [{"min_score": t, "label": n} for t, n in BANDS],
        "detection_count": len(detections),
        "average_score": round(sum(scores) / len(scores), 1) if scores else 0,
        "min_score": min(scores) if scores else 0,
        "max_score": max(scores) if scores else 0,
        "honest_note": "Scores reflect detection-as-code metadata quality, not "
                       "production readiness. Every detection is a candidate that "
                       "requires tenant-specific baselining and tuning before "
                       "deployment.",
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps({"summary": summary, "detections": detections},
                                 indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)} ({len(detections)} detections, "
          f"avg {summary['average_score']}, range {summary['min_score']}-{summary['max_score']})")
    for det in detections:
        print(f"  {det['id']:<11} {det['score']:>3}/100  {det['maturity']}")


if __name__ == "__main__":
    main()
