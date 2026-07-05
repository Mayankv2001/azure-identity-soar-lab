"""Tests for the V2.0 graph-powered correlation engine."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import graph_correlation as gc  # noqa: E402


def test_graph_recovers_full_attack_path():
    result = gc.run("chris.walker@contoso.com")
    gr = result["graph_correlation"]
    assert gr["reaches_internet_exposure"] is True
    # The path must bridge identity -> service principal -> nsg -> vm.
    path = " ".join(gr["attack_path"])
    assert "added_credential_to" in path
    assert "sp-infra-deploy" in path
    assert "nsg-prod-dc-mgmt" in path
    assert "vm-dc-mgmt-01" in path
    assert {"identity", "service_principal", "network_security_group",
            "virtual_machine"} <= set(gr["entity_types"])


def test_time_window_baseline_misses_the_nsg_change():
    """The whole point: a caller-keyed time-window join cannot reach the NSG
    change, because the caller is the service principal, not the victim."""
    result = gc.run("chris.walker@contoso.com")
    assert result["time_window_correlation"]["reaches_nsg_change"] is False
    assert result["graph_correlation"]["reaches_internet_exposure"] is True


def test_graph_is_deterministic():
    a = gc.run("chris.walker@contoso.com")
    b = gc.run("chris.walker@contoso.com")
    assert a["graph_correlation"]["attack_path"] == b["graph_correlation"]["attack_path"]
    assert a["graph_stats"] == b["graph_stats"]


def test_graph_has_expected_scale():
    result = gc.run("chris.walker@contoso.com")
    stats = result["graph_stats"]
    assert stats["nodes"] >= 10
    assert stats["edges"] >= 10
