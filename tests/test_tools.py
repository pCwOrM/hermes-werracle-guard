"""
Unit tests for Werracle EVM Guard tool handlers and `/werracle` CLI status.
Verifies honest error reporting (`success: False`, `status: "unknown"`) when the Radar API
is unreachable, and proper telemetry reporting when the API responds.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR.parent))

from hermes_werracle_guard.radar_client import get_engine  # noqa: E402
from hermes_werracle_guard.tools import (  # noqa: E402
    handle_inspect_contract,
    handle_liquidation_health,
    handle_mempool_radar,
    handle_simulate_tx,
    werracle_cli_status,
)


def test_handle_simulate_tx_json() -> None:
    raw = handle_simulate_tx(
        {
            "to_address": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            "calldata": "0x",
            "value_wei": "0",
            "chain": "base",
        }
    )
    data = json.loads(raw)
    assert data["success"] is True
    assert data["verdict"] == "ALLOW"
    assert "USDC" in data["protocol_label"]
    assert "radar_lookup" in data


def test_mempool_radar_returns_failure_when_api_unreachable() -> None:
    """On API failure, werracle_mempool_radar must return success=False and status='unknown' (no made-up metrics)."""
    engine = get_engine()
    with patch.object(engine, "_get", return_value=None):
        raw = handle_mempool_radar({"chain": "base", "target_pair": "WETH/USDC"})
        data = json.loads(raw)
        assert data["success"] is False
        assert data["status"] == "unknown"
        assert "telemetry" not in data


def test_mempool_radar_returns_telemetry_when_api_connected() -> None:
    """When Radar API responds, werracle_mempool_radar returns live telemetry with success=True."""
    engine = get_engine()
    mock_payload = {"svr_recapture_pct": 94.4, "base_flashblocks_ms": 125.1}
    with patch.object(engine, "_get", return_value=mock_payload):
        raw = handle_mempool_radar({"chain": "base", "target_pair": "WETH/USDC"})
        data = json.loads(raw)
        assert data["success"] is True
        assert data["status"] == "ok"
        assert data["telemetry"] == mock_payload


def test_liquidation_health_returns_failure_when_api_unreachable() -> None:
    """On API failure, werracle_liquidation_health must return success=False and status='unknown' (never fake SAFE)."""
    engine = get_engine()
    with patch.object(engine, "_get", return_value=None):
        raw = handle_liquidation_health(
            {
                "account": "0x1234567890123456789012345678901234567890",
                "protocol": "morpho_blue",
                "chain": "base",
            }
        )
        data = json.loads(raw)
        assert data["success"] is False
        assert data["status"] == "unknown"
        assert "SAFE" not in json.dumps(data)


def test_liquidation_health_when_api_connected() -> None:
    """When Radar API responds, werracle_liquidation_health reports tracked or untracked status accurately."""
    engine = get_engine()
    acct = "0x1234567890123456789012345678901234567890"
    mock_positions = {"positions": [{"user": acct, "health_factor": 1.04, "risk": "HIGH"}]}
    with patch.object(engine, "_get", return_value=mock_positions):
        raw = handle_liquidation_health({"account": acct, "protocol": "morpho_blue", "chain": "base"})
        data = json.loads(raw)
        assert data["success"] is True
        assert data["status"] == "tracked"
        assert data["position"]["health_factor"] == 1.04


def test_handle_inspect_contract_json() -> None:
    raw = handle_inspect_contract(
        {
            "address": "0xbbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb",
            "chain": "base",
        }
    )
    data = json.loads(raw)
    assert data["success"] is True
    assert data["verified_in_werracle_registry"] is True
    assert "Morpho Blue" in data["protocol_label"]


def test_werracle_cli_status_reports_real_connection_state() -> None:
    """`/werracle` must report DISCONNECTED when the API is unreachable and CONNECTED when reachable."""
    engine = get_engine()
    with patch.object(engine, "_get", return_value=None):
        out_offline = werracle_cli_status()
        assert "DISCONNECTED" in out_offline

    with patch.object(engine, "_get", return_value={"ok": True}):
        out_online = werracle_cli_status()
        assert "Radar API Status     : CONNECTED" in out_online
