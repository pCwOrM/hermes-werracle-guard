"""Unit tests for Werracle EVM Guard interactive tools."""

import json
import os
import sys

PLUGIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

from tools import (
    simulate_tx_handler,
    inspect_contract_handler,
    mempool_radar_handler,
    liquidation_guard_handler,
    werracle_cli_status,
)


def test_simulate_tx_handler():
    payload = {
        "to": "0x2626664c2603336E57B271c5C0b26F221705772F",
        "value_wei": "0",
        "data": "0x",
        "chain": "base",
    }
    raw_res = simulate_tx_handler(payload)
    res = json.loads(raw_res)
    assert res["success"] is True
    assert res["simulation_result"] == "SUCCESS"
    assert res["action"] == "PROCEED"


def test_inspect_contract_handler():
    payload = {
        "address": "0xBBBBBbbBBb9cC5e90e3b3Af64bdAF66C3799863d",
        "chain": "base",
    }
    raw_res = inspect_contract_handler(payload)
    res = json.loads(raw_res)
    assert res["success"] is True
    assert res["is_trusted_canonical"] is True
    assert res["risk_score"] == 0


def test_mempool_radar_handler():
    payload = {"chain": "base", "target_pair_or_market": "WETH/USDC"}
    raw_res = mempool_radar_handler(payload)
    res = json.loads(raw_res)
    assert res["success"] is True
    assert "telemetry" in res
    assert "uncontested_ratio_pct" in res


def test_liquidation_guard_handler():
    payload = {
        "account": "0x8f70cc0a8619510f952d9f8ee7a5a2fa25e66a99",
        "chain": "base",
    }
    raw_res = liquidation_guard_handler(payload)
    res = json.loads(raw_res)
    assert res["success"] is True
    assert "health_factor" in res
    assert "is_danger" in res


def test_werracle_cli_status():
    status_str = werracle_cli_status()
    assert "Werracle EVM Guard" in status_str
    assert "Circuit Breaker: ENABLED" in status_str
