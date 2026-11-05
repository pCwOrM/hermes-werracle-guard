"""Unit tests for the Werracle EVM Pre-Execution Circuit Breaker hook."""

import os
import sys

PLUGIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

import pytest
from hooks import evm_pre_flight_guard, _parse_cast_send_command


def test_parse_cast_send():
    cmd = "cast send 0x2626664c2603336E57B271c5C0b26F221705772F 'swap(bytes)' 0x1234 --value 1000000000"
    parsed = _parse_cast_send_command(cmd)
    assert parsed is not None
    assert parsed["to"].lower() == "0x2626664c2603336E57B271c5C0b26F221705772F".lower()
    assert parsed["value_wei"] == "1000000000"


def test_circuit_breaker_blocks_unlimited_approval_to_untrusted():
    untrusted_contract = "0x1111111111111111111111111111111111111111"
    infinite_approval_calldata = (
        "0x095ea7b3"
        "000000000000000000000000" + untrusted_contract[2:] +
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    cmd = f"cast send 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 '{infinite_approval_calldata}'"
    
    result = evm_pre_flight_guard("bash", {"command": cmd})
    assert result["action"] == "block"
    assert "CIRCUIT BREAKER TRIGGERED" in result["message"]
    assert "CRITICAL_UNLIMITED_APPROVAL" in result["message"]


def test_circuit_breaker_allows_safe_commands():
    result = evm_pre_flight_guard("bash", {"command": "ls -la"})
    assert result["action"] == "continue"

    result = evm_pre_flight_guard("read_file", {"Path": "/tmp/test.txt"})
    assert result["action"] == "continue"


def test_circuit_breaker_allows_canonical_protocol():
    uniswap_router = "0x2626664c2603336E57B271c5C0b26F221705772F"
    cmd = f"cast send {uniswap_router} 'exactInputSingle(bytes)' 0xabcdef"
    result = evm_pre_flight_guard("bash", {"command": cmd})
    assert result["action"] == "continue"
