"""
Unit tests for Werracle EVM Guard Circuit-Breaker (`pre_tool_call` hook & calldata/signature simulation).
Covers:
  - Raw hex calldata (`0x095ea7b3`, `0xa22cb465`, `0xd505accf`)
  - Human-readable Foundry `cast send` signatures + arguments (`approve(address,uint256)`, `setApprovalForAll(address,bool)`)
  - `--value` unit parsing (`ether`, `gwei`, `wei`, hex)
  - Proper 32-byte ABI boolean decoding for `setApprovalForAll` (`true` vs `false`)
  - Secret scoping: `WERRACLE_API_KEY` via `agent.secret_scope.get_secret` and host restriction to `api.werracle.com`
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest.mock import patch

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR.parent))

from hermes_werracle_guard.hooks import _parse_cast_send_command, pre_tool_call_hook  # noqa: E402
from hermes_werracle_guard.radar_client import (  # noqa: E402
    WerracleRadarEngine,
    get_engine,
    parse_eth_value_to_wei,
)


def test_unlimited_erc20_approve_raw_calldata_blocked() -> None:
    """Unlimited ERC-20 approve(address,uint256) via raw 0x095ea7b3 calldata to unknown spender must be BLOCKED."""
    engine = get_engine()
    bad_calldata = (
        "0x095ea7b3"
        "000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    res = engine.simulate_tx(
        to_address="0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
        calldata=bad_calldata,
        value_wei=0,
        chain="base",
    )
    assert res["verdict"] == "BLOCK"
    assert res["risk_score"] >= 80


def test_readme_cast_send_signature_approve_blocked() -> None:
    """The exact README example `cast send <token> 'approve(address,uint256)' <spender> 0xffff...` must be BLOCKED."""
    cmd = (
        "cast send 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 "
        "'approve(address,uint256)' "
        "0x1111111111111111111111111111111111111111 "
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    hook_res = pre_tool_call_hook(
        tool_name="terminal",
        args={"command": cmd},
    )
    assert hook_res is not None
    assert hook_res.get("block") is True
    assert "WERRACLE EVM CIRCUIT-BREAKER TRIGGERED" in hook_res.get("reason", "")


def test_cast_send_signature_approve_decimal_max_uint256_blocked() -> None:
    """`cast send` with `approve(address,uint256)` and decimal uint256.max or `type(uint256).max` must be BLOCKED."""
    cmd_decimal = (
        "cast send --rpc-url https://mainnet.base.org "
        "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 "
        "\"approve(address,uint256)\" "
        "0x1111111111111111111111111111111111111111 "
        "115792089237316195423570985008687907853269984665640564039457584007913129639935"
    )
    hook_res = pre_tool_call_hook(tool_name="bash", args={"command": cmd_decimal})
    assert hook_res is not None and hook_res.get("block") is True

    cmd_symbolic = (
        "cast send 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 "
        "'approve(address,uint256)' 0x1111111111111111111111111111111111111111 type(uint256).max"
    )
    hook_res2 = pre_tool_call_hook(tool_name="bash", args={"command": cmd_symbolic})
    assert hook_res2 is not None and hook_res2.get("block") is True


def test_cast_send_bounded_approve_allowed() -> None:
    """Bounded ERC-20 approve (e.g. 1000 USDC = 1000000000) should NOT be blocked."""
    cmd = (
        "cast send 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 "
        "'approve(address,uint256)' 0x1111111111111111111111111111111111111111 1000000000"
    )
    hook_res = pre_tool_call_hook(tool_name="terminal", args={"command": cmd})
    assert hook_res is None


def test_set_approval_for_all_bool_decoding_raw_and_sig() -> None:
    """setApprovalForAll must block when bool is true (1) and allow when bool is false (0) in both raw and signature forms."""
    engine = get_engine()

    # 1. Raw calldata with approved = true (1) and trailing bytes
    raw_true = (
        "0xa22cb465"
        "0000000000000000000000001111111111111111111111111111111111111111"
        "0000000000000000000000000000000000000000000000000000000000000001"
        "0000"  # extra trailing zero padding shouldn't fool the decoder
    )
    res_true = engine.simulate_tx(
        to_address="0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        calldata=raw_true,
    )
    assert res_true["verdict"] == "BLOCK"

    # 2. Raw calldata with approved = false (0)
    raw_false = (
        "0xa22cb465"
        "0000000000000000000000001111111111111111111111111111111111111111"
        "0000000000000000000000000000000000000000000000000000000000000000"
    )
    res_false = engine.simulate_tx(
        to_address="0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        calldata=raw_false,
    )
    assert res_false["verdict"] == "ALLOW"

    # 3. Signature + args with `true` -> BLOCK
    cmd_sig_true = (
        "cast send 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef "
        "'setApprovalForAll(address,bool)' 0x1111111111111111111111111111111111111111 true"
    )
    assert pre_tool_call_hook("terminal", {"command": cmd_sig_true}) is not None

    # 4. Signature + args with `false` -> ALLOW (revocation)
    cmd_sig_false = (
        "cast send 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef "
        "'setApprovalForAll(address,bool)' 0x1111111111111111111111111111111111111111 false"
    )
    assert pre_tool_call_hook("terminal", {"command": cmd_sig_false}) is None


def test_value_units_parsing_ether_and_gwei() -> None:
    """`--value` with `ether`, `gwei`, `wei`, and decimal units must parse accurately and block high-value drains."""
    assert parse_eth_value_to_wei("2ether") == 2 * 10**18
    assert parse_eth_value_to_wei("1.5 ether") == 15 * 10**17
    assert parse_eth_value_to_wei("2000000000gwei") == 2 * 10**18
    assert parse_eth_value_to_wei("100gwei") == 100 * 10**9
    assert parse_eth_value_to_wei("500wei") == 500

    # 2ether to untrusted address -> BLOCKED
    cmd_2eth = (
        "cast send 0x9999999999999999999999999999999999999999 "
        "--value 2ether --rpc-url https://mainnet.base.org"
    )
    res_2eth = pre_tool_call_hook("terminal", {"command": cmd_2eth})
    assert res_2eth is not None and res_2eth.get("block") is True

    # 1.5 ether (separated unit token) to untrusted address -> BLOCKED
    cmd_1_5eth = (
        "cast send --value 1.5 ether 0x9999999999999999999999999999999999999999"
    )
    res_1_5eth = pre_tool_call_hook("terminal", {"command": cmd_1_5eth})
    assert res_1_5eth is not None and res_1_5eth.get("block") is True

    # 2000000000gwei (= 2 ETH) to untrusted address -> BLOCKED
    cmd_gwei_high = (
        "cast send 0x9999999999999999999999999999999999999999 --value 2000000000gwei"
    )
    res_gwei_high = pre_tool_call_hook("terminal", {"command": cmd_gwei_high})
    assert res_gwei_high is not None and res_gwei_high.get("block") is True

    # Small gas-like 500000gwei (0.0005 ETH) -> ALLOWED
    cmd_gwei_low = (
        "cast send 0x9999999999999999999999999999999999999999 --value 500000gwei"
    )
    res_gwei_low = pre_tool_call_hook("terminal", {"command": cmd_gwei_low})
    assert res_gwei_low is None


def test_secret_scope_and_host_restriction(monkeypatch) -> None:
    """WERRACLE_API_KEY must be read via agent.secret_scope.get_secret and ONLY sent to https://api.werracle.com."""
    fake_agent_pkg = types.ModuleType("agent")
    fake_secret_scope = types.ModuleType("agent.secret_scope")
    called_keys = []

    def fake_get_secret(name: str, default: str = "") -> str:
        called_keys.append(name)
        if name == "WERRACLE_API_KEY":
            return "secret_test_token_123"
        return default

    fake_secret_scope.get_secret = fake_get_secret  # type: ignore
    fake_agent_pkg.secret_scope = fake_secret_scope  # type: ignore
    monkeypatch.setitem(sys.modules, "agent", fake_agent_pkg)
    monkeypatch.setitem(sys.modules, "agent.secret_scope", fake_secret_scope)

    # 1. Default official host -> Authorization header included
    engine_default = WerracleRadarEngine(api_url="https://api.werracle.com/v1/radar")
    headers_default = engine_default._build_headers()
    assert "WERRACLE_API_KEY" in called_keys
    assert headers_default.get("Authorization") == "Bearer secret_test_token_123"

    # 2. Custom / non-default host -> Authorization header MUST NOT be sent
    engine_custom = WerracleRadarEngine(api_url="https://evil.example.com/v1/radar")
    headers_custom = engine_custom._build_headers()
    assert "Authorization" not in headers_custom

    # 3. Insecure http:// scheme on api.werracle.com -> Authorization header MUST NOT be sent
    engine_http = WerracleRadarEngine(api_url="http://api.werracle.com/v1/radar")
    headers_http = engine_http._build_headers()
    assert "Authorization" not in headers_http


def test_safe_morpho_interaction_allowed() -> None:
    """Standard read/low-risk interaction with verified Morpho Blue singleton should be ALLOWED."""
    cmd = "cast send 0xbbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb 0x12345678 --value 0"
    hook_res = pre_tool_call_hook(
        tool_name="terminal",
        args={"command": cmd},
    )
    assert hook_res is None
