"""
Hermes Agent Tool Schemas & Handlers for Werracle EVM Guard
===========================================================
Defines the 4 core tools registered with Hermes Agent:
  1. `werracle_simulate_tx`
  2. `werracle_mempool_radar`
  3. `werracle_liquidation_health`
  4. `werracle_inspect_contract`
"""

from __future__ import annotations

import json
from typing import Any, Dict

try:
    from .radar_client import get_engine
except ImportError:
    from radar_client import get_engine  # type: ignore

# ---------------------------------------------------------------------------
# 1. werracle_simulate_tx
# ---------------------------------------------------------------------------
SIMULATE_TX_SCHEMA: Dict[str, Any] = {
    "name": "werracle_simulate_tx",
    "description": (
        "Pre-execution EVM transaction guardrail and calldata risk analyzer. "
        "Use BEFORE signing or broadcasting any Ethereum/Base transaction (e.g. via Foundry `cast send`). "
        "Detects unlimited ERC-20 token approvals, malicious setApprovalForAll NFT drains, "
        "EIP-2612 permit traps, and high-value transfers to unverified contracts, while performing "
        "a Radar lookup to api.werracle.com by default."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "to_address": {
                "type": "string",
                "description": "Target EVM contract or recipient address (0x...)",
            },
            "calldata": {
                "type": "string",
                "description": "Hex-encoded transaction calldata (e.g. 0x095ea7b3...) or function signature",
                "default": "0x",
            },
            "value_wei": {
                "type": "string",
                "description": "Native ETH value in Wei or with unit suffix (e.g. '0', '1.5ether', '100gwei')",
                "default": "0",
            },
            "chain": {
                "type": "string",
                "description": "Target EVM chain ('base' or 'ethereum')",
                "enum": ["base", "ethereum"],
                "default": "base",
            },
            "function_sig": {
                "type": "string",
                "description": "Optional human-readable Solidity function signature (e.g. 'approve(address,uint256)')",
            },
            "function_args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional positional arguments when function_sig is provided",
            },
        },
        "required": ["to_address"],
    },
}


def handle_simulate_tx(args: Dict[str, Any], **kwargs: Any) -> str:
    engine = get_engine()
    result = engine.simulate_tx(
        to_address=str(args.get("to_address", "")),
        calldata=str(args.get("calldata", "0x")),
        value_wei=args.get("value_wei", "0"),
        chain=str(args.get("chain", "base")),
        function_sig=args.get("function_sig"),
        function_args=args.get("function_args"),
    )
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# 2. werracle_mempool_radar
# ---------------------------------------------------------------------------
MEMPOOL_RADAR_SCHEMA: Dict[str, Any] = {
    "name": "werracle_mempool_radar",
    "description": (
        "Fetch real-time EVM mempool congestion, MEV sandwich risk, and Chainlink SVR (Smart Value Recapture) "
        "oracle feed telemetry for Base and Ethereum DeFi markets via api.werracle.com."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "chain": {
                "type": "string",
                "description": "EVM network to query ('base' or 'ethereum')",
                "enum": ["base", "ethereum"],
                "default": "base",
            },
            "target_pair": {
                "type": "string",
                "description": "Optional market pair filter (e.g. 'WETH/USDC', 'cbBTC/USDC')",
            },
        },
        "required": [],
    },
}


def handle_mempool_radar(args: Dict[str, Any], **kwargs: Any) -> str:
    engine = get_engine()
    result = engine.get_mempool_radar(
        chain=str(args.get("chain", "base")),
        target_pair=args.get("target_pair"),
    )
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# 3. werracle_liquidation_health
# ---------------------------------------------------------------------------
LIQUIDATION_HEALTH_SCHEMA: Dict[str, Any] = {
    "name": "werracle_liquidation_health",
    "description": (
        "Inspect a DeFi borrower account's liquidation health factor, collateral-to-debt buffers, "
        "and flash-liquidation risk across Morpho Blue and Aave V3 markets via api.werracle.com."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "account": {
                "type": "string",
                "description": "Borrower wallet or smart account address (0x...)",
            },
            "protocol": {
                "type": "string",
                "description": "DeFi lending protocol ('morpho_blue' or 'aave_v3')",
                "enum": ["morpho_blue", "aave_v3"],
                "default": "morpho_blue",
            },
            "chain": {
                "type": "string",
                "description": "Target EVM chain ('base' or 'ethereum')",
                "enum": ["base", "ethereum"],
                "default": "base",
            },
        },
        "required": ["account"],
    },
}


def handle_liquidation_health(args: Dict[str, Any], **kwargs: Any) -> str:
    engine = get_engine()
    result = engine.check_liquidation_health(
        account=str(args.get("account", "")),
        protocol=str(args.get("protocol", "morpho_blue")),
        chain=str(args.get("chain", "base")),
    )
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# 4. werracle_inspect_contract
# ---------------------------------------------------------------------------
INSPECT_CONTRACT_SCHEMA: Dict[str, Any] = {
    "name": "werracle_inspect_contract",
    "description": (
        "Verify an EVM smart contract address against the Werracle verified DeFi protocol registry "
        "and perform a live Radar lookup to api.werracle.com (Morpho Blue, Aave V3, Uniswap V3, WETH, USDC)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "address": {
                "type": "string",
                "description": "EVM smart contract address to inspect (0x...)",
            },
            "chain": {
                "type": "string",
                "description": "Target EVM chain ('base' or 'ethereum')",
                "enum": ["base", "ethereum"],
                "default": "base",
            },
        },
        "required": ["address"],
    },
}


def handle_inspect_contract(args: Dict[str, Any], **kwargs: Any) -> str:
    engine = get_engine()
    result = engine.inspect_contract(
        address=str(args.get("address", "")),
        chain=str(args.get("chain", "base")),
    )
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Slash Command Handler (/werracle)
# ---------------------------------------------------------------------------
def werracle_cli_status(args: str = "", **kwargs: Any) -> str:
    """Display Werracle EVM Guard status and live Radar connection state."""
    engine = get_engine()
    conn = engine.check_connection()
    conn_state = "CONNECTED" if conn["connected"] else f"DISCONNECTED ({conn.get('error', 'API unreachable')})"
    key_state = "configured" if conn["key_configured"] else "not set"

    lines = [
        "============================================================",
        "  WERRACLE EVM GUARD — HERMES SECURITY & DEFI RADAR v1.0.1  ",
        "============================================================",
        "  Circuit-Breaker Hook : ACTIVE (pre_tool_call / cast send)",
        f"  Radar API Endpoint   : {engine.api_url}",
        f"  Radar API Status     : {conn_state}",
        f"  WERRACLE_API_KEY     : {key_state} (sent only to api.werracle.com)",
        f"  Tx Inspected Session : {engine.inspected_count}",
        f"  Tx Blocked Session   : {engine.blocked_count}",
        "============================================================",
    ]
    return "\n".join(lines)
