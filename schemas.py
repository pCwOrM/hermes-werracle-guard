"""JSON Schemas for Werracle EVM Guard tools in Hermes Agent."""

SIMULATE_TX_SCHEMA = {
    "name": "werracle_simulate_tx",
    "description": (
        "Dry-run and simulate an EVM transaction before execution. "
        "Predicts state changes, asset balance deltas, gas consumption, "
        "revert reasons, and flags unexpected token outflows or malicious behavior."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "chain": {
                "type": "string",
                "description": "Target blockchain network (e.g. 'base', 'ethereum', 'arbitrum'). Defaults to 'base'.",
                "default": "base"
            },
            "to": {
                "type": "string",
                "description": "Recipient or target smart contract address (0x-prefixed hex string)."
            },
            "from_address": {
                "type": "string",
                "description": "Originating sender/signer address (optional)."
            },
            "value_wei": {
                "type": "string",
                "description": "Amount of native gas token sent in wei (e.g. '0' or '1000000000000000000').",
                "default": "0"
            },
            "data": {
                "type": "string",
                "description": "Hex-encoded transaction calldata (0x-prefixed).",
                "default": "0x"
            },
            "gas_limit": {
                "type": "integer",
                "description": "Optional gas limit for simulation.",
                "default": 1000000
            }
        },
        "required": ["to"]
    }
}

INSPECT_CONTRACT_SCHEMA = {
    "name": "werracle_inspect_contract",
    "description": (
        "Audit an EVM smart contract for known exploit patterns, drainer signatures, "
        "unverified bytecode, DEX liquidity lockup, and owner centralization risks."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "address": {
                "type": "string",
                "description": "The contract address to inspect (0x-prefixed hex string)."
            },
            "chain": {
                "type": "string",
                "description": "Blockchain network (e.g. 'base', 'ethereum'). Defaults to 'base'.",
                "default": "base"
            },
            "check_dex_liquidity": {
                "type": "boolean",
                "description": "Whether to verify verified DEX pool liquidity depth (Aerodrome / Uniswap v3).",
                "default": True
            }
        },
        "required": ["address"]
    }
}

MEMPOOL_RADAR_SCHEMA = {
    "name": "werracle_mempool_radar",
    "description": (
        "Query Werracle Radar mempool telemetry and Base Flashblocks sub-second stream. "
        "Detects active frontrunner/sandwich bots, pending competitor transactions, "
        "and evaluates whether a public mempool submission is safe or vulnerable to MEV extraction."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "chain": {
                "type": "string",
                "description": "Blockchain network ('base' or 'ethereum'). Defaults to 'base'.",
                "default": "base"
            },
            "target_pair_or_market": {
                "type": "string",
                "description": "Market identifier or token pair symbol (e.g. 'WETH/USDC', 'mBASIS/USDC', or Morpho market ID)."
            },
            "max_lead_latency_ms": {
                "type": "integer",
                "description": "Max acceptable mempool latency lead in milliseconds.",
                "default": 500
            }
        }
    }
}

LIQUIDATION_GUARD_SCHEMA = {
    "name": "werracle_liquidation_guard",
    "description": (
        "Check health factors and liquidation trigger prices across lending protocols "
        "(Morpho, Aave) via Werracle Radar. Calculates the exact collateral price where HF=1.0 "
        "and warns the agent if collateral is within the danger zone."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "account": {
                "type": "string",
                "description": "Borrower wallet or contract address to monitor (0x-prefixed hex string)."
            },
            "chain": {
                "type": "string",
                "description": "Blockchain network ('base' or 'ethereum'). Defaults to 'base'.",
                "default": "base"
            },
            "buffer_pct": {
                "type": "number",
                "description": "Safety threshold buffer percentage (e.g. 5.0 for 5% drop warning).",
                "default": 5.0
            }
        },
        "required": ["account"]
    }
}
