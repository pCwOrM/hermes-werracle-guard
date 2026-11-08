"""
Werracle EVM Guard — Hermes Agent Plugin Entrypoint
===================================================
Registers 4 Web3/DeFi security tools, 2 lifecycle circuit-breaker hooks
(`pre_tool_call`, `post_tool_call`), and the `/werracle` status slash command.
"""

from __future__ import annotations

import logging
from typing import Any

try:
    from .hooks import post_tool_call_hook, pre_tool_call_hook
    from .radar_client import WERRACLE_DEFAULT_API_URL, get_engine
    from .tools import (
        INSPECT_CONTRACT_SCHEMA,
        LIQUIDATION_HEALTH_SCHEMA,
        MEMPOOL_RADAR_SCHEMA,
        SIMULATE_TX_SCHEMA,
        handle_inspect_contract,
        handle_liquidation_health,
        handle_mempool_radar,
        handle_simulate_tx,
        werracle_cli_status,
    )
except ImportError:
    from hooks import post_tool_call_hook, pre_tool_call_hook  # type: ignore
    from radar_client import WERRACLE_DEFAULT_API_URL, get_engine  # type: ignore
    from tools import (  # type: ignore
        INSPECT_CONTRACT_SCHEMA,
        LIQUIDATION_HEALTH_SCHEMA,
        MEMPOOL_RADAR_SCHEMA,
        SIMULATE_TX_SCHEMA,
        handle_inspect_contract,
        handle_liquidation_health,
        handle_mempool_radar,
        handle_simulate_tx,
        werracle_cli_status,
    )

logger = logging.getLogger(__name__)


def _extract_api_url_from_context(ctx: Any) -> str:
    """Read `api_url` from Hermes PluginContext config if available."""
    for attr in ("get_config", "config"):
        getter = getattr(ctx, attr, None)
        if callable(getter):
            try:
                val = getter("api_url", WERRACLE_DEFAULT_API_URL)
                if val:
                    return str(val)
            except TypeError:
                try:
                    cfg = getter()
                    if isinstance(cfg, dict) and cfg.get("api_url"):
                        return str(cfg["api_url"])
                except Exception:
                    pass
        elif isinstance(getter, dict) and getter.get("api_url"):
            return str(getter["api_url"])
    return WERRACLE_DEFAULT_API_URL


def register(ctx: Any) -> None:
    """
    Standard Hermes Agent plugin registration hook (`register(ctx: PluginContext)`).
    """
    engine = get_engine()
    engine.configure(api_url=_extract_api_url_from_context(ctx))

    # 1. Register AI Agent Tools
    ctx.register_tool(
        name="werracle_simulate_tx",
        toolset="werracle",
        schema=SIMULATE_TX_SCHEMA,
        handler=handle_simulate_tx,
    )
    ctx.register_tool(
        name="werracle_mempool_radar",
        toolset="werracle",
        schema=MEMPOOL_RADAR_SCHEMA,
        handler=handle_mempool_radar,
    )
    ctx.register_tool(
        name="werracle_liquidation_health",
        toolset="werracle",
        schema=LIQUIDATION_HEALTH_SCHEMA,
        handler=handle_liquidation_health,
    )
    ctx.register_tool(
        name="werracle_inspect_contract",
        toolset="werracle",
        schema=INSPECT_CONTRACT_SCHEMA,
        handler=handle_inspect_contract,
    )

    # 2. Register Pre/Post Execution Circuit-Breaker Hooks
    ctx.register_hook("pre_tool_call", pre_tool_call_hook)
    ctx.register_hook("post_tool_call", post_tool_call_hook)

    # 3. Register Interactive CLI Slash Command (/werracle) if supported by host version
    if hasattr(ctx, "register_cli_command"):
        try:
            ctx.register_cli_command(
                name="werracle",
                help_text="Show Werracle EVM Guard circuit-breaker status and live Radar connection state",
                handler=werracle_cli_status,
            )
        except Exception as exc:
            logger.debug("Optional CLI command registration skipped: %s", exc)

    logger.info("Werracle EVM Guard v1.0.1 registered with Hermes Agent.")
