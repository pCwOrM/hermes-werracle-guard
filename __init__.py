"""Werracle EVM Guard: Hermes Agent Plugin Entrypoint."""

try:
    from . import schemas, tools, hooks
except (ImportError, ValueError):
    import schemas, tools, hooks

__version__ = "1.0.0"
__author__ = "pCwOrM"


def register(ctx):
    """
    Register Werracle EVM Guard tools and lifecycle hooks with Hermes Agent.
    
    Args:
        ctx: The Hermes plugin context instance.
    """
    # 1. Register Lifecycle Hooks (Circuit Breaker & Telemetry)
    if hasattr(ctx, "register_hook"):
        ctx.register_hook("pre_tool_call", hooks.evm_pre_flight_guard)
        ctx.register_hook("post_tool_call", hooks.evm_post_execution_logger)

    # 2. Register Interactive Security & Simulation Tools
    if hasattr(ctx, "register_tool"):
        ctx.register_tool(
            name="werracle_simulate_tx",
            toolset="evm_security",
            schema=schemas.SIMULATE_TX_SCHEMA,
            handler=tools.simulate_tx_handler,
        )
        ctx.register_tool(
            name="werracle_inspect_contract",
            toolset="evm_security",
            schema=schemas.INSPECT_CONTRACT_SCHEMA,
            handler=tools.inspect_contract_handler,
        )
        ctx.register_tool(
            name="werracle_mempool_radar",
            toolset="evm_security",
            schema=schemas.MEMPOOL_RADAR_SCHEMA,
            handler=tools.mempool_radar_handler,
        )
        ctx.register_tool(
            name="werracle_liquidation_guard",
            toolset="evm_security",
            schema=schemas.LIQUIDATION_GUARD_SCHEMA,
            handler=tools.liquidation_guard_handler,
        )

    # 3. Register Slash Command (if supported by Hermes runtime)
    if hasattr(ctx, "register_command"):
        ctx.register_command("/werracle", tools.werracle_cli_status)
