"""Hermes Agent Lifecycle Hooks: EVM Pre-Execution Circuit Breaker."""

import re
import shlex
from typing import Dict, Any, Optional

try:
    from .radar_client import WerracleSecurityEngine
except (ImportError, ValueError):
    from radar_client import WerracleSecurityEngine

_engine = WerracleSecurityEngine()


def _parse_cast_send_command(cmd_str: str) -> Optional[Dict[str, Any]]:
    """Parse Foundry's `cast send` CLI command arguments."""
    try:
        tokens = shlex.split(cmd_str)
    except ValueError:
        tokens = cmd_str.split()

    to_addr = None
    sig_or_data = None
    value_wei = "0"

    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t == "send" and i > 0 and tokens[i - 1].endswith("cast"):
            if i + 1 < len(tokens):
                to_addr = tokens[i + 1]
            if i + 2 < len(tokens) and not tokens[i + 2].startswith("-"):
                sig_or_data = tokens[i + 2]
            i += 2
            continue
        if t in ["--value", "-v"] and i + 1 < len(tokens):
            value_wei = tokens[i + 1]
            i += 2
            continue
        i += 1

    if to_addr and re.match(r"^0x[a-fA-F0-9]{40}$", to_addr):
        return {
            "to": to_addr,
            "data": sig_or_data or "0x",
            "value_wei": value_wei,
        }
    return None


def evm_pre_flight_guard(tool_name: str, args: Dict[str, Any], **kwargs) -> Dict[str, Any]:
    """
    Hermes lifecycle hook executed before every tool execution.
    Inspects transaction commands for phishing, honeypots, and unlimited drains.
    Returns:
        {'action': 'continue'} to proceed.
        {'action': 'block', 'message': '...'} to halt execution and protect the wallet.
    """
    if tool_name in ["bash", "terminal", "shell", "run_command", "exec"]:
        cmd_str = args.get("command", "") or args.get("CommandLine", "") or ""
        
        if "cast send" in cmd_str:
            parsed = _parse_cast_send_command(cmd_str)
            if parsed:
                simulation = _engine.simulate_tx(
                    to=parsed["to"],
                    value_wei=parsed["value_wei"],
                    data=parsed["data"],
                )
                if simulation.get("action") == "BLOCK" or simulation.get("risk_score", 0) >= 75:
                    threats = "\n".join(f"  - {f}" for f in simulation.get("risk_factors", []))
                    return {
                        "action": "block",
                        "message": (
                            f"⛔ [WERRACLE CIRCUIT BREAKER TRIGGERED]\n"
                            f"The proposed on-chain transaction was BLOCKED by Werracle EVM Guard.\n"
                            f"Target Address: {parsed['to']}\n"
                            f"Calculated Risk Score: {simulation.get('risk_score')}/100\n"
                            f"Detected Security Violations:\n{threats}\n"
                            f"Action: Execution stopped to prevent potential wallet compromise or asset loss."
                        ),
                    }

    elif tool_name in ["send_transaction", "evm_send", "web3_send"]:
        to_addr = args.get("to", "")
        value = str(args.get("value", "0"))
        data = args.get("data", "0x")
        
        simulation = _engine.simulate_tx(to=to_addr, value_wei=value, data=data)
        if simulation.get("action") == "BLOCK" or simulation.get("risk_score", 0) >= 75:
            threats = "\n".join(f"  - {f}" for f in simulation.get("risk_factors", []))
            return {
                "action": "block",
                "message": (
                    f"⛔ [WERRACLE CIRCUIT BREAKER TRIGGERED]\n"
                    f"Direct EVM Tool call BLOCKED.\n"
                    f"Target: {to_addr}\n"
                    f"Risk Score: {simulation.get('risk_score')}/100\n"
                    f"Reasons:\n{threats}"
                ),
            }

    return {"action": "continue"}


def evm_post_execution_logger(tool_name: str, args: Dict[str, Any], result: Any, **kwargs) -> Dict[str, Any]:
    """Observer hook executed after a tool completes; captures execution audit logs."""
    return {"status": "observed"}
