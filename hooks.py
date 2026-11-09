"""
Hermes Agent Lifecycle Hooks for Werracle EVM Guard
===================================================
Implements `pre_tool_call` and `post_tool_call` hooks to act as an autonomous
EVM Execution Circuit-Breaker. When Hermes Agent attempts to run terminal
commands involving `cast send` (Foundry) — including commands wrapped in
`bash -c "..."`, `sh -lc "..."`, or compound shell pipelines — Werracle inspects
the target address, function signature + arguments, raw calldata, and `--value`
units (`ether`, `gwei`, `wei`) before execution, performing a Radar lookup to
api.werracle.com by default.
"""

from __future__ import annotations

import logging
import shlex
from typing import Any, Dict, List, Optional

try:
    from .radar_client import get_engine, parse_eth_value_to_wei
except ImportError:
    from radar_client import get_engine, parse_eth_value_to_wei  # type: ignore

logger = logging.getLogger(__name__)

# Foundry `cast send` options that consume a following argument token
_CAST_OPTIONS_WITH_VALUE = {
    "--rpc-url",
    "-r",
    "--private-key",
    "--from",
    "--gas-limit",
    "--gas-price",
    "--priority-gas-price",
    "--nonce",
    "--chain",
    "-c",
    "--account",
    "--keystore",
    "--password",
    "--password-file",
    "--mnemonic",
    "--mnemonic-path",
    "--mnemonic-passphrase",
    "--mnemonic-derivation-path",
    "--mnemonic-index",
    "--hd-path",
    "--confirmations",
    "--timeout",
    "--etherscan-api-key",
    "--blob-gas-price",
}

# Foundry `cast send` boolean flags (no separate value argument)
_CAST_BOOLEAN_FLAGS = {
    "--legacy",
    "--json",
    "-j",
    "--async",
    "--Unlocked",
    "--unlocked",
    "--ledger",
    "--trezor",
    "--aws",
    "--gcp",
    "--turnkey",
    "--interactive",
    "-i",
    "--create",
}


def _tokenize_shell(cmd: str) -> List[str]:
    """Tokenize a shell string while splitting unquoted `;`, `&`, and `|` separators."""
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|")
        lex.whitespace_split = True
        return list(lex)
    except ValueError:
        return cmd.split()


def _is_shell_separator(tok: str) -> bool:
    return bool(tok) and all(ch in ";&|" for ch in tok)


def _parse_single_cast_send_segment(tokens: List[str], start_idx: int) -> tuple[Optional[Dict[str, Any]], int]:
    """
    Parse one `cast send` invocation starting right after `cast send` (at `start_idx`).
    Returns `(parsed_dict_or_None, next_token_idx)`.
    """
    positional: List[str] = []
    value_wei: int = 0
    idx = start_idx
    n = len(tokens)

    while idx < n:
        tok = tokens[idx]
        if _is_shell_separator(tok):
            break

        if tok in ("--value", "-v"):
            if idx + 1 < n:
                val_str = tokens[idx + 1]
                # Handle separated unit token, e.g. `--value 1.5 ether` or `--value 100 gwei`
                if (
                    idx + 2 < n
                    and tokens[idx + 2].lower() in ("wei", "kwei", "mwei", "gwei", "szabo", "finney", "ether", "eth")
                ):
                    val_str = f"{val_str}{tokens[idx + 2]}"
                    idx += 3
                else:
                    idx += 2
                value_wei = parse_eth_value_to_wei(val_str)
                continue
            idx += 1
            continue

        if tok.startswith("--value="):
            value_wei = parse_eth_value_to_wei(tok.split("=", 1)[1])
            idx += 1
            continue

        if tok in _CAST_OPTIONS_WITH_VALUE:
            idx += 2
            continue

        if any(tok.startswith(opt + "=") for opt in _CAST_OPTIONS_WITH_VALUE):
            idx += 1
            continue

        if tok in _CAST_BOOLEAN_FLAGS:
            idx += 1
            continue

        if tok.startswith("-"):
            idx += 1
            continue

        positional.append(tok)
        idx += 1

    if not positional:
        return None, idx

    to_addr = positional[0]
    if not to_addr.startswith("0x") or len(to_addr) < 10:
        return None, idx

    sig_or_data = positional[1] if len(positional) >= 2 else "0x"
    call_args = positional[2:] if len(positional) >= 3 else []

    if sig_or_data.startswith("0x"):
        return (
            {
                "to": to_addr,
                "data": sig_or_data,
                "sig": None,
                "args": call_args,
                "value": value_wei,
            },
            idx,
        )

    return (
        {
            "to": to_addr,
            "data": "0x",
            "sig": sig_or_data,
            "args": call_args,
            "value": value_wei,
        },
        idx,
    )


def _extract_cast_send_calls(cmd: str, _depth: int = 0) -> List[Dict[str, Any]]:
    """
    Extract all Foundry `cast send` invocations from a command string, including
    invocations wrapped inside `bash -c "..."`, `sh -lc "..."`, or compound commands.
    """
    if _depth > 5 or "cast" not in cmd or "send" not in cmd:
        return []

    tokens = _tokenize_shell(cmd)
    calls: List[Dict[str, Any]] = []
    i = 0
    n = len(tokens)

    while i < n:
        tok = tokens[i]
        base_tok = tok.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        if base_tok == "cast" and i + 1 < n and tokens[i + 1] == "send":
            parsed, next_idx = _parse_single_cast_send_segment(tokens, i + 2)
            if parsed is not None:
                calls.append(parsed)
            i = max(i + 2, next_idx)
            continue

        # Handle nested subshells such as `bash -c "cast send ..."` or `sh -lc "..."`
        if "cast" in tok and "send" in tok and tok.strip() != cmd.strip():
            calls.extend(_extract_cast_send_calls(tok, _depth + 1))

        i += 1

    return calls


def _parse_cast_send_command(cmd: str) -> Optional[Dict[str, Any]]:
    """
    Detect and parse the first Foundry `cast send` command from a shell string.
    """
    calls = _extract_cast_send_calls(cmd)
    return calls[0] if calls else None


def pre_tool_call_hook(
    tool_name: str = "",
    args: Optional[Dict[str, Any]] = None,
    task_id: Optional[str] = None,
    **kwargs: Any,
) -> Optional[Dict[str, Any]]:
    """
    Hermes `pre_tool_call` hook.
    Intercepts terminal/bash tool invocations containing EVM `cast send` broadcasts.
    If Werracle simulation scores risk >= 80 (CRITICAL), returns
    `{"action": "block", "message": ..., "block": True, "reason": ...}`
    to prevent Hermes from executing the dangerous transaction.
    """
    if not args or not isinstance(args, dict):
        return None

    if tool_name not in ("terminal", "bash", "execute_command", "run_command"):
        return None

    command = str(args.get("command") or args.get("cmd") or "")
    if not command:
        return None

    calls = _extract_cast_send_calls(command)
    if not calls:
        return None

    engine = get_engine()
    for parsed in calls:
        sim = engine.simulate_tx(
            to_address=parsed["to"],
            calldata=parsed["data"],
            value_wei=parsed["value"],
            chain="base",
            function_sig=parsed.get("sig"),
            function_args=parsed.get("args"),
        )

        if sim.get("verdict") == "BLOCK":
            reasons_str = " | ".join(sim.get("reasons", []))
            block_msg = (
                f"🛡️ [WERRACLE EVM CIRCUIT-BREAKER TRIGGERED] "
                f"Blocked high-risk on-chain transaction (Risk Score: {sim['risk_score']}/100) "
                f"targeting {sim['target_address']} ({sim['decoded_function']}). Reason: {reasons_str}"
            )
            logger.warning(block_msg)
            return {
                "action": "block",
                "message": block_msg,
                "block": True,
                "reason": block_msg,
            }

    return None


def post_tool_call_hook(
    tool_name: str = "",
    args: Optional[Dict[str, Any]] = None,
    result: Any = None,
    task_id: Optional[str] = None,
    **kwargs: Any,
) -> None:
    """
    Hermes `post_tool_call` hook for lightweight audit logging of Werracle tool executions.
    """
    if tool_name.startswith("werracle_"):
        logger.debug("Werracle Guard tool completed: %s (task=%s)", tool_name, task_id)
