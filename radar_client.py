"""
Werracle Radar Telemetry & Circuit-Breaker Engine for Hermes Agent
==================================================================
Provides deterministic EVM calldata security heuristics and real-time
telemetry queries to the Werracle Radar infrastructure (Morpho Blue, Aave V3,
Uniswap V3, Chainlink SVR feeds on Base & Ethereum).

Zero private-key access: read-only telemetry and pre-execution risk scoring.
"""

from __future__ import annotations

import decimal
import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

# Default public Werracle Radar endpoint
WERRACLE_DEFAULT_API_URL = "https://api.werracle.com/v1/radar"
WERRACLE_DEFAULT_HOST = "api.werracle.com"

# 2^255 threshold for unlimited / dangerous ERC-20 approval amounts
UNLIMITED_APPROVAL_THRESHOLD = 1 << 255
MAX_UINT256 = (1 << 256) - 1

# Ethereum value unit multipliers to Wei
ETH_UNIT_MULTIPLIERS: Dict[str, int] = {
    "wei": 1,
    "kwei": 10**3,
    "babbage": 10**3,
    "femtoether": 10**3,
    "mwei": 10**6,
    "lovelace": 10**6,
    "picoether": 10**6,
    "gwei": 10**9,
    "shannon": 10**9,
    "nanoether": 10**9,
    "nano": 10**9,
    "szabo": 10**12,
    "microether": 10**12,
    "micro": 10**12,
    "finney": 10**15,
    "milliether": 10**15,
    "milli": 10**15,
    "ether": 10**18,
    "eth": 10**18,
}

# Known dangerous selectors & signatures in EVM transactions
DANGEROUS_SELECTORS: Dict[str, Dict[str, Any]] = {
    "0x095ea7b3": {
        "name": "approve(address,uint256)",
        "risk": "HIGH_IF_UNLIMITED",
        "description": "ERC-20 Token Approval",
    },
    "0xa22cb465": {
        "name": "setApprovalForAll(address,bool)",
        "risk": "CRITICAL",
        "description": "ERC-721 / ERC-1155 Full Operator Approval",
    },
    "0xd505accf": {
        "name": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
        "risk": "HIGH",
        "description": "EIP-2612 Gasless Permit Signature",
    },
    "0x39509351": {
        "name": "increaseAllowance(address,uint256)",
        "risk": "MEDIUM",
        "description": "ERC-20 Allowance Increase",
    },
    "0x42842e0e": {
        "name": "safeTransferFrom(address,address,uint256)",
        "risk": "MEDIUM",
        "description": "NFT Safe Transfer",
    },
    "0xa9059cbb": {
        "name": "transfer(address,uint256)",
        "risk": "MEDIUM",
        "description": "ERC-20 Direct Token Transfer",
    },
    "0x23b872dd": {
        "name": "transferFrom(address,address,uint256,uint256)",
        "risk": "MEDIUM",
        "description": "ERC-20 / ERC-721 Delegated Transfer",
    },
}

# Known verified protocol contracts (Base & Ethereum Mainnet)
TRUSTED_PROTOCOLS: Dict[str, str] = {
    "0xbbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb": "Morpho Blue Singleton (Base/Mainnet)",
    "0xa238dd80c259a72e81d7e4664a9801593f98d1c5": "Aave V3 Pool (Base)",
    "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2": "Aave V3 Pool (Ethereum)",
    "0x2626664c2603336e57b271c5c0b26f421741e481": "Uniswap V3 SwapRouter02 (Base)",
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap V3 SwapRouter02 (Ethereum)",
    "0x4200000000000000000000000000000000000006": "Wrapped Ether WETH (Base)",
    "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": "USD Coin USDC (Base)",
}


def _resolve_api_key() -> str:
    """Read WERRACLE_API_KEY via agent.secret_scope.get_secret with env fallback."""
    try:
        from agent.secret_scope import get_secret  # type: ignore

        val = get_secret("WERRACLE_API_KEY", "")
        if val:
            return str(val).strip()
    except Exception:
        pass
    return os.getenv("WERRACLE_API_KEY", "").strip()


def _is_default_werracle_host(api_url: str) -> bool:
    """Return True only if api_url points over HTTPS to the official api.werracle.com host."""
    try:
        parsed = urllib.parse.urlsplit(api_url.strip())
        return parsed.scheme.lower() == "https" and (parsed.hostname or "").lower() == WERRACLE_DEFAULT_HOST
    except Exception:
        return False


def parse_eth_value_to_wei(raw_value: Any) -> int:
    """
    Parse an EVM value expression into integer Wei.
    Supports:
      - plain integers / decimal strings ("1000000000000000000")
      - hex strings ("0xde0b6b3a7640000")
      - unit-suffixed strings ("2ether", "1.5 ether", "100gwei", "500wei")
    """
    if raw_value is None:
        return 0
    if isinstance(raw_value, int):
        return max(0, raw_value)
    text = str(raw_value).strip().lower().replace("_", "")
    if not text:
        return 0
    if text.startswith("0x"):
        try:
            return int(text, 16)
        except ValueError:
            return 0

    m = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*([a-z]+)?$", text)
    if not m:
        try:
            return int(float(text))
        except ValueError:
            return 0

    num_str, unit = m.group(1), m.group(2)
    multiplier = 1
    if unit:
        if unit not in ETH_UNIT_MULTIPLIERS:
            return 0
        multiplier = ETH_UNIT_MULTIPLIERS[unit]

    try:
        dec_val = decimal.Decimal(num_str) * decimal.Decimal(multiplier)
        return int(dec_val.to_integral_value(rounding=decimal.ROUND_FLOOR))
    except (decimal.InvalidOperation, ValueError):
        return 0


def _parse_uint256_arg(raw_arg: str) -> Optional[int]:
    """Parse a uint256 argument from cast send (hex, decimal, or type(uint256).max)."""
    token = raw_arg.strip().strip("'\"")
    low = token.lower().replace("_", "")
    if low in ("type(uint256).max", "max_uint256", "uint256.max", "max", "unlimited"):
        return MAX_UINT256
    if low.startswith("0x"):
        try:
            return int(low, 16)
        except ValueError:
            return None
    try:
        return int(low, 10)
    except ValueError:
        return None


def _parse_bool_arg(raw_arg: str) -> Optional[bool]:
    """Parse a boolean argument from cast send ('true'/'false', '1'/'0', or hex word)."""
    token = raw_arg.strip().strip("'\"").lower()
    if token in ("true", "t", "yes", "1"):
        return True
    if token in ("false", "f", "no", "0"):
        return False
    if token.startswith("0x"):
        try:
            return int(token, 16) != 0
        except ValueError:
            return None
    return None


def _normalize_address_word(word_or_addr: str) -> str:
    """Extract a normalized 0x + 40-hex-char address from an ABI word or address string."""
    clean = word_or_addr.strip().strip("'\"").lower()
    if clean.startswith("0x"):
        clean = clean[2:]
    if len(clean) == 64:
        clean = clean[24:]
    if len(clean) == 40 and all(c in "0123456789abcdef" for c in clean):
        return "0x" + clean
    return "0x" + clean


def _canonicalize_sig(sig: str) -> str:
    """Normalize a human-readable Solidity function signature like 'approve(address spender, uint256 amount)'."""
    s = sig.strip().strip("'\"")
    if s.startswith("function "):
        s = s[len("function ") :].strip()
    if "(" not in s or ")" not in s:
        return s.lower()
    fn_name, rest = s.split("(", 1)
    params_str = rest.rsplit(")", 1)[0]
    if not params_str.strip():
        return f"{fn_name.strip()}()"
    param_types: List[str] = []
    for part in params_str.split(","):
        tokens = part.strip().split()
        if tokens:
            t = tokens[0].lower()
            if t == "uint":
                t = "uint256"
            elif t == "int":
                t = "int256"
            param_types.append(t)
    return f"{fn_name.strip()}({','.join(param_types)})"


class WerracleRadarEngine:
    """
    Hybrid Local + Cloud Telemetry Engine for Werracle EVM Guard.
    Performs instant local bytecode/calldata analysis and queries the Werracle Radar API
    at api.werracle.com by default on every tool call and intercepted cast send.
    """

    def __init__(self, api_url: Optional[str] = None, api_key: Optional[str] = None) -> None:
        self.api_url: str = (api_url or WERRACLE_DEFAULT_API_URL).rstrip("/")
        self._explicit_api_key: Optional[str] = api_key
        self.blocked_count: int = 0
        self.inspected_count: int = 0
        self.last_api_ok: Optional[bool] = None
        self.last_api_error: Optional[str] = None

    def configure(self, api_url: Optional[str] = None, api_key: Optional[str] = None) -> None:
        """Update engine configuration from Hermes PluginContext."""
        if api_url:
            self.api_url = str(api_url).strip().rstrip("/")
        if api_key is not None:
            self._explicit_api_key = api_key

    @property
    def api_key(self) -> str:
        if self._explicit_api_key is not None:
            return self._explicit_api_key
        return _resolve_api_key()

    def _build_headers(self) -> Dict[str, str]:
        """Build request headers, attaching WERRACLE_API_KEY only for the default Werracle host."""
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "Hermes-Werracle-Guard/1.0.1",
        }
        key = self.api_key
        if key and _is_default_werracle_host(self.api_url):
            headers["Authorization"] = f"Bearer {key}"
        return headers

    def _get(self, path: str, params: Optional[Dict[str, str]] = None, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        """Non-blocking HTTP GET to Werracle Radar API. Returns None on failure."""
        url = f"{self.api_url}/{path.lstrip('/')}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers=self._build_headers())
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    payload = json.loads(resp.read().decode("utf-8"))
                    if isinstance(payload, dict):
                        self.last_api_ok = True
                        self.last_api_error = None
                        return payload
            self.last_api_ok = False
            self.last_api_error = f"HTTP {getattr(resp, 'status', 'error')}"
        except Exception as exc:
            self.last_api_ok = False
            self.last_api_error = str(exc)
            logger.debug("Werracle Radar API unreachable (%s): %s", url, exc)
        return None

    def check_connection(self, timeout: float = 3.0) -> Dict[str, Any]:
        """Ping the configured Werracle Radar API and return the live connection status."""
        data = self._get("health", timeout=timeout)
        if data is not None:
            return {
                "connected": True,
                "status": "CONNECTED",
                "api_url": self.api_url,
                "key_configured": bool(self.api_key),
                "key_eligible_for_host": _is_default_werracle_host(self.api_url),
                "telemetry": data,
            }
        return {
            "connected": False,
            "status": "DISCONNECTED",
            "api_url": self.api_url,
            "key_configured": bool(self.api_key),
            "key_eligible_for_host": _is_default_werracle_host(self.api_url),
            "error": self.last_api_error or "Werracle Radar API unreachable",
        }

    # ------------------------------------------------------------------
    # 1. Pre-Execution Transaction Simulation & Calldata Risk Scoring
    # ------------------------------------------------------------------
    def simulate_tx(
        self,
        to_address: str,
        calldata: str = "0x",
        value_wei: Any = 0,
        chain: str = "base",
        function_sig: Optional[str] = None,
        function_args: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze an EVM transaction before signing or broadcasting.
        Supports both raw hex calldata ('0x095ea7b3...') and human-readable
        Foundry cast signatures + arguments (e.g. 'approve(address,uint256)' + [spender, amount]).
        Performs a Radar lookup to api.werracle.com by default alongside local deterministic checks.
        """
        self.inspected_count += 1
        to_norm = (to_address or "").strip().strip("'\"").lower()
        data_clean = (calldata or "0x").strip().strip("'\"").lower()
        args_list: List[str] = [str(a).strip() for a in (function_args or [])]

        # If calldata looks like a human-readable signature rather than hex, treat it as function_sig
        if not function_sig and data_clean and not data_clean.startswith("0x") and "(" in data_clean:
            function_sig = calldata.strip().strip("'\"")
            data_clean = "0x"

        val_int = parse_eth_value_to_wei(value_wei)

        reasons: List[str] = []
        risk_score = 10  # Baseline minimal risk
        selector = data_clean[:10] if len(data_clean) >= 10 and data_clean.startswith("0x") else "0x"
        canonical_sig = _canonicalize_sig(function_sig) if function_sig else ""

        # Perform default Radar lookup to api.werracle.com for target contract telemetry
        radar_info = self._get("contracts/inspect", {"address": to_norm, "chain": chain}, timeout=2.5)
        radar_connected = radar_info is not None

        is_trusted_target = to_norm in TRUSTED_PROTOCOLS
        protocol_label = TRUSTED_PROTOCOLS.get(to_norm, "Unverified / Unknown Contract")
        if radar_info and radar_info.get("protocol_label"):
            protocol_label = str(radar_info["protocol_label"])

        if radar_info and str(radar_info.get("risk_level", "")).upper() in ("HIGH", "CRITICAL"):
            risk_score = max(risk_score, 85)
            reasons.append(
                f"Werracle Radar flagged target contract {to_norm} as {radar_info.get('risk_level')} risk."
            )

        # 1. Selector / Signature Risk Evaluation
        decoded_fn_name: Optional[str] = None

        # --- Case A: Raw hex calldata ---
        if selector in DANGEROUS_SELECTORS:
            sel_meta = DANGEROUS_SELECTORS[selector]
            decoded_fn_name = sel_meta["name"]

            if selector == "0x095ea7b3":
                # approve(address spender, uint256 amount)
                # ABI word 1 (chars 10..74) = spender, ABI word 2 (chars 74..138) = amount
                spender_word = data_clean[10:74] if len(data_clean) >= 74 else ""
                amount_word = data_clean[74:138] if len(data_clean) >= 138 else ""
                spender_addr = _normalize_address_word(spender_word) if spender_word else ""

                amount_int: Optional[int] = None
                if amount_word:
                    try:
                        amount_int = int(amount_word, 16)
                    except ValueError:
                        amount_int = None

                is_unlimited = (
                    (amount_int is not None and amount_int >= UNLIMITED_APPROVAL_THRESHOLD)
                    or "ffffffffffffffffffffffffffffffff" in data_clean[74:]
                )
                spender_trusted = spender_addr in TRUSTED_PROTOCOLS

                if is_unlimited and not spender_trusted:
                    risk_score = max(risk_score, 92)
                    reasons.append(
                        f"CRITICAL: Unlimited ERC-20 approve(address,uint256) to unverified spender "
                        f"({spender_addr or 'unknown'}) on token {to_norm}. Drainer risk!"
                    )
                elif is_unlimited and spender_trusted:
                    risk_score = max(risk_score, 45)
                    reasons.append(
                        f"MODERATE: Unlimited ERC-20 approval to known protocol ({TRUSTED_PROTOCOLS[spender_addr]})."
                    )
                else:
                    risk_score = max(risk_score, 25)
                    reasons.append("Bounded ERC-20 token approval detected.")

            elif selector == "0xa22cb465":
                # setApprovalForAll(address operator, bool approved)
                # ABI word 1 (chars 10..74) = operator, ABI word 2 (chars 74..138) = bool approved
                operator_word = data_clean[10:74] if len(data_clean) >= 74 else ""
                bool_word = data_clean[74:138] if len(data_clean) >= 138 else data_clean[74:]
                operator_addr = _normalize_address_word(operator_word) if operator_word else ""

                approved_bool = False
                if bool_word:
                    try:
                        approved_bool = int(bool_word, 16) != 0
                    except ValueError:
                        approved_bool = False

                operator_trusted = operator_addr in TRUSTED_PROTOCOLS and is_trusted_target
                if approved_bool and not operator_trusted:
                    risk_score = max(risk_score, 95)
                    reasons.append(
                        f"CRITICAL: setApprovalForAll(operator={operator_addr or 'unknown'}, approved=true) "
                        "grants full NFT/collection control to an untrusted address."
                    )
                elif not approved_bool:
                    risk_score = max(risk_score, 15)
                    reasons.append("SAFE: setApprovalForAll(..., false) revokes operator approval.")
                else:
                    risk_score = max(risk_score, 50)
                    reasons.append("MODERATE: setApprovalForAll(true) on known protocol.")

            elif selector == "0xd505accf":
                if not is_trusted_target:
                    risk_score = max(risk_score, 88)
                    reasons.append(
                        "HIGH RISK: EIP-2612 permit() call to unverified contract. Off-chain signature drain vector."
                    )

        # --- Case B: Human-readable function signature + args (Foundry cast send) ---
        elif canonical_sig:
            decoded_fn_name = canonical_sig
            if canonical_sig == "approve(address,uint256)":
                spender_arg = _normalize_address_word(args_list[0]) if len(args_list) >= 1 else ""
                amount_val = _parse_uint256_arg(args_list[1]) if len(args_list) >= 2 else None
                is_unlimited = amount_val is not None and amount_val >= UNLIMITED_APPROVAL_THRESHOLD
                spender_trusted = spender_arg in TRUSTED_PROTOCOLS

                if is_unlimited and not spender_trusted:
                    risk_score = max(risk_score, 92)
                    reasons.append(
                        f"CRITICAL: Unlimited ERC-20 approve(address,uint256) to unverified spender "
                        f"({spender_arg or 'unknown'}) on token {to_norm}. Drainer risk!"
                    )
                elif is_unlimited and spender_trusted:
                    risk_score = max(risk_score, 45)
                    reasons.append(
                        f"MODERATE: Unlimited ERC-20 approval to known protocol ({TRUSTED_PROTOCOLS[spender_arg]})."
                    )
                elif amount_val is None:
                    risk_score = max(risk_score, 60)
                    reasons.append("WARNING: ERC-20 approve() called with unparseable allowance amount.")
                else:
                    risk_score = max(risk_score, 25)
                    reasons.append(f"Bounded ERC-20 token approval ({amount_val} base units) detected.")

            elif canonical_sig == "setApprovalForAll(address,bool)":
                operator_arg = _normalize_address_word(args_list[0]) if len(args_list) >= 1 else ""
                approved_flag = _parse_bool_arg(args_list[1]) if len(args_list) >= 2 else None
                operator_trusted = operator_arg in TRUSTED_PROTOCOLS and is_trusted_target

                if approved_flag is True and not operator_trusted:
                    risk_score = max(risk_score, 95)
                    reasons.append(
                        f"CRITICAL: setApprovalForAll(operator={operator_arg or 'unknown'}, approved=true) "
                        "grants full NFT/collection control to an untrusted address."
                    )
                elif approved_flag is False:
                    risk_score = max(risk_score, 15)
                    reasons.append("SAFE: setApprovalForAll(..., false) revokes operator approval.")
                elif approved_flag is True and operator_trusted:
                    risk_score = max(risk_score, 50)
                    reasons.append("MODERATE: setApprovalForAll(true) on known protocol.")
                else:
                    risk_score = max(risk_score, 85)
                    reasons.append("HIGH RISK: setApprovalForAll called with ambiguous boolean parameter.")

            elif canonical_sig.startswith("permit("):
                if not is_trusted_target:
                    risk_score = max(risk_score, 88)
                    reasons.append(
                        "HIGH RISK: EIP-2612 permit() call to unverified contract. Off-chain signature drain vector."
                    )

        # 2. High Native ETH Value Transfer to Unknown Target
        eth_value = val_int / 1e18
        if eth_value >= 1.0 and not is_trusted_target:
            risk_score = max(risk_score, 85)
            reasons.append(
                f"HIGH VALUE ALERT: Attempting to transfer {eth_value:.4f} ETH to unverified address {to_norm}."
            )
        elif eth_value > 0:
            risk_score = max(risk_score, 30)
            reasons.append(f"Native value transfer of {eth_value:.6f} ETH detected.")

        # 3. Raw arbitrary calldata to unverified contract
        if (
            len(data_clean) > 200
            and not is_trusted_target
            and selector not in DANGEROUS_SELECTORS
            and not canonical_sig
        ):
            risk_score = max(risk_score, 65)
            reasons.append(
                f"Complex arbitrary calldata ({len(data_clean) // 2} bytes) targeting unverified contract."
            )

        if not reasons:
            reasons.append("Standard transaction profile. No critical calldata anomalies detected.")

        verdict = "BLOCK" if risk_score >= 80 else ("WARN" if risk_score >= 50 else "ALLOW")
        if verdict == "BLOCK":
            self.blocked_count += 1

        return {
            "success": True,
            "verdict": verdict,
            "risk_score": risk_score,
            "chain": chain,
            "target_address": to_norm,
            "protocol_label": protocol_label,
            "selector": selector,
            "decoded_function": decoded_fn_name or DANGEROUS_SELECTORS.get(selector, {}).get("name", "unknown_or_native"),
            "eth_value": round(eth_value, 6),
            "value_wei": val_int,
            "reasons": reasons,
            "radar_lookup": {
                "api_url": self.api_url,
                "status": "connected" if radar_connected else "unreachable",
            },
            "timestamp": int(time.time()),
        }

    # ------------------------------------------------------------------
    # 2. Live Mempool & SVR Oracle Radar Telemetry
    # ------------------------------------------------------------------
    def get_mempool_radar(self, chain: str = "base", target_pair: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetch live mempool congestion, MEV sandwich risk, and Chainlink SVR oracle status
        from api.werracle.com. Returns success=False and status='unknown' if the API is unreachable.
        """
        params: Dict[str, str] = {"chain": chain}
        if target_pair:
            params["pair"] = target_pair
        svr_data = self._get("markets", params)
        if svr_data:
            return {
                "success": True,
                "status": "ok",
                "source": "werracle_radar_live",
                "chain": chain,
                "target_pair": target_pair or "all_markets",
                "telemetry": svr_data,
            }

        return {
            "success": False,
            "status": "unknown",
            "source": "werracle_radar_unreachable",
            "chain": chain,
            "target_pair": target_pair or "all_markets",
            "api_url": self.api_url,
            "error": self.last_api_error or "Werracle Radar API unreachable; live mempool telemetry unavailable.",
            "timestamp": int(time.time()),
        }

    # ------------------------------------------------------------------
    # 3. DeFi Borrower Liquidation Health Check
    # ------------------------------------------------------------------
    def check_liquidation_health(
        self, account: str, protocol: str = "morpho_blue", chain: str = "base"
    ) -> Dict[str, Any]:
        """
        Check a borrower's live Health Factor and liquidation proximity via Werracle Radar.
        Returns success=False and status='unknown' when the Radar API cannot be reached.
        """
        acct_norm = (account or "").strip().lower()
        hot_positions = self._get("positions", {"chain": chain, "protocol": protocol, "account": acct_norm})

        if hot_positions is None:
            return {
                "success": False,
                "status": "unknown",
                "account": acct_norm,
                "protocol": protocol,
                "chain": chain,
                "api_url": self.api_url,
                "error": self.last_api_error or "Werracle Radar API unreachable; borrower liquidation health unknown.",
                "timestamp": int(time.time()),
            }

        matched_pos = None
        if "positions" in hot_positions and isinstance(hot_positions["positions"], list):
            for p in hot_positions["positions"]:
                if str(p.get("user", "")).lower() == acct_norm:
                    matched_pos = p
                    break

        if matched_pos:
            return {
                "success": True,
                "status": "tracked",
                "account": acct_norm,
                "protocol": protocol,
                "chain": chain,
                "position": matched_pos,
                "timestamp": int(time.time()),
            }

        return {
            "success": True,
            "status": "untracked",
            "account": acct_norm,
            "protocol": protocol,
            "chain": chain,
            "message": (
                "Account is not currently indexed in Werracle Radar's critical liquidation watch-queue "
                "(HF < 1.15). Query on-chain protocol state directly for exact health factor."
            ),
            "timestamp": int(time.time()),
        }

    # ------------------------------------------------------------------
    # 4. Smart Contract Structural & Protocol Inspection
    # ------------------------------------------------------------------
    def inspect_contract(self, address: str, chain: str = "base") -> Dict[str, Any]:
        """
        Inspect an EVM smart contract address against Werracle's verified protocol registry
        and live Werracle Radar contract telemetry at api.werracle.com.
        """
        addr_norm = (address or "").strip().lower()
        is_valid_format = addr_norm.startswith("0x") and len(addr_norm) == 42

        radar_info = self._get("contracts/inspect", {"address": addr_norm, "chain": chain})
        radar_connected = radar_info is not None

        is_trusted = addr_norm in TRUSTED_PROTOCOLS
        label = TRUSTED_PROTOCOLS.get(addr_norm, "Unverified / External Contract")
        if radar_info and radar_info.get("protocol_label"):
            label = str(radar_info["protocol_label"])

        risk_tier = "LOW (Verified Core Protocol)" if is_trusted else "UNVERIFIED (Requires Calldata Simulation)"
        if radar_info and radar_info.get("risk_level"):
            risk_tier = str(radar_info["risk_level"])

        return {
            "success": True,
            "address": addr_norm,
            "chain": chain,
            "valid_evm_address": is_valid_format,
            "verified_in_werracle_registry": is_trusted,
            "protocol_label": label,
            "risk_tier": risk_tier,
            "radar_lookup": {
                "api_url": self.api_url,
                "status": "connected" if radar_connected else "unreachable",
                "telemetry": radar_info,
            },
            "security_notes": (
                "Verified core DeFi singleton/router. Safe for standard interactions; always verify slippage and allowance bounds."
                if is_trusted
                else "Address is NOT in the verified core DeFi registry. Always run werracle_simulate_tx before sending funds or approvals."
            ),
        }


# Singleton engine instance shared across tools and hooks
_engine = WerracleRadarEngine()


def get_engine() -> WerracleRadarEngine:
    return _engine
