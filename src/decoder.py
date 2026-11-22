"""
drainer-sim: EVM Calldata Decoder & Drainer Heuristic Engine
Decodes raw transaction calldata to flag malicious approvals, Permit2 traps, and sweeps.
Copyright (c) Shinabaze Ajiya. All rights reserved.
"""

from typing import Dict, List, Any, Optional, Tuple


# Known Standard Signatures
SELECTORS = {
    "095ea7b3": ("approve", "ERC-20", ["address", "uint256"]),
    "39509351": ("increaseAllowance", "ERC-20", ["address", "uint256"]),
    "a22cb465": ("setApprovalForAll", "ERC-721/1155", ["address", "bool"]),
    "23b872dd": ("transferFrom", "ERC-20/721", ["address", "address", "uint256"]),
    "42842e0e": ("safeTransferFrom", "ERC-721", ["address", "address", "uint256"]),
    "30f28b7a": ("permitTransferFrom", "Permit2", ["tuple", "tuple", "bytes"]),
    "2b2ec3b2": ("permit", "Permit2", ["address", "tuple", "bytes"]),
    "ac9650d8": ("multicall", "Batch/Proxy", ["bytes[]"]),
    "5ae401dc": ("multicallWithDeadline", "Batch/Proxy", ["uint256", "bytes[]"]),
}

UINT256_MAX = 2**256 - 1
UNLIMITED_THRESHOLD = 2**128


class CalldataDecoder:
    """Dissects EVM calldata and evaluates security risk of the transaction payload."""

    @classmethod
    def clean_hex(cls, data: str) -> str:
        s = data.strip()
        if s.startswith("0x") or s.startswith("0X"):
            s = s[2:]
        return s.lower()

    @classmethod
    def decode_transaction(cls, calldata: str, to_address: Optional[str] = None) -> Dict[str, Any]:
        raw = cls.clean_hex(calldata)
        if len(raw) < 8:
            return {
                "is_valid": False,
                "error": "Calldata too short to contain 4-byte function selector.",
                "risk_score": 0,
                "verdict": "UNKNOWN",
            }

        selector = raw[:8]
        args_hex = raw[8:]

        func_info = SELECTORS.get(selector, ("unknown", "Unknown", []))
        func_name, protocol, param_types = func_info

        findings: List[Dict[str, Any]] = []
        score = 0
        decoded_params: Dict[str, Any] = {}

        if func_name in ("approve", "increaseAllowance"):
            if len(args_hex) >= 128:
                spender = "0x" + args_hex[24:64]
                amount = int(args_hex[64:128], 16)
                decoded_params = {"spender": spender, "amount": amount, "is_max": amount >= UNLIMITED_THRESHOLD}

                if amount >= UNLIMITED_THRESHOLD:
                    findings.append({
                        "id": "DRAIN-001",
                        "threat": "UNLIMITED_ERC20_ALLOWANCE",
                        "severity": "CRITICAL",
                        "impact": 50,
                        "description": f"Grants infinite token spending approval to spender {spender}.",
                        "mitigation": "Reject transaction or cap approval to the exact required amount.",
                    })
                    score += 50
                else:
                    findings.append({
                        "id": "WARN-001",
                        "threat": "TOKEN_ALLOWANCE_SET",
                        "severity": "LOW",
                        "impact": 10,
                        "description": f"Grants token spending approval of {amount} units to {spender}.",
                    })
                    score += 10

        elif func_name == "setApprovalForAll":
            if len(args_hex) >= 128:
                operator = "0x" + args_hex[24:64]
                approved_val = int(args_hex[64:128], 16)
                is_approved = approved_val == 1
                decoded_params = {"operator": operator, "approved": is_approved}

                if is_approved:
                    findings.append({
                        "id": "DRAIN-002",
                        "threat": "NFT_ALL_ASSETS_OPERATOR_APPROVAL",
                        "severity": "CRITICAL",
                        "impact": 60,
                        "description": f"Grants operator {operator} full custody over ALL NFTs in this contract.",
                        "mitigation": "Reject transaction unless operator is a verified marketplace proxy.",
                    })
                    score += 60

        elif "permit" in func_name.lower():
            findings.append({
                "id": "DRAIN-003",
                "threat": "PERMIT2_OFFCHAIN_TOKEN_DELEGATION",
                "severity": "CRITICAL",
                "impact": 70,
                "description": f"Permit2 signature execution: can sweep pre-approved tokens in a single transaction.",
                "mitigation": "Verify signature domain separator, nonce, and beneficiary recipient address.",
            })
            score += 70

        elif "multicall" in func_name.lower():
            findings.append({
                "id": "WARN-002",
                "threat": "BATCH_MULTICALL_EXECUTION",
                "severity": "MEDIUM",
                "impact": 25,
                "description": "Multicall payload detected: may contain nested hidden transferFrom or permit calls.",
                "mitigation": "Inspect sub-calls individually before signing.",
            })
            score += 25

        if score >= 60:
            verdict = "MALICIOUS / HIGH PROBABILITY DRAINER"
        elif score >= 25:
            verdict = "SUSPICIOUS / ELEVATED RISK"
        elif score > 0:
            verdict = "LOW RISK"
        else:
            verdict = "STANDARD INTERACTION"

        # Generate Firewall Filter Rule
        firewall_rule = {
            "rule_name": f"Block_{func_name}_{selector}",
            "selector": f"0x{selector}",
            "protocol": protocol,
            "action": "BLOCK" if score >= 60 else "WARN",
            "condition": {
                "max_threshold_exceeded": decoded_params.get("is_max", False),
                "operator_sweeping": decoded_params.get("approved", False),
            },
        }

        return {
            "is_valid": True,
            "selector": f"0x{selector}",
            "function_name": func_name,
            "protocol": protocol,
            "calldata_length": len(raw) // 2,
            "decoded_params": decoded_params,
            "risk_score": min(score, 100),
            "verdict": verdict,
            "findings": findings,
            "firewall_rule": firewall_rule,
        }
