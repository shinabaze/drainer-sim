#!/usr/bin/env python3
"""
drainer-sim: Web3 Drainer Exploit Simulator & Firewall Rule Engine CLI
Copyright (c) Shinabaze Ajiya. All rights reserved.
"""

import sys
import os
import argparse
import json
from src.decoder import CalldataDecoder


CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def main():
    parser = argparse.ArgumentParser(
        description="drainer-sim: Evaluates EVM transaction calldata to detect wallet drainers and generate firewall rules."
    )
    parser.add_argument("calldata", help="Raw EVM hex calldata (with or without 0x prefix)")
    parser.add_argument("--json", action="store_true", help="Output analysis and firewall rules in JSON format")
    args = parser.parse_args()

    result = CalldataDecoder.decode_transaction(args.calldata)

    if not result["is_valid"]:
        print(f"[-] Error: {result.get('error', 'Invalid calldata')}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    verdict_color = RED if "DRAINER" in result["verdict"] or "HIGH" in result["verdict"] else (YELLOW if "SUSPICIOUS" in result["verdict"] else GREEN)
    print(f"\n{BOLD}{CYAN}=== DRAINER SIM :: WEB3 TRANSACTION FIREWALL AUDITOR ==={RESET}")
    print(f"Function Selector:    {BOLD}{result['selector']}{RESET} ({result['function_name']})")
    print(f"Protocol Context:     {result['protocol']}")
    print(f"Payload Size:         {result['calldata_length']} bytes")
    print(f"Risk Score:           {verdict_color}{BOLD}{result['risk_score']}/100{RESET}")
    print(f"Threat Verdict:       {verdict_color}{BOLD}{result['verdict']}{RESET}")

    if result["decoded_params"]:
        print(f"\n{BOLD}{CYAN}--- DECODED PARAMETERS ---{RESET}")
        for k, v in result["decoded_params"].items():
            print(f"  * {k}: {v}")

    if result["findings"]:
        print(f"\n{BOLD}{RED}--- DETECTED DRAINER VECTORS ({len(result['findings'])}) ---{RESET}")
        for f in result["findings"]:
            sev_color = RED if f["severity"] == "CRITICAL" else YELLOW
            print(f"  [{sev_color}{f['severity']}{RESET}] {BOLD}{f['threat']}{RESET}")
            print(f"           Details:    {f['description']}")
            if "mitigation" in f:
                print(f"           Mitigation: {f['mitigation']}")

    print(f"\n{BOLD}{CYAN}--- GENERATED WALLET FIREWALL RULE ---{RESET}")
    fw = result["firewall_rule"]
    print(f"  Rule:   {fw['rule_name']}")
    print(f"  Action: {RED if fw['action'] == 'BLOCK' else YELLOW}{fw['action']}{RESET}")
    print(f"  Target: {fw['selector']} ({fw['protocol']})\n")


if __name__ == "__main__":
    main()
