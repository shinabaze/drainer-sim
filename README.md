# drainer-sim

A zero-dependency EVM calldata analyzer and wallet firewall rule generator that detects malicious Web3 drainer exploits, unlimited allowance traps, and Permit2 signature attacks.

## Overview

Web3 phishing campaigns and wallet-draining kits rarely exploit smart contract vulnerabilities directly. Instead, they exploit standard token approval interfaces (`ERC-20`, `ERC-721`, `Permit2`) to trick users into granting unlimited custody to malicious spender contracts.

`drainer-sim` parses raw hex calldata before transaction signing, decodes EVM parameters, flags dangerous asset transfer permissions, and outputs protective firewall rules.

## Detected Attack Vectors

1. **Unlimited ERC-20 Allowances (`0x095ea7b3` / `0x39509351`):**
   - Flags transactions requesting spending limits $\ge 2^{128}$ or `type(uint256).max`.
2. **NFT Sweeper Approvals (`0xa22cb465`):**
   - Catches `setApprovalForAll(operator, true)` calls granting complete authority over entire collections.
3. **Permit2 Off-chain Signature Exploits (`0x30f28b7a` / `0x2b2ec3b2`):**
   - Identifies Uniswap Permit2 batch delegations that permit immediate draining of pre-approved balances.
4. **Multicall Obfuscation (`0xac9650d8` / `0x5ae401dc`):**
   - Warns on batch array payloads that wrap concealed approvals inside aggregate proxy executions.

## Usage

### Inspect Calldata Interactively
```bash
python cli.py 0x095ea7b3000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
```

### Export JSON Analysis & Firewall Rules
```bash
python cli.py 0x095ea7b3... --json > audit.json
```

## Generated Firewall Output

Every analysis generates a structured firewall rule defining:
- Selector fingerprint
- Risk tier and verdict
- Recommended wallet enforcement action (`BLOCK` or `WARN`)
- Decoded transaction parameters and thresholds

## Defensive Scope

`drainer-sim` is designed exclusively for transaction simulation, wallet guard plugins, and security education. It does not initiate on-chain transactions or execute attacks.

## License

MIT - Copyright (c) Shinabaze Ajiya.
