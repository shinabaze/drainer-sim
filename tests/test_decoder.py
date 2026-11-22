"""
Unit tests for drainer-sim calldata analysis and rule generation.
Copyright (c) Shinabaze Ajiya. All rights reserved.
"""

import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.decoder import CalldataDecoder


class TestDrainerSim(unittest.TestCase):

    def test_unlimited_erc20_approval(self):
        # approve(spender=0xdeadbeef..., amount=type(uint256).max)
        spender = "000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        max_amount = "f" * 64
        calldata = "0x095ea7b3" + spender + max_amount

        res = CalldataDecoder.decode_transaction(calldata)
        self.assertTrue(res["is_valid"])
        self.assertEqual(res["function_name"], "approve")
        self.assertGreaterEqual(res["risk_score"], 50)
        self.assertEqual(res["firewall_rule"]["action"], "WARN")
        self.assertTrue(any(f["id"] == "DRAIN-001" for f in res["findings"]))

    def test_nft_set_approval_for_all(self):
        # setApprovalForAll(operator=0xbadc0de..., approved=true)
        operator = "badc0debadc0debadc0debadc0debadc0debadc0de".zfill(64)
        approved = "1".zfill(64)
        calldata = "0xa22cb465" + operator + approved

        res = CalldataDecoder.decode_transaction(calldata)
        self.assertTrue(res["is_valid"])
        self.assertEqual(res["function_name"], "setApprovalForAll")
        self.assertGreaterEqual(res["risk_score"], 60)
        self.assertEqual(res["firewall_rule"]["action"], "BLOCK")
        self.assertTrue(any(f["id"] == "DRAIN-002" for f in res["findings"]))

    def test_permit2_trap(self):
        # permitTransferFrom selector 0x30f28b7a
        calldata = "0x30f28b7a" + ("00" * 64)
        res = CalldataDecoder.decode_transaction(calldata)
        self.assertTrue(res["is_valid"])
        self.assertIn("permit", res["function_name"].lower())
        self.assertGreaterEqual(res["risk_score"], 60)
        self.assertEqual(res["firewall_rule"]["action"], "BLOCK")


if __name__ == "__main__":
    unittest.main()
