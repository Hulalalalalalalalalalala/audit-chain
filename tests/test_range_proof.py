"""Range export: offline proofs, boundary validation, isolation."""

from __future__ import annotations

import json

from audit_chain import Chain, verify_range_proof
from audit_chain import record as rec
from tests._helpers import AuditTestCase


class RangeProofTest(AuditTestCase):
    # ------------------------------------------------------------------
    # Happy paths
    # ------------------------------------------------------------------

    def test_full_range_on_file_layout(self) -> None:
        self.append_many("t", 8)
        proof = self.chain.export_range("t", 0, 8)
        verdict = verify_range_proof(proof)
        self.assertTrue(verdict["ok"], verdict)
        self.assertEqual(verdict["count"], 8)
        self.assertEqual(
            [e["record"]["payload"]["i"] for e in proof["records"]],
            list(range(8)),
        )
        self.assertEqual(proof["start_prev"], "")
        self.assertEqual(proof["end_digest"], self.chain.head("t"))

    def test_cross_segment_range(self) -> None:
        self.append_many("t", 10)
        self.chain.rotate()
        self.append_many("t", 10, start=10)
        proof = self.chain.export_range("t", 3, 17)
        verdict = verify_range_proof(proof)
        self.assertTrue(verdict["ok"], verdict)
        self.assertEqual(
            [e["index"] for e in proof["records"]], list(range(3, 17))
        )
        self.assertEqual(
            [e["record"]["payload"]["i"] for e in proof["records"]],
            list(range(3, 17)),
        )
        # Range straddles at least the two segment windows.
        self.assertGreaterEqual(len({e["window"] for e in proof["records"]}), 2)
        # The boundary anchor is the digest of index 2.
        self.assertEqual(proof["start_prev"], self.chain.entries("t")[2]["digest"])

    def test_compacted_store_range(self) -> None:
        self.append_many("t", 6)
        self.chain.rotate()
        self.append_many("t", 6, start=6)
        self.chain.rotate()
        self.append_many("t", 4, start=12)
        self.chain.compact(1)
        proof = self.chain.export_range("t", 2, 15)
        verdict = verify_range_proof(proof)
        self.assertTrue(verdict["ok"], verdict)
        self.assertEqual(
            [e["record"]["payload"]["i"] for e in proof["records"]],
            list(range(2, 15)),
        )

    def test_single_record_range(self) -> None:
        self.append_many("t", 5)
        proof = self.chain.export_range("t", 2, 3)
        verdict = verify_range_proof(proof)
        self.assertTrue(verdict["ok"], verdict)
        self.assertEqual(verdict["count"], 1)
        self.assertEqual(proof["records"][0]["record"]["payload"], {"i": 2})

    # ------------------------------------------------------------------
    # Boundary validation
    # ------------------------------------------------------------------

    def test_illegal_ranges_raise_value_error(self) -> None:
        self.append_many("t", 5)
        bad_ranges = [
            (0, 0),    # empty
            (3, 3),    # empty in the middle
            (3, 2),    # reversed
            (-1, 2),   # negative start
            (0, -1),   # negative end
            (0, 6),    # end past count
            (5, 7),    # start in range, end past count
            (6, 7),    # start past count
        ]
        for start, end in bad_ranges:
            with self.assertRaises(ValueError):
                self.chain.export_range("t", start, end)

    def test_non_integer_bounds_raise(self) -> None:
        self.append_many("t", 3)
        for start, end in [(1.0, 2), (0, 2.0), ("0", 2), (0, True)]:
            with self.assertRaises((ValueError, TypeError)):
                self.chain.export_range("t", start, end)

    def test_empty_history_tenant(self) -> None:
        self.append_many("t", 3)
        # A tenant with no records is an empty history: any non-empty range is
        # out of range and therefore a ValueError; a verified empty interval
        # is itself illegal, so there is no legal proof for an empty tenant.
        with self.assertRaises(ValueError):
            self.chain.export_range("ghost", 0, 1)
        # But verify/entries on it still describe the empty history.
        self.assertEqual(
            self.chain.verify("ghost"),
            {"count": 0, "first_bad": -1, "ok": True},
        )
        self.assertEqual(self.chain.entries("ghost"), [])
        self.assertIsNone(self.chain.head("ghost"))

    # ------------------------------------------------------------------
    # Proof carries no out-of-range material
    # ------------------------------------------------------------------

    def test_proof_excludes_out_of_range_payloads(self) -> None:
        self.chain.append("a", {"secret": "AAA"})
        self.chain.append("b", {"secret": "BBB"})
        self.chain.rotate()
        self.chain.append("a", {"secret": "CCC"})
        proof = self.chain.export_range("a", 0, 2)
        blob = json.dumps(proof)
        self.assertIn("AAA", blob)
        self.assertIn("CCC", blob)
        self.assertNotIn("BBB", blob)

    def test_proof_excludes_indexes_outside_interval(self) -> None:
        for i in range(10):
            self.chain.append("t", {"i": i})
            self.chain.append("u", {"i": i})
        proof = self.chain.export_range("t", 3, 7)
        self.assertEqual(
            [e["record"]["payload"]["i"] for e in proof["records"]],
            [3, 4, 5, 6],
        )
        blob = json.dumps(proof)
        self.assertNotIn('"tenant":"u"', blob)

    # ------------------------------------------------------------------
    # Independent verification rejects tampering
    # ------------------------------------------------------------------

    def _build(self, n_a: int = 10, n_b: int = 10) -> None:
        for i in range(n_a):
            self.chain.append("a", {"i": i})
        for i in range(n_b):
            self.chain.append("b", {"i": i})
        self.chain.rotate()
        for i in range(n_a, n_a + 3):
            self.chain.append("a", {"i": i})

    def test_tampered_payload_fails(self) -> None:
        self._build()
        proof = self.chain.export_range("a", 2, 12)
        proof["records"][3]["record"]["payload"] = {"i": 999}
        verdict = verify_range_proof(proof)
        self.assertFalse(verdict["ok"])
        self.assertEqual(verdict["first_bad"], proof["records"][3]["index"])

    def test_tampered_digest_fails(self) -> None:
        self._build()
        proof = self.chain.export_range("a", 0, 13)
        proof["records"][1]["record"]["digest"] = "0" * 64
        self.assertFalse(verify_range_proof(proof)["ok"])

    def test_forged_start_prev_fails(self) -> None:
        self._build()
        proof = self.chain.export_range("a", 5, 10)
        proof["start_prev"] = "f" * 64
        self.assertFalse(verify_range_proof(proof)["ok"])

    def test_window_link_commit_size_anchor_tamper_fails(self) -> None:
        self._build()
        for key in ("link", "commit", "sha256"):
            proof = self.chain.export_range("a", 2, 12)
            proof["windows"][0][key] = "0" * 64
            self.assertFalse(verify_range_proof(proof)["ok"], key)
        proof = self.chain.export_range("a", 2, 12)
        proof["windows"][0]["size"] += 7
        self.assertFalse(verify_range_proof(proof)["ok"])

    def test_record_reorder_and_duplicate_fail(self) -> None:
        self._build()
        proof = self.chain.export_range("a", 0, 13)
        first, last = proof["records"][0], proof["records"][-1]
        proof["records"][0] = dict(last)
        proof["records"][-1] = dict(first)
        self.assertFalse(verify_range_proof(proof)["ok"])

        proof = self.chain.export_range("a", 0, 13)
        proof["records"].append(dict(proof["records"][0]))
        self.assertFalse(verify_range_proof(proof)["ok"])

    def test_malformed_proof_raises_value_error(self) -> None:
        for bad in [
            None,
            {"version": 2},
            {"version": 1},
            "not-an-object",
            [],
        ]:
            with self.assertRaises(ValueError):
                verify_range_proof(bad)

    # ------------------------------------------------------------------
    # Damage outside the range does not change the in-range conclusion
    # ------------------------------------------------------------------

    def test_damage_outside_range_is_irrelevant(self) -> None:
        self._build()
        # Corrupt one b record by replacing its digest hex (valid JSON line,
        # broken chain): b is entirely outside a's range.
        first = self.segment_files()[0]
        path = self.path + "/" + first
        with open(path, "rb") as handle:
            lines = handle.read().split(b"\n")
        target = None
        for idx, line in enumerate(lines):
            if not line:
                continue
            obj = json.loads(line)
            if obj.get("tenant") == "b" and obj["payload"] == {"i": 4}:
                obj["digest"] = ("1" if obj["digest"][0] != "1" else "0") + obj["digest"][1:]
                lines[idx] = json.dumps(
                    obj, sort_keys=True, separators=(",", ":")
                ).encode()
                target = idx
                break
        self.assertIsNotNone(target)
        with open(path, "wb") as handle:
            handle.write(b"\n".join(lines))

        proof = self.chain.export_range("a", 0, 13)
        self.assertTrue(verify_range_proof(proof)["ok"])
        # b's own chain really is broken, at the global index 4.
        result_b = self.chain.verify("b")
        self.assertFalse(result_b["ok"])
        self.assertEqual(result_b["first_bad"], 4)

    def test_range_after_damage_still_concludes(self) -> None:
        self._build()
        # Damage b index 2; a proof for b indices strictly after the damage
        # still verifies (the damaged record is outside that interval).
        first = self.segment_files()[0]
        path = self.path + "/" + first
        with open(path, "rb") as handle:
            lines = handle.read().split(b"\n")
        for idx, line in enumerate(lines):
            if not line:
                continue
            obj = json.loads(line)
            if obj.get("tenant") == "b" and obj["payload"] == {"i": 2}:
                obj["digest"] = "1" + obj["digest"][1:]
                lines[idx] = json.dumps(
                    obj, sort_keys=True, separators=(",", ":")
                ).encode()
                break
        with open(path, "wb") as handle:
            handle.write(b"\n".join(lines))
        proof = self.chain.export_range("b", 5, 10)
        self.assertTrue(verify_range_proof(proof)["ok"])
        # But a range covering the damage produces a proof that does not
        # verify (the broken link is reported inside the range).
        covering = self.chain.export_range("b", 0, 10)
        verdict = verify_range_proof(covering)
        self.assertFalse(verdict["ok"])
        self.assertEqual(verdict["first_bad"], 2)

    def test_garbled_foreign_window_does_not_abort_valid_range(self) -> None:
        # A syntactically destroyed line belonging to another tenant inside a
        # sealed window must not stop export of a different tenant's range.
        self._build()
        first = self.segment_files()[0]
        path = self.path + "/" + first
        with open(path, "rb") as handle:
            lines = handle.read().split(b"\n")
        for idx, line in enumerate(lines):
            if line:
                obj = json.loads(line)
                if obj.get("tenant") == "b":
                    lines[idx] = b"{garbage-foreign-line"
                    break
        with open(path, "wb") as handle:
            handle.write(b"\n".join(lines))
        proof = self.chain.export_range("a", 0, 13)
        self.assertTrue(verify_range_proof(proof)["ok"])

    def test_physical_half_line_raises_for_export_too(self) -> None:
        self.append_many("t", 4)
        with open(self.path, "ab") as handle:
            handle.write(b'{"digest":"ab')
        # The half-line is never silently skipped; export raises like verify.
        with self.assertRaises(ValueError):
            self.chain.export_range("t", 0, 4)
        self.chain.recover()
        proof = self.chain.export_range("t", 0, 4)
        self.assertTrue(verify_range_proof(proof)["ok"])
