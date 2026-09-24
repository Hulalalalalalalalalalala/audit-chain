"""Offline range proofs: export, independent verification and boundaries."""

from __future__ import annotations

import copy
import json
import os

from audit_chain import verify_proof
from audit_chain import record as rec
from tests._helpers import AuditTestCase


class RangeProofTest(AuditTestCase):
    def _multi_segment(self) -> None:
        for i in range(20):
            self.chain.append("t", {"i": i})
            if i % 2 == 0:
                self.chain.append("u", {"i": i})
        self.chain.rotate()
        for i in range(20, 35):
            self.chain.append("t", {"i": i})
            if i % 2 == 0:
                self.chain.append("u", {"i": i})
        self.chain.rotate()
        for i in range(35, 45):
            self.chain.append("t", {"i": i})
        self.chain.compact(2)

    def test_full_range_across_segments_verifies_offline(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 0, 45)
        result = verify_proof(proof, tenant="t", start=0, end=45)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["first_bad"], -1)
        # The cross-segment window chain is present and strictly increasing.
        seqs = [window["seq"] for window in proof["windows"]]
        self.assertEqual(seqs, sorted(set(seqs)))
        self.assertGreaterEqual(len(seqs), 2)

    def test_middle_range_linking_material_only(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 10, 30)
        result = verify_proof(proof, tenant="t", start=10, end=30)
        self.assertTrue(result["ok"], result)
        # Exactly 20 interval records, with no out-of-interval payload.
        exported = [
            item
            for window in proof["windows"]
            for item in window["records"]
        ]
        self.assertEqual(len(exported), 20)
        self.assertEqual([item["index"] for item in exported], list(range(10, 30)))
        for item in exported:
            self.assertEqual(item["record"]["tenant"], "t")
        # prev anchors at index 10's actual predecessor digest.
        entries = self.chain.entries("t")
        self.assertEqual(proof["prev"], entries[9]["digest"])

    def test_range_starting_at_zero_anchors_on_empty_string(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 0, 5)
        self.assertEqual(proof["prev"], "")
        self.assertTrue(verify_proof(proof)["ok"])

    def test_illegal_ranges_raise_value_error(self) -> None:
        self._multi_segment()
        for start, end in (
            (5, 5),     # empty
            (0, 0),     # empty for a tenant with history
            (9, 4),     # reversed
            (0, 46),    # past end
            (45, 46),   # past end
            (-1, 3),    # negative
            (3, -1),
        ):
            with self.assertRaises(ValueError):
                self.chain.export_range("t", start, end)

    def test_unknown_tenant_treated_as_empty_history(self) -> None:
        self._multi_segment()
        # Tenant with no records: the empty-history interval is a conclusion.
        proof = self.chain.export_range("nobody", 0, 0)
        self.assertEqual(proof["count"], 0)
        self.assertEqual(proof["windows"], [])
        self.assertTrue(verify_proof(proof, tenant="nobody")["ok"])
        # Any non-empty request against the empty history is out of bounds.
        with self.assertRaises(ValueError):
            self.chain.export_range("nobody", 0, 1)

    def test_missing_log_tenant_has_empty_history(self) -> None:
        chain = type(self.chain)(os.path.join(self._tmp, "absent"))
        proof = chain.export_range("z", 0, 0)
        self.assertTrue(verify_proof(proof)["ok"])
        with self.assertRaises(ValueError):
            chain.export_range("z", 0, 1)

    def test_damage_outside_interval_does_not_change_conclusion(self) -> None:
        self._multi_segment()
        # Corrupt a sealed record at t index 2 (outside [10, 40)) with an
        # equal-length rewrite so the window keeps its byte size.
        first = self.segment_files()[0]
        data = self.raw_bytes(first)
        target = json.dumps({"i": 2}, separators=(",", ":"), sort_keys=True)
        forged = json.dumps({"i": 9}, separators=(",", ":"), sort_keys=True)
        self.assertEqual(len(target), len(forged))
        # The first {"i":2} line in seg0 belongs to t (t2 precedes u2).
        self.write_raw(data.replace(target.encode(), forged.encode(), 1), first)

        proof = self.chain.export_range("t", 10, 40)
        result = verify_proof(proof, tenant="t", start=10, end=40)
        self.assertTrue(result["ok"], result)
        # The damaged record's payload is not present in the proof.
        serialized = json.dumps(proof)
        self.assertNotIn('"i": 9', serialized)
        self.assertNotIn('"i":9', serialized)

    def test_damage_inside_interval_is_rejected_with_first_bad(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 10, 20)
        # Mutate the payload of record index 15 without touching links.
        for window in proof["windows"]:
            for item in window["records"]:
                if item["index"] == 15:
                    item["record"]["payload"] = {"i": 9999}
        result = verify_proof(proof)
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"], 15)

    def test_broken_link_inside_interval_is_rejected(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 10, 20)
        for window in proof["windows"]:
            for item in window["records"]:
                if item["index"] == 12:
                    item["record"]["prev"] = "0" * 64
        result = verify_proof(proof)
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"], 12)

    def test_wrong_tenant_binding_fails(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 0, 5)
        with self.assertRaises(ValueError):
            verify_proof(proof, tenant="u")

    def test_reordered_window_chain_is_rejected(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 0, 45)
        proof["windows"][0]["seq"], proof["windows"][1]["seq"] = (
            proof["windows"][1]["seq"],
            proof["windows"][0]["seq"],
        )
        self.assertFalse(verify_proof(proof)["ok"])

    def test_record_past_anchored_window_is_rejected(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 0, 5)
        window = proof["windows"][0]
        window["records"][0]["offset"] = window["size"] + 10
        result = verify_proof(proof)
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"], 0)

    def test_proof_is_json_serialisable_and_shape_stable(self) -> None:
        self.append_many("t", 3)
        proof = self.chain.export_range("t", 0, 3)
        encoded = json.dumps(proof)
        again = json.loads(encoded)
        self.assertTrue(verify_proof(again)["ok"])
        self.assertEqual(
            set(again),
            {"version", "tenant", "start", "end", "count", "prev", "windows"},
        )

    def test_independent_reader_uses_public_digest_only(self) -> None:
        # The verifier must succeed using only the record format's digest:
        # rebuild every expected digest manually.
        self._multi_segment()
        proof = self.chain.export_range("t", 5, 15)
        expected_prev = proof["prev"]
        for window in proof["windows"]:
            for item in window["records"]:
                record = item["record"]
                self.assertEqual(record["prev"], expected_prev)
                expected_prev = rec.digest(record["prev"], record["payload"])
                self.assertEqual(record["digest"], expected_prev)
