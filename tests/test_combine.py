"""Proof splicing (combine_proofs) and batch verification (verify_proofs)."""

from __future__ import annotations

import copy
import json

from audit_chain import combine_proofs, verify_proof, verify_proofs
from tests._helpers import AuditTestCase


class CombineProofsTest(AuditTestCase):
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

    def test_combine_two_contiguous_proofs_covers_the_union(self) -> None:
        self._multi_segment()
        left = self.chain.export_range("t", 0, 20)
        right = self.chain.export_range("t", 20, 45)
        combined = combine_proofs(left, right)
        result = verify_proof(combined, tenant="t", start=0, end=45)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["first_bad"], -1)
        self.assertEqual(result["count"], 45)
        self.assertEqual(combined["start"], 0)
        self.assertEqual(combined["end"], 45)
        self.assertEqual(combined["tenant"], "t")
        self.assertEqual(combined["prev"], left["prev"])
        exported = [
            item
            for window in combined["windows"]
            for item in window["records"]
        ]
        self.assertEqual([item["index"] for item in exported], list(range(0, 45)))

    def test_combine_three_is_associative_and_consistent(self) -> None:
        self._multi_segment()
        p1 = self.chain.export_range("t", 0, 15)
        p2 = self.chain.export_range("t", 15, 30)
        p3 = self.chain.export_range("t", 30, 45)
        left_assoc = combine_proofs(combine_proofs(p1, p2), p3)
        right_assoc = combine_proofs(p1, combine_proofs(p2, p3))
        r_left = verify_proof(left_assoc, tenant="t", start=0, end=45)
        r_right = verify_proof(right_assoc, tenant="t", start=0, end=45)
        self.assertTrue(r_left["ok"])
        self.assertTrue(r_right["ok"])
        self.assertEqual(r_left, r_right)
        # Same conclusion as a single fresh full-range export.
        fresh = verify_proof(
            self.chain.export_range("t", 0, 45), tenant="t", start=0, end=45
        )
        self.assertEqual(
            (r_left["ok"], r_left["first_bad"], r_left["count"]),
            (fresh["ok"], fresh["first_bad"], fresh["count"]),
        )

    def test_combine_split_inside_one_byte_window(self) -> None:
        # Two adjacent slices of one physical log file splice into a proof
        # that covers and verifies the whole union (whether the exporter kept
        # one shared anchor or two narrowed ones).
        self.append_many("s", 12)
        combined = combine_proofs(
            self.chain.export_range("s", 0, 5),
            self.chain.export_range("s", 5, 12),
        )
        result = verify_proof(combined, tenant="s", start=0, end=12)
        self.assertTrue(result["ok"], result)
        exported = [
            item["index"]
            for window in combined["windows"]
            for item in window["records"]
        ]
        self.assertEqual(exported, list(range(12)))

    def test_combine_split_at_a_segment_boundary(self) -> None:
        self._multi_segment()
        combined = combine_proofs(
            self.chain.export_range("t", 0, 20),
            self.chain.export_range("t", 20, 45),
        )
        # Windows from both sides survive, with a strictly increasing chain.
        seqs = [window["seq"] for window in combined["windows"]]
        self.assertEqual(seqs, sorted(set(seqs)))
        self.assertGreaterEqual(len(seqs), 2)

    def test_combine_does_not_mutate_its_inputs(self) -> None:
        self._multi_segment()
        left = self.chain.export_range("t", 0, 20)
        right = self.chain.export_range("t", 20, 45)
        left_before = copy.deepcopy(left)
        right_before = copy.deepcopy(right)
        combine_proofs(left, right)
        self.assertEqual(left, left_before)
        self.assertEqual(right, right_before)

    def test_combine_with_empty_proofs(self) -> None:
        # The empty-history conclusion for the same tenant, exported before
        # any record existed, splices with a later non-empty proof.
        empty = self.chain.export_range("t", 0, 0)
        self.assertEqual(empty["count"], 0)
        self.append_many("t", 5)
        first = self.chain.export_range("t", 0, 5)
        combined = combine_proofs(empty, first)
        self.assertTrue(verify_proof(combined, start=0, end=5)["ok"])
        self.assertEqual(combined["count"], 5)

    def test_combine_non_dict_argument_is_type_error(self) -> None:
        self.append_many("t", 4)
        good = self.chain.export_range("t", 0, 2)
        for bad in (None, 42, "proof", [good]):
            with self.assertRaises(TypeError):
                combine_proofs(bad, good)
            with self.assertRaises(TypeError):
                combine_proofs(good, bad)

    def test_combine_invalid_side_is_value_error(self) -> None:
        self.append_many("t", 6)
        good = self.chain.export_range("t", 0, 3)
        with self.assertRaises(ValueError):
            combine_proofs(good, {"version": 1, "tenant": "t"})
        with self.assertRaises(ValueError):
            combine_proofs({"version": 1}, good)

    def test_combine_tampered_side_is_value_error(self) -> None:
        self._multi_segment()
        left = self.chain.export_range("t", 0, 20)
        right = self.chain.export_range("t", 20, 45)
        right["windows"][0]["records"][0]["record"]["payload"] = {"i": 9999}
        with self.assertRaises(ValueError):
            combine_proofs(left, right)

    def test_combine_different_tenant_is_value_error(self) -> None:
        self._multi_segment()
        with self.assertRaises(ValueError):
            combine_proofs(
                self.chain.export_range("t", 0, 20),
                self.chain.export_range("u", 0, 10),
            )

    def test_combine_gap_overlap_reversed_are_value_error(self) -> None:
        self._multi_segment()
        with self.assertRaises(ValueError):
            combine_proofs(
                self.chain.export_range("t", 0, 20),
                self.chain.export_range("t", 21, 45),  # gap
            )
        with self.assertRaises(ValueError):
            combine_proofs(
                self.chain.export_range("t", 0, 25),
                self.chain.export_range("t", 20, 45),  # overlap
            )
        with self.assertRaises(ValueError):
            combine_proofs(
                self.chain.export_range("t", 20, 45),
                self.chain.export_range("t", 0, 20),  # reversed
            )

    def test_combined_proof_verifies_after_log_is_discarded(self) -> None:
        import shutil

        self._multi_segment()
        combined = combine_proofs(
            self.chain.export_range("t", 0, 20),
            self.chain.export_range("t", 20, 45),
        )
        shutil.rmtree(self.path)
        self.assertTrue(
            verify_proof(combined, tenant="t", start=0, end=45)["ok"]
        )


class VerifyProofsBatchTest(AuditTestCase):
    def _segmented(self) -> None:
        for i in range(30):
            self.chain.append("t", {"i": i})
        self.chain.rotate()
        for i in range(30, 50):
            self.chain.append("t", {"i": i})

    def test_batch_verdicts_correspond_to_input_order(self) -> None:
        self._segmented()
        proofs = [
            self.chain.export_range("t", 0, 10),
            self.chain.export_range("t", 10, 40),
            self.chain.export_range("t", 40, 50),
        ]
        verdicts = verify_proofs(proofs)
        self.assertEqual(len(verdicts), 3)
        for proof, verdict in zip(proofs, verdicts):
            full = verify_proof(proof)
            # Exactly the on-chain verdict shape: ok / first_bad / count.
            self.assertEqual(set(verdict), {"ok", "first_bad", "count"})
            self.assertEqual(verdict["ok"], full["ok"])
            self.assertEqual(verdict["first_bad"], full["first_bad"])
            self.assertEqual(verdict["count"], full["count"])
        self.assertEqual([v["count"] for v in verdicts], [10, 30, 10])
        self.assertTrue(all(v["ok"] for v in verdicts))

    def test_batch_count_is_records_covered_and_bad_is_global(self) -> None:
        self._segmented()
        damaged = self.chain.export_range("t", 30, 50)
        damaged["windows"][0]["records"][2]["record"]["payload"] = {"i": -7}
        verdicts = verify_proofs([damaged])
        self.assertFalse(verdicts[0]["ok"])
        self.assertEqual(verdicts[0]["count"], 20)
        # Slot 2 of [30, 50) is global tenant index 32.
        self.assertEqual(verdicts[0]["first_bad"], 32)

    def test_batch_tampered_element_does_not_stop_the_batch(self) -> None:
        self._segmented()
        bad = self.chain.export_range("t", 0, 10)
        bad["windows"][0]["records"][4]["record"]["prev"] = "0" * 64
        malformed = {"version": 1, "tenant": "t"}
        good = self.chain.export_range("t", 40, 50)
        verdicts = verify_proofs([good, bad, malformed, good])
        self.assertTrue(verdicts[0]["ok"])
        self.assertFalse(verdicts[1]["ok"])
        self.assertEqual(verdicts[1]["first_bad"], 4)
        self.assertFalse(verdicts[2]["ok"])
        self.assertEqual(set(verdicts[2]), {"ok", "first_bad", "count"})
        self.assertTrue(verdicts[3]["ok"])
        # The bad verdict still has the on-chain verdict shape.
        self.assertEqual(set(verdicts[1]), {"ok", "first_bad", "count"})

    def test_batch_empty_list_is_value_error(self) -> None:
        with self.assertRaises(ValueError):
            verify_proofs([])

    def test_batch_argument_and_element_types(self) -> None:
        self.append_many("t", 3)
        good = self.chain.export_range("t", 0, 3)
        with self.assertRaises(TypeError):
            verify_proofs(good)
        with self.assertRaises(TypeError):
            verify_proofs((good,))
        with self.assertRaises(TypeError):
            verify_proofs([good, "not-a-proof"])
        with self.assertRaises(TypeError):
            verify_proofs([good, None])

    def test_batch_of_combined_proofs(self) -> None:
        self._segmented()
        combined = combine_proofs(
            self.chain.export_range("t", 0, 25),
            self.chain.export_range("t", 25, 50),
        )
        verdicts = verify_proofs([combined])
        self.assertTrue(verdicts[0]["ok"])
        self.assertEqual(verdicts[0]["count"], 50)
