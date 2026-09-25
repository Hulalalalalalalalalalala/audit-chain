"""Proof combination, batch verification and interval-proportional export."""

from __future__ import annotations

import builtins
import json
import os
import shutil

from audit_chain import combine_proofs, verify_proof, verify_proofs
from audit_chain.__main__ import main as cli_main
from tests._helpers import AuditTestCase


def _build_history(chain) -> None:
    """30 records for ``t`` (interleaved with ``u``) across three segments."""
    for i in range(10):
        chain.append("t", {"i": i})
        chain.append("u", {"i": i})
    chain.rotate()
    for i in range(10, 20):
        chain.append("t", {"i": i})
        chain.append("u", {"i": i})
    chain.rotate()
    for i in range(20, 30):
        chain.append("t", {"i": i})
        chain.append("u", {"i": i})


class CombineProofsTest(AuditTestCase):
    def test_combined_proof_covers_union_and_verifies(self) -> None:
        _build_history(self.chain)
        left = self.chain.export_range("t", 0, 12)
        right = self.chain.export_range("t", 12, 30)
        combined = combine_proofs(left, right)
        self.assertEqual(combined["start"], 0)
        self.assertEqual(combined["end"], 30)
        result = verify_proof(combined, tenant="t", start=0, end=30)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["count"], 30)

    def test_combined_equals_direct_export(self) -> None:
        _build_history(self.chain)
        combined = combine_proofs(
            self.chain.export_range("t", 0, 12),
            self.chain.export_range("t", 12, 30),
        )
        self.assertEqual(combined, self.chain.export_range("t", 0, 30))

    def test_combine_is_associative(self) -> None:
        _build_history(self.chain)
        a = self.chain.export_range("t", 0, 8)
        b = self.chain.export_range("t", 8, 21)
        c = self.chain.export_range("t", 21, 30)
        left_assoc = combine_proofs(combine_proofs(a, b), c)
        right_assoc = combine_proofs(a, combine_proofs(b, c))
        self.assertEqual(left_assoc, right_assoc)
        self.assertEqual(left_assoc, self.chain.export_range("t", 0, 30))
        self.assertTrue(verify_proof(left_assoc)["ok"])

    def test_combine_across_compacted_segments(self) -> None:
        _build_history(self.chain)
        self.chain.compact(1)
        left = self.chain.export_range("t", 3, 15)
        right = self.chain.export_range("t", 15, 28)
        combined = combine_proofs(left, right)
        self.assertTrue(verify_proof(combined, tenant="t", start=3, end=28)["ok"])
        self.assertEqual(combined, self.chain.export_range("t", 3, 28))

    def test_combine_with_endpoints_on_segment_boundaries(self) -> None:
        _build_history(self.chain)
        self.chain.compact(2)
        left = self.chain.export_range("t", 0, 10)
        right = self.chain.export_range("t", 10, 30)
        combined = combine_proofs(left, right)
        self.assertTrue(verify_proof(combined)["ok"])
        self.assertEqual(combined, self.chain.export_range("t", 0, 30))

    def test_combine_with_empty_prefix_proof(self) -> None:
        empty = self.chain.export_range("t", 0, 0)  # no history yet
        self.append_many("t", 5)
        right = self.chain.export_range("t", 0, 5)
        combined = combine_proofs(empty, right)
        self.assertEqual(combined, right)
        self.assertTrue(verify_proof(combined)["ok"])

    def test_combine_two_empty_proofs(self) -> None:
        left = self.chain.export_range("t", 0, 0)
        right = self.chain.export_range("t", 0, 0)
        combined = combine_proofs(left, right)
        self.assertEqual(combined["count"], 0)
        self.assertTrue(verify_proof(combined)["ok"])

    def test_combine_type_error_for_non_dicts(self) -> None:
        _build_history(self.chain)
        proof = self.chain.export_range("t", 0, 5)
        for bad in ("x", 1, None, ["x"]):
            with self.assertRaises(TypeError):
                combine_proofs(bad, proof)
            with self.assertRaises(TypeError):
                combine_proofs(proof, bad)

    def test_combine_rejects_unverifiable_side(self) -> None:
        _build_history(self.chain)
        left = self.chain.export_range("t", 0, 10)
        right = self.chain.export_range("t", 10, 20)
        for window in right["windows"]:
            for item in window["records"]:
                if item["index"] == 12:
                    item["record"]["payload"] = {"i": 9999}
        with self.assertRaises(ValueError):
            combine_proofs(left, right)
        with self.assertRaises(ValueError):
            combine_proofs({"version": 1}, left)

    def test_combine_rejects_tenant_mismatch(self) -> None:
        _build_history(self.chain)
        left = self.chain.export_range("t", 0, 10)
        right = self.chain.export_range("u", 10, 20)
        with self.assertRaises(ValueError):
            combine_proofs(left, right)

    def test_combine_rejects_gap_overlap_and_reversed(self) -> None:
        _build_history(self.chain)
        a = self.chain.export_range("t", 0, 10)
        b = self.chain.export_range("t", 10, 20)
        gap = self.chain.export_range("t", 12, 22)
        overlap = self.chain.export_range("t", 5, 15)
        with self.assertRaises(ValueError):
            combine_proofs(a, gap)
        with self.assertRaises(ValueError):
            combine_proofs(a, overlap)
        with self.assertRaises(ValueError):
            combine_proofs(b, a)

    def test_damage_outside_interval_still_verifies_after_combine(self) -> None:
        _build_history(self.chain)
        combined = combine_proofs(
            self.chain.export_range("t", 5, 10),
            self.chain.export_range("t", 10, 25),
        )
        # Corrupt a sealed record at t index 2 (outside [5, 25)) with an
        # equal-length rewrite; the combined proof is offline data.
        first = self.segment_files()[0]
        data = self.raw_bytes(first)
        target = json.dumps({"i": 2}, separators=(",", ":"), sort_keys=True)
        forged = json.dumps({"i": 9}, separators=(",", ":"), sort_keys=True)
        self.assertEqual(len(target), len(forged))
        self.write_raw(data.replace(target.encode(), forged.encode(), 1), first)
        result = verify_proof(combined, tenant="t", start=5, end=25)
        self.assertTrue(result["ok"], result)

    def test_combined_proof_survives_log_compaction_and_loss(self) -> None:
        _build_history(self.chain)
        combined = combine_proofs(
            self.chain.export_range("t", 0, 15),
            self.chain.export_range("t", 15, 30),
        )
        self.chain.compact(1)
        shutil.rmtree(self.path)  # the log itself is discarded
        self.assertTrue(verify_proof(combined)["ok"])

    def test_combined_proof_passes_cli_verify_proof(self) -> None:
        _build_history(self.chain)
        combined = combine_proofs(
            self.chain.export_range("t", 4, 18),
            self.chain.export_range("t", 18, 30),
        )
        proof_file = os.path.join(self._tmp, "proof.json")
        with open(proof_file, "w", encoding="utf-8") as handle:
            json.dump(combined, handle)
        self.assertEqual(cli_main(["verify-proof", proof_file]), 0)


class VerifyProofsBatchTest(AuditTestCase):
    def test_batch_verdicts_ordered_and_shaped_like_chain_verify(self) -> None:
        _build_history(self.chain)
        proofs = [
            self.chain.export_range("t", 0, 10),
            self.chain.export_range("t", 10, 25),
            self.chain.export_range("u", 0, 20),
        ]
        verdicts = verify_proofs(proofs)
        self.assertEqual(len(verdicts), len(proofs))
        for verdict, proof in zip(verdicts, proofs):
            self.assertEqual(set(verdict), {"ok", "first_bad", "count"})
            self.assertTrue(verdict["ok"], verdict)
            self.assertEqual(verdict["first_bad"], -1)
            self.assertEqual(verdict["count"], proof["end"] - proof["start"])
        self.assertEqual(set(self.chain.verify("t")), {"ok", "first_bad", "count"})

    def test_batch_tampered_member_does_not_abort(self) -> None:
        _build_history(self.chain)
        proofs = [
            self.chain.export_range("t", 0, 10),
            self.chain.export_range("t", 10, 20),
            self.chain.export_range("t", 20, 30),
        ]
        for window in proofs[1]["windows"]:
            for item in window["records"]:
                if item["index"] == 14:
                    item["record"]["payload"] = {"i": 9999}
        verdicts = verify_proofs(proofs)
        self.assertTrue(verdicts[0]["ok"])
        self.assertFalse(verdicts[1]["ok"])
        self.assertEqual(verdicts[1]["first_bad"], 14)
        self.assertEqual(verdicts[1]["count"], 10)
        self.assertTrue(verdicts[2]["ok"])

    def test_batch_reports_malformed_member_as_corrupt(self) -> None:
        _build_history(self.chain)
        good = self.chain.export_range("t", 0, 5)
        verdicts = verify_proofs([good, {"version": 1, "tenant": "t"}])
        self.assertTrue(verdicts[0]["ok"])
        self.assertFalse(verdicts[1]["ok"])

    def test_batch_empty_list_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            verify_proofs([])

    def test_batch_non_dict_element_raises_type_error(self) -> None:
        _build_history(self.chain)
        proof = self.chain.export_range("t", 0, 5)
        with self.assertRaises(TypeError):
            verify_proofs([proof, "not a proof"])
        with self.assertRaises(TypeError):
            verify_proofs([None])


class ExportRangeCostTest(AuditTestCase):
    def test_export_with_warm_cache_matches_cold_scan(self) -> None:
        _build_history(self.chain)  # appends/rotates keep the cache warm
        warm = self.chain.export_range("t", 3, 27)
        os.remove(os.path.join(self.path, ".verify-cache"))
        cold = self.chain.export_range("t", 3, 27)
        self.assertEqual(warm, cold)

    def test_export_skips_uninvolved_segments(self) -> None:
        _build_history(self.chain)
        opened: list[str] = []
        real_open = builtins.open

        def counting_open(file, *args, **kwargs):
            if isinstance(file, (str, bytes, os.PathLike)):
                opened.append(os.fspath(file))
            return real_open(file, *args, **kwargs)

        builtins.open = counting_open
        try:
            proof = self.chain.export_range("t", 21, 25)
        finally:
            builtins.open = real_open
        self.assertTrue(verify_proof(proof)["ok"])
        seg_reads = [
            path for path in opened if os.path.basename(path).startswith("seg-")
        ]
        # Only the active segment holds t records 21..24; the two sealed
        # segments are never opened, however long the history grows.
        self.assertEqual(len(seg_reads), 1, seg_reads)

    def test_export_ignores_tampered_cache(self) -> None:
        _build_history(self.chain)
        with open(os.path.join(self.path, ".verify-cache"), "ab") as handle:
            handle.write(b"garbage")
        proof = self.chain.export_range("t", 3, 27)
        self.assertTrue(verify_proof(proof, tenant="t", start=3, end=27)["ok"])
