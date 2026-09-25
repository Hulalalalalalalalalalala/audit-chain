"""Incremental proof extension (extend_proof) onto the current prefix."""

from __future__ import annotations

import hashlib
import json
import os

from audit_chain import Chain, combine_proofs, extend_proof, verify_proof, verify_proofs
from audit_chain import record as rec
from tests._helpers import AuditTestCase


class _HashMeter:
    """Counts bytes fed to sha256 (same shape as test_export_cost.py)."""

    def __init__(self) -> None:
        self.bytes = 0
        self._real = hashlib.sha256

    def install(self) -> None:
        real = self._real
        meter = self

        def counting_sha256(data: bytes = b""):
            digest = real(data)
            meter.bytes += len(data)

            class _H:
                def update(self_inner, chunk: bytes) -> None:
                    meter.bytes += len(chunk)
                    digest.update(chunk)

                def hexdigest(self_inner) -> str:
                    return digest.hexdigest()

                def copy(self_inner):
                    return self_inner

            return _H()

        hashlib.sha256 = counting_sha256

    def remove(self) -> None:
        hashlib.sha256 = self._real


class ExtendProofTest(AuditTestCase):
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

    def _verdict3(self, proof: dict) -> tuple:
        result = verify_proof(proof)
        return (result["ok"], result["first_bad"], result["count"])

    def test_extend_picks_up_new_records(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 0, 20)
        self.append_many("t", 5, start=45)

        extended = self.chain.extend_proof(proof)
        self.assertEqual(extended["start"], 0)
        self.assertEqual(extended["end"], 50)
        self.assertEqual(extended["count"], 50)
        self.assertEqual(extended["tenant"], "t")
        self.assertEqual(extended["prev"], proof["prev"])
        result = verify_proof(extended, tenant="t", start=0, end=50)
        self.assertTrue(result["ok"], result)
        exported = [
            item for window in extended["windows"] for item in window["records"]
        ]
        self.assertEqual([item["index"] for item in exported], list(range(50)))
        # Same conclusion as a fresh export of the full prefix.
        fresh = self.chain.export_range("t", 0, 50)
        self.assertEqual(self._verdict3(extended), self._verdict3(fresh))

    def test_extend_mid_interval_keeps_start(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 10, 30)
        self.append_many("t", 3, start=45)
        extended = self.chain.extend_proof(proof)
        self.assertEqual(extended["start"], 10)
        self.assertEqual(extended["end"], 48)
        self.assertTrue(verify_proof(extended, tenant="t", start=10, end=48)["ok"])
        exported = [
            item for window in extended["windows"] for item in window["records"]
        ]
        self.assertEqual([item["index"] for item in exported], list(range(10, 48)))
        # No out-of-interval payload leaves the store.
        for item in exported:
            self.assertEqual(item["record"]["tenant"], "t")

    def test_no_new_records_returns_equivalent_proof(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 10, 45)
        extended = self.chain.extend_proof(proof)
        self.assertIsNot(extended, proof)
        self.assertEqual(extended, proof)
        # The offline conclusion is unchanged.
        self.assertEqual(self._verdict3(extended), self._verdict3(proof))
        # The input was not mutated.
        self.assertTrue(verify_proof(proof, tenant="t", start=10, end=45)["ok"])

    def test_empty_proof_extended_onto_new_history(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("nobody", 0, 0)
        self.assertEqual(proof["count"], 0)
        self.append_many("nobody", 4, start=100)
        extended = self.chain.extend_proof(proof)
        self.assertEqual(extended["start"], 0)
        self.assertEqual(extended["end"], 4)
        self.assertEqual(extended["count"], 4)
        self.assertTrue(verify_proof(extended, tenant="nobody", start=0, end=4)["ok"])

    def test_empty_proof_stays_empty_without_records(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("nobody", 0, 0)
        extended = self.chain.extend_proof(proof)
        self.assertEqual(extended, proof)
        self.assertTrue(verify_proof(extended, tenant="nobody")["ok"])

    def test_module_level_entry_point(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 0, 40)
        self.append_many("t", 2, start=45)
        extended = extend_proof(proof, self.path)
        self.assertEqual(extended["end"], 47)
        self.assertTrue(verify_proof(extended, tenant="t", start=0, end=47)["ok"])

    def test_non_dict_proof_is_type_error(self) -> None:
        self._multi_segment()
        for bad in (None, 42, "proof", [1, 2], ("x",)):
            with self.assertRaises(TypeError):
                self.chain.extend_proof(bad)
            with self.assertRaises(TypeError):
                extend_proof(bad, self.path)

    def test_tampered_proof_is_value_error(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 10, 20)
        for window in proof["windows"]:
            for item in window["records"]:
                if item["index"] == 15:
                    item["record"]["payload"] = {"i": 9999}
        with self.assertRaises(ValueError):
            self.chain.extend_proof(proof)

    def test_malformed_and_reversed_proof_is_value_error(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 10, 20)
        reversed_proof = dict(proof, start=20, end=10)
        with self.assertRaises(ValueError):
            self.chain.extend_proof(reversed_proof)
        with self.assertRaises(ValueError):
            self.chain.extend_proof({"version": 1})
        with self.assertRaises(ValueError):
            self.chain.extend_proof({})

    def test_end_beyond_intact_prefix_is_value_error(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 0, 45)
        # A different, shorter log for the same tenant: the proof's end lies
        # beyond anything this history can vouch for.
        shorter = Chain(os.path.join(self._tmp, "shorter"))
        for i in range(5):
            shorter.append("t", {"i": i})
        with self.assertRaises(ValueError):
            shorter.extend_proof(proof)
        with self.assertRaises(ValueError):
            extend_proof(proof, os.path.join(self._tmp, "shorter"))

    def test_missing_log_is_file_not_found(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 0, 45)
        absent = Chain(os.path.join(self._tmp, "absent"))
        with self.assertRaises(FileNotFoundError):
            absent.extend_proof(proof)
        with self.assertRaises(FileNotFoundError):
            extend_proof(proof, os.path.join(self._tmp, "absent"))

    def test_corrupt_chain_is_value_error(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 0, 45)
        first = self.segment_files()[0]
        data = self.raw_bytes(first)
        forged = data.replace(b'{"i":36}', b'{"i":39}', 1)
        self.assertNotEqual(data, forged)
        self.write_raw(forged, first)
        with self.assertRaises(ValueError):
            self.chain.extend_proof(proof)

    def test_rewritten_history_same_length_is_value_error(self) -> None:
        self.append_many("t", 6)
        proof = self.chain.export_range("t", 0, 6)
        # Rewrite the whole log with a different but self-consistent chain
        # and drop the verify cache, so only the proof itself can expose it.
        records = []
        prev = ""
        for n in range(6):
            record, line = rec.build_line("t", {"i": 1000 + n}, prev)
            records.append((record, line))
            prev = record["digest"]
        self.write_raw(
            b"".join((line + "\n").encode("utf-8") for _, line in records)
        )
        cache = "." + os.path.basename(self.path) + ".verify-cache"
        os.remove(os.path.join(os.path.dirname(self.path), cache))
        with self.assertRaises(ValueError):
            self.chain.extend_proof(proof)

    def test_extend_across_rotation_compaction_and_archive(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 5, 45)
        self.append_many("t", 5, start=45)
        self.chain.rotate()
        self.append_many("t", 5, start=50)
        self.chain.compact(2)
        archive_dir = os.path.join(self._tmp, "cold")
        self.chain.archive(archive_dir)
        self.append_many("t", 3, start=55)

        extended = self.chain.extend_proof(proof)
        self.assertEqual(extended["start"], 5)
        self.assertEqual(extended["end"], 58)
        result = verify_proof(extended, tenant="t", start=5, end=58)
        self.assertTrue(result["ok"], result)
        fresh = self.chain.export_range("t", 5, 58)
        self.assertEqual(self._verdict3(extended), self._verdict3(fresh))

    def test_batch_and_single_verification_agree_on_extended_proofs(self) -> None:
        self._multi_segment()
        first = self.chain.extend_proof(self.chain.export_range("t", 0, 20))
        self.append_many("t", 4, start=45)
        second = self.chain.extend_proof(self.chain.export_range("t", 10, 30))
        # A tampered sibling does not interrupt the batch.
        tampered = self.chain.export_range("t", 0, 10)
        tampered["windows"][0]["records"][0]["record"]["payload"] = {"i": -1}

        batch = verify_proofs([first, second, tampered])
        self.assertEqual(len(batch), 3)
        for proof, verdict in zip((first, second, tampered), batch):
            single = verify_proof(proof)
            self.assertEqual(
                (verdict["ok"], verdict["first_bad"], verdict["count"]),
                (single["ok"], single["first_bad"], single["count"]),
            )
        self.assertTrue(batch[0]["ok"])
        self.assertTrue(batch[1]["ok"])
        self.assertFalse(batch[2]["ok"])
        self.assertEqual(batch[2]["first_bad"], 0)

    def test_extended_proof_combines_associatively(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 0, 15)
        self.append_many("t", 5, start=45)
        extended = self.chain.extend_proof(proof)  # [0, 50)
        head = self.chain.export_range("t", 0, 10)
        tail = self.chain.export_range("t", 10, 50)
        self.assertEqual(
            self._verdict3(combine_proofs(head, tail)),
            self._verdict3(extended),
        )

    def test_extend_is_json_serialisable_same_shape(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 0, 40)
        self.append_many("t", 2, start=45)
        extended = self.chain.extend_proof(proof)
        again = json.loads(json.dumps(extended))
        self.assertTrue(verify_proof(again)["ok"])
        self.assertEqual(
            set(again),
            {"version", "tenant", "start", "end", "count", "prev", "windows"},
        )

    def test_extend_is_read_only_and_reextendable(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 0, 40)
        self.append_many("t", 2, start=45)
        before = sorted(os.listdir(self.path))
        extended = self.chain.extend_proof(proof)
        # No temporary files, no half-written state: the store is untouched.
        self.assertEqual(sorted(os.listdir(self.path)), before)
        # Re-extending is unaffected and gives the same conclusion.
        again = self.chain.extend_proof(proof)
        self.assertEqual(again, extended)
        self.assertTrue(verify_proof(again)["ok"])

    def test_extend_cost_tracks_increment_not_history(self) -> None:        # 6000 sealed records plus a growing active tail; the proof reaches
        # near the tip, so the increment is small even though the history is
        # large.
        self.append_many("t", 6000)
        self.chain.rotate()
        self.append_many("t", 100, start=6000)
        self.assertTrue(self.chain.verify("t")["ok"])  # warm the cache
        proof = self.chain.export_range("t", 6050, 6100)
        self.append_many("t", 50, start=6100)
        total = os.path.getsize(os.path.join(self.path, self.segment_files()[0]))

        meter = _HashMeter()
        meter.install()
        try:
            extended = self.chain.extend_proof(proof)
            hashed = meter.bytes
        finally:
            meter.remove()

        self.assertEqual(extended["end"], 6150)
        self.assertTrue(verify_proof(extended)["ok"])
        # The proof plus the increment are ~150 small records; the sealed
        # history (a far larger segment) is never re-hashed.
        self.assertLess(hashed, total // 10)
