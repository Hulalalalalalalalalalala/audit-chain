"""Window-sharded streaming export (export_shards) and streaming
verification (verify_proof_stream / ShardVerifier)."""

from __future__ import annotations

import copy
import gc
import json
import os
import threading
from functools import reduce

from audit_chain import (
    ShardVerifier,
    combine_proofs,
    verify_proof,
    verify_proof_stream,
    verify_proofs,
)
from audit_chain.record import digest
from tests._helpers import AuditTestCase
from tests.test_export_cost import _HashMeter, _ReadMeter


class ExportShardsTest(AuditTestCase):
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

    def test_shards_tile_the_interval_and_each_verifies(self) -> None:
        self._multi_segment()
        shards = list(self.chain.export_shards("t", 0, 45, 7))
        self.assertEqual(len(shards), 7)  # ceil(45 / 7)
        self.assertEqual(shards[0]["start"], 0)
        self.assertEqual(shards[-1]["end"], 45)
        for left, right in zip(shards, shards[1:]):
            # End to start, no gap, no overlap.
            self.assertEqual(left["end"], right["start"])
        for shard in shards:
            self.assertLessEqual(shard["end"] - shard["start"], 7)
            self.assertEqual(shard["count"], 45)
            self.assertEqual(shard["tenant"], "t")
            verdict = verify_proof(shard)
            self.assertTrue(verdict["ok"], verdict)
            exported = [
                item["index"]
                for window in shard["windows"]
                for item in window["records"]
            ]
            self.assertEqual(
                exported, list(range(shard["start"], shard["end"]))
            )

    def test_window_larger_than_interval_yields_one_shard(self) -> None:
        self._multi_segment()
        shards = list(self.chain.export_shards("t", 3, 40, 1000))
        self.assertEqual(len(shards), 1)
        self.assertEqual((shards[0]["start"], shards[0]["end"]), (3, 40))
        self.assertTrue(verify_proof(shards[0])["ok"])

    def test_window_of_one_yields_single_record_shards(self) -> None:
        self.append_many("t", 5)
        shards = list(self.chain.export_shards("t", 0, 5, 1))
        self.assertEqual(len(shards), 5)
        for index, shard in enumerate(shards):
            self.assertEqual((shard["start"], shard["end"]), (index, index + 1))
            self.assertTrue(verify_proof(shard)["ok"])

    def test_shards_combine_back_to_the_one_shot_conclusion(self) -> None:
        self._multi_segment()
        shards = list(self.chain.export_shards("t", 0, 45, 4))
        combined = reduce(combine_proofs, shards)
        restored = verify_proof(combined, tenant="t", start=0, end=45)
        one_shot = verify_proof(
            self.chain.export_range("t", 0, 45), tenant="t", start=0, end=45
        )
        self.assertEqual(restored, one_shot)
        self.assertTrue(restored["ok"])
        self.assertEqual(combined["count"], 45)
        self.assertEqual(combined["prev"], shards[0]["prev"])

    def test_shards_survive_archiving_and_compaction(self) -> None:
        self._multi_segment()
        archive_dir = os.path.join(self._tmp, "archive")
        self.chain.archive(archive_dir)
        self.chain.rotate()
        for i in range(45, 52):
            self.chain.append("t", {"i": i})
        self.chain.compact(2)
        shards = list(self.chain.export_shards("t", 0, 52, 6))
        combined = reduce(combine_proofs, shards)
        restored = verify_proof(combined, tenant="t", start=0, end=52)
        one_shot = verify_proof(self.chain.export_range("t", 0, 52))
        self.assertEqual(restored, one_shot)
        self.assertTrue(restored["ok"])

    def test_reexport_is_byte_identical_after_interruption(self) -> None:
        self._multi_segment()
        first = [
            json.dumps(shard, sort_keys=True)
            for shard in self.chain.export_shards("t", 5, 43, 6)
        ]
        # Interrupt a production halfway, then restart from scratch.
        stream = self.chain.export_shards("t", 5, 43, 6)
        next(stream)
        stream.close()
        second = [
            json.dumps(shard, sort_keys=True)
            for shard in self.chain.export_shards("t", 5, 43, 6)
        ]
        self.assertEqual(first, second)

    def test_cold_store_yields_the_same_shards_as_warm(self) -> None:
        self._multi_segment()
        self.assertTrue(self.chain.verify("t")["ok"])  # warm the cache
        warm = [
            json.dumps(shard, sort_keys=True)
            for shard in self.chain.export_shards("t", 2, 44, 5)
        ]
        os.remove(self.chain._layout().cache_path)
        cold = [
            json.dumps(shard, sort_keys=True)
            for shard in self.chain.export_shards("t", 2, 44, 5)
        ]
        self.assertEqual(warm, cold)

    def test_interrupted_export_leaves_no_trace_in_the_store(self) -> None:
        self._multi_segment()
        before = sorted(os.listdir(self.path))
        stream = self.chain.export_shards("t", 0, 45, 4)
        next(stream)
        next(stream)
        stream.close()
        self.assertEqual(sorted(os.listdir(self.path)), before)
        # Abandoning without an explicit close releases the snapshot too.
        orphan = self.chain.export_shards("t", 0, 45, 4)
        next(orphan)
        del orphan
        gc.collect()
        self.assertEqual(sorted(os.listdir(self.path)), before)
        self.chain.append("t", {"i": 45})  # the lock was released

    def test_shards_share_one_complete_prefix(self) -> None:
        self.append_many("t", 30)
        stream = self.chain.export_shards("t", 0, 30, 10)
        first = next(stream)
        done = []

        def writer() -> None:
            self.chain.append("t", {"i": 30})
            done.append(True)

        thread = threading.Thread(target=writer)
        thread.start()
        thread.join(1.0)
        # The appender blocks on the snapshot lock while the stream is open.
        self.assertEqual(done, [])
        rest = list(stream)
        thread.join(5.0)
        self.assertEqual(done, [True])
        for shard in [first] + rest:
            # Every shard describes the pre-append prefix, never a mix.
            self.assertEqual(shard["count"], 30)
        self.assertEqual(self.chain.verify("t")["count"], 31)

    def test_export_shards_never_opens_the_log_for_other_tenants(self) -> None:
        self._multi_segment()
        shards = list(self.chain.export_shards("t", 0, 45, 3))
        for shard in shards:
            for window in shard["windows"]:
                for item in window["records"]:
                    self.assertEqual(item["record"]["tenant"], "t")
        other = list(self.chain.export_shards("u", 0, 15, 4))
        self.assertTrue(all(verify_proof(shard)["ok"] for shard in other))

    def test_bad_window_sizes_raise_value_error(self) -> None:
        self.append_many("t", 10)
        for window in (0, -1, -100, 1.5, "4", None, True):
            with self.assertRaises(ValueError, msg=repr(window)):
                self.chain.export_shards("t", 0, 10, window)

    def test_bad_ranges_raise_value_error(self) -> None:
        self.append_many("t", 10)
        # Empty or reversed intervals.
        for start, end in ((0, 0), (4, 4), (10, 10), (9, 4), (10, 0)):
            with self.assertRaises(ValueError, msg=(start, end)):
                self.chain.export_shards("t", start, end, 3)
        # Non-integer or negative endpoints.
        for start, end in ((0.0, 4), (0, "4"), (None, 4), (True, 4), (-1, 4), (0, -2)):
            with self.assertRaises(ValueError, msg=(start, end)):
                self.chain.export_shards("t", start, end, 3)
        # Out of bounds.
        for start, end in ((0, 11), (10, 11), (15, 20)):
            with self.assertRaises(ValueError, msg=(start, end)):
                self.chain.export_shards("t", start, end, 3)

    def test_empty_history_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            self.chain.export_shards("t", 0, 0, 1)
        with self.assertRaises(ValueError):
            self.chain.export_shards("t", 0, 1, 1)


class VerifyProofStreamTest(AuditTestCase):
    def _shards(self, start: int = 0, end: int = 45, window: int = 4) -> list:
        for i in range(20):
            self.chain.append("t", {"i": i})
            if i % 2 == 0:
                self.chain.append("u", {"i": i})
        self.chain.rotate()
        for i in range(20, 45):
            self.chain.append("t", {"i": i})
        self.chain.rotate()
        return list(self.chain.export_shards("t", start, end, window))

    def test_honest_stream_total_matches_the_one_shot_verdict(self) -> None:
        shards = self._shards()
        result = verify_proof_stream(shards)
        self.assertEqual(len(result["shards"]), len(shards))
        for verdict in result["shards"]:
            self.assertTrue(verdict["ok"], verdict)
            self.assertEqual(
                set(verdict), {"ok", "first_bad", "count", "start", "end", "tenant"}
            )
        one_shot = verify_proof(self.chain.export_range("t", 0, 45))
        self.assertEqual(result["total"], one_shot)
        self.assertTrue(result["total"]["ok"])

    def test_stream_consumes_the_export_iterator_directly(self) -> None:
        for i in range(30):
            self.chain.append("t", {"i": i})
        result = verify_proof_stream(self.chain.export_shards("t", 0, 30, 7))
        self.assertTrue(result["total"]["ok"])
        self.assertEqual(result["total"]["count"], 30)

    def test_tampered_shard_reports_the_real_first_bad_index(self) -> None:
        shards = self._shards(window=10)
        victim = copy.deepcopy(shards[1])
        slot = victim["windows"][0]["records"][2]  # global index 12
        slot["record"]["payload"]["i"] = 9999
        shards[1] = victim

        result = verify_proof_stream(shards)
        self.assertTrue(result["shards"][0]["ok"])
        self.assertFalse(result["shards"][1]["ok"])
        self.assertEqual(result["shards"][1]["first_bad"], 12)
        # The other shards keep checking out, in input order.
        for verdict in result["shards"][2:]:
            self.assertTrue(verdict["ok"], verdict)
        self.assertFalse(result["total"]["ok"])
        self.assertEqual(result["total"]["first_bad"], 12)

        # The same tamper applied to the one-shot export concludes the same.
        full = self.chain.export_range("t", 0, 45)
        for window in full["windows"]:
            for item in window["records"]:
                if item["index"] == 12:
                    item["record"]["payload"]["i"] = 9999
        offline = verify_proof(full)
        self.assertEqual(result["total"], offline)

    def test_malformed_shard_does_not_interrupt_the_stream(self) -> None:
        shards = self._shards(window=10)
        shards[1] = {"version": 1, "tenant": "t", "start": 10, "end": 20,
                     "count": 45, "prev": "", "windows": [{"seq": 0}]}
        result = verify_proof_stream(shards)
        self.assertTrue(result["shards"][0]["ok"])
        self.assertFalse(result["shards"][1]["ok"])
        self.assertEqual(result["shards"][1]["first_bad"], 10)
        self.assertTrue(result["shards"][2]["ok"])
        self.assertFalse(result["total"]["ok"])
        self.assertEqual(result["total"]["first_bad"], 10)

    def test_garbage_shard_resyncs_the_stream(self) -> None:
        shards = self._shards(window=10)
        shards[1] = {"version": 1, "tenant": 42, "start": "x", "windows": "no"}
        result = verify_proof_stream(shards)
        self.assertFalse(result["shards"][1]["ok"])
        self.assertTrue(result["shards"][2]["ok"])
        self.assertFalse(result["total"]["ok"])

    def test_rewritten_boundary_digest_breaks_the_cross_shard_link(self) -> None:
        shards = self._shards(window=10)
        victim = copy.deepcopy(shards[0])
        slot = victim["windows"][-1]["records"][-1]  # global index 9
        slot["record"]["payload"]["i"] = 777
        slot["record"]["digest"] = digest(
            slot["record"]["prev"], slot["record"]["payload"]
        )
        shards[0] = victim
        result = verify_proof_stream(shards)
        self.assertFalse(result["total"]["ok"])
        # The break is attributed at or before the next shard's first record.
        self.assertIn(result["total"]["first_bad"], (9, 10))

    def test_empty_stream_and_non_dict_elements_raise_type_error(self) -> None:
        with self.assertRaises(TypeError):
            verify_proof_stream([])
        with self.assertRaises(TypeError):
            verify_proof_stream(None)
        with self.assertRaises(TypeError):
            verify_proof_stream({"not": "a list"})
        shard = self._shards(window=10)[0]
        with self.assertRaises(TypeError):
            verify_proof_stream([shard, "not a dict"])

    def test_gaps_and_overlaps_raise_value_error(self) -> None:
        shards = self._shards(window=10)
        with self.assertRaises(ValueError):
            verify_proof_stream([shards[0], shards[2]])  # gap
        with self.assertRaises(ValueError):
            verify_proof_stream([shards[0], shards[0]])  # overlap
        with self.assertRaises(ValueError):
            verify_proof_stream([shards[1], shards[0]])  # reversed
        with self.assertRaises(ValueError):
            verify_proof_stream(list(reversed(shards)))

    def test_binds_are_enforced(self) -> None:
        shards = self._shards(window=10)
        result = verify_proof_stream(shards, tenant="t", start=0, end=45)
        self.assertTrue(result["total"]["ok"])
        with self.assertRaises(ValueError):
            verify_proof_stream(shards, tenant="u")
        with self.assertRaises(ValueError):
            verify_proof_stream(shards, start=1)
        with self.assertRaises(ValueError):
            verify_proof_stream(shards, end=44)

    def test_shard_verifier_incremental_form(self) -> None:
        shards = self._shards(window=10)
        verifier = ShardVerifier()
        verdicts = [verifier.check(shard) for shard in shards]
        total = verifier.finish()
        one_shot = verify_proof(self.chain.export_range("t", 0, 45))
        self.assertTrue(all(verdict["ok"] for verdict in verdicts))
        self.assertEqual(total, one_shot)

    def test_shard_verifier_finish_before_any_shard_is_type_error(self) -> None:
        with self.assertRaises(TypeError):
            ShardVerifier().finish()

    def test_batch_verification_still_tolerates_a_tampered_proof(self) -> None:
        shards = self._shards(window=10)
        victim = copy.deepcopy(shards[1])
        slot = victim["windows"][0]["records"][0]
        slot["record"]["payload"]["i"] = 12345
        shards[1] = victim
        verdicts = verify_proofs(shards)
        self.assertEqual(len(verdicts), len(shards))
        self.assertTrue(verdicts[0]["ok"])
        self.assertFalse(verdicts[1]["ok"])
        self.assertEqual(verdicts[1]["first_bad"], 10)
        self.assertTrue(all(verdict["ok"] for verdict in verdicts[2:]))


class ExportShardsCostTest(AuditTestCase):
    """Sharded export cost: work scales with the interval, not history."""

    HISTORY = 4_000
    ROTATE_EVERY = 1_000

    def _build(self, lo: int, hi: int) -> None:
        for i in range(lo, hi):
            self.chain.append("t", {"i": i, "pad": "x" * 24})
            if (i + 1) % self.ROTATE_EVERY == 0 and i + 1 < hi:
                self.chain.rotate()

    def _build_warm(self) -> None:
        self._build(0, self.HISTORY)
        self.assertTrue(self.chain.verify("t")["ok"])  # warm the cache

    def test_sharded_export_opens_only_covering_segments(self) -> None:
        self._build_warm()
        seg_files = {
            os.path.abspath(os.path.join(self.path, name))
            for name in self.segment_files()
        }
        # Interval [100, 200) in 25-record shards lives in the first segment.
        meter = _ReadMeter()
        meter.install()
        try:
            shards = list(self.chain.export_shards("t", 100, 200, 25))
        finally:
            meter.remove()

        self.assertEqual(len(shards), 4)
        self.assertTrue(all(verify_proof(shard)["ok"] for shard in shards))
        opened_segments = meter.paths & seg_files
        self.assertEqual(len(opened_segments), 1)
        self.assertLessEqual(
            meter.bytes, os.path.getsize(next(iter(opened_segments))) + 100_000
        )

    def test_sharded_export_does_not_hash_the_history(self) -> None:
        self._build_warm()
        total = sum(
            os.path.getsize(os.path.join(self.path, name))
            for name in self.segment_files()
        )
        meter = _HashMeter()
        meter.install()
        try:
            shards = list(self.chain.export_shards("t", 100, 200, 10))
            hashed = meter.bytes
        finally:
            meter.remove()

        self.assertEqual(len(shards), 10)
        # Only the ~100 interval record digests, never a sealed window.
        self.assertLess(hashed, total // 10)

    def test_cost_is_independent_of_history_length(self) -> None:
        self._build_warm()
        first = _ReadMeter()
        first.install()
        try:
            list(self.chain.export_shards("t", 100, 200, 25))
            bytes_at_4k = first.bytes
        finally:
            first.remove()

        # Double the history; the same early interval must not read more.
        self._build(self.HISTORY, 2 * self.HISTORY)
        second = _ReadMeter()
        second.install()
        try:
            shards = list(self.chain.export_shards("t", 100, 200, 25))
            bytes_at_8k = second.bytes
        finally:
            second.remove()

        self.assertTrue(all(verify_proof(shard)["ok"] for shard in shards))
        self.assertLess(abs(bytes_at_8k - bytes_at_4k), 100_000)
