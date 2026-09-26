"""Windowed shard streaming export (export_shards) and streaming
verification (verify_shards)."""

from __future__ import annotations

import os
import threading
import types

from audit_chain import combine_proofs, verify_proof, verify_shards
from tests._helpers import AuditTestCase


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

    def test_shards_tile_the_interval_without_gaps(self) -> None:
        self._multi_segment()
        shards = list(self.chain.export_shards("t", 0, 45, 10))
        self.assertEqual(len(shards), 5)
        self.assertEqual(
            [(shard["start"], shard["end"]) for shard in shards],
            [(0, 10), (10, 20), (20, 30), (30, 40), (40, 45)],
        )
        for shard in shards:
            self.assertEqual(shard["tenant"], "t")
            self.assertEqual(shard["count"], 45)
            exported = [
                item["index"]
                for window in shard["windows"]
                for item in window["records"]
            ]
            self.assertEqual(
                exported, list(range(shard["start"], shard["end"]))
            )

    def test_each_shard_verifies_independently(self) -> None:
        self._multi_segment()
        for shard in self.chain.export_shards("t", 3, 41, 7):
            verdict = verify_proof(
                shard, tenant="t", start=shard["start"], end=shard["end"]
            )
            self.assertTrue(verdict["ok"], verdict)
            self.assertEqual(verdict["first_bad"], -1)

    def test_shard_sizes_track_the_window(self) -> None:
        self.append_many("t", 23)
        shards = list(self.chain.export_shards("t", 0, 23, 5))
        self.assertEqual(
            [shard["end"] - shard["start"] for shard in shards], [5, 5, 5, 5, 3]
        )
        # A window larger than the interval yields a single shard.
        alone = list(self.chain.export_shards("t", 0, 23, 1000))
        self.assertEqual(len(alone), 1)
        self.assertEqual((alone[0]["start"], alone[0]["end"]), (0, 23))
        # A window of one yields one shard per record.
        singles = list(self.chain.export_shards("t", 0, 23, 1))
        self.assertEqual(len(singles), 23)

    def test_sub_interval_shards(self) -> None:
        self._multi_segment()
        shards = list(self.chain.export_shards("t", 11, 33, 8))
        self.assertEqual(
            [(shard["start"], shard["end"]) for shard in shards],
            [(11, 19), (19, 27), (27, 33)],
        )
        for shard in shards:
            self.assertTrue(verify_proof(shard)["ok"])

    def test_shards_combine_back_to_the_full_interval(self) -> None:
        self._multi_segment()
        shards = list(self.chain.export_shards("t", 0, 45, 4))
        restored = shards[0]
        for shard in shards[1:]:
            restored = combine_proofs(restored, shard)
        self.assertEqual((restored["start"], restored["end"]), (0, 45))
        restored_verdict = verify_proof(restored, tenant="t", start=0, end=45)
        full_verdict = verify_proof(
            self.chain.export_range("t", 0, 45), tenant="t", start=0, end=45
        )
        self.assertEqual(restored_verdict, full_verdict)
        self.assertTrue(restored_verdict["ok"])

    def test_export_is_lazy(self) -> None:
        self.append_many("t", 10)
        stream = self.chain.export_shards("t", 0, 10, 3)
        self.assertIsInstance(stream, types.GeneratorType)
        first = next(stream)
        self.assertEqual((first["start"], first["end"]), (0, 3))
        self.assertEqual(len(list(stream)), 3)

    def test_export_is_deterministic_across_reruns(self) -> None:
        self._multi_segment()
        first = list(self.chain.export_shards("t", 0, 45, 7))
        second = list(self.chain.export_shards("t", 0, 45, 7))
        self.assertEqual(first, second)

    def test_export_writes_nothing_when_interrupted(self) -> None:
        self._multi_segment()
        before = sorted(os.listdir(self.path))
        stream = self.chain.export_shards("t", 0, 45, 3)
        next(stream)
        stream.close()
        after = sorted(os.listdir(self.path))
        self.assertEqual(before, after)
        self.assertFalse(
            any(name.startswith(".") and name.endswith(".tmp") for name in after)
        )

    def test_shards_cover_one_prefix_despite_concurrent_append(self) -> None:
        self.append_many("t", 30)
        stream = self.chain.export_shards("t", 0, 30, 10)
        first = next(stream)

        errors: list[BaseException] = []

        def writer() -> None:
            try:
                self.chain.append("t", {"i": 30})
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        # The append blocks on the exclusive lock until the stream is
        # fully consumed; every shard still describes the pre-append
        # prefix of 30 records.
        thread = threading.Thread(target=writer)
        thread.start()
        rest = list(stream)
        thread.join(timeout=30)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])

        shards = [first] + rest
        self.assertEqual(len(shards), 3)
        for shard in shards:
            self.assertEqual(shard["count"], 30)
            self.assertTrue(verify_proof(shard)["ok"])
        self.assertEqual(self.chain.verify("t")["count"], 31)

    def test_shards_after_compact_and_archive(self) -> None:
        self._multi_segment()
        archive_dir = os.path.join(self._tmp, "archive")
        self.chain.archive(archive_dir)
        shards = list(self.chain.export_shards("t", 0, 45, 9))
        self.assertEqual(len(shards), 5)
        for shard in shards:
            self.assertTrue(verify_proof(shard)["ok"])
        restored = shards[0]
        for shard in shards[1:]:
            restored = combine_proofs(restored, shard)
        self.assertTrue(
            verify_proof(restored, tenant="t", start=0, end=45)["ok"]
        )

    def test_legacy_file_layout_shards(self) -> None:
        # No rotation: the legacy single file exports tail-run windows.
        self.append_many("t", 12)
        shards = list(self.chain.export_shards("t", 0, 12, 5))
        self.assertEqual([shard["end"] - shard["start"] for shard in shards], [5, 5, 2])
        for shard in shards:
            self.assertTrue(verify_proof(shard)["ok"])

    def test_invalid_window_size_is_value_error(self) -> None:
        self.append_many("t", 4)
        for bad in (0, -1, -100, 1.5, "3", None, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.chain.export_shards("t", 0, 4, bad)

    def test_empty_and_reversed_intervals_are_value_error(self) -> None:
        self.append_many("t", 4)
        with self.assertRaises(ValueError):
            self.chain.export_shards("t", 2, 2, 1)
        with self.assertRaises(ValueError):
            self.chain.export_shards("t", 0, 0, 1)
        with self.assertRaises(ValueError):
            self.chain.export_shards("t", 3, 1, 1)

    def test_non_integer_or_negative_bounds_are_value_error(self) -> None:
        self.append_many("t", 4)
        for start, end in ((0.5, 4), (0, 2.5), ("0", 4), (0, None), (True, 4)):
            with self.assertRaises(ValueError, msg=repr((start, end))):
                self.chain.export_shards("t", start, end, 2)
        with self.assertRaises(ValueError):
            self.chain.export_shards("t", -1, 4, 2)
        with self.assertRaises(ValueError):
            self.chain.export_shards("t", 0, -4, 2)

    def test_out_of_bounds_interval_is_value_error(self) -> None:
        self.append_many("t", 4)
        with self.assertRaises(ValueError):
            list(self.chain.export_shards("t", 0, 5, 2))
        with self.assertRaises(ValueError):
            list(self.chain.export_shards("t", 4, 5, 2))

    def test_missing_or_empty_log_is_value_error(self) -> None:
        with self.assertRaises(ValueError):
            list(self.chain.export_shards("t", 0, 1, 1))
        self.append_many("u", 3)
        with self.assertRaises(ValueError):
            list(self.chain.export_shards("t", 0, 1, 1))


class VerifyShardsTest(AuditTestCase):
    def _segmented(self) -> None:
        for i in range(30):
            self.chain.append("t", {"i": i})
        self.chain.rotate()
        for i in range(30, 50):
            self.chain.append("t", {"i": i})

    def _shards(self, window: int = 10) -> list[dict]:
        return list(self.chain.export_shards("t", 0, 50, window))

    def test_streaming_verdicts_match_offline_verdicts(self) -> None:
        self._segmented()
        shards = self._shards()
        result = verify_shards(shards)
        self.assertEqual(set(result), {"overall", "shards"})
        self.assertEqual(len(result["shards"]), len(shards))
        for shard, verdict in zip(shards, result["shards"]):
            self.assertEqual(verdict, verify_proof(shard))
        # The whole-interval conclusion matches one full offline export.
        full = verify_proof(self.chain.export_range("t", 0, 50))
        self.assertEqual(result["overall"], full)
        self.assertTrue(result["overall"]["ok"])

    def test_overall_conclusion_matches_for_any_window(self) -> None:
        self._segmented()
        full = verify_proof(self.chain.export_range("t", 0, 50))
        for window in (1, 7, 25, 50, 200):
            result = verify_shards(self._shards(window))
            self.assertEqual(result["overall"], full, msg=f"window={window}")

    def test_tampered_shard_reports_real_bad_index_and_continues(self) -> None:
        self._segmented()
        shards = self._shards()
        # Damage slot 2 of the second shard: global tenant index 12.
        shards[1]["windows"][0]["records"][2]["record"]["payload"] = {"i": -1}
        result = verify_shards(shards)
        self.assertTrue(result["shards"][0]["ok"])
        self.assertFalse(result["shards"][1]["ok"])
        self.assertEqual(result["shards"][1]["first_bad"], 12)
        self.assertTrue(result["shards"][2]["ok"])
        self.assertTrue(result["shards"][3]["ok"])
        self.assertTrue(result["shards"][4]["ok"])
        self.assertFalse(result["overall"]["ok"])
        self.assertEqual(result["overall"]["first_bad"], 12)
        self.assertEqual(result["overall"]["count"], 50)

    def test_malformed_shard_does_not_abort_the_sequence(self) -> None:
        self._segmented()
        shards = self._shards()
        shards[2] = {"version": 1, "tenant": "t", "start": 20, "end": 30}
        result = verify_shards(shards)
        self.assertTrue(result["shards"][0]["ok"])
        self.assertFalse(result["shards"][2]["ok"])
        self.assertEqual(result["shards"][2]["first_bad"], 20)
        self.assertTrue(result["shards"][4]["ok"])
        self.assertFalse(result["overall"]["ok"])

    def test_empty_list_and_non_dict_elements_are_type_error(self) -> None:
        self._segmented()
        good = self._shards()
        with self.assertRaises(TypeError):
            verify_shards([])
        with self.assertRaises(TypeError):
            verify_shards(good[0])
        with self.assertRaises(TypeError):
            verify_shards((shard for shard in good))
        with self.assertRaises(TypeError):
            verify_shards([good[0], "not-a-shard"])
        with self.assertRaises(TypeError):
            verify_shards([good[0], None])

    def test_gap_overlap_and_tenant_mismatch_are_value_error(self) -> None:
        self._segmented()
        shards = self._shards()
        with self.assertRaises(ValueError):
            verify_shards(
                [
                    self.chain.export_range("t", 0, 10),
                    self.chain.export_range("t", 11, 20),  # gap
                ]
            )
        with self.assertRaises(ValueError):
            verify_shards(
                [
                    self.chain.export_range("t", 0, 15),
                    self.chain.export_range("t", 10, 20),  # overlap
                ]
            )
        with self.assertRaises(ValueError):
            verify_shards([shards[1], shards[0]])  # reversed
        self.chain.append("u", {"i": 0})
        with self.assertRaises(ValueError):
            verify_shards(
                [shards[0], self.chain.export_range("u", 0, 1)]
            )

    def test_single_shard_sequence(self) -> None:
        self._segmented()
        result = verify_shards([self.chain.export_range("t", 0, 50)])
        self.assertEqual(len(result["shards"]), 1)
        self.assertTrue(result["overall"]["ok"])
        self.assertEqual(result["overall"]["count"], 50)

    def test_broken_cross_shard_link_is_flagged(self) -> None:
        self._segmented()
        shards = self._shards()
        # Replace the third shard with a same-interval proof from another
        # log: it verifies alone but does not attach to its predecessor.
        other_path = os.path.join(self._tmp, "other")
        from audit_chain import Chain

        other = Chain(other_path)
        for i in range(50):
            other.append("t", {"i": i, "foreign": True})
        shards[2] = list(other.export_shards("t", 20, 30, 10))[0]
        self.assertTrue(verify_proof(shards[2])["ok"])
        result = verify_shards(shards)
        self.assertTrue(result["shards"][2]["ok"])
        self.assertFalse(result["overall"]["ok"])
        self.assertEqual(result["overall"]["first_bad"], 20)

    def test_verdicts_follow_input_order(self) -> None:
        self._segmented()
        shards = self._shards()
        shards[3]["windows"][0]["records"][0]["record"]["prev"] = "0" * 64
        result = verify_shards(shards)
        oks = [verdict["ok"] for verdict in result["shards"]]
        self.assertEqual(oks, [True, True, True, False, True])
        self.assertEqual(result["shards"][3]["first_bad"], 30)
