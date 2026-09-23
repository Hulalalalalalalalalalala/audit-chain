"""Segment rotation and compaction."""

from __future__ import annotations

import json
import os

from tests._helpers import AuditTestCase


class SegmentTest(AuditTestCase):
    def test_rotate_migrates_legacy_file_into_store(self) -> None:
        self.append_many("t", 5)
        self.chain.rotate()
        self.assertTrue(os.path.isdir(self.path))
        names = self.segment_files()
        self.assertEqual(len(names), 2)
        with open(os.path.join(self.path, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        self.assertEqual(len(manifest["segments"]), 2)
        self.assertFalse(manifest["segments"][-1]["sealed"])
        self.assertTrue(manifest["segments"][0]["sealed"])
        self.assertTrue(self.chain.verify("t")["ok"])
        # Appends still land, ordered, after migration.
        self.append_many("t", 3, start=5)
        self.assertEqual(
            [e["payload"]["i"] for e in self.chain.entries("t")],
            list(range(8)),
        )

    def test_rotate_on_empty_file_creates_store(self) -> None:
        # rotate without any prior append migrates an empty log.
        self.chain.rotate()
        self.assertTrue(os.path.isdir(self.path))
        self.assertEqual(len(self.segment_files()), 1)
        self.chain.append("t", {})
        self.assertTrue(self.chain.verify("t")["ok"])

    def test_refuses_rotation_with_half_line(self) -> None:
        self.append_many("t", 3)
        with open(self.path, "ab") as handle:
            handle.write(b'{"x"')
        with self.assertRaises(ValueError):
            self.chain.rotate()
        # The legacy file still exists (migration rolled back).
        self.assertTrue(os.path.isfile(self.path))

    def test_multiple_rotations_and_global_order(self) -> None:
        self.append_many("t", 4)
        self.chain.rotate()
        self.append_many("t", 4, start=4)
        self.chain.rotate()
        self.append_many("t", 4, start=8)
        self.assertEqual(len(self.segment_files()), 3)
        result = self.chain.verify("t")
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 12)
        self.assertEqual(
            [e["payload"]["i"] for e in self.chain.entries("t")],
            list(range(12)),
        )

        # Each sealed segment keeps one verification window per source.
        with open(os.path.join(self.path, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        for segment in manifest["segments"][:-1]:
            self.assertTrue(segment["sealed"])
            self.assertGreaterEqual(len(segment["parts"]), 1)

    def test_compact_preserves_order_and_material(self) -> None:
        self.append_many("t", 3)
        self.chain.rotate()
        self.append_many("t", 3, start=3)
        self.chain.rotate()
        self.append_many("t", 3, start=6)
        result = self.chain.compact(2)
        self.assertEqual(result, {"segments": 2})

        # The merged segment carries windows for BOTH source segments.
        with open(os.path.join(self.path, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        merged, active = manifest["segments"]
        self.assertTrue(merged["sealed"])
        self.assertEqual(len(merged["parts"]), 2)
        self.assertFalse(active["sealed"])

        # Global order and verdicts are unchanged by compression.
        self.assertEqual(
            [e["payload"]["i"] for e in self.chain.entries("t")],
            list(range(9)),
        )
        self.assertEqual(
            self.chain.verify("t"), {"count": 9, "first_bad": -1, "ok": True}
        )

    def test_compact_to_one_segment_then_grow(self) -> None:
        self.append_many("t", 3)
        self.chain.rotate()
        self.append_many("t", 3, start=3)
        self.chain.rotate()
        self.append_many("t", 3, start=6)
        self.chain.compact(1)
        self.assertEqual(len(self.segment_files()), 1)
        self.append_many("t", 3, start=9)
        self.assertEqual(
            [e["payload"]["i"] for e in self.chain.entries("t")],
            list(range(12)),
        )
        self.assertTrue(self.chain.verify("t")["ok"])

    def test_corrupt_segment_blocks_compaction_and_rotation_seal(self) -> None:
        self.append_many("t", 3)
        self.chain.rotate()
        self.append_many("t", 3, start=3)
        # Corrupt the sealed segment.
        first = self.segment_files()[0]
        data = self.raw_bytes(first).replace(b'{"i":1}', b'{"i":7}', 1)
        self.write_raw(data, first)
        with self.assertRaises(ValueError):
            self.chain.compact(2)
        with self.assertRaises(ValueError):
            self.chain.rotate()

    def test_cross_segment_corruption_is_located_globally(self) -> None:
        self.append_many("t", 30)
        self.chain.rotate()
        self.append_many("t", 30, start=30)
        self.chain.rotate()
        self.append_many("t", 30, start=60)
        self.chain.compact(2)
        # compact(2) folds seg1+seg2 into the highest-numbered sealed file;
        # the active segment is the lower-numbered one here.
        merged = sorted(self.segment_files())[-1]
        # Damage a record that lives inside the SECOND source window.
        self.replace_in_file(b'{"i":40}', b'{"i":48}', merged)
        result = self.chain.verify("t")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"], 40)

    def test_rotate_idempotent_on_empty_active(self) -> None:
        self.append_many("t", 2)
        self.chain.rotate()
        names_before = self.segment_files()
        # No new segment when the active one is empty.
        self.chain.rotate()
        self.assertEqual(self.segment_files(), names_before)
