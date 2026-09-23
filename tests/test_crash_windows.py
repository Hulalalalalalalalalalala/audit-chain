"""Crash windows around migration and compaction."""

from __future__ import annotations

import json
import os

from tests._helpers import AuditTestCase


class CrashWindowTest(AuditTestCase):
    def test_backup_from_killed_migration_is_adopted(self) -> None:
        self.append_many("t", 5)
        original = self.raw_bytes()

        # Simulate a migration killed between the two renames: the legacy
        # file was moved aside and the staged store was not published.
        os.mkdir(self.path + ".segstage")
        os.replace(self.path, self.path + ".pre-segment")

        reopened = type(self.chain)(self.path)
        result = reopened.verify("t")
        self.assertTrue(os.path.isfile(self.path))
        self.assertFalse(os.path.exists(self.path + ".pre-segment"))
        self.assertEqual(self.raw_bytes(), original)
        self.assertEqual(result, {"count": 5, "first_bad": -1, "ok": True})
        # The leftover staging directory was removed during adoption.
        self.assertFalse(os.path.exists(self.path + ".segstage"))

    def test_orphan_segment_after_killed_compaction_is_reaped(self) -> None:
        self.append_many("t", 3)
        self.chain.rotate()
        self.append_many("t", 3, start=3)
        self.chain.rotate()
        self.append_many("t", 3, start=6)
        self.chain.compact(2)

        with open(os.path.join(self.path, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        referenced = {segment["name"] for segment in manifest["segments"]}
        orphan = "seg-00000099.jsonl"
        with open(os.path.join(self.path, orphan), "wb") as fh:
            fh.write(b"orphan\n")

        # The next writer garbage-collects the unreferenced file; reads are
        # unaffected even before that.
        self.assertTrue(self.chain.verify("t")["ok"])
        self.assertIn(orphan, os.listdir(self.path))
        self.chain.append("t", {"i": 9})
        self.assertNotIn(orphan, os.listdir(self.path))
        self.assertTrue(self.chain.verify("t")["ok"])
        self.assertEqual(self.chain.verify("t")["count"], 10)
        del referenced  # documentation only

    def test_published_store_survives_without_stale_backup(self) -> None:
        self.append_many("t", 2)
        self.chain.rotate()
        # A normal migration leaves no backup or staging directory behind.
        self.assertFalse(os.path.exists(self.path + ".pre-segment"))
        self.assertFalse(os.path.exists(self.path + ".segstage"))
        self.assertTrue(os.path.isdir(self.path))
        self.assertTrue(self.chain.verify("t")["ok"])
