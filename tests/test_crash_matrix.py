"""Real kill crash-injection matrix.

Every window is exercised by hard-killing a separate process (SIGKILL via
the audit chain's own crash hook), never by an in-process exception: no
``finally`` blocks run and the on-disk state is exactly what a killed
process leaves. After each kill the store is reopened and must land on
either the old or the new topology, with a deterministic recovery path for
half lines, orphan segments, backup files and residual temp files.
"""

from __future__ import annotations

import os
import subprocess
import sys

from tests._helpers import AuditTestCase, REPO_ROOT

WORKER = os.path.join(REPO_ROOT, "tests", "_crash_worker.py")


class CrashMatrixTest(AuditTestCase):
    def _kill(self, operation: str, point: str, index: int = 0) -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
        completed = subprocess.run(
            [sys.executable, WORKER, self.path, operation, point, str(index)],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(
            completed.returncode,
            0,
            f"{operation}@{point} did not die: {completed.stderr.decode()[:400]}",
        )

    def _reopened(self):
        return type(self.chain)(self.path)

    # -- append windows: write / flush / durable --------------------------

    def test_killed_after_first_write_leaves_bad_half_line(self) -> None:
        self.append_many("t", 4)
        self._kill("append", "append:after_first_write", index=4)
        reopened = self._reopened()
        # The half line is a bad line, never silently repaired.
        with self.assertRaises(ValueError):
            reopened.verify("t")
        with self.assertRaises(ValueError):
            reopened.entries("t")
        removed = reopened.recover()["truncated_bytes"]
        self.assertGreater(removed, 0)
        self.assertEqual(
            reopened.verify("t"), {"count": 4, "first_bad": -1, "ok": True}
        )

    def test_killed_before_fsync_lands_on_one_prefix(self) -> None:
        self.append_many("t", 4)
        self._kill("append", "append:before_fsync", index=4)
        reopened = self._reopened()
        result = reopened.verify("t")
        # Durability may or may not have caught the un-fsynced line, but
        # whichever prefix survived must be complete and strictly linked.
        self.assertTrue(result["ok"], result)
        self.assertIn(result["count"], (4, 5))
        entries = reopened.entries("t")
        self.assertEqual(len(entries), result["count"])
        self.assertEqual(
            [e["payload"]["i"] for e in entries], list(range(result["count"]))
        )
        # The store must accept further appends regardless.
        reopened.append("t", {"i": result["count"]})
        self.assertTrue(reopened.verify("t")["ok"])

    def test_killed_after_fsync_keeps_the_durable_record(self) -> None:
        self.append_many("t", 4)
        self._kill("append", "append:after_fsync", index=4)
        reopened = self._reopened()
        self.assertEqual(
            reopened.verify("t"), {"count": 5, "first_bad": -1, "ok": True}
        )

    # -- file -> store migration windows ----------------------------------

    def test_killed_after_staging_keeps_legacy_file(self) -> None:
        self.append_many("t", 3)
        self._kill("migrate", "migrate:after_staging")
        self.assertTrue(os.path.isfile(self.path))
        reopened = self._reopened()
        self.assertEqual(
            reopened.verify("t"), {"count": 3, "first_bad": -1, "ok": True}
        )
        # The staged directory is inert for reads and is reaped by the next
        # writer operation, which then completes the migration.
        reopened.rotate()
        self.assertFalse(os.path.exists(self.path + ".segstage"))
        self.assertTrue(os.path.isdir(self.path))
        self.assertTrue(reopened.verify("t")["ok"])

    def test_killed_between_renames_adopts_backup(self) -> None:
        self.append_many("t", 3)
        self._kill("migrate", "migrate:after_backup_rename")
        self.assertFalse(os.path.exists(self.path))
        reopened = self._reopened()
        # The first operation takes the lock and adopts the backup.
        self.assertEqual(
            reopened.verify("t"), {"count": 3, "first_bad": -1, "ok": True}
        )
        self.assertTrue(os.path.isfile(self.path))
        self.assertFalse(os.path.exists(self.path + ".pre-segment"))
        self.assertFalse(os.path.exists(self.path + ".segstage"))

    def test_killed_after_publish_reaps_backup(self) -> None:
        self.append_many("t", 3)
        self._kill("migrate", "migrate:after_publish")
        self.assertTrue(os.path.isdir(self.path))
        reopened = self._reopened()
        self.assertEqual(
            reopened.verify("t"), {"count": 3, "first_bad": -1, "ok": True}
        )
        # Reads leave the backup in place; the next writer operation reaps it.
        self.assertTrue(os.path.exists(self.path + ".pre-segment"))
        reopened.append("t", {"i": 3})
        self.assertFalse(os.path.exists(self.path + ".pre-segment"))

    # -- in-store rotation windows ----------------------------------------

    def test_killed_before_manifest_commit_keeps_old_topology(self) -> None:
        import json

        self.append_many("t", 3)
        self.chain.rotate()
        self.append_many("t", 3, start=3)
        with open(os.path.join(self.path, "manifest.json"), encoding="utf-8") as fh:
            old_names = [s["name"] for s in json.load(fh)["segments"]]

        self._kill("rotate", "rotate:before_manifest")
        reopened = self._reopened()
        self.assertEqual(
            reopened.verify("t"), {"count": 6, "first_bad": -1, "ok": True}
        )
        # The committed manifest is unchanged even though a staged segment
        # file may be sitting unreferenced on disk.
        with open(os.path.join(self.path, "manifest.json"), encoding="utf-8") as fh:
            self.assertEqual(
                [s["name"] for s in json.load(fh)["segments"]], old_names
            )
        # The next writer operation reaps the orphan before appending.
        reopened.append("t", {"i": 6})
        self.assertTrue(reopened.verify("t")["ok"])
        self.assertEqual(reopened.verify("t")["count"], 7)

    def test_killed_after_manifest_commit_is_new_topology(self) -> None:
        self.append_many("t", 3)
        self.chain.rotate()
        self.append_many("t", 3, start=3)
        self._kill("rotate", "rotate:after_manifest")
        reopened = self._reopened()
        self.assertEqual(
            reopened.verify("t"), {"count": 6, "first_bad": -1, "ok": True}
        )
        reopened.append("t", {"i": 6})
        self.assertEqual(
            reopened.verify("t"), {"count": 7, "first_bad": -1, "ok": True}
        )

    # -- compaction windows -----------------------------------------------

    def _fresh_three_segment_store(self, name: str):
        """Build a fresh three-segment store at its own path."""
        path = os.path.join(self._tmp, name)
        chain = type(self.chain)(path)
        for i in range(3):
            chain.append("t", {"i": i})
        chain.rotate()
        for i in range(3, 6):
            chain.append("t", {"i": i})
        chain.rotate()
        for i in range(6, 9):
            chain.append("t", {"i": i})
        return path, chain

    def test_killed_during_merge_write_or_rename_keeps_old_topology(self) -> None:
        import json

        base_path, base_chain = self._fresh_three_segment_store("base")
        # Snapshot the old topology from a clean run's pre-compaction state.
        with open(os.path.join(base_path, "manifest.json"), encoding="utf-8") as fh:
            old_manifest = json.load(fh)
        old_names = [s["name"] for s in old_manifest["segments"]]

        for index, point in enumerate(
            (
                "compact:before_merge_fsync",
                "compact:after_merge_write",
                "compact:after_merge_rename",
            )
        ):
            path, _ = self._fresh_three_segment_store(f"pre-{index}")
            # Run the kill against that path directly.
            completed = subprocess.run(
                [
                    sys.executable,
                    WORKER,
                    path,
                    "compact",
                    point,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(completed.returncode, 0, point)

            reopened = type(self.chain)(path)
            with open(os.path.join(path, "manifest.json"), encoding="utf-8") as fh:
                manifest = json.load(fh)
            self.assertEqual(
                [s["name"] for s in manifest["segments"]], old_names, point
            )
            self.assertEqual(
                reopened.verify("t"),
                {"count": 9, "first_bad": -1, "ok": True},
                point,
            )
            seg_tmps = lambda: [
                n
                for n in os.listdir(path)
                if n.startswith(".seg") and n.endswith(".tmp")
            ]
            # Before the merge rename the staged temp file is still on disk;
            # after the rename it is gone (leaving only an unreferenced
            # segment). Either way it is inert for reads.
            if point == "compact:after_merge_rename":
                self.assertEqual(seg_tmps(), [], point)
            else:
                self.assertEqual(len(seg_tmps()), 1, point)
            # The next writer operation reaps every leftover and then
            # completes a real compaction cleanly.
            self.assertEqual(reopened.compact(2), {"segments": 2})
            self.assertEqual(seg_tmps(), [], point)
            self.assertEqual(
                [e["payload"]["i"] for e in reopened.entries("t")],
                list(range(9)),
                point,
            )

    def test_killed_after_manifest_or_during_delete_is_new_topology(self) -> None:
        for index, point in enumerate(
            (
                "compact:after_manifest",
                "compact:during_delete",
                "compact:after_delete",
            )
        ):
            path, _ = self._fresh_three_segment_store(f"post-{index}")
            completed = subprocess.run(
                [sys.executable, WORKER, path, "compact", point],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(completed.returncode, 0, point)

            reopened = type(self.chain)(path)
            result = reopened.verify("t")
            self.assertEqual(
                result, {"count": 9, "first_bad": -1, "ok": True}, point
            )
            self.assertEqual(
                [e["payload"]["i"] for e in reopened.entries("t")],
                list(range(9)),
                point,
            )
            reopened.append("t", {"i": 9})
            self.assertEqual(reopened.verify("t")["count"], 10, point)

    def test_killed_during_manifest_replace_in_rotate_keeps_old_topology(self) -> None:
        import json

        self.append_many("t", 4)
        self.chain.rotate()
        self.append_many("t", 4, start=4)
        with open(os.path.join(self.path, "manifest.json"), encoding="utf-8") as fh:
            old_names = [s["name"] for s in json.load(fh)["segments"]]

        self._kill("rotate", "atomic:manifest.json:before_replace")
        reopened = self._reopened()
        self.assertEqual(
            reopened.verify("t"), {"count": 8, "first_bad": -1, "ok": True}
        )
        with open(os.path.join(self.path, "manifest.json"), encoding="utf-8") as fh:
            self.assertEqual(
                [s["name"] for s in json.load(fh)["segments"]], old_names
            )
        # The next writer operation reaps the manifest temp file and orphan.
        reopened.append("t", {"i": 8})
        leftovers = [
            n for n in os.listdir(self.path)
            if n.startswith(".") and n.endswith(".tmp")
        ]
        self.assertEqual(leftovers, [])
        self.assertTrue(reopened.verify("t")["ok"])

    def test_killed_during_manifest_replace_in_compact_keeps_old_topology(self) -> None:
        import json

        for index, point in enumerate(
            ("atomic:manifest.json:before_replace",)
        ):
            path, _ = self._fresh_three_segment_store(f"manifest-{index}")
            with open(os.path.join(path, "manifest.json"), encoding="utf-8") as fh:
                old_names = [s["name"] for s in json.load(fh)["segments"]]
            completed = subprocess.run(
                [sys.executable, WORKER, path, "compact", point],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(completed.returncode, 0, point)
            reopened = type(self.chain)(path)
            with open(os.path.join(path, "manifest.json"), encoding="utf-8") as fh:
                self.assertEqual(
                    [s["name"] for s in json.load(fh)["segments"]], old_names, point
                )
            self.assertEqual(
                reopened.verify("t"),
                {"count": 9, "first_bad": -1, "ok": True},
                point,
            )
            # A later compaction completes and reaps the staged segment/tmp.
            self.assertEqual(reopened.compact(2), {"segments": 2}, point)
            self.assertEqual(
                [e["payload"]["i"] for e in reopened.entries("t")],
                list(range(9)),
                point,
            )

    # -- recover window ----------------------------------------------------

    def test_killed_during_recover_eventually_truncates_cleanly(self) -> None:
        self.append_many("t", 3)
        self.chain.rotate()
        self.append_many("t", 2, start=3)
        active = self.segment_files()[-1]
        with open(os.path.join(self.path, active), "ab") as handle:
            handle.write(b'{"digest":"z"')
        self._kill("recover", "recover:after_truncate")
        reopened = self._reopened()
        try:
            result = reopened.verify("t")
        except ValueError:
            # Truncation was not durable: the bad line keeps its semantics,
            # and a second explicit recovery finishes the job.
            result = reopened.recover()
            self.assertGreater(result["truncated_bytes"], 0)
            result = reopened.verify("t")
        self.assertEqual(result, {"count": 5, "first_bad": -1, "ok": True})
