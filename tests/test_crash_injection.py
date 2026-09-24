"""Real SIGKILL crash-injection matrix and deterministic recovery.

Each test arms exactly one crash point in a *separate process* and kills that
process with the unblockable SIGKILL, so no Python ``finally`` runs. It then
reopens the store in a fresh process state and asserts that:

* the log is in exactly one of the old/new topologies;
* a half-line is a bad line (never a silent fix) until explicit recover();
* every temp file, backup and staging directory is settled deterministically;
* the index after reopen matches the intact prefix, per tenant;
* segment files orphaned by a kill after manifest commit are reaped on the
  next exclusive open.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from tests._helpers import AuditTestCase, REPO_ROOT

_RUNNER = [sys.executable, "-m", "tests._crash_runner"]


class CrashInjectionTest(AuditTestCase):
    def _run(self, scenario: str, point: str = "") -> subprocess.CompletedProcess:
        env = dict(os.environ)
        if point:
            env["AUDIT_CHAIN_FAULT"] = point
        proc = subprocess.run(
            _RUNNER + [self.path, scenario] + ([point] if point else []),
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            timeout=120,
        )
        return proc

    def _setup(self, name: str) -> None:
        proc = self._run(name)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())

    def _assert_no_debris(self) -> None:
        parent = os.path.dirname(self.path)
        for name in os.listdir(parent):
            self.assertNotIn(".tmp", name)
            self.assertNotIn(".segstage", name)
            self.assertNotIn(".pre-segment", name)
        if os.path.isdir(self.path):
            for name in os.listdir(self.path):
                self.assertFalse(
                    name.endswith(".tmp"), f"temp file survived: {name}"
                )

    def _assert_segments_referenced(self) -> None:
        if not os.path.isdir(self.path):
            return
        with open(os.path.join(self.path, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        referenced = {segment["name"] for segment in manifest["segments"]}
        for name in os.listdir(self.path):
            if name.startswith("seg-") and name.endswith(".jsonl"):
                self.assertIn(name, referenced)

    def _assert_intact_prefix(self, t: int, u: int) -> None:
        chain = type(self.chain)(self.path)
        self.assertEqual(chain.verify("t"), {"count": t, "first_bad": -1, "ok": True})
        if u:
            self.assertEqual(
                chain.verify("u"), {"count": u, "first_bad": -1, "ok": True}
            )
        self.assertEqual(
            [e["payload"]["i"] for e in chain.entries("t")], list(range(t))
        )

    def _exclusive_settle(self) -> None:
        """Take an exclusive lock and let deterministic cleanup run.

        Temp files, backups and staging debris are reaped on the first
        exclusive open (the same window that GCs orphan segments); a shared
        reader intentionally never deletes another writer's in-flight temp.
        ``recover()`` with no physical half-line is a zero-byte no-op for the
        data but still runs that settlement.
        """
        chain = type(self.chain)(self.path)
        chain.recover()

    # ------------------------------------------------------------------
    # Migration matrix (file layout -> segment store)
    # ------------------------------------------------------------------

    def test_migration_crash_matrix(self) -> None:
        # point -> expected topology after reopen ("file" = old, "dir" = new)
        expect_dir = {
            "migrate:first-segment:segment-tmp": False,
            "migrate:first-segment:segment-rename": False,
            "migrate:second-segment:segment-tmp": False,
            "migrate:second-segment:segment-rename": False,
            "migrate:manifest:tmp": False,
            "migrate:manifest:rename": False,
            "migrate:rename-backup": False,
            "migrate:publish": True,
            "migrate:cleanup": True,
        }
        for point, should_be_dir in expect_dir.items():
            with self.subTest(point=point):
                try:
                    self._setup("setup-file")
                    proc = self._run("migrate", point)
                    self.assertEqual(proc.returncode, -9, proc.stderr.decode())
                    # Settle happens on the first locked operation.
                    chain = type(self.chain)(self.path)
                    self._assert_intact_prefix(6, 0)
                    self._exclusive_settle()
                    self.assertEqual(os.path.isdir(self.path), should_be_dir)
                    self.assertEqual(os.path.isfile(self.path), not should_be_dir)
                    self._assert_no_debris()
                    self._assert_segments_referenced()
                    # A subsequent rotate/append always succeeds post-recovery.
                    if not should_be_dir:
                        chain.rotate()
                    chain.append("t", {"i": 6})
                    self.assertTrue(chain.verify("t")["ok"])
                finally:
                    import shutil

                    shutil.rmtree(self._tmp, ignore_errors=True)
                    os.makedirs(self._tmp)

    # ------------------------------------------------------------------
    # Append windows
    # ------------------------------------------------------------------

    def test_append_half_line_window_is_not_silently_fixed(self) -> None:
        self._setup("setup-rotate")
        proc = self._run("append", "append:write")
        self.assertEqual(proc.returncode, -9)
        chain = type(self.chain)(self.path)
        # The physical half-line keeps the documented bad-line semantics.
        with self.assertRaises(ValueError):
            chain.verify("t")
        with self.assertRaises(ValueError):
            chain.entries("t")
        removed = chain.recover()["truncated_bytes"]
        self.assertGreater(removed, 0)
        self._assert_intact_prefix(10, 10)
        self._assert_no_debris()

    def test_append_durable_windows_keep_full_line(self) -> None:
        for point in ("append:flush", "append:fsync"):
            with self.subTest(point=point):
                try:
                    self._setup("setup-rotate")
                    proc = self._run("append", point)
                    self.assertEqual(proc.returncode, -9)
                    # Whole record or nothing: no half-line, prefix intact with
                    # the new record (its flush/fsync window left a complete line).
                    self._assert_intact_prefix(11, 10)
                    self._assert_no_debris()
                finally:
                    import shutil

                    shutil.rmtree(self._tmp, ignore_errors=True)
                    os.makedirs(self._tmp)

    # ------------------------------------------------------------------
    # Rotate (seal + new active) windows
    # ------------------------------------------------------------------

    def test_rotate_crash_matrix(self) -> None:
        points = [
            "rotate:active:segment-tmp",
            "rotate:active:segment-rename",
            "rotate:manifest:tmp",
            "rotate:manifest:rename",
            "rotate:cache:tmp",
            "rotate:cache:rename",
        ]
        for point in points:
            with self.subTest(point=point):
                try:
                    self._setup("setup-rotate")
                    proc = self._run("rotate", point)
                    self.assertEqual(proc.returncode, -9, proc.stderr.decode())
                    self.assertTrue(os.path.isdir(self.path))
                    self._assert_intact_prefix(10, 10)
                    self._exclusive_settle()
                    self._assert_no_debris()
                    # Reopening with readers works, then rotation can complete.
                    chain = type(self.chain)(self.path)
                    chain.rotate()
                    chain.append("t", {"i": 10})
                    self.assertTrue(chain.verify("t")["ok"])
                finally:
                    import shutil

                    shutil.rmtree(self._tmp, ignore_errors=True)
                    os.makedirs(self._tmp)

    # ------------------------------------------------------------------
    # Compaction windows (including old-segment deletion)
    # ------------------------------------------------------------------

    def test_compaction_crash_matrix(self) -> None:
        points = [
            "compact:segment:segment-tmp",
            "compact:segment:segment-rename",
            "compact:manifest:tmp",
            "compact:manifest:rename",
            "compact:cache:tmp",
            "compact:cache:rename",
        ]
        for point in points:
            with self.subTest(point=point):
                try:
                    self._setup("setup-compact")
                    proc = self._run("compact2", point)
                    self.assertEqual(proc.returncode, -9, proc.stderr.decode())
                    self.assertTrue(os.path.isdir(self.path))
                    self._assert_intact_prefix(10, 0)
                    self._exclusive_settle()
                    self._assert_no_debris()
                finally:
                    import shutil

                    shutil.rmtree(self._tmp, ignore_errors=True)
                    os.makedirs(self._tmp)

    def test_kill_after_manifest_commit_leaves_reapable_orphans(self) -> None:
        self._setup("setup-compact")
        proc = self._run("compact2", "compact:delete")
        self.assertEqual(proc.returncode, -9)
        # New topology is committed; some old source files may still exist.
        chain = type(self.chain)(self.path)
        self.assertTrue(chain.verify("t")["ok"])
        with open(os.path.join(self.path, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        referenced = {segment["name"] for segment in manifest["segments"]}
        on_disk = {
            name
            for name in os.listdir(self.path)
            if name.startswith("seg-") and name.endswith(".jsonl")
        }
        self.assertTrue(on_disk - referenced)  # at least one orphan
        # The next exclusive open reaps the unreferenced files.
        chain.append("t", {"i": 10})
        on_disk = {
            name
            for name in os.listdir(self.path)
            if name.startswith("seg-") and name.endswith(".jsonl")
        }
        self.assertEqual(on_disk, referenced | {self._active_name()})
        self._assert_intact_prefix(11, 0)

    def _active_name(self) -> str:
        with open(os.path.join(self.path, "manifest.json"), encoding="utf-8") as fh:
            return json.load(fh)["active"]
