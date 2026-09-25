"""Online archiving: sealed segments migrate to a caller-specified cold tier.

Every operation keeps working across the hot store and the archive
directory: verdicts, first-bad indices, rotation order, exports and
recovery are exactly what they were with all segments hot, and a migration
killed at any point reopens onto one complete topology -- never a half
moved segment or copies left in both tiers.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from audit_chain import Chain, combine_proofs, verify_proof, verify_proofs
from tests._helpers import REPO_ROOT, AuditTestCase

WORKER = os.path.join(REPO_ROOT, "tests", "_crash_worker.py")


class ArchiveTest(AuditTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.dest = os.path.join(self._tmp, "archive")

    def build_segments(self, per_segment: int = 3, rotations: int = 2) -> int:
        """Append per_segment records, rotate, repeat; return the total."""
        total = 0
        for _ in range(rotations):
            self.append_many("t", per_segment, start=total)
            total += per_segment
            self.chain.rotate()
        self.append_many("t", per_segment, start=total)
        total += per_segment
        return total

    def hot_segments(self) -> list[str]:
        return self.segment_files()

    def cold_segments(self) -> list[str]:
        if not os.path.isdir(self.dest):
            return []
        return sorted(
            name
            for name in os.listdir(self.dest)
            if name.startswith("seg-") and name.endswith(".jsonl")
        )

    def manifest(self) -> dict:
        with open(os.path.join(self.path, "manifest.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def assert_one_topology(self) -> None:
        """Every manifest segment lives in exactly one tier; nothing else does."""
        manifest = self.manifest()
        archived = {s["name"] for s in manifest["segments"] if s.get("archived")}
        hot = set(self.hot_segments())
        cold = set(self.cold_segments())
        self.assertFalse(hot & cold, f"segment in both tiers: {hot & cold}")
        for segment in manifest["segments"]:
            name = segment["name"]
            if name in archived:
                self.assertIn(name, cold)
                self.assertNotIn(name, hot)
            else:
                self.assertIn(name, hot)
                self.assertNotIn(name, cold)
        self.assertEqual(cold, archived)
        self.assertFalse(os.path.exists(os.path.join(self.path, ".archiving")))

    # -- basic two-tier behaviour -----------------------------------------

    def test_archive_moves_sealed_segments_and_keeps_every_verdict(self) -> None:
        total = self.build_segments()
        verdict_before = self.chain.verify("t")
        head_before = self.chain.head("t")
        entries_before = self.chain.entries("t")

        result = self.chain.archive(self.dest)
        self.assertEqual(result, {"archived": 2})

        # The hot directory no longer holds the migrated segments.
        self.assertEqual(len(self.hot_segments()), 1)
        self.assertEqual(len(self.cold_segments()), 2)
        self.assert_one_topology()

        # Verdicts, head and entries are identical across the tiers.
        self.assertEqual(self.chain.verify("t"), verdict_before)
        self.assertEqual(
            self.chain.verify("t"), {"count": total, "first_bad": -1, "ok": True}
        )
        self.assertEqual(self.chain.head("t"), head_before)
        self.assertEqual(self.chain.entries("t"), entries_before)

        # A second call migrates nothing.
        self.assertEqual(self.chain.archive(self.dest), {"archived": 0})

    def test_append_rotate_compact_recover_across_tiers(self) -> None:
        self.build_segments(per_segment=2, rotations=2)
        self.chain.archive(self.dest)

        # Append lands after the archived prefix with continuous indices.
        self.chain.append("t", {"i": 6})
        self.assertEqual(self.chain.verify("t")["count"], 7)
        self.assertEqual(self.chain.entries("t")[-1]["payload"]["i"], 6)

        # Rotation order is unchanged: the new segment continues the sequence.
        self.chain.rotate()
        names = [s["name"] for s in self.manifest()["segments"]]
        self.assertEqual(names, sorted(names))
        self.assertEqual(len(set(names)), len(names))
        self.chain.append("t", {"i": 7})

        # Compaction folds across tiers without losing order or verdicts.
        result = self.chain.compact(2)
        self.assertEqual(result, {"segments": 2})
        self.assertEqual(
            self.chain.verify("t"), {"count": 8, "first_bad": -1, "ok": True}
        )
        self.assertEqual(
            [e["payload"]["i"] for e in self.chain.entries("t")], list(range(8))
        )
        self.assert_one_topology()

        # Recovery still truncates only the active half line.
        active = self.manifest()["active"]
        with open(os.path.join(self.path, active), "ab") as handle:
            handle.write(b'{"digest":"x"')
        with self.assertRaises(ValueError):
            self.chain.verify("t")
        self.assertEqual(self.chain.recover()["truncated_bytes"], len(b'{"digest":"x"'))
        self.assertEqual(
            self.chain.verify("t"), {"count": 8, "first_bad": -1, "ok": True}
        )

    def test_first_bad_index_is_identical_across_tiers(self) -> None:
        self.build_segments(per_segment=4, rotations=1)
        self.chain.archive(self.dest)
        # Damage a record that now lives in the archive tier.
        cold = self.cold_segments()[0]
        with open(os.path.join(self.dest, cold), "rb") as handle:
            data = handle.read()
        data = data.replace(b'{"i":2}', b'{"i":9}', 1)
        with open(os.path.join(self.dest, cold), "wb") as handle:
            handle.write(data)
        result = self.chain.verify("t")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"], 2)
        self.assertEqual(result["count"], 8)

    def test_archive_refuses_a_corrupt_chain(self) -> None:
        self.build_segments(per_segment=3, rotations=1)
        first = self.hot_segments()[0]
        self.replace_in_file(b'{"i":1}', b'{"i":7}', first)
        with self.assertRaises(ValueError):
            self.chain.archive(self.dest)
        # Nothing moved.
        self.assertEqual(self.cold_segments(), [])
        self.assertFalse(os.path.isdir(self.dest))

    def test_archive_errors(self) -> None:
        # Legacy file layout: rotate first.
        self.append_many("t", 2)
        with self.assertRaises(ValueError):
            self.chain.archive(self.dest)

        self.chain.rotate()
        # The store itself is not a valid archive location.
        with self.assertRaises(ValueError):
            self.chain.archive(self.path)
        # Nor is another live segment store.
        other = Chain(os.path.join(self._tmp, "other"))
        other.append("t", {"i": 0})
        other.rotate()
        with self.assertRaises(ValueError):
            self.chain.archive(os.path.join(self._tmp, "other"))

        # The recorded location cannot change between calls.
        self.assertEqual(self.chain.archive(self.dest), {"archived": 1})
        with self.assertRaises(ValueError):
            self.chain.archive(os.path.join(self._tmp, "elsewhere"))

    def test_archive_is_offline_for_untouched_tenants(self) -> None:
        self.append_many("t", 3)
        self.append_many("u", 2)
        self.chain.rotate()
        self.append_many("t", 1, start=3)
        self.chain.archive(self.dest)
        self.assertEqual(
            self.chain.verify("u"), {"count": 2, "first_bad": -1, "ok": True}
        )
        self.assertEqual(
            [e["payload"] for e in self.chain.entries("u")], [{"i": 0}, {"i": 1}]
        )

    # -- offline proofs across tiers ---------------------------------------

    def test_export_combine_and_batch_across_tiers(self) -> None:
        self.build_segments(per_segment=4, rotations=2)
        self.chain.archive(self.dest)

        # An interval spanning the tier boundary exports and verifies.
        proof = self.chain.export_range("t", 2, 10)
        self.assertTrue(verify_proof(proof, tenant="t", start=2, end=10)["ok"])

        left = self.chain.export_range("t", 0, 5)
        right = self.chain.export_range("t", 5, 12)
        combined = combine_proofs(left, right)
        self.assertTrue(verify_proof(combined, start=0, end=12)["ok"])

        verdicts = verify_proofs([proof, left, right, combined])
        self.assertEqual(len(verdicts), 4)
        for verdict in verdicts:
            self.assertTrue(verdict["ok"], verdict)
            self.assertEqual(set(verdict), {"ok", "first_bad", "count"})

    def test_export_after_archive_opens_only_covering_segments(self) -> None:
        import builtins

        self.build_segments(per_segment=50, rotations=2)
        self.assertTrue(self.chain.verify("t")["ok"])  # warm the cache
        self.chain.archive(self.dest)
        # Re-warm across the tiers so the guide covers every unit.
        self.assertTrue(self.chain.verify("t")["ok"])

        opened: set[str] = set()
        real_open = builtins.open

        def counting_open(path, *args, **kwargs):
            mode = args[0] if args else kwargs.get("mode", "r")
            handle = real_open(path, *args, **kwargs)
            if "b" in mode:
                opened.add(os.path.abspath(os.fspath(path)))
            return handle

        # The interval [10, 20) lives wholly in the first (archived) segment.
        builtins.open = counting_open
        try:
            proof = self.chain.export_range("t", 10, 20)
        finally:
            builtins.open = real_open

        self.assertTrue(verify_proof(proof, start=10, end=20)["ok"])
        segment_paths = {
            os.path.abspath(os.path.join(self.path, name))
            for name in self.hot_segments()
        } | {
            os.path.abspath(os.path.join(self.dest, name))
            for name in self.cold_segments()
        }
        opened_segments = opened & segment_paths
        self.assertEqual(len(opened_segments), 1)
        self.assertTrue(opened_segments.pop().startswith(os.path.abspath(self.dest)))

    # -- cache warmth across the move --------------------------------------

    def test_verify_after_archive_does_not_rehash_archived_bytes(self) -> None:
        import hashlib

        self.build_segments(per_segment=1000, rotations=1)
        self.assertTrue(self.chain.verify("t")["ok"])  # warm the cache
        self.chain.archive(self.dest)

        hashed = 0
        real_sha256 = hashlib.sha256

        def counting_sha256(data: bytes = b""):
            nonlocal hashed
            instance = real_sha256(data)
            hashed += len(data)

            class _H:
                def update(self_inner, chunk: bytes) -> None:
                    nonlocal hashed
                    hashed += len(chunk)
                    instance.update(chunk)

                def hexdigest(self_inner) -> str:
                    return instance.hexdigest()

                def copy(self_inner):
                    return self_inner

            return _H()

        cold_size = sum(
            os.path.getsize(os.path.join(self.dest, name))
            for name in self.cold_segments()
        )
        hashlib.sha256 = counting_sha256
        try:
            result = self.chain.verify("t")
        finally:
            hashlib.sha256 = real_sha256
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 2000)
        # The cache was carried across the move: no archived byte is rehashed.
        self.assertLess(hashed, cold_size // 50)

    # -- crash matrix --------------------------------------------------------

    def _kill(self, point: str) -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
        completed = subprocess.run(
            [sys.executable, WORKER, self.path, "archive", point, self.dest],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(
            completed.returncode, 0, f"archive@{point} did not die"
        )

    def test_killed_archive_reopens_on_one_topology(self) -> None:
        points = (
            "archive:after_marker",
            "archive:after_location",
            "archive:before_copy_fsync",
            "archive:after_copy_write",
            "archive:after_copy_rename",
            "archive:after_copy",
            "archive:after_manifest",
            "archive:during_delete",
            "archive:after_delete",
            "atomic:manifest.json:before_replace",
        )
        for index, point in enumerate(points):
            with self.subTest(point=point):
                path = os.path.join(self._tmp, f"victim-{index}")
                dest = os.path.join(self._tmp, f"victim-{index}.archive")
                chain = type(self.chain)(path)
                for round_ in range(2):
                    for i in range(3):
                        chain.append("t", {"i": round_ * 3 + i})
                    chain.rotate()
                chain.append("t", {"i": 6})

                env = dict(os.environ)
                env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
                completed = subprocess.run(
                    [sys.executable, WORKER, path, "archive", point, dest],
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                self.assertNotEqual(completed.returncode, 0, point)

                # Reopen: the very first read heals the tree onto exactly
                # one topology and sees a complete, strictly linked prefix.
                reopened = type(self.chain)(path)
                self.assertEqual(
                    reopened.verify("t"),
                    {"count": 7, "first_bad": -1, "ok": True},
                    point,
                )
                self.assertEqual(
                    [e["payload"]["i"] for e in reopened.entries("t")],
                    list(range(7)),
                    point,
                )
                # No segment is lost or kept in both tiers, and each tier
                # holds exactly the segments the manifest assigns to it.
                hot = {
                    n
                    for n in os.listdir(path)
                    if n.startswith("seg-") and n.endswith(".jsonl")
                }
                cold = {
                    n
                    for n in os.listdir(dest)
                    if n.startswith("seg-") and n.endswith(".jsonl")
                } if os.path.isdir(dest) else set()
                self.assertFalse(hot & cold, point)
                with open(os.path.join(path, "manifest.json"), encoding="utf-8") as fh:
                    manifest = json.load(fh)
                archived = {
                    s["name"] for s in manifest["segments"] if s.get("archived")
                }
                referenced = {s["name"] for s in manifest["segments"]}
                self.assertEqual(cold, archived, point)
                self.assertEqual(hot, referenced - archived, point)
                self.assertFalse(
                    os.path.exists(os.path.join(path, ".archiving")), point
                )
                # No staged temp files survive in either tier.
                for directory in (path, dest):
                    if os.path.isdir(directory):
                        self.assertEqual(
                            [
                                n
                                for n in os.listdir(directory)
                                if n.startswith(".") and n.endswith(".tmp")
                            ],
                            [],
                            point,
                        )

                # The store keeps accepting writes and can archive again.
                reopened.append("t", {"i": 7})
                self.assertEqual(reopened.verify("t")["count"], 8, point)
                result = reopened.archive(dest)
                self.assertIn(result["archived"], (0, 2, 3), point)
                self.assertEqual(
                    reopened.verify("t"),
                    {"count": 8, "first_bad": -1, "ok": True},
                    point,
                )

    def test_killed_after_manifest_commit_settles_on_post_topology(self) -> None:
        self.build_segments(per_segment=3, rotations=2)
        self._kill("archive:after_manifest")
        reopened = type(self.chain)(self.path)
        self.assertEqual(
            reopened.verify("t"), {"count": 9, "first_bad": -1, "ok": True}
        )
        # The post-archive topology won: both sealed segments are archived
        # and their hot duplicates are reaped by the healing read.
        self.assert_one_topology()
        self.assertEqual(len(self.cold_segments()), 2)

    def test_killed_before_copy_settles_on_pre_topology(self) -> None:
        self.build_segments(per_segment=3, rotations=2)
        self._kill("archive:after_location")
        reopened = type(self.chain)(self.path)
        self.assertEqual(
            reopened.verify("t"), {"count": 9, "first_bad": -1, "ok": True}
        )
        # No segment was archived yet; the hot tier owns every segment.
        self.assertEqual(self.cold_segments(), [])
        self.assertEqual(len(self.hot_segments()), 3)
        self.assertFalse(os.path.exists(os.path.join(self.path, ".archiving")))


class ArchiveConcurrencyTest(AuditTestCase):
    def test_reads_during_archive_see_one_complete_prefix(self) -> None:
        import multiprocessing
        import time

        for round_ in range(2):
            self.append_many("t", 3, start=round_ * 3)
            self.chain.rotate()
        self.chain.append("t", {"i": 6})
        dest = os.path.join(self._tmp, "archive")
        path = self.path
        ctx = multiprocessing.get_context("fork")

        def archiver() -> None:  # pragma: no cover
            sys.path.insert(0, REPO_ROOT)
            from audit_chain import Chain

            chain = Chain(path)
            for _ in range(6):
                chain.archive(dest)
                chain.append("t", {"i": 100})
                chain.rotate()
                time.sleep(0.005)

        def appender() -> None:  # pragma: no cover
            sys.path.insert(0, REPO_ROOT)
            from audit_chain import Chain

            chain = Chain(path)
            for i in range(30):
                chain.append("u", {"i": i})

        workers = [ctx.Process(target=archiver), ctx.Process(target=appender)]
        for process in workers:
            process.start()
        while any(process.is_alive() for process in workers):
            entries = self.chain.entries("t")
            # One snapshot: a complete prefix, never mixed or duplicated.
            for pos, entry in enumerate(entries):
                self.assertEqual(
                    entry["prev"], entries[pos - 1]["digest"] if pos else ""
                )
            result = self.chain.verify("t")
            self.assertTrue(result["ok"], result)
        for process in workers:
            process.join(timeout=60)
            self.assertEqual(process.exitcode, 0)

        final = self.chain.verify("t")
        self.assertTrue(final["ok"])
        self.assertEqual(self.chain.verify("u"), {"count": 30, "first_bad": -1, "ok": True})
        # Every segment sits in exactly one tier and the marker is gone.
        with open(os.path.join(self.path, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        archived = {s["name"] for s in manifest["segments"] if s.get("archived")}
        hot = {
            n
            for n in os.listdir(self.path)
            if n.startswith("seg-") and n.endswith(".jsonl")
        }
        cold = (
            {
                n
                for n in os.listdir(dest)
                if n.startswith("seg-") and n.endswith(".jsonl")
            }
            if os.path.isdir(dest)
            else set()
        )
        self.assertFalse(hot & cold)
        self.assertEqual(cold, archived)
        self.assertFalse(os.path.exists(os.path.join(self.path, ".archiving")))
