"""Persisted shard directories (export_shards_dir) and random access
(open_shard): on-disk layout, resumable export, offline retrieval."""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import subprocess
import sys
from functools import reduce

from audit_chain import (
    combine_proofs,
    open_shard,
    verify_proof,
    verify_proof_stream,
)
from audit_chain.record import canonical_json
from audit_chain.sharddir import LOCK_NAME, MANIFEST_NAME
from tests._helpers import AuditTestCase, REPO_ROOT
from tests.test_export_cost import _ReadMeter


class ShardDirCase(AuditTestCase):
    WINDOW = 7
    END = 52

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
        for i in range(35, self.END):
            self.chain.append("t", {"i": i})
        self.chain.compact(2)

    def _export(self, directory: str | None = None) -> dict:
        directory = directory or os.path.join(self._tmp, "shards")
        return self.chain.export_shards_dir(
            "t", 0, self.END, self.WINDOW, directory
        )

    def _dir(self) -> str:
        return os.path.join(self._tmp, "shards")

    def _memory_shards(self) -> list[dict]:
        return list(self.chain.export_shards("t", 0, self.END, self.WINDOW))

    def _manifest(self, directory: str) -> dict:
        with open(os.path.join(directory, MANIFEST_NAME), "rb") as handle:
            raw = handle.read()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b"\n", raw[:-1])  # exactly one compact line
        return json.loads(raw.decode("utf-8")[:-1])


class ExportShardsDirLayoutTest(ShardDirCase):
    def test_one_file_per_shard_byte_identical_to_memory(self) -> None:
        self._multi_segment()
        result = self._export()
        shards = self._memory_shards()
        self.assertEqual(result, {"shards": len(shards)})
        self.assertEqual(set(result), {"shards"})  # no other keys
        names = sorted(
            name
            for name in os.listdir(self._dir())
            if name.startswith("shard-")
        )
        self.assertEqual(len(names), len(shards))
        for index, shard in enumerate(shards):
            name = f"shard-{index:08d}.json"
            self.assertIn(name, names)
            with open(os.path.join(self._dir(), name), "rb") as handle:
                # Byte-identical to the in-memory shard's canonical form.
                self.assertEqual(handle.read(), canonical_json(shard).encode("utf-8"))

    def test_manifest_is_one_compact_line_and_self_authenticating(self) -> None:
        self._multi_segment()
        self._export()
        shards = self._memory_shards()
        manifest = self._manifest(self._dir())
        self.assertEqual(manifest["tenant"], "t")
        self.assertEqual((manifest["start"], manifest["end"]), (0, self.END))
        self.assertEqual(manifest["window"], self.WINDOW)
        self.assertEqual(len(manifest["shards"]), len(shards))
        for index, entry in enumerate(manifest["shards"]):
            self.assertEqual(entry["name"], f"shard-{index:08d}.json")
            self.assertEqual(
                (entry["start"], entry["end"]),
                (shards[index]["start"], shards[index]["end"]),
            )
            with open(os.path.join(self._dir(), entry["name"]), "rb") as handle:
                self.assertEqual(
                    entry["sha256"], hashlib.sha256(handle.read()).hexdigest()
                )
        # The tag authenticates the manifest body.
        body = {key: manifest[key] for key in manifest if key != "tag"}
        self.assertEqual(
            manifest["tag"],
            hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest(),
        )

    def test_restored_directory_matches_one_shot_export(self) -> None:
        self._multi_segment()
        result = self._export()
        one_shot = verify_proof(self.chain.export_range("t", 0, self.END))
        streamed = verify_proof_stream(
            open_shard(self._dir(), i) for i in range(result["shards"])
        )
        self.assertEqual(streamed["total"], one_shot)
        self.assertTrue(streamed["total"]["ok"])
        combined = reduce(
            combine_proofs,
            [open_shard(self._dir(), i) for i in range(result["shards"])],
        )
        self.assertEqual(verify_proof(combined), one_shot)

    def test_restore_matches_after_compaction_and_archiving(self) -> None:
        self._multi_segment()
        self.chain.archive(os.path.join(self._tmp, "archive"))
        self._export()
        one_shot = verify_proof(self.chain.export_range("t", 0, self.END))
        restored = verify_proof_stream(
            open_shard(self._dir(), i)
            for i in range(self._export()["shards"])
        )
        self.assertEqual(restored["total"], one_shot)

    def test_export_does_not_touch_the_store(self) -> None:
        self._multi_segment()
        before = sorted(os.listdir(self.path))
        self._export()
        self.assertEqual(sorted(os.listdir(self.path)), before)

    def test_tenants_stay_isolated(self) -> None:
        self._multi_segment()
        self._export()
        for index in range(self._export()["shards"]):
            shard = open_shard(self._dir(), index)
            for window in shard["windows"]:
                for item in window["records"]:
                    self.assertEqual(item["record"]["tenant"], "t")

    def test_export_from_a_legacy_file_log(self) -> None:
        self.append_many("t", 9)
        result = self.chain.export_shards_dir("t", 0, 9, 4, self._dir())
        self.assertEqual(result, {"shards": 3})
        for index, shard in enumerate(self.chain.export_shards("t", 0, 9, 4)):
            self.assertEqual(open_shard(self._dir(), index), shard)

    def test_damage_outside_the_interval_does_not_change_it(self) -> None:
        self.append_many("t", 25)
        # Corrupt a record outside the exported interval in the log itself.
        target = json.dumps({"i": 24}, separators=(",", ":"), sort_keys=True)
        forged = json.dumps({"i": 99}, separators=(",", ":"), sort_keys=True)
        self.replace_in_file(target.encode(), forged.encode())
        result = self.chain.export_shards_dir("t", 0, 20, 7, self._dir())
        self.assertEqual(result, {"shards": 3})
        restored = verify_proof_stream(
            open_shard(self._dir(), i) for i in range(3)
        )
        self.assertTrue(restored["total"]["ok"])
        self.assertEqual(
            restored["total"],
            verify_proof(self.chain.export_range("t", 0, 20)),
        )

    def test_disk_and_memory_shards_splice_identically(self) -> None:
        self._multi_segment()
        self._export()
        memory = self._memory_shards()
        disk = [open_shard(self._dir(), i) for i in range(len(memory))]
        # A shard read back from disk is content-equal to its in-memory
        # form, so splicing never depends on which side came from disk.
        mixed = reduce(
            combine_proofs,
            [disk[i] if i % 2 == 0 else memory[i] for i in range(len(memory))],
        )
        self.assertEqual(
            verify_proof(mixed), verify_proof(self.chain.export_range("t", 0, self.END))
        )
        # Associativity is preserved over the persisted shards.
        left_assoc = reduce(combine_proofs, disk)
        right_assoc = disk[0]
        for shard in disk[1:]:
            right_assoc = combine_proofs(right_assoc, shard)
        self.assertEqual(verify_proof(left_assoc), verify_proof(right_assoc))

    def test_verdicts_agree_across_offline_batch_and_cli(self) -> None:
        from audit_chain import verify_proofs

        self._multi_segment()
        self._export()
        count = self._export()["shards"]
        shards = [open_shard(self._dir(), i) for i in range(count)]
        combined = reduce(combine_proofs, shards)
        offline = verify_proof(combined)
        (batch,) = verify_proofs([combined])
        self.assertEqual(
            (offline["ok"], offline["first_bad"], offline["count"]),
            (batch["ok"], batch["first_bad"], batch["count"]),
        )
        proof_file = os.path.join(self._tmp, "proof.json")
        with open(proof_file, "w", encoding="utf-8") as handle:
            json.dump(combined, handle)
        proc = subprocess.run(
            [sys.executable, "-m", "audit_chain", "verify-proof", proof_file],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        cli = json.loads(proc.stdout)
        self.assertEqual(
            cli,
            {
                "ok": offline["ok"],
                "first_bad": offline["first_bad"],
                "count": offline["count"],
            },
        )


class ExportShardsDirResumeTest(ShardDirCase):
    def test_complete_resume_rewrites_nothing(self) -> None:
        self._multi_segment()
        self._export()
        before = {
            name: os.path.getmtime(os.path.join(self._dir(), name))
            for name in os.listdir(self._dir())
        }
        result = self._export()
        self.assertEqual(result, {"shards": len(self._memory_shards())})
        after = {
            name: os.path.getmtime(os.path.join(self._dir(), name))
            for name in os.listdir(self._dir())
        }
        self.assertEqual(before, after)

    def test_interrupted_export_resumes_from_the_committed_prefix(self) -> None:
        self._multi_segment()
        shards = self._memory_shards()
        directory = self._dir()
        os.makedirs(directory)
        # Simulate a kill after two committed shards: two shard files and
        # a manifest vouching for exactly them.
        entries = []
        manifest = {
            "version": 1,
            "tenant": "t",
            "start": 0,
            "end": self.END,
            "window": self.WINDOW,
            "shards": entries,
        }
        from audit_chain import sharddir as sd

        for index in range(2):
            raw = canonical_json(shards[index]).encode("utf-8")
            sd.write_shard(directory, sd.shard_name(index), raw)
            entries.append(
                {
                    "name": sd.shard_name(index),
                    "start": shards[index]["start"],
                    "end": shards[index]["end"],
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
            sd.save_manifest(directory, manifest)
        committed_mtimes = {
            entry["name"]: os.path.getmtime(os.path.join(directory, entry["name"]))
            for entry in entries
        }

        result = self._export()
        self.assertEqual(result, {"shards": len(shards)})
        # The committed prefix was not rewritten.
        for name, mtime in committed_mtimes.items():
            self.assertEqual(
                os.path.getmtime(os.path.join(directory, name)), mtime
            )
        for index, shard in enumerate(shards):
            self.assertEqual(open_shard(directory, index), shard)

    def test_missing_shard_file_is_refilled(self) -> None:
        self._multi_segment()
        self._export()
        shards = self._memory_shards()
        victim = os.path.join(self._dir(), "shard-00000002.json")
        os.remove(victim)
        result = self._export()
        self.assertEqual(result, {"shards": len(shards)})
        self.assertEqual(open_shard(self._dir(), 2), shards[2])

    def test_stale_temp_files_are_reaped(self) -> None:
        self._multi_segment()
        self._export()
        junk = os.path.join(self._dir(), ".shard-00000003.json.123.4.tmp")
        with open(junk, "wb") as handle:
            handle.write(b"half-written")
        self._export()
        self.assertNotIn(os.path.basename(junk), os.listdir(self._dir()))

    def test_killed_export_leaves_old_or_new_state_and_resumes(self) -> None:
        self._multi_segment()
        directory = self._dir()
        script = (
            "import sys;"
            "sys.path.insert(0, %r);"
            "from audit_chain import Chain;"
            "Chain(%r).export_shards_dir('t', 0, %d, %d, %r)"
            % (os.getcwd(), self.path, self.END, self.WINDOW, directory)
        )
        env = dict(os.environ)
        env["AUDIT_CHAIN_CRASH"] = "atomic:shard-00000003.json:before_replace"
        proc = subprocess.run(
            [sys.executable, "-c", script],
            env=env,
            capture_output=True,
        )
        self.assertNotEqual(proc.returncode, 0)  # hard-killed mid-export
        # Whatever the kill left behind, a fresh call completes the export
        # and the result matches the uninterrupted one.
        result = self._export()
        self.assertEqual(result, {"shards": len(self._memory_shards())})
        for index, shard in enumerate(self._memory_shards()):
            self.assertEqual(open_shard(directory, index), shard)
        leftovers = [
            name
            for name in os.listdir(directory)
            if name.startswith(".") and name.endswith(".tmp")
        ]
        self.assertEqual(leftovers, [])

    def test_resume_reads_only_the_missing_increment(self) -> None:
        for i in range(52):
            self.chain.append("t", {"i": i})
            if (i + 1) % 13 == 0:
                self.chain.rotate()
        self.assertTrue(self.chain.verify("t")["ok"])  # warm the cache
        self._export()
        # Shard 2 holds records 14..20, all inside the second segment.
        os.remove(os.path.join(self._dir(), "shard-00000002.json"))
        seg_files = {
            os.path.abspath(os.path.join(self.path, name))
            for name in self.segment_files()
        }
        self.assertGreater(len(seg_files), 2)
        meter = _ReadMeter()
        meter.install()
        try:
            self._export()
        finally:
            meter.remove()
        # The refill opens only the one segment covering the missing
        # shard, never the rest of the history.
        opened_segments = meter.paths & seg_files
        self.assertEqual(len(opened_segments), 1)


class ExportShardsDirIncrementTest(ShardDirCase):
    """The log keeps growing; re-landing the same directory extends it."""

    WINDOW = 7

    def _land(self, end: int) -> dict:
        return self.chain.export_shards_dir(
            "t", 0, end, self.WINDOW, self._dir()
        )

    def _disk_conclusion(self, count: int) -> dict:
        return verify_proof_stream(
            open_shard(self._dir(), i) for i in range(count)
        )["total"]

    def test_new_shards_tile_on_from_the_last_committed_end(self) -> None:
        self.append_many("t", 30)
        result = self._land(30)
        self.assertEqual(result, {"shards": 5})  # 7,7,7,7,2 -- short edge
        mtimes = {
            name: os.path.getmtime(os.path.join(self._dir(), name))
            for name in os.listdir(self._dir())
            if name.startswith("shard-")
        }
        self.append_many("t", 11, start=30)
        result = self._land(41)
        # 30..37, 37..40 (aligned on the old short edge? no: the edge was
        # 28..30, so the new grid starts at 30): 30..37, 37..41.
        self.assertEqual(result, {"shards": 7})
        manifest = self._manifest(self._dir())
        intervals = [(entry["start"], entry["end"]) for entry in manifest["shards"]]
        self.assertEqual(
            intervals,
            [(0, 7), (7, 14), (14, 21), (21, 28), (28, 30), (30, 37), (37, 41)],
        )
        # No gap, no overlap, straight from zero to the read-time prefix.
        self.assertEqual([lo for lo, _ in intervals], [0] + [hi for _, hi in intervals[:-1]])
        self.assertEqual(intervals[-1][1], 41)
        self.assertEqual(
            [entry["name"] for entry in manifest["shards"]],
            [f"shard-{i:08d}.json" for i in range(7)],
        )
        for entry in manifest["shards"]:
            self.assertEqual(
                entry["size"],
                os.path.getsize(os.path.join(self._dir(), entry["name"])),
            )
        # The old shards, including the short edge shard, were not rewritten.
        for name, mtime in mtimes.items():
            self.assertEqual(
                os.path.getmtime(os.path.join(self._dir(), name)), mtime
            )
        # The extended directory is item-wise identical to a one-shot export
        # of the same interval.
        self.assertEqual(
            self._disk_conclusion(7), verify_proof(self.chain.export_range("t", 0, 41))
        )

    def test_extension_after_several_growth_rounds(self) -> None:
        self.append_many("t", 10)
        self._land(10)
        ends = [10]
        for round_end in (23, 24, 50, 71):
            self.append_many("t", round_end - ends[-1], start=ends[-1])
            self._land(round_end)
            ends.append(round_end)
        manifest = self._manifest(self._dir())
        intervals = [(e["start"], e["end"]) for e in manifest["shards"]]
        self.assertEqual(intervals[0][0], 0)
        self.assertEqual(intervals[-1][1], 71)
        self.assertEqual(
            [lo for lo, _ in intervals], [0] + [hi for _, hi in intervals[:-1]]
        )
        count = len(intervals)
        self.assertEqual(self._land(71), {"shards": count})  # idempotent
        self.assertEqual(
            self._disk_conclusion(count),
            verify_proof(self.chain.export_range("t", 0, 71)),
        )

    def test_extension_survives_rotation_compaction_and_archive(self) -> None:
        for i in range(20):
            self.chain.append("t", {"i": i})
        self.chain.rotate()
        for i in range(20, 30):
            self.chain.append("t", {"i": i})
        self._land(30)
        for i in range(30, 47):
            self.chain.append("t", {"i": i})
        self.chain.rotate()
        self.chain.compact(2)
        self._land(47)
        self.chain.archive(os.path.join(self._tmp, "archive"))
        for i in range(47, 55):
            self.chain.append("t", {"i": i})
        count = self._land(55)["shards"]
        self.assertEqual(
            self._disk_conclusion(count),
            verify_proof(self.chain.export_range("t", 0, 55)),
        )

    def test_other_tenants_do_not_extend_the_directory(self) -> None:
        self.append_many("t", 12)
        self._land(12)
        self.append_many("u", 30)
        # The t prefix is still 12 records; the same call lands nothing new.
        self.assertEqual(self._land(12), {"shards": 2})

    def test_missing_vouched_shard_is_refilled_with_its_manifest_interval(
        self,
    ) -> None:
        self.append_many("t", 30)
        self._land(30)  # shard 4 is the short edge 28..30
        self.append_many("t", 11, start=30)
        self._land(41)  # shards 5 (30..37) and 6 (37..41)
        os.remove(os.path.join(self._dir(), "shard-00000004.json"))
        count = self._land(41)["shards"]
        self.assertEqual(count, 7)
        # The refilled shard carries exactly its old, edge-straddling slot.
        shard = open_shard(self._dir(), 4)
        self.assertEqual((shard["start"], shard["end"]), (28, 30))
        self.assertEqual(
            shard, self.chain.export_range("t", 28, 30)
        )
        self.assertEqual(
            self._disk_conclusion(7), verify_proof(self.chain.export_range("t", 0, 41))
        )

    def test_extension_reads_only_the_increment_segments(self) -> None:
        for i in range(52):
            self.chain.append("t", {"i": i})
            if (i + 1) % 13 == 0:
                self.chain.rotate()
        self.assertTrue(self.chain.verify("t")["ok"])  # warm the cache
        self._land(26)
        seg_files = {
            os.path.abspath(os.path.join(self.path, name))
            for name in self.segment_files()
        }
        meter = _ReadMeter()
        meter.install()
        try:
            self._land(52)
        finally:
            meter.remove()
        # Records 26..51 live in the last two sealed segments only; the
        # older segments are never opened to extend the directory.
        opened_segments = meter.paths & seg_files
        self.assertEqual(len(opened_segments), 2)


class ExportShardsDirResumeCostTest(ShardDirCase):
    def test_resume_with_everything_committed_opens_no_shard_bytes(self) -> None:
        self.append_many("t", 40)
        self.chain.export_shards_dir("t", 0, 40, 7, self._dir())
        meter = _ReadMeter()
        meter.install()
        try:
            self.chain.export_shards_dir("t", 0, 40, 7, self._dir())
        finally:
            meter.remove()
        shard_files = {
            os.path.abspath(os.path.join(self._dir(), name))
            for name in os.listdir(self._dir())
            if name.startswith("shard-")
        }
        self.assertEqual(meter.paths & shard_files, set())

    def test_same_size_tamper_is_left_to_open_shard(self) -> None:
        # Resume does manifest-level checks only: a same-size byte rewrite
        # keeps the recorded size, so the resume completes; the tamper is
        # still reported, per shard, when the shard is taken.
        self.append_many("t", 14)
        self.chain.export_shards_dir("t", 0, 14, 7, self._dir())
        path = os.path.join(self._dir(), "shard-00000001.json")
        with open(path, "rb") as handle:
            raw = handle.read()
        with open(path, "wb") as handle:
            handle.write(b" " + raw[1:])  # same byte count
        self.assertEqual(
            self.chain.export_shards_dir("t", 0, 14, 7, self._dir()),
            {"shards": 2},
        )
        with self.assertRaises(ValueError):
            open_shard(self._dir(), 1)


class ExportShardsDirOrphanTest(ShardDirCase):
    def test_unreferenced_shard_files_are_reaped(self) -> None:
        self.append_many("t", 20)
        self.chain.export_shards_dir("t", 0, 20, 7, self._dir())
        orphan = os.path.join(self._dir(), "shard-00000009.json")
        with open(orphan, "wb") as handle:
            handle.write(b'{"unrelated": true}')
        self.chain.export_shards_dir("t", 0, 20, 7, self._dir())
        self.assertNotIn("shard-00000009.json", os.listdir(self._dir()))

    def test_orphan_where_the_extension_lands_is_replaced_by_the_real_shard(
        self,
    ) -> None:
        self.append_many("t", 21)
        self.chain.export_shards_dir("t", 0, 21, 7, self._dir())
        # Shard 3 (21..28) does not exist yet; plant garbage under its name
        # as a kill between rename and manifest commit would leave.
        with open(os.path.join(self._dir(), "shard-00000003.json"), "wb") as fh:
            fh.write(b"half-landed garbage")
        self.append_many("t", 7, start=21)
        result = self.chain.export_shards_dir("t", 0, 28, 7, self._dir())
        self.assertEqual(result, {"shards": 4})
        self.assertEqual(
            open_shard(self._dir(), 3), self.chain.export_range("t", 21, 28)
        )


def _shard_dir_worker(path: str, directory: str, end: int, window: int) -> None:  # pragma: no cover
    sys.path.insert(0, REPO_ROOT)
    from audit_chain import Chain

    Chain(path).export_shards_dir("t", 0, end, window, directory)


class ExportShardsDirConcurrencyTest(ShardDirCase):
    def test_concurrent_extensions_serialize_under_one_lock(self) -> None:
        self.append_many("t", 21)
        directory = self._dir()
        self.chain.export_shards_dir("t", 0, 21, 7, directory)
        self.append_many("t", 39, start=21)
        worker_count = 5
        ctx = multiprocessing.get_context("fork")
        processes = [
            ctx.Process(target=_shard_dir_worker, args=(self.path, directory, 60, 7))
            for _ in range(worker_count)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=120)
            self.assertEqual(process.exitcode, 0)
        manifest = self._manifest(directory)
        intervals = [(e["start"], e["end"]) for e in manifest["shards"]]
        self.assertEqual(intervals[0][0], 0)
        self.assertEqual(intervals[-1][1], 60)
        self.assertEqual(
            [lo for lo, _ in intervals], [0] + [hi for _, hi in intervals[:-1]]
        )
        leftovers = [
            name
            for name in os.listdir(directory)
            if name.startswith(".") and name.endswith(".tmp")
        ]
        self.assertEqual(leftovers, [])
        count = len(intervals)
        restored = verify_proof_stream(
            open_shard(directory, i) for i in range(count)
        )
        self.assertEqual(
            restored["total"], verify_proof(self.chain.export_range("t", 0, 60))
        )

    def test_lock_file_is_part_of_the_directory(self) -> None:
        self.append_many("t", 8)
        self.chain.export_shards_dir("t", 0, 8, 7, self._dir())
        self.assertIn(LOCK_NAME, os.listdir(self._dir()))


class ExportShardsDirAppendCrashTest(ShardDirCase):
    def _kill_extension(self, directory: str, end: int, point: str) -> None:
        script = (
            "import sys;"
            "sys.path.insert(0, %r);"
            "from audit_chain import Chain;"
            "Chain(%r).export_shards_dir('t', 0, %d, 7, %r)"
            % (os.getcwd(), self.path, end, directory)
        )
        env = dict(os.environ)
        env["AUDIT_CHAIN_CRASH"] = point
        proc = subprocess.run(
            [sys.executable, "-c", script], env=env, capture_output=True
        )
        self.assertNotEqual(proc.returncode, 0)

    def test_killed_extension_lands_on_old_or_new_state_and_resumes(self) -> None:
        self.append_many("t", 40)
        directory = self._dir()
        for point in (
            "atomic:shard-00000004.json:before_replace",
            "atomic:manifest.json:before_replace",
        ):
            with self.subTest(point=point):
                # Fresh directory committed through 21 for every point.
                import shutil

                shutil.rmtree(directory, ignore_errors=True)
                self.chain.export_shards_dir("t", 0, 21, 7, directory)
                self._kill_extension(directory, 40, point)
                # The interrupted state is coherent: every shard the
                # manifest vouches for is present and authenticates.
                manifest = self._manifest(directory)
                self.assertEqual(
                    [e["end"] for e in manifest["shards"]][-1:],
                    [
                        open_shard(directory, len(manifest["shards"]) - 1)[
                            "end"
                        ]
                    ],
                )
                for index in range(len(manifest["shards"])):
                    self.assertTrue(
                        verify_proof(open_shard(directory, index))["ok"]
                    )
                result = self.chain.export_shards_dir(
                    "t", 0, 40, 7, directory
                )
                leftovers = [
                    name
                    for name in os.listdir(directory)
                    if name.startswith(".") and name.endswith(".tmp")
                ]
                self.assertEqual(leftovers, [])
                self.assertEqual(
                    verify_proof_stream(
                        open_shard(directory, i)
                        for i in range(result["shards"])
                    )["total"],
                    verify_proof(self.chain.export_range("t", 0, 40)),
                )


class ExportShardsDirExtendErrorTest(ShardDirCase):
    def test_smaller_end_than_committed_raises_value_error(self) -> None:
        self.append_many("t", 21)
        self.chain.export_shards_dir("t", 0, 21, 7, self._dir())
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 0, 14, 7, self._dir())
        # The rejected call changed nothing.
        self.assertEqual(self._manifest(self._dir())["end"], 21)

    def test_size_changing_tamper_raises_value_error(self) -> None:
        self.append_many("t", 21)
        self.chain.export_shards_dir("t", 0, 21, 7, self._dir())
        with open(os.path.join(self._dir(), "shard-00000000.json"), "ab") as fh:
            fh.write(b"extra bytes")
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 0, 21, 7, self._dir())

    def test_manifest_with_non_contiguous_entries_is_rejected(self) -> None:
        from audit_chain import sharddir as sd

        self.append_many("t", 21)
        directory = self._dir()
        self.chain.export_shards_dir("t", 0, 21, 7, directory)
        manifest = sd.load_manifest(directory)
        manifest["shards"][1]["start"] = 8  # gap and overlap, re-signed
        sd.save_manifest(directory, manifest)
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 0, 21, 7, directory)
        with self.assertRaises(ValueError):
            open_shard(directory, 0)


class ExportShardsDirErrorTest(ShardDirCase):
    def test_bad_window_and_range_raise_value_error(self) -> None:
        self.append_many("t", 10)
        for window in (0, -1, 1.5, "4", None, True):
            with self.assertRaises(ValueError, msg=repr(window)):
                self.chain.export_shards_dir("t", 0, 10, window, self._dir())
        for start, end in ((0, 0), (4, 4), (9, 4), (-1, 4), (0, 11), (15, 20)):
            with self.assertRaises(ValueError, msg=(start, end)):
                self.chain.export_shards_dir("t", start, end, 3, self._dir())
        for start, end in ((0.0, 4), (0, "4"), (None, 4), (True, 4)):
            with self.assertRaises(ValueError, msg=(start, end)):
                self.chain.export_shards_dir("t", start, end, 3, self._dir())

    def test_bad_argument_types_raise_type_error(self) -> None:
        self.append_many("t", 4)
        with self.assertRaises(TypeError):
            self.chain.export_shards_dir(42, 0, 4, 2, self._dir())
        with self.assertRaises(TypeError):
            self.chain.export_shards_dir("t", 0, 4, 2, 42)

    def test_empty_history_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 0, 1, 1, self._dir())

    def test_rejected_export_creates_no_directory(self) -> None:
        self.append_many("t", 4)
        target = self._dir()
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 0, 99, 2, target)
        self.assertFalse(os.path.exists(target))

    def test_target_that_is_not_a_directory_raises_value_error(self) -> None:
        self.append_many("t", 4)
        target = os.path.join(self._tmp, "a-file")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("x")
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 0, 4, 2, target)

    def test_unparseable_manifest_raises_value_error(self) -> None:
        self.append_many("t", 4)
        directory = self._dir()
        os.makedirs(directory)
        with open(os.path.join(directory, MANIFEST_NAME), "wb") as handle:
            handle.write(b"not json\n")
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 0, 4, 2, directory)

    def test_tampered_manifest_raises_value_error(self) -> None:
        self.append_many("t", 6)
        self.chain.export_shards_dir("t", 0, 6, 2, self._dir())
        manifest = self._manifest(self._dir())
        manifest["window"] = 99  # tag no longer matches
        with open(os.path.join(self._dir(), MANIFEST_NAME), "w", encoding="utf-8") as fh:
            fh.write(json.dumps(manifest) + "\n")
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 0, 6, 2, self._dir())

    def test_manifest_for_a_different_export_raises_value_error(self) -> None:
        self.append_many("t", 12)
        self.chain.export_shards_dir("t", 0, 12, 3, self._dir())
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 0, 12, 4, self._dir())  # window
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 0, 9, 3, self._dir())  # interval
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("u", 0, 12, 3, self._dir())  # tenant

    def test_existing_shard_mismatching_manifest_raises_value_error(self) -> None:
        self.append_many("t", 6)
        self.chain.export_shards_dir("t", 0, 6, 2, self._dir())
        with open(os.path.join(self._dir(), "shard-00000001.json"), "wb") as fh:
            fh.write(b"rewritten behind the manifest")
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 0, 6, 2, self._dir())


class OpenShardTest(ShardDirCase):
    def test_random_access_single_shard(self) -> None:
        self._multi_segment()
        self._export()
        shards = self._memory_shards()
        # Any shard, in any order, without touching the others.
        for index in (3, 0, len(shards) - 1, 1):
            self.assertEqual(open_shard(self._dir(), index), shards[index])
            self.assertTrue(verify_proof(open_shard(self._dir(), index))["ok"])

    def test_missing_directory_and_shard_raise_file_not_found(self) -> None:
        self._multi_segment()
        with self.assertRaises(FileNotFoundError):
            open_shard(os.path.join(self._tmp, "no-such-dir"), 0)
        self._export()
        os.remove(os.path.join(self._dir(), "shard-00000001.json"))
        with self.assertRaises(FileNotFoundError):
            open_shard(self._dir(), 1)

    def test_index_out_of_range_raises_value_error(self) -> None:
        self._multi_segment()
        result = self._export()
        with self.assertRaises(ValueError):
            open_shard(self._dir(), result["shards"])
        with self.assertRaises(ValueError):
            open_shard(self._dir(), -1)

    def test_non_integer_index_raises_type_error(self) -> None:
        self._multi_segment()
        self._export()
        for bad in ("0", 0.0, None, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                open_shard(self._dir(), bad)

    def test_unparseable_shard_raises_value_error(self) -> None:
        self._multi_segment()
        self._export()
        # Rewrite a shard and re-sign the manifest so the bytes authenticate
        # but the content is not a parseable shard.
        from audit_chain import sharddir as sd

        directory = self._dir()
        manifest = sd.load_manifest(directory)
        raw = b"[1, 2, 3]"
        with open(os.path.join(directory, "shard-00000000.json"), "wb") as fh:
            fh.write(raw)
        manifest["shards"][0]["sha256"] = hashlib.sha256(raw).hexdigest()
        sd.save_manifest(directory, manifest)
        with self.assertRaises(ValueError):
            open_shard(directory, 0)

    def test_shard_mismatching_manifest_raises_value_error(self) -> None:
        self._multi_segment()
        self._export()
        with open(os.path.join(self._dir(), "shard-00000000.json"), "wb") as fh:
            fh.write(b"tampered")
        with self.assertRaises(ValueError):
            open_shard(self._dir(), 0)

    def test_tampered_manifest_raises_value_error(self) -> None:
        self._multi_segment()
        self._export()
        manifest = self._manifest(self._dir())
        manifest["shards"][0]["sha256"] = "0" * 64
        with open(os.path.join(self._dir(), MANIFEST_NAME), "w", encoding="utf-8") as fh:
            fh.write(json.dumps(manifest) + "\n")
        with self.assertRaises(ValueError):
            open_shard(self._dir(), 0)

    def test_open_shard_never_opens_the_log(self) -> None:
        import shutil

        self._multi_segment()
        self._export()
        shards = self._memory_shards()
        shutil.rmtree(self.path)
        self.assertEqual(open_shard(self._dir(), 1), shards[1])
