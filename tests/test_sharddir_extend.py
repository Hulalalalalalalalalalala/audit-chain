"""Incremental append into a persisted shard directory.

The first call lays down the prefix; after the log keeps appending, a
further call on the same directory tiles from the old final shard end to
the current complete prefix, keeping every existing shard byte-stable.
Concurrent processes serialize on one directory lock and a killed
process leaves the directory at an old or a new committed state.
"""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import subprocess
import sys

from audit_chain import Chain, open_shard, verify_proof, verify_proof_stream
from audit_chain import combine_proofs
from audit_chain.sharddir import MANIFEST_NAME, load_manifest
from functools import reduce

from tests._helpers import AuditTestCase, REPO_ROOT
from tests.test_export_cost import _HashMeter, _ReadMeter


class ShardDirGrowCase(AuditTestCase):
    WINDOW = 7

    def _dir(self) -> str:
        return os.path.join(self._tmp, "shards")

    def _manifest(self, directory: str | None = None) -> dict:
        directory = directory or self._dir()
        with open(os.path.join(directory, MANIFEST_NAME), "rb") as handle:
            raw = handle.read()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b"\n", raw[:-1])
        return json.loads(raw.decode("utf-8")[:-1])

    def _lay(self, count: int) -> None:
        for i in range(count):
            self.chain.append("t", {"i": i})
            if i % 2 == 0:
                self.chain.append("u", {"i": i})

    def _grow_to(self, count: int) -> dict:
        return self.chain.export_shards_dir(
            "t", 0, count, self.WINDOW, self._dir()
        )

    def _splice(self, result: dict):
        shards = [open_shard(self._dir(), i) for i in range(result["shards"])]
        streamed = verify_proof_stream(shards)
        combined = reduce(combine_proofs, shards)
        return streamed, combined

    def _assert_contiguous(self, end: int) -> None:
        entries = load_manifest(self._dir())["shards"]
        cursor = 0
        for index, entry in enumerate(entries):
            self.assertEqual(entry["name"], f"shard-{index:08d}.json")
            self.assertEqual(entry["start"], cursor)
            self.assertGreater(entry["end"], cursor)
            self.assertLessEqual(entry["end"] - entry["start"], self.WINDOW)
            cursor = entry["end"]
        self.assertEqual(cursor, end)


class IncrementalAppendShapeTest(ShardDirGrowCase):
    def test_new_shards_follow_the_old_final_shard_end_to_start(self) -> None:
        self._lay(52)
        first = self._grow_to(52)
        self.assertEqual(first, {"shards": 8})
        for i in range(52, 70):
            self.chain.append("t", {"i": i})
        second = self._grow_to(70)
        # Eight pre-existing shards (the last a 49..52 remainder) plus
        # 52..59, 59..66, 66..70: three more, end-to-start, no gap.
        self.assertEqual(second, {"shards": 11})
        manifest = load_manifest(self._dir())
        self.assertEqual(manifest["end"], 70)
        self.assertEqual(
            [(e["start"], e["end"]) for e in manifest["shards"]],
            [
                (0, 7), (7, 14), (14, 21), (21, 28), (28, 35),
                (35, 42), (42, 49), (49, 52),
                (52, 59), (59, 66), (66, 70),
            ],
        )
        self._assert_contiguous(70)

    def test_existing_shards_are_never_rewritten(self) -> None:
        self._lay(52)
        self._grow_to(52)
        before = {}
        for name in os.listdir(self._dir()):
            if not name.startswith("shard-"):
                continue
            path = os.path.join(self._dir(), name)
            with open(path, "rb") as handle:
                before[name] = (handle.read(), os.path.getmtime(path))
        for i in range(52, 70):
            self.chain.append("t", {"i": i})
        self._grow_to(70)
        # The pre-existing shard files keep identical bytes and mtimes;
        # only the manifest is re-committed and new shard files appear.
        for name, (raw, mtime) in before.items():
            with open(os.path.join(self._dir(), name), "rb") as handle:
                self.assertEqual(handle.read(), raw, name)
            self.assertEqual(
                os.path.getmtime(os.path.join(self._dir(), name)),
                mtime,
                name,
            )

    def test_grown_directory_conclusions_match_a_one_shot_export(self) -> None:
        self._lay(52)
        self._grow_to(52)
        for i in range(52, 70):
            self.chain.append("t", {"i": i})
        result = self._grow_to(70)
        streamed, combined = self._splice(result)
        one_shot = verify_proof(self.chain.export_range("t", 0, 70))
        self.assertEqual(streamed["total"], one_shot)
        self.assertEqual(verify_proof(combined), one_shot)
        self.assertTrue(one_shot["ok"])
        # Every record 0..69 is present exactly once and in order.
        seen = []
        for index in range(result["shards"]):
            shard = open_shard(self._dir(), index)
            seen.extend(
                item["index"]
                for window in shard["windows"]
                for item in window["records"]
            )
        self.assertEqual(seen, list(range(70)))

    def test_repeated_growth_rounds_with_different_remainders(self) -> None:
        self._lay(10)
        result = self._grow_to(10)
        for end in (11, 13, 20, 21, 50, 51, 53):
            for i in range(self.chain.verify("t")["count"], end):
                self.chain.append("t", {"i": i})
            result = self._grow_to(end)
            self.assertEqual(load_manifest(self._dir())["end"], end)
            self._assert_contiguous(end)
            streamed, _ = self._splice(result)
            self.assertEqual(
                streamed["total"], verify_proof(self.chain.export_range("t", 0, end))
            )

    def test_growth_keeps_working_on_a_segmented_and_archived_log(self) -> None:
        for i in range(30):
            self.chain.append("t", {"i": i})
        self.chain.rotate()
        for i in range(30, 45):
            self.chain.append("t", {"i": i})
        self._grow_to(45)
        self.chain.archive(os.path.join(self._tmp, "cold"))
        for i in range(45, 60):
            self.chain.append("t", {"i": i})
        result = self._grow_to(60)
        streamed, _ = self._splice(result)
        self.assertEqual(
            streamed["total"], verify_proof(self.chain.export_range("t", 0, 60))
        )
        self.assertTrue(streamed["total"]["ok"])

    def test_growth_on_a_legacy_file_log(self) -> None:
        for i in range(9):
            self.chain.append("t", {"i": i})
        self._grow_to(9)
        for i in range(9, 20):
            self.chain.append("t", {"i": i})
        result = self._grow_to(20)
        streamed, _ = self._splice(result)
        self.assertEqual(
            streamed["total"], verify_proof(self.chain.export_range("t", 0, 20))
        )

    def test_growth_with_a_non_zero_start(self) -> None:
        self._lay(60)
        first = self.chain.export_shards_dir(
            "t", 10, 40, self.WINDOW, self._dir()
        )
        for i in range(60, 75):
            self.chain.append("t", {"i": i})
        second = self.chain.export_shards_dir(
            "t", 10, 70, self.WINDOW, self._dir()
        )
        manifest = load_manifest(self._dir())
        self.assertEqual((manifest["start"], manifest["end"]), (10, 70))
        self.assertEqual(manifest["shards"][0]["start"], 10)
        self.assertEqual(manifest["shards"][-1]["end"], 70)
        self._assert_tiling_from(10, 70, second)

    def _assert_tiling_from(self, start: int, end: int, result: dict) -> None:
        entries = load_manifest(self._dir())["shards"]
        cursor = start
        for index, entry in enumerate(entries):
            self.assertEqual(entry["name"], f"shard-{index:08d}.json")
            self.assertEqual(entry["start"], cursor)
            cursor = entry["end"]
        self.assertEqual(cursor, end)
        streamed = verify_proof_stream(
            open_shard(self._dir(), i) for i in range(result["shards"])
        )
        self.assertEqual(
            streamed["total"], verify_proof(self.chain.export_range("t", start, end))
        )


class IncrementalAppendResumeTest(ShardDirGrowCase):
    def test_idempotent_rewrites_nothing(self) -> None:
        self._lay(52)
        self._grow_to(52)
        before = {
            name: os.path.getmtime(os.path.join(self._dir(), name))
            for name in os.listdir(self._dir())
        }
        # Same end with no new records: nothing at all is rewritten.
        self.assertEqual(self._grow_to(52), {"shards": 8})
        self.assertEqual(
            {
                name: os.path.getmtime(os.path.join(self._dir(), name))
                for name in os.listdir(self._dir())
            },
            before,
        )

    def test_resume_after_growth_with_no_further_work(self) -> None:
        self._lay(40)
        self._grow_to(40)
        for i in range(40, 55):
            self.chain.append("t", {"i": i})
        self._grow_to(55)
        before = {
            name: os.path.getmtime(os.path.join(self._dir(), name))
            for name in os.listdir(self._dir())
        }
        self.assertEqual(self._grow_to(55)["shards"], len(before) - 2)
        self.assertEqual(
            {
                name: os.path.getmtime(os.path.join(self._dir(), name))
                for name in os.listdir(self._dir())
            },
            before,
        )

    def test_manifest_level_checks_open_no_existing_shard_bytes(self) -> None:
        self._lay(52)
        result = self._grow_to(52)
        for i in range(52, 90):
            self.chain.append("t", {"i": i})
        old_paths = {
            os.path.abspath(os.path.join(self._dir(), f"shard-{i:08d}.json"))
            for i in range(result["shards"])
        }
        meter = _ReadMeter()
        meter.install()
        try:
            grown = self._grow_to(90)
        finally:
            meter.remove()
        # The eight old shard files are never opened: the manifest alone
        # vouches for them; only new shard bytes (write-only) and small
        # metadata files are touched.
        self.assertFalse(meter.paths & old_paths)
        streamed, _ = self._splice(grown)
        self.assertTrue(streamed["total"]["ok"])

    def test_extension_reads_and_hashes_only_the_increment(self) -> None:
        for i in range(4000):
            self.chain.append("t", {"i": i, "pad": "x" * 24})
            if (i + 1) % 1000 == 0:
                self.chain.rotate()
        self.assertTrue(self.chain.verify("t")["ok"])
        self._grow_to(4000)
        for i in range(4000, 4120):
            self.chain.append("t", {"i": i, "pad": "x" * 24})
        seg_files = {
            os.path.abspath(os.path.join(self.path, name))
            for name in self.segment_files()
        }
        active = os.path.abspath(os.path.join(self.path, self.segment_files()[-1]))

        read_meter = _ReadMeter()
        read_meter.install()
        try:
            result = self._grow_to(4120)
        finally:
            read_meter.remove()
        # Only the active segment (holding the increment) is read from the
        # log; no sealed history is opened.
        self.assertEqual(read_meter.paths & seg_files, {active})
        streamed, _ = self._splice(result)
        self.assertTrue(streamed["total"]["ok"])

        hash_meter = _HashMeter()
        hash_meter.install()
        try:
            # A second identical call is a manifest-level no-op: no log
            # or shard bytes are hashed, only the small manifest body is
            # authenticated.
            self._grow_to(4120)
        finally:
            hash_meter.remove()
        manifest_size = os.path.getsize(
            os.path.join(self._dir(), MANIFEST_NAME)
        )
        self.assertLess(hash_meter.bytes, manifest_size + 1000)

    def test_missing_old_shard_is_refilled_and_then_growth_continues(self) -> None:
        self._lay(52)
        self._grow_to(52)
        os.remove(os.path.join(self._dir(), "shard-00000002.json"))
        for i in range(52, 70):
            self.chain.append("t", {"i": i})
        result = self._grow_to(70)
        self.assertEqual(result, {"shards": 11})
        # The refilled shard and the appended ones all verify, and the
        # whole restored prefix matches a one-shot export.
        streamed, _ = self._splice(result)
        self.assertEqual(
            streamed["total"], verify_proof(self.chain.export_range("t", 0, 70))
        )

    def test_refilled_shard_after_compaction_still_verifies(self) -> None:
        for i in range(20):
            self.chain.append("t", {"i": i})
        self.chain.rotate()
        for i in range(20, 40):
            self.chain.append("t", {"i": i})
        result = self._grow_to(40)
        os.remove(os.path.join(self._dir(), "shard-00000004.json"))
        self.chain.compact(1)
        result = self._grow_to(40)
        streamed, _ = self._splice(result)
        self.assertEqual(
            streamed["total"], verify_proof(self.chain.export_range("t", 0, 40))
        )
        self.assertTrue(streamed["total"]["ok"])


class IncrementalAppendErrorTest(ShardDirGrowCase):
    def test_end_before_the_manifest_end_is_value_error(self) -> None:
        self._lay(40)
        self._grow_to(40)
        with self.assertRaises(ValueError):
            self._grow_to(30)

    def test_end_past_the_current_count_is_value_error(self) -> None:
        self._lay(20)
        self._grow_to(20)
        with self.assertRaises(ValueError):
            self._grow_to(40)

    def test_changed_identity_fields_are_value_error(self) -> None:
        self._lay(40)
        self._grow_to(40)
        for i in range(40, 50):
            self.chain.append("t", {"i": i})
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 5, 50, self.WINDOW, self._dir())
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 0, 50, self.WINDOW + 1, self._dir())
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("u", 0, 50, self.WINDOW, self._dir())

    def test_target_not_a_directory_is_value_error(self) -> None:
        self._lay(10)
        target = os.path.join(self._tmp, "a-file")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("x")
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 0, 10, 3, target)

    def test_missing_directory_is_file_not_found_for_open_shard(self) -> None:
        with self.assertRaises(FileNotFoundError):
            open_shard(os.path.join(self._tmp, "absent"), 0)

    def test_tampered_shard_bytes_raise_value_error_on_open(self) -> None:
        self._lay(30)
        self._grow_to(30)
        with open(os.path.join(self._dir(), "shard-00000001.json"), "wb") as fh:
            fh.write(b"rewritten")
        with self.assertRaises(ValueError):
            open_shard(self._dir(), 1)
        # The manifest-level resume does not re-hash it, but every
        # consuming entry point reports the tamper.
        self._grow_to(30)
        with self.assertRaises(ValueError):
            open_shard(self._dir(), 1)

    def test_tampered_manifest_raises_value_error(self) -> None:
        self._lay(30)
        self._grow_to(30)
        manifest = self._manifest()
        manifest["window"] = 99
        with open(os.path.join(self._dir(), MANIFEST_NAME), "w", encoding="utf-8") as fh:
            fh.write(json.dumps(manifest) + "\n")
        with self.assertRaises(ValueError):
            self._grow_to(30)
        with self.assertRaises(ValueError):
            open_shard(self._dir(), 0)

    def test_bad_argument_types_raise_type_error(self) -> None:
        self._lay(4)
        with self.assertRaises(TypeError):
            self.chain.export_shards_dir(42, 0, 4, 2, self._dir())
        with self.assertRaises(TypeError):
            self.chain.export_shards_dir("t", 0, 4, 2, 42)
        with self.assertRaises(TypeError):
            open_shard(self._dir(), "1")


def _concurrent_worker(path: str, directory: str, rounds: int, seed: int) -> None:  # pragma: no cover
    sys.path.insert(0, REPO_ROOT)
    from audit_chain import Chain

    chain = Chain(path)
    for _ in range(rounds):
        # Append under the log lock, then extend the shared directory to
        # whatever the complete prefix currently is. Another process may
        # advance the directory first; re-read and retry in that case.
        chain.append("t", {"seed": seed})
        for _ in range(1000):
            count = chain.verify("t")["count"]
            try:
                chain.export_shards_dir("t", 0, count, 10, directory)
                break
            except ValueError:
                continue
        else:  # pragma: no cover - failure path
            raise RuntimeError("could not extend the shard directory")


class IncrementalAppendConcurrencyTest(AuditTestCase):
    def test_concurrent_appenders_serialize_on_one_directory(self) -> None:
        path = self.path
        directory = os.path.join(self._tmp, "shards")
        initial = 50
        for i in range(initial):
            self.chain.append("t", {"i": i})
        self.chain.export_shards_dir("t", 0, initial, 10, directory)

        workers = 6
        rounds = 12
        ctx = multiprocessing.get_context("fork")
        processes = [
            ctx.Process(
                target=_concurrent_worker,
                args=(path, directory, rounds, seed),
            )
            for seed in range(workers)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=120)
            self.assertEqual(process.exitcode, 0)

        total = initial + workers * rounds
        result = self.chain.export_shards_dir("t", 0, total, 10, directory)
        manifest = load_manifest(directory)
        self.assertEqual(manifest["end"], total)
        cursor = 0
        names = set()
        for index, entry in enumerate(manifest["shards"]):
            self.assertEqual(entry["name"], f"shard-{index:08d}.json")
            self.assertEqual(entry["start"], cursor)
            self.assertGreater(entry["end"], cursor)
            cursor = entry["end"]
            names.add(entry["name"])
        self.assertEqual(cursor, total)
        # No half state: exactly the manifest's shard files plus the lock
        # and manifest, and no staging files.
        on_disk = {
            name
            for name in os.listdir(directory)
            if name.startswith("shard-") and name.endswith(".json")
        }
        self.assertEqual(on_disk, names)
        self.assertEqual(
            [n for n in os.listdir(directory) if n.endswith(".tmp")], []
        )
        streamed = verify_proof_stream(
            open_shard(directory, i) for i in range(result["shards"])
        )
        self.assertEqual(
            streamed["total"], verify_proof(self.chain.export_range("t", 0, total))
        )
        self.assertTrue(streamed["total"]["ok"])
        self.assertEqual(self.chain.verify("t")["count"], total)


class IncrementalAppendCrashTest(ShardDirGrowCase):
    def _kill_extend(self, point: str, end: int, directory: str) -> None:
        script = (
            "import sys;"
            "sys.path.insert(0, %r);"
            "from audit_chain import Chain;"
            "Chain(%r).export_shards_dir('t', 0, %d, %d, %r)"
            % (os.getcwd(), self.path, end, self.WINDOW, directory)
        )
        env = dict(os.environ)
        env["AUDIT_CHAIN_CRASH"] = point
        proc = subprocess.run(
            [sys.executable, "-c", script], env=env, capture_output=True
        )
        self.assertNotEqual(proc.returncode, 0, proc.stderr.decode()[:400])

    def test_every_kill_window_leaves_old_or_new_state(self) -> None:
        import shutil

        self._lay(52)
        for i in range(52, 90):
            self.chain.append("t", {"i": i})
        for point in (
            "atomic:shard-00000008.json:before_replace",
            "atomic:shard-00000009.json:after_replace",
            "atomic:manifest.json:before_replace",
            "atomic:manifest.json:after_replace",
        ):
            directory = os.path.join(self._tmp, "dir-" + point.replace(":", "_"))
            self.chain.export_shards_dir("t", 0, 52, self.WINDOW, directory)
            self._kill_extend(point, 90, directory)
            manifest = load_manifest(directory)
            committed = manifest["end"]
            self.assertGreaterEqual(committed, 52)
            self.assertLessEqual(committed, 90)
            # The old-or-new committed state is fully readable.
            count = len(manifest["shards"])
            for index in range(count):
                self.assertTrue(
                    verify_proof(open_shard(directory, index))["ok"], point
                )
            result = self.chain.export_shards_dir(
                "t", 0, 90, self.WINDOW, directory
            )
            streamed = verify_proof_stream(
                open_shard(directory, i) for i in range(result["shards"])
            )
            self.assertEqual(
                streamed["total"],
                verify_proof(self.chain.export_range("t", 0, 90)),
                point,
            )
            self.assertEqual(
                [n for n in os.listdir(directory) if n.endswith(".tmp")],
                [],
                point,
            )
            shutil.rmtree(directory)
