"""Durable shard directories: export_shards_dir / open_shard.

Covers the on-disk layout (one canonical-JSON file per shard plus a
signed one-line manifest), resumable exports that never rewrite a
complete shard, random offline access, whole-directory restoration,
tamper isolation, the real-kill crash matrix, the read/digest cost
model and the offline/batch/CLI verdict triple.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from functools import reduce

from audit_chain import (
    Chain,
    combine_proofs,
    export_shards_dir,
    open_shard,
    verify_proof,
    verify_proof_stream,
    verify_proofs,
)
from tests._helpers import REPO_ROOT, AuditTestCase
from tests.test_export_cost import _HashMeter, _ReadMeter
import unittest

WORKER = os.path.join(REPO_ROOT, "tests", "_crash_worker.py")
MANIFEST = "shards-manifest.json"


def canonical_bytes(value: dict) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


class ExportShardsDirTest(AuditTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.sdir = os.path.join(self._tmp, "shards")

    def _multi_segment(self, total: int = 45) -> None:
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
        for i in range(35, total):
            self.chain.append("t", {"i": i})
        self.chain.compact(2)

    # -- layout ------------------------------------------------------------

    def test_writes_one_canonical_file_per_shard_and_a_signed_manifest(self) -> None:
        self._multi_segment()
        memory = list(self.chain.export_shards("t", 0, 45, 7))
        result = self.chain.export_shards_dir("t", 0, 45, 7, self.sdir)

        self.assertEqual(result, {"shards": len(memory)})
        names = sorted(os.listdir(self.sdir))
        self.assertEqual(
            names,
            [f"shard-{i:08d}.json" for i in range(len(memory))] + [MANIFEST],
        )
        for index, shard in enumerate(memory):
            with open(
                os.path.join(self.sdir, f"shard-{index:08d}.json"), "rb"
            ) as handle:
                raw = handle.read()
            # Verbatim canonical serialization of the in-memory shard,
            # no trailing newline of its own.
            self.assertEqual(raw, canonical_bytes(shard))
            self.assertFalse(raw.endswith(b"\n"))

        with open(os.path.join(self.sdir, MANIFEST), "rb") as handle:
            raw = handle.read()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)  # exactly one compact line
        self.assertNotIn(b": ", raw)
        self.assertNotIn(b", ", raw)
        manifest = json.loads(raw)
        self.assertEqual(manifest["version"], 1)
        self.assertEqual(manifest["tenant"], "t")
        self.assertEqual((manifest["start"], manifest["end"]), (0, 45))
        self.assertEqual(manifest["window"], 7)
        self.assertIsInstance(manifest["tag"], str)
        self.assertEqual(len(manifest["shards"]), len(memory))
        for index, entry in enumerate(manifest["shards"]):
            self.assertEqual(entry["index"], index)
            self.assertEqual(entry["name"], f"shard-{index:08d}.json")
            self.assertEqual(entry["start"], memory[index]["start"])
            self.assertEqual(entry["end"], memory[index]["end"])
            with open(
                os.path.join(self.sdir, entry["name"]), "rb"
            ) as handle:
                digest = hashlib.sha256(handle.read()).hexdigest()
            self.assertEqual(entry["sha256"], digest)
            self.assertEqual(entry["size"], os.path.getsize(
                os.path.join(self.sdir, entry["name"])
            ))

    def test_module_level_and_bound_entry_points_agree(self) -> None:
        self.append_many("t", 10)
        r1 = self.chain.export_shards_dir("t", 0, 10, 3, self.sdir)
        r2 = export_shards_dir(self.chain, "t", 0, 10, 3, self.sdir)
        self.assertEqual(r1, r2)
        self.assertEqual(r1, {"shards": 4})

    def test_creates_missing_parent_directories(self) -> None:
        self.append_many("t", 4)
        deep = os.path.join(self.sdir, "a", "b", "c")
        self.assertEqual(
            self.chain.export_shards_dir("t", 0, 4, 2, deep), {"shards": 2}
        )
        self.assertTrue(os.path.isfile(os.path.join(deep, MANIFEST)))

    # -- random access -----------------------------------------------------

    def test_open_shard_loads_any_single_shard(self) -> None:
        self._multi_segment()
        self.chain.export_shards_dir("t", 3, 43, 6, self.sdir)
        for index in range(7):
            shard = open_shard(self.sdir, index)
            verdict = verify_proof(shard)
            self.assertTrue(verdict["ok"], verdict)
            self.assertEqual(
                (shard["start"], shard["end"]),
                (3 + 6 * index, min(3 + 6 * (index + 1), 43)),
            )

    def test_open_shard_needs_neither_siblings_nor_the_log(self) -> None:
        self._multi_segment()
        self.chain.export_shards_dir("t", 0, 45, 5, self.sdir)
        keep = 4
        for index in range(9):
            if index != keep:
                os.remove(os.path.join(self.sdir, f"shard-{index:08d}.json"))
        # The log itself is irrelevant to an offline open.
        if os.path.isdir(self.path):
            import shutil

            shutil.rmtree(self.path)
        else:
            os.remove(self.path)
        shard = open_shard(self.sdir, keep)
        self.assertTrue(verify_proof(shard)["ok"])
        self.assertEqual((shard["start"], shard["end"]), (20, 25))

    # -- restore / verdicts ------------------------------------------------

    def test_whole_directory_restores_the_one_shot_conclusion(self) -> None:
        self._multi_segment()
        n = len(list(self.chain.export_shards("t", 0, 45, 4)))
        self.chain.export_shards_dir("t", 0, 45, 4, self.sdir)

        loaded = [open_shard(self.sdir, i) for i in range(n)]
        restored = reduce(combine_proofs, loaded)
        one_shot = self.chain.export_range("t", 0, 45)
        stream_total = verify_proof_stream(
            list(self.chain.export_shards("t", 0, 45, 4))
        )["total"]
        verdict = verify_proof(restored, tenant="t", start=0, end=45)
        self.assertEqual(
            verdict, verify_proof(one_shot, tenant="t", start=0, end=45)
        )
        self.assertEqual(verdict, stream_total)
        self.assertTrue(verdict["ok"])

    def test_offline_batch_and_cli_verdicts_are_the_same_three_values(self) -> None:
        self._multi_segment()
        n = len(list(self.chain.export_shards("t", 0, 45, 6)))
        self.chain.export_shards_dir("t", 0, 45, 6, self.sdir)

        for index in range(n):
            shard = open_shard(self.sdir, index)
            offline = verify_proof(shard)
            batch = verify_proofs([shard])[0]
            # The batch verdict is exactly the on-chain three-key shape.
            self.assertEqual(
                batch,
                {
                    "ok": offline["ok"],
                    "first_bad": offline["first_bad"],
                    "count": offline["count"],
                },
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "audit_chain",
                    "verify-proof",
                    os.path.join(self.sdir, f"shard-{index:08d}.json"),
                ],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            line = completed.stdout.decode("utf-8")
            self.assertTrue(line.endswith("\n"))
            self.assertEqual(line.count("\n"), 1)
            self.assertEqual(json.loads(line), batch)
            self.assertEqual(
                line.encode("utf-8"),
                canonical_bytes(batch) + b"\n",
            )

    # -- resume ------------------------------------------------------------

    def test_repeat_call_is_a_resume_that_keeps_complete_shards(self) -> None:
        self._multi_segment()
        first = self.chain.export_shards_dir("t", 0, 45, 4, self.sdir)
        self.assertEqual(first, {"shards": 12})

        originals = {}
        for name in os.listdir(self.sdir):
            if name.endswith(".json") and name.startswith("shard-"):
                with open(os.path.join(self.sdir, name), "rb") as handle:
                    originals[name] = handle.read()

        # Remove two non-adjacent shards (and pretend a kill left their
        # files absent): the resume fills only those two.
        os.remove(os.path.join(self.sdir, "shard-00000002.json"))
        os.remove(os.path.join(self.sdir, "shard-00000007.json"))
        second = self.chain.export_shards_dir("t", 0, 45, 4, self.sdir)
        self.assertEqual(second, {"shards": 12})
        for name, raw in originals.items():
            with open(os.path.join(self.sdir, name), "rb") as handle:
                self.assertEqual(handle.read(), raw, name)

        # A fully complete resume does no work and leaves bytes identical.
        third = self.chain.export_shards_dir("t", 0, 45, 4, self.sdir)
        self.assertEqual(third, {"shards": 12})
        for name, raw in originals.items():
            with open(os.path.join(self.sdir, name), "rb") as handle:
                self.assertEqual(handle.read(), raw, name)
        self.assertFalse(
            [n for n in os.listdir(self.sdir) if n.startswith(".")]
        )

    def test_resume_after_interrupted_stream(self) -> None:
        self._multi_segment()
        stream = self.chain.export_shards("t", 0, 45, 4)
        next(stream)
        stream.close()  # left nothing on disk
        result = self.chain.export_shards_dir("t", 0, 45, 4, self.sdir)
        self.assertEqual(result["shards"], 12)

    def test_resume_with_different_parameters_is_value_error(self) -> None:
        self._multi_segment()
        self.chain.export_shards_dir("t", 0, 45, 4, self.sdir)
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 0, 45, 5, self.sdir)
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 1, 45, 4, self.sdir)
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 0, 44, 4, self.sdir)
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("u", 0, 45, 4, self.sdir)

    # -- crash matrix ------------------------------------------------------

    def _kill_export(self, point: str, path: str, sdir: str) -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
        completed = subprocess.run(
            [
                sys.executable,
                WORKER,
                path,
                "shards",
                point,
                "0",
                "20",
                "4",
                sdir,
            ],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(
            completed.returncode,
            0,
            f"{point} did not die: {completed.stderr.decode()[:400]}",
        )

    def _assert_resume_lands_on_one_consistent_directory(
        self, point: str, tag: str
    ) -> None:
        path = os.path.join(self._tmp, f"log-{tag}")
        sdir = os.path.join(self._tmp, f"shards-{tag}")
        chain = Chain(path)
        for i in range(25):
            chain.append("t", {"i": i})
        chain.rotate()
        for i in range(25, 33):
            chain.append("t", {"i": i})
        self._kill_export(point, path, sdir)

        # Resume, then prove every residual temp was reaped and the
        # directory holds only shard files plus the manifest.
        reopened = Chain(path)
        result = reopened.export_shards_dir("t", 0, 20, 4, sdir)
        leftovers = [
            n
            for n in os.listdir(sdir)
            if n.startswith(".") or n.endswith(".tmp")
        ]
        self.assertEqual(leftovers, [], point)
        self.assertEqual(result, {"shards": 5}, point)
        memory = list(reopened.export_shards("t", 0, 20, 4))
        loaded = [open_shard(sdir, i) for i in range(5)]
        for index, shard in enumerate(loaded):
            self.assertEqual(
                canonical_bytes(shard), canonical_bytes(memory[index]), point
            )
            self.assertTrue(verify_proof(shard)["ok"], point)
        restored = verify_proof(
            reduce(combine_proofs, loaded), tenant="t", start=0, end=20
        )
        one_shot = verify_proof(
            reopened.export_range("t", 0, 20), tenant="t", start=0, end=20
        )
        self.assertEqual(restored, one_shot, point)

    def test_killed_in_every_commit_window_resumes_cleanly(self) -> None:
        for tag, point in enumerate(
            (
                "atomic:shards-manifest.json:before_replace",
                "atomic:shard-00000000.json:before_replace",
                "atomic:shard-00000000.json:after_replace",
                "shards:before_manifest_update",
                "shards:after_manifest_update",
            )
        ):
            self._assert_resume_lands_on_one_consistent_directory(point, str(tag))

    def test_resume_twice_after_partial_kills(self) -> None:
        self.append_many("t", 30)
        self._kill_export(
            "shards:after_manifest_update", self.path, self.sdir
        )  # shard 0 done
        reopened = Chain(self.path)
        # Kill a second time while filling the remaining run; the hook
        # lands on shard 1's manifest update.
        env = dict(os.environ)
        env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
        env["AUDIT_CHAIN_CRASH"] = "shards:after_manifest_update"
        killed = subprocess.run(
            [
                sys.executable, WORKER, self.path, "shards", "",
                "0", "20", "4", self.sdir,
            ],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.assertNotEqual(killed.returncode, 0)
        result = reopened.export_shards_dir("t", 0, 20, 4, self.sdir)
        self.assertEqual(result, {"shards": 5})
        for index in range(5):
            self.assertTrue(verify_proof(open_shard(self.sdir, index))["ok"])

    # -- tampering ----------------------------------------------------------

    def test_tampered_shard_does_not_interrupt_the_other_checks(self) -> None:
        self._multi_segment()
        n = len(list(self.chain.export_shards("t", 0, 45, 5)))
        self.chain.export_shards_dir("t", 0, 45, 5, self.sdir)

        # Byte-level tamper: open_shard refuses the one shard but every
        # sibling still checks out.
        victim = os.path.join(self.sdir, "shard-00000001.json")
        with open(victim, "r+b") as handle:
            data = handle.read()
            handle.seek(0)
            handle.write(data.replace(b'"i":5', b'"i":9001', 1))
        with self.assertRaises(ValueError):
            open_shard(self.sdir, 1)
        for index in range(n):
            if index == 1:
                continue
            self.assertTrue(verify_proof(open_shard(self.sdir, index))["ok"])

        # Content-level tamper (valid JSON, bad payload): the parsed
        # shard's batch verdict lands on the real first bad index and
        # the remaining verdicts stay ok.
        with open(victim, "rb") as handle:
            broken = json.loads(handle.read())
        batch = verify_proofs(
            [
                broken if i == 1 else open_shard(self.sdir, i)
                for i in range(n)
            ]
        )
        self.assertTrue(batch[0]["ok"])
        self.assertFalse(batch[1]["ok"])
        self.assertEqual(batch[1]["first_bad"], 5)
        self.assertTrue(all(v["ok"] for v in batch[2:]))

        # The same tamper against a one-shot export concludes identically.
        full = self.chain.export_range("t", 0, 45)
        for window in full["windows"]:
            for item in window["records"]:
                if item["index"] == 5:
                    item["record"]["payload"]["i"] = 9001
        self.assertEqual(
            batch[1]["first_bad"], verify_proof(full)["first_bad"]
        )

    def test_tampered_manifest_is_value_error_for_both_entries(self) -> None:
        self.append_many("t", 8)
        self.chain.export_shards_dir("t", 0, 8, 3, self.sdir)
        path = os.path.join(self.sdir, MANIFEST)
        with open(path, "rb") as handle:
            manifest = json.loads(handle.read())
        manifest["window"] = 9
        with open(path, "wb") as handle:
            handle.write(
                (json.dumps(manifest, separators=(",", ":")) + "\n").encode()
            )
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 0, 8, 3, self.sdir)
        with self.assertRaises(ValueError):
            open_shard(self.sdir, 0)

    def test_unparseable_manifest_is_value_error(self) -> None:
        self.append_many("t", 8)
        self.chain.export_shards_dir("t", 0, 8, 3, self.sdir)
        with open(os.path.join(self.sdir, MANIFEST), "wb") as handle:
            handle.write(b"{not json\n")
        with self.assertRaises(ValueError):
            open_shard(self.sdir, 0)
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 0, 8, 3, self.sdir)

    def test_stray_shard_file_is_value_error(self) -> None:
        self.append_many("t", 8)
        self.chain.export_shards_dir("t", 0, 8, 3, self.sdir)
        with open(os.path.join(self.sdir, "shard-00000099.json"), "wb") as fh:
            fh.write(b"{}")
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 0, 8, 3, self.sdir)

    # -- errors -------------------------------------------------------------

    def test_open_shard_errors(self) -> None:
        self.append_many("t", 8)
        self.chain.export_shards_dir("t", 0, 8, 3, self.sdir)
        with self.assertRaises(FileNotFoundError):
            open_shard(os.path.join(self._tmp, "missing"), 0)
        with self.assertRaises(ValueError):
            open_shard(self.sdir, 99)
        with self.assertRaises(ValueError):
            open_shard(self.sdir, -1)
        with self.assertRaises(TypeError):
            open_shard(self.sdir, "1")
        with self.assertRaises(TypeError):
            open_shard(self.sdir, None)
        with self.assertRaises(ValueError):
            open_shard(self.sdir, True)
        with self.assertRaises(ValueError):
            open_shard(self.sdir, 1.0)
        # An advertised shard whose file is missing is FileNotFoundError.
        os.remove(os.path.join(self.sdir, "shard-00000001.json"))
        with self.assertRaises(FileNotFoundError):
            open_shard(self.sdir, 1)
        # The other shards stay usable.
        self.assertTrue(verify_proof(open_shard(self.sdir, 0))["ok"])

    def test_pending_shard_is_file_not_found_then_resumes(self) -> None:
        # Kill after shard 0's bytes landed but before (or without) its
        # manifest revision: shard 0 is unadvertised and therefore
        # missing to open_shard, and a resume rebuilds the full plan.
        self.append_many("t", 12)
        env = dict(os.environ)
        env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
        completed = subprocess.run(
            [
                sys.executable, WORKER, self.path, "shards",
                "shards:before_manifest_update",
                "0", "8", "2", self.sdir,
            ],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        self.assertNotEqual(completed.returncode, 0)
        with open(os.path.join(self.sdir, MANIFEST), "rb") as handle:
            manifest = json.loads(handle.read())
        self.assertIsNone(manifest["shards"][0]["sha256"])
        with self.assertRaises(FileNotFoundError):
            open_shard(self.sdir, 0)
        self.assertEqual(
            self.chain.export_shards_dir("t", 0, 8, 2, self.sdir),
            {"shards": 4},
        )
        for index in range(4):
            self.assertTrue(verify_proof(open_shard(self.sdir, index))["ok"])

    def test_target_that_is_a_file_is_value_error(self) -> None:
        self.append_many("t", 4)
        target = os.path.join(self._tmp, "a-file")
        with open(target, "wb") as handle:
            handle.write(b"x")
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 0, 4, 2, target)

    def test_bad_parameters(self) -> None:
        self.append_many("t", 10)
        for window in (0, -1, -100):
            with self.assertRaises(ValueError, msg=repr(window)):
                self.chain.export_shards_dir("t", 0, 10, window, self.sdir)
        for window in (1.5, True):
            with self.assertRaises(ValueError, msg=repr(window)):
                self.chain.export_shards_dir("t", 0, 10, window, self.sdir)
        for window in ("4", None, [4]):
            with self.assertRaises(TypeError, msg=repr(window)):
                self.chain.export_shards_dir("t", 0, 10, window, self.sdir)
        for start, end in ((0, 0), (9, 4), (0, -2), (-1, 4)):
            with self.assertRaises(ValueError, msg=(start, end)):
                self.chain.export_shards_dir("t", start, end, 3, self.sdir)
        for start, end in ((0.0, 4), (True, 4), (0, 11), (10, 11)):
            with self.assertRaises(ValueError, msg=(start, end)):
                self.chain.export_shards_dir("t", start, end, 3, self.sdir)
        for start, end in (("0", 4), (None, 4), (0, "4")):
            with self.assertRaises(TypeError, msg=(start, end)):
                self.chain.export_shards_dir("t", start, end, 3, self.sdir)
        with self.assertRaises(TypeError):
            self.chain.export_shards_dir(0, 0, 10, 3, self.sdir)
        with self.assertRaises(TypeError):
            self.chain.export_shards_dir("t", 0, 10, 3, 4096)

    def test_empty_history_is_value_error(self) -> None:
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 0, 0, 1, self.sdir)
        with self.assertRaises(ValueError):
            self.chain.export_shards_dir("t", 0, 1, 1, self.sdir)

    # -- isolation / cold store --------------------------------------------

    def test_tenants_and_out_of_interval_damage_stay_isolated(self) -> None:
        self._multi_segment()
        self.chain.export_shards_dir("t", 0, 45, 5, self.sdir)
        udir = os.path.join(self._tmp, "ushards")
        self.chain.export_shards_dir("u", 0, 10, 4, udir)
        # Damage the other tenant on disk: t shards are self-contained.
        for i in range(10):
            self.chain.append("u", {"i": 1000 + i})
        for index in range(9):
            self.assertTrue(
                verify_proof(open_shard(self.sdir, index))["ok"], index
            )
        for index in range(3):
            self.assertTrue(verify_proof(open_shard(udir, index))["ok"])

    def test_cold_store_writes_the_same_shards_as_a_warm_one(self) -> None:
        self._multi_segment()
        warm_dir = os.path.join(self._tmp, "warm")
        self.assertTrue(self.chain.verify("t")["ok"])
        self.chain.export_shards_dir("t", 2, 44, 5, warm_dir)
        os.remove(self.chain._layout().cache_path)
        cold_dir = os.path.join(self._tmp, "cold")
        self.chain.export_shards_dir("t", 2, 44, 5, cold_dir)
        warm = sorted(os.listdir(warm_dir))
        cold = sorted(os.listdir(cold_dir))
        self.assertEqual(warm, cold)
        for name in warm:
            with open(os.path.join(warm_dir, name), "rb") as a, open(
                os.path.join(cold_dir, name), "rb"
            ) as b:
                self.assertEqual(a.read(), b.read(), name)


class ShardsDirCostTest(AuditTestCase):
    HISTORY = 8_000
    ROTATE_EVERY = 2_000

    def _build(self, lo: int, hi: int) -> None:
        for i in range(lo, hi):
            self.chain.append("t", {"i": i, "pad": "x" * 24})
            if (i + 1) % self.ROTATE_EVERY == 0 and i + 1 < hi:
                self.chain.rotate()

    def test_complete_resume_reads_neither_shards_nor_log(self) -> None:
        self._build(0, self.HISTORY)
        self.assertTrue(self.chain.verify("t")["ok"])
        sdir = os.path.join(self._tmp, "shards")
        self.chain.export_shards_dir("t", 100, 500, 25, sdir)

        meter = _ReadMeter()
        meter.install()
        try:
            result = self.chain.export_shards_dir("t", 100, 500, 25, sdir)
            read_bytes = meter.bytes
        finally:
            meter.remove()
        self.assertEqual(result, {"shards": 16})
        # Only the small manifest is read: no shard content, no log byte.
        self.assertLess(read_bytes, 100_000)

    def test_resume_cost_tracks_the_missing_increment_only(self) -> None:
        self._build(0, self.HISTORY)
        self.assertTrue(self.chain.verify("t")["ok"])
        sdir = os.path.join(self._tmp, "shards")
        self.chain.export_shards_dir("t", 0, 4_000, 100, sdir)
        # Pretend the last run was lost: remove a tail of shards.
        for index in range(36, 40):
            os.remove(os.path.join(sdir, f"shard-{index:08d}.json"))

        total_log = sum(
            os.path.getsize(os.path.join(self.path, name))
            for name in self.segment_files()
        )
        meter = _ReadMeter()
        meter.install()
        try:
            result = self.chain.export_shards_dir("t", 0, 4_000, 100, sdir)
            read_bytes = meter.bytes
        finally:
            meter.remove()
        self.assertEqual(result, {"shards": 40})
        # The four missing shards live in one tail segment; the earlier
        # segments and the 36 complete shards are never read.
        self.assertLess(read_bytes, total_log // 2)

    def test_resume_hashing_tracks_the_missing_increment_only(self) -> None:
        self._build(0, self.HISTORY)
        self.assertTrue(self.chain.verify("t")["ok"])
        sdir = os.path.join(self._tmp, "shards")
        self.chain.export_shards_dir("t", 0, 4_000, 100, sdir)
        for index in range(36, 40):
            os.remove(os.path.join(sdir, f"shard-{index:08d}.json"))

        total_log = sum(
            os.path.getsize(os.path.join(self.path, name))
            for name in self.segment_files()
        )
        meter = _HashMeter()
        meter.install()
        try:
            result = self.chain.export_shards_dir("t", 0, 4_000, 100, sdir)
            hashed = meter.bytes
        finally:
            meter.remove()
        self.assertEqual(result, {"shards": 40})
        # Only the ~400 missing interval records' small windows are
        # hashed, never the sealed history nor the 36 complete shards.
        self.assertLess(hashed, total_log // 2)

    def test_cold_export_does_not_hold_the_history(self) -> None:
        # One un-rotated, never-verified legacy file forces the cold
        # line-by-line counting path; production must still succeed.
        for i in range(2_000):
            self.chain.append("t", {"i": i})
        sdir = os.path.join(self._tmp, "shards")
        result = self.chain.export_shards_dir("t", 100, 300, 20, sdir)
        self.assertEqual(result, {"shards": 10})
        for index in range(10):
            self.assertTrue(verify_proof(open_shard(sdir, index))["ok"])


class IterLinesTest(unittest.TestCase):
    """The streaming line iterator used by cold counting/collection."""

    def _lines(self, raw: bytes, chunk: int) -> list[bytes]:
        import io

        from audit_chain.chain import _iter_lines

        class _Chunks:
            # Simulates an OS read that returns at most ``chunk`` bytes
            # (a legal short read that _iter_lines must tolerate).
            def __init__(self, data: bytes) -> None:
                self._io = io.BytesIO(data)
                self._chunk = chunk

            def read(self, n: int) -> bytes:
                return self._io.read(min(n, self._chunk))

        return list(_iter_lines(_Chunks(raw)))

    def test_visits_every_complete_line_at_every_chunk_size(self) -> None:
        raw = b"".join(f"line-{i}\n".encode() for i in range(50))
        for chunk in (1, 2, 3, 7, 64, 1 << 20):
            lines = self._lines(raw, chunk)
            self.assertEqual(len(lines), 50)
            self.assertEqual(b"".join(lines), raw)

    def test_drops_only_the_trailing_half_line(self) -> None:
        raw = b"a\nbb\nccc\npartial"
        self.assertEqual(self._lines(raw, 3), [b"a\n", b"bb\n", b"ccc\n"])
        self.assertEqual(self._lines(b"", 4), [])
        self.assertEqual(self._lines(b"\n\n", 1), [b"\n", b"\n"])
