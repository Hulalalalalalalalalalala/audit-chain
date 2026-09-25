"""Online archival: hot + archive tiers.

Covers the migration itself and every public entry point working across both
tiers, unchanged chain/record semantics, identical first-bad attribution,
cross-tier compaction and range proofs, crash atomicity at every archive
window, and concurrent readers during an in-flight migration.
"""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import subprocess
import sys
import time

from tests._helpers import AuditTestCase, REPO_ROOT

WORKER = os.path.join(REPO_ROOT, "tests", "_crash_worker.py")


class ArchiveBasicTest(AuditTestCase):
    def _three_segments(self) -> None:
        for i in range(3):
            self.chain.append("t", {"i": i})
        self.chain.rotate()
        for i in range(3, 6):
            self.chain.append("t", {"i": i})
        self.chain.rotate()
        for i in range(6, 9):
            self.chain.append("t", {"i": i})

    def _manifest(self) -> dict:
        with open(os.path.join(self.path, "manifest.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def test_archive_moves_only_sealed_segments(self) -> None:
        self._three_segments()
        archive_dir = os.path.join(self._tmp, "archive")
        result = self.chain.archive(archive_dir)
        self.assertEqual(result, {"archived": 2})

        # The two sealed segments left the hot directory; the active stayed.
        hot = self.segment_files()
        self.assertEqual(hot, ["seg-00000003.jsonl"])
        self.assertEqual(
            sorted(os.listdir(archive_dir)),
            ["seg-00000001.jsonl", "seg-00000002.jsonl"],
        )
        manifest = self._manifest()
        self.assertEqual(manifest["archive"], os.path.abspath(archive_dir))
        locations = [s.get("location", "hot") for s in manifest["segments"]]
        self.assertEqual(locations, ["archive", "archive", "hot"])

    def test_archived_bytes_are_identical(self) -> None:
        for i in range(4):
            self.chain.append("t", {"i": i})
        self.chain.rotate()
        self.chain.append("t", {"i": 4})
        sealed = self.segment_files()[0]
        original = self.raw_bytes(sealed)
        archive_dir = os.path.join(self._tmp, "archive")
        self.chain.archive(archive_dir)
        with open(os.path.join(archive_dir, sealed), "rb") as fh:
            self.assertEqual(fh.read(), original)
        self.assertFalse(os.path.exists(os.path.join(self.path, sealed)))

    def test_entries_verify_head_across_tiers(self) -> None:
        self._three_segments()
        self.chain.archive(os.path.join(self._tmp, "archive"))
        self.assertEqual(
            [e["payload"]["i"] for e in self.chain.entries("t")],
            list(range(9)),
        )
        self.assertEqual(
            self.chain.verify("t"), {"count": 9, "first_bad": -1, "ok": True}
        )
        self.assertEqual(
            self.chain.head("t"), self.chain.entries("t")[-1]["digest"]
        )

    def test_append_after_archive_keeps_continuous_indices(self) -> None:
        self._three_segments()
        self.chain.archive(os.path.join(self._tmp, "archive"))
        for i in range(9, 12):
            self.chain.append("t", {"i": i})
        self.chain.append("u", {"n": 1})
        result = self.chain.verify("t")
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 12)
        self.assertEqual(
            [e["payload"]["i"] for e in self.chain.entries("t")],
            list(range(12)),
        )
        entries = self.chain.entries("t")
        for pos, entry in enumerate(entries):
            self.assertEqual(
                entry["prev"], entries[pos - 1]["digest"] if pos else ""
            )

    def test_rotate_and_second_archive(self) -> None:
        self._three_segments()
        archive_dir = os.path.join(self._tmp, "archive")
        self.chain.archive(archive_dir)
        self.chain.append("t", {"i": 9})
        self.chain.rotate()
        self.chain.append("t", {"i": 10})
        # The freshly sealed hot segment migrates too; the active never does.
        self.assertEqual(self.chain.archive(archive_dir), {"archived": 1})
        self.assertEqual(
            [e["payload"]["i"] for e in self.chain.entries("t")],
            list(range(11)),
        )
        self.assertTrue(self.chain.verify("t")["ok"])

    def test_archive_without_sealed_segments_is_noop(self) -> None:
        self.chain.append("t", {})
        # A file-layout log cannot be archived.
        with self.assertRaises(ValueError):
            self.chain.archive(os.path.join(self._tmp, "archive"))
        # An empty file rotated into a store yields one empty active segment
        # and no sealed segment, so there is nothing to migrate.
        plain = type(self.chain)(os.path.join(self._tmp, "empty"))
        plain.rotate()
        self.assertEqual(plain.archive(os.path.join(self._tmp, "archive0")),
                         {"archived": 0})

    def test_rebinding_to_another_archive_is_value_error(self) -> None:
        self._three_segments()
        self.chain.archive(os.path.join(self._tmp, "archive"))
        with self.assertRaises(ValueError):
            self.chain.archive(os.path.join(self._tmp, "other"))

    def test_archive_dir_must_not_nest_the_store(self) -> None:
        self._three_segments()
        with self.assertRaises(ValueError):
            self.chain.archive(os.path.join(self.path, "inside"))

        # The store nested inside the proposed archive is rejected too.
        nested_path = os.path.join(self._tmp, "nestedstore")
        nested = type(self.chain)(nested_path)
        nested.rotate()  # creates an empty segment store
        with self.assertRaises(ValueError):
            nested.archive(self._tmp)


class ArchiveSemanticsTest(AuditTestCase):
    def _archived_store(self, per_segment: int = 8, segments: int = 3) -> str:
        index = 0
        for seg in range(segments):
            for _ in range(per_segment):
                self.chain.append("t", {"i": index})
                index += 1
            if seg < segments - 1:
                self.chain.rotate()
        archive_dir = os.path.join(self._tmp, "archive")
        self.chain.archive(archive_dir)
        return archive_dir

    def test_first_bad_index_is_real_across_tiers(self) -> None:
        archive_dir = self._archived_store()
        # Tamper a record that now lives in the archived first segment.
        target = os.path.join(archive_dir, "seg-00000001.jsonl")
        with open(target, "rb") as fh:
            data = fh.read()
        forged = data.replace(b'{"i":3}', b'{"i":7}', 1)
        self.assertEqual(len(forged), len(data))
        with open(target, "wb") as fh:
            fh.write(forged)
        result = self.chain.verify("t")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"], 3)
        # A broken chain blocks further appends; entries still parses (the
        # line is structurally well-formed, only its digest link is broken).
        with self.assertRaises(ValueError):
            self.chain.append("t", {"i": 100})

    def test_recomputed_forgery_in_archived_window_does_not_pass(self) -> None:
        import json as _json

        from audit_chain import record as recmod

        # All of tenant t's records live in the segment that gets archived;
        # only a different tenant grows the hot active afterwards. An
        # equal-length rewrite with fully recomputed digests leaves t's own
        # chain re-derivable inside the window, so only the sealed window
        # tripwire can catch it -- attributing the window's first index.
        for i in range(4):
            self.chain.append("t", {"i": i})
        self.chain.append("u", {"n": 0})
        self.chain.rotate()
        self.chain.append("u", {"n": 1})
        archive_dir = os.path.join(self._tmp, "archive")
        self.chain.archive(archive_dir)

        target = os.path.join(archive_dir, "seg-00000001.jsonl")
        with open(target, encoding="utf-8") as fh:
            records = [_json.loads(line) for line in fh.read().splitlines()]
        prev: dict[str, str] = {}
        out = bytearray()
        for record in records:
            tenant = record["tenant"]
            head = prev.get(tenant, "")
            if tenant == "t":
                payload = (
                    {"i": 8} if record["payload"] == {"i": 1} else record["payload"]
                )
            else:
                payload = record["payload"]
            record["payload"] = payload
            record["prev"] = head
            record["digest"] = recmod.digest(head, payload)
            prev[tenant] = record["digest"]
            out += (
                _json.dumps(
                    record, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                )
                + "\n"
            ).encode()
        with open(target, "rb") as fh:
            original = fh.read()
        self.assertEqual(len(bytes(out)), len(original))
        with open(target, "wb") as fh:
            fh.write(bytes(out))
        result_t = self.chain.verify("t")
        self.assertFalse(result_t["ok"])
        self.assertEqual(result_t["first_bad"], 0)
        # u also had a record in the rewritten window.
        self.assertFalse(self.chain.verify("u")["ok"])
        with self.assertRaises(ValueError):
            self.chain.append("t", {"i": 4})

    def test_archived_window_anchor_tamper_is_corruption(self) -> None:
        self._archived_store()
        from audit_chain import storage as st

        layout = st.Layout(self.path, "dir")
        manifest = st.load_manifest(layout)
        manifest["segments"][0]["parts"][0]["sha256"] = "b" * 64
        st.save_manifest(layout, manifest)
        result = self.chain.verify("t")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"], 0)

    def test_payload_type_and_missing_file_contracts_hold(self) -> None:
        self._archived_store()
        with self.assertRaises(TypeError):
            self.chain.append("t", [1, 2])
        missing = type(self.chain)(os.path.join(self._tmp, "absent"))
        with self.assertRaises(FileNotFoundError):
            missing.verify("t")

    def test_lost_archived_segment_is_file_not_found(self) -> None:
        archive_dir = self._archived_store()
        os.remove(os.path.join(archive_dir, "seg-00000001.jsonl"))
        with self.assertRaises(FileNotFoundError):
            self.chain.verify("t")

    def test_cache_and_manifest_both_tampered_never_passes(self) -> None:
        archive_dir = self._archived_store()
        from audit_chain import storage as st

        layout = st.Layout(self.path, "dir")
        # Corrupt the signed cache body.
        cache_path = layout.cache_path
        with open(cache_path, "rb") as fh:
            raw = bytearray(fh.read())
        raw[40] ^= 0x01
        with open(cache_path, "wb") as fh:
            fh.write(bytes(raw))
        # And independently rewrite a manifest window anchor.
        manifest = st.load_manifest(layout)
        manifest["segments"][0]["parts"][0]["sha256"] = "c" * 64
        st.save_manifest(layout, manifest)
        result = self.chain.verify("t")
        self.assertFalse(result["ok"])
        self.assertGreaterEqual(result["first_bad"], 0)
        with self.assertRaises(ValueError):
            self.chain.append("t", {"i": 99})

    def test_half_line_in_active_after_archive_still_bad_then_recovers(self) -> None:
        self._archived_store()
        active = self.segment_files()[-1]
        with open(os.path.join(self.path, active), "ab") as fh:
            fh.write(b'{"digest":"z"')
        with self.assertRaises(ValueError):
            self.chain.verify("t")
        removed = self.chain.recover()["truncated_bytes"]
        self.assertEqual(removed, len(b'{"digest":"z"'))
        total = self.chain.verify("t")["count"]
        self.assertTrue(self.chain.verify("t")["ok"])
        # Indices stay continuous after recovery.
        self.assertEqual(
            [e["payload"]["i"] for e in self.chain.entries("t")],
            list(range(total)),
        )


class CrossTierCompactTest(AuditTestCase):
    def _store(self):
        for i in range(3):
            self.chain.append("t", {"i": i})
        self.chain.rotate()
        for i in range(3, 6):
            self.chain.append("t", {"i": i})
        self.chain.rotate()
        for i in range(6, 9):
            self.chain.append("t", {"i": i})

    def test_compact_one_folds_archived_and_hot_sources(self) -> None:
        self._store()
        archive_dir = os.path.join(self._tmp, "archive")
        self.chain.archive(archive_dir)
        result = self.chain.compact(1)
        self.assertEqual(result, {"segments": 1})
        # Every source is gone from BOTH tiers; the merged segment is hot.
        self.assertEqual(len(self.segment_files()), 1)
        self.assertEqual(os.listdir(archive_dir), [])
        self.assertEqual(
            [e["payload"]["i"] for e in self.chain.entries("t")],
            list(range(9)),
        )
        self.assertEqual(
            self.chain.verify("t"), {"count": 9, "first_bad": -1, "ok": True}
        )
        self.chain.append("t", {"i": 9})
        self.assertEqual(self.chain.verify("t")["count"], 10)

    def test_compact_pairwise_after_partial_archive(self) -> None:
        self._store()
        archive_dir = os.path.join(self._tmp, "archive")
        self.chain.archive(archive_dir)  # seg1 + seg2 archived
        self.chain.append("t", {"i": 9})
        self.chain.rotate()
        self.chain.append("t", {"i": 10})
        result = self.chain.compact(2)
        self.assertEqual(result, {"segments": 2})
        self.assertTrue(self.chain.verify("t")["ok"])
        self.assertEqual(
            [e["payload"]["i"] for e in self.chain.entries("t")],
            list(range(11)),
        )


class CrossTierExportTest(AuditTestCase):
    def _store(self):
        for i in range(20):
            self.chain.append("t", {"i": i})
            if i % 2 == 0:
                self.chain.append("u", {"i": i})
        self.chain.rotate()
        for i in range(20, 35):
            self.chain.append("t", {"i": i})

    def test_export_inside_archived_segment_verifies_offline(self) -> None:
        from audit_chain import verify_proof

        self._store()
        self.chain.archive(os.path.join(self._tmp, "archive"))
        proof = self.chain.export_range("t", 2, 12)
        verdict = verify_proof(proof, tenant="t", start=2, end=12)
        self.assertTrue(verdict["ok"], verdict)
        exported = [
            item["index"]
            for window in proof["windows"]
            for item in window["records"]
        ]
        self.assertEqual(exported, list(range(2, 12)))

    def test_export_spanning_archived_and_hot_units(self) -> None:
        from audit_chain import combine_proofs, verify_proof

        self._store()
        self.chain.archive(os.path.join(self._tmp, "archive"))
        left = self.chain.export_range("t", 0, 20)
        right = self.chain.export_range("t", 20, 35)
        combined = combine_proofs(left, right)
        self.assertTrue(
            verify_proof(combined, tenant="t", start=0, end=35)["ok"]
        )
        self.assertEqual(
            [
                item["index"]
                for window in combined["windows"]
                for item in window["records"]
            ],
            list(range(35)),
        )

    def test_archived_damage_outside_interval_is_irrelevant(self) -> None:
        from audit_chain import verify_proof

        self._store()
        archive_dir = os.path.join(self._tmp, "archive")
        self.chain.archive(archive_dir)
        target = os.path.join(archive_dir, "seg-00000001.jsonl")
        with open(target, "rb") as fh:
            data = fh.read()
        forged = data.replace(b'{"i":1}', b'{"i":8}', 1)
        with open(target, "wb") as fh:
            fh.write(forged)
        proof = self.chain.export_range("t", 20, 35)
        self.assertTrue(
            verify_proof(proof, tenant="t", start=20, end=35)["ok"]
        )

    def test_bounded_export_opens_only_covering_units(self) -> None:
        import builtins

        from audit_chain import verify_proof

        self._store()
        archive_dir = os.path.join(self._tmp, "archive")
        self.chain.archive(archive_dir)
        self.assertTrue(self.chain.verify("t")["ok"])

        opened: set[str] = set()
        real_open = builtins.open

        def counting_open(path, *args, **kwargs):
            mode = args[0] if args else kwargs.get("mode", "r")
            if "b" in mode:
                opened.add(os.path.abspath(os.fspath(path)))
            return real_open(path, *args, **kwargs)

        builtins.open = counting_open
        try:
            proof = self.chain.export_range("t", 10, 15)
        finally:
            builtins.open = real_open
        self.assertTrue(verify_proof(proof, start=10, end=15)["ok"])
        archive_first = os.path.abspath(
            os.path.join(archive_dir, "seg-00000001.jsonl")
        )
        hot_active = os.path.abspath(
            os.path.join(self.path, "seg-00000002.jsonl")
        )
        self.assertIn(archive_first, opened)
        # The hot active unit carries no interval record and is never opened.
        self.assertNotIn(hot_active, opened)

    def test_batch_verify_across_tiers(self) -> None:
        from audit_chain import verify_proofs

        self._store()
        self.chain.archive(os.path.join(self._tmp, "archive"))
        proofs = [
            self.chain.export_range("t", 0, 10),
            self.chain.export_range("t", 10, 20),
            self.chain.export_range("t", 20, 35),
        ]
        verdicts = verify_proofs(proofs)
        self.assertEqual([v["count"] for v in verdicts], [10, 10, 15])
        self.assertTrue(all(v["ok"] for v in verdicts))
        # Same verdict shape and bad-index caliber as the on-chain verdict.
        self.assertEqual(set(verdicts[0]), {"ok", "first_bad", "count"})


class ArchiveCacheTest(AuditTestCase):
    def test_rewritten_prefix_plus_growth_is_full_recomputed(self) -> None:
        # Warm the cache, then tamper a prefix byte AND append a further line
        # on the raw file (bypassing the chain). Any continuation must
        # authenticate the cached prefix first, reject it, re-derive the
        # whole unit, and pin the real bad index -- never adopt the cached
        # cumulative states and blame the new tail.
        for i in range(40):
            self.chain.append("t", {"i": i})
        self.assertTrue(self.chain.verify("t")["ok"])
        data = self.raw_bytes()
        good = data
        forged = data.replace(b'{"i":10}', b'{"i":17}', 1)
        self.assertEqual(len(forged), len(good))
        # Append a well-formed, fresh tail line after the tampered prefix.
        tail = (
            b'{"digest":"0000000000000000000000000000000000000000000000000000000000000000",'
            b'"payload":{"i":40},"prev":"","tenant":"t"}\n'
        )
        self.write_raw(forged + tail)
        result = self.chain.verify("t")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"], 10)

    def test_reverify_does_not_hash_archived_bytes(self) -> None:
        real_sha = hashlib.sha256
        total = [0]

        def counting(data: bytes = b""):
            instance = real_sha(data)
            total[0] += len(data)

            class _H:
                def update(self_inner, chunk: bytes) -> None:
                    total[0] += len(chunk)
                    instance.update(chunk)

                def hexdigest(self_inner) -> str:
                    return instance.hexdigest()

            return _H()

        for i in range(3000):
            self.chain.append("t", {"i": i})
        self.chain.rotate()
        for i in range(3000, 3010):
            self.chain.append("t", {"i": i})
        archive_dir = os.path.join(self._tmp, "archive")
        self.chain.archive(archive_dir)
        sealed_size = os.path.getsize(
            os.path.join(archive_dir, "seg-00000001.jsonl")
        )
        self.assertGreater(sealed_size, 100_000)
        self.assertTrue(self.chain.verify("t")["ok"])

        hashlib.sha256 = counting
        try:
            result = self.chain.verify("t")
        finally:
            hashlib.sha256 = real_sha
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 3010)
        self.assertLess(total[0], sealed_size // 50)


class ArchiveConcurrencyTest(AuditTestCase):
    def test_reads_see_complete_prefix_around_archiving(self) -> None:
        ctx = multiprocessing.get_context("fork")
        archive_dir = os.path.join(self._tmp, "archive")
        ready = ctx.Queue()

        def writer_main() -> None:  # pragma: no cover
            sys.path.insert(0, REPO_ROOT)
            from audit_chain import Chain

            chain = Chain(self.path)
            index = 0
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                chain.append("t", {"i": index})
                index += 1
                if index == 3:
                    ready.put(True)
                if index % 40 == 0:
                    chain.rotate()
                if index % 120 == 0:
                    chain.archive(archive_dir)

        writer = ctx.Process(target=writer_main)
        writer.start()
        self.assertTrue(ready.get(timeout=30))
        ticks = 0
        while writer.is_alive() and ticks < 20000:
            entries = self.chain.entries("t")
            payloads = [entry["payload"]["i"] for entry in entries]
            self.assertEqual(payloads, list(range(len(entries))))
            result = self.chain.verify("t")
            self.assertTrue(result["ok"], result)
            ticks += 1
        writer.join(timeout=30)
        self.assertEqual(writer.exitcode, 0)
        final = self.chain.verify("t")
        self.assertTrue(final["ok"])
        self.assertEqual(
            [e["payload"]["i"] for e in self.chain.entries("t")],
            list(range(final["count"])),
        )
        # The run must actually have crossed into the archive tier.
        with open(os.path.join(self.path, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        self.assertEqual(manifest.get("archive"), os.path.abspath(archive_dir))
        self.assertTrue(
            any(
                s.get("location") == "archive"
                for s in manifest["segments"]
            )
            or final["count"] >= 120
        )


def _self_read_worker(path: str, archive_dir: str, role: int) -> None:  # pragma: no cover
    sys.path.insert(0, REPO_ROOT)
    from audit_chain import Chain

    chain = Chain(path, lock_timeout=60.0)
    for index in range(30):
        entry = chain.append("t", {"i": role * 1000 + index})
        # The instant the append returns, head/verify/entries must already
        # show the just-committed record -- never starved by an archive or
        # compaction lock held by the other process.
        assert chain.head("t") is not None
        result = chain.verify("t")
        assert result["ok"], result
        assert entry["digest"] in [e["digest"] for e in chain.entries("t")]
        if index % 7 == 0:
            chain.rotate()
        if role == 0 and index % 11 == 0:
            chain.archive(archive_dir)
        if role == 1 and index % 13 == 0:
            try:
                chain.compact(1)
            except ValueError:
                pass


class ArchiveWriterVisibilityTest(AuditTestCase):
    def test_each_writer_sees_its_record_and_is_not_starved(self) -> None:
        archive_dir = os.path.join(self._tmp, "archive")
        # Seed enough history so rotate/archive/compact have something to do.
        for i in range(20):
            self.chain.append("t", {"i": i})
        self.chain.rotate()
        for i in range(20, 24):
            self.chain.append("t", {"i": i})

        ctx = multiprocessing.get_context("fork")
        processes = [
            ctx.Process(target=_self_read_worker, args=(self.path, archive_dir, role))
            for role in range(2)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=120)
            self.assertEqual(process.exitcode, 0)

        result = self.chain.verify("t")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["count"], 24 + 60)
        self.assertEqual(len(self.chain.entries("t")), result["count"])



class ArchiveCrashTest(AuditTestCase):
    def _kill(self, point: str) -> subprocess.CompletedProcess:
        archive_dir = os.path.join(self._tmp, "archive")
        env = dict(os.environ)
        env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
        return subprocess.run(
            [
                sys.executable,
                WORKER,
                self.path,
                "archive",
                point,
                "0",
                archive_dir,
            ],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

    def _prepare(self) -> None:
        for i in range(3):
            self.chain.append("t", {"i": i})
        self.chain.rotate()
        for i in range(3, 6):
            self.chain.append("t", {"i": i})
        self.chain.rotate()
        for i in range(6, 9):
            self.chain.append("t", {"i": i})

    def _assert_intact(self, reopened, count: int = 9) -> None:
        self.assertEqual(
            reopened.verify("t"),
            {"count": count, "first_bad": -1, "ok": True},
        )
        self.assertEqual(
            [e["payload"]["i"] for e in reopened.entries("t")],
            list(range(count)),
        )

    def test_every_crash_window_lands_on_one_topology(self) -> None:
        points = (
            "archive:after_register",
            "archive:after_sentinel",
            "archive:before_copy_fsync",
            "archive:after_copy_write",
            "archive:after_copy_rename",
            "archive:after_copy",
            "archive:after_manifest",
            "archive:during_delete_hot",
            "archive:after_delete_hot",
            "archive:after_finalize",
            "atomic:manifest.json:before_replace",
        )
        for index, point in enumerate(points):
            self._prepare()
            completed = self._kill(point)
            self.assertNotEqual(
                completed.returncode,
                0,
                f"{point}: {completed.stderr.decode()[:400]}",
            )
            reopened = type(self.chain)(self.path)
            # Whichever topology survived, it is complete and strictly linked.
            self._assert_intact(reopened)
            # Never copies in both tiers for the same segment.
            for name in ("seg-00000001.jsonl", "seg-00000002.jsonl"):
                in_hot = os.path.exists(os.path.join(self.path, name))
                in_archive = os.path.exists(
                    os.path.join(self._tmp, "archive", name)
                )
                self.assertFalse(
                    in_hot and in_archive, f"{point}: duplicate copy of {name}"
                )
            # The sentinel is always retired on reopen and no moving segment
            # survives a healer pass.
            self.assertFalse(
                os.path.exists(os.path.join(self.path, ".archiving")),
                point,
            )
            # Further appends and a fresh archive work from either topology.
            reopened.append("t", {"i": 9})
            self.assertTrue(reopened.verify("t")["ok"])
            # Reset store for the next matrix point.
            import shutil

            shutil.rmtree(self.path, ignore_errors=True)
            shutil.rmtree(os.path.join(self._tmp, "archive"), ignore_errors=True)
            self.chain = type(self.chain)(self.path)

    def test_lost_archive_copy_after_commit_rolls_back(self) -> None:
        self._prepare()
        archive_dir = os.path.join(self._tmp, "archive")
        self._kill("archive:after_manifest")
        # Simulate losing the archive volume before reopen: every archived
        # copy disappears while the manifest says moving.
        import shutil

        shutil.rmtree(archive_dir)
        reopened = type(self.chain)(self.path)
        self._assert_intact(reopened)
        # Rolled back to the pre-archive topology: hot copies present.
        self.assertEqual(
            self.segment_files(),
            ["seg-00000001.jsonl", "seg-00000002.jsonl", "seg-00000003.jsonl"],
        )
        with open(os.path.join(self.path, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        self.assertTrue(
            all("location" not in s for s in manifest["segments"])
        )
        # Retrying the migration then completes forward.
        reopened.archive(archive_dir)
        self.assertEqual(
            [e["payload"]["i"] for e in reopened.entries("t")],
            list(range(9)),
        )


class ArchiveCliTest(AuditTestCase):
    def test_archive_command_and_exit_codes(self) -> None:
        import contextlib
        import io

        from audit_chain.__main__ import main

        for i in range(3):
            self.chain.append("t", {"i": i})
        self.chain.rotate()
        self.chain.append("t", {"i": 3})

        archive_dir = os.path.join(self._tmp, "archive")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(
                ["--path", self.path, "archive", archive_dir]
            )
        self.assertEqual(code, 0)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(json.loads(out.getvalue()), {"archived": 1})

        # A file-layout log archives as a silent exit-2 error.
        plain = os.path.join(self._tmp, "plain")
        type(self.chain)(plain).append("t", {})
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
            io.StringIO()
        ):
            code = main(["--path", plain, "archive", os.path.join(self._tmp, "a2")])
        self.assertEqual(code, 2)
