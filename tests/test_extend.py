"""Proof extension: continue an exported proof to the current prefix."""

from __future__ import annotations

import copy
import json
import os
import threading

from audit_chain import (
    Chain,
    combine_proofs,
    extend_proof,
    verify_proof,
    verify_proofs,
)
from audit_chain import record as rec
from tests._helpers import AuditTestCase
from tests.test_export_cost import _HashMeter, _ReadMeter


class ExtendProofTest(AuditTestCase):
    def _multi_segment(self) -> None:
        # Same shape as the proof/combine suites: 45 t-records over three
        # rotations, compacted down to two segments.
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

    def _corrupt_record(self, old: bytes, new: bytes, tenant: str) -> None:
        for name in self.segment_files():
            data = self.raw_bytes(name)
            lines = data.split(b"\n")
            for j, line in enumerate(lines):
                if old in line and f'"tenant":"{tenant}"'.encode() in line:
                    lines[j] = line.replace(old, new, 1)
                    self.write_raw(b"\n".join(lines), name)
                    return
        self.fail("target record not found")

    # -- shape and conclusions ---------------------------------------------

    def test_extends_to_current_complete_prefix(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 0, 20)
        for i in range(45, 60):
            self.chain.append("t", {"i": i})
        extended = extend_proof(proof, self.path)
        # Same shape an export produces.
        self.assertEqual(
            set(extended),
            {"version", "tenant", "start", "end", "count", "prev", "windows"},
        )
        self.assertEqual(extended["tenant"], "t")
        self.assertEqual(extended["start"], 0)
        self.assertEqual(extended["end"], 60)
        self.assertEqual(extended["count"], 60)
        self.assertEqual(extended["prev"], proof["prev"])
        result = verify_proof(extended, tenant="t", start=0, end=60)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["first_bad"], -1)
        exported = [item for w in extended["windows"] for item in w["records"]]
        self.assertEqual([item["index"] for item in exported], list(range(60)))
        for item in exported:
            self.assertEqual(item["record"]["tenant"], "t")
        # Same conclusion as a fresh full-range export.
        fresh = verify_proof(self.chain.export_range("t", 0, 60))
        self.assertEqual(
            (result["ok"], result["first_bad"], result["count"]),
            (fresh["ok"], fresh["first_bad"], fresh["count"]),
        )

    def test_middle_range_extension_keeps_its_start(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 10, 30)
        for i in range(45, 50):
            self.chain.append("t", {"i": i})
        extended = extend_proof(proof, self.path)
        self.assertEqual(extended["start"], 10)
        self.assertEqual(extended["end"], 50)
        entries = self.chain.entries("t")
        self.assertEqual(extended["prev"], entries[9]["digest"])
        result = verify_proof(extended, tenant="t", start=10, end=50)
        self.assertTrue(result["ok"], result)
        exported = [item for w in extended["windows"] for item in w["records"]]
        self.assertEqual([item["index"] for item in exported], list(range(10, 50)))

    def test_no_new_records_returns_equivalent_proof(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 0, 45)
        before = copy.deepcopy(proof)
        extended = extend_proof(proof, self.path)
        self.assertEqual(extended, proof)
        # The input is not mutated and the result shares nothing with it.
        self.assertEqual(proof, before)
        self.assertIsNot(extended, proof)
        self.assertEqual(verify_proof(extended), verify_proof(proof))

    def test_extend_empty_proof_grows_from_zero(self) -> None:
        empty = self.chain.export_range("t", 0, 0)
        self.append_many("t", 5)
        extended = extend_proof(empty, self.path)
        self.assertEqual((extended["start"], extended["end"], extended["count"]), (0, 5, 5))
        self.assertEqual(extended["prev"], "")
        self.assertTrue(verify_proof(extended, tenant="t", start=0, end=5)["ok"])

    def test_extend_on_legacy_file_layout(self) -> None:
        self.append_many("t", 10)
        proof = self.chain.export_range("t", 0, 10)
        self.append_many("t", 5, start=10)
        extended = extend_proof(proof, self.path)
        self.assertTrue(verify_proof(extended, start=0, end=15)["ok"])

    def test_extend_across_rotation_and_compaction(self) -> None:
        self.append_many("t", 10)
        proof = self.chain.export_range("t", 0, 10)
        self.chain.rotate()
        self.append_many("t", 10, start=10)
        self.chain.rotate()
        self.append_many("t", 5, start=20)
        self.chain.compact(2)
        extended = extend_proof(proof, self.path)
        result = verify_proof(extended, start=0, end=25)
        self.assertTrue(result["ok"], result)
        seqs = [window["seq"] for window in extended["windows"]]
        self.assertEqual(seqs, sorted(set(seqs)))

    def test_extend_across_archive(self) -> None:
        self._multi_segment()
        self.assertTrue(self.chain.verify("t")["ok"])
        proof = self.chain.export_range("t", 0, 40)
        self.chain.archive(os.path.join(self._tmp, "cold"))
        self.append_many("t", 5, start=45)
        extended = extend_proof(proof, self.path)
        self.assertTrue(verify_proof(extended, start=0, end=50)["ok"])

    def test_extended_proof_is_self_contained(self) -> None:
        import shutil

        self._multi_segment()
        proof = self.chain.export_range("t", 0, 20)
        self.append_many("t", 5, start=45)
        extended = extend_proof(proof, self.path)
        shutil.rmtree(self.path)
        self.assertTrue(verify_proof(extended, tenant="t", start=0, end=50)["ok"])

    def test_extend_combined_proof_and_combine_extended(self) -> None:
        self._multi_segment()
        left = self.chain.export_range("t", 0, 20)
        right = self.chain.export_range("t", 20, 45)
        combined = combine_proofs(left, right)
        self.append_many("t", 10, start=45)
        extended = extend_proof(combined, self.path)
        self.assertTrue(verify_proof(extended, start=0, end=55)["ok"])
        # Extending the splice agrees with splicing onto an extended
        # piece: combine stays associative across extension.
        spliced = combine_proofs(left, extend_proof(right, self.path))
        self.assertEqual(
            verify_proof(spliced)["ok"],
            verify_proof(extended)["ok"],
        )
        self.assertEqual(
            (
                verify_proof(spliced)["first_bad"],
                verify_proof(spliced)["count"],
            ),
            (
                verify_proof(extended)["first_bad"],
                verify_proof(extended)["count"],
            ),
        )

    def test_repeated_extension_is_incremental(self) -> None:
        self.append_many("t", 5)
        proof = self.chain.export_range("t", 0, 5)
        self.append_many("t", 5, start=5)
        first = extend_proof(proof, self.path)
        self.assertEqual(first["end"], 10)
        # Nothing new since: equivalent to the input.
        self.assertEqual(extend_proof(first, self.path), first)
        self.append_many("t", 5, start=10)
        second = extend_proof(first, self.path)
        self.assertTrue(verify_proof(second, start=0, end=15)["ok"])

    def test_batch_and_single_verdicts_agree_on_extended_proofs(self) -> None:
        self._multi_segment()
        self.append_many("t", 5, start=45)
        proofs = [
            extend_proof(self.chain.export_range("t", 0, 10), self.path),
            extend_proof(self.chain.export_range("t", 10, 40), self.path),
            extend_proof(self.chain.export_range("t", 40, 45), self.path),
        ]
        verdicts = verify_proofs(proofs)
        self.assertEqual(len(verdicts), 3)
        for proof, verdict in zip(proofs, verdicts):
            full = verify_proof(proof)
            self.assertEqual(
                verdict,
                {
                    "ok": full["ok"],
                    "first_bad": full["first_bad"],
                    "count": full["count"],
                },
            )
        self.assertTrue(all(v["ok"] for v in verdicts))

    # -- error surface -------------------------------------------------------

    def test_non_dict_proof_is_type_error(self) -> None:
        self.append_many("t", 3)
        for bad in (None, 42, "proof", [self.chain.export_range("t", 0, 3)]):
            with self.assertRaises(TypeError):
                extend_proof(bad, self.path)

    def test_tampered_proof_is_value_error(self) -> None:
        self.append_many("t", 6)
        proof = self.chain.export_range("t", 0, 6)
        proof["windows"][0]["records"][2]["record"]["payload"] = {"i": -1}
        with self.assertRaises(ValueError):
            extend_proof(proof, self.path)

    def test_malformed_and_reversed_proofs_are_value_error(self) -> None:
        self.append_many("t", 6)
        with self.assertRaises(ValueError):
            extend_proof({"version": 1, "tenant": "t"}, self.path)
        reversed_proof = self.chain.export_range("t", 0, 5)
        reversed_proof["start"], reversed_proof["end"] = 5, 0
        with self.assertRaises(ValueError):
            extend_proof(reversed_proof, self.path)

    def test_missing_log_is_file_not_found(self) -> None:
        self.append_many("t", 4)
        proof = self.chain.export_range("t", 0, 4)
        absent = os.path.join(self._tmp, "absent")
        with self.assertRaises(FileNotFoundError):
            extend_proof(proof, absent)

    def test_end_beyond_record_count_is_value_error(self) -> None:
        # A genuine proof of a longer history does not extend against a
        # shorter one, even for the same tenant.
        self.append_many("t", 10)
        proof = self.chain.export_range("t", 0, 10)
        other = Chain(os.path.join(self._tmp, "other"))
        other.append("t", {"i": 0})
        other.append("t", {"i": 1})
        with self.assertRaises(ValueError):
            extend_proof(proof, other.path)

    def test_corruption_before_proof_end_is_value_error(self) -> None:
        self._multi_segment()
        self.assertTrue(self.chain.verify("t")["ok"])
        proof = self.chain.export_range("t", 0, 20)
        # Flip t record index 2's payload in its sealed segment.
        self._corrupt_record(b'{"i":2}', b'{"i":9}', "t")
        with self.assertRaises(ValueError):
            extend_proof(proof, self.path)

    def test_corruption_inside_increment_is_value_error(self) -> None:
        self._multi_segment()
        self.assertTrue(self.chain.verify("t")["ok"])
        proof = self.chain.export_range("t", 0, 20)
        # The damage lies past the proof's end: the increment would carry
        # it, so the spliced proof cannot check out.
        self._corrupt_record(b'{"i":30}', b'{"i":39}', "t")
        with self.assertRaises(ValueError):
            extend_proof(proof, self.path)

    def test_shrunk_log_is_value_error(self) -> None:
        self.append_many("t", 10)
        self.assertTrue(self.chain.verify("t")["ok"])
        proof = self.chain.export_range("t", 0, 10)
        lines = self.raw_bytes().split(b"\n")[:-1]
        self.write_raw(b"\n".join(lines[:-2]) + b"\n")
        with self.assertRaises(ValueError):
            extend_proof(proof, self.path)

    def test_recomputed_rewrite_is_value_error(self) -> None:
        # A same-shape rewrite with fully recomputed digests is still a
        # rewritten history: the surviving cache anchors the chain head.
        self.append_many("t", 6)
        self.assertTrue(self.chain.verify("t")["ok"])
        proof = self.chain.export_range("t", 0, 6)
        records = [
            json.loads(line)
            for line in self.raw_bytes().decode().split("\n")[:-1]
        ]
        out = bytearray()
        prev = ""
        for record in records:
            if record["payload"] == {"i": 0}:
                continue
            record["prev"] = prev
            record["digest"] = rec.digest(prev, record["payload"])
            prev = record["digest"]
            out += (
                json.dumps(
                    record, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                )
                + "\n"
            ).encode()
        self.write_raw(bytes(out))
        with self.assertRaises(ValueError):
            extend_proof(proof, self.path)

    def test_tampered_cache_is_value_error(self) -> None:
        self.append_many("t", 5)
        self.assertTrue(self.chain.verify("t")["ok"])
        proof = self.chain.export_range("t", 0, 5)
        cache_path = os.path.join(
            self._tmp, "." + os.path.basename(self.path) + ".verify-cache"
        )
        with open(cache_path, "rb") as handle:
            raw = bytearray(handle.read())
        raw[40] ^= 0x01
        with open(cache_path, "wb") as handle:
            handle.write(bytes(raw))
        with self.assertRaises(ValueError):
            extend_proof(proof, self.path)

    def test_tampered_manifest_is_value_error(self) -> None:
        self._multi_segment()
        self.assertTrue(self.chain.verify("t")["ok"])
        proof = self.chain.export_range("t", 0, 20)
        manifest_path = os.path.join(self.path, "manifest.json")
        with open(manifest_path, "rb") as handle:
            raw = bytearray(handle.read())
        raw[30] ^= 0x01
        with open(manifest_path, "wb") as handle:
            handle.write(bytes(raw))
        with self.assertRaises(ValueError):
            extend_proof(proof, self.path)

    def test_other_tenant_damage_does_not_change_the_interval(self) -> None:
        # Damage to another tenant's records in the un-windowed active
        # tail neither breaks t's chain nor enters t's proof.
        for i in range(10):
            self.chain.append("t", {"i": i})
            self.chain.append("u", {"i": i})
        self.assertTrue(self.chain.verify("t")["ok"])
        proof = self.chain.export_range("t", 0, 10)
        self.append_many("t", 5, start=10)
        data = self.raw_bytes()
        lines = data.split(b"\n")
        for j, line in enumerate(lines):
            if b'{"i":4}' in line and b'"tenant":"u"' in line:
                lines[j] = line.replace(b'{"i":4}', b'{"i":9}', 1)
                break
        self.write_raw(b"\n".join(lines))
        extended = extend_proof(proof, self.path)
        self.assertTrue(verify_proof(extended, tenant="t", start=0, end=15)["ok"])
        self.assertFalse(self.chain.verify("u")["ok"])

    def test_half_line_tail_extends_to_last_complete_record(self) -> None:
        self.append_many("t", 10)
        proof = self.chain.export_range("t", 0, 10)
        self.append_many("t", 5, start=10)
        with open(self.path, "ab") as handle:
            handle.write(b'{"digest":"abc')
        extended = extend_proof(proof, self.path)
        self.assertTrue(verify_proof(extended, start=0, end=15)["ok"])

    def test_missing_cache_falls_back_to_bytes(self) -> None:
        self.append_many("t", 10)
        proof = self.chain.export_range("t", 0, 10)
        self.append_many("t", 5, start=10)
        os.remove(
            os.path.join(
                self._tmp, "." + os.path.basename(self.path) + ".verify-cache"
            )
        )
        extended = extend_proof(proof, self.path)
        self.assertTrue(verify_proof(extended, start=0, end=15)["ok"])

    # -- snapshot consistency and cleanliness --------------------------------

    def test_concurrent_appends_extend_to_one_complete_prefix(self) -> None:
        self.append_many("t", 30)
        proof = self.chain.export_range("t", 0, 30)
        stop = threading.Event()
        errors: list[BaseException] = []

        def writer() -> None:
            index = 30
            try:
                while not stop.is_set() and index < 200:
                    self.chain.append("t", {"i": index})
                    if index % 25 == 0:
                        self.chain.rotate()
                    index += 1
            except BaseException as exc:  # pragma: no cover - failure path
                errors.append(exc)

        worker = threading.Thread(target=writer)
        worker.start()
        ends = []
        try:
            for _ in range(30):
                extended = extend_proof(proof, self.path)
                self.assertTrue(verify_proof(extended)["ok"])
                ends.append(extended["end"])
        finally:
            stop.set()
            worker.join()
        self.assertEqual(errors, [])
        final = self.chain.verify("t")["count"]
        # Every result named one complete prefix: never below the proof's
        # end, never past the final count, never mixed.
        self.assertTrue(all(30 <= end <= final for end in ends))

    def test_extend_writes_nothing_to_the_store(self) -> None:
        self._multi_segment()
        proof = self.chain.export_range("t", 0, 20)
        self.append_many("t", 5, start=45)
        before = sorted(os.listdir(self.path))
        extend_proof(proof, self.path)
        after = sorted(os.listdir(self.path))
        self.assertEqual(before, after)
        leftovers = [
            name
            for name in after
            if name.startswith(".") and name.endswith(".tmp")
        ]
        self.assertEqual(leftovers, [])
        # A repeated extension works identically.
        self.assertTrue(verify_proof(extend_proof(proof, self.path))["ok"])


class ExtendProofCostTest(AuditTestCase):
    HISTORY = 4_000
    ROTATE_EVERY = 1_000

    def _build(self) -> None:
        for i in range(self.HISTORY):
            self.chain.append("t", {"i": i, "pad": "x" * 24})
            if (i + 1) % self.ROTATE_EVERY == 0 and i + 1 < self.HISTORY:
                self.chain.rotate()
        self.assertTrue(self.chain.verify("t")["ok"])  # warm the cache

    def _segment_paths(self) -> dict[str, str]:
        return {
            name: os.path.abspath(os.path.join(self.path, name))
            for name in self.segment_files()
        }

    def test_extend_reads_and_hashes_only_the_increment(self) -> None:
        self._build()
        proof = self.chain.export_range("t", self.HISTORY - 100, self.HISTORY)
        for i in range(self.HISTORY, self.HISTORY + 200):
            self.chain.append("t", {"i": i, "pad": "x" * 24})

        segments = self._segment_paths()
        active = os.path.abspath(
            os.path.join(self.path, self.segment_files()[-1])
        )
        active_size = os.path.getsize(active)
        total = sum(os.path.getsize(p) for p in segments.values())

        read_meter = _ReadMeter()
        read_meter.install()
        try:
            extended = extend_proof(proof, self.path)
            read_bytes = read_meter.bytes
        finally:
            read_meter.remove()
        self.assertTrue(
            verify_proof(extended, start=self.HISTORY - 100, end=self.HISTORY + 200)[
                "ok"
            ]
        )
        # Only the segment holding the increment is ever opened.
        self.assertEqual(read_meter.paths & set(segments.values()), {active})
        self.assertLessEqual(read_bytes, active_size + 100_000)

        hash_meter = _HashMeter()
        hash_meter.install()
        try:
            extend_proof(proof, self.path)
            hashed = hash_meter.bytes
        finally:
            hash_meter.remove()
        # Digest work tracks the increment, never the sealed history.
        self.assertLess(hashed, active_size // 2)
        self.assertLess(hashed, total // 4)

    def test_noop_extend_opens_no_segment(self) -> None:
        self._build()
        proof = self.chain.export_range("t", 0, self.HISTORY)
        segments = set(self._segment_paths().values())
        read_meter = _ReadMeter()
        read_meter.install()
        try:
            again = extend_proof(proof, self.path)
        finally:
            read_meter.remove()
        self.assertEqual(again, proof)
        self.assertFalse(read_meter.paths & segments)
