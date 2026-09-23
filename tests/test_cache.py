"""Incremental verify cache: cost model and tamper evidence."""

from __future__ import annotations

import hashlib
import json
import os

from tests._helpers import AuditTestCase


class IncrementalCacheTest(AuditTestCase):
    total_hashed = 0
    real_sha256 = staticmethod(hashlib.sha256)

    def setUp(self) -> None:
        super().setUp()
        type(self).total_hashed = 0
        real = self.real_sha256

        def counting_sha256(data: bytes = b""):
            real_instance = real(data)
            type(self).total_hashed += len(data)

            class _H:
                def update(self_inner, chunk: bytes) -> None:
                    type(self).total_hashed += len(chunk)
                    real_instance.update(chunk)

                def hexdigest(self_inner) -> str:
                    return real_instance.hexdigest()

                def copy(self_inner) -> "_H":
                    return self_inner

            return _H()

        self._orig = hashlib.sha256
        hashlib.sha256 = counting_sha256

    def tearDown(self) -> None:
        hashlib.sha256 = self._orig
        super().tearDown()

    def hashed_bytes(self) -> int:
        return type(self).total_hashed

    def reset_counter(self) -> None:
        type(self).total_hashed = 0

    def test_reverify_does_not_rehash_whole_file(self) -> None:
        self.append_many("t", 10000)
        data_size = os.path.getsize(self.path)
        self.assertGreater(data_size, 100_000)
        self.reset_counter()
        result = self.chain.verify("t")
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 10000)
        # Only the small cache tag is hashed, never the data file.
        self.assertLess(self.hashed_bytes(), data_size // 50)

    def test_append_only_hashes_the_new_record(self) -> None:
        self.append_many("t", 10000)
        data_size = os.path.getsize(self.path)
        self.reset_counter()
        self.chain.append("t", {"i": 10000})
        # One new record plus the small cache tag; nowhere near the file.
        self.assertLess(self.hashed_bytes(), data_size // 50)

    def test_disk_corruption_after_warm_verify_is_detected(self) -> None:
        self.append_many("t", 200)
        self.chain.rotate()
        self.append_many("t", 5, start=200)
        self.assertTrue(self.chain.verify("t")["ok"])
        self.reset_counter()

        first = self.segment_files()[0]
        data = self.raw_bytes(first).replace(b'{"i":150}', b'{"i":157}', 1)
        self.write_raw(data, first)

        result = self.chain.verify("t")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"], 150)
        # Detection actually paid for hashing the sealed segment once, far
        # beyond the small cache-tag baseline.
        self.assertGreater(self.hashed_bytes(), 10_000)

    def test_cache_file_tampering_is_corruption_not_a_pass(self) -> None:
        self.append_many("t", 5)
        self.chain.rotate()
        self.chain.append("t", {"i": 5})
        self.assertTrue(self.chain.verify("t")["ok"])

        cache_path = os.path.join(self.path, ".verify-cache")
        with open(cache_path, "rb") as fh:
            raw = bytearray(fh.read())
        raw[40] ^= 0x01
        with open(cache_path, "wb") as fh:
            fh.write(bytes(raw))
        with self.assertRaises(ValueError):
            self.chain.verify("t")

    def test_cache_with_forged_tag_is_rejected(self) -> None:
        self.append_many("t", 3)
        cache_path = "." + os.path.basename(self.path) + ".verify-cache"
        full = os.path.join(os.path.dirname(self.path), cache_path)
        self.assertTrue(self.chain.verify("t")["ok"])
        with open(full, encoding="utf-8") as fh:
            cache = json.load(fh)
        # Tamper with the protected segment payload but keep a tag present.
        first_name = next(iter(cache["segments"]))
        cache["segments"][first_name]["records"] = 999
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(cache))
        with self.assertRaises(ValueError):
            self.chain.verify("t")

    def test_missing_cache_is_rebuilt(self) -> None:
        self.append_many("t", 4)
        self.chain.verify("t")
        cache_path = "." + os.path.basename(self.path) + ".verify-cache"
        os.remove(os.path.join(os.path.dirname(self.path), cache_path))
        self.assertTrue(self.chain.verify("t")["ok"])

    def test_shrink_of_active_segment_is_detected(self) -> None:
        self.append_many("t", 10)
        self.chain.verify("t")
        raw = self.raw_bytes()
        lines = raw.split(b"\n")[:-1]
        self.write_raw(b"\n".join(lines[:-2]) + b"\n")
        result = self.chain.verify("t")
        self.assertFalse(result["ok"])
        self.assertEqual(result["count"], 8)

    def test_recomputed_rewrite_of_active_unit_is_anchored(self) -> None:
        # A same-shape rewrite with fully recomputed digests on the active
        # unit must not pass: the surviving cache anchors the chain head.
        import json as _json

        from audit_chain import record as recmod

        self.append_many("a", 6)
        for n in range(2):
            self.chain.append("b", {"n": n})
        self.assertTrue(self.chain.verify("a")["ok"])

        records = [
            _json.loads(line) for line in self.raw_bytes().decode().split("\n")[:-1]
        ]
        # Drop a's first record and recompute a's chain; keep b byte-identical.
        out = bytearray()
        prev = ""
        for record in records:
            if record["tenant"] == "a" and record["payload"] == {"i": 0}:
                continue
            if record["tenant"] == "a":
                record["prev"] = prev
                record["digest"] = recmod.digest(prev, record["payload"])
                prev = record["digest"]
            out += (
                _json.dumps(
                    record, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                )
                + "\n"
            ).encode()
        self.write_raw(bytes(out))

        result_a = self.chain.verify("a")
        result_b = self.chain.verify("b")
        self.assertFalse(result_a["ok"])
        # b's records are byte-identical and its anchored head is unchanged.
        self.assertTrue(result_b["ok"], result_b)
        self.assertEqual(result_b["count"], 2)
