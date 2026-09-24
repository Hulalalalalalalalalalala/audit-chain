"""Tamper evidence with the real first bad index, and constant read cost.

Covers the hot-path requirement end to end on a segmented store:

* a tampered cache never yields a pass (``ValueError``);
* a tampered manifest window (size or sha256) is reported as corruption at
  the real first global per-tenant index that window contains;
* tampered segment bytes in a merged window are located at the true index;
* a repeated verification only touches incremental bytes plus small sidecar
  material -- it never rehashes a whole sealed segment.
"""

from __future__ import annotations

import hashlib
import json
import os

from tests._helpers import AuditTestCase


class TamperAttributionTest(AuditTestCase):
    def _manifest(self) -> dict:
        with open(os.path.join(self.path, "manifest.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def _write_manifest(self, manifest: dict) -> None:
        path = os.path.join(self.path, "manifest.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, sort_keys=True, separators=(",", ":"))

    def test_manifest_window_sha_tamper_locates_first_index(self) -> None:
        self.append_many("t", 20)
        self.chain.append("u", {"n": 1})
        self.chain.rotate()
        self.append_many("t", 5, start=20)

        manifest = self._manifest()
        first_segment = manifest["segments"][0]
        # Rewrite the preserved window anchor without touching segment bytes.
        first_segment["parts"][0]["sha256"] = "0" * 64
        self._write_manifest(manifest)
        # A manifest whose windows lie is corruption; the first t record in
        # that window is global index 0.
        result = self.chain.verify("t")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"], 0)

    def test_manifest_window_size_tamper_locates_first_index(self) -> None:
        self.append_many("t", 12)
        self.chain.rotate()
        self.append_many("t", 3, start=12)
        manifest = self._manifest()
        manifest["segments"][0]["parts"][0]["size"] += 1
        self._write_manifest(manifest)
        result = self.chain.verify("t")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"], 0)

    def test_tampered_cache_raises_not_passes(self) -> None:
        self.append_many("t", 6)
        self.chain.rotate()
        self.chain.append("t", {"i": 6})
        self.assertTrue(self.chain.verify("t")["ok"])
        cache_path = os.path.join(self.path, ".verify-cache")
        with open(cache_path, "rb") as fh:
            raw = bytearray(fh.read())
        raw[30] ^= 0x01
        with open(cache_path, "wb") as fh:
            fh.write(bytes(raw))
        with self.assertRaises(ValueError):
            self.chain.verify("t")

    def test_segment_byte_tamper_in_merged_window_index(self) -> None:
        self.append_many("t", 30)
        self.chain.rotate()
        self.append_many("t", 30, start=30)
        self.chain.rotate()
        self.append_many("t", 30, start=60)
        self.chain.compact(2)
        merged = sorted(self.segment_files())[-1]
        self.replace_in_file(b'{"i":40}', b'{"i":48}', merged)
        result = self.chain.verify("t")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"], 40)


class ConstantReadAmplificationTest(AuditTestCase):
    def setUp(self) -> None:
        super().setUp()
        type(self)._total = 0
        real = hashlib.sha256

        def counting(data: bytes = b""):
            type(self)._total += len(data)
            return real(data)

        self._orig = hashlib.sha256
        hashlib.sha256 = counting

    def tearDown(self) -> None:
        hashlib.sha256 = self._orig
        super().tearDown()

    def hashed(self) -> int:
        return type(self)._total

    def test_reverify_on_segmented_store_reads_only_sidecar(self) -> None:
        self.append_many("t", 5000)
        self.chain.rotate()
        self.append_many("t", 5000, start=5000)
        self.assertTrue(self.chain.verify("t")["ok"])
        # A repeated verify must not rehash any of the big sealed material.
        type(self)._total = 0
        result = self.chain.verify("t")
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 10000)
        sealed = os.path.getsize(
            os.path.join(self.path, self.segment_files()[0])
        )
        self.assertLess(self.hashed(), sealed // 50)

    def test_append_after_compaction_hashes_increment_only(self) -> None:
        self.append_many("t", 4000)
        self.chain.rotate()
        self.append_many("t", 4000, start=4000)
        self.chain.rotate()
        self.append_many("t", 2000, start=8000)
        self.chain.compact(1)
        self.assertTrue(self.chain.verify("t")["ok"])
        type(self)._total = 0
        self.chain.append("t", {"i": 10000})
        total_bytes = sum(
            os.path.getsize(os.path.join(self.path, name))
            for name in self.segment_files()
        )
        # One record plus a small sidecar tag, nowhere near the whole store.
        self.assertLess(self.hashed(), total_bytes // 50)
