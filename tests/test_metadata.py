"""Tampered cache / manifest / window metadata is corruption, exit-code 1.

Distinct from the half-line / bad-line path (which stays ValueError):
damaged metadata must make ``verify`` return ``ok=False`` with the real
first bad index, never raise and never pass.
"""

from __future__ import annotations

import hashlib
import json
import os

from tests._helpers import AuditTestCase


class MetadataTamperTest(AuditTestCase):
    def _manifest(self) -> dict:
        with open(os.path.join(self.path, "manifest.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def _write_manifest(self, manifest: dict, *, sign: bool) -> None:
        from audit_chain import record as recmod
        from audit_chain import storage as st

        body = {
            "version": manifest["version"],
            "active": manifest["active"],
            "segments": manifest["segments"],
        }
        if sign:
            body["tag"] = hashlib.sha256(
                recmod.canonical_json(body).encode("utf-8")
            ).hexdigest()
        else:
            body["tag"] = manifest.get("tag", "")
        with open(os.path.join(self.path, "manifest.json"), "w", encoding="utf-8") as fh:
            fh.write(recmod.canonical_json(body))

    def test_manifest_tag_mismatch_is_corruption(self) -> None:
        self.append_many("t", 6)
        self.chain.rotate()
        self.append_many("t", 2, start=6)
        manifest = self._manifest()
        # Real content edit (flip the active pointer) while keeping the old
        # tag: the tag no longer matches the body.
        manifest["active"] = manifest["segments"][0]["name"]
        self._write_manifest(manifest, sign=False)
        result = self.chain.verify("t")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"], 0)
        self.assertEqual(result["count"], 8)

    def test_manifest_garbage_is_corruption_not_value_error(self) -> None:
        self.append_many("t", 4)
        self.chain.rotate()
        with open(os.path.join(self.path, "manifest.json"), "wb") as fh:
            fh.write(b"{not json")
        result = self.chain.verify("t")
        self.assertFalse(result["ok"])
        self.assertEqual(result["count"], 4)

    def test_window_rewrite_with_recomputed_tag_is_corruption(self) -> None:
        self.append_many("t", 8)
        self.chain.rotate()
        self.append_many("t", 2, start=8)
        manifest = self._manifest()
        manifest["segments"][0]["parts"][0]["sha256"] = "f" * 64
        self._write_manifest(manifest, sign=True)
        result = self.chain.verify("t")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"], 0)

    def test_byte_tamper_with_matching_manifest_still_locates_real_index(self) -> None:
        # Attacker rewrites a sealed payload at index 5 and updates the
        # manifest window + tag to match the new bytes. The stale record
        # digest still breaks the chain at the real index.
        self.append_many("t", 8)
        self.chain.rotate()
        self.append_many("t", 2, start=8)
        first = self.segment_files()[0]
        data = self.raw_bytes(first).replace(b'{"i":5}', b'{"i":9}', 1)
        self.write_raw(data, first)

        manifest = self._manifest()
        window = manifest["segments"][0]["parts"][0]
        window["sha256"] = hashlib.sha256(data).hexdigest()
        window["size"] = len(data)
        self._write_manifest(manifest, sign=True)

        result = self.chain.verify("t")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"], 5)

    def test_cache_tamper_on_file_layout_is_corruption(self) -> None:
        self.append_many("t", 4)
        self.assertTrue(self.chain.verify("t")["ok"])
        cache_path = os.path.join(
            os.path.dirname(self.path),
            "." + os.path.basename(self.path) + ".verify-cache",
        )
        with open(cache_path, "rb") as handle:
            raw = bytearray(handle.read())
        raw[30] ^= 0x01
        with open(cache_path, "wb") as handle:
            handle.write(bytes(raw))
        result = self.chain.verify("t")
        self.assertFalse(result["ok"])
        self.assertEqual(result["count"], 4)

    def test_half_line_still_raises_value_error(self) -> None:
        # The metadata/corruption split must leave the bad-line semantics
        # untouched: a half line is ValueError (exit code 2), not a verdict.
        self.append_many("t", 3)
        self.chain.rotate()
        active = self.segment_files()[-1]
        with open(os.path.join(self.path, active), "ab") as fh:
            fh.write(b'{"digest":"x"')
        with self.assertRaises(ValueError):
            self.chain.verify("t")

    def test_append_refuses_on_tampered_manifest(self) -> None:
        self.append_many("t", 3)
        self.chain.rotate()
        manifest = self._manifest()
        # Flip the active pointer but keep the old tag.
        manifest["active"] = manifest["segments"][0]["name"]
        self._write_manifest(manifest, sign=False)
        with self.assertRaises(ValueError):
            self.chain.append("t", {"i": 3})

    def test_tampered_fold_window_cannot_ride_growth_branch(self) -> None:
        # fold-to-one leaves preserved prefix windows on the ACTIVE segment.
        # Editing one of those anchors and then appending must still be
        # reported as corruption; the suffix-only growth path compares the
        # preserved window material and refuses to adopt the cache.
        from audit_chain import storage as st

        self.append_many("t", 6)
        self.chain.rotate()
        self.append_many("t", 3, start=6)
        self.chain.compact(1)
        self.append_many("t", 3, start=9)
        self.assertTrue(self.chain.verify("t")["ok"])

        layout = st.Layout(self.path, "dir")
        manifest = st.load_manifest(layout)
        manifest["segments"][0]["parts"][0]["sha256"] = "9" * 64
        st.save_manifest(layout, manifest)

        for _ in range(3):
            result = self.chain.verify("t")
            self.assertFalse(result["ok"])
        with self.assertRaises(ValueError):
            self.chain.append("t", {"i": 12})
