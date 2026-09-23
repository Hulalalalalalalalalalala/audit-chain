"""Baseline semantics: append/verify/entries/head, formats and error types."""

from __future__ import annotations

import json

from tests._helpers import AuditTestCase


class BasicChainTest(AuditTestCase):
    def test_no_records_but_present_log(self) -> None:
        # An empty (existing) log verifies clean for any tenant.
        open(self.path, "wb").close()
        self.assertEqual(self.chain.entries("t"), [])
        self.assertIsNone(self.chain.head("t"))
        self.assertEqual(
            self.chain.verify("nobody"),
            {"count": 0, "first_bad": -1, "ok": True},
        )

    def test_append_returns_stored_entry_and_links(self) -> None:
        first = self.chain.append("t", {"a": 1})
        second = self.chain.append("t", {"a": 2})
        self.assertEqual(set(first), {"digest", "payload", "prev", "tenant"})
        self.assertEqual(first["prev"], "")
        self.assertEqual(second["prev"], first["digest"])
        self.assertEqual(second["digest"], self.chain.head("t"))

    def test_on_disk_format_is_compact_sorted_jsonl(self) -> None:
        self.chain.append("t", {"z": 1, "a": "值"})
        raw = self.raw_bytes()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        record = json.loads(raw)
        self.assertEqual(
            raw.decode("utf-8").rstrip("\n"),
            json.dumps(
                record, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ),
        )
        # Raw non-ASCII is preserved (no \uXXXX escaping).
        self.assertIn("值", raw.decode("utf-8"))

    def test_indices_are_continuous_zero_based(self) -> None:
        self.append_many("t", 25)
        result = self.chain.verify("t")
        self.assertEqual(result, {"count": 25, "first_bad": -1, "ok": True})
        self.assertEqual(
            [entry["payload"]["i"] for entry in self.chain.entries("t")],
            list(range(25)),
        )

    def test_tenants_are_independent_chains(self) -> None:
        self.chain.append("a", {"n": 1})
        self.chain.append("b", {"n": 1})
        self.chain.append("a", {"n": 2})
        self.chain.append("b", {"n": 2})
        self.chain.append("a", {"n": 3})
        for tenant, count in (("a", 3), ("b", 2)):
            result = self.chain.verify(tenant)
            self.assertTrue(result["ok"])
            self.assertEqual(result["count"], count)
        self.assertEqual(
            [entry["prev"] for entry in self.chain.entries("b")],
            ["", self.chain.entries("b")[0]["digest"]],
        )

    def test_payload_must_be_dict(self) -> None:
        for bad in ([1], "x", 1, None, [{}]):
            with self.assertRaises(TypeError):
                self.chain.append("t", bad)

    def test_non_serializable_payload_is_type_error(self) -> None:
        with self.assertRaises(TypeError):
            self.chain.append("t", {"x": {1, 2}})

    def test_verify_missing_file_raises_file_not_found(self) -> None:
        with self.assertRaises(FileNotFoundError):
            self.chain.verify("t")
        # entries/head keep the missing-means-empty behavior.
        self.assertEqual(self.chain.entries("t"), [])
        self.assertIsNone(self.chain.head("t"))

    def test_bad_lines_raise_value_error(self) -> None:
        self.append_many("t", 2)
        good = self.raw_bytes()
        cases = [
            b"{not json}\n",
            b"[1,2]\n",
            b'{"digest":"x","payload":{},"prev":"","tenant":"t","extra":1}\n',
            b'{"digest":1,"payload":{},"prev":"","tenant":"t"}\n',
            b'{"digest":"x","payload":[],"prev":"","tenant":"t"}\n',
            b"\n",
            b"\xff\xfe\n",
        ]
        for bad in cases:
            self.write_raw(good + bad)
            with self.assertRaises(ValueError):
                self.chain.verify("t")
            with self.assertRaises(ValueError):
                self.chain.entries("t")
            self.write_raw(good)
        # Intact again after restoring the good prefix.
        self.assertTrue(self.chain.verify("t")["ok"])

    def test_broken_link_raises_value_error_from_append(self) -> None:
        self.append_many("t", 3)
        self.replace_in_file(b'{"i":1}', b'{"i":9}')
        result = self.chain.verify("t")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"], 1)
        with self.assertRaises(ValueError):
            self.chain.append("t", {"i": 3})
