"""Crash safety: half-written tail lines and the explicit recovery entry."""

from __future__ import annotations

import json
import os

from tests._helpers import AuditTestCase


class RecoveryTest(AuditTestCase):
    def _half_line(self, text: str = '{"digest":"ab') -> None:
        with open(self.path, "ab") as handle:
            handle.write(text.encode("utf-8"))

    def test_half_line_is_a_bad_line_not_a_silent_fix(self) -> None:
        self.append_many("t", 4)
        self._half_line()
        with self.assertRaises(ValueError):
            self.chain.verify("t")
        with self.assertRaises(ValueError):
            self.chain.entries("t")
        with self.assertRaises(ValueError):
            self.chain.append("t", {"i": 4})

    def test_recover_truncates_only_the_half_line(self) -> None:
        self.append_many("t", 4)
        self.chain.append("u", {"n": 1})
        before = self.chain.verify("t")
        entries_before = self.chain.entries("t")

        half = '{"digest":"deadbeef"'
        self._half_line(half)
        result = self.chain.recover()
        self.assertEqual(result, {"truncated_bytes": len(half.encode())})

        # Post-recovery indices equal the visible good prefix pre-recovery.
        after = self.chain.verify("t")
        self.assertEqual(after, before)
        self.assertEqual(self.chain.entries("t"), entries_before)
        self.assertTrue(self.chain.verify("u")["ok"])

        # The half line is physically gone.
        self.assertTrue(self.raw_bytes().endswith(b"\n"))
        with self.assertRaises(ValueError):
            json.loads("deadbeef")  # sanity: the removed tail was never valid

    def test_recover_is_idempotent(self) -> None:
        self.append_many("t", 2)
        self.assertEqual(self.chain.recover(), {"truncated_bytes": 0})
        self._half_line()
        self.chain.recover()
        self.assertEqual(self.chain.recover(), {"truncated_bytes": 0})
        self.assertTrue(self.chain.verify("t")["ok"])

    def test_recover_does_not_repair_complete_broken_records(self) -> None:
        self.append_many("t", 4)
        self.replace_in_file(b'{"i":2}', b'{"i":8}')
        # A complete-but-bad record must survive recover and still be bad.
        self.assertEqual(self.chain.recover(), {"truncated_bytes": 0})
        result = self.chain.verify("t")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"], 2)

    def test_recover_missing_file_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            self.chain.recover()

    def test_recover_in_segment_store_truncates_active(self) -> None:
        self.append_many("t", 3)
        self.chain.rotate()
        self.append_many("t", 3, start=3)
        active = self.segment_files()[-1]
        with open(os.path.join(self.path, active), "ab") as handle:
            handle.write(b'{"digest":"x"')
        with self.assertRaises(ValueError):
            self.chain.verify("t")
        removed = self.chain.recover()["truncated_bytes"]
        self.assertEqual(removed, len(b'{"digest":"x"'))
        self.assertEqual(
            self.chain.verify("t"), {"count": 6, "first_bad": -1, "ok": True}
        )
