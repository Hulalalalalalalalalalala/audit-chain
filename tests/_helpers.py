"""Shared helpers for the audit-chain test suite."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


class AuditTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp(prefix="audit-chain-test-")
        self.path = os.path.join(self._tmp, "log")
        self.chain = __import__("audit_chain").Chain(self.path)

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self._tmp, ignore_errors=True)

    # -- low level helpers -------------------------------------------------

    def append_many(self, tenant: str, count: int, start: int = 0) -> None:
        for index in range(start, start + count):
            self.chain.append(tenant, {"i": index})

    def raw_bytes(self, name: str = "") -> bytes:
        target = os.path.join(self.path, name) if name else self.path
        with open(target, "rb") as handle:
            return handle.read()

    def write_raw(self, data: bytes, name: str = "") -> None:
        target = os.path.join(self.path, name) if name else self.path
        with open(target, "wb") as handle:
            handle.write(data)

    def segment_files(self) -> list[str]:
        return sorted(
            name
            for name in os.listdir(self.path)
            if name.startswith("seg-") and name.endswith(".jsonl")
        )

    def good_prefix(self, data: bytes | None = None) -> list[dict]:
        """Decode every complete newline-terminated line of raw bytes."""
        if data is None:
            data = self.raw_bytes()
        text = data.decode("utf-8")
        if not text:
            return []
        return [json.loads(line) for line in text.split("\n")[:-1]]

    def replace_in_file(self, old: bytes, new: bytes, name: str = "") -> None:
        data = self.raw_bytes(name)
        self.assertIn(old, data)
        self.assertEqual(len(old), len(new))
        self.write_raw(data.replace(old, new, 1), name)
