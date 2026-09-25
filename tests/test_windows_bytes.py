"""Cross-platform byte fidelity: record bytes must be identical on Windows.

``os.open()`` defaults to text mode on Windows, where every descriptor
silently rewrites ``\\n`` into ``\\r\\n`` (and re-translates bytes that
already carry CRLF on an archive/merge copy). The on-disk format is defined
byte for byte around one ``\\n`` terminator per record, so a translated line
shifts every later byte offset, changes the window sizes/hashes and
desynchronizes the preserved window material. A range proof spanning a
migrated-out segment and the hot segment then verified clean on POSIX but
falsely reported corruption on Windows. Every data descriptor is opened
binary, so these checks hold identically on both platforms.
"""

from __future__ import annotations

import copy
import os

from audit_chain import verify_proof
from tests._helpers import AuditTestCase


class WindowsByteFidelityTest(AuditTestCase):
    def _all_segment_bytes(self, *directories: str) -> list[tuple[str, bytes]]:
        blobs = []
        for directory in directories:
            if not os.path.isdir(directory):
                continue
            for name in os.listdir(directory):
                if name.endswith(".jsonl"):
                    with open(os.path.join(directory, name), "rb") as handle:
                        blobs.append((name, handle.read()))
        return blobs

    def test_append_writes_single_lf_terminators(self) -> None:
        # Varied payload lengths so a translated terminator would be visible
        # at several distinct offsets.
        for index in range(8):
            self.chain.append("t", {"i": index, "pad": "p" * index})
        data = self.raw_bytes()
        self.assertNotIn(b"\r", data)
        self.assertEqual(data.count(b"\n"), 8)
        self.assertTrue(data.endswith(b"}\n"))

    def test_every_tier_and_merged_segment_keeps_lf_bytes(self) -> None:
        archive_dir = os.path.join(self._tmp, "cold")
        for i in range(4):
            self.chain.append("t", {"i": i})
            self.chain.append("u", {"i": i})
        self.chain.rotate()
        for i in range(4, 8):
            self.chain.append("t", {"i": i})
            self.chain.append("u", {"i": i})
        self.chain.rotate()
        for i in range(8, 10):
            self.chain.append("t", {"i": i})
        # Fold the two sealed units (their preserved windows are copied),
        # seal again, then migrate into the cold tier.
        self.assertEqual(self.chain.compact(1)["segments"], 1)
        for i in range(10, 12):
            self.chain.append("t", {"i": i})
        self.chain.rotate()
        self.chain.archive(archive_dir)
        for i in range(12, 14):
            self.chain.append("t", {"i": i})

        for name, blob in self._all_segment_bytes(self.path, archive_dir):
            self.assertNotIn(b"\r", blob, f"CRLF translation in {name}")
            self.assertTrue(
                blob == b"" or blob.endswith(b"\n"), f"{name} tail terminator"
            )

    def test_cross_layer_proof_conclusion_is_platform_independent(self) -> None:
        archive_dir = os.path.join(self._tmp, "cold")
        # Two sealed units, then a longer active one.
        for i in range(2):
            self.chain.append("t", {"i": i})
        self.chain.rotate()
        for i in range(2, 4):
            self.chain.append("t", {"i": i})
        self.chain.rotate()
        for i in range(4, 12):
            self.chain.append("t", {"i": i})
        # Merge the early sealed units: the merged segment keeps both source
        # byte windows, which the CRLF bug corrupted on the archive copy.
        self.assertEqual(self.chain.compact(2)["segments"], 2)
        self.chain.rotate()
        self.chain.archive(archive_dir)
        for i in range(12, 14):
            self.chain.append("t", {"i": i})

        # The interval straddles the migrated-out segment and the hot one.
        proof = self.chain.export_range("t", 2, 14)
        verdict = verify_proof(proof, tenant="t", start=2, end=14)
        self.assertTrue(verdict["ok"], verdict)
        self.assertEqual(verdict["first_bad"], -1)
        self.assertEqual(verdict["count"], 12)

        # A rewritten record inside the interval is still reported at its
        # real global index on both platforms -- never a false pass.
        tampered = copy.deepcopy(proof)
        for window in tampered["windows"]:
            for slot in window["records"]:
                if slot["index"] == 11:
                    slot["record"]["payload"] = {"i": 9999}
        bad = verify_proof(tampered)
        self.assertFalse(bad["ok"])
        self.assertEqual(bad["first_bad"], 11)
