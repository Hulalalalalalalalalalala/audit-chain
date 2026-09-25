"""Read snapshot consistency while writers rotate/merge/append.

Every single read must observe one complete prefix: no mixed segments, no
duplicated run, no skipped run, and a definite verdict immediately before
and after a segment merge / manifest commit.

``entries``/``head``/``verify`` are separate locked calls, so the invariant
is asserted per call, never by comparing the results of two calls (a writer
may commit between them).
"""

from __future__ import annotations

import multiprocessing
import os
import sys
import time

from tests._helpers import AuditTestCase, REPO_ROOT


def _writer(path: str, stop_after: float, ready) -> None:  # pragma: no cover
    sys.path.insert(0, REPO_ROOT)
    from audit_chain import Chain

    chain = Chain(path)
    index = 0
    deadline = time.monotonic() + stop_after
    while time.monotonic() < deadline:
        chain.append("t", {"i": index})
        chain.append("u", {"i": index})
        index += 1
        if index == 3:
            ready.put(True)
        if index % 25 == 0:
            chain.rotate()
        if index % 60 == 0:
            try:
                chain.compact(1)
            except ValueError:
                pass


class SnapshotConsistencyTest(AuditTestCase):
    def test_reads_always_see_a_complete_prefix(self) -> None:
        ctx = multiprocessing.get_context("fork")
        ready = ctx.Queue()
        writer = ctx.Process(target=_writer, args=(self.path, 4.0, ready))
        writer.start()
        # Wait until the log exists so every read exercises the contended
        # append/rotate/compact window rather than the absent-log startup.
        self.assertTrue(ready.get(timeout=30))

        distinct_counts: set[int] = set()
        ticks = 0
        while writer.is_alive() and ticks < 20000:
            entries = self.chain.entries("t")
            # One snapshot: indices are exactly 0..n-1 -- this rules out
            # mixed segments, duplicate runs and skipped runs.
            payloads = [entry["payload"]["i"] for entry in entries]
            self.assertEqual(payloads, list(range(len(entries))))
            for pos, entry in enumerate(entries):
                self.assertEqual(
                    entry["prev"], entries[pos - 1]["digest"] if pos else ""
                )
            # head() is its own snapshot call and must, by itself, match the
            # last digest of some consistent entries snapshot; assert the
            # chain shape inside the entries snapshot instead.
            result = self.chain.verify("t")
            self.assertTrue(result["ok"], result)
            distinct_counts.add(result["count"])
            ticks += 1

        writer.join(timeout=30)
        self.assertEqual(writer.exitcode, 0)
        self.assertGreater(len(distinct_counts), 5)

        final = self.chain.verify("t")
        self.assertTrue(final["ok"])
        self.assertEqual(
            [e["payload"]["i"] for e in self.chain.entries("t")],
            list(range(final["count"])),
        )

    def test_exports_always_cover_a_complete_prefix(self) -> None:
        from audit_chain import verify_proof

        ctx = multiprocessing.get_context("fork")
        ready = ctx.Queue()
        writer = ctx.Process(target=_writer, args=(self.path, 4.0, ready))
        writer.start()
        self.assertTrue(ready.get(timeout=30))

        ticks = 0
        while writer.is_alive() and ticks < 500:
            # A writer may commit between verify and export, so the count is
            # only a lower bound; the proof itself must be one prefix.
            count = self.chain.verify("t")["count"]
            if count < 2:
                continue
            proof = self.chain.export_range("t", 0, count)
            # The export is append-only consistent: the tenant total it
            # reports is at least the count observed moments before, and
            # the interval records are exactly payloads 0..count-1 -- no
            # mixed pre/post-merge halves, no duplicated or skipped run.
            self.assertGreaterEqual(proof["count"], count)
            payloads = [
                window_record["record"]["payload"]["i"]
                for window in proof["windows"]
                for window_record in window["records"]
            ]
            self.assertEqual(payloads, list(range(count)))
            self.assertTrue(verify_proof(proof, tenant="t")["ok"])
            ticks += 1

        writer.join(timeout=30)
        self.assertEqual(writer.exitcode, 0)
        self.assertGreater(ticks, 5)
