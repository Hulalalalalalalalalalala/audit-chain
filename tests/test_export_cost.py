"""Range export cost: work scales with the interval, not history length."""

from __future__ import annotations

import builtins
import hashlib
import os

from audit_chain import combine_proofs, verify_proof
from tests._helpers import AuditTestCase


class _ReadMeter:
    """Records total bytes read and every distinct file opened in binary."""

    def __init__(self) -> None:
        self.bytes = 0
        self.paths: set[str] = set()
        self._real_open = builtins.open

    def install(self) -> None:
        meter = self

        class CountingFile:
            def __init__(self_inner, raw) -> None:
                self_inner._f = raw

            def read(self_inner, *args):
                data = self_inner._f.read(*args)
                meter.bytes += len(data)
                return data

            def __enter__(self_inner):
                self_inner._f.__enter__()
                return self_inner

            def __exit__(self_inner, *exc):
                return self_inner._f.__exit__(*exc)

            def __getattr__(self_inner, name):
                return getattr(self_inner._f, name)

        def counting_open(path, *args, **kwargs):
            mode = args[0] if args else kwargs.get("mode", "r")
            handle = meter._real_open(path, *args, **kwargs)
            if "b" in mode:
                meter.paths.add(os.path.abspath(os.fspath(path)))
                return CountingFile(handle)
            return handle

        builtins.open = counting_open

    def remove(self) -> None:
        builtins.open = self._real_open


class _HashMeter:
    """Counts bytes fed to sha256 (same shape as test_cache.py)."""

    def __init__(self) -> None:
        self.bytes = 0
        self._real = hashlib.sha256

    def install(self) -> None:
        real = self._real
        meter = self

        def counting_sha256(data: bytes = b""):
            digest = real(data)
            meter.bytes += len(data)

            class _H:
                def update(self_inner, chunk: bytes) -> None:
                    meter.bytes += len(chunk)
                    digest.update(chunk)

                def hexdigest(self_inner) -> str:
                    return digest.hexdigest()

                def copy(self_inner):
                    return self_inner

            return _H()

        hashlib.sha256 = counting_sha256

    def remove(self) -> None:
        hashlib.sha256 = self._real


class ExportCostTest(AuditTestCase):
    HISTORY = 20_000
    ROTATE_EVERY = 5_000

    def _build(self, lo: int, hi: int) -> None:
        for i in range(lo, hi):
            self.chain.append("t", {"i": i, "pad": "x" * 24})
            if (i + 1) % self.ROTATE_EVERY == 0 and i + 1 < hi:
                self.chain.rotate()

    def _total_bytes(self) -> int:
        return sum(
            os.path.getsize(os.path.join(self.path, name))
            for name in os.listdir(self.path)
            if name.endswith(".jsonl")
        )

    def test_small_interval_does_not_hash_the_history(self) -> None:
        self._build(0, self.HISTORY)
        self.assertTrue(self.chain.verify("t")["ok"])  # warm the cache
        total = self._total_bytes()

        meter = _HashMeter()
        meter.install()
        try:
            proof = self.chain.export_range("t", 100, 200)
            hashed = meter.bytes
        finally:
            meter.remove()

        self.assertTrue(verify_proof(proof, start=100, end=200)["ok"])
        # Only the ~100 interval record digests, never a sealed window.
        self.assertLess(hashed, total // 100)

    def test_export_opens_only_covering_segments(self) -> None:
        self._build(0, self.HISTORY)
        self.assertTrue(self.chain.verify("t")["ok"])

        seg_files = {
            os.path.abspath(os.path.join(self.path, name))
            for name in self.segment_files()
        }
        # Interval [100, 200) lives wholly in the first segment.
        meter = _ReadMeter()
        meter.install()
        try:
            proof = self.chain.export_range("t", 100, 200)
        finally:
            meter.remove()

        self.assertTrue(verify_proof(proof, start=100, end=200)["ok"])
        opened_segments = meter.paths & seg_files
        self.assertEqual(len(opened_segments), 1)
        # The other (non-covering) segment files are never opened.
        self.assertLessEqual(
            meter.bytes, os.path.getsize(next(iter(opened_segments))) + 100_000
        )

    def test_cost_is_independent_of_history_length(self) -> None:
        self._build(0, self.HISTORY)
        self.assertTrue(self.chain.verify("t")["ok"])
        covering = os.path.join(self.path, self.segment_files()[0])
        covering_size = os.path.getsize(covering)
        first = _ReadMeter()
        first.install()
        try:
            self.chain.export_range("t", 100, 200)
            bytes_at_20k = first.bytes
        finally:
            first.remove()

        # Grow the history by another full set of segments; the same early
        # interval must read neither more of its covering segment nor any of
        # the newly added history.
        self._build(self.HISTORY, 2 * self.HISTORY)
        second = _ReadMeter()
        second.install()
        try:
            proof = self.chain.export_range("t", 100, 200)
            bytes_at_40k = second.bytes
        finally:
            second.remove()

        self.assertTrue(verify_proof(proof, start=100, end=200)["ok"])
        total = self._total_bytes()
        # Bounded by the single covering segment (plus small sidecars), far
        # below the whole history, and unchanged as history doubles.
        self.assertLess(bytes_at_40k, covering_size + 100_000)
        self.assertLess(bytes_at_40k, total // 8)
        self.assertLess(abs(bytes_at_40k - bytes_at_20k), 100_000)

    def test_active_tail_interval_hashes_only_interval_bytes(self) -> None:
        self._build(0, self.HISTORY)
        # Records beyond the last rotation sit in the un-sealed active unit,
        # interleaved with many co-tenant records.
        for i in range(self.HISTORY, self.HISTORY + 200):
            self.chain.append("t", {"i": i})
            for _ in range(5):
                self.chain.append("u", {"pad": "Z" * 40})
        self.assertTrue(self.chain.verify("t")["ok"])

        active = os.path.join(self.path, self.segment_files()[-1])
        active_size = os.path.getsize(active)

        meter = _HashMeter()
        meter.install()
        try:
            proof = self.chain.export_range(
                "t", self.HISTORY + 10, self.HISTORY + 110
            )
            hashed = meter.bytes
        finally:
            meter.remove()

        self.assertTrue(
            verify_proof(
                proof, start=self.HISTORY + 10, end=self.HISTORY + 110
            )["ok"]
        )
        # 100 small interval records, not the active unit nor the 1000 u rows.
        self.assertLess(hashed, active_size // 5)

    def test_combine_is_offline_and_hashes_no_history(self) -> None:
        self._build(0, self.HISTORY)
        self.assertTrue(self.chain.verify("t")["ok"])
        left = self.chain.export_range("t", 100, 150)
        right = self.chain.export_range("t", 150, 200)

        meter = _ReadMeter()
        meter.install()
        try:
            combined = combine_proofs(left, right)
            read_bytes = meter.bytes
        finally:
            meter.remove()

        # Splicing is purely in-memory: the log is never opened.
        self.assertEqual(read_bytes, 0)
        self.assertTrue(verify_proof(combined, start=100, end=200)["ok"])
