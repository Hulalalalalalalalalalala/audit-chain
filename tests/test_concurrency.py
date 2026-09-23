"""File-lock serialization: concurrent appenders keep one strict chain."""

from __future__ import annotations

import multiprocessing
import os
import sys

from tests._helpers import AuditTestCase, REPO_ROOT


def _worker(path: str, tenant: str, count: int) -> None:  # pragma: no cover
    sys.path.insert(0, REPO_ROOT)
    from audit_chain import Chain

    chain = Chain(path)
    for index in range(count):
        chain.append(tenant, {"i": index, "pid": os.getpid()})


class ConcurrencyTest(AuditTestCase):
    def test_concurrent_appenders_one_unbroken_chain(self) -> None:
        tenant_count = 6
        per_tenant = 40
        ctx = multiprocessing.get_context("fork")
        processes = [
            ctx.Process(target=_worker, args=(self.path, f"t{n}", per_tenant))
            for n in range(tenant_count)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=60)
            self.assertEqual(process.exitcode, 0)

        # Global insertion order is a strict interleaving of whole records;
        # every tenant chain re-derives with continuous zero-based indices.
        total = 0
        for n in range(tenant_count):
            tenant = f"t{n}"
            result = self.chain.verify(tenant)
            self.assertTrue(result["ok"], (tenant, result))
            self.assertEqual(result["count"], per_tenant)
            entries = self.chain.entries(tenant)
            self.assertEqual(
                [entry["payload"]["i"] for entry in entries],
                list(range(per_tenant)),
            )
            for index, entry in enumerate(entries):
                expected_prev = entries[index - 1]["digest"] if index else ""
                self.assertEqual(entry["prev"], expected_prev)
            total += per_tenant

        raw = self.raw_bytes()
        self.assertEqual(raw.count(b"\n"), total)
        self.assertTrue(raw.endswith(b"\n"))

    def test_lock_timeout_is_system_error(self) -> None:
        import fcntl

        from audit_chain import storage as st

        layout = st.Layout(self.path, "file")
        st.ensure_lockfile(layout.lock_path)
        lock_fd = os.open(layout.lock_path, os.O_RDWR)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            fast = type(self.chain)(self.path, lock_timeout=0.02)
            with self.assertRaises(TimeoutError):
                fast.append("t", {})
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
