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


def _mixed_worker(path: str, worker_id: int, count: int, gate) -> None:  # pragma: no cover
    sys.path.insert(0, REPO_ROOT)
    from audit_chain import Chain

    chain = Chain(path)
    mine = f"w{worker_id}"
    gate.wait(timeout=30)
    for index in range(count):
        shared_entry = chain.append("shared", {"w": worker_id, "i": index})
        # Read-your-writes: the just-returned record is visible at once,
        # even while other writers keep appending to the same tenant.
        digests = [entry["digest"] for entry in chain.entries("shared")]
        assert shared_entry["digest"] in digests
        result = chain.verify("shared")
        assert result["ok"], result

        own_entry = chain.append(mine, {"i": index})
        # A tenant only this process writes: the head is exactly the record.
        assert chain.head(mine) == own_entry["digest"]
        assert chain.entries(mine)[-1]["digest"] == own_entry["digest"]

        # Interleave topology changes and recovery with the other writers.
        if index % 6 == 3:
            chain.rotate()
        if index % 9 == 4:
            try:
                chain.compact(2)
            except ValueError:
                pass
        if index % 11 == 5:
            chain.recover()


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

    def test_concurrent_writers_linearizable_with_maintenance(self) -> None:
        # Three processes append to one shared tenant and to private tenants
        # while interleaving rotate/compact/recover.
        ctx = multiprocessing.get_context("fork")
        gate = ctx.Event()
        workers = 3
        per_worker = 18
        processes = [
            ctx.Process(
                target=_mixed_worker, args=(self.path, n, per_worker, gate)
            )
            for n in range(workers)
        ]
        for process in processes:
            process.start()
        gate.set()
        for process in processes:
            process.join(timeout=120)
            self.assertEqual(process.exitcode, 0)

        # The shared tenant is one strict chain holding every worker's
        # records, each worker's own order preserved inside it.
        result = self.chain.verify("shared")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["count"], workers * per_worker)
        entries = self.chain.entries("shared")
        for pos, entry in enumerate(entries):
            expected_prev = entries[pos - 1]["digest"] if pos else ""
            self.assertEqual(entry["prev"], expected_prev)
        for n in range(workers):
            mine = [
                entry["payload"]["i"]
                for entry in entries
                if entry["payload"]["w"] == n
            ]
            self.assertEqual(mine, list(range(per_worker)))

        # Private tenants: continuous zero-based indices, no skips/dups.
        for n in range(workers):
            tenant = f"w{n}"
            own_result = self.chain.verify(tenant)
            self.assertTrue(own_result["ok"], own_result)
            self.assertEqual(own_result["count"], per_worker)
            own = self.chain.entries(tenant)
            self.assertEqual(
                [entry["payload"]["i"] for entry in own], list(range(per_worker))
            )

        # The physical log holds exactly one line per committed record: no
        # record was duplicated or lost across rotations and merges.
        total = workers * per_worker * 2
        if os.path.isdir(self.path):
            lines = 0
            for name in os.listdir(self.path):
                if name.startswith("seg-") and name.endswith(".jsonl"):
                    with open(os.path.join(self.path, name), "rb") as handle:
                        lines += handle.read().count(b"\n")
        else:
            lines = self.raw_bytes().count(b"\n")
        self.assertEqual(lines, total)

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
