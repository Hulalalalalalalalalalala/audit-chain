"""Snapshot consistency under concurrent append / rotate / compact.

Real OS processes hammer one store: one writer interleaves appends with
rotation and compaction (including the file -> store migration), while
several readers continuously call ``entries``/``verify``/``head`` and build a
range proof. Every single read must observe one complete prefix -- never a
cross-segment mix, a duplicate or a gap -- or the reader exits non-zero.
"""

from __future__ import annotations

import multiprocessing
import os
import sys

from tests._helpers import AuditTestCase, REPO_ROOT

_RUNNER = [sys.executable, "-m", "tests._crash_runner"]


def _writer(path: str, rounds: str) -> None:  # pragma: no cover
    sys.path.insert(0, REPO_ROOT)
    import subprocess

    subprocess.run(
        _RUNNER + [path, "stress-write", "", rounds],
        cwd=REPO_ROOT,
        check=True,
    )


def _reader(path: str, iterations: str, tenant: str) -> None:  # pragma: no cover
    sys.path.insert(0, REPO_ROOT)
    import subprocess

    proc = subprocess.run(
        _RUNNER + [path, "stress-read", "", iterations, tenant],
        cwd=REPO_ROOT,
        capture_output=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode())
        sys.exit(proc.returncode)


class SnapshotConcurrencyTest(AuditTestCase):
    def test_readers_see_only_complete_prefixes(self) -> None:
        ctx = multiprocessing.get_context("fork")
        writer = ctx.Process(target=_writer, args=(self.path, "80"))
        readers = [
            ctx.Process(target=_reader, args=(self.path, "400", tenant))
            for tenant in ("t", "u", "t")
        ]
        writer.start()
        for reader in readers:
            reader.start()
        writer.join(timeout=120)
        for reader in readers:
            reader.join(timeout=120)

        self.assertEqual(writer.exitcode, 0)
        for index, reader in enumerate(readers):
            self.assertEqual(reader.exitcode, 0, f"reader {index} saw a bad snapshot")

        # Final state: a strict, gap-free, duplication-free prefix.
        for tenant, count in (("t", 80), ("u", 80)):
            result = self.chain.verify(tenant)
            self.assertTrue(result["ok"], (tenant, result))
            self.assertEqual(result["count"], count)
            entries = self.chain.entries(tenant)
            self.assertEqual(
                [entry["payload"]["i"] for entry in entries], list(range(count))
            )

    def test_migration_concurrent_with_reader(self) -> None:
        # Pre-populate a legacy file, then migrate while a reader spins.
        from tests._crash_runner import main as runner_main  # noqa: F401

        ctx = multiprocessing.get_context("fork")
        seed = ctx.Process(
            target=lambda: _runner(self.path, "setup-file")
        )
        seed.start()
        seed.join(60)
        self.assertEqual(seed.exitcode, 0)

        reader = ctx.Process(target=_reader, args=(self.path, "300", "t"))
        migrator = ctx.Process(target=lambda: _runner(self.path, "migrate"))
        reader.start()
        migrator.start()
        migrator.join(60)
        reader.join(60)
        self.assertEqual(migrator.exitcode, 0)
        self.assertEqual(reader.exitcode, 0)
        self.assertTrue(self.chain.verify("t")["ok"])
        self.assertEqual(self.chain.verify("t")["count"], 6)


def _runner(path: str, scenario: str) -> None:  # pragma: no cover
    sys.path.insert(0, REPO_ROOT)
    import subprocess

    subprocess.run(
        _RUNNER + [path, scenario], cwd=REPO_ROOT, check=True
    )
