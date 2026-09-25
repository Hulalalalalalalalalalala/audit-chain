"""Cross-platform locking: import must not depend on a single platform."""

from __future__ import annotations

import os
import subprocess
import sys
from unittest import mock

from tests._helpers import REPO_ROOT, AuditTestCase


class CrossPlatformLockTest(AuditTestCase):
    def test_importing_storage_never_loads_fcntl_at_module_level(self) -> None:
        # Spoof Windows in a fresh interpreter where importing fcntl is made
        # impossible: the storage package must still import and dispatch to
        # the Windows lock backend.
        code = r"""
import builtins, os, sys
sys.path.insert(0, %r)
real_import = builtins.__import__

def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name == 'fcntl':
        raise ImportError('simulated platform without fcntl')
    return real_import(name, globals, locals, fromlist, level)

builtins.__import__ = fake_import
sys.platform = 'win32'

import audit_chain.storage as st
assert 'fcntl' not in sys.modules

events = []
st._windows_lock = lambda fd, *, shared, timeout: events.append(('lock', shared))
st._windows_unlock = lambda fd: events.append(('unlock',))

lock = os.path.join(%r, 'spoof.lock')
with st.file_lock(lock, timeout=1.0, shared=True):
    assert events == [('lock', True)], events
assert ('unlock',) in events
print('ok')
""" % (REPO_ROOT, self._tmp)
        completed = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "ok")

    def test_posix_backend_still_serializes(self) -> None:
        from audit_chain import storage as st

        lock = os.path.join(self._tmp, "native.lock")
        with st.file_lock(lock, timeout=1.0, shared=False):
            import fcntl

            fd = os.open(lock, os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)

    def test_lock_path_is_stable_across_topologies(self) -> None:
        # File layout and the directory it migrates into share one lock path.
        from audit_chain import storage as st

        file_layout = st.Layout(self.path, "file")
        dir_layout = st.Layout(self.path, "dir")
        self.assertEqual(file_layout.lock_path, dir_layout.lock_path)


class DirectorySyncToleranceTest(AuditTestCase):
    def test_operations_complete_when_directory_cannot_be_synced(self) -> None:
        # Windows-style environment (e.g. a Windows temp directory): opening
        # a directory for synchronization fails. Directory sync is
        # best-effort, so append/verify/recover/rotate/compact/export all
        # still complete.
        from audit_chain import verify_proof

        real_open = os.open

        def refusing_open(path, flags, mode=0o777, **kwargs):
            if os.path.isdir(path):
                raise PermissionError(13, "directory sync unsupported", str(path))
            return real_open(path, flags, mode)

        self.append_many("t", 3)
        with mock.patch.object(os, "open", refusing_open):
            self.chain.append("t", {"i": 3})
            self.assertEqual(
                self.chain.verify("t"), {"count": 4, "first_bad": -1, "ok": True}
            )
            # A half-written tail line is truncated by recover as usual.
            with open(self.path, "ab") as handle:
                handle.write(b"{half")
            self.assertEqual(self.chain.recover(), {"truncated_bytes": 5})
            self.assertEqual(
                self.chain.verify("t"), {"count": 4, "first_bad": -1, "ok": True}
            )
            self.chain.rotate()
            self.chain.append("t", {"i": 4})
            self.assertEqual(self.chain.compact(1), {"segments": 1})
            proof = self.chain.export_range("t", 0, 5)

        self.assertEqual(
            self.chain.verify("t"), {"count": 5, "first_bad": -1, "ok": True}
        )
        self.assertTrue(verify_proof(proof, tenant="t", start=0, end=5)["ok"])
