"""File locking: platform independence and the system-error contract.

The package must import on any platform: the POSIX-only ``fcntl`` module is
imported lazily inside the POSIX backend, never at module top level, and the
Windows backend (``msvcrt``/ctypes) is selected on ``sys.platform``.
"""

from __future__ import annotations

import builtins
import importlib
import os
import sys

from tests._helpers import AuditTestCase


class LockPlatformTest(AuditTestCase):
    def test_storage_imports_without_fcntl_available(self) -> None:
        # Simulate a platform where fcntl does not exist (Windows): a fresh
        # import of storage must succeed even though fcntl is unimportable.
        real_import = builtins.__import__

        def guarded_import(name, *args, **kwargs):
            if name == "fcntl":
                raise ImportError("No module named 'fcntl'")
            return real_import(name, *args, **kwargs)

        for module_name in [
            "audit_chain.storage",
            "audit_chain.chain",
            "audit_chain",
        ]:
            sys.modules.pop(module_name, None)
        builtins.__import__ = guarded_import
        try:
            storage = importlib.import_module("audit_chain.storage")
        finally:
            builtins.__import__ = real_import
            for module_name in [
                "audit_chain.storage",
                "audit_chain.chain",
                "audit_chain",
            ]:
                sys.modules.pop(module_name, None)
            importlib.import_module("audit_chain")
        self.assertTrue(hasattr(storage, "file_lock"))
        self.assertTrue(hasattr(storage, "_windows_lock"))
        self.assertTrue(hasattr(storage, "_posix_lock"))

    def test_top_level_module_does_not_reference_fcntl(self) -> None:
        import audit_chain.storage as storage

        source_path = storage.__file__
        with open(source_path, encoding="utf-8") as handle:
            source = handle.read()
        # fcntl may only appear inside the POSIX backend function.
        self.assertIn("def _posix_lock", source)
        before_posix = source.split("def _posix_lock")[0]
        self.assertNotIn("import fcntl", before_posix)

    def test_dispatch_selects_platform_backend(self) -> None:
        import audit_chain.storage as storage

        if sys.platform == "win32" or os.name == "nt":
            self.assertTrue(storage._IS_WINDOWS)
        else:
            self.assertFalse(storage._IS_WINDOWS)

    def test_path_errors_propagate_as_os_error(self) -> None:
        import audit_chain.storage as storage

        missing_dir = os.path.join(self._tmp, "does-not-exist", "x.lock")
        with self.assertRaises(OSError):
            with storage.file_lock(missing_dir, timeout=0.01, shared=False):
                pass

    def test_permission_error_is_os_error(self) -> None:
        # Locking through an unwritable directory fails at lockfile creation;
        # whatever the platform, it surfaces as OSError (CLI maps to exit 2).
        import audit_chain.storage as storage

        locked_dir = os.path.join(self._tmp, "readonly")
        os.mkdir(locked_dir)
        os.chmod(locked_dir, 0o500)
        try:
            if os.geteuid() == 0:
                self.skipTest("root bypasses directory permissions")
            with self.assertRaises(OSError):
                with storage.file_lock(
                    os.path.join(locked_dir, "x.lock"),
                    timeout=0.01,
                    shared=False,
                ):
                    pass
        finally:
            os.chmod(locked_dir, 0o700)

    def test_contention_raises_timeout(self) -> None:
        import audit_chain.storage as storage

        path = os.path.join(self._tmp, "log")
        layout = storage.Layout(path, "file")
        with storage.file_lock(layout.lock_path, timeout=None, shared=False):
            fast = storage.Layout(path, "file")
            with self.assertRaises(TimeoutError):
                with storage.file_lock(
                    fast.lock_path, timeout=0.02, shared=False
                ):
                    pass
        # TimeoutError is an OSError subclass, as the CLI contract requires.
        self.assertTrue(issubclass(TimeoutError, OSError))

    def test_shared_readers_coexist(self) -> None:
        import audit_chain.storage as storage

        path = os.path.join(self._tmp, "log")
        layout = storage.Layout(path, "file")
        with storage.file_lock(layout.lock_path, timeout=1, shared=True):
            with storage.file_lock(layout.lock_path, timeout=1, shared=True):
                pass
