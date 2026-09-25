"""File-level storage primitives: layout, locking, manifest and cache.

Two on-disk layouts are supported:

* segment store -- ``path`` is a directory holding ordered segment files
  (``seg-00000001.jsonl`` ...), an atomic ``manifest.json`` and a tamper
  evident verify cache;
* legacy single file -- ``path`` is a plain JSON-lines file, exactly as the
  pre-extension log wrote it. Its verify cache lives next to it as a
  dotfile; ``rotate()`` migrates the file itself into a segment store.

A segment store is optionally two-tiered: the manifest records an archive
directory (the cold tier) and flags the sealed segments that were migrated
there, so every reader resolves a segment's bytes to exactly one of the
two locations.

The lock file is a sibling dotfile (``.<name>.lock``) for *both* layouts, so
migrating a file into a segment store never changes the lock path and a
migration in progress stays mutually exclusive with readers. Locking uses
the native system capability of each platform (``flock`` on POSIX,
``LockFileEx`` on Windows); importing this module never depends on one
platform's primitives.
"""

from __future__ import annotations

import contextlib
import hashlib
import itertools
import json
import os
import sys
import time
from typing import Any, Iterator, Optional

from . import record as rec

_ENCODING = "utf-8"
LOCK_SUFFIX = ".lock"
MANIFEST_NAME = "manifest.json"
CACHE_NAME = ".verify-cache"
SEG_PREFIX = "seg-"
SEG_SUFFIX = ".jsonl"
FIRST_SEQ = 1
_CHUNK = 1 << 20
_LOCK_POLL_SECONDS = 0.01
_tmp_counter = itertools.count()


def _tmp_name_for(name: str) -> str:
    # Unique per call so concurrent processes/threads never collide on the
    # staging temp file of one atomic replace.
    return f".{name}.{os.getpid()}.{next(_tmp_counter)}.tmp"

# When set, the process hard-kills itself at the named crash point. Used by
# the crash-injection matrix (real SIGKILL, never an in-process exception).
_CRASH_ENV = "AUDIT_CHAIN_CRASH"


def crash_point(name: str) -> None:
    """Kill this process at ``name`` when the crash-injection hook matches.

    The hook is consumed on match so any forked descendant cannot loop on
    it. The kill is asynchronous and ungraceful: no ``finally`` handlers or
    interpreter cleanup run, exactly like ``kill -9``.
    """
    if os.environ.get(_CRASH_ENV) != name:
        return
    os.environ.pop(_CRASH_ENV, None)
    _hard_exit()


def _hard_exit() -> None:
    import signal

    if sys.platform == "win32":  # pragma: win32 cover
        # There is no SIGKILL on Windows; TerminateProcess semantics are the
        # closest hard kill. os.kill with SIGTERM calls TerminateProcess.
        os.kill(os.getpid(), signal.SIGTERM)
    else:
        os.kill(os.getpid(), signal.SIGKILL)
    # Defense in depth in case the signal is caught/held.
    os._exit(137)


def seg_name(seq: int) -> str:
    return f"{SEG_PREFIX}{seq:08d}{SEG_SUFFIX}"


def seg_seq(name: str) -> Optional[int]:
    if not (name.startswith(SEG_PREFIX) and name.endswith(SEG_SUFFIX)):
        return None
    middle = name[len(SEG_PREFIX) : -len(SEG_SUFFIX)]
    if len(middle) != 8 or not middle.isdigit():
        return None
    return int(middle)


def atomic_write_text(directory: str, name: str, text: str) -> None:
    """Durably replace ``directory/name`` with ``text`` (fsync + rename)."""
    atomic_write_bytes(directory, name, text.encode(_ENCODING))


def atomic_write_bytes(directory: str, name: str, raw: bytes) -> None:
    """Durably replace ``directory/name`` with ``raw`` (fsync + rename)."""
    tmp_path = os.path.join(directory, _tmp_name_for(name))
    try:
        with open(tmp_path, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        crash_point(f"atomic:{name}:before_replace")
        os.replace(tmp_path, os.path.join(directory, name))
        crash_point(f"atomic:{name}:after_replace")
        fsync_dir(directory)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp_path)
        raise


def fsync_dir(directory: str) -> None:
    """Best-effort directory sync; never fails the caller.

    Some environments (notably Windows, where a directory cannot be opened
    as a file handle at all) provide no way to sync a directory. Append and
    recovery must still complete there, so an ``OSError`` from opening or
    syncing the directory is tolerated: the atomic-rename commit protocol
    already keeps every crash window on one complete topology.
    """
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        fd = os.open(directory, flags)
    except OSError:
        return
    try:
        with contextlib.suppress(OSError):
            os.fsync(fd)
    finally:
        os.close(fd)


def verify_windows(path: str, parts: list[dict]) -> bool:
    """Verify retained byte windows (parts) cover the whole file.

    The file size must equal the windows' total and each window's sha256
    must match. Used for sealed (never-growing) segments.
    """
    actual_size = os.path.getsize(path)
    return actual_size == sum(part["size"] for part in parts) and verify_prefix_windows(
        path, parts
    )


def verify_prefix_windows(path: str, parts: list[dict]) -> bool:
    """Verify the leading byte windows of ``path``; trailing bytes allowed.

    A merged segment keeps the size and sha256 of every source segment as
    verification material; the merged bytes are the exact concatenation of
    those windows, so one streaming read re-checks every source segment. An
    active (still growing) segment uses the same check against its preserved
    prefix windows.
    """
    if not parts:
        return True
    with open(path, "rb") as handle:
        for part in parts:
            h = hashlib.sha256()
            remaining = part["size"]
            while remaining:
                chunk = handle.read(min(_CHUNK, remaining))
                if not chunk:
                    return False
                h.update(chunk)
                remaining -= len(chunk)
            if h.hexdigest() != part["sha256"]:
                return False
    return True


class Layout:
    """Resolved view of where the log data, lock and cache live."""

    def __init__(self, root: str, kind: str):
        self.root = root
        self.kind = kind  # "dir" or "file"
        # The lock is a sibling dotfile in both layouts, so its identity is
        # stable across the file -> segment-store migration.
        normalized = os.path.normpath(root)
        parent = os.path.dirname(normalized) or "."
        self.lock_path = os.path.join(
            parent, "." + os.path.basename(normalized) + LOCK_SUFFIX
        )
        if kind == "dir":
            self.data_dir = root
            self.manifest_path = os.path.join(root, MANIFEST_NAME)
            self.cache_dir = root
            self.cache_name = CACHE_NAME
        else:
            directory = os.path.dirname(root) or "."
            self.data_dir = directory
            self.manifest_path = ""
            self.cache_dir = directory
            self.cache_name = "." + os.path.basename(root) + ".verify-cache"

    @property
    def cache_path(self) -> str:
        return os.path.join(self.cache_dir, self.cache_name)

    def segment_path(self, name: str) -> str:
        return os.path.join(self.data_dir, name)


def resolve_existing(path: str) -> Optional[Layout]:
    """Resolve an existing log path, or return None when nothing is there."""
    if os.path.isdir(path):
        return Layout(path, "dir")
    if os.path.isfile(path):
        return Layout(path, "file")
    return None


# ---------------------------------------------------------------------------
# Cross-platform process-shared file locking
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def file_lock(lock_path: str, *, timeout: Optional[float], shared: bool) -> Iterator[None]:
    """Serialize access to one log behind a process-shared OS file lock.

    Readers take a shared lock and the writer an exclusive one. The backing
    primitive is chosen per platform at call time (``fcntl.flock`` on POSIX,
    ``LockFileEx`` on Windows), so this module imports cleanly everywhere.

    A timeout that elapses raises ``TimeoutError`` (an ``OSError`` subclass);
    permission failures and path-class system errors propagate as their
    native ``OSError`` subclasses -- callers signal all of them silently via
    exit code two.
    """
    if sys.platform == "win32":  # pragma: win32 cover
        backend = _windows_lock
    else:
        backend = _posix_lock

    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    acquired = False
    try:
        backend(fd, shared=shared, timeout=timeout)
        acquired = True
        yield
    finally:
        if acquired:
            with contextlib.suppress(OSError):
                _unlock(fd)
        os.close(fd)


def _posix_lock(fd: int, *, shared: bool, timeout: Optional[float]) -> None:
    import fcntl

    mode = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
    if timeout is None:
        fcntl.flock(fd, mode)
        return
    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(fd, mode | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"audit log lock busy: fd {fd}")
            time.sleep(_LOCK_POLL_SECONDS)


def _unlock(fd: int) -> None:
    if sys.platform == "win32":  # pragma: win32 cover
        _windows_unlock(fd)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)


def _windows_lock(fd: int, *, shared: bool, timeout: Optional[float]) -> None:  # pragma: win32 cover
    import ctypes
    from ctypes import wintypes

    import msvcrt

    LOCKFILE_EXCLUSIVE_LOCK = 0x00000002
    LOCKFILE_FAIL_IMMEDIATELY = 0x00000001
    ERROR_LOCK_VIOLATION = 33

    class _Overlapped(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_void_p),
            ("InternalHigh", ctypes.c_void_p),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    lock_file_ex = kernel32.LockFileEx
    lock_file_ex.restype = wintypes.BOOL
    lock_file_ex.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_Overlapped),
    ]

    handle = msvcrt.get_osfhandle(fd)
    flags = LOCKFILE_FAIL_IMMEDIATELY if timeout is not None else 0
    if not shared:
        flags |= LOCKFILE_EXCLUSIVE_LOCK
    deadline = None if timeout is None else time.monotonic() + timeout
    while True:
        overlapped = _Overlapped()
        if lock_file_ex(handle, flags, 0, 0xFFFFFFFF, 0xFFFFFFFF, ctypes.byref(overlapped)):
            return
        error = ctypes.get_last_error()
        if error != ERROR_LOCK_VIOLATION:
            raise OSError(error, f"LockFileEx failed (error {error})")
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError(f"audit log lock busy: fd {fd}")
        time.sleep(_LOCK_POLL_SECONDS)


def _windows_unlock(fd: int) -> None:  # pragma: win32 cover
    import ctypes
    from ctypes import wintypes

    import msvcrt

    class _Overlapped(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_void_p),
            ("InternalHigh", ctypes.c_void_p),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    unlock_file_ex = kernel32.UnlockFileEx
    unlock_file_ex.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_Overlapped),
    ]
    handle = msvcrt.get_osfhandle(fd)
    overlapped = _Overlapped()
    unlock_file_ex(handle, 0, 0xFFFFFFFF, 0xFFFFFFFF, ctypes.byref(overlapped))


# Backwards-compatible helper used by the test suite and external callers.
def ensure_lockfile(lock_path: str) -> None:
    # O_CREAT without O_EXCL: harmless if another process created it first.
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    os.close(fd)


# ---------------------------------------------------------------------------
# Manifest (self-authenticating, atomically replaced)
# ---------------------------------------------------------------------------


class AuditMetadataError(ValueError):
    """A tampered manifest or verify cache.

    Distinct from a malformed record line: damaged *metadata* is reported as
    chain corruption (verify returns ``ok=False``), whereas a half-written
    record keeps its existing bad-line semantics (ValueError, exit code 2).
    """


def default_manifest(first: str) -> dict:
    return {
        "version": 1,
        "active": first,
        "segments": [{"name": first, "sealed": False, "parts": []}],
    }


def _manifest_payload_text(manifest: dict) -> str:
    body = {
        "version": manifest["version"],
        "active": manifest["active"],
        "segments": manifest["segments"],
    }
    # The archive location is part of the signed body only when present, so
    # manifests written before two-tier storage existed keep their tags.
    if manifest.get("archive") is not None:
        body["archive"] = manifest["archive"]
    return rec.canonical_json(body)


def sign_manifest(manifest: dict) -> dict:
    """Return a manifest copy carrying its authentication tag."""
    signed = {
        "version": manifest["version"],
        "active": manifest["active"],
        "segments": manifest["segments"],
    }
    if manifest.get("archive") is not None:
        signed["archive"] = manifest["archive"]
    signed["tag"] = hashlib.sha256(
        _manifest_payload_text(signed).encode(_ENCODING)
    ).hexdigest()
    return signed


def load_manifest(layout: Layout) -> Optional[dict]:
    try:
        with open(layout.manifest_path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return None
    try:
        manifest = json.loads(raw.decode(_ENCODING))
    except (UnicodeDecodeError, ValueError) as exc:
        raise AuditMetadataError("malformed audit manifest") from exc
    if not isinstance(manifest, dict) or not _valid_manifest(manifest):
        raise AuditMetadataError("malformed audit manifest")
    tag = manifest.get("tag")
    if tag is not None:
        if not isinstance(tag, str):
            raise AuditMetadataError("tampered audit manifest")
        expected = hashlib.sha256(
            _manifest_payload_text(manifest).encode(_ENCODING)
        ).hexdigest()
        if not constant_time_equal(tag, expected):
            raise AuditMetadataError("tampered audit manifest")
    # A manifest without a tag was written by the pre-tag build: structurally
    # valid and accepted read-only; the next write re-signs it.
    return manifest


def _valid_manifest(manifest: Any) -> bool:
    if not isinstance(manifest, dict):
        return False
    if manifest.get("version") != 1 or not isinstance(manifest.get("active"), str):
        return False
    archive = manifest.get("archive")
    if archive is not None and not isinstance(archive, str):
        return False
    segments = manifest.get("segments")
    if not isinstance(segments, list) or not segments:
        return False
    for index, segment in enumerate(segments):
        if not isinstance(segment, dict):
            return False
        if not isinstance(segment.get("name"), str) or not isinstance(
            segment.get("sealed"), bool
        ):
            return False
        archived = segment.get("archived", False)
        if not isinstance(archived, bool):
            return False
        if archived:
            # An archived segment lives in the recorded archive location; it
            # is always sealed and never the active segment.
            if not archive or not segment["sealed"]:
                return False
            if segment["name"] == manifest["active"]:
                return False
        parts = segment.get("parts")
        if not isinstance(parts, list):
            return False
        for part in parts:
            if not _valid_part(part):
                return False
        if index == len(segments) - 1:
            if segment["name"] != manifest["active"] or segment["sealed"]:
                return False
        elif not segment["sealed"] or not parts:
            return False
    tag = manifest.get("tag")
    if tag is not None and not isinstance(tag, str):
        return False
    return True


def _valid_part(part: Any) -> bool:
    return (
        isinstance(part, dict)
        and isinstance(part.get("name"), str)
        and isinstance(part.get("size"), int)
        and isinstance(part.get("sha256"), str)
    )


def save_manifest(layout: Layout, manifest: dict) -> None:
    save_manifest_at(layout.data_dir, manifest)


def save_manifest_at(directory: str, manifest: dict) -> None:
    """Write a signed manifest into an arbitrary directory (e.g. staging)."""
    signed = sign_manifest(manifest)
    atomic_write_text(directory, MANIFEST_NAME, rec.canonical_json(signed))


# ---------------------------------------------------------------------------
# Incremental verify cache
# ---------------------------------------------------------------------------


def cache_tag_payload(version: int, segments: dict) -> bytes:
    return rec.canonical_json({"version": version, "segments": segments}).encode(
        _ENCODING
    )


def load_cache(layout: Layout) -> Optional[dict]:
    """Load the verify cache or return None when absent.

    A present cache whose authentication tag fails to verify is tampering:
    ``AuditMetadataError`` is raised rather than silently rebuilding, because
    reporting a clean pass off a forged cache must be impossible.
    """
    try:
        with open(layout.cache_path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return None
    try:
        cache = json.loads(raw.decode(_ENCODING))
    except (UnicodeDecodeError, ValueError) as exc:
        raise AuditMetadataError("tampered audit cache") from exc
    if not isinstance(cache, dict) or cache.get("version") != 1:
        raise AuditMetadataError("tampered audit cache")
    tag = cache.get("tag")
    segments = cache.get("segments")
    if not isinstance(tag, str) or not isinstance(segments, dict):
        raise AuditMetadataError("tampered audit cache")
    expected = hashlib.sha256(cache_tag_payload(1, segments)).hexdigest()
    if not constant_time_equal(tag, expected):
        raise AuditMetadataError("tampered audit cache")
    if not _valid_cache_segments(segments):
        raise AuditMetadataError("tampered audit cache")
    return {"version": 1, "segments": segments, "tag": tag}


def constant_time_equal(actual: str, expected: str) -> bool:
    if len(actual) != len(expected):
        return False
    result = 0
    for a, b in zip(actual, expected):
        result |= ord(a) ^ ord(b)
    return result == 0


def _valid_cache_segments(segments: Any) -> bool:
    if not isinstance(segments, dict):
        return False
    for name, entry in segments.items():
        if not isinstance(name, str) or not isinstance(entry, dict):
            return False
        if (
            not isinstance(entry.get("records"), int)
            or entry["records"] < 0
            or not isinstance(entry.get("size"), int)
            or entry["size"] < 0
            or not isinstance(entry.get("mtime_ns"), int)
            or not isinstance(entry.get("ctime_ns"), int)
        ):
            return False
        parts = entry.get("parts")
        if not isinstance(parts, list):
            return False
        for part in parts:
            if not _valid_part(part):
                return False
        # The fold is absent only in a structurally-valid pre-fold cache,
        # which the walker rebuilds from bytes; a present but malformed fold
        # cannot be trusted and is treated like any forged field.
        fold = entry.get("fold")
        if fold is not None:
            if not isinstance(fold, str) or len(fold) != 64:
                return False
            try:
                int(fold, 16)
            except ValueError:
                return False
        tenants = entry.get("tenants")
        if not isinstance(tenants, dict):
            return False
        for tenant, state in tenants.items():
            if not isinstance(tenant, str) or not isinstance(state, list):
                return False
            if len(state) != 3:
                return False
            count, digest, bad = state
            if (
                not isinstance(count, int)
                or not isinstance(digest, str)
                or not isinstance(bad, int)
                or count < 0
                or bad < -1
            ):
                return False
    return True


def save_cache(layout: Layout, segments: dict) -> None:
    tag = hashlib.sha256(cache_tag_payload(1, segments)).hexdigest()
    payload = {"version": 1, "segments": segments, "tag": tag}
    atomic_write_text(
        layout.cache_dir, layout.cache_name, rec.canonical_json(payload)
    )


# ---------------------------------------------------------------------------
# Record scanning
# ---------------------------------------------------------------------------


def scan_segment_bytes(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def decode_records(raw: bytes) -> list[dict]:
    """Decode log bytes into validated records; bad/truncated lines raise."""
    try:
        text = raw.decode(_ENCODING)
    except UnicodeDecodeError as exc:
        raise ValueError("malformed audit record") from exc
    return [rec.parse_line(line) for line in rec.split_records(text)]
