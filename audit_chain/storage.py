"""File-level storage primitives: layout, locking, manifest and cache.

Two on-disk layouts are supported:

* segment store -- ``path`` is a directory holding ordered segment files
  (``seg-00000001.jsonl`` ...), an atomic ``manifest.json`` and a tamper
  evident verify cache;
* legacy single file -- ``path`` is a plain JSON-lines file, exactly as the
  pre-extension log wrote it. Its lock and verify cache live next to it as
  dotfiles; ``rotate()`` migrates the file itself into a segment store.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import time
from typing import Any, Iterator, Optional

from . import record as rec

_ENCODING = "utf-8"
LOCK_NAME = ".lock"
MANIFEST_NAME = "manifest.json"
CACHE_NAME = ".verify-cache"
SEG_PREFIX = "seg-"
SEG_SUFFIX = ".jsonl"
FIRST_SEQ = 1
_CHUNK = 1 << 20
_LOCK_POLL_SECONDS = 0.01


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
    tmp_name = f".{name}.tmp"
    tmp_path = os.path.join(directory, tmp_name)
    with open(tmp_path, "w", encoding=_ENCODING, newline="") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, os.path.join(directory, name))
    fsync_dir(directory)


def fsync_dir(directory: str) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd = os.open(directory, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def verify_windows(path: str, parts: list[dict]) -> bool:
    """Verify retained byte windows (parts) cover the whole file.

    The file size must equal the windows' total and each window's sha256
    must match. Used for sealed (never-growing) segments.
    """
    try:
        actual_size = os.path.getsize(path)
    except OSError:
        raise
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
        if kind == "dir":
            self.data_dir = root
            self.lock_path = os.path.join(root, LOCK_NAME)
            self.manifest_path = os.path.join(root, MANIFEST_NAME)
            self.cache_dir = root
            self.cache_name = CACHE_NAME
        else:
            directory = os.path.dirname(root) or "."
            self.data_dir = directory
            self.lock_path = os.path.join(directory, "." + os.path.basename(root) + ".lock")
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


def ensure_lockfile(lock_path: str) -> None:
    # O_CREAT without O_EXCL: harmless if another process created it first.
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    os.close(fd)


@contextlib.contextmanager
def file_lock(lock_path: str, *, timeout: Optional[float], shared: bool) -> Iterator[None]:
    """Serialize access to one log behind a process-shared flock.

    Readers take a shared lock and the writer an exclusive one. A timeout
    that elapses raises ``TimeoutError`` (an ``OSError`` subclass); callers
    treat it like any other system error.
    """
    ensure_lockfile(lock_path)
    fd = os.open(lock_path, os.O_RDWR)
    acquired = False
    try:
        mode = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, mode | fcntl.LOCK_NB)
                acquired = True
                break
            except BlockingIOError:
                if deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError(f"audit log lock busy: {lock_path}")
                time.sleep(_LOCK_POLL_SECONDS)
        yield
    finally:
        if acquired:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


def default_manifest(first: str) -> dict:
    return {
        "version": 1,
        "active": first,
        "segments": [{"name": first, "sealed": False, "parts": []}],
    }


def load_manifest(layout: Layout) -> Optional[dict]:
    try:
        with open(layout.manifest_path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return None
    try:
        manifest = json.loads(raw.decode(_ENCODING))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("malformed audit manifest") from exc
    if not _valid_manifest(manifest):
        raise ValueError("malformed audit manifest")
    return manifest


def _valid_manifest(manifest: Any) -> bool:
    if not isinstance(manifest, dict):
        return False
    if manifest.get("version") != 1 or not isinstance(manifest.get("active"), str):
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
    return True


def _valid_part(part: Any) -> bool:
    return (
        isinstance(part, dict)
        and isinstance(part.get("name"), str)
        and isinstance(part.get("size"), int)
        and isinstance(part.get("sha256"), str)
    )


def save_manifest(layout: Layout, manifest: dict) -> None:
    atomic_write_text(layout.data_dir, MANIFEST_NAME, rec.canonical_json(manifest))


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
    ValueError is raised rather than silently rebuilding, because reporting
    a clean pass off a forged cache must be impossible.
    """
    try:
        with open(layout.cache_path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return None
    try:
        cache = json.loads(raw.decode(_ENCODING))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("tampered audit cache") from exc
    if not isinstance(cache, dict) or cache.get("version") != 1:
        raise ValueError("tampered audit cache")
    tag = cache.get("tag")
    segments = cache.get("segments")
    if not isinstance(tag, str) or not isinstance(segments, dict):
        raise ValueError("tampered audit cache")
    expected = hashlib.sha256(cache_tag_payload(1, segments)).hexdigest()
    if not constant_time_equal(tag, expected):
        raise ValueError("tampered audit cache")
    if not _valid_cache_segments(segments):
        raise ValueError("tampered audit cache")
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
