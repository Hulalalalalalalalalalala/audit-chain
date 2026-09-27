"""On-disk shard directories: a persisted, resumable window-sharded export.

A shard directory holds one file per shard -- ``shard-00000000.json``,
``shard-00000001.json``, ... -- where each file's bytes are exactly the
canonical JSON of the corresponding in-memory shard proof, plus a
self-authenticating ``manifest.json``: one compact JSON line terminated
by a single newline, recording in shard order every shard's file name,
index interval and the sha256 of its file bytes, sealed by an
authentication tag over the whole manifest.

Every file is committed with a temp-file write + fsync + atomic rename
and the manifest is re-committed as each shard lands, so a process
killed in any commit window leaves the directory at either the old or
the new committed state -- never a half-written shard. A later export
call on the same directory resumes from the committed manifest: shards
the manifest vouches for are authenticated in place and never rewritten,
only the missing ones are produced.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
from typing import Any

from . import record as rec
from . import storage as st

MANIFEST_NAME = "manifest.json"
SHARD_PREFIX = "shard-"
SHARD_SUFFIX = ".json"
MANIFEST_VERSION = 1
_CHUNK = 1 << 20
_HEX64 = frozenset("0123456789abcdef")


def shard_name(index: int) -> str:
    return f"{SHARD_PREFIX}{index:08d}{SHARD_SUFFIX}"


def shard_count(start: int, end: int, window: int) -> int:
    """Shards needed to tile ``[start, end)`` with pieces of ``window``."""
    return -(-(end - start) // window)


def shard_slot(start: int, end: int, window: int, index: int) -> tuple[int, int]:
    """The index interval shard ``index`` of the tiling must cover."""
    lo = start + index * window
    return lo, min(lo + window, end)


def shard_bytes(shard: dict) -> bytes:
    """The canonical on-disk bytes of one shard: compact JSON, nothing else."""
    return rec.canonical_json(shard).encode("utf-8")


def file_digest(path: str) -> str:
    """Streaming sha256 of a file; memory stays bounded for any file size."""
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(_CHUNK)
            if not chunk:
                return h.hexdigest()
            h.update(chunk)


def write_shard(directory: str, name: str, raw: bytes) -> None:
    """Commit one shard file (temp file + fsync + atomic rename)."""
    st.atomic_write_bytes(directory, name, raw)


def save_manifest(directory: str, manifest: dict) -> None:
    """Sign and commit the manifest as one compact JSON line + newline."""
    st.atomic_write_text(directory, MANIFEST_NAME, manifest_text(manifest))


def manifest_text(manifest: dict) -> str:
    return rec.canonical_json(sign_manifest(manifest)) + "\n"


def sign_manifest(manifest: dict) -> dict:
    """A manifest copy carrying its authentication tag."""
    signed = _manifest_body(manifest)
    signed["tag"] = hashlib.sha256(
        rec.canonical_json(signed).encode("utf-8")
    ).hexdigest()
    return signed


def load_manifest(directory: str) -> dict:
    """Read and authenticate the shard directory's manifest.

    ``FileNotFoundError`` when the manifest is absent; ``ValueError``
    when it cannot be parsed, is structurally invalid, or its
    authentication tag does not match its content.
    """
    with open(os.path.join(directory, MANIFEST_NAME), "rb") as handle:
        raw = handle.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("malformed shard manifest") from exc
    # The on-disk form is one compact JSON line plus a trailing newline.
    if text.endswith("\n"):
        text = text[:-1]
    try:
        manifest = json.loads(text)
    except ValueError as exc:
        raise ValueError("malformed shard manifest") from exc
    if not _valid_manifest(manifest):
        raise ValueError("malformed shard manifest")
    expected = hashlib.sha256(
        rec.canonical_json(_manifest_body(manifest)).encode("utf-8")
    ).hexdigest()
    if not st.constant_time_equal(manifest["tag"], expected):
        raise ValueError("tampered shard manifest")
    return manifest


def reap_temp_files(directory: str) -> None:
    """Drop staging temp files left behind by a killed commit."""
    for name in os.listdir(directory):
        if name.startswith(".") and name.endswith(".tmp"):
            with contextlib.suppress(OSError):
                os.remove(os.path.join(directory, name))


def open_shard(directory: Any, index: Any) -> dict:
    """Read one shard back out of a shard directory, offline.

    The shard is located through the self-authenticating manifest and
    its bytes are checked against the manifest's recorded digest before
    it is returned, so a shard rewritten behind the manifest's back is
    reported rather than handed out. Neither the log nor any other
    shard is opened. The returned shard is an ordinary offline proof,
    verifiable with :func:`audit_chain.proof.verify_proof`.

    A missing directory, manifest or shard file raises
    ``FileNotFoundError``; an unparseable manifest or shard, a shard
    that does not match the manifest, or an out-of-range index raises
    ``ValueError``; a non-integer index raises ``TypeError``.
    """
    if not isinstance(index, int) or isinstance(index, bool):
        raise TypeError("shard index must be an integer")
    try:
        directory = os.fspath(directory)
    except TypeError:
        raise TypeError("directory must be a path-like object") from None
    if isinstance(directory, bytes):
        directory = os.fsdecode(directory)
    if index < 0:
        raise ValueError("shard index is out of range")
    if not os.path.isdir(directory):
        raise FileNotFoundError(directory)
    manifest = load_manifest(directory)
    shards = manifest["shards"]
    if index >= len(shards):
        raise ValueError("shard index is out of range")
    entry = shards[index]
    path = os.path.join(directory, entry["name"])
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, "rb") as handle:
        raw = handle.read()
    if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
        raise ValueError("shard file does not match the manifest")
    try:
        shard = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("malformed shard file") from exc
    if not isinstance(shard, dict):
        raise ValueError("malformed shard file")
    return shard


def _manifest_body(manifest: dict) -> dict:
    return {
        "version": manifest["version"],
        "tenant": manifest["tenant"],
        "start": manifest["start"],
        "end": manifest["end"],
        "window": manifest["window"],
        "shards": manifest["shards"],
    }


def _valid_manifest(manifest: Any) -> bool:
    if not isinstance(manifest, dict):
        return False
    if manifest.get("version") != MANIFEST_VERSION:
        return False
    if not isinstance(manifest.get("tenant"), str):
        return False
    start, end, window = (
        manifest.get("start"),
        manifest.get("end"),
        manifest.get("window"),
    )
    if not (_nonneg_int(start) and _nonneg_int(end)):
        return False
    if not _nonneg_int(window) or window == 0:
        return False
    if not start < end:
        return False
    shards = manifest.get("shards")
    if not isinstance(shards, list):
        return False
    # The entries are a prefix of the interval's tiling: a shorter list
    # is a committed checkpoint of an interrupted export, a longer one
    # can never have been written by an exporter of this interval.
    if len(shards) > shard_count(start, end, window):
        return False
    for index, entry in enumerate(shards):
        if not isinstance(entry, dict):
            return False
        lo, hi = shard_slot(start, end, window, index)
        if entry.get("name") != shard_name(index):
            return False
        if entry.get("start") != lo or entry.get("end") != hi:
            return False
        sha = entry.get("sha256")
        if (
            not isinstance(sha, str)
            or len(sha) != 64
            or any(char not in _HEX64 for char in sha)
        ):
            return False
    return isinstance(manifest.get("tag"), str)


def _nonneg_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0
