"""On-disk shard directories: a persisted, resumable, incremental export.

A shard directory holds one file per shard -- ``shard-00000000.json``,
``shard-00000001.json``, ... -- where each file's bytes are exactly the
canonical JSON of the corresponding in-memory shard proof, plus a
self-authenticating ``manifest.json``: one compact JSON line terminated
by a single newline, recording in shard order every shard's file name,
index interval and the sha256 of its file bytes, sealed by an
authentication tag over the whole manifest.

The directory describes one growing prefix ``[start, end)`` of one
tenant, tiled into consecutive shards of at most ``window`` records.
The tiling is a plain contiguous chain of entries -- each entry begins
exactly where the previous one ended, every one but the last spans a
full window and the last carries the remainder -- so when the log keeps
appending and another export call advances ``end``, the new shards
continue end-to-start right after the existing final shard. The
existing final shard is byte-stable (it keeps covering exactly the
records it was written with); only the newly missing shards are
produced, and the manifest is re-committed as each one lands. Shards
the manifest already vouches for are checked at the manifest level
(name, interval, recorded digest) without re-reading or re-hashing
their bytes.

Every file is committed with a temp-file write + fsync + atomic rename
and the manifest is re-committed as each shard lands, so a process
killed in any commit window leaves the directory at either the old or
the new committed state -- never a half-written shard.
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
    """The index interval shard ``index`` of a full tiling must cover."""
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


def reap_orphan_shards(directory: str, entries: list[dict]) -> None:
    """Remove shard files the committed manifest does not vouch for.

    A process killed between a shard-file rename and the manifest
    commit that names it leaves the bytes staged but unreferenced; they
    are inert (a shard is only reachable through the manifest) and are
    reaped here so a later resume or extend never carries half-built
    state. A name the manifest lists is never removed.
    """
    referenced = {entry["name"] for entry in entries}
    for name in os.listdir(directory):
        if name in referenced:
            continue
        if name.startswith(SHARD_PREFIX) and name.endswith(SHARD_SUFFIX):
            with contextlib.suppress(OSError):
                os.remove(os.path.join(directory, name))


def expected_manifest(
    tenant: str, start: int, end: int, window: int, entries: list[dict]
) -> dict:
    """Assemble the manifest body describing a prefix tiled by ``entries``."""
    return {
        "version": MANIFEST_VERSION,
        "tenant": tenant,
        "start": start,
        "end": end,
        "window": window,
        "shards": [dict(entry) for entry in entries],
    }


def manifest_tiled_end(manifest: dict) -> int:
    """The prefix end the committed shard entries actually tile to."""
    entries = manifest["shards"]
    return manifest["start"] if not entries else entries[-1]["end"]


def check_entries(
    start: int, window: int, entries: Any, *, declared_end: int
) -> bool:
    """Validate the committed entries as one contiguous window tiling.

    The entries must begin at ``start``, each begin exactly where the
    previous one ended, and span between one and ``window`` records. A
    grown directory keeps the remainder shard of every earlier append
    cycle (a later cycle starts its own window grid right at the prior
    tiling end), so a short entry may appear in the middle as well as
    at the end: contiguity plus the window cap is the whole shape.
    File names are the fixed ``shard-NNNNNNNN.json`` sequence, every
    digest is 64 hex chars, and the tiled prefix may lag (a checkpoint)
    but never overshoot the declared interval end.
    """
    if not isinstance(entries, list):
        return False
    cursor = start
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            return False
        lo, hi = entry.get("start"), entry.get("end")
        if not (_nonneg_int(lo) and _nonneg_int(hi)):
            return False
        if lo != cursor or hi <= lo or hi - lo > window:
            return False
        if entry.get("name") != shard_name(index):
            return False
        sha = entry.get("sha256")
        if not (
            isinstance(sha, str)
            and len(sha) == 64
            and all(char in _HEX64 for char in sha)
        ):
            return False
        cursor = hi
    return cursor <= declared_end


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
    if not isinstance(shards, list) or not shards:
        return False
    if not check_entries(start, window, shards, declared_end=end):
        return False
    # The committed entries tile a prefix that may lag the declared
    # interval (a checkpoint of an interrupted export) but can never
    # overshoot it. A grown directory keeps its earlier remainder shard,
    # so the entry count need not equal the fresh-tiling formula: the
    # contiguous-chain shape above is the whole definition.
    return isinstance(manifest.get("tag"), str)


def _nonneg_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0
