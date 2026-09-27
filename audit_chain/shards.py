"""On-disk shard directories for windowed interval exports.

A shard directory is the durable, resumable and randomly accessible form
of the lazy :meth:`audit_chain.Chain.export_shards` stream:

* one file per shard (``shard-00000000.json`` ...), whose bytes are the
  canonical compact JSON of exactly the proof dict the in-memory exporter
  produces for that shard's sub-interval -- verbatim, no re-serialization;
* one self-authenticating manifest (``shards-manifest.json``): a single
  compact JSON line followed by one newline, recording, per shard index,
  the shard file's name, interval and byte digest, signed with a tag over
  the canonical manifest body.

Every write -- each shard file and each manifest revision -- is a
temp-file write, fsync and atomic rename (see
:func:`audit_chain.storage.atomic_write_bytes`). A process hard-killed in
any commit window therefore leaves either the previous consistent
manifest revision or the next one: a shard file is only ever advertised
once its bytes are durable, a partially written temp is reaped on the
next call, and no shard is ever half renamed. Re-calling
:func:`export_shards_dir` on the same directory resumes: only the shards
the manifest does not yet vouch for are produced (grouped into contiguous
runs, each exported through the ordinary single-window streaming path),
so read volume, digest work and memory track one window plus the missing
increment, never the history length; complete shards are never rewritten.

:func:`open_shard` fetches one shard by index for an offline check using
the manifest's byte digest alone: it neither reads another shard nor
opens the log.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from . import record as rec
from . import storage as st

_ENCODING = "utf-8"
MANIFEST_NAME = "shards-manifest.json"
SHARD_PREFIX = "shard-"
SHARD_SUFFIX = ".json"
SHARD_VERSION = 1
_HEX64 = "0123456789abcdef"


def _is_shard_file(name: str) -> bool:
    if not (
        name.startswith(SHARD_PREFIX) and name.endswith(SHARD_SUFFIX)
    ):
        return False
    middle = name[len(SHARD_PREFIX) : -len(SHARD_SUFFIX)]
    return len(middle) == 8 and middle.isdigit()


def shard_name(index: int) -> str:
    return f"{SHARD_PREFIX}{index:08d}{SHARD_SUFFIX}"


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# Parameter validation
# ---------------------------------------------------------------------------


def _bound_int(name: str, value: Any) -> int:
    """Coerce an integer bound, mirroring the in-memory exporter.

    ``bool`` and ``float`` are numeric-but-not-integer values and, like
    out-of-range integers, raise ``ValueError`` ("not an integer");
    other non-integer types (``str``, ``None``, ...) are the wrong
    parameter type and raise ``TypeError``.
    """
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise ValueError(f"{name} must be an integer")
    raise TypeError(f"{name} must be an integer")


def _validate_params(
    tenant: Any, start: Any, end: Any, window: Any, dir_path: Any
) -> tuple[str, int, int, int, str]:
    if not isinstance(dir_path, str):
        raise TypeError("directory path must be a string")
    if not isinstance(tenant, str):
        raise TypeError("tenant must be a string")
    window_i = _bound_int("window", window)
    start_i = _bound_int("start", start)
    end_i = _bound_int("end", end)
    if window_i <= 0:
        raise ValueError("window must be a positive integer")
    if start_i < 0 or end_i < 0:
        raise ValueError("range bounds must be non-negative")
    if end_i < start_i:
        raise ValueError("range is reversed: start must be <= end")
    if start_i == end_i:
        raise ValueError("range must be a non-empty interval")
    return tenant, start_i, end_i, window_i, dir_path


# ---------------------------------------------------------------------------
# Manifest (self-authenticating, one compact line + one newline)
# ---------------------------------------------------------------------------


def _plan_entries(start: int, end: int, window: int) -> list[dict]:
    """The deterministic shard plan tiling ``[start, end)``."""
    entries: list[dict] = []
    cursor = start
    index = 0
    while cursor < end:
        shard_end = min(cursor + window, end)
        entries.append(
            {
                "index": index,
                "name": shard_name(index),
                "start": cursor,
                "end": shard_end,
                # None while the shard is pending; once the file landed
                # durably its size and byte digest replace None and the
                # next atomic manifest revision advertises it.
                "size": None,
                "sha256": None,
            }
        )
        cursor = shard_end
        index += 1
    return entries


def _manifest_body(manifest: dict) -> dict:
    return {
        "version": manifest["version"],
        "tenant": manifest["tenant"],
        "start": manifest["start"],
        "end": manifest["end"],
        "window": manifest["window"],
        "shards": [
            {
                "index": entry["index"],
                "name": entry["name"],
                "start": entry["start"],
                "end": entry["end"],
                "size": entry["size"],
                "sha256": entry["sha256"],
            }
            for entry in manifest["shards"]
        ],
    }


def _sign(manifest: dict) -> dict:
    signed = dict(manifest)
    signed["tag"] = _sha256_bytes(
        rec.canonical_json(_manifest_body(manifest)).encode(_ENCODING)
    )
    return signed


def _save_manifest(directory: str, manifest: dict) -> None:
    """Atomically replace the manifest: compact one-liner plus newline."""
    raw = (
        rec.canonical_json(_sign(manifest)).encode(_ENCODING) + b"\n"
    )
    st.atomic_write_bytes(directory, MANIFEST_NAME, raw)


def _is_hex64(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in _HEX64 for ch in value)
    )


def _valid_manifest(manifest: Any) -> bool:
    if not isinstance(manifest, dict):
        return False
    if manifest.get("version") != SHARD_VERSION:
        return False
    if not isinstance(manifest.get("tenant"), str):
        return False
    for key in ("start", "end", "window"):
        value = manifest.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return False
    entries = manifest.get("shards")
    if not isinstance(entries, list) or not entries:
        return False
    if not isinstance(manifest.get("tag"), str):
        return False
    return True


def _load_manifest(directory: str) -> dict:
    """Load and authenticate the shard-directory manifest.

    A missing manifest raises ``FileNotFoundError``; anything present
    that does not parse, carry a valid tag or describe a consistent
    tiling raises ``ValueError``.
    """
    path = os.path.join(directory, MANIFEST_NAME)
    with open(path, "rb") as handle:
        raw = handle.read()
    try:
        manifest = json.loads(raw.decode(_ENCODING))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("shards manifest is not parseable") from exc
    if not _valid_manifest(manifest):
        raise ValueError("malformed shards manifest")
    tag = manifest["tag"]
    expected = _sha256_bytes(
        rec.canonical_json(_manifest_body(manifest)).encode(_ENCODING)
    )
    if not st.constant_time_equal(tag, expected):
        raise ValueError("shards manifest fails authentication")
    if not _entries_match_plan(manifest):
        raise ValueError("shards manifest does not describe its interval")
    return manifest


def _entries_match_plan(manifest: dict) -> bool:
    planned = _plan_entries(
        manifest["start"], manifest["end"], manifest["window"]
    )
    entries = manifest["shards"]
    if len(entries) != len(planned):
        return False
    for entry, expected in zip(entries, planned):
        if not isinstance(entry, dict):
            return False
        if entry.get("index") != expected["index"]:
            return False
        if entry.get("name") != expected["name"]:
            return False
        if entry.get("start") != expected["start"]:
            return False
        if entry.get("end") != expected["end"]:
            return False
        size = entry.get("size")
        digest = entry.get("sha256")
        if (size is None) != (digest is None):
            # Size and digest are published together.
            return False
        if size is not None and (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            return False
        if digest is not None and not _is_hex64(digest):
            return False
    return True


# ---------------------------------------------------------------------------
# Export / resume
# ---------------------------------------------------------------------------


def export_shards_dir(
    chain: Any,
    tenant: Any,
    start: Any,
    end: Any,
    window: Any,
    dir_path: Any,
) -> dict:
    """Write the windowed shards of ``[start, end)`` into ``dir_path``.

    The interval is cut exactly as :meth:`Chain.export_shards` cuts it;
    each shard is one file whose bytes are the canonical compact JSON of
    that shard proof, and the signed manifest records every shard's
    name, interval and byte digest. Calling again on the same directory
    resumes the export: parameters must match the recorded ones and only
    shards the manifest does not yet vouch for are produced -- complete
    shards are verified against the manifest and never rewritten.

    Returns ``{"shards": n}`` with the number of complete shards on disk
    (the whole tiling once the call returns). A non-positive or
    non-integer ``window``, an empty or reversed interval, and
    non-integer or out-of-bounds endpoints raise ``ValueError``; an
    argument of the wrong Python type raises ``TypeError``; a target
    that is not a directory, an unparseable manifest, an interval the
    manifest does not describe, or an existing shard that disagrees with
    the manifest raise ``ValueError``.
    """
    tenant, start, end, window, dir_path = _validate_params(
        tenant, start, end, window, dir_path
    )

    if os.path.lexists(dir_path) and not os.path.isdir(dir_path):
        raise ValueError("export target is not a directory")
    os.makedirs(dir_path, exist_ok=True)
    _reap_temp_files(dir_path)

    manifest_path = os.path.join(dir_path, MANIFEST_NAME)
    if os.path.exists(manifest_path):
        manifest = _load_manifest(dir_path)
        if (
            manifest["tenant"] != tenant
            or manifest["start"] != start
            or manifest["end"] != end
            or manifest["window"] != window
        ):
            raise ValueError(
                "shards directory was exported for a different interval"
            )
        entries = manifest["shards"]
        expected_names = {entry["name"] for entry in entries}
        for name in os.listdir(dir_path):
            # A shard-shaped file the manifest does not name is a
            # half-built leftover from a *different* plan or a planted
            # file; never silently resume onto such a directory.
            if _is_shard_file(name) and name not in expected_names:
                raise ValueError(
                    f"shard file {name} is not recorded in the manifest"
                )
        # Advertised shards must still have a file of the recorded
        # length. The content itself is authenticated when a shard is
        # opened (digest check); a same-length rewrite is reported
        # there, and never touches the resume's read/digest cost.
        for entry in entries:
            if entry["sha256"] is None:
                continue
            path = os.path.join(dir_path, entry["name"])
            if os.path.exists(path) and os.path.getsize(path) != entry["size"]:
                raise ValueError(
                    f"existing shard {entry['name']} does not match the manifest"
                )
    else:
        entries = _plan_entries(start, end, window)
        manifest = {
            "version": SHARD_VERSION,
            "tenant": tenant,
            "start": start,
            "end": end,
            "window": window,
            "shards": entries,
        }
        # The first atomic commit publishes the complete plan; the
        # directory jumps from "nothing" (old) to a manifest describing
        # every pending shard, never a half-written manifest.
        _save_manifest(dir_path, manifest)

    def is_complete(entry: dict) -> bool:
        return entry["sha256"] is not None and os.path.exists(
            os.path.join(dir_path, entry["name"])
        )

    pending = [
        index
        for index, entry in enumerate(entries)
        if not is_complete(entry)
    ]

    for run_start_index, run_end_index in _runs(pending):
        run_start = entries[run_start_index]["start"]
        run_end = entries[run_end_index - 1]["end"]
        # Each contiguous pending run is one ordinary lazy export: one
        # snapshot, single-window memory, and only the units covering the
        # missing run are opened.
        stream = chain.export_shards(tenant, run_start, run_end, window)
        with stream:
            for offset, shard in enumerate(stream):
                index = run_start_index + offset
                if index >= run_end_index:
                    # The live export produced more shards than the
                    # recorded plan: never trust a layout that does not
                    # tile the recorded interval.
                    raise ValueError(
                        "exported shard does not match the manifest"
                    )
                entry = entries[index]
                if shard["start"] != entry["start"] or shard["end"] != entry["end"]:
                    # The live export no longer describes the recorded
                    # tiling (e.g. history changed out from under it).
                    raise ValueError("exported shard does not match the manifest")
                raw = rec.canonical_json(shard).encode(_ENCODING)
                # Publish bytes first; only the following atomic
                # manifest revision advertises this shard's digest. A
                # kill in between leaves an unadvertised file that the
                # next resume simply replaces.
                st.atomic_write_bytes(dir_path, entry["name"], raw)
                st.crash_point("shards:before_manifest_update")
                entry["size"] = len(raw)
                entry["sha256"] = _sha256_bytes(raw)
                _save_manifest(dir_path, manifest)
                st.crash_point("shards:after_manifest_update")

    complete = sum(1 for entry in entries if is_complete(entry))
    if complete != len(entries):
        # Defensive: the streaming export should either fill every
        # pending shard or raise. Never report a partial export as done.
        raise ValueError("shards export is incomplete")
    return {"shards": complete}


def _runs(indices: list[int]) -> list[tuple[int, int]]:
    """Group sorted indices into contiguous ``[first, one-past-last)`` runs."""
    runs: list[tuple[int, int]] = []
    if not indices:
        return runs
    run_start = previous = indices[0]
    for index in indices[1:]:
        if index == previous + 1:
            previous = index
            continue
        runs.append((run_start, previous + 1))
        run_start = previous = index
    runs.append((run_start, previous + 1))
    return runs


def _reap_temp_files(directory: str) -> None:
    """Remove temp files a killed atomic write/rename left behind."""
    changed = False
    for name in os.listdir(directory):
        if name.startswith(".") and name.endswith(".tmp"):
            try:
                os.remove(os.path.join(directory, name))
                changed = True
            except OSError:
                pass
    if changed:
        st.fsync_dir(directory)


# ---------------------------------------------------------------------------
# Random access
# ---------------------------------------------------------------------------


def open_shard(dir_path: Any, index: Any) -> dict:
    """Load one shard from a shard directory for an offline check.

    Only the named shard file and the manifest are read: no other shard
    and no log file is opened, so the proof can be checked with
    :func:`audit_chain.verify_proof` anywhere. A missing directory,
    manifest, shard file -- or a shard the manifest does not yet vouch
    for after an interrupted export -- raises ``FileNotFoundError``; a
    non-numeric index raises ``TypeError``; a bool/float or out-of-range
    index, an unparseable or unauthenticated manifest, or shard bytes
    that do not parse or do not match the manifest digest raise
    ``ValueError``.
    """
    if not isinstance(dir_path, str):
        raise TypeError("directory path must be a string")
    if isinstance(index, bool) or isinstance(index, float):
        raise ValueError("shard index must be an integer")
    if not isinstance(index, int):
        raise TypeError("shard index must be an integer")
    if index < 0:
        raise ValueError("shard index is out of range")
    if not os.path.isdir(dir_path):
        raise FileNotFoundError(dir_path)

    manifest = _load_manifest(dir_path)
    entries = manifest["shards"]
    if index >= len(entries):
        raise ValueError("shard index is out of range")
    entry = entries[index]
    if entry["sha256"] is None:
        # The manifest does not vouch for this shard yet: an export was
        # interrupted before its manifest revision committed (any bytes
        # on disk are an unadvertised leftover), so the shard is missing.
        raise FileNotFoundError(os.path.join(dir_path, entry["name"]))
    path = os.path.join(dir_path, entry["name"])
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, "rb") as handle:
        raw = handle.read()
    if _sha256_bytes(raw) != entry["sha256"]:
        raise ValueError(f"shard {entry['name']} does not match the manifest")
    try:
        shard = json.loads(raw.decode(_ENCODING))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"shard {entry['name']} is not parseable") from exc
    if not isinstance(shard, dict):
        raise ValueError(f"shard {entry['name']} is malformed")
    return shard
