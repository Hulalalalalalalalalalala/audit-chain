"""Per-tenant hash-chained audit log.

Each entry stores the digest of its predecessor, so a reader can walk a
tenant's history offline and pinpoint the first tampered index. Tenants are
independent: an entry only links to the previous entry of the same tenant.

The log is stored as compact JSON lines, one record per line. Concurrent
appends to the same file are serialised with a file-level lock, so every
record still links strictly to its predecessor. A crashed append leaves a
torn trailing line, which is reported as a bad line (never silently
repaired); ``recover`` truncates such a tail explicitly.

The active log can be sealed into numbered segment files (``rotate``) and
old segments merged (``compact``) while preserving per-segment verification
material and the global insertion order of records. ``verify`` uses an
incremental cache so re-running it on a long chain does not re-derive every
digest; a tampered cache or damaged record is reported as corruption, never
as a pass.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Optional

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platform
    fcntl = None

__all__ = ["Chain"]

_RECORD_KEYS = {"digest", "payload", "prev", "tenant"}
_ENCODING = "utf-8"

# Layout next to the active log file: ``<path>.lock`` serialises writers,
# ``<path>.segments/`` holds sealed segments and their manifest, and
# ``<path>.cache`` is the incremental verification cache.
_LOCK_SUFFIX = ".lock"
_CACHE_SUFFIX = ".cache"
_SEGMENTS_SUFFIX = ".segments"
_MANIFEST_NAME = "manifest.json"


def _canonical_payload(payload: Any) -> str:
    """Compact JSON text used in the digest: sorted keys, raw non-ASCII."""
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _digest(prev: str, payload: Any) -> str:
    material = prev + _canonical_payload(payload)
    return hashlib.sha256(material.encode(_ENCODING)).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_line(line: str) -> dict:
    """Parse one on-disk line into a validated record or raise ValueError."""
    try:
        record = json.loads(line)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError("malformed audit record") from exc
    if not isinstance(record, dict) or set(record) != _RECORD_KEYS:
        raise ValueError("malformed audit record")
    if not isinstance(record["digest"], str):
        raise ValueError("malformed audit record: digest must be a string")
    if not isinstance(record["prev"], str):
        raise ValueError("malformed audit record: prev must be a string")
    if not isinstance(record["tenant"], str):
        raise ValueError("malformed audit record: tenant must be a string")
    if not isinstance(record["payload"], dict):
        raise ValueError("malformed audit record: payload must be an object")
    return record


def _parse_records(raw: bytes) -> list[dict]:
    """Decode and structurally validate every record in a log blob.

    A truncated trailing line (crash mid-write), blank line or unparsable
    line is a bad line and raises ``ValueError``.
    """
    try:
        text = raw.decode(_ENCODING)
    except UnicodeDecodeError as exc:
        raise ValueError("malformed audit record") from exc

    if text == "":
        return []

    # Every complete record ends with a newline; anything after the last
    # newline is a half-written line left by a crashed append.
    if not text.endswith("\n"):
        raise ValueError("truncated audit record")

    records: list[dict] = []
    # The trailing newline leaves one final empty segment, which is the
    # only empty segment a healthy log contains.
    lines = text.split("\n")[:-1]
    for line in lines:
        records.append(_parse_line(line))
    return records


class _FileLock:
    """File-level lock serialising concurrent access to one log file.

    The lock is acquired with a bounded retry loop: contenders are
    serialised (each waits its turn), but a lock that never becomes
    available surfaces as ``OSError`` instead of hanging forever.
    """

    _TIMEOUT_SECONDS = 5.0
    _RETRY_INTERVAL = 0.02

    def __init__(self, path: str, exclusive: bool):
        self._path = path
        self._exclusive = exclusive
        self._fd: Optional[int] = None

    def __enter__(self) -> "_FileLock":
        if fcntl is None:  # pragma: no cover - non-POSIX platform
            return self
        self._fd = os.open(self._path, os.O_CREAT | os.O_RDWR, 0o644)
        flag = fcntl.LOCK_EX if self._exclusive else fcntl.LOCK_SH
        flag |= fcntl.LOCK_NB
        deadline = time.monotonic() + self._TIMEOUT_SECONDS
        try:
            while True:
                try:
                    fcntl.flock(self._fd, flag)
                    return self
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise OSError("timed out acquiring audit log lock")
                    time.sleep(self._RETRY_INTERVAL)
        except BaseException:
            os.close(self._fd)
            self._fd = None
            raise

    def __exit__(self, *exc: object) -> None:
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
            self._fd = None


def _valid_hex_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def _validate_segment_meta(meta: Any) -> dict:
    """Validate one manifest segment entry or raise ValueError."""
    if not isinstance(meta, dict):
        raise ValueError("malformed segment manifest")
    if not set(meta) <= {"id", "file", "records", "sha256", "tenants", "sources"}:
        raise ValueError("malformed segment manifest")
    if not isinstance(meta.get("id"), int) or isinstance(meta["id"], bool):
        raise ValueError("malformed segment manifest")
    name = meta.get("file")
    if not isinstance(name, str) or os.path.basename(name) != name or not name:
        raise ValueError("malformed segment manifest")
    records = meta.get("records")
    if not isinstance(records, int) or isinstance(records, bool) or records < 0:
        raise ValueError("malformed segment manifest")
    if not _valid_hex_digest(meta.get("sha256")):
        raise ValueError("malformed segment manifest")
    tenants = meta.get("tenants")
    if not isinstance(tenants, dict):
        raise ValueError("malformed segment manifest")
    for tenant, state in tenants.items():
        if not isinstance(tenant, str) or not isinstance(state, dict):
            raise ValueError("malformed segment manifest")
        if set(state) != {"count", "head"}:
            raise ValueError("malformed segment manifest")
        count = state["count"]
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError("malformed segment manifest")
        if not _valid_hex_digest(state["head"]):
            raise ValueError("malformed segment manifest")
    sources = meta.get("sources", [])
    if not isinstance(sources, list):
        raise ValueError("malformed segment manifest")
    for source in sources:
        if not isinstance(source, dict) or set(source) != {"id", "sha256", "records"}:
            raise ValueError("malformed segment manifest")
        if not isinstance(source["id"], int) or isinstance(source["id"], bool):
            raise ValueError("malformed segment manifest")
        if not _valid_hex_digest(source["sha256"]):
            raise ValueError("malformed segment manifest")
        count = source["records"]
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError("malformed segment manifest")
    return meta


class Chain:
    """Append-only, per-tenant hash-chained audit log stored as JSON lines.

    ``max_segment_bytes`` optionally rotates the active log into a sealed
    segment once it grows past the given size.
    """

    def __init__(self, path: str, *, max_segment_bytes: Optional[int] = None):
        self.path = path
        self.max_segment_bytes = max_segment_bytes

    # -- paths -----------------------------------------------------------

    def _lock_path(self) -> str:
        return self.path + _LOCK_SUFFIX

    def _cache_path(self) -> str:
        return self.path + _CACHE_SUFFIX

    def _segments_dir(self) -> str:
        return self.path + _SEGMENTS_SUFFIX

    def _manifest_path(self) -> str:
        return os.path.join(self._segments_dir(), _MANIFEST_NAME)

    # -- low-level reading ------------------------------------------------

    def _read(self, *, missing_empty: bool) -> list[dict]:
        """Read and structurally validate every record in the active log.

        A missing file yields an empty log when ``missing_empty`` is true
        (otherwise ``FileNotFoundError`` propagates).
        """
        try:
            with open(self.path, "rb") as handle:
                raw = handle.read()
        except FileNotFoundError:
            if missing_empty:
                return []
            raise
        return _parse_records(raw)

    def _load_manifest(self) -> list[dict]:
        """Return the live segment metas in order; [] when there are none."""
        try:
            with open(self._manifest_path(), "rb") as handle:
                raw = handle.read()
        except FileNotFoundError:
            return []
        try:
            manifest = json.loads(raw.decode(_ENCODING))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("malformed segment manifest") from exc
        if not isinstance(manifest, dict) or manifest.get("version") != 1:
            raise ValueError("malformed segment manifest")
        segments = manifest.get("segments")
        if not isinstance(segments, list):
            raise ValueError("malformed segment manifest")
        return [_validate_segment_meta(meta) for meta in segments]

    def _read_segment_bytes(self, meta: dict) -> bytes:
        try:
            with open(os.path.join(self._segments_dir(), meta["file"]), "rb") as handle:
                return handle.read()
        except FileNotFoundError as exc:
            raise ValueError("missing segment file") from exc

    def _snapshot(self, *, missing_empty: bool) -> tuple[list[tuple[dict, list[dict]]], list[dict]]:
        """Return ``(segments, active)``: every record in global order.

        ``segments`` is a list of ``(meta, records)`` in manifest order.
        A missing active file is empty when segments exist or when
        ``missing_empty`` is set; otherwise ``FileNotFoundError``
        propagates, matching the single-file behaviour.
        """
        segments = [
            (meta, _parse_records(self._read_segment_bytes(meta)))
            for meta in self._load_manifest()
        ]
        try:
            active = self._read(missing_empty=False)
        except FileNotFoundError:
            if not missing_empty and not segments:
                raise
            active = []
        return segments, active

    def _tenant_records(self, tenant: str, *, missing_empty: bool) -> list[dict]:
        segments, active = self._snapshot(missing_empty=missing_empty)
        return [
            record
            for _, records in segments
            for record in records
            if record["tenant"] == tenant
        ] + [record for record in active if record["tenant"] == tenant]

    # -- append ------------------------------------------------------------

    def append(self, tenant: str, payload: Any) -> dict:
        """Append one record for ``tenant`` and return the stored entry.

        Concurrent appends are serialised by a file-level lock, so each
        record links strictly to its predecessor. Raises ``TypeError`` for
        a non-object payload and ``ValueError`` if the existing log is
        corrupt; existing records are left untouched.
        """
        if not isinstance(payload, dict):
            raise TypeError("payload must be a dict")

        with _FileLock(self._lock_path(), exclusive=True):
            segments, active = self._snapshot(missing_empty=True)

            # Refuse to extend a damaged log: every line must be
            # structurally sound and every tenant's chain must re-derive
            # cleanly.
            prev_by_tenant: dict[str, str] = {}
            for _, records in segments:
                for record in records:
                    self._check_link(record, prev_by_tenant)
            for record in active:
                self._check_link(record, prev_by_tenant)

            prev = prev_by_tenant.get(tenant, "")
            # Non-serialisable payloads surface as TypeError from json.dumps.
            record = {
                "digest": _digest(prev, payload),
                "payload": payload,
                "prev": prev,
                "tenant": tenant,
            }
            line = _canonical_payload(record)

            with open(self.path, "a", encoding=_ENCODING, newline="") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())

            if (
                self.max_segment_bytes is not None
                and os.path.getsize(self.path) >= self.max_segment_bytes
            ):
                self._rotate_locked()

            return record

    @staticmethod
    def _check_link(record: dict, prev_by_tenant: dict[str, str]) -> None:
        prev_digest = prev_by_tenant.get(record["tenant"], "")
        recomputed = _digest(record["prev"], record["payload"])
        if record["prev"] != prev_digest or record["digest"] != recomputed:
            raise ValueError("corrupt audit chain")
        prev_by_tenant[record["tenant"]] = record["digest"]

    # -- reads -------------------------------------------------------------

    def entries(self, tenant: str) -> list[dict]:
        """Return all of the tenant's records in insertion order."""
        with _FileLock(self._lock_path(), exclusive=False):
            return self._tenant_records(tenant, missing_empty=True)

    def head(self, tenant: str) -> Optional[str]:
        """Return the tenant's newest digest, or None for an empty chain."""
        with _FileLock(self._lock_path(), exclusive=False):
            records = self._tenant_records(tenant, missing_empty=True)
        if not records:
            return None
        return records[-1]["digest"]

    # -- recovery ------------------------------------------------------------

    def recover(self) -> dict:
        """Truncate the active log at the first bad line.

        A crash can leave a torn trailing line; this removes that tail so
        the intact prefix verifies exactly as it did before the damage.
        Returns ``{"kept": n, "removed": m}``. A missing log is a no-op.
        """
        with _FileLock(self._lock_path(), exclusive=True):
            try:
                with open(self.path, "rb") as handle:
                    raw = handle.read()
            except FileNotFoundError:
                self._drop_cache()
                return {"kept": 0, "removed": 0}

            kept = 0
            cut: Optional[int] = None
            offset = 0
            parts = raw.split(b"\n")
            for index, part in enumerate(parts):
                if index == len(parts) - 1:
                    # A healthy log ends with exactly one newline, leaving a
                    # final empty part; anything else is a torn tail.
                    if part != b"":
                        cut = offset
                    break
                try:
                    _parse_line(part.decode(_ENCODING))
                except (UnicodeDecodeError, ValueError):
                    cut = offset
                    break
                kept += 1
                offset += len(part) + 1

            if cut is None:
                self._drop_cache()
                return {"kept": kept, "removed": 0}

            tail = raw[cut:]
            removed = tail.count(b"\n")
            if not raw.endswith(b"\n"):
                removed += 1

            with open(self.path, "r+b") as handle:
                handle.truncate(cut)
                handle.flush()
                os.fsync(handle.fileno())
            self._drop_cache()
            return {"kept": kept, "removed": removed}

    # -- rotation and compaction --------------------------------------------

    def _write_manifest_locked(self, segments: list[dict]) -> None:
        os.makedirs(self._segments_dir(), exist_ok=True)
        manifest = {"version": 1, "segments": segments}
        tmp = self._manifest_path() + ".tmp"
        with open(tmp, "w", encoding=_ENCODING, newline="") as handle:
            handle.write(_canonical_payload(manifest) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self._manifest_path())

    @staticmethod
    def _tenant_material(records: list[dict]) -> dict[str, dict]:
        tenants: dict[str, dict] = {}
        for record in records:
            state = tenants.setdefault(record["tenant"], {"count": 0, "head": ""})
            state["count"] += 1
            state["head"] = record["digest"]
        return tenants

    def _rotate_locked(self) -> Optional[dict]:
        """Seal the active log into a numbered segment (lock held)."""
        try:
            with open(self.path, "rb") as handle:
                raw = handle.read()
        except FileNotFoundError:
            return None
        records = _parse_records(raw)
        if not records:
            return None

        metas = self._load_manifest()
        seg_id = max((meta["id"] for meta in metas), default=0) + 1
        name = f"{seg_id:06d}.seg"

        # Copy first, then publish via the manifest, then clear the active
        # log: a crash anywhere leaves either the old state or an orphan
        # segment file, never a published-but-duplicated record.
        os.makedirs(self._segments_dir(), exist_ok=True)
        with open(os.path.join(self._segments_dir(), name), "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())

        meta = {
            "id": seg_id,
            "file": name,
            "records": len(records),
            "sha256": _sha256_bytes(raw),
            "tenants": self._tenant_material(records),
        }
        self._write_manifest_locked(metas + [meta])
        os.remove(self.path)
        self._drop_cache()
        return meta

    def rotate(self) -> Optional[dict]:
        """Seal the active log into a segment; None when the log is empty."""
        with _FileLock(self._lock_path(), exclusive=True):
            return self._rotate_locked()

    def compact(self) -> Optional[dict]:
        """Merge all sealed segments into one, keeping per-segment material.

        The merged segment preserves the global insertion order of records
        and carries the digests of its source segments, so verification
        after compaction reports the same indices as before. Returns the
        merged segment's meta, or None when there is nothing to merge.
        """
        with _FileLock(self._lock_path(), exclusive=True):
            metas = self._load_manifest()
            if len(metas) < 2:
                return None

            blob = b""
            records: list[dict] = []
            for meta in metas:
                raw = self._read_segment_bytes(meta)
                blob += raw
                records.extend(_parse_records(raw))

            seg_id = max(meta["id"] for meta in metas) + 1
            name = f"{seg_id:06d}.seg"
            with open(os.path.join(self._segments_dir(), name), "wb") as handle:
                handle.write(blob)
                handle.flush()
                os.fsync(handle.fileno())

            merged = {
                "id": seg_id,
                "file": name,
                "records": len(records),
                "sha256": _sha256_bytes(blob),
                "tenants": self._tenant_material(records),
                "sources": [
                    {"id": meta["id"], "sha256": meta["sha256"], "records": meta["records"]}
                    for meta in metas
                ],
            }
            self._write_manifest_locked([merged])
            for meta in metas:
                os.remove(os.path.join(self._segments_dir(), meta["file"]))
            self._drop_cache()
            return merged

    # -- verification cache ---------------------------------------------------

    def _drop_cache(self) -> None:
        try:
            os.remove(self._cache_path())
        except FileNotFoundError:
            pass

    def _load_cache(self) -> tuple[Optional[dict], str]:
        """Return ``(cache, state)`` with state absent/invalid/ok.

        A cache that exists but does not parse, validates or match its own
        checksum has been tampered with and is reported as ``invalid``.
        """
        try:
            with open(self._cache_path(), "rb") as handle:
                raw = handle.read()
        except FileNotFoundError:
            return None, "absent"
        try:
            cache = json.loads(raw.decode(_ENCODING))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, "invalid"
        if not isinstance(cache, dict) or not set(cache) <= {
            "version", "segments", "active_offset", "active_sha256", "tenants", "checksum",
        }:
            return None, "invalid"
        if cache.get("version") != 1 or not _valid_hex_digest(cache.get("checksum")):
            return None, "invalid"
        body = {key: cache[key] for key in cache if key != "checksum"}
        if _sha256_bytes(_canonical_payload(body).encode(_ENCODING)) != cache["checksum"]:
            return None, "invalid"
        segments = cache.get("segments")
        offset = cache.get("active_offset")
        tenants = cache.get("tenants")
        if (
            not isinstance(segments, list)
            or any(
                not isinstance(seg, dict)
                or set(seg) != {"file", "sha256"}
                or not isinstance(seg["file"], str)
                or not _valid_hex_digest(seg["sha256"])
                for seg in segments
            )
            or not isinstance(offset, int)
            or isinstance(offset, bool)
            or offset < 0
            or not _valid_hex_digest(cache.get("active_sha256"))
            or not isinstance(tenants, dict)
            or any(
                not isinstance(tenant, str)
                or not isinstance(state, dict)
                or set(state) != {"count", "head"}
                or not isinstance(state["count"], int)
                or isinstance(state["count"], bool)
                or state["count"] < 0
                or not _valid_hex_digest(state["head"])
                for tenant, state in tenants.items()
            )
        ):
            return None, "invalid"
        return cache, "ok"

    def _write_cache_locked(
        self,
        metas: list[dict],
        active_raw: bytes,
        states: dict[str, dict],
    ) -> None:
        body = {
            "version": 1,
            "segments": [
                {"file": meta["file"], "sha256": meta["sha256"]} for meta in metas
            ],
            "active_offset": len(active_raw),
            "active_sha256": _sha256_bytes(active_raw),
            "tenants": states,
        }
        body["checksum"] = _sha256_bytes(
            _canonical_payload(body).encode(_ENCODING)
        )
        tmp = self._cache_path() + ".tmp"
        with open(tmp, "w", encoding=_ENCODING, newline="") as handle:
            handle.write(_canonical_payload(body) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self._cache_path())

    # -- verification ---------------------------------------------------------

    @staticmethod
    def _derive(records: list[dict], states: dict[str, dict], first_bad: dict[str, int]) -> None:
        """Advance per-tenant chain state over ``records`` in order."""
        for record in records:
            tenant = record["tenant"]
            state = states.setdefault(tenant, {"count": 0, "head": ""})
            bad = first_bad.setdefault(tenant, -1)
            recomputed = _digest(record["prev"], record["payload"])
            if record["prev"] != state["head"] or record["digest"] != recomputed:
                if bad == -1:
                    first_bad[tenant] = state["count"]
            state["head"] = record["digest"]
            state["count"] += 1

    def verify(self, tenant: str) -> dict:
        """Re-derive the tenant's chain.

        Returns ``{"count": n, "first_bad": i, "ok": bool}`` where
        ``first_bad`` is the zero-based index of the earliest entry whose
        digest or predecessor link fails re-derivation, or -1 when the
        whole tenant history is intact. Raises ``FileNotFoundError`` when
        the log is absent and ``ValueError`` on a bad line.

        Verification is incremental: a cache records the verified prefix,
        so re-running on a long chain does not re-derive every digest. A
        tampered cache or damaged record is reported as corruption, never
        as a pass.
        """
        with _FileLock(self._lock_path(), exclusive=False):
            return self._verify_locked(tenant)

    def _verify_locked(self, tenant: str) -> dict:
        metas = self._load_manifest()

        suspect = False
        segments: list[tuple[dict, bytes, list[dict]]] = []
        for meta in metas:
            raw = self._read_segment_bytes(meta)
            records = _parse_records(raw)
            # A sealed segment is immutable; any drift from its published
            # verification material is corruption.
            if _sha256_bytes(raw) != meta["sha256"] or len(records) != meta["records"]:
                suspect = True
            segments.append((meta, raw, records))

        try:
            with open(self.path, "rb") as handle:
                active_raw = handle.read()
        except FileNotFoundError:
            if not metas:
                raise
            active_raw = b""
        active = _parse_records(active_raw)

        cache, cache_state = self._load_cache()

        if cache is not None and not suspect:
            result = self._verify_incremental(
                tenant, metas, segments, active_raw, cache
            )
            if result is not None:
                return result
            # Cache and disk disagree: fall through to a full re-derivation
            # to locate the damage, but never report a pass.
            suspect = True

        states: dict[str, dict] = {}
        first_bad: dict[str, int] = {}
        for _, _, records in segments:
            self._derive(records, states, first_bad)
        self._derive(active, states, first_bad)

        result = self._result_for(tenant, states, first_bad)
        if suspect or cache_state == "invalid":
            # Either the records or the cache itself were tampered with;
            # report corruption even if the chain re-derives cleanly.
            result = {
                "count": result["count"],
                "first_bad": result["first_bad"] if result["first_bad"] != -1 else 0,
                "ok": False,
            }
        elif all(bad == -1 for bad in first_bad.values()):
            self._write_cache_locked(metas, active_raw, states)
        return result

    def _verify_incremental(
        self,
        tenant: str,
        metas: list[dict],
        segments: list[tuple[dict, list[dict]]],
        active_raw: bytes,
        cache: dict,
    ) -> Optional[dict]:
        """Verify using the cached prefix; None when cache and disk disagree."""
        cached_segments = cache["segments"]
        if cached_segments != [
            {"file": meta["file"], "sha256": meta["sha256"]} for meta in metas
        ]:
            return None
        for (_, raw, _), cached in zip(segments, cached_segments):
            if _sha256_bytes(raw) != cached["sha256"]:
                return None

        offset = cache["active_offset"]
        if offset > len(active_raw):
            return None
        prefix = active_raw[:offset]
        if prefix and not prefix.endswith(b"\n"):
            return None
        if _sha256_bytes(prefix) != cache["active_sha256"]:
            return None

        # The cached prefix is intact: only records appended since the
        # cache was written need their digests re-derived.
        tail = _parse_records(active_raw[offset:])
        states = {
            name: dict(state) for name, state in cache["tenants"].items()
        }
        first_bad: dict[str, int] = {name: -1 for name in states}
        self._derive(tail, states, first_bad)

        result = self._result_for(tenant, states, first_bad)
        if all(bad == -1 for bad in first_bad.values()) and (
            tail or states != cache["tenants"]
        ):
            self._write_cache_locked(metas, active_raw, states)
        return result

    @staticmethod
    def _result_for(tenant: str, states: dict[str, dict], first_bad: dict[str, int]) -> dict:
        state = states.get(tenant, {"count": 0, "head": ""})
        bad = first_bad.get(tenant, -1)
        return {"count": state["count"], "first_bad": bad, "ok": bad == -1}
