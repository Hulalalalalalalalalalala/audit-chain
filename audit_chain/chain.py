"""Per-tenant hash-chained audit log.

Every entry stores the digest of its predecessor, so a tenant's history can
be walked offline and the first tampered index pinpointed. Tenants are
independent chains that share one physical log.

The original single JSON-lines file is extended without changing its
semantics:

* concurrent appenders to the same log are serialized by a process-shared
  file lock, so interlocked writes still link strictly;
* the log can be rotated into ordered segment files and compacted, with
  every source segment's verification material (byte size + sha256)
  retained through merges;
* verification of long logs is incremental: unchanged byte windows are
  authenticated by an on-disk cache (stat-guarded, content-hashed on
  change), so a repeated verification of a ten-thousand-entry log only
  hashes newly appended bytes instead of the whole file;
* ``recover`` is the explicit entry point that truncates a half-written
  tail line left by a killed process;
* every call sees a single snapshot: the on-disk topology is resolved
  inside the lock and crash leftovers are settled to exactly one of the
  old/new topologies before any byte is read;
* ``export_range`` produces an offline proof (in-range chained records plus
  the cross-segment window chain) that an independent reader can check with
  the public digest algorithm alone.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
from typing import Any, Optional

from . import proof as pf
from . import record as rec
from . import storage as st
from ._fault import crash_point

_ENCODING = "utf-8"
_FILE_UNIT = "$"
_DEFAULT_LOCK_TIMEOUT = 10.0
_DEFAULT_MAX_SEGMENTS = 2


class Chain:
    """Append-only, per-tenant hash-chained audit log."""

    def __init__(
        self,
        path: str,
        *,
        lock_timeout: Optional[float] = _DEFAULT_LOCK_TIMEOUT,
    ):
        self.path = path
        self.lock_timeout = lock_timeout

    # ------------------------------------------------------------------
    # Layout / locking / crash settlement
    # ------------------------------------------------------------------

    def _layout(self) -> st.Layout:
        existing = st.resolve_existing(self.path)
        if existing is not None:
            return existing
        # Nothing on disk yet: stay in the legacy file layout until the
        # first append (or an explicit rotate) creates anything.
        return st.Layout(self.path, "file")

    @contextlib.contextmanager
    def _locked(self, *, exclusive: bool):
        # The lock is one stable sibling file (path + ".lock") for the whole
        # lifetime of the path, so a migrating writer and any reader always
        # contend on the same lock even across the file -> directory rename.
        layout = self._layout()
        with st.file_lock(
            layout.lock_path, timeout=self.lock_timeout, shared=not exclusive
        ):
            # Re-resolve *after* waiting: the topology visible when the lock
            # was requested may already have been replaced by the time it is
            # granted. Settle every crash leftover to a single topology
            # before the caller observes anything.
            self._settle(exclusive=exclusive)
            layout = self._layout()
            if exclusive and layout.kind == "dir":
                # Reap segment files orphaned by a compaction killed after
                # its manifest commit but before its source-file removal.
                manifest = st.load_manifest(layout)
                if manifest is not None:
                    self._gc_segments(layout, manifest)
            yield layout

    def _settle(self, *, exclusive: bool) -> None:
        """Bring a crash-interrupted store to exactly one old/new topology.

        Possible leftovers, each with one deterministic resolution:

        * migration killed between the two renames -> legacy file adopted
          back from its backup, stale staging directory removed (old
          topology wins; the store was never published);
        * atomic manifest/cache/segment writes killed mid-flight -> their
          unique ``.*.tmp`` files removed (the replacement either happened
          atomically or never did);
        * staging directory left beside a finished/never-started migration
          -> removed.

        Adoption (an atomic rename guarded by an existence check) is safe
        under a shared lock; debris *deletion* is exclusive-only so one
        shared reader can never remove another reader's in-flight temp file.
        Sealed-segment bytes themselves are never repaired here; a
        half-written tail line keeps its bad-line semantics until the
        explicit ``recover()``.
        """
        self._adopt_backup()
        if not exclusive:
            return
        if os.path.isdir(self.path):
            st.remove_temp_files(self.path)
            # The store was published, so the new topology won: the legacy
            # file renamed aside and the old file-layout sidecar cache are now
            # stale leftovers to reap deterministically.
            backup = self.path + ".pre-segment"
            with contextlib.suppress(OSError):
                os.remove(backup)
            old_cache = os.path.join(
                os.path.dirname(self.path) or ".",
                "." + os.path.basename(self.path) + ".verify-cache",
            )
            with contextlib.suppress(OSError):
                os.remove(old_cache)
        parent = os.path.dirname(self.path) or "."
        st.remove_temp_files(parent)
        staging = self.path + ".segstage"
        if os.path.isdir(staging) and os.path.exists(self.path):
            # The store was published (or never moved): staging is debris.
            for name in os.listdir(staging):
                with contextlib.suppress(OSError):
                    os.unlink(os.path.join(staging, name))
            with contextlib.suppress(OSError):
                os.rmdir(staging)

    def _adopt_backup(self) -> None:
        """Restore a log left behind by a migration killed mid-rename.

        rotate() renames the legacy file aside before putting the segment
        store in its place; if the process is killed between the two renames,
        the file survives as a backup and is moved back on the next open.
        """
        backup = self.path + ".pre-segment"
        staging = self.path + ".segstage"
        if os.path.exists(self.path) or not os.path.exists(backup):
            return
        with contextlib.suppress(OSError):
            if os.path.isdir(staging):
                for name in os.listdir(staging):
                    os.unlink(os.path.join(staging, name))
                os.rmdir(staging)
        os.replace(backup, self.path)

    def _view(self, layout: st.Layout) -> list[dict]:
        """Ordered units that make up the log, oldest first.

        A unit is the legacy single file or one manifest segment. Sealed
        units carry preserved byte windows (verification material); the
        active unit and the legacy file are fingerprinted as they grow.
        """
        if layout.kind == "file":
            return [
                {
                    "name": _FILE_UNIT,
                    "path": layout.root,
                    "sealed": False,
                    "parts": [],
                }
            ]

        manifest = st.load_manifest(layout)
        if manifest is None:
            # Segment stores are created atomically (manifest + first
            # segment) by rotate(); a directory without one is a path
            # collision, never an implicit store.
            raise ValueError("missing audit manifest")

        return [
            {
                "name": segment["name"],
                "path": layout.segment_path(segment["name"]),
                "sealed": segment["sealed"],
                "parts": [dict(part) for part in segment["parts"]],
            }
            for segment in manifest["segments"]
        ]

    # ------------------------------------------------------------------
    # Raw reads (entries/head; structure only, no chain or cache)
    # ------------------------------------------------------------------

    def _all_records(self, units: list[dict], *, missing_empty: bool) -> list[dict]:
        records: list[dict] = []
        for unit in units:
            try:
                raw = st.scan_segment_bytes(unit["path"])
            except FileNotFoundError:
                if missing_empty and not unit["sealed"]:
                    continue
                raise
            records.extend(st.decode_records(raw))
        return records

    def _tenant_records(self, tenant: str, *, missing_empty: bool) -> list[dict]:
        with self._locked(exclusive=False) as layout:
            if layout.kind == "file" and not os.path.exists(layout.root):
                if missing_empty:
                    return []
                raise FileNotFoundError(layout.root)
            units = self._view(layout)
            records = self._all_records(units, missing_empty=missing_empty)
        return [record for record in records if record["tenant"] == tenant]

    # ------------------------------------------------------------------
    # Public read API (unchanged shapes)
    # ------------------------------------------------------------------

    def entries(self, tenant: str) -> list[dict]:
        """Return all of the tenant's records in insertion order."""
        return self._tenant_records(tenant, missing_empty=True)

    def head(self, tenant: str) -> Optional[str]:
        """Return the tenant's newest digest, or None for an empty chain."""
        records = self._tenant_records(tenant, missing_empty=True)
        if not records:
            return None
        return records[-1]["digest"]

    def verify(self, tenant: str) -> dict:
        """Re-derive the tenant's chain, incrementally across segments.

        Returns ``{"count": n, "first_bad": i, "ok": bool}`` with global,
        zero-based per-tenant indices. Raises ``FileNotFoundError`` when the
        log is absent, ``ValueError`` on a bad line, damaged segment bytes or
        a tampered cache -- a damaged cache can never produce a pass.
        """
        with self._locked(exclusive=False) as layout:
            self._require_present(layout)
            units = self._view(layout)
            states, _ = self._walk(units, layout)
        state = states.get(tenant)
        if state is None:
            return {"count": 0, "first_bad": -1, "ok": True}
        return {"count": state[0], "first_bad": state[2], "ok": state[2] == -1}

    def _require_present(self, layout: st.Layout) -> None:
        if layout.kind == "file":
            if not os.path.isfile(layout.root):
                raise FileNotFoundError(layout.root)
            return
        # An existing directory without a manifest is malformed; let the
        # view report it rather than masking it as a missing file.
        if not os.path.isdir(layout.root):
            raise FileNotFoundError(layout.root)

    # ------------------------------------------------------------------
    # Append
    # ------------------------------------------------------------------

    def append(self, tenant: str, payload: Any) -> dict:
        """Append one record for ``tenant`` and return the stored entry.

        Raises ``TypeError`` for a non-object payload and ``ValueError`` if
        the existing log or its cache is corrupt; existing records are left
        untouched. Concurrent appenders are serialized by a file lock.
        """
        if not isinstance(payload, dict):
            raise TypeError("payload must be a dict")

        with self._locked(exclusive=True) as layout:
            units = self._view(layout)

            # Refuse to extend a damaged log.
            states, _ = self._walk(units, layout)
            for _count, _head, bad in states.values():
                if bad != -1:
                    raise ValueError("corrupt audit chain")

            prev = states.get(tenant, (0, "", -1))[1]
            record, line = rec.build_line(tenant, payload, prev)
            target = units[-1]["path"]
            # Two visible crash windows: death between the line body and its
            # terminator leaves the documented half-line; death after the
            # flush but before fsync leaves the line in the OS cache. Either
            # way reopening sees whole-prefix-or-half-line, never a mix.
            with open(target, "a", encoding=_ENCODING, newline="") as handle:
                handle.write(line)
                handle.flush()
                # Kill window 1: the record body is in the OS page cache but
                # its terminator is not, so reopening finds the documented
                # physical half-line (a bad line until explicit recover()).
                crash_point("append:write")
                handle.write("\n")
                handle.flush()
                # Kill window 2: complete line flushed but not fsynced.
                crash_point("append:flush")
                os.fsync(handle.fileno())
                # Kill window 3: complete line durable.
                crash_point("append:fsync")

            # Warm the cache with the single record just written: suffix
            # only, never a rehash of the whole file.
            self._walk(self._view(layout), layout)
        return record

    # ------------------------------------------------------------------
    # Crash recovery
    # ------------------------------------------------------------------

    def recover(self) -> dict:
        """Truncate a half-written tail line left by a crashed append.

        Only the physical trailing partial line of the active log is
        removed; complete but chain-broken records are never silently
        repaired. Returns the number of bytes removed. The verify cache is
        discarded because the bytes legitimately shrank.
        """
        with self._locked(exclusive=True) as layout:
            self._require_present(layout)
            units = self._view(layout)
            target = units[-1]["path"]

            with open(target, "rb") as handle:
                raw = handle.read()
            if raw == b"" or raw.endswith(b"\n"):
                return {"truncated_bytes": 0}

            cut = raw.rfind(b"\n") + 1
            removed = len(raw) - cut
            with open(target, "r+b") as handle:
                handle.truncate(cut)
                handle.flush()
                os.fsync(handle.fileno())
            self._delete_cache(layout)
        return {"truncated_bytes": removed}

    # ------------------------------------------------------------------
    # Rotation and compaction
    # ------------------------------------------------------------------

    def rotate(self) -> None:
        """Cut a new active segment.

        On a legacy single-file log this first migrates the file into a
        segment store at the same path, sealing the original bytes as the
        first segment. On an already segmented log the active segment is
        sealed (its preserved windows plus one window for the bytes appended
        after them) and a fresh empty segment becomes active.
        """
        with self._locked(exclusive=True) as layout:
            if layout.kind == "file":
                self._migrate_file(layout)
            else:
                self._rotate_dir(layout)

    def _migrate_file(self, layout: st.Layout) -> None:
        path = layout.root
        raw = b""
        if os.path.exists(path):
            with open(path, "rb") as handle:
                raw = handle.read()
            # A crashed half-line must be recovered, not silently migrated.
            st.decode_records(raw)

        parent = os.path.dirname(path) or "."
        staging = path + ".segstage"
        backup = path + ".pre-segment"
        if os.path.exists(backup):
            os.remove(backup)
        os.mkdir(staging)

        try:
            if raw:
                first = st.seg_name(st.FIRST_SEQ)
                second = st.seg_name(st.FIRST_SEQ + 1)
                self._write_bytes(
                    staging, first, raw, crash="migrate:first-segment"
                )
                self._write_bytes(
                    staging, second, b"", crash="migrate:second-segment"
                )
                manifest = {
                    "version": 1,
                    "active": second,
                    "segments": [
                        {
                            "name": first,
                            "sealed": True,
                            "parts": [
                                {
                                    "name": first,
                                    "size": len(raw),
                                    "sha256": _sha256(raw),
                                }
                            ],
                        },
                        {"name": second, "sealed": False, "parts": []},
                    ],
                }
            else:
                first = st.seg_name(st.FIRST_SEQ)
                self._write_bytes(staging, first, b"", crash="migrate:first-segment")
                manifest = st.default_manifest(first)
            st.atomic_write_text(
                staging,
                st.MANIFEST_NAME,
                rec.canonical_json(manifest),
                crash="migrate:manifest",
            )

            # Keep the old data until the new store is in place: rename it
            # aside, publish the store, then drop the backup. A crash after
            # the first rename is healed on the next open (_adopt_backup).
            committed = False
            if os.path.exists(path):
                os.replace(path, backup)
                st.fsync_dir(parent)
                crash_point("migrate:rename-backup")
            try:
                os.replace(staging, path)
                st.fsync_dir(parent)
                crash_point("migrate:publish")
                committed = True
            finally:
                if not committed:
                    with contextlib.suppress(OSError):
                        os.replace(backup, path)
                        st.fsync_dir(parent)
            if os.path.exists(backup):
                os.remove(backup)
                st.fsync_dir(parent)
                crash_point("migrate:cleanup")
        except BaseException:
            # Roll the staging directory back out; the original file lives on
            # as the backup until the new store is fully published.
            if os.path.isdir(staging):
                for name in os.listdir(staging):
                    with contextlib.suppress(OSError):
                        os.unlink(os.path.join(staging, name))
                with contextlib.suppress(OSError):
                    os.rmdir(staging)
            raise

        # The sidecar cache described the former single file; the stable
        # sibling lock (path + ".lock") is unchanged by the migration.
        with contextlib.suppress(OSError):
            os.remove(layout.cache_path)

    def _rotate_dir(self, layout: st.Layout) -> None:
        units = self._view(layout)
        manifest = st.load_manifest(layout)
        active_name = manifest["active"]
        active_unit = next(unit for unit in units if unit["name"] == active_name)
        active_manifest = next(
            segment for segment in manifest["segments"] if segment["name"] == active_name
        )
        size = os.path.getsize(active_unit["path"])
        if size == 0:
            return

        # Walk first so a corrupt active segment cannot be sealed away.
        states, entries = self._walk(units, layout)
        for _count, _head, bad in states.values():
            if bad != -1:
                raise ValueError("corrupt audit chain")

        # Freeze the active bytes as verification material: keep windows the
        # segment already preserved (e.g. from a fold-to-one compaction) and
        # add one window for the bytes appended after them.
        with open(active_unit["path"], "rb") as handle:
            active_bytes = handle.read()
        sealed_prefix = sum(part["size"] for part in active_manifest["parts"])
        seal_parts = [dict(part) for part in active_manifest["parts"]]
        if seal_parts and not st.verify_prefix_windows(
            active_unit["path"], seal_parts
        ):
            raise ValueError("corrupt audit segment")
        if len(active_bytes) > sealed_prefix:
            seal_parts.append(
                {
                    "name": active_name,
                    "size": len(active_bytes) - sealed_prefix,
                    "sha256": _sha256(active_bytes[sealed_prefix:]),
                }
            )
        entries[active_name]["parts"] = [dict(part) for part in seal_parts]
        for segment in manifest["segments"]:
            if segment["name"] == active_name:
                segment["sealed"] = True
                segment["parts"] = seal_parts
        next_seq = max(st.seg_seq(s["name"]) for s in manifest["segments"]) + 1
        new_active = st.seg_name(next_seq)
        # The new segment file is durably in place before the manifest names
        # it; a kill here leaves one orphan tmp/file under the old topology.
        self._write_bytes(layout.root, new_active, b"", crash="rotate:active")
        manifest["segments"].append(
            {"name": new_active, "sealed": False, "parts": []}
        )
        manifest["active"] = new_active
        st.save_manifest(layout, manifest, crash="rotate:manifest")
        st.save_cache(layout, entries, manifest, crash="rotate:cache")

    def compact(self, max_segments: int = _DEFAULT_MAX_SEGMENTS) -> dict:
        """Merge old sealed segments while keeping each one's material.

        The log is folded until at most ``max_segments`` segments remain
        (the active segment counts). Each merge concatenates the source
        bytes and retains their ordered (size, sha256) windows, so every
        source segment's verification material survives compression and the
        global insertion order is unchanged.
        """
        if max_segments < 1:
            raise ValueError("max_segments must be >= 1")
        with self._locked(exclusive=True) as layout:
            if layout.kind != "dir":
                raise ValueError("log is not segmented; call rotate() first")
            units = self._view(layout)

            # Never fold a damaged log.
            states, _ = self._walk(units, layout)
            for _count, _head, bad in states.values():
                if bad != -1:
                    raise ValueError("corrupt audit chain")

            manifest = st.load_manifest(layout)
            cache = st.load_cache(layout, manifest)
            cache_segments = {} if cache is None else dict(cache["segments"])

            if max_segments == 1 and len(manifest["segments"]) > 1:
                removed = self._merge_all(layout, manifest, cache_segments)
            else:
                removed: list[str] = []
                while len(manifest["segments"]) > max_segments:
                    removed += self._merge_pair(layout, manifest, cache_segments)

            # Commit the new topology first; the now-unreferenced sources are
            # removed after the durable manifest swap and otherwise garbage
            # collected on the next open, so a crash never loses data.
            st.save_manifest(layout, manifest, crash="compact:manifest")
            st.save_cache(layout, cache_segments, manifest, crash="compact:cache")
            for name in removed:
                with contextlib.suppress(FileNotFoundError):
                    os.remove(layout.segment_path(name))
                    crash_point("compact:delete")
            st.fsync_dir(layout.root)
            count = len(manifest["segments"])
        return {"segments": count}

    def _gc_segments(self, layout: st.Layout, manifest: dict) -> None:
        """Remove segment files not referenced by the committed manifest."""
        referenced = {segment["name"] for segment in manifest["segments"]}
        for name in os.listdir(layout.root):
            if st.seg_seq(name) is not None and name not in referenced:
                with contextlib.suppress(OSError):
                    os.remove(layout.segment_path(name))
        st.fsync_dir(layout.root)

    def _merge_all(
        self, layout: st.Layout, manifest: dict, cache_segments: dict
    ) -> list[str]:
        """Fold every segment, active included, into one active segment."""
        sources = manifest["segments"]
        merged, parts, carried = self._compose(layout, sources, cache_segments)
        name = st.seg_name(max(st.seg_seq(s["name"]) for s in sources) + 1)
        target = layout.segment_path(name)
        self._write_bytes(layout.root, name, merged, crash="compact:segment")
        for source in sources:
            cache_segments.pop(source["name"], None)
        if carried is not None:
            cache_segments[name] = _cache_entry(
                carried["records"], os.stat(target), [], _states_from(carried)
            )
        manifest["segments"] = [
            {"name": name, "sealed": False, "parts": parts}
        ]
        manifest["active"] = name
        return [source["name"] for source in sources]

    def _merge_pair(
        self, layout: st.Layout, manifest: dict, cache_segments: dict
    ) -> list[str]:
        """Merge the two oldest segments into one new sealed segment."""
        sources = manifest["segments"][:2]
        merged, parts, carried = self._compose(layout, sources, cache_segments)
        name = st.seg_name(
            max(st.seg_seq(s["name"]) for s in manifest["segments"]) + 1
        )
        target = layout.segment_path(name)
        self._write_bytes(layout.root, name, merged, crash="compact:segment")
        manifest["segments"] = [
            {"name": name, "sealed": True, "parts": parts}
        ] + manifest["segments"][2:]
        for source in sources:
            cache_segments.pop(source["name"], None)
        if carried is not None:
            cache_segments[name] = _cache_entry(
                carried["records"], os.stat(target), parts, _states_from(carried)
            )
        return [source["name"] for source in sources]

    def _compose(
        self, layout: st.Layout, sources: list[dict], cache_segments: dict
    ) -> tuple[bytes, list[dict], Optional[dict]]:
        """Concatenate source bytes and windows, carrying warm cached states."""
        chunks: list[bytes] = []
        parts: list[dict] = []
        for source in sources:
            path = layout.segment_path(source["name"])
            with open(path, "rb") as handle:
                data = handle.read()
            if source["sealed"]:
                windows = source["parts"]
                if len(data) != sum(w["size"] for w in windows) or not st.verify_windows(
                    path, windows
                ):
                    raise ValueError("corrupt audit segment")
            else:
                # The active segment carries no preserved byte windows;
                # freeze one full-content window for it now (read once).
                windows = [
                    {
                        "name": source["name"],
                        "size": len(data),
                        "sha256": _sha256(data),
                    }
                ]
            chunks.append(data)
            parts.extend(dict(part) for part in windows)

        # Cache entries hold cumulative per-tenant states, so after the
        # sources in order the last cached entry describes the whole merge.
        carried: Optional[dict] = None
        for source in sources:
            cached = cache_segments.get(source["name"])
            if cached is None:
                carried = None
                break
            carried = {
                "records": cached["records"],
                "tenants": {
                    tenant: list(state) for tenant, state in cached["tenants"].items()
                },
            }
        return b"".join(chunks), parts, carried


    # ------------------------------------------------------------------
    # Incremental verification walk
    # ------------------------------------------------------------------

    def _walk(
        self, units: list[dict], layout: st.Layout
    ) -> tuple[dict[str, tuple[int, int, int]], dict]:
        """Walk every unit in order, reusing authenticated cached prefixes.

        Returns ``(states, entries)``: states maps tenant to
        ``(count, head_digest, first_bad)``; entries maps unit name to its
        cache entry. Cost model:

        * a unit unchanged since caching adopts the cached states with no
          record reads or digest work;
        * a grown active/legacy unit parses and chains only the appended
          suffix, so a ten-thousand-entry re-verify never rehashes the file;
        * a sealed segment is authenticated by its preserved byte windows
          (merged segments keep one window per source segment), and damaged
          windows are attributed to the tenants whose records they hold, so
          one tenant's corruption never changes another tenant's verdict
          while ``first_bad`` stays the global per-tenant index.
        """
        manifest = st.load_manifest(layout) if layout.kind == "dir" else None
        cache = st.load_cache(layout, manifest)
        cached = {} if cache is None else cache["segments"]
        states: dict[str, list] = {}
        entries: dict[str, dict] = {}
        total_records = 0
        # Once any unit is re-walked outside its cache, the cached cumulative
        # states of every later unit were derived from the old prefix and can
        # no longer be adopted: cross-boundary links must be re-derived too.
        desynced = False
        # Per-tenant tripwire: earliest global index at which a tenant has a
        # record in a content-hash-failed window. Acts on tenants whose own
        # chain nevertheless re-derives (a recomputed-digest forgery).
        suspect: dict[str, int] = {}

        for unit in units:
            name = unit["name"]
            path = unit["path"]
            try:
                stat = os.stat(path)
            except FileNotFoundError:
                if name == _FILE_UNIT:
                    # The legacy file does not exist before the first append.
                    continue
                raise
            entry = cached.get(name)

            if entry is not None and not desynced and self._stat_fresh(entry, stat):
                self._adopt_states(states, entry)
                total_records = entry["records"]
                entries[name] = _cache_entry(
                    total_records, stat, entry["parts"], states
                )
                continue

            if (
                entry is not None
                and not desynced
                and not unit["sealed"]
                and stat.st_size > entry["size"]
            ):
                # Appended-only growth on the active unit. Writers are
                # lock-serialized and O_APPEND-only, and the writer warms
                # this cache itself; an unwarmed growth (crashed writer,
                # out-of-band append) is still safe because the suffix's
                # predecessor links must match the cached heads. Only the
                # suffix is parsed and hashed.
                self._adopt_states(states, entry)
                with open(path, "rb") as handle:
                    handle.seek(entry["size"])
                    tail = handle.read()
                records = st.decode_records(tail)
                self._apply_records(records, states)
                total_records = entry["records"] + len(records)
                entries[name] = _cache_entry(total_records, stat, [], states)
                continue

            # Cold unit, shrink, same-size rewrite, any change to a sealed
            # unit, or a unit following one that desynced: full parse; sealed
            # windows are re-authenticated and every link is re-derived.
            desynced = True
            walked, parts, failed_tenants = self._walk_bytes(unit, states)
            for tenant, index in failed_tenants.items():
                suspect.setdefault(tenant, index)
            if entry is not None:
                # The surviving cache anchors what this unit's per-tenant
                # heads and counts must be. Legitimate writes take the
                # growth branch above (or drop the cache via recover), so a
                # stat change landing here whose re-derived heads differ is
                # a rewritten history even when its digests recompute.
                for tenant, anchored in entry["tenants"].items():
                    current = states.get(tenant)
                    if current is None:
                        suspect.setdefault(tenant, 0)
                    elif (
                        current[0] != anchored[0] or current[1] != anchored[1]
                    ) and current[2] == -1:
                        suspect.setdefault(tenant, 0)
                if stat.st_size < entry["size"]:
                    # Records were deleted while the cache survived: flag the
                    # first missing global index for each affected tenant.
                    for tenant, anchored in entry["tenants"].items():
                        current = states.get(tenant)
                        remaining = current[0] if current is not None else 0
                        if remaining < anchored[0]:
                            suspect.setdefault(tenant, remaining)
            total_records += walked
            entries[name] = _cache_entry(total_records, stat, parts, states)

        # A chain break attributes first_bad precisely and is used as-is.
        # Separately, every tenant with a record in a content-hash-failed
        # window whose own chain still re-derives is flagged: its bytes were
        # rewritten with recomputed digests and must not pass. This is
        # evaluated per tenant, so a real break in another tenant's chain
        # never suppresses it.
        for tenant, index in suspect.items():
            state = states.get(tenant)
            if state is not None and state[2] == -1:
                state[2] = index

        st.save_cache(layout, entries, manifest)
        return (
            {tenant: (state[0], state[1], state[2]) for tenant, state in states.items()},
            entries,
        )

    @staticmethod
    def _adopt_states(states: dict[str, list], entry: dict) -> None:
        for tenant, state in entry["tenants"].items():
            count, digest, bad = state
            current = states.get(tenant)
            if current is None:
                states[tenant] = [count, digest, bad]
            else:
                # Never let a cached -1 erase an earlier first_bad.
                prior_bad = current[2]
                if prior_bad != -1 and (bad == -1 or prior_bad < bad):
                    bad = prior_bad
                states[tenant] = [count, digest, bad]

    @staticmethod
    def _stat_fresh(entry: dict, stat: os.stat_result) -> bool:
        # size + mtime identify an unchanged append-only file; ctime (which
        # utimes cannot restore) exposes a same-size content rewrite.
        return (
            entry["size"] == stat.st_size
            and entry["mtime_ns"] == stat.st_mtime_ns
            and entry["ctime_ns"] == stat.st_ctime_ns
        )

    def _walk_bytes(
        self, unit: dict, states: dict[str, list]
    ) -> tuple[int, list[dict], dict]:
        """Parse and chain one unit's bytes.

        Returns ``(record_count, cache_parts, failed_tenants)`` where
        ``failed_tenants`` maps each tenant with a record in a
        content-hash-failed window to that record's global index.

        Content tampering normally breaks the victim's digest chain, which
        attributes ``first_bad`` precisely and leaves tenants with no record
        in the damaged window untouched. The window hash is an independent
        tripwire: it only needs to act when the attacker also recomputed
        digests (a clean-looking but rewritten log).
        """
        path = unit["path"]
        windows = unit["parts"]
        with open(path, "rb") as handle:
            raw = handle.read()

        failed: set[int] = set()
        window_ends: list[int] = []
        if windows:
            if unit["sealed"] and len(raw) != sum(
                window["size"] for window in windows
            ):
                failed.update(range(len(windows)))
            elif not st.verify_prefix_windows(path, windows):
                failed.update(range(len(windows)))
            running = 0
            for window in windows:
                running += window["size"]
                window_ends.append(running)

        try:
            text = raw.decode(_ENCODING)
        except UnicodeDecodeError as exc:
            raise ValueError("malformed audit record") from exc
        lines = rec.split_records(text)

        first_index: dict[str, int] = {}
        win_index = 0
        pos = 0
        for line in lines:
            length = len((line + "\n").encode(_ENCODING))
            start, end = pos, pos + length
            pos = end
            while win_index < len(window_ends) and start >= window_ends[win_index]:
                win_index += 1
            past_end = win_index >= len(window_ends)
            crosses = not past_end and end > window_ends[win_index]
            window_failed = not past_end and win_index in failed

            record = rec.parse_line(line)
            tenant = record["tenant"]
            count, head, bad = states.get(tenant, [0, "", -1])
            if window_failed:
                first_index.setdefault(tenant, count)
            if crosses:
                # Windows only ever concatenate whole lines, so a record may
                # never straddle a window boundary.
                if bad == -1:
                    bad = count
            if unit["sealed"] and past_end and bad == -1:
                # Bytes appended past a sealed segment's frozen material.
                bad = count
            recomputed = rec.digest(record["prev"], record["payload"])
            if record["prev"] != head or record["digest"] != recomputed:
                if bad == -1:
                    bad = count
            states[tenant] = [count + 1, record["digest"], bad]

        parts = [dict(part) for part in windows] if unit["sealed"] else []
        return len(lines), parts, first_index

    def _apply_records(self, records: list[dict], states: dict[str, list]) -> None:
        for record in records:
            tenant = record["tenant"]
            count, head, bad = states.get(tenant, [0, "", -1])
            recomputed = rec.digest(record["prev"], record["payload"])
            if record["prev"] != head or record["digest"] != recomputed:
                if bad == -1:
                    bad = count
            states[tenant] = [count + 1, record["digest"], bad]

    # ------------------------------------------------------------------
    # Range export
    # ------------------------------------------------------------------

    def export_range(self, tenant: str, start: int, end: int) -> dict:
        """Build an offline proof for ``tenant``'s indices ``[start, end)``.

        The proof holds exactly the in-range chained records plus the
        cross-segment window chain needed to link them; no out-of-range
        payload is included. An independent reader verifies it with
        :func:`audit_chain.proof.verify_range_proof` and the public digest
        algorithm alone; damage outside the range cannot change its verdict.

        Raises ``ValueError`` for non-integer/negative bounds, a reversed or
        empty interval, or an end past the tenant's record count.
        """
        if isinstance(start, bool) or isinstance(end, bool) or not (
            isinstance(start, int) and isinstance(end, int)
        ):
            raise ValueError("range bounds must be integers")
        if start < 0 or end < 0:
            raise ValueError("range bounds must be non-negative")
        if start >= end:
            raise ValueError("range must be non-empty with start < end")

        with self._locked(exclusive=False) as layout:
            self._require_present(layout)
            units = self._view(layout)
            # A physical half-line at the tail of the log keeps the usual
            # bad-line semantics for every reader, including export; it is
            # never silently skipped.
            self._require_clean_tail(units)
            windows, picked, start_prev, count = self._scan_range(
                units, tenant, start, end
            )

        if end > count:
            raise ValueError(
                f"end {end} is out of range for {count} record(s)"
            )
        return pf.build_proof(tenant, start, end, start_prev, windows, picked)

    def _require_clean_tail(self, units: list[dict]) -> None:
        """Raise ``ValueError`` on a physical half-written tail line."""
        if not units:
            return
        active = units[-1]
        try:
            with open(active["path"], "rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                if size == 0:
                    return
                handle.seek(-1, os.SEEK_END)
                last = handle.read(1)
        except FileNotFoundError:
            if not active["sealed"]:
                return
            raise
        if last != b"\n":
            raise ValueError("truncated audit record")

    def _scan_range(
        self, units: list[dict], tenant: str, start: int, end: int
    ) -> tuple[list[dict], list[dict], str, int]:
        """Scan the snapshot for one tenant's range without reading trust.

        Each preserved window is decoded from its *own declared byte slice*,
        so damage in a window the range never touches -- including windows in
        earlier/later segments -- cannot change the in-range result. Only the
        manifest-declared window sizes bound the parsing; the preserved
        sha256 anchors are carried into the proof for holders of the store and
        are never needed to locate in-range records.

        Returns ``(windows, picked, start_prev, count)``.
        """
        windows: list[dict] = []
        picked: list[dict] = []
        start_prev = ""
        count = 0
        for unit in units:
            try:
                with open(unit["path"], "rb") as handle:
                    raw = handle.read()
            except FileNotFoundError:
                if not unit["sealed"]:
                    continue
                raise

            slices: list[tuple[int, int, Optional[str]]] = []
            running = 0
            for part in unit["parts"]:
                slices.append((running, running + part["size"], part["sha256"]))
                running += part["size"]
            if not unit["sealed"] and len(raw) > running:
                # Grown tail of an active/legacy unit: one fresh window.
                slices.append((running, len(raw), _sha256(raw[running:])))

            for lo, hi, anchor in slices:
                if hi <= lo:
                    continue
                body = raw[lo:hi]
                order = len(windows)
                windows.append(
                    {
                        "name": unit["name"],
                        "size": hi - lo,
                        "sha256": anchor if anchor is not None else _sha256(body),
                    }
                )
                text = body.decode(_ENCODING)
                # Tolerant per-window scan over every line's bytes. Complete
                # newline-terminated lines only; a fragment here is corruption
                # confined to this window (the physical tail half-line is
                # handled separately). Byte offsets advance over *all* lines,
                # so honest placement is exact even when foreign garbage is
                # interleaved.
                raw_lines = text.split("\n")
                if raw_lines and raw_lines[-1] == "":
                    raw_lines = raw_lines[:-1]
                offset = 0
                for line in raw_lines:
                    length = len((line + "\n").encode(_ENCODING))
                    # A damaged line belonging to another tenant is outside
                    # the range: skip it without letting it abort the proof,
                    # while its byte length still advances placement. A
                    # damaged line of *this* tenant is simply absent, so the
                    # count/bounds checks below can never return a clean
                    # proof across it.
                    record = None
                    if line != "":
                        try:
                            record = rec.parse_line(line)
                        except ValueError:
                            record = None
                    if record is not None and record["tenant"] == tenant:
                        if count == start:
                            start_prev = record["prev"]
                        if start <= count < end:
                            picked.append(
                                {
                                    "index": count,
                                    "window": order,
                                    "offset": offset,
                                    "length": length,
                                    "record": record,
                                }
                            )
                        count += 1
                    offset += length
        return windows, picked, start_prev, count

    # ------------------------------------------------------------------
    # Small helpers
    # ------------------------------------------------------------------

    def _write_bytes(
        self, directory: str, name: str, raw: bytes, *, crash: Optional[str] = None
    ) -> None:
        st.atomic_write_bytes(directory, name, raw, crash=crash)

    def _delete_cache(self, layout: st.Layout) -> None:
        with contextlib.suppress(FileNotFoundError):
            os.remove(layout.cache_path)


def _cache_entry(
    records: int, stat: os.stat_result, parts: list[dict], states: dict[str, list]
) -> dict:
    return {
        "records": records,
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "ctime_ns": stat.st_ctime_ns,
        "parts": parts,
        "tenants": {tenant: list(state) for tenant, state in states.items()},
    }


def _states_from(carried: dict) -> dict:
    return {
        tenant: list(state) for tenant, state in carried["tenants"].items()
    }


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()
