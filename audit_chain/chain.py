"""Per-tenant hash-chained audit log.

Every entry stores the digest of its predecessor, so a tenant's history can
be walked offline and the first tampered index pinpointed. Tenants are
independent chains that share one physical log.

The original single JSON-lines file is extended without changing its
semantics:

* concurrent appenders to the same log are serialized by a process-shared,
  cross-platform file lock, so interlocked writes still link strictly;
* every read (``verify``/``entries``/``head``) takes a snapshot under a
  shared lock: a single call always sees one complete prefix -- the old
  topology or the new one around a rotation, merge or recovery -- never a
  mix of segments, a duplicate run or a skipped run;
* the log can be rotated into ordered segment files and compacted, with
  every source segment's verification material (byte size + sha256)
  retained through merges, committed by an atomic, self-authenticating
  manifest replacement; merged bytes are published through a temp file and
  rename, so every crash window lands on the old or the new topology;
* verification of long logs is incremental: unchanged byte windows are
  authenticated by an on-disk cache (stat-guarded on the active unit,
  window-material-guarded on sealed units), so a repeated verification of
  a ten-thousand-entry log only hashes newly appended bytes plus a small
  amount of sidecar material;
* tampering with the cache, the manifest or a sealed window is reported as
  chain corruption with the real first bad global index (never a pass, and
  distinct from the half-line bad-line semantics);
* ``export_range`` produces an offline proof for a contiguous index
  interval: only the interval's records plus the window anchors needed to
  attach the chain, verifiable with the public digest alone;
* ``recover`` is the explicit entry point that truncates a half-written
  tail line left by a killed process.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
from typing import Any, Optional

from . import record as rec
from . import storage as st

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
    # Layout / locking
    # ------------------------------------------------------------------

    def _lock_path(self) -> str:
        normalized = os.path.normpath(self.path)
        parent = os.path.dirname(normalized) or "."
        return os.path.join(parent, "." + os.path.basename(normalized) + ".lock")

    def _layout(self) -> st.Layout:
        existing = st.resolve_existing(self.path)
        if existing is not None:
            return existing
        # Nothing on disk yet: stay in the legacy file layout until the
        # first append (or an explicit rotate) creates anything.
        return st.Layout(self.path, "file")

    def _needs_adoption(self) -> bool:
        backup = self.path + ".pre-segment"
        return not os.path.exists(self.path) and os.path.exists(backup)

    @contextlib.contextmanager
    def _locked(self, *, exclusive: bool):
        # Readers open shared. A tree left mid-operation by a killed process
        # is not in a quiescent state (backup to adopt, staging dir, merge
        # temp file or an unreferenced segment); such a reader escalates
        # once to an exclusive lock, heals the tree deterministically, and
        # only then reads. In a quiescent tree no escalation happens, so the
        # ordinary read path stays shared.
        want_exclusive = exclusive or self._needs_adoption()
        while True:
            with st.file_lock(
                self._lock_path(), timeout=self.lock_timeout, shared=not want_exclusive
            ):
                if not want_exclusive:
                    layout = st.resolve_existing(self.path)
                    if layout is None:
                        layout = st.Layout(self.path, "file")
                    if self._needs_healing(layout):
                        want_exclusive = True
                        continue  # release the shared lock, re-enter exclusive
                    yield layout
                    return

                self._adopt_backup()
                layout = st.resolve_existing(self.path)
                if layout is None:
                    layout = st.Layout(self.path, "file")
                self._reap_crash_leftovers(layout)
                yield layout
                return

    def _needs_healing(self, layout: st.Layout) -> bool:
        """Whether a shared read must escalate to heal before reading.

        A read only escalates when the live path is absent and a migration
        backup is waiting -- without adoption there is nothing to read.
        Every other leftover (staging directory, an unreferenced segment
        from a rotation/compaction killed before/after its manifest commit,
        a merge temp file, a post-publish backup) is inert while the
        committed manifest stays authoritative, so reads leave it untouched
        and the next writer (exclusive) reaps it -- matching the baseline
        rule that reads never move garbage out from under other readers.
        """
        return not os.path.exists(self.path) and os.path.exists(
            self.path + ".pre-segment"
        )

    def _reap_crash_leftovers(self, layout: st.Layout) -> None:
        """Deterministically finish every crash window's housekeeping."""
        backup = self.path + ".pre-segment"
        staging = self.path + ".segstage"
        if layout.kind == "file":
            # The store never happened: drop any staged directory and let
            # _adopt_backup move the file back.
            if os.path.isdir(staging):
                self._remove_tree(staging)
            return

        # The segment store is the published topology. A backup left behind
        # means the migration was killed right after publishing the store.
        if os.path.exists(backup):
            with contextlib.suppress(OSError):
                os.remove(backup)
                st.fsync_dir(os.path.dirname(self.path) or ".")
        if os.path.isdir(staging):
            self._remove_tree(staging)

        manifest = None
        with contextlib.suppress(st.AuditMetadataError):
            manifest = st.load_manifest(layout)
        if manifest is not None:
            self._gc_segments(layout, manifest)
        # Temp files of killed atomic writes/merges (never the lock).
        if os.path.isdir(layout.root):
            for name in os.listdir(layout.root):
                if name.startswith(".") and name.endswith(".tmp"):
                    with contextlib.suppress(OSError):
                        os.remove(os.path.join(layout.root, name))
            st.fsync_dir(layout.root)

    @staticmethod
    def _remove_tree(path: str) -> None:
        import shutil

        with contextlib.suppress(OSError):
            shutil.rmtree(path)

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
        if os.path.isdir(staging):
            self._remove_tree(staging)
        parent = os.path.dirname(self.path) or "."
        os.replace(backup, self.path)
        st.fsync_dir(parent)

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

    def _raw_units(self, layout: st.Layout) -> list[dict]:
        """Units reconstructed from ordered segment file names alone.

        Used when the manifest cannot be trusted: the records themselves
        still carry the chain, so the real first bad index stays derivable.
        """
        if layout.kind == "file":
            return self._view(layout)
        names = sorted(
            name
            for name in os.listdir(layout.root)
            if st.seg_seq(name) is not None
        )
        return [
            {
                "name": name,
                "path": layout.segment_path(name),
                "sealed": False,
                "parts": [],
            }
            for name in names
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

    def _snapshot_units(
        self, layout: st.Layout, *, tolerate_metadata: bool
    ) -> list[dict]:
        try:
            return self._view(layout)
        except st.AuditMetadataError:
            if not tolerate_metadata:
                raise
            return self._raw_units(layout)

    def _tenant_records(self, tenant: str, *, missing_empty: bool) -> list[dict]:
        with self._locked(exclusive=False) as layout:
            if layout.kind == "file" and not os.path.exists(layout.root):
                if missing_empty:
                    return []
                raise FileNotFoundError(layout.root)
            # One fixed unit list and one ordered byte read under the shared
            # lock: writers (exclusive) cannot rotate, merge or recover
            # mid-call, so the result is always one complete prefix.
            units = self._snapshot_units(layout, tolerate_metadata=True)
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
        log is absent and ``ValueError`` on a bad or half-written line.
        Tampering with the cache, the manifest or a sealed window is itself
        corruption: the verdict is ``ok=False`` with the real first bad
        index rather than an exception.
        """
        metadata_damaged = False
        with self._locked(exclusive=False) as layout:
            self._require_present(layout)
            try:
                units = self._view(layout)
            except st.AuditMetadataError:
                # A rewritten manifest cannot vouch for any window: fall
                # back to the physically ordered segment files and re-derive
                # every link from the bytes themselves.
                metadata_damaged = True
                units = self._raw_units(layout)

            try:
                states, _ = self._walk(
                    units,
                    layout,
                    ignore_cache=metadata_damaged,
                    persist=not metadata_damaged,
                )
            except st.AuditMetadataError:
                # The sidecar cache was tampered with. It is neither trusted
                # nor silently healed: re-derive from bytes and report the
                # metadata damage as corruption below.
                metadata_damaged = True
                states, _ = self._walk(units, layout, ignore_cache=True, persist=False)

        state = states.get(tenant)
        if state is None:
            return {"count": 0, "first_bad": -1, "ok": True}
        count, _head, bad = state
        if bad != -1:
            # The byte-level walk found the real break first; it always
            # outranks the metadata tripwire.
            return {"count": count, "first_bad": bad, "ok": False}
        if metadata_damaged:
            # The bytes still re-derive, but authentication material the
            # chain depended on (manifest windows or the verified cache) was
            # rewritten: the earliest index it could vouch for is 0.
            return {"count": count, "first_bad": 0, "ok": False}
        return {"count": count, "first_bad": -1, "ok": True}

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
        the existing log, its cache or its manifest is corrupt; existing
        records are left untouched. Concurrent appenders are serialized by
        a file lock.
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
            data = (line + "\n").encode(_ENCODING)
            # Two raw writes with a real kill point between them model the
            # write/flush/fsync crash window: a kill after the first syscall
            # leaves a deterministic half line that reopen treats as a bad
            # line, never as a silently repaired record.
            cut = max(1, len(data) // 2)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                _write_all(fd, data[:cut])
                st.crash_point("append:after_first_write")
                _write_all(fd, data[cut:])
                st.crash_point("append:before_fsync")
                os.fsync(fd)
                st.crash_point("append:after_fsync")
            finally:
                os.close(fd)

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
            # Drop the cache before changing bytes: whichever window a kill
            # lands in, reopen never mistakes the legitimate shrink for a
            # cached deletion (either the half line still reads as a bad
            # line, or the cache is already gone and the prefix re-derives).
            self._delete_cache(layout)
            fd = os.open(target, os.O_WRONLY)
            try:
                os.ftruncate(fd, cut)
                st.crash_point("recover:after_truncate")
                os.fsync(fd)
            finally:
                os.close(fd)
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
                self._write_bytes(staging, first, raw)
                self._write_bytes(staging, second, b"")
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
                self._write_bytes(staging, first, b"")
                manifest = st.default_manifest(first)
            st.save_manifest_at(staging, manifest)
            st.crash_point("migrate:after_staging")

            # Keep the old data until the new store is in place: rename it
            # aside, publish the store, then drop the backup. Every kill in
            # between lands on one topology and is healed on next open.
            committed = False
            if os.path.exists(path):
                os.replace(path, backup)
                st.fsync_dir(parent)
            st.crash_point("migrate:after_backup_rename")
            try:
                os.replace(staging, path)
                st.fsync_dir(parent)
                committed = True
            finally:
                if not committed:
                    with contextlib.suppress(OSError):
                        os.replace(backup, path)
                        st.fsync_dir(parent)
            st.crash_point("migrate:after_publish")
            if os.path.exists(backup):
                os.remove(backup)
                st.fsync_dir(parent)
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

        # The lock is topology-independent and stays put; the legacy sidecar
        # described the former single file, whereas the store's cache lives
        # inside the directory. Drop the stale one and warm the store's cache
        # from the bytes just migrated (mirrors _rotate_dir), so an export
        # right after the first rotation need not cold-scan the history.
        with contextlib.suppress(OSError):
            os.remove(layout.cache_path)
        new_layout = st.Layout(self.path, "dir")
        with contextlib.suppress(OSError, ValueError):
            self._walk(self._view(new_layout), new_layout)

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
        # The new segment is an unreferenced orphan until the manifest commit
        # names it; a kill in this window simply has it garbage-collected and
        # the old topology remains authoritative.
        self._write_bytes(layout.root, new_active, b"")
        st.crash_point("rotate:before_manifest")
        manifest["segments"].append(
            {"name": new_active, "sealed": False, "parts": []}
        )
        manifest["active"] = new_active
        st.save_manifest(layout, manifest)
        st.crash_point("rotate:after_manifest")
        st.save_cache(layout, entries)

    def compact(self, max_segments: int = _DEFAULT_MAX_SEGMENTS) -> dict:
        """Merge old sealed segments while keeping each one's material.

        The log is folded until at most ``max_segments`` segments remain
        (the active segment counts). Each merge concatenates the source
        bytes and retains their ordered (size, sha256) windows, so every
        source segment's verification material survives compression and the
        global insertion order is unchanged.

        Merged bytes are staged in a temp file and renamed before the
        atomic manifest commit; the old segments are removed only after the
        commit. A kill at any point therefore leaves the old topology or
        the complete new topology plus unreferenced files reaped on reopen.
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
            cache = st.load_cache(layout)
            cache_segments = {} if cache is None else dict(cache["segments"])

            if max_segments == 1 and len(manifest["segments"]) > 1:
                removed = self._merge_all(layout, manifest, cache_segments)
            else:
                removed: list[str] = []
                while len(manifest["segments"]) > max_segments:
                    removed += self._merge_pair(layout, manifest, cache_segments)

            if removed:
                # Commit the new topology first; the now-unreferenced
                # sources are removed after the durable manifest swap and
                # otherwise garbage collected on the next open, so a crash
                # never loses data and never exposes a mixed topology.
                st.save_manifest(layout, manifest)
                st.crash_point("compact:after_manifest")
                st.save_cache(layout, cache_segments)
                for name in removed:
                    with contextlib.suppress(FileNotFoundError):
                        os.remove(layout.segment_path(name))
                    st.crash_point("compact:during_delete")
                st.fsync_dir(layout.root)
                st.crash_point("compact:after_delete")
            count = len(manifest["segments"])
        return {"segments": count}

    def _gc_segments(self, layout: st.Layout, manifest: dict) -> None:
        """Remove segment files not referenced by the committed manifest."""
        referenced = {segment["name"] for segment in manifest["segments"]}
        changed = False
        for name in os.listdir(layout.root):
            if st.seg_seq(name) is not None and name not in referenced:
                with contextlib.suppress(OSError):
                    os.remove(layout.segment_path(name))
                    changed = True
        if changed:
            st.fsync_dir(layout.root)

    def _publish_bytes(self, layout: st.Layout, name: str, raw: bytes) -> str:
        """Stage ``raw`` in a temp file and rename it to segment ``name``."""
        target = layout.segment_path(name)
        tmp_path = os.path.join(layout.root, st._tmp_name_for(name))
        try:
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                _write_all(fd, raw)
                st.crash_point("compact:before_merge_fsync")
                os.fsync(fd)
            finally:
                os.close(fd)
            st.crash_point("compact:after_merge_write")
            os.replace(tmp_path, target)
            st.fsync_dir(layout.root)
            st.crash_point("compact:after_merge_rename")
        except BaseException:
            with contextlib.suppress(OSError):
                os.remove(tmp_path)
            raise
        return target

    def _merge_all(
        self, layout: st.Layout, manifest: dict, cache_segments: dict
    ) -> list[str]:
        """Fold every segment, active included, into one active segment."""
        sources = manifest["segments"]
        merged, parts, carried = self._compose(layout, sources, cache_segments)
        name = st.seg_name(max(st.seg_seq(s["name"]) for s in sources) + 1)
        target = self._publish_bytes(layout, name, merged)
        for source in sources:
            cache_segments.pop(source["name"], None)
        if carried is not None:
            cache_segments[name] = _cache_entry(
                carried["records"], os.stat(target), parts, _states_from(carried)
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
        target = self._publish_bytes(layout, name, merged)
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
        self,
        units: list[dict],
        layout: st.Layout,
        *,
        ignore_cache: bool = False,
        persist: bool = True,
    ) -> tuple[dict[str, tuple[int, int, int]], dict]:
        """Walk every unit in order, reusing authenticated cached prefixes.

        Returns ``(states, entries)``: states maps tenant to
        ``(count, head_digest, first_bad)``; entries maps unit name to its
        cache entry. Cost model:

        * a unit unchanged since caching adopts the cached states with no
          record reads or digest work -- the active unit is stat-guarded and
          a sealed unit is guarded by its preserved window material, so no
          sealed byte is hashed on the hot path;
        * a grown active/legacy unit parses and chains only the appended
          suffix, so a ten-thousand-entry re-verify never rehashes the file;
        * a sealed segment is authenticated by its preserved byte windows
          (merged segments keep one window per source segment), and damaged
          windows are attributed to the tenants whose records they hold, so
          one tenant's corruption never changes another tenant's verdict
          while ``first_bad`` stays the global per-tenant index.
        """
        cache = None if ignore_cache else st.load_cache(layout)
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

            if entry is not None and not desynced and self._entry_fresh(
                entry, stat, unit
            ):
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
                and entry.get("parts", []) == unit["parts"]
            ):
                # Appended-only growth on the active unit. Writers are
                # lock-serialized and O_APPEND-only, and the writer warms
                # this cache itself; an unwarmed growth (crashed writer,
                # out-of-band append) is still safe because the suffix's
                # predecessor links must match the cached heads and its
                # preserved prefix windows must match, so a rewritten prefix
                # or edited manifest window cannot ride the suffix branch.
                # Only the suffix is parsed and hashed.
                self._adopt_states(states, entry)
                with open(path, "rb") as handle:
                    handle.seek(entry["size"])
                    tail = handle.read()
                records = st.decode_records(tail)
                self._apply_records(records, states)
                total_records = entry["records"] + len(records)
                # Appended-only growth leaves the preserved prefix windows
                # untouched, so carry their material forward in the cache.
                entries[name] = _cache_entry(
                    total_records, stat, entry.get("parts", []), states
                )
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

        # Never warm the cache from a walk that saw corruption: otherwise a
        # manifest whose window anchors were rewritten would, on a second
        # verify, match its own (bad) cached parts and take the constant hot
        # path straight to a false pass. A corrupt tree is re-derived from
        # bytes on every verify until it is genuinely repaired.
        any_bad = any(state[2] != -1 for state in states.values())
        if persist and not suspect and not any_bad:
            st.save_cache(layout, entries)
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
    def _stat_fresh(entry: dict, stat: os.stat_result, *, exact: bool = True) -> bool:
        # size + mtime identify an unchanged append-only file; ctime (which
        # utimes cannot restore) exposes a same-size content rewrite. The
        # growth branch only needs size-growth + unchanged ctime.
        if entry["ctime_ns"] != stat.st_ctime_ns:
            return False
        if not exact:
            return entry["size"] <= stat.st_size
        return (
            entry["size"] == stat.st_size
            and entry["mtime_ns"] == stat.st_mtime_ns
        )

    @staticmethod
    def _entry_fresh(entry: dict, stat: os.stat_result, unit: dict) -> bool:
        """Hot-path freshness with constant read amplification.

        The size + mtime + ctime guard identifies an unchanged append-only
        file (ctime exposes a same-size content rewrite and cannot be
        restored). In addition, whenever the unit carries preserved byte
        windows -- always for a sealed unit, and for an active unit after a
        fold-to-one compaction -- the manifest's window material must match
        what the cache authenticated, so an edited manifest window forces
        the cold path and is reported as corruption, without a single sealed
        byte being hashed on the ordinary path.
        """
        if not Chain._stat_fresh(entry, stat):
            return False
        cached_parts = entry.get("parts", [])
        if unit["sealed"] or cached_parts or unit["parts"]:
            return cached_parts == unit["parts"]
        return True

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

        # Sealed units carry their full window material; an active unit
        # carries preserved *prefix* windows after a fold-to-one compaction.
        # Both are retained in the cache so the hot-path freshness guard
        # compares the manifest's window material for either kind.
        parts = [dict(part) for part in windows]
        return len(lines), parts, first_index

    def _apply_records(self, records: list[dict], states: dict[str,list]) -> None:
        for record in records:
            tenant = record["tenant"]
            count, head, bad = states.get(tenant, [0, "", -1])
            recomputed = rec.digest(record["prev"], record["payload"])
            if record["prev"] != head or record["digest"] != recomputed:
                if bad == -1:
                    bad = count
            states[tenant] = [count + 1, record["digest"], bad]

    # ------------------------------------------------------------------
    # Interval export / offline proofs
    # ------------------------------------------------------------------

    def export_range(self, tenant: str, start: int, end: int) -> dict:
        """Build an offline proof for tenant records ``[start, end)``.

        The proof contains only the interval's chained records and the
        window anchors (ordered, strictly increasing windows) needed to
        attach the interval to the prefix and confirm it is contiguous. No
        payload outside the interval is included. An independent reader can
        check it with :func:`audit_chain.proof.verify_proof` and the public
        digest function alone.

        Illegal, reversed, empty or out-of-range intervals raise
        ``ValueError``; for a tenant with no history the empty-history
        conclusion ``(0, 0)`` is the only interval accepted.
        """
        from . import proof as pf

        if (
            not isinstance(start, int)
            or not isinstance(end, int)
            or isinstance(start, bool)
            or isinstance(end, bool)
        ):
            raise ValueError("range bounds must be integers")
        if start < 0 or end < 0:
            raise ValueError("range bounds must be non-negative")
        if end < start:
            raise ValueError("range is reversed: start must be <= end")

        with self._locked(exclusive=False) as layout:
            if layout.kind == "file" and not os.path.exists(layout.root):
                # A log that was never created implies an empty history for
                # every tenant; only the (0, 0) empty-history conclusion is
                # in bounds.
                if (start, end) == (0, 0):
                    return pf.empty_proof(tenant)
                raise ValueError("range is out of bounds for an empty history")
            units = self._snapshot_units(layout, tolerate_metadata=True)
            # Fast path: an authentic warm cache states each unit's
            # cumulative tenant counts, so only units holding interval bytes
            # are opened. With no trustworthy guide (never-verified log,
            # grown active unit, edited bytes or metadata) fall back to the
            # full ordered byte scan.
            guide = self._export_guide(units, layout, tenant)
            if guide is not None:
                material = self._collect_range_bounded(
                    units, tenant, start, end, guide
                )
            else:
                material = self._collect_range(units, tenant, start, end)
        return pf.build_proof(material)

    # ------------------------------------------------------------------
    # Small helpers
    # ------------------------------------------------------------------

    def _write_bytes(self, directory: str, name: str, raw: bytes) -> None:
        path = os.path.join(directory, name)
        with open(path, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        st.fsync_dir(directory)

    def _collect_range(
        self, units: list[dict], tenant: str, start: int, end: int
    ) -> dict:
        """One ordered snapshot scan collecting interval material.

        Windows are numbered with one strictly increasing global sequence
        across all units, so the proof carries an explicit cross-segment
        window chain. Only records of ``tenant`` are parsed; malformed lines
        and a trailing half line outside the interval are skipped, so damage
        outside the interval cannot change its conclusion.
        """
        buckets: dict[int, list[tuple[int, int, dict]]] = {}
        anchors: dict[int, dict] = {}
        predecessor: Optional[str] = None
        count = 0
        global_seq = 0

        for unit in units:
            try:
                with open(unit["path"], "rb") as handle:
                    raw = handle.read()
            except FileNotFoundError:
                if not unit["sealed"]:
                    continue
                raise

            parts = unit["parts"]
            window_ends: list[int] = []
            running = 0
            for part in parts:
                running += part["size"]
                window_ends.append(running)
                anchors[global_seq + len(window_ends) - 1] = {
                    "name": part["name"],
                    "size": part["size"],
                    "sha256": part["sha256"],
                }
            tail_offset = running
            tail_seq = global_seq + len(parts)
            if len(raw) > tail_offset:
                anchors[tail_seq] = {
                    "name": unit["name"],
                    "size": len(raw) - tail_offset,
                    "sha256": _sha256(raw[tail_offset:]),
                }
            elif not parts:
                # Legacy/active unit with no preserved material: its whole
                # bytes are one implicit window.
                anchors[tail_seq] = {
                    "name": unit["name"],
                    "size": len(raw),
                    "sha256": _sha256(raw),
                }

            # Whole-line scan: a piece after the final newline is a crashed
            # half line -- never a record, and irrelevant when out of range.
            pos = 0
            for line_raw in raw.split(b"\n")[:-1]:
                line_start = pos
                line_end = pos + len(line_raw) + 1
                pos = line_end
                try:
                    record = st.decode_records(line_raw + b"\n")[0]
                except ValueError:
                    continue
                if record["tenant"] != tenant:
                    continue
                if count == start:
                    predecessor = record["prev"]
                win_index = 0
                while win_index < len(window_ends) and line_start >= window_ends[win_index]:
                    win_index += 1
                if win_index < len(window_ends):
                    seq = global_seq + win_index
                    window_start = window_ends[win_index - 1] if win_index else 0
                else:
                    seq = tail_seq
                    window_start = tail_offset
                if start <= count < end:
                    buckets.setdefault(seq, []).append(
                        (count, line_start - window_start, record)
                    )
                count += 1

            global_seq += len(parts) + (1 if len(raw) > tail_offset or not parts else 0)

        if count == 0:
            if (start, end) == (0, 0):
                return {
                    "tenant": tenant,
                    "start": 0,
                    "end": 0,
                    "count": 0,
                    "prev": "",
                    "anchors": {},
                    "buckets": [],
                }
            raise ValueError("range is out of bounds for an empty history")
        if start == end:
            raise ValueError("range must be a non-empty interval")
        if start >= count or end > count:
            raise ValueError("range is out of bounds")

        return {
            "tenant": tenant,
            "start": start,
            "end": end,
            "count": count,
            "prev": predecessor if predecessor is not None else "",
            "anchors": anchors,
            "buckets": [
                {"seq": seq, "records": records}
                for seq, records in sorted(buckets.items())
            ],
        }

    # ------------------------------------------------------------------
    # Bounded-export fast path (warm, authenticated verify cache)
    # ------------------------------------------------------------------

    def _export_guide(
        self, units: list[dict], layout: st.Layout, tenant: str
    ) -> Optional[list[int]]:
        """Each unit's cumulative tenant record count, or None when cold.

        The verify cache is signed and a unit is adopted only when the exact
        stat guard and its preserved-window material both match, so a
        rewritten prefix, a same-size edit, a shrunk file, a grown active
        unit or an edited manifest window all force the full byte scan
        instead of trusting a guide that no longer matches the bytes.
        """
        try:
            cache = st.load_cache(layout)
        except st.AuditMetadataError:
            return None
        if cache is None or len(cache["segments"]) != len(units):
            return None

        counts: list[int] = []
        for unit in units:
            entry = cache["segments"].get(unit["name"])
            if entry is None:
                return None
            try:
                stat = os.stat(unit["path"])
            except FileNotFoundError:
                if not unit["sealed"]:
                    return None
                raise
            if not self._entry_fresh(entry, stat, unit):
                return None
            state = entry["tenants"].get(tenant)
            counts.append(state[0] if state is not None else 0)
        return counts

    def _collect_range_bounded(
        self,
        units: list[dict],
        tenant: str,
        start: int,
        end: int,
        counts: list[int],
    ) -> dict:
        """Collect interval material opening only covering units.

        Only the units that hold an interval record are read. A record in a
        preserved sealed window is anchored by that window's manifest
        material, so no sealed byte is hashed; records in the still-growing
        un-preserved tail of an active/legacy unit are grouped into small
        windows that contain only the interval's own consecutive lines, so
        digest work tracks the interval rather than the unit. Total cost
        therefore grows with the interval and the (bounded) covering units,
        never with overall history length: non-covering units are never
        opened and their sealed windows contribute no reads or hashes.
        """
        total = counts[-1]
        if total == 0:
            if (start, end) == (0, 0):
                return {
                    "tenant": tenant,
                    "start": 0,
                    "end": 0,
                    "count": 0,
                    "prev": "",
                    "anchors": {},
                    "buckets": [],
                }
            raise ValueError("range is out of bounds for an empty history")
        if start == end:
            raise ValueError("range must be a non-empty interval")
        if start >= total or end > total:
            raise ValueError("range is out of bounds")

        first_unit = self._first_unit_for(counts, start)
        last_unit = self._first_unit_for(counts, end - 1)

        # Emitted windows in physical order; seqs are assigned at the end so
        # the cross-window chain is strictly increasing.
        emitted: list[dict] = []
        sealed_index: dict[tuple[int, int], int] = {}
        predecessor: Optional[str] = None

        for ui in range(first_unit, last_unit + 1):
            unit = units[ui]
            with open(unit["path"], "rb") as handle:
                raw = handle.read()

            parts = unit["parts"]
            window_ends: list[int] = []
            running = 0
            for part in parts:
                running += part["size"]
                window_ends.append(running)
            tail_offset = running

            # Pending narrowed tail window: [blob, slots]. It holds one run
            # of physically consecutive interval lines, so its bytes contain
            # only interval records -- no other-tenant or out-of-range line.
            run: Optional[list] = None
            prev_tail_end: Optional[int] = None
            base = counts[ui - 1] if ui else 0
            local = base
            pos = 0

            def flush_tail() -> None:
                nonlocal run
                if not run:
                    run = None
                    return
                blob, slots = run
                emitted.append(
                    {
                        "name": unit["name"],
                        "size": len(blob),
                        "sha256": _sha256(blob),
                        "records": slots,
                    }
                )
                run = None

            for line_raw in raw.split(b"\n")[:-1]:
                line_start = pos
                line = line_raw + b"\n"
                pos += len(line)
                try:
                    record = st.decode_records(line)[0]
                except ValueError:
                    record = None
                is_tenant = record is not None and record["tenant"] == tenant
                included = is_tenant and start <= local < end

                if is_tenant and local == start:
                    predecessor = record["prev"]

                if included:
                    win_index = 0
                    while (
                        win_index < len(window_ends)
                        and line_start >= window_ends[win_index]
                    ):
                        win_index += 1
                    if win_index < len(window_ends):
                        # Preserved sealed window: reuse the manifest anchor.
                        flush_tail()
                        prev_tail_end = line_start + len(line)
                        window_start = window_ends[win_index - 1] if win_index else 0
                        key = (ui, win_index)
                        slot_pos = sealed_index.get(key)
                        if slot_pos is None:
                            part = parts[win_index]
                            slot_pos = len(emitted)
                            sealed_index[key] = slot_pos
                            emitted.append(
                                {
                                    "name": part["name"],
                                    "size": part["size"],
                                    "sha256": part["sha256"],
                                    "records": [],
                                }
                            )
                        emitted[slot_pos]["records"].append(
                            (local, line_start - window_start, record)
                        )
                    else:
                        # Growing tail: consecutive interval lines share one
                        # small window; any intervening physical line (another
                        # tenant, an out-of-range record, a bad line) splits it.
                        if run is None or line_start != prev_tail_end:
                            flush_tail()
                            run = [b"", []]
                        offset_in_run = len(run[0])
                        run[0] += line
                        run[1].append((local, offset_in_run, record))
                        prev_tail_end = line_start + len(line)
                else:
                    flush_tail()
                    prev_tail_end = None

                if is_tenant:
                    local += 1

            flush_tail()

        anchors = {
            seq: {
                "name": window["name"],
                "size": window["size"],
                "sha256": window["sha256"],
            }
            for seq, window in enumerate(emitted)
        }
        return {
            "tenant": tenant,
            "start": start,
            "end": end,
            "count": total,
            "prev": predecessor if predecessor is not None else "",
            "anchors": anchors,
            "buckets": [
                {"seq": seq, "records": window["records"]}
                for seq, window in enumerate(emitted)
            ],
        }

    @staticmethod
    def _first_unit_for(counts: list[int], index: int) -> int:
        """First unit whose cumulative tenant count is greater than ``index``."""
        for ui, cumulative in enumerate(counts):
            if cumulative > index:
                return ui
        return len(counts) - 1

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


def _write_all(fd: int, data: bytes) -> None:
    """Write every byte of ``data`` to ``fd``, tolerating short writes."""
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]
