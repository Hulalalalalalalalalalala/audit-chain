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
* sealed segments can be migrated online into a caller-specified archive
  directory (cold tier): the signed manifest records the archive location
  and keeps every migrated segment's window material, so append, query,
  verify, rotate, compact, recover and export all work unchanged across
  the two tiers, and a process killed mid-migration reopens onto either
  the pre-archive or the complete post-archive topology -- never a half
  moved segment or copies left in both tiers;
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
* ``extend_proof`` continues such an exported proof onto the current
  history prefix, reading only the records past the proof's end, so the
  cost tracks the increment rather than the total history length;
* ``recover`` is the explicit entry point that truncates a half-written
  tail line left by a killed process.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import os
from typing import Any, Optional

from . import record as rec
from . import storage as st

_ENCODING = "utf-8"
_FILE_UNIT = "$"
# os.open() defaults to text mode on Windows, which silently rewrites "\n"
# into "\r\n" (and re-translates bytes that already carry CRLF). The record
# format is defined byte for byte around a single "\n" terminator -- window
# sizes/hashes, byte offsets and folds all depend on that -- so every data
# fd must be opened binary. O_BINARY is absent (and therefore zero) on
# POSIX, where this changes nothing.
_O_BINARY = getattr(os, "O_BINARY", 0)
_DEFAULT_LOCK_TIMEOUT = 10.0
_DEFAULT_MAX_SEGMENTS = 2
# Present in the store directory while an archive migration is in flight;
# left behind only by a killed migration and cleared by the next healer.
_ARCHIVE_MARKER = ".archiving"


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

        A read escalates when the live path is absent and a migration
        backup is waiting -- without adoption there is nothing to read --
        or when an archive migration marker is present: the marker means a
        migration was interrupted between its first manifest commit and its
        final cleanup, so the tree may physically straddle the two tiers
        (a hot duplicate of an archived segment, or a staged copy/temp in
        the archive directory) and must be settled onto exactly one
        topology before reading. Both checks are bare ``exists`` probes, so
        the ordinary read path pays no extra I/O. Every other leftover
        (staging directory, an unreferenced segment from a rotation or
        compaction killed before/after its manifest commit, a merge temp
        file, a post-publish backup) is inert while the committed manifest
        stays authoritative, so reads leave it untouched and the next
        writer (exclusive) reaps it -- matching the baseline rule that
        reads never move garbage out from under other readers.
        """
        if not os.path.exists(self.path) and os.path.exists(
            self.path + ".pre-segment"
        ):
            return True
        return layout.kind == "dir" and os.path.exists(
            os.path.join(layout.root, _ARCHIVE_MARKER)
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
            self._gc_archive(layout, manifest)
            # The migration is settled once the tiers agree with the
            # committed manifest; drop the in-flight marker so shared reads
            # stop escalating.
            with contextlib.suppress(OSError):
                os.remove(os.path.join(layout.root, _ARCHIVE_MARKER))
                st.fsync_dir(layout.root)
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
                "path": self._segment_path(layout, manifest, segment),
                "sealed": segment["sealed"],
                "parts": [dict(part) for part in segment["parts"]],
            }
            for segment in manifest["segments"]
        ]

    @staticmethod
    def _segment_path(layout: st.Layout, manifest: dict, segment: dict) -> str:
        """Where a manifest segment's bytes live: hot store or archive."""
        archive_dir = manifest.get("archive")
        if segment.get("archived") and archive_dir:
            return os.path.join(archive_dir, segment["name"])
        return layout.segment_path(segment["name"])

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
            states, entries = self._walk(units, layout)
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
            fd = os.open(
                target, os.O_WRONLY | os.O_CREAT | os.O_APPEND | _O_BINARY, 0o600
            )
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
            # only, never a rehash of the whole file. The continuation is
            # computed from the entries this same locked section
            # authenticated above -- the cache file is not re-read here, so
            # nothing swapped onto disk behind the walk can be laundered
            # into a trusted prefix.
            self._warm_append_cache(layout, units[-1], entries, states, record, line)
        return record

    def _warm_append_cache(
        self,
        layout: st.Layout,
        unit: dict,
        entries: dict,
        states: dict,
        record: dict,
        line: str,
    ) -> None:
        """Extend the just-authenticated cache with one appended record.

        ``entries``/``states`` come from the verification walk that ran
        under the same exclusive lock moments before the record was
        written, so the cached prefix they describe was authenticated in
        this critical section; only the new line is hashed on top of it.
        """
        name = unit["name"]
        line_bytes = (line + "\n").encode(_ENCODING)
        continued = {tenant: list(state) for tenant, state in states.items()}
        count, _head, bad = continued.get(record["tenant"], [0, "", -1])
        continued[record["tenant"]] = [count + 1, record["digest"], bad]
        entry = entries.get(name)
        if entry is None:
            # First append to a unit that did not exist at walk time.
            records, parts, fold = 0, [dict(p) for p in unit["parts"]], _FOLD_BLANK
        else:
            records = entry["records"]
            parts = entry.get("parts", [])
            fold = entry["fold"]
        entries[name] = _cache_entry(
            records + 1,
            os.stat(unit["path"]),
            parts,
            continued,
            _extend_fold(fold, [line_bytes]),
        )
        st.save_cache(layout, entries)

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
            fd = os.open(target, os.O_WRONLY | _O_BINARY)
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
                removed: list[dict] = []
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
                for source in removed:
                    with contextlib.suppress(FileNotFoundError):
                        os.remove(self._segment_path(layout, manifest, source))
                    st.crash_point("compact:during_delete")
                st.fsync_dir(layout.root)
                st.crash_point("compact:after_delete")
            count = len(manifest["segments"])
        return {"segments": count}

    # ------------------------------------------------------------------
    # Online archiving (cold tier)
    # ------------------------------------------------------------------

    def archive(self, archive_dir: str) -> dict:
        """Migrate every sealed segment to ``archive_dir``, online.

        The archive location is caller-specified and recorded in the
        self-authenticating manifest, so every later open of this store
        resolves archived segments across the two tiers with no extra
        arguments. Migrated segments keep their names, window material and
        position in the manifest: per-tenant indices, rotation order,
        verdicts and exported proofs are exactly what they were before the
        move, and the hot directory no longer holds the migrated bytes.

        The migration is online and crash-safe. It runs under the same
        exclusive lock as append/rotate/compact, so a concurrent caller
        always observes one complete prefix -- the pre-archive or the
        post-archive topology, never a mix. The location is committed
        first, then every segment is copied through a temp file + fsync +
        atomic rename, then a second manifest commit marks the segments
        archived, and only then are the hot copies removed. A process
        killed in any window reopens onto one complete topology: staged
        copies, orphans and hot duplicates are reaped deterministically,
        and no segment is ever lost or left in both tiers.

        Returns ``{"archived": n}`` -- the number of segments this call
        migrated (zero when every sealed segment is already archived).
        Raises ``ValueError`` on a legacy file layout (rotate first), a
        corrupt chain, an archive directory inside the store itself, or a
        different location than an earlier archive call recorded.
        """
        dest = os.path.abspath(os.fspath(archive_dir))
        with self._locked(exclusive=True) as layout:
            if layout.kind != "dir":
                raise ValueError("log is not segmented; call rotate() first")
            if os.path.normpath(dest) == os.path.normpath(
                os.path.abspath(layout.root)
            ):
                raise ValueError("archive directory must differ from the store")
            if os.path.exists(os.path.join(dest, st.MANIFEST_NAME)):
                raise ValueError("archive directory is itself a segment store")
            units = self._view(layout)
            manifest = st.load_manifest(layout)

            # Never migrate a damaged log.
            states, _ = self._walk(units, layout)
            for _count, _head, bad in states.values():
                if bad != -1:
                    raise ValueError("corrupt audit chain")

            recorded = manifest.get("archive")
            if recorded is not None and os.path.normpath(recorded) != os.path.normpath(
                dest
            ):
                raise ValueError("log already archives to a different location")

            targets = [
                segment
                for segment in manifest["segments"]
                if segment["sealed"] and not segment.get("archived")
            ]
            if not targets:
                return {"archived": 0}

            os.makedirs(dest, exist_ok=True)
            # Raise the in-flight marker before the first commit: until the
            # migration is fully settled the marker tells every reopening
            # reader/writer to finish the tier housekeeping first, so a
            # kill anywhere in the middle never reopens onto copies kept in
            # both tiers.
            marker = os.path.join(layout.root, _ARCHIVE_MARKER)
            fd = os.open(
                marker, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _O_BINARY, 0o600
            )
            os.close(fd)
            st.fsync_dir(layout.root)
            st.crash_point("archive:after_marker")
            if recorded is None:
                # Commit the location first: a kill during the copies then
                # still reopens knowing where staged bytes may lie, and the
                # reaper settles the tree back onto the hot-only topology.
                manifest["archive"] = dest
                st.save_manifest(layout, manifest)
                st.crash_point("archive:after_location")

            for segment in targets:
                source = layout.segment_path(segment["name"])
                # The pre-walk may have vouched for this segment from the
                # authenticated cache alone; re-check its frozen windows
                # against the bytes before they become the only copy.
                if not st.verify_windows(source, segment["parts"]):
                    raise ValueError("corrupt audit segment")
                with open(source, "rb") as handle:
                    raw = handle.read()
                self._publish_bytes(dest, segment["name"], raw, phase="archive", kind="copy")
                st.crash_point("archive:after_copy")

            migrated = {segment["name"] for segment in targets}
            for segment in manifest["segments"]:
                if segment["name"] in migrated:
                    segment["archived"] = True
            st.save_manifest(layout, manifest)
            st.crash_point("archive:after_manifest")

            # Keep the verify cache warm across the move: the bytes are
            # identical, only each migrated segment's stat identity changed.
            cache = st.load_cache(layout)
            if cache is not None:
                cached_segments = cache["segments"]
                changed = False
                for name in migrated:
                    entry = cached_segments.get(name)
                    if entry is not None:
                        new_stat = os.stat(os.path.join(dest, name))
                        entry["size"] = new_stat.st_size
                        entry["mtime_ns"] = new_stat.st_mtime_ns
                        entry["ctime_ns"] = new_stat.st_ctime_ns
                        changed = True
                if changed:
                    st.save_cache(layout, cached_segments)

            # The post-archive topology is durable; the hot copies are now
            # unreferenced and their removal is completed (or reaped on the
            # next open) without ever exposing a mixed topology.
            for name in migrated:
                with contextlib.suppress(FileNotFoundError):
                    os.remove(layout.segment_path(name))
                st.crash_point("archive:during_delete")
            st.fsync_dir(layout.root)
            # Settled: lower the in-flight marker last of all.
            with contextlib.suppress(FileNotFoundError):
                os.remove(marker)
            st.fsync_dir(layout.root)
            st.crash_point("archive:after_delete")
        return {"archived": len(migrated)}

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

    def _gc_archive(self, layout: st.Layout, manifest: dict) -> None:
        """Settle an archived store onto exactly one topology.

        A migration killed after its manifest commit leaves hot duplicates
        of archived segments; one killed before it leaves copied-but-
        unreferenced segments (or staging temp files) in the archive
        directory. Both are removed here so a reopened store never keeps
        copies of one segment in the two tiers.
        """
        archive_dir = manifest.get("archive")
        if not archive_dir:
            return
        changed = False
        for segment in manifest["segments"]:
            if not segment.get("archived"):
                continue
            hot = layout.segment_path(segment["name"])
            if os.path.exists(hot):
                with contextlib.suppress(OSError):
                    os.remove(hot)
                    changed = True
        if changed:
            st.fsync_dir(layout.root)
        if not os.path.isdir(archive_dir):
            return
        archived = {
            segment["name"] for segment in manifest["segments"] if segment.get("archived")
        }
        changed = False
        for name in os.listdir(archive_dir):
            # The archive tier holds exactly the segments the committed
            # manifest marks archived; any other segment file here is a
            # staged copy or merge orphan whose authoritative bytes live
            # in the hot tier.
            if (st.seg_seq(name) is not None and name not in archived) or (
                name.startswith(".") and name.endswith(".tmp")
            ):
                with contextlib.suppress(OSError):
                    os.remove(os.path.join(archive_dir, name))
                    changed = True
        if changed:
            st.fsync_dir(archive_dir)

    def _publish_bytes(
        self,
        directory: str,
        name: str,
        raw: bytes,
        *,
        phase: str = "compact",
        kind: str = "merge",
    ) -> str:
        """Stage ``raw`` in a temp file and rename it to ``directory/name``."""
        target = os.path.join(directory, name)
        tmp_path = os.path.join(directory, st._tmp_name_for(name))
        try:
            fd = os.open(
                tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _O_BINARY, 0o600
            )
            try:
                _write_all(fd, raw)
                st.crash_point(f"{phase}:before_{kind}_fsync")
                os.fsync(fd)
            finally:
                os.close(fd)
            st.crash_point(f"{phase}:after_{kind}_write")
            os.replace(tmp_path, target)
            st.fsync_dir(directory)
            st.crash_point(f"{phase}:after_{kind}_rename")
        except BaseException:
            with contextlib.suppress(OSError):
                os.remove(tmp_path)
            raise
        return target

    def _merge_all(
        self, layout: st.Layout, manifest: dict, cache_segments: dict
    ) -> list[dict]:
        """Fold every segment, active included, into one active segment."""
        sources = manifest["segments"]
        merged, parts, carried = self._compose(layout, manifest, sources, cache_segments)
        name = st.seg_name(max(st.seg_seq(s["name"]) for s in sources) + 1)
        # The active segment always stays in the hot tier.
        target = self._publish_bytes(layout.root, name, merged)
        for source in sources:
            cache_segments.pop(source["name"], None)
        if carried is not None:
            cache_segments[name] = _cache_entry(
                carried["records"],
                os.stat(target),
                parts,
                _states_from(carried),
                _fold_of_bytes(merged),
            )
        manifest["segments"] = [
            {"name": name, "sealed": False, "parts": parts}
        ]
        manifest["active"] = name
        return list(sources)

    def _merge_pair(
        self, layout: st.Layout, manifest: dict, cache_segments: dict
    ) -> list[dict]:
        """Merge the two oldest segments into one new sealed segment."""
        sources = manifest["segments"][:2]
        merged, parts, carried = self._compose(layout, manifest, sources, cache_segments)
        name = st.seg_name(
            max(st.seg_seq(s["name"]) for s in manifest["segments"]) + 1
        )
        # A merge of exclusively archived sources stays in the archive tier;
        # anything else is published hot.
        to_archive = all(source.get("archived") for source in sources)
        directory = manifest["archive"] if to_archive else layout.root
        target = self._publish_bytes(directory, name, merged)
        merged_segment = {"name": name, "sealed": True, "parts": parts}
        if to_archive:
            merged_segment["archived"] = True
        manifest["segments"] = [merged_segment] + manifest["segments"][2:]
        for source in sources:
            cache_segments.pop(source["name"], None)
        if carried is not None:
            cache_segments[name] = _cache_entry(
                carried["records"],
                os.stat(target),
                parts,
                _states_from(carried),
                _fold_of_bytes(merged),
            )
        return list(sources)

    def _compose(
        self,
        layout: st.Layout,
        manifest: dict,
        sources: list[dict],
        cache_segments: dict,
    ) -> tuple[bytes, list[dict], Optional[dict]]:
        """Concatenate source bytes and windows, carrying warm cached states."""
        chunks: list[bytes] = []
        parts: list[dict] = []
        for source in sources:
            path = self._segment_path(layout, manifest, source)
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
            entry_fold = entry.get("fold") if entry is not None else None

            if (
                entry is not None
                and entry_fold is not None
                and not desynced
                and self._entry_fresh(entry, stat, unit)
            ):
                self._adopt_states(states, entry)
                total_records = entry["records"]
                entries[name] = _cache_entry(
                    total_records, stat, entry["parts"], states, entry_fold
                )
                continue

            growth = (
                entry is not None
                and entry_fold is not None
                and not desynced
                and not unit["sealed"]
                and stat.st_size > entry["size"]
                and entry.get("parts", []) == unit["parts"]
            )
            if growth:
                # Appended-only growth on the active unit. Before the
                # cache's cumulative states are continued, the bytes the
                # cache was built on authenticate themselves byte for byte:
                # a fold over every complete line up to the cached size
                # must equal the fold stored in the (tag-authenticated)
                # cache. A rewritten prefix -- stale digests, recomputed
                # digests, edited bytes behind preserved manifest windows,
                # a shifted boundary -- changes that fold, so the
                # continuation is refused and the walk falls through to a
                # complete re-derivation, whose verdict equals a full
                # verification and whose first bad index is the real
                # position rather than the first new line.
                with open(path, "rb") as handle:
                    raw = handle.read()
                prefix_raw = raw[: entry["size"]]
                tail_raw = raw[entry["size"] :]
                prefix_lines = _split_whole_lines(prefix_raw)
                tail_lines = _split_whole_lines(tail_raw)
                prefix_ok = (
                    prefix_lines is not None
                    and _fold_lines(prefix_lines) == entry_fold
                )
                if prefix_ok and tail_lines is not None:
                    candidate = {
                        tenant: list(state)
                        for tenant, state in states.items()
                    }
                    self._adopt_states(candidate, entry)
                    before_bad = {
                        tenant: state[2] for tenant, state in candidate.items()
                    }
                    tail_records = st.decode_records(b"".join(tail_lines))
                    self._apply_records(tail_records, candidate)
                    tail_broken = any(
                        state[2] != before_bad.get(tenant, -1)
                        for tenant, state in candidate.items()
                    )
                    if not tail_broken:
                        states.clear()
                        states.update(candidate)
                        total_records = entry["records"] + len(tail_records)
                        new_fold = _extend_fold(entry_fold, tail_lines)
                        entries[name] = _cache_entry(
                            total_records,
                            stat,
                            entry.get("parts", []),
                            states,
                            new_fold,
                        )
                        continue
                # Prefix authentication failed or the boundary moved:
                # re-derive this unit completely below.

            # Cold unit, shrink, same-size rewrite, any change to a sealed
            # unit, a unit following one that desynced, or a growth whose
            # cached prefix failed authentication: full parse; sealed windows
            # are re-authenticated and every link is re-derived.
            desynced = True
            walked, parts, failed_tenants, fold = self._walk_bytes(unit, states)
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
            entries[name] = _cache_entry(total_records, stat, parts, states, fold)

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
    ) -> tuple[int, list[dict], dict, str]:
        """Parse and chain one unit's bytes.

        Returns ``(record_count, cache_parts, failed_tenants, fold)`` where
        ``failed_tenants`` maps each tenant with a record in a
        content-hash-failed window to that record's global index, and
        ``fold`` is the extendable byte fingerprint of the unit's complete
        lines.

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
        # split_records guaranteed raw ends in a terminator, so this folds
        # every complete line exactly as the continuation branch will.
        fold = _fold_of_bytes(raw)
        return len(lines), parts, first_index, fold

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

    def extend_proof(self, proof: Any) -> dict:
        """Continue an exported range proof onto the current history prefix.

        ``proof`` is a proof previously produced by :meth:`export_range`
        (or spliced from such proofs). The result is an ordinary version-1
        proof -- the same shape :meth:`export_range` returns -- covering
        ``[proof["start"], N)`` where ``N`` is the tenant's record count at
        the moment of the read, verifiable through
        :func:`audit_chain.proof.verify_proof` like any exported proof.

        Only records past ``proof["end"]`` are read from the store: the
        tenant's current count and head come from the same incremental
        walk ``verify`` uses (a warm, authenticated cache is adopted with
        no record reads at all) and the increment is collected through the
        bounded export path, so reads, digest work and memory track the
        increment, never the total history length. A never-verified or
        altered store transparently falls back to one ordered scan with
        identical conclusions. The whole read runs under the shared lock
        on one fixed unit list, so a concurrent append, rotation,
        compaction or archive migration yields the proof of exactly one
        complete prefix -- never a mixed topology. The result still
        carries only the covered interval's chained records plus the
        window anchors needed to attach them; no out-of-interval payload
        is included.

        When the history has no records past the proof's end the returned
        proof is equivalent to the input and its offline verdict is
        unchanged. A non-dict proof raises ``TypeError``. A malformed,
        reversed or non-verifying proof raises ``ValueError``, as does a
        proof whose end lies beyond the intact prefix (a shortened,
        rewritten or corrupt history) or one whose terminal digest the
        current chain does not descend from. A missing log raises
        ``FileNotFoundError``. The store is never written: like
        :meth:`export_range` the extension only reads, so an interrupted
        extension leaves no temporary files or half-written state behind
        and re-extending is unaffected.
        """
        from . import proof as pf

        if not isinstance(proof, dict):
            raise TypeError("proof must be a dict")
        # The input must be a genuine, independently verifiable exported
        # proof before any continuation is attempted.
        try:
            verdict = pf.verify_proof(proof)
        except ValueError as exc:
            raise ValueError(
                "cannot extend: proof is not a valid range proof"
            ) from exc
        if not verdict["ok"]:
            raise ValueError("cannot extend: proof does not independently verify")

        tenant = proof["tenant"]
        end = proof["end"]
        # The digest the verified interval chains up to: the first record
        # after the proof's end must link from exactly this digest.
        terminal = proof["prev"]
        for window in proof["windows"]:
            for item in window["records"]:
                terminal = item["record"]["digest"]

        with self._locked(exclusive=False) as layout:
            self._require_present(layout)
            units = self._snapshot_units(layout, tolerate_metadata=True)
            # Read-only like export_range: the walk may adopt a warm,
            # authenticated cache but never persists one, so an interrupted
            # extension cannot leave a half-written sidecar behind.
            try:
                states, _ = self._walk(units, layout, persist=False)
            except st.AuditMetadataError:
                # Tampered metadata cannot vouch for anything: re-derive
                # from the bytes themselves, exactly as verify() does.
                states, _ = self._walk(units, layout, ignore_cache=True, persist=False)

            state = states.get(tenant)
            count, head, bad = state if state is not None else (0, "", -1)
            if bad != -1:
                raise ValueError("corrupt audit chain")
            if end > count:
                raise ValueError(
                    "cannot extend: proof end is beyond the intact prefix"
                )

            if count == end:
                # No new records: the input already covers the full prefix.
                # It is only equivalent to the current history when the
                # re-derived chain ends on the proof's own terminal digest.
                if head != terminal:
                    raise ValueError(
                        "cannot extend: proof does not match the current history"
                    )
                return copy.deepcopy(proof)

            guide = self._export_guide(units, layout, tenant)
            if guide is not None:
                material = self._collect_range_bounded(
                    units, tenant, end, count, guide
                )
            else:
                material = self._collect_range(units, tenant, end, count)
            increment = pf.build_proof(material)

        # Splice offline: the increment's first record must link from the
        # proof's terminal digest, so a history rewritten behind the proof
        # fails here even when its chain still re-derives.
        return pf.combine_proofs(proof, increment)

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
    records: int,
    stat: os.stat_result,
    parts: list[dict],
    states: dict[str, list],
    fold: str,
) -> dict:
    return {
        "records": records,
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "ctime_ns": stat.st_ctime_ns,
        "parts": parts,
        "fold": fold,
        "tenants": {tenant: list(state) for tenant, state in states.items()},
    }


# Empty fold seed and the per-line chaining. A fold is a byte-for-byte
# fingerprint of a unit's complete lines that can be extended over appended
# lines in O(new bytes) without re-reading the prefix: the cache stores the
# authenticated fold at the cached size, so a continued verify first proves
# every byte before that boundary is unchanged before trusting any cached
# cumulative state. A rewritten prefix (stale or recomputed digests, bytes
# edited behind preserved manifest windows) changes the fold and forces a
# full recompute. Chaining on the hex digest keeps this working under a
# sha256 stand-in that only exposes ``update``/``hexdigest``.
_FOLD_BLANK = hashlib.sha256(b"").hexdigest()


def _fold_accumulate(acc: str, lines: list[bytes]) -> str:
    for line in lines:
        acc = hashlib.sha256(acc.encode("ascii") + line).hexdigest()
    return acc


def _fold_lines(lines: list[bytes]) -> str:
    return _fold_accumulate(_FOLD_BLANK, lines)


def _extend_fold(fold: str, lines: list[bytes]) -> str:
    return _fold_accumulate(fold, lines)


def _split_whole_lines(raw: bytes) -> Optional[list[bytes]]:
    """Split bytes that are exactly a sequence of newline-ended lines.

    Returns the lines (each with its terminator) or None when the bytes end
    in a partial line -- which, at a cached-size boundary, means the prefix
    was rewritten and the boundary moved mid-line.
    """
    if raw == b"":
        return []
    if not raw.endswith(b"\n"):
        return None
    # Canonical JSON escapes embedded newlines, so a raw 0x0A is only ever a
    # record terminator.
    return [piece + b"\n" for piece in raw.split(b"\n")[:-1]]


def _fold_of_bytes(raw: bytes) -> str:
    lines = _split_whole_lines(raw)
    return _fold_lines(lines if lines is not None else [])


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
