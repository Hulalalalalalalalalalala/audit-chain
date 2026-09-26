"""Offline range proofs for a tenant's contiguous index interval.

A proof is self-contained JSON data:

* ``tenant``/``start``/``end``/``count`` name the interval and the total
  number of records the tenant had when it was exported;
* ``prev`` is the digest the first interval record must link from (``""``
  when the interval begins at index zero);
* ``windows`` is an ordered list of byte-window anchors. Each anchor names
  its global window sequence number (strictly increasing across segments,
  so the cross-segment window chain is explicit), carries the window's
  byte size and sha256, and lists the interval records that live in that
  window with their byte offset inside it. Only windows that hold an
  interval record appear, and the only payloads present are those of the
  interval itself -- no out-of-interval record ever leaves the exporter.

An independent reader needs nothing but this proof and the public digest
function in :mod:`audit_chain.record`: every record's digest is recomputed,
the predecessor links are checked, the indices are checked to be exactly
``start .. end-1``, offsets are checked to fall inside the anchored
windows, and the window sequence is checked to be strictly increasing.
Damage outside the interval cannot affect this conclusion because no
out-of-interval byte participates in the check.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from . import record as rec

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
PROOF_VERSION = 1


def empty_proof(tenant: str) -> dict:
    """The empty-history conclusion for a tenant with no records."""
    return {
        "version": PROOF_VERSION,
        "tenant": tenant,
        "start": 0,
        "end": 0,
        "count": 0,
        "prev": "",
        "windows": [],
    }


def build_proof(material: dict) -> dict:
    """Assemble the public proof object from exporter-collected material."""
    if material.get("count") == 0:
        return empty_proof(material["tenant"])

    windows = []
    for bucket in material["buckets"]:
        anchor = material["anchors"][bucket["seq"]]
        windows.append(
            {
                "seq": bucket["seq"],
                "name": anchor["name"],
                "size": anchor["size"],
                "sha256": anchor["sha256"],
                "records": [
                    {"index": index, "offset": offset, "record": dict(record)}
                    for index, offset, record in bucket["records"]
                ],
            }
        )
    return {
        "version": PROOF_VERSION,
        "tenant": material["tenant"],
        "start": material["start"],
        "end": material["end"],
        "count": material["count"],
        "prev": material["prev"],
        "windows": windows,
    }


def verify_proof(
    proof: Any,
    *,
    tenant: Optional[str] = None,
    start: Optional[int] = None,
    end: Optional[int] = None,
) -> dict:
    """Independently verify a range proof.

    Returns ``{"ok": bool, "first_bad": i, "count": n, "start": s,
    "end": e, "tenant": t}`` where ``first_bad`` is the global tenant index
    of the first record that fails to link, is mis-indexed, or does not sit
    inside its anchored window. A structurally malformed proof raises
    ``ValueError``. Optional ``tenant``/``start``/``end`` bind the caller's
    request to the proof.
    """
    _require(
        isinstance(proof, dict) and proof.get("version") == PROOF_VERSION,
        "malformed range proof",
    )
    p_tenant = proof.get("tenant")
    p_start = proof.get("start")
    p_end = proof.get("end")
    p_count = proof.get("count")
    p_prev = proof.get("prev")
    windows = proof.get("windows")
    _require(isinstance(p_tenant, str), "malformed range proof: tenant")
    _require(_nonneg_int(p_start), "malformed range proof: start")
    _require(_nonneg_int(p_end), "malformed range proof: end")
    _require(_nonneg_int(p_count), "malformed range proof: count")
    _require(isinstance(p_prev, str), "malformed range proof: prev")
    _require(isinstance(windows, list), "malformed range proof: windows")
    if tenant is not None:
        _require(tenant == p_tenant, "proof is for a different tenant")
    if start is not None:
        _require(start == p_start, "proof covers a different start")
    if end is not None:
        _require(end == p_end, "proof covers a different end")

    if p_count == 0:
        _require(
            p_start == 0 and p_end == 0 and p_prev == "" and windows == [],
            "malformed empty proof",
        )
        return _verdict(p_tenant, 0, 0, -1)

    _require(p_start < p_end, "malformed range proof: empty interval")
    _require(p_end <= p_count, "malformed range proof: interval past history")

    first_bad = -1
    seen = 0
    previous_seq: Optional[int] = None
    expected_index = p_start
    expected_digest = p_prev

    def flag(index: int) -> None:
        nonlocal first_bad
        if first_bad == -1:
            first_bad = index

    for window in windows:
        _require(isinstance(window, dict), "malformed range proof: window")
        seq = window.get("seq")
        size = window.get("size")
        sha = window.get("sha256")
        records = window.get("records")
        _require(_nonneg_int(seq), "malformed range proof: window seq")
        _require(_nonneg_int(size), "malformed range proof: window size")
        _require(isinstance(sha, str) and bool(_HEX64.match(sha)), "bad window anchor")
        _require(
            isinstance(records, list) and records,
            "malformed range proof: window without records",
        )
        if previous_seq is not None and seq <= previous_seq:
            # Cross-segment windows must form a strictly increasing chain.
            flag(p_start)
        previous_seq = seq

        previous_offset = -1
        for item in records:
            _require(isinstance(item, dict), "malformed range proof: record slot")
            index = item.get("index")
            offset = item.get("offset")
            record = item.get("record")
            _require(_nonneg_int(index), "malformed range proof: record index")
            _require(_nonneg_int(offset), "malformed range proof: record offset")
            if index != expected_index:
                flag(expected_index)
            if offset <= previous_offset:
                flag(index)
            previous_offset = offset

            try:
                parsed = (
                    rec.parse_line(rec.canonical_json(record))
                    if isinstance(record, dict)
                    else None
                )
            except ValueError:
                parsed = None
            if parsed is None:
                flag(index)
                expected_index = index + 1
                seen += 1
                continue

            line_len = len((rec.canonical_json(parsed) + "\n").encode("utf-8"))
            if offset + line_len > size:
                # The record does not live inside the anchored window.
                flag(index)
            if parsed["tenant"] != p_tenant:
                flag(index)
            recomputed = rec.digest(parsed["prev"], parsed["payload"])
            if parsed["prev"] != expected_digest or parsed["digest"] != recomputed:
                flag(index)
            else:
                expected_digest = parsed["digest"]
            expected_index = index + 1
            seen += 1

    if seen != p_end - p_start:
        flag(p_start)
    if expected_index != p_end:
        flag(p_end)
    return _verdict(p_tenant, p_start, p_end, first_bad)


def extend_proof(proof: Any, path: str) -> dict:
    """Continue an exported range proof to the log's current prefix.

    ``proof`` is a previously exported (or combined) range proof and
    ``path`` the store it was exported from. The result is an ordinary
    version-1 range proof covering ``[proof["start"], n)``, where ``n``
    is the tenant's record count at the moment of the read -- the same
    shape :meth:`audit_chain.Chain.export_range` produces. Only records
    appended after ``proof["end"]`` are read from the store and chained,
    so the cost tracks the increment, never the total history length;
    the increment is spliced onto the input with :func:`combine_proofs`,
    so the result still carries only in-interval records plus the window
    anchors needed to attach the chain. With no new records the result
    is equivalent to the input and its offline verdict is unchanged.

    A non-dict proof raises ``TypeError``; a proof that is malformed
    (including a reversed interval) or does not verify raises
    ``ValueError``; a proof whose end lies beyond the log's intact
    prefix raises ``ValueError``; a missing log raises
    ``FileNotFoundError``.
    """
    if not isinstance(proof, dict):
        raise TypeError("proof must be a dict")
    from .chain import Chain

    return Chain(path).extend_proof(proof)


def clone_proof(proof: dict) -> dict:
    """A copy of a verified proof that shares no window or record."""
    return {
        "version": proof["version"],
        "tenant": proof["tenant"],
        "start": proof["start"],
        "end": proof["end"],
        "count": proof["count"],
        "prev": proof["prev"],
        "windows": [_clone_window(window) for window in proof["windows"]],
    }


def combine_proofs(left: Any, right: Any) -> dict:
    """Splice two contiguous proofs of the same tenant into one proof.

    The interval of ``right`` must begin exactly where ``left`` ends
    (``left["end"] == right["start"]``); the result then covers the union
    ``[left["start"], right["end"])`` and is itself an ordinary version-1
    proof verifiable through :func:`verify_proof`. The combined proof is
    re-verified before it is returned, so splicing can never produce a proof
    that does not independently check out.

    A non-dict argument raises ``TypeError`` (the same rule the on-chain
    append uses for its payload). Anything else that is not a legally
    exported, independently verifiable proof -- a tenant mismatch, a gap, an
    overlap, a reversed order, or a side that fails verification -- raises
    ``ValueError`` and yields no result.
    """
    if not isinstance(left, dict) or not isinstance(right, dict):
        raise TypeError("proofs must be dicts")

    # Both sides must be genuine exported proofs and must independently check
    # out before any splicing is attempted.
    try:
        left_verdict = verify_proof(left)
        right_verdict = verify_proof(right)
    except ValueError as exc:
        raise ValueError("cannot combine: proof is not a valid range proof") from exc
    if not left_verdict["ok"] or not right_verdict["ok"]:
        raise ValueError("cannot combine: a proof does not independently verify")

    if left["tenant"] != right["tenant"]:
        raise ValueError("cannot combine: proofs are for different tenants")
    if left["end"] != right["start"]:
        # One message covers gap, overlap and reversed ordering: the only
        # accepted relation is end-of-left exactly touching start-of-right.
        raise ValueError("cannot combine: intervals are not contiguous")

    if left["count"] == 0:
        # The empty-history proof only touches a non-empty proof at zero;
        # the union is then exactly the right side.
        merged_windows = [_clone_window(window) for window in right["windows"]]
    elif right["count"] == 0:
        merged_windows = [_clone_window(window) for window in left["windows"]]
    else:
        merged_windows = [_clone_window(window) for window in left["windows"]]
        first_right = right["windows"][0] if right["windows"] else None
        boundary = merged_windows[-1] if merged_windows else None
        if (
            boundary is not None
            and first_right is not None
            and _same_anchor(boundary, first_right)
        ):
            # The split landed inside one physical byte window: keep one
            # window and concatenate the records in index order.
            boundary["records"].extend(_clone_slot(slot) for slot in first_right["records"])
            rest = right["windows"][1:]
        else:
            rest = right["windows"]
        merged_windows.extend(_clone_window(window) for window in rest)

    # Seq numbers are local to each export, so renumber the merged chain from
    # zero; verification only relies on them being strictly increasing.
    for seq, window in enumerate(merged_windows):
        window["seq"] = seq

    combined = {
        "version": PROOF_VERSION,
        "tenant": left["tenant"],
        "start": left["start"],
        "end": right["end"],
        "count": max(left["count"], right["count"]),
        "prev": left["prev"],
        "windows": merged_windows,
    }
    verdict = verify_proof(combined)
    if not verdict["ok"]:
        raise ValueError("cannot combine: combined proof does not verify")
    return combined


def verify_proofs(proofs: Any) -> list[dict]:
    """Verify a batch of proofs, one verdict per proof, in input order.

    Each verdict has exactly the shape the on-chain ``Chain.verify`` returns
    -- ``{"ok": bool, "first_bad": i, "count": n}`` and nothing else. A proof
    whose content was tampered with yields an ``ok=False`` verdict carrying
    the real first bad index; verification of the remaining proofs continues.
    A structurally malformed proof likewise yields a corrupted verdict
    instead of interrupting the batch.

    The list itself being empty raises ``ValueError``; the argument or any
    element not being a dict raises ``TypeError``.
    """
    if not isinstance(proofs, list):
        raise TypeError("proofs must be a list")
    if not proofs:
        raise ValueError("proofs list must not be empty")

    verdicts: list[dict] = []
    for proof in proofs:
        if not isinstance(proof, dict):
            raise TypeError("each proof must be a dict")
        try:
            verdicts.append(_chain_verdict(verify_proof(proof)))
        except ValueError:
            # Structurally malformed: no chain walk was possible, so there is
            # no record-derived bad index. Report corruption at the earliest
            # index the proof itself claims, keeping the verdict shape.
            verdicts.append(_corrupted_verdict(proof))
    return verdicts


class ShardVerifier:
    """Incremental verifier for a stream of window shards of one interval.

    Shards are checked one at a time with :meth:`check`, in the order
    they were produced; each call returns a verdict of exactly the shape
    :func:`verify_proof` returns for that shard alone. Once every shard
    has been checked, :meth:`finish` returns the whole-interval verdict,
    item-wise identical to the offline verdict of a single proof
    exported over the same interval: the shard-to-shard chain links are
    tracked across the stream, so a break still lands on the real first
    bad record. A tampered or malformed shard reports corruption in its
    own verdict without affecting the other shards' verdicts, and the
    stream keeps going in input order.

    Optional ``tenant``/``start``/``end`` bind the caller's request to
    the stream, exactly as the :func:`verify_proof` binds do. A non-dict
    shard raises ``TypeError``; a shard that does not begin where the
    previous one ended (a gap or an overlap), or one for a different
    tenant, raises ``ValueError`` and is not absorbed. :meth:`finish`
    before any shard was checked raises ``TypeError``.
    """

    def __init__(
        self,
        *,
        tenant: Optional[str] = None,
        start: Optional[int] = None,
        end: Optional[int] = None,
    ):
        self._tenant = tenant
        self._bound_start = start
        self._bound_end = end
        # The index the next shard must start at; None accepts the next
        # shard's position (initial state, or resync after a malformed
        # shard whose claimed end could not be read).
        self._expected_next = start
        # The digest the next shard's first record must link from, or
        # None when the previous shard could not vouch for one.
        self._prev_outgoing: Optional[str] = None
        self._first_bad = -1
        self._stream_start: Optional[int] = None
        self._stream_end: Optional[int] = None
        self._checked = 0

    def check(self, shard: dict) -> dict:
        """Check one shard and return its standalone verdict."""
        if not isinstance(shard, dict):
            raise TypeError("each shard must be a dict")
        try:
            verdict = verify_proof(shard)
        except ValueError:
            # Structurally malformed: no chain walk was possible. Report
            # corruption at the earliest index the shard claims, keep
            # the verdict shape, and resync the stream from whatever
            # end the shard claims so the remaining shards still check.
            verdict = _corrupted_shard_verdict(
                shard, self._expected_next, self._tenant
            )
            self._absorb(verdict, shard, valid=False)
            return verdict
        if self._tenant is not None and verdict["tenant"] != self._tenant:
            raise ValueError("shard is for a different tenant")
        if (
            self._expected_next is not None
            and verdict["start"] != self._expected_next
        ):
            raise ValueError("shard stream has a gap or overlap")
        self._absorb(verdict, shard, valid=True)
        return verdict

    def finish(self) -> dict:
        """The whole-interval verdict once every shard was checked."""
        if self._checked == 0:
            raise TypeError("shard stream must not be empty")
        if self._bound_start is not None and self._stream_start != self._bound_start:
            raise ValueError("shards do not cover the bound start")
        if self._bound_end is not None and self._stream_end != self._bound_end:
            raise ValueError("shards do not cover the bound end")
        return _verdict(
            self._tenant if self._tenant is not None else "",
            self._stream_start,
            self._stream_end,
            self._first_bad,
        )

    def _absorb(self, verdict: dict, shard: dict, *, valid: bool) -> None:
        if self._tenant is None and verdict["tenant"]:
            self._tenant = verdict["tenant"]
        if self._stream_start is None:
            self._stream_start = verdict["start"]
        self._stream_end = verdict["end"]
        if valid:
            # Cross-shard link: the first record of this shard must link
            # from the digest the previous shard's chain ended on, the
            # same check a one-shot verification applies at that index.
            if (
                self._prev_outgoing is not None
                and shard["prev"] != self._prev_outgoing
            ):
                self._flag(verdict["start"])
            self._prev_outgoing = _proof_outgoing_digest(shard)
            self._expected_next = verdict["end"]
        else:
            # A malformed shard cannot vouch for an outgoing digest, and
            # only a readable claimed end may pin the next shard's
            # position; otherwise the next shard resyncs the stream.
            self._prev_outgoing = None
            claimed_end = shard.get("end")
            self._expected_next = claimed_end if _nonneg_int(claimed_end) else None
        if verdict["first_bad"] != -1:
            self._flag(verdict["first_bad"])
        self._checked += 1

    def _flag(self, index: int) -> None:
        if self._first_bad == -1 or index < self._first_bad:
            self._first_bad = index


def verify_proof_stream(
    shards: Any,
    *,
    tenant: Optional[str] = None,
    start: Optional[int] = None,
    end: Optional[int] = None,
) -> dict:
    """Verify a stream of window shards covering one interval.

    ``shards`` is any iterable of proofs tiling one interval -- for
    example the iterator :meth:`audit_chain.Chain.export_shards`
    returns -- and is consumed lazily, one shard at a time. Returns
    ``{"shards": [...], "total": {...}}``: one verdict per shard in
    input order, then the whole-interval verdict, each in exactly the
    shape :func:`verify_proof` returns. The total is item-wise identical
    to the offline verdict of a single proof exported over the same
    interval, with ``first_bad`` on the real first bad record. A
    tampered or malformed shard yields a corrupted verdict carrying the
    real first bad index without interrupting the remaining shards.

    An empty shard stream or a non-dict element raises ``TypeError``; a
    gap or overlap between shards raises ``ValueError``. Optional
    ``tenant``/``start``/``end`` bind the caller's request to the
    stream, exactly as the :func:`verify_proof` binds do.
    """
    if isinstance(shards, (dict, str, bytes, bytearray)):
        raise TypeError("shards must be an iterable of proof dicts")
    try:
        iterator = iter(shards)
    except TypeError:
        raise TypeError("shards must be an iterable of proof dicts") from None

    verifier = ShardVerifier(tenant=tenant, start=start, end=end)
    verdicts = [verifier.check(shard) for shard in iterator]
    return {"shards": verdicts, "total": verifier.finish()}


def _proof_outgoing_digest(proof: dict) -> str:
    """The digest a successor shard's first record must link from.

    Replays the proof's own chain state with the same update rule
    :func:`verify_proof` applies -- the digest of the last record that
    linked and recomputed cleanly, seeded with the proof's ``prev`` --
    so a sharded stream tracks the cross-shard links exactly the way a
    one-shot verification of the whole interval does.
    """
    expected = proof["prev"]
    for window in proof["windows"]:
        for item in window["records"]:
            record = item["record"]
            try:
                parsed = (
                    rec.parse_line(rec.canonical_json(record))
                    if isinstance(record, dict)
                    else None
                )
            except ValueError:
                parsed = None
            if parsed is None:
                continue
            recomputed = rec.digest(parsed["prev"], parsed["payload"])
            if parsed["prev"] == expected and parsed["digest"] == recomputed:
                expected = parsed["digest"]
    return expected


def _corrupted_shard_verdict(
    shard: dict, expected_next: Optional[int], tenant: Optional[str]
) -> dict:
    """Corrupted verdict for a malformed shard, in the proof-verdict shape."""
    claimed_start = shard.get("start")
    claimed_end = shard.get("end")
    claimed_tenant = shard.get("tenant")
    if not _nonneg_int(claimed_start):
        claimed_start = expected_next if expected_next is not None else 0
    if not _nonneg_int(claimed_end) or claimed_end < claimed_start:
        claimed_end = claimed_start
    if not isinstance(claimed_tenant, str):
        claimed_tenant = tenant if tenant is not None else ""
    return {
        "ok": False,
        "first_bad": claimed_start,
        "count": claimed_end - claimed_start,
        "start": claimed_start,
        "end": claimed_end,
        "tenant": claimed_tenant,
    }


def _same_anchor(a: dict, b: dict) -> bool:    return (
        a["name"] == b["name"] and a["size"] == b["size"] and a["sha256"] == b["sha256"]
    )


def _clone_slot(slot: dict) -> dict:
    return {
        "index": slot["index"],
        "offset": slot["offset"],
        "record": dict(slot["record"]),
    }


def _clone_window(window: dict) -> dict:
    return {
        "seq": window["seq"],
        "name": window["name"],
        "size": window["size"],
        "sha256": window["sha256"],
        "records": [_clone_slot(slot) for slot in window["records"]],
    }


def _chain_verdict(verdict: dict) -> dict:
    """Project a proof verdict onto the on-chain verdict's three keys."""
    return {
        "ok": verdict["ok"],
        "first_bad": verdict["first_bad"],
        "count": verdict["count"],
    }


def _corrupted_verdict(proof: dict) -> dict:
    start = proof.get("start")
    end = proof.get("end")
    if not _nonneg_int(start):
        start = 0
    if not _nonneg_int(end) or end < start:
        end = start
    return {
        "ok": False,
        "first_bad": start,
        "count": end - start,
    }


def _verdict(tenant: str, start: int, end: int, first_bad: int) -> dict:
    return {
        "ok": first_bad == -1,
        "first_bad": first_bad,
        "count": end - start,
        "start": start,
        "end": end,
        "tenant": tenant,
    }


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _nonneg_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0
