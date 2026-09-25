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


def _same_anchor(a: dict, b: dict) -> bool:
    return (
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
