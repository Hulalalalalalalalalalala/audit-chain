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

Two proofs exported for one tenant can be joined with
:func:`combine_proofs` when their intervals touch: the result is again an
ordinary proof of the union interval, verifiable by :func:`verify_proof`
alone. :func:`verify_proofs` checks a whole batch in one call, returning
one verdict per proof in the caller's order, each shaped like the on-chain
verify result.
"""

from __future__ import annotations

import copy
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
    """Join two adjacent proofs of one tenant into their union proof.

    Both sides must be genuine, independently verifiable proofs (as produced
    by ``export_range``) with ``left.end == right.start``; the combined
    proof covers ``[left.start, right.end)`` and verifies with
    :func:`verify_proof` alone, exactly like a direct export of the union
    interval. Combination is deterministic and associative: joining three
    adjacent proofs in either grouping yields the same proof.

    Raises ``TypeError`` when either argument is not a dict (the same
    convention as ``Chain.append``), and ``ValueError`` when a side is
    malformed or does not verify on its own, when the tenants differ, when
    the intervals overlap, leave a gap or run in reverse, or when the two
    sides cannot form one consistent, verifiable proof.
    """
    if not isinstance(left, dict) or not isinstance(right, dict):
        raise TypeError("proofs must be dicts")
    for side in (left, right):
        if not verify_proof(side)["ok"]:
            raise ValueError("proof does not verify on its own")
    if left["tenant"] != right["tenant"]:
        raise ValueError("proofs are for different tenants")
    if left["end"] != right["start"]:
        raise ValueError("proof intervals are not adjacent")

    left_windows = copy.deepcopy(left["windows"])
    right_windows = copy.deepcopy(right["windows"])
    if left["count"] and right["count"]:
        # The chain link across the junction must hold, or the combined
        # proof could never verify on its own.
        last_digest = left_windows[-1]["records"][-1]["record"]["digest"]
        _require(right["prev"] == last_digest, "proofs do not chain")
    if left_windows and right_windows:
        tail = left_windows[-1]
        head = right_windows[0]
        if tail["seq"] == head["seq"]:
            # The interval boundary sits inside one shared byte window:
            # merge the two record runs into that window's anchor.
            for key in ("name", "size", "sha256"):
                _require(tail[key] == head[key], "conflicting window anchors")
            _require(
                tail["records"][-1]["offset"] < head["records"][0]["offset"],
                "window records do not chain",
            )
            tail["records"].extend(head["records"])
            right_windows = right_windows[1:]
        else:
            # The joined window list must stay strictly increasing.
            _require(tail["seq"] < head["seq"], "incompatible window chains")

    return {
        "version": PROOF_VERSION,
        "tenant": left["tenant"],
        "start": left["start"],
        "end": right["end"],
        "count": max(left["count"], right["count"]),
        "prev": left["prev"],
        "windows": left_windows + right_windows,
    }


def verify_proofs(proofs: Any) -> list[dict]:
    """Verify a batch of range proofs: one verdict per proof, in order.

    Each verdict is shaped like the on-chain verify result --
    ``{"count": n, "first_bad": i, "ok": bool}`` -- where ``count`` is the
    number of records the proof covers and ``first_bad`` the global tenant
    index of the first broken record. One tampered proof never aborts the
    batch: its verdict reports the corruption with the real bad index and
    the remaining proofs are still checked. An empty list raises
    ``ValueError``; a non-dict element raises ``TypeError``.
    """
    if not isinstance(proofs, list):
        raise TypeError("proofs must be a list")
    if not proofs:
        raise ValueError("no proofs to verify")
    verdicts = []
    for proof in proofs:
        if not isinstance(proof, dict):
            raise TypeError("proof must be a dict")
        try:
            verdict = verify_proof(proof)
        except ValueError:
            verdicts.append(_corrupt_verdict(proof))
            continue
        verdicts.append(
            {
                "count": verdict["count"],
                "first_bad": verdict["first_bad"],
                "ok": verdict["ok"],
            }
        )
    return verdicts


def _corrupt_verdict(proof: dict) -> dict:
    """Corruption verdict for a proof too malformed to verify at all."""
    start = proof.get("start")
    end = proof.get("end")
    if not _nonneg_int(start):
        start = 0
    if not _nonneg_int(end) or end < start:
        end = start
    return {"count": end - start, "first_bad": start, "ok": False}


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
