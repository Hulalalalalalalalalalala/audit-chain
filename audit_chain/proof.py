"""Offline range proofs and their independent verification.

A range proof is a self-contained, JSON-serialisable object that lets a
reader who does **not** have the log -- only this proof and the public
digest algorithm (:func:`audit_chain.record.digest`, plain SHA-256) --
confirm that one tenant's records for indices ``[start, end)`` are:

* continuous -- zero-based per-tenant indices with no gaps;
* correctly chained -- every digest re-derives from its predecessor and
  payload, starting from the boundary anchor ``start_prev``;
* correctly linked across segments -- each record sits inside one of the
  proof's byte windows at a concrete offset, and the touched windows are
  bound to one another in a SHA-256 window chain.

The proof deliberately contains no out-of-range payload. Each touched
window is represented by:

* ``order``  -- its position in the global window sequence (the
  cross-segment link order);
* ``size``   -- the window's byte length (bounds for record placement);
* ``sha256`` -- the window digest preserved by the manifest (the on-disk
  anchor a holder of the store can cross-check independently);
* ``commit`` -- SHA-256 over the canonical bytes of exactly the in-range
  records that fall in that window -- the part an offline reader can
  recompute without seeing any other payload;
* ``link``   -- the running window hash-chain value.

Damage outside the range lives in windows the proof never names, so it
cannot change the in-range verdict.
"""

from __future__ import annotations

import hashlib
from typing import Any, Optional

from . import record as rec

_ENCODING = "utf-8"
PROOF_VERSION = 1


# ---------------------------------------------------------------------------
# Window placement helpers (shared with the exporter/verifier)
# ---------------------------------------------------------------------------


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _record_line(record: dict) -> bytes:
    return (rec.canonical_json(record) + "\n").encode(_ENCODING)


def _window_link(previous: str, sha256: str, commit: str, size: int) -> str:
    material = previous + ":" + sha256 + ":" + commit + ":" + str(size)
    return _sha256(material.encode(_ENCODING))


# ---------------------------------------------------------------------------
# Proof construction (exporter side)
# ---------------------------------------------------------------------------


def build_proof(
    tenant: str,
    start: int,
    end: int,
    start_prev: str,
    windows: list[dict],
    picked: list[dict],
) -> dict:
    """Assemble the proof object from the exporter's gathered material.

    ``windows`` is the global window chain (order = list index); ``picked``
    are the in-range records tagged with their window order, offset and
    length.
    """
    picked = sorted(picked, key=lambda item: item["index"])

    # Group the in-range record lines by the window they live in.
    by_window: dict[int, list[dict]] = {}
    for item in picked:
        by_window.setdefault(item["window"], []).append(item)
    for items in by_window.values():
        items.sort(key=lambda item: item["offset"])

    proof_windows: list[dict] = []
    # The window chain is seeded with the boundary predecessor, binding the
    # proof to the exact point just before index ``start``.
    previous = start_prev
    for order in sorted(by_window):
        if order < 0 or order >= len(windows):
            raise ValueError("record lies outside any verification window")
        window = windows[order]
        body = b"".join(_record_line(item["record"]) for item in by_window[order])
        commit = _sha256(body)
        proof_windows.append(
            {
                "order": order,
                "size": window["size"],
                "sha256": window["sha256"],
                "commit": commit,
                "link": _window_link(previous, window["sha256"], commit, window["size"]),
            }
        )
        previous = proof_windows[-1]["link"]

    records = [
        {
            "index": item["index"],
            "window": item["window"],
            "offset": item["offset"],
            "length": item["length"],
            "record": item["record"],
        }
        for item in picked
    ]
    end_digest = picked[-1]["record"]["digest"] if picked else start_prev
    return {
        "version": PROOF_VERSION,
        "tenant": tenant,
        "start": start,
        "end": end,
        "start_prev": start_prev,
        "end_digest": end_digest,
        "windows": proof_windows,
        "records": records,
    }


# ---------------------------------------------------------------------------
# Independent verification (reader side)
# ---------------------------------------------------------------------------


def verify_range_proof(proof: Any) -> dict:
    """Verify a range proof using only its material and SHA-256.

    Returns ``{"ok": bool, "tenant": t, "start": s, "end": e, "count": n,
    "first_bad": i}``. A structurally malformed proof raises ``ValueError``;
    a well-formed proof that fails any continuity, chaining, placement or
    window-chain check reports the first bad in-range index with
    ``ok = False``.
    """
    if not isinstance(proof, dict):
        raise ValueError("proof must be an object")
    if proof.get("version") != PROOF_VERSION:
        raise ValueError("unsupported proof version")
    tenant = proof.get("tenant")
    start = proof.get("start")
    end = proof.get("end")
    start_prev = proof.get("start_prev")
    end_digest = proof.get("end_digest")
    windows = proof.get("windows")
    entries = proof.get("records")
    if not isinstance(tenant, str) or not isinstance(start_prev, str):
        raise ValueError("malformed proof: tenant/start_prev must be strings")
    if not isinstance(end_digest, str):
        raise ValueError("malformed proof: end_digest must be a string")
    if (
        not isinstance(start, int)
        or isinstance(start, bool)
        or not isinstance(end, int)
        or isinstance(end, bool)
        or start < 0
        or end <= start
    ):
        raise ValueError("malformed proof: bad range bounds")
    if not isinstance(windows, list) or not isinstance(entries, list):
        raise ValueError("malformed proof: windows/records must be lists")

    window_by_order: dict[int, dict] = {}
    for window in windows:
        if (
            not isinstance(window, dict)
            or not isinstance(window.get("order"), int)
            or not isinstance(window.get("size"), int)
            or not all(isinstance(window.get(k), str) for k in ("sha256", "commit", "link"))
            or window["order"] < 0
            or window["size"] < 0
        ):
            raise ValueError("malformed proof: bad window entry")
        if window["order"] in window_by_order:
            raise ValueError("malformed proof: duplicate window order")
        window_by_order[window["order"]] = window

    count = end - start
    result: dict = {"tenant": tenant, "start": start, "end": end, "count": count}

    def fail(index: int) -> dict:
        result.update({"ok": False, "first_bad": index})
        return result

    if len(entries) != count:
        return fail(start)

    expected_indices = list(range(start, end))
    expected_prev = start_prev
    head = start_prev

    # Track per-window placement (strictly increasing, in-bounds offsets) and
    # the in-range byte stream committed by each window.
    placement: dict[int, int] = {}
    commits: dict[int, bytes] = {}
    previous_position: Optional[tuple[int, int]] = None

    for position, entry in enumerate(entries):
        index = expected_indices[position]
        if not _valid_entry(entry, index, tenant, window_by_order):
            return fail(index)
        order = entry["window"]
        offset = entry["offset"]
        record = entry["record"]

        window = window_by_order[order]
        line = _record_line(record)
        if len(line) != entry["length"]:
            return fail(index)
        if offset < 0 or offset + len(line) > window["size"]:
            return fail(index)
        last_offset = placement.get(order)
        if last_offset is not None and offset <= last_offset:
            return fail(index)
        # Global byte order must be a strict interleaving: (window, offset)
        # never goes backwards, so no cross-segment reorder or duplicate.
        if previous_position is not None and (order, offset) <= previous_position:
            return fail(index)
        previous_position = (order, offset)
        placement[order] = offset
        commits[order] = commits.get(order, b"") + line

        # Tenant chain continuity, using the public digest algorithm.
        recomputed = rec.digest(record["prev"], record["payload"])
        if record["prev"] != expected_prev or record["digest"] != recomputed:
            return fail(index)
        expected_prev = record["digest"]
        head = record["digest"]

    if head != end_digest:
        return fail(end - 1)

    # Re-derive the cross-segment window chain and each window commitment.
    previous = start_prev
    for window in sorted(window_by_order.values(), key=lambda w: w["order"]):
        order = window["order"]
        body = commits.get(order, b"")
        if _sha256(body) != window["commit"]:
            return fail(_first_index_in_window(entries, order, start))
        if (
            _window_link(previous, window["sha256"], window["commit"], window["size"])
            != window["link"]
        ):
            return fail(_first_index_in_window(entries, order, start))
        previous = window["link"]

    result.update({"ok": True, "first_bad": -1})
    return result


def _valid_entry(
    entry: Any, index: int, tenant: str, window_by_order: dict
) -> bool:
    if not isinstance(entry, dict):
        return False
    if entry.get("index") != index or not isinstance(entry.get("offset"), int):
        return False
    if not isinstance(entry.get("length"), int) or entry["length"] <= 0:
        return False
    if entry["offset"] < 0:
        return False
    if entry.get("window") not in window_by_order:
        return False
    record = entry.get("record")
    if not isinstance(record, dict) or record.get("tenant") != tenant:
        return False
    required = {"digest", "payload", "prev", "tenant"}
    if set(record) != required:
        return False
    return all(
        isinstance(record[k], str) for k in ("digest", "prev")
    ) and isinstance(record["payload"], dict)


def _first_index_in_window(entries: list[dict], order: int, start: int) -> int:
    for entry in sorted(entries, key=lambda e: e["index"]):
        if entry["window"] == order:
            return entry["index"]
    return start
