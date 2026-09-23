"""Per-tenant hash-chained audit log.

Each entry stores the digest of its predecessor, so a reader can walk a
tenant's history offline and pinpoint the first tampered index. Tenants are
independent: an entry only links to the previous entry of the same tenant.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Optional

__all__ = ["Chain"]

_RECORD_KEYS = {"digest", "payload", "prev", "tenant"}
_ENCODING = "utf-8"


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


class Chain:
    """Append-only, per-tenant hash-chained audit log stored as JSON lines."""

    def __init__(self, path: str):
        self.path = path

    def _read(self, *, missing_empty: bool) -> list[dict]:
        """Read and structurally validate every record in the log.

        A missing file yields an empty log when ``missing_empty`` is true
        (otherwise ``FileNotFoundError`` propagates). A truncated trailing
        line (crash mid-write), blank line or unparsable line is a bad line
        and raises ``ValueError``.
        """
        try:
            with open(self.path, "rb") as handle:
                raw = handle.read()
        except FileNotFoundError:
            if missing_empty:
                return []
            raise

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

    def _tenant_records(self, tenant: str, *, missing_empty: bool) -> list[dict]:
        return [
            record
            for record in self._read(missing_empty=missing_empty)
            if record["tenant"] == tenant
        ]

    def append(self, tenant: str, payload: Any) -> dict:
        """Append one record for ``tenant`` and return the stored entry.

        Raises ``TypeError`` for a non-object payload and ``ValueError`` if
        the existing log is corrupt; existing records are left untouched.
        """
        if not isinstance(payload, dict):
            raise TypeError("payload must be a dict")

        records = self._read(missing_empty=True)

        # Refuse to extend a damaged log: every line must be structurally
        # sound and every tenant's chain must re-derive cleanly.
        prev_by_tenant: dict[str, str] = {}
        for record in records:
            prev_digest = prev_by_tenant.get(record["tenant"], "")
            recomputed = _digest(record["prev"], record["payload"])
            if record["prev"] != prev_digest or record["digest"] != recomputed:
                raise ValueError("corrupt audit chain")
            prev_by_tenant[record["tenant"]] = record["digest"]

        prev = prev_by_tenant.get(tenant, "")
        # Non-serialisable payloads surface as TypeError from json.dumps.
        record = {
            "digest": _digest(prev, payload),
            "payload": payload,
            "prev": prev,
            "tenant": tenant,
        }
        line = json.dumps(
            record,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

        with open(self.path, "a", encoding=_ENCODING, newline="") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())

        return record

    def entries(self, tenant: str) -> list[dict]:
        """Return all of the tenant's records in insertion order."""
        return self._tenant_records(tenant, missing_empty=True)

    def verify(self, tenant: str) -> dict:
        """Re-derive the tenant's chain.

        Returns ``{"count": n, "first_bad": i, "ok": bool}`` where
        ``first_bad`` is the zero-based index of the earliest entry whose
        digest or predecessor link fails re-derivation, or -1 when the whole
        tenant history is intact. Raises ``FileNotFoundError`` when the log
        is absent and ``ValueError`` on a bad line.
        """
        records = self._tenant_records(tenant, missing_empty=False)

        first_bad = -1
        prev_digest = ""
        for index, record in enumerate(records):
            recomputed = _digest(record["prev"], record["payload"])
            if record["prev"] != prev_digest or record["digest"] != recomputed:
                if first_bad == -1:
                    first_bad = index
            prev_digest = record["digest"]

        return {
            "count": len(records),
            "first_bad": first_bad,
            "ok": first_bad == -1,
        }

    def head(self, tenant: str) -> Optional[str]:
        """Return the tenant's newest digest, or None for an empty chain."""
        records = self._tenant_records(tenant, missing_empty=True)
        if not records:
            return None
        return records[-1]["digest"]
