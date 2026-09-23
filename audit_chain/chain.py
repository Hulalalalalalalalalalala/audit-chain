"""Core hash-chained audit log implementation."""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

_KEYS = ("digest", "payload", "prev", "tenant")


def _canonical(payload: Any) -> str:
    """Compact JSON text with keys sorted lexicographically, non-ASCII kept."""
    return json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _digest(prev: str, payload: Any) -> str:
    text = prev + _canonical(payload)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse_line(line: str) -> dict:
    try:
        record = json.loads(line)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError("malformed audit record line") from exc
    if not isinstance(record, dict) or set(record) != set(_KEYS):
        raise ValueError("malformed audit record")
    if not isinstance(record["digest"], str):
        raise ValueError("malformed audit record: digest must be a string")
    if not isinstance(record["prev"], str):
        raise ValueError("malformed audit record: prev must be a string")
    if not isinstance(record["tenant"], str):
        raise ValueError("malformed audit record: tenant must be a string")
    return record


class Chain:
    """Append-only per-tenant audit log stored as JSON Lines."""

    def __init__(self, path: str | os.PathLike[str]):
        self.path = os.fspath(path)

    def _read(self) -> list[dict]:
        try:
            with open(self.path, "rb") as handle:
                data = handle.read().decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("malformed audit record line") from exc

        if data == "":
            return []
        # Every persisted line ends with "\n"; a missing terminator means a
        # crash left a truncated half line, which counts as a bad line.
        if not data.endswith("\n"):
            raise ValueError("truncated audit record line")

        records: list[dict] = []
        for line in data.split("\n")[:-1]:
            records.append(_parse_line(line))
        return records

    def _tenant_records(self, tenant: str) -> list[dict]:
        try:
            records = self._read()
        except FileNotFoundError:
            return []
        return [r for r in records if r["tenant"] == tenant]

    def append(self, tenant: str, payload: Any) -> dict:
        if not isinstance(payload, dict):
            raise TypeError("payload must be a dict")

        expected_prev = ""
        for record in self._tenant_records(tenant):
            recomputed = _digest(expected_prev, record["payload"])
            if record["prev"] != expected_prev or record["digest"] != recomputed:
                raise ValueError("audit chain is corrupted")
            expected_prev = record["digest"]

        entry = {
            "digest": _digest(expected_prev, payload),
            "payload": payload,
            "prev": expected_prev,
            "tenant": tenant,
        }
        line = json.dumps(
            entry,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        with open(self.path, "a", encoding="utf-8", newline="") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return entry

    def entries(self, tenant: str) -> list[dict]:
        try:
            return self._tenant_records(tenant)
        except FileNotFoundError:
            return []

    def head(self, tenant: str) -> str | None:
        records = self.entries(tenant)
        return records[-1]["digest"] if records else None

    def verify(self, tenant: str) -> dict:
        # A missing log file is an error, not an empty chain.
        records = self._read()

        expected_prev = ""
        first_bad = -1
        index = 0
        for record in records:
            if record["tenant"] != tenant:
                continue
            if first_bad == -1:
                recomputed = _digest(expected_prev, record["payload"])
                if (
                    record["prev"] != expected_prev
                    or record["digest"] != recomputed
                ):
                    first_bad = index
                expected_prev = record["digest"]
            index += 1

        return {
            "count": index,
            "first_bad": first_bad,
            "ok": first_bad == -1,
        }
