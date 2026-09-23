"""On-disk record format for the hash-chained audit log.

The format is unchanged from the single-file log: one compact JSON object
per line, sorted keys, raw non-ASCII, terminated by a single ``"\\n"``.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

_RECORD_KEYS = {"digest", "payload", "prev", "tenant"}
_ENCODING = "utf-8"


def canonical_payload(payload: Any) -> str:
    """Compact JSON text used in the digest: sorted keys, raw non-ASCII."""
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def digest(prev: str, payload: Any) -> str:
    material = prev + canonical_payload(payload)
    return hashlib.sha256(material.encode(_ENCODING)).hexdigest()


def canonical_json(value: Any) -> str:
    """Compact JSON text for manifest/cache bookkeeping."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def parse_line(line: str) -> dict:
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


def split_records(text: str) -> list[str]:
    """Split log text into lines the same way the single-file log did.

    Every complete record ends with a newline; bytes after the final newline
    are a half-written line left by a crashed append and are reported as a
    truncated record rather than silently dropped.
    """
    if text == "":
        return []
    if not text.endswith("\n"):
        raise ValueError("truncated audit record")
    # The trailing newline leaves one final empty segment, which is the only
    # empty segment a healthy log contains.
    return text.split("\n")[:-1]


def build_line(tenant: str, payload: Any, prev: str) -> tuple[dict, str]:
    """Build the stored record and its canonical on-disk line."""
    record = {
        "digest": digest(prev, payload),
        "payload": payload,
        "prev": prev,
        "tenant": tenant,
    }
    line = canonical_json(record)
    return record, line
