# audit-chain

Per-tenant audit log where every entry is chained to its predecessor, so a reader can verify a tenant history offline and pinpoint the first broken index.

## Requirements

Python 3.11 or newer. Standard library only.

## Install

    python3 -m pip install -e .

## Run

    python3 -m audit_chain --path ./audit append <tenant> --payload <json-file>
    python3 -m audit_chain --path ./audit verify <tenant>
    python3 -m audit_chain --path ./audit recover
    python3 -m audit_chain --path ./audit rotate
    python3 -m audit_chain --path ./audit compact

`verify` exits 0 when the chain is intact and 1 when it is broken. Missing files, bad lines, corrupt chains, bad payloads, lock failures and permission errors all exit 2 with no extra output.

## Public interface

`audit_chain.Chain(path)` opens the log file. `Chain(path, max_segment_bytes=n)` additionally rotates the active log into a segment once it grows past `n` bytes.
- `append(tenant, payload) -> dict` appends and returns the stored entry. Raises `TypeError` for a non-dict payload and `ValueError` when the existing chain is corrupt.
- `entries(tenant) -> list[dict]` returns entries in insertion order.
- `verify(tenant) -> dict` re-derives the chain and reports the first bad index. Raises `FileNotFoundError` when the log is absent and `ValueError` on a bad line.
- `head(tenant) -> str | None` returns the newest digest.
- `recover() -> dict` truncates a torn tail (e.g. a half-written line left by a killed process) and reports `{"kept": n, "removed": m}`. The intact prefix is never rewritten, so verification afterwards reports the same indices as the prefix did before.
- `rotate() -> dict | None` seals the active log into a numbered segment under `<path>.segments/` and returns its verification material; returns `None` when the log is empty.
- `compact() -> dict | None` merges all sealed segments into one, preserving each source segment's verification material under `sources`. The global insertion order of records is unchanged, so `verify` reports the same indices before and after compaction, and corruption inside an old segment is still located.

## On-disk layout

The active log is compact JSON lines at `<path>`, one record per line with a trailing newline. Alongside it:

- `<path>.lock` — file-level lock serialising concurrent appends; interleaved writers still produce a strictly linked chain.
- `<path>.segments/` — sealed segment files plus `manifest.json` holding per-segment verification material (record counts, SHA-256 digests, per-tenant heads).
- `<path>.cache` — incremental verification cache. Re-running `verify` on a long chain re-derives only records appended since the last run. A tampered cache or damaged record is reported as corruption, never as a pass.

## Tests

    python3 -m unittest discover -s tests -t .

## Limits

Concurrent appends are serialised with a file lock; readers may run concurrently.
Payloads must be JSON-serialisable objects.
No network service and no remote anchoring.
