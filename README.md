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
    python3 -m audit_chain --path ./audit compact [--max-segments N]

`--path` is either a single JSON-lines log file or a segment store
(directory); the first `rotate` migrates an existing file into a store at the
same path. Exit codes: `0` success, `1` verification found a broken entry,
`2` any other error (missing file, bad line, corrupt chain, bad payload
type, lock contention, path/permission errors). Error paths print nothing.

## Public interface

`audit_chain.Chain(path)` opens the log file.
- `append(tenant, payload) -> dict` appends and returns the stored entry.
- `entries(tenant) -> list[dict]` returns entries in insertion order.
- `verify(tenant) -> dict` re-derives the chain and reports the first bad index.
- `head(tenant) -> str | None` returns the newest digest.

Additional entry points:
- `recover() -> {"truncated_bytes": n}` truncates a half-written tail line
  left by a killed process; complete but broken records are never repaired.
- `rotate()` seals the active segment and starts a new one.
- `compact(max_segments=2) -> {"segments": n}` merges old sealed segments.

Concurrent appenders to one log are serialized by a file lock, so records
always link strictly with continuous zero-based per-tenant indices. Each
sealed segment keeps byte-level verification material (size + sha256 per
source segment, retained through compaction); repeated verification is
incremental and caches per-tenant chain state in an authenticated cache.
Tenants are independent chains: one tenant's damage never changes another
tenant's verdict.

## Tests

    python3 -m unittest discover -s tests -t .

## Limits

Payloads must be JSON-serialisable.
No network service and no remote anchoring.
