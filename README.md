# audit-chain

Per-tenant audit log where every entry is chained to its predecessor, so a reader can verify a tenant history offline and pinpoint the first broken index.

## Requirements

Python 3.11 or newer. Standard library only.

## Install

    python3 -m pip install -e .

## Run

    python3 -m audit_chain --path ./audit append <tenant> --payload <json-file>
    python3 -m audit_chain --path ./audit verify <tenant>
    python3 -m audit_chain --path ./audit export <tenant> --start I --end J
    python3 -m audit_chain --path ./audit recover
    python3 -m audit_chain --path ./audit rotate
    python3 -m audit_chain --path ./audit compact [--max-segments N]

`--path` is either a single JSON-lines log file or a segment store
(directory); the first `rotate` migrates an existing file into a store at the
same path. Exit codes: `0` success, `1` verification found a broken entry,
`2` any other error (missing file, bad line, corrupt chain, bad payload
type, lock contention, path/permission errors, or an illegal export range).
Error paths print nothing.

## Public interface

`audit_chain.Chain(path)` opens the log file.
- `append(tenant, payload) -> dict` appends and returns the stored entry.
- `entries(tenant) -> list[dict]` returns entries in insertion order.
- `verify(tenant) -> dict` re-derives the chain and reports the first bad index.
- `head(tenant) -> str | None` returns the newest digest.
- `export_range(tenant, start, end) -> dict` builds an offline range proof
  for the half-open per-tenant index interval `[start, end)`.

Additional entry points:
- `recover() -> {"truncated_bytes": n}` truncates a half-written tail line
  left by a killed process; complete but broken records are never repaired.
- `rotate()` seals the active segment and starts a new one.
- `compact(max_segments=2) -> {"segments": n}` merges old sealed segments.

`audit_chain.verify_range_proof(proof) -> dict` independently checks a range
proof using the proof material and the public SHA-256 digest algorithm
alone; it never opens the log. It returns `{"ok", "tenant", "start", "end",
"count", "first_bad"}`; a structurally malformed proof raises `ValueError`.

### Range proofs

`export_range(tenant, start, end)` returns exactly the in-range chained
records plus the cross-segment window chain needed to link them; no
out-of-range payload is included. An empty or reversed interval, a negative
bound, a non-integer bound, or an `end` past the tenant's record count
raises `ValueError`; a tenant with no records is an empty history (any
non-empty interval on it is therefore out of range). Damage outside the
interval cannot change the in-range verdict: windows the proof does not
name are never consulted.

Concurrent appenders to one log are serialized by a process-shared file
lock, so records always link strictly with continuous zero-based per-tenant
indices. Every `verify`/`entries`/`head`/`export_range` call observes one
snapshot of some complete prefix, even while an append, rotation,
compaction or recovery is committing: topology is resolved inside the lock
after waiting and crash leftovers are settled to exactly one topology
before any byte is read.

Each sealed segment keeps byte-level verification material (size + sha256
per source segment, retained through compaction); repeated verification is
incremental and caches per-tenant chain state in an authenticated cache
that is itself bound to the manifest view. Tenants are independent chains:
one tenant's damage never changes another tenant's verdict.

## Crash model

Labelled crash points throughout the write/commit paths can be armed in a
subprocess via `AUDIT_CHAIN_FAULT=<point-id>` to terminate the process with
real `SIGKILL` (see the crash-injection test matrix). A reopen lands on
exactly the old or the new topology: a killed migration adopts its backup
back, killed atomic writes leave unique `.*.tmp` files that the next
exclusive open removes, and sources deleted only after a manifest commit
are otherwise garbage-collected as orphan segments. The physical half-line
of a killed append is never repaired silently — it stays a bad line until
explicit `recover()`; after recovery the index matches the intact prefix.

## Locking

The lock is one stable file at `<path>.lock` across the file -> directory
migration. It uses the platform's own byte-range locking: `fcntl.flock` on
POSIX and Win32 `LockFileEx`/`UnlockFileEx` on Windows, so importing the
package never depends on a single platform. Contention raises
`TimeoutError` (an `OSError`); permission and path errors surface as
`OSError`, both mapping to exit code `2`.

## Tests

    python3 -m unittest discover -s tests -t .

## Limits

Payloads must be JSON-serialisable.
No network service and no remote anchoring.
