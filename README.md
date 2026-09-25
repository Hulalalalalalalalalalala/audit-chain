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
    python3 -m audit_chain --path ./audit export <tenant> --start N --end M > proof.json
    python3 -m audit_chain verify-proof proof.json [--tenant T] [--start N] [--end M]

`--path` is either a single JSON-lines log file or a segment store
(directory); the first `rotate` migrates an existing file into a store at the
same path. Exit codes: `0` success, `1` verification found a broken entry
(including a tampered cache, manifest or sealed window), `2` any other error
(missing file, bad/half-written line, corrupt chain, bad payload type,
illegal proof range, lock contention, path/permission errors). Error paths
print nothing. `verify-proof` never opens the log.

## Public interface

`audit_chain.Chain(path)` opens the log file.
- `append(tenant, payload) -> dict` appends and returns the stored entry.
- `entries(tenant) -> list[dict]` returns entries in insertion order.
- `verify(tenant) -> dict` re-derives the chain and reports the first bad index.
- `head(tenant) -> str | None` returns the newest digest.
- `export_range(tenant, start, end) -> dict` builds an offline proof for the
  half-open interval `[start, end)` (see below).

Additional entry points:
- `recover() -> {"truncated_bytes": n}` truncates a half-written tail line
  left by a killed process; complete but broken records are never repaired.
- `rotate()` seals the active segment and starts a new one.
- `compact(max_segments=2) -> {"segments": n}` merges old segments.

`audit_chain.verify_proof(proof, *, tenant=None, start=None, end=None)`
verifies an exported proof with the public digest function alone; it never
touches the log. `audit_chain.combine_proofs(left, right)` joins two
adjacent proofs of one tenant into a single proof for the union interval,
and `audit_chain.verify_proofs(proofs)` verifies a batch of proofs offline,
returning one verdict per proof in input order, each shaped like the
on-chain `verify` result.

### Snapshot consistency

`verify`, `entries` and `head` each run under a shared process lock and read
one fixed unit list in one ordered pass, while append/rotate/compact/recover
run under an exclusive lock. A single call therefore always observes one
complete prefix — the topology immediately before or immediately after a
rotation or merge — never mixed segments, a duplicated run or a skipped run.

### Incremental, constant-read-amplification verification

Concurrent appenders to one log are serialized by a cross-platform file lock
(`flock` on POSIX, `LockFileEx` on Windows), so records always link strictly
with continuous zero-based per-tenant indices. Each sealed segment keeps
byte-level verification material (size + sha256 per source segment, retained
through compaction). A repeat verify hashes only newly appended bytes plus a
small amount of sidecar material — never the whole file, and never a sealed
byte window on the hot path. The manifest is self-authenticating and the
verify cache is authenticated; tampering with the cache, the manifest or a
sealed window is reported as corruption (`ok=False`) with the real first bad
index rather than a pass. Tenants stay isolated: one tenant's damage never
changes another tenant's verdict.

### Offline range proofs

`export_range(tenant, start, end)` returns a self-contained proof for a
contiguous interval. It contains only the interval's chained records and the
strictly-increasing cross-segment window anchors (offset/size/sha256) needed
to attach them; no out-of-interval payload is included. An independent reader
recomputes every digest, checks predecessor links, indices, offsets and the
window chain using `verify_proof` (and the public digest) alone. Damage
outside the interval cannot affect its conclusion. Empty or reversed
intervals, non-integer or out-of-bounds ranges raise `ValueError`; a tenant
with no history returns a verifiable empty-history proof for `(0, 0)`.
Export reads and hashes in proportion to the exported interval, not the
history length.

### Proof combination and batch verification

`combine_proofs(left, right)` joins two proofs of one tenant whose
intervals touch (`left.end == right.start`) into an ordinary proof for the
union interval that `verify_proof` (and the `verify-proof` subcommand)
checks exactly like a direct export; joining three adjacent proofs is
associative. A side that is not a dict raises `TypeError`; a side that is
malformed or does not verify on its own, mismatched tenants, gaps,
overlaps, reversed intervals or proofs that do not chain raise
`ValueError`. `verify_proofs(proofs)` returns one verdict per proof in
input order, each `{"count", "first_bad", "ok"}` like the on-chain `verify`
result, with `count` the number of records the proof covers and `first_bad`
the global tenant index; one tampered proof never aborts the batch. An
empty list raises `ValueError`, a non-dict element `TypeError`. Combined
proofs stay verifiable after the log is compacted, damaged or discarded.

### Crash recovery

Every commit is a temp-file write + fsync + atomic rename, and a merge
publishes its bytes before swapping the manifest and only removes old
segments afterwards. A process hard-killed in any window (partial write,
flush/fsync, segment rename, manifest replacement, old-segment deletion)
reopens onto either the old topology or the complete new one: a migration
backup is adopted, a staged directory / orphan segment / residual temp file
is reaped by the next writer, and a half-written tail line keeps its bad-line
semantics until `recover()` truncates it.

## Tests

    python3 -m unittest discover -s tests -t .

The suite includes a real-kill crash-injection matrix (separate processes
hard-killed at each commit window), concurrent snapshot-consistency stress,
tamper-evidence tests and offline-proof tests.

## Limits

Payloads must be JSON-serialisable.
No network service and no remote anchoring.
