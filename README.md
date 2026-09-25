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
    python3 -m audit_chain --path ./audit archive ./archive-store
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
- `archive(archive_dir) -> {"archived": n}` moves sealed segments online from
  the hot store into the caller-supplied archive directory (see below).

`audit_chain.verify_proof(proof, *, tenant=None, start=None, end=None)`
verifies an exported proof with the public digest function alone; it never
touches the log.

Two more offline entry points work purely on proof objects (no log):
- `audit_chain.combine_proofs(left, right) -> dict` splices two proofs of the
  same tenant whose intervals meet end-to-start (`left["end"] ==
  right["start"]`) into one ordinary proof covering the union
  `[left["start"], right["end"])`. It is associative, re-verifies both inputs
  and the result, and the combined proof checks out through `verify_proof`
  after the log itself has been compressed or deleted. A non-dict argument is
  `TypeError`; a side that is not a valid exporting proof or does not verify,
  or a tenant mismatch / gap / overlap / reversed order, is `ValueError`.
- `audit_chain.verify_proofs(proofs) -> list[dict]` verifies a batch and
  returns one verdict per proof, in input order, each with the same shape as
  the on-chain verdict. A tampered proof yields an `ok=False` verdict with the
  real global bad index without interrupting the rest. An empty list is
  `ValueError`; the argument or an element that is not a dict is `TypeError`.

### Snapshot consistency

`verify`, `entries` and `head` each run under a shared process lock and read
one fixed unit list in one ordered pass, while append/rotate/compact/recover/
archive run under an exclusive lock. A single call therefore always observes
one complete prefix — the topology immediately before or immediately after a
rotation, merge or archival migration — never mixed segments, a duplicated
run or a skipped run.

### Online archival (hot + archive tiers)

`archive(archive_dir)` moves every sealed segment from the hot store into a
caller-supplied archive directory while the log stays online. The archive
location is recorded and signed in the manifest, and each migrated segment
carries its residency; the on-disk record format, digest algorithm, segment
order and per-tenant zero-based indices are unchanged. The active segment is
never archived, so appends keep landing on the hot tier.

After an archive, every entry point works across both tiers as one log:
append, entries/head, verify, rotate, compact, recover and export all resolve
archived segments from the archive directory and hot segments from the
store. A migrated segment keeps its byte-level verification material, so the
first bad index after archival is exactly what it was before and the warm
verify cache carries over to the new path with constant read amplification.
Archived segments can be compacted like any other: the merged result is
published hot and the (possibly archived) sources are removed on their tier.

The migration is staged and crash-atomic. Each selected segment is copied to
a temp file in the archive, fsynced, atomically renamed and re-authenticated
against its manifest windows while the committed manifest still describes the
hot-only topology; a cheap `.archiving` sentinel is then raised, one signed
manifest commit flips the segments through a transient `moving` residency,
the hot copies are deleted, and a final commit marks them `archive` and
retires the sentinel. A process hard-killed in any window reopens onto
either the pre-archive topology or the complete post-archive one: a kill
before the commit leaves an unreferenced archive copy that the next writer
reaps, and a kill after it finds the sentinel and deterministically finishes
(or rolls back, if the archive copy is missing/unauthentic) the move. No
reopen ever sees a half segment or copies in both tiers.

A store binds to one archive location; calling `archive` with a different
directory is `ValueError`, as is archiving a non-segmented or corrupt log.
As with every other non-verification failure, path/permission errors and a
missing archive volume surface as ordinary `OSError`/`ValueError` (the CLI
reports them silently with exit code 2).

### Incremental, constant-read-amplification verification

Concurrent appenders to one log are serialized by a cross-platform file lock
(`flock` on POSIX, `LockFileEx` on Windows), so records always link strictly
with continuous zero-based per-tenant indices. Each sealed segment keeps
byte-level verification material (size + sha256 per source segment, retained
through compaction and archival). A repeat verify hashes only newly appended
bytes plus a small amount of sidecar material — never the whole file, and
never a sealed byte window on the hot path. Every continuation past a cached
boundary, including the cache a writer warms for the line it just appended,
first authenticates every byte before that boundary against the cache's
fold: the writer extends only the fold of its own just-written bytes over
the states derived under its exclusive lock (nothing is read back and
trusted), and any other continuation hashes the cached prefix and falls back
to a full re-derivation when it was rewritten, so its verdict equals a full
verification with the real first bad index. The manifest is self-
authenticating and the verify cache is authenticated; tampering with the
cache, the manifest or a sealed window is reported as corruption (`ok=False`)
with the real first bad index rather than a pass. Tenants stay isolated: one
tenant's damage never changes another tenant's verdict.

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

Two proofs exported from the same tenant can be joined with
`combine_proofs`: when their indices meet end-to-start the result is the same
kind of proof over the union, independently verifiable, and associating three
pieces pairwise gives the same conclusion as one proof over the whole range.
This holds with endpoints on segment boundaries, across segments merged by
compaction, and across the cross-segment window chain; it stays verifiable
after the log is compacted, corrupted or deleted. `verify_proofs` verifies
many proofs at once, one verdict each in order.

### Export cost

Exporting (and splicing, and batch verification) costs work proportional to
the interval, not to total history length. With a warm, authenticated verify
cache an export opens only the segment files that hold an interval record and
reads no others; records in sealed segments are anchored straight from the
signed manifest material, so sealed bytes are never hashed, and records in the
still-growing tail are anchored over small windows containing only the
interval's own lines. A never-verified or altered store transparently falls
back to a full ordered byte scan with identical conclusions.

### Crash recovery

Every commit is a temp-file write + fsync + atomic rename, a merge
publishes its bytes before swapping the manifest and only removes old
segments afterwards, and an archival migration publishes and authenticates
the archive copies before one manifest commit flips residency, deleting the
hot copies only after that commit. A process hard-killed in any window
(partial write, flush/fsync, segment rename, manifest replacement,
old-segment deletion, an archive copy/flip/finalize) reopens onto either the
old topology or the complete new one: a migration backup is adopted, a
staged directory / orphan segment / residual temp file is reaped by the
next writer, an in-flight archival sentinel is finished forward or rolled
back, and a half-written tail line keeps its bad-line semantics until
`recover()` truncates it.

## Tests

    python3 -m unittest discover -s tests -t .

The suite includes a real-kill crash-injection matrix (separate processes
hard-killed at each commit window), concurrent snapshot-consistency stress,
tamper-evidence tests and offline-proof tests.

## Limits

Payloads must be JSON-serialisable.
No network service and no remote anchoring.
