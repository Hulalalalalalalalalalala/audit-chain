# audit-chain

Per-tenant audit log where every entry is chained to its predecessor, so a reader can verify a tenant history offline and pinpoint the first broken index.

## Requirements

Python 3.11 or newer. Standard library only.

## Install

    python3 -m pip install -e .

## Run

    python3 -m audit_chain --path ./audit append <tenant> --payload <json-file>
    python3 -m audit_chain --path ./audit verify <tenant>

## Public interface

`audit_chain.Chain(path)` opens the log file.
- `append(tenant, payload) -> dict` appends and returns the stored entry.
- `entries(tenant) -> list[dict]` returns entries in insertion order.
- `verify(tenant) -> dict` re-derives the chain and reports the first bad index.
- `head(tenant) -> str | None` returns the newest digest.

## Tests

    python3 -m unittest discover -s tests -t .

## Limits

Single writer per log file.
Payloads must be JSON-serialisable.
No network service and no remote anchoring.
