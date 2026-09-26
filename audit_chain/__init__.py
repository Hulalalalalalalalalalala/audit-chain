"""Per-tenant hash-chained audit log.

Each entry stores the digest of its predecessor, so a reader can walk a
tenant's history offline and pinpoint the first tampered index. Tenants are
independent: an entry only links to the previous entry of the same tenant.
"""

from __future__ import annotations

from .chain import Chain
from .proof import (
    ShardVerifier,
    combine_proofs,
    extend_proof,
    verify_proof,
    verify_proof_stream,
    verify_proofs,
)

__all__ = [
    "Chain",
    "ShardVerifier",
    "combine_proofs",
    "extend_proof",
    "verify_proof",
    "verify_proof_stream",
    "verify_proofs",
]
