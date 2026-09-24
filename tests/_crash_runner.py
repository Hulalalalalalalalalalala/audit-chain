"""Subprocess entry point for real-kill crash-injection tests.

Usage::

    python -m tests._crash_runner <log-path> <scenario> [fault-point]

``scenario`` builds a deterministic amount of state then performs one
mutating operation; when ``fault-point`` is given it is armed via
``AUDIT_CHAIN_FAULT`` so the process is killed with SIGKILL at that exact
point. The parent test then reopens the store and checks recovery.

This module exists under ``tests/``; it is never imported by the package.
"""

from __future__ import annotations

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from audit_chain import Chain  # noqa: E402
from audit_chain import record as rec  # noqa: E402


def main(argv: list[str]) -> int:
    path = argv[1]
    scenario = argv[2]
    point = argv[3] if len(argv) > 3 else ""
    if point:
        os.environ["AUDIT_CHAIN_FAULT"] = point

    chain = Chain(path, lock_timeout=30.0)

    def _path_exists(target: str) -> bool:
        return os.path.exists(target)

    if scenario == "setup-rotate":
        for i in range(6):
            chain.append("t", {"i": i})
            chain.append("u", {"i": i})
        chain.rotate()
        for i in range(6, 10):
            chain.append("t", {"i": i})
            chain.append("u", {"i": i})
        return 0

    if scenario == "setup-compact":
        for i in range(4):
            chain.append("t", {"i": i})
        chain.rotate()
        for i in range(4, 8):
            chain.append("t", {"i": i})
        chain.rotate()
        for i in range(8, 10):
            chain.append("t", {"i": i})
        return 0

    if scenario == "append":
        chain.append("t", {"i": 10})
        return 0

    if scenario == "rotate":
        chain.rotate()
        return 0

    if scenario == "compact2":
        chain.compact(2)
        return 0

    if scenario == "compact1":
        chain.compact(1)
        return 0

    if scenario == "migrate":
        chain.rotate()
        return 0

    if scenario == "setup-file":
        for i in range(6):
            chain.append("t", {"i": i})
        return 0

    if scenario == "stress-write":
        # Mix appends with rotation and compaction while readers may be
        # running concurrently; every committed state must be a valid prefix.
        # argv layout here: path scenario <point> [iterations]
        iterations = int(argv[4]) if len(argv) > 4 else 60
        for round_no in range(iterations):
            chain.append("t", {"i": round_no, "round": round_no})
            chain.append("u", {"i": round_no, "round": round_no})
            if round_no % 7 == 6:
                chain.rotate()
            if round_no % 11 == 10:
                try:
                    chain.compact(2)
                except ValueError:
                    pass
        return 0

    if scenario == "stress-read":
        # path scenario <point> [iterations] [tenant]
        iterations = int(argv[4]) if len(argv) > 4 else 200
        tenant = argv[5] if len(argv) > 5 else "t"
        import json as _json

        from audit_chain import verify_range_proof

        for _ in range(iterations):
            # Every individual call must observe one complete prefix. Calls
            # are separate snapshots, so they are never compared to each
            # other; each result is validated for its own internal integrity.
            try:
                entries = chain.entries(tenant)
            except FileNotFoundError:
                continue
            # Before the first append the log path does not exist; verify and
            # friends legitimately raise FileNotFoundError (baseline
            # semantics), so that startup window is simply "nothing yet".
            if not entries and not _path_exists(chain.path):
                continue
            # One call, one strict prefix: contiguous indices and a
            # self-consistent predecessor chain within the returned list.
            payloads = [entry["payload"]["i"] for entry in entries]
            if payloads != list(range(len(payloads))):
                print("non-contiguous entries", payloads[:10], flush=True)
                return 3
            for pos, entry in enumerate(entries):
                expected_prev = entries[pos - 1]["digest"] if pos else ""
                if entry["prev"] != expected_prev:
                    print("broken prev chain at", pos, flush=True)
                    return 4
                if rec.digest(entry["prev"], entry["payload"]) != entry["digest"]:
                    print("bad digest at", pos, flush=True)
                    return 5

            # verify is its own snapshot: it must re-derive a clean chain.
            try:
                result = chain.verify(tenant)
            except FileNotFoundError:
                continue
            if not result["ok"]:
                print("bad verify", _json.dumps(result), flush=True)
                return 6

            # head is its own snapshot: when the history is non-empty it must
            # be a self-consistent digest of a real predecessor boundary.
            head = chain.head(tenant)
            if entries and head is None:
                print("head vanished", flush=True)
                return 7

            # A range proof built in one export call verifies on its own.
            if entries:
                proof = chain.export_range(tenant, 0, len(entries))
                verdict = verify_range_proof(proof)
                if not verdict["ok"]:
                    print("bad proof", _json.dumps(verdict), flush=True)
                    return 8
        return 0

    raise SystemExit(f"unknown scenario: {scenario}")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
