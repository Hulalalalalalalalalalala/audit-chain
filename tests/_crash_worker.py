"""Worker process for the real-kill crash-injection matrix.

Run as a subprocess with ``AUDIT_CHAIN_CRASH`` set: the audit chain hard-kills
itself (SIGKILL on POSIX) at the named crash point, so no ``finally`` block
or interpreter cleanup runs -- the crash window is the real one.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_chain import Chain  # noqa: E402


def main() -> None:
    path, operation, crash_point = sys.argv[1], sys.argv[2], sys.argv[3]
    if crash_point:
        os.environ["AUDIT_CHAIN_CRASH"] = crash_point
    chain = Chain(path)
    if operation == "append":
        index = int(sys.argv[4]) if len(sys.argv) > 4 else 0
        chain.append("t", {"i": index})
    elif operation == "migrate":
        chain.rotate()
    elif operation == "rotate":
        chain.rotate()
    elif operation == "compact":
        chain.compact(2)
    elif operation == "archive":
        # argv[4] carries the archive directory for this operation.
        chain.archive(sys.argv[4] if len(sys.argv) > 4 else path + ".archive")
    elif operation == "recover":
        chain.recover()
    elif operation == "shards":
        # argv[4..7] carry start, end, window and the shard directory.
        chain.export_shards_dir(
            "t",
            int(sys.argv[4]),
            int(sys.argv[5]),
            int(sys.argv[6]),
            sys.argv[7],
        )
    else:  # pragma: no cover - test harness error
        raise SystemExit(f"unknown operation {operation}")


if __name__ == "__main__":
    main()
