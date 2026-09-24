"""Command-line interface for the per-tenant audit chain.

    python -m audit_chain --path <log> append <tenant> --payload <json-file>
    python -m audit_chain --path <log> verify <tenant>
    python -m audit_chain --path <log> export <tenant> --start I --end J
    python -m audit_chain --path <log> recover
    python -m audit_chain --path <log> rotate
    python -m audit_chain --path <log> compact [--max-segments N]

``verify`` exits 0 when the chain is intact and 1 when verification finds a
broken entry. Missing files, bad lines, chain corruption, payload type
errors, lock contention and other system errors (e.g. a path that is a
directory or is not writable) exit 2. No tracebacks or explanatory text are
emitted on those paths.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from . import Chain

_ENCODING = "utf-8"


def _compact(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="audit_chain")
    parser.add_argument("--path", required=True, help="path to the log file or segment store")
    subparsers = parser.add_subparsers(dest="command", required=True)

    append_parser = subparsers.add_parser("append", help="append one record")
    append_parser.add_argument("tenant")
    append_parser.add_argument(
        "--payload",
        required=True,
        help="path to a JSON file holding the payload object",
    )

    verify_parser = subparsers.add_parser("verify", help="verify a tenant chain")
    verify_parser.add_argument("tenant")

    export_parser = subparsers.add_parser(
        "export", help="export a range proof for one tenant"
    )
    export_parser.add_argument("tenant")
    export_parser.add_argument(
        "--start", required=True, type=int, help="first index, inclusive"
    )
    export_parser.add_argument(
        "--end", required=True, type=int, help="last index, exclusive"
    )

    subparsers.add_parser("recover", help="truncate a half-written tail record")
    subparsers.add_parser("rotate", help="seal the active segment and start a new one")

    compact_parser = subparsers.add_parser("compact", help="merge old segments")
    compact_parser.add_argument(
        "--max-segments",
        type=int,
        default=2,
        help="fold the log until at most this many segments remain",
    )

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    chain = Chain(args.path)

    try:
        if args.command == "append":
            with open(args.payload, "r", encoding=_ENCODING) as handle:
                payload = json.load(handle)
            entry = chain.append(args.tenant, payload)
            sys.stdout.write(_compact(entry) + "\n")
            return 0

        if args.command == "verify":
            result = chain.verify(args.tenant)
            sys.stdout.write(_compact(result) + "\n")
            return 0 if result["ok"] else 1

        if args.command == "export":
            proof_obj = chain.export_range(args.tenant, args.start, args.end)
            sys.stdout.write(_compact(proof_obj) + "\n")
            return 0

        if args.command == "recover":
            result = chain.recover()
            sys.stdout.write(_compact(result) + "\n")
            return 0

        if args.command == "rotate":
            chain.rotate()
            return 0

        result = chain.compact(args.max_segments)
        sys.stdout.write(_compact(result) + "\n")
        return 0
    except (OSError, ValueError, TypeError):
        # Missing file / bad line / corrupt chain / bad payload / lock
        # contention / directory or permission errors: signal by exit code
        # alone, never with a traceback.
        return 2


if __name__ == "__main__":
    sys.exit(main())
