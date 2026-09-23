"""Command-line interface for the per-tenant audit chain.

    python -m audit_chain --path <log> append <tenant> --payload <json-file>
    python -m audit_chain --path <log> verify <tenant>
    python -m audit_chain --path <log> recover
    python -m audit_chain --path <log> rotate
    python -m audit_chain --path <log> compact

``verify`` exits 0 when the chain is intact and 1 when verification finds a
broken entry; missing files, bad lines, lock failures, permission problems
and other errors exit 2. No tracebacks or explanatory text are emitted on
those paths.
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
    parser.add_argument("--path", required=True, help="path to the log file")
    parser.add_argument(
        "--max-segment-bytes",
        type=int,
        default=None,
        help="rotate the active log into a segment once it passes this size",
    )
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

    subparsers.add_parser("recover", help="truncate a torn trailing line")
    subparsers.add_parser("rotate", help="seal the active log into a segment")
    subparsers.add_parser("compact", help="merge sealed segments into one")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    chain = Chain(args.path, max_segment_bytes=args.max_segment_bytes)

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

        if args.command == "recover":
            sys.stdout.write(_compact(chain.recover()) + "\n")
            return 0

        if args.command == "rotate":
            meta = chain.rotate()
            sys.stdout.write(_compact(meta if meta is not None else {"rotated": False}) + "\n")
            return 0

        meta = chain.compact()
        sys.stdout.write(_compact(meta if meta is not None else {"merged": False}) + "\n")
        return 0
    except (OSError, ValueError, TypeError):
        # Missing file / bad line / corrupt chain / bad payload / lock or
        # permission failure: signal via the exit code alone.
        return 2


if __name__ == "__main__":
    sys.exit(main())
