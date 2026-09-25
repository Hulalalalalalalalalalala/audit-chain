"""Command-line interface for the per-tenant audit chain.

    python -m audit_chain --path <log> append <tenant> --payload <json-file>
    python -m audit_chain --path <log> verify <tenant>
    python -m audit_chain --path <log> recover
    python -m audit_chain --path <log> rotate
    python -m audit_chain --path <log> compact [--max-segments N]
    python -m audit_chain --path <log> archive <archive-dir>
    python -m audit_chain --path <log> export <tenant> --start N --end M
    python -m audit_chain verify-proof <proof-file> [--tenant T] [--start N] [--end M]

``verify`` and ``verify-proof`` exit 0 when the chain is intact and 1 when
verification finds a broken entry. Missing files, bad lines, chain
corruption, payload type errors, illegal proof ranges, lock contention and
other system errors (e.g. a path that is a directory or is not writable)
exit 2. No tracebacks or explanatory text are emitted on those paths.
``verify-proof`` is fully offline: it never opens the log.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from . import Chain, verify_proof

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
    parser.add_argument("--path", help="path to the log file or segment store")
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

    subparsers.add_parser("recover", help="truncate a half-written tail record")
    subparsers.add_parser("rotate", help="seal the active segment and start a new one")

    compact_parser = subparsers.add_parser("compact", help="merge old segments")
    compact_parser.add_argument(
        "--max-segments",
        type=int,
        default=2,
        help="fold the log until at most this many segments remain",
    )

    archive_parser = subparsers.add_parser(
        "archive", help="move sealed segments online to an archive directory"
    )
    archive_parser.add_argument("archive_dir", help="caller-supplied archive path")

    export_parser = subparsers.add_parser(
        "export", help="export an offline range proof [start, end)"
    )
    export_parser.add_argument("tenant")
    export_parser.add_argument("--start", type=int, required=True)
    export_parser.add_argument("--end", type=int, required=True)

    proof_parser = subparsers.add_parser(
        "verify-proof", help="verify an exported range proof offline"
    )
    proof_parser.add_argument("proof_file", help="JSON file holding the proof (-: stdin)")
    proof_parser.add_argument("--tenant")
    proof_parser.add_argument("--start", type=int)
    proof_parser.add_argument("--end", type=int)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    # verify-proof is standalone: no log path, no log file is opened.
    if args.command == "verify-proof":
        try:
            if args.proof_file == "-":
                proof = json.load(sys.stdin)
            else:
                with open(args.proof_file, "r", encoding=_ENCODING) as handle:
                    proof = json.load(handle)
            result = verify_proof(
                proof,
                tenant=args.tenant,
                start=args.start,
                end=args.end,
            )
            sys.stdout.write(_compact(result) + "\n")
            return 0 if result["ok"] else 1
        except (OSError, ValueError, TypeError):
            return 2

    if not args.path:
        return 2
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

        if args.command == "recover":
            result = chain.recover()
            sys.stdout.write(_compact(result) + "\n")
            return 0

        if args.command == "rotate":
            chain.rotate()
            return 0

        if args.command == "compact":
            result = chain.compact(args.max_segments)
            sys.stdout.write(_compact(result) + "\n")
            return 0

        if args.command == "archive":
            result = chain.archive(args.archive_dir)
            sys.stdout.write(_compact(result) + "\n")
            return 0

        result = chain.export_range(args.tenant, args.start, args.end)
        sys.stdout.write(_compact(result) + "\n")
        return 0
    except (OSError, ValueError, TypeError):
        # Missing file / bad line / corrupt chain / bad payload / illegal
        # range / lock contention / directory or permission errors: signal
        # by exit code alone, never with a traceback.
        return 2


if __name__ == "__main__":
    sys.exit(main())
