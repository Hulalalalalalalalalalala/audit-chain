"""Command-line interface for the per-tenant audit chain.

    python -m audit_chain --path <log> append <tenant> --payload <json-file>
    python -m audit_chain --path <log> verify <tenant>

``verify`` exits 0 when the chain is intact and 1 when verification finds a
broken entry; missing files, bad lines and other errors exit 2. No
tracebacks or explanatory text are emitted on those paths.
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

        result = chain.verify(args.tenant)
        sys.stdout.write(_compact(result) + "\n")
        return 0 if result["ok"] else 1
    except (FileNotFoundError, ValueError, TypeError):
        # Missing file / bad line / corrupt chain / bad payload: signal via
        # the exit code alone.
        return 2


if __name__ == "__main__":
    sys.exit(main())
