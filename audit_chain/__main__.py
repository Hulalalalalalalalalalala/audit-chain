"""Command line interface: python -m audit_chain ..."""

from __future__ import annotations

import argparse
import json
import sys

from .chain import Chain


def _compact(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="audit_chain")
    parser.add_argument("--path", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)

    append_parser = subparsers.add_parser("append")
    append_parser.add_argument("tenant")
    append_parser.add_argument("--payload", required=True)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("tenant")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    chain = Chain(args.path)

    try:
        if args.command == "append":
            with open(args.payload, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            result = chain.append(args.tenant, payload)
        else:
            result = chain.verify(args.tenant)
    except (OSError, ValueError, TypeError):
        return 2

    print(_compact(result))
    if args.command == "verify" and not result["ok"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
