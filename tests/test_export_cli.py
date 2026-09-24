"""CLI for the range-export entry point."""

from __future__ import annotations

import contextlib
import io
import json

from audit_chain.__main__ import main
from audit_chain import verify_range_proof
from tests._helpers import AuditTestCase


class ExportCliTest(AuditTestCase):
    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_export_outputs_verifiable_proof(self) -> None:
        self.append_many("t", 6)
        self.chain.rotate()
        self.append_many("t", 4, start=6)
        code, out, err = self.run_cli(
            "--path", self.path, "export", "t", "--start", "2", "--end", "9"
        )
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        proof = json.loads(out)
        self.assertEqual(proof["start"], 2)
        self.assertEqual(proof["end"], 9)
        verdict = verify_range_proof(proof)
        self.assertTrue(verdict["ok"], verdict)
        self.assertEqual(
            [e["record"]["payload"]["i"] for e in proof["records"]],
            list(range(2, 9)),
        )

    def test_export_illegal_range_is_silent_exit_2(self) -> None:
        self.append_many("t", 3)
        for argv in [
            ("export", "t", "--start", "1", "--end", "1"),  # empty
            ("export", "t", "--start", "2", "--end", "1"),  # reversed
            ("export", "t", "--start", "0", "--end", "9"),  # out of range
            ("export", "ghost", "--start", "0", "--end", "1"),  # empty tenant
        ]:
            code, out, err = self.run_cli("--path", self.path, *argv)
            self.assertEqual(code, 2, argv)
            self.assertEqual(out, "", argv)
            self.assertEqual(err, "", argv)

    def test_export_missing_log_is_exit_2(self) -> None:
        code, out, err = self.run_cli(
            "--path", self.path, "export", "t", "--start", "0", "--end", "1"
        )
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
