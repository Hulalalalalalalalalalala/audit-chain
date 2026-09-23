"""Command-line interface: outputs and the silent exit-code contract."""

from __future__ import annotations

import contextlib
import io
import json
import os
import stat as stat_module

from audit_chain.__main__ import main
from tests._helpers import AuditTestCase


class CliTest(AuditTestCase):
    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def write_payload(self, payload: object) -> str:
        payload_path = os.path.join(self._tmp, "payload.json")
        with open(payload_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        return payload_path

    def test_append_and_verify(self) -> None:
        payload = self.write_payload({"a": 1})
        code, out, err = self.run_cli(
            "--path", self.path, "append", "t", "--payload", payload
        )
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        entry = json.loads(out)
        self.assertEqual(entry["payload"], {"a": 1})

        code, out, err = self.run_cli("--path", self.path, "verify", "t")
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(json.loads(out), {"count": 1, "first_bad": -1, "ok": True})

    def test_verify_failure_is_exit_1(self) -> None:
        self.append_many("t", 3)
        self.replace_in_file(b'{"i":1}', b'{"i":7}')
        code, out, err = self.run_cli("--path", self.path, "verify", "t")
        self.assertEqual(code, 1)
        self.assertEqual(err, "")
        self.assertFalse(json.loads(out)["ok"])

    def test_missing_file_is_silent_exit_2(self) -> None:
        code, out, err = self.run_cli("--path", self.path, "verify", "t")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err, "")

    def test_bad_line_is_silent_exit_2(self) -> None:
        self.append_many("t", 2)
        with open(self.path, "ab") as handle:
            handle.write(b"{half")
        code, out, err = self.run_cli("--path", self.path, "verify", "t")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err, "")

    def test_bad_payload_type_is_silent_exit_2(self) -> None:
        payload_path = os.path.join(self._tmp, "payload.json")
        with open(payload_path, "w", encoding="utf-8") as handle:
            handle.write("[1, 2, 3]")
        code, out, err = self.run_cli(
            "--path", self.path, "append", "t", "--payload", payload_path
        )
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err, "")

    def test_payload_path_is_directory_is_exit_2(self) -> None:
        os.mkdir(os.path.join(self._tmp, "dirpayload"))
        code, out, err = self.run_cli(
            "--path", self.path,
            "append", "t",
            "--payload", os.path.join(self._tmp, "dirpayload"),
        )
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err, "")

    def test_log_path_is_directory_is_exit_2(self) -> None:
        os.mkdir(self.path)
        payload = self.write_payload({})
        code, _out, err = self.run_cli(
            "--path", self.path, "append", "t", "--payload", payload
        )
        self.assertEqual(code, 2)
        self.assertEqual(err, "")

    def test_unwritable_log_is_silent_exit_2(self) -> None:
        self.append_many("t", 1)
        os.chmod(self.path, stat_module.S_IRUSR)
        try:
            payload = self.write_payload({})
            code, _out, err = self.run_cli(
                "--path", self.path, "append", "t", "--payload", payload
            )
            self.assertEqual(code, 2)
            self.assertEqual(err, "")
        finally:
            os.chmod(self.path, stat_module.S_IRUSR | stat_module.S_IWUSR)

    def test_lock_busy_is_silent_exit_2(self) -> None:
        import fcntl

        from audit_chain import storage as st

        self.append_many("t", 1)
        layout = st.Layout(self.path, "file")
        fd = os.open(layout.lock_path, os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            payload = self.write_payload({})
            code, _out, err = self.run_cli(
                "--path", self.path, "append", "t", "--payload", payload
            )
            self.assertEqual(code, 2)
            self.assertEqual(err, "")
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def test_recover_rotate_compact_commands(self) -> None:
        self.append_many("t", 2)
        with open(self.path, "ab") as handle:
            handle.write(b"{half")
        code, out, err = self.run_cli("--path", self.path, "recover")
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(json.loads(out)["truncated_bytes"], 5)

        code, _out, err = self.run_cli("--path", self.path, "rotate")
        self.assertEqual(code, 0)
        self.assertEqual(err, "")

        self.chain.append("t", {"i": 2})
        code, out, err = self.run_cli(
            "--path", self.path, "compact", "--max-segments", "1"
        )
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(json.loads(out)["segments"], 1)
