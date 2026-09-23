"""Tests for the audit_chain package."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import threading
import unittest

import audit_chain
from audit_chain import Chain, _digest
from audit_chain.__main__ import main


def _line(record: dict) -> str:
    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _build_records(pairs: list[tuple[str, dict]]) -> list[dict]:
    """Build a valid chain of records for (tenant, payload) pairs."""
    prev: dict[str, str] = {}
    records = []
    for tenant, payload in pairs:
        head = prev.get(tenant, "")
        record = {
            "digest": _digest(head, payload),
            "payload": payload,
            "prev": head,
            "tenant": tenant,
        }
        prev[tenant] = record["digest"]
        records.append(record)
    return records


def _write_log(path: str, pairs: list[tuple[str, dict]]) -> list[dict]:
    records = _build_records(pairs)
    with open(path, "w", encoding="utf-8", newline="") as handle:
        for record in records:
            handle.write(_line(record) + "\n")
    return records


class TempDirCase(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = os.path.join(self.dir.name, "audit.log")

    def read_lines(self) -> list[str]:
        with open(self.path, "r", encoding="utf-8") as handle:
            return handle.read().splitlines()


class BaselineTest(TempDirCase):
    def test_append_entries_head_verify(self) -> None:
        chain = Chain(self.path)
        first = chain.append("acme", {"event": "login"})
        second = chain.append("acme", {"event": "logout"})
        self.assertEqual(first["prev"], "")
        self.assertEqual(second["prev"], first["digest"])
        self.assertEqual(chain.entries("acme"), [first, second])
        self.assertEqual(chain.head("acme"), second["digest"])
        self.assertEqual(
            chain.verify("acme"), {"count": 2, "first_bad": -1, "ok": True}
        )

    def test_on_disk_format_is_compact_sorted_json_lines(self) -> None:
        chain = Chain(self.path)
        chain.append("acme", {"b": 1, "a": "é"})
        (line,) = self.read_lines()
        self.assertEqual(
            line,
            '{"digest":"%s","payload":{"a":"é","b":1},"prev":"","tenant":"acme"}'
            % chain.head("acme"),
        )
        with open(self.path, "rb") as handle:
            self.assertTrue(handle.read().endswith(b"\n"))

    def test_tenants_are_independent_chains(self) -> None:
        chain = Chain(self.path)
        a1 = chain.append("a", {"n": 1})
        chain.append("b", {"n": 1})
        a2 = chain.append("a", {"n": 2})
        self.assertEqual(a2["prev"], a1["digest"])
        self.assertEqual(chain.verify("a"), {"count": 2, "first_bad": -1, "ok": True})
        self.assertEqual(chain.verify("b"), {"count": 1, "first_bad": -1, "ok": True})

    def test_append_rejects_non_dict_payload(self) -> None:
        chain = Chain(self.path)
        with self.assertRaises(TypeError):
            chain.append("acme", [1, 2])
        with self.assertRaises(TypeError):
            chain.append("acme", "text")

    def test_verify_missing_file_raises_file_not_found(self) -> None:
        with self.assertRaises(FileNotFoundError):
            Chain(self.path).verify("acme")

    def test_entries_and_head_on_missing_file_are_empty(self) -> None:
        chain = Chain(self.path)
        self.assertEqual(chain.entries("acme"), [])
        self.assertIsNone(chain.head("acme"))

    def test_bad_line_raises_value_error(self) -> None:
        _write_log(self.path, [("acme", {"n": 1})])
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write("not json\n")
        chain = Chain(self.path)
        with self.assertRaises(ValueError):
            chain.verify("acme")
        with self.assertRaises(ValueError):
            chain.entries("acme")

    def test_append_on_corrupt_chain_raises_value_error(self) -> None:
        records = _write_log(self.path, [("acme", {"n": 1}), ("acme", {"n": 2})])
        lines = self.read_lines()
        tampered = dict(records[0], payload={"n": 999})
        lines[0] = _line(tampered)
        with open(self.path, "w", encoding="utf-8", newline="") as handle:
            handle.write("\n".join(lines) + "\n")
        chain = Chain(self.path)
        with self.assertRaises(ValueError):
            chain.append("acme", {"n": 3})
        result = chain.verify("acme")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"], 0)

    def test_one_tenants_corruption_does_not_change_anothers_result(self) -> None:
        records = _write_log(
            self.path, [("a", {"n": 1}), ("b", {"n": 1}), ("a", {"n": 2}), ("b", {"n": 2})]
        )
        lines = self.read_lines()
        lines[0] = _line(dict(records[0], payload={"n": 999}))
        with open(self.path, "w", encoding="utf-8", newline="") as handle:
            handle.write("\n".join(lines) + "\n")
        chain = Chain(self.path)
        self.assertEqual(chain.verify("b"), {"count": 2, "first_bad": -1, "ok": True})
        result = chain.verify("a")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"], 0)


class ConcurrencyTest(TempDirCase):
    def test_concurrent_appends_are_serialised_and_linked(self) -> None:
        chain = Chain(self.path)
        errors: list[BaseException] = []
        tenants = ["t0", "t1", "t2", "t3"]

        def worker(tenant: str) -> None:
            try:
                for n in range(25):
                    chain.append(tenant, {"n": n})
            except BaseException as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(t,)) for t in tenants]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        for tenant in tenants:
            entries = chain.entries(tenant)
            self.assertEqual(len(entries), 25)
            prev = ""
            for index, entry in enumerate(entries):
                self.assertEqual(entry["prev"], prev, f"{tenant} entry {index}")
                self.assertEqual(entry["digest"], _digest(prev, entry["payload"]))
                prev = entry["digest"]
            self.assertEqual(
                chain.verify(tenant), {"count": 25, "first_bad": -1, "ok": True}
            )


class RecoveryTest(TempDirCase):
    def test_torn_tail_is_a_bad_line_and_recover_truncates_it(self) -> None:
        records = _write_log(self.path, [("acme", {"n": i}) for i in range(3)])
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write('{"digest": "half-written')

        chain = Chain(self.path)
        with self.assertRaises(ValueError):
            chain.verify("acme")

        outcome = chain.recover()
        self.assertEqual(outcome, {"kept": 3, "removed": 1})

        # After recovery the chain verifies exactly like the intact prefix.
        self.assertEqual(
            chain.verify("acme"), {"count": 3, "first_bad": -1, "ok": True}
        )
        self.assertEqual(chain.entries("acme"), records)
        self.assertEqual(chain.head("acme"), records[-1]["digest"])

    def test_recover_reports_each_dropped_line(self) -> None:
        _write_log(self.path, [("acme", {"n": 1})])
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write("garbage\nmore garbage\n")
        self.assertEqual(Chain(self.path).recover(), {"kept": 1, "removed": 2})
        self.assertTrue(Chain(self.path).verify("acme")["ok"])

    def test_recover_on_missing_file_is_a_noop(self) -> None:
        self.assertEqual(Chain(self.path).recover(), {"kept": 0, "removed": 0})

    def test_recover_on_healthy_log_changes_nothing(self) -> None:
        _write_log(self.path, [("acme", {"n": 1})])
        self.assertEqual(Chain(self.path).recover(), {"kept": 1, "removed": 0})


class SegmentTest(TempDirCase):
    def test_rotate_seals_active_log_and_reads_span_segments(self) -> None:
        chain = Chain(self.path)
        first = chain.append("acme", {"n": 1})
        meta = chain.rotate()
        self.assertIsNotNone(meta)
        self.assertFalse(os.path.exists(self.path))

        second = chain.append("acme", {"n": 2})
        self.assertEqual(second["prev"], first["digest"])
        self.assertEqual(chain.entries("acme"), [first, second])
        self.assertEqual(chain.head("acme"), second["digest"])
        self.assertEqual(
            chain.verify("acme"), {"count": 2, "first_bad": -1, "ok": True}
        )

    def test_rotate_on_empty_log_is_a_noop(self) -> None:
        self.assertIsNone(Chain(self.path).rotate())

    def test_auto_rotation_by_size(self) -> None:
        chain = Chain(self.path, max_segment_bytes=200)
        for n in range(10):
            chain.append("acme", {"n": n})
        self.assertTrue(os.path.isdir(self.path + ".segments"))
        self.assertEqual(len(chain.entries("acme")), 10)
        self.assertEqual(
            chain.verify("acme"), {"count": 10, "first_bad": -1, "ok": True}
        )

    def test_compact_merges_segments_and_keeps_their_material(self) -> None:
        chain = Chain(self.path)
        expected = []
        for n in range(6):
            expected.append(chain.append("acme", {"n": n}))
            if n % 2 == 1:
                chain.rotate()

        merged = chain.compact()
        self.assertIsNotNone(merged)
        self.assertEqual(merged["records"], 6)
        self.assertEqual(len(merged["sources"]), 3)
        for source in merged["sources"]:
            self.assertEqual(set(source), {"id", "sha256", "records"})

        # Global insertion order and verification are unchanged.
        self.assertEqual(chain.entries("acme"), expected)
        self.assertEqual(
            chain.verify("acme"), {"count": 6, "first_bad": -1, "ok": True}
        )
        # Nothing left to merge.
        self.assertIsNone(chain.compact())

    def test_cross_segment_corruption_is_located_after_compact(self) -> None:
        chain = Chain(self.path)
        chain.append("acme", {"n": 0})
        chain.append("acme", {"n": 1})
        chain.rotate()
        chain.append("acme", {"n": 2})
        chain.append("acme", {"n": 3})
        chain.rotate()

        # Tamper with the second record inside the first sealed segment.
        seg_dir = self.path + ".segments"
        seg_file = os.path.join(seg_dir, "000001.seg")
        with open(seg_file, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        record = json.loads(lines[1])
        record["payload"] = {"n": 999}
        lines[1] = _line(record)
        with open(seg_file, "w", encoding="utf-8", newline="") as handle:
            handle.write("\n".join(lines) + "\n")

        chain.compact()
        result = chain.verify("acme")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"], 1)
        self.assertEqual(result["count"], 4)


class IncrementalCacheTest(TempDirCase):
    def test_rerun_verification_does_not_rederive_the_whole_file(self) -> None:
        _write_log(self.path, [("acme", {"n": i}) for i in range(10_000)])
        chain = Chain(self.path)
        self.assertEqual(
            chain.verify("acme"), {"count": 10_000, "first_bad": -1, "ok": True}
        )
        self.assertTrue(os.path.exists(self.path + ".cache"))

        calls = 0
        real_digest = audit_chain._digest

        def counting(prev: str, payload: object) -> str:
            nonlocal calls
            calls += 1
            return real_digest(prev, payload)

        audit_chain._digest = counting
        try:
            result = chain.verify("acme")
        finally:
            audit_chain._digest = real_digest
        self.assertTrue(result["ok"])
        self.assertEqual(calls, 0)

        # Only records appended after the cache was written are re-derived.
        chain.append("acme", {"n": 10_000})
        calls = 0
        audit_chain._digest = counting
        try:
            result = chain.verify("acme")
        finally:
            audit_chain._digest = real_digest
        self.assertEqual(result, {"count": 10_001, "first_bad": -1, "ok": True})
        self.assertEqual(calls, 1)

    def test_tampered_cache_is_reported_as_corruption(self) -> None:
        _write_log(self.path, [("acme", {"n": i}) for i in range(5)])
        chain = Chain(self.path)
        self.assertTrue(chain.verify("acme")["ok"])

        cache_path = self.path + ".cache"
        with open(cache_path, "r", encoding="utf-8") as handle:
            cached = handle.read()
        # Flip one hex digit inside a stored digest.
        marker = '"head":"'
        start = cached.index(marker) + len(marker)
        replacement = "0" if cached[start] != "0" else "1"
        cached = cached[:start] + replacement + cached[start + 1 :]
        with open(cache_path, "w", encoding="utf-8") as handle:
            handle.write(cached)

        result = chain.verify("acme")
        self.assertFalse(result["ok"])

    def test_garbage_cache_is_reported_as_corruption(self) -> None:
        _write_log(self.path, [("acme", {"n": 1})])
        chain = Chain(self.path)
        self.assertTrue(chain.verify("acme")["ok"])
        with open(self.path + ".cache", "w", encoding="utf-8") as handle:
            handle.write("not a cache")
        self.assertFalse(chain.verify("acme")["ok"])

    def test_disk_corruption_under_a_valid_cache_is_detected(self) -> None:
        records = _write_log(self.path, [("acme", {"n": i}) for i in range(6)])
        chain = Chain(self.path)
        self.assertTrue(chain.verify("acme")["ok"])

        lines = self.read_lines()
        lines[2] = _line(dict(records[2], payload={"n": 999}))
        with open(self.path, "w", encoding="utf-8", newline="") as handle:
            handle.write("\n".join(lines) + "\n")

        result = chain.verify("acme")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"], 2)

    def test_recover_drops_the_cache(self) -> None:
        _write_log(self.path, [("acme", {"n": 1})])
        chain = Chain(self.path)
        self.assertTrue(chain.verify("acme")["ok"])
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write("torn")
        chain.recover()
        self.assertFalse(os.path.exists(self.path + ".cache"))
        self.assertTrue(chain.verify("acme")["ok"])


class CliTest(TempDirCase):
    def run_cli(self, *argv: str) -> tuple[int, str]:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(["--path", self.path, *argv])
        return code, stdout.getvalue()

    def write_payload(self, value: object) -> str:
        payload_path = os.path.join(self.dir.name, "payload.json")
        with open(payload_path, "w", encoding="utf-8") as handle:
            json.dump(value, handle)
        return payload_path

    def test_append_and_verify_exit_codes(self) -> None:
        code, out = self.run_cli("append", "acme", "--payload", self.write_payload({"n": 1}))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["tenant"], "acme")

        code, out = self.run_cli("verify", "acme")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), {"count": 1, "first_bad": -1, "ok": True})

    def test_verify_failure_exits_one(self) -> None:
        records = _write_log(self.path, [("acme", {"n": 1})])
        lines = self.read_lines()
        lines[0] = _line(dict(records[0], payload={"n": 2}))
        with open(self.path, "w", encoding="utf-8", newline="") as handle:
            handle.write("\n".join(lines) + "\n")
        code, out = self.run_cli("verify", "acme")
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(out)["ok"])

    def test_missing_file_exits_two_silently(self) -> None:
        code, out = self.run_cli("verify", "acme")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")

    def test_bad_payload_exits_two_silently(self) -> None:
        code, out = self.run_cli("append", "acme", "--payload", self.write_payload([1]))
        self.assertEqual(code, 2)
        self.assertEqual(out, "")

    def test_directory_as_log_path_exits_two_silently(self) -> None:
        self.path = self.dir.name  # a directory, not a file
        for argv in (("verify", "acme"),):
            code, out = self.run_cli(*argv)
            self.assertEqual(code, 2)
            self.assertEqual(out, "")

    def test_lock_failure_exits_two_silently(self) -> None:
        os.mkdir(self.path + ".lock")  # the lock path cannot be opened
        code, out = self.run_cli("append", "acme", "--payload", self.write_payload({"n": 1}))
        self.assertEqual(code, 2)
        self.assertEqual(out, "")

    def test_recover_rotate_and_compact_commands(self) -> None:
        _write_log(self.path, [("acme", {"n": 1})])
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write("torn")
        code, out = self.run_cli("recover")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), {"kept": 1, "removed": 1})

        code, out = self.run_cli("rotate")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["file"], "000001.seg")

        code, _ = self.run_cli("append", "acme", "--payload", self.write_payload({"n": 2}))
        self.assertEqual(code, 0)
        code, _ = self.run_cli("rotate")
        self.assertEqual(code, 0)

        code, out = self.run_cli("compact")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["records"], 2)

        code, out = self.run_cli("verify", "acme")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), {"count": 2, "first_bad": -1, "ok": True})


if __name__ == "__main__":
    unittest.main()
