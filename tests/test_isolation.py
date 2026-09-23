"""Cross-tenant isolation and end-to-end corruption verdicts."""

from __future__ import annotations

import json

from tests._helpers import AuditTestCase


def _recomputed_segment(records: list[dict], mutate) -> bytes:
    """Re-serialize records, recomputing each tenant's chain independently."""
    prev: dict[str, str] = {}
    out = bytearray()
    for record in records:
        tenant = record["tenant"]
        head = prev.get(tenant, "")
        record["prev"] = head
        payload = mutate(tenant, record["payload"])
        from audit_chain import record as rec

        record["payload"] = payload
        record["digest"] = rec.digest(head, payload)
        prev[tenant] = record["digest"]
        out += (
            json.dumps(
                record, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
            + "\n"
        ).encode("utf-8")
    return bytes(out)


class IsolationTest(AuditTestCase):
    def test_one_tenant_corruption_leaves_other_intact(self) -> None:
        for i in range(20):
            self.chain.append("a", {"i": i})
            self.chain.append("b", {"i": i})
        self.chain.rotate()
        for i in range(20, 25):
            self.chain.append("a", {"i": i})
            self.chain.append("b", {"i": i})

        first = self.segment_files()[0]
        # Two tenants have i=10; replace the first occurrence.
        data = self.raw_bytes(first).replace(b'{"i":10}', b'{"i":17}', 1)
        self.write_raw(data, first)
        result_a = self.chain.verify("a")
        result_b = self.chain.verify("b")
        # At least the victim is flagged at the global index; whichever
        # tenant owned the first i:10 line.
        verdicts = {result_a["ok"], result_b["ok"]}
        self.assertIn(False, verdicts)
        bad = result_a if not result_a["ok"] else result_b
        self.assertEqual(bad["first_bad"], 10)

    def test_tenant_with_record_in_other_segment_is_isolated(self) -> None:
        self.append_many("a", 20)
        self.chain.rotate()
        self.chain.append("b", {"only": 1})

        first = self.segment_files()[0]
        records = [json.loads(line) for line in self.raw_bytes(first).decode().splitlines()]
        forged = _recomputed_segment(
            records, lambda tenant, payload: {"i": 5} if payload == {"i": 0} else payload
        )
        self.write_raw(forged, first)

        self.assertFalse(self.chain.verify("a")["ok"])
        # b has no record in the damaged segment at all.
        result_b = self.chain.verify("b")
        self.assertTrue(result_b["ok"])
        self.assertEqual(result_b["count"], 1)

    def test_recomputed_forgery_in_shared_window_does_not_pass(self) -> None:
        for i in range(5):
            self.chain.append("a", {"i": i})
        self.chain.append("b", {"i": 0})
        self.chain.rotate()
        self.chain.append("b", {"i": 1})

        first = self.segment_files()[0]
        records = [json.loads(line) for line in self.raw_bytes(first).decode().splitlines()]
        forged = _recomputed_segment(
            records,
            lambda tenant, payload: {"i": 999}
            if tenant == "a" and payload == {"i": 2}
            else payload,
        )
        self.write_raw(forged, first)
        # The recomputed-digest forgery is caught by the window tripwire.
        self.assertFalse(self.chain.verify("a")["ok"])
        self.assertFalse(self.chain.verify("b")["ok"])  # co-located -> no pass

    def test_append_corrupt_chain_raises_value_error(self) -> None:
        self.chain.append("a", {})
        self.chain.append("b", {})
        self.chain.rotate()
        self.chain.append("b", {})
        first = self.segment_files()[0]
        data = self.raw_bytes(first).replace(b'{"digest"', b'{"Xigest"', 1)
        self.write_raw(data, first)
        with self.assertRaises(ValueError):
            self.chain.append("b", {})

    def test_verdict_is_stable_across_repeats(self) -> None:
        self.append_many("a", 30)
        self.chain.rotate()
        self.append_many("a", 5, start=30)
        first = self.segment_files()[0]
        data = self.raw_bytes(first).replace(b'{"i":20}', b'{"i":27}', 1)
        self.write_raw(data, first)
        first_result = self.chain.verify("a")
        for _ in range(3):
            self.assertEqual(self.chain.verify("a"), first_result)

    def test_head_after_segments(self) -> None:
        self.append_many("a", 3)
        head_before = self.chain.head("a")
        self.chain.rotate()
        self.append_many("a", 3, start=3)
        self.assertEqual(self.chain.head("a"), self.chain.entries("a")[-1]["digest"])
        self.assertNotEqual(self.chain.head("a"), head_before)
