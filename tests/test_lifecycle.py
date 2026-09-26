"""补充场景：事件关闭/重开、补证升级、自定义策略、并发写入。"""
from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from incident_vault import DomainError, EvidenceKind, IncidentService

CST = timezone(timedelta(hours=8))
T0 = datetime(2026, 9, 25, 9, 0, tzinfo=CST)


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.svc = IncidentService(":memory:")
        self.eng = self.svc.engine
        self.eng.open_incident("case-1", "x", "c1", clock_anchor=T0)

    def tearDown(self) -> None:
        self.svc.close()

    def _confirmed_delivered(self, party_id="p-a", region="EU",
                             categories=("personal_data",)):
        ev = self.eng.preserve_evidence(
            "case-1", EvidenceKind.DELIVERY_RECEIPT, "t-a", "dl/1",
            list(categories), actor="a1", fingerprint="fp", stage="delivered",
            captured_at=T0)
        self.eng.record_finding("case-1", "t-a", region, [ev["evidence_id"]],
                                actor="a1", basis="x", party_id=party_id)
        self.eng.judge_scope(party_id, "i1", "affected", "x")
        self.eng.judge_scope(party_id, "i2", "affected", "x")
        return ev

    def test_close_blocked_while_pending_then_reopen(self) -> None:
        self._confirmed_delivered()
        with self.assertRaises(DomainError):
            self.eng.close_incident("case-1", "c1")
        for duty in list(self.svc.store.projection.incident_duties("case-1")):
            if duty["status"] == "pending":
                self.eng.send_notification(duty["duty_id"], "ops",
                                           f"rcpt-{duty['duty_id']}")
        self.eng.close_incident("case-1", "c1")
        self.assertEqual(self.svc.store.projection.incidents["case-1"]["status"],
                         "closed")
        # 关闭后新事实出现可重开，历史义务与事实均保留
        self.eng.reopen_incident("case-1", "c1", "发现新的交付回执")
        self.assertEqual(self.svc.store.projection.incidents["case-1"]["status"],
                         "open")
        sent = [d for d in self.svc.store.projection.incident_duties("case-1")
                if d["status"] == "sent"]
        self.assertTrue(sent)

    def test_supplement_escalates_stage_and_regenerates_duties(self) -> None:
        """补证使阶段 listed → delivered：义务按新结论补提，已发不撤回。"""
        ev = self.eng.preserve_evidence(
            "case-1", EvidenceKind.LISTING_SUMMARY, "t-u", "ls/1",
            ["personal_data"], actor="a1", fingerprint="fp-l", stage="listed",
            captured_at=T0)
        self.eng.record_finding("case-1", "t-u", "US", [ev["evidence_id"]],
                                actor="a1", basis="x", party_id="p-u")
        self.eng.judge_scope("p-u", "i1", "affected", "x")
        self.eng.judge_scope("p-u", "i2", "affected", "x")
        before = {d["rule_code"] for d in
                  self.svc.store.projection.incident_duties("case-1")}
        self.assertNotIn("R-US-PI-DELIVER", before)
        receipt = self.eng.preserve_evidence(
            "case-1", EvidenceKind.DELIVERY_RECEIPT, "t-u", "dl/9",
            ["personal_data"], actor="a1", fingerprint="fp-d", stage="delivered",
            captured_at=T0 + timedelta(hours=1))
        self.eng.supplement_finding("p-u", [receipt["evidence_id"]], actor="a1",
                                    reason="网关确认领取")
        after = {d["rule_code"]: d["status"] for d in
                 self.svc.store.projection.incident_duties("case-1")}
        self.assertIn("R-US-PI-DELIVER", after)
        self.assertIn("R-TENANT-ANY-DELIVER", after)
        self.assertEqual(self.svc.store.party("p-u")["stage"], "delivered")

    def test_policy_engine_loads_rules_from_file(self) -> None:
        from incident_vault.policy import PolicyEngine
        rules = [{
            "rule_code": "R-JP", "region": "JP", "data_category": "personal_data",
            "min_stage": "listed", "deadline_hours": 36, "channel": "regulator",
            "regulator": "JP-PPC",
        }]
        path = Path(tempfile.mkdtemp()) / "rules.json"
        path.write_text(json.dumps(rules), encoding="utf-8")
        engine = PolicyEngine.from_file(path)
        results = engine.evaluate("JP", {"personal_data"},
                                  __import__("incident_vault.models", fromlist=["Stage"]).Stage.LISTED,
                                  T0)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].deadline, T0 + timedelta(hours=36))
        with self.assertRaises(ValueError):
            PolicyEngine([{"rule_code": "bad", "region": "JP",
                           "data_category": "personal_data",
                           "min_stage": "listed", "deadline_hours": 0,
                           "channel": "regulator"}]).validate_rules()

    def test_concurrent_appends_both_persist_and_chain_stays_valid(self) -> None:
        """两个并发连接同时追加：事实都保留，哈希链始终可校验。"""
        import sqlite3
        import threading
        from incident_vault.store import EventStore
        db_path = Path(tempfile.mkdtemp()) / "c.db"
        store = EventStore(db_path)
        store.append("case-1", "incident.opened", "c1",
                     {"title": "x", "clock_anchor": T0.isoformat()})

        def worker(idx: int) -> None:
            s = EventStore(db_path)
            try:
                for i in range(5):
                    s.append("case-1", "evidence.preserved", f"w{idx}", {
                        "evidence_id": f"ev-{idx}-{i}", "kind": "suspicious_request",
                        "tenant_id": f"t{idx}", "fingerprint": f"fp-{idx}-{i}",
                        "source_ref": f"src-{idx}-{i}", "data_categories": [],
                        "credential_version": None,
                        "captured_at": T0.isoformat(), "stage": "none",
                        "supersedes": None, "summary": "",
                    })
            finally:
                s.close()

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # 原连接的内存投影未看到其他连接写入；以库内事件重算链校验为准
        fresh = EventStore(db_path)
        result = fresh.verify_chain()
        self.assertEqual(result["events"], 11)  # 1 开场 + 10 条证据
        self.assertEqual(len(fresh.projection.custody["case-1"]), 10)
        fresh.close()
        store.close()


if __name__ == "__main__":
    unittest.main()
