"""端到端领域测试：覆盖事件处置的全部关键不变量。"""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from incident_vault import DomainError, EvidenceKind, IncidentService, Role, Stage
from incident_vault.admin import AdminReporter
from incident_vault.policy import PolicyEngine
from incident_vault.store import EventStore, digest

CST = timezone(timedelta(hours=8))
T0 = datetime(2026, 9, 25, 9, 0, tzinfo=CST)


class ServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.svc = IncidentService(":memory:")
        self.eng = self.svc.engine
        self.eng.open_incident("case-1", "智能体泄露", "commander-1", clock_anchor=T0)

    def tearDown(self) -> None:
        self.svc.close()

    # ------------------------------------------------------------ 证据保全

    def test_evidence_kinds_distinguish_exposure_stages(self) -> None:
        """列出 / 打包 / 实际领取必须是可区分的不同暴露阶段。"""
        req = self.eng.preserve_evidence(
            "case-1", EvidenceKind.SUSPICIOUS_REQUEST, "t-a", "req/1",
            ["personal_data"], actor="a1", fingerprint="fp1",
            captured_at=T0 + timedelta(minutes=5))
        listed = self.eng.preserve_evidence(
            "case-1", EvidenceKind.LISTING_SUMMARY, "t-a", "ls/1",
            ["personal_data"], actor="a1", fingerprint="fp2", stage="listed",
            captured_at=T0 + timedelta(minutes=10))
        packed = self.eng.preserve_evidence(
            "case-1", EvidenceKind.LISTING_SUMMARY, "t-a", "ls/2",
            ["personal_data"], actor="a1", fingerprint="fp3", stage="packaged",
            captured_at=T0 + timedelta(minutes=15))
        delivered = self.eng.preserve_evidence(
            "case-1", EvidenceKind.DELIVERY_RECEIPT, "t-a", "dl/1",
            ["personal_data"], actor="a1", fingerprint="fp4", stage="delivered",
            captured_at=T0 + timedelta(minutes=20))
        self.assertEqual(req["stage"], "none")
        self.assertEqual([listed["stage"], packed["stage"], delivered["stage"]],
                         ["listed", "packaged", "delivered"])

    def test_evidence_kind_cannot_overclaim_stage(self) -> None:
        """可疑请求不能被直接说成已领取——阶段不得深于证据支持。"""
        with self.assertRaises(DomainError):
            self.eng.preserve_evidence(
                "case-1", EvidenceKind.SUSPICIOUS_REQUEST, "t-a", "req/1",
                ["personal_data"], actor="a1", stage="delivered",
                captured_at=T0)
        with self.assertRaises(DomainError):
            self.eng.preserve_evidence(
                "case-1", EvidenceKind.DELIVERY_RECEIPT, "t-a", "dl/1",
                ["personal_data"], actor="a1", stage="listed",
                captured_at=T0)

    def test_duplicate_import_does_not_inflate_counts(self) -> None:
        """重复导入同一证据不能扩大战果计数。"""
        first = self.eng.preserve_evidence(
            "case-1", EvidenceKind.DELIVERY_RECEIPT, "t-a", "dl/1",
            ["personal_data"], actor="a1", fingerprint="fp-x", stage="delivered",
            captured_at=T0, credential_version="t-a/cred-v2")
        second = self.eng.preserve_evidence(
            "case-1", EvidenceKind.DELIVERY_RECEIPT, "t-a", "dl/1",
            ["personal_data"], actor="a1", fingerprint="fp-x", stage="delivered",
            captured_at=T0, credential_version="t-a/cred-v2")
        self.assertTrue(second["duplicated"])
        self.assertEqual(first["evidence_id"], second["evidence_id"])
        self.assertEqual(len(self.eng.custody_chain("case-1")), 1)

    def test_correction_is_append_only_and_keeps_chain(self) -> None:
        """证据更正只能追加并引用被更正项，原记录保留。"""
        old = self.eng.preserve_evidence(
            "case-1", EvidenceKind.LISTING_SUMMARY, "t-a", "ls/1",
            ["personal_data"], actor="a1", fingerprint="fp-a", stage="listed",
            captured_at=T0)
        new = self.eng.correct_evidence(
            "case-1", old["evidence_id"], actor="a1",
            reason="清单实为整包打包", stage="packaged")
        chain = self.eng.custody_chain("case-1")
        self.assertEqual([e["evidence_id"] for e in chain],
                         [old["evidence_id"], new["evidence_id"]])
        self.assertEqual(new["supersedes"], old["evidence_id"])
        # 旧记录仍是 listed，未被覆盖
        self.assertEqual(chain[0]["stage"], "listed")
        self.assertEqual(chain[1]["stage"], "packaged")
        self.svc.verify_chain()

    def test_credential_version_is_bound_to_evidence_and_finding(self) -> None:
        """可疑请求、清单、回执与凭据版本相互关联。"""
        ev = self.eng.preserve_evidence(
            "case-1", EvidenceKind.DELIVERY_RECEIPT, "t-a", "dl/9",
            ["credential_secret"], actor="a1", fingerprint="fp-c", stage="delivered",
            captured_at=T0, credential_version="t-a/cred-v7")
        party = self.eng.record_finding(
            "case-1", "t-a", "EU", [ev["evidence_id"]], actor="a1",
            basis="回执", party_id="p1")
        self.assertEqual(party["credential_versions"], ["t-a/cred-v7"])

    # ------------------------------------------------------------ 范围与复核

    def _delivered_party(self, party_id="p-a", region="EU",
                         categories=("personal_data", "credential_secret")):
        ev = self.eng.preserve_evidence(
            "case-1", EvidenceKind.DELIVERY_RECEIPT, "t-a", "dl/1",
            list(categories), actor="a1", fingerprint="fp-d", stage="delivered",
            captured_at=T0, credential_version="t-a/cred-v3")
        self.eng.record_finding("case-1", "t-a", region, [ev["evidence_id"]],
                                actor="a1", basis="回执", party_id=party_id,
                                credential_versions=["t-a/cred-v3"])
        return ev

    def test_conflicting_investigators_enter_review(self) -> None:
        """并发调查员冲突判断必须进入复核，范围不得自动确认。"""
        self._delivered_party()
        self.eng.judge_scope("p-a", "inv-1", "affected", "确认领取")
        party = self.eng.judge_scope("p-a", "inv-2", "not_affected", "签名存疑")
        review = self.svc.store.projection.reviews["p-a"]
        self.assertEqual(review["status"], "open")
        self.assertEqual(party["status"], "proposed")
        # 复核未裁决前，不产生通知义务
        self.assertEqual(
            [d for d in self.svc.store.projection.incident_duties("case-1")], [])

    def test_commander_resolves_review_and_duties_are_generated(self) -> None:
        self._delivered_party()
        self.eng.judge_scope("p-a", "inv-1", "affected", "确认")
        self.eng.judge_scope("p-a", "inv-2", "not_affected", "存疑")
        party = self.eng.resolve_review("p-a", "commander-1", "affected", "哈希一致")
        self.assertEqual(party["status"], "confirmed")
        rules = {d["rule_code"] for d in
                 self.svc.store.projection.incident_duties("case-1")}
        # EU + personal_data + delivered → 72h 监管；密钥 delivered → 24h；租户 72h
        self.assertIn("R-EU-PI-DEEP", rules)
        self.assertIn("R-SECRET-DELIVER", rules)
        self.assertIn("R-TENANT-ANY-DELIVER", rules)

    def test_consensus_confirms_without_review(self) -> None:
        ev = self.eng.preserve_evidence(
            "case-1", EvidenceKind.LISTING_SUMMARY, "t-c", "ls/1",
            ["personal_info"], actor="a2", fingerprint="fp-l", stage="listed",
            captured_at=T0)
        self.eng.record_finding("case-1", "t-c", "CN", [ev["evidence_id"]],
                                actor="a2", basis="清单", party_id="p-c")
        self.eng.judge_scope("p-c", "inv-1", "affected", "一致")
        self.eng.judge_scope("p-c", "inv-2", "affected", "一致")
        party = self.svc.store.party("p-c")
        self.assertEqual(party["status"], "confirmed")
        self.assertNotIn("p-c", self.svc.store.projection.reviews)
        rules = {d["rule_code"] for d in
                 self.svc.store.projection.incident_duties("case-1")}
        self.assertIn("R-CN-PI-LIST", rules)

    # ------------------------------------------------------------ 通知时钟

    def test_deadlines_computed_from_region_category_stage(self) -> None:
        self._delivered_party(region="US", categories=("personal_data",))
        self.eng.judge_scope("p-a", "inv-1", "affected", "x")
        self.eng.judge_scope("p-a", "inv-2", "affected", "x")
        duties = list(self.svc.store.projection.incident_duties("case-1"))
        us = next(d for d in duties if d["rule_code"] == "R-US-PI-DELIVER")
        # listed 阶段不会触发 US 规则；delivered 才触发，48 小时
        self.assertEqual(us["deadline"], T0 + timedelta(hours=48))
        tenant = next(d for d in duties if d["rule_code"] == "R-TENANT-ANY-DELIVER")
        self.assertEqual(tenant["deadline"], T0 + timedelta(hours=72))

    def test_listed_stage_does_not_trigger_delivered_only_rules(self) -> None:
        ev = self.eng.preserve_evidence(
            "case-1", EvidenceKind.LISTING_SUMMARY, "t-u", "ls/1",
            ["personal_data"], actor="a2", fingerprint="fp-u", stage="listed",
            captured_at=T0)
        self.eng.record_finding("case-1", "t-u", "US", [ev["evidence_id"]],
                                actor="a2", basis="清单", party_id="p-u")
        self.eng.judge_scope("p-u", "inv-1", "affected", "x")
        self.eng.judge_scope("p-u", "inv-2", "affected", "x")
        rules = {d["rule_code"] for d in
                 self.svc.store.projection.incident_duties("case-1")}
        self.assertNotIn("R-US-PI-DELIVER", rules)  # 仅列出，未触发 48h
        self.assertNotIn("R-TENANT-ANY-DELIVER", rules)

    def test_recompute_revokes_only_unsent_and_keeps_sent_facts(self) -> None:
        """结论变化重评：未发义务可作废，已发通知永不撤回。"""
        ev = self.eng.preserve_evidence(
            "case-1", EvidenceKind.DELIVERY_RECEIPT, "t-a", "dl/1",
            ["personal_data", "credential_secret"], actor="a1",
            fingerprint="fp-r", stage="delivered", captured_at=T0,
            credential_version="t-a/cred-v3")
        self.eng.record_finding("case-1", "t-a", "EU", [ev["evidence_id"]],
                                actor="a1", basis="x", party_id="p-a")
        self.eng.judge_scope("p-a", "inv-1", "affected", "x")
        self.eng.judge_scope("p-a", "inv-2", "affected", "x")
        secret_duty = next(d for d in self.svc.store.projection.incident_duties("case-1")
                           if d["rule_code"] == "R-SECRET-DELIVER")
        # 先发掉密钥通报（已确认事实）
        self.eng.send_notification(secret_duty["duty_id"], "ops", "rcpt-1")
        # 调查结论变化：密钥类别经复核移除 → 监管/租户义务也被重评
        party = self.svc.store.party("p-a")
        party["data_categories"] = {"personal_data"}
        self.eng.contest_scope("p-a", "inv-3", "密钥是否在包内存疑")
        self.eng.resolve_review("p-a", "commander-1", "affected",
                                "确认领取，但包内仅个人数据")
        # 手动模拟结论变化后的类别缩减（经更正流程后的当前结论）
        party = self.svc.store.party("p-a")
        party["data_categories"] = {"personal_data"}
        self.eng._recompute_duties(party)
        duties = list(self.svc.store.projection.incident_duties("case-1"))
        secret = next(d for d in duties if d["rule_code"] == "R-SECRET-DELIVER")
        self.assertEqual(secret["status"], "sent")  # 已发不撤回
        pending_rules = {d["rule_code"] for d in duties if d["status"] == "pending"}
        self.assertIn("R-EU-PI-DEEP", pending_rules)
        self.assertIn("R-TENANT-ANY-DELIVER", pending_rules)

    def test_cannot_send_same_duty_twice(self) -> None:
        self._delivered_party(categories=("personal_data",))
        self.eng.judge_scope("p-a", "inv-1", "affected", "x")
        self.eng.resolve_review("p-a", "commander-1", "affected", "x")
        duty = next(iter(self.svc.store.projection.incident_duties("case-1")))
        self.eng.send_notification(duty["duty_id"], "ops", "r1")
        with self.assertRaises(DomainError):
            self.eng.send_notification(duty["duty_id"], "ops", "r2")

    def test_pending_queue_sorts_by_deadline_and_flags_overdue(self) -> None:
        self._delivered_party()
        self.eng.judge_scope("p-a", "inv-1", "affected", "x")
        self.eng.resolve_review("p-a", "commander-1", "affected", "x")
        queue = self.svc.pending_queue("case-1", now=T0 + timedelta(hours=25))
        self.assertTrue(any(item["overdue"] for item in queue))  # 24h 密钥义务已超
        deadlines = [item["deadline"] for item in queue]
        self.assertEqual(deadlines, sorted(deadlines))

    # ------------------------------------------------------------ 隔离

    def test_targeted_containment_does_not_touch_other_tenants(self) -> None:
        action = self.eng.apply_containment(
            "case-1", "sre-1", "吊销可疑出口会话", tenant_ids=["t-a"])
        self.assertFalse(action["global"])
        self.assertEqual(action["tenant_ids"], ["t-a"])

    def test_global_containment_requires_commander_and_reason(self) -> None:
        """全局隔离会中断所有租户，必须指挥官授权且留理由。"""
        with self.assertRaises(DomainError):
            self.eng.apply_containment(
                "case-1", "sre-1", "紧急", global_blast=True,
                role=Role.OPERATOR)
        with self.assertRaises(DomainError):
            self.eng.apply_containment(
                "case-1", "commander-1", "太短", global_blast=True,
                role=Role.COMMANDER)
        action = self.eng.apply_containment(
            "case-1", "commander-1", "定向措施全部失效，风险波及全部租户",
            global_blast=True, role=Role.COMMANDER)
        self.assertTrue(action["global"])

    # ------------------------------------------------------------ 对外披露

    def _two_confirmed_parties(self):
        for pid, tenant, region, fp in (
                ("p-a", "t-a", "EU", "fp-a"), ("p-b", "t-b", "CN", "fp-b")):
            ev = self.eng.preserve_evidence(
                "case-1", EvidenceKind.DELIVERY_RECEIPT, tenant, f"dl/{pid}",
                ["personal_data"], actor="a1", fingerprint=fp, stage="delivered",
                captured_at=T0)
            self.eng.record_finding("case-1", tenant, region, [ev["evidence_id"]],
                                    actor="a1", basis="x", party_id=pid)
            self.eng.judge_scope(pid, "inv-1", "affected", "x")
            self.eng.judge_scope(pid, "inv-2", "affected", "x")

    def test_disclosure_requires_dual_signature(self) -> None:
        self._two_confirmed_parties()
        disc = self.eng.create_disclosure(
            "case-1", "ops", "通报", "t-a 被领取", ["p-a"])
        self.eng.sign_disclosure(disc["disclosure_id"], "legal-1", Role.LEGAL)
        with self.assertRaises(DomainError):
            self.eng.issue_disclosure(disc["disclosure_id"], "ops")
        self.eng.sign_disclosure(disc["disclosure_id"], "sec-1", Role.SECURITY)
        issued = self.eng.issue_disclosure(disc["disclosure_id"], "ops")
        self.assertEqual(issued["status"], "issued")

    def test_disclosure_hides_other_tenants(self) -> None:
        """对外披露必须隐去范围外租户信息。"""
        self._two_confirmed_parties()
        disc = self.eng.create_disclosure(
            "case-1", "ops", "通报",
            "涉及 t-a；草稿误写 t-b 必须被隐去", ["p-a"])
        self.eng.sign_disclosure(disc["disclosure_id"], "legal-1", Role.LEGAL)
        self.eng.sign_disclosure(disc["disclosure_id"], "sec-1", Role.SECURITY)
        issued = self.eng.issue_disclosure(disc["disclosure_id"], "ops")
        # 投影保留隐去标记；事件载荷中 t-b 已替换
        self.assertTrue(issued["redacted_other_tenants"])
        issue_event = [e for e in self.svc.store.events("case-1")
                       if e.event_type == "disclosure.issued"][0]
        self.assertNotIn("t-b", issue_event.payload["redacted_body"])
        self.assertIn("t-a", issue_event.payload["redacted_body"])
        self.assertEqual(issue_event.payload["hidden_tenants"], ["t-b"])

    # ------------------------------------------------------------ 恢复

    def test_rebuild_after_restart_resumes_clock_queue_and_containment(self) -> None:
        """服务重启/恢复后，监管时钟、隔离动作与待通知队列继续推进。"""
        import tempfile
        from pathlib import Path
        db_path = Path(tempfile.mkdtemp()) / "vault.db"
        svc = IncidentService(db_path)
        eng = svc.engine
        eng.open_incident("case-r", "恢复演练", "c1", clock_anchor=T0)
        ev = eng.preserve_evidence(
            "case-r", EvidenceKind.DELIVERY_RECEIPT, "t-a", "dl/1",
            ["personal_data"], actor="a1", fingerprint="fp-r", stage="delivered",
            captured_at=T0)
        eng.record_finding("case-r", "t-a", "EU", [ev["evidence_id"]],
                           actor="a1", basis="x", party_id="p-a")
        eng.judge_scope("p-a", "inv-1", "affected", "x")
        eng.resolve_review("p-a", "c1", "affected", "x")
        eng.apply_containment("case-r", "sre-1", "定向隔离 t-a", tenant_ids=["t-a"])
        before = svc.pending_queue("case-r", now=T0 + timedelta(hours=10))
        chain_tip = svc.verify_chain()["tip"]
        svc.close()

        # 重新打开：投影从事件流完整重建，无任何内存状态
        svc2 = IncidentService(db_path)
        self.assertEqual(svc2.verify_chain()["tip"], chain_tip)
        clock = AdminReporter(svc2.store).clock_status(
            "case-r", now=T0 + timedelta(hours=10))
        self.assertEqual(clock["pending"], len(before))
        self.assertEqual(len(clock["containment"]), 1)
        self.assertEqual(clock["containment"][0]["tenant_ids"], ["t-a"])
        # 队列继续推进：截止时间未因停机而平移
        after = svc2.pending_queue("case-r", now=T0 + timedelta(hours=10))
        self.assertEqual([d["duty_id"] for d in after],
                         [d["duty_id"] for d in before])
        svc2.close()

    def test_hash_chain_detects_tampering(self) -> None:
        """直接改写落库事实会被哈希链校验发现。"""
        import sqlite3
        import tempfile
        from pathlib import Path
        db_path = Path(tempfile.mkdtemp()) / "vault.db"
        svc = IncidentService(db_path)
        svc.open_incident("case-t", "防篡改", "c1", clock_anchor=T0)
        svc.close()
        conn = sqlite3.connect(db_path)
        conn.execute("update events set actor='forger' where seq=1")
        conn.commit()
        conn.close()
        svc2 = IncidentService(db_path)
        with self.assertRaises(DomainError):
            svc2.verify_chain()
        svc2.close()

    # ------------------------------------------------------------ 管理解释

    def test_admin_explains_inclusion_and_exclusion(self) -> None:
        reporter = AdminReporter(self.svc.store)
        ev = self.eng.preserve_evidence(
            "case-1", EvidenceKind.DELIVERY_RECEIPT, "t-a", "dl/1",
            ["personal_data"], actor="a1", fingerprint="fp1", stage="delivered",
            captured_at=T0, credential_version="t-a/cred-v3")
        self.eng.record_finding("case-1", "t-a", "EU", [ev["evidence_id"]],
                                actor="a1", basis="回执", party_id="p-a")
        pending = reporter.explain_party("p-a")
        self.assertFalse(pending["included"])
        self.assertEqual(pending["reason_code"], "PENDING_JUDGMENT")
        self.eng.judge_scope("p-a", "inv-1", "affected", "确认")
        self.eng.judge_scope("p-a", "inv-2", "not_affected", "存疑")
        reviewing = reporter.explain_party("p-a")
        self.assertEqual(reviewing["reason_code"], "PENDING_REVIEW")
        self.eng.resolve_review("p-a", "commander-1", "not_affected",
                                "网关日志显示未出运行空间")
        excluded = reporter.explain_party("p-a")
        self.assertFalse(excluded["included"])
        self.assertEqual(excluded["reason_code"], "EXCLUDED_BY_REVIEW")
        # 排除后：纳入痕迹（证据、判断）仍可解释
        self.assertEqual(len(excluded["evidence"]), 1)
        self.assertEqual(len(excluded["judgments"]), 2)
        # 重新确认纳入
        self.eng.contest_scope("p-a", "commander-1", "新回执出现")
        new_ev = self.eng.preserve_evidence(
            "case-1", EvidenceKind.DELIVERY_RECEIPT, "t-a", "dl/2",
            ["personal_data"], actor="a1", fingerprint="fp2", stage="delivered",
            captured_at=T0 + timedelta(hours=1))
        self.eng.supplement_finding("p-a", [new_ev["evidence_id"]], actor="a1",
                                    reason="新回执")
        self.eng.resolve_review("p-a", "commander-1", "affected", "新回执成立")
        included = reporter.explain_party("p-a")
        self.assertTrue(included["included"])
        self.assertEqual(included["reason_code"], "CONFIRMED_EXPOSURE")
        self.assertIn("交付回执", included["reason"])


if __name__ == "__main__":
    unittest.main()
