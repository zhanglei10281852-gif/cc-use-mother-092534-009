"""证据保全与处置系统的端到端业务规则测试。"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

from app.event_store import EventStore, GENESIS  # noqa: E402
from app.policy_engine import NotificationPolicy  # noqa: E402
from app.service import (  # noqa: E402
    DomainError,
    GlobalDisruptionError,
    IncidentSystem,
    ScopeConflictError,
)

T0 = "2026-09-25T09:00:00+08:00"


def fresh_system(path: str | Path | None = None) -> IncidentSystem:
    return IncidentSystem(EventStore(path), NotificationPolicy.load())


def build_case(system: IncidentSystem) -> None:
    """三租户：t-1001 实际领取、t-1002 凭据被列出（EU）、t-1003 仅列名（US）。"""
    system.open_incident("commander", T0, "外泄事件", case_id="case-1")
    # t-1001：请求 + 清单 + 交付回执
    system.import_evidence("r-a", "2026-09-25T09:20:00+08:00", "request_log", "gw:req-1",
                           {"prompt": "打包外发", "tenant_hint": "t-1001"}, idempotency_key="k-req1")
    system.import_evidence("r-a", "2026-09-25T09:40:00+08:00", "manifest_summary", "run:m1",
                           {"archive": "b.tar", "entries": ["/t-1001/customers.csv"]}, idempotency_key="k-man1")
    system.import_evidence("r-a", "2026-09-25T10:10:00+08:00", "delivery_receipt", "egress:rc1",
                           {"delivery": "https://ext/d/b.tar", "completed_at": "2026-09-25T09:58:02+08:00"},
                           idempotency_key="k-rc1")
    system.record_finding("r-a", "2026-09-25T10:12:00+08:00", "f-1001",
                          tenant_id="t-1001", region="CN", data_category="personal_data", stage="received",
                          request_evidence_id=_ev(system, "gw:req-1"),
                          summary="列出-打包-领取")
    # t-1002：凭据被列出
    system.import_evidence("r-a", "2026-09-25T09:25:00+08:00", "request_log", "gw:req-2",
                           {"prompt": "贴出凭据", "tenant_hint": "t-1002"}, idempotency_key="k-req2")
    system.record_finding("r-a", "2026-09-25T10:14:00+08:00", "f-1002",
                          tenant_id="t-1002", region="EU", data_category="credential", stage="listed",
                          request_evidence_id=_ev(system, "gw:req-2"),
                          credential_version_id="credv-7720", summary="凭据被列出")
    # t-1003：仅列名
    system.import_evidence("r-a", "2026-09-25T09:30:00+08:00", "request_log", "gw:req-3",
                           {"prompt": "列文件名", "tenant_hint": "t-1003"}, idempotency_key="k-req3")
    system.record_finding("r-a", "2026-09-25T10:16:00+08:00", "f-1003",
                          tenant_id="t-1003", region="US", data_category="personal_data", stage="listed",
                          request_evidence_id=_ev(system, "gw:req-3"), summary="仅列名")


def _ev(system: IncidentSystem, source_ref: str) -> str:
    for item in system.model.evidence.values():
        if item.source_ref == source_ref:
            return item.evidence_id
    raise KeyError(source_ref)


class EvidenceChainTest(unittest.TestCase):
    def setUp(self) -> None:
        self.system = fresh_system()
        build_case(self.system)

    def test_correction_is_append_only_and_original_remains(self) -> None:
        original_id = _ev(self.system, "gw:req-2")
        original = self.system.model.evidence[original_id]
        self.system.correct_evidence(
            "r-b", "2026-09-25T15:00:00+08:00", original_id,
            reason="归因错误：内部健康检查", source_kind="request_log", source_ref="gw:req-2:reanalyzed",
            content={"source": "internal-healthcheck"},
        )
        # 原记录内容、指纹与引用完全不变
        self.assertEqual(self.system.model.evidence[original_id].content["prompt"], "贴出凭据")
        self.assertIsNone(self.system.model.evidence[original_id].corrects)
        correction = next(e for e in self.system.model.evidence.values() if e.corrects == original_id)
        self.assertEqual(correction.correction_reason, "归因错误：内部健康检查")
        # 双向保管链
        actions = {a["action"] for a in self.system.model.custody[original_id]}
        self.assertIn("corrected_by", actions)
        self.assertIn("correction_added", {a["action"] for a in self.system.model.custody[correction.evidence_id]})

    def test_tampering_with_history_breaks_chain_on_reload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "log.jsonl"
            system = fresh_system(path)
            build_case(system)
            lines = path.read_text(encoding="utf-8").splitlines()
            record = json.loads(lines[1])
            record["event"]["payload"]["content"]["prompt"] = "篡改后的内容"
            lines[1] = json.dumps(record, ensure_ascii=False)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                EventStore(path)

    def test_genesis_link_and_chain_verify(self) -> None:
        records = self.system.store.records()
        self.assertEqual(records[0]["prev_hash"], GENESIS)
        self.system.verify_integrity()


class DeduplicationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.system = fresh_system()
        build_case(self.system)

    def test_same_idempotency_key_is_rejected_without_count_growth(self) -> None:
        before = len(self.system.model.evidence)
        result = self.system.import_evidence(
            "ingest-bot", "2026-09-25T11:00:00+08:00", "delivery_receipt", "egress:rc1",
            {"delivery": "https://ext/d/b.tar", "completed_at": "2026-09-25T09:58:02+08:00"},
            idempotency_key="k-rc1",
        )
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(len(self.system.model.evidence), before)
        self.assertEqual(len(self.system.model.rejected_imports), 1)

    def test_same_source_and_fingerprint_is_rejected_even_without_key(self) -> None:
        before = len(self.system.model.evidence)
        result = self.system.import_evidence(
            "ingest-bot", "2026-09-25T11:05:00+08:00", "request_log", "gw:req-1",
            {"prompt": "打包外发", "tenant_hint": "t-1001"},
        )
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(len(self.system.model.evidence), before)

    def test_replay_same_event_id_is_idempotent(self) -> None:
        before = len(self.system.store)
        event = self.system.store.events()[0]
        self.system.store.append(event)
        self.assertEqual(len(self.system.store), before)


class ScopeConflictTest(unittest.TestCase):
    def setUp(self) -> None:
        self.system = fresh_system()
        build_case(self.system)

    def test_conflicting_proposals_enter_review(self) -> None:
        self.system.propose_scope("r-a", "2026-09-25T10:25:00+08:00", "t-1003", True, "保守纳入")
        with self.assertRaises(ScopeConflictError):
            self.system.propose_scope("r-b", "2026-09-25T10:35:00+08:00", "t-1003", False, "阶段不足")
        contested = self.system.store.events("scope.contested")
        self.assertEqual(len(contested), 1)
        state = self.system.model.scope_state("t-1003")
        self.assertTrue(state["conflicted"])
        # 复核队列形成后继续提交提案，仍被拒绝且不重复留痕
        with self.assertRaises(ScopeConflictError):
            self.system.propose_scope("r-c", "2026-09-25T10:38:00+08:00", "t-1003", False, "补充意见")
        self.assertEqual(len(self.system.store.events("scope.contested")), 1)

    def test_proposer_cannot_resolve(self) -> None:
        self.system.propose_scope("r-a", "2026-09-25T10:25:00+08:00", "t-1003", True, "纳入")
        with self.assertRaises(ScopeConflictError):
            self.system.propose_scope("r-b", "2026-09-25T10:35:00+08:00", "t-1003", False, "排除")
        with self.assertRaises(DomainError):
            self.system.resolve_scope("r-a", "2026-09-25T10:50:00+08:00", "t-1003", False, "自己裁决")

    def test_independent_reviewer_resolves_and_explains(self) -> None:
        self.system.propose_scope("r-a", "2026-09-25T10:25:00+08:00", "t-1003", True, "保守纳入")
        with self.assertRaises(ScopeConflictError):
            self.system.propose_scope("r-b", "2026-09-25T10:35:00+08:00", "t-1003", False, "阶段不足")
        self.system.resolve_scope("lead", "2026-09-25T10:50:00+08:00", "t-1003", False,
                                  "US 个人数据仅 listed", exclusion_reason="stage_below_threshold")
        explanation = self.system.explain_party("t-1003")
        self.assertEqual(explanation["decision"], "out_of_scope")
        self.assertEqual(explanation["exclusion_reason"], "stage_below_threshold")
        self.assertTrue(explanation["scope_rounds"][0]["conflicted"])
        self.assertEqual(len(explanation["scope_rounds"][0]["proposals"]), 2)


class NotificationDutyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.system = fresh_system()
        build_case(self.system)

    def resolve_all(self) -> None:
        self.system.propose_scope("r-a", "2026-09-25T10:20:00+08:00", "t-1001", True, "received")
        self.system.resolve_scope("lead", "2026-09-25T10:40:00+08:00", "t-1001", True, "证据链完整")
        self.system.propose_scope("r-a", "2026-09-25T10:22:00+08:00", "t-1002", True, "EU listed 即触发")
        self.system.resolve_scope("lead", "2026-09-25T10:42:00+08:00", "t-1002", True, "EU 凭据 listed")
        self.system.propose_scope("r-a", "2026-09-25T10:25:00+08:00", "t-1003", True, "保守纳入")
        with self.assertRaises(ScopeConflictError):
            self.system.propose_scope("r-b", "2026-09-25T10:35:00+08:00", "t-1003", False, "阈值不足")
        self.system.resolve_scope("lead", "2026-09-25T10:50:00+08:00", "t-1003", False,
                                  "阶段不足", exclusion_reason="stage_below_threshold")

    def test_duties_follow_region_category_stage_matrix(self) -> None:
        self.resolve_all()
        ids = set(self.system.model.duties)
        # CN 个人数据 received：权威机构 + 租户双通知
        self.assertIn("duty-t-1001-authority-personal_data", ids)
        self.assertIn("duty-t-1001-tenant-personal_data", ids)
        # EU 凭据 listed：两类接收方均触发
        self.assertIn("duty-t-1002-authority-credential", ids)
        self.assertIn("duty-t-1002-tenant-credential", ids)
        # US 个人数据仅 listed：无任何义务
        self.assertFalse(any(d.tenant_id == "t-1003" for d in self.system.model.duties.values()))

    def test_deadlines_are_absolute_72h_from_first_scope_anchor(self) -> None:
        self.resolve_all()
        duty = self.system.model.duties["duty-t-1001-authority-personal_data"]
        self.assertEqual(duty.anchor_at, "2026-09-25T10:40:00+08:00")
        self.assertEqual(duty.deadline_at, "2026-09-28T10:40:00+08:00")
        queue = self.system.pending_queue("2026-09-28T11:00:00+08:00")
        statuses = {row["duty_id"]: row["clock_status"] for row in queue}
        self.assertEqual(statuses["duty-t-1001-authority-personal_data"], "overdue")

    def test_reassessment_supersedes_unsent_but_keeps_sent_facts(self) -> None:
        self.resolve_all()
        # t-1002 的租户通知先发出（确认事实）
        self.system.send_notification("comms", "2026-09-25T11:30:00+08:00",
                                      "duty-t-1002-tenant-credential", "secure_email", "mail-1")
        # 随后更正证据：f-1002 为误报
        self.system.correct_evidence(
            "r-b", "2026-09-25T15:00:00+08:00", _ev(self.system, "gw:req-2"),
            reason="内部健康检查静态模板", source_kind="request_log", source_ref="gw:req-2:re",
            content={"source": "internal-healthcheck"},
        )
        corrected_id = next(e.evidence_id for e in self.system.model.evidence.values()
                            if e.source_ref == "gw:req-2:re")
        self.system.record_finding("r-b", "2026-09-25T15:10:00+08:00", "f-1002b",
                                   tenant_id="t-1002", region="EU", data_category="credential",
                                   stage="listed", request_evidence_id=corrected_id,
                                   supersedes_finding_id="f-1002", verdict="false_positive",
                                   summary="误报")
        self.system.propose_scope("r-a", "2026-09-25T15:20:00+08:00", "t-1002", False, "撤回纳入")
        self.system.resolve_scope("lead", "2026-09-25T15:30:00+08:00", "t-1002", False,
                                  "误报", exclusion_reason="corrected_as_false_positive")
        # 尚未发送的 authority 义务被废止
        self.assertEqual(self.system.model.duties["duty-t-1002-authority-credential"].status, "superseded")
        # 已发送的 tenant 通知不撤回、不覆盖
        sent_duty = self.system.model.duties["duty-t-1002-tenant-credential"]
        self.assertEqual(sent_duty.status, "sent")
        self.assertEqual(sent_duty.notification["receipt_ref"], "mail-1")
        self.assertEqual(len(self.system.model.notifications), 1)
        # 不能对已发送义务重复发送
        with self.assertRaises(DomainError):
            self.system.send_notification("comms", "2026-09-25T16:00:00+08:00",
                                          "duty-t-1002-tenant-credential", "secure_email", "mail-2")

    def test_clock_anchor_does_not_move_on_reinclusion(self) -> None:
        self.resolve_all()
        original_anchor = self.system.model.duties["duty-t-1001-authority-personal_data"].anchor_at
        # 先排除（义务废止），两天后重新纳入
        self.system.propose_scope("r-b", "2026-09-26T09:00:00+08:00", "t-1001", False, "质疑")
        self.system.resolve_scope("lead", "2026-09-26T10:00:00+08:00", "t-1001", False,
                                  "暂排除", exclusion_reason="no_evidence")
        self.assertEqual(self.system.model.duties["duty-t-1001-authority-personal_data"].status, "superseded")
        self.system.propose_scope("r-a", "2026-09-27T09:00:00+08:00", "t-1001", True, "新证据")
        self.system.resolve_scope("lead", "2026-09-27T10:00:00+08:00", "t-1001", True, "重新纳入")
        duty = self.system.model.duties["duty-t-1001-authority-personal_data"]
        self.assertEqual(duty.status, "active")
        self.assertEqual(duty.anchor_at, original_anchor)  # 监管时钟不重置
        self.assertEqual(duty.deadline_at, "2026-09-28T10:40:00+08:00")


class ContainmentAndDisclosureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.system = fresh_system()
        build_case(self.system)

    def test_global_disruption_is_blocked_by_default(self) -> None:
        with self.assertRaises(GlobalDisruptionError):
            self.system.apply_isolation("sre", T0, "act-global", "all_tenants")
        # 作用域内动作放行
        self.system.apply_isolation("sre", T0, "act-1", "request_pattern", pattern="dump_and_exfil")
        self.system.apply_isolation("sre", T0, "act-2", "credential",
                                    credential_version_id="credv-7720", action="rotate")
        self.assertEqual(len(self.system.model.isolations), 2)

    def test_explicitly_approved_global_action_is_recorded(self) -> None:
        self.system.apply_isolation("sre", T0, "act-global", "all_tenants", approved_global=True,
                                    approver="ciso", reason="紧急止血")
        self.assertEqual(len(self.system.model.isolations), 1)

    def test_disclosure_requires_two_distinct_signers(self) -> None:
        self.system.propose_scope("r-a", "2026-09-25T10:20:00+08:00", "t-1001", True, "received")
        self.system.resolve_scope("lead", "2026-09-25T10:40:00+08:00", "t-1001", True, "证据链完整")
        self.system.prepare_disclosure("legal", "2026-09-25T16:00:00+08:00", "authority", "阶段报告",
                                       disclosure_id="dis-1")
        with self.assertRaises(DomainError):
            self.system.release_disclosure("legal", "2026-09-25T16:30:00+08:00", "dis-1")
        self.system.sign_disclosure("legal-08", "2026-09-25T16:10:00+08:00", "dis-1", "legal")
        # 同一人不能双签
        with self.assertRaises(DomainError):
            self.system.sign_disclosure("legal-08", "2026-09-25T16:15:00+08:00", "dis-1", "security")
        self.system.sign_disclosure("sec-09", "2026-09-25T16:20:00+08:00", "dis-1", "security")
        result = self.system.release_disclosure("legal-08", "2026-09-25T16:30:00+08:00",
                                                "dis-1", allowed_tenant_ids={"t-1001"})
        # 发布视图隐藏未授权的其他租户
        visible = {t["tenant_id"] for t in result["view"]["tenants"]}
        self.assertEqual(visible, {"t-1001"})
        # 默认视图不含任何租户明细
        self.system.prepare_disclosure("legal", "2026-09-25T17:00:00+08:00", "authority", "公开通告",
                                       disclosure_id="dis-2")
        self.system.sign_disclosure("legal-08", "2026-09-25T17:10:00+08:00", "dis-2", "legal")
        self.system.sign_disclosure("sec-09", "2026-09-25T17:20:00+08:00", "dis-2", "security")
        result2 = self.system.release_disclosure("legal-08", "2026-09-25T17:30:00+08:00", "dis-2")
        self.assertEqual(result2["view"]["tenants"], [])
        # 不可重复发布
        with self.assertRaises(DomainError):
            self.system.release_disclosure("legal-08", "2026-09-25T18:00:00+08:00", "dis-1")


class RecoveryTest(unittest.TestCase):
    def test_clock_queue_and_containment_resume_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "log.jsonl"
            system = fresh_system(path)
            build_case(system)
            system.propose_scope("r-a", "2026-09-25T10:20:00+08:00", "t-1001", True, "received")
            system.resolve_scope("lead", "2026-09-25T10:40:00+08:00", "t-1001", True, "完整证据链")
            system.apply_isolation("sre", "2026-09-25T11:00:00+08:00", "act-1", "request_pattern")
            del system

            # 模拟服务停机后恢复：从只追加日志重建
            restored = IncidentSystem(EventStore(path), NotificationPolicy.load())
            restored.verify_integrity()
            self.assertEqual(restored.model.incident_status, "opened")
            self.assertEqual(len(restored.model.isolations), 1)
            queue = restored.pending_queue("2026-09-29T00:00:00+08:00")  # 已过截止
            self.assertTrue(queue)
            self.assertTrue(all(row["clock_status"] == "overdue" for row in queue))
            explanation = restored.explain_party("t-1001")
            self.assertEqual(explanation["regulatory_anchor_at"], "2026-09-25T10:40:00+08:00")


class ExampleReplayTest(unittest.TestCase):
    def test_shipped_example_replays_cleanly(self) -> None:
        events = json.loads((ROOT / "examples" / "events.json").read_text(encoding="utf-8"))
        store = EventStore()
        for event in events:
            store.append(event)
        system = IncidentSystem(store, NotificationPolicy.load())
        system.verify_integrity()
        # 范围结果：t-1001 纳入，t-1002 先纳入后更正排除，t-1003 冲突复核后排除
        self.assertEqual(system.model.scope_state("t-1001")["status"], "in_scope")
        self.assertEqual(system.model.scope_state("t-1002")["status"], "out_of_scope")
        self.assertEqual(system.model.scope_state("t-1003")["status"], "out_of_scope")
        # t-1003 经历了冲突复核
        self.assertTrue(system.explain_party("t-1003")["scope_rounds"][0]["conflicted"])
        # 重复导入被拦截一次
        self.assertEqual(len(system.model.rejected_imports), 1)
        # t-1002：authority 义务废止、tenant 通知保留
        self.assertEqual(system.model.duties["duty-t-1002-authority-credential"].status, "superseded")
        self.assertEqual(system.model.duties["duty-t-1002-tenant-credential"].status, "sent")
        # 披露完成双签并发布
        disclosure = system.model.disclosures["dis-01"]
        self.assertEqual(set(disclosure.signatures), {"legal", "security"})
        self.assertIsNotNone(disclosure.released_event)
        # 事件状态
        self.assertEqual(system.model.incident_status, "contained")


if __name__ == "__main__":
    unittest.main()
