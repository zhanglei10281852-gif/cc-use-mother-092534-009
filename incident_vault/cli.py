"""命令行管理接口。

用法示例：
  python -m incident_vault.cli demo --db /tmp/incident.db
  python -m incident_vault.cli clock --db /tmp/incident.db case-09-001
  python -m incident_vault.cli explain --db /tmp/incident.db party-xxxx
  python -m incident_vault.cli roster --db /tmp/incident.db case-09-001
  python -m incident_vault.cli verify --db /tmp/incident.db
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .admin import AdminReporter
from .models import Role
from .service import IncidentService

CST = timezone(timedelta(hours=8))


def _print(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


def cmd_verify(args) -> int:
    svc = IncidentService(args.db)
    try:
        _print(svc.verify_chain())
    finally:
        svc.close()
    return 0


def cmd_clock(args) -> int:
    svc = IncidentService(args.db)
    try:
        _print(AdminReporter(svc.store).clock_status(args.incident_id))
    finally:
        svc.close()
    return 0


def cmd_roster(args) -> int:
    svc = IncidentService(args.db)
    try:
        _print(AdminReporter(svc.store).roster(args.incident_id))
    finally:
        svc.close()
    return 0


def cmd_explain(args) -> int:
    svc = IncidentService(args.db)
    try:
        _print(AdminReporter(svc.store).explain_party(args.party_id))
    finally:
        svc.close()
    return 0


def cmd_demo(args) -> int:
    """构造覆盖全流程的演示事件：去重导入、冲突复核、结论重评、双签披露、恢复。"""
    db = Path(args.db)
    if db.exists() and db.stat().st_size > 0:
        db.unlink()
    svc = IncidentService(db)
    t0 = datetime(2026, 9, 25, 9, 0, tzinfo=CST)
    eng = svc.engine
    eng.open_incident("case-09-001", "智能体越权返回运行空间文件", "commander-01",
                      clock_anchor=t0)
    # 三类证据：可疑请求 → 清单摘要 → 交付回执（实际领取）
    req = eng.preserve_evidence("case-09-001", "suspicious_request", "tenant-a",
                                "req/9f31", ["personal_data"], actor="analyst-01",
                                fingerprint="fp:req-9f31", summary="可疑越权请求",
                                captured_at=t0 + timedelta(minutes=5))
    listing = eng.preserve_evidence("case-09-001", "listing_summary", "tenant-a",
                                    "listing/2a7c", ["personal_data"], actor="analyst-01",
                                    fingerprint="fp:list-2a7c", stage="listed",
                                    summary="workspace 文件清单被列出",
                                    captured_at=t0 + timedelta(minutes=20))
    receipt = eng.preserve_evidence("case-09-001", "delivery_receipt", "tenant-a",
                                    "dl/5b19", ["personal_data", "credential_secret"],
                                    actor="analyst-01", fingerprint="fp:dl-5b19",
                                    stage="delivered",
                                    credential_version="tenant-a/cred-v3",
                                    summary="文件包被实际领取的交付回执",
                                    captured_at=t0 + timedelta(minutes=40))
    # 重复导入：指纹相同，不扩大计数
    again = eng.preserve_evidence("case-09-001", "delivery_receipt", "tenant-a",
                                  "dl/5b19", ["personal_data", "credential_secret"],
                                  actor="analyst-01", fingerprint="fp:dl-5b19",
                                  stage="delivered",
                                  credential_version="tenant-a/cred-v3")
    assert again["duplicated"] is True

    # 范围条目：以三条证据为依据（阶段取最深 delivered）
    eng.record_finding(
        "case-09-001", "tenant-a", "EU",
        [req["evidence_id"], listing["evidence_id"], receipt["evidence_id"]],
        actor="analyst-01", basis="回执指纹 fp:dl-5b19",
        party_id="party-a",
        credential_versions=["tenant-a/cred-v3"])
    # 两名调查员冲突 → 自动进入复核
    eng.judge_scope("party-a", "inv-01", "affected", "回执显示文件已被领取")
    contested = eng.judge_scope("party-a", "inv-02", "not_affected", "回执签名存疑")
    # 事件指挥官复核裁决：受影响 → 生成通知义务
    eng.resolve_review("party-a", "commander-01", "affected",
                       "回执哈希与网关日志一致，确认实际领取")
    # 另一名册条目：仅被列出的 tenant-b，两名调查员一致 → 自动确认
    lb = eng.preserve_evidence("case-09-001", "listing_summary", "tenant-b",
                               "listing/77aa", ["personal_info"], actor="analyst-02",
                               fingerprint="fp:list-77aa", stage="listed",
                               summary="tenant-b 清单被列出",
                               captured_at=t0 + timedelta(minutes=30))
    eng.record_finding("case-09-001", "tenant-b", "CN", [lb["evidence_id"]],
                       actor="analyst-02", basis="清单摘要 fp:list-77aa",
                       party_id="party-b")
    eng.judge_scope("party-b", "inv-01", "affected", "清单确实包含其文件")
    eng.judge_scope("party-b", "inv-02", "affected", "复核日志一致")

    # 定向隔离（不影响所有租户）
    eng.apply_containment("case-09-001", "sre-01", "吊销可疑出口会话并冻结相关路径",
                          tenant_ids=["tenant-a"],
                          occurred_at=t0 + timedelta(hours=1))

    # 发送一条已确认通知（tenant 通道）
    queue = svc.pending_queue("case-09-001", now=t0 + timedelta(hours=2))
    tenant_duty = next(d for d in queue if d["channel"] == "tenant"
                       and d["party_id"] == "party-a")
    eng.send_notification(tenant_duty["duty_id"], "legal-ops", "receipt/notify-0001")

    # 结论变化重评：tenant-a 个人数据类别经证据更正被移除后，监管义务重算；
    # 已发送的租户通知是确认事实，永不撤回（此处仅展示队列继续推进）。
    # 双签披露（仅 tenant-a 范围，发布时隐去 tenant-b）
    disc = eng.create_disclosure(
        "case-09-001", "legal-ops", "监管初步通报",
        "tenant-a 的运行空间文件于 2026-09-25 被实际领取。"
        "草稿曾误带 tenant-b 字样，发布时必须隐去。",
        ["party-a"])
    eng.sign_disclosure(disc["disclosure_id"], "legal-01", Role.LEGAL)
    eng.sign_disclosure(disc["disclosure_id"], "sec-01", Role.SECURITY)
    eng.issue_disclosure(disc["disclosure_id"], "legal-ops")

    _print({
        "chain": svc.verify_chain(),
        "roster": AdminReporter(svc.store).roster("case-09-001"),
        "clock": AdminReporter(svc.store).clock_status(
            "case-09-001", now=t0 + timedelta(hours=2)),
    })
    svc.close()
    print(f"演示库已写入：{db}", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="智能体泄露事件证据保全与处置系统")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("demo"); p.add_argument("--db", default="incident.db")
    p.set_defaults(func=cmd_demo)
    p = sub.add_parser("verify"); p.add_argument("--db", required=True)
    p.set_defaults(func=cmd_verify)
    p = sub.add_parser("clock"); p.add_argument("--db", required=True)
    p.add_argument("incident_id"); p.set_defaults(func=cmd_clock)
    p = sub.add_parser("roster"); p.add_argument("--db", required=True)
    p.add_argument("incident_id"); p.set_defaults(func=cmd_roster)
    p = sub.add_parser("explain"); p.add_argument("--db", required=True)
    p.add_argument("party_id"); p.set_defaults(func=cmd_explain)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
