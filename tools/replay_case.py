"""把样例事件（或任一 JSONL/JSON 事件档案）重放进系统，打印指挥视图。

用法：
  python3 tools/replay_case.py                 # 重放 examples/events.json
  python3 tools/replay_case.py path/to.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.event_store import EventStore  # noqa: E402
from app.policy_engine import NotificationPolicy  # noqa: E402
from app.service import IncidentSystem  # noqa: E402

AS_OF = "2026-09-27T09:00:00+08:00"


def load_events(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "examples" / "events.json"
    events = load_events(path)
    store = EventStore()
    for event in events:
        store.append(event)
    system = IncidentSystem(store, NotificationPolicy.load())
    system.verify_integrity()

    incident = system.model.incident
    print("=" * 72)
    print(f"案件 {incident['case_id']}｜{incident['title']}｜状态：{system.model.incident_status}")
    print("=" * 72)

    print("\n[证据保全]")
    print(f"  证据条目：{len(system.model.evidence)}（其中更正记录 "
          f"{sum(1 for e in system.model.evidence.values() if e.corrects)}）")
    print(f"  重复导入拦截：{len(system.model.rejected_imports)} 次（不增加任何计数）")
    for rej in system.model.rejected_imports:
        print(f"    - {rej.source_ref} -> 命中既有证据 {rej.duplicate_of}")

    print("\n[范围裁决]")
    for tenant_id in sorted(system.model.all_tenants()):
        explanation = system.explain_party(tenant_id)
        marker = {"in_scope": "纳入", "out_of_scope": "排除", "contested": "冲突待复核",
                  "proposed": "待裁决", "collecting": "收证中"}[explanation["decision"]]
        extra = f"（{explanation['exclusion_reason']}）" if explanation["exclusion_reason"] else ""
        print(f"  {tenant_id}: {marker}{extra}")

    print("\n[待通知队列]（监管时钟，截至", AS_OF, "）")
    for row in system.pending_queue(AS_OF):
        print(f"  {row['duty_id']}  截止 {row['deadline_at']}  [{row['clock_status']}]")

    sent = system.model.notifications
    print(f"  已发送（确认事实，不撤回）：{len(sent)}")
    for note in sent:
        print(f"    - {note['duty_id']} 于 {note['sent_at']} 发送，回执 {note['receipt_ref']}")

    print("\n[隔离动作]")
    for act in system.model.isolations:
        print(f"  {act['action_id']}: {act['scope_kind']} @ {act['applied_at']}")

    print("\n[对外披露]")
    for dis in system.model.disclosures.values():
        signed = ", ".join(f"{role}:{actor}" for role, actor in dis.signatures.items()) or "无"
        released = "已发布" if dis.released_event else "未发布"
        print(f"  {dis.disclosure_id}: 签署[{signed}] {released}")

    print("\n[纳入/排除解释示例] t-1003（被排除方）")
    explanation = system.explain_party("t-1003")
    print(json.dumps(explanation, ensure_ascii=False, indent=2, default=str))

    print("\n[已发布披露视图]（不含其他租户明细）")
    if system.model.disclosures:
        view = system.render_disclosure(next(iter(system.model.disclosures)), allowed_tenant_ids={"t-1001"})
        print(json.dumps(view, ensure_ascii=False, indent=2, default=str))

    print("\n哈希链完整性校验：通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
