"""校验领域合同、策略矩阵与样例事件的一致性，并对样例做哈希链重放。"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.event_store import EventStore  # noqa: E402


def load_json(relative_path: str):
    return json.loads((ROOT / relative_path).read_text(encoding="utf-8"))


def validate() -> tuple[int, int, int]:
    contract = load_json("domain/contract.json")
    events = load_json("examples/events.json")
    policies = load_json("domain/policies.json")

    required = {"project", "entities", "states", "event_types", "exposure_stages",
                "data_categories", "time_policy", "rules"}
    missing = sorted(required - set(contract))
    if missing:
        raise ValueError("领域合同缺少字段：" + "、".join(missing))
    if contract["time_policy"] != "ISO 8601 with timezone":
        raise ValueError("time_policy 必须明确包含时区")
    if len(contract["entities"]) < 7:
        raise ValueError("实体集合应覆盖事件、证据、保管、结论、范围、受影响方、义务、披露")

    allowed_events = set(contract["event_types"])
    allowed_stages = set(contract["exposure_stages"])
    allowed_categories = set(contract["data_categories"])

    matrix = policies["notification_matrix"]
    for rule in matrix["rules"]:
        if rule["min_stage"] not in allowed_stages:
            raise ValueError(f"策略矩阵出现未知暴露阶段：{rule['min_stage']}")
        if rule["data_category"] not in allowed_categories:
            raise ValueError(f"策略矩阵出现未知数据类别：{rule['data_category']}")
        if rule["recipient"] not in {"authority", "tenant"}:
            raise ValueError(f"策略矩阵出现未知接收方：{rule['recipient']}")
        if rule["deadline_hours"] is not None and rule["deadline_hours"] <= 0:
            raise ValueError("截止小时数必须为正数或 null")

    store = EventStore()
    previous: datetime | None = None
    for event in events:
        if event["event_type"] not in allowed_events:
            raise ValueError(f"未知事件类型：{event['event_type']}")
        occurred_at = datetime.fromisoformat(event["occurred_at"])
        if occurred_at.tzinfo is None:
            raise ValueError("样例事件必须包含时区")
        if previous is not None and occurred_at < previous:
            raise ValueError(f"样例事件必须按发生时间排序：{event['event_id']}")
        previous = occurred_at
        store.append(event)
    store.verify_chain()

    return len(contract["entities"]), len(events), len(policies["policies"])


if __name__ == "__main__":
    entity_count, event_count, policy_count = validate()
    print(f"合同校验通过：{entity_count} 类实体，{event_count} 条样例事件，{policy_count} 项策略，哈希链完整")
