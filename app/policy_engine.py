"""通知义务策略引擎：按租户地区 × 数据类别 × 实际暴露阶段匹配义务与截止时长。

矩阵来自 domain/policies.json，可版本化替换；引擎本身无状态。
暴露阶段单调：listed < packaged < received；规则给出触发该义务所需的最低阶段。
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class DutyRule:
    region: str
    data_category: str
    min_stage: str
    recipient: str
    deadline_hours: int | None

    @property
    def rule_key(self) -> str:
        return f"{self.region}/{self.data_category}/{self.min_stage}/{self.recipient}"


class NotificationPolicy:
    def __init__(self, rules: list[DutyRule], stage_rank: dict[str, int], policy_version: int = 1) -> None:
        self.rules = rules
        self.stage_rank = stage_rank
        self.policy_version = policy_version

    @classmethod
    def load(cls, path: str | Path | None = None) -> "NotificationPolicy":
        data = json.loads(Path(path or ROOT / "domain" / "policies.json").read_text(encoding="utf-8"))
        matrix = data["notification_matrix"]
        rules = [
            DutyRule(
                region=r["region"],
                data_category=r["data_category"],
                min_stage=r["min_stage"],
                recipient=r["recipient"],
                deadline_hours=r["deadline_hours"],
            )
            for r in matrix["rules"]
        ]
        return cls(rules, matrix["stage_rank"], policy_version=data.get("version", 1))

    def stage_at_least(self, actual: str, required: str) -> bool:
        return self.stage_rank[actual] >= self.stage_rank[required]

    def evaluate(self, region: str, data_category: str, stage: str) -> list[DutyRule]:
        """返回该事实组合当前触发的全部义务规则（可能含 authority 与 tenant 两类接收方）。"""
        matched: list[DutyRule] = []
        for rule in self.rules:
            if (
                rule.region == region
                and rule.data_category == data_category
                and self.stage_at_least(stage, rule.min_stage)
                and rule.deadline_hours is not None
            ):
                matched.append(rule)
        return matched
