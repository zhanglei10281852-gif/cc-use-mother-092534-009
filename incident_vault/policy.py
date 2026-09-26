"""通知策略引擎：按租户地区、数据类别与实际暴露阶段计算义务和截止时间。

策略为数据驱动的规则表，规则按 (地区, 数据类别, 最低阶段) 匹配；
时限自事件被确认发现（监管时钟锚点）起算，服务中断不暂停时钟。
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from .models import Stage

# 内置默认策略；可被 JSON 文件整体替换（新版本追加，不就地改历史）。
DEFAULT_RULES: list[dict] = [
    {
        "rule_code": "R-EU-PI-DEEP",
        "region": "EU",
        "data_category": "personal_data",
        "min_stage": "packaged",
        "deadline_hours": 72,
        "channel": "regulator",
        "regulator": "EU-DPA",
        "description": "个人数据被打包或领取，72 小时内通知监管机构",
    },
    {
        "rule_code": "R-CN-PI-LIST",
        "region": "CN",
        "data_category": "personal_info",
        "min_stage": "listed",
        "deadline_hours": 72,
        "channel": "regulator",
        "regulator": "CN-CAC",
        "description": "个人信息被列出即触发，72 小时内通知监管部门",
    },
    {
        "rule_code": "R-US-PI-DELIVER",
        "region": "US",
        "data_category": "personal_data",
        "min_stage": "delivered",
        "deadline_hours": 48,
        "channel": "regulator",
        "regulator": "US-AG",
        "description": "个人数据被实际领取，48 小时内通知州监管",
    },
    {
        "rule_code": "R-SECRET-DELIVER",
        "region": "*",
        "data_category": "credential_secret",
        "min_stage": "delivered",
        "deadline_hours": 24,
        "channel": "security_team",
        "regulator": None,
        "description": "凭据密钥被实际领取，24 小时内通报安全团队并强制轮换",
    },
    {
        "rule_code": "R-TENANT-ANY-DELIVER",
        "region": "*",
        "data_category": "*",
        "min_stage": "delivered",
        "deadline_hours": 72,
        "channel": "tenant",
        "regulator": None,
        "description": "任何数据被实际领取，72 小时内通知租户本人",
    },
]

# 纯内部数据不产生外部通知义务（仅内部通道），用于解释“为何排除”。
INTERNAL_ONLY = {"internal_ops"}


@dataclass(frozen=True)
class DutyResult:
    rule_code: str
    region: str
    data_category: str
    stage: str
    channel: str
    regulator: str | None
    deadline: datetime
    description: str


class PolicyEngine:
    def __init__(self, rules: list[dict] | None = None) -> None:
        self.rules = rules if rules is not None else list(DEFAULT_RULES)

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyEngine":
        rules = json.loads(Path(path).read_text(encoding="utf-8"))
        engine = cls(rules)
        engine.validate_rules()
        return engine

    def validate_rules(self) -> None:
        required = {"rule_code", "region", "data_category", "min_stage", "deadline_hours", "channel"}
        for rule in self.rules:
            missing = required - set(rule)
            if missing:
                raise ValueError(f"策略 {rule.get('rule_code', '?')} 缺少字段：{sorted(missing)}")
            Stage(rule["min_stage"])
            if int(rule["deadline_hours"]) <= 0:
                raise ValueError(f"策略 {rule['rule_code']} 时限必须为正")

    def evaluate(
        self,
        region: str,
        data_categories: set[str],
        reached_stage: Stage,
        anchor: datetime,
    ) -> list[DutyResult]:
        """返回当前结论下应承担的全部义务（已按规则编码去重）。"""
        results: dict[str, DutyResult] = {}
        categories = set(data_categories) - INTERNAL_ONLY
        if not categories:
            categories = {"*"}
        for rule in self.rules:
            region_match = rule["region"] == "*" or rule["region"] == region
            category_match = rule["data_category"] == "*" or rule["data_category"] in categories
            stage_match = reached_stage.depth >= Stage(rule["min_stage"]).depth
            if region_match and category_match and stage_match:
                results[rule["rule_code"]] = DutyResult(
                    rule_code=rule["rule_code"],
                    region=region,
                    data_category=rule["data_category"],
                    stage=reached_stage.value,
                    channel=rule["channel"],
                    regulator=rule.get("regulator"),
                    deadline=anchor + timedelta(hours=int(rule["deadline_hours"])),
                    description=rule.get("description", ""),
                )
        return list(results.values())
