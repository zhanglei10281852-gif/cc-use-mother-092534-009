"""统一时间语义：所有时间戳均为带时区的 ISO 8601 绝对时刻。"""
from __future__ import annotations

from datetime import datetime, timezone


def parse_ts(value: str | datetime) -> datetime:
    """解析为带时区 datetime；拒绝无时区时间（监管时钟必须可跨重启比较）。"""
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        raise ValueError(f"时间戳必须包含时区：{value!r}")
    return dt


def iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("时间戳必须包含时区")
    return dt.isoformat()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
