"""服务门面：组合存储、策略引擎与领域引擎，提供统一入口。"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .engine import IncidentEngine
from .models import Role
from .policy import PolicyEngine
from .store import EventStore


class IncidentService:
    """事件指挥官使用的总门面；命令方法见 :class:`IncidentEngine`。"""

    def __init__(self, store_path: str | Path = ":memory:",
                 policy: PolicyEngine | None = None) -> None:
        self.store = EventStore(store_path)
        self.policy = policy or PolicyEngine()
        self.engine = IncidentEngine(self.store, self.policy)

    # 常用命令转发
    def open_incident(self, *args, **kwargs):
        return self.engine.open_incident(*args, **kwargs)

    def preserve_evidence(self, *args, **kwargs):
        return self.engine.preserve_evidence(*args, **kwargs)

    def correct_evidence(self, *args, **kwargs):
        return self.engine.correct_evidence(*args, **kwargs)

    def record_finding(self, *args, **kwargs):
        return self.engine.record_finding(*args, **kwargs)

    def judge_scope(self, *args, **kwargs):
        return self.engine.judge_scope(*args, **kwargs)

    def resolve_review(self, *args, **kwargs):
        return self.engine.resolve_review(*args, **kwargs)

    def send_notification(self, *args, **kwargs):
        return self.engine.send_notification(*args, **kwargs)

    def apply_containment(self, *args, tenant_ids=None, role=Role.OPERATOR, **kwargs):
        return self.engine.apply_containment(
            *args, tenant_ids=tenant_ids, role=role, **kwargs)

    def close(self) -> None:
        self.store.close()

    def verify_chain(self) -> dict:
        return self.store.verify_chain()

    def pending_queue(self, incident_id: str, *, now: datetime | None = None):
        return self.engine.pending_queue(incident_id, now=now)
