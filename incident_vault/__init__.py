"""智能体泄露事件证据保全与处置系统。

唯一事实源是追加式哈希链事件日志（见 :mod:`incident_vault.store`），
所有处置规则在 :mod:`incident_vault.engine` 中，服务门面见
:mod:`incident_vault.service`，管理解释接口见 :mod:`incident_vault.admin`。
"""

from .errors import DomainError
from .models import EvidenceKind, Role, Stage, Verdict
from .service import IncidentService

__all__ = [
    "DomainError",
    "EvidenceKind",
    "IncidentService",
    "Role",
    "Stage",
    "Verdict",
]
