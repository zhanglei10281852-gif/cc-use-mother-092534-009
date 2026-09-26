"""领域枚举与值对象。"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class EvidenceKind(str, Enum):
    """证据种类：可疑请求、清单摘要、交付回执。"""

    SUSPICIOUS_REQUEST = "suspicious_request"
    LISTING_SUMMARY = "listing_summary"
    DELIVERY_RECEIPT = "delivery_receipt"


class Stage(str, Enum):
    """实际暴露阶段。排序即暴露深度：仅列出 < 打包 < 实际领取。"""

    NONE = "none"
    LISTED = "listed"
    PACKAGED = "packaged"
    DELIVERED = "delivered"

    @property
    def depth(self) -> int:
        return {"none": 0, "listed": 1, "packaged": 2, "delivered": 3}[self.value]


class Role(str, Enum):
    """处置角色。对外披露需要 LEGAL 与 SECURITY 双签。"""

    OPERATOR = "operator"
    INVESTIGATOR = "investigator"
    LEGAL = "legal"
    SECURITY = "security"
    COMMANDER = "commander"


class Verdict(str, Enum):
    """调查员对受影响范围的判断。"""

    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNCERTAIN = "uncertain"


class PartyStatus(str, Enum):
    """受影响方条目状态；更正只能追加，不删除旧判断。"""

    PROPOSED = "proposed"        # 已有调查判断，等待范围复核
    CONFIRMED = "confirmed"      # 范围已批准
    EXCLUDED = "excluded"        # 经复核排除（保留纳入痕迹与理由）
    NOTIFYING = "notifying"      # 存在尚未完成的通知义务
    NOTIFIED = "notified"        # 本代义务全部完成


class DutyStatus(str, Enum):
    PENDING = "pending"
    SENT = "sent"
    SUPERSEDED = "superseded"    # 被新一代义务替代（调查结论变化）


class ReviewStatus(str, Enum):
    OPEN = "open"
    APPROVED = "approved"
    REJECTED = "rejected"


class DisclosureStatus(str, Enum):
    DRAFT = "draft"
    SIGNED = "signed"            # 已完成法务与安全双签
    ISSUED = "issued"


@dataclass(frozen=True)
class DataCategory:
    """数据类别：决定通知义务与时限。"""

    code: str
    name: str

    def __str__(self) -> str:
        return f"{self.code}:{self.name}"


@dataclass(frozen=True)
class CredentialVersion:
    """凭据版本：泄露关联到具体版本，轮换不改变历史关联。"""

    tenant_id: str
    version: str
    rotated_at: str | None = None
