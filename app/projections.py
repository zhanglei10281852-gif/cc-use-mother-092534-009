"""读模型：从只追加事件日志重放得到全部查询视图。

重放是纯函数式折叠：同一份日志必然得到同一状态，因此服务重启后
监管时钟、隔离动作与待通知队列都能无损恢复。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from .clock import parse_ts
from .fingerprint import fingerprint


@dataclass
class EvidenceItem:
    evidence_id: str
    source_kind: str
    source_ref: str
    idempotency_key: str
    content_fingerprint: str
    content: dict
    preserved_at: str
    preserved_by: str
    corrects: str | None = None
    correction_reason: str | None = None


@dataclass
class RejectedImport:
    at: str
    by: str
    source_ref: str
    idempotency_key: str
    reason: str
    duplicate_of: str | None


@dataclass
class Finding:
    finding_id: str
    tenant_id: str
    region: str
    data_category: str
    stage: str
    summary: str
    evidence_ids: list[str]
    credential_version_id: str | None
    recorded_at: str
    recorded_by: str
    superseded_by: str | None = None
    verdict: str = "positive"


@dataclass
class Proposal:
    event_id: str
    actor: str
    at: str
    included: bool
    rationale: str
    finding_ids: list[str]


@dataclass
class ScopeRound:
    proposals: list[Proposal] = field(default_factory=list)
    resolution: dict | None = None  # 整个 scope.resolved 事件
    contested_recorded: bool = False

    @property
    def conflicted(self) -> bool:
        votes = {p.included for p in self.proposals}
        return len(votes) > 1


@dataclass
class Duty:
    duty_id: str
    tenant_id: str
    recipient_kind: str
    data_category: str
    stage: str
    anchor_at: str
    deadline_hours: int
    deadline_at: str
    basis: dict
    policy_version: int | None = None
    status: str = "active"  # active / superseded / sent
    superseded_reason: str | None = None
    notification: dict | None = None


@dataclass
class Disclosure:
    disclosure_id: str
    recipient_kind: str
    subject: str
    prepared_at: str
    signatures: dict[str, str] = field(default_factory=dict)  # role -> actor
    released_event: dict | None = None


class ReadModel:
    def __init__(self) -> None:
        self.incident: dict | None = None
        self.incident_status: str | None = None  # opened / contained / closed / reopened
        self.evidence: dict[str, EvidenceItem] = {}
        self.custody: dict[str, list[dict]] = {}  # evidence_id -> 保管/处置流水
        self.rejected_imports: list[RejectedImport] = []
        self.fingerprint_index: dict[tuple[str, str], str] = {}  # (source_ref, fingerprint) -> evidence_id
        self.idempotency_index: dict[str, str] = {}
        self.findings: dict[str, Finding] = {}
        self.rounds: dict[str, list[ScopeRound]] = {}
        self.duties: dict[str, Duty] = {}
        self.notifications: list[dict] = []
        self.isolations: list[dict] = []
        self.disclosures: dict[str, Disclosure] = {}

    # ----- 折叠入口 -----
    def apply(self, event: dict) -> None:
        etype = event["event_type"]
        payload = event.get("payload", {})
        handler = getattr(self, f"_on_{etype.replace('.', '_')}", None)
        if handler:
            handler(event, payload)

    def _on_incident_opened(self, event: dict, p: dict) -> None:
        self.incident = {
            "case_id": event["aggregate_id"],
            "title": p.get("title"),
            "severity": p.get("severity"),
            "opened_at": event["occurred_at"],
            "opened_by": event["actor_id"],
        }
        self.incident_status = "opened"

    def _on_incident_contained(self, event: dict, p: dict) -> None:
        self.incident_status = "contained"

    def _on_incident_closed(self, event: dict, p: dict) -> None:
        self.incident_status = "closed"

    def _on_incident_reopened(self, event: dict, p: dict) -> None:
        self.incident_status = "reopened"

    def _on_evidence_preserved(self, event: dict, p: dict) -> None:
        item = EvidenceItem(
            evidence_id=p["evidence_id"],
            source_kind=p["source_kind"],
            source_ref=p["source_ref"],
            idempotency_key=p.get("idempotency_key", ""),
            content_fingerprint=p.get("content_fingerprint", fingerprint(p["content"])),
            content=p["content"],
            preserved_at=event["occurred_at"],
            preserved_by=event["actor_id"],
        )
        self._index_evidence(item)
        self.custody.setdefault(item.evidence_id, []).append(
            {"at": event["occurred_at"], "by": event["actor_id"], "action": "preserved", "note": "进入保全"}
        )

    def _on_evidence_corrected(self, event: dict, p: dict) -> None:
        item = EvidenceItem(
            evidence_id=p["evidence_id"],
            source_kind=p["source_kind"],
            source_ref=p["source_ref"],
            idempotency_key=p.get("idempotency_key", f"correction-of:{p['corrects_evidence_id']}"),
            content_fingerprint=p.get("content_fingerprint", fingerprint(p["content"])),
            content=p["content"],
            preserved_at=event["occurred_at"],
            preserved_by=event["actor_id"],
            corrects=p["corrects_evidence_id"],
            correction_reason=p["reason"],
        )
        self._index_evidence(item)
        self.custody.setdefault(item.evidence_id, []).append(
            {"at": event["occurred_at"], "by": event["actor_id"], "action": "correction_added", "note": p["reason"]}
        )
        target = self.custody.setdefault(p["corrects_evidence_id"], [])
        target.append(
            {
                "at": event["occurred_at"],
                "by": event["actor_id"],
                "action": "corrected_by",
                "note": f"由 {item.evidence_id} 追加更正；原记录保留不变：{p['reason']}",
            }
        )

    def _index_evidence(self, item: EvidenceItem) -> None:
        self.evidence[item.evidence_id] = item
        self.fingerprint_index[(item.source_ref, item.content_fingerprint)] = item.evidence_id
        if item.idempotency_key:
            self.idempotency_index.setdefault(item.idempotency_key, item.evidence_id)

    def _on_evidence_import_rejected(self, event: dict, p: dict) -> None:
        self.rejected_imports.append(
            RejectedImport(
                at=event["occurred_at"],
                by=event["actor_id"],
                source_ref=p["source_ref"],
                idempotency_key=p.get("idempotency_key", ""),
                reason=p.get("reason", "rejected"),
                duplicate_of=p.get("duplicate_of"),
            )
        )

    def _on_finding_recorded(self, event: dict, p: dict) -> None:
        evidence_ids = [
            p[k] for k in ("request_evidence_id", "manifest_evidence_id", "receipt_evidence_id") if p.get(k)
        ]
        finding = Finding(
            finding_id=p["finding_id"],
            tenant_id=p["tenant_id"],
            region=p["region"],
            data_category=p["data_category"],
            stage=p["stage"],
            summary=p.get("summary", ""),
            evidence_ids=evidence_ids,
            credential_version_id=p.get("credential_version_id"),
            recorded_at=event["occurred_at"],
            recorded_by=event["actor_id"],
            verdict=p.get("verdict", "positive"),
        )
        self.findings[finding.finding_id] = finding
        if p.get("supersedes_finding_id"):
            prior = self.findings.get(p["supersedes_finding_id"])
            if prior is not None:
                prior.superseded_by = finding.finding_id

    def _pending_round(self, tenant_id: str) -> ScopeRound:
        rounds = self.rounds.setdefault(tenant_id, [])
        if not rounds or rounds[-1].resolution is not None:
            rounds.append(ScopeRound())
        return rounds[-1]

    def _on_scope_proposed(self, event: dict, p: dict) -> None:
        round_ = self._pending_round(p["tenant_id"])
        round_.proposals.append(
            Proposal(
                event_id=event["event_id"],
                actor=event["actor_id"],
                at=event["occurred_at"],
                included=p["included"],
                rationale=p.get("rationale", ""),
                finding_ids=list(p.get("finding_ids", [])),
            )
        )

    def _on_scope_contested(self, event: dict, p: dict) -> None:
        rounds = self.rounds.get(p["tenant_id"], [])
        if rounds and rounds[-1].resolution is None:
            rounds[-1].contested_recorded = True

    def _on_scope_resolved(self, event: dict, p: dict) -> None:
        round_ = self._pending_round(p["tenant_id"])
        round_.resolution = event

    def _on_duty_calculated(self, event: dict, p: dict) -> None:
        # 同一 duty_id 的重新计算（排除后再纳入）沿用最初锚点与截止时间：
        existing = self.duties.get(p["duty_id"])
        duty = Duty(
            duty_id=p["duty_id"],
            tenant_id=p["tenant_id"],
            recipient_kind=p["recipient_kind"],
            data_category=p["data_category"],
            stage=p["stage"],
            anchor_at=p["anchor_at"],
            deadline_hours=p["deadline_hours"],
            deadline_at=p["deadline_at"],
            basis=p.get("basis", {}),
            policy_version=p.get("policy_version"),
        )
        if existing is not None and existing.status == "sent":
            return  # 已发送是确认事实，不允许被重算覆盖
        if existing is not None:
            duty.notification = existing.notification
        self.duties[p["duty_id"]] = duty

    def _on_duty_superseded(self, event: dict, p: dict) -> None:
        duty = self.duties.get(p["duty_id"])
        if duty is None or duty.status == "sent":
            return  # 已确认发送的事实不撤回、不废止
        duty.status = "superseded"
        duty.superseded_reason = p.get("reason")

    def _on_notification_sent(self, event: dict, p: dict) -> None:
        record = dict(p)
        record.update({"sent_at": event["occurred_at"], "sent_by": event["actor_id"], "event_id": event["event_id"]})
        self.notifications.append(record)
        duty = self.duties.get(p["duty_id"])
        if duty is not None:
            duty.status = "sent"
            duty.notification = record

    def _on_isolation_applied(self, event: dict, p: dict) -> None:
        record = dict(p)
        record.update({"applied_at": event["occurred_at"], "applied_by": event["actor_id"]})
        self.isolations.append(record)

    def _on_disclosure_prepared(self, event: dict, p: dict) -> None:
        self.disclosures[p["disclosure_id"]] = Disclosure(
            disclosure_id=p["disclosure_id"],
            recipient_kind=p["recipient_kind"],
            subject=p.get("subject", ""),
            prepared_at=event["occurred_at"],
        )

    def _on_disclosure_signed(self, event: dict, p: dict) -> None:
        disclosure = self.disclosures[p["disclosure_id"]]
        disclosure.signatures[p["role"]] = event["actor_id"]

    def _on_disclosure_released(self, event: dict, p: dict) -> None:
        self.disclosures[p["disclosure_id"]].released_event = event

    # ----- 派生查询 -----
    def all_tenants(self) -> set[str]:
        tenants = set(self.rounds) | {f.tenant_id for f in self.findings.values()}
        return tenants

    def effective_findings(self, tenant_id: str) -> list[Finding]:
        """当前仍有效的正面结论：未被后续结论取代、非误报。"""
        return [
            f
            for f in self.findings.values()
            if f.tenant_id == tenant_id and f.superseded_by is None and f.verdict != "false_positive"
        ]

    def tenant_region(self, tenant_id: str) -> str | None:
        findings = [f for f in self.findings.values() if f.tenant_id == tenant_id]
        return findings[-1].region if findings else None

    def scope_state(self, tenant_id: str) -> dict:
        rounds = self.rounds.get(tenant_id, [])
        if not rounds:
            return {"status": "collecting", "rounds": rounds}
        current = rounds[-1]
        if current.resolution is None:
            return {
                "status": "contested" if current.conflicted else "proposed",
                "conflicted": current.conflicted,
                "rounds": rounds,
                "current_round": current,
            }
        p = current.resolution["payload"]
        # 监管时钟锚点：该方首次被确认纳入的时刻，一经确定不再移动
        anchor = next(
            (
                r.resolution["occurred_at"]
                for r in rounds
                if r.resolution is not None and r.resolution["payload"].get("included")
            ),
            None,
        )
        return {
            "status": "in_scope" if p.get("included") else "out_of_scope",
            "exclusion_reason": p.get("exclusion_reason"),
            "resolved_at": current.resolution["occurred_at"],
            "resolved_by": current.resolution["actor_id"],
            "rationale": p.get("rationale"),
            "anchor_at": anchor,
            "rounds": rounds,
            "current_round": current,
        }

    def in_scope_tenants(self) -> list[str]:
        return sorted(t for t in self.all_tenants() if self.scope_state(t)["status"] == "in_scope")

    def pending_duties(self) -> list[Duty]:
        return sorted(
            (d for d in self.duties.values() if d.status == "active"),
            key=lambda d: d.deadline_at,
        )

    def duty_status_at(self, duty: Duty, as_of: str) -> str:
        if duty.status == "sent":
            return "sent"
        if duty.status == "superseded":
            return "superseded"
        now = parse_ts(as_of)
        deadline = parse_ts(duty.deadline_at)
        if now >= deadline:
            return "overdue"
        if deadline - now <= timedelta(hours=24):
            return "due_within_24h"
        return "on_track"
