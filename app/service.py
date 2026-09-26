"""应用服务：事件指挥官与调查员使用的命令/查询接口。

所有写操作都被翻译为只追加事件；读操作基于重放投影。
"""
from __future__ import annotations

import uuid
from datetime import timedelta

from .clock import iso, parse_ts
from .event_store import EventStore
from .fingerprint import fingerprint
from .policy_engine import NotificationPolicy
from .projections import ReadModel


class DomainError(Exception):
    """业务规则拒绝。"""


class ScopeConflictError(DomainError):
    """并发调查员对同一租户范围给出冲突判断，必须进入复核。"""


class GlobalDisruptionError(DomainError):
    """默认拒绝影响全部租户的中断性处置。"""


def _eid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class IncidentSystem:
    def __init__(self, store: EventStore, policy: NotificationPolicy | None = None) -> None:
        self.store = store
        self.policy = policy or NotificationPolicy.load()
        self.model = ReadModel()
        for event in store.events():
            self._apply(event)

    # ----- 内部 -----
    def _apply(self, event: dict) -> None:
        self.model.apply(event)

    def _record(self, event_type: str, case_id: str, actor: str, occurred_at: str, payload: dict,
                event_id: str | None = None) -> dict:
        event = {
            "event_id": event_id or _eid("evt"),
            "event_type": event_type,
            "aggregate_id": case_id,
            "occurred_at": occurred_at,
            "actor_id": actor,
            "payload": payload,
        }
        record = self.store.append(event)
        self._apply(record["event"])
        return record["event"]

    # ----- 事件生命周期 -----
    def open_incident(self, actor: str, occurred_at: str, title: str, severity: str = "high",
                      case_id: str | None = None) -> dict:
        case_id = case_id or _eid("case")
        return self._record("incident.opened", case_id, actor, occurred_at,
                            {"title": title, "severity": severity}, event_id=_eid("evt"))

    def contain(self, actor: str, occurred_at: str, reason: str) -> dict:
        return self._record("incident.contained", self._case_id(), actor, occurred_at, {"reason": reason})

    def _case_id(self) -> str:
        if self.model.incident is None:
            raise DomainError("事件尚未建立")
        return self.model.incident["case_id"]

    # ----- 证据保全 -----
    def import_evidence(self, actor: str, occurred_at: str, source_kind: str, source_ref: str,
                        content: dict, idempotency_key: str | None = None) -> dict:
        """保全一条证据。按幂等键与 (来源标识, 内容指纹) 双重去重。

        重复导入不会创建证据、不增加计数，只会追加一条 import_rejected 留痕。
        """
        fp = fingerprint(content)
        existing = self._find_existing_evidence(idempotency_key, source_ref, fp)
        if existing is not None:
            self._record(
                "evidence.import_rejected",
                self._case_id(),
                actor,
                occurred_at,
                {
                    "source_kind": source_kind,
                    "source_ref": source_ref,
                    "idempotency_key": idempotency_key or "",
                    "reason": "duplicate_import",
                    "duplicate_of": existing,
                },
            )
            return {"status": "rejected", "reason": "duplicate_import", "evidence_id": existing}
        evidence_id = _eid("ev")
        return self._record(
            "evidence.preserved",
            self._case_id(),
            actor,
            occurred_at,
            {
                "evidence_id": evidence_id,
                "source_kind": source_kind,
                "source_ref": source_ref,
                "idempotency_key": idempotency_key or "",
                "content_fingerprint": fp,
                "content": content,
            },
        )

    def _find_existing_evidence(self, idempotency_key: str | None, source_ref: str, fp: str) -> str | None:
        if idempotency_key and idempotency_key in self.model.idempotency_index:
            return self.model.idempotency_index[idempotency_key]
        return self.model.fingerprint_index.get((source_ref, fp))

    def correct_evidence(self, actor: str, occurred_at: str, corrects_evidence_id: str,
                         reason: str, source_kind: str, source_ref: str, content: dict) -> dict:
        """对已保全证据追加更正。原证据与哈希链原样保留，仅追加一条更正记录。"""
        if corrects_evidence_id not in self.model.evidence:
            raise DomainError(f"被更正证据不存在：{corrects_evidence_id}")
        fp = fingerprint(content)
        evidence_id = _eid("ev")
        return self._record(
            "evidence.corrected",
            self._case_id(),
            actor,
            occurred_at,
            {
                "evidence_id": evidence_id,
                "corrects_evidence_id": corrects_evidence_id,
                "reason": reason,
                "source_kind": source_kind,
                "source_ref": source_ref,
                "content_fingerprint": fp,
                "content": content,
            },
        )

    # ----- 调查结论 -----
    def record_finding(self, actor: str, occurred_at: str, finding_id: str | None, **fields) -> dict:
        required = {"tenant_id", "region", "data_category", "stage"}
        missing = required - set(fields)
        if missing:
            raise DomainError("调查结论缺少字段：" + "、".join(sorted(missing)))
        if fields["stage"] not in self.policy.stage_rank:
            raise DomainError(f"未知暴露阶段：{fields['stage']}")
        payload = {"finding_id": finding_id or _eid("f"), **fields}
        return self._record("finding.recorded", self._case_id(), actor, occurred_at, payload)

    # ----- 范围判定与冲突复核 -----
    def propose_scope(self, actor: str, occurred_at: str, tenant_id: str, included: bool,
                      rationale: str, finding_ids: list[str] | None = None) -> dict:
        event = self._record(
            "scope.proposed",
            self._case_id(),
            actor,
            occurred_at,
            {"tenant_id": tenant_id, "included": included, "rationale": rationale,
             "finding_ids": finding_ids or []},
        )
        state = self.model.scope_state(tenant_id)
        if state.get("conflicted") and not state["current_round"].contested_recorded:
            # 冲突已被日志固定：自动留痕一次 contested，调度系统据此拉入复核队列
            self._record(
                "scope.contested",
                self._case_id(),
                "system",
                occurred_at,
                {"tenant_id": tenant_id,
                 "proposal_ids": [p.event_id for p in state["current_round"].proposals]},
            )
        if state.get("conflicted"):
            raise ScopeConflictError(
                f"租户 {tenant_id} 范围判断冲突，已进入复核；须由未参与判断的复核人裁决"
            )
        return event

    def resolve_scope(self, actor: str, occurred_at: str, tenant_id: str, included: bool,
                      rationale: str, exclusion_reason: str | None = None) -> dict:
        """复核人作出终局裁决，随后自动重估通知义务。"""
        state = self.model.scope_state(tenant_id)
        round_ = state.get("current_round")
        if round_ is None or not round_.proposals:
            raise DomainError("没有可裁决的范围提案")
        proposers = {p.actor for p in round_.proposals}
        if actor in proposers:
            raise DomainError("裁决人不能是范围提案人之一，必须由独立复核人裁决")
        proposal_ids = [p.event_id for p in round_.proposals]
        payload = {
            "tenant_id": tenant_id,
            "included": included,
            "reviewed_proposal_ids": proposal_ids,
            "rationale": rationale,
        }
        if not included:
            payload["exclusion_reason"] = exclusion_reason or "no_evidence"
        event = self._record("scope.resolved", self._case_id(), actor, occurred_at, payload)
        self._reevaluate_duties(tenant_id, occurred_at)
        return event

    # ----- 通知义务重估 -----
    def _reevaluate_duties(self, tenant_id: str, resolved_at: str) -> dict | None:
        state = self.model.scope_state(tenant_id)
        if state["status"] != "in_scope":
            # 排除：废止尚未发送的义务；已发送通知作为确认事实保留
            for duty in list(self.model.duties.values()):
                if duty.tenant_id == tenant_id and duty.status == "active":
                    self._record(
                        "duty.superseded",
                        self._case_id(),
                        "policy-engine",
                        resolved_at,
                        {"duty_id": duty.duty_id, "tenant_id": tenant_id,
                         "reason": f"scope_excluded:{state.get('exclusion_reason')}"},
                    )
            return None
        anchor = parse_ts(state["anchor_at"])
        region = self.model.tenant_region(tenant_id)
        for finding in self.model.effective_findings(tenant_id):
            for rule in self.policy.evaluate(region, finding.data_category, finding.stage):
                duty_id = f"duty-{tenant_id}-{rule.recipient}-{finding.data_category}"
                existing = self.model.duties.get(duty_id)
                if existing is not None and existing.status in ("active", "sent"):
                    continue  # 已存在保留原锚点与截止；已发送为确认事实永不重建
                # superseded 义务随重新纳入而复活：追加新 calculated 事件，仍用最初锚点，不重置时钟
                deadline = anchor + timedelta(hours=rule.deadline_hours)
                self._record(
                    "duty.calculated",
                    self._case_id(),
                    "policy-engine",
                    iso(anchor + timedelta(seconds=10)),
                    {
                        "duty_id": duty_id,
                        "tenant_id": tenant_id,
                        "recipient_kind": rule.recipient,
                        "data_category": finding.data_category,
                        "stage": finding.stage,
                        "anchor_at": iso(anchor),
                        "deadline_hours": rule.deadline_hours,
                        "deadline_at": iso(deadline),
                        "policy_version": self.policy.policy_version,
                        "basis": {"region": region, "matched_rule": rule.rule_key},
                    },
                )
        return None

    def send_notification(self, actor: str, occurred_at: str, duty_id: str,
                          channel: str, receipt_ref: str) -> dict:
        duty = self.model.duties.get(duty_id)
        if duty is None:
            raise DomainError(f"义务不存在：{duty_id}")
        if duty.status != "active":
            raise DomainError(f"义务当前状态为 {duty.status}，不能发送（已确认事实不可重复/撤回）")
        return self._record(
            "notification.sent",
            self._case_id(),
            actor,
            occurred_at,
            {
                "duty_id": duty_id,
                "tenant_id": duty.tenant_id,
                "recipient_kind": duty.recipient_kind,
                "data_category": duty.data_category,
                "channel": channel,
                "receipt_ref": receipt_ref,
            },
        )

    # ----- 隔离处置 -----
    def apply_isolation(self, actor: str, occurred_at: str, action_id: str, scope_kind: str,
                        approved_global: bool = False, **detail) -> dict:
        disruptive = {"all_tenants", "global", "platform_wide"}
        if scope_kind in disruptive and not approved_global:
            raise GlobalDisruptionError(
                "拒绝影响全部租户的中断性动作；如确有必要须取得显式全局批准 "
                "(approved_global=True) 并留痕"
            )
        return self._record(
            "isolation.applied",
            self._case_id(),
            actor,
            occurred_at,
            {"action_id": action_id, "scope_kind": scope_kind, **detail},
        )

    # ----- 对外披露（双签 + 跨租户隐藏） -----
    def prepare_disclosure(self, actor: str, occurred_at: str, recipient_kind: str,
                           subject: str, disclosure_id: str | None = None) -> dict:
        return self._record(
            "disclosure.prepared",
            self._case_id(),
            actor,
            occurred_at,
            {"disclosure_id": disclosure_id or _eid("dis"),
             "recipient_kind": recipient_kind, "subject": subject},
        )

    def sign_disclosure(self, actor: str, occurred_at: str, disclosure_id: str, role: str) -> dict:
        disclosure = self.model.disclosures.get(disclosure_id)
        if disclosure is None:
            raise DomainError(f"披露包不存在：{disclosure_id}")
        if role not in {"legal", "security"}:
            raise DomainError("签署角色只能是 legal 或 security")
        other = "security" if role == "legal" else "legal"
        if disclosure.signatures.get(other) == actor:
            raise DomainError("法务与安全签署必须是两名不同的责任人")
        return self._record(
            "disclosure.signed",
            self._case_id(),
            actor,
            occurred_at,
            {"disclosure_id": disclosure_id, "role": role},
        )

    def render_disclosure(self, disclosure_id: str, allowed_tenant_ids: set[str] | None = None) -> dict:
        """生成对外发布视图：只含案件级信息与被允许租户（默认不含任何租户明细）。"""
        disclosure = self.model.disclosures.get(disclosure_id)
        if disclosure is None:
            raise DomainError(f"披露包不存在：{disclosure_id}")
        allowed = allowed_tenant_ids or set()
        return {
            "disclosure_id": disclosure.disclosure_id,
            "subject": disclosure.subject,
            "recipient_kind": disclosure.recipient_kind,
            "incident": {
                "case_id": self.model.incident["case_id"],
                "severity": self.model.incident["severity"],
                "opened_at": self.model.incident["opened_at"],
            },
            "tenants": [self.explain_party(t) for t in self.model.in_scope_tenants() if t in allowed],
        }

    def release_disclosure(self, actor: str, occurred_at: str, disclosure_id: str,
                           allowed_tenant_ids: set[str] | None = None) -> dict:
        disclosure = self.model.disclosures.get(disclosure_id)
        if disclosure is None:
            raise DomainError(f"披露包不存在：{disclosure_id}")
        if set(disclosure.signatures) != {"legal", "security"}:
            raise DomainError("对外披露必须完成法务与安全双签")
        signers = set(disclosure.signatures.values())
        if len(signers) != 2:
            raise DomainError("双签必须来自两名不同责任人")
        if disclosure.released_event is not None:
            raise DomainError("披露包已发布，不可重复发布；更正请另发新版本")
        view = self.render_disclosure(disclosure_id, allowed_tenant_ids)
        event = self._record(
            "disclosure.released",
            self._case_id(),
            actor,
            occurred_at,
            {"disclosure_id": disclosure_id,
             "visible_tenant_ids": sorted(allowed_tenant_ids or set())},
        )
        return {"event": event, "view": view}

    # ----- 管理接口：解释每一方为何纳入/排除 -----
    def explain_party(self, tenant_id: str) -> dict:
        state = self.model.scope_state(tenant_id)
        findings = []
        for f in self.model.findings.values():
            if f.tenant_id != tenant_id:
                continue
            findings.append(
                {
                    "finding_id": f.finding_id,
                    "stage": f.stage,
                    "data_category": f.data_category,
                    "region": f.region,
                    "summary": f.summary,
                    "verdict": f.verdict,
                    "superseded_by": f.superseded_by,
                    "credential_version_id": f.credential_version_id,
                    "evidence": [
                        {"evidence_id": eid, "source_kind": self.model.evidence[eid].source_kind,
                         "source_ref": self.model.evidence[eid].source_ref,
                         "corrects": self.model.evidence[eid].corrects}
                        for eid in f.evidence_ids if eid in self.model.evidence
                    ],
                }
            )
        rounds = []
        for index, round_ in enumerate(state.get("rounds", []), start=1):
            rounds.append(
                {
                    "round": index,
                    "conflicted": round_.conflicted,
                    "proposals": [
                        {"actor": p.actor, "included": p.included, "rationale": p.rationale, "at": p.at}
                        for p in round_.proposals
                    ],
                    "resolution": (
                        {
                            "by": round_.resolution["actor_id"],
                            "at": round_.resolution["occurred_at"],
                            "included": round_.resolution["payload"].get("included"),
                            "rationale": round_.resolution["payload"].get("rationale"),
                            "exclusion_reason": round_.resolution["payload"].get("exclusion_reason"),
                        }
                        if round_.resolution else None
                    ),
                }
            )
        duties = [
            {
                "duty_id": d.duty_id,
                "recipient_kind": d.recipient_kind,
                "status": d.status,
                "deadline_at": d.deadline_at,
                "anchor_at": d.anchor_at,
                "matched_rule": d.basis.get("matched_rule"),
            }
            for d in self.model.duties.values()
            if d.tenant_id == tenant_id
        ]
        return {
            "tenant_id": tenant_id,
            "decision": state["status"],
            "exclusion_reason": state.get("exclusion_reason"),
            "regulatory_anchor_at": state.get("anchor_at"),
            "findings": findings,
            "scope_rounds": rounds,
            "notification_duties": duties,
        }

    # ----- 队列与时钟（恢复后续跑） -----
    def pending_queue(self, as_of: str) -> list[dict]:
        rows = []
        for duty in self.model.pending_duties():
            rows.append(
                {
                    "duty_id": duty.duty_id,
                    "tenant_id": duty.tenant_id,
                    "recipient_kind": duty.recipient_kind,
                    "deadline_at": duty.deadline_at,
                    "clock_status": self.model.duty_status_at(duty, as_of),
                }
            )
        return rows

    def verify_integrity(self) -> None:
        self.store.verify_chain()
