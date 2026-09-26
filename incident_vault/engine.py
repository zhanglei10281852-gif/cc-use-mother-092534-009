"""领域引擎：所有处置命令在此校验不变量并产生追加事件。

关键不变量
----------
* 证据以指纹去重；更正只能追加 ``evidence.corrected`` 并引用被更正项。
* 暴露阶段不得深于证据所支持的深度（listed < packaged < delivered）。
* 调查员判断冲突自动进入复核；一致才确认范围。
* 通知义务按代际追加：结论变化时仅作废“尚未发送”的义务，
  已发送通知作为确认事实永不撤回。
* 对外披露须法务与安全双签，发布时隐去范围外租户信息。
* 全局隔离会中断所有租户，默认禁止，须事件指挥官给出理由。
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any

from .errors import DomainError
from .models import Role, Stage, Verdict
from .policy import PolicyEngine
from .store import EventStore

# 证据种类可支持的暴露阶段上限/下限。
KIND_STAGE_SUPPORT: dict[str, set[Stage]] = {
    "suspicious_request": {Stage.NONE},
    "listing_summary": {Stage.LISTED, Stage.PACKAGED},
    "delivery_receipt": {Stage.PACKAGED, Stage.DELIVERED},
}


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class IncidentEngine:
    def __init__(self, store: EventStore, policy: PolicyEngine | None = None) -> None:
        self.store = store
        self.policy = policy or PolicyEngine()

    # ============================================================== 事件生命周期

    def open_incident(self, incident_id: str, title: str, actor: str,
                      clock_anchor: datetime | None = None) -> dict:
        if incident_id in self.store.projection.incidents:
            raise DomainError(f"事件已存在：{incident_id}")
        anchor = clock_anchor or datetime.now().astimezone()
        if anchor.tzinfo is None:
            raise DomainError("监管时钟锚点必须包含时区")
        self.store.append(incident_id, "incident.opened", actor,
                          {"title": title, "clock_anchor": anchor.isoformat()})
        return self.store.projection.incidents[incident_id]

    def close_incident(self, incident_id: str, actor: str) -> None:
        incident = self._incident(incident_id)
        pending = [d for d in self.store.projection.incident_duties(incident_id)
                   if d["status"] == "pending"]
        if pending:
            raise DomainError(f"仍有 {len(pending)} 项待发送通知，不能关闭事件")
        self.store.append(incident_id, "incident.closed", actor, {})

    def reopen_incident(self, incident_id: str, actor: str, reason: str) -> None:
        self.store.append(incident_id, "incident.reopened", actor, {"reason": reason})

    # ============================================================== 证据保全

    def preserve_evidence(self, incident_id: str, kind: str, tenant_id: str,
                          source_ref: str, data_categories: list[str], *,
                          actor: str, fingerprint: str | None = None,
                          stage: str | None = None,
                          credential_version: str | None = None,
                          captured_at: datetime | None = None,
                          summary: str = "",
                          occurred_at: datetime | None = None) -> dict:
        """保全一条证据。

        同一 (事件, 指纹) 重复导入不会新建证据、不扩大计数，
        只返回已保全记录与 ``duplicated=True``。
        """
        self._incident(incident_id)
        if kind not in KIND_STAGE_SUPPORT:
            raise DomainError(f"未知证据种类：{kind}")
        supported = KIND_STAGE_SUPPORT[kind]
        claimed = Stage(stage) if stage else min(supported, key=lambda s: s.depth)
        if claimed not in supported:
            raise DomainError(f"证据种类 {kind} 不能证明暴露阶段 {claimed.value}")
        fp = fingerprint or f"sha256:{source_ref}:{tenant_id}:{claimed.value}"
        existing = self.store.projection.evidence_fingerprints.get((incident_id, fp))
        if existing:
            record = dict(self.store.projection.evidence[existing])
            record["duplicated"] = True
            return record
        evidence_id = _new_id("ev")
        captured = captured_at or occurred_at or datetime.now().astimezone()
        if captured.tzinfo is None:
            raise DomainError("证据采集时间必须包含时区")
        payload = {
            "evidence_id": evidence_id, "kind": kind, "tenant_id": tenant_id,
            "fingerprint": fp, "source_ref": source_ref,
            "data_categories": sorted(set(data_categories)),
            "credential_version": credential_version,
            "captured_at": captured.isoformat(), "stage": claimed.value,
            "supersedes": None, "summary": summary,
        }
        self.store.append(incident_id, "evidence.preserved", actor, payload,
                          occurred_at=occurred_at)
        return dict(self.store.projection.evidence[evidence_id], duplicated=False)

    def correct_evidence(self, incident_id: str, supersedes_id: str, *,
                         actor: str, reason: str, **fields: Any) -> dict:
        """更正证据：原记录保留，追加一条引用它的新记录（原链不断）。"""
        old = self.store.projection.evidence.get(supersedes_id)
        if old is None or old["incident_id"] != incident_id:
            raise DomainError(f"被更正证据不属于本事件：{supersedes_id}")
        if old.get("supersedes"):
            raise DomainError("应更正最新版本的证据，不得越级更正")
        merged = {
            "kind": old["kind"], "tenant_id": old["tenant_id"],
            "source_ref": old["source_ref"],
            "data_categories": old["data_categories"],
            "credential_version": old["credential_version"],
            "stage": old.get("stage", "none"),
            "summary": old["summary"], "fingerprint": None,
        }
        merged.update(fields)
        claimed = Stage(merged["stage"])
        if claimed not in KIND_STAGE_SUPPORT[merged["kind"]]:
            raise DomainError(f"证据种类 {merged['kind']} 不能证明暴露阶段 {claimed.value}")
        new_id = _new_id("ev")
        fp = merged["fingerprint"] or f"sha256:corr:{new_id}"
        if self.store.projection.evidence_fingerprints.get((incident_id, fp)):
            raise DomainError("更正内容与既有证据指纹相同，应直接引用原证据")
        payload = {
            "evidence_id": new_id, "kind": merged["kind"],
            "tenant_id": merged["tenant_id"], "fingerprint": fp,
            "source_ref": merged["source_ref"],
            "data_categories": sorted(set(merged["data_categories"])),
            "credential_version": merged["credential_version"],
            "captured_at": datetime.now().astimezone().isoformat(),
            "stage": claimed.value, "supersedes": supersedes_id,
            "summary": f"[更正] {reason} | {merged['summary']}",
        }
        self.store.append(incident_id, "evidence.corrected", actor, payload)
        # 更正可能加深或减弱暴露阶段，受影响条目待调查员复核后重评义务。
        return self.store.projection.evidence[new_id]

    def custody_chain(self, incident_id: str) -> list[dict]:
        """按保全顺序返回证据链（含被更正的历史版本）。"""
        return [self.store.projection.evidence[eid]
                for eid in self.store.projection.custody[incident_id]]

    # ============================================================== 范围认定

    def record_finding(self, incident_id: str, tenant_id: str, region: str,
                       evidence_ids: list[str], *, actor: str,
                       basis: str, party_id: str | None = None,
                       extra_categories: list[str] | None = None,
                       credential_versions: list[str] | None = None) -> dict:
        self._incident(incident_id)
        records = self.store.evidence_for(incident_id, evidence_ids)
        stage = max((Stage(self._evidence_stage(r)) for r in records),
                    default=Stage.NONE, key=lambda s: s.depth)
        categories: set[str] = set()
        for r in records:
            categories.update(r["data_categories"])
        categories.update(extra_categories or [])
        creds = list(credential_versions or {r["credential_version"] for r in records
                                             if r["credential_version"]})
        pid = party_id or _new_id("party")
        if pid in self.store.projection.parties:
            raise DomainError(f"范围条目已存在：{pid}（补充结论请用 supplement_finding）")
        self.store.append(incident_id, "finding.recorded", actor, {
            "party_id": pid, "tenant_id": tenant_id, "region": region,
            "data_categories": sorted(categories), "stage": stage.value,
            "evidence_ids": evidence_ids, "credential_versions": creds,
            "basis": basis,
        })
        return self.store.projection.parties[pid]

    def supplement_finding(self, party_id: str, evidence_ids: list[str], *,
                           actor: str, reason: str,
                           extra_categories: list[str] | None = None) -> dict:
        """追加证据到既有范围条目（只追加），随后按新结论重评义务。"""
        party = self.store.party(party_id)
        records = self.store.evidence_for(party["incident_id"], evidence_ids)
        new_stage = max([Stage(party["stage"])]
                        + [Stage(self._evidence_stage(r)) for r in records],
                        key=lambda s: s.depth)
        categories = set(party["data_categories"])
        for r in records:
            categories.update(r["data_categories"])
        categories.update(extra_categories or [])
        merged_ids = list(dict.fromkeys(party["evidence_ids"] + evidence_ids))
        creds = list(dict.fromkeys(party["credential_versions"] +
                                   [r["credential_version"] for r in records if r["credential_version"]]))
        self.store.append(party["incident_id"], "finding.supplemented", actor, {
            "party_id": party_id, "evidence_ids": merged_ids,
            "data_categories": sorted(categories), "stage": new_stage.value,
            "credential_versions": creds, "reason": reason,
        })
        party = self.store.projection.parties[party_id]
        party["evidence_ids"] = merged_ids
        party["data_categories"] = categories
        party["stage"] = new_stage.value
        party["credential_versions"] = creds
        party["history"].append({"type": "supplement", "by": actor, "reason": reason,
                                 "stage": new_stage.value})
        if party["status"] in ("confirmed", "notifying", "notified"):
            self._recompute_duties(party)
        return party

    def judge_scope(self, party_id: str, investigator: str, verdict: str,
                    reason: str) -> dict:
        """调查员对范围作出判断；不同调查员冲突即进入复核。"""
        party = self.store.party(party_id)
        v = Verdict(verdict)
        self.store.append(party["incident_id"], "scope.judged", investigator,
                          {"party_id": party_id, "verdict": v.value, "reason": reason})
        prior = [j for j in party["judgments"] if j["investigator"] != investigator]
        distinct_investigators = {j["investigator"] for j in party["judgments"]}
        review = self.store.projection.reviews.get(party_id)
        if review and review["status"] == "open":
            return party  # 已在复核中，等待指挥官裁决
        if prior and any(j["verdict"] != v.value for j in prior):
            self.store.append(party["incident_id"], "scope.contested", investigator, {
                "party_id": party_id,
                "reason": f"调查员对范围存在冲突判断，进入复核：{reason}",
            })
        elif len(distinct_investigators) >= 2 and all(
                j["verdict"] == v.value for j in party["judgments"]):
            self.store.append(party["incident_id"], "scope.consensus", investigator,
                              {"party_id": party_id, "verdict": v.value})
            if v == Verdict.AFFECTED:
                self._recompute_duties(self.store.party(party_id))
        return self.store.party(party_id)

    def contest_scope(self, party_id: str, actor: str, reason: str) -> None:
        """主动发起复核（例如对自动一致结论有异议）。"""
        party = self.store.party(party_id)
        self.store.append(party["incident_id"], "scope.contested", actor,
                          {"party_id": party_id, "reason": reason})

    def resolve_review(self, party_id: str, commander: str,
                       final_verdict: str, reason: str) -> dict:
        """事件指挥官裁决范围。

        可裁决两种情形：调查员冲突形成的待决复核，或仅有初步判断、
        指挥官依证据直接定夺的未决条目；裁决同样追加在链上。
        """
        party = self.store.party(party_id)
        review = self.store.projection.reviews.get(party_id)
        if review and review["status"] != "open":
            raise DomainError("该条目的复核已经裁决，应重新发起复核")
        if not review and party["status"] not in ("proposed", "excluded"):
            raise DomainError("范围已确认且无待决复核，不能直接裁决")
        self.store.append(party["incident_id"], "scope.resolved", commander, {
            "party_id": party_id, "resolution": "approved"
            if final_verdict == Verdict.AFFECTED.value else "rejected",
            "final_verdict": Verdict(final_verdict).value, "reason": reason,
        })
        party = self.store.party(party_id)
        self._recompute_duties(party)  # 排除时作废尚未发送的义务
        return party

    # ============================================================== 通知义务

    def _next_generation(self, party_id: str) -> int:
        gens = [d["generation"] for d in self.store.projection.duties.values()
                if d["party_id"] == party_id]
        return (max(gens) + 1) if gens else 1

    def _recompute_duties(self, party: dict) -> list[dict]:
        """依据当前结论重新评估义务。

        新结论覆盖的规则：补提（新一代）；不再适用的规则：仅作废
        尚处于 pending 的义务；已经 sent 的义务原样保留——
        已确认的对外事实不撤回。
        """
        incident = self.store.projection.incidents[party["incident_id"]]
        active = [d for d in self.store.projection.incident_duties(party["incident_id"])
                  if d["party_id"] == party["party_id"]
                  and d["status"] in ("pending", "sent")]
        generation = self._next_generation(party["party_id"])
        if party["status"] in ("confirmed", "notifying", "notified"):
            results = self.policy.evaluate(
                party["region"], set(party["data_categories"]),
                Stage(party["stage"]), incident["clock_anchor"])
        else:
            results = []
        wanted = {r.rule_code: r for r in results}
        kept = {d["rule_code"] for d in active}
        # 作废：现存但新结论不再需要、且尚未发送
        for d in active:
            if d["status"] == "pending" and d["rule_code"] not in wanted:
                self.store.append(party["incident_id"], "duty.superseded",
                                  "system", {"duty_id": d["duty_id"],
                                             "generation": generation,
                                             "reason": "调查结论变化，义务不再适用"})
        # 新增：新结论需要、且历史上既无待发也无已发
        for rule_code, result in wanted.items():
            if rule_code in kept:
                continue
            duty_id = _new_id("duty")
            self.store.append(party["incident_id"], "duty.generated", "system", {
                "duty_id": duty_id, "party_id": party["party_id"],
                "generation": generation, "rule_code": rule_code,
                "channel": result.channel, "regulator": result.regulator,
                "deadline": result.deadline.isoformat(),
                "stage": result.stage, "data_category": result.data_category,
                "description": result.description,
            })
        return [d for d in self.store.projection.incident_duties(party["incident_id"])
                if d["party_id"] == party["party_id"]]

    def send_notification(self, duty_id: str, actor: str, receipt: str) -> dict:
        duty = self.store.projection.duties.get(duty_id)
        if duty is None:
            raise DomainError(f"未知通知义务：{duty_id}")
        if duty["status"] != "pending":
            raise DomainError(f"义务当前状态为 {duty['status']}，不能重复发送")
        self.store.append(duty["incident_id"], "notification.sent", actor,
                          {"duty_id": duty_id, "receipt": receipt})
        return self.store.projection.duties[duty_id]

    def pending_queue(self, incident_id: str, *, now: datetime | None = None) -> list[dict]:
        """待通知队列，按截止时间排序；服务恢复后由此继续推进。"""
        moment = now or datetime.now().astimezone()
        queue = []
        for d in self.store.projection.incident_duties(incident_id):
            if d["status"] != "pending":
                continue
            item = dict(d)
            item["overdue"] = d["deadline"] < moment
            item["remaining_hours"] = round(
                (d["deadline"] - moment).total_seconds() / 3600, 1)
            queue.append(item)
        return sorted(queue, key=lambda x: x["deadline"])

    # ============================================================== 隔离动作

    def apply_containment(self, incident_id: str, actor: str, reason: str,
                          tenant_ids: list[str] | None = None,
                          *, role: Role = Role.OPERATOR,
                          global_blast: bool = False,
                          occurred_at: datetime | None = None) -> dict:
        self._incident(incident_id)
        if global_blast:
            if role != Role.COMMANDER:
                raise DomainError("全局隔离会中断所有租户，仅事件指挥官可批准")
            if not reason or len(reason) < 10:
                raise DomainError("全局隔离必须提供充分理由")
        action_id = _new_id("iso")
        self.store.append(incident_id, "containment.applied", actor, {
            "action_id": action_id, "tenant_ids": tenant_ids or [],
            "global": global_blast, "reason": reason,
        }, occurred_at=occurred_at)
        return self.store.projection.containment[incident_id][-1]

    # ============================================================== 对外披露

    def create_disclosure(self, incident_id: str, actor: str, title: str,
                          body: str, party_scope: list[str]) -> dict:
        self._incident(incident_id)
        for pid in party_scope:
            party = self.store.projection.parties.get(pid)
            if party is None or party["incident_id"] != incident_id:
                raise DomainError(f"披露范围包含未知条目：{pid}")
            if party["status"] not in ("confirmed", "notifying", "notified"):
                raise DomainError(f"条目 {pid} 尚未确认纳入范围，不能对外披露")
        disclosure_id = _new_id("disc")
        self.store.append(incident_id, "disclosure.created", actor, {
            "disclosure_id": disclosure_id, "title": title, "body": body,
            "party_scope": party_scope,
        })
        return self.store.projection.disclosures[disclosure_id]

    def sign_disclosure(self, disclosure_id: str, actor: str, role: Role) -> dict:
        d = self._disclosure(disclosure_id)
        if role not in (Role.LEGAL, Role.SECURITY):
            raise DomainError("只有法务与安全角色可以签署披露")
        if role.value in d["signatures"]:
            raise DomainError(f"{role.value} 已完成签署，不能重复签署")
        self.store.append(d["incident_id"], "disclosure.signed", actor,
                          {"disclosure_id": disclosure_id, "role": role.value})
        d = self.store.projection.disclosures[disclosure_id]
        if {Role.LEGAL.value, Role.SECURITY.value} <= set(d["signatures"]):
            d["status"] = "signed"
        return d

    def issue_disclosure(self, disclosure_id: str, actor: str) -> dict:
        """双签齐全后发布；自动隐去范围外租户标识。"""
        d = self._disclosure(disclosure_id)
        needed = {Role.LEGAL.value, Role.SECURITY.value}
        if not needed <= set(d["signatures"]):
            raise DomainError("对外披露必须完成法务与安全双签")
        scope_tenants = {self.store.projection.parties[p]["tenant_id"]
                         for p in d["party_scope"]}
        all_tenants = {p["tenant_id"] for p in
                       self.store.projection.incident_parties(d["incident_id"])}
        hidden = sorted(all_tenants - scope_tenants)
        redacted = d["body"]
        for tenant_id in hidden:
            redacted = redacted.replace(tenant_id, "【其他租户信息已隐去】")
        leftover = [t for t in hidden if re.search(re.escape(t), redacted)]
        if leftover:
            raise DomainError(f"披露文本仍含范围外租户信息：{leftover}")
        self.store.append(d["incident_id"], "disclosure.issued", actor, {
            "disclosure_id": disclosure_id, "redacted_body": redacted,
            "hidden_tenants": hidden,
        })
        return self.store.projection.disclosures[disclosure_id]

    # ============================================================== 辅助

    def _evidence_stage(self, record: dict) -> str:
        return record.get("stage", "none")

    def _incident(self, incident_id: str) -> dict:
        incident = self.store.projection.incidents.get(incident_id)
        if incident is None:
            raise DomainError(f"未知事件：{incident_id}")
        return incident

    def _disclosure(self, disclosure_id: str) -> dict:
        d = self.store.projection.disclosures.get(disclosure_id)
        if d is None:
            raise DomainError(f"未知披露：{disclosure_id}")
        return d
