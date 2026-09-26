"""管理解释接口：对每名受影响方“为何纳入 / 为何排除”给出可审计说明。

输出全部来自事件流投影，不做额外判断，保证解释与系统动作同源。
"""
from __future__ import annotations

from datetime import datetime

from .models import Stage
from .store import EventStore


class AdminReporter:
    def __init__(self, store: EventStore) -> None:
        self.store = store

    def explain_party(self, party_id: str) -> dict:
        party = self.store.party(party_id)
        review = self.store.projection.reviews.get(party_id)
        evidence = self.store.evidence_for(party["incident_id"], party["evidence_ids"])
        duties = [d for d in self.store.projection.incident_duties(party["incident_id"])
                  if d["party_id"] == party_id]
        inclusion = self._inclusion_reason(party, review, evidence)
        return {
            "party_id": party_id,
            "tenant_id": party["tenant_id"],
            "region": party["region"],
            "status": party["status"],
            "stage": party["stage"],
            "data_categories": sorted(party["data_categories"]),
            "credential_versions": party["credential_versions"],
            "included": party["status"] in ("confirmed", "notifying", "notified"),
            "reason": inclusion["reason"],
            "reason_code": inclusion["code"],
            "evidence": [
                {"evidence_id": e["evidence_id"], "kind": e["kind"],
                 "stage": e["stage"], "fingerprint": e["fingerprint"],
                 "supersedes": e.get("supersedes")}
                for e in evidence
            ],
            "judgments": party["judgments"],
            "review": review,
            "duties": [
                {"duty_id": d["duty_id"], "rule_code": d["rule_code"],
                 "channel": d["channel"], "regulator": d["regulator"],
                 "deadline": d["deadline"].isoformat(), "status": d["status"],
                 "generation": d["generation"]}
                for d in duties
            ],
            "timeline": party["history"],
        }

    def _inclusion_reason(self, party: dict, review: dict | None,
                          evidence: list[dict]) -> dict:
        status = party["status"]
        if status == "proposed":
            if review and review["status"] == "open":
                return {"code": "PENDING_REVIEW",
                        "reason": f"调查员判断冲突，复核进行中：{review['reason']}"}
            return {"code": "PENDING_JUDGMENT",
                    "reason": "已记录线索但调查员尚未形成一致结论，暂不纳入通知范围"}
        if status == "excluded":
            resolution = review or {}
            return {"code": "EXCLUDED_BY_REVIEW",
                    "reason": f"经复核排除：{resolution.get('resolve_reason', '结论为不受影响')}；"
                              f"纳入申请与全部证据仍保留在链上"}
        kinds = {e["kind"] for e in evidence}
        return {
            "code": "CONFIRMED_EXPOSURE",
            "reason": (
                f"暴露阶段 {party['stage']}（"
                + self._stage_basis(kinds)
                + f"），地区 {party['region']}，数据类别 "
                f"{sorted(party['data_categories'])}，经范围确认后纳入；"
                f"关联凭据版本 {party['credential_versions'] or '无'}"
            ),
        }

    @staticmethod
    def _stage_basis(kinds: set[str]) -> str:
        if "delivery_receipt" in kinds:
            return "存在交付回执，证明文件被实际领取"
        if "listing_summary" in kinds:
            return "存在清单摘要，证明文件被列出或打包"
        return "仅可疑请求，未证实文件离开运行空间"

    def roster(self, incident_id: str) -> list[dict]:
        """受影响方名册摘要。"""
        rows = []
        for party in self.store.projection.incident_parties(incident_id):
            duties = [d for d in self.store.projection.incident_duties(incident_id)
                      if d["party_id"] == party["party_id"]]
            rows.append({
                "party_id": party["party_id"], "tenant_id": party["tenant_id"],
                "region": party["region"], "stage": party["stage"],
                "status": party["status"],
                "included": party["status"] in ("confirmed", "notifying", "notified"),
                "pending_duties": sum(1 for d in duties if d["status"] == "pending"),
                "sent_duties": sum(1 for d in duties if d["status"] == "sent"),
            })
        return sorted(rows, key=lambda r: (not r["included"], r["tenant_id"]))

    def clock_status(self, incident_id: str, now: datetime | None = None) -> dict:
        """监管时钟与队列状态；服务恢复后据此继续推进。"""
        moment = now or datetime.now().astimezone()
        incident = self.store.projection.incidents[incident_id]
        queue = []
        sent = 0
        for d in self.store.projection.incident_duties(incident_id):
            if d["status"] == "pending":
                queue.append({
                    "duty_id": d["duty_id"], "party_id": d["party_id"],
                    "rule_code": d["rule_code"], "channel": d["channel"],
                    "deadline": d["deadline"].isoformat(),
                    "remaining_hours": round(
                        (d["deadline"] - moment).total_seconds() / 3600, 1),
                    "overdue": d["deadline"] < moment,
                })
            elif d["status"] == "sent":
                sent += 1
        queue.sort(key=lambda x: x["deadline"])
        return {
            "incident_id": incident_id,
            "clock_anchor": incident["clock_anchor"].isoformat(),
            "elapsed_hours": round(
                (moment - incident["clock_anchor"]).total_seconds() / 3600, 1),
            "pending": len(queue), "sent": sent, "queue": queue,
            "containment": self.store.projection.containment[incident_id],
        }
