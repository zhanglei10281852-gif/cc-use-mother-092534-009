"""追加式哈希链事件存储。

事件日志是唯一事实源：

* 任何状态变化都以事件追加，不更新、不删除历史；
* 每条事件包含前一条事件的哈希，形成可独立校验的证据链；
* 读模型（投影）随时可从事件全部重建，服务重启后监管时钟、
  隔离动作与待通知队列据此恢复，不依赖易失内存。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable

from .errors import DomainError

SCHEMA = """
create table if not exists events (
    seq          integer primary key autoincrement,
    event_id     text not null unique,
    aggregate_id text not null,
    event_type   text not null,
    actor        text not null,
    occurred_at  text not null,
    payload      text not null,
    prev_hash    text not null,
    hash         text not null
);
"""


def canonical(event_id: str, aggregate_id: str, event_type: str, actor: str,
              occurred_at: str, payload: dict, prev_hash: str) -> bytes:
    body = {
        "event_id": event_id,
        "aggregate_id": aggregate_id,
        "event_type": event_type,
        "actor": actor,
        "occurred_at": occurred_at,
        "payload": payload,
        "prev_hash": prev_hash,
    }
    return json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(event_id: str, aggregate_id: str, event_type: str, actor: str,
           occurred_at: str, payload: dict, prev_hash: str) -> str:
    return hashlib.sha256(canonical(event_id, aggregate_id, event_type, actor,
                                    occurred_at, payload, prev_hash)).hexdigest()


@dataclass
class StoredEvent:
    seq: int
    event_id: str
    aggregate_id: str
    event_type: str
    actor: str
    occurred_at: datetime
    payload: dict
    prev_hash: str
    hash: str


@dataclass
class Projection:
    """从事件流重建的读模型。"""

    incidents: dict[str, dict] = field(default_factory=dict)
    events_by_aggregate: dict[str, list[StoredEvent]] = field(default_factory=lambda: defaultdict(list))
    evidence: dict[str, dict] = field(default_factory=dict)              # evidence_id -> 当前记录
    evidence_fingerprints: dict[tuple[str, str], str] = field(default_factory=dict)  # (incident, fingerprint) -> evidence_id
    custody: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))  # incident -> [evidence_id] 保全顺序
    parties: dict[str, dict] = field(default_factory=dict)               # party_id
    reviews: dict[str, dict] = field(default_factory=dict)               # party_id -> 当前复核
    duties: dict[str, dict] = field(default_factory=dict)                # duty_id
    notifications: list[dict] = field(default_factory=list)
    containment: dict[str, list[dict]] = field(default_factory=lambda: defaultdict(list))
    disclosures: dict[str, dict] = field(default_factory=dict)

    def incident_parties(self, incident_id: str) -> Iterable[dict]:
        return (p for p in self.parties.values() if p["incident_id"] == incident_id)

    def incident_duties(self, incident_id: str) -> Iterable[dict]:
        return (d for d in self.duties.values() if d["incident_id"] == incident_id)


class EventStore:
    """SQLite 支持的追加式存储。``path=":memory:"`` 用于测试。"""

    GENESIS = "0" * 64

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self.connection = sqlite3.connect(self.path, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA busy_timeout=5000")
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.executescript(SCHEMA)
        self.projection = Projection()
        self._rebuild()

    # ------------------------------------------------------------------ 基本读写

    def append(self, aggregate_id: str, event_type: str, actor: str,
               payload: dict, *, event_id: str | None = None,
               occurred_at: datetime | None = None) -> StoredEvent:
        """在事务内追加事件；重复 event_id 被拒绝（不会产生第二条事实）。"""
        occurred = occurred_at or datetime.now().astimezone()
        if isinstance(occurred, str):
            raise DomainError("occurred_at 必须是带时区的 datetime")
        if occurred.tzinfo is None:
            raise DomainError("事件时间必须包含时区")
        eid = event_id or f"evt-{event_type}-{occurred.strftime('%Y%m%d%H%M%S%f')}"
        occurred_text = occurred.isoformat()
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            if self.connection.execute("select 1 from events where event_id=?", (eid,)).fetchone():
                raise DomainError(f"事件标识重复：{eid}")
            prev = self.connection.execute(
                "select hash from events order by seq desc limit 1").fetchone()
            prev_hash = prev["hash"] if prev else self.GENESIS
            h = digest(eid, aggregate_id, event_type, actor, occurred_text, payload, prev_hash)
            cur = self.connection.execute(
                "insert into events(event_id, aggregate_id, event_type, actor, occurred_at, "
                "payload, prev_hash, hash) values (?,?,?,?,?,?,?,?)",
                (eid, aggregate_id, event_type, actor, occurred_text,
                 json.dumps(payload, ensure_ascii=False, sort_keys=True), prev_hash, h),
            )
            self.connection.commit()
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        stored = StoredEvent(
            seq=cur.lastrowid, event_id=eid, aggregate_id=aggregate_id,
            event_type=event_type, actor=actor, occurred_at=occurred,
            payload=payload, prev_hash=prev_hash, hash=h,
        )
        self._apply(stored)
        return stored

    def events(self, aggregate_id: str | None = None) -> list[StoredEvent]:
        if aggregate_id is None:
            rows = self.connection.execute("select * from events order by seq").fetchall()
        else:
            rows = self.connection.execute(
                "select * from events where aggregate_id=? order by seq", (aggregate_id,)).fetchall()
        return [self._row_to_event(row) for row in rows]

    def close(self) -> None:
        self.connection.close()

    # ------------------------------------------------------------------ 链校验

    def verify_chain(self) -> dict:
        """重算整条哈希链。任何篡改或缺环都会抛出 :class:`DomainError`。"""
        rows = self.connection.execute("select * from events order by seq").fetchall()
        prev_hash = self.GENESIS
        for row in rows:
            expected = digest(row["event_id"], row["aggregate_id"], row["event_type"],
                              row["actor"], row["occurred_at"], json.loads(row["payload"]),
                              prev_hash)
            if row["prev_hash"] != prev_hash:
                raise DomainError(f"证据链断裂于 seq={row['seq']}：前链不匹配")
            if row["hash"] != expected:
                raise DomainError(f"证据链被篡改于 seq={row['seq']}：哈希不匹配")
            prev_hash = row["hash"]
        return {"events": len(rows), "tip": prev_hash, "ok": True}

    # ------------------------------------------------------------------ 重建投影

    def _rebuild(self) -> None:
        self.projection = Projection()
        for row in self.connection.execute("select * from events order by seq"):
            self._apply(self._row_to_event(row))

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> StoredEvent:
        return StoredEvent(
            seq=row["seq"], event_id=row["event_id"], aggregate_id=row["aggregate_id"],
            event_type=row["event_type"], actor=row["actor"],
            occurred_at=datetime.fromisoformat(row["occurred_at"]),
            payload=json.loads(row["payload"]), prev_hash=row["prev_hash"], hash=row["hash"],
        )

    def _apply(self, e: StoredEvent) -> None:  # noqa: C901 - 投影路由集中在此
        p = self.projection
        p.events_by_aggregate[e.aggregate_id].append(e)
        data = e.payload

        if e.event_type == "incident.opened":
            p.incidents[e.aggregate_id] = {
                "incident_id": e.aggregate_id, "title": data["title"],
                "opened_at": e.occurred_at, "clock_anchor": datetime.fromisoformat(data["clock_anchor"]),
                "opened_by": e.actor, "status": "open",
            }
        elif e.event_type in ("evidence.preserved", "evidence.corrected"):
            record = {
                "evidence_id": data["evidence_id"], "incident_id": e.aggregate_id,
                "kind": data["kind"], "tenant_id": data["tenant_id"],
                "fingerprint": data["fingerprint"], "source_ref": data["source_ref"],
                "data_categories": list(data["data_categories"]),
                "credential_version": data.get("credential_version"),
                "stage": data.get("stage", "none"),
                "captured_at": datetime.fromisoformat(data["captured_at"]),
                "preserved_at": e.occurred_at, "preserved_by": e.actor,
                "supersedes": data.get("supersedes"),
                "summary": data.get("summary", ""),
            }
            p.evidence[data["evidence_id"]] = record
            key = (e.aggregate_id, data["fingerprint"])
            p.evidence_fingerprints.setdefault(key, data["evidence_id"])
            p.custody[e.aggregate_id].append(data["evidence_id"])
        elif e.event_type == "finding.recorded":
            p.parties[data["party_id"]] = {
                "party_id": data["party_id"], "incident_id": e.aggregate_id,
                "tenant_id": data["tenant_id"], "region": data["region"],
                "data_categories": set(data["data_categories"]),
                "stage": data["stage"],
                "evidence_ids": list(data["evidence_ids"]),
                "credential_versions": list(data.get("credential_versions", [])),
                "basis": data["basis"], "recorded_by": e.actor,
                "recorded_at": e.occurred_at,
                "judgments": [], "status": "proposed", "history": [],
            }
        elif e.event_type == "finding.supplemented":
            party = p.parties[data["party_id"]]
            party["evidence_ids"] = list(data["evidence_ids"])
            party["data_categories"] = set(data["data_categories"])
            party["stage"] = data["stage"]
            party["credential_versions"] = list(data.get("credential_versions", []))
            party["history"].append({"type": "supplement", "by": e.actor,
                                     "reason": data.get("reason", ""),
                                     "stage": data["stage"],
                                     "at": e.occurred_at.isoformat()})
        elif e.event_type == "scope.judged":
            party = p.parties[data["party_id"]]
            party["judgments"].append({
                "investigator": e.actor, "verdict": data["verdict"],
                "reason": data["reason"], "judged_at": e.occurred_at,
            })
            party["history"].append({"type": "judgment", "by": e.actor,
                                     "verdict": data["verdict"], "reason": data["reason"],
                                     "at": e.occurred_at.isoformat()})
        elif e.event_type == "scope.contested":
            p.reviews[data["party_id"]] = {
                "party_id": data["party_id"], "status": "open",
                "reason": data["reason"], "opened_at": e.occurred_at,
                "resolution": None,
            }
            p.parties[data["party_id"]]["status"] = "proposed"
            p.parties[data["party_id"]]["history"].append(
                {"type": "contested", "reason": data["reason"], "at": e.occurred_at.isoformat()})
        elif e.event_type == "scope.resolved":
            review = p.reviews.get(data["party_id"]) or {"party_id": data["party_id"]}
            review["status"] = data["resolution"]
            review["resolution"] = data["final_verdict"]
            review["resolved_by"] = e.actor
            review["resolved_at"] = e.occurred_at
            review["resolve_reason"] = data["reason"]
            p.reviews[data["party_id"]] = review
            party = p.parties[data["party_id"]]
            party["status"] = "confirmed" if data["final_verdict"] == "affected" else "excluded"
            party["history"].append({"type": "resolved", "by": e.actor,
                                     "verdict": data["final_verdict"],
                                     "reason": data["reason"], "at": e.occurred_at.isoformat()})
        elif e.event_type == "scope.consensus":
            party = p.parties[data["party_id"]]
            party["status"] = "confirmed" if data["verdict"] == "affected" else "excluded"
            party["history"].append({"type": "consensus", "verdict": data["verdict"],
                                     "at": e.occurred_at.isoformat()})
        elif e.event_type == "duty.generated":
            p.duties[data["duty_id"]] = {
                "duty_id": data["duty_id"], "incident_id": e.aggregate_id,
                "party_id": data["party_id"], "generation": data["generation"],
                "rule_code": data["rule_code"], "channel": data["channel"],
                "regulator": data.get("regulator"), "deadline": datetime.fromisoformat(data["deadline"]),
                "stage": data["stage"], "data_category": data["data_category"],
                "status": "pending", "description": data.get("description", ""),
            }
        elif e.event_type == "duty.superseded":
            p.duties[data["duty_id"]]["status"] = "superseded"
        elif e.event_type == "notification.sent":
            duty = p.duties[data["duty_id"]]
            duty["status"] = "sent"
            duty["receipt"] = data["receipt"]
            duty["sent_at"] = e.occurred_at
            duty["sent_by"] = e.actor
            p.notifications.append({"duty_id": data["duty_id"], "receipt": data["receipt"],
                                    "sent_at": e.occurred_at, "by": e.actor})
            party = p.parties[duty["party_id"]]
            if all(d["status"] in ("sent", "superseded")
                   for d in p.incident_duties(e.aggregate_id) if d["party_id"] == party["party_id"]):
                party["status"] = "notified"
            else:
                party["status"] = "notifying"
        elif e.event_type == "containment.applied":
            p.containment[e.aggregate_id].append({
                "action_id": data["action_id"], "tenant_ids": list(data.get("tenant_ids", [])),
                "global": data.get("global", False), "reason": data["reason"],
                "by": e.actor, "at": e.occurred_at,
            })
        elif e.event_type == "disclosure.created":
            p.disclosures[data["disclosure_id"]] = {
                "disclosure_id": data["disclosure_id"], "incident_id": e.aggregate_id,
                "title": data["title"], "party_scope": list(data["party_scope"]),
                "body": data["body"], "signatures": {}, "status": "draft",
            }
        elif e.event_type == "disclosure.signed":
            p.disclosures[data["disclosure_id"]]["signatures"][data["role"]] = {
                "by": e.actor, "at": e.occurred_at}
        elif e.event_type == "disclosure.issued":
            d = p.disclosures[data["disclosure_id"]]
            d["status"] = "issued"
            d["issued_at"] = e.occurred_at
            d["issued_by"] = e.actor
            d["redacted_other_tenants"] = True
        elif e.event_type == "incident.closed":
            p.incidents[e.aggregate_id]["status"] = "closed"
        elif e.event_type == "incident.reopened":
            p.incidents[e.aggregate_id]["status"] = "open"

    # 便捷查询

    def party(self, party_id: str) -> dict:
        try:
            return self.projection.parties[party_id]
        except KeyError:
            raise DomainError(f"未知范围条目：{party_id}")

    def evidence_for(self, incident_id: str, evidence_ids: list[str]) -> list[dict]:
        found = []
        for eid in evidence_ids:
            record = self.projection.evidence.get(eid)
            if record is None or record["incident_id"] != incident_id:
                raise DomainError(f"证据不属于本事件或不存在：{eid}")
            found.append(record)
        return found
