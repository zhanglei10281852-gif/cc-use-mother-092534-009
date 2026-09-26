"""只追加事件日志：持久化 JSONL，逐条哈希链，重放即恢复。

这是系统的唯一事实来源。任何状态都不允许原地修改；更正只能以新事件追加。
每条记录形如：
  {"event": <业务事件>, "seq": n, "recorded_at": "...", "prev_hash": "...", "hash": "..."}
hash = sha256(prev_hash + canonical_json(event))，因此任何对历史事件的篡改都会断链。
"""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

from .clock import iso, parse_ts, utc_now

GENESIS = "0" * 64


def _canonical(event: dict) -> bytes:
    return json.dumps(event, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _digest(prev_hash: str, event: dict) -> str:
    return hashlib.sha256(prev_hash.encode("ascii") + _canonical(event)).hexdigest()


class EventStore:
    """文件后备的只追加日志；并发写入由进程内锁串行化。"""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._lock = threading.RLock()
        self._records: list[dict] = []
        self._event_ids: set[str] = set()
        if self.path and self.path.exists():
            self._load()

    # ----- 持久化与重放 -----
    def _load(self) -> None:
        assert self.path is not None
        for line_no, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            self._verify_record(record, line_no)
            self._records.append(record)
            self._event_ids.add(record["event"]["event_id"])

    def _verify_record(self, record: dict, line_no: int) -> None:
        event = record["event"]
        expected_prev = GENESIS if line_no == 1 else self._records[-1]["hash"]
        if record.get("prev_hash") != expected_prev:
            raise ValueError(f"第 {line_no} 条记录哈希链断裂（prev_hash 不匹配）")
        if record.get("hash") != _digest(record["prev_hash"], event):
            raise ValueError(f"第 {line_no} 条记录内容与哈希不符，证据链可能被篡改")
        parse_ts(event["occurred_at"])  # 必须带时区

    def verify_chain(self) -> None:
        """对外暴露的完整性校验：全量重算哈希链。"""
        prev = GENESIS
        for index, record in enumerate(self._records):
            if record["prev_hash"] != prev:
                raise ValueError(f"第 {index + 1} 条记录哈希链断裂")
            if record["hash"] != _digest(prev, record["event"]):
                raise ValueError(f"第 {index + 1} 条记录哈希不匹配")
            prev = record["hash"]

    # ----- 写入 -----
    def append(self, event: dict) -> dict:
        """追加一条业务事件。event_id 重复时幂等返回既有记录，不产生第二条。"""
        event_id = event["event_id"]
        parse_ts(event["occurred_at"])
        with self._lock:
            for record in self._records:
                if record["event"]["event_id"] == event_id:
                    return record  # 幂等：重复提交同一事件不扩大任何计数
            prev_hash = self._records[-1]["hash"] if self._records else GENESIS
            record = {
                "event": event,
                "seq": len(self._records) + 1,
                "recorded_at": iso(utc_now()),
                "prev_hash": prev_hash,
            }
            record["hash"] = _digest(prev_hash, event)
            self._records.append(record)
            self._event_ids.add(event_id)
            if self.path:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            return record

    # ----- 查询 -----
    def events(self, event_type: str | None = None) -> list[dict]:
        with self._lock:
            items = [dict(r["event"]) for r in self._records]
        if event_type:
            items = [e for e in items if e["event_type"] == event_type]
        return items

    def records(self) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._records]

    def __len__(self) -> int:
        return len(self._records)
