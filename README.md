# 智能体泄露事件证据保全与处置系统

面向事件指挥官的安全事件处置内核：在**不中断所有租户**的前提下，完成泄露范围判定、
证据保全、通知义务计算、监管时钟推进与对外披露管控。

系统采用事件溯源（event sourcing）：**只追加事件日志是唯一事实来源**，全部读模型由日志
重放得到。服务停机恢复后重放日志，监管时钟、隔离动作与待通知队列原样继续推进。

## 领域规则如何落地

| 需求 | 实现 |
| --- | --- |
| 区分文件被列出 / 打包 / 实际领取 | 暴露阶段 `listed < packaged < received`，写入调查结论（`finding.recorded`）并驱动策略矩阵 |
| 可疑请求、清单摘要、交付回执、租户、凭据版本关联 | 调查结论同时引用三类证据 ID 与 `credential_version_id`；证据分 `request_log / manifest_summary / delivery_receipt` |
| 证据更正只能追加并保留原链 | `evidence.corrected` 引用被更正项；原记录不可变，证据条目之间形成双向保管链（custody） |
| 证据防篡改 | 事件日志逐条 SHA-256 哈希链（`prev_hash`/`hash`），加载即校验，篡改任一历史记录直接断链报错 |
| 重复导入不扩大计数 | 幂等键 +（来源标识, 内容指纹）双重去重；重复导入产生 `evidence.import_rejected` 留痕，证据与计数零增长；重放同一 `event_id` 也幂等 |
| 并发调查员冲突判断进入复核 | 第二份相反提案触发 `scope.contested` 并抛 `ScopeConflictError`；裁决人必须未参与提案，`scope.resolved` 记录终局结论与理由 |
| 通知义务与截止时间 | `domain/policies.json` 的矩阵按 **租户地区 × 数据类别 × 实际暴露阶段 × 接收方** 匹配，截止为锚点后的绝对时刻 |
| 结论变化重估未发通知、不撤回已确认事实 | 排除时仅废止 `active` 义务（`duty.superseded`）；已 `sent` 的通知永不覆盖；重新纳入时义务复活但沿用最初锚点，时钟不重置 |
| 对外披露法务+安全双签 | 必须由两名不同责任人分别以 `legal`、`security` 签署，否则禁止 `disclosure.released` |
| 隐藏其他租户信息 | 发布视图默认不含任何租户明细，仅在显式授权的 `allowed_tenant_ids` 内输出 |
| 不中断所有租户 | `apply_isolation` 默认拒绝 `all_tenants/global/platform_wide`，需显式全局批准并留痕；作用域动作（请求模式、单租户、凭据轮换）直接放行 |
| 服务恢复后续跑 | 监管截止时间锚定绝对时刻；从 JSONL 日志重放即可恢复全部队列、时钟状态与解释 |
| 解释每一方纳入/排除原因 | `explain_party(tenant_id)` 返回全部结论（含被取代/误报）、证据链、每轮提案与裁决、排除原因、义务与截止 |

## 目录

- `domain/contract.json`：实体、状态、事件类型、暴露阶段、数据类别与业务规则。
- `domain/policies.json`：通知义务矩阵（地区 × 类别 × 阶段 × 接收方 → 截止小时数）。
- `examples/events.json`：完整生命周期样例（含重复导入拦截、冲突复核、发送后更正、双签披露）。
- `app/event_store.py`：只追加日志 + 哈希链 + JSONL 持久化 + 幂等重放。
- `app/policy_engine.py`：通知义务策略引擎（无状态、可版本化）。
- `app/projections.py`：读模型折叠（证据、保管链、范围轮次、义务时钟、披露）。
- `app/service.py`：命令/查询 API（`IncidentSystem`）。
- `tools/validate_contract.py`：合同、策略矩阵、样例排序与哈希链一致性校验。
- `tools/replay_case.py`：重放样例并打印指挥仪表盘。
- `tests/test_incident_system.py`：19 个端到端规则测试。

## 构建与测试

```bash
python3 -m compileall -q .
python3 -m unittest discover -s tests -v
python3 tools/validate_contract.py
python3 tools/replay_case.py
```

仅依赖 Python 3.11 标准库；不启动数据库或其他服务。

## 典型流程（Python API）

```python
from app.event_store import EventStore
from app.policy_engine import NotificationPolicy
from app.service import IncidentSystem, ScopeConflictError

system = IncidentSystem(EventStore("case.jsonl"), NotificationPolicy.load())

system.open_incident("commander", "2026-09-25T09:00:00+08:00", "运行空间外泄", case_id="case-1")
ev = system.import_evidence("r-a", "...", "delivery_receipt", "egress:rc-1",
                            {"delivery": "https://ext/d/b.tar"}, idempotency_key="ingest-rc-1")
system.record_finding("r-a", "...", "f-1", tenant_id="t-1001", region="CN",
                      data_category="personal_data", stage="received",
                      request_evidence_id=ev["payload"]["evidence_id"])

system.propose_scope("r-a", "...", "t-1001", True, "存在交付回执")
system.resolve_scope("lead", "...", "t-1001", True, "请求-清单-回执证据链完整")
# -> policy-engine 自动追加 duty.calculated，截止为锚点 + 矩阵小时数

for row in system.pending_queue("2026-09-27T09:00:00+08:00"):
    print(row)  # on_track / due_within_24h / overdue

print(system.explain_party("t-1001"))  # 纳入/排除的完整可审计解释
```

冲突复核、证据更正、双签披露、全局中断守卫等完整用法见 `tests/test_incident_system.py`。
