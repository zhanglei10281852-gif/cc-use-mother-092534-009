# 智能体泄露事件证据保全与处置系统

安全响应团队确认某些请求可让智能体返回运行空间文件后，事件指挥官用本系统
判断泄露范围、保全证据、计算通知义务并按时完成通知与对外披露，**不中断所有租户**。

唯一事实源是追加式哈希链事件日志（SQLite）：所有处置动作只追加事件，
读模型随时可从事件流完整重建，服务恢复后监管时钟、隔离动作与待通知队列继续推进。

## 领域能力与对应规则

| 要求 | 实现 |
| --- | --- |
| 关联可疑请求、清单摘要、交付回执、受影响租户与凭据版本 | `engine.record_finding` / 证据 `credential_version` |
| 区分文件被列出 / 打包 / 实际领取 | `models.Stage`（none < listed < packaged < delivered），证据种类不得越级主张阶段 |
| 证据进入保全后更正只能追加并保留原链 | `evidence.corrected` 引用被更正项；`EventStore` 前序 SHA-256 哈希链 |
| 重复导入同一证据不扩大计数 | 以 `(事件, 指纹)` 去重，返回 `duplicated=True` |
| 按数据类别、租户地区、实际暴露阶段计算通知义务与截止 | `policy.PolicyEngine` 规则表（可 JSON 替换） |
| 调查结论变化时重评，未发义务可作废、已确认事实不撤回 | 义务按**代际**管理：`pending` 可 `superseded`，`sent` 永不撤回 |
| 并发调查员冲突判断进入复核 | 第二名调查员结论冲突自动 `scope.contested`，指挥官裁决 |
| 对外披露法务与安全双签，隐去其他租户信息 | `sign_disclosure` × 2 后才能 `issue_disclosure`，发布时替换范围外租户标识 |
| 不中断所有租户的隔离 | 默认仅定向租户；全局隔离须指挥官角色 + 理由 |
| 恢复后时钟/隔离/队列继续 | 投影从事件重建；截止时间锚定事件确认发现时刻，停机不平移时钟 |
| 解释每名受影响方为何纳入或排除 | `admin.AdminReporter.explain_party`（理由码、证据、判断、时间线） |

## 目录

- `domain/contract.json`：实体、状态、暴露阶段、事件类型与业务规则。
- `domain/policies.json`：策略与实现位置对照。
- `examples/events.json`：按业务发生时间排列的完整处置链样例。
- `incident_vault/`：处置系统实现（仅依赖 Python 标准库）。
  - `store.py`：追加式哈希链事件存储与可重建投影。
  - `policy.py`：地区 × 数据类别 × 暴露阶段的通知策略引擎。
  - `engine.py`：全部领域不变量与命令。
  - `admin.py`：管理解释接口（纳入/排除理由、监管时钟、名册）。
  - `cli.py`：命令行接口与端到端演示。
- `tools/validate_contract.py`：领域资料离线一致性校验。
- `tests/`：25 项测试，覆盖全部关键不变量（含重启恢复、防篡改、并发追加）。

## 构建与测试

```bash
python3 -m compileall -q .
python3 -m unittest discover -s tests -v
python3 tools/validate_contract.py
```

不需要另行启动数据库、缓存或其他服务。

## 管理接口演示

```bash
# 构造端到端处置事件并写入磁盘库
python3 -m incident_vault.cli demo --db /tmp/incident.db
# 校验哈希证据链
python3 -m incident_vault.cli verify --db /tmp/incident.db
# 监管时钟与待通知队列（截止排序、逾期标记、隔离动作）
python3 -m incident_vault.cli clock --db /tmp/incident.db case-09-001
# 受影响方名册
python3 -m incident_vault.cli roster --db /tmp/incident.db case-09-001
# 解释某一方为何纳入/排除（证据、判断、复核、义务、时间线）
python3 -m incident_vault.cli explain --db /tmp/incident.db party-a
```
