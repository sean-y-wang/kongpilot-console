# M8 独占浏览器验收

这是 SOURCE_READY 的手工脚本合同，尚未执行实际浏览器。入口为 `tests/security/manual-m8-ui.mjs`，原包守卫为 `tests/security/lib/m8-manual-journal.mjs`。

## 实际启动前提

Root 明确交接唯一 UI 写窗口；Security 的实际 HTTP 验收完成；新的 M8 私有引用具有 `phase=http-complete`、`httpAcceptanceComplete=true` 与 `manualUiHandoff.phase=ready`。交接只接受五个固定路径：`artifacts/M8/security-live-final.json`、`artifacts/M8/security-live-deck124-compatibility.json`、`artifacts/M8/security-live-deck-pool-transaction.json`、`artifacts/M8/security-live-deck-record-merge.json` 或 `artifacts/M8/security-live-deck-wire-body.json`；必须绑定实际原始 SHA、M8/testTag、`allPassed=true`、`failed=0`、`unknownWrites=0`。前四个路径对应的实际旧失败原件及历史 Source-ready 证据全部保留，不能覆盖、掩盖 failed/unknown 或作为绿色交接；当前封存等价匹配与初始执行 projection 修复后的独立成功候选应绑定第五个固定路径。新结果尚未生成，不因 Source allowlist 接纳便视为 GREEN。其他路径、阶段报告、错误 SHA 或失败事实都被拒绝。

完整原 HTTP 请求前缀（包括已发生的 133 包及后续真实 CLI/RBAC/审计闭环包）按交接时真实数量与完整 SHA 原样保留，不删旧失败包、不重新发送旧包。CLI 使用工具版本 1.2.4 验证 `_format_version: "1.1"` 配置格式；工具版本与文件格式不同。阶段失败原件、诊断及全部私有历史保留，不能因更换工具或报告路径掩盖失败。

复用交接时真正有效的 M8 admin、owner、read-only 三个会话；各自剩余至少 300 秒。当前 actor/SID/CSRF/cookies 来自 Security 的真实验证及浏览器 `GET /auth/me`；不假定它们必定等于最初注册会话。手工窗口自身不登录、不刷新，不读取 M7 或 M6 引用。`readM8Reference` 负责固定 M8 引用及外部历史的权限、大小、SHA 验证。

已授权的默认 Form scope 修复须先由 DevOps 完成 Web-only 部署；源码增量绑定 `artifacts/M8/web-form-scope-source-fix-freeze.json`。部署和实际交接完成后，在仓库根目录运行：

```sh
M8_MANUAL_UI_READY=true node tests/security/manual-m8-ui.mjs
```

## 十二个独特操作

按以下顺序，所有写请求由 admin 原交接会话执行，固定 direct CID/WID，查询只含 `workspaceId`。`m8UiExpected` 逐项严格匹配真实 method/path/query/body；随机原键必须未用过，首次发送前完整私有包持久化。

| 顺序 | action | 行为 |
| --- | --- | --- |
| 1 | snapshot.capture | workspace 范围捕获新快照，固定名称，完整对象与恢复摘要 |
| 2 | review.export | 创建脱敏 review 导出作业，确认真实工作区名称 |
| 3 | review.download | 原 exportId/exportRevision 的确认 POST，消费一次下载许可 |
| 4 | schedule.create | 新捕获策略；60 分钟间隔、UTC、保留 30 天 |
| 5 | schedule.pause | 使用原策略 ID/revision 暂停 |
| 6 | schedule.archive | 使用当前 ID/revision 软删除 |
| 7 | schedule.restore | 使用原 ID/revision 恢复，实际状态必须 paused |
| 8 | gitops.record | 已有实际 jobId 的安全元数据记录，合成 commit SHA 仅作为验收输入 |
| 9 | snapshot.archive | 仅新捕获的快照元数据软删除；先验证错误名称禁用及取消不发包 |
| 10 | snapshot.restore | 恢复同一快照，并验证迟到回执切换工作区后仍使用原 scope/key |
| 11 | noop.import | `_format_version: "1.1"` 与空 services 的 merge，真实 plan 必须零步骤、零删除 |
| 12 | plan.reconcile | 交接中实际 planId 的只读核验；causalOutcomeUnproven，不改变原执行状态 |

Service body 始终保留 `serviceIds: []`。计划和快照下载均采用真实服务器版本；禁止以 job revision 或默认 1 代替 exportRevision。approval 环境仅阅读已完成的原工作流，不批准、不执行、不切换集群模式。手工 UI 不再次 apply、rollback 或重播 Security 已完成的 Native 操作。

过期执行收口控件作为第十三项**只读/负向观察**，不属于上述十二个实际写意图：仅在 Security 明确交接已有原作业时读取其服务器能力及失败事实；有能力时可检查错误名称禁用并取消，无能力或 read-only 时不应出现提交按钮。不能从本手工窗口调用 abandon，不增加登录、刷新、Native、审批或故障记账请求。原 `manual-m8-ui.mjs` 与十二包守卫保持原冻结 SHA；没有实际负向观察材料时，不将这项写成浏览器验收通过。

生产界面的收口与导入/apply 使用不同结果通道：单次 POST 只针对原 job 的完整执行元组，未知响应核验 GET 原 job 与 steps；不拿新的收口键查询新的 configuration job。只有输入 `abandon:原作业ID` 明确确认且同 SID/当前权限、原 key、完整执行/计划/租约元组和服务端 abandoned/terminalFailureRecorded 事实均获保护 GET 证明后，才解除恰好对应原请求的界面引用；原 uncertain 状态和其他未知引用保持不变。该 SOURCE 边界由独立 focused 单测验证，不能替代真实故障收口验收。

## 原包与结果证据

BrowserContext route 在 transport 前校验 actor/SID、Cookie/CSRF、CID/WID、原键、完整 raw body 及固定 endpoint。0600 `wx` 临时文件、fsync、原子 rename 与目录 fsync 成功后才允许 continue。未知请求、未知结果、保存失败、重复键或越界操作使后续 non-GET 全部停止；不生成新键重试。ACK 不表示成功，必须经当前 actor 在原 `configuration/jobs/by-key/:key` 的独立 GET 验证 durable 原回执与真实终态。下载另核验接收字节、SHA、32 MiB 上限、安全响应头和原许可已消费。

原 HTTP 请求前缀按数量和完整 SHA 保留；手工每个原包追加进私有 journal/global requests，包含原 headers/key/body/status/requestId。报告只发布安全 ID、计数、摘要、SHA；cookies、凭证和 YAML 内容不进入报告、日志或截图。固定旧报告和图片不覆盖。若失败，保留原 phase、包与原键，仅经 Root 确认后的独立续行处理，不直接重跑本入口。

迟到回执测试仅暂缓 snapshot.restore 的 UI 原键 GET，切换到 foreign 工作区后释放读取；不阻止或重发写请求。随后使用 UI 原操作引用核验，展示原 CID/WID/key，核验完成后引用解除。

## 只读检查和截图

六个页面均使用实际 DTO；列表以 `size=20` 服务端游标和缓存页码前后翻页。snapshot 详情展示真实完整性/凭证恢复能力，job 展示逐对象结果；plan 的只读 observations 不声称证明原写成功。readonly 写控件禁用，已完成审批工作流无批准/执行控件。移动端 viewport 为 390×844，同时记录 document/table 横向尺寸，页面 body 不应溢出。

每次截图等待目标实际内容及非 loading，检查无可见密码输入/非空临时 YAML，滚到顶部。固定新文件为：

- `artifacts/M8/manual-snapshots-desktop.png`
- `artifacts/M8/manual-snapshot-detail-objects.png`
- `artifacts/M8/manual-job-object-results.png`
- `artifacts/M8/manual-review-export-job.png`
- `artifacts/M8/manual-schedule-paused.png`
- `artifacts/M8/manual-schedule-recycle.png`
- `artifacts/M8/manual-gitops-original-job.png`
- `artifacts/M8/manual-snapshot-recycle.png`
- `artifacts/M8/manual-late-scope-original-receipt-pending.png`
- `artifacts/M8/manual-late-scope-original-receipt-verified.png`
- `artifacts/M8/manual-noop-import-immutable-plan.png`
- `artifacts/M8/manual-plan-readonly-causal-unproven.png`
- `artifacts/M8/manual-readonly-snapshots.png`
- `artifacts/M8/manual-completed-approval-readonly.png`
- `artifacts/M8/manual-snapshots-mobile.png`

实际汇总输出 `artifacts/M8/manual-ui.json`，记录每张图片 SHA、独立原回执 requestId 与十二个独特成功操作。SOURCE 单测证明守卫行为，不作为 live Kong、调度、decK 或审批链的实际验收；实际 Native 接受证据单独继承 Security 的最终报告。
