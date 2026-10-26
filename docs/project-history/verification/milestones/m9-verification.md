# M9 运维工具箱验证记录

更新日期：2026-10-13。状态：M9 技术验收通过，源码、存储、真实网关、浏览器、审计及最终秘密扫描均已验证。本文不代表 M10/M11 已实现，也不代表正式生产站点已经部署。

## 交付与执行边界

运维工具箱提供节点状态、精确缓存键查看与失效、传统路由模拟、真实代理探测、批量变更和本人草稿。工作区迁移接入基础审批引擎，批量删除在首个原生删除前封存完整回收图，并按对象实际工作区恢复。

所有请求经 BFF。缓存仅返回安全元数据；代理探测只访问登记的固定代理目的地，使用 GET/HEAD、二次确认、地址与端口防护及严格预算。路由模拟对无法证明的 PCRE、缺少上下文、权限覆盖缺口或预算耗尽返回不完整结果。草稿拒绝凭证、认证头、证书原文及脚本，不物理删除本人历史版本。

迁移审批绑定冻结的源/目标、操作者及对象图。另一位当前具备两侧权限的审批人批准后，由原提交人执行。已知原生成功但父工单异常时，可使用原执行键对账；恢复只修改原账本，允许有界授权 GET 验证当前对象，禁止重新发送迁移写入或延长原生许可。

## 实际验证证据

| 验证 | 结果与范围 | 证据 |
| --- | --- | --- |
| 全量源码回归 | 366 个文件、6,789 项通过，零失败、零跳过；生产源码在运行期间保持一致，证据工具增量另验 | 汇总 (`artifacts/M9/all-source-current-summary.json`, not public) |
| 全链迁移源码 | 389 项相关验证；执行、恢复、当前权限与原回执边界 | [执行测试](../../../../tests/security/m9-migration-workflow-execution.test.ts) |
| 恢复页面 | 64 项通过，其中迁移新增 32 项、门户兼容 32 项；原 key/hash、范围变化与卸载保护 | [页面测试](../../../../tests/unit/m9-workspace-migration-metadata-recovery.test.ts) |
| 完整迁移与角色启动 | 隔离 PostgreSQL 14 项检查；全部 SQL000–016、历史校验和、重复启动及运行角色只读 schema 校验 | 存储结果 (`artifacts/M9/storage-verification.json`, not public) |
| 复合回收图实库 | 21 项检查，18 次回滚试验，3 个真实回收图与 6 个原生组件 | 回收结果 (`artifacts/M9/recycle-storage-verification.json`, not public) |
| SQL016 及恢复 SQL | 25 项检查、24 次回滚；实际 UUID/TEXT JOIN、复合 FK、冻结材料、CAS 与事件插入 | 实库诊断 (`artifacts/M9/migration-storage-verification.json`, not public) |
| 真实 Kong 1.5.1 | 节点/缓存、直接及审批失效、批量、完整凭证恢复、工作区隔离、审批迁移与原密钥认证 | 请求与断言 (`artifacts/M9/native-verification.json`, not public) |
| 原执行对账 | 原键关闭已确认成功的迁移账本，原失败响应保留；独立新工单正常执行、原 API Key 可用 | 恢复结果 (`artifacts/M9/native-migration-recovery-verification.json`, not public) |
| 真实浏览器 | 11 项检查、7 张截图，3 个写请求均观测到原响应；无页面错误、无直连 Admin | 页面结果 (`artifacts/M9/browser/verification.json`, not public) |
| 审计 | 10 项检查，84 个业务请求、264 条实际审计；每个已完成迁移组件、原异常和恢复分别核对 | 审计结果 (`artifacts/M9/audit-verification.json`, not public) |
| 秘密扫描 | 12 项检查、117 个实际秘密材料、383 个编码 pattern、约 302 MB；公开产物、三端 dist、自有容器完整日志与审计字段零实际泄漏匹配 | 扫描结果 (`artifacts/M9/secret-scan-verification.json`, not public) |

真实请求断言是累积日志，存在重复的拒绝测试；不将其总数称为独立验收用例数。测试使用独立 RAM 验收环境，原网关及应用服务未修改或重启；该环境不作为持久生产部署证明。

## 保留的历史失败与短项

原始失败、首次源码回归失败、SQL/mock 差异和证据工具误判均保留在 尝试记录 (`artifacts/M9/attempt-history.json`, not public) 及 审计工具记录 (`artifacts/M9/audit-tool-attempt-history.json`, not public)。没有改写原请求或回填审计。

历史审计短项共三笔：两笔修复前路由模拟没有审计事务；一笔修复前直接迁移的四条审计缺少来源 IP。新的路由模拟及新的直接迁移已独立验证完整审计字段。不能据此宣称全部历史记录完整；本阶段修复后的实际变更按原请求与组件逐项验证。

审批迁移曾在发包前因身份复核失败；之后的另一原执行已完成网关写入，但终态 SQL 的 UUID/TEXT 比较错误使父工单停留待核验。错误已修复，原已成功变更通过原键元数据对账结束，未重放原生写入。另一个独立对象验证了正常审批执行路径。

## 后续阶段

M9 阶段验收已落盘，现按 [M10 计划](../../milestones/m10-implementation-plan.md) 实施治理、Lint、双环境漂移与 Promote。M10 验收后按 [M11 计划](../../milestones/m11-implementation-plan.md) 实施多级审批、计划执行、变更窗口及完整回滚。最终还需发布镜像、平台持久化与恢复、整体安全回归和正式手册验收。
