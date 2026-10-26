# KongPilot M11 门户发证链路闭环 · 2026-10-20

> 后续独立 CI 已结束：全量测试在 901,003ms 达到命令上限，完整计数无效，镜像作业跳过。最新目标/方案/卡点及原始摘要见 [项目检查点](2026-10-20-project-checkpoint.md)；下文保留本专项发生时的记录。

**M11 与商用准入仍未通过。** 本页承接 [此前进展与原始失败记录](2026-10-15-m11-continuation.md)，时间使用 UTC。本轮针对门户自然定时发证的调用预算问题；不代表 M0–M11 全量验收。

## 已定位的问题与修复

原独立诊断工单 `7c309ecc-56d7-4a56-ab1f-fe943e4338c1` 的 Consumer、ACL、Key Auth 写入和回读成功，但第四步激活前已经消耗 497 次调用，最终以 `KONG_EXECUTION_CALL_LIMIT` 部分失败。前三个写入步骤分别增加 95、143、143 次调用。原失败、原 claim 和未激活凭证保留，不重放。

- 加入有界阶段计数，仅记录固定阶段、步骤序号、调用/分页/记录/字节数；不记录请求内容或凭证，日志失败不替换业务结果。
- EntityService 的 Consumer 父对象辅助读取与最终激活读取，限定为原封存工单的指定对象，进入现有 Validation 只读通道。
- 保留当前主体、权限、工作区、SQL 材料与原执行上下文检查，以及最终发送前完整校验和原始回执回读。不扩大查询范围，不产生写入许可。
- 原 500 次调用、100 页、5 分钟 claim 上限不变；没有缓存旧批准结果或延长原授权。
- 完整链路测试接入生产 EntityService，包括准备与写入前的两次父对象读取；MutationService 生命周期/持久化、SQL、网络和租约仍为显式受控测试适配器，不能代替真实环境验收。

证据：原实际阶段计数 (`artifacts/M11/runs/20261020-closure/observation-execution-original.json`, not public)。

## 本轮验证

| 验证范围 | 结果与边界 |
| --- | --- |
| 辅助读取、业务执行与普通门户等回归 | 336/336 通过 |
| 权限、原上下文、SQL 预检、过期与边界回归 | 修复测试时钟竞争后 124/124 通过；首次 123/124 的失败保留 |
| 完整源码链路 | 3/3 通过；成功与跨 31 秒场景均为 253 次调用；最早绑定过期场景 0 次写入、执行失败 |
| 测试时钟修复 | 两组用例固定 Date/单调时钟，保持原 50ms 绑定期限，在真实 SQL consume 回调后推进 51ms；不调整生产期限或测试超时 |
| API 隔离编译 | 431 个源输入、390 个 JS、41 条原有迁移，退出 0 |
| 验收 API 部署 | 15:20:26 UTC 启动，ready 200；部署前无活跃工单执行/claim，备份完成；原 claim、日程、未知 mutation 不变 |

运行源码摘要：`d143874143a1e23056369b3043986b16d39c281805012bcda3013b59a00cb7b9`。此为自有验收环境部署，不是正式生产部署；未修改 Kong 代码或镜像，未直连 Kong 数据库。

证据：336 项回归 (`artifacts/M11/runs/20261020-closure/parent-support-source-original.json`, not public)、124 项安全回归 (`artifacts/M11/runs/20261020-closure/parent-security-clock-fixed-source-original.json`, not public)、完整链路范围与计数 (`artifacts/M11/runs/20261020-closure/parent-whole-topology-original.json`, not public)、编译 (`artifacts/M11/runs/20261020-closure/parent-support-build-original.json`, not public)、验收环境部署 (`artifacts/M11/runs/20261020-closure/parent-support-runtime-original.json`, not public)。

## 真实环境新工单

新应用 `9901185b-2939-4676-ab5f-4f65cb588fcc` 订阅已有发布 API，新工单 `c862bb05-b27e-450b-ab88-ad447a4eecb1`、新日程 `b3dd9767-855d-48fe-9ca3-0239ff6ffdbe` 已完成真实 BFF 申请、排程、独立审批、自然执行及激活。

- 独立只读 SQL 确认只有一个 claim；原期限为 15:23:07.165–15:28:07.165，四步于 15:27:36.616 完成，日程/工单/执行全部 succeeded。
- Consumer、ACL、Key Auth 三个原生操作均取得成功回执，执行前加密快照 ready；创建、激活和工作流成功审计均存在。
- 授权揭示后，经平台代理探测首次返回 200。
- 新吊销工单 `220e9a85-1834-4edf-ba99-faf6d141d371` 经过独立审批后成功执行；同一凭证首次探测返回 401。
- Key Auth、ACL、Consumer 各有一条回收站记录，状态 deleted、加密对象图仍在、未永久清除；三条删除审计和凭证吊销审计存在。

这证明本次初次签发→使用→审批吊销链路通过。约 269.45 秒的 claim 内耗时仍需后续容量和并发验证，不构成性能 SLA；轮换、故障恢复、全量越权验证及其他 M11 能力不能由本次成功推导通过。

证据：原 claim 与实际发证终态 (`artifacts/M11/runs/20261020-closure/parent-support-issue-terminal-original.json`, not public)、11 阶段闭环、200/401 与独立吊销/回收站核验 (`artifacts/M11/runs/20261020-closure/parent-support-lifecycle-joined-original.json`, not public)。

本轮通过实际 BFF 重新核验全局 139 行、当前集群 2,147 行审计，两个范围均完整、哈希链 verified。链完整性不证明历史应记事件零遗漏；历史遗漏不补写。本次 API 日志和 51 条生命周期期间审计固定快照纳入凭证材料扫描，原始内容只保留在私密目录。

证据：审计完整性 (`artifacts/M11/runs/20261020-closure/lifecycle-audit-integrity-original/summary.json`, not public)。秘密扫描首次因单批材料触发原有预算而停止，保留原失败 (`artifacts/M11/runs/20261020-closure/precommit-parent-support-budget-original.json`, not public)；按原始顶层字段与请求批次完整拆分，不提高扫描预算、不删除材料，最终范围与结果见有界分批扫描 (`artifacts/M11/runs/20261020-closure/precommit-parent-support-bounded-original.json`, not public)。该扫描不覆盖全部历史日志、全仓库或三端构建产物。

## 独立 CI 与后续门禁

远端 `3f19e888` 的 [CI 39441627444](https://github.com/sean-y-wang/kongpilot-console/actions/runs/39441627444) 已结束：16,400 项中 16,396 通过、4 失败、0 跳过。三个测试文件分别出现 1 个断言失败和 3 个超时；三端类型检查、构建及 npm 生产依赖公告检查通过，镜像验收因前置失败跳过。此次测试时钟修复尚无新远端全量结果。不得将此前不同提交的绿色结果作为当前候选通过证明。

证据：本次远端原始摘要 (`artifacts/M11/runs/20261020-closure/remote-ci-3f19e88-original.json`, not public)。

后续按以下顺序继续：

1. 在本次初次签发/吊销成功的基础上，补齐轮换、禁用、执行中撤权、故障与并发场景，核对原工单/claim/操作/审计及回收站。
2. 补齐普通实体六类凭证及五类对象删除恢复、配置发布/Promote/回滚与故障路径；保留历史未知结果，通过安全核验流程处理。
3. SQL041 控制面覆盖和 SQL042 未知结果恢复候选分别完成根工程整合与迁移/恢复验证；本轮未部署这两条迁移。
4. 同一最终提交完成独立全量源码、镜像、浏览器、IDOR/并发、容量、持久部署及异机备份恢复验收，并更新部署/用户手册。

开发分支和 Draft PR 继续承载检查点；不合并主分支、不创建 GA 标签，商用状态保持未通过。
