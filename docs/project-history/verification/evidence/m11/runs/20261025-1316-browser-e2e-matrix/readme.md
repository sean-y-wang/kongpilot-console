# M11 浏览器 E2E 矩阵（20261025-1316，UTC+8）

- 运行器：`tests/e2e/m11-browser-matrix.mjs`（headless Chromium / Playwright，需 `KP_LAB_E2E=true` 与 0600 私有 secrets 文件，凭据不进仓库）。
- 目标：实验室真实 Kong（cluster A admin :38001）、console :8090、BFF :33000，BFF 运行仓库 HEAD dist（含 d40f37a、8b1ffc1），`ENTITY_SCHEDULES_ENABLED=true`（仅实验室，生产默认 false 未改）。
- 结果：9/9 通过，pageErrors=0；证据 `browser-e2e-matrix.json`（已脱敏，无口令/cookie/DB URL）与 `shots/*.png`。
- commercialClosed=false。

| KP | 用例 | 关键结果 |
|---|---|---|
| KP-007 | 错误口令 | login 401，/auth/me 401 |
| KP-007 | 只读角色 | 写按钮 0 个可用（20 个禁用显示），强制 prepare/restore 均 403 |
| KP-007 | IDOR | 他人工作区 404、伪集群 404、只读改他人口令 403；全局用户目录读取 200 为只读角色设计权限 |
| KP-004 | 双人审批删除 | 申请人不可自批、批准人无执行按钮；Kong service/route 404 |
| KP-004 | 回收站恢复 | 原 service/route ID 在 Kong 200 |
| KP-004 | 旧 mutation 来源条目恢复 | prepare 即 409 ENTITY_RECYCLE_LEGACY_ORIGIN_RESTORE_UNSUPPORTED（修复 d40f37a） |
| KP-002 | 定时创建：批准前激活 / 只读撤销 / 撤销 | 409 ENTITY_SCHEDULE_APPROVAL_REQUIRED；403；cancelled，Kong 未创建 |
| KP-002 | 定时创建：批准→显式激活→自然 worker 领取 | notBefore 前 Kong 404；到期后 succeeded，Kong created_at ≥ notBefore |
| KP-008 | 本次全部成功写请求审计对账 | 15/15 requestId 存在于 audit_events（只读事务查询） |

发现并修复的缺陷：
1. d40f37a（KP-004）：审批模式恢复旧 mutation 来源回收条目会通过审批后在执行时失败（ENTITY_RECYCLE_FACT_INVALID）；现于 prepare 阶段 409 拒绝。剩余产品缺口：此类旧条目在审批模式下仍无法恢复。
2. 8b1ffc1（KP-002）：实体定时 worker 从未发布 readiness，/health/ready 在已启用并执行时仍报告 entity disabled；现发布并在 timer 未运行时 fail-closed（503）。

未覆盖（仍待补）：KP-003 未知结果处分的浏览器负例、KP-006 Portal 完整浏览器流程（注册→审批→应用→申请 key→审批执行→掩码→代理 200→轮换→吊销）。
