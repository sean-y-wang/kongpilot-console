# M3 多工作区验证

状态：M3 范围验收通过。真实 HTTP 完整重跑763/763、修复后的真实浏览器1/1通过；人工元数据/备注界面复核、最终部署边界、依赖审计和秘密扫描均通过。HTTP 和浏览器实际连接 Kong OSS 1.5.1；下表明确区分真实网络操作与故障模拟。

初次执行发现 Target 权重修改的前置核验使用地址进行通用 GET，不能可靠定位指定 Upstream 下当前生效的 Target（实际返回404）。修复改为在指定 Upstream 的有界有效集合中解析并校验 UUID；没有自动重发失败写入。初始证据保留于 `artifacts/M3/security-live-pre-fix-target.json`。

浏览器故障注入中的 apply 在后端成功后丢弃响应，UI 正确禁止重复提交并保存来源回执，但初次确认框的已处理错误又被组件 Promise 传播为 pageerror。现改用组件明确关闭回调，只有成功才关闭，错误保留提示、未知结果锁定提交，且自行消费异步失败。清洁重跑 pageerror 为0。初始证据为 `artifacts/M3/browser-pageerror-pre-fix.json`；该失败记录保留，不计入最终通过结果。

| 验证 | 实际结果 | 证据 |
| --- | --- | --- |
| 单元/集成基线 | 全量基线515/515通过；确认框修复后另行独立3/3通过 | unit-results.json (`artifacts/M3/unit-results.json`, not public)、mutation-confirm-unit-results.json (`artifacts/M3/mutation-confirm-unit-results.json`, not public) |
| Kong OSS 1.5.1 HTTP | 763/763通过；20个关联对象联合迁移完成 | security-live.json (`artifacts/M3/security-live.json`, not public) |
| 浏览器隔离与迁移 | 1/1通过；apply仅1次，原来源回执跨切换/重载有效 | browser-verification.json (`artifacts/M3/browser-verification.json`, not public) |
| 浏览器请求边界 | pageerror、直连 Admin API、缺失 workspaceId 均为0 | 同上 |
| 迁移故障/客户端恢复逻辑 | 35/35通过；后端故障为明确标注的模拟 | migration-recovery-unit-results.json (`artifacts/M3/migration-recovery-unit-results.json`, not public) |
| 人工桌面/移动端 UI | 元数据与备注生命周期、只读工作区、自动打标均通过；错误/直连 Admin/缺失范围均为0 | UI-review.json (`artifacts/M3/UI-review.json`, not public) |
| 最终启动与网络/运行权限 | 14/14启动、27/27边界检查通过；仅核验，未重启运行时 | startup-final-verification.json (`artifacts/M3/startup-final-verification.json`, not public)、deployment-boundary-final.json (`artifacts/M3/deployment-boundary-final.json`, not public) |
| 真实 PostgreSQL 004约束 | 53/53通过，测试事务全部回滚 | database-constraints.json (`artifacts/M3/database-constraints.json`, not public) |
| 最终依赖审计 | 已知漏洞0，包括生产 high/critical 为0 | dependency-audit-final.json (`artifacts/M3/dependency-audit-final.json`, not public) |
| 最终运行时秘密扫描 | 338个文件、2个嵌入 ZIP 条目，0泄露；0600私有引用已删除 | runtime-secret-artifact-scan.json (`artifacts/M3/runtime-secret-artifact-scan.json`, not public) |
| 环境秘密与源码产物扫描 | 独立环境秘密扫描通过，0泄露；精确文件数量以报告为准 | environment-secret-artifact-scan.json (`artifacts/M3/environment-secret-artifact-scan.json`, not public) |

```sh
node tests/security/live-m3.mjs
npx playwright test tests/e2e/m3.spec.ts
npx vitest run tests/unit/mutation-confirm.test.ts
```

真实 HTTP 覆盖默认未打标范围与两个标记工作区，八类核心实体、Target、六类凭证的作用域 CRUD/回收/恢复，以及关系、手动健康状态、插件中心和原来源回执的跨范围拒绝。分页测试使用真实 `size`/`offset` 游标，验证工作区与业务标签 AND/OR 的交集及三页无重复，并拒绝跨范围或旧工作区 revision 游标。未知和多个保留标签夹具实际进入索引后，同时从原生和索引列表排除，单实体读取403。

联合迁移包括 Service/Routes/Plugins、Consumer/全部凭证、Upstream/Targets、Certificate/SNI 和 CA。私有后端网络读取只在测试进程内比较原生配置，报告只保存比较结果；实际保持 Basic 原生密码哈希和 Key/JWT/HMAC/OAuth 秘密、原 ID 与配置，并通过 API Key/原始 Basic 的真实代理认证。Target 继承父 Upstream，实际迁移没有 Target 写入，历史和有效 ID 完全相同。Service 的控制台 owner/description 备注完成作用域、版本、软删除/恢复和迁移保留核验，原生 Service 配置未增加不支持的字段。

迁移 preview 与含共享引用冲突的 preview 返回200供审核；冲突 apply409且网关配置完整不变。计划共享100页/10,000记录和节点预算。reconcile 仅核验所有步骤、标签/非标签配置、双方工作区 revision 与当前引用，不执行原生写入。原生写入完成后传输失败的部分执行/恢复使用另行标明的集成模拟；浏览器真实丢弃已成功完成的 apply 响应，验证只读回执仍绑定原来源工作区，并在切换和重载后保持。

独立迁移/浏览器恢复逻辑测试已35/35通过，证据为 `artifacts/M3/migration-recovery-unit-results.json`。其中后端传输未知、部分执行及显式继续使用内存原生适配器故障模拟；不能据此宣称真实 Kong 网络故障注入已通过。

测试脚本从本地 `.env` 读取登录凭据，不打印远端错误正文、私钥或凭证。真实请求按70ms间隔串行执行，配置传播使用有界重试；网关业务探测仅连接隔离 echo-upstream。受控原生 POST 仅创建历史未打标或异常标签的 Service，用于演示直接 Admin API 可绕过软隔离，没有产品透传接口。

最终运行时扫描覆盖 HTTP 报告、清洁浏览器结果、两份保留失败证据及人工 UI 的六张截图；人工流程没有创建新凭证或读取秘密。扫描识别原始、JSON转义、URL编码和报告内嵌 ZIP 内容，扫描后删除工作区外的私有秘密引用。环境秘密扫描单独进行，不将两者的覆盖范围混为一谈。

可演示截图：工作区隔离 (`artifacts/M3/workspace-isolation.png`, not public)、迁移差异 (`artifacts/M3/workspace-migration-preview.png`, not public)、原来源回执恢复 (`artifacts/M3/workspace-migration-recovery.png`, not public)、实体备注 (`artifacts/M3/UI-entity-annotations.png`, not public)、移动端 (`artifacts/M3/UI-workspace-mobile.png`, not public)。人工 UI 报告如实记录两阶段继续执行及测试定位器调整；没有重复执行未知网关写入。

M3 只验证工作区管理范围。Kong 的名称空间、Consumer 与全局插件仍共享运行空间；用户、团队、tag_group/entity 四维权限及公开 IDOR 专项由 M4 再验证，不能将本里程碑的管理员工作区检查作为完整 RBAC 验收。
