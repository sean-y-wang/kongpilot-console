# M6 浏览器新 Key 扫描 SQL：隔离 PostgreSQL 交接

前次规划交接状态为 **SOURCE_READY / PG_PENDING**，其 6 项源码检查与未执行边界保留在原 artifact 中。随后经 Root 继续执行授权，已完成下面的真实隔离验证；原记录没有覆盖。

## 实际隔离验证结果

`tests/integration/portal-browser-key-scan.ts` 在 PostgreSQL **16.15**、原始 000–009 全部 10 条迁移与真正非 owner/非 superuser runtime 角色下完成 **12/12 PASS**。实际固定 query 执行 12 次、原 runner 子程序执行 8 次、原 sameSID reader 子程序执行 5 次。实际 production compiler、Plan.persist、PortalAuth.login/authenticate、approved metadata activation 与审计均由 runtime 连接执行。

结果记录：`artifacts/M6/browser-key-scan-postgres-2026-10-11T04-18-17-139Z.json`，SHA-256 `b8a0bc6fb6750e1d83f3814c72f76310503736a711945df51207ae87d994511f`。验证源码 SHA-256 `3038d9ce5945b209dd90e625c1764758294320a758bd90a9d27a6391924018d9`。严格 TypeScript 编译及 `git diff --check` 通过；随机 disposable 容器已经移除。

Storage 对 fixture 与故障回滚做了独立源码复核，未发现具体约束问题。成功 ACK 与 Gateway 的 8 次 GET 对象读取是明确声明的合成 fixture，因此这项证据验证 SQL、实际 proof 和子程序；它不证明 native transport、真实 Kong 凭证可用或浏览器行为，也不等于商用验收通过。实际 native 写、业务 HTTP、browser、当前数据库/私有材料/环境文件访问均为 0。未禁用任何数据库约束，错误 generation 等不可提交的故障状态只在明确回滚的隔离事务中检查。

## 冻结合同

| 材料 | SHA-256 |
| --- | --- |
| `tests/security/lib/m6-browser-key-scan.mjs` | `55d8ae2d50f035bb5b4cccd4ba03e80955d19ab6a1587b14e61bf104ac904598` |
| `tests/security/capture-m6-browser-key.mjs` | `2f696777294dae61b97e7abe10d02617a8d25916ce67b08f5cf5b3b19bba1f3c` |
| 实际导出 `BROWSER_KEY_SCAN_SQL` | `aade72bcf3bac4f717bfd3e945832422171cca7ba3bdafc833c6ad3c2c5258ff` |
| runner 内实际 `const program` 展开值 | `e5a2e1f42822325578e749ebc869850e2a30fee6cf1c26ae3b409aa85c20cbfe` |

`artifacts/M6/browser-key-scan-sql-handoff.json` 保留 6 项源码检查、程序哈希与明确的未执行边界。后续如 helper 或 runner 变化，应重新核对实际展开值，并保留本记录。

源码审阅已确认：`PortalNativeService.nativeStep` 对 CREATE 保持 logical `entityId` 未定义，`WorkflowPlansService.persist` 因而写入不可变的 `workflow_steps.entity_id=NULL`。预分配的真正 ID 位于 `normalizedNativeRequests` 生成的 snake_case `native_requests[0].native_id`，成功 `mutation_operations.entity_id` 为该 ID 的文本值。未来 fixture 必须由真实 compiler/persist 生成这套关系；不得手写非 NULL logical CREATE 行来迁就查询。

## 后续隔离验证

复用 `tests/integration/portal-browser-session-reader.ts` 的本地 Docker socket、`postgres:16-alpine --pull=never`、随机容器名、随机仅 loopback 端口、000–009 原始迁移与 `provisionRuntimeRole`。读取运行角色、非 owner 状态及审计 SELECT/INSERT 权限作为实际证据；仅 owner 执行迁移和必要的合成 seed，业务服务与待测 SQL/program 使用 runtime 数据库连接。

使用 `tests/integration/portal-credential-activation.ts` 现有合法造数合同，调用真实 `PortalCredentialsService.request`、`WorkflowPlansService.persist/load`、credential store 与 approved metadata activation。Gateway 只能用明确声明的合成只读对象 fixture，任何真实网络写调用必须立即失败。审批、执行、三个 native mutation ACK、两条 credential refs 与 active generation 1 应在现有约束允许的同一事务顺序下生成；保留 NULL logical CREATE。

独立 Portal 身份由真实 `PortalAuthService.login/authenticate` 与 `AuditService` 生成，同 SID、当前 credential epoch、refresh/CSRF 仅存内存。禁止复制实际运行环境、读取 private reference、访问当前 DB、Kong DB 或任何 HTTP/browser。待测 query 从实际 helper 导出文本提取；待测子程序从实际 runner 的 template 展开，不重写 PG reader。

计划 12 个有意义检查组：

1. 实际 PostgreSQL 16、000–009 校验和、非 superuser/非 owner 及 append-only 审计权限。
2. 完成发证后真实 NULL logical CREATE 能绑定 Consumer → ACL/Key 父链，native ACK 3、active refs 2、generation 1。
3. 原错误 `m.entity_id=s.entity_id::text` 在合法实际 fixture 上得不到三条绑定，原问题确实被复现。
4. 修改 sealed manifest 的 method/type/native ID/parent/kind 被原数据库 identity 约束拒绝；保留拒绝结果，不移除触发器。
5. 错误 logical entity type 被原约束拒绝；错误 mutation receipt actual ID 在允许的回滚事务故障快照中被实际 query 排除。
6. workflow/CID/WID/original execution key 任一不符，实际固定 query 无匹配行。
7. 非成功、未 remote-completed 或缺 result receipt 被实际 query/实际 proof 校验拒绝。
8. 当前 generation/pointer 不符时 fail closed；不可提交的故障用回滚事务检查，禁止把它当作合法持久状态。
9. 少一条或 inactive credential ref 导致 active_refs 不足，实际 proof 不接受。
10. 当前 same SID/epoch/原 login audit/refresh/CSRF 成功；foreign/revoked SID fail closed，不输出 cookie。
11. 真实 `PortalCredentialsService.reveal` 生成一次合成 owner 查看及 request-ID 审计；待测 after query 验证 cipher/native IDs/refs 不变，另一个 audit request ID 不被接受。
12. 实际展开子程序使用 BEGIN READ ONLY、固定五个绑定参数、timeout 和 ROLLBACK；公开 artifact 仅 count/hash/boolean，不序列化 rows/key/token/SQL 错误文本。

每个故障案例应明确属于数据库约束拒绝、实际查询排除或实际 proof 拒绝，避免把不同结果混写成执行成功。若合法 fixture 无法形成，应保留失败 artifact 并标记 PG_PENDING，禁止改产品迁移、禁用约束或伪造 query rows。仅移除本脚本随机创建的 disposable 容器。

这项实际验证属于第一批 M6 闭环的独立检查点。它没有启动真实 scanner-material reveal；真实浏览器/部署由 Root 的对应窗口单独控制。
