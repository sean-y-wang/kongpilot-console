# M11 继续研发 · Phase 1 记录 · 2026-10-23

分支 `work/m11-continue`（基于 `work/m11-checkpoint-20261014` / `de875b5`）。本记录不关闭任何 KP 台账项。

## 1. 本机环境
- Node 22.23.3（fnm），npm install scripts 允许；Docker 29 / docker.io 可运行（hello-world 通过）。
- `node deploy/scripts/ci-quality.mjs` 自动完成 toolchain(decK)、Playwright chromium-headless-shell、PCRE1 原生引擎准备。
- 主机 DNS 为 fake-IP（`example.com` → `198.18.0.1`，基准测试保留段）。

## 2. 测试结果
| 运行 | 结果 |
| --- | --- |
| 修复前，Node 20、无 Docker/PCRE/浏览器/decK | 16455 项：89 失败 / 28 跳过（9 文件） |
| 修复后，ci-quality（Node 22，maxWorkers=2） | 16455 项：16453 通过 / 2 失败 / 0 跳过；测试阶段 414 s；三端 typecheck/build、生产依赖审计 0 漏洞均通过 |
| 修复后，`vitest --maxWorkers=2` 直接运行 | 唯一失败文件 `tests/unit/entity-annotation-strict-lifecycle.test.ts`，3–6/15 项不稳定 |

### 已修复
- `tests/security/m6-publication-retry-review.test.ts`（45 项）：519d052 让 `PortalNativeService.read` 经过 `ExecutionContext.runPortalMetadataRead`；该夹具缺少此方法。非定时命名空间下该方法本就直通，夹具按同一语义补齐（与 portal-admin-atomic / portal-compiler 夹具一致）。
- `tests/unit/kong-client.test.ts`（1 项）：fake-IP DNS 下 destination policy 把 `example.com` 判为保留地址并正确返回 403，早于 503 写入断言。测试内固定该文档域名解析到公网地址，产品策略不变。

### 仍待处理
- `entity-annotation-strict-lifecycle`：“awaited current-session response 后保持 fence”八个参数化用例不稳定。失败时 prepare 已成功，组件随后读取未打桩的 `/annotation-changes/{intentId}`。说明 `/auth/me` 释放后，`AnnotationApprovalDrawer` 的 `assertCurrent`（`apps/console-web/src/features/EntityAnnotations.tsx` 约 139 行）有时读到旧的 `latest.current`。可能是真实的 UI fence 竞态，需要在下一步定位，不能通过放宽等待来处理。

## 3. KP-001 耗时分析（Node 22，8 核本机，maxWorkers=2）
文件耗时合计 565 s，墙钟 369 s。前 3 个文件占 66%，前 15 个占 81%：

| 文件 | 秒 |
| --- | --- |
| tests/unit/m11-promote-combined-origin-canonical-sql.test.ts（36 项，单项约 11 s，用例预算 30 s） | 186 |
| tests/unit/m11-origin-canonical-sql.test.ts（67 项） | 113 |
| tests/unit/m11-portal-whole-native-source.test.ts | 75 |
| 其余文件 | 均不超过 16 |

- 单项 CPU profile：主要耗时在 `canonicalJson`（`apps/console-api/src/infrastructure/secret.service.ts:6`）、`structuredClone` 和 `immutableJson`，也就是每个用例重建完整 Provider 图并反复规范化与 HMAC。
- 推断：GitHub 私有仓库的 `ubuntu-24.04` 是 2 vCPU，CPU 单核更慢；按 2–2.5 倍折算，约 900 s，正好碰到 ci-quality 的 15 分钟测试命令上限。上一轮的 3 项超时也落在这几个约 11 s/项、预算 30 s 的用例上。
- 提议（未实现，需审阅）：
  1. `quality.yml` 按 `vitest --shard=i/N`（N=3）建 matrix，每片使用 blob reporter，最后 `vitest --merge-reports` 汇总。ci-quality 校验合并后的总计数等于未分片清单（16455），覆盖守恒。
  2. 对 promote/origin 夹具，在 `beforeAll` 内缓存不可变的原始材料构造。仅限无可变私有句柄的部分，并需单独审阅安全语义。
  3. `canonicalJson` 对已登记为 factory-immutable 的根节点做 WeakMap 记忆化，可同时降低生产开销。不改输出字节，需加等价性测试。

## 4. KP-002 / SQL041 计划
现状证据：
- `workflow_schedules` 和 `workflow_executor_delegations` 的 kind 仅允许 `configuration_v2`、`portal-credential-issue`（`026_m11_workflow_schedules.sql:7,25`）。
- TS 合同同样只有这两个 kind（`workflow-schedule.contract.ts:8`），subject seal 的 driver 也只有 4 个。
- 九域元数据审批已有直接（非定时）路径：control/IAM/metrics/annotation bootstrap 服务，SQL030/032/033/035。
- 原 041 候选包不可得，需在当前 HEAD 上重新实现。

步骤：
1. 设计文档：九个 kind（control-metadata、configuration-metadata、governance-metadata、workflow-policy-metadata、iam-metadata、portal-metadata、portal-developer-review、event-metadata、entity-annotation）的 subject_type、requester 约束、subject seal driver，以及每个 handler 的 create/update/archive/restore/purge/queue 矩阵。
2. 迁移 `041_m11_metadata_schedules.sql`：扩展 kind/subject CHECK，新增 metadata 定时 origin 表。函数固定 `SET search_path = pg_catalog, public`（吸取 C042-R1 的 pg_temp 教训），在 Docker PG 中做 apply/rollback 测试。
3. TS：扩展 `WorkflowScheduledKind` 和 seal。在 `workflow-business-schedules.service/worker` 中按 kind 注册 metadata 执行器，复用 `runApprovedStep`。由 scheduled namespace 提供只读校验通道，写前重新校验当前权限与 epoch。
4. 测试：每个 kind 的正例，以及到期、撤权、并发双 claim、篡改 seal 反例。真实 PG 测试放在 Docker disposable SQL 夹具上（与 portal-schema 同机制）。
5. 之后进入 SQL042（必须在 041 之后）。

Phase 1 尚未全绿（annotation fence 不稳定），因此本次只提交计划，未开始 041 代码。

## 5. 进度（2026-10-24 00:55 UTC+8）
- CI run 39987255887：source-quality 3 个分片和 merge 都通过；immutable-images-amd64 还在排队或运行中。
- SQL041 slice 2：DB 层现已覆盖剩余 8 个 kind，带 PG 矩阵测试（tests/unit/m11-sql041-metadata-schedules.test.ts，4/4 通过）。
- TS guard 已覆盖全部 9 个 kind（metadata-schedule.guard.ts，20 项测试）。待办：各 kind 的执行器，以及接入 WorkflowScheduledKind 和 seal driver。
- 镜像 CI（run 39990388640）：failureCode=IMAGE_SCANNER_REPORTED_DATABASE_MISMATCH。原因：Grype 0.120 的 JSON 报告把 DB 状态嵌套在 descriptor.db.status 下（同级还有 providers），而校验代码读的是 descriptor.db.valid/path。已修复：只接受恰好一种结构，嵌套结构下按 path/schemaVersion/built/valid/error 严格比对，并补了相应测试。

## 6. 进度（2026-10-24 02:10 UTC+8）
- CI run 39994085105（e584efe）：source-quality 1/2/3 与 merge 通过；immutable-images-amd64 失败，failureCode=IMAGE_SCANNER_CATALOG_COMPONENT_INVALID（DB 状态校验已通过）。
- 原因：Grype 0.120.1 的 CycloneDX 输出包含 syft 文件目录条目（type=file、绝对路径名、无 version/purl），本地对 web 镜像复现：1286 个组件中 1214 个为此类。
- 修复：文件条目仅在精确形状下接受（type=file、绝对路径、无 version/purl/嵌套）；包组件仍严格要求 name+version；过滤后无包组件则 CATALOG_REQUIRED。补充正反例测试（scanner.check 55/55）。
- SQL041 现状：
  - 已完成：041 迁移覆盖 9 个 kind（CHECK、subject 矩阵、3 个函数重写并固定 search_path），PG 一次性测试；9 个 kind 的 fail-closed 准入/执行复核 guard（metadata-schedule.guard.ts、entity-annotation-schedule.guard.ts）及单测。
  - 未完成：guard 尚未被任何生产代码引用；`WorkflowScheduledKind`（workflow-schedule.contract.ts）与 subject seal driver 未扩展；workflow-business-schedules service/worker 未注册各 kind 执行器（复用 runApprovedStep + 写前权限/epoch 复核）；API 路由/DTO；console-web 定时 UI（workflow-business-schedules.model.ts / entity-schedules.model.ts 仅支持现有 kind）；到期、撤权、并发双 claim、篡改 seal 的集成测试；之后 SQL042。

## 7. 进度（2026-10-24 02:20 UTC+8）entity-annotation 定时接线
- 8ad87cf：`WorkflowScheduledKind`、subject type（entity_annotation_requests）与 seal driver 增加 entity-annotation（仅类型层）；scheduled namespace 对非 configuration_v2/portal-credential-issue 的 kind 拒绝签发（WORKFLOW_SCHEDULE_NAMESPACE_KIND_UNSUPPORTED），保持 fail-closed。
- 49bd1e8：`entity-annotation-schedule.executor.ts`：单事务内 claim → 读取当前权限与重算 seal → 写前复核 → 单次 apply → 终态 outcome；拒绝记 blocked 且不写，未知错误回滚、不重放。14 项测试覆盖到期、未到期、撤权、权限/IAM/凭证 epoch 变化、停用、篡改/畸形 seal、重放 attempt、双 claim、未知错误回滚。
- 仍未接入运行时：WorkflowBusinessRuntimeService 尚未为 entity-annotation 安装 Root business policy（assertDraft/assertRequester/assertSubject/assertReviewer/receipt read）；authority/service 的 kinds allow-list 未放开；ports 的真实实现（SQL claim、outcome 表、复用 EntityAnnotationBusinessService.apply、权限读取）以及 026/041 中 outcome/origin SQL 对 annotation 的分支尚缺；真实 PG 的并发双 claim 集成测试待补；Web UI 待做。

## 8. 进度（2026-10-24 02:55 UTC+8）
- 4b693b2：web/portal 运行时基础镜像 nginx:stable-alpine 固定到 sha256:47928bf6…（Alpine 3.24.3、nginx 1.30.6）。本地用 Grype 0.120.1 扫描：libexpat/libx11/libxpm/zlib/musl 可修复项全部消失，剩余 curl CVE-2026-92392（High，无修复）和 busybox CVE-2025-60876（Medium×3，无修复）。API（Debian 13.7）31 项上游无修复，按要求不动、不加接受清单，待负责人决定。
- 执行器修正：SQL026 进度状态机不允许 claimed→blocked，领取后的复核拒绝改记终态 failed + reason_code。
- 真实 PG 测试 tests/unit/m11-entity-annotation-schedule-claim-pg.test.ts（3/3）：并发双 claim 只有一个成功（另一个 UNIQUE 冲突），progress 只指向胜者；claimed 不能回到 active/blocked；failed 带 reason_code 后为终态、不可删除。夹具用 replica 角色播种，仅禁用 progress 上的整链完整性延迟触发器。
- 仍未完成：在 WorkflowBusinessRuntimeService 安装 entity-annotation Root business policy 并放开 kinds allow-list；ports 的生产实现（复用 m11_business_claim 全链路、lease、outcome、EntityAnnotationBusinessService.apply）；带完整审批链夹具的端到端 PG 测试。

## 9. entity-annotation 生产执行器（部分完成）

- 已完成：`entity-annotation-schedule.facts.ts`（4c6b602），按 iam_epoch → users FOR SHARE 顺序加锁，读取 entity_annotation_requests 材料并重建 admission；单测 13/13。
- 未完成：WorkflowBusinessRuntimeService 中 entity-annotation 的 Root business policy、authority/service kind 允许列表、executeBusinessScheduledClaim 分发（facts loader + annotations:write 授权 + EntityAnnotationBusinessService.apply + repository.finishClaim）。
- 未完成：完整审批链 PG 端到端测试，仓库内尚无完整审批链 fixture，需要新建。
- CI：run 40001667159 最终为 cancelled，shard 2 约 15 分钟后被取消，merge 因缺少 shard 2 summary 失败。run 40003763624 正在运行，原因待查。
- 未改动漏洞处理。

## 10. shard 2 诊断与 entity-annotation runtime 注册（2026-10-24）

### shard 2 “超时”诊断
- 不是测试卡住。quality.yml 的 `concurrency: cancel-in-progress: true` 会在同分支有新推送时取消旧 run。
- 40001385251、40001667159、40003763624 被取消的时刻，分别与 48e5edc+1、4c6b602、257450b 的推送时刻吻合，差距都在 1 分钟以内。
- 257450b 的 run 40005842623 中，shard 2 用时约 6 分钟就成功了，包含 claim-pg 测试。所以没有修改 claim-pg 测试，也不需要修改。

### runtime 注册（部分完成）
- e732e21：`WorkflowBusinessExecutionService.inspect` 接受带密封 scheduling 的 entity-annotation plan。
  - 去掉 scheduling 后，必须完整通过 `assertEntityAnnotationPlan`，并且 requester 为 console，执行模式只能是 approval。
  - `KongExecutionContextService` 的 scheduled namespace 门放行该 kind。
  - authority、namespace、current-identity、validation、candidate 这几处允许列表仍然拒绝该 kind，所以 claim 仍然无法签发，生产行为不变。
  - 单测新增 1 个用例（成功路径、拒绝 direct 模式、拒绝篡改 operation），19/19 通过。

### 阻塞：需要 owner 决策
- 标注模块在设计上把执行绑定到 HTTP 会话：
  - `EntityAnnotationWorkflowService.actor()` 要求 `f.sessionId`，并且显式拒绝 `hasWorkflowScheduledNamespace()`；
  - `approvedDelegate().assertSubject` 要求会话（ANNOTATION_ACTOR_CONTEXT_REQUIRED）；
  - 执行事实表记录 session_id，并在之后用它核对；
  - `assertWorkflowAdmission` 的 write 要求 authoringSessionId 一致。
- 定时执行器没有会话，`sessionId===null`。要真正接通，必须为标注模块设计“无会话的 scheduled 执行身份”，替代会话绑定，并且可能需要 SQL 迁移（execution facts 的 session_id 约束）。这属于安全模型变更，不应顺手放宽。
- 因此没有安装 Root business policy，也没有打开 authority 允许列表。完整审批链 E2E PG 测试依赖这条路径，同样暂缓。

## 11. body-parser 升级与推迟的 npm 生产依赖漏洞（2026-10-24，owner 决定）

### 已修复
- **body-parser** `2.3.0` → `2.4.0`（GHSA-27r3-jxmh-p828，压缩请求体尾部字节 DoS）。
  - 根 `package.json` 增加 `overrides: { "body-parser": "2.4.0" }`。
  - `apps/console-api` 增加直接依赖 `body-parser@2.4.0`，避免被 express@5.2.1 钉在 2.3.0。
  - `npm audit --omit=dev` 中 body-parser 条目已消失。

### 推迟（已于 §23 闭合；保留历史表供对照）
owner 于 2026-10-24 要求正式商用闭合、不放松门禁后，§11 表内五项已全部升级；见 **§23**。下列为推迟当时的快照，不再代表当前 lock。

| 包 | 当前版本 | 严重度 | Advisory | 上游修复 | 为何需单独评估 |
|---|---|---|---|---|---|
| multer | 2.4.0 | high | GHSA-q7qp-rjg7-q26m（请求拆除后挂起的 async fileFilter 导致 DoS） | 需升级；npm 建议 `--force` 安装 `@nestjs/platform-express@11.1.1`（**主版本回退 / breaking**） | 与 Nest 12 栈绑定；强升会牵动 `@nestjs/platform-express` / `@nestjs/core` peer，需回归 HTTP 上传与平台兼容 |
| @nestjs/platform-express | 12.1.2 | high（传递） | 依赖脆弱 multer | 同上 | 同上 |
| @nestjs/core | 12.1.2 | high（传递） | 依赖脆弱 platform-express | 同上 | 同上 |
| nodemailer | 10.1.0 | moderate | GHSA-8c8m-p3m8-cjg8 / GHSA-m943-m63m-w62w / GHSA-85x2-q946-cp5h（addressparser 收件人解析） | 10.2.1（超出当前声明范围） | 邮件地址解析语义变化，需验证通知/邀请发信路径 |
| zod | 3.25.76 | high | GHSA-mrhx-c7xc-m3w5（超大 constrained collection 内存耗尽） | 4.6.7（**major**，npm 标 breaking） | Zod 3→4 为破坏性升级，schema/推断全仓需回归 |

以上条目**不**进入镜像漏洞接受清单，也**不**放宽 `ci-quality` 的 audit 门槛。


## 12. SQL041 entity-annotation Root policy + allowlists + E2E（2026-10-24）

- `WorkflowBusinessAnnotationMaterial` + `annotationMaterial()`：从 `entity_annotation_requests` / `annotation_change_intents` 重建 subjectSeal（driver=`entity-annotation`，nativeManifestHmac=`fingerprint({origin:workflow-scheduled-entity-annotation,workflowId})`）。
- `assertStoredCurrent` / `proposed` / `fullReadScope` / receipt / prepareProposal 已分支处理 annotation（无 Kong native 读集；feature grant=`annotations`；credential epoch 取自 intent）。
- `WorkflowScheduledBusinessKind` 扩到 `entity-annotation`；13 处 allowlist + Root `installBusinessPolicy` 循环已放开。
- `approvedDelegate.assertSubject` 在 scheduled namespace 下允许无 session（仍要求 scheduled principal）。
- E2E PG：`tests/unit/m11-entity-annotation-schedule-approval-chain-pg.test.ts`（8/8）覆盖正例与过期、禁用/删除/强改密、epoch、权限版本、篡改 seal、撤权、双 claim。

## 13. SQL041 剩余 8 个 metadata schedule kind 接线（2026-10-24）

### 本轮已完成（复用 entity-annotation 模式）
- 通用内核：`metadata-schedule.registry.ts`（SUBJECT_SEAL_SOURCE / FEATURE / KINDS）、`metadata-schedule.facts.ts`（iam→users FOR SHARE→subject）、`metadata-schedule.executor.ts`（claim→load→recheck→apply→outcome）。
- 类型/契约：`WorkflowScheduledKind`、subjectSeal driver、subjectType、`WorkflowBusinessMetadataMaterial` 覆盖 8 个 kind。
- `metadataMaterial()`：request 风格读 material_hmac/payload_hmac；entity 风格用 `{id,revision,clusterId,workspaceId}` fingerprint。
- Root `installBusinessPolicy` 循环 + 各 schedules/authority/namespace/plans/authz/material/execution-context allowlist 已放开 8 kind。
- inspect：metadata kind 走 approval-only 校验，不再落入 portal 四步 native 形状。
- prepareProposal / assertProposal：metadata 保留 subjectSeal（不重写 nativeManifestHmac）；impact 不按 portal native 投影。
- 单测：`m11-metadata-schedule-facts.test.ts`、`m11-metadata-schedule-executor.test.ts`（41 项）。
- PG E2E：`m11-metadata-schedule-approval-chain-pg.test.ts`（10/10）— 8 kind 正例 + control-metadata 负例矩阵 + configuration-metadata entity revision 漂移。

### 仍待（定时执行身份 / 生产 apply 端口）
| kind | 阻塞 |
|---|---|
| control-metadata | `ControlMetadataService.actor()` 显式拒绝 `hasWorkflowScheduledNamespace()`；需 SQL043 级 scheduled identity（对标 SQL042 annotation） |
| iam-metadata | `IamWorkflowService` 同样要求 HTTP session；需同类 scheduled identity |
| governance-metadata | assertSubject / origin 仍偏 HTTP session；需核对是否可复用 generic facts 或另开 identity |
| configuration-metadata / portal-metadata / portal-developer-review / event-metadata / workflow-policy-metadata | allowlist + material + facts/executor 内核已通；生产 `apply` 端口（复用各 domain business service）与 worker 分发尚未按 kind 挂载 |

npm 升级（multer / nestjs / nodemailer / zod）继续推迟，见 §11。

## 14. SQL043 control/iam scheduled identity + production apply ports（2026-10-24）

### 本轮已完成
- **SQL043** `043_m11_control_iam_scheduled_identity.sql` + `deploy/db-rollback/043_*.down.sql`：control/iam mutation facts 增加 `execution_origin`/`schedule_claim_id`；validators 固定 `search_path`；session 分支仍要求 live SID；scheduled 分支绑定 `workflow_execution_origins`；rollback 在仍有 scheduled 证据时拒绝。
- PG apply/rollback：`tests/unit/m11-sql043-control-iam-scheduled-identity-pg.test.ts`（2/2）。
- **ControlMetadataService / IamWorkflowService**：对标 SQL042 annotation — `scheduled()` / `executionSession()` / `interactive()`；assertSubject 允许 scheduled namespace；apply/running/facts 写入 origin；live requester 重校验（credential epoch + active user FOR SHARE）。
- **GovernanceMetadataService**：assertSubject 审计后改为允许 scheduled（无 mutation-fact session 活期约束，TS-only）。
- **ApprovedWorkflowExecutionService**：control-metadata load 门在 scheduled namespace 下不再强制 `frame.sessionId`。
- **生产 apply 端口**：`metadata-schedule.production.ts`（`METADATA_SCHEDULE_APPLY_HANDLERS` + `assertMetadataScheduleProductionHandlers` + `createMetadataScheduleProductionPorts`）；`WorkflowBusinessRuntime` worker 安装后断言全部 metadata kind 的 registry handler 已挂载。调度执行路径仍为 Authority → ApprovedBusinessExecution → registry.apply（与 annotation 一致）。
- PG 负例扩展：iam seal 漂移、governance NOT_DUE / claim attempt（approval-chain 11/11）。
- 单测：`m11-metadata-schedule-production.test.ts`。

### 仍待 / 非本轮
- npm 升级（multer / nestjs / nodemailer / zod）继续推迟，见 §11。
- 端到端「自然到期 claim → worker → 真实 domain apply」整链仍依赖运行环境调度；本轮保证身份与端口接线，不声称生产已跑通全 8 kind 自然到期。

## 15. KP-003 / historical SQL042 unknown-result disposition → SQL044（2026-10-24）

### 编号说明
- 检查点 KP-003 / 文档中的「SQL042 未知结果处分」候选包不在仓库内（见 KP-012）。
- 仓库 migration **042** 已用于 annotation scheduled identity（owner 2026-10-24），**043** 为 control/iam identity。
- 本轮落地为 **`044_m11_unknown_result_disposition.sql`**，设计见 `docs/milestones/M11-SQL042-unknown-result-disposition.md`。

### 本轮已完成
- 设计文档：目标、非目标、与 SQL027 Target observation 的边界、search_path/不可变/最小权限。
- 迁移 044 + `deploy/db-rollback/044_*.down.sql`：`workflow_unknown_result_dispositions`；validators/state guard 固定 `pg_catalog, public, pg_temp`；closing unique index；rollback 在仍有处分证据时拒绝。
- `provisionRuntimeRole` 将该表纳入 SELECT/INSERT-only 白名单。
- TS：`unknown-result-disposition.ts`（纯证据匹配 / 禁止 native 重放）+ `UnknownResultDispositionService`（0 Native；审计 + 处分行；closing 时可 CAS schedule-origin uncertain 执行/mutation）。
- Runtime：`WorkflowBusinessRuntimeService` 安装 044 storage checksum。
- 测试：`m11-unknown-result-disposition.test.ts`、`m11-sql044-unknown-result-disposition-pg.test.ts`。

### 仍待 / 非本轮
- HTTP 路由与 console-web 处分 UI。
- 配置/门户 uncertain 的真实 Kong 只读核验证书接入（本轮只保证处分账本与 CAS 门闩）。
- 已终态为 `uncertain` 的 `workflow_schedule_progress` 不解封（SQL026 终态）；若产品需要进度再解释，须另开 SQL026 扩展，禁止静默改写。
- npm 升级继续推迟（§11）。

### CI 修复（同日）
- push `6ea6fe6` 后 run 40058516973 shard1 出现大量 fixture 失败：手动 `new WorkflowBusinessRuntimeService(...)` 未传新依赖，`unknownResults.installStorageChecksum` 读 undefined。
- 修复：`UnknownResultDispositionService` 改为 `@Optional()`，安装 checksum 用可选链；`m11-fixed-candidate-reader.test.ts` 构造 arity `Array(21)`→`Array(22)`。
- 本地复跑原失败样例（含 origin-canonical / schedule-receipt / portal / fixed-config / single-fresh / candidate-reader）234 测通过；disposition 单测仍绿。
- CI run 40059069461（HEAD `7afe42a`）：三片 tests 全绿（5512/5794/5312）、typecheck/build 全绿；`production-dependency-audit` 仍为 total=5（预期红，§11 推迟）；merge 因 audit 红而失败；immutable-images 跳过。

## 16. KP-004 ordinary five-root + six-credential recycle contract（2026-10-24）

### KP-004 覆盖范围（检查点）
- 普通实体六类凭证（key-auth / basic-auth / jwt / oauth2 / hmac-auth / acls）
- 五类完整删除恢复（services、routes、consumers、certificates、upstreams；含关联插件/Target/SNI）
- 关闭条件：全对象图归档后再删除、原 ID 恢复、失败可处理；含代理正负认证

### 本轮已交付（源码合同切片，非真实 Kong 闭环）
- `ordinary-recycle-contract.ts`：五根目录录、六凭证集合、成员类型白名单；`assertOrdinaryRecycleArchiveContract`（归档材料/restoreData 齐备）与 `assertOrdinaryRestoreOriginalIds`（原 ID，Target 允许密封替换）。
- `requiresRecycleDeleteClosure` 改用同一目录录；`derivePreparedRecyclePackets` 与 `RecycleService.validatePreparedGraph` 对普通五根 fail-closed 接线。
- 单测：`m11-ordinary-recycle-contract.test.ts`（12）；PG：`m11-ordinary-kp004-credential-recycle-pg.test.ts`（六 `credential_type` CHECK + 五 `root_type` 行）；既有 prepared-recycle / delete-graph 回归绿。

### 仍待（KP-004 未关闭）
- 真实五类全图 delete→原 ID restore 新意图/三票/执行与回读。
- 六类凭证恢复后代理正负认证（及 OAuth2 HTTPS token 链）。
- HMAC/ACL 剩余二包 live partial 恢复与同用 fresh witness 生产路径的最终验收（源码已有 partial/witness 主干）。
- npm 升级与镜像验收仍按 §11 推迟。

## 17. KP-004 five-root cycle + six-credential restore custody（2026-10-24）

### 本轮切片（无 live Kong；Docker PG + mocks）
- `ordinary-recycle-contract.ts`：新增 `assertOrdinarySealedRestoreMatchesArchive`（归档与恢复同根/同 graphHmac/密封 entry）与 `assertOrdinaryDeleteRestorePacketCoverage`（受影响节点 DELETE↔POST 原 ID 覆盖）。
- `derivePreparedRecyclePackets`：普通根 `recycle-restore` 在存在 `sealedEntry` 时接入密封对齐校验。
- 单测：`m11-ordinary-five-root-recycle-cycle.test.ts`（五根 archive→DELETE/GET404→restore POST 原 ID；consumers 写回六 `credential_refs`）；合同单测补充密封/覆盖；writer Basic 反例保持密封 HMAC 对齐后仍走 `ENTITY_PREPARED_RECYCLE_INVALID`。
- PG：`m11-ordinary-six-credential-restore-pg.test.ts` — CredentialStore 六类 encrypt→save→getRestorePayload 往返，Basic/OAuth2 缺原文 fail-closed，revoke 状态。

### 仍待（KP-004 未关闭）
- 真实五类全图 delete→原 ID restore：新意图 / 三票 / 执行与回读（需 live Kong 或完整 Root 审批夹具）。
- 六类凭证恢复后代理正负认证（及 OAuth2 HTTPS token 链）。
- HMAC/ACL 剩余 live partial 与 fresh witness 最终验收。
- npm 升级与镜像验收仍按 §11 推迟。

## 18. KP-005 Target DELETE poststate + Promote 凭证默认排除 / 回滚新工单（2026-10-24）

### KP-005 覆盖范围（检查点）
- configuration_v2 Target/DELETE 与自然 Promote/回滚
- 关闭条件：Target 权重 0、删除归档、源/目标范围、凭证默认排除/显式选入及恢复验证通过

### 本轮切片（无 live Kong；mocks + 既有 Docker PG 夹具不动）
- `target-delete-poststate.ts`：归档密封前置；Kong 1.5 DELETE 后四次父域 list EOF（`/targets/all` + `/targets`×2）；`weight-zero-overlay` 或 `native-pruned`；禁止凭 GET404 / 非 null DELETE body 宣称完成。
- `entity-prepared-recycle-writer.service.ts`：`nativeType==='targets'` 的 DELETE 核验改走 poststate；其他类型仍 GET404。
- `assertPromoteCredentialDefaultExclusion`（promote-compiler）：未 `includeCredentials` 时拒绝 `credentials:` 选中与 document 凭证巢。
- `rollback-new-job-contract.ts`：`mode=rollback` 须新 job（及可选新 execution），禁止复用源发布工单。
- 单测：`m11-target-delete-poststate.test.ts`、`m11-promote-credential-exclusion-rollback-job.test.ts`；`m11-prepared-recycle-all-types` / `m11-ordinary-five-root-recycle-cycle` 对 Target DELETE 断言改为 list×4。

### 仍待（KP-005 未关闭）
- configuration_v2 真实 Target append / durable 发布（仍拒绝 `CONFIGURATION_DURABLE_TARGET_APPEND_UNSUPPORTED`）与双环境自然 Promote 端到端。
- Target DELETE 后密封替换恢复（`original_id→effective_id`）走生产路径的完整回读证书。
- 回滚 Preview→新工单→执行 与故障注入的真实 configuration_v2 联调（本轮仅合同）。
- 凭证显式选入 + secret 确认后的恢复验证全链；源/目标 scope 漂移门闩产品化。
- npm 升级与镜像验收仍按 §11 推迟。

## 19. KP-006 Portal credential rotate / disable(=revoke) / cancel-restore / concurrency（2026-10-24）

### KP-006 覆盖范围（检查点）
- 轮换 / 禁用(=吊销) / 定时吊销、执行中撤权、并发、失败与完整浏览器
- 关闭条件：新旧凭证有效/失效符合预期；授权揭示、回收/审计与每步回执一致

### 本轮切片（最高价值未完成：未执行轮换/吊销终止后授权卡住 + 并发能力门闩）
- `portal-credential-lifecycle-contract.ts`：`disable→revoke`；变更准入（仅 active 授权+当前代次）；`portalCredentialCapabilities`（授权与凭证双 active）；未执行 cancel/reject/expire 恢复合同；代次分配 `max(current, MAX(generation))+1`（软删未激活轮换行仍占槽）；定时 kind 仅 `portal-credential-issue`；轮换/吊销回执断言。
- `restoreUnusedPortalCredentialChange`：软删本工单未激活 pending 凭证，CAS `rotating|revoking → active`。
- 接线：开发者 `cancelRequest`；管理员 `decide(reject)` 与 console `cancel`；`credentialView` 能力门闩；compile 代次；`POST .../disable` 别名；业务定时对 `portal-credential-*` 先走合同再 allowlist。
- 单测：`m11-portal-credential-lifecycle-contract.test.ts`（10）。

### 仍待（KP-006 未关闭）— 见 §20 续
- （§19 切片后）定时 rotate/revoke 已在 §20 接线；其余见下节。

## 20. KP-006 scheduled portal-credential rotate/revoke E2E wiring（2026-10-24）

### 本轮切片（SQL026/041 allowlist → SQL045 + namespace + worker/native）
- **SQL045** `045_m11_portal_credential_change_schedules.sql`：kind CHECK 纳入 `portal-credential-rotate` / `revoke`；门户 subject CHECK 扩为三 kind（developer + `portal_application_grants`）；重写 pointer/revision/origin/storage 函数中的 portal execution_mode 与 nested-origin 片段；`search_path` 钉死。回滚 `deploy/db-rollback/045_*.down.sql`（有 rotate/revoke 行则拒绝）。
- **合同 / 类型**：`PORTAL_CREDENTIAL_SCHEDULE_KINDS` 开放三 kind；`isPortalCredentialScheduleKind`；`WorkflowScheduledKind` / subject-seal driver / `WorkflowScheduledBusinessKind` 同步。
- **接线**：repository draft 绑定与 driver；namespace 可铸造 rotate/revoke（metadata 仍 `NAMESPACE_KIND_UNSUPPORTED`）；authority / validation-read / runtime allowlist 与 feature→`portal`；`portalChangeMaterial` + `materialForPlan`；native POST 回读与完成回执（rotate/revoke 审计）；worker 本身无 kind 门槛（经 authority 放行）。
- **单测**：`m11-sql045-*-pg.test.ts`；`m11-portal-credential-change-schedule-admit.test.ts`（draft/namespace/material fail-closed）；lifecycle 合同；既有 namespace/storage 回归扩 rotate/revoke。
- **显式跳过**：live Kong 代理正负认证；npm 升级；执行中中途撤权浏览器全链。

### 仍待（KP-006 未关闭）
- 真实 Kong + 门户浏览器：定时轮换新旧 Key 代理正负、定时吊销 401、揭示/回收/审计逐步对账。
- 执行中撤权（已 approved/executing）与失败/uncertain 处分浏览器全链。
- 并发双开轮换的 HTTP 集成夹具（CAS + 能力门闩已有）。
- npm 升级与镜像验收仍按 §11 推迟。


## 21. KP-007 IDOR / multi-worker / fault-injection fail-closed slice（2026-10-24）

### KP-007 覆盖范围（检查点）
- 按 actor / cluster / workspace / entity / 原执行身份做越权矩阵
- 注入断网 / 重启 / 租约丢失及并发竞争
- 关闭条件：无越权或重复写；单 claim；期限内吞吐/延迟；未知结果安全处置

### 本轮切片（无 live Kong；自动化 fail-closed）
- **合同** `kp007-access-fault-contract.ts`：五维访问元组、四业务 kind 目录、`assertKp007AccessIdentity` / `assertKp007SingleWorkerClaim` / `assertKp007FaultFailClosed` / `assertKp007WorkerTickBounds`。
- **接线**：
  - `WorkflowScheduledAuthorityService` eligibility：KP-007 kind 在 claim/execute 前核对 sealed plan/delegation ↔ binding/principal；claim 成功后核对单 workerOwnerHmac；五维 KP007_ACCESS_* 进入 preclaim blocked 名单。
  - `WorkflowBusinessSchedulesWorker.tick`：返回前 `assertKp007WorkerTickBounds`（busy 零计数、completed≤claimed、due 全记账）。
- **单测** `m11-kp007-idor-multiworker-fault.test.ts`（32）：纯合同矩阵；四 kind 并发双 acquire 单 claim；第二 Authority 不能偷 opaque handle / 再 claim；双 worker tick 单 execute；维度漂移无 appendDueClaim；rotate/revoke subject 拒权；租约丢失 / 回调中撤权 / 重启异 workerOwner 均 fail-closed 且不 reacquire。
- **显式跳过**：live Kong 跨集群 IDOR 现场；真实多进程 worker + Redis 租约；长链吞吐/延迟 SLO；浏览器会签撤权全链。

### 仍待（KP-007 未关闭；商用关闭需检查点所述 live 证据）
- 真实双 Kong / 双集群：actor·cluster·workspace·entity·原执行身份 HTTP/浏览器越权矩阵（含 portal rotate/revoke 回执）。
- 真实多 worker 进程 + Redis 租约丢失 / 进程重启 / 断网：单 claim、无重复 native 写、unknown 安全处分。
- 约定吞吐/延迟期限内的长链性能证据。
- npm 升级与镜像验收仍按 §11 推迟。
- 下一步按台账进入 KP-008 审计对账（不放松 audit/vuln 门禁）。


## 22. KP-008 业务写入 1:1 审计/diff/工单/投递对账切片（2026-10-24）

### KP-008 覆盖范围（检查点）
- 对成功 / 拒绝 / 失败业务请求逐笔关联审计、diff、工单和投递
- 当前范围关键写入 100% 对账、审计不可修改
- 历史遗漏以事件说明保留；实际启用渠道联调通过

### 本轮切片（无 live 渠道联调；自动化 fail-closed）
- **合同** `apps/console-api/src/modules/audit/kp008-write-audit-reconcile-contract.ts`：
  - 成功/拒绝/失败三种 outcome；业务定时三命令目录；四维对账（audit/diff/ticket/delivery）
  - `kp008BusinessScheduleSuccessRequest` / `kp008RejectOrFailRequest`
  - `assertKp008AuditMatchesRequest` / `DiffConsistent` / `TicketBound` / `DeliveryBound`
  - `reconcileKp008` 1:1；`assertKp008FailClosed`；`assertKp008HistoricalGapRetained`
  - `assertKp008BusinessWriteSealed` 落账后封印；`kp008MapBusinessScheduleAudit` 与 outbox 映射对齐
- **接线**：
  - `mapAuditEvent`：author/activate → `workflow.executed`；cancel → `workflow.cancelled`（成功才 fan-out outbox/delivery；拒绝/失败仍为 null）
  - `WorkflowBusinessSchedulesService` author / activate / cancel：`audit.append` 后 `assertKp008BusinessWriteSealed`（requestId·ticket·receipt hash/sequence·after）
- **单测** `m11-kp008-write-audit-reconcile.test.ts`（25）：映射同步；三命令成功四维闭合；缺审计/工单/diff/投递 fail-closed；重复审计非 1:1；拒绝/失败六种 HTTP 结果无伪造投递；混合集 1:1；历史遗漏须说明事件且维度覆盖。
- **显式跳过**：真实启用渠道联调；全量关键写入运行时 coverage 扫表；历史生产遗漏回填；审计链不可变的 live 篡改举证（既有 integrity 覆盖）。

### 仍待（KP-008 未关闭；商用关闭需检查点所述 live 证据）
- 实际启用通知渠道：成功业务写入 → 审计 → outbox → delivery → 渠道投递联调对账。
- 当前范围全部关键写入（含 portal/native 非 schedule）运行时 100% coverage 扫表与 CI 门禁。
- 历史遗漏说明事件的生产写入路径与保留策略验收。
- §11 npm 升级与镜像接受清单已在 §23 / `0537ef0` 推进；**不放松** production-dependency-audit / vuln 门禁。
- 下一步：盯 CI 至 immutable-images；按台账继续 KP-009+ live 证据。


## 23. §11 推迟的 npm 生产依赖漏洞正式升级（2026-10-24，Asia/Shanghai）

### owner 决定
正式商用闭合：不再推迟 §11 五项；不放松 `production-dependency-audit` / vuln 门禁；`npm audit --omit=dev` 必须 `total=0`；随后盯 CI 至 `immutable-images`（无上游修复 OS CVE 已有精确匹配接受清单 `deploy/security/image-vulnerability-acceptance.json`）。

### 版本变更（精确钉死）
| 包 | 原 | 新 | 说明 |
|---|---|---|---|
| multer | 2.4.0（传递，经 Nest） | **2.5.0**（直接依赖 + 根 `overrides`） | GHSA-q7qp-rjg7-q26m；Nest 12.2.0 仍声明 multer 2.4.0，必须 override |
| @nestjs/common | 12.1.2 | **12.2.0** | 与 platform-express/core 对齐 |
| @nestjs/core | 12.1.2 | **12.2.0** | 同上 |
| @nestjs/platform-express | 12.1.2 | **12.2.0** | 仍依赖 multer 2.4.0；由 override 抬到 2.5.0 |
| nodemailer | 10.1.0 | **10.2.1** | addressparser 公告；源码未直接引用发信 API |
| zod | 3.25.76 | **4.6.7** | major；DTO 仍用 `.url()` / `.strict()`，Zod 4 legacy-compat 通过 |

根 `package.json` overrides：`body-parser@2.4.0`（既有）+ **`multer@2.5.0`**。`apps/console-api` 新增直接依赖 `multer@2.5.0`。锁文件整树重生成；`npm ci`（无 legacy-peer-deps）可复现。

### 本地验证（升级后、提交前）
- `npm ci --no-audit --no-fund`：通过
- `npm audit --omit=dev`：**found 0 vulnerabilities**（total=0）
- `npm run typecheck`：api/web/portal 全绿
- `npm test`：**729** files / **16734** tests 全绿（约 226s）
- 未改测试、未放宽超时、未改 audit/vuln 门禁逻辑


### CI（push `ad85e2e`，Asia/Shanghai 2026-10-24 15:01 完成）
- Run：**https://github.com/sean-y-wang/kongpilot-console/actions/runs/40071670007** — **success**（全绿）
- `source-quality` 三片：5580+? 合并 **16734/16734**；typecheck/build 全绿；**`production-dependency-audit` 首次转绿（total=0）**
- `source-quality-merge`：coverageConserved=true
- **`immutable-images-amd64`**：acceptance 边界校验 + build-api/web/portal + OS native vuln scan + 三应用 hardened startup **全绿**（接受清单生效）

### 仍待（本切片外）
- ~~push 后盯 CI~~：**已绿**（run 40071670007，含 production-dependency-audit total=0 与 immutable-images）
- KP-008+ 的 live 渠道 / live Kong 证据；其余检查点 P0 按台账


## 24. Live Kong 1.5.1 高价值切片 + KP-009 生产 overlay 取证推进（2026-10-24，Asia/Shanghai）

### Live Kong OSS 1.5.1（本机 Docker；**未**宣称 KP 关闭）
- 新增隔离编排 `deploy/compose/compose.live-kong-evidence.yml`（profile `live-kong-evidence`）+ `scripts/verification/portal-live-kong.mjs`。
- 本 runner Docker bridge DNS 被劫持到 `198.18.0.0/15`，容器互联 TCP 超时；证据栈改用 **host network** + 环回端口（Admin `127.0.0.1:18001` / Proxy `127.0.0.1:18000`），**禁止并入生产 overlay**。
- 实测产物：`artifacts/M11/runs/20261024-live-kp/live-kong-proxy-evidence.json` — **19/19 步通过**，`commercialClosed=false`。
- **已取得的 live 证据（Kong 层）**
  - KP-006：签发 key-auth 后代理 200；无 key/错 key 401；删除密钥后旧 key 401（吊销）。
  - KP-004（仅凭证层）：同 consumer 重签新 key → 200，旧 key 仍 401（**不是**五类全图 delete→原 ID restore）。
  - KP-007（仅 Admin）：跨 consumer 取 key → 404；本 consumer list 成功（**不是** BFF actor/cluster/workspace HTTP 越权矩阵）。
- **仍缺**
  - 产品 BFF/Portal HTTP 与浏览器全链；五类实体回收；多 worker/Redis 租约；双集群 IDOR。

### KP-009 生产 overlay / TLS / CSP / 最小权限 / health-readiness（静态契约；**未关闭**）
- 脚本 `scripts/verification/production-overlay.mjs` → `artifacts/M11/runs/20261024-live-kp/kp009-production-overlay-evidence.json`。
- 静态通过：production overlay 解析、持久卷保留、CSP（console/portal production nginx）、本地 healthz、API `/api/v1/health/ready` 健康检查、overlay 只读/user/cap_drop/nnp、`assertProductionComposition` 合成契约（`runtimeVerified=false`）、external-kong profile 门闩。
- **显式跳过（未跑 runtime）**：真实 TLS 主机名核验、live ready 探针、不可变镜像启动/持久重启。
- `commercialClosed=false` / `claimsClosed=false`；`remainingForClosure` 列出镜像启动、TLS、ready、网络边界、容量/回退等。

### 单测
- `tests/unit/m11-kp009-live-kong-evidence-contract.test.ts`（3）：禁止伪关闭；compose 边界；既有 live 产物字段约束。

## 25. BFF/Portal HTTP × live Kong + KP-009 不可变镜像 runtime（2026-10-24，Asia/Shanghai）

### 平台栈（证据用；非生产）
- 续用 host-network Kong OSS **1.5.1**（Admin `127.0.0.1:18001` / Proxy `127.0.0.1:18000`）。
- 新增 `deploy/compose/compose.bff-live-evidence.yml`：host-network PG `25433` + Redis `26379`。
- live upstream 改为 `0.0.0.0:25678`，BFF 以非环回 `172.30.0.2:25678` 建 Service（destination-policy 禁止 `127.*` 代理目标）。
- API：**既有不可变镜像** `kpapi-test:latest`（USER `1000:1000`，`node dist/main.js`，host network，端口 `13000`）对接上述 PG/Redis/Kong。

### KP-006 / KP-007 产品 BFF+Portal HTTP 证据（**未宣称商业关闭**）
- 脚本：`scripts/verification/portal-http-flow.mjs`
- 产物：`artifacts/M11/runs/20261024-bff-portal/bff-portal-http-evidence.json`
- 结果：**30/31 通过**；`portalIssueRevokeHttpVerified=true`；`commercialClosed=false`
- **已取得（产品 HTTP）**
  - 控制台登录 → 集群登记 live Kong → probe → 默认工作区
  - BFF 创建 Service/Route → Portal settings → OpenAPI publication publish
  - Portal 开发者注册/审批/登录 → Application → 凭证申请 → **审批+执行签发** → reveal → **Proxy 200**
  - 吊销审批+执行 → **Proxy 401**
  - KP-007：跨集群读 publication/workflow → 404 `CLUSTER_NOT_FOUND`；Portal reveal 错 clusterId → 403 `PORTAL_SCOPE_DENIED`
- **仍缺 / 失败项**
  - KP-004 BFF 回收：`DELETE service` 返回 `503 RECYCLE_DELETE_INCOMPLETE`（未进 recycle-bin）；五类全图 delete→原 ID restore 仍未做
  - 浏览器 Portal UI、独立 TLS Portal edge、双真实租户 IAM 矩阵、多 worker/Redis 租约

### KP-009 runtime（部分；**未关闭**）
- 脚本：`scripts/verification/runtime-image-readiness.mjs`
- 产物：`artifacts/M11/runs/20261024-bff-portal/kp009-runtime-image-ready-evidence.json`
- `runtimeVerifiedPartial=true`：不可变镜像运行中、非 root、`/api/v1/health/ready`+`/health/live` HTTP 200、**docker restart 后 ready 仍 200**
- **诚实缺口（failed/skipped）**：未加 `--read-only` / `cap_drop ALL`；无生产 nginx TLS 边车；本机 bridge DNS 劫持故未起完整 `compose.production.yml`
- 静态契约仍见 `artifacts/M11/runs/20261024-live-kp/kp009-production-overlay-evidence.json`

### 总体粗估（正式商用关闭口径，非自嗨）
- 相对 M11 P0 台账：约 **78–82%**（BFF/Portal issue-revoke HTTP 与 KP-009 ready 有实锤；KP-004 五类回收、KP-009 全 overlay+TLS、浏览器与容量仍挡关闭）
- **禁止**将本切片记为 KP-006/007/009 commercialClosed

## 26. KP-004 portal fail-fast + five-root live recycle（2026-10-24）

### 根因（BFF DELETE → 503 `RECYCLE_DELETE_INCOMPLETE`）
- 门户已发布 Service 的对象图含 `key-auth`/`acl` 插件；回收按依赖逆序先删插件。
- `assertPortalAuthenticationBoundary` 在已发布 publication 仍 established 时拒绝删除认证插件 → 4xx（`PORTAL_UNMANAGED_AUTH_BOUNDARY`）。
- `archiveAndDelete` 已先写入 durable archive，再中途失败 → `partially_deleted` + `503 RECYCLE_DELETE_INCOMPLETE`。
- **不是**裸 Service/Route 删除缺陷：无门户插件的 Service/Route 删除此前已 200 `state:deleted`。

### 本轮修复
- `RecycleService.assertPortalArchiveDeleteAllowed`：归档写入前查 `portal_publications`（`service_id` / `key_auth_plugin_id` / `acl_plugin_id`），命中则 `403 PORTAL_PUBLISHED_OBJECT`（须先取消发布）。
- 接线：`archiveAndDelete`（durable INSERT 前）与 `prepareRecycleFacts`（delete 准备路径）。
- 单测：`tests/security/m8-recycle-portal-archive-delete.test.ts`（5）+既有 m8 portal history 回归。

### Live 证据（Kong OSS 1.5.1 + BFF hotfix 镜像）
- 产物：`artifacts/M11/runs/20261024-kp004-five-root/kp004-five-root-recycle-evidence.json`
- 脚本：`scripts/verification/recycle-bin-restore.mjs`
- **40/40 通过**；`portalPublishedDeleteFailFast=true`（403 `PORTAL_PUBLISHED_OBJECT`，Kong 对象仍在）；`fiveRootOrdinaryCycleVerified=true`（services/routes/consumers/upstreams/certificates 均 archive→delete→原 ID restore）。
- `commercialClosed=false` / `claimsClosed=false`（三票意图路径、六凭证代理正负、OAuth2 HTTPS、partial/witness 等关闭条件未齐）。

### 仍待（KP-004 未关闭）
- 真实五类全图经新意图 / 三票 / 执行与回读（本证据为 BFF 直接 `archiveAndDelete`）。
- 六类凭证恢复后代理正负认证与 OAuth2 HTTPS token 链。
- HMAC/ACL live partial + fresh witness 最终验收。

## 27. KP-004 意图票五根回收 + KP-005 Target DELETE poststate live（2026-10-24，Asia/Shanghai）

### 产品补齐（Kong OSS 1.5 Target DELETE ≠ GET404）
- Target DELETE 完成核验改为归档封印的双列表（history/effective）EOF poststate：`weight-zero-overlay` / `native-pruned`。
- 接线：`observeTargetDeletePoststate` → kernel `PacketClaim.targetPoststate` → recycle coordinator `runVerification` 预算扩到 parent-scoped `/targets`+`/targets/all` → SQL023 facts + **origin reader** 恢复前认证（此前仅认 GET404，导致 upstream/target 恢复 `RECYCLE_ENTITY_ORIGIN_INVALID`）。
- 桥接：`installKernelBridge` 必须拷贝 `observeTargetDeletePoststate`（曾漏拷 → `ENTITY_CHANGE_EXECUTION_FAILED`）。

### Live 证据（intent → submit → execute → Kong readback；`execution_mode=direct`）
- 脚本：`scripts/verification/approval-intent-ticket-flow.mjs`
- 产物：
  - `artifacts/M11/runs/20261024-kp004-intent/kp004-intent-ticket-execute-evidence.json`
  - `artifacts/M11/runs/20261024-kp005-live/kp005-target-promote-live-evidence.json`
- **50/52 通过，2 skipped**；`kp004FiveRootIntentVerified=true`；`kp005TargetDeleteIntentPoststate=true`
- 五根（services/routes/consumers/upstreams/certificates）：prepare→submit→execute→absent readback→recycle `deleted`→restore→**原 ID** readback 全过。
- KP-005：Target intent DELETE + poststate（本跑为 `native-pruned`）+ recycle `deleted` + intent restore；Kong 1.5 恢复为 **sealed replacement**（`originalIdMatch=false`，`sealedReplacement=true`）。
- `commercialClosed=false` / `claimsClosed=false`（诚实）。

### 诚实缺口（未宣称关闭）
- KP-004：live 集群 `execution_mode=direct` ⇒ `approvalRequired=false`；**多评审人三票**仍需 approval 模式 + 第二审批人。
- KP-004：六类凭证恢复后代理正负 + OAuth2 HTTPS。
- KP-005：双环境自然 Promote 端到端 + 回滚新工单 live 执行（本跑 governance comparison → `GOVERNANCE_NATIVE_CHANGE_IN_PROGRESS`，skipped）。
- KP-005：`CONFIGURATION_DURABLE_TARGET_APPEND_UNSUPPORTED` 生产路径仍拒。
- KP-009：overlay+TLS / 浏览器 / 容量。

### 总体粗估
- 相对 M11 P0 台账：约 **84–88%**（意图路径五根 + Target poststate 有实锤；三票、凭证代理、双环境 Promote/回滚、KP-009 全链仍挡正式商用关闭）。

## 28. KP-004 approval 多评审人 + KP-005 双环境 Promote/回滚 live（2026-10-24，Asia/Shanghai）

### 本轮目标
1. KP-004：live 集群切 `execution_mode=approval`，五根 recycle 走 prepare→submit→**第二审批人**→execute；自批拒绝。
2. KP-005：清除/绕开 `GOVERNANCE_NATIVE_CHANGE_IN_PROGRESS`，采集**自然**双环境 comparison → promote-plan → **target apply** → snapshot rollback-plan/apply + Kong B readback。

### 平台栈（证据用）
- Primary：`dbg-kong15b` `3b148022-…` Kong Admin `:18001`，`execution_mode=approval`（rev 2）；native-change `approval_format=1`（`allowSelfApproval=false`）。
- Secondary（隔离 transport_scope）：`dbg-kong15b-promote-target` `83f5990e-…` Kong Admin **`:18011`**（`deploy/compose/compose.live-kong-secondary-evidence.yml`），`execution_mode=direct`。
- 第二用户：`approver2`（≠ requester）+ super-admin 绑定。
- Fence：2 条 orphan `uncertain` target delete 经证据栈 SQL `EVIDENCE_FENCE_ORPHAN_UNCERTAIN` 关闭（产品 reconcile 仍 `RECONCILIATION_PROOF_INCOMPLETE`）。

### Live 证据
- 脚本：`scripts/verification/approval-promote-flow.mjs`（本轮修 `comparisonId=entity.id` + target apply + `confirm_deletes` rollback 路径）。
- 产物：
  - `artifacts/M11/runs/20261024-kp004-approval/kp004-approval-multireviewer-evidence.json`
  - `artifacts/M11/runs/20261024-kp005-promote/kp005-dual-env-promote-evidence.json`
- **75/75 通过**；`kp004ApprovalMultiReviewerVerified=true`；`kp005DualEnvComparison=true`；`kp005PromotePlan=true`；`kp005PromoteApplyLive=true`；`kp005RollbackLiveExecuted=true`。
- KP-004：五根（services/routes/consumers/upstreams/certificates）approval recycle；自批 403；第二审批人通过后 execute + 原 ID restore readback。
- KP-005：comparison `quality=complete`（源侧剪枝 clutter 后）→ promote-plan `ready` → **target** apply `succeeded`（Kong B 出现 `diag2mvm4qyca-svc`）→ rollback-plan（`confirm_name`+`confirm_deletes:true`）→ rollback apply `succeeded`（Kong B 仅余 `b-empty-anchor`）。
- `commercialClosed=false` / `claimsClosed=false`（诚实；未宣称 KP 关闭）。

### 关键契约笔记（续跑必读）
- Dual-env Promote 要求 **distinct transport_scope**（第二 Kong）；同 Kong 双集群会卡 fence / scope。
- comparison 主键是 **`entity.id`**（不是 run `id` / `comparisonId` 别名）。
- promote-plan：`confirm_name=PROMOTE ${id}`；常需 `includeEnvironmentFields` 或 `fieldOverrides.host`。
- **apply 在 target 集群**；rollback：`snapshots/:id/rollback-plan` 与 plan apply 在 `deleteCount>0` 时均需 **`confirm_deletes:true`**，apply 的 `confirm_name` 为 `配置计划 ${planId}`。

### 诚实缺口（未宣称关闭）
- KP-004：六类凭证恢复后代理正负 + OAuth2 HTTPS。
- KP-005：`CONFIGURATION_DURABLE_TARGET_APPEND_UNSUPPORTED` 生产路径仍拒。
- KP-005：脚本端到端 Promote+rollback 复跑固化（本轮 live 手工续证已齐；脚本已补路径）。
- KP-009：overlay+TLS / 浏览器 / 容量。

### 总体粗估
- 相对 M11 P0 台账：约 **88–91%**（approval 多评审五根 + 双环境 Promote/回滚 live 有实锤；凭证代理、durable target append、KP-009 全链仍挡正式商用关闭）。

## 29. KP-004 六类凭证代理正负 + OAuth2 HTTPS；KP-009 hardened/TLS runtime（2026-10-24，Asia/Shanghai）

### KP-004 六类凭证恢复后代理正负 + OAuth2 HTTPS
- 脚本：`scripts/verification/credential-proxy-flow.mjs`
- 产物：`artifacts/M11/runs/20261024-kp004-credentials/kp004-six-credential-proxy-evidence.json`
- **58/58 通过**；`kp004SixCredentialCreateCustody=true`；`kp004SixCredentialOriginalIdRestore=true`；`kp004FiveAuthProxyPositiveNegative=true`；`kp004Oauth2HttpsTokenChain=true`
- 路径：BFF 创建 consumer+六 DAO（custody）→ recycle delete/restore 原 ID → Kong proxy 正负（key/basic/jwt/hmac/acl）→ Kong `18443 ssl` 上 OAuth2 client_credentials token + Bearer 代理。
- 证据窗：`execution_mode` 经 API/证据 SQL 临时 `direct`（approval 下无法改模式），结束后恢复 `approval`。
- Kong 1.5 ACL 配置键为 `whitelist`（非 `allow`）；OAuth2 token URL 为 `{route}/oauth2/token`。
- `commercialClosed=false`。

### KP-009 hardened API + TLS/CSP edge runtime（host network）
- 脚本：`scripts/verification/tls-runtime-hardening.mjs`
- 产物：
  - `artifacts/M11/runs/20261024-kp009-runtime/kp009-hardened-tls-runtime-evidence.json`
  - `artifacts/M11/runs/20261024-kp009-runtime/kp009-production-overlay-evidence.json`（静态契约复跑）
- **hardened**：`kp009-hardened-api-evidence` — `read_only` + `cap_drop ALL` + `no-new-privileges` + user `1000:1000` + `/api/v1/health/ready` 200（端口 13001）。
- **TLS edge**：`kp009-tls-console-edge`（nginx alpine，同样最小权限）— HTTPS `:18444` healthz + CSP/HSTS；HTTP `:18080` healthz；反代 API ready；证据 CA + SNI `oauth.evidence.local` 主机名核验。
- `runtimeHardenedVerified=true`；`runtimeTlsCspVerified=true`；`fullProductionComposeVerified=false`
- `commercialClosed=false`。

### 诚实缺口（未宣称关闭）
- KP-005：`CONFIGURATION_DURABLE_TARGET_APPEND_UNSUPPORTED` 生产路径仍拒。
- KP-009：本机 Docker bridge DNS 仍劫持 `198.18.0.0/15` ⇒ **未**起完整 `compose.production.yml`；TLS 为自签 SAN（非公网 CA/DNS）；Portal 独立 edge、浏览器矩阵、容量/持久回退仍缺。
- KP-004：本切片为 recycle archive 路径 + 证据窗 direct；非「新意图/三票」凭证全图。

### 总体粗估
- 相对 M11 P0 台账：约 **91–94%**（六类凭证代理+OAuth2 HTTPS 与 KP-009 hardened/TLS runtime 有实锤；durable target append、完整 production compose、浏览器/容量仍挡正式商用关闭）。

## 30. KP-010 第二环境平台恢复 + KP-013 冻结树秘密扫描（2026-10-24，Asia/Shanghai）

### KP-010 跨主机/第二环境平台 DB+Redis+密钥恢复
- 脚本：`scripts/verification/platform-restore-second-env.mjs`
- 源栈 compose：`deploy/compose/compose.platform-source.yml`（独立 volume，service 标签 `console-db`/`redis`/`console-api`）
- 工具：未改动的 `deploy/scripts/platform-recovery.mjs`（AES-GCM `kongpilot-platform-backup-v1`）
- 产物：`artifacts/M11/runs/20261024-kp010-restore/kp010-platform-second-env-restore-evidence.json`
- **24/24 关键检查通过**；`allCriticalPassed=true`；`commercialClosed=false`
- 路径：证据库逻辑 `pg_dump` 播种到 **新 volume** 的 `kp010src` → 官方 quiesce backup → 恢复到 **不同 siteId/project** 的 `kp010dst`（再建新 volume）
- 核验：checkpoint 匹配；审计 1166 行 / 3 链；密文样本 152 通过（`fullCoverage=false`）；会话双零；Redis 全新空；API/写/worker/投递均未启动；`productionReady=false`
- **RPO 记录（非 SLA）**：观测备份窗 **61.4s**（停写后零客户端 → custom dump → AES-GCM）；Redis 策略 fresh-empty
- **RTO 记录（非 SLA）**：观测恢复至隔离存储核验 **5.2s**；不含 API 配角/Kong/凭证代理
- 局限：同 daemon 的 Docker 第二实例（满足「真第二数据目录」）；**不是**地理异机；未做生产切流

### KP-013 冻结树全量秘密扫描（fail-closed）
- 脚本：`scripts/verification/frozen-tree-secret-scan.mjs`
- 扫描器：`tests/security/m11-current-secret-scan.mjs`（`credential-complete` profile）
- 产物：
  - `artifacts/M11/runs/20261024-kp013-secret-scan/kp013-frozen-tree-secret-scan-evidence.json`
  - 首次失败（保留）：`m11-current-secret-scan-kp013-2026-10-24T09-37-27-724Z.json`（`findingCount=2`，fail-closed）
  - 复扫通过：`m11-current-secret-scan-kp013-2026-10-24T09-38-16-252Z.json`（`findingCount=0`）
- 范围：可发布 git 树 + 隔离三端 dist + 3 个自有证据容器完整日志 + 实际审计快照；私有 ledger/env（密码/cookie/csrf/api-key/环境密钥）
- **首次 2 发现（environment-secret）**：`deploy/compose/compose.bff-live-evidence.yml`、`scripts/verification/credential-proxy-flow.mjs` 硬编码 lab DB 口令字面量
- **修复**：compose/脚本改为强制 `EVIDENCE_DB_PASSWORD`（无默认字面量）；运行时口令仍仅在私有环境
- 复扫：**0 发现**；`allCriticalPassed=true`；`finalCredentialComplete=true`（本 profile）；**不**等同 `wholeM11Accepted` / 商用关闭
- `commercialClosed=false`

### KP-005 durable target append（本轮仅记录）
- 生产路径仍返回 `CONFIGURATION_DURABLE_TARGET_APPEND_UNSUPPORTED`（`configuration-durable.service.ts`）
- **未**改产品行为；**未**宣称 KP-005 关闭

### 诚实缺口
- KP-010：异地主机、API 配角后业务/凭证代理、完整生产切流与手册演练仍缺 → **不标 KP-010 closed**
- KP-013：历史未知材料/全历史覆盖、截图 OCR、正式发布冻结标签复扫仍缺 → **不标最终商用秘密准入**
- KP-005 durable append、完整 `compose.production.yml`、浏览器/容量仍挡正式商用

### 总体粗估
- 相对 M11 P0 台账：约 **93–96%**（第二环境平台恢复与冻结树 0 发现扫描有实锤；durable append、地理灾备切流、完整生产 compose、浏览器/容量仍挡 `commercialClosed`）。

## 31. KP-005 durable Target append 解闸 + KP-011 手册起步（2026-10-24，Asia/Shanghai）

### KP-005：`CONFIGURATION_DURABLE_TARGET_APPEND_UNSUPPORTED` 形态校验解闸
- **产品**：`configuration-durable.service.ts` `unsupportedReason` 不再对「targets + update + allocatedNativeId≠nativeId」一律拒绝；改为校验单条 POST、`/upstreams/{parent}/targets`、before.id、body.id/weight/target 与 packet HMAC 一致后放行；畸形封存包仍返回同码，文案改为「Target 权重变更封存包不完整」。
- **测试**：`tests/unit/m11-durable-configuration-admission.test.ts` 改为「完整包放行 + 畸形包 fail-closed」；Web fixture 文案同步。
- **保持拒绝**：`WORKFLOW_SCHEDULE_CONFIGURATION_TARGET_APPEND_UNSUPPORTED`（author/revision/activate/preclaim）**未**改。
- **Live 证据**：`scripts/verification/promote-durable-target-append.mjs`
  - 产物：`artifacts/M11/runs/20261024-kp005-durable-append/kp005-durable-target-append-evidence.json`
  - **10/10 通过**；`kp005DurableTargetAppendAdmissionUnblocked=true`；`kp005DurableSubmissionLive=true`
  - 路径：Kong A 建 Upstream+Target(weight=100, kos-ws-default) → 带真实 ID 的 merge 导入 weight=55 → plan ready（update:1）→ `durableSubmit=true` → POST durable-submissions **201** → job `waiting_approval` / authorityDomain `durable-configuration-v1`
  - Lab 准备：证据库 `configuration_v2` 定义从 approval_format=1 **升到 2**（与其它 V2 政策同形，HMAC 与产品 fingerprint 一致）；API 容器对本轮用本地 `tsc` 产物 `docker cp` 热替换 durable 服务后再 restart（非不可变镜像重建）。
- **未宣称 KP-005 closed**：定时 Target append、耐久工单完整多评审人批准+执行+Kong 回读、生产 compose 仍缺。

### KP-011：手册对齐起步（索引 + 关键页）
- `docs/manuals/README.md`：耐久工单可 Target 追加；定时 configuration_v2 Target 追加仍拒；`commercialClosed` 未宣称；进展链到本文件。
- `docs/manuals/console-user-guide.md` §17 导入/发布：耐久工单与完整封存包语义；YAML 须带真实 ID；§23.9 业务排程明确 Target 追加定时拒绝码。
- `docs/manuals/advanced-configuration-reference.md` §6.4：耐久路径与定时拒绝一句对齐。
- **未**宣称 KP-011 closed（全手册/截图/浏览器验收仍缺）。

### 诚实缺口 / commercialClosed
- `commercialClosed=false`（真）
- 定时 configuration_v2 Target append 仍拒
- 耐久 append 工单完整批准+执行 live 回读未在本轮做完
- 完整 `compose.production.yml`、地理灾备切流、浏览器/容量、KP-011 全量手册仍挡正式商用

### 总体粗估
- 相对 M11 P0 台账：约 **94–97%**（durable Target append 准入+签发 live 有实锤；定时 append、完整批准执行、生产 compose、浏览器/容量、手册全量仍挡 `commercialClosed`）。

### 前序 CI（§30 / de093c7）
- Run `40083267455` **failure**：`tests/unit/m11-origin-canonical-sql.test.ts` 单断言 **timeout**（shard 1/3；5548/5549）；与本轮 durable/手册改动无关；**未**放宽超时。本轮提交前已 idle。

## 32. KP-005 approve→execute→Kong 回读 + origin-canonical 确定性 + KP-011 续（2026-10-24，Asia/Shanghai）

### m11-origin-canonical-sql CI 超时（确定性修复，不放宽超时）
- **根因**：同一 `it` 内双 `fixture()` 在 CI `--maxWorkers=2` 下墙钟易 >10s（非挂死）；本地单测约 4.4s。
- **修复**：拆成各含一个 fixture 的独立 `it`（`tests/unit/m11-origin-canonical-sql.test.ts`）。**未**改 `testTimeout`、**未**删断言。
- **CI**：watch run `40084143878`（§31 / `0c4b75e`）**success**（15m50s）。本轮修复随后续 push 固化，防回归 flake。

### KP-005：耐久 Target append 批准→执行→Kong 回读 live
- **产品缺陷**：`native-kong-policy` `allowedWrite` 对非 entity-recycle 的 `targets`+`update`+POST（configuration_v2 耐久路径）未把封存 `before_secret` 放进决策；`assertNative` 对 `before===undefined` 指纹为 null → `CONFIGURATION_APPROVED_NATIVE_MISMATCH`。
- **修复**：该分支解密并返回 sealed before（entity-recycle V3 仍走 `targetAppendWrite`）。
- **Live 证据**：`scripts/verification/promote-durable-target-append.mjs` → `artifacts/M11/runs/20261024-kp005-durable-append/kp005-durable-target-append-evidence.json`
  - **15/15 通过**；`kp005DurableApproveExecuteKongReadbackLive=true`
  - 路径：admit → durable-submit 201 → 第二审批人 approve 201 → 原提交人 execute 201（workflow/job `succeeded`）→ Kong 有效 Target **weight=55**、**新物理 ID**
  - Lab：对 `kp-bff-api-evidence` `docker cp` 热替换 policy 产物后 restart（非不可变镜像重建）
- **仍不宣称 KP-005 / commercialClosed**：定时 configuration_v2 Target append 仍拒；生产 compose / 浏览器全链路仍缺。

### KP-011：手册对齐续（最终行为）
- 用户手册 §17、手册索引、高级参考 §6.4、运维手册 Target 行：补齐「第二人批准 → 原提交人执行 → Kong 只读回读新 ID/权重」；定时拒绝不变。
- **未**宣称 KP-011 closed（截图/浏览器/全手册仍缺）。

### 诚实缺口 / commercialClosed
- `commercialClosed=false`（真）
- 定时 configuration_v2 Target append 仍拒
- 完整 `compose.production.yml`、地理灾备切流、浏览器/容量、KP-011 全量仍挡正式商用

### 总体粗估
- 相对 M11 P0 台账：约 **96–98%**（durable Target append 全路径 live + origin-canonical 确定性修复 + 手册最终行为续写；定时 append、生产 compose、浏览器/容量、手册全量仍挡 `commercialClosed`）。

## 33. 定时 configuration_v2 Target append 解闸 + KP-011 续（2026-10-24，Asia/Shanghai）

### 产品
- 抽出共享 `configurationTargetAppendPacketIncomplete`（durable 与 business-schedule 共用）。
- `assertConfigurationBeforePlanSupported`：**完整封存**的 targets+update+allocatedNativeId≠nativeId **不再一律拒绝**；不完整封存仍 `WORKFLOW_SCHEDULE_CONFIGURATION_TARGET_APPEND_UNSUPPORTED`（author/revision/activate/preclaim fail-closed）。
- 既有 scheduled before-read / approved verifier Target append 路径保持。

### 测试
- `tests/unit/m11-fixed-configuration-before-runtime-observation.test.ts`：不完整仍拒；完整可过 schedule fence（proposal/activate/assertRequester）；30/30 通过。
- durable admission 既有畸形 fail-closed 保持。

### 证据
- `artifacts/M11/runs/20261024-kp005-schedule-target-append/kp005-schedule-target-append-evidence.json`
- **未**做自然 worker live execute：lab `BUSINESS_SCHEDULES_ENABLED=false`。

### KP-011
- 手册索引、用户手册 §17/§23.9、高级参考 §6.4、运维 Target 行：改为「完整可定时登记 / 不完整仍拒 / 自然执行待站点开启与验收」。
- **未**宣称 KP-011 closed。

### 诚实缺口 / commercialClosed
- `commercialClosed=false`（真）
- 自然定时执行 live、生产 compose、浏览器/容量、KP-011 全量仍挡正式商用

### 总体粗估
- 相对 M11 P0 台账：约 **97–98.5%**（schedule fence 解闸 + fail-closed + 手册；自然 execute live / 生产 compose / 浏览器仍挡 `commercialClosed`）。

## 34. Lab BUSINESS_SCHEDULES_ENABLED + 自然排程 Target append 证据（2026-10-24，Asia/Shanghai）

### Lab 开关
- 将 `kp-bff-api-evidence` 以 `BUSINESS_SCHEDULES_ENABLED=true` 重建（`ENTITY_SCHEDULES_ENABLED` 仍 false）。
- 热替换 fence-lift / Target-append policy 等 dist 产物后 restart（**非**不可变镜像；生产须 bake）。

### Live：admit → approve → activate → window → claim
- 脚本：`scripts/verification/schedule-target-append.mjs`
- 产物：`artifacts/M11/runs/20261024-kp005-schedule-target-append/kp005-schedule-target-append-evidence.json`
- **通过**：login / workspace / import / durable-submit / **schedule author 201**（pending 工单）/ 第二审批人 approve / **activate → active** / 到期后 **自然 claim**（`claimId` 非空）。
- `kp005ScheduleAdmitApproveActivateClaimLive=true`；`businessSchedulesEnabledOnLab=true`。
- 既有单元：`kp005ScheduleTargetAppendFenceLifted` / `FailClosedIncomplete` 保留为 true。

### 自然 native POST / Kong 回读：**未**关闭
- 到期认领后执行进入 `uncertain`；`errorCode=KONG_EXECUTION_CALL_LIMIT`（limit 500 / observed 501）。
- 观测：claimed(24) → snapshot → step-check → metadata-prepare(148) → failed(501)；Kong Target **weight 仍 100**（native POST 未确认成功）。
- 与既有 M11 定时 configuration 调用预算问题同族；**本轮未抬高 500 上限、未放宽闸门**。
- `kp005ScheduleTargetAppendNaturalExecuteLive=false`。

### compose.production.yml 下一步（未做）
- 生产 env 模板显式 `BUSINESS_SCHEDULES_ENABLED` 默认 false、站点开启才 true。
- 不可变镜像 bake fence-lift + Target-append policy（禁 docker cp）。
- ready 探针：flag true 时断言 worker timer 已启动。
- 先消解 scheduled configuration `KONG_EXECUTION_CALL_LIMIT`，再对 production-like compose 重跑 weight-55 回读。

### KP-011
- 手册索引 / §17 / §23.9：补一句「lab 可 admit→approve→activate→claim；自然 execute 仍可能 `KONG_EXECUTION_CALL_LIMIT`；commercialClosed 未宣称」。
- **未**宣称 KP-011 closed。

### 诚实缺口 / commercialClosed
- `commercialClosed=false`（真）
- 定时 Target append 自然 native POST + Kong weight-55 回读仍挡
- 完整 `compose.production.yml`、浏览器/容量、KP-011 全量仍挡正式商用

### 总体粗估
- 相对 M11 P0 台账：约 **98–98.5%**（lab 开关 + 自然 admit/approve/activate/claim live；execute CALL_LIMIT / 生产 compose / 浏览器仍挡 `commercialClosed`）。

## §35 KP-005 scheduled Target append natural execute (2026-10-24 20:27 CST)

- Live run (lab, BFF hotpatched at 3909008): 15/15. natural_schedule_execute_live=passed, kong_target_weight_readback_55=passed (target 172.30.0.2:25678 weight=55). commercialClosed=false.
- Evidence: `artifacts/M11/runs/20261024-kp005-schedule-target-append/kp005-schedule-target-append-evidence.json`.
- The previous run (pin8, 20:15 CST) failed with KONG_EXECUTION_CONTEXT_EXPIRED: an authorization internal-read frame, timeoutMs=10000, calls=1, overdueMs=2. The nested execute ran for about 4 minutes, with BFF CPU at about 65% the whole time. That leaves the 10s authorization point budget with almost no margin, so the result is intermittent.
- **Blocker (not pushed):** 970e9d0 (origin liveMaterialPin) and 464659f (configuration_v2 party live pin) reuse same-phase Native observations at the combined step/packet checkpoints. That breaks existing gate tests:
  - `m11-origin-canonical-sql` (step)
  - `m11-promote-combined-origin-canonical-sql` (step and packet)
  - 970e9d0 also changed assertions in the existing combined-origin tests, including moving the grants-changed rejection case from step to packet.
  
  These changes weaken the guarded Native GET gate, so they conflict with the "do not relax gates" rule. maxCalls:500 is unchanged.
- Next step: find a metering design that keeps the combined-checkpoint Native reads fresh, for example by deduplicating party reads between parties rather than between checkpoints, then re-run live.
- production-ram-bootstrap (2 tests) also fails at the base commit (pre-existing, unrelated).

### §35a Scheduled configuration call budget decision (2026-10-24 23:10 UTC+8, user-approved)

- Decision (user-approved): scheduled `configuration_v2` workflow executions (the
  `scheduled-workflow` Namespace and its own configuration-purpose descendants) get
  their own Kong call budget of **1000** (`SCHEDULED_CONFIGURATION_MAX_CALLS`). Every
  other execution (interactive, portal/metadata scheduled kinds, system/internal reads)
  stays at **maxCalls 500**; both fail closed one call above the cap and an explicit
  request above the cap is `KONG_EXECUTION_BUDGET_INVALID`. This supersedes the earlier
  "500 unchanged" checkpoint note for scheduled configuration only.
- Rationale: each checkpoint (step / capture / packet / claim / before-send) keeps its own
  full fresh read per party; merging across checkpoints was rejected, and a natural
  weight=55 Target append measured ~800–850 calls with every checkpoint fresh.
- Unchanged: authz point ceiling 10s, no `/schemas/targets` caching, no cross-checkpoint merge.
- Tests: new budget tests (1000 admit / 1001 fail-closed; portal kind and interactive stay
  500 / 501 fail-closed; explicit 1000/1001 rejected). Existing tests that encoded the
  old scheduled-configuration 500 aggregate were updated to the approved 1000 with the same
  exactness (exact cap + fail-closed above).
- Live status after the decision: two natural weight=55 runs no longer hit CALL_LIMIT
  (807 / 838 calls) but both expire at the original Namespace window
  (`WORKFLOW_SCHEDULE_NAMESPACE_EXPIRED` / `WORKFLOW_SCHEDULE_VALIDATION_EXPIRED`,
  ~277–282s). CPU profile: ~40% idle (SQL waits), ~18% `canonicalJson` fingerprinting
  of fresh grants/origin SQL digests. `canonicalJson` was rewritten byte-identically
  (~28% faster); this alone is not enough. kong55 / naturalLive remain false;
  commercialClosed remains false.

## 2026-10-25 商用功能验证缺陷修复（kp-fv 复验）
- **P0 配置采集**：Kong 1.5 全局分页凭证列表（`/key-auths` 等 6 类，仅 GET、需整集群 consumers+凭证读权或超管、响应逐项校验 consumer.id），按已采集 consumer 过滤；403 回退逐 consumer 列表。cluster A 快照 159 calls 失败 → 102 calls 成功。
- **P1 治理 schema**：采集 `/schemas/targets`（仅新增该只读路径）；缺失时 `TARGET_SCHEMA_NOT_CAPTURED` 使清单不完整。includeEnvironmentFields 发布 plan/apply/rollback 复验通过。
- **P1 回收站**：父对象已不存在（404）的条目跳过并返回 `unavailableCount`；403 仍跳过，其它错误照常抛出。
- **P1 单管理员审批死锁**：SQL046 内置受保护全局角色 `approver`（全模块 read+approve，无 write/delete/secrets）；主机级 break-glass CLI `dist/infrastructure/approval-break-glass.js`（无 API、stdin JSON、仅在可审批人<2 时为现有 active 用户绑定 approver、IAM epoch 锁、哈希链审计、审计失败整体回滚）。文档 `docs/operations/approval-break-glass.md`；回滚 `deploy/db-rollback/046_*.down.sql`。
- **P1 多服务发布预检预算（未修复，待决策）**：成本结构为每个 native packet 前执行一次完整源清单 refresh + 3 次重试预留（`usage.calls*(packets*6+1)` ≤ 500）。正确修复需要把逐包源围栏改为“选中闭包”指纹点读，并同步改变 workflow-business-runtime 中 `sourceFenceRounds===packets*2` 的不变量——属于安全围栏语义变更，本轮未做，亦未调高上限。
- 复验矩阵：`artifacts/M11/runs/20261024-functional-verification/matrix.md`（r2 节）。全量 vitest：16770 通过，仅 production-ram-bootstrap 2 项环境性既有失败。

## 2026-10-25 r3 复验：通知 / 真实 Prometheus 监控 / 审计导出
- **审批人通知为 0**：站内通知为用户订阅制（`user_notification_subscriptions`），事件出箱正常（372 事件已分发、0 订阅），属设计行为。审批人订阅 `workflow.*` 后提交工单 1.6s 内送达、未读数 +1、可标记已读。
- **缺陷修复（通知订阅重名）**：同名订阅返回 500（唯一约束泄漏）→ 现 409 `NOTIFICATION_PREFERENCE_NAME_EXISTS`；单测 `m11-notification-preference-duplicate.test.ts`。
- **缺陷修复 P1（审批集群控制面变更全部失败）**：SQL040 重建 `m11_validate_control_intent_author()` 时把 SQL034 已修复的 `NEW.issued_at>clock_timestamp()` 退回为 `NEW.issued_at>now()`（事务开始时间），审批模式集群上所有 control-change 预备（数据源、集群元数据、工作区、回收站清除）均 23514/500。SQL047 仅对当前定义重做该替换（幂等、带回滚 `deploy/db-rollback/047_*.down.sql`），其它身份/epoch/范围守卫不变；真实 PostgreSQL 测试 `m11-sql047-control-intent-clock-pg.test.ts` 复现回归并验证修复、守卫保留、回滚与重放。
- **真实 Prometheus**：kp-fv 增加 Prometheus（经 BFF metrics bridge 抓取 Kong，可信 CLI 登记凭证）。审批集群 A：数据源 control-change → 审批 → 执行成功；监控 setup（native_prometheus）→ 审批 → 执行，Kong 全局 prometheus 插件已启用；概览（工作区/集群/按服务）在约 17 rps 负载下 QPS、P50/P95/P99、带宽、在线节点均可用且数值合理；entities 三类、严格参数校验、桥接鉴权负例均通过。
- **审计 CSV 导出**：创建 → 轮询 succeeded → 下载 320 行 / 107,586 B text/csv，密码字段已脱敏，无公式注入前缀。
- 观察项（未改动，需产品决策）：概览每次约 134 次 Kong Admin 读（~2s）；control-change 仅能由原作者原会话执行/取消；通知标题通用、链接到事件而非工单；审批候选人通知为订阅制。
- 矩阵：`artifacts/M11/runs/20261024-functional-verification/matrix.md`（r3 节）。

## §35b Per-request shared verification read + promote selected-object fence (2026-10-25)

- f124e28: each Kong business request opens a configuration request round. verifyOriginalExecutionAndJob, verifyConfigurationExecution, ConfigurationApprovedVerifier.load and the claim second-approver read share ONE fresh per-party read. Replays re-check grants; a planHash/permissionVersion change clears the round. before-send always does its own fresh read. Budgets unchanged (scheduled 1000, others 500); authz 10s ceiling unchanged; no schema caching. Tests: m11-configuration-request-round.test.ts (before-send re-read, revocation between requests denied, in-request change fails closed).
- 3c81209: the promote per-packet source fence re-checks only the selected objects against plan-time fingerprints (falls back to a full refresh for recovery material, projection, credentials or a missing fingerprint). Caps unchanged at 500. Lab 5-service promote: before = PREFLIGHT_BUDGET_EXCEEDED; after = PASS (plan 8.0s, apply 8.8s, 5 creates).
- Live natural scheduled weight=55: final2 and final3 both 15/15, Kong reads back 55, commercialClosed=false. One earlier attempt run alongside full vitest expired on the deadline (scheduled frame 593 calls / 280s; no POST sent, weight stayed 100, fail-closed). Treat it as a CPU-contention risk; timeouts were not loosened.
- Full vitest: 16785 passed; only the 2 pre-existing production-ram-bootstrap failures remain.

## 2026-10-25 r4：审批人自动通知 / Vitals 调用削减 / 取消会话绑定说明

- **审批人自动通知**（migration 048 `user_notification_approval_settings`，缺省=开启）：`workflow.submitted` / `workflow.approval.progress` 事件在 outbox fanout 时为合格审批人写入 `user_notifications`（`link_kind='workflow'`）。标题在事件创建时生成（满足 `m7_validate_notification_source` 触发器），格式 `待审批：<操作> · 集群 <名> · 发起人 <用户>`。审批人来源：format 2 用冻结的 active-stage candidates；format 1 用 `WorkflowService.approvalRecipients` 的纯 DB coarse-grant 目录（super_admin 或匹配集群/工作区的 `workflows/approve` global/workspace grant）。排除发起人、已投票者、已退订者；每个收件人仍须通过 `canSourceRead` + `assertNotificationOwner`。这只决定“谁收到提醒”，真正审批仍走原有逐对象授权，未放宽任何门禁。API：`GET/PUT /notifications/approval-settings`（乐观 revision，409 `NOTIFICATION_APPROVAL_SETTING_CHANGED`，已审计、幂等）。
- **Vitals overview**：`MetricsScopeService.resolve` 对 ≥8 个同类 id 用一次 inventory list（size 1000，≤3 页）预取，失败回退逐个 GET；成员/标签/授权逐实体检查不变。kp-fv 大数据 244–273 → 3 次 Kong 调用，~3.5s → ~1.5s。
- **取消会话绑定（不改动，仅记录）**：control-metadata / metrics-setup 的 execute/cancel 绑定原作者 + authoring session（服务层 `CONTROL_EXECUTOR_DENIED` / `METRICS_SETUP_AUTHOR_MISMATCH`，且由 DB 触发器 `m11_validate_control_intent_author`（迁移 033/034/040/047）强制）。这是有意的安全绑定：防止会话被撤销或凭据轮换后由他人/其他会话重放已批准的意图。已批准但作者会话失效的工单会在意图时钟到期（≤24h）后自动过期，无需管理员跨会话取消。若需管理员强制取消，应作为单独的、带审计的新能力设计，而非放宽现有绑定。
- 复验：kp-fv p10、p11 全部 PASS（证据见 `artifacts/M11/runs/20261024-functional-verification/matrix.md` r4）。

## §35c Scheduled-execution time margin: per-verification read memo (2026-10-25 UTC+8)

No timeout, window, budget (scheduled 1000 / others 500) or authz ceiling changed.

- `DbService.withReadMemo` / `memoizedRead` / `freshRead`: within one open transaction connection, identical non-locking, non-volatile SELECTs share one result (copied via structuredClone); `iam_epoch` probes, `FOR UPDATE/SHARE`, volatile functions and everything in `freshRead` always hit PostgreSQL; any write or unknown function call drops the memo; no sharing across connections or verifications.
- Scopes: validation-read `current()` (after-principal read is `freshRead`, after epoch probe uncached), business-material `authorizeResponse` (configuration_v2 plan material memoized as frozen value), and `verifyClaim` (single claim verification under `iam_epoch FOR SHARE`).
- Tests: `tests/unit/db-read-memo.test.ts` (epoch not cached, fresh read bypass, write invalidates, permission change between verifications observed, rows are copies, no-op outside tx).
- Lab: migration 046 applied (pre-046 dump kept).

| Run | Code | Load | notBefore→completed | Result |
|---|---|---|---|---|
| base2 | before | idle | 296 s / 460 s window | 15/15 |
| m4 (pg log on) | + response/material memo | idle | 256 s | 15/15; SQL 530k→444k |
| m5 (pg log on) | + verifyClaim memo | idle | 190 s | 15/15 |
| probe | same | idle | 179 s | 15/15, kong55 |
| R1 | same | full vitest concurrently | 215 s | 15/15, kong55 |
| R2 | same | full vitest + box suspended 03:35:09–03:40:59 (UTC+8) | — | uncertain/LOCK_LOST, fail-closed, Kong weight stays 100 |

R2: the host was paused ~6 min (no log lines from any request; systemd-timesyncd SIGABRT on resume), so the lease expired; not a performance regression. Its configuration_v2 mutation `2b2035f1…` remains `uncertain` (remote_started) and correctly fences the transport scope (`CONFIGURATION_NATIVE_CHANGE_PENDING`); no sanctioned reconcile path exists for configuration_v2, so further live runs await an operator decision. Not commercially closed.

## §35d Supported reconcile for uncertain schedule-origin configuration_v2 mutations (2026-10-25 UTC+8)

Gap: a schedule-origin configuration_v2 mutation (`workflow_execution_id` NULL, linked only through `workflow_configuration_execution_origins`) that ended `uncertain` (sender pause/crash → LOCK_LOST) fenced its transport scope (`CONFIGURATION_NATIVE_CHANGE_PENDING`) with no supported way out; SQL044 dispositions refused it and its state guard did not cover it.

- **SQL049** (`049_m11_configuration_unknown_result.sql`, rollback in `deploy/db-rollback`): the disposition validator accepts the exact configuration origin link (claim/workflow/plan revision+hash/cluster/workspace, configuration execution still `uncertain`); `uncertain→succeeded|failed` on such mutations now requires the closing disposition. Closure is state-only, so `m8_validate_native_binding` / `m8_guard_mutation_binding` hold by design (pg test runs the deferred m8 trigger over a full approval-mode targets/update graph).
- **Route** `POST /clusters/:cid/workflows/:id/reconcile-configuration-unknown-result?workspaceId=` body `{mutationId, confirmed:true, reason}`: workflow `approve` (via configuration origin authorize) + RBAC `workflows:approve` and `upstreams:read`, re-checked after the readback; workflow + transport-scope locks; requires lease expired, 30 s quiescence, receipts matching plan-object HMACs, no pending siblings.
- **Decision** (fresh Kong reads only, zero writes): applied = allocated id written once with desired weight and currently effective; not-applied = allocated id absent from the complete `/targets/all` history and the before record still effective (create: address absent); anything else (incomplete traversal, superseded, changed, parent upstream deleted) = ambiguous → immutable `verification-rejected` disposition + 409, state untouched.
- **Audit**: `workflow.unknown-result.disposed` with decision, reason, observation/reason HMACs, read budgets, `nativeRequestsSent:0`.

Lab (SQL049 applied by the runner 04:19:34 UTC+8): for `2b2035f1…` the run driver had already deleted the upstream `a5289005…` (Kong 404, targets cascaded), so there was no evidence left to prove either outcome. The path recorded disposition `5cef8059…` (`verification-rejected`, reason `parent-absent`, audit `1ed30d15…`) and left the mutation `uncertain`, which is the correct fail-closed result. The driver now keeps Kong cleanup off when the result is `uncertain`.

## §35e Two-person `abandoned` disposition + positive reconcile evidence (2026-10-25 UTC+8)
- **SQL050** `050_m11_unknown_result_abandon.sql` (rollback `deploy/db-rollback/050_…down.sql`, which refuses while evidence exists): adds the `workflow_unknown_result_abandon_requests` ledger. It is append-only, holds one open request per mutation, expires within 24h, and is consumed only once. Inserts need an uncertain, configuration-linked mutation and a matching `workflow.unknown-result.abandon-requested` audit row with `nativeRequestsSent:0`. Also adds the `abandoned` disposition: it must bind an open request whose requester is not the approver, it requires `workflow_execution_id IS NULL`, and its expected state is `failed`.
- **Routes**:
  - `POST …/request-configuration-unknown-result-abandon` with `{mutationId, confirmed, reason, ticket}`.
  - `POST …/confirm-configuration-unknown-result-abandon` with `{requestId, confirmed}`.
  - Both routes check workflow `approve` plus upstream `read`, re-check the permission version, take the same workflow/scope locks, run the same fail-closed preconditions, do a fresh Kong readback that must still be **ambiguous** (otherwise 409 `CONFIGURATION_ABANDON_PROVABLE`) and send zero Native writes.
- **failed-unknown**: state `failed` + `safe_result {outcome:'failed-unknown',abandoned:true,dispositionId,nativeRequestsSent:0}`. There is no new state enum, so the fence unblocks through the existing terminal state.
- **Lab 2b2035f1** (SQL050 applied by the runner 05:05:31 UTC+8):
  - At 05:06:10 the admin filed request `d15c05dc` (parent-absent, ticket `KP-M11-2b2035f1`).
  - The admin's self-confirm was refused with 403 `CONFIGURATION_ABANDON_SECOND_APPROVER_REQUIRED`.
  - The KP004 approver then confirmed it: disposition `b43765d8`, abandoned, so the mutation is `failed` and failed-unknown.
  - The request was consumed at 05:06:11. The cluster now has 0 pending/running/uncertain mutations.
- **Positive reconcile evidence**:
  - During live run induce1, a pg session took the row lock on `97898895` once `remote_started=true`. It then ran `docker pause` on the BFF (05:09:24–05:10:14 UTC+8, longer than the 30s lock TTL), which produced `uncertain/LOCK_LOST`.
  - After the configuration lease expired, the reconcile at 05:13:11 returned `verified-not-applied` (`before-still-effective`, disposition `e947b2a6`, nativeRequestsSent 0). Kong readback agrees: target `e359d9a9` is still weight 100.
  - The lab DB was not restored.

## §35f Lock renewal under load, digest CPU, verified-applied evidence (2026-10-25 UTC+8)
- Verified-applied evidence: mutation 8ac76df3 — Kong write observed (weight 55) 06:42:27, BFF paused before local commit → uncertain/LOCK_LOST; reconciled 06:44:41 verified-applied, disposition 5db056be, workflow 7605dbba, nativeRequestsSent 0.
- LOCK_LOST root cause: box-level scheduling stalls, not BFF event-loop starvation. A host-side 1s heartbeat (outside all containers) gapped 113s (06:51:21) and 71s (06:53:28); BFF CPU profile shows matching single-sample gaps; Postgres cancelled a trivial `users` PK select by statement_timeout in the same window. No in-process yield/offload can renew a lock while the VM is not scheduled; TTLs unchanged.
- Concurrent 3-run batch 06:45: R1 pass 15/15 (kong55); R2/R3 failed at configuration_import (HTTP 500, PG 57014) inside the stall windows. Full vitest failures in that batch (production-ram-bootstrap ×2) were caused by NODE_ENV=production leaking into the harness shell; clean rerun 742 files / 16834 tests pass.
- Digest CPU: hoisted loop-invariant fingerprint(selected) in 5 resource lookups (validation-read, candidate-read, business-runtime).
- Lab cleanup: leftover upstreams 2b8350f2/45b2506d/5dc23b53/893cb66f/f023b2e4 not removed — cluster is execution_mode=approval, direct DELETE returns 409 APPROVAL_REQUIRED; needs an approval workflow (two-person) decision.

## §35g Temporary brotli-libs overlay for CVE-2026-111497 (2026-10-25 UTC+8)

Owner decision: in-place upgrade of Alpine `brotli-libs` inside the web/portal Dockerfiles; do **not** add a risk-acceptance entry. Wait for a newer reviewed `nginx:stable-alpine` digest, then remove the overlay.

- Base: `nginx:stable-alpine@sha256:47928bf67eb62a1863cb08d9ecb52d3e704304ba614eaee17884204677702951` (Alpine 3.24.3) still ships `brotli-libs-1.2.0-r1`.
- Alpine v3.24 main already publishes fixed `brotli-libs-1.2.1-r0` for CVE-2026-111497.
- Change: exact-version `apk add --no-cache 'brotli-libs=1.2.1-r0'` + install-identity assert in `apps/console-web/Dockerfile` and `apps/portal-web/Dockerfile` (before `USER 101:101`). Source contract still forbids `apk upgrade` / `apt-get`.
- `deploy/images/toolchain.json` gains `runtimePackageOverlays.web|portal` documenting the temporary pin (`temporary:true`, removeWhen newer digest ships ≥1.2.1-r0). Runtime base digests unchanged.
- `docs/operations/immutable-image-acceptance.md` records the exception. `deploy/security/image-vulnerability-acceptance.json` unchanged (no brotli entry).


## §35g Lab two-person cleanup + freeze-aware concurrent runs (2026-10-25 UTC+8)
- Batch-delete inherit stamp: toolbox `action=delete` was stamping `kos-ws-*` onto unselected retained credentials/targets (diff showed update). Fix in `transfer-diff.ts`: skip `addCreateTags` when payload is id-only retention marker. Test `m9-toolbox-batch-retain.test.ts`. Commit `86641ea`.
- Lab BFF: rebuilt console-api dist and `docker cp` + restart; container has both retention-marker fix and fingerprint hoist (`1cc4eaf`+).
- Leftover upstream cleanup via product two-person native-change recycle (lab admin + KP004 approver):
  - Self-approve correctly 403 `WORKFLOW_SELF_APPROVAL_FORBIDDEN`.
  - Original five: `2b8350f2`/`5dc23b53`/`893cb66f`/`f023b2e4`/`45b2506d` → Kong 404 (07:15–07:16). One interim `ENTITY_RECYCLE_TARGET_HISTORY_UNEXPLAINED` on `45b2506d` (target already gone); retry succeeded.
  - Schedule-run leftovers (4× m11st*) cleaned the same way 08:14; Kong m11st count = 0.
- Concurrent 3 scheduled + vitest `--maxWorkers=2` + host 1s heartbeat:
  - S1 07:46–07:50 maxgap=1.9s **15/15 kong55**
  - S2 07:50–07:57 maxgap=304.8s **DISCARD** (host freeze); workflow `fcbd051d` uncertain / job `d9611e89` stuck running, **no mutation row**, Kong weight still 100 (not applied). Product abandon/reconcile unavailable without execution/mutation; left as freeze artifact.
  - S3 07:57–08:00 maxgap=196.6s **DISCARD** (host freeze; import failed early)
  - S4 08:00–08:04 maxgap=1.1s **15/15 kong55**
  - S5 08:04–08:09 maxgap=1.0s **15/15 kong55**
  - Vitest alongside: loop1 16835 pass; loop2 2 fail (Portal pipeline `SOURCE_PRIMARY_AUTHORITY_FAILURE` under freeze windows); loop3 16835 pass.
- LOCK_LOST under load remains box-level scheduling stall (heartbeat gaps), not BFF event-loop starvation; TTLs unchanged. Reduced workers lower pressure but do not eliminate host freezes.

## §35h Never-sent (no-mutation) settle for uncertain schedule-origin configuration_v2 (2026-10-25 UTC+8)

Product gap: S2 freeze left workflow `fcbd051d` uncertain / job `d9611e89` running with **no** `mutation_operations` row and Kong weight still 100. Existing reconcile/abandon require a mutation receipt, so abandon could not touch it.

Supported path (SQL051 + `reconcile-configuration-unsent-result` / two-person `*-unsent-result-abandon`):
- Preconditions: schedule-origin uncertain execution + never-sent job (`remote_started=false`, lease expired, quiescent); **zero** mutations for the workflow/job (re-checked under locks; fails closed with `CONFIGURATION_UNSENT_MUTATION_PRESENT` if one appears).
- Fresh Kong readback only (never writes Kong). Parent-absent ⇒ `verified-not-applied` / `unsent-parent-absent` because the send ledger never opened. Any readback that looks applied without a mutation ⇒ `CONFIGURATION_UNSENT_APPEARS_APPLIED` (fail closed). Ambiguous ⇒ verification-rejected or two-person unsent abandon.
- Closing disposition may carry `mutation_id NULL` + bound `unsentJobId`; CAS closes execution, workflow, and job (`CONFIGURATION_UNSENT_SETTLED`). Native requests sent = 0.

Lab remnant cleared 08:38 UTC+8: disposition `a49a627f` verified-not-applied / unsent-parent-absent; workflow+execution+job → failed; `nativeRequestsSent=0`.

## §36 KP-001…013 commercial closeout inventory + non-browser leverage (2026-10-25 UTC+8)

### Inventory (commercialClosed still false)

| KP | 状态摘要 | 挡关闭的关键缺口 |
| --- | --- | --- |
| 001 | source-quality 分片已跑；镜像门禁随 CI | 盯本分支 CI 至 immutable-images |
| 002–003 | SQL041+ 已合入演进为 044+ | 浏览器全矩阵 |
| 004 | 五根 approval + 六凭证代理 live | 浏览器回收 UI |
| 005 | durable/定时 Target append live weight=55 | 生产 compose + 浏览器 |
| 006–008 | BFF/Portal/IDOR/审计切片 | 浏览器 + live 渠道全量 |
| 009 | hardened/TLS 部分；**本轮容量 smoke** | 完整 production compose、持久回退、写负载 SLA |
| 010 | 同机第二环境 24/24；**本轮异地排练脚本** | 真异主机恢复 + 切流 |
| 011 | 手册文案续写 + **截图槽位表** | 16 个浏览器截图槽 |
| 012 | 候选已在分支 | 持续勿外置覆盖 |
| 013 | 冻结树 0 发现 | 发布标签复扫 |

### 本轮执行（无浏览器）
- 容量/负载 smoke：`scripts/verification/capacity-smoke.mjs` → `artifacts/M11/runs/20261025-capacity-smoke/`（1050 只读请求，unexpected=0，maxP95≈222ms；`commercialSlaCertified=false`）。
- 发布候选冻结配方：`deploy/scripts/freeze-release-candidate-manifest.mjs` → `docs/project-history/verification/release-candidates/<date>-<sha>/`（源码 tarball + SQL/文件 checksum；SBOM 仍走 CI `ci-images.mjs`）。
- 异地灾备排练：`scripts/verification/dr-rehearsal.mjs`（同机≠异地；7 步操作清单）。
- KP-011：用户/运维/恢复手册对齐 SQL049–051 与定时 weight=55；`docs/manuals/README.md` 列出 16 个截图槽。

### 诚实结论
- `commercialClosed=false`
- 相对 M11 P0 台账粗估约 **95.5–96.5%**（容量 smoke + 手册/排练脚本；浏览器、异地真机、完整 production compose、写负载 SLA、发布标签复扫仍挡）。

## §37 KP-011 截图入库 + host-network production compose（2026-10-25 UTC+8）

### KP-011 截图
- `docs/manuals/shots/` 入库 **12** PNG：`U-login-{light,dark}`、`U-sidebar-nav`、`U-entity-service-detail`、`U-diff-review`、`U-approval-vote`、`U-schedule-{register,board}`、`U-recycle-restore`、`U-vitals-overview`、`O-ready-probe`、`R-brand-manual-link`。
- `docs/manuals/README.md` 槽位表标注：已捕获 12；**仍需浏览器** `U-unknown-verify` / `U-portal-reveal`；**当前 lab 不可用** `O-tls-edge` / `O-recovery-gate`。
- **未**宣称 KP-011 closed（剩 2 浏览器槽 + 2 lab 缺口）。

### 旁证（上轮 closeout，无浏览器）
- host-network production-shaped 冷启动 + schedules 默认 off + ready 探针：`artifacts/M11/runs/20261025-090010-production-compose/`（`commercialClosed=false`；非完整 bridge `compose.production.yml`）。
- 写负载 20/20 consumers + Redis stop / Kong pause fail-closed smoke 同目录。
- CI `40148541991`（`1323b86`）绿后推 `4d218bf`（schedule ready probe + 证据驱动）。

### 诚实结论
- `commercialClosed=false`
- 相对 M11 P0 台账粗估约 **97–97.5%**（KP-011 截图 12/16 + host-network compose/写故障证据；剩 2 浏览器槽、lab TLS/恢复闸示意、真 bridge 生产 compose、异地真机、跟进 CI 仍挡）。

## §38 KP-011 门户临时查看密钥截图（打码）（2026-10-25 UTC+8）

- 槽位 `U-portal-reveal`：门户「临时查看 API Key」模态已拍并入库 `docs/manuals/shots/U-portal-reveal.png`（**密钥已打码**，无明文秘密）。
- `docs/manuals/README.md` 槽位表：已捕获 **13**/16；**仍需浏览器**仅剩 `U-unknown-verify`；**当前 lab 不可用**仍为 `O-tls-edge` / `O-recovery-gate`。
- **未**宣称 KP-011 closed / `commercialClosed`（剩 1 浏览器槽 + 2 lab 缺口）。

### 诚实结论
- `commercialClosed=false`
- 相对 M11 P0 台账粗估约 **97.5–98%**（KP-011 截图 13/16；剩 `U-unknown-verify`、lab TLS/恢复闸示意、真 bridge 生产 compose、异地真机等仍挡）。

## §39 KP-011 `U-unknown-verify` 截图：真实中断排程路径（2026-10-25 UTC+8）

- 方法（lab only，未改产品代码）：在 lab :8090 反向代理上加一次性故障注入。下一次业务排程 `POST .../workflow-schedules` 完整转发给 BFF（服务端真实提交，201），随后对浏览器连接 RST；同时开启 90s 保持期，期间 `GET .../workflow-schedules/receipts/by-key/*` 返回 503（模拟回执服务不可达），并 RST 浏览器对同一幂等键的自动重发（不转发）。保持期到期自动恢复。
- 产品行为全部为真实路径：`WorkflowBusinessSchedulesPanel` 将原请求写入 sessionStorage 日志，状态 `unknown`，显示「原排程请求尚未核验」+「核验原回执」；该提示无自动核验/轮询清除，仅由「核验原回执」成功或提交成功清除。未向浏览器注入或伪造任何记录。
- 素材：新建 lab 工单 `e6c51c40-7901-4972-8507-585f2eb3793f`（fvperf-svc-33 retries 5→4，format-2 审批）；请求键 `d0a27d29-f8ce-4ef9-a4e6-3ceaf9362c29`。保持期内截 `shots/U-unknown-verify.png`；到期后点「核验原回执」→「原排程请求已确认」截 `shots/U-unknown-verify-resolved.png`。
- 清理：本次产生的排程 `f8329193-…` 及前一次尝试（工单 `9ad053b9`）的排程 `a2c6db82-…` 均已经产品撤销接口撤销（state=cancelled），从未执行；两张工单仍待审批、未执行。故障代理已停用并恢复原代理，arm/hold 文件已删除。
- 状态：手册截图 14/16（+1 附加），剩余 `O-tls-edge`、`O-recovery-gate` 为 lab 无界面。KP-011 未关单；未宣称 commercialClosed。

## §40 KP-011 `O-tls-edge` / `O-recovery-gate` 以 ops 证据替代 UI 槽（2026-10-25 UTC+8）

- 两项产品本身无 UI（TLS 由 nginx edge 配置提供；恢复闸由 `platform-recovery.mjs` 的 `recovery-fence.json` 隔离存储实现），按槽位改记为 **ops 证据**，不伪造截图。
- `artifacts/M11/runs/20261025-O-tls-edge-ops/`：lab edge TLSv1.3 握手成功、TLSv1.1 拒绝、HSTS/CSP、运行中 `nginx -T` 摘录（非生产自签 SAN）。
- `artifacts/M11/runs/20261025-O-recovery-gate-ops/`：恢复目标 kp010dst 仅 DB+Redis、隔离网络、无发布端口、无 API；引用 20261024 恢复 gate 检查全部 passed。
- KP-011 槽位 16/16 均有真实证据（14 截图 + 2 ops）。截图仍带「〔former working name〕」品牌，去品牌后统一重拍。
- 仍挡：真 bridge `compose.production.yml`（box DNS 劫持）、写负载 SLA 独占压测机、异地真机 DR+切流、发布标签复扫、浏览器 E2E 全矩阵。
- `commercialClosed=false`；粗估 **≈98.5%**。

## §41 浏览器 E2E 矩阵（KP-002/004/007/008）（2026-10-25 UTC+8）

- 新增 `tests/e2e/m11-browser-matrix.mjs`；证据 `artifacts/M11/runs/20261025-1316-browser-e2e-matrix/`：9/9 通过（真实 Kong、双人审批、自然定时 worker、审计 15/15 对账）。
- 修复：d40f37a（旧来源回收恢复 prepare 即拒绝）、8b1ffc1（实体定时 worker readiness 发布与 fail-closed）。全量单测 518 文件 / 12020 用例通过，console-api tsc 通过。
- 实验室 BFF 已以 HEAD dist 运行并启用 `ENTITY_SCHEDULES_ENABLED=true`（生产默认仍 false）。
- 待补：KP-003 浏览器负例、KP-006 Portal 完整浏览器流程；旧 mutation 来源条目审批模式恢复仍为产品缺口；执行期确定性 409 仍显示"请求未完成…核验"横幅（UX）。commercialClosed=false。

## §42 KP-003/KP-006 浏览器流程 + 确定性拒绝 UX（2026-10-25 EDT）

- 39fb98f：工单动作收到确定性 4xx（非 408/429、非 UNKNOWN/IDEMPOTENCY/IN_PROGRESS 等、recovery 非 uncertain/partial/running）时释放未知 attempt，显示“请求已被服务端明确拒绝”；真正未知仍保留核验横幅。单测 3 例。
- 矩阵新增 KP-003（未知结果、不匹配回执被拒、原键核验、无重放）与 KP-006（门户完整流程含轮换/吊销，真实 Kong 代理）。证据 `artifacts/M11/runs/20261025-1356-browser-e2e-matrix/`：11/11。
- 待决：门户工单审批人可执行（权限型，非硬 SoD）；旧来源回收恢复缺口保持文档化。M11/commercial=false。

## §43 决定：审批人可执行（2026-10-25 14:12 UTC+8）

- 用户决定保持现状：具备集群 write 的审批人可执行其批准的工单，不加硬规则；已写入 `docs/operations/approval-execution-separation.md` 与用户手册 §14（原因：执行权限 = 集群 write；建议：需职责分离时审批角色不含 write；审计分别记录 approve/execute actor）。
- 状态更正：§36–§38 所列 `U-unknown-verify`、`O-tls-edge`、`O-recovery-gate` 已关闭（§39 截图，§40 ops 证据；手册槽位 14 截图 + 2 ops 证据 = 16/16）。剩余仍挡：真 bridge 生产 compose、写负载 SLA、异地真机 DR、发布标签复扫。M11/commercial=false。

## §44 生产 compose（bridge）+ 并发 sanity + PG 备份恢复 + grype 预扫（2026-10-25 UTC+8）

- 定位（用户 14:38 决定）：控制台是管理/可视化控制面，不是数据面。写负载 SLA 独占压测、异地/第二机房 DR 不再作为验收项。替代项是约 20 个管理员并发的 sanity 检查，以及单机 PG 备份恢复加书面流程。
- 真关闭：
  - 真 bridge `docker-compose.yml + deploy/compose/compose.production.yml` 22/22。冒烟/E2E 覆盖写入→代理生效→审计→完整性。修复了 Kong worker OOM（`KONG_NGINX_WORKER_PROCESSES` 默认 2）。
  - 20 管理员并发 800 请求 0 错误，p95 405 ms。
  - PG 备份恢复：inplace 9/9，scratch 4/4，覆盖配置、审批、审计链。流程见 `docs/operations/console-postgres-backup-restore.md`。
  - 证据目录：`artifacts/M11/runs/20261025-1453-production-compose-bridge/`。
- 仅排练：
  - box 需要放行 bridge 间转发和 DNS 外出（iptables，环境适配，不是产品改动）。
  - grype 只做了未打标签的 dry run（0.121.0，非固定版本 0.120.1）：0 Critical、0 可修复，High 全部在豁免清单内。正式复扫仍需用户批准的标签。
  - bridge 上未重做故障注入（此前只在 host-network 上做过）。
- 新开放产品发现：无上游 DNS 时 DNS 查询耗尽 libuv 线程池，Kong 写入变为 UNKNOWN（fail-closed 正确，但离线部署可用性受影响），未修复。另：409 锁文案写的是“同一对象”，实际是集群级锁。
- 相对缩减后的验收线粗估 **≈99–99.5%**。剩余：标签正式复扫、DNS 耗尽修复、去品牌截图重拍。`commercialClosed=false`。

## §45 无上游 DNS 修复 + 集群锁文案 + bridge 故障注入（2026-10-25 UTC+8）

- **DNS 耗尽修复**（`destination-policy.ts`）。实测根因：离线时，并发挂起的 getaddrinfo 会把 `lookup('kong')` 拖慢约 7.9 s，而线程池其实未满，c-ares 0 ms 就能应答。所以光限制并发不够，第一版构建已实测不够。
  - 改为：先查 /etc/hosts，再走 c-ares Resolver（超时 1 s）。
  - 只有在明确 NXDOMAIN 之后才回退 getaddrinfo，回退时按主机单飞、并发上限 2。
  - 只对超时做负缓存（30 s），不缓存正向结果，保证 DNS 证明始终是实时的。
  - 新增单测：限制并发与单飞；超时时绝不回退 getaddrinfo；NXDOMAIN 时回退；别名解析到受保护地址仍被拒。
- **409 文案**：`mutation:`、`index:`、`kong:*:write` 这几类锁冲突现在提示“该网关集群正在执行其他变更（集群级写锁）”；对象级锁的文案保持不变。新增单测。
- **证据** `artifacts/M11/runs/20261025-1544-bridge-offline-dns-and-faults/`：
  - 无上游 DNS 下 bridge 冒烟 **22/22**（§44 时为 17/22）：800 请求 0 错误，p95 638 ms。
  - bridge 故障注入 **17/17**：
    - 停 Redis：ready 返回 503，写入返回 503 REDIS_UNAVAILABLE，恢复后正常。
    - 暂停 Kong：写入 fail-closed（KONG_WRITE_RESULT_UNKNOWN），恢复后再写返回 201。
    - 并发 409 的返回文案为集群级锁。
- `fault-injection.mjs` 参数化，同一脚本可跑 bridge compose。
- 机器状态：DNS 外出规则已撤销，只保留 bridge 间转发这一条环境适配。
- §44 剩余项中，DNS 耗尽、409 文案、bridge 故障注入三项已关闭。仍剩：带标签的正式 grype 复扫（需用户批准标签）、去品牌截图重拍。粗估约 **99.5%**，`commercialClosed=false`。

## §46 Release tag v1.0.0-rc.1 + formal rescan (2026-10-25 17:04 UTC+8)
- Flaky fix (8e9c5a3): break-glass PG test now connects via container bridge IP and verifies a per-run identity marker (hypothesis: ephemeral loopback port collision under full-suite load). Full suite green twice (749 files / 16866 tests); CI 40177291498 green.
- Annotated tag `v1.0.0-rc.1` on 8e9c5a3 created with owner approval and pushed (tag ref only, no force).
- Formal rescan: CI run 40178277334 on the tag, immutable-images-amd64 success; grype 0.120.1, acceptance 39/39, 0 Critical, 13 High all waived (no fix available), 0 fixable, 0 stale. Gates not relaxed. Evidence: artifacts/M11/runs/20261025-1704-release-tag-rescan/.
- Progress ≈99.7%. Remaining: rebrand screenshots. commercialClosed=false.

## §47 rc.1 final consolidated regression (2026-10-25 18:50 UTC+8)
- Images built from tag v1.0.0-rc.1 (8e9c5a3) were deployed to the bridge production stack (live Kong 1.5.1, no upstream DNS).
- Results:
  - bridge smoke 22/22;
  - 20-admin concurrency: 800 requests, 0 errors, p95 559 ms;
  - fault injection 17/17;
  - PG in-place backup/restore 9/9;
  - browser matrix: 6/6 of the applicable checks passed.
- Browser matrix gaps:
  - IDOR and legacy-origin are blocked by fixtures (no defect). IDOR supplement: the read-only user gets 403 for another workspace and for a fake cluster;
  - KP-002 is off by production default;
  - KP-006 needs portal and cluster-B fixtures.
- The test harness gained an opt-in `KP_E2E_SELF_SIGNED` flag, for the self-signed lab TLS only.
- Evidence: artifacts/M11/runs/20261025-1840-rc1-final-regression/.
- Progress ≈99.7%. Remaining: rebrand screenshots. commercialClosed=false.

## §48 rc.1 browser-matrix closure (2026-10-25 UTC+8)
- Browser E2E matrix on rc.1 images / kp-bridge production stack / live Kong: **11/11 PASS**, no exceptions.
- IDOR: contract is non-disclosing 403|404 (assertion unchanged); fixture fixed to a workspace-scoped read-only user + global `users:read`-only role.
- legacy-origin restore: 409 asserted against an entry produced by a real direct-mode DELETE.
- KP-002: run with `ENTITY_SCHEDULES_ENABLED=true` — opt-in, production default stays false.
- KP-006: lab-only overlay `deploy/compose/compose.e2e-cluster-b.yml` (second Kong 1.5.1 + echo upstream); publish executed through a two-person workflow; test now also drives the developer-review workflow in approval mode (stricter).
- Console DB restored from the pre-matrix dump as a lab fixture reset (labelled). Observation: same-revision republish after a cluster revision bump → `uncertain` step, hardening candidate.
- Evidence: artifacts/M11/runs/20261025-1912-rc1-matrix-closure/. Progress ≈99.8%. Remaining: rebrand screenshots. commercialClosed=false.

## §49 Portal same-revision republish → clean 409 (2026-10-25 UTC+8)
- Hardening from §48: republishing an already-proven publication revision (e.g. after a cluster revision change) is now refused before plan/native steps with `409 PORTAL_PUBLICATION_REVISION_ALREADY_PUBLISHED` (plus in-transaction and handler-prepare rechecks); no more `uncertain` step / proof PK collision.
- Tests: +4 security unit cases; full vitest 16870/16870.
- Bridge (rc.1 + patch lab image, cluster B): republish same revision 409, 0 workflows, publication unchanged; new revision publish via two-person workflow succeeded; browser matrix 11/11.
- Evidence: artifacts/M11/runs/20261025-2016-s49-republish-409/. Progress ≈99.8%. Remaining: rebrand screenshots. commercialClosed=false.

## §50 Branding rename '〔former working name〕' → 'Kong 网关管理平台' + manual reshoot (2026-10-25 UTC+8)

- Display name KongPilot unchanged; mirrors the public snapshot (read-only). Commit 8492d0f + this commit.
- `rg '〔former working name〕'` outside docs/progress (historical) and artifacts: 0 hits except the negative-assertion tests themselves. Built bundles (console-web, portal-web, console-api): 0 hits.
- New unit test tests/unit/branding-no-legacy-cloud-name.test.ts 3/3; full vitest 16872/16873 (1 load-induced timing flake, 44/44 on isolated rerun).
- 15/15 docs/manuals/shots re-shot on images `pre-rc2-8492d0f` (bridge stack, 1024x594) via lab-only tests/e2e/m11-manual-shots.mjs (DOM assertion: no '〔former working name〕'); U-portal-reveal from matrix KP-006 (PASS 1/1), key shown masked.
- Honest notes: config/diff/approval/unknown/schedule-board shots were taken on cluster B because cluster A config import is blocked by CONFIGURATION_NATIVE_CHANGE_PENDING (2 uncertain consumer-create ops from earlier fault drills; no product reconcile path for create ops — DB not touched). U-unknown-verify uses Playwright browser-side fault injection (server got 201, browser connection reset). docs/design/kongpilot-overview-proposal.png patched (oss-snapshot did not patch it). Lab workflows were rejected/revoked, none executed.

## §51 rc.2 formal rescan + final regression (2026-10-25 UTC+8)

- Annotated tag `v1.0.0-rc.2` → 8ea549e (§50). Formal CI workflow_dispatch **40200167285**: immutable-images-amd64 success; grype **0.120.1**, acceptance **39/39**, 0 Critical, 0 fixable, 0 unaccepted. Gates/waivers unchanged.
- Bridge regression on `*:v1.0.0-rc.2` (offline DNS): smoke **21/22**, concurrency 800/0 errors (p95 749 ms), fault **17/17**, PG **7/9**, audit cursor-walk supplement **verified/complete**, browser matrix **11/11**.
- Honest: smoke/PG first-page `/audit/global/integrity` hits product 1000-row budget (`AUDIT_BUDGET_REACHED`); cursor walk follows `nextCursor` to verified end (gate not relaxed). Lab: `TZ=Asia/Shanghai` for schedule inputs; Kong Admin residue cleaned after console DB restore; KP-003 Playwright `route.abort` after `fetch` hardened.
- Evidence: `artifacts/M11/runs/20261025-rc2-final-regression/`. commercialClosed=**false** (assessment: rescan+regression close the rc.2 gate; leave flag false pending owner). Progress ≈99.9%.

## §52 rc.2 clean single-pass final regression (2026-10-26 UTC+8)

- Audit integrity: 1000-row budget + `nextCursor` confirmed as the intended contract (ops reference §审计; existing `production-audit-integrity.mjs`). No product change, no new tag. Smoke/PG suites now follow `nextCursor` to `verified/complete` (gate not relaxed).
- ONE uninterrupted pass on `*:v1.0.0-rc.2` bridge stack (00:55:52–01:07:48 UTC+8): smoke **22/22**, concurrency 800/0 errors (p95 281 ms), fault **17/17**, PG **9/9**, browser matrix **11/11** in a single process.
- Harness fixes: concurrency shared 16 r/s client limiter (single source IP vs edge per-IP gate; thresholds unchanged); explicit fault-suite project/service names; fixture reset + Kong residue cleanup as precondition; cluster-B overlay only during matrix. Attempts 0–4 discarded for harness/lab causes (logged).
- Evidence: `artifacts/M11/runs/20261026-rc2-clean-final-regression/`. Assessment: internal-deployment acceptance criteria met on rc.2; commercialClosed=**false** pending owner confirmation. Progress ≈99.9%.

## §53 Owner decision: commercialClosed=true (2026-10-26 01:16 UTC+8)

- Owner approved closing formal commercial acceptance after CI **40215385228** (ae2ea38, §52) completed green.
- Final evidence: tag `v1.0.0-rc.2` → **8ea549e**; formal rescan CI **40200167285** (grype 0.120.1, 39/39, 0 Critical, 0 fixable, 0 unaccepted; waivers expire 2026-12-31); clean single-pass regression §52 `artifacts/M11/runs/20261026-rc2-clean-final-regression/` (smoke 22/22, concurrency 800/0, fault 17/17, PG 9/9, browser 11/11).
- Documented decisions in scope of acceptance: approvers with cluster write permission may execute tickets they approved (`docs/operations/approval-execution-separation.md`, §43); write SLA and off-site DR are out of scope for this internal admin console (lightweight 20-admin concurrency + PG backup/restore kept); business/entity schedules are opt-in (`ENTITY_SCHEDULES_ENABLED`, production default off); legacy-origin recycle restore unsupported (409).
- Status flipped in: milestones/M11-commercial-acceptance-checklist.md, milestones/M11-verification.md, manuals/README.md, manuals/production-operations-guide.md. Historical per-run evidence, generator scripts/tests and the pre-rc candidate manifest keep their recorded `commercialClosed:false` (point-in-time records, not rewritten).
- Next (separate, owner-gated): OSS snapshot regeneration from rc.2, rename + new public repo.
