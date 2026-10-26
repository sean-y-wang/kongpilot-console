# M10 配置治理中心实施计划

状态：**下一阶段实施计划，尚未编码、迁移、部署或验收**。整理日期：2026-10-12；实施归属与 Promote 授权补充：2026-10-13。

M9 尚在阶段验收，必须先完成 M9 的当前代码回归与验收落盘，再实施本文。本文记录的是对当前源码的只读勘察与下一阶段接口设计，不能作为 M10 已存在或商用验证通过的证据。用户已经授权按 M9 → M10 → M11 连续推进；阶段验收由实际证据控制，不需要再次索取常规方案确认。

历史 [M9–M11 存储候选合同](m9-m11-storage-contract.md) 中 SQL013/014 的编号已经过时。SQL000–015 已用于已有模块，SQL016 由 M9 工作区迁移审批占用。**M10 SQL 从 017 以后由 Root 在阶段开始时分配**，本文不提前创建或占用迁移编号，不修改既有迁移内容和校验和。

## 1. 阶段目标与最小完整闭环

交付一个真实可运行的治理中心，完成以下四条链路：

1. 手动或定时有界巡检 → 规则与结构检查 → 保存有覆盖证明的不可变报告 → 定位对象 → 明确输入后生成修复 diff → 二次确认或审批 → M8 执行与回收 → 重新巡检确认问题消失。
2. 内置及自定义 Lint 规则 → 校验受限 DSL → 规则版本/按集群启用 → 实际规则引擎执行 → 字段定位及报告。
3. 两个真实环境的工作区或 Service 范围 → 各自授权、有界采集 → 逻辑身份正规化 → 双环境 diff → 阈值判断 → M7 通知与投递记录。
4. 选定源工作区或 Service → 目标实体映射及环境覆盖项 → 默认排除凭证、秘密、环境字段 → 目标 diff → 二次确认或目标集群审批 → M8 执行前快照/逐步回执 → 回滚与原键核验。

阶段不创建第二套 Kong native apply engine、不直接连接 Kong 数据库、不以报告 ID 或 DTO 中的 `approved` 字段发放写许可。所有 native 管理端点及字段仍以已探测的 Kong OSS 1.5.x schema 为准。

## 2. 现有代码可以复用的准确接口

### 2.1 配置捕获、diff、计划与执行

以下接口在当前源码中已经存在，不代表新增治理接口已经存在。

| 文件 / 服务 | 已有签名与行为 | M10 的使用方式 |
| --- | --- | --- |
| `modules/configuration/configuration.service.ts` / `ConfigurationService` | `captureSnapshot(cid: string, body: Record<string, any>, actor: EntityActor): Promise<any>` | 为需要完整恢复或明确包含秘密的源材料建立真实 M8 作业；返回真实 `jobProjection`，不是浏览器伪造的快照 |
| 同上 | `importDocument(cid, body, actor)`；body 为 `{scope, serviceIds?, yaml, mode: 'merge' \| 'sync', basicPasswordIntents?, confirm_deletes?}` | 修复及 Promote 的默认目标为服务器编译的 `merge` 文档；内部冻结输入、重新捕获目标 baseline、正规化、diff、编译 DAG 和封存计划 |
| 同上 | `plan(cid, id, query, actor)` | 读取实际计划、当前能力及分页变化；使用 `size/cursor`，不伪造 Kong 跳页 |
| 同上 | `apply(cid, id, body, actor)`；body 包含 `planRevision, planHash, confirmed, confirm_name, confirm_deletes?` | 使用目标集群当前执行模式；direct 执行或产生统一 `configuration_v2` 工单，沿用 native 私有授权、执行前快照及回收 |
| 同上 | `rollbackPreview(cid, snapshotId, body, actor)` | 创建真实回滚预览；仍须当前权限、有效凭证恢复材料及新确认 |
| 同上 | `job(cid, id, actor)`、`steps(cid, id, query, actor)`、`receipt(cid, originalKey, actor)` | 原始作业/原键回执与步骤日志是唯一执行事实；未知结果不自动重发 |
| 同上 | `compareSnapshots(cid, id, otherId, actor, view = 'configuration')` | 仅用于**同一真实 scope** 的历史比较；不能直接用于跨环境 drift |
| `modules/configuration/configuration-access.service.ts` / `ConfigurationAccessService` | `acquireJob({actor, clusterId, workspaceId, kind, rootIds?, purpose, kindOfJob, idempotencyKey, module?: 'snapshots' \| 'gitops'})` | M8 的 WeakMap 私有 capability；普通对象或断言为其 TS 类型不能授权 |
| 同上 | `assertCurrent(handle, {phase, jobId?, scope?, manifestHash?}, tx?)`、`runRead(handle, paths, fn)`、`runJob(handle, fn)`、`assertHistoricalGraph(handle, graph, secretsRequired = false)` | 使用 M8 真实材料时保留当前身份、权限、物理连接、版本、lease 和每个历史对象检查；不得自行反序列化句柄 |
| `modules/config-capture/configuration-capture.service.ts` / `ConfigurationCaptureService` | `capture(handle: ConfigurationAccessHandle, stage: CaptureStage, scope: ConfigurationScope): Promise<SnapshotSummary>` | 用于完整、可恢复的配置捕获，不用于容错巡检所有坏引用 |
| `modules/config-storage/configuration-repository.service.ts` / `ConfigurationRepositoryService` | `beginCapture(handle, input)`、`readSnapshot(handle, {scope, snapshotId, version?})`、`freezePlan(handle, {jobId, plan})`、`readPlan(handle, {scope, planId, planRevision, planHash})` | 仅通过真实私有句柄读取/封存；如治理服务需要服务器内部操作，增加固定目的桥接接口，不暴露原始 repo 到 controller |
| `modules/config-transfer/index.ts` | `normalizeDeckDocument`、`normalizeCaptureGraph`、`diffTransferGraphs`、`compileTransferDag`、`formatSafeDiff`、`compareCapturedSchemas` | 复用已经验证的 target-side 正规化、显式清空、schema 对比、secret 遮罩与依赖 DAG |

当前 `ConfigurationModule` 是 `@Global()`，imports 为 `ConfigStorageModule, ConfigCaptureModule, WorkflowsModule`；exports 只有 `ConfigurationAccessService, CONFIGURATION_ACCESS, ConfigurationService, CONFIGURATION_DECK_ACCESS`，并未导出 capture/repository。优先新增 **ConfigurationService 的固定服务器桥接入口**，由它继续持有完整捕获、材料和执行所有权，避免治理 controller 直接依赖存储和 native handler。

`ConfigurationService.captureBaseline`、`persistDiff`、`assertPlanGrants`、`createWrapper`、`executeJob` 目前都是 private，不能在新模块写假调用。M10 如需复用，应在该服务内新增窄入口或 installer，入口必须独立验证真实材料/作用域/输入 HMAC；不把 private 方法改成任意调用的公开 proxy。

### 2.2 实体、作用域、权限与元数据

| 文件 / 服务 | 已有签名或事实 | 约束 |
| --- | --- | --- |
| `modules/entities/entities.service.ts` / `EntityService` | `list(clusterId, type, query: ListQuery, actor)`、`get(clusterId, type, id, query, actor)`、`targets(clusterId, upstreamId, query, actor)` | 默认返回脱敏结果，服务端工作区及 RBAC 过滤；`query.reveal` 才会要求 secrets.read；治理不得设置 reveal |
| 同上 | `list` 无 search/sort 时调用 `filteredList`、真实 `KongService.list(size, cursor)`；search/sort 则使用实体索引 | 巡检应使用真实分页分支，不能把索引刷新滞后当 native 事实 |
| `modules/workspaces/workspace-resolver.service.ts` / `WorkspaceResolverService` | `resolve(cid, wid?)`、`listScope(cid, wid?, requestedPhysicalTags?)`、`classify(cid, physicalTags)`、`matches(scope, entity)` | 以实际物理标签判断，默认工作区包含未打标实体；多重/未知工作区标签不能归入正常统计 |
| `modules/authorization/authorization.service.ts` / `AuthorizationService` | `permissionVersion(user)`、`snapshot(user)`、`assertCluster(user, cid, module, action, wid?, tx?)` | coarse 模块许可不是全部实体许可；保持完整 grant tuple |
| 同上 | `hasWholeCluster / assertWholeCluster`、`hasWholeWorkspace / assertWholeWorkspace` | 共享规则/政策/定时任务管理及完整统计使用 whole scope；禁止 tag/entity 权限推断完整覆盖 |
| 同上 | `assertEntity(user, cid, nativeType, action, entity, wid?)`、`filterEntities(...)`、`assertScopedResource(...)` | 每个报告对象和修复对象还要核验当前原生范围权限 |
| `modules/workspaces/entity-annotations.service.ts` / `EntityAnnotationsService` | 控制台 `entity_annotations` 保存 `description, owner_user_id, metadata, revision, status`；已有写入/归档/恢复与 native scope 验证 | 巡检只读取授权对象的 description/owner 字段，不将任意 metadata 原文纳入报告；Kong Service 不添加虚假的 description 字段 |
| `common/authorization.types.ts` 与 SQL005 | 已包含 `governance, lint, drift, promote` 四个权限模块 | 无需扩大权限 module 白名单；可能需要增加实体/历史资源的固定别名与前端能力 |

### 2.3 审批、调度与通知

| 文件 / 服务 | 已有接口 | M10 用法 |
| --- | --- | --- |
| `modules/workflows/workflow-plans.service.ts` / `WorkflowPlansService` | `definitions(cid, wid, userId, tx?)`、`definition(cid, wid, kind, tx?)`、`persist(plan, key, request, tx, serverAuditRequest)`、`load(cid, wid, id, tx?)` | 规则/政策/共享调度的 approval metadata plan 必须由服务器编译、固定 subject 与 handler，不能让客户端提交 workflow steps |
| `modules/workflows/workflow-registry.service.ts` | `register(handlerName, {authorize, inspect, prepare, apply})` | 参考 `EventsMetadataService.onModuleInit` 注册治理 metadata handlers，`nativeRequests` 恒为空 |
| `modules/configuration/configuration-scheduler.service.ts` | 每 10 秒调用 `ConfigurationService.runDueSchedules()` | 借鉴非重入调度，不假造 due job 完成；不直接将它变成治理 native write worker |
| `ConfigurationAccessService` | `acquireDueSchedule(locator)`、`completeScheduleRegistration(handle)` | 借鉴 timer-only、持久 owner、不可变策略版本/HMAC、当前 grant、physical scope 与实际 run/job 绑定模式 |
| `modules/event-core/audit-outbox-writer.service.ts` / `AuditOutboxWriter` | `fromAudit(receipt, scopeHints, tx)`、固定 `mapAuditEvent(action, result)` | 增加固定成功动作 `governance.drift.threshold_crossed → config.drift`，让审计、事件、outbox 同事务写入 |
| `modules/events/events.service.ts` / `EventsService` | `catalog` 当前明确将 `config.drift` 标为 `not_implemented` | M10 真实事件落地并验证后再改为 supported，不提前在 UI 宣称支持 |
| `modules/event-core` / `modules/event-delivery` | 已有 fanout、站内通知、渠道订阅、投递尝试与重试 | 复用，不在治理模块另写 Webhook/邮件/Slack/飞书发送器 |

现有 `EventRepositoryService.enqueueObservation` 专用于证书/Upstream 的不可变观察来源，`DetectorKey/DetectorSubject` 与 SQL010 的完整性证明限制明确。**不要硬塞 drift 到证书观察 DTO。** 最小可靠实现是通过固定审计动作产生 `config.drift`，保持 sourceKind 为已有 audit，并让详情页再次核验双环境权限。

## 3. 必须单独设计的只读治理 Inventory

### 3.1 不能直接把 M8 快照当巡检数据源

M8 `ConfigurationCaptureService` 的职责是完整可恢复图：

- 它对 private key、秘密 Plugin 配置及凭证调用 `freezeRecovery`，从而要求 secrets.read；普通治理只读用户不应该因此获得这些秘密。
- `closeReferences` 会读取真实 FK 引用，缺失引用、父关系无效或 schema 不一致会拒绝捕获；这是正确的回滚保护，却会阻止巡检产出孤儿/坏引用报告。
- 它的 complete 图只有在 EOF、依赖闭包、scope/epoch/schema 检查全部通过后成立；不得把不完整巡检结果包装成同样的 CaptureGraph。

新增 **GovernanceInventoryService + GovernanceAuthorityService**，产出独立只读 inventory。修复和 Promote 的可恢复写计划仍回到 M8 捕获/执行链。

### 3.2 数据获取与作用域规则

完整 cluster 巡检要求 `governance.read` 与八类 native 实体的 whole-cluster read；完整 workspace 巡检要求对应 whole-workspace read。Service 级巡检要求所选 Service/Routes/Plugins 与真实引用的权限。

tag_group/entity 角色可以通过 `EntityService.list` 仿照已授权服务端过滤获得**授权对象投影巡检**。它只统计实际可见对象，报告包含 `projection: true`，不称全工作区统计，不计算覆盖全部资源的健康百分比。正向字段问题（如已见 Route 非 HTTPS、缺 owner）可确认；负向存在性问题（无引用/孤儿/名称冲突）只有被引用集合完整或授权的定向 GET 证明后才能确认，否则 `not_evaluated`。未授权引用的 403/过滤后的缺行绝不是不存在证明。

固定遍历八类实体的 `size/offset/next` 游标；Targets 只在已授权 Upstream 下分页读取当前有效集合，必要时有界读取 `/targets/all` 并明确历史性质。规则可以通过 typed 元数据检查 Consumer 的存在性，但默认 inventory **不读取凭证集合**。证书内容仅在服务器 RAM 内解析到期/指纹后丢弃 key 与完整 PEM，公共 inventory 不存私钥。

workspace 归属由 `WorkspaceResolverService` 使用**物理标签**判断；调用 EntityService 的显示结果时其标签已经解码，应重新使用已有 encodeTag 规范化，不能直接拿解码标签调用 classify。Targets 继承真实父 Upstream 的工作区，不相信 child tag。无法分类对象只在拥有 whole-cluster 权限的报告中形成范围异常；普通 workspace 报告不展示其他/未知工作区内容。

每个 run 统一硬预算：最多 100 native 页、10,000 条记录、32 MiB 响应、500 次调用、120 秒；不独立给每类对象无限预算。EOF、循环 cursor、native call/byte/record meter、enabled/schema/version、observedFrom/Until、permission/credential/cluster/workspace epoch 均记录。预算耗尽或范围变化 → incomplete/changed，不发布完整覆盖，也不生成破坏性修复许可。

### 3.3 私有只读授权

新增运行时 WeakMap 句柄，入口固定为：

- HTTP：从真实当前 actor/SID、所选 CID/WID/Service IDs 与 live grants mint；不从 DTO 的 owner/superAdmin/transportScope mint。
- Timer：仅当没有 HTTP/operation frame 时，从真实 active schedule、不可变 version/hash、owner 用户当前 DB 身份及 grant mint；不生成 JWT、会话或伪造 super-admin。
- 固定用途只允许 GET 八类实体、Targets、必要 schema、`GET /` 与 `/plugins/enabled`；路径由服务器生成，不能读 cache、metrics、任意 URL，更不能 POST/PATCH/DELETE。
- Context/NativePolicy 每次发包前验证该真实句柄及 owner、权限/credential epoch、schedule state/version/hash、registry physical transport/endpoint、lease。只读 capability 的持有者不能转成 Mutation/approved native 写许可。
- 授权、采集、投影与报告封存前再次校验同一 permissionVersion；新 SID 不能续签旧执行。

可参考 `KongExecutionContextService.runConfigurationJob` 的 installer/WeakMap 和 `ConfigurationAccessService.acquireDueSchedule`；不要使用 `runSystemRead('indexer')` 绕过用户许可。普通 `runInternalRead('inventory')` 是私有原始读，必须在服务器完整 scope/native 权限与逐对象过滤围栏内调用，不能直接把它的 raw 数组给 HTTP。

## 4. 巡检与 Lint 引擎

### 4.1 巡检规则与精确判断

| 检查 | 确认依据 | 修复策略 |
| --- | --- | --- |
| Plugin 的 Service/Route/Consumer 引用不存在 | 完整对应 inventory 或授权的真实 GET404，并区分投影缺口 | 预览解除指定绑定或归档；保持已知 graph/recovery 限制，不盲删 |
| SNI 引用无证书 | 完整证书 inventory 或真实授权 GET404 | 明确选择证书后生成 PATCH diff；不填写随机 UUID |
| Service.client_certificate/ca_certificates 无效 | 实际 1.5 schema 提供字段且目标存在性可证明 | 明确替换/清空引用，重新捕获完整写入 baseline |
| 没有 SNI 的证书 | 全范围 SNI 与 Service.client_certificate 引用集合完整 | 未使用才提示可归档；client/mTLS 用途不能误报为待删除孤儿 |
| Service.host 与 Upstream | DNS/IP host 是合法目的地；只有规则明确声明“必须使用 Upstream”时要求名称引用 | 明确选择目标 Upstream 后改 host；不把所有 DNS host 报错 |
| 重名 / Plugin binding tuple / Target 重复 | schema.unique 与真实当前 scope/完整集合，复用 M8 最终唯一性校验 | 不提供自动随机改名；用户明确新名，再生成 diff |
| Route host/path/method 重叠 | 规范化匹配条件，正则/通配符无法证明时标为 potential overlap | 展示候选与字段，用户修订条件后再预览；不声称每种重叠都会 409 |
| 无 owner、无描述 | owner 标签 / 控制台授权 annotation 的字段可读 | 补 owner 需要用户选择/明确标签；description 只写控制台 metadata |
| 命名规范 | 受限命名规则引擎；无可命名字段明确跳过 | 用户给出新名，当前 schema 与唯一性复验 |
| 缺全局安全基线 Plugin | whole-cluster Plugin 完整集合、enabled 清单与当前全局权限 | 选择当前真实自带 Plugin、schema 动态表单；由平台权限创建固定全局绑定 |

Kong 正常 FK/unique 约束会阻止通过合法 Admin API 创建某些孤儿、坏引用或重复名称。对应规则需要录制 1.5 schema/合法响应基础上的**明确标注损坏图 fixture** 测试；不能改 Kong DB 注入坏数据或把 fixture 当真实 native 验收。真实网关验证可合法预置非 HTTPS、缺 owner/描述、Route 重叠、未使用证书与缺基线等。

### 4.2 有限 DSL

规则结构固定 `{code, given, then, severity, description, enabled}`，可选修复只能是服务器固定 registry code。`given` 为 typed 集合 + 有限属性路径/`[*]` + 有限条件筛选；禁止任意 JSONPath 函数、递归下降、网络 `$ref`、脚本模板和 SQL。`then` 只包含 `required/exists/type/enum/min/max/length/equals/includes/tags_contains/https_only/reference_exists/matches` 等明确 typed predicate。

missing、null、false、0 与空集合分别处理；不存在字段按当前 schema `not_supported/not_evaluated`，不能直接报错。嵌套 array/record 可走有界路径，原型保留键、getter、函数值全部拒绝。布尔树最多 128 个节点、深度 16、200 条规则、路径 256 字符、单规则 16 KiB；单 run 统一 operation/time budget。给定集合零对象记录 `evaluatedObjects: 0`，不把零 finding 称为全量通过。

命名 regex 最小方案使用与 M9 同等级的**固定静态 worker 代码 + userData pattern** 隔离执行：模式长度有界、输入长度有界、250 ms、16 MiB worker heap、最多 4 并发，超时/不可支持 → rule_not_evaluated，不回退主线程 `new RegExp(userInput)`。名称规则明确采用 JS 兼容子集，不声称支持 Kong PCRE；DSL 不允许用户 JavaScript。历史候选合同中的 RE2 方案只有真实依赖通过构建和验证后才采用，不写不存在的 RE2 API，也不让未安装依赖隐式失效开放。

固定修复 registry 建议首批支持：`owner_tag_add`、`route_https_only`、`service_timeouts_set`、`entity_rename`、`reference_replace_or_clear`、`unused_certificate_archive`、`baseline_plugin_configure`、`annotation_description_set`。任何不可推断值由用户明确输入；自定义规则不能携带任意 path/method/native body handler。

## 5. 双环境漂移及 Promote

### 5.1 独立逻辑身份正规化

`diffTransferGraphs` 的 `sameScope` 明确比较 `clusterId, workspaceId, transportScope, kind, rootIds`，且 schema validation 等价必须成立。`compareSnapshots` 也拒绝不同真实 scope。**不能修改源快照 scope 或使用 target ID 假装同一 capture 来跨环境 diff。**

新增 pure `governance-normalization.ts / governance-drift.ts / governance-promote.ts`：

- Service/Route/Upstream/SNI 用各自稳定 name；Consumer 用 username，必要时显式 custom_id 规则；Plugin 用 name + 逻辑 Service/Route/Consumer 绑定 tuple。
- Targets 用所属 Upstream 逻辑 key + target address；证书/CA 使用指纹及显式 mapping；凭证比较默认排除，显式包含时只比较安全性质/secret-change 标记，不公共返回 key/HMAC。
- 无名对象、重复逻辑 key、多候选或歧义产生映射 blocker，用户必须明确 typed source→target 映射；不能凭 UUID 相似或数组位置猜测。
- 规范化忽略 native ID、timestamps、capture metadata 与环境工作区保留标签；引用改为逻辑 key，并保留无效/未授权引用质量状态。
- workspace/service 选择分别在两端验证。报告阅读和导出都要求两侧当前权限；IDOR 不能只校验报告 anchor CID。
- 默认 comparison policy 与 Promote policy 均冻结版本和 HMAC；env字段及凭证的勾选明确区分，不通过复用可变全局设置改变已生成报告。

### 5.2 默认排除与目标 overrides

默认不 Promote 凭证、cert/key/CA 材料、secret Plugin 配置、环境连接字段（Service.host/port/client_certificate/ca_certificates、Route.hosts/snis/sources/destinations、Targets 地址、Plugin 后端地址及秘密等）。可用 allowlist 先保留安全通用字段，再按已捕获的 Plugin schema 与固定环境字段规则补足；未知 custom Plugin 配置默认要求明确审查，不能猜测为安全。

对于目标已有对象，被排除字段**保持目标当前值**；不能写 null 或把源值漏进全配置。对于新 Service 等必填字段，被排除项缺失时必须填写目标 override，否则 blocker，不用源地址“补默认”。用户显式包含环境字段或秘密/凭证时，分别需要两侧当前读取/秘密权限、目标 native 写权限与明确二次确认；所有秘密仅服务器加密材料中传递。

目标编译过程：

1. 冻结选择清单、源 inventory/material identity、source epoch、target scope、policy version、explicit overrides 与 input HMAC。
2. 在目标真实 scope 捕获完整 M8 baseline；读取 schema/启用清单并校验与选定字段兼容。
3. 逻辑映射到目标已有 native IDs；缺失 ID 由服务器分配，FK、parent、Plugin 绑定全部映射到目标 ID。源 UUID 不默认为目标 UUID。
4. 仅生成选定对象的 `_format_version: '1.1'` **merge** YAML，携带目标工作区标签；未选目标对象、未选凭证保留。YAML 不经浏览器往返明文。
5. 内部调用 `ConfigurationService.importDocument`；或在该服务新增专用同等围栏的目标 plan bridge，最终执行仍调用实际 M8 plan/apply。
6. 固定目标 `execution_mode`；approval 只能通过原 `configuration_v2` 工单。已生成计划的 mode/transport/权限/源材料或 target baseline 变化阻止执行并要求新 diff，不自动重放旧包。
7. report/promotion rows 仅保存与真实 configuration job/plan 的 immutable link；显示状态从 M8 回执派生，不能独立写 `succeeded`。

Promote 默认不删除目标对象；显式扩展到删除时必须完整 scope、实际受影响图、typed delete confirmation、回收与独立确认，不以“环境同步”暗中清理未选对象。Portal/metrics 受管对象仍服从当前 M8 blockers，不能克隆托管凭证绕过门户状态。

### 5.3 阈值、调度与通知

巡检/漂移 schedule root 使用 active/paused/deleted、revision CAS、不可变 version、owner、nextRunAt。run 用唯一 `(scheduleId, version, scheduledAt)` claim，Redis + DB lease 及 terminal receipt 防重复；worker 默认顺序处理，限制每 tick 的 due 数量，不并行冲击网关。

双环境 schedule 每次运行都检查 owner 两侧当前 grants、cluster/workspace 状态及 physical scope；单侧撤权/停用/重绑 → paused_authority/failed，无修复、无 native 写、无伪造成功。scheduled run 不依赖一个永远在线的浏览器会话，但不能续签旧 HTTP 执行或拥有超出真实 owner 的权限。

阈值只从 complete、固定政策的 diff 计算，partial 不触发“已准确超阈值”的断言。持久 baseline/threshold state 绑定两侧 scope/policy/input manifest，首次超过或发生新的实质差异通知；同一指纹不每 10 秒重复通知。

`config.drift` 事件只包含安全标题/opaque report link，默认不在事件 payload 放另一侧名称、对象 diff 或计数，避免单侧 events.read 用户收到另一环境数据；查看报告仍检查两侧范围。`AuditService.append` + 固定 mapAuditEvent + existing outbox 在同一 SQL transaction 完成，公共报告 secret scan 通过后才允许事件 fanout。

### 5.4 Promote 原点是所有目标执行入口的强制围栏

只在 `Promote controller → preview` 检查 source/target 权限是不完整设计。用户可以复制目标 `planId/planHash` 直接调用现有 `configuration/plans/:planId/apply`，随后从配置工单、decK 或已复制 apply job 发包。**任何源于 Promote 的 target plan/job 都必须在持久来源、完整材料及 native 内核三个层面保留同一原点；不允许通过普通 M8 入口丢失来源。**

新增固定、服务器拥有的 `governance-promote` origin 类型和不可变 binding，候选 `configuration_plan_origin_bindings` 由 Root 与 SQL owner 在阶段开始时冻结。其准确身份至少包括：

- target CID/WID/physical transport、source import job、plan ID/revision/hash 与 actor；复制后的 apply job/plan/execution 仍引用同一 origin identity。
- source CID/WID/physical transport/endpoint fingerprint、scope kind/root IDs、source inventory/material ID/version/manifest HMAC、实际 selected object/parent/closure 清单及当前字段 fingerprint。
- comparison/promotion ID、mapping/exclusion/explicit secret/env inclusion/override 的 immutable policy version/HMAC、origin material HMAC；不公开 secret 指纹。
- origin-required marker 和 provenance 纳入**不可变 ConfigPlan HMAC 与 target job 的 frozen typed origin**。存在 required marker 却缺 binding、跨 tenant/plan revision/hash、指向别的 material 或重复 binding 都拒绝；不能把“查不到 origin 行”默认为 generic M8 plan。

生成桥接入口只能接收真实运行时 opaque handle 或 Root 从实际封存 promotion 行获得的固定 typed locator。句柄由唯一 provider 的 WeakMap 持有，并且重新核验数据库完整 tuple；TS cast、复制 JSON、DTO `approved/sourceProof/originKind`、客户端提供 callback 都不能 mint。公共 import/apply DTO 不接受这些字段；普通导入不会因 YAML 内容相似自动成为 Promote，但**复用原 Promote plan** 必须始终保留 origin。

Root 独占以下落点；治理 UI/编译器不得自行补替代检查：

| 现有落点 | 必須增加的固定校验 |
| --- | --- |
| `ConfigurationService` 的新增服务器 plan bridge | 在 target import job/plan 生成事务中固定 origin-required marker、source材料和binding，第一次封存即完整；不能先返回可用计划再异步补origin |
| `ConfigurationRepositoryService.freezePlan` / target apply 复制计划 | 在同事务传播 required origin，完整 FK/HMAC 与 source material证明；复制新planId不能洗成普通import |
| `ConfigurationService.plan` / `ConfigurationAccessService.assertStorage` | 读取或解密origin plan/diff时按实际plan tuple查origin并检查两侧当前权限；不只检查一个没有jobId的compare handle |
| `ConfigurationService.apply`（普通配置HTTP入口也一样） | 在新apply job、mode判定、claim前检查source live permission/selected配置、target grants与before；不能只有Promote自己的API调用此校验 |
| `ConfigurationService.authorizeWrapper` / `ApprovedWorkflowExecutionService.assertSubject` | 工单read/approve/execute统一读取实际configuration job/plan的origin。审批人必须能读取两侧所需范围、目标批准范围；提交人两侧当前权限也必须仍有效 |
| `ConfigurationService.prepareWrapper/executeJob/startDeckExecution` | claim、exec快照和进入第一步前重核source/target、policy材料、mode；变更源或target之前不存在任何写包 |
| `ConfigurationAccessService.assertCurrent/verifyHandle/runStep` | 真实job/plan scope绑定origin，不因入口是generic M8、direct或工单而跳过；由固定origin verifier检查live identity/grants/registry/policy/lease |
| `KongExecutionContextService` / NativePolicy 的 native **before-send** | 在每一个具体 target packet 发包前重新核source authority与已选配置/闭包；后续撤权或观察到源漂移停止余下native包；metadata handle不能变写许可 |
| `ConfigurationService.deckExecutionHandle/executeDeckPacket` 与BFF decK authority | 同样检查origin，或M10首版明确拒绝origin Promote使用deck driver；不可因driver切换绕过source fence |
| safe `receipt/by-key` 与失败ledger | 仍允许真实原提交人核验自己的安全已发送事实，但不借source拒绝隐藏native成功/unknown；不返回当前已无source权限的源diff/secret |

origin verifier 由单一 `ConfigurationOriginPolicy`（候选名称）注册到 ConfigurationAccess/Service；方法固定为 `assertPlanOrigin / propagateOrigin / verifyCurrent` 等，参数来自真实持久 tuple/私有 handle，不能从 HTTP 获取“已验证proof”。Policy不直接发native写；网络读与SQL事务边界分别处理：

1. 先在**独立受限 source readonly authority**中进行源GET与selected graph/children membership检验。退出target ALS frame仅允许持久origin+private source handle恢复真实actor/SID；不能开放任意跨cluster `runActor` 或继承target native Mutation。
2. 源读取和正常target SQL锁事务分开，避免持有IAM/job行锁等待网络或recursive verifier造成pool耗尽；返回短时private read receipt，并以物理scope、credential/permission/registry/policy epoch与exact material HMAC绑定。
3. 最终target ticket发包前再验证receipt/live权限与两侧epoch及确定的已选source字段/闭包。持续验证共享source/target范围的Console锁使用确定顺序，避免双向Promote死锁；origin source读取共用严格预算，不能每步重新给无限100页额度。
4. 新source child/Plugin、删除依赖、普通字段改变、受管边界或策略版本改变均为source drift，阻止复用旧计划。超预算、权限变更、source无法读取不是“源未变”的证明；宁可拒绝、缩小选择后生成新diff。

跨Kong没有分布式原子事务。Console路径的源变更由锁/epoch挡住，发包前实际GET观察到的源漂移阻止下一目标包；拥有外部Admin特权的人仍可能在最后source GET和target发送之间修改配置，这属于与既有capture相同的 `console_fenced_best_effort` 边界，不能在报告里声称零竞态。记录观察窗口、准确source proof与已发步骤；partial保留、不自动补偿或重放。

## 6. 模块、文件与 DI 边界

新增 `modules/governance`：

```text
governance.module.ts
governance.controller.ts
governance.service.ts                 # scope/actor、分析、报告、修复/Promote 编排
governance-authority.service.ts       # 唯一 HTTP/timer 只读 capability 所有者
governance-inventory.service.ts       # 固定 GET 白名单、有界采集与脱敏
governance-repository.service.ts      # SQL-only、typed identity、CAS/不可变事实
governance-metadata.service.ts        # 固定规则/政策/调度 metadata handlers
governance-scheduler.service.ts       # bounded due worker、lease、owner fresh grants
governance-input.ts                   # 严格 DTO、预算、游标、确认
governance.types.ts
governance-lint.ts                    # pure 受限 DSL
governance-inspection.ts              # pure 结构/治理检查
governance-regex.ts                   # 静态 worker、时间/内存/并发预算
governance-normalization.ts           # pure 逻辑身份、field policy、映射
governance-drift.ts                   # pure 双环境差异
governance-promote.ts                 # pure 目标 merge 文档编译
governance-fixes.ts                   # pure 固定修复 registry
```

`GovernanceModule` imports `ConfigurationModule, EntitiesModule, WorkflowsModule, EventCoreModule`。Infrastructure 的 DB/Redis/Secrets/Authz/Kong/WorkspaceResolver/Audit 是当前全局 provider；避免 GovernanceRepository 引入网络或 WorkflowService 循环。若只读 capability 的 installer 需要全局 Root provider，由基础模块提供唯一 authority bridge，再 exports 给 GovernanceModule；不让 generic callback 获得 native permit。

### 6.1 实施归属与冻结顺序

所有业务编码以M9最终审计/秘密扫描和阶段release gate通过为前提。当前仅分配下一阶段边界，不提前写src/SQL、部署或开启M10能力。

| 归属 | 独立文件边界 | 与Root冻结的接口 / 不可改动范围 |
| --- | --- | --- |
| **Root：安全与持久原点集成** | `ConfigurationService/Access/Repository`、Kernel/NativePolicy、ApprovedWorkflow、SQL017+及runtime provisioning、GovernanceService集成 | 独占5.4全部origin传播/拒绝路径、metadata kinds/SQL编号和DI installer；其他agent不能修改这些共享文件或声称source预览已经充分授权 |
| **A：Readonly Authority / Inventory** | 新governance authority/inventory/input/types及专项unit/security tests | 冻结HTTP/timer private handle、fixedGET列表、aggregate meters/EOF/projection/fresh epochs与source-only隔离read接口；不写native、Workflow、Configuration核心 |
| **B：Typed DSL / Inspection / Fix compiler** | pure lint/inspection/regex/fixes与fixture tests | 入参为真实authorized safe inventory+规则不可变版本，输出safe finding/coverage/fixedchange建议；不给controller操作许可，不访问Kong/DB，不接受任意handler |
| **C：Logical Drift / Promote compiler** | pure normalization/drift/promote、typed mapping/env policy与fixture tests | 源/目标逻辑身份、目标ID分配需Root冻结；输出目标merge文档与required mappings/blockers，**不输出authorization proof**，不写target计划或自己调用apply |
| **D：Governance前端** | 新GovernancePage、API/types、安全forms与真实browser runner | Root冻结endpoint/receipt/分页/能力contract后再写；只展示真实quality/diff与typed确认，不接受sourceProof/任意URL/hiddenapproved，不改既有M9工作流 |
| **Root或后置E：Repository / metadata / scheduling / events** | 新governance SQL-onlyrepo/metadata/scheduler与fixedevent action | 等Root schema/authority/workflow contract冻结，先readonly report，再shared配置审批与due；不扩展M7 observation原生证书source，不自动修复 |

先由Root+A冻结readonly capability、材料类型和scope/预算，再由B/C并行实现pure逻辑；Root冻结持久origin及metadata接口后D/E并行实现。两本manual、README、progress/evidence由Root统一收尾，避免多个agent改相同资产。保留一槽处理review/真实联调而不是同时争用SQL/共用docker。

### 6.2 两个真实Kong的分阶段验证所有权

Root创建并持有release lab部署门控、网络/端口/独立卷与私有journal；在M9gate通过后仅追加**第二套Kong1.5.1+独立Kong PostgreSQL**，Admin无公网publish，BFF仍不在任何KongDB网络。不能把同一物理Admin的两个cluster别名当双环境证据，也不改当前原服务。

第一步验证两侧probe/version/transport/readonlyinventory，第二步创建不同UUID但同逻辑配置并做纯drift，第三步加入target-only凭证与environment配置验证默认排除，第四步target direct/approval各执行真实Promote/fix/rollback与5.4攻击矩阵。Native调用由Root统一运行journal runner；agents可提供只读断言、fixture和审查结果，不并发独立向同测试对象写入。

规则/政策/共享调度等配置写操作按 cluster mode 使用 direct IAM durable transaction 或固定 `governance-metadata` workflow family；仿照 `EventsMetadataService / EventsCompilerService`，固定 table/resource/operation 映射、服务器 plan、before revision/HMAC、零 nativeRequests、exact source receipt。同一工作流引擎只扩展受限业务 kind，不能借规则内容成为 native capability。规则归档/恢复软删除，版本保留；永久材料清除如实现仍需独立确认。

前端新增 `GovernancePage`，主 tabs 为「巡检报告 / Lint 规则 / 配置漂移 / 环境发布 / 调度」。列表与 finding 分页、对象详情链接、两侧选择、diff 预览、配置 job/工单/回滚链接、原键 recovery 使用已有交互模型。不给 UI 原始私有材料、script editor 执行能力或任意 URL proxy。沿用现有商用蓝白/低饱和主题、暗色与移动菜单，不加入非必要解释文案；只有质量缺口/危险确认才展示必须的信息。

## 7. SQL 设计与不可变事实

实际编号由 Root 从 017 以后分配，迁移只在 M9 验收之后编写。下列为表候选，不表示当前存在。

| 表 | 关键事实与约束 |
| --- | --- |
| `governance_rule_sets` / `governance_rule_set_versions` / `governance_rules` | root: CID/WID、code、owner、currentVersion、revision、state；版本与规则 append-only，engineVersion/DSL/rulesHmac/sourceActor 固定，完整复合 FK，不跨版引用 |
| `governance_policies` / `governance_policy_versions` | inspection baseline、env exclusion、命名及阈值政策；参数是受限 JSON，版本不可变；按集群启用与工作区适用范围明确 |
| `governance_runs` / `governance_inventory_materials` | origin HTTP/schedule、actor/SID 或实际 scheduleRun、scope/transport、permission/credential/registry epoch、sourceHmac、quality、budget、lease；诊断库存与可恢复 M8 snapshot 分开类型，不伪造 snapshot FK |
| `governance_report_versions` / `governance_findings` | immutable report manifest/rules/policy/engine/coverage/count；finding typed entity/native/parent/objectWS/physicalTags、ruleCode/severity/path/safeEvidence；deferred count/seal guard，封存后不得插入更多 finding 改变报告 |
| `governance_fix_links` | report/finding 与真实 target `configuration_job_id/plan_id/plan_revision/plan_hash` 或 annotation metadata receipt 的完整 immutable FK；resolved 只能从新观察派生 |
| `governance_comparisons` / `governance_comparison_versions` | 完整 source/target CID/WID/transport、scope/root、各 inventory/material、policy version、inputHmac、quality；读取两侧 fresh 权限，不能只凭 anchor FK |
| `governance_promotions` | source comparison/version、显式选择/mapping/override HMAC、target actual configuration job/plan identity、actor；无第二套 native terminal truth |
| `governance_schedules` / `governance_schedule_versions` / `governance_schedule_runs` | root CAS/soft archive；版本 owner、两侧scope、rules/policy、interval/timezone、阈值；run 唯一 occurrence、lease generation、真实 readonly authority 与 terminal receipt |
| `governance_drift_states` | 固定双 scope/policy、lastManifest/diffHmac、lastReport/threshold state、revision；不能未经 actual complete report 更新 baseline |
| `governance_metadata_operations`（如不能直接复用 IAM） | 原 actor/CID/WID/key/inputHmac 的 durable receipt；workflow 与 source metadata 保持 reciprocal immutable link |

immutable fact 表 runtime role 仅 SELECT/INSERT，并以 update/delete/truncate trigger 和 runtime grants 双重保护；可变 root 只允许固定身份不变和 CAS state/revision。更新 runtime provisioning 的 append-only allowlist 时增加 storage verification。所有 secret/raw material 使用真实 SecretService/SnapshotCrypto 的加密与 typed AAD，只存必要材料；公共 projections 不含密文、private key、API Key、secret 值或可离线猜测的 secret HMAC。

## 8. 分步实施与真实验证矩阵

### 8.1 实施顺序

1. M9 实际阶段验收完成后冻结接口/SQL 编号、已有 schema 校验和、NativePolicy/权限边界；在隔离 release lab 增加第二个真实 Kong 1.5.1 环境，保留原运行服务。
2. Governance SQL + readonly authority/inventory + pure inspection/Lint；先完成只读与存储安全测试，启动验证与手动真实巡检。
3. rules/policy metadata 模式、定时巡检、只读 reports/finding UI；验证 read-only、tag/entity 投影、CAS/软归档/审批与撤权。
4. 双环境 canonical drift + 周期阈值/真实通知，验证 IDs 不同而配置等价、实际差异与两侧权限。
5. 固定修复 compiler + Promote target compiler，复用 M8 diff/apply/approval/recycle/rollback；补当前 before 变化与 unknown recovery。
6. browser、审计/秘密扫描、完整 M0–M10 回归、详细手册增补和 M10 证据落盘；阶段通过后再进入 M11。

### 8.2 两个真实集群最小矩阵（预期，尚未执行）

测试集群 A/B 均为独立 Kong OSS 1.5.1 + 独立 Kong PostgreSQL，仅控制台 BFF 可达其 Admin 网络。控制台不能连接任一 Kong DB。操作使用显式 own-test fixture 前缀，原 credential/request/cookie 只保留 RAM 私有 journal，公开 evidence 仅方法/路径/actor/原键/ID/状态/HMAC 安全摘要，不记录凭证正文。

| 编号 | 实际测试 | 必须给出的证据 |
| --- | --- | --- |
| G01 | 两集群探测正确、八类 inventory 真实 size/offset 多页、默认/指定工作区归属 | 起停健康、真实1.5 version、完整 native GET 请求摘要/EOF/aggregate meters；无 forbidden endpoints |
| G02 | A 工作区预置 HTTP Route、缺 owner/description Service、潜在重复 Route、未使用证书及正常 mTLS client certificate | 报告只检出应有问题，证书 client 用途不误判；pointer/Object ID 与 Admin 实际数据一致 |
| G03 | Lint 自定义嵌套 array/record、required/default/false/0/null 与当前1.5 unsupported字段 | typed engine 单测 + 真实合法配置 finding/skip；非法 DSL、prototype、函数、超深输入被拒绝 |
| G04 | 凭证/API Key/private key 插入测试对象，普通治理 read-only 巡检 | native read key 不公开、无 credentials 集合读、report/audit/log/browser 全部 secret scan 零明文 |
| G05 | tag_group/entity 用户只可见自身对象、foreign scope reporter IDOR | 授权 projection 标记、无外部对象统计/名称、foreign report/details/fix 403/404；不能报告未授权 FK 不存在 |
| G06 | 100 页/500 calls/120 s/byte quota、cursor loop、scope/权限 epoch 中途变化 | incomplete/changed、零 native 写、无完整覆盖 claim，主线程不被命名 regex 阻塞 |
| G07 | 规则/政策 CAS 更新、软归档/恢复、approval metadata 模式 | 原key回执、并发冲突、无实际批准不得改配置；immutable rows runtime UPDATE/DELETE/TRUNCATE 失败 |
| G08 | 定时巡检实际 due tick，owner 撤权/停用、policy改版、transport重绑 | 真实 scheduleRun/readonly句柄/actual GET；一次 occurrence；撤权后零发送且保留失败/暂停原因 |
| D01 | A/B 同名等价 Service/Route/Plugin 但 native UUID 全部不同 | canonical drift 为零；不修改历史 capture scope/ID；source/target权限与实际graph计数 |
| D02 | A/B 各合法配置真实超时/协议/Plugin config 差异 | diff 对应字段与 Admin 原始查询一致；timestamps/WS标签/UUID 不形成伪漂移 |
| D03 | 无名/同名歧义、来源引用缺权限、低覆盖 inventory | mapping blocker 或 partial；未授权信息不泄露；不据 partial 触发完整阈值结论 |
| D04 | 定时双环境 drift 达阈值，再跑同diff，随后实际新diff | M7 event/outbox/站内/own Webhook receiver 实际投递；same fingerprint 不重复、fresh差异有新记录 |
| D05 | 用户只有A或只有B报告权限 / 通知订阅权限 | 两侧报告拒绝；通知只含安全标题opaque链接、不泄露另一侧名称与diff |
| P01 | A→B Promote，B 已有 Service、自己的 host/port、Consumers 与原 API Key | 默认目标 host/port/证书引用及凭证不变，业务通用字段改变，原 B Key 仍可真实代理认证 |
| P02 | 创建新 Service 默认未给 host override | 明确 blocker，B 零写；填合法 B override 后 target schema/diff 正确 |
| P03 | Service级 Promote 含依赖/Upstream/Routes/Plugins、两端 UUID不同 | FK/parent/binding 均为 B ID，未选对象未变，source A配置未改 |
| P04 | 明确包含 environment 与 credential 开关，缺 secrets权限，basic恢复受限 | 开关默认 false；无权限403、不可恢复material blocker；合法显式 Key传输实际可用，公共证据无Key正文 |
| P05 | B设approval模式，提交Promote/fix、自己审批、执行前target变化 | 未审批零写、自审403、旧before变化409、合法独立审批才执行，原workflow/configuration reciprocal links完整 |
| P06 | fixed修复 RouteHTTPS/owner/timeouts、证书归档、修复后再巡检 | typed确认、M8 plan/actual native steps、证书完整回收、问题仅在真实新report中消失 |
| P07 | 原执行响应丢失/已知native成功后metadata故障、再查原key | unknown停发后续、原回执只读核验，无自动POST/PATCH重放、事实不从GET猜成成功 |
| P08 | Promote/fix后从M8执行前快照回滚 | 实体与FK回读、凭证真实认证；restore限制如Targets历史、OAuth客户端/令牌区别真实说明 |
| P09 | 只在preview有source权限，封存后撤销source grant，再直接调用**普通M8 plan/apply endpoint** | 拒绝且target零native写；原target plan的requiredorigin/link仍存在，safe原回执可读 |
| P10 | 同一Promote plan走target approval；提交后撤销source requester或approver权限 | approve/execute均走同一origin验证，不因M8wrapper绕过；未授权批准或原permission epoch变化零target包 |
| P11 | source真实Service字段、Route/Plugin或依赖/child集合在preview后改变 | 即使targetbefore未变也拒绝旧计划，显示source drift；不能只比Console DB epoch掩盖Admin实际变化 |
| P12 | 复制Promote计划到新apply job/plan，再改driver或使用deck/BFF直接入口 | 新plan完整传播origin；deck或明确拒绝或同等围栏；runtime写请求无绑定不能发包 |
| P13 | DTO伪造approved/sourceProof/origin，复制/序列化WeakMap handle、错CID/WID/material/planHash | 参数拒绝/句柄拒绝，无read/write authority；origin required而binding缺失/错误storage测试失败关闭 |
| P14 | target步骤1真实成功后，步骤2发送前撤source权限或更改source所选对象 | step1 immutable成功保留，step2及后续零发送，父作业partial/failed/uncertain如实，不重放第一步或伪整批成功 |
| P15 | source/target互换Promote并发、重绑sourcephysical端点、source权限/配置检查超预算 | 固定锁顺序无deadlock；scope changed/limit拒绝，source凭证不泄露，不跳过检查发target包 |
| P16 | 已知targetnative成功后source失权、metadata故障或响应丢失 | 原key只能读安全已发送事实，source拒绝不能抹去成功/未知；无source diff/secret输出、无自动retry |
| W01 | 新治理tabs、两环境选择、报告finding分页、diff确认、job/workflow/rollback导航 | 真实BFF浏览器检查与截图；无直连8001、无pageerrors、暗色与手机无横向溢出 |
| A01 | 元数据更新、巡检/漂移封存、阈值事件、fix/promote写与失败 | 原actor/IP/CID/WID/原键/diff/结果准确；关键写审计匹配，append-only/HMAC chain与secret scan |

单元及录制 mock 测试额外覆盖原生 API 不能合法预置的孤儿 Plugin、无证书 SNI、无效 CA、重复 unique 值、refs cycle/shape invalid；这些证据标题明确 fixture，不能替代 G02/P 系列真实验证。

## 9. 阶段验收材料与开放项

实施后新增 `artifacts/M10/`：source/storage/security/native-dual-cluster/browser/audit-secret-scan/request-manifest/attempt-history/progress 等结果，失败尝试保留；构建及实际部署 SHA、SQL 校验和、runtime nonowner role、端点拒绝日志一并记录。手册补充巡检质量、DSL例子、调度、阈值、目标覆盖项、审批/原键核验/回滚与软隔离局限。

以下必须在实施时以真实接口/证据最终冻结：只读 GovernanceReadPolicy 与 Root installer 的 exact类型；metadata workflow subject/check trigger 与 SQL编号；第5.4节的持久source原点传播/每packet围栏（这是强制准入项，不是可略过的后续增强）；native损坏图无法恢复时的修复 blocker；privateinventory retention与生产容量预算；外部邮件/Slack/飞书真实联调。未配置外部渠道时只标“未验证”，不把 own测试receiver通过称为全部外部商用联调通过。

**M10 尚未实施。本文只定义可实施方案与验收目标，M9 当前状态及真实通过证据仍以 M9 落盘记录为准。**
