# M7 共享事件管理实施清单

状态：仅设计与接口冻结。M6 产品源码已冻结，实际验收、提交和 Root 明确 M7 release 之前，不创建产品文件、SQL010、Worker，不 build、部署或实际投递。

依据：[实施合同](m7-implementation-contract.md)、[Event Core 接口](m7-event-core-interface.md)、[投递合同](m7-delivery-contract.md)。本清单针对 Kong/Workflow owner 的共享事件渠道、订阅、测试与重放；审计查询、个人通知、fanout、传输及部署继续由各自 owner 实现。

## 1. 文件、依赖与启动顺序

| 未来文件/现有扩展点 | 责任 |
| --- | --- |
| `modules/events/events.types.ts` | 严格 request/safe DTO、固定 handlers/subjects、provider 类型与预算 |
| `events-input.ts` | 独立 EVENT 错误码、未知字段/原型字段拒绝、revision/确认/UUID/逻辑标签校验、签名 keyset 游标 |
| `events-metadata.service.ts` | 渠道/订阅 CAS、同事务版本记录、safe projection、固定 handler、真实成功审计与 DB-only enqueue |
| `events-compiler.service.ts` | direct IAM 与 approval immutable plan 分流；原 key 优先、完整 operation identity/HMAC、hidden reservation 原子持久化 |
| `events.service.ts`、`events.controller.ts` | catalog、共享目录、详情、CRUD/状态/回收、test/replay、专用回执投影 |
| `events.module.ts` | imports Workflows/Iam/EventCore/EventDelivery；固定 handlers bootstrap 注册 |
| `workflows/workflow.types.ts`、`workflow-validation.ts`、`workflow-registry.service.ts` | 只增量加入 event-metadata kind、明确 subject/handler；旧 Portal V1 保持 |
| `workflows/approved-workflow-execution.service.ts` | owner 增量实现事件 subject/metadata 验证，Reviewer 独立审阅；不扩展 Portal native claim 白名单 |
| `workflows/workflow.service.ts` | 仅 event-metadata 的 server business-audit receipt 核验与内部字段剥离；Portal branch 不变 |
| `workflows/workflow-plans.service.ts` | 事件专用安全 diff 投影；不公开 URL/token 路径、收件人、认证或密文 |
| `iam/iam-mutations.service.ts` | Root 接受的兼容 callback `fn(tx, operationId)`；原单参数 caller 行为保持 |

Root 安装 AppModule/Swagger 与全局 Audit/Authz/EventAccess provider；不在 EventsModule 重建全局服务。Workflows 不反向 import Events；Core 不注入 Audit/Engine/管理服务；DeliveryPolicy 不注入 Events。所有调用采用实际必需 provider，缺依赖 fail closed。

先由 Storage/DevOps 发布实际 types 与 exports，再落管理 types/compiler/handler，最后 Root 注册模块。文档候选类型不当作已存在源文件导入，不写猜测 SQL 列或兼容别名。

## 2. 固定事件工作流

kind 为 `event-metadata`，subjects 为 `notification_channels`、`event_subscriptions`、`event_deliveries`。handlers 为：

`event.channel.save/status/delete/restore/test`、`event.subscription.save/delete/restore`、`event.delivery.replay`。

handler 与 subject、permissionAction 固定映射；delete 为 `delete`，其他为 `write`。初版每个共享配置操作一个 metadata step，`nativeRequests=[]`、无原生 mutation 字段、generated 或 prerequisite。审批计划 `approvalRequired=true`；direct 服务直接使用普通 `events` IAM 操作，不生成 false-approved 计划，不进入 Engine 中现有硬编码 Portal direct metadata 路径。

metadata before 为同 CID/WID 锁定的原始 root 行，revision、before HMAC、完整 payload HMAC 绑定 sealed step。审批者当前完整工作区 `workflows.approve`；执行者当前完整工作区 `workflows.write` 与 step 的 `events.write/delete` 分别成立。提交、审批与读取自身原提交回执均不能授予执行权。事件 kind 永不进入既有 Portal native claim 的四种 kind 白名单。

审批 create 的 reservation 仅保存固定身份与不活动状态，与定义、计划、版本、步骤和提交审计同一事务；请求目标与认证材料仅进入加密计划，未批准不能变 active 或发包。Storage 需明确 pending credential_generation 的初值及 pending→active 首次版本约束，业务不自造 generation。

## 3. 请求身份与原 key

在任何当前 revision CAS、目标分配或 DNS await 之前，查原 actor/CID/WID/key 的真实 handler 命名空间，并比较 `{handler, createOrUpdate, targetIdOrCollection, originalRequestHmac}`。相同 key 跨 method/target/body/作用域均 409；旧成功返回同一 actual entity/queued ID，失败/未决只返回旧回执，不换 key 或自动执行。

direct 创建在 IAM callback 事务内写最终对象、版本与审计，不先提交无回执占位；approval reservation 与 immutable plan 同事务。共享目录用 `(created_at,id)` keyset，不用全表拉取或 OFFSET 计数；size 默认20、最大100，游标绑定 actor、permissionVersion、CID/WID、完整过滤、size 和绝对 expiry。

`GET /clusters/:cid/events/operations/by-key/:key?workspaceId` 读取实际 IAM/workflow 证据，不按当前 mode 猜 domain。原提交者当前完整 events.write 可获取 submission-only proof，不需要 workflows.read/write；投影不含 sealed plan、目标秘密或其他人的操作。IAM action delete 的原回执继续按实际原 action 校验，不能由 events.write 代替 delete。其他审批/执行动作沿用真实工作流专用回执域。

## 4. 真实审计 receipt 与队列原子性

Root 已选择 handler 在 DB 配置 CAS 后自行 append 实际 safe before/after 的成功审计，再 enqueue；三者在同一 metadata transaction。审批 handler 使用真实 execution/step tuple；direct callback 接收服务器分配的真实 IAM operationId。

Engine 分支只由已封存的 `event-metadata` kind、固定 handler/subject 和 zeroNative 条件选择，不由返回值是否具有某个 property 选择。事件 handler 的内部返回类型为 `{result,auditReceipt}`，Engine 读取同一 tx 的实际 audit row，核验全部 id/chainScope/sequence/eventHash/occurredAt、actorType=user、真实actor、CID/WID、typed subject ID、固定 action、success 和 `workflow_id=plan.workflowId`。固定服务器 operation envelope 绑定 executionId、stepId、planRevision、planHash、当前 inspection before HMAC 与 sealed payload HMAC，防止重用同 actor/subject 的旧审计。before/after 必须是当前已核验 before 与实际保存的安全行/入队事实，不能只使用预期输入。receipt 缺失、字段错误或行不存在均回滚，不把客户端 property、时间接近或公开 hash 当证明。

Engine 校验后只保存/返回内部 result，剥离 auditReceipt，不向只有 events 权限的用户公开 cluster chain 序号或 hash。跳过重复的 generic step business Audit.append，保留父 workflow terminal audit。handler 配置/版本/审计/队列与 step/execution/workflow 成功 CAS 同事务；末端 lease、permissionVersion 或任一 CAS 失败整体回滚。Deferred queue terminal proof 在提交时核验实际完整 tuple 的真实成功，未知提交保留原 key 回执。Portal 返回 Record 的既有路径与 generic audit 原样保持。

Storage canonical 接口为：

```ts
EventRepositoryService.enqueueTest({
  auditReceipt, clusterId, workspaceId, channelId,
  channelRevision, credentialGeneration, actorId,
  // Exactly one server-derived source:
  iamOperationId?, workflow?: {id, executionId, planRevision, planHash, stepId}
}, tx): Promise<{eventId, deliveryId}>;
EventRepositoryService.enqueueReplay({
  auditReceipt, clusterId, workspaceId, deliveryId, expectedRevision,
  actorId, iamOperationId?, workflow?: {id, executionId, planRevision, planHash, stepId}
}, tx): Promise<{eventId, deliveryId, replayGeneration}>;
```

test deliveryKind=test，subscription ID/revision 均 NULL，不能造临时订阅。replay expectedRevision 是 SQL010 真正的 delivery root revision；正在 sending、未决 intent 或未证明的 uncertain 不能借 replay 逃避核验。重放新 generation 保存 parentDeliveryId、原 event 与安全 payload，不改原 attempts。

## 5. 目标与秘密版本

DevOps 接口：`describeProviders()` 返回安全目录；`validateChannelConfig({type,endpoint,auth,options})` 仅固定语法/allowlist/全部 DNS 验证，零 HTTP/AUTH/DATA 发包。返回 plaintext material 只留 RAM，不直接 HTTP 序列化。当前配置校验不替代 Worker 最终 DNS pin、权限、租约与 generation fence。

- webhook auth none/bearer/basic；Slack none，整个 token URL 加密；飞书 none/feishu-signature；email none，SMTP auth/authority 固定 operator 配置。
- email endpoint 为 recipients<=20，收件人同样加密；options 只固定 provider 白名单，无任意 headers、模板或 SMTP 地址。
- public 只有 type/configured/authConfigured/destinationHost/maskedDestination/optionsSafe；email 只 count 和固定脱敏摘要，无地址。mask 不能作为输入或秘密 reveal。
- 目标或认证变更递增 credential_generation；两个密文均按新 generation AAD 重封，不能留下旧 AAD 密文。仅状态更新保留 generation 和原密文。新目标必须显式指定新认证或 none，不移植旧 host 凭证。
- AAD 为 `event-channel:<id>:<cid>:<wid>:<generation>:endpoint|auth`。channel scope/type/name/creator 固定，不以PATCH偷偷 reparent 或改名。
- direct IAM requested 审计会脱敏整个 payload；私有材料明确包装为 `endpointSecret/authSecret` 或 `desiredConfigSecret`，原请求只保存 keyed HMAC。不能把裸 token URL 路径放到普通 endpoint/name/options 字段后依赖 URL 自动脱敏。

生产及本地 HTTP provider 都验证 TLS；测试明确 `https://event-receiver:9087`，独立 CA 和精确 SAN。SMTP `event-mail:2465` 强制 STARTTLS，同 CA 验证，AUTH/DATA 前 fresh fence，无明文降级。此目录不能自动试发或联系外部账户。

## 6. 订阅与权限

catalog 可粗粒度 events.read。共享 channel/subscription list/detail/trash 为当前 whole-workspace events.read；写/delete 分别完整 events.write/delete，不用 entity/tag coarse grant 提升整区目录权限。

条件已与 Storage 冻结为 eventTypes 内 OR、nativeIds 内 OR、tags 全 AND，三类之间 AND，CID/WID 固定。HTTP tags 仅 logical business tags encode 一次，拒绝 reserved workspace 标签；固定 typed nativeType、UUID ids<=256、types<=32、tags<=256。初版 typed UUID 条件不查询当前原生对象存在、不读取配置；只与可信历史 source 的 typed ID 比较。标签条件必须由历史 before 或 after 的一个完整存在侧满足，不合并两侧 tags。条件只缩小匹配集合，不提供新授权；投递仍以历史可信 source scope 和当前完整 grant 验证。

目录、详情、写入和原键回执在 await 后复核当前权限版本和实际 whole scope；数据库/401/5xx 不吞为不可见或成功。历史事件由 Root/EventAccess 处理，不按当前标签重归属；shared metadata 不冒充历史资源。停用/删除渠道不能继续发旧配置；恢复不改历史 delivery，仍需显式受控新投递。

## 7. 必需验证与源冻结

聚焦真实服务测试：wholeWS vs typed/tag grant、跨 actor/CID/WID、async 撤权；atomic reservation/persist 回滚；跨 target/method 同 key；endpoint/auth mask 和 generation 重封；订阅条件不扩大授权；approval kind/handler/native packet 注入拒绝。

actual disposable PostgreSQL：全部实际列/版本 FK、pending reservation 与 immutable plan 原子性、direct IAM 与 approved queue terminal证明、旧 key 不重分配、并发 CAS、错误/未知终态零可见队列、原 Audit receipt/hash 绑定。fake SQL 不能替代列名与FK测试。

Worker 的网络/租约、fanout 后页、站内 owner 与本地实际收件由 Storage/DevOps/Security 独立验证。业务只在源码、独立审阅、实际 PG 与 API typecheck 通过后给 SOURCE_READY；Root 统一 build/deploy，Security 独占实际窗口。测试矩阵明确 fake Gateway/Authz 与真实 DB/代码范围。

## 8. 正式 release 前仍需 owner 冻结

1. Storage 发布 SQL010 实际导出与完整 snake_case 列（cid/wid 只为文档缩写），pending generation/版本初值、replay root revision、canonical enqueueTest(input,tx)/enqueueReplay(input,tx)。
2. DevOps 发布实际 provider types、配置校验/安全 summary、可用状态与 options 白名单；新 receiver 仍加入普通 Service/Target/plugin 的控制面保护集合，不放宽一般出站策略。
3. Root/业务 owner 发布 Audit receipt 返回类型、IAM callback operationId 兼容扩展、事件 Engine内部receipt envelope/校验与剥离；Portal native whitelist保持。
4. Root 确定 deleted/disabled workspace 的 shared config 只读政策。typed-ID 初版不查询原生存在的决策已冻结；未知接口不写 default fallback。

以上风险已向相应 owner 报告；在明确 release 前只修本文和其他合同，不修改 M7 产品或 M6 冻结源。

## 9. 真实证书预警与 Upstream 健康变化生产者（待 Root 审定）

本节补齐 [两批商用验收复核](../../architecture/security/two-batch-production-acceptance-review.md) B1-4 指出的生产者缺口；是读取现有源码后的实施提案，不是探测或运行证据。M6 实际验收和提交前不创建检测器、SQL010 或新的 Context purpose，不调用 Kong、Worker、测试或部署。漂移生产者仍由 M10 的真实比较作业提供，M7 不用合成漂移事件代替。

### 9.1 已存在的接线点和不可复用边界

| 当前源文件/方法 | 已有事实 | M7 必要增量 |
| --- | --- | --- |
| `entities/entity-index.service.ts` 的 `tick/sync/upsert` | 后台 timer 在无 HTTP ALS 下以 `runSystemRead(cid,'indexer')` 读取八类集合。`sync` 每类固定 size100、保留真实 Kong continuation；`upsert` 存储的是 redact 后的 document。现在没有到期或健康事件。 | 在 `sync` 成功收到 certificates/ca_certificates 的原始页后、redact 前提取最小证书观察；不能把 index 搜索结果、旧 document 或人工填写的 expiresAt 当成新观测。继续按页扫描，不能为了事件先拉全量。 |
| `entities/certificates.ts` 的 `inspectCertificate` | Node X509 解析 PEM；现有 EntityService.get 只在详情读取时给出证书摘要，未产生事件。该 helper 可选私钥校验，不是检测器权限入口。 | 只传 public cert，不传 key；有界解析后取有效期与 leaf 指纹。以统一 observedAt 计算精确到期阈值，不用当前 helper 的整天取整结果判断 expired。 |
| `entities/entities.service.ts` 的 `health` | 当前真实 console actor、Upstream/Target 读取规则，GET `/upstreams/:UUID/health`；返回明确 `node_scope=current_admin_node`。NativePolicy 会过滤无权 Target，并给非平台响应加 permission projection 标记。 | HTTP 保留现有当前身份与原生 read 权限。受限/过滤的健康响应不能充当完整后台基线，不能据此宣布所有 Targets 恢复或消失。 |
| `execution-context.service.ts` 的 `runSystemRead/allowRead` | 已有 system purposes 只有 probe/indexer/metrics-scrape/metrics-catalog；任何已有 ALS 都拒绝 runSystemRead。indexer 只允许八类顶层集合，不能读 `/upstreams/:id/health`。 | Root 如采纳后台健康检测，应新增**单独 GET-only 的观测用途**，只允许本节固定集合、精确 Upstream UUID 与 health 路径；不是 event-metadata 的 approved/native claim，不复用 Portal/metrics purpose，也不放宽通用 Admin 白名单。 |

拟议 `modules/events/event-observation.service.ts` 只依赖 Db/Redis/Secret/Kong/Context/Workspace 与 DB-only EventRepository，不注入 Entities、Audit、WorkflowEngine 或通知传输。索引器调用其最小证书观察入口；健康 timer 由该服务启动。Root 注册 purpose/政策与 provider；Storage owns 检测状态、可信观察来源与事件/outbox 事务。只有管理 compiler/metadata handler 使用 Workflows；检测器不创建工单或原生 mutation。

### 9.2 证书预警的实际观察、阈值与去重

1. 原始 certificates 和 ca_certificates 页每条最多解析256KiB PEM、最多16段证书；页面响应还受共享 byte/record budget。无法解析、超限、日期无效或归属有歧义时保存固定质量码，不能发假到期事件，不保留 PEM/私钥/subject/SAN 到事件正文。
2. 候选阈值为剩余30天、7天、1天和 `expiresAt<=observedAt` 的 expired；用毫秒区间归入最严重的一个 bucket。初次实际观察已处于预警 bucket 可以发一次 `certificate.expiring`；未预警的初次观察只建基线。相同 leaf 指纹、到期时间、scope epoch、bucket 不重复发。更严重 bucket 产生新 occurrence；换证重建证书 epoch，不从旧证书延续恢复/到期状态。
3. 归属来自该页原始 physical tags 与发生时的实际数据库工作区，严格保留 default 无标签规则、未知/多工作区标签隔离和各侧完整 business tags。Scope/classification 变更建立新基线，不将旧提醒改挂新 WID。分类时不能调用会创建默认工作区的 `ensureDefault` 路径作为检测器隐式写；Root/Storage 提供仅查询已有工作区的 classification，缺元数据则 unavailable。
4. 稳定去重 identity 包含真实 cluster、captured transportScope、typed certificate UUID、leaf fingerprint/expiry、工作区/标签归属 epoch 与 threshold。公开 payload 仅 typed ID、severity、expiresAt、observedAt、质量及安全剩余时间；无 raw tags、证书配置、私钥、序列/Subject/SAN 或任意名称拼接。EventAccess 以真实历史范围与当前事件 read grant 决定可见性。
5. 索引页失败或 cursor traversal 尚未 complete 时，不把未见证书当删除，也不凭旧 document 刷新 lastObservedAt。完整遍历才允许清理旧检测基线；没有新观察时 UI 如实显示 lastSuccessfulObservation/age 和 incomplete/stale。轮询能在下一次实际观察时触发阈值，不能宣称在 expiresAt 瞬间已经检测。

### 9.3 Upstream 健康检测的固定路径与节点语义

后台只读取实际已启用、未删除且兼容 Kong1.5 的注册端点。候选 Upstream 来自真实 size100 `/upstreams` 页，保存原生 continuation 和 `(CID,transportScope)`；旧 entity_index 可以作调度提示，必须 fresh 原生证明候选 UUID、tags、归属和 config fingerprint。路径只能由服务器候选 UUID 生成：GET `/upstreams`、GET `/upstreams/:UUID`、GET `/upstreams/:UUID/health`。精确版本/节点 identity 用已有 separate probe 的 GET `/`，不新增 `/endpoints`；node_id 缺失时不能编造节点 UUID。

每个 health 响应在正式实现前以固定1.5.1源码与真实**非空**响应冻结字段/状态 enum 和分页语义。若响应具有真实 next/offset，就使用固定 size 和原生 continuation；不能假设所有 health 响应天然完整。若该版本一次返回完整集合，则以响应 records/bytes 限额拒绝过大对象，不在截断集合上提交完整观察。正常 HTTP status200、空数组、HEALTHCHECKS_OFF、未知枚举、响应缺 Target ID 或权重信息分别处理，不把它们转为 HEALTHY/零故障。401/403/404/5xx、DNS/超时是 observation unavailable，不能把观测通道错误当 Target UNHEALTHY。

受验证的一次观察需要当前有效 Target UUID/父 Upstream 关系、全部有效健康项与实际节点；health 与必要的有效 `/upstreams/:UUID/targets` 集合在同一受限观察内核对。不使用 `/targets/all` 历史作为活动项，不按地址推断最新有效 ID。所需 targets 路径也必须列入 Root 的固定只读用途；初版无需读取凭证、plugins、cache、schemas 或任意业务 URL。

检测 identity 为 `(CID,transportScope,observedNodeId,UpstreamUUID,config/target-membership fingerprint,scope epoch)`。节点、版本、注册 URL/auth revision、Upstream 配置、有效 Target 集合或工作区/tags 变更时重置基线；不能把新节点/新 Target 的首次状态当旧节点恢复。单 Admin endpoint 只能声称该 endpoint 当前可观察节点；负载均衡 Admin 节点交替时不合并为全节点健康。前后 separate probe 若节点/版本变化，该批不可用。两个 probe 分别在各自无父 ALS 的 probe frame执行，观测用途 frame 在它们之间关闭，不在已有 system frame嵌套mint另一个system purpose；三段共用本批总预算与captured端点身份。

候选去抖为两个连续、完整、同节点同配置的30秒采样均确认新状态后，CAS 提交 `upstream.health_changed`。第一份完整状态只建立 baseline；unknown/stale 不填补间隙、不使去抖计数继续。初版按 Upstream 聚合事件，source typed ID 是真实 Upstream；正文只有 observedNodeId、nodeScope、前后安全状态计数、changedTargetCount、observedAt/previousObservedAt 和质量，不携带 Target地址、子 UUID 列表或配置。Typed Target 订阅不会被虚假匹配到这个 Upstream 聚合事件；将来独立逐 Target 事件需完整自己的历史 scope 授权。

### 9.4 总预算、调度与失败边界

以下为待 Root 审定的保守硬上限，不继承 Context 默认500calls/120秒作为检测预算。现有索引器的全集群无 LIMIT 查询也不能直接复制成新的生产者调度。

| 范围 | 候选硬上限/行为 |
| --- | --- |
| 集群调度 | SQL keyset 每批20个兼容活动 CID；总并发2，每物理 transportScope 同时1个观察任务；保存 continuation，后页不能因首批慢而永远不执行。 |
| 证书原生采集 | 复用已有索引页，不新增证书网络扫描；indexer 每轮最多八类各1页、size100、累计800records/32MiB/10秒，实际超预算保留 continuation 并标 incomplete。证书 observer 每个已成功页最多100条、单条 PEM256KiB/链16，不影响其他类型页的完整性。 |
| 健康采样 | 每CID每30秒至多8个 Upstream；固定集合 size100、每次最多2个目录页，health/targets累计最多20页/1000records/8MiB、最多32calls/15秒，计入最多24个exact identity/health/targets调用和前后2个node probe；额外真实next页同样扣减32calls总额。预算耗尽保存候选位置，当前未完整的 Upstream 不提交。 |
| DB 提交 | 最多50条已验证观察/事务，mutable detector root revision CAS；原生网络全部在 SQL事务外。无界 target vector 不进 payload；整批事件正文仍每条8KiB。 |
| 故障/停机 | 单 CID singleflight、受控 backoff30秒→最多5分钟；timer unref、onModuleDestroy 停止新批并关闭过期 callback；其他 CID 继续，失联不制造健康事件。 |

Health 目录 cursor/候选位置绑定 cluster revision/transport scope/size/expiry；配置变化丢弃旧 continuation 并重新建立有效基线。共享 Kong Redis rate/timeout/DNS/目的地址策略原样生效，不因“检测”绕限流或开放远程 endpoint。Redis 观察锁和 DB CAS 用于避免重复观察，并不提供 Native write 权限。

### 9.5 当前授权、HTTP 与后台严格分开

- 后台 timer 必须在应用 bootstrap 且不存在任何 ALS 时创建；system actor 为 `actorType=system,actorId=NULL`，没有伪 console user、SID、JWT 或历史审批。Root 私有 GET-only purpose 只证明服务器可以采样固定已注册网关，不授予订阅作者、用户或事件 handler 原生 write/config read。每批开始、网络 await 后与 DB提交前核验当前 cluster/WS enabled、revision、physical scope、节点/版本与实际采样归属；失配丢弃观察而不是按旧权限继续。
- HTTP 详情/健康操作继续真实 current console actor 的现有 read grant、selected WID 和 await后 permissionVersion/session栅栏，不调用 runSystemRead、不把排队函数包进假 system frame。不提供客户端提交 expiresAt/health/actor/scope 的 observation append 接口。`event-metadata` handler 仍严格 zeroNative，仅配置/审计/DB队列；它既不采样，也不能借 metadata approved proof mint detector/Native claim。
- private background 采样不等于对外广播；fanout、站内通知读取和网络投递分别 fresh 验证 EventAccess 的同一完整历史 source grant/current身份。Shared deliverycreator 与 channelcreator 当前有效/授权、channel/subscription revision/generation仍全部要求，不能由 system observation 绕过。无当前授权收件人时可以保留真实事件，不产生未经授权 delivery。
- disabled/deleted工作区不继续采样/修改配置/投递；既有历史保留并按已冻结历史读取政策授权。HTTP受限健康页若要记真实观察，只能保存其实际已授权子集的 partial 质量与当前actor，不能替换后台complete baseline或生成聚合恢复事件；初版可完全不把HTTP读操作当生产者。

### 9.6 同事务真实来源与 release 门禁

`event_detection_state` 是 mutable 去重根，不能独自充当不可变 event source。建议 SQL010 增量增加 `event_detection_observations`（最终命名由 Storage冻结）：append-only 的 scope/node/transport/config fingerprint、observedAt、quality、安全观察与 HMAC，完整typed subject/context FK；同事务插真实观察、CAS baseline、插 `event_records` 和 outbox。EventRepository 的 `appendTrusted` 只接受该服务器来源的 opaque/internal证据，校验实际 source row与 occurrence；不接受 HTTP JSON、自称system或仅一个UUID。若 Storage采用同等强度的其他 immutable source pointer，需写明精确FK/HMAC/去重合同再编码。

baseline CAS、观察、event/outbox任一失败整体回滚；纯重复观察只更新真实freshness，不再发event。运行角色对immutable source表仅SELECT/INSERT；锁mutable detection root，不给immutable观察行UPDATE来满足 JOIN行锁。Audit十九字段不变；观测事实不是Native配置写，不能伪造entity.changed/write成功审计。异常日志/质量只固定code与UUID/时间/预算，绝不记录PEM、Target地址、认证或原生body。

M7验收必须包含：实际近到期证书→真实一次预警→更严重阈值/换证去重；超过100条/第二页不漏与预算未完成诚实显示；实际有效 Target 两次健康变化→当前节点事件；HTTP过滤页不污染baseline；节点切换/Target新有效ID/跨WS标签变更/stale/未知状态/403/5xx无假恢复；停用、撤权和过期continuation零未经授权投递；Runtime非owner正式producer事务成功及CAS回滚。未来纯helper/fakeGateway测试、disposablePG与真实Kong/本地收件器证据分别标注，catalog中显示支持或unsupported都不能替代上述检测证据。
