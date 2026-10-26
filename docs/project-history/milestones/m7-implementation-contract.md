# M7 实施边界与分工

状态：设计预备。仅在 M6 真实验收、清理及提交完成后，由 Root 发布实施指令；此文件不启动后台投递或新的迁移。

M7 复用 M0–M6 的真实身份、当前数据库授权、原幂等键回执与统一工作流。Kong 不提供企业事件端点，所有事件和通知存在控制台侧。

## 已决策的权限与生命周期

- 审计和事件历史使用记录发生时的可信 CID/WID、原生类型、ID、before/after 物理标签。受限修改记录需同一完整 grant 同时覆盖 before 与 after；不拼接不同 grant，不按当前实体标签重写历史。旧行缺乏可信归属时仅完整集群或平台权限可读。
- `audit/events/notifications` 的原生 entity 条件允许明确的实体类型和 ID；历史匹配仅检查可信保存值，不调用已删除实体的 Admin API，也不从对象名字推导权限。所有分页、导出下载和通知计数均复核当前 permissionVersion。
- 完整链验证要求完整集群或平台 `audit.read`。链算法保持既有 canonicalJson 的原始十九字段：sequence 使用十进制字符串，occurred_at 转 UTC 毫秒 ISO；新增范围注解不进入旧 hash。验证报告声明真实区间、完整性和预算。
- 新的历史范围注解引用不可变 event_hash，并使用带 event/CID/WID 上下文的 HMAC 封存；不声称旧 hash 已覆盖新注解。公开 JSON patch 从当前脱敏的原始 before/after 重新生成，不直接对已持久 patch 的 value 做无路径脱敏。受限审计中的 cascade deleted/restored 子对象数组仅显示计数；工作区权限本身不证明每个子对象归属，事件模板永不复制这些子 ID。
- 渠道、外部订阅、测试和重放需要完整工作区 `events.write/delete`，遵循集群 direct/approval 模式。使用独立 `event-metadata` 工作流 kind 和明确事件 subject，不冒充 Portal subject，不获取 Portal 原生私有执行能力。
- 个人标记已读/忽略及本人站内偏好由当前本人身份执行独立持久元数据操作；它们不修改网关或共享渠道。要求当前 `notifications.read/write` 和所引用事件的当前范围权限、owner 匹配、revision CAS，批量操作二次确认。偏好不能授予新权限，也不替他人或门户开发者操作。
- 渠道和共享订阅软删除后保留历史，Events 回收站提供显式恢复；不物理删除审计、事件或投递尝试。目标变更递增 credential_generation，不继承旧目标凭证；公开 DTO 永不包含原始 URL、token 路径或认证材料。
- Worker 使用服务器加载的真实 active 控制台账号和当前有效 grants，无伪造 HTTP session、开发者执行身份或平台万能绕过。源事件的当前范围、配置创建者的当前共享配置权限、目标 revision/generation 和租约在最终发包前复核。创建者停用或撤权后停止旧投递。
- 发送前先提交固定 delivery 的 attempt_no、lease_generation 和发送意图；完成结果只追加 attempt 行，不更新历史。崩溃后为过期发送意图补 uncertain 结果，同一 delivery/key 重试。Outbox fanout 逐批保存 continuation，只有所有订阅及接收者页完成才标 dispatched，唯一约束抵御重放；DNS await 后再次复验当前权限、lease、revision 和 generation。

## 服务接口与唯一所有权

Root：`modules/audit/` 查询、历史范围匹配、链验证、有界异步导出；Authorization 历史 matcher；AppModule/Swagger 集成；Audit.append 保留旧 hash 并返回安全 receipt。Storage 提供无网络 outbox writer，由 Audit 在同一数据库事务调用。

实施时由 Audit owner 承担 Root 委派的查询、完整性、导出、历史 matcher/EventAccess 和三个历史模块的 typed native entity IAM 特例；Root 保留最终集成。最小集群/工作区发现增加 `audit/events/notifications`，不附赠原生读取。导出采用独立 `audit_export_jobs` 的 actor/scope/key/HMAC 账本，创建 job 与审计同事务；原键核验固定为集群 `/clusters/:cid/audit/exports/by-key/:key` 和全局 `/audit/global/exports/by-key/:key`。导出要求当前 `audit.read`，不是网关写入，不受集群配置审批模式阻断；文件下载仍逐次复核 owner 与当前权限。

Storage：新增 SQL010、append-only 运行角色清单、`modules/event-core/` 的事件派生/outbox 认领/站内通知、owner 偏好与有界游标。提供只读 `EventAccess` adapter token，由 Root 历史 matcher 实现；不依赖 Audit 或 HTTP，避免依赖环。

证书和健康检测以新的只追加 `event_detection_observations` 保存可信观察来源，实际实体/租户/配置版本与 source scope HMAC 绑定；可变 baseline 仅作 CAS 进度，不能充当事件授权来源。观察、baseline 推进、事件和 outbox 在同一事务提交。具体 FK 与 `enqueueObservation` 参数由 Storage/Kong 在正式 M7 实施前固定；不启用检测器或扩展当前 Kong 内部读取能力。

Kong/Workflow：`modules/events/` 共享渠道和订阅 CRUD、目录/安全 DTO、独立 event-metadata compiler/registry handlers、真实 IAM/workflow 结果和按原 key 核验。只扩展明确新 kind/subject 的元数据政策，不改 Portal 原生能力与历史迁移。

DevOps：`modules/event-delivery/` 后端 Worker、出站 DNS pin/SSRF/租约复核、固定 Webhook/SMTP/Slack/飞书模板、部署与本地独立收件器。SMTP 未配置时返回真实不可用；测试期间仅发送明确白名单本地收件器，不自动联系外部账号。

Frontend：审计、事件中心、通知页与 Bell；明确有限完整性区间和未知回执；Query scope/actor/权限隔离；渠道秘密仅临时表单内存；安全同源导出下载。

Security：离线威胁用例和唯一真实写入窗口；本地实际 Webhook/SMTP、重试、DNS/撤权/IDOR、全写审计和浏览器证据。Reviewer 独立检查关键授权、事务与投递竞态。

## M6 验收期间冻结的实施接线

本节仅冻结接口与所有权，不启动 M7 产品实现。M7 产品源码、SQL010、Worker、部署和实际投递仍须等待 M6 实际验收、提交及 Root 的明确实施 release；先前临时 release 已撤回，各 owner 未修改 M7 产品文件。

- Kong/Workflow owner 在未来 release 后扩展 `ApprovedWorkflowExecutionService.assertSubject` 及固定 metadata verifier 的 `event-metadata` 分支，Reviewer 独立审阅与验证。Portal native claim 的 kind 白名单保持原样；事件计划永不进入 Portal 原生能力。
- kind 固定为 `event-metadata`；subject 固定为 `notification_channels`、`event_subscriptions`、`event_deliveries`。渠道测试使用渠道 subject，投递重放使用 delivery subject。SQL010 增量扩展原 kind/subject CHECK 和 subject 验证函数，不改写 Portal 已封存计划与历史。
- 固定 handlers 为 `event.channel.save`、`event.channel.status`、`event.channel.delete`、`event.channel.restore`、`event.channel.test`、`event.subscription.save`、`event.subscription.delete`、`event.subscription.restore`、`event.delivery.replay`。这些名称由服务器 registry 选择，不接受客户端指定函数或 callback。
- 所有事件步骤均为 `metadata`，`nativeRequests=[]`，无 `mutationAction`、`generated` 或原生 prerequisite。原始 before 使用当前锁定的同 CID/WID 数据库行；revision、before HMAC、完整 sealed payload HMAC 与 step 绑定。HTTP operation identity 另外绑定 create/update、target UUID 或固定 collection identity、原请求 body，先核验原 key，再做当前 revision CAS。
- 共享渠道与订阅的列表、详情、回收列表需要当前完整工作区 `events.read`；配置写入与删除分别需要完整工作区 `events.write/delete`。固定 catalog 可采用粗粒度 events.read 发现入口。实体/tag grant 的粗粒度 assertCluster 不得提升为整区共享配置读取或修改权限。
- 审批者需要当前完整工作区 `workflows.approve`；执行者分别需要当前完整工作区 `workflows.write` 和 step 的 `events.write/delete`。提交共享事件计划不授予审批或执行能力。审批模式创建时只保留固定身份、hidden disabled reservation，requested endpoint/auth/options 不生效；reservation 与 immutable workflow、版本和步骤在同一事务提交。direct 模式创建在普通 IAM callback 事务内持久化最终对象，不先提交无回执的 reservation，不 mint approval claim。
- `/events/operations/by-key/:key` 只投影真实命名空间下原 actor/CID/WID/key 的 IAM 或 workflow 回执，不按当前集群模式选择域。原提交者当前 `events.write` 可以核验已持久化的 submission-only proof，即使没有 workflows.read/write；此专用投影不公开其他工单、配置或执行能力。审批已登记、SQL 配置提交、queued 和远端 delivery 成功分别说明，不互相推断。

`EventsModule` imports `WorkflowsModule` 和 `IamModule`，依赖全局 Db/Secret/Authorization/Workspace/Audit provider；bootstrap 注册固定 handlers。WorkflowsModule 不反向 import EventsModule。Storage 的 event-core 只提供 DB-only repository/enqueue 和 EventAccess token；DevOps 的 event-delivery provider 只提供固定目标验证与安全能力目录。二者不注入事件管理服务或工作流 Engine，避免依赖环。

渠道密文 AAD 冻结为 `event-channel:<id>:<cid>:<wid>:<credential_generation>:endpoint` 与同前缀 `:auth`。scope/type/creator 固定；目标或认证变更递增 generation。新目标不继承旧认证，提交方必须显式选择新认证或无认证；普通省略字段只表示保留同一现有目标。public DTO 只含脱敏目标、configured 标记、安全 options 和当前能力，无 raw URL、token 路径或 reveal。

Storage 冻结的 DB-only 测试入队接口为 `EventRepositoryService.enqueueTest({auditReceipt,clusterId,workspaceId,channelId,channelRevision,credentialGeneration,actorId,iamOperationId?或exact workflow tuple},tx)`；它核验同一事务内的成功审计 receipt、真实账本和当前渠道版本。测试 delivery 使用明确 `delivery_kind='test'`，subscription ID/revision 为 NULL，creator 来自真实 IAM/workflow actor；普通 `delivery_kind='subscription'` 则要求完整 subscription tuple，不虚构临时共享订阅。审批测试 enqueue 与 metadata step、父终态在同一事务提交，Worker 只能看到提交后的测试。

渠道与共享订阅各自保存 append-only versions，当前 root revision 引用实际版本；fanout 使用冻结的 subscription/channel version，不能重新从当前 root 取旧 delivery 的目标或配置。`EventRepositoryService.enqueueReplay(input,tx)` 在同一事务生成新 generation，并保存 original parentDeliveryId，保留旧 event/delivery/attempt identity。expectedRevision 对应 SQL010 将新增的实际 event_deliveries.revision，不取 attempt 或 plan 版本；实际导出以正式源码为准，不能先假定迁移已存在。网络发送只由 Worker 在 terminal 配置成功后进行，metadata handler 不调用外部 provider。共享目录采用 `(created_at,id)` keyset 游标，签名绑定完整过滤、actor、permissionVersion、CID/WID 和 size。详细实施接线见 [共享事件管理清单](m7-events-implementation-checklist.md)。

## HTTP 合同

### 停用及删除工作区的读取规则（Root 已决策）

工作区为 `disabled` 时，当前完整工作区 `events.read` 可读取共享配置、回收记录和投递历史；配置修改、恢复、测试、重放及 Worker 发送全部停止。工作区为 `deleted` 时，共享渠道和订阅的活动目录、详情和写接口返回工作区不可用，不使用默认工作区代替原 ID。已发生的审计、事件及本人通知仍保留原历史 WID：历史 matcher 直接核验该 WID 的实际归档数据库行、当前身份和完整 grant，不使用要求活动工作区的 Native resolver，不查询 Kong。已撤销的当前授权仍不能读取；归档工作区不扩大 tag/entity grant，也不能恢复发送能力。集群已删除时保留数据库历史，但普通集群接口不可用；平台审计历史入口的扩展需另有明确实现，不能以此次规则暗设平台绕过。

控制台路径沿用 `/api/v1` 前缀。

- `/clusters/:cid/audit`、`/:id`：GET；固定 workspaceId 与过滤、size/cursor。静态 `/integrity`、`/exports` 在 ID 路由之前。完整性仅 GET。有界导出 POST `/exports`、GET `/exports/:id` 和 `/download`，同源认证、owner/current permission 校验。
- `/audit/global`、`/audit/global/:id`、`/audit/global/integrity`：只查询真实 NULL CID/WID 的 IAM、登录等全局历史，要求当前完整 global `audit.read`；不映射默认集群。全局导出沿用同一 owner/当前权限和原 key 合同。
- `/clusters/:cid/events/catalog`、`/records`、`/records/:id`：只读；渠道和订阅复用 M7-web-contract 草案路径、明确 revision 与二次确认。
- `/clusters/:cid/events/deliveries`、`/:id/attempts`：有界只读；`/:id/replay` 为显式配置写入，保留原历史。
- `/clusters/:cid/events/operations/by-key/:key`：GET 投影真实工作流或 IAM 父回执，绑定原 actor、CID、WID 与原 key；不通过当前模式猜测回执域。
- `/notifications/unread-count`、`/preferences`、`/:id`：当前控制台 owner；read-batch 仅最多 100 个实际 ID、同 CID/WID、确认后执行。无任意 userId 接口。

列表统一 `{items,nextCursor,size,total:null}`，默认 20、最大 100；游标绑定身份、permissionVersion、完整过滤与租户。默认时间范围 7 天；不全量浏览器扫描。

## 交付门禁

SQL010 在隔离 PostgreSQL 验证 append-only、不可变身份、CAS、回滚无事件、并发租约。源码、三端 typecheck 和相关安全测试先通过，再唯一部署、唯一实际 HTTP/浏览器窗口。事件至少一次投递，网络未知不声称未送达；日志仅状态码、耗时、安全错误和 UUID。真实外部账号未配置时明确记录，不能将本地测试替代外部联调。


## 真实运行数据库角色的验收

隔离数据库的正式成功与重放路径必须以实际非owner、非superuser运行账户调用业务服务；迁移账户仅用于建库和预置夹具。不可变历史和证明表保持SELECT/INSERT，不通过增授UPDATE来满足行锁。对关联事实使用可变root行的版本锁、不可变版本外键与HMAC/原hash验证。直接权限拒绝测试不能替代正式路径在运行角色下的成功测试。

## M6 实际诊断确定的终态审计补缺

manual-publish-original-receipt-readonly-diagnostic.json 已真实证明 existing direct page publish 的原IAM回执成功，但该requestId仅有 iam.write.requested/pending 审计。M7实施必须在PortalAdmin.metadataRequest直接执行的同一事务内、实际apply/readBack之后追加真实subject before/after、success、当前requestId/IP与scopeHints，并补齐IAM成功账本的终态来源；发布、归档和恢复均覆盖。不得修改既有pending审计或把历史事后猜测当原终态，原证据保持。标准11须重新实际验证成功及失败结果、diff和100%对应，而非只计requestId存在。新event-metadata handler的真实业务audit/queue和IAM终态同TX关系仍按现有合同。
