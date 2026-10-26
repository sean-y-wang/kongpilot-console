# M7 审计、事件钩子与通知存储合同（设计稿）

状态：仅设计。M6 尚在实际验收阶段；本文件不授权 SQL010、产品源码、迁移、后台投递或外部消息发送。已冻结 SQL000–008 均不因本设计改写。预算、导出类名、queue签名与Root已决定权限政策以 [M7 核心接口清单](m7-event-core-interface.md) 为准，早期示例不能覆盖后续冻结值。

M7 在现有 `audit_events` / `audit_chain_heads` 和 M6 `workflow_events` 上扩展查询、验证、导出及异步事件通道。它不调用 Kong 企业 Event Hooks 端点，不新增原生写入旁路。已有变更仍经 Mutation/IAM/Portal/Workflow 的真实权限、回执与审计。

## 1. 范围与不变量

- 审计记录仍只追加。所有正文、JSON patch 和错误摘要在公开读取、导出与通知模板中再次使用当前 SecretService 脱敏；历史已写入的行及其 hash 不更新。JSON pointer 的转义路径、OAuth provision_key、AWS key、URL userinfo、认证头及短秘密的错误回显同样受保护。
- 事件只有在相应业务 SQL 事务提交后可投递。配置失败或未决结果使用独立事件类型，不能发出“已成功”的通知。原生包 ACK、业务父工作流终态与请求受理是不同事件。
- 外部投递至少一次；相同事件与订阅生成唯一 delivery，使用稳定事件 UUID / Idempotency-Key。网络超时不能证明接收方未处理，重试沿用同一投递标识。
- 列表、导出、站内通知和投递日志均带明确 cluster/workspace 范围，四维授权按完整 grant 逐行计算。不得把不同 grant 的功能、操作、标签和实体范围拼成新权限。
- 当前权限撤销立即生效。读取开始和结束复验 permissionVersion；发送前复验订阅、目标、源事件范围与当前配置 revision。历史通知不因实体迁移改挂到新工作区。
- `actor_id` 继续只引用控制台 users；开发者事件为 actor_type=developer / actor_id=NULL，并以同 scope 的 developer UUID 记录安全身份，不生成控制台账号。
- 不为健康/漂移/证书轮询伪造实体或遥测标签；检测器产生的观察事件携带真实采集时间和质量，不能代表未观测的状态。

## 2. 拟议 SQL010 表

以下名称供后续分工确认，尚未落地。所有对象 UUID、完整 tenant FK 和时间约束沿用 SQL008；普通删除均软保留。新增 append-only 表的运行时角色只有 SELECT/INSERT，触发器另禁止 UPDATE/DELETE/TRUNCATE；投递队列进度允许受限 CAS UPDATE，但固定身份不能更改。

| 表 | 关键字段 | 约束与用途 |
| --- | --- | --- |
| `audit_event_scopes` | event_id, cluster_id?, workspace_id?, source_module, native_type?, native_id?, physical_tags JSONB, quality `verified/legacy_unknown` | PK event_id；引用 audit_events 的完整 event/cid/wid tuple。不可变采样时归属用于范围过滤；不按当前实体标签重标历史。没有可信 scope 的旧审计不默认归入 default；受限范围不能读取未证明的历史。 |
| `event_records` | id, cluster_id?, workspace_id?, event_type, source_kind, source_id, source_version?, actor_type, actor_id?, developer_id?, entity_type?, entity_id?, workflow_id?, mutation_id?, audit_event_id?, native_type?, native_id?, physical_tags JSONB, payload_safe JSONB, occurred_at, dedupe_key | 只追加；source+dedupe_key 唯一；实际 CID/WID/FK 有且只能同 scope；payload_safe 严格字段白名单与 64KiB 上限，无 native config/raw body/密文秘密。developer actor 与 console actor 成组互斥。 |
| `event_outbox` | id, event_id, state `pending/dispatching/dispatched/failed`, lease_owner?, lease_until?, next_attempt_at, attempt_count, error_code?, created_at, updated_at | event_id 唯一；事件引用/ID/创建时间 immutable；FOR UPDATE SKIP LOCKED 有界认领。实例异常后过期租约可由另一 worker 继续，不影响原业务提交。 |
| `notification_channels` | id, cluster_id, workspace_id, name, type `webhook/email/slack/feishu`, status `active/disabled/deleted`, endpoint_secret?, auth_secret?, options_safe JSONB, credential_generation, revision, created_by, deleted_at?, retention_until?, created_at, updated_at | 完整 workspace FK；目标 URL（包含 Slack/飞书 token 路径）与认证材料上下文 AES 加密；公开只有脱敏 host/type/状态/最后探测，不返回 URL/token。所有配置写入按集群 direct/approval 策略，不能以“通知配置”为旁路。 |
| `event_subscriptions` | id, cluster_id, workspace_id, channel_id, name, event_types TEXT[], native_type?, native_ids UUID[], physical_tags TEXT[], status, revision, created_by, deleted_at?, retention_until?, created_at, updated_at | 完整同 tenant channel FK；配置事件白名单，最多 32 类型、256 实体/标签条件；对象 scope 只缩小原订阅管理授权。固定 CID/WID、channel identity 与 creator 不可更换。 |
| `event_deliveries` | id, cluster_id, workspace_id, event_id, subscription_id, subscription_revision, channel_id, channel_revision, credential_generation, state `pending/sending/succeeded/retrying/uncertain/exhausted/cancelled`, lease_owner?, lease_until?, next_attempt_at, attempt_count, idempotency_key, payload_safe, created_at, updated_at | UNIQUE(event_id,subscription_id,subscription_revision)；生成时保存不可变安全模板结果，不延迟读取实体秘密。固定事件/订阅/渠道/原安全 payload 不可改；endpoint generation 变化或订阅停用需取消旧 delivery 或显式新重放，不将旧 token 带往新 host。 |
| `event_delivery_attempts` | id, cluster_id, workspace_id, delivery_id, attempt_no, started_at, finished_at, outcome `succeeded/failed/uncertain`, http_status?, duration_ms, error_code?, response_summary_safe, request_id | 只追加；UNIQUE(delivery_id,attempt_no)，完整 scope+delivery FK；只保存 status/有限错误码，响应摘要最多 2KiB 再脱敏。无 request Authorization、目标原始 URL、原始 response body。 |
| `user_notification_subscriptions` | id, user_id, cluster_id, workspace_id, event_types TEXT[], native_type?, native_ids UUID[], physical_tags TEXT[], in_app_enabled, channel_subscription_id?, status, revision, deleted_at?, created_at, updated_at | 只影响当前 users 账号自己的站内订阅；外部 channel 选择必须另有同范围通知配置权限。订阅不能授予原本没有的事件读取权限。 |
| `user_notifications` | id, user_id, cluster_id?, workspace_id?, event_id, title, summary_safe, link_kind, link_id?, read_at?, dismissed_at?, created_at | UNIQUE(user_id,event_id)；固定 owner、事件、范围及正文不可改，允许 read/dismiss 时间单向更新。读/标记/批量标记先 owner 检查再复核当前事件范围；合法通知链接只是导航，不是权限。 |
| `event_detection_state` | cluster_id, workspace_id, detector_key, subject_type, subject_id, last_observation_safe, observation_fingerprint, last_observed_at, revision | 真实检测器去重状态，CAS 发生状态变化才发事件；无源配置/凭证，不能成为事件授权依据。证书剩余天数阈值/健康变化去抖均明确配置。 |
| `audit_export_jobs` | id, actor_id, cluster_id?, workspace_id?, request_hash, filter_safe, upper_bounds JSONB, permission_version, state, row_count, bytes_count, digest?, output_ref_secret?, expires_at, created_at, updated_at | 用户自己的有界异步导出回执。输出暂存加密或受控私有文件；每批复验当前权限，撤销后停止并拒绝下载；不是把已过期权限冻结为下载能力。不得在 artifact 中长期保留凭证或导出公开 URL。 |

`event_records` / `event_delivery_attempts` / `audit_event_scopes` 为新增 append-only 集合。`event_outbox`、deliveries 与 export_jobs 的身份 tuple 使用触发器保护，其 lease/进度使用 CAS。所有 queue 索引以 `(state,next_attempt_at,id)` 有界取批，另有 `(cluster_id,workspace_id,created_at DESC,id DESC)` 列表索引。保留期到期默认标记过期；M7 不开放删除审计/投递历史接口。

现有 audit 表无需改变任何正文。新增完整唯一 tuple、可空 scope CHECK 和 `NOT VALID` FK 可以增量建立，但必须留住历史 NULL；是否引入 audit scopes 应以当前审计内容能否可靠分类逐类确认，不能臆造工作区。

## 3. 审计查询与完整性

拟议接口：

```ts
interface AuditQuery {
  clusterId?: string; workspaceId?: string; actorId?: string;
  entityType?: string; entityId?: string; action?: string; result?: string;
  from?: string; to?: string; workflowId?: string; size?: number; cursor?: string;
}
AuditQueryService.list(actor: AuthUser, query: AuditQuery): Promise<CursorPage<AuditSafeView>>;
AuditQueryService.get(actor: AuthUser, eventId: string, scope: AuditScope): Promise<AuditSafeView>;
AuditIntegrityService.verify(actor: AuthUser, chain: string, interval: SequenceInterval): Promise<IntegrityReport>;
AuditExportService.request(actor: EntityActor, query: AuditQuery): Promise<ExportJobSafeView>;
AuditExportService.status(actor: AuthUser, jobId: string): Promise<ExportJobSafeView>;
```

分页 size 1..100，时间窗口默认 7 天，keyset 为 `(occurred_at,id)`；签名 cursor 绑定完整过滤、actor、permissionVersion、CID/WID，禁止全表拉取或 OFFSET 跳页。导出 request 冻结各 chain 已提交 sequence 上界，按 cursor 分批并复验权限，默认 100k 行 / 32MiB，超限明确停止并报告，不悄悄截断为“全量”。格式 NDJSON 与安全 CSV（文本单元格防公式执行）。

内部完整性检查对原始持久行按已有 canonicalJson/sequence/prev_hash/event_hash 验证，不对二次脱敏视图重新算 hash。完整 chain 验证只授权拥有完整该 cluster/global audit 读取范围的账号；受限工作区用户不能获得其他工作区行、链头、未过滤计数或全局序号活动分布。公开历史摘要是当前脱敏投影，不能当原始链字节证明。数据库 owner/超级账号仍能绕过触发器，因此“防篡改”声明应准确为运行时不可变 + hash 链可验证；可选外部签名 anchor 另经部署合同审定。

## 4. 事件生产与审批

拟议 server-only EventService：

```ts
EventService.append(event: TrustedEventInput, tx: DbService): Promise<{eventId:string}>;
EventService.fromAudit(eventId: string, tx: DbService): Promise<void>;
EventDispatcher.claim(limit: number): Promise<ClaimedOutbox[]>;
DeliveryService.dispatch(claim: ClaimedDelivery): Promise<void>;
NotificationService.list(actor: AuthUser, query: NotificationQuery): Promise<CursorPage<NotificationSafeView>>;
NotificationService.markRead(actor: EntityActor, ids: string[], confirmed: boolean): Promise<NotificationReceipt>;
```

Event append 从真实业务事务调用，source/action/result 映射到服务器固定事件类型，不接受 HTTP 任意 payload 或“已批准” flag。最小事件集合：entity.changed、entity.delete/recovered、workflow.submitted/approved/rejected/cancelled/executed/uncertain、certificate.expiring、governance.drift、upstream.health_changed。请求受理和最终成功分别去重。已存在 audit 写入点统一补 outbox 时，推荐 Audit.append 返回安全 audit receipt（旧调用方可继续忽略）；先在同一事务写 audit，再以其 ID 派生 event+outbox，不先发网络通知。

Channels/subscriptions 创建、编辑、软删除和手动外部 test/replay 都是写操作：direct 模式经 IAM durable ledger + CAS + atomic audit；approval 模式编译固定 metadata handler 并使用 M6 私有 metadata policy，不能传 workflowId 自行放行。检测器仅持内部最小读/append 身份，无原生管理权限。纯元数据管理使用 whole-workspace/global 完整 `events.write/delete` grant；原生对象限定订阅与查询另使用已验证 typed entity/tag 范围，不能用粗 assertCluster 把 entity grant 提升到整工作区。

## 5. 投递安全与运行边界

独立审阅补充：outbox fanout 必须保存本次订阅版本集合的稳定上界与 continuation，不只读取前 50 项。每批固定按 subscription/version keyset 前进，创建 delivery 用 `UNIQUE(event_id,subscription_id,subscription_revision,replay_generation)` 幂等；批进度与 delivery INSERT 同事务 CAS，只有扫描全部完成才 outbox→dispatched。重启从 durable continuation 继续，不能丢弃后续订阅或因重跑重复投递。

append-only attempt 不是可更新的网络事务：send 前先在 mutable delivery 行 durable 保存 attempt_no/lease_generation/send intent 并提交；完成后 append 一次 attempt outcome，再以同 lease CAS 推进队列。旧 sending 租约过期只证明本地失联，不证明未送达；新 worker 先为旧 intent append uncertain，再认领下一 attempt，沿用 delivery/idempotency key。不能先 INSERT started 的 attempt 再 UPDATE finished，不能在 DB 行锁内等待网络。

`audit_event_scopes` 的新注解绑定精确原 `audit_id/event_hash` 和可信原 before/after/typed business subject；核验 scope 注解自身的完整性与来源，但不宣称既有审计 SHA 链包含以后新增的 annotation。旧链仍按原十九字段验证，缺可信历史归属不按当前实体 tags 补成更宽权限。

- 只使用后端 allowlist 出站，DNS 每次解析并 pin；禁 redirect、URL userinfo、链接本地/metadata/管理端/控制台 DB/Redis/collector，禁止任意 headers（Host、Cookie、Connection 等）。Slack/飞书完整 token URL 加密，masked URL 永不直接写回。明确配置 host/path 变化时不继承旧凭证。
- Webhook 默认 HTTPS；开发测试 HTTP 只允许明确部署白名单。最终 HTTP 发包前再次验证 channel active/revision/generation、delivery lease 和事件范围，执行当前目标安全检查。同步检查与发包同一轮次，不能在 DNS await 后继续使用失效租约。
- 每集群/渠道独立 Redis 限流与队列并发；最多 4 workers/channel、每批 50 deliveries、8KiB payload、5s 请求预算、256KiB response 接收上限。重试指数退避含 jitter（例如 5s、30s、2m、10m、30m，最多 6 次），仅网络/429/5xx 自动重试；其他 4xx terminal failed，遵守上限内 Retry-After。生产速率/预算通过环境与元数据管理，不能无限重试压垮网关或接收方。
- 站内通知未读角标基于 owner + 当前可读事件范围，在后端计数；用户撤销权限后不得继续显示旧业务摘要。SSE 若采用则仅发送 opaque notification ID/refresh signal，每次详情仍当前权限校验；不把秘密和完整事件注入广播。
- 邮件 SMTP credential 环境或加密 channel 中管理；邮件/Slack/飞书参数是固定白名单模板，不允许任意脚本或动态模板执行。test 也是显式授权的外部消息，源码阶段与自动单测不实际发送。
- 所有日志保留 event/delivery/request UUID、状态码/耗时/安全 errorCode；不记录明文 credential、URL token、Kong原始 before/config、portal key 或第三方回显正文。

## 6. HTTP 草案与测试交付

控制台拟议 `/clusters/:cid/audit`、`/clusters/:cid/events/{channels,subscriptions,deliveries}`；workspaceId 显式 query/body。个人通知 `/notifications` 与 `/notifications/subscriptions` 绑定 current console user。不存在读取任意 userId 的个人通知接口。Developer 的通知身份不与 console notifications 合用；M7 若需要门户站内通知另做独立 developer scope 表/API。

审计只提供 GET、导出 request/status/download、只读 integrity verify；无 audit UPDATE/DELETE。渠道/订阅 DELETE 和批量 read/dismiss 二次确认，回执域使用真实 IAM/workflow ledger，不虚构 operation ID。手动 retry 重用原 event/订阅定义并创建显式新的重放版本，保留历史 attempt，不能 UPDATE 历史为未尝试。

意义验证计划：

1. 非超级 PG runtime 对所有新增 append-only 表 UPDATE/DELETE/TRUNCATE 被拒；故意误 grant CRUD 后触发器仍拒绝。队列进度可 CAS、固定事件/订阅/渠道 tuple 不可改。
2. 事务回滚无可见 outbox/通知；业务成功只有一个 source event；并发 worker、进程崩溃、过期 lease 和重复 HTTP 均不会创造新 event identity。
3. 已使用真实 grant 的跨 CID/WID、actor、tag-group/entity、scope NULL 历史、撤权后分页/导出/通知阅读全部拒绝；filtered total 与链头不能泄露其他工作区。
4. 原始链 verify 正确，插入/改 hash/删中间样本的隔离恶意 fixture 被准确检测；二次 redaction 不破坏已有 chain。JSON patch、URL userinfo、schema/plugin 历史秘密和错误回显不能进入导出/外部 payload。
5. SSRF、DNS rebinding、redirect、auth generation 旋转、host change、停用 subscription/channel、lease lost during DNS、响应过大与 429/5xx/4xx 重试分类有实际 loopback HTTP 测试，不使用外部真实账号。
6. Web 未读角标/标记已读/订阅设置和审计按人/对象/时间查询可演示；真实网关写入对应 audit+event+delivery 完整证据，证书/健康变化只在真实观察变化后出事件。

实施所有权、API DTO 与 append-only 运行角色清单由 Root 在 M6 实际通过并提交后正式冻结，本设计不提前启动 worker、发送测试消息或申请外部渠道权限。

## 7. 当前源码复用点与明确改动边界

本节来自 M6 开发期间只读检查，所述改动全部等 M6 commit 后 Root 正式释放 M7 才实施。

| 当前文件/合同 | 已有能力 | M7 明确复用或改动 |
| --- | --- | --- |
| `modules/audit/audit.service.ts` | 先脱敏 before/after，再 RFC6902 diff；按 global/cluster 锁链头；保存 canonical SHA256；append 支持 supplied tx | 保留 hash 字节合同；append 返回 receipt，新增 server-only DB outbox writer 注入。先 audit INSERT、head UPDATE，再同一 tx 写可信 scope/event/outbox。无网络和 Authz 依赖，防 Audit→Authz→业务→Audit DI/锁循环。 |
| `infrastructure/db.service.ts` | supplied tx 的嵌套 transaction 使用同一连接 SAVEPOINT；migration advisory lock/checksum | outbox 与原审计处于同连接/同提交，不创建并行 Promise 在同 tx 混用 savepoint；SQL010 顺序新文件，不改旧 migration。 |
| `infrastructure/migrate.ts` | runtime 非超级/non-owner；schema_migrations SELECT-only；现有9张历史表 SELECT/INSERT-only，广泛 CRUD 后再 revoke | allowlist 加 `audit_event_scopes,event_records,event_delivery_attempts`，保留全部 M6 历史表。队列表保留必要 UPDATE，触发器固定 tuple；禁止所有业务队列表物理 DELETE/TRUNCATE。 |
| `modules/mutations/mutation.service.ts` | requested、success/failed/uncertain 分离；实际 native outcome + durable ledger | 新审计上下文仅加不进入 legacy hash 的关联注解：operationId/native type/parent/credential kind/阶段。请求事件不是成功事件；unknown 只发 uncertain。 |
| `modules/recycle-bin/recycle.service.ts` | 归档事务、逐 node DELETE/restore 结果与独立 audit，再由 Mutation 写 root aggregate audit | 逐 node 事件使用 entryId+nodeKey+action/result 定义 occurrence；父结果使用 operationId，event role=aggregate。同 root 不把 node 和 aggregate 映射为两条同名 entity.deleted 通知。 |
| `modules/iam/iam-mutations.service.ts` | requested ledger 与结果 SQL callback；配置实际 before/after audit 在 callback 中 | IAM wrapper pending/失败与业务成功分别映射；不能假定 `iam.*.requested` 已成功，也不在 outbox worker 重新执行 callback。Channels/subscriptions SQL写用真实IAM ledger而非Native Mutation。 |
| `modules/workflows/workflow-plans.service.ts` / `workflow.service.ts` | workflow.submit/approve/reject/cancel/execute.requested/execute success或failed/uncertain；terminal metadata同tx提交 | 工作流通知以 source workflow id + plan revision + transition revision去重；仅终态 workflow.execute success→executed。Native step事件可先发生，不代替父 executed。Developer submit audit actorType保持developer、actorIdNULL。 |
| `modules/portal-auth/portal-auth.service.ts` | 独立 principal/session/epoch；Portal audit actorIdNULL + safe developer identity | M7 console notifications 不接收 Portal Cookie/Principal。开发者事件 sourceFK 补 scoped developer ID，只用于安全追溯，不变为控制台账号。密码/登录/csrf类事件默认不投递业务配置 before/after。 |
| `modules/authorization/authorization.service.ts` | snapshot/permissionVersion、hasWholeCluster/hasWholeWorkspace、typed scoped resource | Root 提供历史审计范围 matcher，依据可信记录时标签/ID而不是当前 entity GET；audit/events/notifications的发现权限另需注册 minimal cluster/workspace selector，不赠送 native.read。 |
| `infrastructure/kong/outbound.ts` | allowlist、DNS pin、禁 redirect、5s预算、beforeSend/prepareSend、response byte limit | 不直接复用其 Kong host allowlist 默认值。M7 单独通知 allowlist 与 SMTP/Slack/飞书目标合同，transport仍复用同样约束；验证 config revision/generation/lease 后同步发包。 |
| `infrastructure/kong/cursor.ts` 与现有 ConsoleCursor | HMAC cursor+subject/query/path/CID绑定 | DB keyset cursor 绑定 actor+permissionVersion+scope+filter+size+上界/截止时间；不把 query OFFSET 当 Kong native offset，不传未验证 SQL排序列。 |

事务锁顺序沿用当前写入：IAM epoch/目标 CAS 锁 → audit scope advisory/head row → 新 outbox/scope INSERT。Outbox writer只使用 supplied tx，绝不回调 Authz、Kong、Redis或业务。worker claim 独立短事务提交后才网络投递；不能握住 DB 行锁等待第三方响应。

## 8. 精确 audit v1 哈希验证合同

`AuditService` 当前 sha256 输入是以下 object（仅这些字段，**没有 event_hash、没有未来注解**）：

```ts
{
  id, chain_scope, sequence, actor_id, actor_type, source_ip,
  cluster_id, workspace_id, entity_type, entity_id, action,
  before, after, json_patch, workflow_id, result, request_id,
  prev_hash, occurred_at
}
```

sequence 必须使用十进制 bigint 字符串（SELECT sequence::text；不能转 JS Number）；occurred_at 必须是 UTC `Date.toISOString()`（审计 writer 原本只存 JS 毫秒精度）。JSONB field 使用 pg 已解析的 JSON value；before/after SQL NULL 或 JSON null 都是 writer规范中的null，但非法 hash/时间/字段类型不能自作默认补齐。SQL查询额外校验 timestamp无亚毫秒精度，避免 pg Date 投影丢失被修改的微秒。键递归 canonicalJson 排序保持当前函数，不用 JSON.stringify、PostgreSQL jsonb::text或脱敏safeView算原hash。

实际算法步骤：

1. 当前 whole-cluster/global `audit.read` 核验后，capture chain head 的 `(last_sequence,last_hash)` 和固定 upperBound；permissionVersion 首尾一致。
2. 验证区间 from/to 为 bigint十进制字符串；from>=1/to>=from/to<=captured上界。每请求最多1000行或2MiB原始记录，超限返回 bounded continuation，不声称已完整通过。
3. from=1 时 expected prev=GENESIS；其他起点从同chain sequence=from-1加载可信 predecessor hash。按sequence升序 keyset size<=100；连续 sequence、prev_hash等于前条computed hash、event_hash等于本条SHA256均须成立。
4. 若验证到captured head，将最后computed hash与captured last_hash比较；中间区间报告“此区间有效/尚未验完整链”，不把部分检查表述成全链完整。
5. 分类错误固定为 `AUDIT_SEQUENCE_GAP/AUDIT_PREVIOUS_HASH_MISMATCH/AUDIT_CONTENT_HASH_MISMATCH/AUDIT_HEAD_MISMATCH/AUDIT_RECORD_INVALID`。受限范围调用此接口403，错误不泄漏未授权chain、其他用户或workspace row。
6. 检查过程只读，不自动修复hash/head/历史scope，不解密秘密。continued cursor含固定upperBound、verifiedTo、expectedNextHash、actor+permissionVersion+chain，并由服务端签名；客户端不能提供一个“已验证前缀”对象直接跳过检查。

早期fixtures中手动SQL插入的任意假hash会被报告为无效，这不是修改既有行的理由。已有 writer unit 是重建精确insert参数并重算hash；M7增加真实pg往返（NULL、Date、数组、转义pointer、BigInt sequence）以及隔离恶意修改/缺行/gap案例。

## 9. SQL010 落地约束清单

在第2节表草案基础上，下列约束已明确为实施项，具体表名/API仍等Root冻结。

- 所有可空tenanttuple均 `workspace_id IS NULL OR cluster_id IS NOT NULL`；同scope链接同时建立简单ID FK与完整scope FK，并以触发器 `IS DISTINCT FROM` 复验 nullable cluster/global链接，不能让 MATCH SIMPLE 的NULL跳过实际隔离。
- `audit_event_scopes` 为同 event 唯一只追加注解；记录 `before_tags/after_tags` 分开，而不合并成授权tag union。创建只验证after、删除只验证before、修改须分别完整授权两侧；M7 Root决定跨标签 transfer diff是否只允许whole workspace。native ID来自已验证上下文/真实before-after；未知为legacy_unknown而不是default。此注解不进入旧hash。
- 新source关联采用明确 audit_event_id/workflow_id/mutation_id/iam_operation_id/portal_operation_id 可空列，而不是任意 `source_kind/source_id` 动态SQL读；source_kind与必填指针CHECK一致。native parent/credentialKind若需回显保留类型+ID，不从当前DAO猜历史父。
- `event_records`新增 `phase` (`requested/node/aggregate/terminal/observation`) 与 `occurrence_key`，UNIQUE(source_kind,source_id,event_type,occurrence_key)；auditEvent UUID唯一保证重复消费不新发事件。一个 DELETE图只产生逐对象node事件和不同名父结果事件；工作流pending/apply不生成executed。
- `event_outbox` lease_owner/lease_until成组非NULL只在dispatching；claimed row有递增lease_generation，最终 CAS同时检查generation，过期旧worker不能写新认领结果。event_id固定不可更换。
- delivery固定 tuple包括 event/source_scope/subscription_version/channel_version/generation/replay_generation/payload_digest；UNIQUE(event_id,subscription_id,subscription_revision,replay_generation)。手动replay产生新显式generation+原parent_delivery_id，自动retry沿用delivery ID。
- attempts有唯一delivery+attempt number，完成写一次不可更新；超时/网络结果unknown如实outcome=uncertain。event_deliveries达到succeeded/cancelled/exhausted后不能重开，重放另起generation；attempt时间/响应预算/状态码CHECK。
- personal notifications FK users；user_id不能改，read_at/dismissed_at只能首次设置，不用DELETE。批量ID100上限、owner集合必须精确，不允许混入另一owner后“部分成功”泄露存在性。
- channels/subscriptions/user subscriptions状态软删与deleted_at/retention_until成组；name不重用、scope/creator/创建时间immutable；密文v1格式CHECK只是格式，不当AEAD真实性校验。URL/auth AAD含channelCID/WID/id+credential_generation+用途，generation单调、变更目标不带旧token。
- `audit_export_jobs`增加 idempotency_key与actor+key唯一、完整HMAC请求绑定、terminal output封存、租约CAS和强制expiry。未决commit按原key重读，不另生成文件或重复导出；无可公开猜测下载路径。
- append-only角色whitelist与防错grant触发器包含全部旧+新表，真实non-super test逐表证明 UPDATE/DELETE/TRUNCATE拒绝；mutable表DELETE/TRUNCATE也显式revoke并加软保留触发器。
- migration只创建新表/FK/索引/trigger，不UPDATE audit_events/workflow_events；不seed外部URL或SMTP凭证，不启动worker，不修改.env或当前metrics/portal身份材料。

## 10. M7 待冻结 HTTP/DTO 清单

所有请求经BFF、统一response envelope，列表 `{items,size,total:null,nextCursor}`，无全量响应。row revision为正整数；未知字段拒绝。

| 方法/路径 | 请求 | 权限与结果 |
| --- | --- | --- |
| GET `/clusters/:cid/audit` | 第3节filter+workspaceId+size+cursor | 当前audit.read整区或可信历史资源scope；AuditSafeView默认隐藏全局chain sequence/head。 |
| GET `/audit/global`、GET `/audit/global/:eventId`、GET `/audit/global/integrity` | 仅 cluster_id/workspace_id 为NULL的真实global记录；有界filters/sequence | `assertConsole(user,'audit','read')`当前完整global grant，拒绝cluster/workspace限定角色；不把全局IAM/登录audit伪装在defaultcluster。 |
| GET `/clusters/:cid/audit/:eventId` | workspaceId（明确legacy/global模式） | 同list策略，IDOR403；不因知道UUID绕过scope。 |
| GET `/clusters/:cid/audit/integrity` | fromSequence,toSequence,cursor?；不得附workspace过滤 | 当前whole-cluster audit.read；安全report `verifiedFrom/verifiedTo/upperBound/complete/errors/nextCursor`。静态route先于:eventId注册。 |
| POST `/clusters/:cid/audit/exports` | filters、format `ndjson/csv` | audit.read+确认导出范围；x-idempotency-key，异步job receipt，导出只读原始配置且不要求audit.write。 |
| GET `.../audit/exports/:jobId`、GET `.../:jobId/download` | 明确scope | owner+原scope当前audit.read复验，no-store；expired或撤权无下载。 |
| GET/POST `/clusters/:cid/events/channels` | listscope；create name/type/endpoint/auth/options | read和wholeWS events.write分别；safeChannel含id/name/type/status/revision/generation/endpointHost脱敏，不返回tokenURL。 |
| PATCH/DELETE `.../channels/:id`、POST `.../:id/restore` | revision；删除/恢复confirmed+confirm_name | wholeWS events.write/delete；真实IAM或workflow receipt。 |
| POST `.../channels/:id/test` | revision,confirmed:true,confirm_name | 明确wholeWS events.write；创建一次受控delivery/test事件与原key回执，不同步调用第三方后伪成功。 |
| GET/POST `.../events/subscriptions`、PATCH/DELETE `.../:id`、POST `.../:id/restore` | eventTypes/nativeType/nativeIds/tags + revision/confirmation | 同tenant channel；logical tags先encode一次；写配置wholeWS events.write/delete并核验缩小的资源范围。 |
| GET `.../events/deliveries`、GET `.../:id`、GET `.../:id/attempts` | workspaceId、size/cursor/status/time | events.read + source事件可读范围；回显安全状态/耗时/固定errorCode，无原始provider响应。 |
| POST `.../deliveries/:id/replay` | revision,confirmed:true,confirm_name,reason? | events.write+current source/channel/subscription范围；新replay_generation、原历史不变。 |
| GET `/notifications`、GET `/notifications/unread-count` | clusterId?/workspaceId?/size/cursor/unreadOnly? | 当前consoleowner + notifications.read/current source范围；unreadCount仅授权owner子集，GLOBAL通知仅完整global权限。 |
| POST `/notifications/:id/read`、POST `/notifications/read-batch` | 单条ID；批量ids<=100,confirmed:true | current owner notifications.write +各source read；真实durable key回执，不修改正文。单条只读标记不要求批量确认，UI可限制当前页50条。 |
| GET/POST `/notifications/subscriptions`、PATCH/DELETE `.../:id`、POST `.../:id/restore` | explicitCID/WID+eventTypes/filter/flag/revision/confirmation | owner notifications.read/write/delete +source范围；选择外部channel还需events权限。 |

channels/subscriptions/test/replay在approvalcluster不能通过普通IAM direct handler跳过审批；使用固定metadata/workflow handler，投递只在真正terminal成功后的队列配置上开始。export/read标记不是Native配置写，但持久metadata状态同样需要真实回执；具体个人偏好是否不受clusterapproval、需Root在M7冻结前明确，不推断同意。

M6实际 Workflow kind 与 subject_type CHECK、`m6_validate_workflow_subject` 只含既定Portal表。因此SQL010需**增量**扩展 `workflow_definitions/workflows` kind与subject约束、新固定 `event-metadata` 计划/handler及该subject检查函数；同时Root/业务owner更新 compiler kind白名单与metadata registry，不假借 `portal-metadata` 名称。旧Portal版本、proof、step/cap/FK约束全部保留，审批能力只能来自真实新计划+当前授权。Channel审批create先保留hidden pending reservation固定ID/身份，不将未批准URL/config置active或投递；拒绝/过期留安全软状态。

原key恢复建议固定 `GET /clusters/:cid/events/operations/by-key/:key?workspaceId=原WID`：只查询当前actor+原CID/WID+真实管理handler命名空间下已有IAM/workflow receipt，不新造ledger、不开native调用、不按当前mode猜domain。返回 `{domain:'iam'|'workflow',receipt}` 与原动作安全summary；跨scope或另一个人的key404/403，不允许同key属于不同domain时任意选一个。客户端unknown状态保存原scope/key，不存URL/config/secret。导出jobs在自身actor+key唯一表恢复，通过独立export by-key read，不和事件配置domain混淆。

外部组织订阅的持续authority需Root明确：建议固定受管workspace/channel配置为服务器投递授权来源，个人订阅每次计算当前recipient grants；不得用失效JWT、退出的console session或作者历史grant缓存构造发送身份。若采用“配置授权人必须继续active/具当前events scope”的保守策略，需加入可见paused_authority状态与重新授权动作，不能隐蔽持续投递或静默丢弃。

## 11. 所有者切分与实施顺序（尚未执行）

1. Storage：SQL010、AuditOutboxWriter（DB-only，避免DI环）、EventRepository/OutboxRepository/Delivery lease+attempts、owner NotificationService、runtime rolegrant；先给Root/Front exacttypes和scope合同。
2. Root：App/worker生命周期/private投递能力、历史AuditScopePolicy/授权模块typed例外、审批metadatahandler边界及publicguards；审定全局与deleted workspace history读取和个人偏好审批策略。
3. Kong/业务owner：AuditQuery/Integrity/Export和channels/subscriptions管理、固定事件分类与证书/健康真实检测器；复用真实批准handler，绝不追加原生企业端点。
4. Front：audit filters/diff安全显示/导出、channels/subscription/forms、deliveries进度、owner通知角标和偏好、IAM/workflow原key未知结果恢复。
5. DevOps：固定出站allowlist/SMTP可选secret、worker限额/health、无外部账户的本地webhook/mail测试接收器与网络隔离；Security/Reviewer独立当前授权、scopeNULL、hash、SSRF/lease/attempt fault专项。
6. 合并顺序：合同冻结→迁移+repository隔离PG→事务producer无投递→本地loopback投递及retries→API/UI→统一source/typecheck→明确stage release→真实网关写入+本地通知收件证据→清理、密钥/导出扫描、M7 commit。每一步报告实际通过证据，不提前运行后台发送。

本清单不把建议所有权当已派发任务；Root正式安排后再编码。M6 owner源码、实际runtime、.env与当前Portal/metrics材料本轮均未改动。
