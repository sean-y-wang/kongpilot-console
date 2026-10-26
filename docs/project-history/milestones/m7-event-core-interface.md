# M7 Event Core 接口冻结候选

状态：**仅接口设计，产品实施未释放**。Root 已更正提前发布的指令：M6 实际验收与提交完成前，不写 SQL010 或 M7 产品文件。本文供 Audit、Events、Delivery、Notifications 所有者冻结依赖；下列文件与导出尚不存在。依据 [M7 实施合同](m7-implementation-contract.md)；旧设计稿中 64KiB/claim50/6 次的示例由本页保守预算替代。

## 1. 导出路径、预算与作用域

未来路径统一 `modules/event-core/`：`event.types.ts`、`event-access.ts`、`audit-outbox-writer.service.ts`、`event-repository.service.ts`、`outbox-repository.service.ts`、`delivery-repository.service.ts`、`notification.service.ts`、`notification-operations.service.ts`、`notification.controller.ts`、`event-core.module.ts`。Core 无网络、不注入 Audit/WorkflowEngine；Root 将 `EVENT_ACCESS` 绑定到历史权限 adapter，避免 Audit→Outbox→Audit 循环。DI/导出是否全局由 Root 安装，业务类不提供缺依赖 fallback。

| 常量候选 | 值 |
| --- | --- |
| `EVENT_PAYLOAD_MAX_BYTES` | 8192，按 UTF-8 序列化后的固定安全 envelope 计数 |
| `EVENT_SCOPE_MAX_BYTES` | 65536，服务器历史 before/after 归属证明，不公开原标签清单 |
| `EVENT_FANOUT_PAGE_SIZE` | 50，固定 keyset continuation |
| `DELIVERY_CLAIM_LIMIT` / `DELIVERY_CONCURRENCY` | 20 / 2 |
| `DELIVERY_MAX_ATTEMPTS` / `DELIVERY_MAX_AGE_MS` | 8 / 86400000 |
| `DELIVERY_LEASE_MS` / `DELIVERY_HEARTBEAT_MS` | 30000 / 5000 |
| `HTTP_DELIVERY_TIMEOUT_MS` / `SMTP_DELIVERY_TIMEOUT_MS` | 5000 / 15000，小于租约 |
| `NOTIFICATION_BATCH_LIMIT` / `LIST_MAX_SIZE` | 100 / 100，默认列表20 |

自动重试保持同 delivery ID/key。bounded jitter 与 Retry-After 最多1小时；第8次或事件/队列年龄达到24小时停止为 exhausted。claim 批量20不意味着并发20。最大 payload8KiB、HTTP响应8KiB、安全attempt无响应正文。配置变化、权限拒绝、策略拒绝均不会通过持续重试绕过。

```ts
type EventPhase = 'requested'|'node'|'aggregate'|'terminal'|'observation';
interface HistoricalEventScope {
  version:1; quality:'verified'|'legacy_unknown'; module:string;
  nativeType?:string; nativeId?:string; parentId?:string; credentialKind?:string;
  before:{workspaceId:string|null; physicalTags:readonly string[]}|null;
  after:{workspaceId:string|null; physicalTags:readonly string[]}|null;
  subject?:{type:string; id:string};
}
interface EventRecord {
  id:string; clusterId:string|null; workspaceId:string|null;
  eventType:string; phase:EventPhase; sourceKind:string; sourceId:string;
  actorType:'user'|'developer'|'system'; actorId:string|null;
  developerId:string|null; occurredAt:string;
  sourceScope:HistoricalEventScope; sourceScopeHmac:string;
  payloadSafe:EventPayload; payloadDigest:string;
}
```

nativeType/ID 用真实 typed child，固定八类核心实体、targets与六种credentialKind，不能将credentials泛型丢掉kind；metadata subject只固定允许的表/类型。Root已确认IAM的audit/events/notifications operational实体范围只允许这些typed原生实体，不将共享channel/subscription元数据提升为entity scope。before/after absent 表示真实创建/删除的不存在一侧，不是任意范围 wildcard。scope来自真实 Audit/业务元数据，client tags、当前实体GET、名字和旧缓存均不能形成历史权限。未知历史只 whole-cluster/global 或当前平台完整 grant。

`source_scope_hmac = fingerprint({version:1,eventId,auditEventId,auditEventHash,clusterId,workspaceId,scope})`；Audit scope注解使用 audit ID/hash 与 CID/WID上下文。全局CID/WID为NULL，不能默认归某cluster/workspace。事件payload只固定中文摘要、阶段/结果、当前已授权sourceUUID；不复制before/after/config/凭证/子图UUID。event scope仅服务器权限判断，公开projection删除原标签清单/HMAC。

## 2. SQL010 关键列冻结候选

实际列名全部 snake_case，`cid/wid`为下表缩写。所有新表加完整scope/identity FK；可空 scope 使用 CHECK 与实际源行比较，不能依赖 MATCH SIMPLE 规避跨租户验证。追加唯一目标 `(audit_events.id,event_hash)` 不更新旧审计正文或hash。

| 表 | 固定字段与关键关系 |
| --- | --- |
| `audit_event_scopes` | `audit_event_id PK,audit_event_hash,cid?,wid?,scope JSONB,scope_hmac,created_at`；append-only；exact Audit ID/hash与真实CID/WID；不改变旧链算法 |
| `event_records` | `id,cid?,wid?,event_type,phase,source_kind,source_id UUID,audit_event_id?,workflow_id?,mutation_id?,iam_operation_id?,portal_operation_id?,actor_type,actor_id?,developer_id?,entity_type?,entity_id?,source_scope,source_scope_hmac,payload_safe,payload_digest,occurrence_key,occurred_at,created_at`；source_kind对应明确FK列；`UNIQUE(source_kind,source_id,event_type,phase,occurrence_key)`；append-only |
| `event_outbox` | `id,event_id UNIQUE,state(pending/dispatching/dispatched/failed),revision,lease_owner_hash?,lease_generation,lease_until?,next_attempt_at,attempt_count,error_code?,subscription_upper_bound?,personal_upper_bound?,subscription_cursor?,personal_cursor?,subscription_complete,personal_complete,created_at,updated_at`；固定event不可改；progress/lease CAS |
| `notification_channels` | `id,cid,wid,name,type(webhook/email/slack/feishu),status(pending/active/disabled/deleted),endpoint_secret?,auth_secret?,options_safe,credential_generation,revision,created_by,updated_by,workflow_id?,deleted_at?,retention_until?,created_at,updated_at`；name/scope/creator不复用、不换；active必须有完整配置；pending reservation不投递 |
| `notification_channel_versions` | `cid,wid,channel_id,revision,status,type,endpoint_secret?,auth_secret?,options_safe,credential_generation,created_by,created_at`；append-only精确root版本；根引用current revision；不公开旧目标URL/token |
| `event_subscriptions` | `id,cid,wid,channel_id,name,event_types TEXT[],native_type?,native_ids UUID[],physical_tags TEXT[],status(pending/active/disabled/deleted),revision,created_by,updated_by,workflow_id?,deleted_at?,retention_until?,created_at,updated_at`；同tenantchannelFK；固定channel/creator；最多32types/256ids/256tags；native_ids不空则native_type必需 |
| `event_subscription_versions` | `sequence BIGSERIAL,cid,wid,subscription_id,revision,channel_id,status,event_types,native_type?,native_ids,physical_tags,created_by,created_at`；append-only；`UNIQUE(cid,wid,subscription_id,revision)`；稳定fanout上界按sequence，不按可变root读取旧revision |
| `event_deliveries` | `id,cid,wid,event_id,delivery_kind(subscription/test),subscription_id?,subscription_revision?,channel_id,channel_revision,credential_generation,creator_id,replay_generation,parent_delivery_id?,state(pending/claimed/sending/retrying/uncertain/paused_authority/succeeded/exhausted/cancelled),revision,lease_owner_hash?,lease_generation,lease_until?,intent_attempt_no?,intent_lease_generation?,intent_started_at?,next_attempt_at,attempt_count,idempotency_key,payload_safe,payload_digest,error_code?,expires_at,created_at,updated_at`；test无subscription；普通delivery完整subscription版本FK；固定creator/config/payload/key；terminal不重开 |
| `event_delivery_attempts` | `id,cid,wid,delivery_id,attempt_no,lease_generation,started_at,finished_at,outcome(succeeded/failed/uncertain),send_started,http_status?,duration_ms,error_code?,retryable,created_at`；append-only；`UNIQUE(delivery_id,attempt_no)`；无response正文 |
| `user_notification_subscriptions` / `_versions` | root `id,user_id,cid,wid,name,event_types,native_type?,native_ids,physical_tags,in_app_enabled,status,revision,deleted_at?,retention_until?,created_at,updated_at`；version追加sequence/配置快照；owner身份固定、仅站内，不借个人偏好发送外部渠道 |
| `user_notifications` | `id,user_id,cid?,wid?,event_id,title,summary_safe,link_kind,link_id?,revision,read_at?,dismissed_at?,created_at`；`UNIQUE(user_id,event_id)`；owner/body/event固定；read/dismiss只能一次设置 |
| `event_detection_observations` | `id,cid,wid,detector_key,subject_type,subject_id,transport_scope,observed_node_id?,cluster_revision,workspace_revision,config_fingerprint,scope_epoch,observed_at,quality,source_scope,source_scope_hmac,observation_safe,observation_hmac,occurrence_key,created_at`；append-only；exact typed source pointer，字段与第14节一致 |
| `event_detection_state` | `cid,wid,detector_key,subject_type,subject_id,transport_scope,observed_node_id?,config_fingerprint,scope_epoch,last_observation_id,last_observation_safe,observation_fingerprint,last_observed_at,revision`；只CAS进度；immutable观察FK，字段与第14节一致；不能成为event读取权限 |
| `audit_export_jobs` | `id,actor_id,cid?,wid?,idempotency_key,request_hash,filter_safe,upper_bounds,permission_version,state(queued/running/succeeded/incomplete/failed/cancelled/expired),revision,row_count,bytes_count,digest?,output_secret?,lease_owner_hash?,lease_generation,lease_until?,error_code?,expires_at,created_at,updated_at`；actor/key唯一、scope/current grant；输出材料密封、opaque非HTTP下载路径 |

channel options安全白名单由Devops provider冻结；EMAIL收件人身份也属加密endpoint材料，不放options_safe。AAD已协调：`event-channel:<id>:<cid>:<wid>:<credential_generation>:endpoint|auth`。目标更换递增generation，不能携旧host token到新host；只备注/状态更新可保留完全未变密文。root每版本更新在同TX插version，deferrable FK/trigger保证完整；版本history不可后补篡改。

普通delivery唯一 `(event_id,subscription_id,subscription_revision,replay_generation)`；test唯一采用 `(event_id,channel_id,replay_generation)` partial index。每个explicitreplay新增generation和parent_delivery_id，不更新旧attempt或terminal。replay继承不可变sourceevent、安全payload与当前channel/subscription配置，全部当前权限重查，不把旧目标secret用于当前endpoint。generation由锁定root parent再按该source/subscription族计算，客户端不能传。

## 3. Root EventAccess adapter

未来 `event-access.ts` 导出 `EVENT_ACCESS = Symbol('EVENT_ACCESS')` 与interface。Core没有访问控制fallback；所有private sourceproof与worker proof由Root读当前DB权限实现。

```ts
interface EventAccess {
  permissionVersion(actor:AuthUser):Promise<string>;
  assertSourceRead(actor:AuthUser, event:EventRecord,
    module:'events'|'notifications'|'audit'):Promise<void>;
  canSourceRead(actor:AuthUser,event:EventRecord,
    module:'events'|'notifications'):Promise<boolean>;
  assertWholeWorkspace(actor:AuthUser,cid:string,wid:string,
    module:'events'|'notifications',action:'read'|'write'|'delete'):Promise<void>;
  assertDeliveryCurrent(claim:DeliveryClaim):Promise<DeliveryAuthorityProof>;
  assertNotificationOwner(actor:AuthUser,ownerId:string,
    cid:string|null,wid:string|null,action:'read'|'write'|'delete'):Promise<void>;
  assertObservationCurrent(input:DetectorObservationInput,tx:DbService):Promise<void>;
}
interface DeliveryAuthorityProof {
  readonly actorId:string; readonly permissionVersion:string;
  readonly channelRevision:number; readonly subscriptionRevision:number|null;
  readonly credentialGeneration:number; readonly sourceProofDigest:string;
}
```

`assertDeliveryCurrent`读取真实active deliverycreator **及 channelcreator** 的当前grants与source历史scope，两人均需当前wholeWS events.write与source events.read，以及根channel/subscription active且revision/generation精确。testcreator是明确测试配置写的consoleactor；普通投递creator是订阅版本作者，不接受worker伪AuthUser或历史JWT。任一作者停用/撤权为诚实 `paused_authority`，不暗中换systemadmin重新授权；暂停不进入claimDue。恢复必须原授权条件真正恢复并显式受控重放/重新配置，旧事实和发送意图保留。

module/action/typedID/tag/before+after需同一完整grant；metadatawholeWS不由entity/taggrant提升。每列表批末、unread-count末、payload发送前复核permissionVersion。`canSourceRead`只能捕获真正授权403，不吞数据库错误当无数据。global通知当前完整global通知权限；deleted/disabledworkspace历史读由Root政策明确定义，不调用active-write resolver把历史错误重标为default。

## 4. Audit outbox writer 与事件查询

```ts
interface AuditOutboxReceipt {
  id:string; chainScope:string; sequence:string; eventHash:string; occurredAt:string;
}
interface TrustedAuditScopeHints {
  quality:'verified'|'legacy_unknown'; module:string;
  nativeType?:string; nativeId?:string;
  beforeTags?:readonly string[]; afterTags?:readonly string[];
  beforeExists?:boolean; afterExists?:boolean;
  beforeWorkspaceId?:string|null; afterWorkspaceId?:string|null;
  parentContext?:{nativeType:string; nativeId:string; credentialKind?:string};
  subject?:{type:string; id:string};
}
class AuditOutboxWriter {
  fromAudit(receipt:AuditOutboxReceipt,hints:TrustedAuditScopeHints,
            tx:DbService):Promise<{eventId:string}|null>;
}
```

writer在同tx读取真实audit row与receipt.id/hash/chainScope/sequence/occurredAt，事件根CID/WID只来自真实row，不由receipt或HTTP指定。历史scope的beforeWorkspaceId/afterWorkspaceId分别由producer在操作当时提供真实已核验归属；跨工作区迁移不能把audit row单一workspace_id复制到两侧，也不能通过当前WorkspaceResolver或保留tag事后解析。两侧存在性、归属、tags使用显式服务器证据；`undefined`归属不等于全局NULL，任一真实存在侧缺可信归属则legacy_unknown。固定action/result→eventType/phase白名单；未知或内部派生非业务action可返回null，不接受客户端自由payload。hints仅可信server调用者提供；没有真实nativeID/类型/父上下文/前后tags采样则legacy_unknown，不按当前GET/tag索引回填；`undefined` tags与真实`[]`不能混用。只从safe receipt/source固定字段生成EventPayload；重复调用同source/occurrence返回同event与outbox。scope注解/id/hash/事件/outbox均同TX，rollback后无fanout。Audit.append旧调用方可忽略新返回值；Root安装writer，不产生DI环。

EventRepository未来 `get(id)`, `list(actor,query)`；公开GET只返回SafeEventView，经EventAccess当前source检查与脱敏。Detector只使用第14节冻结的 `enqueueObservation(input,tx)`；不公开通用 `appendTrusted`、HTTP append或任意 eventType/payload callback。source pointers row触发器验证实际OID/完整CIDWID一致；只写UUID不构成真实terminal成功证明。

## 5. 稳定 fanout continuation

认领outbox后第一次同TX保存 `MAX(event_subscription_versions.sequence)` 与personal version上界。每个subscription选择不超过上界的最新snapshot版本，按稳定(subscription ID/版本) keyset固定50续扫；root已更新/停用时旧snapshot仍是已冻结候选，freshcurrent检查会取消/跳过它，不偷换成新版本。

每页同TX插幂等delivery/owner notification并CAScursor+leaseGeneration；订阅和个人两路都complete才dispatched。超过50项、空匹配页、worker崩溃后恢复均继续后页。Root已冻结：无隐式广播全部users；personal仅显式activein-app偏好候选，再当前recipient权限过滤。新注册偏好不自动得到早于upperbound的所有历史事件。

```ts
interface OutboxRepository {
  claimDue(input:{owner:string;limit:number;leaseMs:number}):Promise<OutboxClaim[]>;
  fanoutPage(claim:OutboxClaim):Promise<{complete:boolean;created:number}>;
  release(claim:OutboxClaim,errorCode:string,retryAt:string):Promise<boolean>;
}
```

Root access与recipientgrants复核不跨网络；未知Authz/DB错误不推进cursor表示已跳过。不得在DB rowlock内逐收件人进行网络投递。fanout只准备数据，deliveryworker单独执行。

## 6. Delivery 认领、意图、完成与过期恢复

```ts
interface DeliveryClaim {
  readonly deliveryId:string; readonly eventId:string;
  readonly clusterId:string; readonly workspaceId:string;
  readonly deliveryKind:'subscription'|'test';
  readonly subscriptionId:string|null; readonly subscriptionRevision:number|null;
  readonly channelId:string; readonly channelRevision:number;
  readonly credentialGeneration:number; readonly creatorId:string;
  readonly leaseOwner:string; readonly leaseGeneration:number;
  readonly leaseUntil:string; readonly attemptNo:number;
  readonly idempotencyKey:string; readonly payloadSafe:EventPayload;
  readonly payloadDigest:string;
}
interface DeliveryOutcome {
  outcome:'succeeded'|'failed'|'uncertain'; sendStarted:boolean;
  httpStatus?:number; durationMs:number; errorCode?:string;
  retryable:boolean; retryAfterMs?:number;
}
class DeliveryRepositoryService {
  claimDue(input:{owner:string;limit:number;leaseMs:number}):Promise<DeliveryClaim[]>;
  commitSendIntent(claim:DeliveryClaim):Promise<boolean>;
  assertLeaseCurrent(claim:DeliveryClaim):Promise<void>;
  renewLease(claim:DeliveryClaim,leaseMs:number):Promise<boolean>;
  finalize(claim:DeliveryClaim,outcome:DeliveryOutcome):Promise<boolean>;
  recoverExpiredIntents(input:{limit:number}):Promise<number>;
}
```

claim从SQL真实row+event/config版本生成冻结对象，服务器登记不可复制标识，caller spread/JSON clone不作为可信claim。owner随机opaque值只存HMAC；lease generation严格递增。`commitSendIntent`同TX CAS claimed→sending并durable保存本次attempt/generation/startedAt，提交后才准许provider准备；重复同claim返回原intent状态，不多增attempt。

intent前、DNS后、TLS后以及HTTP创建或SMTP AUTH/DATA前，worker同时调用EventAccess.assertDeliveryCurrent与assertLeaseCurrent；同步最终fence是Devops私有transport能力，不靠UTC字符串假授权。claim/lease断开永久关闭socket，latecontinuation零packet。Repository assert不替代当前source/config权限。

finalize只接受exactclaim/generation与原intent，append一次完整outcome再CAS队列。succeeded不重开；failed不可重试为exhausted/cancelled安全reason，retryable或uncertain按bounded次数/24h重试同ID/key。send_started=false只有实际证明未发时才可用；unknown不写false。过期sending先为旧intentappenduncertain、CAS清intent/旧lease后再认领；旧ACK finalize=false不能更新那条immutable uncertain。过期claimed且无intent可重认领，不伪造attempt。finished≥started、duration finite/nonnegative、httpStatus100..599、errorCode固定安全码，无任意provider message。

`getDelivery(id)`和`listAttempts`服务端有界；channelmaterials私有 `loadChannelSecrets(claim)`仅返回RAM解密值给provider，读取前后tuple/lease/generation复验，HTTP不导出秘密。渠道AAD冻结如第2节；auth/token不能写claim公开safe DTO或日志。

## 7. 渠道测试与手动 replay 的 DB-only 接口

```ts
interface QueueMetadataReceipt {
  actorId:string; clusterId:string; workspaceId:string;
  auditReceipt:AuditOutboxReceipt;
  iamOperationId?:string;
  workflow?:{id:string;executionId:string;planRevision:number;planHash:string;stepId:string};
}
EventRepositoryService.enqueueTest(input:QueueMetadataReceipt&{
  channelId:string;channelRevision:number;credentialGeneration:number;
},tx:DbService):Promise<{eventId:string;deliveryId:string}>;
EventRepositoryService.enqueueReplay(input:QueueMetadataReceipt&{
  deliveryId:string;expectedRevision:number;
},tx:DbService):Promise<{eventId:string;deliveryId:string;replayGeneration:number}>;
```

test不用fake订阅：delivery_kind=test，subscription_id/revision必须全NULL；明确当前channel exactrevision/generation与actor，actor配置write/test审计为真实success。普通delivery_kind=subscription要求完整same-tenant subscription/version/channel FK。queue不能立即网络发送，只有同TX真实IAM成功或workflow固定metadata terminal提交才可投递。IAM callback时op尚running可使用DEFERRED terminalfact验证，workflow finalstep同理；失败/rollback不能留下可见测试delivery。服务签名不能接受operationId“授权”，会实际读其当前完整actor/CID/WID/module/action/target/plan/terminal tuple。既有fromAudit若产生testrecord，enqueue幂等复用同source，不多发另一test。

replay.expectedRevision取真实 `event_deliveries.revision`；不取attempt number或planversion。锁原delivery、核验原sourcecurrent可读、wholeWS配置写与当前channel/subscriptionactive，再创建新revision/generation目标tuple。旧成功/耗尽/未知attempt不改；正在sending/未决原intent不可用replay生成新队列逃过未知，需明确只读reconcile/原key先核验。原请求key相同返回真实parentreceipt+同deliveryID，不新分配replaygeneration。

未来独立event-metadata subjects：`notification_channels/event_subscriptions/event_deliveries`；handlers：`event.channel.save/status/delete/restore/test`、`event.subscription.save/delete/restore`、`event.delivery.replay`。SQL010需显式kind/subject/validator增量，旧Portal V1保持。Kong负责compiler与metadataverifier新分支；Storage仅做exactqueuedfacts约束，不能以tx、workflowId或任意callback绕过批准。

Root已冻结接线：普通 IAM.execute callback 兼容新增服务器参数 `fn(tx,operationId)`，旧单参数调用方不变。event-metadata handler在真实配置SQLCAS后、enqueue前，同TX写自己的真实business success Audit，使用真实before/after行生成receipt；Engine仅对event分支复验实际audit row的actor/CID/WID/step subject/action/hash/success，并跳过重复generic step success Audit。父workflow terminal Audit保持。Portal原分支不变，不在apply前将计划after写成实际成功。queue携服务器execution tuple，以deferred约束在最终commit复验parent terminal；receipt与operationId本身均不是客户端可提交的执行授权。

## 8. Owner Notifications HTTP、严格 DTO 与回执

未来controller `/notifications`（统一 `/api/v1`）绑定当前consoleuser，拒绝body/query.userId；不服务Portaldeveloper。

| 方法/路径 | 明确DTO与响应 |
| --- | --- |
| GET `/notifications` | `{clusterId?,workspaceId?,size?,cursor?,unreadOnly?,dismissed?}`；workspace必须配cluster；无scope只聚合当前owner当前可读事件，签名bounded keyset，不称完整cluster目录 |
| GET `/notifications/unread-count` | 同scope，不接cursor；返回 `{unreadCount,complete}`；遇budget返回不完整标记，不泄未授权总数 |
| GET `/notifications/:id` | `{clusterId?,workspaceId?}`；owner+actualsource scope；安全正文/no原标签或HMAC |
| POST `/notifications/:id/read` / `/:id/dismiss` | `{revision}`；当前owner/sourceread+notifications.write；返回 `{notification,receipt}` |
| POST `/notifications/read-batch` / `/dismiss-batch` | `{clusterId,workspaceId,items:[{id,revision}],confirmed:true}`，1..100实际ID；全部sameCID/WID/owner且权限通过才TX执行，mixedowner/scope零修改 |
| GET `/notifications/preferences` | `{clusterId,workspaceId,size?,cursor?}`；本人当前notifications.read与source范围 |
| POST/PATCH `/notifications/preferences[/:id]` | create `{clusterId,workspaceId,name,eventTypes,nativeType?,nativeIds?,tags?,inAppEnabled}`；patch再revision；tags只logical，encode一次；不可改owner/CID/WID |
| DELETE/POSTrestore `/notifications/preferences/:id[/restore]` | `{revision,confirmed:true,confirm_name}`；确认名由server给安全name，当前owner/source/notifications.delete或write |
| GET `/notifications/operations/by-key/:key` | 原scope/key当前owner，只读取真实 `iam_operations` 且固定personalhandler命名空间；不导出其他IAM操作 |

SafeNotification字段 `{id,clusterId,workspaceId,eventId,title,summary,link:{kind,id}|null,revision,readAt,dismissedAt,createdAt,capabilities}`。GET source撤权后403或列表omit/计数不含，真实权限错误与DB错误区分。正文固定server模板，无用户Markdown/HTML/原before/after。read/dismiss时间单向；对已设置状态同原key replay不重复advance revision。

Personalmetadata按Root已决定政策不经集群共享审批。Root已冻结专用 `NotificationOperationsService`：仅固定owner-only通知/偏好SQLwriter，复用现有 `iam_operations` 实际ledger，不新增通知ledger或泛用IAMapproval绕过。模块/action/payload身份固定 `notifications.personal.read/dismiss/preferences.save/delete/restore`；**原始 X-Idempotency-Key不改写、不加前缀**，actualactor/rawkey唯一、完整hash/scope与原键恢复。服务锁定owner rows/revision，重新验证当前notifications权限与source范围；无HTTPallowDirect字段，不接受任意module/handler/callback。

单条/批量当前actor/CID/WID/key/bodyHMAC/加密result/durable终态/审计同TX；未知commit重新读取原IAM成功，不覆盖为failed。`/notifications/operations/by-key`为同ledger的owner-only专用投影，只允许上述handler命名空间与当前原scope/source权限；前端回执域引用此resolver，不按当前cluster模式猜测。read/dismiss/preference内部审计不派生新的同类通知以免反馈循环。`/events/operations/by-key`仍只投影共享events的真实IAM/workflow，不接个人通知scope替换。

## 9. 释放前待共同审定

Root已接受Auditreceipt/fromAudit/historicalSourceScope、owner专用IAMwriter、explicitprefs-onlyfanout、deliverycreator与channelcreator持续当前权限。剩余EventAccess实际导出methods、global/deletedworkspace历史读细节需与Root实现一次核对；Kong确认root/version列、queue真实terminalreceipt与metadatahandler；Devops确认DeliveryClaim test nullabletuple、AAD、8KiB/20/2/8次24h与SMTP多阶段fence。Reviewer据此独立验证historysamegrant、foreignscope、>50fanout、latelease、mixedowner IDs。正式SQL010/源码只能在M6 actual+commit明确释放后创建；本文不替代后续真实non-superPG/回滚/并发租约/本地收件器验收。

## 10. 接入已有 producers 的精确清单

Audit.append未来 `append(event:{...existing,scopeHints?:TrustedAuditScopeHints},tx?):Promise<AuditOutboxReceipt>`。它保持原十九字段/hash不变，chain head UPDATE后在同TX调用writer；无scopeHints的旧调用方一律legacy_unknown，不从已脱敏after或当前Native/index/WorkspaceResolver推导history。调用方不能通过HTTP/body传scopeHints。未知记录仍可进入审计；writer未知action返回null，不把所有内部audit自动通知。

| 现有调用点 | future可信证据与必要限制 |
| --- | --- |
| MutationService成功事务，当前readBack之后 | 核心八类 `nativeType=context.entityType,nativeId=readBack.id`；before从已锁内核验context.before，after从刚验证真实readBack；各侧存在性、物理tags、已证明WID分别保存。新create无before、真实after；普通update两侧同已核验WID。不得从plannedpayload当已生效after。metadata/domainwrapper不是原生对象，必须固定subject或unknown。 |
| Mutation Targets/credentials成功 | nativeType使用targets或实际六种credentialKind；parentContext明确upstreams/consumers原生ID。WID来自请求期间已核验父归属；child实际业务tags分别保存，不将父tag union冒充child授权。Target新有效ID按实际readBack记录；旧historyID与新ID关系只服务器固定subject，不让旧IDgrant授权新ID。 |
| Mutation requested/blocked/failed/uncertain | pendingpayload不是实际after；未知remote结果不宣称delete/create成功。缺完整历史侧证据保持legacy_unknown，phase/action/result明确pending或uncertain；不派生成entity.changed terminal。knownfailed也不靠结果标签填伪after。 |
| Recycle逐node delete成功，404/有效Target集合验证之后 | before=node.data或已核验current；after不存在。真实node.type/id及graph捕获与当前loop核验的父上下文/WID。只为affected node发node事件，reference不发删除；archive/parentaggregate只计数，不复制children ID。 |
| Recycle逐node restore成功，真实readback之后 | 创建前已证404则before不存在；retry遇existing对象则使用刚核验existing为before，不能总写beforeExists=false。after=restoredObject；Target可能新ID，不能用originalID替代after授权对象；必要时该ID变化标unknown或仅完整whole scope查看。每个node独立，不借根对象grant看到其他子对象。 |
| WorkspaceMigrationService.recordStep的succeeded分支 | beforeWorkspaceId=node.sourceWorkspaceId，afterWorkspaceId=sealed target_workspace_id且已fresh核验目标；beforeTags=node.data.tags，afterTags=刚验证data.tags。根audit.workspace_id仍source不能复制两侧。Targets inheritedOnly无tagPATCH，tags可能未变，但before/afterWID必须分别源/目标且parentContext=Upstream；credential业务tags/实际parent同样分开。failed/uncertain无真实after则unknown。 |
| workspace migration父结果、reconcile、impact.claimed、scope_bound | 固定metadata subject或纯聚合安全计数，不从plan的所有节点拼成一条tag-group授权，也不生成重复逐对象changed事件。未来检测器使用真实observation/完整scope，不能自动继承Mutation nativewrite身份。 |
| Workflow/IAM/Portal业务metadata | 纯metadata固定subject+真实CID/WID与已核验rowrevision，通常wholeWorkspace权限；Service关联业务可由发生当时sealed/fresh业务subject证明单个nativeService。Portaldeveloper actorId仍NULL，仅developerId安全上下文，不假consoleuser。 |

producer应在最终事务调用Audit之前将scopeHints整理成bounded副本，避免await期间修改源对象。Root负责producer接入与历史授权adapter；Storage writer仅校验结构、source上下文/HMAC并持久化，绝不网络或回查当前实体。历史多workspace/multiple-native-ID的事实不塞进单一nativeId来假装完整，可拆逐对象event或用whole-scope aggregate/unknown。

## 11. 不可变 hash/scope 证明与运行角色

- 原hash输入精确十九字段，sequence十进制bigint字符串，occurred_at原UTC毫秒ISO；新annotation/event不改老SHA、row或head历史。SQL010可新增 `audit_events UNIQUE(id,event_hash)` 支撑annotation复合FK，不更新既有行。
- audit_event_scopes固定auditID/eventHash/CIDWID与scopeJSON/HMAC；SQLtrigger读取实际audit row，用 `IS DISTINCT FROM` 检查NULLscope，禁止foreignrow/crossCID或WIDwithoutCID。before/afterWID可以不同但必须属于同实际CID，不能仅MATCHSIMPLE nullableFK。原已删工作区元数据仍保留FK历史，不映射default。
- Scope HMAC/AAD上下文包含version、eventID、auditID、原eventHash、实际CIDWID、完整scope内容。writer实际核验receipt精确chain/seq/hash/time；Root adapter在授权前校验HMAC。摘要无parent children IDs或rawtag清单。加注解自身可验证不代表原chain已包含新字段。
- event_records固定source_kind与明确FK指针，sourceID/eventType/phase/occurrence唯一；source pointers trigger检查实际同scope、actor和允许的真实source阶段。terminal success事件须实际source terminal事实或同TXdeferred证明，不能用receipt UUID/任意workflowId伪造。
- runtime immutable whitelist新增 `audit_event_scopes,event_records,notification_channel_versions,event_subscription_versions,user_notification_subscription_versions,event_delivery_attempts,event_detection_observations`，保持既有immutable集合；仅SELECT/INSERT，REVOKE UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER。各表owner-side防误修改trigger同样拒UPDATE/DELETE/TRUNCATE；runtime角色本来不是owner/superuser。
- outbox/delivery/rootpreferences/notifications/exportjobs可更新progress，但identity/payload/creator/scope/source/原key/hash/createdAt不可改；soft-delete表禁止物理DELETE/TRUNCATE。租约generation、固定tuple与terminal单向状态由SQLtrigger/CAS验证，不依赖UI。

## 12. audit_export_jobs 给 Root 的 SQL010 约束合同

该表是当前owner的有界只读导出job，不成为audit.write接口或分享下载能力。SQL010由Storage落DDL，Root owns repository/API/export runner；实际实现前按本节对齐字段，不在未来code猜column。

固定列：`id,actor_id,cluster_id?,workspace_id?,idempotency_key,request_hash,format(ndjson/csv),filter_safe,upper_bounds,permission_version,state,revision,row_count,bytes_count,digest?,output_secret?,lease_owner_hash?,lease_generation,lease_until?,error_code?,expires_at,created_at,updated_at`。`UNIQUE(actor_id,idempotency_key)`；scope CHECK和复合workspace FK；upper_bounds按真实chain保存sequence十进制字符串/hash，JSON必须有界对象。request_hash绑定actor、actualCIDWID、format及完整filter；没有任意userId、SQL排序字段、path、URL或文件名输入。

| trigger/constraint | 要求 |
| --- | --- |
| immutable request | actor/CIDWID/id/key/hash/format/filter/upper_bounds/permission_version/expires_at/created_at建后不变；同key不同请求409，不能改条件扩大下载。 |
| lease progress | state queued/running/succeeded/incomplete/failed/cancelled/expired；running租约ownerhash/until成组、generation递增，finished旧lease不得提交新的output。row_count/bytes_count/revision单调，updated_at>=created_at。网络/导出stream不握DB行锁。 |
| sealed output | output_secret必须AEAD格式，terminal publication只允许set一次；digest与精确输出bytes对应。AAD固定 `audit-export:<id>:<actorId>:<clusterId-or-global>:<workspaceId-or-global>:<requestHash>:output`。材料不包含未脱敏before/after、公开文件路径或外部URL。 |
| terminal completeness | succeeded/incomplete必须明确完成或budget截止状态，并有封存output/digest；failed/cancelled不声称完整输出；所有终态不可running重开。超100k行/32MiB仅诚实incomplete，不能静默称全量。 |
| expiry | expires_at原请求固定；到期可单向expired并清output_secret，保留身份/计数/digest/错误历史。不得延长expires或以新lease给旧下载权限续期；真实backup/WAL保留另按运维政策，不声称此清材料即全备份物理消失。 |
| current owner read | claim每批重载真实active creator与currentaudit.read历史scope，无假HTTPsid；afterawaitpermissionVersion一致。下载同源当前owner+原scope+当前grant+未过期+digest验证，旧signedcursor/URL/receipt不是授权。SQLFK只做结构，当前RBAC由Root实现。 |
| rollback/unknown | job request与对应真实receipt同TX；输出发布租约CAS失败零公开结果。未知COMMIT重新读原actor/key/job，不另创建第二job，不能将已committedsucceeded覆盖failed。 |

formats只安全NDJSON/CSV，CSV防公式前缀；fixedbytesbuffer或私有加密material，no-store下载。链验证与导出各自预算和授权：导出已过滤历史不等于完整链有效，不能公开链上界/未授权计数给受限用户。globaljob仅真实NULLscope，不能赋默认cluster。

## 13. 最终设计接线确认

Kong与Devops已确认 `EventRepositoryService.enqueueTest/Replay(input,tx)` 和 `DeliveryRepositoryService` 第6节methods；Kong确认用真实delivery.revision。Root确认Event branch实际business Audit afterSQLCAS/同TXqueued/deferred parentterminal和IAM callback服务器operationId；旧Portal branch保持。Shared subscription matcher：eventTypes内OR、nativeIds内OR、业务tags全部AND，各类条件之间AND；CIDWIDexact，logicaltags只encode一次并拒reservedWS。tags在一个完整存在侧匹配，不合并before/after标签形成虚构交集；filter仅缩小候选，不提升EventAccess授权。首版typedUUID过滤可不要求native当前存在，比较可信historical nativeType/ID，不用配置read下载全部实体或按name解析。

未来编译导出清单：event.types导出本页Event/Scope/Claims/Outcome/SafeDTO/QueueMetadataReceipt及第14节Detector types与常量；event-access导出EVENT_ACCESS/EventAccess/DeliveryAuthorityProof；classes为AuditOutboxWriter、EventRepositoryService、OutboxRepositoryService、DeliveryRepositoryService、NotificationService、NotificationOperationsService、NotificationController、EventCoreModule。当前这些文件都未创建。Root安装依赖后不设缺依赖fallback；正式释放后Storage最先落types/SQL010草稿给所有owners再并行实现，每个实际method有typed参数和scopeproof，不用any当批准。

## 14. Detector 唯一 DB-only 入口冻结

本节落实 Root 最新决定，替代旧检测提案“首次已近到期即可通知”的分支：**首次完整采样只建基线；配置、节点或归属变化后的首次采样也只重建基线**。当前仅文档，SQL010、产品文件、采样和测试均未释放。Root owns 实际有界证书/健康 sampler、私有 GET-only purpose、源新鲜度证明；Storage owns 下面的 immutable source/HMAC、baseline CAS、事件/outbox同事务。不注入 Audit、Kong、Engine或网络 provider，不创建新的审批/Native能力。

```ts
type DetectorKey='certificate.expiry.v1'|'upstream.health.v1';
type DetectorSubject='certificates'|'ca_certificates'|'upstreams';
type ObservationQuality='verified'|'partial'|'unavailable'|'invalid'|'stale';
type SafeObservation=
  |{kind:'certificate_expiry';expiresAt:string} // finite UTC 毫秒 ISO
  |{kind:'upstream_health';health:'healthy'|'unhealthy'|'degraded'|'checks_off'};
// 唯一 mint 方是 Root 的真实固定 sampler；私有登记，不可 spread/JSON复制。
interface TrustedObservationProof {readonly __trustedObservation:unique symbol}
interface DetectorObservationInput {
  observationId:string; actorType:'system'; actorId:null;
  clusterId:string; workspaceId:string; detectorKey:DetectorKey;
  subjectType:DetectorSubject; subjectId:string;
  transportScope:string; observedNodeId:string|null;
  clusterRevision:number; workspaceRevision:number;
  configFingerprint:string; scopeEpoch:string;
  observedAt:string; quality:ObservationQuality;
  sourceScope:HistoricalEventScope;
  observationSafe:SafeObservation|null;
  beforeBaselineRevision:number|null;
  sourceProof:TrustedObservationProof;
}
interface ObservationReceipt {
  observationId:string; baselineRevision:number;
  disposition:'baseline_created'|'baseline_reset'|'unchanged'|'candidate'
    |'event_queued'|'quality_only'|'duplicate';
  eventId:string|null; outboxId:string|null;
}
EventRepositoryService.enqueueObservation(input:DetectorObservationInput,
  tx:DbService):Promise<ObservationReceipt>;
// EVENT_ACCESS 必需新增方法；Root adapter验证真实私有源，不是观察HTTP授权。
EventAccess.assertObservationCurrent(input:DetectorObservationInput,
  tx:DbService):Promise<void>;
```

`certificate.expiry.v1`只配certificates/ca_certificates，`upstream.health.v1`只配upstreams；真实 native UUID是单个 typed subject。无父/Target/credential列表。actor固定system/null，不能接受用户、开发者、假SID或自由actor。`sourceScope.quality`必须verified、module='events'、nativeType/ID精确subject；before/after都为当前实际同WID/同physicalTags的观察范围。发生时的归属由Root原始采样核验，不由Core查询当前tag索引补成历史。多标签/unknown/deleted归属无法证明时丢弃该候选，不归default；非verified观察质量也不能借legacy_unknown制造事件。

### 14.1 字段来源、fresh fence与hash

| 字段 | 固定解释与校验 |
| --- | --- |
| `transport_scope` | 已登记端点实际canonical scope或显式shared scope的hex64；Root在网络采样前后核验。不是DNS解析/IP猜测，也不是Kong node UUID。重绑CID不能沿用旧scope。 |
| `observed_node_id` | fresh GET `/` 实际返回的Kong节点identity，最多256字节；缺失为NULL。健康verified必须非NULL且前后同节点；证书读取无节点证明可NULL。不得用metrics `node_id=transport_scope`冒充实际节点。 |
| `cluster_revision/workspace_revision` | 采样时真实可变registry版本。提交事务锁/核验同CID/WID root且active/notdeleted、当前版本exact，版本变化拒绝本次发布，不把旧观察“更新”为新版本。 |
| `config_fingerprint` | Root对实际已读取原生配置、证书leaf/expiry或完整当前Target membership及healthcheck配置，加captured注册端点/版本身份所作的SecretService HMAC。只有hex64入库；无计划body、PEM、私钥、名称、地址或子ID向量。未知/截断集合不生成verified值。 |
| `scope_epoch` | 独立detector归属HMAC：`fingerprint({version:1,clusterId,workspaceId,subjectType,subjectId,sourceScope})`。来自真实当时WID/tags；不是M5 traffic epoch、不复用当前索引、不按旧事件重分类。业务tags/归属改变必须改变epoch。 |
| `observed_at` | 实际该观察完成时间，finite UTC毫秒ISO；Root proof包含真实开始/结束与注册purpose，不接受未来时间、人工日期或“计划生效时间”。提交时最多15秒old；超时丢弃，不靠重复claim/DB刷新延长。 |
| `quality/observation_safe` | verified必须有匹配detector的严格安全union；其他质量value=NULL。certificate只expiryUTC；health只上述规范枚举，Root由实际完整1.5响应映射；未知enum、空/截断/权限projection、网络错误不当healthy/unhealthy。无PEM、Subject/SAN、Target地址、childIDs或raw response。 |
| `beforeBaselineRevision` | 首行不存在必须NULL（并发INSERT只一个赢家），存在必须exact正整数revision；NULL不是跳过CAS。调用者从服务器DB调度记录拿值，HTTP不能指定。 |

Root `assertObservationCurrent` 在持有真实tx的入库前和最终CAS/event/outbox后各执行一次：重新验证不可复制proof与input全部字段、有效固定purpose/完整实际source、实际current registry/WS版本、physical scope、节点、配置/归属HMAC、≤15秒 freshness及没有未决或介入的same-physical-scope变更。Root sampler使用受控观察/变更互斥或实际write-fence代际证明跨网络await一致；旧index、旧metrics catalog、裸timestamp/哈希值本身不是fresh proof。该检查不在Core内发网络请求，不把tx参数、quality='verified'或HTTP JSON当能力。失败全部回滚，不能写一条“已观察”再随后异步补权限。

Core生成immutable observation的 `source_scope_hmac=fingerprint({version:1,sourceKind:'observation',observationId,clusterId,workspaceId,scope:sourceScope})`；`observation_hmac=fingerprint({version:1,observationId,actorType:'system',actorId:null,clusterId,workspaceId,detectorKey,subjectType,subjectId,transportScope,observedNodeId,clusterRevision,workspaceRevision,configFingerprint,scopeEpoch,observedAt,quality,sourceScopeHmac,observationSafe})`。原audit SHA19字段完全不参与或改变。

### 14.2 baseline CAS、first sample和dedup

一次事务最多50条实际观察；每条的固定root PK为 `(cluster_id,workspace_id,detector_key,subject_type,subject_id)`，锁此mutable root，不锁immutable observation。每个 observation ID和完整identity/time occurrence唯一；同ID相同HMAC只返回duplicate及已有event/outbox指针，内容不同409。distinct新观察必须 `observedAt>last_observed_at`，过期或倒序不推进baseline；失败/超时网络采样不以重试时间假装新观察。

`last_observation_id`始终指本次immutable实际观察，复合FK完整绑定CID/WID/detector/typed subject。state的 `last_observation_safe`是固定小progress envelope：`{version:1,baseline:{observationId,value}|null,candidate:{observationId,value}|null}`，不保存任意配置或payload。baseline/candidate指针须由deferred trigger读取immutable source，校验同scope/node/config/epoch、verified质量与值/HMAC。`observation_fingerprint`是该完整progress与当前root identity/revision/lastObservationId/time的HMAC；mutable baseline本身永不成为授权source。不可变source行的HMAC必须先验，不接受篡改state中的期望值。

- 第一次verified观察：INSERT rv1，baseline=this observation、candidate=NULL；receipt baseline_created、event/outbox=NULL。
- transport/node/config/scope epoch改变，或先前baseline=NULL：当前verified值重新baseline，清candidate；receipt baseline_reset，不发旧主体恢复/近到期通知，不搬旧事件到新WID。
- 非verified观察：仅追加实际质量记录、last pointer与CAS rv，清baseline/candidate；receipt quality_only，无event。下一次verified重建baseline，不能跨未知间隙累计健康去抖。
- 同context的certificate：从真实expiresAt/observedAt归入normal/>30天、30天、7天、1天、expired最严重bucket。只有后续实际采样进入更严重bucket才certificate.expiring或certificate.expired；发事件同时把本次观察升为baseline，下一次相同bucket只CAS真实freshness，不重复提醒。Core计算阈值和固定eventType，输入不带自由severity/payload/eventType。
- 同context的health：baseline不同的新规范枚举需要两次连续verified同值、间隔30..90秒的真实观察。第一份记candidate，无event；第二份再次确认才upstream.health_changed并把本次观察升为baseline、清candidate。间隔不足30秒只记录本次freshness，不伪造第二确认；超过90秒重建baseline，不跨停止采样的间隙宣称连续恢复。回到baseline清candidate；非verified/上下文改变清candidate。checks_off仅可保存基线，不作为健康恢复通知；改变healthcheck配置使configFingerprint改变并重建基线。

baseline SQLCAS、immutable observation INSERT、固定派生event与唯一outbox都在传入tx内提交；任一失败全回滚。同一实际采样被重复提交不创建新event；不同并发样本只有exact baseline revision赢家，其余重读调度或丢弃样本，不拿旧观察盲重试新revision。

### 14.3 event/source exact pointer与公开边界

检测事件固定 `source_kind='observation'`、`source_id=observation_id=<本次已验证source row.id>`、`phase='observation'`，其余audit/workflow/mutation/IAM/Portal source列全NULL。`event_records`复合FK绑定 `(cluster_id,workspace_id,observation_id)` 与typed subject，deferred trigger再比实际detector、actor=system/null、quality=verified、observedAt、scope/HMAC和允许的固定eventType；不能引用别CID、旧baseline source、planned对象或只有一个UUID的任意行。

`occurrence_key`由Core HMAC绑定detector/physicalscope/node/typedsubject/config/epoch、原baseline observation、确认观察和固定bucket/health transition；event source唯一规则不变。event scope HMAC独立绑定 `{version:1,eventId,sourceKind:'observation',sourceId,observationHmac,clusterId,workspaceId,scope}`。安全8KiB envelope只subject typed UUID、实际observedAt、quality和expiry/bucket或前后health枚举；无raw tags、PEM、Target地址、child IDs。worker通过event的**本次immutable observation**验证historical scope/HMAC，再当前creator/recipient grant与lease，不把mutable state/latest config当授权依据。

没有HTTP enqueueObservation、producer DTO导出路由、任意 append或自称system入口；固定注册Root sampler才能mintproof调用。fanout当前权限仍独立，由真实显式订阅/personal preference匹配并EventAccess审核；观察能力不授予events管理、Native配置读写或通知发送。未知COMMIT只能按原observationId读实际已提交source/event，不创建新ID/别epoch再发同观察。M6全部DDL/proof/权限不变。
