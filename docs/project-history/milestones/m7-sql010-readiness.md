# SQL010 实施清单

状态：**SOURCE READINESS ONLY；SQL010、M7 产品代码和运行态尚未授权实施。** 本清单核对最新 `M7-implementation-contract.md`、`M7-event-core-interface.md`、`M7-delivery-contract.md` 与当前 000–009/API 源码；不覆盖较旧 storage 稿，不加入 M6 SourceFreeze。下列均为待实现项，无已执行迁移、Worker 或投递证明。

## 现有接口与必须保持的事实

- `AuditService.append(event,tx?)` 已返回 `{id,chainScope,sequence,eventHash,occurredAt}`。原 SHA256 输入是 `canonicalJson` 的十九字段：`id,chain_scope,sequence,actor_id,actor_type,source_ip,cluster_id,workspace_id,entity_type,entity_id,action,before,after,json_patch,workflow_id,result,request_id,prev_hash,occurred_at`。sequence 为十进制字符串、时间为 UTC 毫秒 ISO；`event_hash` 不在输入中。SQL010 不改旧行、链头历史或算法。
- `SecretService.fingerprint` 是独立 HMAC-SHA256：固定 `kongos-fingerprint:v1:` 前缀加 canonical JSON，使用 Console 加密密钥；不是原审计 SHA，也不是 APP/Portal JWT 密钥。新 scope/queue/observation HMAC 必须明确绑定其实际源 ID/hash、CID/WID、完整内容；旧链不因此覆盖新增注解。
- 000–009 与 M6 Portal/Workflow/proof/abandonment 密文、AAD、tuple、terminal 防护、运行角色权限均保留。不可变证明不 `FOR SHARE/UPDATE` 锁；锁可变 root 的版本，核验不可变版本 FK/HMAC。正式隔离 PG 成功/重放路径必须全程非 owner、非 superuser。
- 当前 `Audit.append` 尚无 scopeHints/outbox writer；`IamMutationsService.execute` callback 仍是 `fn(tx)`；`WorkflowService` metadata apply 后仍写 generic success Audit。这三处增量由各 owner 在 M7 release 后接入，不是已经实现的 M7 功能。

## Storage owner 文件与依赖

正式 release 后 Storage 独占 `infrastructure/migrations/010_m7_events.sql`、`infrastructure/migrate.ts` 的新表权限增量，以及 `modules/event-core/{event.types.ts,event-access.ts,audit-outbox-writer.service.ts,event-repository.service.ts,outbox-repository.service.ts,delivery-repository.service.ts,notification.service.ts,notification-operations.service.ts,notification.controller.ts,event-core.module.ts}`。有意义的独立 repository/通知与真实非 owner PostgreSQL 测试按对应域新增；当前这些产品文件及 SQL010 不存在。

| 依赖 owner | Storage 等待的实际导出 / 接线 | Storage 提供的固定接口 |
| --- | --- | --- |
| Root/Audit | `EVENT_ACCESS` 当前权限 adapter；Audit scopeHints 与同 TX writer 安装；历史 matcher、审计导出 producer；AppModule/Swagger | `AuditOutboxWriter.fromAudit(receipt,hints,tx)`；历史 Scope/Receipt types；`audit_export_jobs` DDL |
| Root/Detector | 实际有界 certificate/health网络sampler、固定purpose、private sourceProof、`EVENT_ACCESS.assertObservationCurrent(input,tx)` 当前源栅栏 | `enqueueObservation(input,tx)`、immutable observation/HMAC、baseline CAS、固定派生event/outbox；无Audit/网络依赖 |
| Kong/Events/Workflow | 渠道与订阅 root/version SQLCAS；真实业务 Audit；IAM callback 第二参数 operationId；event-only metadata receipt 核验 | `EventRepositoryService.enqueueTest/Replay(input,tx)`；版本和 queue exact tuple DDL |
| DevOps/Delivery | transport current authority/lease 与最后同步发包 fence；只白名单本地收件器验收 | `DeliveryRepositoryService` 固定 claim/intent/assert/renew/finalize/recover/load methods、冻结 Claims/Outcome types |
| Frontend/Security/Reviewer | current actor/scope 原 key恢复、owner-only UI与真实验收 | `/notifications` 固定 DTO/回执投影、Safe DTO、非 owner正式成功/重放与竞态证据 |

`EventAccess` 固定 methods：`permissionVersion(actor)`、`assertSourceRead(actor,event,module)`、`canSourceRead(actor,event,module)`、`assertWholeWorkspace(actor,cid,wid,module,action)`、`assertDeliveryCurrent(claim)`、`assertNotificationOwner(actor,ownerId,cid,wid,action)`、`assertObservationCurrent(input,tx)`；方法的完整 typed参数以 `M7-event-core-interface.md` 为准。Core 不生成伪 HTTP session，不自行实现当前授权 adapter，不设 optional/no-op fallback。

## SQL010 表/字段合同

实际列名使用 `cluster_id/workspace_id`，下表用 `cid/wid` 缩写。UUID FK 全部 `ON DELETE RESTRICT`；可空 scope 必须 `workspace_id IS NULL OR cluster_id IS NOT NULL`，并由源校验 trigger 用 `IS DISTINCT FROM` 比较 NULL，不依赖 nullable MATCH SIMPLE 掩盖错租户。`revision>0`、generation/count 非负、hash 为小写 hex64、时间单调、JSON 类型和字节预算均在 DDL 落地。

| 用户 M7 能力 / 表 | 精确字段 | 唯一/FK/不可变规则 |
| --- | --- | --- |
| 历史审计权限 `audit_event_scopes` | `audit_event_id,audit_event_hash,cluster_id?,workspace_id?,scope JSONB,scope_hmac,created_at` | PK audit ID；新增 `audit_events UNIQUE(id,event_hash)` 支持复合 FK；实际 Audit scope、hash 与两侧 WID 所属 CID 校验；append-only；scope 最大64KiB |
| Hooks/事件 `event_records` | `id,cluster_id?,workspace_id?,event_type,phase,source_kind,source_id,audit_event_id?,observation_id?,workflow_id?,mutation_id?,iam_operation_id?,portal_operation_id?,actor_type,actor_id?,developer_id?,entity_type?,entity_id?,source_scope,source_scope_hmac,payload_safe,payload_digest,occurrence_key,occurred_at,created_at` | PK id +可引用 scope tuple；typed source 指针与 source_kind 精确对应实际行；`UNIQUE(source_kind,source_id,event_type,phase,occurrence_key)`；append-only；payload UTF-8≤8192；不得含配置/秘密/子图列表 |
| 共享 test/replay 的终态证明：`event_records` 附加列 | `workflow_execution_id?,workflow_plan_revision?,workflow_plan_hash?,workflow_step_id?,queue_request_hmac?` | 新四列全 NULL 或完整且 workflow_id 非 NULL；exact execution/version/step composite FK；IAM 与完整 Workflow queue proof 互斥。普通 Audit 记录仅 workflow_id 不构成队列批准证明。deferred 核验实际 Audit/actor/subject/action/HMAC 和父终态，不能只存 workflow UUID |
| Hooks fanout `event_outbox` | `id,event_id,state,revision,lease_owner_hash?,lease_generation,lease_until?,next_attempt_at,attempt_count,error_code?,subscription_upper_bound?,personal_upper_bound?,subscription_cursor?,personal_cursor?,subscription_complete,personal_complete,created_at,updated_at` | `event_id UNIQUE`；event identity 固定；claim/cursor/generation CAS；两个候选流完成才 dispatched；due 索引 `(state,next_attempt_at,id)`；无网络行锁 |
| 渠道 `notification_channels` | `id,cid,wid,name,type,status,endpoint_secret?,auth_secret?,options_safe,credential_generation,revision,created_by,updated_by,workflow_id?,deleted_at?,retention_until?,created_at,updated_at` | `(cid,wid,id)`、`(cid,wid,name)` 唯一，名称/类型/scope/creator 固定且不复用；same-scope workflow FK；pending 不投递；软删除；current root revision 引用真实版本 |
| 渠道历史 `notification_channel_versions` | `cid,wid,channel_id,revision,status,type,endpoint_secret?,auth_secret?,options_safe,credential_generation,created_by,created_at` | PK `(cid,wid,channel_id,revision)`；channel/generation 可引用唯一 tuple；append-only；exact root snapshot 同 TX 插入；endpoint/auth 都 AES-GCM 密封 |
| 共享订阅 `event_subscriptions` | `id,cid,wid,channel_id,name,event_types TEXT[],native_type?,native_ids UUID[],physical_tags TEXT[],status,revision,created_by,updated_by,workflow_id?,deleted_at?,retention_until?,created_at,updated_at` | same-scope channel FK；channel/scope/creator 固定；types≤32、IDs/tags≤256；有 IDs 必有 typed native_type；软删除；root revision 引用版本 |
| 订阅历史 `event_subscription_versions` | `sequence BIGSERIAL,cid,wid,subscription_id,revision,channel_id,status,event_types,native_type?,native_ids,physical_tags,created_by,created_at` | `(cid,wid,subscription_id,revision)` 唯一；sequence 唯一用于稳定 fanout 上界；append-only；不回读 current root 冒充旧版本 |
| 投递队列 `event_deliveries` | `id,cid,wid,event_id,delivery_kind,subscription_id?,subscription_revision?,channel_id,channel_revision,credential_generation,creator_id,replay_generation,parent_delivery_id?,state,revision,lease_owner_hash?,lease_generation,lease_until?,intent_attempt_no?,intent_lease_generation?,intent_started_at?,next_attempt_at,attempt_count,idempotency_key,payload_safe,payload_digest,error_code?,expires_at,created_at,updated_at` | 普通唯一 `(event_id,subscription_id,subscription_revision,replay_generation)`；test partial unique `(event_id,channel_id,replay_generation)`；test subscription tuple 全 NULL，普通完整版本 FK；channel version/generation FK；identity/key/payload 固定；终态不能重开 |
| 投递结果 `event_delivery_attempts` | `id,cid,wid,delivery_id,attempt_no,lease_generation,started_at,finished_at,outcome,send_started,http_status?,duration_ms,error_code?,retryable,created_at` | `UNIQUE(delivery_id,attempt_no)`；full delivery FK；append-only；一次完整结果 INSERT；100..599 状态码、finite非负毫秒；无 response/body/SMTP文本 |
| 本人偏好 `user_notification_subscriptions` | `id,user_id,cid,wid,name,event_types,native_type?,native_ids,physical_tags,in_app_enabled,status,revision,deleted_at?,retention_until?,created_at,updated_at` | owner/scope 固定；仅站内；过滤预算同共享订阅；显式偏好才 fanout；软删除，不广播所有 users |
| 本人偏好历史 `user_notification_subscription_versions` | `sequence BIGSERIAL,cid,wid,subscription_id,revision,user_id,name,event_types,native_type?,native_ids,physical_tags,in_app_enabled,status,created_at` | same-root/owner tuple FK，版本唯一、sequence唯一；append-only；第二路 fanout 上界 |
| 站内通知 `user_notifications` | `id,user_id,cluster_id?,workspace_id?,event_id,title,summary_safe,link_kind,link_id?,revision,read_at?,dismissed_at?,created_at` | `UNIQUE(user_id,event_id)`；源 event FK +真实 nullable scope 校验；owner/source/body 固定；read/dismiss 仅 NULL→一次时间；不以删除隐藏历史 |
| 证书/健康真实来源 `event_detection_observations` | `id,cid,wid,detector_key,subject_type,subject_id,transport_scope,observed_node_id?,cluster_revision,workspace_revision,config_fingerprint,scope_epoch,observed_at,quality,source_scope,source_scope_hmac,observation_safe,observation_hmac,occurrence_key,created_at` | append-only；detector certificate.expiry.v1仅certificates/ca_certificates，upstream.health.v1仅upstreams；FK可引用唯一 `(cid,wid,id,detector_key,subject_type,subject_id)`；quality verified/partial/unavailable/invalid/stale；verified匹配严格safe union，其余NULL；actual source HMAC与同scope FK；无PEM/key/地址/child列表 |
| 检测进度 `event_detection_state` | `cid,wid,detector_key,subject_type,subject_id,transport_scope,observed_node_id?,config_fingerprint,scope_epoch,last_observation_id,last_observation_safe,observation_fingerprint,last_observed_at,revision` | PK `(cid,wid,detector_key,subject_type,subject_id)`；last source指针exact immutable复合FK；固定progress JSON baseline/candidate指针由deferred actual source trigger复验，progress HMAC；只CAS；配置/节点/归属变化与未知间隙新基线，无首次通知 |
| 审计异步导出 `audit_export_jobs` | `id,actor_id,cluster_id?,workspace_id?,idempotency_key,request_hash,format,filter_safe,upper_bounds,permission_version,state,revision,row_count,bytes_count,digest?,output_secret?,lease_owner_hash?,lease_generation,lease_until?,error_code?,expires_at,created_at,updated_at` | `UNIQUE(actor_id,idempotency_key)`；request tuple/expiry 固定；lease CAS；output AEAD首次封存、expired才清材料；succeeded/incomplete须实际output/digest；终态不 running 重开；32MiB/100k行截止诚实 incomplete |

event/notification/audit 可有真实全局 NULL scope，不能填 default CID/WID。共享 channel/subscription/delivery/detector 均完整 CID/WID。历史 source、owner 或账号身份的 FK 使用实际 users/developers；developer Audit.actor_id 仍 NULL，不创造 Console 用户。

观察列和 `enqueueObservation(input,tx)` 已一次冻结于 [Event Core第14节](m7-event-core-interface.md#14-detector-唯一-db-only-入口冻结)：camel DTO→本表snake列一一映射，不加新ledger/审批或额外表。Root负责真实网络源证明；Storage DB-only同TX写入。quality只实际观测，配置/归属/节点变更和null first sample只建立基线，覆盖旧提案首次近到期发通知分支。queue完整tuple仍是deferred终态证明，不是新的审批流程。所有实现继续等M6闭环提交后release。

## SQL trigger 与运行角色清单

1. **Append-only**：新 `audit_event_scopes,event_records,notification_channel_versions,event_subscription_versions,user_notification_subscription_versions,event_delivery_attempts,event_detection_observations` 全部 BEFORE UPDATE/DELETE 和 BEFORE TRUNCATE 拒绝；迁移运行角色清单增量只 SELECT/INSERT，REVOKE UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER，保持所有 M6 immutable 表原权限。
2. **Mutable identity/progress**：root channel/subscription/preference、outbox/delivery/notification/detector/export 表拒物理 DELETE/TRUNCATE；identity/payload/key/hash/creator/scope/createdAt 不可改；revision/count/generation 单调、lease tuple 成组、terminal 和时间单向；行锁只持有到 SQL提交，不跨 DNS/TLS/流输出。
3. **Version completeness**：root insert/update 同 TX 必须 append exact revision snapshot；root→version deferred FK +比较实际配置列的 deferred trigger，不能给 root 的 revision 指向旧配置。恢复/停用也是新版本；AAD `event-channel:<id>:<cid>:<wid>:<generation>:endpoint|auth`。新目标不带旧认证。
4. **Source/queue integrity**：Audit annotation 实际 hash/actor/scope；event source 各明确 FK和完整 scope 对应；test/replay queue 用实际业务 success audit +IAM ID XOR完整 Workflow tuple，COMMIT 时核验 terminal。并在后续相关 ledger/workflow/step事实变化时重验，防提交后被改为未知。HMAC真实性由持 SecretService 的服务核验，SQL不接客户端“已批准”flag。
5. **Lease/intent/attempt**：claim `SKIP LOCKED` 后递增 generation；durable send intent commit 在首个发送准备前；finish append一次 outcome并 exact lease CAS；expired sending append uncertain，旧 ACK不覆写它；expired claimed 无 intent 不造 attempt。bounds为8KiB、claim20、并发2、8次/24h、lease30s、heartbeat5s，HTTP5s、SMTP15s。
6. **Export**：sealed output AAD `audit-export:<id>:<actorId>:<clusterId-or-global>:<workspaceId-or-global>:<requestHash>:output`；request/source bounds/permissionVersion不改；输出 lease CAS、当前 owner/read权限与到期逐次复核。CSV防公式；明文材料、公开磁盘路径、任意 URL不进入 SQL/回执。过期保留identity/counters/digest历史，不宣称清理备份/WAL。
7. **Workflow additive-only**：SQL010增量扩展 workflow_definitions/workflows kind 为 `event-metadata`，subject 仅 `notification_channels/event_subscriptions/event_deliveries`；保留 Portal 原分支的全部检查。新 subject trigger完整 CID/WID检查；新版本必须 metadata-only、native_requests=[]、operation_id NULL、无generated/prerequisites原生对象，不扩原 Native/Portal capability。M6 single-stage/V1 16/32预算不变。
8. **Observation/baseline/source**：观察source append-only且运行角色仅SELECT/INSERT；detector/typedsubject组合CHECK、实际CID/WID复合FK、UTC/≤8KiB安全union/64KiBscope预算、hex64 HMAC/scopeEpoch、版本正整数、健康verified节点非NULL。state exact revisionCAS，first NULL严格代表无root；lastObservation和progress baseline/candidate均由actual不可变source逐一复验same tuple/quality/config/node/epoch，非verified清baseline/candidate；timestamp严格前进。event检测分支固定 observation_id=source_id且其他账本source全NULL，exact真实observation FK/quality=verified/type/actor/scope/HMAC/current确认值与eventType比较；禁止指旧mutable baseline冒充本次事实。观察/state/event/outbox任一失败全回滚；SQLite/mockSQL不能替正式非ownerPG证据。

必建索引：audit/event/notification/delivery目录 `(cid,wid,occurred_at或created_at DESC,id DESC)`，owner通知 `(user_id,created_at DESC,id DESC)`与 unread partial；due outbox/delivery `(state,next_attempt_at,id)`；subscription和personal version sequence上界/最新revision索引；attempt `(delivery_id,attempt_no)`；export owner/key唯一及due/expiry；typed source/observation occurrence/检测调度索引。HTTP不接可自由拼接 SQL 的列名或排序表达式。

## 同事务接线与 exact 导出

| 入口 / owner | 必须实施的调用顺序 |
| --- | --- |
| Audit / Root | 原 chain advisory lock→真实 Audit INSERT→head UPDATE→`AuditOutboxWriter.fromAudit(receipt,scopeHints,tx)`。先注解真实历史scope；action无事件映射只不建event/outbox，不应因此跳过审计注解。rollback后三者全无。既有无 hints 调用一律 legacy_unknown。 |
| Shared direct metadata / Kong+IAM owner | 当前 wholeWS events权限→真实 IAM ID/原key→兼容 callback `fn(tx,operationId)`→配置 SQLCAS/version→真实 before/after business Audit→enqueueTest/Replay→IAM succeeded 同 TX→deferred验证。不另造 IAM审批绕过。 |
| Shared approval metadata / Kong+Workflow owner | 私有 exact event metadata祖先→SQLCAS/version→handler自己实际 Audit→enqueue exact tuple→Engine event-only复验本次 step/execution/version/before/payload/receipt并省重复generic Audit→step/execution/workflow终态同 TX。Portal分支不变。 |
| Observation / Root+Storage | Root真实有界网络采样在SQL事务外→私有固定purpose sourceProof→`assertObservationCurrent(input,tx)` actual registry/WS/version/scope/node/config/≤15s/writefence→immutable observation INSERT→exact beforeBaselineRevision CAS→first/reset只建baseline或后续真实transition才event/outbox→最终同txfresh source栅栏→COMMIT。无HTTP arbitraryappend、Audit/Engine调用或伪actor；完整DTO第14节。 |
| Fanout / Storage | 首claim固定两个 version序列上界→50项keyset续页→fresh recipient/config当前授权→delivery/notification幂等 INSERT→同 TX CAS cursors。两流全完才 dispatched；新偏好不倒灌历史；空匹配页继续下一页。 |
| Send / DevOps | claim→加载当前两 creator与source/config/lease→commitSendIntent→DNS/TLS准备→fresh EventAccess与lease→同步send fence→完整attempt INSERT+CAS。没有网络 SQL行锁或 provider 自动重放。 |
| Personal SQL / Storage | 固定 NotificationOperationsService owner/source/current notifications权限→原key+bodyHMAC actual iam_operations→owner行锁/revision CAS→状态/偏好版本+Audit+result同 TX；unknown COMMIT重读原key。仅此固定处理器，不改通用IAM direct/approval规则。 |
| Export / Root | 当前 audit.read+原filter/scope/key→独立 export job +审计同 TX→每页当前权限与lease→材料封存 CAS→owner/current permission/no-store下载。它是只读导出，不受 cluster配置审批阻断。 |

固定 public classes：`AuditOutboxWriter,EventRepositoryService,OutboxRepositoryService,DeliveryRepositoryService,NotificationService,NotificationOperationsService,NotificationController,EventCoreModule`；types和 `EVENT_ACCESS` 路径 `modules/event-core/`。Core只DB/Secret/当前权限 adapter，不注入 Audit/Engine/Kong/传输。Root装 provider，不设 optional授权fallback。

固定方法：`fromAudit(receipt,hints,tx)`；`enqueueObservation(DetectorObservationInput,tx):Promise<ObservationReceipt>`；`enqueueTest({actorId,cid,wid,auditReceipt,channelId,channelRevision,credentialGeneration,iamOperationId?|workflow完整tuple},tx)`；`enqueueReplay({actorId,cid,wid,auditReceipt,deliveryId,expectedRevision,同proof},tx)`；Outbox `claimDue/fanoutPage/release`；Delivery `claimDue/commitSendIntent/assertLeaseCurrent/renewLease/finalize/recoverExpiredIntents/loadChannelSecrets`。真实 typed参数名称按 event-core-interface 的 `clusterId/workspaceId`，不是HTTP提交执行证明。

## 历史授权与当前源码待接入点

- 原生 typed列表八核心、targets、六credentials（保留具体 kind/父上下文）。before/after各侧显式真实 WID/tags，创建/删除 absent侧不是wildcard；单个完整 grant同时匹配两侧。迁移两 WID分别保存；Target换ID目前 legacy_unknown，不假原ID授权新ID。current native GET/index/名字不补旧历史。
- disabled WS允许已授权 history/shared只读，停止修改和发送；deleted WS保留原 WID历史与当前 grant，拒共享活动目录/配置写；不调用active Native resolver映射default。真实全局记录需要当前完整global权限。链验证只完整cluster/global；过滤导出不等于完整链。
- `audit/events/notifications` 已在当前 TS/SQL005模块 allowlist，**无需新增role module枚举或重写旧权限**。待 IAM `normalizePermission` 加这三模块对固定十五 native typedID的特例；不放开共享channel metadata entity scope。当前特例只有 secrets/annotations/monitoring以及portal/workflows部分实体。
- `AuthorizationService.discoverableModules` 待增三历史模块，仅最小cluster/WS selector发现，不附赠 Native配置read。Root实现 DB-only historical matcher和 EVENT_ACCESS：当前 account+permissionsVersion、scope HMAC、同完整grant、source read、owner、防跨租户复制；worker两 creator持续 wholeWS.events.write +source.events.read。任何数据库错误不能吞成“无权限/空结果”。
- producer接线归 Root：Mutation actual readBack、Recycle逐节点 verified delete/restore、workspace迁移每步 actual tags/source+target WID。requested/failed/uncertain或缺一侧证明一律 unknown，不把 plannedafter记录为生效配置。纯metadata固定subject/安全计数；developer event actor_id仍 NULL。

实施release后按已冻结observation参数和queue完整tuple先落types/SQL草稿；之后执行真实runtime-role正式producer/重放、append-only所有权限、rollback、>50fanout continuation、lease/lateACK、mixed-owner IDs、historical两侧grant、export撤权/过期门禁。当前只有文档定型，没有新的代码/PG/采样或测试通过声明。
