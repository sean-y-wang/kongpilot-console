# M8 存储、备份与配置作业合同

状态：**仅设计，未实施**。M6 正在唯一部署窗口内验收，M7 尚未发布编码指令。本文只定义 SQL011 与服务接口的冻结候选，不创建迁移、运行后台作业、捕获配置、导出秘密、执行 decK 或修改运行环境。M8 实施须由 Root 在 M7 通过后单独放行；端点、V2 能力和表名需与业务、Web、私有执行所有者共同冻结。

依据：[M8 业务合同](m8-business-contract.md)、[M8 Web 合同](m8-web-contract.md)、[decK 1.5 兼容性调查](../../reference/deck-1.5-compatibility.md)、当前 `GraphCapturerService`、`CredentialStoreService`、`SecretService`、`MutationService` 和 M6 工作流源码。当前 SQL000–008 **没有配置快照表**。`workflow_executions.snapshot_secret` 是执行前授权证明；`recycle_entries` 是删除恢复图，二者不能改名或复用为配置快照权限。

## 1. 已有能力与明确扩展

| 当前组件 | 可复用的事实 | M8 必须新增的边界 |
| --- | --- | --- |
| `SecretService` | AES-256-GCM、上下文 AAD、以控制台密钥为键的 HMAC、秘密与错误脱敏 | 独立的 artifact DEK 封装；不能把通用加密方法或可读 HMAC 当作公开秘密导出许可 |
| `CredentialStoreService` | 六类凭证、Consumer/类型/ID 绑定；Basic/OAuth 原文与当前 remote hash 一致性证明 | 捕获时冻结原文恢复材料副本，不能只引用以后可变的 `credential_refs.payload_secret` |
| `GraphCapturerService` | 真正父子关系、共享引用、Consumer/Plugin DAG；100 页、10,000 记录/节点、32 MiB 上限；有效 Target 与历史区分 | snapshot 专用只读用途、全局集合与六类 nested credential manifest；不触发删除用途、不自行扩大既有预算 |
| `MutationService` | actor/CID/WID/payload 幂等 HMAC；before CAS、physical scope 锁、remote 不确定、原键回执、当前权限与 before-send 检查 | V2 配置步骤的明确完整绑定；不能靠传入 jobId、HTTP workflowId 或 metadata handler 绕过审批 |
| M6 Workflow V1 | 不可变加密版本、审批事实、精确 step/operation reciprocal FK、16 步/32 packet 限制 | 独立配置 DAG V2 清单与逐对象私有证明；V1、Portal 能力及其 SQL 限制保持原样 |
| M7 事件/审计 | 预计提供历史 before/after scope、当前权限重验、事务 outbox | M8 审计/完成事件关联真实 job/plan/operation；不把整份明文图或秘密文件写入事件 |

恢复拓扑使用实际依赖边，不以一张固定类型排序代替：证书/CA 在引用 Service/SNI 之前；Upstream 在 Target 之前；Service 在 Route 之前；Consumer 在其 credential 和绑定 Plugin 之前；组合绑定 Plugin 等待所有父对象。删除采用逆 DAG、完整加密归档先于任何 DELETE；共享引用只核验，未经明确授权不重建或覆盖。

## 2. SQL011 通用规范

所有新业务表使用 `cluster_id UUID`、规范 `workspace_id UUID`，完整 `(cluster_id,workspace_id,...)` FK，`ON DELETE RESTRICT`。cluster 级 capture 仍有明确 workspace 锚点，同时 `scope_kind='cluster'`，不能把缺少 workspaceId 当作全局。对象归属在 manifest 每行单独记录；完整集群任务不会借单个工作区锚点缩窄或放大授权。

不可变身份包含 captured `transport_scope TEXT hex64`、actor、来源、plan/snapshot version、input HMAC、typed UUID、原父 UUID 和 secret generation。CID Admin URL 重绑不会修改旧快照、作业或原生回执的物理 scope。导出秘密、比较当前配置和 apply 重新验证当前实际 transport scope；不匹配返回 `SOURCE_SCOPE_CHANGED`，不把旧 gateway 的秘密静默交给新绑定范围。历史安全摘要可保留；跨环境发布由 M10 的显式 Promote 合同决定。

`revision INT>0` 只用于可变元数据 CAS；内容版本与清单不可变。时间列统一 TIMESTAMPTZ，响应 UTC 毫秒 ISO；BIGINT 计数/序号由服务规范转换，避免 JS 精度或驱动字符串误判。HMAC 为 hex64，仅用于私有比对；公开 planHash 是不具权限的关联标识。普通 DTO 不公开 secret HMAC、原始 cursor、wrapped key 或数据库密文。

列表默认 20、最大 100，返回 `{items,nextCursor,size,total:null}`。有签名游标绑定当前 actor、permissionVersion、CID、WID、captured physical scope、不可变版本/manifest HMAC、完整过滤、固定 page size 与稳定上界。工作区/业务 tags 的 AND/OR 与 default 负过滤沿用真实 resolver；unknown/multi/deleted 保留标签对象拒绝归属，不归入 default。

## 3. 表结构冻结候选

以下 `cid/wid` 为表格缩写，实际列名始终是 `cluster_id/workspace_id`。普通可变行含 `created_at/updated_at`；append-only 行仅 `created_at`，不能通过 UPDATE 补写内容。

| 表 | 关键列 | 约束与用途 |
| --- | --- | --- |
| `config_snapshots` | `id,cid,wid,transport_scope,name,description,created_by,current_version,revision,state(capturing/ready/incomplete/failed/deleted/expired),deleted_at?,retention_until?` | ID/scope/creator 不可变；软归档/恢复 CAS；`current_version` 完整 FK 到版本，不物理删除对象历史 |
| `config_snapshot_versions` | `cid,wid,snapshot_id,version,version_id,source_job_id,material_id,scope_kind,root_ids UUID[],manifest_hmac,completeness(complete/incomplete),consistency(console_fenced_best_effort/changed/unverified),observed_from,observed_until,kong_version,adapter_version,schema_hmac,permission_version,capture_epoch,object_count,secret_count,page_count,record_count,byte_count,recovery_summary JSONB,warning_codes TEXT[]` | append-only；PK `(cid,wid,snapshot_id,version)`；完整唯一 `(cid,wid,version_id,manifest_hmac)`；预算/count/时间窗口 CHECK；缺页、缺权限或变更不能封为 complete |
| `config_snapshot_collections` | `cid,wid,version_id,collection_key,entity_type,parent_id?,query_hmac,page_size,page_count,record_count,terminal_observed,cursor_chain_hmac,coverage_hmac` | append-only；PK scoped version/collection；FK 到精确版本；每个必需集合均有 terminal marker，即使为空也需真实完成；无公开路径/offset |
| `config_snapshot_objects` | `cid,wid,version_id,object_key,entity_type,native_id,parent_type?,parent_id?,object_workspace_id,ownership_tags TEXT[],affected,reference_only,dependencies TEXT[],payload_ciphertext,restore_ciphertext?,before_hmac,restore_hmac?,schema_hmac,recovery_state,managed_boundary,observed_at` | append-only；typed ID/父关系完整匹配；PK scoped version/object_key；同版 native type/ID 唯一；引用边必须存在于同版或有独立已证明的 external-reference entry；不存公开秘密摘要 |
| `config_snapshot_secret_refs` | `cid,wid,version_id,object_key,secret_ref_id,credential_kind?,consumer_id?,native_id?,source_credential_ref_id?,source_hash_hmac?,secret_ciphertext,recovery_state(complete/requires_secret_input/requires_rotation/nonrestorable),verified_at` | append-only；FK 同版本同 object；consumer/kind/ID 与 object tuple CHECK；source store FK 只是出处，真正恢复材料为不可变加密副本；非恢复凭证不伪造 raw password |
| `configuration_jobs` | `id,cid,wid,transport_scope,actor_id,origin_type(http/schedule/pipeline),origin_session_id?,authority_expires_at,kind(capture/import/compare/export/apply/rollback/reconcile),idempotency_key,request_hmac,input_secret?,scope_kind,root_ids,revision,state,execution_mode,approval_required,plan_id?,plan_revision?,plan_hash?,workflow_id?,before_snapshot_id?,before_snapshot_version?,permission_version,lease_owner_hash?,lease_generation,lease_until?,attempt_no,remote_started,remote_completed,safe_progress JSONB,error_code?,expires_at,started_at?,completed_at?` | 原始 actor/CID/WID/key 唯一；body 不同冲突；身份和绑定一次写定；原会话完整 session/actor FK；schedule 仅 capture、无伪 session；SQL 元数据提交与 requested audit 同事务；大操作 202+轮询；native unknown 保留 uncertain，租约到期不构成未发送证明 |
| `configuration_job_pages` | `cid,wid,job_id,collection_key,page_no,query_hmac,cursor_hmac,next_cursor_secret?,page_ciphertext,record_count,byte_count,terminal_observed` | 捕获阶段 append-only checkpoint；固定 query/size；同页唯一；保密 offset；加密页在恢复 worker 后仍需 current authority，不把页 checkpoint 当 complete manifest |
| `configuration_materials` | `id,cid,wid,job_id,artifact_kind(snapshot/plan/import/export),artifact_id,wrapped_key_secret?,revision,state(available/destroyed),destroyed_at?` | 持有每产物 DEK；完整作用域/owner-job/类型/产物 FK；仅一次封存，销毁只能 available→destroyed 且 wrapped key 同事务变 NULL；持有未决回滚依赖时禁止销毁 |
| `configuration_plans` | `id,cid,wid,transport_scope,created_by,source_job_id,source_snapshot_id?,source_snapshot_version?,current_revision,revision,state(draft/ready/pending_approval/approved/executing/succeeded/partial/failed/uncertain/cancelled/expired),mode(merge/sync/rollback),deleted_at?,retention_until?` | 元数据 root；当前加密内容引用不可变版本；scope 不可迁移；不接收用户传 actor/mode policy/approved flags |
| `configuration_plan_versions` | `cid,wid,plan_id,plan_revision,plan_hash,source_job_id,material_id,input_hmac,steps_hmac,manifest_ciphertext,source_manifest_hmac,baseline_manifest_hmac,cluster_revision,workspace_revision,permission_version,kong_version,schema_hmac,step_count,native_packet_count,delete_count,recovery_complete,expires_at` | append-only；唯一完整 `(cid,wid,plan_id,plan_revision,plan_hash)`；封存时 count/DAG/全部 typed native body/before HMAC 核验；plan private manifest 包含预分配 ID/秘密，不进入公开 diff |
| `configuration_plan_objects` | `cid,wid,plan_id,plan_revision,plan_hash,step_id,step_order,object_key,entity_type,native_id?,allocated_native_id?,parent_type?,parent_id?,credential_kind?,permission_action,mutation_action,body_hmac,before_hmac,dependencies UUID[],payload_ciphertext,before_ciphertext?,impact_ciphertext,reference_only,blocker_codes TEXT[],masked_diff JSONB` | append-only；精确 kind/action/typed ID；native CREATE 的已分配 ID 与 before absence 分开；依赖同版本且早于当前步；masked diff 在读取时再次 SecretService.redact，不使用其替代完整 payload |
| `configuration_executions` | `id,cid,wid,job_id,plan_id,plan_revision,plan_hash,actor_id,workflow_id?,approved_version?,claim_hash,state,revision,current_permission_version,snapshot_hmac,snapshot_ciphertext?,lease_generation,expires_at,started_at,completed_at?` | 每一次执行对应不可变 plan tuple 和真实 before snapshot；claimed proof 一次封存；approved 与 direct 严格区分；execution actor 是 active 控制台账号，不是 Portal developer 或伪 system user |
| `configuration_job_steps` | `id,cid,wid,job_id,execution_id,plan_id,plan_revision,plan_hash,plan_step_id,step_order,state(pending/running/succeeded/failed/uncertain/skipped),operation_id?,receipt_ciphertext?,recycle_entry_id?,before_hmac,after_hmac?,original_native_id?,effective_native_id?,safe_result JSONB,error_code?,revision,started_at?,completed_at?` | plan identity 固定，进度允许 UPDATE；approved operation bind-once；direct的operation_id为NULL、普通receipt关联仅sealed receipt/safe_result；一个 step 一个 native operation；Target 保存原/有效 ID 映射；success 要有精确 durable child receipt +实际 readback，不由客户端结果决定 |
| `configuration_job_attempts` | `id,cid,wid,job_id,execution_id?,step_id?,attempt_no,lease_generation,phase,result,error_code?,duration_ms?,created_at` | append-only；只存安全 UUID/状态/耗时；send intent 先在 mutable job/step 上持久化，完成事实 append 一次；不 INSERT started 后 UPDATE 历史 |
| `configuration_exports` | `id,cid,wid,job_id,artifact_id,material_id,source_snapshot_id?,source_version?,format(deck-1.1/review-json),mode(review/deployment),manifest_hmac,byte_count,expires_at,state(ready/expired/destroyed),created_by` | 完整 manifest/material 同scope FK；deployment 凭证缺失时不 ready；无 public blob URL 或 token query；只在 current-authorized 单次下载流中解密 |
| `configuration_download_grants` | `id,cid,wid,export_id,actor_id,session_id,artifact_hmac,permission_version,token_hash,state(ready/consumed/revoked/expired),expires_at,consumed_at?` | 短期限、单用途、当前会话；body/header 交付许可不在URL；原始 token 不存 DB；最终首字节与每个后续 chunk current recheck；部分下载不称完成 |
| `configuration_deck_sessions` | `id,cid,wid,transport_scope,actor_id,session_id,purpose(read/write),token_hash,credential_epoch,permission_version,job_id,plan_id?,plan_revision?,plan_hash?,revision,state(active/revoked/expired),expires_at,revoked_at?` | 完整 actor/session/job/plan FK；write必需具体已确认且按当前模式真正批准的plan；purpose不互换；每packet从manifest挑精确唯一ready step，不接受body权限；token不进URL/argv；当前role/session/期限每次重查 |
| `configuration_gitops_runs` | `id,cid,wid,job_id,created_by,repository_label,commit_sha,pipeline_reference,created_at` | append-only安全关联；真实job结果为唯一执行状态；commit仅40或64hex，名称/reference受长度与字符约束；无原GitURL/密码/token、不自动push或声称已推送 |
| `config_snapshot_schedules` | `id,cid,wid,transport_scope,name,owner_user_id,current_version,revision,state(active/paused/deleted),next_run_at,deleted_at?,retention_until?` | 只读捕获计划；当前 owner 与整体范围权限；soft-delete；worker 不继承旧创建权限、不自动 native apply |
| `config_snapshot_schedule_versions` | `cid,wid,schedule_id,version,scope_kind,root_ids,schedule_rule JSONB,timezone,retention_policy JSONB,policy_hmac,created_by` | append-only；受限固定调度语法，不接受 shell/JS/crontab command；时区/边界有意义测试 |
| `config_snapshot_schedule_runs` | `id,cid,wid,schedule_id,schedule_version,scheduled_at,creator_id,job_id?,state,reason_code?,permission_version,created_at,completed_at?` | 唯一 `(schedule_id,schedule_version,scheduled_at)`，防多 worker 重复；绑定真实 job 原键；撤权/停用/重绑暂停，不生成假成功 |

上述表先后循环 FK 使用 DEFERRABLE INITIALLY DEFERRED，捕获 material/job/版本和执行前 snapshot 可在同事务完成完整关联。opaque material 不采用仅 `owner_type+owner_id` 无验证 polymorphic FK；版本/导出加入 generated 固定 artifact_kind，把 `(cid,wid,job_id,artifact_id,artifact_kind,material_id)` 全 tuple 绑定到 materials 的唯一目标。

捕获先把逐页加密 checkpoint 持久化，最终核验后一次性插入不可变版本/对象/collection manifest 并 CAS snapshot root.current_version。不能先插 append-only version 声称 ready 再 UPDATE 补内容。staging artifact ID 预生成并用于最终 AAD；未完成 checkpoint 只有 job 权限，无公开快照权限。SQL 延迟 count/hash/DAG 验证通过后才能 ready，错误事务不会留下半份 ready 版本。finalizer 与页/对象写入使用同一 job/version 行锁与 lease CAS；封存完成后禁止追加新 page/object/collection/secretref，使 append-only INSERT 也不能改变已发布 manifest。

## 4. 加密、真实恢复与销毁

建议新增内部 `SnapshotCryptoService`，每产物随机 32-byte DEK；DEK 用 `SecretService.encrypt` 封装，AAD 为 `configuration-material:<cid>:<wid>:<kind>:<artifactId>:<materialId>`。对象/页/秘密副本用 DEK 的 AES-GCM，AAD 绑定 CID/WID、snapshot-version/plan-version、typed object_key、credential kind/parent/generation 和 section，防互换 ciphertext。DEK 不通过 HTTP、argv、env、stdout 或日志出库；只在当前授权请求/worker 的短期内存使用。

新密文验证函数只检查 envelope/字节预算，不能声称验证了明文内容；只有服务器解密、对照完整 manifest/HMAC 与当前权限后使用。无普通 `decryptById` 路由。导入文件、错误响应和 decK 输出按秘密处理，不记录内容 hash 作为公开低熵凭证摘要；公开只有安全 counts、恢复状态与固定 blocker code。

捕获秘密需要每个真实实体 config.read，加密保管/恢复材料还需要明确 `secrets.read`；存入加密库不使未来读取者自动获得明文。Basic 捕获冻结 `{remotePasswordHash,verifiedOriginalPassword}`，且 remembered remote hash 必须一致。当前实际 Kong1.5.1 OAuth schema **没有 hash_secret 字段**，导入/导出必须拒绝该未支持字段；CredentialStore 的 hash_secret 分支仅为防御代码，不代表当前能力。后续适配器若真正探测到该字段，须独立冻结与 Basic 同级的原 client_secret 恢复证明。没有可信原文时记录 recovery blocker，不能以 raw hash、mask marker 或新生成值冒充可恢复原密码。JWT/HMAC/KeyAuth 保留实际 secret/算法；OAuth 客户端备份不声称包含授权码/token/session；TTL 无可信绝对有效期则 nonrestorable，不能静默延长。

授权 deployment 导出必须实体/credential 全部覆盖且可恢复、秘密授权完整；review 摘要不是可 sync 文件。SNIs/Targets 在 decK1.1 内随父对象嵌套；六种 credential 随 Consumer 嵌套，公开 manifest 独立按所有类型计数。禁止新增顶层 snis/targets 或企业 `_workspace`，固定真实 schema 去除只读字段，不添加真实1.5不存在的 Service TLS 字段。

快照 root 软归档后保留 immutable 版本和加密材料；恢复仅元数据 CAS。purge 要当前授权、名称二次确认、无未决 job/plan/rollback/download pin；在同事务锁定依赖、销毁 wrapped DEK、更新材料状态并追加审计。ciphertext/历史版本仍不可改，在线库材料不可再解密；既存受控数据库备份/WAL 可能仍持有旧 wrapped key，其销毁遵循独立备份保留政策，不能宣称擦除了全部历史副本。由新任务复制的恢复材料是独立 artifact，并非原 holder 的别名。

## 5. 捕获完整性与安全游标

每任务共享 aggregate 上限：**100 native pages、10,000 records/objects、32 MiB、120s**。credentials 六种、每个 Upstream targets、父子重复发现/引用核验均计入实际预算。若后续需更大上限，先冻结新的 API/SQL/资源验证，不自行把普通列表变成无限全量扫描。

每集合固定起始 size（≤100），后续保持 size/tags/parent/query 不变；remaining budget 不足时终止为 incomplete，不能改变 size 使签名 offset binding 失效。跟随 Kong offset/next，经当前 KongClient origin/path whitelist 验证；next 不是客户端或 collector 提供的任意 URL。签名 checkpoint 固定 parent、kind、actor、scope、permissionVersion、输入 query 与 cursor chain；重复 next/cursor loop、缺页、重复 typed ID、意外 parent/不完整 root relation 一律中止。

空集合也需真实读取到终点；六类凭证每个允许 Consumer 均完成，而非因为本页为空就推断全局零。应用权限投影导致 omitted 时公开摘要不可显示未授权姓名/秘密/count，整个部署 export/apply baseline 不能完整。快照默认工作区仅真正无保留标签对象；跨工作区引用记 reference_only，含完整只读证明，不跟随扩大写范围。

Kong 1.5 无多对象原子快照。捕获前记录实际 root version/node/physical scope、当前 mutation/fence epoch；捕获中在每页/await 后复核真实权限、workspace/cluster revision与在途 unresolved impact；完成时对明确 root/引用/关键对象指纹再验证。任何受控变更、父关系漂移、node/version变化使 consistency=changed 且不得完整发布。外部 Admin 不受控制台锁的瞬时变化仍无法完全排除，必须保留 `console_fenced_best_effort` 的真实含义，不能写“原子备份”或直连 Kong 数据库。

## 6. 当前权限与恢复依赖

快照功能按 `snapshots`，GitOps pipeline/session 按 `gitops`，每个 object 的真实原生 module read/write/delete 仍单独授权；完整明文材料另需精确 `secrets.read`，Consumer 权限不自动给 child credential secret。metadata root/schedule 的共享配置管理需 whole-workspace/global grant，不用粗 `assertCluster` 作为最终授权。

历史 artifact 的可信 recorded CID/WID/typed ID/tags 从 sealed manifest 取得，不能由浏览器覆写，也不按当前 tag 改写旧归属。读取历史秘密同时核验 recorded scope 和存在实体的当前 scope；不同 grant 的 before/after tag 不能拼成一个越权许可。已删除对象用可信历史 tuple 判断当前角色是否有恢复该对象/目标的完整权限；无法证明历史 scope 的旧 material fail closed，不默认为 default。以当前 `permissionVersion` 检查列表、count、下载、diff 和执行，after-await 变化返回 `PERMISSIONS_CHANGED`。

回滚不是重发旧成功 job：从明确 snapshot version 编译新的 current-before→snapshot-after immutable diff。原 ID 冲突、名称/FK 冲突、secret/TTL不可恢复、共享依赖没有 read/write、managed boundary 都进入 blocker。执行前创建完整 baseline snapshot，并在 plan version 保存其 immutable manifest/material FK。任何破坏性步骤只有 rollback baseline ready 后才发包；受引用 baseline 与所需恢复材料不可过期销毁。

每个拟删除受影响对象图先由当前授权 capture 完整归档；归档不足、原密码缺失、budget耗尽则 **零 DELETE**。credential/Target 父归属与最新有效Target ID单独证明；恢复Target/weight生成新effective ID，不能按历史ID GET200认定成功。stage凭证使用明确原parent，不能在restore时默改Consumer外键。

Portal 已释放空 reservation、revoked grant、历史 Consumer/ACL/Key UUID 的所有权都持续受 Root 物理范围 policy 保护。普通 import/rollback 即使平台有 secrets.read 也不能复活旧Portal key、创建新凭证绕过申请，或把 native 状态回退而 SQL grant 留在 revoked。受管监控/token-generation/Collector URL 同样不得借 YAML 复制私有 provision cap。首版 M8 这些对象允许不变的已证明 references；任何专用业务恢复未注册固定 approved handler 就阻止整份破坏性执行。

## 7. V2 配置作业与不可复制的原生绑定

这是 Root/Reviewer 在 M8 release 前必须冻结的明确扩展，不修改 M6 V1 16-step/32-packet 预算，也不重用 Portal approved cap。建议 V2 由精确 `configuration_plan_versions`+`configuration_plan_objects` manifest 及当前执行 snapshot 支撑，整体审批绑定全部 DAG/body/before HMAC，发送能力仅针对一个已 ready 的 object/packet。

`mutation_operations` 新配置绑定列候选：

```text
configuration_job_id UUID
configuration_execution_id UUID
configuration_step_id UUID
configuration_plan_revision INT > 0
configuration_plan_hash TEXT hex64
```

上述五列必须全NULL或全非NULL，approved V2 native operation 分配时与 `configuration_job_steps.operation_id` CAS 在同一事务写定；新增完整 scope/job/execution/step/plan/hash reciprocal FK、step_id唯一和 bind-once trigger，允许 DEFERRABLE cycle，禁止迟到补授权。与 M6 `workflow_execution_id/workflow_plan_revision/workflow_plan_hash/workflow_step_id` 四列互斥；旧 workflow_id 或普通 direct recovery关联不代表批准。V2 parent approval仍链接真实 current workflow/version/decision，不把该新五列本身当能力。

direct 配置作业通过普通 Entity/Mutation，不填写 approved五列；step.operation_id保持NULL，普通operation仅通过 sealed receipt 与 safe_result.nativeOperationId关联，单独按 actor/CID/WID/key/request HMAC精确核验，用于恢复证明，不生成approved handle或无法满足的reciprocal FK。approved V2通过独立私有 `ApprovedConfigurationExecutionPolicy` 重新解密完整manifest/当前execution/审批事实，mint只能在可信服务器祖先使用的 opaque WeakMap handle；NativePolicy 每包绑定真实logical action、method/path/body、before/absence、parent/kind、claim/execution revision和当前权限。

计划第一次就预分配每个 ID 和 secret；所有缺失/默认/false/0/null/嵌套config差异冻结，不在执行期重新生成。大DAG不能拆成自动自审的多个V1，不能通过 metadata callback执行native，也不临时将cluster模式改direct。job锁与physical Mutation锁使用不同键，避免外套同锁或回调重入；send intent先durable，packet完成再readback/audit。unknown立即停止后续步骤，parent uncertain/partial保持物理impact阻断；不因租约到期、单次404或不同原key重发。

reconcile只读当前证据，绝不接收客户端outcome或恢复native回调。已证明成功步骤不重发；所有未决child receipt完成后，新的显式预览/typed确认可以编译剩余任务，不能以自动resume偷偷生成新原key。成功父终态要求所有实际step/readback与baseline material链完整，最终safe进度/审计/事件同SQL事务提交；丢COMMIT ack重新读取durable成功，不改写成failed。

## 8. 原键回执、服务接口与 API 候选

配置job原键统一归属，不按重试时当前direct/approval模式猜域。业务候选采用 `GET /clusters/:cid/configuration/jobs/by-key/:key`；Web草案的 `/configuration/operations/by-key/:key` 若保留只能是同一个安全resolver别名。当前actor/CID/WID与原body HMAC校验后返回真实job、plan、workflow与native child receipts；不能把审批提交完成视为gateway全部完成。

root/版本/diff/object/steps/export/schedule列表都服务端有界。artifact下载采用业务候选 POST `/configuration/exports/:id/download`，重新授权并typed确认秘密输出后返回同源单用途no-store流或短许可；不是无需确认的普通GET链接。token只存SHA256摘要，purpose/session/actor/scope/manifest/期限绑定，首字节前和后续chunk重新授权，撤权停止后续输出。无public blob/跨域预签名/token query。

建议 Storage 只负责 repository/crypto/worker lease primitives，不依赖 HTTP/WorkflowEngine，避免循环：

```ts
interface ConfigurationScope {
  clusterId: string; workspaceId: string; transportScope: string;
  kind: 'cluster' | 'workspace' | 'services'; rootIds: readonly string[];
}
interface ConfigurationActorProof {
  userId: string; permissionVersion: string; credentialEpoch: string;
  // Proof is server-created and opaque. JSON input never supplies authority.
}
interface ConfigurationRepository {
  createJob(input: TrustedJobInput, tx: DbService): Promise<SafeJobReceipt>;
  findByOriginalKey(actor: ConfigurationActorProof, scope: ConfigurationScope,
                    key: string): Promise<SafeJobReceipt>;
  claimJob(id: string, expectedRevision: number, ownerHash: string,
           leaseMs: number): Promise<OpaqueJobLease>;
  appendCapturePage(lease: OpaqueJobLease, page: TrustedCapturePage,
                    tx: DbService): Promise<void>;
  sealSnapshot(input: VerifiedSnapshotManifest, tx: DbService): Promise<SafeSnapshotVersion>;
  sealPlan(input: VerifiedConfigurationPlan, tx: DbService): Promise<SafePlanVersion>;
  allocateNativeStep(binding: TrustedConfigurationBinding,
                     operation: TrustedMutationAllocation, tx: DbService): Promise<void>;
  recordStepEvidence(lease: OpaqueJobLease, evidence: TrustedStepEvidence,
                     tx: DbService): Promise<void>;
  finishJob(lease: OpaqueJobLease, evidence: CompleteJobEvidence,
            tx: DbService): Promise<SafeJobReceipt>;
  destroyMaterial(input: AuthorizedMaterialPurge, tx: DbService): Promise<void>;
}
```

Trusted类型是内部解密/完整manifest/当前Authorization返回值，不能成为公开 DTO；普通 tx 也不是能力。Root提供窄 CurrentConfigurationAccess adapter用于current actor+native历史matcher、每page/packet/response复核；repository最终写事务重新校验scope/lease/version/count，不能只相信业务层缓存的permissionVersion。终态complete evidence不能从 safe_result 客户端JSON重建。

202 HTTP 返回后既有私有 HTTP frame 已关闭，不能复制旧 ALS frame 或伪造 session 继续 Entity 调用。M8 需 Root 单独安装窄 configuration-job 执行来源：从 durable job 的原 request/key/actor/session/版本和期限重新证明当前真实 session/account/credential epoch/权限，再建立仅绑定 exact job-step 的 server-private context；logout、session revoke、account disable、期限或permission变化在下一包前停止。direct job仍按普通direct权限/确认结果执行，不因该worker context获得批准；approval job还需上述独立V2能力。pipeline session须独立purpose并绑定真实控制台主体，不给浏览器可传的origin字段或系统万能上下文。M11前 schedule 没有native写来源。

schedule只做readonly capture。worker从DB加载实际active creator/account epoch/当前grants和不可变schedule version，使用M8新窄background-capture能力及固定1.5路径/预算；不构造HTTP sid/JWT/superAdmin，不采用metrics-system-purpose绕过RBAC。缺账号、撤权、disabled workspace、CID重绑或secret权限不完整暂停并记录安全原因。每次due run有唯一key/版本/时间和freshcreator授权；M11前不提供脱离当前主体的后台apply/rollback。

GitOps仅记录安全commit SHA/repository display name/pipeline reference和真实job/plan，不主动push外部Git。decK session单独purpose/read或精确已批准plan/write，当前授权每响应/packet重验；全局credential协议列表在BFF转成Consumer及六类nested分页，不放宽Kong白名单。rawtoken由受控secretfile注入固定runner，不进argv/env/日志/artifacts，`DECK_ANALYTICS=off`/parallelism1、官方固定decK1.1.0校验；未知packet/额外DELETE/PUT通用upsert拒绝。

## 9. 约束测试、真实备份恢复与证据

SQL011实际隔离PostgreSQL测试覆盖完整cid/wid/typed-parent/版本/hash/material FK、不可变manifest、DAG循环/缺parent/count缺页、身份与secret互换、lease_generation/CAS、同key不同body、lostCOMMIT、并发purge与activebaseline/download pin、跨alias physicalscope、当前撤权及schedule暂停。runtime角色为非super/nonowner；版本、objects、secretrefs、collection/pages、plan对象、attempts、scheduleversions等append-only表SELECT/INSERT且UPDATE/DELETE/TRUNCATE拒绝，误grantCRUD后仍由trigger拒绝。

所有job阶段都有真实独立故障证据：预算、分页loop、错kind/parent、临时网络失败、capture中变更、缺失Basic/OAuth原文、审批体篡改、late revoke、native timeout、旧lease、DB丢COMMIT ack和下载半途撤权；不能只写与实现相同的镜像assertion。至少两个page含全部八核心、有效Target、SNI/CA和六种credential。manifest/count/recovery完整后固定decK离线validate，再真实BFFadapter diff/sync，DELETE有recyclegraph和审计，approval无授权零packet。

回滚要真实Proxy验证原KeyAuth/BasicAuth/JWT/OAuth/HMAC、ACL允许/拒绝、证书/SNI及Target有效权重；Admin GET、CLI exit0或YAML格式通过不代替凭证可用性。Portal旧key/Consumer/ACL历史和managedmetrics复制必须明确拒绝。原始秘密只存在获授权短期下载或运行验证内存/0600材料；审计、事件、日志、CLIstdout、screenshots、reports和Git扫描无原文。

控制台数据库灾备与Native配置导出分开：恢复独立PostgreSQL加密备份需要控制台schema migrations、加密密钥管理和一致metadata恢复；不能把decK文件称为RBAC/Portal/workflows/审计完整备份。真实演练在独立库/独立Kong中进行，不把生产库restore成测试。SQL011/V2/全部端点冻结、源码与多端typecheck通过后才唯一部署和Security独占实测；本文目前不是验收证据。


## 真实运行数据库角色

正式快照、manifest/apply、状态更新、原键重放及回滚的真实数据库验证使用实际非owner、非superuser运行角色调用服务，owner仅负责迁移与预置。不可变版本和证明的SELECT/INSERT权限保持，不为行锁增授UPDATE；锁定可变root引用和revision，使用不可变外键/HMAC验证对应版本。单独证明非法DML被拒绝，不能替代正式成功路径在该运行角色下的验证。
