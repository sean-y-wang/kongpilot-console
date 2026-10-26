# M6 存储、独立门户认证与公共工作流合同

本文件是 M6 已审定的存储与认证合同。M5 已提交 df98907，Root 已正式释放 M6 源码实施；SQL008 与门户认证正在实现和隔离验证，尚未部署到应用运行库。M5 的 SQL007 保持冻结。若实施时合同变化，先同步接口所有者再更新本文件。

迁移所有者 `/root/m0_storage`；`modules/portal-auth/**` 同属该所有者。`modules/portal/**` 与 `modules/workflows/**` 由 `/root/m0_kong` 实现。Root 和 `/root/m1_review` 负责已批准计划的私有执行能力、Mutation/NativePolicy/Kong 逐层校验，Root 负责 AppModule 注册与控制台授权；前端由 `/root/m0_frontend` 实现。以 [公共工作流基础设计](../../architecture/security/m6-m11-workflow-foundation-proposal.md) 和 [M6 实施计划](m6-implementation-plan.md) 为基础，不临时改集群执行模式。

## 身份、租户和通用数据约定

- 门户开发者按 `cluster_id + workspace_id` 分别注册。账号、应用、密钥、会话不跨租户继承；一个人访问另一门户租户时须独立注册和登录。开发者不是控制台 `users`，不能写入控制台角色、团队或用户绑定。
- 租户由启用且公开发布的 `portal_settings.slug` 引导。公共选择器仅展示该集合；不调用 `/clusters`，不扫描或暴露未发布工作区。所有受保护门户请求显式携带引导返回的 `clusterId`、`workspaceId`，与当前门户会话完全相等。缺省工作区不能按当前控制台选择器或未验证 tag 推断。
- 下述 `cid/wid` 是数据库列 `cluster_id/workspace_id` 的缩写，`UUID` 均由服务器生成。以 UUID id 为主键的租户业务表有 `(cid,wid,id)` 唯一键和到 `workspaces(cid,id)` 的复合 FK；修订/步骤等关联表使用下文完整复合 PK；子表用完整 `(cid,wid,parent_id)` FK，不靠服务代码补救跨集群引用。数据库 FK 均 `ON DELETE RESTRICT`，除明确的过期认证历史清理外不物理级联删除。
- 所有 `revision` 为正整数，CAS 失败返回 `409 REVISION_CONFLICT`。普通可变业务对象默认含 `created_at/updated_at TIMESTAMPTZ`；软删除含 `deleted_at/retention_until`，状态与两列相互约束，ID/slug/账号名称不复用。每张表的时间列在下文列明；UTC 时间通过 ISO 字符串返回。
- UUID 格式、字段数量、长度和 JSON 类型同时由 DTO 与 SQL CHECK 限制。正文和上传有明确字节预算；SQL 全部参数化。列表采用绑定 actor、cid/wid、过滤项、权限/对象修订号的签名游标，默认 20、最大 100，不全量拉取、不提供伪跳页。
- Native Consumer、Service、Plugin、ACL、Key UUID 是经过验证的原生引用，不引用可淘汰的 `entity_index`。工作区仍按现有保留标签和父实体规则核验；不存在、未知或多保留标签的原生对象不能因门户记录而获得授权。

## SQL008 门户表

下列为完整合同字段，实际源文件为 `infrastructure/migrations/008_m6_portal.sql`。`TEXT` 自由输入的长度限制注明，秘密密文为 `TEXT` 并带对象上下文 AAD，哈希为小写 SHA256/HMAC hex64。SQL CHECK 对状态、hash、长度、JSON 类型和非空关联做限制，服务层补充语义与当前原生事实校验。

| 表 | 字段 | 主键、关联与约束 |
| --- | --- | --- |
| `portal_settings` | `id UUID`, `cid UUID`, `wid UUID`, `slug TEXT(1..80)`, `name TEXT(1..128)`, `description TEXT(0..8192)`, `status active/disabled/deleted`, `published BOOLEAN`, `registration_enabled BOOLEAN`, `public_proxy_origin TEXT`, `branding JSONB object`, `revision INT`, `created_at`, `updated_at`, `deleted_at`, `retention_until` | 唯一 `(cid,wid)`、全局唯一 slug；slug 为小写字母/数字/短横线；代理 origin 仅 HTTP(S) 公共来源、无 userinfo/query/fragment，不接受 Kong Admin URL；branding 只白名单颜色、标题和本地资源引用，不存任意 CSS/HTML/脚本 URL；deleted 必须 unpublished。 |
| `portal_developers` | `id UUID`, `cid UUID`, `wid UUID`, `username TEXT(3..64)`, `email TEXT(3..254)`, `display_name TEXT(1..128)`, `password_hash TEXT`, `status pending/active/disabled/rejected/deleted`, `credential_epoch BIGINT default 1`, `revision INT default 1`, `failed_attempts INT default 0`, `locked_until TIMESTAMPTZ?`, `must_change_password BOOLEAN default false`, `reviewed_by UUID?`, `reviewed_at TIMESTAMPTZ?`, `review_reason TEXT(0..2048)`, `created_at`, `updated_at`, `deleted_at`, `retention_until` | 用户名规范化后唯一 `(cid,wid,username)`，邮箱规范化后唯一 `(cid,wid,email)`；reviewed_by FK 控制台 users，不由注册或 profile DTO 写入；epoch 正数、失败次数非负；pending 不能登录或领取 key；账号 status/credential_epoch 的安全变化在同一事务撤销对应门户会话；仅 displayName 修改不因 revision++强制退出。 |
| `portal_sessions` | `id UUID`, `cid UUID`, `wid UUID`, `developer_id UUID`, `family_id UUID`, `credential_epoch BIGINT`, `refresh_token_hash TEXT hex64`, `csrf_token_hash TEXT hex64`, `refresh_generation INT default 0`, `expires_at`, `revoked_at?`, `ip TEXT?`, `user_agent TEXT(0..1024)?`, `created_at`, `updated_at` | 完整作用域 FK 到开发者；`UNIQUE(cid,wid,id)`；会话与当前账号 epoch/status、当前门户/工作区状态每次认证和 refresh 重查；数据库是撤销权威，Redis 不能放行数据库已撤销会话。 |
| `portal_refresh_history` | `cid UUID`, `wid UUID`, `session_id UUID`, `token_hash TEXT hex64`, `generation INT`, `used_at TIMESTAMPTZ`, `expires_at TIMESTAMPTZ` | PK `(session_id,token_hash)`，完整作用域 FK 到 sessions；仅命中已使用的有效 refresh hash 才认定重放并撤销整 family，任意伪造 sid/secret 不得导致他人退出；过期清理按 expires_at 索引。 |
| `portal_operations` | `id UUID`, `cid UUID`, `wid UUID`, `developer_id UUID`, `idempotency_key TEXT(8..128)`, `request_hash TEXT hex64`, `module TEXT`, `action TEXT`, `target_id UUID?`, `workflow_id UUID?`, `state running/succeeded/failed/uncertain`, `remote_started BOOLEAN`, `remote_completed BOOLEAN`, `payload_secret TEXT?`, `result_secret TEXT?`, `safe_result JSONB object`, `error_code TEXT?`, `created_at`, `updated_at` | 唯一 `(developer_id,idempotency_key)`；作用域开发者/工作流 FK；module 限 applications/credentials/profile/password；只向原开发者与当前同租户会话返回安全回执。密码不保留在 payload/result，request_hash 只使用秘密 HMAC。SQL-only 成功回执与业务/audit 同事务；未知 COMMIT 不覆盖已成功回执。 |
| `portal_applications` | `id UUID`, `cid UUID`, `wid UUID`, `developer_id UUID`, `name TEXT(1..128)`, `description TEXT(0..8192)`, `status active/disabled/deleted`, `revision INT`, `created_at`, `updated_at`, `deleted_at`, `retention_until` | 作用域开发者 FK；唯一 `(cid,wid,developer_id,name)`；创建者不能任意指定 developer_id/status/native Consumer；停用/删除不假称原生 key 已失效，须通过明确的凭证撤销工作流完成。 |
| `portal_publications` | `id UUID`, `cid UUID`, `wid UUID`, `transport_scope TEXT hex64`, `slug TEXT(1..80)`, `name TEXT(1..128)`, `description TEXT(0..8192)`, `category TEXT(0..128)?`, `service_id UUID`, `acl_group TEXT`, `key_auth_plugin_id UUID?`, `acl_plugin_id UUID?`, `current_revision INT`, `published_revision INT?`, `workflow_id UUID?`, `state draft/pending/published/suspended/deleted`, `revision INT`, `created_by UUID`, `updated_by UUID`, `created_at`, `updated_at`, `deleted_at`, `retention_until` | 控制台创建/更新人 FK；draft 时捕获原物理 gateway transport_scope，之后不可改；唯一 `(cid,wid,slug)`，另有部分唯一 `(transport_scope,service_id) WHERE state <> 'deleted'`，防止不同 CID 别名对同一原生 Service 建竞争发布；原有租户 registry 唯一性保留；acl_group 固定 `kos-portal-api-<publication UUID>`；published_revision 只能指向同对象不可变修订；published 要求两个已验证 Service-bound 插件引用。有旧 published_revision 时新草稿/待审批不覆盖公开字段或把旧内容隐式撤回。 |
| `portal_publication_revisions` | `cid UUID`, `wid UUID`, `publication_id UUID`, `revision INT`, `service_id UUID`, `title TEXT(1..128)`, `version_label TEXT(1..64)`, `description TEXT(0..8192)`, `categories TEXT[]`, `openapi_document JSONB object`, `document_hash TEXT hex64`, `source_secret TEXT?`, `validation_report JSONB object`, `created_by UUID`, `created_at` | PK `(cid,wid,publication_id,revision)`；append-only；规范化、验证后的文档最大 3 MiB，类别最多 20 个；原上传若保留仅加密，public API 仅返回通过校验的文档。服务器生成说明只能使用公共代理 origin，不能公开 Service.host/Admin 地址。 |
| `portal_publication_proofs` | `cid UUID`, `wid UUID`, `publication_id UUID`, `publication_revision INT`, `transport_scope TEXT hex64`, `publication_proof_secret TEXT`, `publication_proof_hmac TEXT hex64`, `workflow_id UUID`, `workflow_execution_id UUID`, `workflow_plan_revision INT`, `workflow_plan_hash TEXT hex64`, `verified_at TIMESTAMPTZ`, `created_at` | PK `(cid,wid,publication_id,publication_revision)`，完整同租户 document revision/workflow execution+plan version/hash FK，transport_scope 与 publication 完整 FK 匹配；append-only；在发布执行成功的 metadata 事务内插入，不以 UPDATE 修改 draft 文档。证明含已批准并实际核验的 Service/plugin/schema/tag/FK/workspace+cluster revision/transportScope/version 证据，按 publication/cid/wid/revision 加密。public API 不返回证明或 HMAC。 |
| `portal_content` | `id UUID`, `cid UUID`, `wid UUID`, `slug TEXT(1..80)`, `title TEXT(1..128)`, `current_revision INT`, `published_revision INT?`, `workflow_id UUID?`, `state draft/published/deleted`, `revision INT`, `created_by UUID`, `updated_by UUID`, `created_at`, `updated_at`, `deleted_at`, `retention_until` | 唯一 `(cid,wid,slug)`，发布修订完整 FK；元数据修改 CAS，删除软保留；public title/markdown 只取 published_revision，不取正在编辑草稿。 |
| `portal_content_revisions` | `cid UUID`, `wid UUID`, `content_id UUID`, `revision INT`, `title TEXT(1..128)`, `markdown TEXT`, `content_hash TEXT hex64`, `created_by UUID`, `created_at` | PK `(cid,wid,content_id,revision)`，append-only；Markdown 最大 256 KiB，禁原始 HTML、脚本/数据 URL、任意远端嵌入，持久化和渲染均校验。 |
| `portal_application_grants` | `id UUID`, `cid UUID`, `wid UUID`, `transport_scope TEXT hex64`, `application_id UUID`, `publication_id UUID`, `developer_id UUID`, `consumer_id UUID`, `acl_group TEXT`, `acl_id UUID`, `acl_credential_ref_id UUID?`, `current_generation INT default 0`, `current_credential_id UUID?`, `state pending/active/partial/rotating/revoking/revoked/uncertain/disabled`, `workflow_id UUID?`, `reservation_released_at TIMESTAMPTZ?`, `revision INT`, `created_at`, `updated_at`, `revoked_at?` | transport_scope 从已封存成功 publication proof 捕获且不可改，在第一个 native 包前连同预分配 Consumer/ACL/Key ID/group 持久化 pending reservation；consumer_id、acl_group、预分配 acl_id 和 scope 均为不可变身份，不允许改指针转移受控所有权；部分唯一 `(cid,wid,application_id,publication_id)` 排除严格证明的 revoked/released 历史，永久唯一 `(cid,consumer_id)` 和 `(transport_scope,consumer_id)`；作用域 app/publication/developer FK；每个应用×publication 独立 Consumer，绝不让同一个应用 key 自动访问另一 API。group/transport_scope 与 publication 完整 FK 匹配，ACL 归属该 Consumer；完整原生对应关系由审批与执行前再核验。active 必须有正 generation 和同 grant 的 current_credential_id；released 条件及历史重验见下文。 |
| `portal_credentials` | `id UUID`, `cid UUID`, `wid UUID`, `grant_id UUID`, `developer_id UUID`, `consumer_id UUID`, `credential_kind TEXT default key-auth`, `kong_id UUID`, `credential_ref_id UUID?`, `generation INT`, `previous_credential_id UUID?`, `key_secret TEXT`, `key_fingerprint TEXT hex64`, `state pending/active/rotating/revoking/revoked/uncertain/deleted`, `workflow_id UUID`, `issue_operation_id UUID?`, `revoke_workflow_id UUID?`, `revoke_operation_id UUID?`, `recycle_entry_id UUID?`, `last_revealed_at TIMESTAMPTZ?`, `revision INT`, `created_at`, `updated_at`, `revoked_at?`, `deleted_at?`, `retention_until?` | 作用域 grant/developer/workflow FK；workflow_id 是原始发放版本所属请求，revoke_workflow_id 单独关联实际吊销请求；唯一 `(cid,wid,grant_id,generation)`、`(cid,consumer_id,kong_id)`；一个 grant 至多一个 active generation；previous 指向同 grant；kind 仅 key-auth，其他插件凭证以后显式扩展。key 不进入普通 JSON、审计或 diff；AAD 绑定 cid/wid/credentialID/generation。 |

凭证复合关系：008 为既有 `credential_refs` 增加只读唯一键 `(cluster_id,consumer_id,credential_type,kong_id,id)`，门户 Key 和 ACL 引用同时约束上述五列，不能把另一 Consumer 的加密恢复引用挂入应用。`portal_credentials` 保存 owner-bound 领取密文，`CredentialStoreService` 保存原生回收恢复所需密文，两者用途不互相授予权限。回收引用用 `(cid,wid,recycle_entry_id)` FK，008 追加既有 recycle_entries 的 `(cid,wid,id)` 唯一键而不改旧数据；legacy NULL archive scope 不用于门户领取或批准能力。

作用域相同仍不能混用所有者：apps 加 `(cid,wid,id,developer_id)` 唯一键，grant 用同四列 app FK；grant 加 `(cid,wid,id,developer_id,consumer_id)` 唯一键，credential 用同五列 FK，历史物理作用域沿 grant 的不可变 transport_scope 推导；publication 加 `(cid,wid,id,acl_group,transport_scope)` 唯一键，grant 的 group/物理作用域由完整 FK 绑定。credential 的 `(cid,wid,grant_id,id,generation,consumer_id)` 唯一键与 grant.current_credential_id/current_generation/consumer_id 反向完整 FK，采用延迟校验以允许原子轮换。服务层仍核验真实 Native 引用，数据库记录不替代网关证据。DB 的 soft-deleted 应用状态 deleted 显式映射公开 ApplicationSummary.state=archived；其他 DTO 状态与 camelCase 字段按 [业务合同](m6-business-contract.md) 映射，不借状态别名隐藏 partial/uncertain。

门户 developer 请求中的 issuance compiler 严格 DB-only：读取当前公开 publication、不可变 successful publication proof、本人 app/grant 和数据库 workspace/cluster revision，生成一次 key/UUID 后封存计划；不调用 Entities/Kong、不切出 HTTP ALS、不构造 console actor、不开启 system-read。证明只有规划用途，不代表当前原生发送许可；真实控制台 approve/execute 解密计划后 fresh 核验全部依赖、认证图、预分配 ID 不存在和当前权限。变更后重新发布即使文档相同也产生新的 publication revision/proof，旧证明永不改写。

索引：所有门户列表按 `(cid,wid,state/status,created_at DESC,id DESC)`；开发者应用和回执额外索引 developer_id；活跃会话按 developer_id/family_id；refresh_history 按 expires_at；grant 按 application/publication/state；credential 按 grant/state/generation。公共 tenant 列表只走 published+active 部分索引。

## SQL008 公共工作流表

使用 `workflows` 作为请求总表，不另建同义 workflow_requests。使用 `workflow_approvals` 表示决策，不另建 workflow_decisions。修改计划产生新的 `workflow_versions` 行；已经提交的版本不覆盖。

| 表 | 字段 | 主键、关联与约束 |
| --- | --- | --- |
| `workflow_definitions` | `id UUID`, `cid UUID`, `wid UUID`, `code TEXT(1..80)`, `name TEXT(1..128)`, `kind TEXT`, `current_version INT`, `status active/disabled/deleted`, `revision INT`, `created_by UUID`, `created_at`, `updated_at`, `deleted_at`, `retention_until` | 作用域唯一 code；kind 白名单 portal-publication/portal-credential-issue/portal-credential-rotate/portal-credential-revoke/portal-developer-review/portal-metadata/native-change；native-change 仅为 M11 模型预留，M6 HTTP 不启用通用变更入口。 |
| `workflow_definition_versions` | `cid UUID`, `wid UUID`, `definition_id UUID`, `version INT`, `mode single/multi/quorum`, `allow_self_approval BOOLEAN default false`, `policy JSONB object`, `policy_hash TEXT hex64`, `created_by UUID`, `created_at` | PK `(cid,wid,definition_id,version)`，append-only；M6 mode 只能 single，自审固定 false；policy 只安全审批结构，无脚本、secret、任意 SQL/URL。M11 才启用其他模式。 |
| `workflow_definition_stages` | `cid UUID`, `wid UUID`, `definition_id UUID`, `definition_version INT`, `level INT`, `name TEXT(1..128)`, `required_approvals INT`, `approver_module TEXT`, `approver_action TEXT`, `selector JSONB object`, `created_at` | PK 完整 scope+definition/version/level，版本 FK；M6 只有 level=1、required_approvals=1、workflows.approve；selector 只候选限制，永远不代替当前完整权限校验。 |
| `workflows` | `id UUID`, `cid UUID`, `wid UUID`, `kind TEXT`, `subject_type TEXT`, `subject_id UUID`, `requester_type developer/console`, `requester_developer_id UUID?`, `requester_user_id UUID?`, `definition_id UUID`, `definition_version INT`, `plan_revision INT`, `plan_hash TEXT hex64`, `execution_mode direct/approval`, `approval_required BOOLEAN`, `state draft/pending/approved/executing/succeeded/partial/failed/uncertain/rejected/cancelled/expired`, `revision INT`, `request_hash TEXT hex64`, `idempotency_key TEXT(8..128)`, `approved_by UUID?`, `approved_at?`, `not_before?`, `window_start?`, `window_end?`, `expires_at`, `cancelled_at?`, `created_at`, `updated_at` | requester 两列恰一非空，developer 完整 scope FK，console FK users；唯一作用域+requester+idempotency key（分别部分索引）；当前版本/mode/approvalRequired 完整 FK；kind/subject 组合白名单；window_end > window_start，执行时间不能延长 expires_at。无审批的 direct 请求不能有 approved_by/approved_at/approved 状态。M6 不接受客户端计划时间/审批人/执行身份。 |
| `workflow_versions` | `cid UUID`, `wid UUID`, `workflow_id UUID`, `plan_revision INT`, `plan_hash TEXT hex64`, `execution_mode direct/approval`, `approval_required BOOLEAN`, `payload_secret TEXT`, `policy_version INT`, `step_count INT`, `native_request_count INT`, `steps_hash TEXT hex64`, `safe_diff JSONB array`, `safe_impact JSONB object`, `expires_at`, `created_by UUID?`, `created_by_developer_id UUID?`, `created_at` | PK `(cid,wid,workflow_id,plan_revision)`，唯一同键+plan_hash，以及同版本/hash/mode/approvalRequired；append-only；creator 恰一非空；step_count≤16、native_request_count≤32；计划、范围、执行模式、原生 ID/秘密、依赖、hash、expiry 不可改；safe JSON 不含 raw config、password、key 或 URL userinfo。 |
| `workflow_stages` | `cid UUID`, `wid UUID`, `workflow_id UUID`, `plan_revision INT`, `plan_hash TEXT hex64`, `level INT`, `required_approvals INT`, `state pending/active/approved/rejected/skipped`, `activated_at?`, `completed_at?`, `created_at`, `updated_at` | PK scope+workflow/revision/level，完整版本/hash FK；仅 approval_required=true 创建实例阶段且与定义版本相同；无审批 direct 没有阶段/批准行。M6 只有单级，一票通过不能因重复 HTTP 加两票。 |
| `workflow_approvals` | `id UUID`, `cid UUID`, `wid UUID`, `workflow_id UUID`, `plan_revision INT`, `plan_hash TEXT hex64`, `level INT`, `approver_id UUID`, `decision approve/reject`, `reason TEXT(0..2048)`, `request_id TEXT?`, `idempotency_key TEXT(8..128)`, `decided_at TIMESTAMPTZ` | 完整 stage 与 version/hash FK；唯一 `(workflow_id,plan_revision,level,approver_id)`；append-only，拒绝后不能覆盖成批准；同 key/同请求返回同决策，不同决策冲突；当前 approve tuple、非提交人、自身非 developer 必须校验。 |
| `workflow_steps` | `id UUID`, `cid UUID`, `wid UUID`, `workflow_id UUID`, `plan_revision INT`, `plan_hash TEXT hex64`, `execution_mode direct/approval`, `approval_required BOOLEAN`, `step_key TEXT(1..160)`, `step_order INT`, `kind native/metadata`, `handler TEXT?`, `entity_type TEXT`, `entity_id UUID?`, `parent_id UUID?`, `credential_kind TEXT?`, `permission_action write/delete`, `mutation_action create/update/delete/restore?`, `mutation_payload_hmac TEXT?`, `mutation_idempotency_key TEXT?`, `before_fingerprint TEXT?`, `native_requests JSONB array`, `metadata_before_hmac TEXT?`, `metadata_revision INT?`, `metadata_payload_hmac TEXT?`, `dependencies UUID[]`, `state pending/running/succeeded/failed/uncertain/skipped`, `operation_id UUID?`, `recycle_entry_id UUID?`, `safe_result JSONB object`, `receipt_secret TEXT?`, `after_fingerprint TEXT?`, `error_code TEXT?`, `revision INT`, `started_at?`, `completed_at?`, `created_at`, `updated_at` | 唯一 scope+workflow/revision/key 和 order，以及 `(cid,wid,id,workflow_id,plan_revision,plan_hash)`；完整版本/hash/mode/approvalRequired FK；步骤配置字段 immutable，只有进度字段 CAS；native_requests 保存 method/path_hash/native_type/native_id/parent_id/credential_kind/body_hmac/before_hmac 的安全白名单清单，不存 raw body；native 方法仅 Kong1.5写白名单。metadata handler 固定服务器函数、native_requests 为空、operation_id/mutation_action 必为 NULL；无审批 direct native 的 operation_id 必为 NULL；依赖必须是同版本 step UUID、无环且先于步骤；approved native operation 精确绑定一次并反向唯一。 |
| `workflow_executions` | `id UUID`, `cid UUID`, `wid UUID`, `workflow_id UUID`, `plan_revision INT`, `plan_hash TEXT hex64`, `execution_mode direct/approval`, `approval_required BOOLEAN`, `approved_by UUID?`, `execution_actor_id UUID`, `state claimed/executing/succeeded/partial/failed/uncertain`, `revision INT`, `snapshot_state pending/ready/failed`, `snapshot_secret TEXT?`, `snapshot_hash TEXT?`, `snapshot_id UUID?`, `claim_token_hash TEXT hex64`, `request_id TEXT?`, `idempotency_key TEXT(8..128)`, `expires_at`, `started_at`, `completed_at?`, `updated_at` | 唯一 `(workflow_id,plan_revision)` 及 `(cid,wid,id,workflow_id,plan_revision,plan_hash)`；完整版本/hash/mode/approvalRequired FK；执行账号始终 FK users 且非空，approval_required=true 才要求 approved_by 非空，false 时 approved_by 必为 NULL；snapshot_state=ready 必须有加密快照/hash，第一步之前验证；snapshot_id 为 M8/M11 兼容预留，不建不存在 snapshots 表的假 FK。claim 是随机服务器值，不公开、不成为 HTTP 授权。 |
| `workflow_events` | `id UUID`, `cid UUID`, `wid UUID`, `workflow_id UUID`, `plan_revision INT`, `plan_hash TEXT hex64`, `execution_id UUID?`, `step_id UUID?`, `actor_type developer/user/system`, `actor_id UUID?`, `developer_id UUID?`, `action TEXT`, `result TEXT`, `error_code TEXT?`, `safe_metadata JSONB object`, `request_id TEXT?`, `operation_id UUID?`, `created_at` | 完整 workflow/version/hash/execution/step FK；append-only；developer 时 actor_id NULL 且 developer_id 在相同租户；user 时 actor_id 必填且 developer_id NULL；system 两者均 NULL；仅安全结果/code/UUID，不保存未脱敏的 Kong error.message。 |

所有 state 转移由锁/CAS 和有限状态机允许；CHECK 的状态列表不能单独证明合法转移。版本/定义版本/文档修订/审批/事件表使用 append-only UPDATE/DELETE/TRUNCATE 触发器，运行时非超级数据库账号只获必需 SELECT/INSERT；迁移器 grants 必须同步这些新表，而不能仅依赖 audit_events 的既有例外。普通业务删除软保留，门户 owner 不能清理工作流审批/审计。workflows 的 subject_type/subject_id 对照白名单 portal_settings/developers/applications/publications/content/grants；同租户 subject 存在与 kind 相符由延迟约束触发器及 compiler 双重验证，不允许任意实体 ID 当门户对象。

Root 已审定 M6 最多 16 个逻辑步骤、32 个原生写请求，计划和执行前快照各不超过 2 MiB。单 publication auth 边界扫描沿用已有聚合分页/字节预算。不能通过把逐页 size 改小改变已签名游标 query。运行时不得把任一预算不足解释为安全或默认无冲突。

模式约束是单向而非等价：`execution_mode='approval'` 必须 `approval_required=true`；`approval_required=false` 必须 `execution_mode='direct'`。direct 集群的 credential issue/rotate/revoke 仍为 approval_required=true、真实批准记录和私有批准能力。版本中 mode/approvalRequired 是不可变快照，实际集群 revision/mode 在每步执行前核验；客户端不能把 approvalRequired 改 false。

Direct compound publication/configuration 在真实控制台确认后按普通 direct Mutation 执行，不自审、不写伪审批记录、不进入私有 approved capability。对应 `workflow_approvals` 零行、approved_by NULL。直接 native 步骤的 operation_id 必须 NULL，既有普通原生账本四个新 workflow binding 列仍全 NULL；步骤仅在 safe_result.nativeOperationId 和上下文加密 receipt_secret 保存实际回执关联，用原 actor/cid/wid/key/requestHash 重验作恢复证据，不能作发送权限或 approved FK。最后 direct metadata 通过现有 IAMexecute callback 原子保存 proof/active/步骤/父终态。需要审批的 metadata 则经私有固定 handler SQL 事务，仍无 native operation 关联。

008 对 `mutation_operations` 只新增 `workflow_execution_id UUID?`、`workflow_plan_revision INT?`、`workflow_plan_hash TEXT?`、`workflow_step_id UUID?`。新四列必须全 NULL 或全非 NULL；非 NULL 时既有 `workflow_id`、`workspace_id` 也必须非空，并用完整 cid/wid/workflow/execution/revision/hash/step 关联对应表。非空 workflow_step_id 加唯一约束，每个 native 逻辑步骤只能有一个 operation；`workflow_steps.operation_id` 与新 mutation 的创建在同一个事务内 CAS 关联，循环 FK 使用延迟校验。既有 legacy workflow_id 单独存在不授予任何已批准能力，不回填为猜测的版本。metadata 步骤在固定 handler 的 SQL 事务内保存结果并审计，operation_id 必为 NULL；M6 不修改 IamMutationsService 的 approval bypass，M11 扩展通用 IAM 工作流时另设计 ledger 关联。

### 私有计划与执行接口

以下为 Kong/Reviewer 对接目标，不是给客户端直接提交的 DTO：

```ts
interface WorkflowPlanV1 {
  version: 1;
  clusterId: string; workspaceId: string; workflowId: string;
  planRevision: number; kind: WorkflowKind;
  executionMode: 'direct' | 'approval'; approvalRequired: boolean;
  subject: { type: string; id: string };
  requester: { type: 'developer' | 'console'; id: string };
  definition: { id: string; version: number; policyHash: string };
  issuedAt: string; expiresAt: string;
  scope: { transportScope: string; clusterRevision: number; workspaceRevision: number };
  prerequisites: Array<{ type: string; id: string; fingerprint: string }>;
  steps: Array<{
    id: string; key: string; order: number;
    kind: 'native' | 'metadata'; handler?: string;
    entityType: string; entityId?: string; parentId?: string; credentialKind?: string;
    permissionAction: 'write' | 'delete'; dependencies: string[];
    mutationAction?: 'create' | 'update' | 'delete' | 'restore';
    mutationPayload?: unknown; mutationPayloadHmac?: string; mutationIdempotencyKey?: string;
    nativeRequests?: Array<{ method: string; canonicalPath: string; nativeType: string;
      nativeId?: string; parentId?: string; credentialKind?: string;
      body?: unknown; bodyHmac: string; beforeHmac?: string }>;
    metadata?: unknown;
    beforeFingerprint?: string;
    metadataBeforeHmac?: string; metadataRevision?: number; metadataPayloadHmac?: string;
  }>;
  generated?: { consumerId: string; aclId: string; credentialId: string; key: string };
}
```

计划含 raw key/body 的唯一存储路径是上下文加密的 payload_secret；plan_hash/steps_hash/mutation_payload_hmac/native body_hmac 使用服务端 canonical + SecretService HMAC，不能用普通 SHA256 暴露低熵秘密。逻辑 DELETE 的确认/回收 payload 与原生 DELETE 空 body 分别计算 HMAC，不能共用含义不清的摘要。公开 planView 只含版本、范围、masked diff、影响面、步骤安全摘要、依赖与状态，绝不返回 generated/nativeRequests.body 或加密载荷。

`WorkflowEngine.claimSnapshot(...)` 的批准路径应在数据库行锁下核验已提交审批、当前版本/hash/expiry、当前执行账号与权限，创建或读取唯一 execution 并完成执行前只读对象图快照。返回候选仅供服务器调用：

```ts
interface ApprovedClaimSnapshot {
  executionId: string; workflowId: string; clusterId: string; workspaceId: string;
  planRevision: number; planHash: string;
  executionMode: 'direct' | 'approval'; approvalRequired: true;
  approvedBy: string; executionActorId: string; expiresAt: string;
  stepsHash: string; snapshotHash: string;
}
```

候选自身不是授权：私有能力服务重新解密版本、比对全部 normalized step 行/数量/hash/parent、ready snapshot、执行行 CAS 和当前审批，才建立 WeakMap 祖先能力。无审批 direct 使用普通执行快照，approvedBy=NULL，不构造或传递 ApprovedClaimSnapshot；direct+approvalRequired=true 的凭证流程才使用该批准候选。

`ApprovedWorkflowExecutionService.runApprovedExecution` / `KongExecutionContextService.runApprovedWorkflow` / `runApprovedStep` 的步骤能力绑定上述版本/执行/step、当前真实控制台会话、逻辑 mutationAction/payload 与独立 native method/path/body、workspace/parent 和分配的 operationId。Mutation/NativePolicy/Kong before-send 各自 fresh 校验；网络请求携带 workflowId、普通对象拷贝、伪造 claim_token 或 portal JWT 都不能创建能力。祖先失效、会话结束、权限撤销、计划/配置变化、lease 丢失、未决相同影响范围都阻止下一包。执行模式始终不变。

M6 在 approve 的真实控制台 HTTP 请求中同步执行；批准已提交而未认领显示 approved/待执行，可由当前合格管理员显式执行。执行已认领/已发包后不会因为新 idempotency key、重复 approve、门户重交或账号切换而重发。failed 已知结果与 uncertain 未知结果区分，partial 的成功步骤不重发。reconcile 在物理锁内查实际可信证据和 CAS 回写；单次 404 不能证明超时请求以后不会完成。

M11 使用同表增加多级/会签/调度/窗口；预留字段不意味着 M6 已交付这些功能。M11 的后台 approved executor 必须显式由服务器创建并核验当前批准账号权限，不能假造控制台 session 或默认 superAdmin。

## 独立 PortalAuth 实现合同

计划文件：`modules/portal-auth/portal-auth.types.ts`、`portal-auth.service.ts`、`portal-auth.controller.ts`、`portal-auth.guard.ts`、`portal-auth.module.ts`。模块只注册自身 controller/service/guard；Db/Redis/Secret/Audit 是全局既有服务，不重复注册。PortalAuthService 构造依赖为 DbService、RedisService、SecretService、AuditService、AuthorizationService，外加注入 `APPROVED_WORKFLOW_METADATA_POLICY` 窄接口；AuthorizationService 只供内部控制台审核校验，不注入 WorkflowEngine，避免 Engine→PortalAuth→Engine 循环。缺 metadata verifier 的审批集群写入保持 APPROVAL_REQUIRED。PortalAuth 不注入控制台 AuthService，不设置 req.user，不创建 Kong console HTTP actor；业务请求通过独立 `req.portalPrincipal` 传递门户身份。控制台管理审核使用真实控制台 AuthorizationService。

```ts
interface PortalScope { clusterId: string; workspaceId: string }
interface PortalDeveloperView extends PortalScope {
  id: string; username: string; email: string; displayName: string;
  status: 'pending'|'active'|'disabled'|'rejected'|'deleted';
  revision: number; mustChangePassword: boolean; createdAt: string;
}
interface PortalPrincipal extends PortalScope {
  kind: 'portal_developer'; developerId: string; sessionId: string;
  credentialEpoch: number;
}
interface PortalRequestContext {
  requestId: string; ip?: string; userAgent?: string; idempotencyKey?: string;
}
```

服务目标签名：

```ts
PortalAuthService.csrf(scope, {accessToken?,refreshToken?,csrfCookie?}, originProof): Promise<{csrfToken,cookieToken?,expiresAt,authenticated:boolean}>
PortalAuthService.register(scope, {username,email,displayName,password}, context): Promise<{status:'pending'}>
PortalAuthService.login(scope, {username,password}, context): Promise<{developer,accessToken,refreshToken,csrfToken,expiresAt}>
PortalAuthService.authenticate(accessToken): Promise<PortalPrincipal>
PortalAuthService.refresh(scope, refreshToken, csrfToken, context): Promise<{developer,accessToken,refreshToken,csrfToken,expiresAt}>
PortalAuthService.logout(principal, context): Promise<void>
PortalAuthService.me(principal): Promise<PortalDeveloperView>
PortalAuthService.updateProfile(principal, {revision,displayName}, context): Promise<PortalDeveloperView>
PortalAuthService.changePassword(principal, {revision,currentPassword,newPassword,confirmed:true}, context): Promise<{changed:true,reauthenticate:true}>
PortalAuthService.revokeSessions(developerId, scope, tx, context): Promise<void>
PortalAuthService.reviewDeveloper(actor, developerId, scope, {revision,status,reason}, context, tx?): Promise<PortalDeveloperView>
```

Token 三字段仅供 controller 写 Cookie，业务/controller 公开 JSON 不返回 accessToken/refreshToken。`reviewDeveloper` 是 console controller 调用的内部方法，fresh 调用 `assertWholeWorkspace(actor.user,cid,wid,'developers','write')`（审核激活另须 workflows.approve 的同一明确管理范围）；pending→active/rejected、active→disabled、disabled→active 均 CAS/审计，不能由 PortalController 暴露。纯 developer/app/settings 元数据仅允许当前 global/workspace 完整 grant，不能用 tag_group/entity grant 和粗 assertCluster 扩大到整区账号管理。与实际 Service 关联的 publication/request/workflow 使用已有 assertScopedResource，不隐含原生 Service 读取权限。审批模式中的控制台配置写入通过已批准 metadata step，不能把可选 tx 参数当授权。注册用户名固定规范化 `^[a-z0-9._-]{3,64}$`，email 规范化并校验格式；同名不同 scope 不共享账号。

Root 已审定 metadata token 的精确窄接口：

```ts
interface ApprovedWorkflowMetadataPolicy {
  assertStep(input: {
    handler: string; actor: AuthUser; clusterId: string; workspaceId: string;
    entityType: string; entityId: string; before: unknown; revision: number; payload: unknown;
  }, tx: DbService): Promise<void>;
}
// Injection token: APPROVED_WORKFLOW_METADATA_POLICY
```

verifier 要求活跃私有 metadata-step 祖先、同 execution/version/step、固定 handler/当前 before/revision/payload HMAC、同一 SQL tx、fresh 账号/会话/权限/对象状态，并在 await 后、SQL write 前复核；native_requests 必空、operation_id 必 NULL。普通 DTO/对象/tx/workflowId 不创建该祖先。直接模式仍校验自身当前 grants/CAS，审批模式额外 assertStep；IAM 普通入口不增加绕过。

认证机制：

- 必填 `PORTAL_SECRET`，独立于 APP_SECRET；至少 256 bit，拒绝为空、测试默认值或与 APP_SECRET 相等。Issuer=`kongos-portal`，audience=`kongos-portal`，JWT payload 的 kind=`portal_developer`，仅有 sub/sid/cid/wid/credential_epoch/iat/exp，不含控制台角色或 superAdmin。access 15 分钟，refresh 7 天；refresh 为随机 opaque `sid.secret`，数据库仅存 SHA256 hash，轮换、已使用 hash 家族重放检查与当前 epoch 在同一事务。
- 三个 Cookie 分别 `kongos_portal_access`、`kongos_portal_refresh`、`kongos_portal_csrf`，均 Path=`/api/v1/portal`、HttpOnly、SameSite=Strict，生产 HTTPS Secure；不设置跨站 Domain。匿名 csrf Cookie 最长 10 分钟，登录后替换为 session-bound csrf。退出、禁用、密码更改撤销 DB session 并清同路径 Cookie。
- GET `/auth/csrf` 区分已有会话与匿名：存在有效门户 access 或当前未使用的 refresh Cookie 时，fresh 核验会话/开发者/epoch/租户及过期时间，恒时比较 csrf Cookie 与 session hash，返回该原始已验证 csrfToken，不改 hash、不轮换、不覆盖为匿名 Cookie。没有有效会话才发 tenant+origin 绑定、最长10分钟签名的匿名 csrf Cookie。只有已经通过可信 GET origin/Sec-Fetch-Site、scope 与当前 session 证明后，发现 csrf Cookie 缺失/篡改才返回 `403 PORTAL_CSRF_INVALID` 并清当前浏览器三枚 Portal Cookie；该响应不发匿名 token、不撤销 DB family，下一次显式 scoped GET 可匿名发放并要求密码登录。跨 origin/错误 scope 拒绝不能清除另一合法 tenant 的 Cookie。
- 注册和登录也必须验证匿名 cookie+`X-Portal-CSRF`、期限/租户和 Origin。认证后 cookie 写请求、refresh/logout 必须校验 server session 的 csrf hash。不能仅用 SameSite 或前端隐藏按钮代替后端 CSRF。
- `PORTAL_PUBLIC_ORIGINS` 是独立、显式部署的门户 origin 白名单，不复用控制台 PUBLIC_ORIGINS。POST Origin 必须等于配置的门户来源；不信任任意代理 Host/X-Forwarded-Host。缺失/非法 POST origin 或 csrf 返回 403。GET csrf 允许浏览器不发送 Origin；此时要求 Sec-Fetch-Site=same-origin 并使用部署可信路由与已配置门户 origin 验证，不能仅凭任意转发头授权。存在 Origin 时校验同一门户来源；cross-site/same-site跨 origin 请求不能读取或发放 csrf。CORS 只允许明示 origin+credentials；公共文档 GET 不创建登录权限。
- 独立 PortalGuard，控制器使用 `@Public()` 跳过 console AuthGuard 后由自身 guard 保护。门户只接受自身 Cookie；不把控制台 Cookie、控制台 Bearer 或 HTTP 用户字段转成 PortalPrincipal，也不接受门户 JWT 进入控制台。缺省拒绝无 PortalGuard 的 private handler。
- 每次认证/refresh/业务写入读取当前 developer/session/epoch、tenant 发布/启用状态、cluster/workspace 非删除及写入是否 disabled；长 await 后重复核验，不用 Redis TTL allow-cache。不同 cid/wid、developer/app/grant/credential 返回 403，不能仅凭 UUID 读取。
- 复用纯函数 `hashPolicyPassword`，至少 12 字符、最多 72 UTF-8 字节及大小写/数字/符号，bcrypt 成本 10..14（默认 12），不截断。登录失败使用相同安全 401 文案和 dummy bcrypt，按 tenant+username 与来源 IP 限流；连续 5 次失败锁 15 分钟，计数/锁在数据库原子更新。密码更改必须验证旧密码、防重复、确认并立即 epoch++/撤销 family。
- DTO 严格拒绝 status/superAdmin/roles/userId/developerId/credentialEpoch/sessionId/lockedUntil/passwordHash 任意混入。email 和 username 不通过 profile mass assignment 更改；M6 profile 只 displayName。注册返回统一 pending，不自动登录；重复用户名/邮箱响应不返回已有账号身份或密码状态。
- 审计 actorType=`developer`、actorId=`null`，safe before/after 携带 developerId/cid/wid；不要把 developer UUID 填入 users FK。失败审计不含 password、Cookie、Authorization、csrf、refresh 或原始异常。Developer 全局停用只影响自己的 tenant 账号，不同步修改 console users。

## HTTP 合同与 UI 结构

响应继续使用既有统一 envelope。下面只列 envelope 内 `data`；错误使用安全 code/message/requestId。门户业务由 PortalService 实现，PortalAuthService 不生成原生 Consumer/Plugin 或绕过 WorkflowEngine。

### 公共及登录门户

| 方法/路径（前缀 `/api/v1/portal`） | 输入 | data / 约束 |
| --- | --- | --- |
| `GET /tenants` | size/cursor/search | `{items:[{slug,name,clusterId,workspaceId,branding,registrationEnabled}],nextCursor}`，只有 active+published 元数据，无 Admin/Prometheus/内部 URL。 |
| `GET /tenants/:slug` | 无 | 同一安全 tenant descriptor；不存在/未发布/disabled 统一 `404 PORTAL_NOT_AVAILABLE`。 |
| `GET /auth/csrf` | clusterId/workspaceId | `{csrfToken,expiresAt}`；已有合法会话返回原 session-bound token、不 Set-Cookie 覆盖；匿名才设置短期 Cookie。不登录、不轮换 refresh。 |
| `POST /auth/register` | `{clusterId,workspaceId,username,email,displayName,password}` | 202 `{status:'pending'}`，带匿名 CSRF；不返回 password/token。 |
| `POST /auth/login` | `{clusterId,workspaceId,username,password}` | `{developer,csrfToken,expiresAt}` +三 Cookie；pending/disabled/rejected 不可登录。 |
| `POST /auth/refresh` | `{clusterId,workspaceId}` | `{developer,csrfToken,expiresAt}` +轮换三 Cookie；refresh Cookie+CSRF，禁止从 body 传 refresh token。 |
| `POST /auth/logout` | `{clusterId,workspaceId}` | `{loggedOut:true}`，撤销当前 family；CSRF。 |
| `GET /auth/me` | clusterId/workspaceId | PortalDeveloperView；仅自身。 |
| `PATCH /auth/me` | `{clusterId,workspaceId,revision,displayName}` | PortalDeveloperView；CSRF +X-Idempotency-Key。 |
| `POST /auth/password` | `{clusterId,workspaceId,revision,currentPassword,newPassword,confirmed:true}` | `{changed:true,reauthenticate:true,operationId}`；CSRF +幂等键，成功后清 Cookie。 |
| `GET /publications` | clusterId/workspaceId、size/cursor/search/category | published 安全摘要；public metadata，不以应用或 console角色授予 native 读取。 |
| `GET /publications/:id`、`GET /publications/:id/document` | clusterId/workspaceId | 前者已发布 revision 摘要，后者 `{publicationId,revision,format,document}`；无 native config/credentials。 |
| `GET /pages`、`GET /pages/:slug` | clusterId/workspaceId、列表游标 | 已发布 Markdown 安全文档；禁原始 HTML/远端 `$ref`、脚本 URL；Try-it 默认关闭，不代理任意地址。 |
| `GET /applications`、`GET /applications/:id` | clusterId/workspaceId、列表过滤 | 仅当前 developer 的 `{id,name,description,status,revision,createdAt,grantCount}`。 |
| `POST /applications`、`PATCH /applications/:id` | scope+name/description，编辑带 revision | 对象 safe view+operationId；状态只由专门停用流程处理，禁止写 owner/nativeID。 |
| `DELETE /applications/:id`、`POST /applications/:id/restore` | scope+revision+`confirmed:true,confirm_name:<app.name>` | 没有 active/uncertain grant 才可软删除，否则 `PORTAL_ACTIVE_GRANTS`；恢复只恢复应用元数据，不复活旧 key。 |
| `POST /requests` | scope+`applicationId,publicationId,reason?` | 202 工作流摘要含 workflowId/planRevision/state/operationId；issue 请求，服务器生成唯一 Consumer/ACL/Key IDs 与秘密，客户端不提交 native JSON。 |
| `GET /requests`、`GET /requests/:id` | scope、列表过滤 | 自己提交的工作流 masked planView/步骤/决策，不返回私有审批能力。 |
| `POST /requests/:id/cancel` | scope+revision+reason? | 仅自身 pending/approved 且未认领；执行/unknown 拒绝取消后重新申请。 |
| `GET /applications/:id/grants`、`GET /applications/:appId/grants/:grantId/credentials` | scope+size/cursor | 自己的 grant/credential ID、publication、generation/state、masked key、revision/workflowId；不默认明文。 |
| `POST /applications/:appId/grants/:grantId/credentials/:credentialId/reveal` | scope+revision | 独立显式读取，仅本人 active 账号+app+grant+credential，重新核验返回 `{credentialId,key,expiresAt}`，no-store并审计领取；不把 key 写入回执、通知或前端持久化。 |
| `POST /applications/:appId/grants/:grantId/credentials/:credentialId/rotate`、`/revoke` | scope+revision+confirmed+confirm_name+reason? | 202 工作流摘要，应用名精确确认；需要审批，创建/删除尚未执行时不能返回已生效。 |
| `GET /operations/by-key/:key`、`GET /operations/:id` | scope | 原 developer 安全 durable receipt `{id,state,remoteStarted,remoteCompleted,errorCode?,workflowId?,safeResult,createdAt,updatedAt}`。终态 succeeded/failed 且 remoteCompleted=true 才允许 UI 解锁重试；uncertain 不因换 key 消除。 |

门户 tenant 切换立即清除所有 private Query cache、表单、明文 key 和待核验上下文，并要求该租户重新登录。浏览器不能调用 Admin API；门户只经 BFF。所有秘密响应 Cache-Control=no-store，普通列表/公开文档不得误缓存私有认证 JSON。

浏览器启动：解析公开 tenant 后 GET scoped csrf（credentials 同源），随后 GET me；access 已过期但 refresh 仍有效时，csrf GET 只读验证当前 refresh 证明并返回原 session csrf，再 POST refresh 后 GET me。me 响应保持直接 DeveloperView，不夹带 csrf；Cookie 都 HttpOnly，前端 CSRF 只保留内存。旧 tenant Cookie 不匹配目标 scope 返回403，不悄悄切换或覆盖已有身份。GET csrf/登录/私有 me 都 no-store。

### 控制台管理合同

门户管理前缀 `/api/v1/clusters/:clusterId/portal`；公共工作流前缀 `/api/v1/clusters/:clusterId/workflows`。每个请求显式 workspaceId，使用既有控制台 Cookie/CSRF/当前授权和 X-Idempotency-Key。对象列表后端筛选；不能因为调用者能访问某原生 Service 就查看全局开发者目录。

| 路径 | 职责与当前权限 |
| --- | --- |
| `GET/PATCH /settings` | portal.read/write；CAS、安全 branding、公用代理 origin；只有明确发布的 tenant 才可被公共选择器发现。 |
| `GET /developers`、`GET /developers/:id` | developers.read，精确 tenant；不返回 password_hash/session/token。 |
| `POST /developers/:id/approve`、`/reject` | developers.write + workflows.approve，同租户、revision/reason/确认；控制台审核激活 metadata 在 approval 集群需明确已批准步骤；公共 PortalController 无审核入口。 |
| `POST /developers/:id/disable`、`/restore` | developers.write，revision/confirmed/confirm_name=username；epoch++/会话撤销；已有 key 撤销是明确列出的共同工作流，不伪称 session 禁用等于 key 失效。 |
| `GET /applications`、`GET /applications/:id` | applications.read；跨 developer 的管理视图限当前 tenant；无 raw key。 |
| `GET/POST /publications`、`GET/PATCH /publications/:id`、`POST /publications/:id/document`、`/publish`、`/unpublish` | portal.read/write；文档/Service 选择只允许已授权对象；publish 提交显式 Service-bound ACL→key-auth→metadata 计划；unpublish 只撤回内容和新申请，不隐式吊销 key。 |
| `GET/POST /pages`、`GET/PATCH/DELETE /pages/:id`、`POST /pages/:id/publish`、`/unpublish` | portal.read/write/delete；严格文档校验、CAS、软删除确认；新修订未成功批准前继续原 published_revision。 |
| `GET /clusters/:cid/workflows`、`GET /clusters/:cid/workflows/:id` | 公共工作流前缀，workflows.read +对象授权；masked plan、审批、执行、安全 diff，后端按 scope 全 tuple 过滤。 |
| `POST /clusters/:cid/workflows/:id/approve`、`/reject` | 公共工作流前缀，workflows.approve +关联 portal/developers/applications 及每步当前实体 write/delete/secret 权限；approve `{revision,planHash,reason?,confirmed:true,confirm_name,execute:boolean}`，reject `{revision,planHash,reason}`；hash只是 CAS 提示，不是客户端授权字段。 |
| `POST /clusters/:cid/workflows/:id/execute`、`/cancel` | 公共工作流前缀，execute `{revision,planHash,confirmed:true,confirm_name}`、cancel `{revision,reason?}`；当前合格批准人/执行人，在物理锁和 immutable version 证据下操作；缺权限、过期、范围变化、unknown 未核验均 fail closed。 |
| `GET /clusters/:cid/workflows/receipts/by-key/:key`、`GET /clusters/:cid/workflows/:id/receipt` | 公共工作流父安全回执；原 actor/cid/wid/key 与当前范围校验。unknown 只使用既有受控平台 reconcile 证据流程，不新增普通 POST 重试入口。 |

这些为端到端对接目标；Portal/Workflow 所有者在开始实现前须确认具体 DTO 与 envelope，不单方面另建同义路径。控制台纯配置写入仍复用 IAM durable ledger 和审批模式检查；已批准 metadata handler 必须私有能力授权，普通可选 tx 不能跳过。注册、登录、密码/会话安全操作和“提交待审批请求”不等价于已执行网关配置变更。

## API 认证边界与生命周期

publication 的安全边界是整个 Service 的 Routes，而非 OpenAPI 页面中任选 path。发布必须明确呈现该影响面：Service-bound key-auth + ACL 白名单唯一 group，无 anonymous，且原生 schema 来自探测到的 1.5 插件。发布原生顺序为 ACL 白名单先于 key-auth，最后提交发布 metadata，避免中间状态仅有 key-auth 而没有 API 授权隔离。已有合法 whitelist 保留并追加 publication group；不静默替换 blacklist、anonymous 或 key_names。只有已批准计划能建立/调整这两个插件。扫描发现不能证明安全的现有全局/Route/Consumer 认证覆盖或 unmanaged auth 时返回 `PORTAL_UNMANAGED_AUTH_BOUNDARY`，不能自动覆盖其他配置或把未完整扫描当无冲突。Root 注册 PortalAuthBoundaryService，在存在活动或发放中门户凭证时，后续所有接受入口/FK/ACL group 成员/key-auth/ACL 创建、更新、删除和恢复都校验 prospective 认证边界，包含回收引擎 DELETE 包；不能通过普通控制台修改破坏已发布 API 的隔离。受控门户 Consumer/Key/ACL 的通用 CRUD、创建子凭证、恢复和迁移所有权只允许匹配私有已批准门户步骤，不因普通管理员授权自动放行。

issue 原生顺序为 Consumer → ACL credential → key-auth credential；随后加密 CredentialStore/门户引用、真实代理验证和最终应用 grant 激活。Consumer 名称、owner/workspace tags、acl_group、Consumer/ACL/Key UUID 和随机 key 在提交计划时生成一次并加密，审批/重复执行不重生成。最终 grant-active/publication-published metadata 与最后步骤、execution/workflow terminal-success 在同一固定 handler SQL 事务提交；不能做到该原子终态时，public/reveal 额外要求父工作流确为终态成功。丢失 COMMIT 响应核验原行，不覆盖成功、不提前公开密钥。服务共享证书、Upstream、其他 Consumer 或插件不因一个申请而修改/删除。

rotate 计划必须包含新 credential 的一次性 UUID/key、旧 credential 回收归档和撤销步骤、需要审阅的短暂重叠窗口与真实旧/新认证验证；同一 grant 不允许两份并行 issue/rotate/revoke。撤销走既有 RecycleService 先归档后删除，保留原 ID、凭证恢复密文、依赖图和审核记录。停用、吊销、轮换结果记录 Kong DB 模式传播时间和 proxy 证据，UI 可显示“配置生效中”；不承诺事务提交瞬时覆盖所有节点。

历史受控所有权集合与活动/发放中认证风险集合分开：被吊销的 Portal Consumer/ACL/Key 仍属于历史受控对象，不能因为不再 active 就允许普通 Entity/Recycle restore 恢复旧 key。同 app×publication 的 revoked grant 只通过新的显式申请和审批重发；新建 grant、Consumer、ACL 和 Key UUID，旧 grant/credential 终态和归属永久保留，不恢复旧 key、不重写旧 Consumer 外键。轮换仍在同一个活动 grant 内递增 generation。

`portal_application_grants.reservation_released_at TIMESTAMPTZ?` 只供服务器标记从未执行的空预留；HTTP 输入不接受该字段，公开只读 `reservationReleased` 布尔值。应用×publication 唯一约束改为部分唯一 `(cluster_id,workspace_id,application_id,publication_id) WHERE state<>'revoked' AND reservation_released_at IS NULL`，物理 Consumer 的永久唯一约束保留。释放必须 disabled、generation=0、current credential/ACL ref 为空，当前及全部历史 issue 请求均 cancelled/rejected/expired，并且无任何执行、原生 operation、CredentialStore 引用、步骤进度、领取或发放/吊销事实；仅已封存且仍 pristine pending 的 key 预分配行可保留。释放时间与原 issue workflow_id 一旦写入不可修改，旧 UUID 始终受历史所有权保护。

SQL008 在 grant、credential、workflow、execution、step、原生 operation 与 CredentialStore 后续变更时延迟重验上述证明；读取事实前先锁 grant，并显式要求 READ COMMITTED，避免旧 repeatable-read 快照误放行。捕获/声明的同 transport_scope、同 CID 或登记的同 Admin 地址别名也纳入原生事实核验，不根据 DNS/IP 推断物理身份。原生证据不能物理删除或重绑身份以伪造空预留。账号/应用/发布归档先在同一元数据事务内释放合格空预留，仍有效或未知的授权必须先完成撤销或处理请求。

历史所有权和风险查找按 publications/grants 捕获的原始 transport_scope 直接覆盖所有物理别名 CID（含 revoked 和 pending reservation），不能只 JOIN 当前 clusters 的 Admin 地址。CID 重绑 Admin URL 后旧 gateway 的归属仍保留，另一原 alias 不能绕过受控对象 guard。publication 当前操作若实际 cluster/proof transport 不匹配即拒绝，须显式 withdraw 并重新登记新 publication，绝不静默迁移旧密钥或篡改 scope；新物理 scope 可登记新 publication，旧 deleted 证明保留。publication_proof 的明列 scope 与密文内部 scope 均比对；Native guard 在现有物理锁内复核。Portal metadata 仍活动时，受控已发布 Service/Routes 的保留工作区标签或关系迁移同样 fail closed，普通 workspace migration 不能把已发布 graph 移到另一工作区而留下旧门户授权。

Portal JWT 没有原生调用权限。请求者可看自己的申请，但 approve/execute 总是当前控制台身份和原生授权。在 uncertain 时保持相关原生影响范围栅栏和 grant 不可领取，Portal/Console receipts 关联原工作流步骤，不可用第二个申请生成另一把 key。

## DDL 可落地复核与实现交接

已只读检查既有 000–007 的父键和迁移器；下面是实施约束，不代表已执行 SQL 或真实数据库验收：

1. workspaces 已有 `UNIQUE(cluster_id,id)`，users 的 id 为全局 PK；008 新作用域表的 cid/wid 均 NOT NULL。可选 parent_id 允许 NULL，但一旦非空完整 scope 列不能 NULL，避免 MATCH SIMPLE 把错误范围跳过。actor/developer 的互斥 CHECK 独立于可选 FK。
2. publication.current/published revision、content.current/published revision、workflow.current version、grant.current credential 存在创建时循环。先建全部表和必需唯一键，再 ALTER ADD FK；当前指针循环使用 DEFERRABLE INITIALLY DEFERRED，同一事务插入根与修订/凭证。不可依赖不存在的 parent row 临时禁用触发器，不能把复合 FK 换成单 ID FK。
3. 非 NULL native operation 的精确双向键为 `(cid,wid,step_id,workflow_id,plan_revision,plan_hash,operation_id)`：steps 的列映射 `id/.../operation_id`，mutation 的列映射 `workflow_step_id/workflow_id/workflow_plan_revision/workflow_plan_hash/id`。双方建该完整 UNIQUE 并互相 DEFERRABLE FK，保证同事务分配 operation 和 CAS step.operation_id；单方向 FK 不足以保证互相指向同一操作。steps CHECK 仅 native+approval_required=true 允许 operation_id 非 NULL；直接/metadata 步骤只能 NULL，普通 legacy operation 因新四列全 NULL 不进入该关联。
4. mutation 再通过 `(cid,wid,workflow_execution_id,workflow_id,workflow_plan_revision,workflow_plan_hash)` 关联 execution 完整唯一键；版本/hash 外键分别关联 workflow_versions。FK 目标用普通 UNIQUE，不能引用部分唯一索引；唯一允许多 NULL 的普通键已足够处理未绑定 legacy 行。generation/active 的业务唯一性另用部分索引，而不把该索引作为 FK 目标。
5. portal credential 的 original issue 与 revoke 是不同 workflow，不能用一个 workflow_id 同时约束两次 operation；使用上表独立 revoke_workflow_id，原生引用核对 actual entity/kind/parent。CredentialStore 和 recycle_entries 新复合 UNIQUE 是新增索引/约束，绝不回填或重写旧密文/audit。legacy NULL workspace 的 archive 不能被猜测为当前门户范围。
6. 版本的 step_count/native_request_count、阶段数、同版本依赖存在且 step_order 更小、无审批版本无决策行，通过延迟约束触发器和 Engine 完整比对双重验证。加密 plan 本身不在 PostgreSQL 解密；数据库约束不能替代 private verifier 的逐字段 canonical/HMAC 比较。16/32 上限让依赖检查有明确预算。
7. 无审批 direct 必须 approved_by/approved_at NULL、零 approvals/stages；需要审批的 execution 必须存在同版本/hash 的真实 approve 决策。前者不能靠设置自己批准制造事实。直接 publication 与始终审批 credential 的两类版本完整传播 mode/approvalRequired，不能只保存在客户端或 mutable current row。
8. audit_events 新 workflow 关联如纳入 008，采用同 cid/wid/workflow FK 及 `workflow_id非空→cid/wid非空` CHECK；先只读验证 legacy 兼容，不更新不可变审计。存在旧未解析 workflow_id 时以 NOT VALID 新约束保护后续写入并记录保留策略，旧 ID 不授予私有能力。

运行时 grants 已确认需修改 `infrastructure/migrate.ts`：当前 provisionRuntimeRole 在全部表 GRANT CRUD 后只对 audit_events 收紧，因此仅在 008 中 REVOKE 会被迁移 Job 覆盖。M6 在同一次 runtime-role 授权阶段、广泛 GRANT 后明确收紧这些新 append-only 表：`workflow_definition_versions`、`workflow_definition_stages`、`workflow_versions`、`workflow_approvals`、`workflow_events`、`portal_publication_revisions`、`portal_publication_proofs`、`portal_content_revisions`，以及原 audit_events。逐表仅 SELECT/INSERT，撤销 UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER；普通 runtime 不是 owner、superuser、schema creator，不能 DISABLE/DROP trigger。以 pg_catalog 的固定白名单存在性检查兼容旧阶段，不从 HTTP 表名拼接权限 SQL。

steps/executions 的 state/progress 可 UPDATE，但固定 version/hash/mode/approvalRequired/tuple/handler/secret/snapshot identity 由 BEFORE UPDATE trigger 拒绝更改；snapshot 从 pending→ready 仅一次 seal 后不可改，operation_id 从 NULL→唯一绑定后不可换。同类密文凭证身份/历史修订有各自 immutable-field 保护。append-only 同时有行级 UPDATE/DELETE 和语句级 TRUNCATE 拒绝触发器，即使管理员授错 CRUD 也不能改历史。真实隔离 PostgreSQL 验证必须用非超级 runtime 用户对每张表逐一 UPDATE/DELETE/TRUNCATE，不能只测试 owner 或检查 grants 文本。

| Owner / 文件范围 | 已确认实现接口和交接 |
| --- | --- |
| Storage：`008_m6_portal.sql`、`infrastructure/migrate.ts`、`modules/portal-auth/**`、对应 unit/isolated PostgreSQL tests | 本文完整 DDL、grants、PortalScope/Principal/DeveloperView、csrf/register/login/refresh/authenticate/me/profile/password/session/review 服务与 controller/guard；不能注入 WorkflowEngine；profile PATCH、pending 无登录。 |
| Kong：`modules/portal/**`、`modules/workflows/**` | 业务合同 DTO/路径、DB-only developer compiler、immutable version/hash、single-level approval、Direct ordinary chain、固定 metadata handlers/亲属 FK/proofs/终态事务、恢复回执；只使用 PortalPrincipal，不造 console actor。 |
| Reviewer：ApprovedWorkflowExecutionService 与 Context/Mutation/Kong 私有能力接线 | execution/step handles、APPROVED_WORKFLOW_METADATA_POLICY、logical/native 分离HMAC、approved operation 双向 CAS、after-await/最后发包当前证明。 |
| Root：AppModule/Authz/NativePolicy/PortalAuthBoundary | token/provider 单实例注册；`hasWholeWorkspace(user,cid,wid,module,action)`、`assertWholeWorkspace(...)`、关联 Service 的 assertScopedResource；prospective 接受面/managed ownership hook 与独立源码审核。 |
| Front：portal-web 与 console portal/workflow UI | public tenant、独立认证/CSRF重载流程、typed confirmation、原键父回执恢复、无秘密缓存/OpenAPI/Markdown受限渲染；不把审批通过展示成凭证已生效。 |
| DevOps/Security | 统一部署/唯一 live handoff、真实普通身份/跨租户/API代理隔离、响应丢失和秘密扫描；设计阶段不启动008或产品代码。 |

后续测试用只读秘密捕获工具待 Root 单独分配：建议 `infrastructure/metrics-test-capture.ts`，stdin `{clusterIds:UUID[]}` 最多8，单次一致性读取当前四 purpose/同 generation/hash，按原 AAD 解密后仅写 CLI 自建随机0700 `/dev/shm` 目录内0600文件。stdout 只安全 captureId/path/cid/generation/count；不 rotate/enroll、不公开 HTTP export、不原文 stdout/env/argv。宿主 helper 在0700临时目录复制、原子0600生成测试引用，并 finally 清理两侧临时捕获。此设计不改变冻结007或当前M5凭证家族。

## 源码与真实验收要求

008 落地先在一次性 PostgreSQL 验证跨 CID/WID FK、账号/租户唯一性、全部状态与 secret CHECK、append-only、版本/步骤不可变、同版本唯一执行、步/Mutation 原子关联、回收凭证引用、soft delete/retention。迁移自动有序执行并保存 checksum，不改 000–007 已执行源文件。

单元和受控故障验证覆盖：Portal/Console JWT 互拒；缺 login/refresh CSRF；注册/profile mass assignment；密码锁定/epoch/已用 refresh 家族；账号停用/tenant 切换立即拒绝旧 session；应用/credential/workflow IDOR；secret 日志/错误/审计 scrub；审批篡改与 fake capability 零 native；批准后降权/状态变更/lease loss 阻断下一步；lost response/COMMIT 不覆盖成功回执、不换 key 重发。

真实门禁由唯一部署器统一 handoff 后执行：公开 tenant→注册 pending→另一管理员 active→独立登录→应用/API 申请→单级批准→Consumer/ACL/key→正确 API 认证可用、另一 publication 不可用；再 rotate/revoke 并记录旧/新 key 真实状态和传播耗时。验证 tenant 隔离与 portal token 不能调用 console。截图、结构化请求证据和凭证引用分开，秘密只放仓库外临时 0600 文件且清理；不能把 mock 通过写成真实运行证据。

M6 接口、数据库和真正闭环全部通过后才提交里程碑并释放 M7。M11 预留的数据模型、调度字段或安全接口不计为 M6 已交付的多级/定时审批能力。
