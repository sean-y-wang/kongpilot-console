# M9–M11 工具箱、配置治理与工作流存储合同

状态：**设计候选，未实施**。本文起草于 M6 阶段；截至 2026-10-11，M6、M7 已交付，M8 API/Web 与 SQL011 已实际部署并正在端到端验收。本文只提出按顺序实施的 SQL012、SQL013、SQL014 及内部接口，不创建未来迁移、产品代码、后台任务或运行环境。每阶段必须先与当时实际 M7/M8 schema、业务、Web、私有执行所有者冻结，再获得 Root 对该阶段的实施指令。本合同不是测试或商用验收证据。

依据：[M7 实施合同](m7-implementation-contract.md)、[M8 存储合同](m8-storage-contract.md)、[M8 业务合同](m8-business-contract.md)、实际 M6 `workflow.types.ts`、SQL008、`MutationService`、`RecycleService` 与 `AuthorizationService`。当前 SQL000–011 没有工具箱草稿、巡检、lint、漂移或 Promote 表。SQL008 已有 `not_before/window_start/window_end`，但 definition/stage 的 CHECK、完整性 trigger 和实际能力仍严格限制单级审批；存在时间列不代表已实现定时执行或多级审批。

## 1. 复用关系与不能扩大的权限

| 阶段 | 新业务事实 | 唯一执行/回执来源 |
| --- | --- | --- |
| M9 / SQL012 | 加密草稿版本、批量选中对象清单、路由模拟/探测安全报告 | owner 元数据复用 IAM 原键事务；原生批处理引用 M8 `configuration_jobs/plans/steps`，child 仍为真实 Mutation/Recycle 回执 |
| M10 / SQL013 | 不可变规则版本、完整扫描报告、双环境对比与 Promote 选择策略 | 只读 capture 复用 M8 manifest/job；修复与 Promote 编译成 M8 的精确 diff/DAG，不创建另一套 native apply ledger |
| M11 / SQL014 | 多级/会签政策、版本化候选审批人、窗口预约、定时执行授权、步骤快照与回滚关联 | 扩展同一 Workflow family，复用 M6/M8 exact step 私有能力、Mutation/配置 job 回执；决策与定时 claim 不能成为 native 写许可 |

所有作用域为真实 `cluster_id/workspace_id`，完整复合 FK、captured `transport_scope`、typed native ID 与 parent。Target 权限规范到 Upstream，六种 credential 规范到 Consumer，但 secret 权限仍针对实际 child；不能只看模块布尔值。原始 actor/CID/WID/key/body HMAC 不随重试时模式或当前 selector 改变。既有 workflowId、planHash、SQL tx 或 HTTP `approved` 字段都不授权。

共享规则/调度/审批定义管理要求当前完整 whole-workspace/global grant；关联原生对象的任务还需要每个真实对象的模块操作与历史/当前范围证明。tag/entity 角色只能在已授权对象投影内运行/读取对应报告，不借规则、统计或依赖导航取得其他对象配置。M7 的历史 before/after complete-tuple 规则继续生效，标签范围不能在不同 grant 间拼接。

原生删除仍先完整加密回收图，再逆 DAG 删除；不能以批量、治理修复、Promote 或回滚名义直接 DELETE。Portal 的历史 Consumer/ACL/Key UUID、publication 的物理范围与保留 ACL 边界、托管监控 token/generation 始终由当前 NativePolicy 检查，不因来源是新模块而放宽。未知结果停在 uncertain，租约过期、新键或一次 GET404 不证明未发送。

## 2. 通用 SQL、秘密与游标规范

新增表实际列名采用 `cluster_id/workspace_id`，下表 `cid/wid` 仅缩写。不可变 rows 包括作者、输入 HMAC、物理 scope、引用版本和 typed identity；可变 root/progress 含 `revision` CAS。所有历史对象 `ON DELETE RESTRICT`，配置元数据软归档并可恢复，保留期只表示可申请材料销毁。删除/批量/秘密导出/破坏性执行需要 typed confirmation。不可变事实表 runtime 仅 SELECT/INSERT，拒绝 UPDATE/DELETE/TRUNCATE；progress 的固定 tuple 另有 trigger 防修改。

草稿、扫描原始对象、双环境对比材料、secret 值与调试敏感输入使用 M8 每产物 wrapped DEK/AAD 方案；当时若该方案尚未落地，必须先冻结实际接口，不能写假调用。AAD 包含 CID/WID、artifact ID/version、typed object/parent 和 section。公开只有脱敏 diff、counts、恢复限制、固定 reason code；无私钥、API Key、Basic hash/原密码、密文、秘密 HMAC 或原始请求头。保留期销毁遵守材料 pin 与数据库备份政策，不声称抹除了全部 WAL/备份历史。

列表统一 `{items,nextCursor,size,total:null}`，默认20、最大100。签名游标绑定 actor、当前 permissionVersion、CID/WID、物理 scope、原过滤、固定 size、不可变版本及稳定上界。数据库列表用稳定 keyset；Kong 集合用真实 size/offset 固定页大小，不能用 OFFSET/页码伪造 Kong 跳页。所有 native capture 继续共用 M8 的 pages/records/bytes/time aggregate budget；权限遗漏、cursor loop、父关系不符、范围变动或预算耗尽为 incomplete，不得计算完整覆盖百分比或生成破坏性计划。

## 3. SQL012：草稿与工具箱批处理

| 表候选 | 关键列 | 约束与关联 |
| --- | --- | --- |
| `configuration_drafts` | `id,cid,wid,transport_scope,owner_user_id,name,entity_type,parent_id?,native_id?,kind(create/update/batch/import),current_version,revision,state(active/deleted/expired),created_at,updated_at,deleted_at?,retention_until?` | owner/scope/对象身份不可变；软归档；owner-only 默认，转共享须另外冻结显式授权，不能 by-ID 访问其他人草稿 |
| `configuration_draft_versions` | `cid,wid,draft_id,version,material_id,payload_ciphertext,input_hmac,before_hmac?,baseline_snapshot_id?,baseline_version?,schema_hmac,cluster_revision,workspace_revision,created_by,created_at` | append-only；同版材料完整 FK；缺失/false/0/null/秘密保留意图独立冻结；schema/current before 变化不能直接提交旧表单 |
| `toolbox_batches` | `id,cid,wid,transport_scope,actor_id,configuration_job_id,plan_id?,plan_revision?,plan_hash?,kind(tags/plugin-enabled/workspace-move/delete),selection_hmac,selected_count,created_at` | immutable origin；1:1 引用真实配置 job，唯一 job；不保存第二套 succeeded/remote-completed 真相 |
| `toolbox_batch_selection` | `cid,wid,batch_id,selection_order,entity_type,native_id,parent_id?,credential_kind?,recorded_workspace_id,before_hmac,requested_change_ciphertext` | append-only；同批 typed identity 唯一；selection 仅显式 ID，不接受 “当前全部” 后台无限扩大；最终 manifest/DAG 为执行许可 |
| `toolbox_debug_runs` | `id,cid,wid,transport_scope,actor_id,origin_job_id?,kind(route-simulation/proxy-probe/node-status/cache-view/cache-invalidate),input_hmac,material_id?,state,quality,rule_adapter_version,kong_version,observed_from,observed_until,safe_result,created_at` | safe report 有界；native 写/缓存失效关联真实 Mutation/配置 job 原键；GET 报告不执行第二次请求；过期或不完整不能伪称命中证明 |

draft 创建、自动保存、归档和恢复是个人编辑材料操作，拟复用 M7 owner-only 元数据政策与 IAM durable receipt，不修改 Kong；该分类须在 M9 release 冻结。用户提交 draft 编译成新的 configuration job，按照集群当前 direct/approval 政策执行。旧 draft 不是当前实体权限、旧秘密读取许可或审批事实。无 `superAdmin/clusterId/ownerId/approved/status` mass assignment；不同用户不能通过 PATCH `owner_user_id` 接管材料。秘密保留 marker 不能被序列化为真实 Plugin secret。

批处理默认最多 **50 个显式根对象**，DAG 与所有子对象仍计入 M8 aggregate budget。先完整 selection/当前 before/依赖/回收能力预检，再冻结一次 plan；确认显示实际 affected count、共享引用、受管 blockers。任何 unknown 使后续零包，父回执显示 partial/uncertain。成功 child 不重发；“继续处理剩余”必须读取原回执、重新证明当前 before，并编译新的显式剩余 diff，不能随机新键重放整批。

工作区迁移复用 M3 专用迁移计划与 parent-derived tags/完整凭证闭包，不在通用 batch 中手写 reserved tag PATCH。若 M8 job 封装现有 migration，关联其 authoritative 原键及结果，不生成两套相互冲突的父终态。打业务标签保留 workspace 标签及未选业务 tags；不能以一次 tag_batch 绕过 Root published-graph guard。Plugin 启停仍遵守实际 schema、fresh platform/global运行边界与绑定对象权限。

### 工具箱读与真实探测

节点状态只调用实际 `GET /status`。路由模拟从完整已授权 manifest 和真实1.5 adapter进行，记录 regex_priority、前缀、method/host/header/SNI/source/destination、Service关联与插件选择；未扫描全部可能竞争的Route/Plugin时标记 projection/incomplete，不能显示唯一确定 winner。默认工作区/业务 tags 软隔离不能阻止另一工作区的 runtime global Plugin 执行，沿用 M2 警告。1.5不存在的 debug endpoint不猜路径；只有真实探测白名单明确存在才可使用，不增加 `/clustering`、表达式路由或新版本 schema。

输入规范化方法、URL、headers、来源 IP，但不把 Authorization/Cookie/query/body 原文写入报告或审计。模拟不向任意用户URL请求。真实 proxy probe 绑定已登记 cluster proxy 地址、明确目标 Route/Service与当前权限，遵守 outbound allowlist、固定scheme/host/port/path、无重定向与严格超时/字节上限。默认只提供显式确认的 GET/HEAD；任何扩展方法/含body探测需单独冻结业务副作用与权限政策。不开放 arbitrary destination/内网扫描，不把业务调用结果或模拟毫秒值称为真实各阶段耗时；只有实际可观察的 connect/TTFB/total 或可信gateway指标才返回。

缓存按精确 key 读取和失效，key/path校验与当前 toolbox 权限逐请求执行；禁止通用 cache key/path passthrough及默认清空全部缓存。缓存失效是用户明确要求的运维操作，发送前加密保留实际已观察的诊断数据并记录原键/审批/审计；Kong1.5没有写回 cache 的恢复端点，不编造回滚按钮或把缓存行当可重建实体。配置实体删除仍全部走回收站。公开 cache value 再次递归脱敏，无法证明安全时仅返回存在状态与元数据。

## 4. SQL013：规则、巡检报告与安全修复

| 表候选 | 关键列 | 约束与关联 |
| --- | --- | --- |
| `governance_rule_sets` | `id,cid,wid,code,name,owner_user_id,current_version,revision,state(active/disabled/deleted),deleted_at?,retention_until?` | whole-scope 元数据管理；code 不复用已归档身份；变更产生新不可变版本 |
| `governance_rule_set_versions` | `cid,wid,rule_set_id,version,engine_version,rules_hmac,created_by,created_at` | append-only；绑定完整规则清单及 engine 版本，不引用以后可变规则 |
| `governance_rules` | `cid,wid,rule_set_id,set_version,rule_id,code,given,then JSONB,severity(error/warn/info),description,enabled,fix_handler?,rule_hmac,created_at` | append-only；同版code唯一；DSL结构/路径/深度/字符串/运算符预算CHECK；修复仅固定registry handler |
| `governance_runs` | `id,cid,wid,transport_scope,actor_id,origin_type(http/schedule),origin_schedule_run_id?,configuration_job_id,rule_set_id,set_version,rules_hmac,revision,state(queued/capturing/evaluating/succeeded/incomplete/failed/cancelled),started_at?,completed_at?` | 原始捕获/回执来自 configuration job；scope/作者固定；终态后进度不可回退 |
| `governance_report_versions` | `cid,wid,run_id,version,input_snapshot_id,input_snapshot_version,manifest_hmac,engine_version,rule_set_id,set_version,rules_hmac,coverage JSONB,issue_count,quality,observed_from,observed_until,created_at` | append-only；FK 真实完整或明确incomplete manifest；报告封存后不能 INSERT 新finding改变count；完整性与finding数deferred证明 |
| `governance_findings` | `id,cid,wid,run_id,report_version,rule_id,entity_type,native_id?,parent_id?,object_key?,recorded_workspace_id,recorded_tags,severity,reason_code,field_path,safe_evidence,object_hmac,fix_handler?,created_at` | append-only；对象与规则来自同一报告manifest；无secret值/HMAC公开；历史/当前对象完整scope才能查看 |
| `governance_fix_links` | `id,cid,wid,run_id,report_version,finding_id,configuration_job_id,plan_id,plan_revision,plan_hash,created_by,created_at` | append-only；fix是新diffjob，finding不能由客户端置fixed；实际readback新报告验证消失才有resolved派生状态 |
| `governance_schedules` / `governance_schedule_versions` / `governance_schedule_runs` | root有owner/current_version/state/next_run_at；version有scope、rules版本、受限schedule/timezone；run有scheduled_at/job_id/currentpermission证据/reason_code | 复用 M8 schedule primitives；唯一版本/触发时间；worker只读capture/evaluate，无自动修复或自动审批；停用/撤权/重绑暂停 |

巡检只有真实观察才能报问题。孤儿Plugin/不存在引用由完整被引用集合或定向真实GET证明；Kong外键可能使某类孤儿无法通过合法API预置，不能为了演示伪造actual报告。缺权限、404投影、预算不足、不同观察窗口或未知引用为 `not_evaluated/incomplete`，不是断言对象不存在。无SNI引用证书只属于治理warning，可用于mTLS客户端证书，不默认删除。

Service.host不匹配Upstream.name通常是合法DNS/IP目的地，不能无条件报无效Upstream。只在明确声明Upstream约定或已证明引用被删除时报告；IP host合法，不能对 `/upstreams/<IP>` 的400当不存在。Service真实1.5不支持的 TLS/CA字段按当前schema跳过并标记capability，不调用不存在字段。描述/负责人来自授权的 `entity_annotations` 与实际owner tags，不能往Kong发送fake description字段。重复名称/冲突以实际DAO唯一性及明确匹配条件评价；潜在Route重叠标明模拟置信度，不把所有重叠当必然409。

“一键修复”先编译当前 before→固定 after 的diff，显示影响/回滚/缺失秘密，用户确认后走direct或审批。只允许有限registry，如补合规owner标签、在明确输入后设置超时；不能执行上传的JS、SQL、Lua、shell或任意path/method，也不根据rule.fix字符串自由发包。删除无引用证书仍需当前完整图、回收站与typed confirmation。

### 受限 Lint DSL 冻结候选

`given` 仅支持已冻结 manifest root集合与字段路径/`[*]`，不接收任意JSONPath函数、递归无界查询、网络 `$ref` 或动态SQL。`then` 为有限 typed predicate：`required/exists/type/enum/min/max/length/tags_contains/equals/https_only/reference_exists`，明确 missing/null/false/0语义；布尔组合总nodes≤128、深度≤16，规则≤200、path长度≤256、每输入≤M8预算。与描述/标签有关的映射统一实际 schema/annotation，无权限字段不会自动当缺失。

命名匹配使用有界 RE2 兼容语法或已审定确定性实现；拒绝回溯型/超预算regex，不因库未安装退回用户可控JS RegExp。engine解释纯数据，无eval、require、自定义函数或模板命令；每run总运算量/超时有硬上限，超限report incomplete且零修复。given匹配零对象仍记录evaluated coverage，不能用0 findings宣称全部通过。自定义规则导入本身按metadata模式/CAS/审计，不成为平台代码执行权限。

## 5. SQL013：漂移与跨环境 Promote

| 表候选 | 关键列 | 约束与关联 |
| --- | --- | --- |
| `configuration_comparisons` | `id,source_cluster_id,source_workspace_id,source_transport_scope,target_cluster_id,target_workspace_id,target_transport_scope,actor_id,source_job_id,target_job_id,policy_version,revision,state,created_at` | 两个完整scope FK与各自job FK；不能把target绑定source CID；同物理scope默认拒绝或只允许明确只读诊断 |
| `configuration_comparison_versions` | `comparison_id,version,source_snapshot_id/source_version/source_manifest_hmac,target_snapshot_id/target_version/target_manifest_hmac,normalization_hmac,quality,diff_count,drift_score,created_at` | append-only双端manifest绑定；任一incomplete不计算完整漂移率；无秘密或账号数量侧信道 |
| `configuration_comparison_objects` | `comparison_id,version,object_key,source_type/source_id?,target_type/target_id?,source_recorded_scope,target_recorded_scope,change_kind,reason_code,safe_diff,source_hmac?,target_hmac?,created_at` | append-only；同版typed双方映射唯一；不存在/歧义/只读reference分开，nativeID不同不能自动同一对象 |
| `configuration_drift_policies` / `configuration_drift_policy_versions` / `configuration_drift_runs` | source/target scopes、owner、不可变比较/阈值/时间规则；run唯一版本/时间并绑定comparison/job | 只读双端fresh授权；阈值与可评价总量来自真实manifest；告警走M7事务outbox，无自动Promote |
| `configuration_promotions` | `id,target_cid,target_wid,target_transport_scope,comparison_id,comparison_version,actor_id,configuration_job_id,plan_id?,plan_revision?,plan_hash?,selection_hmac,created_at` | immutable目标job入口；唯一实际job；成功/不确定为job派生值，不平行状态ledger |
| `configuration_promotion_selection` | `promotion_id,object_key,source_version,source_object_key,target_object_key?,include_credentials,environment_fields_policy JSONB,mapping_ciphertext,selection_hmac,created_at` | append-only；显式选中secret/环境字段；reservedworkspace重新按目标策略生成，不能无审阅复制来源WID/credential/host/token |

比较需要source和target两个scope的当前 `drift.read` 与每对象native.read；读取秘密/比较秘密另需各自精确secrets.read，未授权秘密仅显示“未比较”，不暴露是否相等或hash。取两端当前permissionVersion、scope/node/version/manifest，并在所有await后复查；只读比较不获得目标write。不同集群的相同名字不是可信身份，依赖显式typed映射/受限规则；冲突或多候选blocker，不能名称碰撞时覆盖任意target。

Promote需要 source.promote.read、target.promote.write 及目标每对象write/delete、依赖read/secret操作；审批还需target.workflows.approve完整subject范围，不能用source权限批准target。计划冻结双端当前版本和目标before；apply时target重绑/漂移或source版本变化返回409重新预览，不静默重抓替换已批准内容。一个target plan不得混入另一cluster step；多target Promote分别生成真实target作业，父聚合仅安全关联。

默认不Promote credential、私钥、监控/Portal托管配置或环境特定目的地/secret；明确勾选也不绕过其真实恢复能力、Root受管policy或不存在handler。环境字段策略只能retain-target/explicit-value/explicit-source有限选项，解密值密封到plan，不接受模板代码/任意secret变量解析。CA/证书/shared references未选择时必须证明目标已有合法映射；引用不足则阻止相关step。删除仅在明确target同步范围、完整baseline和typed确认时存在；不能因source没有target对象就顺手删除target。

## 6. SQL014：在同一工作流中增加版本化审批

M11针对实施时实际schema做增量迁移，不修改已部署SQL008–013。使用同一 `workflow_definitions/definition_versions/definition_stages`、`workflows/versions/stages/approvals/executions/events` families，新增 **policy/plan format discriminator** 并让新validator按版本分派。旧V1固定single/level1/required1、Portal仅固定kind/handler、16steps/32packets的constraints、reciprocalFK和私有cap继续适用。不能直接DROP单级CHECK后让旧payload被新多级validator接受；迁移须为旧行标记V1并保留分支完整性验证。

M8配置大DAG仍引用独立sealed configuration manifest，M11审批plan只绑定该精确job/plan/version/hash与policy，不把所有对象复制塞进V1，也不靠拆多个自审批V1扩预算。新的format2由Root/Reviewer显式实现exact plan/step source，其cap不复用Portal特殊例外。M7 event-metadata、M8配置subject新增fixed registry和完整FK，不开放客户端table-name或通用metadata handler。

| 新列/表候选 | 关键列 | 约束 |
| --- | --- | --- |
| definition/version新增 | `policy_format,mode(single/sequential/quorum),stage_count,stage_manifest_hmac` | version immutable；V1维持单级；V2最多8level、每stage候选≤100/threshold≤候选数；`allow_self_approval=false`恒定 |
| definition_stages新增 | `stage_mode(any/quorum/all),required_approvals,selector_hmac,decision_ttl_ms,require_distinct_previous_stage` | 政策immutable；level连续1..stage_count；权限要求固定workflows.approve与真实subject scope，不通过selector授予权限 |
| `workflow_stage_candidate_versions` | `cid,wid,workflow_id,plan_revision,plan_hash,level,candidate_revision,candidate_hmac,eligible_count,sealed_at,created_by` | append-only；candidate list明确版本；原始角色/团队选择规则来自policy，提交时解析候选不等于持续授权 |
| `workflow_stage_candidates` | `cid,wid,workflow_id,plan_revision,plan_hash,level,candidate_revision,user_id,source_kind(user/team/role),source_id?,created_at` | append-only；每stage/version/user唯一；候选冻结和当前成员资格均需证明；当前requester排除 |
| stages新增 | `policy_format,stage_mode,candidate_revision,candidate_hmac,revision,activated_at,expires_at?` | identity固定，state/revision可CAS；前stage真正满足且当前有效才activate；不同version禁止串票 |
| approvals新增 | `policy_format,candidate_revision,stage_revision,decision_request_hmac,authority_receipt_hmac,reason_ciphertext?,safe_reason` | append-only；同scope/version/stage/user一次decision，原key+body冲突409；无后台自动approve/撤销旧事实UPDATE |
| `workflow_approval_invalidations` | `id,cid,wid,workflow_id,plan_revision,plan_hash,approval_id,reason_code,observed_permission_version,created_at` | append-only补充事实；不删除旧approval；失效vote不计当前threshold，reopen/重新审批必须新policy-bound version而非改旧决定 |
| `workflow_window_reservations` | `id,cid,wid,workflow_id,plan_revision,plan_hash,transport_scope,impact_domain,impact_key_hmac,window tstzrange,state(reserved/running/released/cancelled/expired),revision,created_at,released_at?` | exactplan/impactFK；半开UTC interval；同物理相关impact并发冲突；已发unknown不可随到期release |
| `workflow_schedule_authorizations` | `id,cid,wid,workflow_id,plan_revision,plan_hash,execution_actor_id,actor_credential_epoch,delegation_hmac,permission_version,not_before,window_start,window_end,expires_at,state(active/revoked/expired),revision,created_by,created_at` | explicit当前真实控制台主体，不创建fakeHTTP；创建必须审批/窗口/typed确认且主体有当前全部step权限；受限serverprivate新背景来源 |
| `workflow_schedule_claims` | `id,cid,wid,workflow_id,plan_revision,plan_hash,authorization_id,scheduled_at,claim_generation,lease_owner_hash,lease_until,state(claimed/executing/succeeded/blocked/uncertain/expired),execution_id?,created_at,completed_at?` | 唯一authorization/触发时间；claim-before-execution CAS；旧lease不能resume写；真实workflow execution唯一事实 |
| `workflow_step_snapshot_links` | `cid,wid,execution_id,step_id,snapshot_id,snapshot_version,manifest_hmac,material_id,purpose(pre-execution/pre-step/post-step),created_at` | append-only；执行前/破坏性前baseline ready且same physicalscope；不能引用另一tenant材料；pin阻止purge |
| `workflow_rollback_links` | `id,cid,wid,source_workflow_id,source_execution_id,source_plan_revision,source_plan_hash,target_configuration_job_id,target_plan_id,target_plan_revision,target_plan_hash,created_by,created_at` | append-only；rollback是新current-before diff/job，不回退旧workflow rows或重放成功operation |

`approved_by` 旧字段保留V1兼容/展示，V2不可作为唯一审批证据；完成授权来源为immutable policy+完整当前有效decisionset/stage链。新增approvalset/sealed claim HMAC冻结每个decisionID/level/candidateVersion和threshold。V2 execution原actor/capturedscope/plan/approvedset不变；SQL FK把候选、stage、decision、execution全部绑定同cid/wid/workflow/rev/hash，错误hash/跨scope不能插票或claim。

## 7. 多级、会签、CAS 与不自批

审批事务锁workflow与当前stage，再当前会话/accountepoch/grants/候选成员资格复查、检查expected workflow/stage revision及planHash、append一次decision并CAS stage/parent/audit/outbox。并发投票distinct-count；同人重复请求回真实原decision，换key不能双票。同body丢COMMIT ack读取durable事实，不能变成failed或再写一次。任何reject使当前版本rejected并停止后级；all/quorum/any按不同用户计数，不按角色、团队或同人多个binding计数。

顺序多级level必须连续，后级在前级当前有效threshold满足后才能active。会签all的候选名单在version冻结，停用/移除某人不降低门槛；角色/团队新增成员不自动成为当前候选，成员撤销使其不能再批。policy可要求前后stage审批人不同；不要求时同人可跨stage，但任一stage仍只一票。requester console user永远不能自批，Portal developer不能成为consoleapprover；执行actor与提交人相同也不能伪造approval。涉及创建账号/换角色的step不以其after权限给自己授权。

审批人与执行主体在execute和每packet前重新证明实际当前账户、完整subject/workflow.approve与各stepwrite/delete scope；已撤权批准不自动维持永久效力，记录invalidation并阻止执行。运行中授权变化立即停止后续packet，既发结果保持真实partial/uncertain；不能自动降低threshold或换executor续写。若政策允许重新申请审批，必须新plan/policy-bound revision与当前before，不将新审批附到已发送旧版本。

direct +approvalRequired=false始终零approval/stage rows、不mint approvedcap，native approvedbinding=NULL；其普通operation sealedreceipt关联仅recovery。direct +approvalRequired=true（例如Portal凭证）仍需要真的decision；approval cluster任何write不临时改direct。M11统一接管Entity write请求时，先持久native-change configuration plan及subject，再返回真实pending工作流；不能在未批准时先Entity写再补工单。

## 8. 窗口冲突与定时执行当前权限

窗口用半开 `[start,end)` UTC，输入time必须含明确时区，服务存UTC，UI仅格式转换；end>start、not_before在有效window内、windowEnd≤planExpires。调度采用受限规则/明确timestamp，不接受cron命令或shell。DST重叠/不存在时间显式错误或按冻结timezone策略产生唯一UTC时点，不悄悄多执行。窗口只限定**每packet开始发送**；到期后停止新包，已发请求等待真实结果/uncertain，不能声称跨多对象原子截止。

预约根据captured physical transportScope与server-derived impact清单，跨CID别名共享冲突。entity-specific key与domain/whole-scope wildcard有真实overlap逻辑，不能只相等HMAC就遗漏父/child/globalPlugin冲突。建议预约时持有physical scope advisory lock，并在同事务按固定域层级校验rangeoverlap+祖先/wildcard；相同leaf可另用btree_gist排他约束，但不能把leaf exclusion当完整冲突算法。SQL新函数只接可信固定domain与不可变manifest keys，runtime普通用户无宽泛SECURITY DEFINER调用。强制冲突覆盖首版不提供；futureexception必须独立审批与明确可审计policy。

定时写需要Root明确新的private `scheduled-workflow-step` 来源：由durable schedule authorization+exact plan+当前execution+完整approvalset+window+claim/lease证明重建，只绑定一个ready step/packet。不是复制已关闭MainHTTP ALS、fakeJWT/sid/superAdmin、metrics-systempurpose，也不信body执行人。主体为当前active真实console user/受限登记服务账号，有独立credentialepoch、当前每对象权限和有效scheduleauthorization；schedule本身不扩大其权限。Portal requester只能以原developer主体发申请，nativeexec仍真实consoleexecutor；audit保留origin/schedule/requester/approval/executor分别身份。

claim前、snapshot后、每await后、送包前再次验证actor状态/credentialepoch/current permissionVersion、当前所有批准人资格、planHash/cluster/workspace revision/capturedscope、未决physicalimpact、时间窗口和lease。失效为blocked reason，零后续包；没有授权账号不能自动换Super执行。logout策略与长期调度关系需Root冻结：显式scheduleauthorization不等于原浏览器session复制，用户关闭网页不影响既授权任务，但accountdisable/credentialreset/撤销授权/权限移除立即阻断。HTTP origin任务仍按真实session有效性；不能把两类origin混用。

worker启动仅M11释放并通过schema/authority故障测试后；due claim唯一key为authorization/version/UTC时刻。运行/unknown父不因窗口、lease到期自动释放预约；只有真实completed/reconciled证明可release。通知走M7outbox，计划冲突/逾期/阻断与发包结果分别记录，不能把“已入队”“已审批”“窗口过去”显示为变更成功。

## 9. 每步快照与回滚

M6 execution snapshot是精确当前before授权证明，不等于完整可恢复配置快照。M11要求执行前完整M8 recovery baseline，破坏性step另保存前置snapshot link或同版baseline的精确对象/依赖subset；实际材料含秘密恢复证据、effectiveTarget映射与完整collection终点。未ready、预算不足、Basic缺可信原密码、父依赖未知或managed boundary未支持，则零破坏性包。快照材料pin必须与execution/step同SQLtx关联，不能发包后补FK。

执行时仍验证每step current-before/absence、依赖完成和原body HMAC；snapshot不授予覆盖新配置权力。readback/post-step snapshot保存真实结果；failed/unknown不写假after。表progress和sealedafter evidence分别处理，append-only snapshot不能 UPDATE补结果。metadata固定handler与native packets始终分开，nativecallback不能藏在SQLtx；Parent/step/审计/outbox终态同TX提交。

回滚编译新job+current-before→old-baseline-after exactdiff，再实际当前permissions/secret能力、影响、窗口、审批和二次确认。原ID/name冲突、credentialTTL、Portal历史Key、publicationSQL/native终态、托管metricsgeneration均按当前policy阻断；不能时光倒退SQL audit/approval/grant后假装原访问已恢复。unknown原step先只读reconcile，不自动补偿DELETE或用baseline盲覆盖；自动回滚首版禁用。成功回滚需真实Proxy credential/route/SNI/Target验证，Admin GET/工作流终态不代替业务可用性。

## 10. 服务接口与 API 冻结候选

这些签名仅描述Storage边界；Trusted/Lease是服务器私有类型，不是HTTPDTO，也不因传入tx产生权限。

```ts
interface ToolboxRepository {
  saveDraft(input: TrustedDraftRevision, tx: DbService): Promise<SafeDraft>;
  attachBatch(input: VerifiedBatchSelection, job: ExistingConfigurationJob,
              tx: DbService): Promise<SafeBatch>;
  sealDebugReport(input: TrustedDebugEvidence, tx: DbService): Promise<SafeDebugReport>;
}
interface GovernanceRepository {
  sealRuleSet(input: ValidatedRuleSet, tx: DbService): Promise<SafeRuleSetVersion>;
  createRun(input: AuthorizedGovernanceRun, job: ExistingConfigurationJob,
            tx: DbService): Promise<SafeGovernanceRun>;
  sealReport(input: EvaluatedManifestReport, tx: DbService): Promise<SafeReport>;
  sealComparison(input: AuthorizedDualManifestComparison,
                 tx: DbService): Promise<SafeComparison>;
  attachPromotion(input: VerifiedPromotionSelection, job: ExistingConfigurationJob,
                  tx: DbService): Promise<SafePromotion>;
}
interface WorkflowSchedulingRepository {
  appendDecision(input: CurrentAuthorizedDecision, expected: WorkflowStageCas,
                 tx: DbService): Promise<SafeDecisionReceipt>;
  reserveWindow(input: VerifiedPlanImpactWindow, tx: DbService): Promise<SafeWindow>;
  createScheduleAuthorization(input: VerifiedScheduledExecution,
                              tx: DbService): Promise<SafeScheduleAuthorization>;
  claimDue(input: CurrentScheduledActorProof): Promise<OpaqueScheduleClaim>;
  assertClaimCurrent(claim: OpaqueScheduleClaim, step: ExactWorkflowStep): Promise<void>;
  pinStepSnapshot(input: VerifiedStepSnapshot, tx: DbService): Promise<void>;
  attachRollback(input: VerifiedRollbackPlan, tx: DbService): Promise<SafeRollbackLink>;
}
```

普通metadata原键仍 `/iam/operations/by-key/:key`；native批处理、修复、Promote仍 `/clusters/:cid/configuration/jobs/by-key/:key`；工单决策/执行复用现有 `/clusters/:cid/workflows/...` 的原键resolver。新模块可提供安全投影alias，但不能新增一套假成功ledger。所有回执基于原actor/CID/WID/key和真实authoritative记录，当前有对应action/history权限才可读取。metadata/submit/approve完成不等于native远端完成。

| API候选 | 业务与回执 |
| --- | --- |
| `/clusters/:cid/drafts` 及 `/:id/versions`、`/:id/submit` | owner当前scope分页/CAS；submit生成新configuration job，不自批 |
| POST `/clusters/:cid/toolbox/batches` | 显式selection+kind+typed确认；编译配置job或专用migration真实回执 |
| POST `/clusters/:cid/toolbox/route-debug`、`/proxy-probes` | 模拟/真实请求明确quality；按前述完整/权限/SSRF预算；只读报告查询不再请求 |
| `/clusters/:cid/governance/rule-sets`、`/runs`、`/reports/:id/findings` | 定义whole-scope管理；run只读真实capture，报告immutable按当前scope过滤 |
| POST `/clusters/:cid/governance/findings/:id/fix-plan` | 当前before+固定handler编译configuration diff；另确认/审批执行 |
| `/clusters/:cid/drift/policies`、`/comparisons` | 两端真实权限，双manifest版本；schedule只读，不告警即自动publish |
| POST `/clusters/:targetCid/promotions` | 显式source/target manifest+selection；target job为唯一执行结果 |
| `/clusters/:cid/workflow-definitions` | 新版本single/sequential/quorum政策，whole-scope/CAS/模式；旧版本不可修改 |
| POST `/clusters/:cid/workflows/:id/decisions` | revision+stageRevision+planHash+approve/reject+typed确认；append事实与CAS |
| POST `/clusters/:cid/workflows/:id/schedule`、`/schedule-revoke` | 当前真实executor、窗口、planversion、revision和typed确认；原键metadata回执关联actualworkflow |
| POST `/clusters/:cid/workflows/:id/rollback-plan` | 新configuration diff/job；不是旧execution重发或自动rollback |

列表、matrix、待我审批、窗口看板与逾期提示均服务端当前scope+keyset分页；不全量拉取浏览器按人过滤。权限不能看某finding/entity时，不通过总count/impact/TopN泄露名称。API最终命名与M8实际产物一起冻结，此处不能让Web提前接不存在端点。

## 11. 分阶段约束测试与真实验收清单

SQL012：真实非owner角色append-only权限、完整draft/material/typedparent FK、crossowner IDOR、samekey不同body/CAS/lostCOMMIT、secretmarker与rawsecret审计扫描；真实50根/分页预算partial与targeteffectivehistory、archive先于delete、Unknown整批停止、原键返回成功child零重发。模拟说明权限投影和真实1.5匹配差异，probe真实请求与SSRF/DNS/redirect/bytes故障证据独立标记。

SQL013：规则nested/false/null/缺字段/空集合、ReDoS/SQL/JS/网络ref拒绝、运算预算和incomplete coverage；实际巡检检测可由Kong合法状态形成的真实问题，对FK禁止的状态用独立mock/SQLfixture明确标记synthetic。普通DNS/IP host、mTLS无SNI证书与真实schema字段不误报。双环境permission-before/after、rename/typedID冲突、secret无权不泄等值信息；Promote默认排除credentials/env值，target漂移409、删除完整回收和真实Proxy回滚验证。

SQL014：隔离真实PostgreSQL验证V1不被V2接受、完整FK/阶段顺序/candidate版本/一人一票/append-only/Direct无approval、并发最后两票/CAS/reject竞争、requester自批拒绝、跨scope/hash投票、定义更新不影响旧计划、授权撤销不自动降低threshold、worker重复claim、physicalalias窗口/祖先wildcard冲突、过期unknown不释放、lease丢失和DBack未知。实际PrivatePolicy证明fakeworkflowId、复制cap、旧HTTPframe、fakeexecutor、当前账号或批准人撤权、到窗口边界后零下一包。

统一真实E2E：direct与approval配置write、单级→多级→会签、工单窗口计划执行、执行前/每破坏性step快照、Portal凭证审批继续可用、普通Key/Basic/JWT/HMAC及证书Target回滚、拒绝/撤销/过期与M7通知、所有关键包100%真实审计/原键/childreceipt。event/network重试只使用Root授权本地receiver；不能未经授权发送真实外部Slack/邮件/Webhook。故障产物保留并标记actualKong/actualBFF/actualPG/offline/synthetic，截图与日志无秘密。

实施切分候选：Storage维护SQL012–014/repository/规则与窗口约束，业务所有者维护compiler/report/routing/DAG和fixedhandlers，Root/Reviewer维护当前范围与背景/approvedcap，Devops维护受控worker/单一部署，Front维护原键恢复与真实状态，Security独立实测。各阶段源码/类型检查/必要实际约束通过后才进入唯一部署窗口；M9→M10→M11顺序不合并，本文不提前释放任何代码或迁移。
