# M11 变更工单与审批工作流实施计划

状态：**门禁 1、2 已完成真实部署和技术验收；门禁 3 编码中，M11 整体验收尚未通过**。初稿编写于 2026-10-12，本次于 2026-10-13 更新。M9 已验收并提交 `0f03f50`，M10 已验收并提交 `4434d31`。M11 门禁范围和证据见 门禁 1 验收记录 (`artifacts/M11/gate1-acceptance.json`, not public)、门禁 2 验收记录 (`artifacts/M11/gate2-acceptance.json`, not public) 与 [验证说明](../verification/milestones/m11-verification.md)。该验收不代表原生实体执行、后台定时执行、持久生产部署或平台商用验收通过。

本计划补充 [M9–M11 存储合同](m9-m11-storage-contract.md) 与 [M6–M11 工作流基础草案](../../architecture/security/m6-m11-workflow-foundation-proposal.md)，以 M6–M10 已交付服务及 M10 已验收 V8 源码为依据。SQL000–020 已冻结，禁止改写；SQL019 已正式应用，校验和 `a78c530fa0eb0078ed196217c8ccb5819afbacb1744611c8769da15e421f0fdb`。SQL020 长期意图迁移也已在验收环境应用，校验和 `d220ee5401d5b704f0dd189ef6d9763d3591fbede52f5cf5a236deddd04cccce`，相关 HTTP 与存储约束仍在验收。原合同中的 SQL012/013/014 是历史候选编号。下文是完整设计及门禁顺序；只有门禁 1 记录明确列出的接口已完成验收，其余不能当作现有生产功能使用。

## 1. 当前能力与必须补齐的缺口

| 当前真实来源 | 已实现 | M11 缺口 |
| --- | --- | --- |
| `modules/workflows/workflow-plans.service.ts` | 默认定义、不可变 definition/version、密文计划、HMAC、原键提交及审计 | 默认定义固定 single；persist 只写 level 1；无候选名单冻结、计划日程或长寿命 intent |
| `modules/workflows/workflow.service.ts` | list/get/approve/reject/cancel/execute/by-key、单级决策、顺序步骤、执行前指纹快照及结果账本 | decide 一票即 approved；时间列未执行；get 不返回 UI 所需快照；无 board、完整影响面、回滚接口 |
| `modules/workflows/approved-workflow-execution.service.ts` | Bootstrap 注册 policy、WeakMap 私有 execution/step/binding、SQL/密文/归一化 step 三方核验、每包实时授权 | `authority()` 只核验 `approved_by` 一个批准人；`runApprovedExecution()` 要求真实 HTTP 会话；没有定时 native capability |
| `modules/workflows/configuration-approved-verifier.ts` | M8 独立大 DAG 的 V2 native binding、完整 reciprocal FK、当前 SID/epoch、before/body/packet 与配置账本核验 | 明确限制一个 stage、一个 approval、single definition；仍要求原 SID 与短期 job authority |
| `modules/configuration/configuration-access.service.ts` | HTTP 私有 job handle、原 SID 与权限版本、timer-only `acquireDueSchedule` | timer 只允许 capture；无定时写。`acquireDueSchedule` 不能被重用成后台 apply |
| `infrastructure/kong/execution-context.service.ts` | ALS、HTTP closing、注册 policy、operation/archive、configuration job / approved capability | 无 SID 的 configuration proof 强制 readonly；不能用 system-read、伪 SID、旧 HTTP ALS 或 `approved:true` 绕过 |
| SQL008 | 已有 not_before/window_start/window_end、不可变审批记录与唯一执行 | CHECK 实际把 mode、level、required_approvals 固定为 single/1/1；完整性 trigger 同样固定单级 |
| SQL011 | 加密配置计划、完整捕获、恢复材料、执行前 baseline、失败账本 | `origin_type='schedule'` 仅允许 kind=capture、SID=NULL；计划、job authority 与原 SID 是短寿命约束 |
| M9 migration / `workspace-migration-workflow-recovery.service.ts` | 固定 tags 迁移 compiler、完整 source/target 和 reviewer 权限复查；真实已知 native 成功后的同原键 metadata-only 核验已验收 | 保留原 503 与实际成功回执的分离；V2 扩展审批集及定时执行不能重放旧 native 或把原计划续期 |
| M10 `governance-metadata` / `governance-metadata.service.ts` | 已验收源码已接同一 V1 workflow、固定 intent/HMAC/主体/reviewer 回调，纯数据库业务变更与审计；无 native permit | 新政策及 approval set 必须覆盖这条固定链路，不能另外新建治理审批引擎；M10 技术链已验收，M11 扩展仍待实现 |
| M10 `configuration-origin.service.ts` / `governance-promotion-source.service.ts` / SQL018 | 已验收源码已绑定 Promote 来源、目标、immutable origin tuple 与双边当前权限；public/private 原生 fingerprint 与 opt-in 私有读取边界 | source provider 和 private recovery 都依赖真实 HTTP SID/originFrame；scheduled target capability 不能直接复用它们。需新的固定 scheduled source-read/recovery adapter；M10 技术链已验收，M11 扩展仍待实现 |
| `console-web/src/features/WorkflowsPage.tsx` | 列表、单级审批、手动执行、M6 与 M9 固定 metadata recovery | JSON 预览式详情；无 policy/候选/会签进度、计划窗口、看板；snapshot 条件展示尚无 API 返回的真实 snapshot/rollback 链 |
| EntityEditor/EntitiesPage/EntityDetails/CredentialManager/RecycleBinPage | 直接执行表单和 M9 批量计划 | 多处 approval 模式禁用按钮；表单到工单的 typed compiler 未实现，不能只去掉 disabled |

新增迁移需按 format/version discriminator 更新 SQL008 建立的具体约束/函数：`workflow_definition_versions.mode`、definition/workflow stage 与 approvals 的 `level=1`、required_approvals=1、`m6_validate_definition_stages`、`m6_validate_version_graph`、`m6_validate_approval_fact`。这不允许编辑 SQL008 文件。必须保留旧 V1 精确 single 语义；不能直接放宽旧 payload 的验证预算或元数据/native 分界。SQL008 预留的 `native-change` 并未形成当前可用能力：`WORKFLOW_KINDS`、固定 handler、主体/source verifier 与表单 compiler 仍须一起实现。

### 1.1 原始 M11 要求对照

| 原始要求 | 可复用链路 | 本次必须完成的验收闭环 |
| --- | --- | --- |
| 单级/多级/会签，M6 共用统一引擎 | 现有 definition/version、decisions、固定业务 delegates | PolicyV2、连续 stages、冻结候选、distinct 投票、immutable approval set；Portal/配置/迁移/治理/事件共用当前资格 verifier |
| 所有变更对象及操作进入工单，审批前不能写 | Mutation 审批拦截、现有 sealed workflow / Config DAG | 所有实体/Target/凭证/删除/恢复及业务入口 fixed compiler；无 arbitrary native proxy、无 `approved:true` 旁路 |
| diff、影响面、回滚方案与执行前快照 | 密文 before/body、safe diff、M8 recovery baseline、M9 recycle graph | 实际受影响图、共享边界、真实 baseline 关联/material pin；回滚产生新 current-before intent 并再审批 |
| 计划执行时间、变更窗口 | 现有时间列、timer-only capture、锁/lease 与账本 | durable intent 与短期 authority 分离；真实 owner delegation、窗口/物理影响预约、一次 claim/execution、每包实时资格 |
| 每步执行日志、结果回写及通知 | Workflow/Mutation/配置回执、M7 audit→outbox | 审批阶段/计划阻塞/逾期/冲突/回滚事件同事务；站内与受控外部投递结果分别展示 |
| 待我审批、我提交、逾期/窗口冲突看板 | 当前 submitted/pending-my-approval/all 列表 | 当前 stage/candidate 感知的列表、看板、真实 snapshot/rollback/log 导航与原键恢复 |

当前缺口不属于仅补 UI 的低复杂度工作。审批政策、原 SID 短期权限和固定实体副作用必须先闭环，再启用后台执行和完整页面。

## 2. 最小完整模型与实施顺序

复用同一 workflow family、MutationService、NativeKongPolicy、M8 DAG 和 M7 outbox，新增三种事实：版本化审批政策与冻结候选、长期审阅 intent 与短时执行授权、带物理影响范围的日程与租约。单级、多级和会签是同一引擎的 policy，不创建另一套工单执行器或凭证审批实现。

M10 整体验收、源码/SQL/接口冻结后，按以下五个门禁顺序实施。与初稿相比，将 durable intent/source 合同提前到实体 compiler 前，避免先把新实体工单绑定现有约 15 分钟、原 SID 的 M8 job，再重做整个提交与执行链。

| 门禁 | 待实施内容 | 必须先满足的证据 |
| --- | --- | --- |
| 1：政策与审批事实 | PolicyV2、候选冻结、连续阶段、审批集、SQL 完整性、共用当前资格 verifier | V1 精确 single 回归；实库跨 stage/scope/hash/source 负例、并发 distinct 票及 approval set 完整性；所有现有固定 delegates 仍有效 |
| 2：长期意图与固定 compiler | 先冻结 durable intent/version、execution source FK/manifest 等价合同，再接 Entity 共用 prepare 与 fixed compiler；短期 job/claim 不续期旧 SID | 原意图/原键不可改；普通/tag_group/entity 范围闭环；schema/before/ref/秘密保留与所有真实副作用准确封存，审批前零 native 写 |
| 3：基线、影响与新回滚 | 完整受影响图的 recovery baseline/material pin，真实影响投影及固定 rollback intent/link | 第一包前 baseline ready；缺失材料不能发送；回滚按当前权限与集群模式生成新计划，原 ID/凭证实际恢复 |
| 4：后台委托、窗口与 worker | scheduled-change 私有 authority、scheduled source-read/private recovery adapters、物理影响预约、due claim/lease、故障核验 | 先无 worker 验证 genuine handle/原身份/撤权/lease/window；再证明关闭浏览器仍能按真实 owner 委托触发，source 与 target 均实时验证，unknown 不重发 |
| 5：产品与发布验收 | 所有写入口 review/submit、阶段/会签进度、日程/看板/通知/回滚导航，M0–M11 回归与手册 | 真实 native/DB/fault/browser 证据、秘密扫描、明暗/移动端、生产部署及用户手册；外部未联调明确列出 |

每个门禁的固定接口先由 owner 向 Root 提交评审、冻结后交相邻 owner 集成。客户端或共享 SQL mock 不构成私有权限证明；部署、实际 SQL 迁移和 native 写验收仍由 Root 统一执行。

首版约束：最多 8 级，每级候选最多 100 人，审批人始终是真实启用的控制台用户。stage mode 为 any/quorum/all；多级为顺序 stage，单级与会签可以混用。`allow_self_approval=false` 不可配置为 true。每级同一用户只有一票；是否禁止同人跨级由不可变政策显式设置，默认禁止跨级重复批准。候选为空或少于 threshold 时不能提交可执行工单。

## 3. SQL 与审批集合同

新增 `policy_format/plan_format` discriminator，旧 rows 默认 1；V1 保持 single、level 1、threshold 1。新 V2 定义与计划包含 stage manifest 和 candidate manifest HMAC；参数均由服务端 compiler 产生，不从 HTTP 接收授权证明。

| 新增或扩展事实 | 内容及完整性要求 |
| --- | --- |
| definition versions/stages | immutable policy、连续 level、mode/threshold、用户/团队/角色 selector、候选选择策略、最大 intent TTL、跨级 distinct 规则；管理需 whole-workspace workflows.write |
| workflow candidate versions/candidates | 提交时服务器解析 selector，排除 console requester；真实 user/team/role 来源记录、候选版本/HMAC；绑定 CID/WID/workflow/revision/hash/level；仅追加 |
| workflow approval set / members | 终审满足各级后封存准确 decision ID、level、candidate version、policy hash；execution 引用整个 approval set，不能只信 `approved_by` |
| approval invalidations | 追加已批准人失效的事实与固定原因；不更新/删除原 approval、不偷偷降低 threshold |
| durable change intents / versions | 精确变更、schema/before/transport/范围、policy、日程、原提交人及 credential epoch、授权来源和材料引用；密文、固定来源、加密恢复证据及 pin |
| schedule authorizations / claims | 显式执行人委托、计划版本/HMAC、窗口、UTC 时刻、scope/epoch；claim generation、lease owner hash/until、固定 execution、send intent 与结果，不靠租约失效证明零发送 |
| window reservations | 同物理 transport scope、半开 UTC 窗口、服务器 deriveImpact 的 keys/domains/wildcards；CAS 与保留事实；unknown 不自动解除预约 |
| snapshot/rollback links | workflow/execution/step 与真实 M8 snapshot/material 的复合 FK、manifest hash、purpose、material pin；rollback 指向新的 current-before diff/plan/job |

所有新事实表 runtime 仅 SELECT/INSERT，禁止 UPDATE/DELETE/TRUNCATE；可变进度表固定 tuple 不可改，state/revision 使用 CAS。`approved_by` 保留 V1 兼容及展示；V2 不能以此字段代替 approval set。完整性 trigger 在提交时验证连续 levels、policy/stage/candidate/decision/source/execution 的整个复合 scope，跨 CID/WID/hash/source 票据必须失败。

投票事务锁 workflow + active stage，核验 expected workflow/stage revision、planHash、真实会话、当前账号/epoch、候选身份及当前 approve scope，追加 decision+audit/outbox 并 CAS。只有当前 stage 可以投票；distinct-count 达门槛后激活下一级，全部完成后 approved。任何 reject 使当前版本终态 rejected。原 key 相同 body 返回同一事实；不同内容 409，换 key 不能产生第二票。

冻结候选不是持续授权：团队/角色新增用户不能自动加入旧工单；冻结候选被移出原 selector、停用或撤销 approve grant 后不能继续投票，其既有票也不能支持执行。all 会签的人员变化不会降低门槛。需要调整名单/计划时新建版本或新工单并重新审批；旧决定和原执行事实保留。

## 4. 共用当前审批资格 verifier

新增单一 `WorkflowApprovalAuthorityService`（名称候选），由 WorkflowService、ApprovedWorkflowExecutionService、ConfigurationApprovedVerifier、M9 migration/cache verifier、M10 governance/Promote 固定 delegates 及 scheduler 共同调用。它验证完整不可变 policy、候选、stage 链和 approval set，并重新读取**所有构成执行批准集的批准人**当前账号、forcePasswordChange、deleted_at、selector 成员关系、effective grants 与真实 subject scope。V1 single 的 `approved_by` 精确验证保留；V2 对每个当前有效批准人调用固定业务 subject/reviewer policy，不能把只校验最后批准人的旧分支用于会签。

跨 source/target 工作区迁移与 Promote 必须核验所有受影响作用域，不只 anchor WID；Service/Route/tag_group/entity 权限使用真实对象关系，不拼接不同 grant 得到一个不存在的完整 tuple。审批权限不替代执行者每个对象的 write/delete/reveal，以及 published portal 和 managed metrics 边界。

检查时间点：投票事务、终审封存、execution claim、快照完成、每一步及每次 native before-send。批准人授权变化后阻断后续包；已发请求保留真实结果。不要在 executor ALS 中调用另一个 user 的 AuthorizationService.snapshot 来假冒批准人；当前服务已有 anti-IDOR。后台 verifier 直接读取真实 approver SQL/grants 并使用同一纯 grant policy，或新增专用受限内部 verifier，不复制身份。

## 5. typed entity/change compiler 与审批表单

新增 fixed `native-change` business subject（候选表名 `entity_change_requests`，以门禁 2 冻结合同为准）及固定 registry handler。subject_type 必须是明确允许的控制台表且有完整 FK；不能沿用 SQL 预留 kind 当作任意 subject 的豁免。客户端不能提交 SQL 表名、native path、任意方法或 workflow step manifest。只有服务端 compiler 生成和封存 exact packets，原生发送仍经现有 Mutation/Recycle/NativePolicy。

将 EntityService 的准备逻辑提取为共用无写入 prepare API：scoping、原生 schema、字段白名单、workspace tags、before/引用权限、隐藏值保留、证书检查和业务 guard。直接模式与工单 compiler 使用同一准备器，不能实现两套有差异的 payload 规则。审批只保存计划，不先写 Kong 再补工单。

| 操作 | 必须封存的实际副作用 |
| --- | --- |
| core create/update | server UUID、schema、before/absent 证据、保留 workspace tag、真实绑定/引用；Plugin config 合并、Route hidden headers、Upstream health headers 保留意图先解析成 exact native body |
| Certificate / SNI | cert/key 有效性、现有 SNI 关联与冲突；证书写入后确实发生的 SNI tag PATCH 必须成为计划明确步骤，不藏在 callback |
| Target 权重 | Kong 1.5 使用 POST 新 Target 历史而非 PATCH；新 effective UUID 和原 ID 要冻结并分别展示，完整快照记录 effective 映射 |
| Target healthy/unhealthy | 固定实际 1.5 endpoint、当前节点作用范围、当前权限/parent；没有原节点状态证明时不能伪称可自动回滚 |
| six credential kinds | canonical Consumer UUID、parent scope、继承 tags、allocated UUID、恢复所需 secret provenance；Basic 原密码/hash 区分，metadata credential store 结果与 native 一致 |
| delete / recycle restore | 完整对象图、准确依赖删除/恢复顺序、逐 child permission；删除前 archive ready；原 ID/完整凭证恢复证据；不能把多包 graph 描成只有一个被执行的 packet |
| annotation / metadata | 固定 handler、原对象授权、revision CAS，approval gate 与原事务审计；不可接受 generic native callback |

优先复用 M8 ConfigPlan/DAG、native receipts、完整 recycle graph 与 before snapshot；但 Entity 表单必须保留原有 tag_group/entity scoped 使用能力，不能要求用户获得 whole-workspace snapshots 权限才编辑一个授权对象。实现时应新增受限 typed-change access capability 来授权精确 DAG；不得放宽原 whole-workspace configuration 权限。M6 V1 16-step/32-packet 限制保留；大图引用独立 M8 sealed manifest，不拆成若干自审批 V1 绕过预算。

新增 EntityEditor 的“提交工单”路径及 review drawer：从同一表单输出 typed body，服务端返回脱敏 diff、影响对象、恢复限制、policy/时间参数，再显式提交。EntitiesPage 单删、EntityDetails 插件/Targets、CredentialManager、RecycleBin、批量及治理修复/Promote 同样接入。按钮按真实前后端 capability；不能简单解禁 approval-mode save 调原普通写端点。

## 6. 长期审阅 intent 与执行期限

现有 M8 job/handle authority 约 15 分钟且绑定 origin SID，plan.expiresAt/row.expires_at/HMAC、workflow identity 不可修改。M6 portal/event 计划约 24 小时，M9 cache 约 14 分钟、migration 约 30 分钟。延长一个数据库时间列、刷新登录或后台伪 SID 均不能使原短期 job 获得新 native 权限。

M11 必须把以下三种寿命分开：

1. **durable review intent**：提交前选择日程与有效期，默认 24 小时，上限 7 天（可按集群政策收紧）。批准绑定精确变更、before/schema/物理 scope、policy、恢复材料和绝对截止时间。
2. **HTTP execution authority**：手动执行由当前真实会话签发短时 claim；同一用户新登录可申请新的 execution claim，但不能续租原 SID 的 M8 job 或修改批准内容。
3. **scheduled execution authority**：由显式委托+当前资格签发短时私有 claim，独立于浏览器 session，不是旧 HTTP authority 的延长。

推荐新增 durable intent subject，让新 workflow wrapper 绑定 intent ID/version/HMAC，而非一个即将到期的 planning/apply job ID。执行时在当前 live grants 下创建新的短时 configuration execution job，服务端证明其 manifest/changeDigest 与获批 intent 完全一致，同时 baseline、schema、endpoint、workspace/cluster revisions 均未漂移。新 job 的精确来源 FK/intent-binding verifier 是必需实现项；不能临时重写旧 SQL011 job 或把不同 job 当作同一个批准计划。旧 configuration_v2 wrapper 原样保留。

执行时发现 before/schema/source 已变：block/replan，零 native 包；新 diff 改变批准意图时重新审批，不自动借旧票生成新配置。日程/候选/有效期变更同样创建新版本或工单。过期、failed/unknown claim 不自动换键或延长窗口；reconcile 只根据已存在可信回执修补元数据，不重发未知包。

提交、各级决策、委托、执行与回滚分别保存原键及准确 request HMAC/actor/CID/WID/intent/version/hash 绑定。查询原 receipt、刷新登录或到期不创建新的执行意图。已发原 execution 的 parent 状态与 actual component/native 结果分别保留；已知 native 完成而 metadata 未闭环只允许固定 metadata-only reconcile。M9 已验收链路必须继续回归，不能将旧失败请求改写为成功响应，也不能用审计缺失或 404 推断零发送。

## 7. 私有定时 capability 与 worker

可参考 M8 `ConfigurationAccessService.acquireDueSchedule` 的 timer-only WeakMap + SQL owner/policy 校验，以及 M7 `DeliveryWorkerService` 的小批 claim、heartbeat、发送前 intent、authority pause 与 unknown 终态；不可复用其读 capability 为 native 写。

新增 `ScheduledWorkflowAuthorityService` + 私有 branded handle，bootstrap 安装唯一 policy。`acquireDueClaim()` 只在没有 HTTP ALS 的 worker 调用路径中生效，校验已提交 schedule authorization、准确 approved intent/approval set、due UTC/window、owner/执行人 live epoch/grants、scope、lease/generation。执行 identity 为真实指定控制台用户，`sessionId=null`，origin 显式 `scheduled-change`，禁止 fake JWT/SID、默认 super-admin 或 body 提供 approved/execution actor。

`ExecutionContext.runScheduledWorkflow(handle, fn)` 候选接口从私有 verifier 获得准确主体、intent/execution/approval set、scope、epoch/permission version、lease generation、window、short deadline。其独立 WeakMap 根 frame 不继承旧 HTTP ancestors，每次 current/before-send 重新验证 claim；只允许该执行的真实 step/packet。NativePolicy 与 ApprovedWorkflowExecutionService 分支只认该 registered genuine handle，普通 actor/system/read path 无此能力。M8 typed-change adapter 同时需显式 scheduled origin/source FK，旧 schedule-capture 继续 readonly。

调度使用 `FOR UPDATE SKIP LOCKED` + 唯一 authorization/version/UTC occurrence + workflow version 唯一 execution。claim 后执行前快照完成再发第一包；snapshot 阶段计入 lease/budget。每次 await 后和 send 前检查 lease、窗口、epoch、批准集、scope/current before。并行 worker 最多领取可用执行 slot，不预取大量会过期的 claim。

窗口为 UTC `[start,end)`，输入带明确时区，UI 展示当地时区；not_before 位于窗口内且 end≤intent expiry。窗口关闭停止新包，已发请求等待真实结果，不承诺多对象原子截止。每物理 transportScope 的预约使用 deriveImpact/impactOverlaps（keys/domains/wildcards），包括跨 CID 别名、父子、global plugin；不能只用同叶子 HMAC 排他检查。预约/执行/unknown 的冲突状态真实落盘，unknown 不因 lease/window 到期释放。

显式 scheduled delegation 在用户关闭网页或单次 logout 后仍可运行；账号停用/删除、forcePasswordChange、credential epoch 改变、角色/候选资格撤销、委托撤销或窗口到期立即阻断。HTTP 任务继续要求当前真实 session，不与 scheduled origin 混用。metadata recovery 与 failed no-send closure 需要明确可信事实，不能把审计缺失、超时或 GET404 视作“肯定没写”。

### 7.1 M10 source/private recovery 带来的新增约束

当前 M10 已验收源码中，`GovernancePromotionSourceService.actualActor()/acquire()`、`ConfigurationOriginService.prepare()` 与私有 `PromotionRecoveryReadProof` 都要求真实 HTTP SID；私有 proof 还绑定 genuine HTTP/actor originFrame。跨 target 请求恢复 source 读取时，现有 private bootstrap 仅 SQL、read namespace 清除 target write/approved 祖先，只接受固定捕获图 point/凭证 collection/schema GET。这些条件是安全边界，不能改成 SID 可选后让定时器绕过。

因此 scheduled Promote 必须同时实现 target 执行 adapter 与专用 scheduled source-read/private recovery adapter，由显式委托、当前真实 owner/credential epoch、source+target 完整 live grants、scope/source/material/intent 绑定、lease/window/short deadline 签发 genuine 私有 handle。scheduled proof 走独立注册 namespace 与固定 verifier；不得伪 SID、借当前 executor SID 冒充 source owner、复用 `system-read` 或 capture timer 的 readonly proof。用户关闭页面不依赖旧 HTTP frame；账号/委托/角色/批准集变化仍立即阻断。

adapter 继续验证 M10 加密 v2 comparison envelope 的 public inventory 和私有 native fingerprint 精确对象集合，包含 referenceOnly；隐藏字段变化也必须阻断。每个 native before-send 使用同一个 private source handle 做 fresh raw fingerprint/目标来源绑定核验，不以旧 safe/redacted inventory 或缓存授权代替。opt-in secrets/credentials 必须保留完整真实恢复 provenance、固定消费者凭证 collection、合法 size/offset/next、跨页去重和 EOF；旧无 private manifest 的材料不能补造证明。public/private 读取 budget、deadline 与第一包前预算检查使用当时已经消耗的累计值，不能通过换 frame/handle 重置。

metadata-only 固定 kinds 同样使用共享 PolicyV2 与 scheduled 委托 verifier，但保持 `nativeRequests=0`，只能执行其明确数据库 business handler，不能成为 Kong 写权限。

## 8. 快照、影响、回滚与通知

执行前完整受影响图的 recovery baseline 及 material pin 必须 ready 后第一包才能发送；复用 M8 材料与图格式，但不额外暴露或要求无关 whole-workspace 对象。M6 的局部 `WorkflowSnapshotV1` 是指纹证据，metadata-only wrapper 的空 objects 不是完整配置恢复快照。get/detail 应关联真实 configuration execution 的 before_snapshot_id/version，并只公开脱敏摘要、可恢复性和授权后的对象导航。每个破坏性 step 引用同版 baseline 精确子集或独立 pre-step snapshot，不能事后补发包前证据。

影响面以服务端完整当前图与 deriveImpact 生成：真实 Services/Routes/Plugins/Consumers/凭证数量、授权后的名称/链接、global/共享边界、恢复阻塞原因。可经 M5 Vitals Provider 给实际时间窗内调用量提示；没有数据源/缺少 labels 时显示“暂无统计”，不能示例 QPS 当真实影响。preview/get/list 的后端投影重新校验整个授权闭包，禁止根对象可读就暴露其他根对象的 before/config。

回滚调用现有 `ConfigurationService.rollbackPreview(cid,snapshotId,body,actor)` 生成新的 current-before→旧 baseline exact diff，保存 immutable rollback link，按目标当前 direct/approval 及窗口再执行；不回退 audit/workflow/grant SQL，不重放旧成功 operation。unknown 原执行须先受控核验，禁止自动补偿。Credential TTL、Basic provenance、Portal 保留凭证、managed metrics、ID/name 占用等 blockers 明确展示。Kong 1.5 无 cache 写回 endpoint，缓存失效只能记录不可回滚原因，不能提供假的恢复按钮；节点健康置位同样需真实前态能力。

上述现有配置 API 保留 its whole-workspace 权限边界。tag_group/entity 的 typed-change 回滚使用固定受限 adapter 复用 diff/material/receipt 校验，只授权原受影响且当前仍可写的准确图；不能为支持该入口放宽通用 `rollbackPreview()` 或 snapshot 读取权限。历史 receipt/detail 的当前授权与执行前 fresh-before 校验分开：执行后的真实目标状态不应被误当成历史事实损坏，历史阅读也不签发新的执行能力。

M7 `AuditOutboxWriter.mapAuditEvent` 已将 submit/approve/reject/cancel/execute 转事件；M11 保留来源并新增 stage progress、schedule due/blocked/overdue、window conflict、rollback planned/completed 的固定 safe mappings/订阅清单。决策与状态+audit+outbox 同 SQL 事务；邮件/Webhook/Slack/飞书通过既有 receiver/policy，不由业务直接发送或写秘密 diff。站内通知归属当前用户，外部实际投递结果与执行结果分别展示。

## 9. API、实施所有者与集成合同

现有 API 保留 `GET /clusters/:cid/workflows`、`GET /:id`、`POST /:id/approve|reject|cancel|execute`、`GET /receipts/by-key/:key`。V2 vote DTO 增加明确 level/stageRevision/candidateVersion，所有动作保留原键/expected revision/planHash/typed confirmation。列表 view 维持 submitted/pending-my-approval/all 并添加 overdue/window-conflict；游标绑定 actor/permissionVersion/CID/WID/过滤与稳定上界。

候选新增 fixed API：定义 list/version create/archive/restore、entity typed plan/submit、workflow stage/policy detail、schedule create/cancel/by-key、board、snapshot links、rollback-plan。日程 create 只能引用已有准确 intent，不接受 raw native manifest；definition/metadata 删除走软归档；调度取消记录事实不物理删除。

以下为 Root 指定的待实施 ownership；M10 验收后再正式开工，不因本表提前编辑源码。现有共享文件必须由唯一 owner 修改；callback/接口先冻结，调用方不得并行改对方文件。

| Owner / 对应 agent | 独占待实施范围 | 输出给相邻 owner 的固定合同与门禁 |
| --- | --- | --- |
| Policy / `/root/m9_approval_migration` | `modules/workflows/workflow.types.ts`、`workflow-validation.ts`、`workflow-plans.service.ts`、`workflow.service.ts`、`workflow.controller.ts`、`workflow-registry.service.ts`；新 policy/candidates/approval-authority/durable-intent 模块及 repository；首个 SQL019 候选由 Root 最终分配 | 门禁 1 的 immutable policy/candidate/approval-set 与 shared reviewer verifier；门禁 2 的 durable intent/source manifest、原键/版本/current-context 合同；DTO/API 投影冻结后交 web。不编辑 SQL000–018、kernel 或 Approved 私有验证文件 |
| Root / authority integration | `infrastructure/kong/execution-context.service.ts`、`authorization/native-kong-policy.service.ts`、`workflows/approved-execution.types.ts`、`approved-workflow-execution.service.ts`、`configuration-approved-verifier.ts`；既有 Mutation/Recycle 私有执行集成和模块 wiring | 统一消费 V1/V2 approval authority；真正 branded/WeakMap HTTP 与 scheduled native proof、固定 step/packet/source 校验。Root 统一整合 migration、构建、部署、实库及实际 native 写；不得新增 generic waiver |
| Compare / `/root/m10_compare` | `configuration-origin.service.ts`、`governance-promotion-source.service.ts` 与后续固定 source/private recovery/durable Config adapters；必要的 ConfigurationAccess/Service/storage 原有文件在 Root 显式交接后修改 | source/target live grants、origin tuple、durable intent→新短 job 的准确 source FK/manifest 等价；scheduled source-read/private recovery genuine handle；public/private fingerprint、凭证 EOF 与累计预算。不修改普通 HTTP proof 的真实 SID 要求 |
| Typed compiler / `/root/m10_inventory` | EntityService 共用无写入 prepare 抽取；新 fixed entity/change compiler；core/Target/health/Certificate SNI/六凭证/delete/restore/batch 的准确图与 packets | 输入只含类型化用户意图；输出 server-generated sealed material/exact DAG 与真实 before/schema/ref/recovery/impact。必须保留 tag_group/entity、managed boundaries、原 ID 与凭证 provenance；不编辑 kernel 或创建执行权限 |
| Scheduled metadata/storage/window worker / `/root/m10_design` | 新 schedule/delegation/reservation/claim repository、窗口冲突算法、worker、固定 scheduled metadata handler；审计/outbox 集成及新迁移草案 | 真实 owner 委托、半开 UTC 窗口、物理 transport impact、generation/lease/CAS/原 execution key 与 current fact 集；worker 仅消费 Root 签发的真实能力。迁移草案交 Policy/Root 顺序合并，不占用编号或同写 SQL019 |
| Web owner / 由 Root 分配可用 agent | WorkflowsPage/model、EntityEditor/Details/Credential/Recycle/batch/governance approval flows，政策/阶段/会签/日程 review、看板、通知/日志/回滚导航、部署与用户手册 | 等真实 API/错误/receipt/capability 合同冻结后实现；复用原键恢复，未知状态禁止 retry/new key；所有展示来自实际数据并脱敏 |
| Independent review/verification / 由 Root 分配 review agent | 实库 migration/storage、policy/concurrency/IDOR、native/fault/browser harness、证据报告与秘密扫描 | 使用真实 repository/verifier 与实库约束；记录失败与修复；不读取/改写生产秘密、不部署、不实际 native 写、不盲重发 unknown。Root 执行已评审 runner |

集成顺序：Policy 与 Root 先冻结 approval-set/current-reviewer 接口；Policy、Compare、Typed compiler 再冻结 durable intent/source/manifest/受限 access 合同；Design 与 Root 冻结 scheduled claim/lease/window/private namespace；各 fixed business delegates 接统一资格检查；最后 Web 接真实 DTO/receipt，Review 做完整门禁。`workflows.module.ts`、ConfigurationModule 及 App wiring 由 Root 统一修改。M7 outbox/shared audit 文件需要修改时先明确交接给 Design 或 Root；没有所有权的 agent 只提供 callback 或补丁建议。

本阶段不创建 generic `runAsUser`、`approved:boolean`、任意 URL/path proxy、可写 system-read 或参数构造 handle。每个新固定 kind 需要专属 assert/subject/source validator 和否认相似 shape 的测试。

## 10. 验收门禁与落盘证据

单测与真实 DB：旧 V1 兼容、多级顺序、quorum/all、重复票/键冲突、candidate冻结、跨阶段票串用、跨 scope/hash FK、不可变事实、计划/normalized packets/source 更改拒绝。并发投票只计算 distinct users；并发 execute/worker 只能一次真实 execution。

安全与故障：提交人自批、门户冒充console、非candidate、已撤 role/team/approve、只撤其中一个有效批准人、执行人降权/epoch/forcePasswordChange、IDOR/tag/entity继承、fake handle/proof copy/SID/body actor、readonly forged scheduled origin、expired原HTTPframe、lease/window关闭、snapshot失败、unknown包中断、已成功native而metadata失败核验。上述拒绝需实际 native request count=0 或准确“已发 N 包、停止后续”，不能只验证HTTP状态。

新增 source/private 专项：scheduled Promote 使用真实委托且不保留浏览器登录；只撤 source 或 target 的对象/secret grant、source 仅隐藏字段变化、target 初始 private map 变化、source frame/proof 复制、缺少 genuine scheduled source adapter、凭证跨页重复/截断/非 EOF、预算或窗口在 before-send 失效均 fail closed。旧 V1 HTTP/SID 与 M10 ordinary/private source 链路继续通过，不允许为定时功能放宽它们。M9 实际原键 known-success metadata-only recovery 保留原失败响应并禁止 native replay。

真实端到端：两个控制台批准人多级、三个候选会签；未来计划时间无需保持浏览器登录即可触发；跨cluster别名窗口冲突；审批前原native不变；执行前完整snapshot、每步回执/审计、M7站内通知与本地授权 synthetic receiver；CRUD/Target/Certificate SNI/六凭证/完整回收恢复；凭证经真实代理认证、吊销/轮换验证；rollback按当前模式再审批、原ID恢复与原凭证实际可用。

UI：实体表单→脱敏review→工单→多级/会签→计划执行→结果/日志→rollback链，看板待我/我提交/逾期/冲突；明暗/移动端；API/审计/通知/截图秘密扫描；没有直连Admin API。所有 screenshots 数值来自本次真实测试，示意资料明确标记。

发布：保存 M11 migration/storage/native/browser/fault/security reports、失败尝试与修复证据、schema/源码版本、包版本与完整 M0–M11 regression；更新生产部署和用户手册的 policy、定时委托、窗口、unknown 处置及恢复限制。外部生产DNS/IdP/SMTP/Slack/飞书未提供时记未联调，不将 synthetic receiver 通过写成外部生产成功。M11通过后才执行用户授权的最终整体商用回归与仓库发布。
