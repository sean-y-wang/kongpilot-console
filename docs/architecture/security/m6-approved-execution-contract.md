# M6 已批准执行能力合同（Root 已审定，待 M5 提交后实施）

本合同只定义 M6 的实现接口与验收要求。M5 的真实部署、攻击验证和提交完成后，Root 才释放 M6 产品编码。本文件与 [工作流基础提案](m6-m11-workflow-foundation-proposal.md)、[M6 实施计划](../../project-history/milestones/m6-implementation-plan.md) 配套。SQL 008 的最终名称与约束由 Storage 汇总并由 Root 审定。

Root 已审定本文私有能力接口、16 logical/32 native/2 MiB 限额、不可变计划/归一化步骤/执行前快照、logical/native HMAC 分离、原生 operation 同事务 CAS 关联，以及三个审批门禁与 NativePolicy after-await/fence 核验。此审定不构成 M6 产品编码 release。

## 责任与现有安全边界

| 责任 | Owner |
| --- | --- |
| 私有审批执行能力、Mutation/Kong 审批门禁、NativePolicy 最终复核 | `m1_review` |
| WorkflowEngine、Portal 业务计划、批准事务、同步步骤调度 | `m0_kong` |
| SQL 008、PortalAuth、门户独立会话 | `m0_storage` |
| PortalAuthBoundary 独立实现/测试、AppModule/OpenAPI/授权集成、独立源码审阅 | Root |
| 独立真实 HTTP/网关攻击和业务验证 | `m0_security` |

`m1_review` 自 M6 起承担能力实现；其单测属于实现验证。Root 和 Security 分别承担独立安全审阅与真实攻击验证。

当前直接写审批门禁分别位于：

1. `MutationService.executeScoped` 在物理 `mutation:<transportScope>` 锁内、分配新账本前检查集群模式。
2. `KongService.request` 在版本/路径/执行上下文授权后、发送前检查模式。
3. `KongService.perform.prepareWrite` 在限流等待之后及 DNS 完成之后重新读取真实集群模式。

`NativeKongPolicyService` 另外验证当前原生权限、持久化操作、精确 body/对象/父关系及回收能力；其 `beforeNativeSend` 在指标 epoch 栅栏 SQL 等待后重新授权。批准执行将覆盖以上三个审批门禁的批准证明，并在 NativePolicy 的授权与最终发送阶段再次校验同一能力。集群 `execution_mode` 始终保存原真实值。

Root 另批准 M6 `PortalAuthBoundaryService`：所有影响已发布门户认证边界的 enabled key-auth/ACL 配置创建、更新、删除，接受请求的 Service/Route 表面及其关联变化，以及门户 Consumer 的 ACL credential 分组变更，在发送前验证变更后的实际认证边界。嵌套回收 DELETE 也经过该验证。审批能力保留此 prospective guard；批准的 body 不会替代当前门户/API/Consumer/ACL 状态的复核。Root 独占 Boundary 的独立实现/测试与 DI 注册，`m1_review` 独占 NativePolicy/Context 接线，Root 独立审阅接线源码。

活动或 pending 门户 grant 关联的 Consumer/key-auth/ACL credential 另有 managed-object 一致性门禁：普通 CRUD、DELETE、restore、工作区迁移和新建其子对象拒绝 `PORTAL_MANAGED_OBJECT`；只有当前私有批准 Portal step 的精确对象和包可操作。批准并不授予任意旁路维护能力。未来 M8 恢复若包含这些对象，必须明确恢复门户绑定 metadata，不能把裸原生凭证当作已恢复的门户授权。

现有路径、Kong 1.5 schema、SSRF/插件执行权限、四维完整 grant、workspace/tag/实体权限、当前会话、物理锁、未决变更影响面、配置指纹、DELETE 回收归档、监控写入栅栏、写后授权、审计和幂等规则继续适用。

## 信任来源与执行入口

M6 从控制台审批人的真实 HTTP 会话执行：先提交批准/执行认领事务，再在同一请求的受限服务器执行上下文中运行步骤。门户身份不会绑定为控制台 actor。

WorkflowEngine 向能力服务传递 `executionId`，或 Storage 返回的 `ClaimSnapshot` 候选。候选字段仅帮助定位已提交 SQL 记录。能力服务重新读取完整版本、批准、执行、归一化步骤和快照，解密计划并逐项比较后，才在私有 WeakMap 中登记一个不透明对象。对象没有公开的 plan/body/secret 属性。

建议由 `ApprovedWorkflowExecutionService` 持有候选核验及不透明 handle 的私有 WeakMap；`KongExecutionContextService` 持有祖先 frame 到已核验 claim 的私有 WeakMap。通过安装一次的策略接口连接二者，避免 Context 构造函数与 Authz/WorkflowEngine 的依赖循环。缺少已安装核验器时，approval 写入返回 `APPROVAL_REQUIRED`；已有 direct 请求保持现有授权链。

对 Controller、DTO、请求头和 `peek()/current()` 只提供关联用的公开 ID。普通 `workflowId`、客户端 hash、复制的 handle/frame、门户 JWT、body 中的 `approved:true`、workflow/operation ID、internal-read 和 system-read 上下文均不能登记私有能力。

服务端 API（Root 已确认 Engine 的两个执行入口，非 HTTP API）：

```ts
ApprovedWorkflowExecutionService.runApprovedExecution(executionId, fn)
KongExecutionContextService.runApprovedWorkflow(opaqueExecutionHandle, fn)
KongExecutionContextService.runApprovedStep(stepId, fn)
KongExecutionContextService.approvedMutationBinding(context)
KongExecutionContextService.bindApprovedOperation(context, operationId, tx)
KongExecutionContextService.assertApprovedNativeRequest(ticket, stage)
```

`runApprovedStep` 从可信执行祖先寻找已登记能力，重新核验 SQL 步骤后登记步骤祖先。普通调用者传入同名 `stepId` 不会产生祖先能力。`runActor`、`runOperation` 和 `runArchiveDelete` 通过真实私有祖先链继承能力；内部 GET 保持只读。每次读取能力都验证整个祖先链仍存活、当前 actor/CID/WID、步骤和 operation 绑定。callback 结束、HTTP frame 关闭或 deadline 到期时立即失效，遗留异步 continuation 无法延长能力。

### 已冻结的门户边界读取接口

M6 console compiler 不预先扫描完整跨工作区认证图，也不增加 preview purpose。它仅在真实当前 console actor 的受限上下文内读取目标、实际 1.5 schema 和当前 SQL publication proof，校验完整 `portal.write/workflows` grant 后编译计划；发包前的 prospective boundary 才是最终决定。门户开发者编译继续 DB-only。编译和快照都不虚构 native operation、system actor、console session 或 approved claim。

Context 在现有 `beforeNativeSend(ticket)` 中，以自身 private ticket WeakMap 的有效写 ticket 创建不透明 `PortalBoundaryReadPermit`，并将它作为 `KongPolicyHooks.beforeNativeSend` 的第八参数，保留原第七参数 `decision`。permit 的私有记录绑定存活的 ticket/frame/operation、actor/session、CID/WID、physical transportScope 及当前不可变 method/path/body/query。它不是一般读取权限，复制对象或知道 packet/operation ID 均不能创建 permit。hook 的 `finally` 立即撤销 permit；HTTP/父 callback 关闭、过期和替换 scope 同样使它失效。

```ts
declare const portalBoundaryPermitBrand: unique symbol;
type PortalBoundaryReadPermit = Readonly<{
  [portalBoundaryPermitBrand]: true;
}>; // Runtime authority additionally requires Context's private WeakMap.

interface PortalNativePacket {
  clusterId: string;
  transportScope: string;
  workspaceId: string;
  operationId: string;
  method: 'POST' | 'PATCH' | 'PUT' | 'DELETE';
  canonicalPath: string;
  body: unknown;
  before: unknown;
  mutationAction: 'create' | 'update' | 'delete' | 'restore';
  parentId?: string;
  credentialKind?: 'key-auth' | 'basic-auth' | 'jwt' | 'oauth2' | 'hmac-auth' | 'acls';
}

interface KongPolicyHooks {
  beforeNativeSend?(
    frame: KongExecutionFrame, cluster: KongPolicyCluster,
    method: string, path: string, body: unknown,
    query: Record<string, string | number>,
    decision: unknown, permit: PortalBoundaryReadPermit
  ): Promise<void>;
  // Existing authorizeRequest/authorizeResponse signatures remain unchanged.
}

interface PortalAuthBoundaryApi {
  assertBeforeNativeSend(
    input: Readonly<PortalNativePacket>, permit: PortalBoundaryReadPermit
  ): Promise<void>;
}

interface PortalBoundaryReadApi {
  runPortalBoundaryRead<T>(
    permit: PortalBoundaryReadPermit,
    paths: readonly string[],
    fn: () => Promise<T>,
    limits?: Omit<KongReadLimits, 'paths' | 'workspaceId'>
  ): Promise<T>;
  assertPortalBoundaryRead(frame: KongExecutionFrame): void;
}

interface ApprovedPortalStepPolicy {
  assertNativeWrite(input: Readonly<PortalNativePacket>): Promise<void>;
}
// Root installs APPROVED_PORTAL_STEP_POLICY once; missing policy denies the
// managed-object exception. It never skips the complete prospective graph.
```

现有 hook 实际有七个参数（最后一个是 `decision`），因此在现有签名末尾追加 permit 后，它是第八个 TypeScript 参数。实现与三方编译器以以上完整签名为准；保留 decision，不把不透明 permit 当作原 decision。

Boundary 只向此 API 传入固定 `/services`、`/routes`、`/plugins` collections/UUID paths 和当前 SQL 派生的 Portal Consumer UUID、该 Consumer 的 `/acls` collection；确有必要的 Key 证明仅允许 exact Consumer+Key UUID。不允许整区 Key list、targets、cache、状态或任意其他 schema/凭证集合。collection query 仅固定 `size<=100` 与 offset，UUID GET 无 query。保留 100 pages/10,000 records/32 MiB/120 秒及全部真实祖先预算；不能靠新 read frame 重置预算。读取 frame 再登记私 WeakMap provenance；普通 `runInternalRead('portal-boundary')`、系统/门户 HTTP、直接构造/复制 frame 全部拒绝。NativePolicy 的内部 GET 分支必须调用 `assertPortalBoundaryRead(frame)`，读取结果仅供 Root Boundary 的私有图证明，不能透传公开列表/HTTP。

最终发送次序保持：fresh native/批准 tuple → metrics fence（启用时）→ Portal boundary → fresh 当前 grants/批准/集群/ticket → transport 的同步 ancestor/lease fence。现有 `beforeNativeSend` 在 metricsFence 缺失时的 early return 必须收窄为只跳过 metrics，不得跳过 Portal boundary。每次 await 后仍复核当前证明；DB 故障、撤权、取消或未知 lineage 使当前 packet 不发送。外部直连 Admin 并行修改仍没有原生 CAS，BFF 物理锁只能约束共享此控制台的写入。

### 已冻结的执行与门禁类型

以下结构是服务器内部消费接口；不能从 HTTP body/query/header 解构后直接传入。Context 持有一次安装的 policy callback，能力服务依赖现有 Db/Secret/Authz/Workspace/Kong/Redis/Context，Context 不反向构造或注入 WorkflowEngine。所有 binding/handle 还需运行时私 WeakMap provenance，而不是只校验 TypeScript shape。

```ts
declare const approvedHandleBrand: unique symbol;
type ApprovedExecutionHandle = Readonly<{ [approvedHandleBrand]: true }>;

interface ApprovedMutationBinding {
  workflowId: string;
  executionId: string;
  planRevision: number;
  planHash: string;
  stepId: string;
  beforeHmac: string;
}

interface ApprovedMetadataInput {
  handler: string; // Fixed server registration; never an arbitrary callback.
  actor: AuthUser;
  clusterId: string;
  workspaceId: string;
  entityType: string;
  entityId: string;
  before: unknown;
  revision: number;
  payload: unknown;
}

type ApprovedNativeStage = 'authorize' | 'prepare' | 'before-send' | 'response';

interface ApprovedWorkflowExecutionApi {
  runApprovedExecution<T>(executionId: string, fn: () => Promise<T>): Promise<T>;
}

interface ApprovedContextApi {
  runApprovedWorkflow<T>(handle: ApprovedExecutionHandle, fn: () => Promise<T>): Promise<T>;
  runApprovedStep<T>(stepId: string, fn: () => Promise<T>): Promise<T>;
  approvedMutationBinding(context: Readonly<MutationContext>): Promise<ApprovedMutationBinding | null>;
  bindApprovedOperation(
    context: Readonly<MutationContext>, binding: ApprovedMutationBinding,
    operationId: string, tx: DbService
  ): Promise<void>;
  assertApprovedNativeRequest(ticket: KongPolicyTicket, stage: ApprovedNativeStage): Promise<void>;
}

interface ApprovedMetadataStepPolicy {
  assertStep(input: Readonly<ApprovedMetadataInput>, tx: DbService): Promise<void>;
}
```

`runApprovedExecution` 验证当前真实 console HTTP/actor 祖先及 SQL executing+ready snapshot，再私 mint handle，回调结束后撤销。Engine 进入它后仅通过 `runApprovedStep` 调用实际 EntityService 方法；EntityService 自己分配 Mutation，不能外包一层 Mutation.execute 再调用 Entities，避免同物理锁嵌套和双账本。metadata step 只调用固定 SQL handler 与 `APPROVED_WORKFLOW_METADATA_POLICY.assertStep`。

`approvedMutationBinding` 没有 approved 祖先时返回 null；存在但已失效、mode/revision/hash/step不一致时抛错，不能退化为普通 direct。Mutation 在物理锁内取 binding并比较 exact logical tuple；原 key 的已存在账本先准确匹配，之后才做新账本未决影响面检查。新 native operation INSERT、四列 binding 和 step.operation_id CAS 同一事务提交。`bindApprovedOperation` 仅接受本活跃步骤的私有 binding，事务异常全部回滚，不能先发包再补关联。

Context 从自身 private ticket 解出当前 frame、fresh cluster 和不可变 packet后调用已安装批准核验器。NativePolicy 的 authorize/response 分支同样验证 actual durable operation 与 exact approved请求；`prepare`/`before-send` 重新检查 approval、权限和快照，`response` 对 sealed nativeId 核验真实 ACK。method/path/body任一不符、非本 operation 或未批准的副写均失败。metadata 的可选 tx 不授予权限；固定 handler 在该事务内锁定实际业务 row，核验 actual before/revision，policy另核同版本/步骤/handler/HMAC、当前真实 actor/grants和 state，业务写入与审计/终态在同一事务。

## SQL 008 的批准版本与 ClaimSnapshot

Storage 已提出 `workflow_versions`，主键 `(cluster_id, workspace_id, workflow_id, plan_revision)`，并让步骤与执行通过同 revision/hash 的复合 FK 绑定。建议不可变版本记录至少含：

| 对象 | 必要字段/约束 |
| --- | --- |
| workflow_versions | CID/WID/workflow/revision、plan_hash、payload_secret、policy_version、step_count、expires_at；批准后内容不可更新，修改须新 revision 并重新审批 |
| workflow_approvals | 版本复合 FK、approver_id、level、decision、decision_hash/revision、request_id/time；仅追加，M6 单级且默认禁止自审 |
| workflow_steps | 同版本/hash FK、step_id、ordinal、kind、exact logical tuple、native 请求清单、dependency step IDs、state、operation_id；step/ordinal 唯一，计数和内容与加密计划一致 |
| workflow_executions | execution_id、版本/hash FK、approved_by、execution_actor_id、state/revision、snapshot_secret/hash/state、started/completed/expiry；一个批准版本唯一执行认领 |
| workflow_events | 版本/执行/步骤关联、actor/来源/requestId、action/result、安全错误 code；仅追加 |
| mutation_operations | 可空成组 workflow binding：workflow_id、workflow_execution_id、workflow_plan_revision、workflow_plan_hash、workflow_step_id；绑定步骤 FK 和 operation 唯一关联 |

SQL 008 已对齐为新增 `workflow_execution_id UUID`、`workflow_plan_revision INT`、`workflow_plan_hash TEXT`、`workflow_step_id UUID` 四列。四列必须全空或全非空；非空时原 `workflow_id`、`workspace_id` 也非空，revision 为正整数、hash 为 lowercase hex64，并通过完整 CID/WID/workflow/execution/revision/hash/step 复合 FK 关联对应版本、执行和步骤。`workflow_step_id IS NOT NULL` 唯一索引限制一个 native 逻辑步骤只有一个原生 operation。`workflow_steps.operation_id` 反向唯一关联采用延迟校验 FK，在同一 allocation 事务内 CAS 链接。metadata 行的 operation_id 必须为空。旧行仅有 workflow_id 可以保留，不回填猜测版本，也不获得批准能力。

Storage 候选接口已提出：

```ts
ClaimSnapshot = {
  executionId, workflowId, clusterId, workspaceId,
  planRevision, planHash, approvedBy, executionActorId, expiresAt,
  stepsHash, snapshotHash
}
```

能力服务按该候选重新核验实际 SQL；`stepsHash` 是服务器从解密计划和归一化行计算的摘要，`snapshotHash` 绑定当前执行前快照。任一 row 缺失、重复、不在同一版本、数量不符、hash 不一致、FK/状态/过期不符都拒绝。执行状态须为已认领的 `executing`，快照须 `ready`；批准完成尚未认领不具备发送能力。

建议 SQL 防止批准后更新版本及计划步骤内容。可修改部分只有执行状态、operation 关联、证明/回执和步骤结果；修改也必须 revision CAS。不能在失败时退回“只信加密 plan”或“只信 normalized rows”的备用路径。

M6 metadata 步骤由 WorkflowEngine 的固定 handler 在 SQL 事务内校验精确 before/revision/payload、保存步骤状态并追加审计。它保持 `operation_id=NULL`，且不能产生 native 请求能力。M6 不给普通 `IamMutationsService` 增加 approval bypass；M11 若支持通用 IAM metadata 工作流，再设计 `iam_operations` 的版本/步骤关联。native 步骤才关联本合同的 `mutation_operations`。

为避免 WorkflowEngine 与 PortalAuth 相互注入，能力服务提供 `APPROVED_WORKFLOW_METADATA_POLICY` 窄接口 `assertStep({handler,actor,clusterId,workspaceId,entityType,entityId,before,revision,payload},tx)`；Root 已原则审定此接口边界。它只在私有活跃 metadata-step 祖先下成功：固定 handler、实际 before/revision/payload HMAC、同版本执行及步骤、当前真实会话与完整 grant 均需匹配；nativeRequests 必须为空，operation_id 必须为空。核验使用固定 handler 持有的 SQL 事务读取/锁定实际行，在 await 后、业务写入前复核。PortalAuth 只注入此接口，不注入 Engine；可选 tx 不是授权，复制参数、workflowId 或 HTTP 的 approved 字段不能生成能力。direct metadata 仍独立校验自身授权与 revision，approval metadata 必须获得此精确 step 证明。最终 TypeScript 名称在 M6 release 后由接口三方冻结。

## 计划、步骤和运行时绑定

计划分开绑定逻辑 Mutation 与真实原生请求。DELETE 的逻辑 payload 是二次确认/回收参数，实际 Kong body 是空；二者不能共用一个含义不清的 `payloadHmac`。

每个逻辑步骤应含：

```ts
{
  stepId, ordinal, kind: 'native' | 'metadata', dependencies,
  clusterId, transportScope, workspaceId, workspaceRevision,
  entityType, entityId, permissionAction, mutationAction, parentId?, credentialKind?,
  mutationPayloadHmac, beforeHmac, mutationIdempotencyKey,
  nativeRequests: [{ method, canonicalPath, nativeType, nativeId?,
                     parentId?, credentialKind?, bodyHmac, beforeHmac }],
  dependencyProofs,
  deleteConfirmation?, archiveGraphHmac?,
  metadataBeforeHmac?, metadataRevision?, metadataPayloadHmac?
}
```

方法、路径和 query 按当前严格 1.5 白名单规范化；M6 native 写 query 应为空。子凭证逻辑类型仍可为 `credentials`，真实 native 类型为精确六种之一；parent 路径与字段相同。所有 secret 只存在于按版本/步骤上下文加密的 payload，列表、审批 diff、HMAC keys、事件和回执不含明文。

`permissionAction` 为四维授权使用的 `write/delete`，`mutationAction` 为既有 MutationContext 使用的实际 `create/update/delete/restore`。计划、normalized row、逻辑 payload/before HMAC、operation 分配和原 key 回执均绑定实际 mutationAction；不能以粗粒度 write 替代 create/update。metadata 使用其固定 handler 的明确业务 action，不能据此产生 native MutationContext。Kong 的 compiler DTO 与 Storage 的 normalized 字段按此语义冻结名称。

Consumer/credential UUID 和 API Key 在服务器计划阶段预生成并密文封存，生成后不随 approve/retry 再次生成。使用已批准 ID 直接确定后续 parent 关联，schema 校验和 workspace 标签准备后的真实 body 必须匹配计划的 `bodyHmac`。原生响应 ID 不等于预定 ID 时保持 unknown/停止后续步骤。若业务需要后续增加由前一步响应生成的 FK，须先审定明确的 recipe、可信成功回执和 CAS seal 规则；M6 不采用任意运行时 payload 回填。

既有 EntityService.create/createCredential 在 CREATE 中的 `MutationContext.entityId` 为 undefined，SQL original logical entity_id 为 NULL；预分配 UUID 在 payload.id/nativeRequests.nativeId 中。计划中的 logical entityId 应为 null/缺省，不能强行等于 sealed nativeId；绑定核验使用实际 logical tuple，同时要求 create/restore 的 effectiveNativeId=`context.entityId ?? context.payload.id` 精确等于 sealed nativeId，并拒绝缺失/替换的 body.id。native ACK 后才 CAS 记录实际 entity_id，实际 Consumer/ACL/Key ID 必須与 sealed UUID 相同。requestHash 继续绑定原 CREATE null tuple，而不是后来 ACK ID。

EntityService 返回的 `{entity,propagation}` 已脱敏，不能从该返回值重建批准 payload、secret、tags 或 fingerprint。compiler 保存 workspace/schema 准备后的实际 mutationPayload 和最终 wire body；嵌套 Consumer credential wirebody 中移除 consumer FK 的行为也必须体现，逻辑 parentId/credentialKind 与真实路径独立绑定。

不可变 plan tuple 不保存易变化的当前会话/权限版本。私有运行时 claim 另外绑定执行 actor、真实 console session、issue 时 permissionVersion、HTTP deadline、execution lease、批准 expiry。每一步及最终发送时复核当前版本；变更时旧 handle 失效，重新验证批准计划及当前权限后才能由服务端重新进入。M11 后台执行另行增加专用服务器上下文，不能伪造 console session。

M6 建议限额：最多 16 个逻辑步骤、32 个原生写请求；解密计划/快照各不超过 2 MiB。步骤调度和读取沿用真实请求 120 秒/500 calls/32 MiB 上限，不能以创建新子 frame 重置祖先预算。工作流数量、门户 application/API 集合另由 Portal 层按服务端预算限制。最终数字由 Root 冻结。

## 批准、账本与物理锁次序

1. WorkflowEngine 校验当前 `workflows.approve` 完整 grant 和原 API/工作区/标签/实体范围，开发者、应用和已发布 API 状态，并检查待执行 Consumer/credential/plugin 的所需权限。批准 SQL 事务以 revision/hash/state CAS 保存批准及唯一执行认领。批准事务内统一 IAM epoch 锁次序与现有 IAM 相同，避免和当前授权变更锁反序。
2. 生成执行前的最小定向加密快照：已有目标/共享引用的完整 before，创建 ID 的明确不存在证明，依赖关系和批准前指纹。该能力基础不依赖尚未实现的 M8 全量快照模块。快照必须与批准计划的 before 一致，才持久化 `snapshot_state=ready`。
3. 在已提交认领及快照下进入私有 execution/step 能力。WorkflowEngine 可持有不同的 `workflow:<executionId>:execute` 外层锁；各 Mutation 继续自行持有 `mutation:<physicalScope>`。现有 Redis 明确拒绝同 key 嵌套，Engine 不能持有 physical mutation 锁后再调用同 key 的 MutationService。定向快照的物理锁核验完成后释放，每步 Mutation 锁内重新核验相关 before/refs。
4. native 步骤的 `approvedMutationBinding` 在 Mutation 的物理锁内验证当前批准/执行/步骤/权限和逻辑 payload/before/scope。Mutation 保留原 key 查找、未决影响面阻断和 native stale guard。新账本分配时，在同一 SQL 事务中插入 operation 并 CAS 绑定 `workflow_steps.operation_id`，防止步骤与 native ledger 分离。metadata 步骤走上述固定 SQL handler，不进入原生账本分配。
5. `requestHash` 增加可信 workflow binding（执行/版本/hash/step，以及已批准 beforeHmac）；从私有祖先派生。单独的 `context.workflowId` 只用于关联和审计。原 direct 请求的未绑定 hash 保持兼容；相同 key 不能从 direct 改为 approved，也不能用于另一批准版本/步骤/actor。
6. callback 在可信 native operation frame 内执行。NativePolicy 把当前 native ticket/body/before 与私有步骤允许的请求、operation 和已批准 SQL 行比较，并保留所有现有授权/父关系/归档逻辑。
7. `Kong.request` 和 fresh `prepareWrite` 的 approval 判断只在此次请求通过上述能力证明时放行。after rate wait、before/after DNS、指标栅栏 SQL 等待之后均重查当前批准/执行/权限、集群真实 revision/连接/模式、租约与 context；最后同步 fence 检查活跃链和 lease flags 后才发一次原生写。
8. native ACK/readback 后，Mutation 保存自己的结果和审计，Engine 再 CAS 保存步骤状态并开启下一步。若 Engine 回写丢失，后续调度只读取原 operation 回执，不能发新 key。UNKNOWN、running 或没有 remote_completed 的步骤继续阻断；HTTP timeout 或单次不存在 GET 不能证明原 packet 已停止。

批准允许审批模式的计划内写入；同一批准计划在集群 mode 变化后须重新核验记录的 revision/policy。plan 绑定集群 revision，模式/连接/注册标签等变化使旧 plan 409 stale；不能把切换为 direct 视为批准仍然有效的证明。

### Direct 计划与必须批准的 Direct 凭证计划

Storage 最新 SQL 合同分别绑定不可变 `execution_mode` 与 `approval_required`：approval mode 必须 approval_required=true；approval_required=false 必须 direct mode，但 direct mode 也允许 approval_required=true。门户 credential issue/rotate/revoke 始终属于后者，必须完整真实批准/ready snapshot/私有 claim，不能因为当前集群 direct 而自动发 Key。cap verifier 因此不能仅接受 execution_mode=approval；它接受同 captured mode/revision且approval_required=true的已批准业务计划。

`approval_required=false` 的 direct publication/configuration 计划永远不能 mint approved handle，即使被插入伪造批准行也拒绝。它没有 workflow_stages/approvals/approved_by，执行自己的普通 current native 权限和普通 Mutation ledger。四个新 workflow binding 列和 direct step.operation_id 全 NULL；safeResult.nativeOperationId 与加密原 key/actual receipt 只做恢复相关，不作发送权限。最后 direct metadata 使用正常 IAM SQL callback，approved metadata 不借该 callback 放行。

直接链恢复必须匹配原 actor/CID/WID/server step key 和原 logical request hash。现有 `Mutation.completed()` 是 DELETE replay helper，会将 entityId canonicalize 为 ACK ID，不能直接拿来验证 CREATE 的 original null hash。M6 要增加明确只读的 original-tuple receipt helper（或准确扩展此 CREATE 分支），并再次核对 sealed nativeId/当前 desired状态；UNKNOWN/partial 不能由新 key 触发重发。此修订属于 M6 实施，不修改冻结的 M5 runtime。

## NativePolicy 的最终当前证明

在允许一次 native write 前必须同时成立：

- 有私有活跃 workflow/step 祖先，其 actor/CID/WID 与 operation 一致。
- SQL 批准仍属于同版本/hash，执行/步骤处于合法状态，未撤销/过期，前置步骤持有成功 ACK，snapshot ready。
- operation 为当前 actor/cluster/workspace/type/action 的 running+remote_started，且是步骤唯一关联的 ID。
- method/path/body 与批准 native 请求一致；当前 before 与批准指纹一致，workspace 和父/所有 plugin bindings 当前仍在允许范围。
- 当前账号与真实会话仍有效，当前批准权限与实际 native 写/删权限仍满足完整四维 grant；tag_group 子对象自身标签交集等规则仍生效。
- 物理锁、所有外层执行锁、未决影响面和 after-await context 均有效。
- DELETE 额外持有真实 Recycle archive/node 能力，graph 完整且匹配批准 closure；restore 同样匹配归档的精确对象/秘密恢复语义。
- 指标 epoch before-write 栅栏持久化成功，随后再次验证批准及授权。栅栏等待后撤权/取消/过期阻止发包，已关闭的 epoch 由实际证明恢复，不能手工开放。

上层每次批准证明都无原始配置的公开返回值，错误只给安全 code/自己的关联 ID。执行期间权限或批准状态变化后，已发请求按账本保持 uncertain，后续未发请求停止。执行中取消不释放任何 unresolved guard，也不自动创建补偿操作。

## M6 门户审批与 M11 扩展

门户提交 ID 只能定位本人 application 的已发布 API 请求。服务器从真实 API metadata/native identity 生成 plan，使用当前目标 API 的 `workflows.approve` 范围校验；application、开发者、目标 API 和原 workspace 的变更在执行前重新核验。申请人提供的 native JSON、role、workspace 保留标签、parent/Consumer/Plugin ID、任意 URL 均不参与生成执行权限。

开发者 HTTP 编译仅读取所属 DB metadata 和成功 publication revision 的加密证明模板；模板绑定当时的 Service/plugins/schema/tags/FK/transport/version。开发者请求不执行 native capture，不创建 console actor、假 session 或 system-read。服务器只预分配 ID/Key，不声称 ID 已不存在。真实控制台 approve/execute 时重新核验当前 native 依赖、创建 ID 缺席及执行前快照；证明不再匹配则拒绝，不能在原批准版本里静默 replan。

Kong 的业务计划明确包含发布和授权两条链：发布先处理 ACL 插件、再处理 key-auth 插件、最后提交发布 metadata；授权申请依次创建预分配 Consumer、ACL 凭证、key-auth 凭证，再提交应用授权 metadata。metadata 步骤同样绑定 SQL before/revision/payload HMAC，通过服务端事务和当前授权核验；审批记录本身可在 approval 集群提交，草稿/发布等业务写操作仍按集群模式执行。

M6 优先使用所选 Service/Route 上明确批准的 key-auth/ACL 绑定；全局插件步骤必须在计划中明确列出并获得现有平台执行权限，不能因凭证申请隐含启用全局安全配置。Consumer、ACL 分组、credential 和业务标签由服务器选择，Portal 凭证查看继续独立 owner 校验，控制台回执不返回 API Key。

轮换先创建批准的预分配新凭证，再完整归档旧凭证；新 key 在终态成功前不向门户揭示。部分失败不会自动清理、新建另一份计划或自动发第二把 key。撤销/恢复和各步骤的 key-auth/ACL prospective boundary 仍以当前真实状态为准。

M6 先支持单级 approve HTTP 同步执行与原批准人显式核验/继续未发送步骤；失败/unknown 不执行自动补偿。M11 在同一版本、execution 和 ledger 上增加 quorum/level、时间窗口和 scheduler 专用 claim。scheduler 使用已批准 actor 的当前账号/grants和窗口证明，不能使用任意 system-read、旧 JWT 或假的 HTTP/session 上下文。

## 实现与独立验收门禁

### Source 实施切分（M6 release 后）

1. **类型与私有版本验证**：新增 `modules/workflows/approved-execution.types.ts`、`approved-workflow-execution.service.ts`（m1_review）。先实现 SQL version/execution/approvals/normalized steps/ready snapshot完整验证、16/32/2 MiB 限额、current actor/session/grants与 immutable mode/revision；纯候选、direct=false、复制handle都不能 mint。Root/Storage 冻结 008 后只使用它的实际列名，不另造平行 workflow 表。
2. **Context 私有祖先与窄读取**：m1_review 修改既有 `execution-context.service.ts`，一次安装 approved policy，无 DI 构造循环；实现 execution/step/binding/ticket lineage 与关闭语义，追加 opaque portal-read permit及有界 path whitelist。先验证 fake/copy/跨 scope/祖先结束和双 prepare 生命周期。
3. **Mutation 关联与幂等**：m1_review 修改 `mutation.service.ts` 的物理锁内批准门禁、可信 requestHash、同事务 INSERT+step CAS、原 tuple历史回执；保留未决影响面、真实 stale/readback、回收和审计。Engine 只 dispatch Entities，不自行调用外层 Mutation；DELETE 不绕 Recycle。
4. **Kong/NativePolicy 三门禁与最终发包**：m1_review 修改 `kong.service.ts` 的 request及fresh prepare approval分支、`native-kong-policy.service.ts` 的 exact approved operation/response与Root Boundary hook。metrics关停不能跳过Boundary，审批/租约/上下文在所有 await 后保持当前证明。Root 独占 Boundary service/测试，私 managed-object 例外只通过 `APPROVED_PORTAL_STEP_POLICY`。
5. **实施验证与独立审阅**：m1_review 的实施测试覆盖 raw plan篡改、normalized缺/重行、承认direct=true批准但拒false、create null与bodyUUID、SQL CAS回滚、currentgrant/session/模式变更、metadata handler旁路、copy permit及hook结束continuation。Root 独立读源码和SQL，Security 独立 HTTP攻击/真实proxy A/B Key/rotation/revoke；Devops统一构建迁移后才运行真实门禁。

此切分不释放 M6 编码。M5 真实验收、commit及Root explicit release仍是产品文件修改的前置条件。

| 验证 | 必须观察到的结果 |
| --- | --- |
| approval 集群普通 CRUD、workflowId/header/body 伪造 | 全部 409/403，零 native 写 |
| 复制 handle/frame，HTTP/system-read 伪能力，跨 actor/CID/WID/parent/path/body | 零 native 写；原批准记录不变 |
| 版本/hash/steps 数量/normalized row/FK/snapshot 被改或缺失 | fail closed，不降级、不自动重新批准 |
| 同时批准/执行、同 key 另一计划、metadata link CAS 冲突 | 唯一执行/步骤 operation，另一请求不发包 |
| 创建 ID 已存在、已有目标/引用 before 漂移、非批准的副写 | 零后续 native 写，原计划/回执可查看 |
| await SQL/DNS/rate/fence 期间撤权、会话撤销、过期、取消、锁丢失 | 当前 packet 或下一 packet 被拦截；不复活旧 claim |
| approval mode 始终保留 | DB 真实模式不变，计划内请求经过三个门禁与 NativePolicy |
| Consumer/key-auth 申请批准 | 真实代理可用，Portal owner 可领取，其他开发者和控制台安全回执不泄露 key |
| parent/step 认领或 commit ACK 丢失、native response 丢失 | 原 ledger 保留，原 key 回执明确，UNKNOWN 不换 key 重发 |
| DELETE/restore/轮换/吊销 | 当前权限、二次确认、完整回收图、指标栅栏、逐步审计继续成立 |
| 进程/HTTP callback 结束后的异步 continuation | 私有祖先已关闭，零额外 native 写 |

实现单测、SQL 集成、真实 HTTP/代理故障验证分别标记证据来源。Root 审阅 capability 源码，Security 独立执行伪造、越权、重放、竞态及实际凭证验证；产品 owner 的 mock 测试不能替代真实部署证据。
