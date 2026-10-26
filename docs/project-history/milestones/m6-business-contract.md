# M6 门户业务与统一工作流合同

状态：设计合同。M5 已进入部署验收；本文件不新增产品代码、迁移或运行时能力。M6 编码以 Root 的 M5 提交与 implementation release 为起点。M6 使用单级审批和当前控制台 HTTP 会话同步执行；M11 在同一引擎上扩展多级、会签、计划时间和变更窗口。

相关合同：[Web](m6-web-contract.md)、[实施计划](m6-implementation-plan.md)、[工作流安全基础](../../architecture/security/m6-m11-workflow-foundation-proposal.md)、[精确批准执行能力](../../architecture/security/m6-approved-execution-contract.md)。本文定义业务编译器、持久计划及公开 HTTP 的交接边界。

## 1. 所有权与模块

| 所有者 | 实现边界 |
| --- | --- |
| Kong/business | `modules/workflows/**` 公共工作流业务、`modules/portal/**` 内容/应用/发布/凭证业务与编译器；复用 Entities、Mutation、Recycle、CredentialStore |
| Storage | SQL 008、门户独立认证/会话与数据库服务；门户身份不转换为控制台用户 |
| Reviewer | 私有已批准计划能力、Mutation/Kong 审批门禁与 NativePolicy 私有能力/PortalBoundary before-send 接线；原生删除仍需独立的已持久回收能力 |
| Root | AppModule/依赖、当前授权规则、独立 PortalAuthBoundaryService 及真实策略单测、私有审批能力源码审阅；批准精确计划不会跳过权限 |
| Front | 独立门户站点 8082 与现有管理站的门户/审批页面 |
| Security/Devops | 独立权限及真实代理验证、网络与统一部署；单个所有者不并行运行有状态验收 |

建议服务接口为 `WorkflowService`、`WorkflowPlanCompiler`、`PortalPublicationService`、`PortalApplicationService`、`PortalCredentialService`、`PortalAuthBoundaryService`。计划编译只支持注册的业务 kind，不接受任意 Kong method/path/body。数据仓库不持有 Kong Client，门户守卫不接受控制台 issuer/audience，原生实体服务不接受开发者身份。

## 2. 租户、权限与应用授权模型

门户开发者账号固定属于一个 `cluster_id + workspace_id`。公共入口仅显示活动且公开的租户描述，不能借入口枚举 Admin URL、控制台用户、私有工作区或原生配置。私有业务的 CID/WID 必须同时匹配当前门户会话、当前数据库开发者和实际对象；客户端不能指定 owner/Consumer/原生插件配置。

开发者 HTTP 请求不绑定 console actor，不构造假的 AuthUser/console session，也不通过 `runSystemRead` 获取 Kong 配置。现有执行上下文禁止在任何已有 HTTP ALS 中开启系统读取；门户请求不能绕过或清空该规则。开发者业务服务仅使用门户身份、数据库元数据与服务器已保存的发布证明生成申请，不能调用 Entities 或私有 native capture。

一个应用属于一个开发者；一个授权 grant 对应一个 application × publication。每个 grant 使用独立 Consumer、ACL credential 和 key-auth credential。发布项绑定一个真实 Service；活动发布项对 `(cluster_id,workspace_id,service_id)` 唯一。不能为同一个 Service 发布互相冲突的 ACL 认证配置。

publication 的原生授权范围是该 Service 的全部 Routes，不是上传文档里出现的 path/operation 子集；发布/申请页面明确呈现这一范围。要限制单个 Route，应先使用独立 Service 和单独发布项，不能以隐藏文档操作假装网关已做权限隔离。

发布项专属 ACL group 为 `kos-portal-api-<publication UUID>`。服务器预分配 Consumer/ACL/key-auth UUID 和随机 Key，并将完整计划加密保存；密钥不经门户请求、审批评论、diff、回执、审计或通知传递。原生 tags 从实际发布 Service 的已授权业务 tags 和工作区规则生成，`portal-grant:<uuid>` 等标记只是管理元数据，数据库关联才是门户所有权证据。

控制台内容、应用和工作流查询使用 `portal/developers/applications/workflows` 模块的完整四维授权。发布项及其申请/workflow 必须读取真实关联 Service，并调用 Root 的 `assertScopedResource(user,cid,'portal'|'workflows',action,'services',actualService,wid)`，不能将粗粒度 `assertCluster` 当对象授权。这样 tag_group/entity 的门户权限可基于真实 Service 生效，不隐含原生 Service config read/write。列表使用对应当前 `filterScopedResources` 逐实际对象过滤，不把不同 grant 行拼接。Developer/application 纯门户元数据采用明确 global/workspace 管理 row；tag/entity grant 不能借 `assertCluster` 扩大为整区管理，与具体 publication 关联的申请才按实际 Service 投影。执行原生步骤另行校验实际 Consumer、Plugin、ACL、key-auth 的当前原生权限与外键归属。私有审批能力只解决 execution_mode 门禁。

开发者自身的应用及申请是门户业务元数据，按独立当前会话、ownership、revision 和审计写入。控制台的发布、撤回、配置、开发者状态等业务变更遵守集群直接/审批模式；不能用自研 SQL 绕过审批集群。工作流提交、批准、驳回和撤销本身是流程元数据，允许在审批集群完成，且必须保留当前审批权限和不可自审规则。

`audit_events.actor_id` 当前引用控制台 users。开发者审计使用 `actorId:null, actorType:'developer'` 和安全的 developer/tenant/subject 标识，不把开发者 UUID 写入控制台用户外键。所有原生执行的 actor 是实际当前控制台审批/执行人。

## 3. Kong 1.5 认证边界

Kong OSS 1.5 的 key-auth credential 在网关内具有全局认证意义。工作区 tags 只控制管理视图，不能让一个 Key 自动限定到某 Service。因此仅创建 Consumer 与 key-auth credential 不满足 API 授权隔离。

发布计划明确管理 Service-bound `acl` 与 `key-auth` 实例，不创建或改写 global key-auth。启用顺序为 **ACL whitelist → key-auth → 发布元数据**，避免先开放认证再补访问限制。ACL 使用实际 1.5 schema 的 `whitelist`，不伪造新版 allow/deny 字段。已有合法 whitelist 必须保留原 groups，追加本 publication group，diff 明确呈现；不能覆盖旧名单使原客户失去访问。既有 blacklist、anonymous 或其他认证语义不能自动转为门户默认值，需要明确整改/批准计划，安全无法证明时拒绝发布。已存在 key-auth 的 key_names/其他参数保留实际配置并在文档中呈现认证位置，不能暗中重置。Consumer 发放顺序为 **Consumer → ACL credential(group) → key-auth credential → grant/credential 元数据**。

### 发放前和后续变更的持续校验

`PortalAuthBoundaryService` 在发布、发放、轮换及认证相关原生发包前检查当前/拟提交配置。只检查批准页面上的 Service 不够；它必须在严格预算内建立当前网关的完整认证图，并按 1.5 的有效同名插件选择顺序 `RSC > RC > SC > RS > C > R > S > global` 分析 Service、Route、Consumer 组合。disabled 实例被跳过；插件执行顺序与同名实例选择不是同一概念。

凡某个其他启用 key-auth 表面可能接受活动或本次计划的 Portal Consumer，而有效 ACL whitelist 不能拒绝该 Consumer 的门户 group，必须拒绝：`PORTAL_UNMANAGED_AUTH_BOUNDARY`。黑名单式 ACL、缺 ACL、覆盖 Service ACL 的 Route/Consumer 绑定、未知自定义认证行为、缺失 schema、未完整扫描、预算耗尽或计划依赖变化均不能被当作安全证据。旧 global key-auth 且缺 whitelist 边界的网关需管理员先整改，控制台不能静默修改其他 Service。

本服务作为 Root NativePolicy 的业务 hook 集成；存在已发布 API、活动/发放中凭证或历史受管对象时，缺少 hook 或不能完成证明必须 fail closed。它检查 key-auth/acl 的 prospective create/update/delete、绑定变化、enable/disable 和恢复；回收图中删除 ACL 的具体 DELETE 包也必须检查，不能因已归档而跳过。新增/重绑定 Service/Route 可能沿用现有 global key-auth，新建接受表面不能漏检；门户 Consumer 的 ACL credential group 添加/变更/删除也会改变可达 API，应纳入同一 prospective guard。新建 key-auth 路由入口同样受保护。已批准能力不豁免此校验，校验或数据库不可用时零原生发包。

已发布 Service 的认证基线在尚未创建任何 Consumer/Key 时也受保护。成功 publication/proof 提供实际 `serviceId`、专属 `aclGroup`、受管 ACL/key-auth plugin IDs 及同版本 terminal-success execution 关联；boundary 使用只供私有分析的 prospective Portal Consumer 和所需 group 验证该 Service 的有效认证链，不创建原生 Consumer。普通 CRUD 不能移除 ACL、禁用 key-auth 或改写绑定，使已发布 API 开放或旧证明失效。此基线与真实 active/pending 凭证检查并存，不能因 Key 数量为零跳过。

数据库 active/发放中关联的 Portal Consumer、Key 和 ACL credential 另有业务一致性约束：generic M1 CRUD、批量、回收删除/恢复不能直接改写这些对象；只允许私有已批准的匹配 Portal 业务步骤，其 actual tuple/body/before 与 grant/credential 计划一致。向受管 Consumer 新增普通 Key/ACL credential 同样禁止，不能用未关联的新实体绕过管理记录。返回 `PORTAL_MANAGED_OBJECT` 并指导从门户轮换/吊销流程处理，HTTP workflowId 不能放行。Consumer 迁移/删除/改属也不能使 SQL grant 仍 active 而原生关联漂移。未来 M8 回滚必须显式包含 Portal binding metadata 恢复步骤；M6 不实现通用快照回滚，默认拒绝未规划的受管对象恢复。

管理所有权不会随 revoke 消失：所有历史关联 Portal Consumer/Key/ACL UUID 和这些 Consumer 下新增 Key/ACL 子对象持续受上述 private Portal-step 限制。特别是 generic Recycle restore 不能复活旧 Key 后留下 SQL revoked 的矛盾状态。认证图除 active/pending reservations 外，保守纳入历史 Portal Consumer；这不把 revoked Key 宣称为活动凭证。受管 UUID 集合始终使用完整历史关联，不能按 active 状态缩小。吊销后重新发放必须显式新申请、当前 grant revision 和新审批；M6 默认保留并复核原 Consumer/ACL 归属，预分配全新 Key UUID/秘密和下一 generation，不恢复旧 Key，不自动创建第二份 grant。原 Consumer/ACL 证明来自已成功历史加密计划与 DB 引用，console snapshot 再次核验实际状态；改变 Consumer 需要独立明确批准的迁移/重新绑定计划，不隐含重写历史 credential FK。

风险、受管 UUID 和 pending reservation 查询覆盖**所有共享实际 transportScope 的注册 CID**，不是只查询当前请求 CID。注册别名访问的是同一物理网关，不能借另一个没有 portal 元数据的 alias 破坏 ACL 或恢复旧 Key。每条业务记录仍保留真实原 CID/WID；跨别名的错误只给权限允许的定位，不把原租户配置公开。尚未确认物理身份的 DNS 别名不能被自动视为强隔离，注册与软隔离局限明确说明。

危险并发范围使用实际 Admin endpoint 的 transportScope 锁，计划/发放的 pending reservation 也纳入风险集合。发放计划在首个 Consumer 原生请求之前持久化 pending grant、预分配 Consumer/ACL/Key IDs 与 group，使最终 hook 能从 SQL 看见真实计划；不能在创建了 Key、尚未提交 active 元数据的间隙开启另一个无 ACL 入口。新开启/删除认证对象会影响有效链，必须在发包前复核，不用旧缓存作为授权证据。Engine 的执行锁使用独立 workflow execution key，每步由现有 Mutation 获取 physical lock；不能将同一 physical lock 嵌套获取。编译/快照的 physical proof 锁在进入逐步 Mutation 前释放，每步重新证明依赖。

完整认证图属于私有受控 capture，不向普通列表请求全量加载。它使用固定 native size=100 游标，预算最多 100 pages/10,000 records/32 MiB/120 秒，并对同一 effective-chain 运算设置有限组合预算；超预算拒绝而不是凭部分图发放。外部 Admin 并行改写仍无原生 CAS，文档明确该局限。

### Boundary 与 NativePolicy 的窄交接

Root 的 boundary 实现接收 NativePolicy 已验证的当前 durable native 请求；Reviewer 持有 NativePolicy hook 与私有已批准步骤 verifier。建议接口：

```ts
assertBeforeNativeSend({
  clusterId, transportScope, workspaceId, operationId,
  method, canonicalPath, body, before,
  mutationAction, parentId?, credentialKind?
}): Promise<void>
```

输入仅定位/描述已经核验的当前 packet，不接受 `approved:true`、workflowId 或用户提供的安全结果。受管对象例外由 boundary 调用服务器安装的私有 Portal-step verifier，对当前活跃 claim、version、binding 和 exact body/before 重新证明；缺 verifier 不放行。当前 DB 的成功发布基线、active/pending grant/credential reservations 与保守历史 Consumer 证明共同形成风险输入，graph 上叠加本次 prospective packet 后验证完整边界；历史受管 UUID 另按完整关联集合校验。

建议 trusted internal-read purpose `portal-boundary` 只允许固定 bounded GET `/services`、`/routes`、`/plugins` 的 size/offset collection 与 exact UUID 路径，及当前 DB 派生的 Portal Consumer UUID/ACL collection；确有必要的 Key 存在证明限该 Consumer 的 exact Key UUID，不能遍历所有凭证明文。该 purpose 由已核验 native mutation 的服务器 handler 使用，绑定实际 actor/operation/物理 scope 和祖先预算，不要求额外 public entity.read，也不能从门户 HTTP 建立。原始跨工作区 graph 仅用于私有安全证明，不能作为 public response 或普通列表输出。

平台管理员可查看被拒绝位置的脱敏 Service/Route/Plugin ID 和修复建议。普通 scoped 管理员只收到已授权定位项或不含配置/名称的风险数量，不能借报错枚举其他工作区。外部直连 Admin API 可以绕过 BFF hook；网络边界与持续巡检只能降低风险，Kong 1.5 无工作区和原生 CAS 的限制须在 UI/README 说明。

验收必须使用真实代理证明：同一 app 为两个发布项领取两把 Key，A Key 可调用 A、调用 B 返回 401/403；另一个旧 API 不接受 Portal Key；后续去除 ACL、建立覆盖插件或新建无 ACL 的 key-auth 表面被 BFF 拒绝。不能仅以数据库 grant 或 Consumer tags 证明隔离。

## 4. HTTP 路径与公开 DTO

全部路径以 `/api/v1` 为前缀。公共/门户身份路径是 `/portal`；管理路径是 `/clusters/:cid/portal`；共用工作流是 `/clusters/:cid/workflows`。所有私有门户请求携带明确 CID/WID，且与当前会话相同；管理查询携带 `workspaceId`。未知字段拒绝，列表签名游标绑定当前 actor/tenant/permission epoch/filter/size，不提供随机跳页或全量下载。

标准列表为 `{items,nextCursor,size,total:null}`，统一成功/错误 envelope 沿用项目现有规范。下面字段使用 camelCase；数据库使用 snake_case。`revision` 为正整数 CAS，所有持久写入需要原始 `X-Idempotency-Key`，不把新 key 当作未决变更的重试许可。

### 公开门户与本人业务

| 方法与路径 | 输入 | `data` 响应 |
| --- | --- | --- |
| GET `/portal/tenants`、`/tenants/:slug` | size/cursor 或 slug | 当前公开租户安全描述；沿用 Storage 认证合同 |
| GET `/portal/publications` | clusterId/workspaceId、size/cursor/search/category | PublicationSummary 列表 |
| GET `/portal/publications/:id` | clusterId/workspaceId | PublicationSummary、当前公开文档版本摘要 |
| GET `/portal/publications/:id/document` | clusterId/workspaceId | `{publicationId,revision,format,document}`，受限脱敏 JSON |
| GET `/portal/pages`、`/pages/:slug` | clusterId/workspaceId、分页或 slug | 已发布页面摘要或 `{slug,title,revision,markdown}` |
| GET/POST `/portal/applications` | POST `{clusterId,workspaceId,name,description?}` | 本人 ApplicationSummary；创建不写 Kong |
| GET/PATCH `/portal/applications/:id` | PATCH `{clusterId,workspaceId,revision,name?,description?}` | 当前本人应用；revision CAS |
| DELETE `/portal/applications/:id` | `{clusterId,workspaceId,revision,confirmed:true,confirm_name}` | 没有活动/未决 grant 时软归档；否则 `PORTAL_ACTIVE_GRANTS`，先显式吊销 |
| POST `/portal/applications/:id/restore` | 同范围与确认/CAS | 恢复本人软归档应用，不恢复原生凭证 |
| GET/POST `/portal/requests` | POST `{clusterId,workspaceId,applicationId,publicationId,reason?}` | 本人请求 WorkflowSummary；服务端生成唯一 immutable 发放计划 |
| GET `/portal/requests/:id` | 当前范围 | 本人安全 WorkflowDetail/执行摘要 |
| POST `/portal/requests/:id/cancel` | `{clusterId,workspaceId,revision,reason?}` | 仅未开始执行的本人请求可撤销 |
| GET `/portal/applications/:id/grants` | 当前范围、size/cursor | 本人 GrantSummary 列表 |
| GET `/portal/applications/:appId/grants/:grantId/credentials` | 当前范围、size/cursor | CredentialSummary；永不自动返回 Key |
| POST `.../credentials/:credentialId/reveal` | `{clusterId,workspaceId,revision}` | `{credentialId,key,expiresAt}`，独立显式秘密请求，no-store，不进入通用缓存 |
| POST `.../credentials/:credentialId/rotate`、`/revoke` | `{clusterId,workspaceId,revision,confirmed:true,confirm_name,reason?}` | 新工作流安全摘要；不直接执行 Kong 写入 |
| GET `/portal/operations/by-key/:key` | 当前范围 | 本人门户操作安全回执；申请返回 workflowId，不转换为 native operation 权限 |

门户认证路径、Cookie/CSRF、资料和密码路由以 Storage 的独立认证合同为准。公开文档可匿名看；注册只返回 pending 的安全确认，待审核开发者不能登录，审核 active 后才建立门户会话。停用开发者、应用、发布项或未决执行均阻止秘密领取。控制台审核页面不返回开发者 Key。

### 控制台门户业务

| 方法与路径 | 输入与语义 |
| --- | --- |
| GET/PATCH `/clusters/:cid/portal/settings` | 当前 WID；品牌、安全字段白名单；PATCH revision CAS，审批模式返回 pending 工作流，非任意 CSS/HTML |
| GET `/.../developers`、`/developers/:id` | 分页/状态/搜索；scoped 当前租户开发者安全投影 |
| POST `/.../developers/:id/approve`、`/reject`、`/disable`、`/restore` | revision、reason、确认；批准无原生执行，cluster approval 模式按明确 metadata 计划执行 |
| GET `/.../applications`、`/applications/:id` | 当前已授权应用与 grant/请求安全关系；无秘密 |
| GET/POST `/.../publications`、GET/PATCH `/.../publications/:id` | 创建/修改草稿 `{serviceId,name,description?,category?,revision?}`；不能客户端提交 managed plugin IDs 或 ACL group |
| POST `/.../publications/:id/document` | revision、JSON/YAML 文档或文档生成类型；受限上传，自动生成只读取已授权实际 Service/Route |
| POST `/.../publications/:id/publish`、`/unpublish` | revision、confirmed、confirm_name；publish 为显式 ACL→key-auth→metadata 计划；unpublish 只撤回公开内容/新申请，不隐式吊销已发 Key |
| GET/POST `/.../pages`、GET/PATCH `/.../pages/:id` | 字段化 Markdown 草稿、revision CAS；发布/撤回为独立计划，不能用草稿覆盖已批准公开版本 |
| POST `/.../pages/:id/publish`、`/unpublish` | revision、confirmed、confirm_name；已有页面保持旧批准版本直到新版本执行成功 |
| GET `/.../requests` | 当前 authorized 工作流门户摘要，可跳转统一 workflow 控制器 |

直接模式的纯 metadata 变更经过现有 IAM ledger/audit。审批模式返回 `{state:'pending',workflowId,revision}`，不同时修改目标业务状态。门户请求不决定 direct/approval；credentialIssue/rotate/revoke 默认总是显式审批。

### Direct 集群的复合发布

Direct 集群的 publication/page 复合变更不强迫额外审批，也不记录虚假的 self-approval。服务器先持久化 immutable plan 和父回执，记录 `executionMode:'direct',approvalRequired:false`、当前 confirmed console actor/原始 key，再以其正常 native 权限执行 ACL→key-auth→metadata。每个 native 步骤使用普通 EntityService/Mutation ledger、服务器派生 step key 与 exact before/body guard；它不持有私有已批准能力，不能绕过真实 cluster mode。工作流 approval rows 保持为空，审批按钮为 false。

Direct native step 的 `operation_id=NULL`，不能关联到要求 full approved workflow binding 的 SQL reverse FK。只在安全结果保存 `nativeOperationId`，加密保存 actual receipt/source-key HMAC，作为恢复关联而非授权。关联未保存时，Engine 仅按原 actor/cid/wid/server step key 与 exact logical payload/before 查询原 ledger 后 CAS 保存已有回执，不能因此重新发包。成功 step 当前证明一致才 skip；failed/uncertain 不自动重发。普通 Mutation 的完整权限、物理锁、回收、边界和 metrics fence 仍是实际写入依据。

最后固定 metadata handler 调用正常 `IamMutations.execute`，在该事务中提交 publication proof、业务可见状态、step 及 workflow terminal-success。Approval 集群采用另一个执行路径：pending→明确批准→私有 claim→atomic bound native ledger→固定 approved metadata handler；不得给普通 IAM 增加 bypass。原计划绑定的 cluster mode/revision 变化时停止下一步，不能在运行中把 direct 计划转为已批准计划或把 approval 计划当普通 direct。凭证发放/轮换/吊销始终要求明确审批，不因集群 direct 改为自动发 Key。

### 统一工作流

| 方法与路径 | 输入与语义 |
| --- | --- |
| GET `/clusters/:cid/workflows` | workspaceId、kind/state/mine/size/cursor；后端当前范围过滤 |
| GET `/clusters/:cid/workflows/:id` | workspaceId；safe immutable 计划/diff/依赖/审批与执行摘要 |
| POST `/.../:id/approve` | `{revision,planHash,reason?,confirmed:true,confirm_name,execute:boolean}`；单级决策追加、禁止自审；execute=true 在本次当前 console HTTP 会话同步执行 |
| POST `/.../:id/reject` | `{revision,planHash,reason}`；只追加决定，不能改计划 |
| POST `/.../:id/cancel` | `{revision,reason?}`；仅未执行、当前授权提交人/管理员 |
| POST `/.../:id/execute` | `{revision,planHash,confirmed:true,confirm_name}`；当前批准版本、当前真实会话及每步实际写权限；不由门户账号执行 |
| GET `/.../receipts/by-key/:key` | workspaceId；原始 console actor/cid/wid/key 的父执行回执 |
| GET `/.../:id/receipt` | workspaceId；当前 authorized 对象的安全执行状态，非任意 step/native 再执行入口 |

approve HTTP 的 metadata 提交成功后才能 mint 私有执行能力。没有执行的 approved 状态显示“待执行”。approval 响应丢失通过原始 key 安全回执核验，不重新批准或创建新计划。门户用户查看本人请求的父回执；不能用 request/workflow ID 调用 console execute。

### 安全 DTO 字段

```ts
type WorkflowState = 'pending' | 'approved' | 'executing' | 'succeeded'
  | 'partial' | 'uncertain' | 'failed' | 'rejected' | 'cancelled' | 'expired';
type WorkflowStepState = 'not_started' | 'running' | 'succeeded'
  | 'failed' | 'uncertain' | 'skipped_verified';

interface PublicationSummary {
  id: string; name: string; description: string | null; category: string | null;
  revision: number; documentRevision: number | null; status: 'published';
  authentication: { type: 'key-auth'; authorization: 'service-acl' };
}
interface ApplicationSummary {
  id: string; name: string; description: string | null; revision: number;
  state: 'active' | 'disabled' | 'archived'; createdAt: string; updatedAt: string;
}
interface GrantSummary {
  id: string; applicationId: string; publicationId: string; publicationName: string;
  state: 'pending' | 'active' | 'partial' | 'uncertain' | 'revoked'; revision: number;
  credentialGeneration: number; createdAt: string; currentWorkflowId: string | null;
}
interface CredentialSummary {
  id: string; grantId: string; generation: number; revision: number;
  state: 'pending' | 'active' | 'rotating' | 'revoked' | 'uncertain';
  key: '[REDACTED]'; createdAt: string; rotatedAt: string | null; revokedAt: string | null;
  capabilities: { reveal: boolean; rotate: boolean; revoke: boolean };
}
interface WorkflowSummary {
  id: string; kind: string; revision: number; planHash: string; state: WorkflowState;
  executionMode: 'direct' | 'approval'; approvalRequired: boolean;
  subject: { type: string; id: string; name: string }; createdAt: string; updatedAt: string;
  capabilities: { approve: boolean; reject: boolean; execute: boolean; cancel: boolean };
}
interface WorkflowReceipt {
  workflowId: string | null; executionId: string | null; revision: number | null;
  state: 'not_sent' | WorkflowState;
  steps: Array<{ id: string; ordinal: number; label: string; state: WorkflowStepState;
    operationId: string | null; remoteStarted: boolean; remoteCompleted: boolean;
    recycleEntryId: string | null; errorCode: string | null }>;
  propagation: 'not_started' | 'pending' | 'acknowledged';
}
```

Console WorkflowDetail 可增加已授权的脱敏 before/after diff、当前审批人显示名、计划到期和定位；门户版本只保留自身申请、业务标签/时间、状态和安全步骤名称，不返回其他用户、原生 config、密文计划或 Admin/上游地址。所有能力由当前服务器权限投影，缺失为 false；`planHash` 是安全的服务器 opaque HMAC，客户端回传仅 CAS，不是能力凭证。

## 5. 不可变计划、执行能力和恢复

每次计划版本包含 server kind/tenant/requester、subject revision、preallocated IDs、随机 Key、compiled wire payload、当前 before、依赖与权限范围、schema/version 证据、影响范围和补偿摘要。原始 secret 保存在 `workflow_versions.payload_secret`，AAD 包含 workflow ID/revision/cid/wid；`plan_hash` 是覆盖全部规范化结构和秘密值的服务器 HMAC，不用公开 SHA-256 作为可猜测秘密指纹。Root 已审定最多 16 logical steps/32 native write requests，解密计划和执行前定向快照各最多 2 MiB；文档上传的独立 3 MiB 上限不扩大计划上限。

### 门户申请编译的证明来源

正式 publication 发布执行成功时，真实 console 会话将已经批准并验证的 Service、受管 key-auth/ACL 插件、实际 schema、tags、FK、工作区/集群 revision、transportScope 和版本证据保存为加密 immutable publication proof，绑定 publication revision/HMAC。公开目录不返回该证明。开发者发放请求只从该证明模板和当前服务器 DB 的 developer/app/publication/grant 元数据编译待审批 plan，预生成一次 Consumer/ACL/key-auth UUID 与随机 Key；此路径不访问 Kong，不声称证明仍是当前 native 配置，也不宣称预分配 UUID 已得到原生不存在证明。

控制台 approve/execute 必须以真实当前 console actor 重新读取全部实际依赖、有效认证边界和待创建 ID 不存在，核验实际 Service/插件/schema/tags 与批准模板一致，完成定向快照后才生成私有能力。模板已经变化或不能证明安全时返回 stale/dependency 错误，不在原审批下改写 plan，也不把旧发布证明当当前 NativePolicy 授权。

若业务需要最新原生配置重新规划，只能由当前有权的 console 显式规划操作生成新计划版本；不得为门户开发者创建 fake console actor、借系统上下文 fresh planning，或从服务器缓存中选一个管理员身份。M6 默认采用已经正式发布的 proof 模板，避免新增这一规划入口。已发包/uncertain 的旧版本不能通过重新规划解除影响范围锁或生成第二把 Key。

不可变计划绑定 logical Mutation payload 与实际 native body 的独立 HMAC；DELETE 的确认/回收参数和空 native body 不能共用一个 fingerprint。metadata before/revision/payload 则使用独立 tuple。真实 session 与 permissionVersion 属于私有运行时 claim，不能嵌入持久计划并误当永久授权。私有步骤能力的建议 tuple：

```text
workflowId, executionId, planRevision, planHmac, stepId, ordinal,
clusterId, transportScope, workspaceId, workspaceRevision,
consoleActorId, consoleSessionId, currentPermissionVersion,
stepType(native|metadata), method, canonicalPath, entityType,
entityId, parentId?, credentialKind?, mutationPayloadHmac, beforeHmac,
nativeRequests[{method,canonicalPath,nativeType,nativeId,parentId?,bodyHmac}],
dependencyProofs, deleteRoot?, confirmed?, confirmName?
```

步骤还需分别保存 `permissionAction:'write'|'delete'` 与 `mutationAction:'create'|'update'|'delete'|'restore'`。前者用于实际权限，后者必须等于现有 MutationContext.action 并进入 logical HMAC/ledger/request hash；不能用 write 替代 create/update/restore，实际 native method/path 再独立绑定。

只有检查了实际已批准 SQL snapshot、唯一执行认领和当前会话后，服务器私有 factory 才 mint WeakMap/祖先上下文能力。body/query/header 中的 workflowId、planHash、approved 标志和普通 operation frame 都不构成权限。能力结束或父 HTTP 关闭即失效；每次发包前重新核验当前批准版本、实际 DB ledger/payload、before、actor/session/permissions、租约与 metrics fence。

EntityService 会注入工作区 tags、默认值和继承 FK，因此计划必须保存**实际最终 wire payload**。原生 body 的 HMAC 不能对未经规范化的门户请求计算，也不能因准备阶段结果变化而在审批之后悄悄重新签名。凭证/Consumer UUID 预分配；需要前步 ACK 的信息只允许预批准的精确 FK recipe 与可信 ACK/CAS，禁止客户端回填。

执行认领后先取得实际 existing before、创建 ID 不存在及依赖关系的最小定向加密快照，复核与计划一致后持久化 `snapshot_state=ready`。该快照不依赖尚未交付的 M8 全量快照模块，未 ready 不能 mint 执行能力。

NativeStep 顺序执行。Approval 路径由 Engine 先进入已验证的 private step，再调用 EntityService；EntityService 内部的 Mutation allocation 在同一事务建立 ledger/audit 并 CAS 绑定 `step.operation_id` 与 workflow execution/version/hash/step 外键。Engine 不在 EntityService 外再调用 Mutation.execute 或获取同一 physical lock，不能拿其他步骤的 ledger 授权。Direct 路径直接使用普通 EntityService/Mutation，不建立 approved step 能力，其 native `step.operation_id` 保持 NULL，安全原始回执只用于恢复核验。DELETE 仍由 EntityService 委托 Recycle 完整持久归档后执行；Workflow 私有能力不能直接 mint 归档能力。

M6 metadata step 由 Engine 固定注册 handler 在事务内核验 exact SQL before/revision/payload、记录 workflow step ledger/audit 并更新目标；它的 `operation_id=NULL`，不 mint native capability。不能为普通 `IamMutations` 增加 approval bypass，也不能把受批准步骤扩展为任意 SQL callback。M11 再按正式合同增加 IAM operation link。直接模式之外的 publication draft/settings/developer 状态更改也使用这个固定 metadata 计划模型。

最终 publication/grant/key-active metadata 与 execution/workflow terminal-success 在最后固定 handler 的同一事务提交；如实现保留分段终态，所有 public/reveal reader 必须额外核验实际 parent terminal-success。未知 COMMIT 不能在公开目录中显示新发布、提供新 proof 编译或领取新 Key。直接模式的纯 metadata 可复用现有 `IamMutations.execute` 的 Portal 固定 handler 与明确 row scope，HTTP 不能传任意 callback，也不能借同一个 handler 绕 approval。

审批计划失效条件包括开发者/应用/发布状态变化、实际 Service/FK/工作区变化、业务 tags 或 schema/version 变化、认证边界不安全、before 不同、账号/权限撤销、计划过期和未决操作。需要新版本及重新审批，不在旧批准下自动修正。

同一提交 key 绑定 developer/console actor、CID/WID、业务 payload 和版本。唯一执行 claim 绑定批准版本，每步 native idempotency key 由 server workflow/version/step 派生。成功的 step 不再发包；恢复时只有当前实际对象、依赖、desired fingerprint 和原账本完全一致才记 `skipped_verified`。running/uncertain/failed 不能自动重发或换 key 创建另一个对象。

M6 不提供后台执行器或自动 failed 重试；approved 未执行可由当前有权 console 会话 execute。执行中断后先显示 parent partial/uncertain 并锁住关联 grant，读取原始回执。未知 native 结果只能走已有平台受控 reconcile 与实际证据流程；补偿是另一明确批准计划，不能把隐藏 DELETE 当失败清理。

## 6. 发放、轮换、吊销及传播

| 业务 | 已批准步骤 | 成功条件 |
| --- | --- | --- |
| 发布 API | 计划 target/schema/SQL proof 预检 → Service ACL whitelist → Service key-auth → publication 公开版本 metadata；每个原生请求另经最终 prospective Boundary | 编译不扫描跨区认证图、不持久化“安全通过”布尔值；actual 插件回显/绑定/ACL group 及最终 hook 已验证，metadata terminal commit；无隐含全局插件 |
| 首次发放 | 当前开发者/app/publication/边界复核 → Consumer → ACL credential → key-auth credential → grant/credential metadata | 全部原生 ACK/readback 和业务 metadata 成功，Key 才可显式 reveal |
| 轮换 | 生成一次新 encrypted Key/UUID → 建立新 key-auth credential → 回收旧 credential → 切换 current generation metadata | 旧凭证已归档并删除、新凭证已验证、metadata terminal succeeded；新 Key 前面任何状态不可领取 |
| 吊销/禁用 Key | 实际旧凭证完整归档 → 原生 DELETE → credential/grant revoked metadata | 真实 native 删除和 metadata 成功；不使用不存在的 credential enabled 字段 |
| 撤回公开文档 | publication/page metadata 版本撤回 | 不隐式吊销既有 Key，不删除共享插件 |

Kong 1.5 无跨原生对象事务。轮换创建新凭证后删除旧凭证有短暂重叠，必须在计划/UI 明确；新 Key 在服务器加密计划内、未成功前不给开发者。若删除旧 Key 失败，新 Key 不能被领取，状态 partial/uncertain，旧 Key 不伪标 revoked。所谓 disable 是吊销凭证；重新 enable 需要重新申请/审批，不恢复一个已泄露或旧生成的 Key。

管理操作成功表示持久写入已确认，不代表所有 worker 缓存立刻传播。界面显示“配置生效中”，`propagation:'acknowledged'` 不声称代理凭证已经实测。自动化验收通过固定真实 Route 做 key-auth 请求和时间观测验证新 Key 可用、旧 Key 失效；不发送自选 URL，也不伪造即时撤销。生产需要立即阻断时应由独立网络/运维方案明确处理，不能把 DB metadata disabled 当网关认证已失效。

Reveal 独立重新查当前 Portal session/developer/app/grant/publication/credential generation，调用服务器持有的加密 Store，并记录秘密访问审计。响应 no-store、专用页面临时内存，不进入通用 QueryClient、URL、持久化恢复标识、日志/截图/事件。pending/partial/uncertain 或 publication 不活动时拒绝领取。普通管理者审批不因此获得门户 Key 的公开读取接口。

## 7. 数据库交接

Storage 使用 canonical `workflows/workflow_versions/workflow_approvals/workflow_steps/workflow_executions/workflow_events` 与 `portal_*` 表。约束和 CAS 在 SQL 008 中实现；加密服务和执行能力验证同一结构，不能允许 step 表与加密 plan 不一致。

| 表 | 必需业务字段/约束 |
| --- | --- |
| workflows | id/kind/cid/wid/subject/requester_type(console\|developer)/requester_id、revision/state/plan_hash、execution_mode/approval_required、idempotency_key/request_hmac、submitted/approved/executed actor、expires_at；原 actor+tenant+key 唯一，direct 计划不伪造 approved_by |
| workflow_versions | workflow_id/plan_revision、payload_secret/plan_hash、scope/subject revisions、step_count、created_at；版本 immutable，受批准版本不可覆盖 |
| workflow_approvals | version/hash、level=1、approver/decision/reason/request_id/time；append-only，禁止同一 approver 重复覆盖或自审 |
| workflow_executions | id/version/hash/actor/session/state/claim revision/request_id、started/completed；同批准版本唯一认领 |
| workflow_steps | version/step_id/ordinal/type、exact native parent/kind/id/path、payload/before HMAC、dependencies、state、operation_id/recycle_entry_id/remote flags；与 encrypted plan 逐项一致 |
| workflow_events | workflow/execution/step、actor_type/id、event/state/error_code/request_id/time；只追加，无秘密、无更新/删除 HTTP |
| portal_publications/revisions | cid/wid/service_id/name/category/state/document/revision、managed_acl_plugin_id/managed_key_auth_plugin_id/acl_group；活动 Service 唯一，draft/published revisions 分离 |
| portal_publication_proofs | cid/wid/publication_id/publication_revision、publication_proof_secret/publication_proof_hmac、workflow_id/workflow_execution_id、verified_at；独立 immutable 表，完整 published revision/execution FK；proof 与成功发布 metadata 原子插入，不修改已有草稿 revision |
| portal_applications | cid/wid/developer_id/name/description/revision/state；owner immutable、软归档、租户复合 FK |
| portal_application_grants | application_id/publication_id/cid/wid、consumer_id/acl_id/acl_group、state/revision/current_workflow_id/generation；pair unique，Consumer 不跨发布复用 |
| portal_credentials | grant/native_credential_id/kind=key-auth/generation/state、encrypted ref、workflow/version、timestamps/recycle_entry_id；active generation CAS，不公开保存 key 字段 |
| portal_content/revisions | cid/wid/slug/title/markdown/state/revision、批准版本；不允许后续 draft 改写已公开版本 |
| portal_operations | developer/cid/wid/key/request HMAC、state/receipt/error/audit refs；门户单独账本与恢复命名空间 |

Workflow version/approval/event 不提供物理删除或修改历史的接口。元数据软归档保持引用，删除 developer/app 前检查活动与未决 grant。Key 原始值既保存在 encrypted immutable plan 供审批执行，也用 CredentialStore 独立 AAD 保存供恢复；两者只能服务器私有读取，不能依靠公开 planHash 解密或导出。

## 8. 文档与内容安全

文档最大 3 MiB，JSON/YAML 规范化为 JSON；使用现有 yaml 2.9.1，禁 YAML alias/merge/custom tag、多 document 和外部 `$ref`。仅允许本文件 `#/...` JSON Pointer，递归深度≤32、解析节点≤50,000、操作≤2,000；循环可展示引用但不无限展开。拒绝 prototype 污染键、控制字符 URL、任意网络抓取和动态 JS。Schema/示例经统一秘密脱敏，不能导入 credentials/Authorization 的原文并发布。

从实际 Service/Route 生成的文档只包含已授权请求匹配和发布人审阅的公开入口；不会自动暴露 Service.host、Admin API 或内部 upstream URL。读取器没有默认 Try It Out，不能把文档中的任意 servers URL 交给 BFF 代理。

Markdown 禁原始 HTML；链接限定安全 HTTPS/受控站内路径，远程图片/脚本/iframe/SVG 执行拒绝。外观仅标题/描述/颜色/受控素材 ID，不支持任意 CSS/模板/HTML。公共发布内容仍与 CID/WID/版本绑定，不能通过旧缓存公开已撤回内容。

## 9. 实施与验收门禁

1. SQL 008、独立 Portal Auth 与 Workflow immutable/cas/append-only 验证；主体/租户/唯一执行/提交幂等/秘密 AAD 检查。
2. 完成 Portal 业务 compiler、单级决策、精确私有 capability、metadata ledger 和 Entities/Recycle 步骤；失效权限、plan/body/before/FK 篡改、假 workflowId 必须零原生发包。
3. 完成完整 Gateway auth-boundary guard，实际覆盖全局/Service/Route/Consumer overrides、删 ACL/禁用/恢复、partial issuance reservation 与未知/超预算 fail closed。
4. 独立门户文档/应用/申请/reveal、管理审核/发布/批准执行、原始父 key 恢复；partial/uncertain 不产生第二个 Key，不假成功。
5. Root 统一源码/迁移/构建门禁后由唯一部署器启动；Security 独占真实代理闭环，再 Front 浏览器和截图。

真实验证至少包括：门户身份不能访问 console；跨开发者/跨租户 app/request/secret IDOR 拒绝；未审核/停用不能申请/reveal；read-only 管理员不能写/approve；批准前原生不存在；审批模式保持不变而批准精确步骤可执行；应用 × 两 API 的 Key 跨 API 被拒绝；旧未托管 key-auth 边界必须整改后才可发布；后续 BFF 破坏 ACL 被阻止；批准之后权限/租约/依赖变化阻止下一包；响应丢失父回执、原 key 恢复及真实旧 Key 失效。

OpenAPI/YAML/Markdown 安全载荷、活动发布撤回/缓存、390px 基础响应式、完整审计与 append-only、私钥/API Key/密码运行时证据扫描均在门禁内。故障模拟、mock 与真实 Kong/浏览器证据分别标注；M6 通过前不把未实现的 M11 scheduler/quorum/snapshot UI 描述为交付能力。
