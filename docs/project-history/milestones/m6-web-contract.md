# M6 门户与管理侧 Web 合同

状态：M6 产品源码已实施，尚待统一部署、真实 HTTP / 浏览器与手工验收。M5 已提交，Root 已发出正式实施授权。Root 已确认按 CID/WID 分离开发者账号和公开租户入口；Storage/Kong 已冻结认证、公开业务和公共工作流合同。本文与 [存储/认证合同](m6-storage-contract.md)、[业务合同](m6-business-contract.md) 对齐。实现期间若 DTO 变化，先通知接口所有者；这些设计不代表已运行功能。

## 两个独立入口

| 入口 | 运行位置 | 身份与接口 | 内容 |
| --- | --- | --- | --- |
| KongPilot | 现有 `apps/console-web`，端口 8080 | 控制台用户、现有 Cookie/CSRF；管理侧接口 | 开发者审核、应用、API/文档、页面/外观、凭证工单与执行记录 |
| Developer Portal | 新增 `apps/portal-web`，端口 8082 | 独立开发者、门户 Cookie/CSRF；仅门户接口 | 已发布 API 和页面、注册/登录、自己的应用、申请记录、授权查看密钥 |

门户 Nginx 只代理其门户 API 前缀，不提供任意代理、控制台 `/clusters`、IAM、管理 Swagger、内部采集监听或 Admin API 入口。BFF 继续使用同一 Nest 服务，但门户守卫只接受门户 issuer/audience、签名密钥和会话；控制台守卫不接受门户凭证。端口不同不足以隔离同一主机 Cookie，必须使用不同 Cookie 名称和路径，并在服务端严格校验身份体系。

开发者账号、会话、应用和凭证属于一个明确的 CID/WID；不同租户分别注册，不复用另一租户的账号身份。注册成功只显示“申请已提交，等待管理员审核”。pending/disabled/rejected 不能登录；管理员批准为 active 后才可登录并申请密钥。已公开文档仍可匿名阅读。应用和凭证的所有权始终由当前数据库开发者 ID 推导，客户端不提交 `owner_id`、控制台角色、Consumer ID、原生插件 JSON 或保留工作区标签作为权限。

门户入口仅从 `GET /api/v1/portal/tenants?size&cursor` 和 `GET /api/v1/portal/tenants/:slug` 解析当前已发布租户。详情为 `{slug,name,clusterId,workspaceId,branding,registrationEnabled}`，仅来源于活动且公开的 portal_settings；未发布、停用、不存在统一返回 `PORTAL_NOT_AVAILABLE`。不能调用原生集群或全部工作区接口获取租户。所有认证 body 和私有业务请求显式携带解析出的 CID/WID，私有缓存键同时包含租户、开发者和会话版本。切换租户先退出原门户会话、清空私有查询/密钥/未提交秘密，再重新登录该租户；公开页面内容也按租户分别缓存。

## 目录与依赖

拟定目录：

```text
apps/portal-web/
  index.html / vite.config.ts / tsconfig.json / package.json
  src/
    api/       portal-client、DTO、幂等键与恢复标识
    app/       PortalAuthContext、QueryClient、路由和 i18n
    layouts/   PortalLayout（目录导航、搜索、个人入口）
    features/  Catalog、ApiDocument、MarkdownPage、Login、Register
               Applications、ApplicationDetail、CredentialRequests、Profile
    components/  OpenApiReader、MarkdownReader、CursorPagination
    locales/zh-CN/common.json / styles.css
apps/console-web/src/features/
  PortalAdminPage、PortalDevelopers、PortalApplications
  PortalApis、PortalPages、PortalAppearance、PortalApprovals
packages/contracts/src/  公共无秘密 DTO（最终文件所有权由 Root 分配）
```

复用现有锁定版本：React/ReactDOM 18.3.1、Ant Design 5.27.6、icons 5.6.1、TanStack Query 5.90.5、React Router 7.18.4、i18next 25.6.0、react-i18next 16.1.4、react-markdown 10.1.0；开发依赖 TypeScript 5.7.3、Vite 6.4.4、plugin-react 4.7.0 及现有 React 类型。门户不依赖 ECharts、Swagger UI、HTML 执行器或额外 YAML 解析包。BFF 使用已安装 yaml 2.9.1，将受限 YAML/JSON 上传归一化为 JSON。

Root 负责新增 workspace manifest、lockfile 与根 build/typecheck/dev 脚本。Web 所有者不执行 root npm install。Vite 门户开发端口 8082；Compose 对外 8082 映射门户 Nginx 内部 8080。构建输出复用现有仅 dist 目录的 0755/0644 权限修正。公开门户与管理站分别构建，不导入控制台 AuthContext、全局 client 或当前选择器状态。

## 页面与可演示流程

门户使用浅色内容区、独立品牌页头与清晰的 API 目录。默认中文，基础移动端可用；API 标签、分类、搜索和应用状态通过真实响应呈现。分类过滤使用 publications 的 category 查询，不调用未提供的 categories 端点。

| 门户路由 | 页面行为 |
| --- | --- |
| `/`、`/apis` | 已发布 API 目录；服务端分类/搜索与 size/cursor 上下页，不下载全量目录 |
| `/apis/:id` | 摘要、版本、操作列表、参数/请求/响应、安全要求；申请入口只选自己的活动应用 |
| `/pages/:slug` | 已发布 Markdown 页面；未发布/已删除页面返回真实不可用状态 |
| `/register`、`/login` | 独立注册/登录；密码与失败锁定由门户后端策略权威校验 |
| `/applications`、`/applications/:id` | 仅本人应用、申请/凭证状态；创建/修改、软删除恢复、轮换/吊销 |
| `/requests`、`/requests/:id` | 本人申请、审批与执行摘要、未知状态核验；不包含控制台账号或原生秘密 |
| `/profile` | 本人资料、密码、账号；M6 的本人页面只实施合同提供的 displayName 与密码功能，独立会话列表未发布前不显示虚构列表 |

管理站新增 `/portal`，按开发者、应用、API、页面、外观、审批分标签；当前集群和规范工作区作用于该租户对象。开发者审核、应用和外观记录都保留其真实 CID/WID，不能因同名账号或全局导航而修改另一租户的记录；每个实际操作仍核验完整四维授权行。

审批详情提供不可变计划的脱敏 diff、影响范围、依赖步骤、校验警告、执行/回滚摘要、原始请求与修订号。批准和拒绝有原因；批准执行前输入申请或应用名称二次确认。审批人默认不能自审。页面明确区分“待审批”“已批准待执行”“执行中”“成功”“失败”“结果待核验”，不把批准当作凭证已经可用。

## 已冻结 HTTP 操作

所有路径以 `/api/v1` 为前缀。门户仅调用 `/portal`；控制台管理业务使用 `/clusters/:cid/portal` 并显式 `workspaceId`；统一工作流使用 `/clusters/:cid/workflows`。管理站不直接发送原生 Kong 路径。门户所有公开业务查询和私有请求携带租户引导的 CID/WID；私有范围还必须匹配当前会话。

| 门户方法与路径 | 输入/响应语义 |
| --- | --- |
| GET `/portal/tenants`、`/tenants/:slug` | 已发布租户安全描述、分页；未知/未发布同一安全错误 |
| GET `/portal/publications`、`/publications/:id` | clusterId/workspaceId、size/cursor/search/category；仅已发布 PublicationSummary |
| GET `/portal/publications/:id/document` | clusterId/workspaceId；`{publicationId,revision,document}`，归一化脱敏 JSON |
| GET `/portal/pages`、`/pages/:slug` | clusterId/workspaceId、分页或 slug；已发布摘要/Markdown 修订 |
| GET/POST `/portal/applications`、GET/PATCH `/applications/:id` | 创建 `{clusterId,workspaceId,name,description?}`；修改增加 revision；只操作本人应用 |
| DELETE `/portal/applications/:id`、POST `/applications/:id/restore` | `{clusterId,workspaceId,revision,confirmed:true,confirm_name}`；软归档/恢复，没有活动或未决 grant 才能删除 |
| GET/POST `/portal/requests`、GET `/requests/:id` | 申请 `{clusterId,workspaceId,applicationId,publicationId,reason?}`；服务端创建 immutable 发放计划，返回安全 WorkflowSummary |
| POST `/portal/requests/:id/cancel` | `{clusterId,workspaceId,revision}`；只撤销本人尚未开始的请求 |
| GET `/portal/applications/:id/grants` | 当前范围、size/cursor；本人 GrantSummary |
| GET `/portal/applications/:appId/grants/:grantId/credentials` | 当前范围、size/cursor；脱敏 CredentialSummary |
| POST `.../credentials/:credentialId/reveal` | `{clusterId,workspaceId,revision}`；`{credentialId,key,generation}`，显式 no-store 秘密响应；客户端另设最多 60 秒显示期限 |
| POST `.../credentials/:credentialId/rotate`、`/revoke` | `{clusterId,workspaceId,revision,confirmed:true,confirm_name,reason?,retireConsumer?}`；确认名为 `轮换 UUID` / `吊销 UUID`，返回待审批工作流，不直接写 Kong |
| GET `/portal/operations/by-key/:key` | 当前范围；本人安全父操作回执，不转成 native capability |

| 管理侧方法与路径 | 输入/响应语义 |
| --- | --- |
| GET/POST/PATCH `/clusters/:cid/portal/settings` | 当前 WID、revision CAS、白名单 branding 与公开 proxy origin；审批模式返回 pending 工作流 |
| GET `/.../developers`、`/developers/:id` | 当前租户安全投影、分页/状态/搜索；无密码或 token |
| POST `/.../developers/:id/review` | revision、status=active/disabled/rejected、reason、confirmed、confirm_name；停用前先完成已发放授权吊销，恢复账号不恢复旧 Key |
| GET `/.../applications`、`/applications/:id` | 当前 authorized 应用与 grant/请求关系，无 raw key |
| GET/POST `/.../publications`、GET/PATCH `/publications/:id` | `{slug,serviceId,name,description?,category?,document,revision?}` 草稿；managed plugin ID、ACL group 由服务端生成 |
| POST `/.../publications/:id/document` | revision +受限 JSON/YAML 文档；单独 POST `/document/generate` 生成，不能执行外部引用 |
| POST `/.../publications/:id/publish`、`/unpublish` | revision、confirmed、confirm_name；publish 的显式 ACL→key-auth→metadata 计划，unpublish 不隐式吊销旧 key |
| GET/POST `/.../pages`、GET/PATCH/DELETE `/pages/:id` | Markdown 草稿/CAS/确认软删除；待审批草稿不覆盖原已发布版本 |
| POST `/.../pages/:id/publish`、`/unpublish` | revision、confirmed、confirm_name；单独发布/撤回计划 |
| GET `/.../requests` | 当前 authorized 请求摘要，可导航到公共 workflows 详情 |
| GET `/clusters/:cid/workflows`、`/workflows/:id` | workspaceId、state/view/size/cursor；安全 immutable 计划与执行摘要 |
| POST `/.../workflows/:id/approve` | `{revision,planHash,reason?,confirmed:true,confirm_name,execute:boolean}`；execute=true 本次真实 console 会话同步执行 |
| POST `/.../workflows/:id/reject` | `{revision,planHash,reason?,confirmed:true,confirm_name}`；决定只追加，计划不修改 |
| POST `/.../workflows/:id/cancel` | `{revision,confirmed:true,confirm_name}`；当前授权、尚未执行；原键持久撤销回执 |
| POST `/.../workflows/:id/execute` | `{revision,planHash,confirmed:true,confirm_name}`；当前批准版本与当前实际原生权限 |
| GET `/.../workflows/receipts/by-key/:key`、`/workflows/:id/receipt` | 原账号/cid/wid/key 或当前 authorized 对象的安全父回执 |

直接模式的控制台纯元数据变更复用 IAM ledger；publication/page 的复合变更也先持久化 immutable 计划和父回执，经当前确认账号的正常原生权限执行，不增加自审或多余审批。WorkflowSummary 返回 `executionMode:'direct'|'approval'`、`approvalRequired:boolean`；direct 的审批按钮为 false、没有 approval rows，页面展示真实步骤和回执。直接步骤的 `safeResult.nativeOperationId` 只是安全关联，不是批准能力。

审批模式返回 `{state:'pending',workflowId,revision}` 并导航到公共工作流，不同时修改业务目标。issue/rotate/revoke 在所有集群始终显式审批。门户可以提交请求并读取自己的安全状态，不能调用 console approve/execute。

标准列表为 `{items,nextCursor,size,total:null}`。分页使用 SQL 或业务签名游标，不支持跳页时仅提供上/下一页与已访问页缓存；禁止自行遍历全部列表获得计数。公开统计若存在必须由服务端提供，未知不填 0。

标准成功响应沿用 `{data,meta:{requestId}}`；失败沿用 `{error:{code,message,fields?,operationId?,state?},meta:{requestId}}`。复用相同的类型与外观不意味着复用控制台身份状态。

## 登录、缓存与未决写入

已确认门户 Cookie 为 `kongos_portal_access`、`kongos_portal_refresh`、`kongos_portal_csrf`，三个 Path 都是 `/api/v1/portal`；签名使用独立 `PORTAL_SECRET`，issuer/audience 为 `kongos-portal`。密码策略、刷新 family、独立会话表由 Storage/auth 实施。浏览器仅保留当前门户 CSRF 在内存；不使用 localStorage 保存 bearer、Cookie、API Key 或密码。所有私有请求使用同源 fetch；登录完成必须校验 me 与登录开发者 ID 一致，然后同步发布门户 actor，再更新 React 状态。

| 已确认认证路由 | 请求/响应 |
| --- | --- |
| GET `/portal/auth/csrf` | clusterId/workspaceId；`{csrfToken,expiresAt}`，注册/登录前获取，用于防登录 CSRF |
| POST `/portal/auth/register` | `{clusterId,workspaceId,username,email,displayName,password}`，202 `{status:'pending'}`；不返回已有账户身份，不自动登录 |
| POST `/portal/auth/login` | `{clusterId,workspaceId,username,password}`，返回 `{developer,csrfToken,expiresAt}`，不返回原始 JWT |
| POST `/portal/auth/refresh`、`/logout` | `{clusterId,workspaceId}`；使用门户 Cookie、`X-Portal-CSRF` 和同源 Origin；refresh 返回 `{developer,csrfToken,expiresAt}`，logout 返回 `{loggedOut:true}` |
| GET `/portal/auth/me` | clusterId/workspaceId；直接 PortalDeveloperView；仅登录返回的同一开发者和租户可发布为当前身份 |
| PATCH `/portal/auth/me` | `{clusterId,workspaceId,revision,displayName}`，本人资料 CAS |
| POST `/portal/auth/password` | `{clusterId,workspaceId,revision,currentPassword,newPassword,confirmed:true}`；成功 `{changed:true,reauthenticate:true,operationId}` 后退出相关会话 |

注册/登录以及 Cookie 认证的写入、刷新、退出均发送 `X-Portal-CSRF`；同源 Origin 由浏览器发送，不能把客户端声明的 Origin 当作服务端授权。门户持久化操作查询 `/portal/operations/by-key/:key`，控制台工作流查询 `/clusters/:cid/workflows/receipts/by-key/:key?workspaceId=原WID`，绝不回退到控制台 IAM/native 子步骤回执证明父流程完成。

请求开始时捕获 developer ID、会话/权限版本、应用或申请 ID；登录切换、退出和降权清除私有 QueryClient 缓存并中止旧请求。401 单次刷新必须阻止旧开发者请求在新会话下重放；已有刷新先排空，登录过渡期间禁止旧请求启动新刷新。原账号迟到的 200/401 不能恢复旧身份或结束新账号会话。

配置写入发送一次幂等键。连接中断、502/504 或不可读成功响应保留原键、原账号、应用/申请/工作流及原范围，只读核验后才解除写入阻止。门户恢复标识使用独立 sessionStorage 键和白名单；不保存请求正文、配置、密钥、文档、Cookie 或 CSRF。过期/切换账号清理；刷新浏览器和页面跳转不会重发。

复合申请执行不能以单个 Consumer/凭证步骤成功证明全流程完成，必须使用统一工作流父回执。WorkflowReceipt 的步骤标记为 camelCase `remoteStarted`/`remoteCompleted`，state 包含 not_sent/pending/approved/executing/succeeded/partial/uncertain/failed/rejected/cancelled/expired；步骤可为 not_started/running/succeeded/failed/uncertain/skipped_verified。执行完成证明同时核验当前计划版本、父终态和步骤证据，不能套用现有 native `remote_completed` 单字段判断。partial/uncertain 时保留原计划和原键，不自动创建第二把密钥、不用新的请求或新的审批绕过未决范围。轮换/吊销同样走计划、审计和归档，不用不存在的 native credential enabled 字段。

## 密钥呈现

应用详情默认只显示脱敏标识、状态、创建/轮换时间、API 名称与安全摘要。每个 application × publication 使用独立受控 Consumer，publication 对应单个 Service，认证要求明确的 key-auth 和 ACL 插件；不能把应用的一把 key 当作其他发布 API 的访问授权。用户点击“查看 API Key”才发起独立的当前所有者授权请求；服务器再次核验开发者、应用、API/审批及凭证状态，记录秘密访问审计。

明文只在专用查看面板的临时内存中出现；不进入 TanStack Query、URL、路由 state、通用错误提示、通知、diff、工作流列表、JSON 预览、日志或缓存。关闭面板、退出、切换应用、页面隐藏、权限变化、轮换或吊销时清空；临时查看到期后重新进行显式授权查看。复制由用户显式操作，成功提示不含 key。普通截图和自动化报告始终关闭此面板；真实代理认证使用仓库外 0600 临时引用。

轮换与停用 / 吊销输入 `轮换 UUID` / `吊销 UUID` 二次确认，展示原凭证将失效及审批模式行为。新 key 只在服务端确认执行成功后可授权领取；未知执行状态不展示新 key，也不把旧 key 标记为已吊销。Kong 传播仍属 eventual consistency，界面显示“配置生效中”，验收以真实代理认证结果和观测耗时判断。

## 文档安全与渲染合同

OpenAPI 阅读器仅渲染白名单字段：info、tags、paths、operation、parameters、requestBody、responses、schema 和 security；不提供执行远端请求、任意 iframe、动态 JavaScript 或插件入口。OpenAPI 3.0/3.1 与 Swagger 2.0 的常见字段按已发布的规范化版本展示；不认识的字段显示“暂不支持”，不默默执行。

只解析文档内 `#/...` JSON Pointer；外部、相对文件、HTTP(S)、data、file 引用均拒绝。BFF 导入拒绝外部引用，阅读器也校验。解析有引用深度、展开节点数、文档字节数、操作数上限和循环检测；循环及超预算显示受限提示，不能阻塞浏览器。`__proto__`/constructor/prototype 不参与属性遍历或对象合并。服务端提供已发布文档摘要/版本，前端按 revision 缓存；过期发布内容不会通过旧权限缓存继续显示。

Markdown 用 react-markdown `skipHtml`，不启用 raw HTML 插件、不使用 dangerouslySetInnerHTML。链接只允许安全 HTTPS 或受控站内相对路径，外部打开使用 noopener/noreferrer；拒绝 javascript/data/file 协议、协议相对 URL、控制字符和用户信息 URL。图片只接受受控同源静态素材路径，拒绝远程图片追踪和 SVG/HTML 执行载荷；M6 合同没有自定义素材上传端点，因此不添加上传按钮。文档中的示例先经过服务器秘密分类脱敏；客户端再次防御性处理已知秘密字段，不能把导入文档当作可信配置。

外观使用 `logoText`、`welcomeText` 和白名单 `primaryColor`；不接受任意 CSS、HTML、脚本、外部字体 URL 或模板执行。服务器 CSP 与门户 Nginx 保留 `script-src 'self'`、`connect-src 'self'`、object-src none、frame-ancestors none、nosniff、referrer 与权限头。

## 权限与 UI 操作

管理侧使用现有 `portal`、`developers`、`applications`、`workflows` 四维完整授权行；写入、删除、审批分别校验，不能把不同授权行的 CID/WID/tag/entity 部分拼接。内容和审批列表由服务端完成范围过滤，按钮能力由服务端当前对象投影确定，缺失能力为 false。任意 native Consumer/Plugin/credential 步骤保留现有实际对象权限、业务标签、工作区、实体白名单、物理锁与 before-send 检查。

公开门户只暴露显式发布的业务内容，不暴露 Admin 地址、真实 native configuration、工作区私有文档、秘密、内部错误堆栈或控制台用户清单。对外 API 标题和代理地址由发布人审阅；不能直接把 Service.host/Admin URL 作为开发者可用入口。门户账号访问控制台、跨开发者应用/申请/密钥、伪造 workflow ID、尚未批准/撤销/过期计划均拒绝。

## 验证计划与稳定选择器

实现时为页面入口、申请记录、文档操作、恢复核验提供稳定 testid；表单使用清晰的中文 aria-label。建议标识 `portal-catalog`、`portal-document`、`portal-openapi-operation-METHOD-PATHHASH`、`portal-markdown`、`portal-application-ID`、`portal-request-ID`、`portal-credential-masked`、`portal-workflow-state`，不把明文 key 放入 DOM 属性或 testid。

聚焦单测验证安全 JSON Pointer/循环/预算、Markdown 链接/HTML/图片、文档载荷秘密脱敏、门户 actor 切换与迟到响应、原键复合回执、密钥关闭/隐藏清理和四维按钮边界。集成验证门户与控制台身份/CSRF 隔离、列表游标/所有权、revision CAS 和只追加审计。浏览器真实闭环覆盖注册审核→创建应用→申请→另一管理员审批执行→已批准凭证脱敏可见→代理验证→轮换→旧 key 拒绝→吊销→新 key 拒绝，以及申请响应丢失不会产生第二把 key。

真实 OpenAPI/Markdown、手机 390px、未审核/停用账号、只读管理员、跨开发者 IDOR、安全载荷与审批未知状态都要有可复核证据。角色不同必须使用真实账号；HTTP 伪 JWT/原生 Admin 直连失败由 Security 检查。所有成功写入验证 requestId 审计，截图不含秘密；完整运行时秘密引用扫描完成后删除私有引用，才进入 M6 门禁提交。


## 已实施源码与实际接口补充

独立门户位于 `apps/portal-web`，控制台管理位于 `PortalAdminPage.tsx` / `WorkflowsPage.tsx`。门户只有 `/api/v1/portal` BFF 请求，不读取控制台集群注册接口或 Kong Admin API。公开门户选择只使用已发布租户目录。认证 CSRF、Cookie、账号和回执均独立；原操作标识只能保存 UUID、原始账号和租户、时间与状态，不保存密码或请求配置。

管理端开发者审核实际使用 `POST /clusters/:cid/portal/developers/:id/review`，模块为 `developers`；应用元数据为 `applications`；发布、内容和设置为 `portal`。共同审批入口为 `/workflows`。门户注册成功仅显示待审核，审核通过后才能登录。工作区共享元数据按钮需要完整工作区 / 全局授权；发布行使用服务端对象能力。角色白名单的 Portal / Workflows 支持 Services 和 Routes，通过最小身份端点选择，不要求浏览器读取原生配置。

管理员上传或生成文档后仍需单独确认发布。生成接口为 `POST publications/:id/document/generate {revision}`，不接受前端原生配置或自由 URL。Markdown 不执行 HTML，仅受控站内导航和 HTTPS 文本链接；图片限定静态同源位图。OpenAPI 拒绝外部引用与原型键，展开预算限制递归和循环引用；不提供向文档地址发送请求的功能。

凭证轮换 / 吊销确认名为 `轮换 <credentialUUID>` / `吊销 <credentialUUID>`。吊销可显式选中 `retireConsumer:true`，由不可变计划额外将所属授权 Consumer / ACL 移入回收站。默认仅吊销 Key。查看密钥只在单独 POST reveal 后保留于面板内存，最多显示 60 秒；关闭、页面隐藏、账号 / 租户切换、组件卸载和新的查看请求会撤销旧响应，面板期限不代表 API Key 失效时间。

控制台中断写入按 Portal / Workflow 父操作路由核验原键。待审批 SQL 提交或纯审批决定只有服务端明确完成证明才解除原写阻止；直接执行、部分完成或不确定子步骤不能用审批标记替代完整执行证明。不会自动重试、审批或继续执行。自助密码变更中断时清除旧会话视图，保留安全原操作标识，用户用新密码重新登录后核验。

本阶段源码测试包含独立门户请求/CSRF/账号租户竞争、同键单次刷新、未知写不重发、实际 PortalProvider 延迟响应、文档安全和父回执证明。运行时验收证据将在统一部署后补充；源码通过不代表已完成商用验收。

停用 / 吊销沿用同一 `/revoke` 审批归档路径，Kong 1.5 的 key-auth 凭证不存在 enabled 字段。完整执行后旧 Key 失效，恢复访问必须重新申请并审批全新 Key，不恢复旧凭证。同一应用与发布 API 可以在历史授权已吊销后重新申请；界面不因存在历史 grant 禁用申请入口。应用 / 开发者停用前须完成已发放授权的吊销；已取消或驳回且被后端证明从未执行的预留申请可以安全释放。
