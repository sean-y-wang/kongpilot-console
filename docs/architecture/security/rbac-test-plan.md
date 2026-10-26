# RBAC 与审批攻击回归计划

核对日期：2026-10-10。本文是 M4 / M11 的实现约束与待执行测试计划，不能作为已经通过权限验收的证据。当前 M1 的 AuthorizationService 为仅 super-admin 可访问的保守基线；M0 / M1 已有测试覆盖认证、CSRF、跨集群数据源 IDOR、跨 Consumer 凭证 IDOR、跨 Upstream Target IDOR、代理路径白名单及归档完整性，但尚未验证完整四维 RBAC。

## 1. Konga CVE 的准确对应

| 漏洞 | 已核实的攻击条件和行为 | KongOS 对应回归 |
| --- | --- | --- |
| CVE-2021-42192 | Konga 0.14.9；攻击者已有普通用户登录凭证。公开 PoC 先登录，再对自身 `/api/user/{id}` 发送 PUT，将 `admin` 置为字符串 `true`，同时提交本人的密码相关字段。问题是用户更新接口允许低权限用户修改特权字段，从而取得管理员权限。 | 普通用户更新自己的资料、密码或注册信息时，不能写入 superAdmin、角色、权限、scope、状态等受控字段；嵌套对象、字符串布尔值和未知字段也不得绕过 DTO。随后重新登录，权限仍不变。 |
| CVE-2023-26987 | Konga 0.14.9；原始报告使用已登录普通用户的 token 枚举账号，再修改另一个管理员的密码，最终登录管理员账号。CVE 描述称 crafted POST；原始报告的可读文本未列出完整请求路径，因此这里不编造精确路径。 | 账号枚举、跨用户 ID 修改密码、重置密码、切换目标 ID、角色分配与账号状态变更均检查后端权限；低权限账户不能修改其他用户或管理员凭证，目标的密码和会话保持原状。 |

两者的 NVD CVSS 都标明 PR:L，即攻击需要已有低权限。它们是 **Konga 控制台账号访问控制**问题，并非 Kong 1.5 Admin API 的原生接口漏洞。连接注册、SSRF、网关实体 IDOR 是相关的独立攻击面，不能仅凭这类测试通过就声称已经覆盖上述 CVE 的攻击机制。已核实的版本为 0.14.9；不推断其他版本的影响范围。

来源：[CVE-2021-42192 NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-42192)、[研究者公告](https://payatu.com/advisory/privilege-escalation-in-konga-v0-14-9/)、[公开 PoC 源码](https://github.com/whokilleddb/Konga-Privilege-Escalation-Exploit/blob/main/exploit.py)、[CVE-2023-26987 NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-26987)、[Red Team Brasil 原始报告](https://docs.google.com/document/d/14DYoZfKN__As8gBXMFae7wChKJXpmbuUdMn2Gf803Lw)。

参考来源的局限：2021 年原始 Google 文档在核对时返回 410，2023 年参考的 GitHub 模板仓库返回 404。CVE-2021-42192 参考列表中的 [d615352 提交](https://github.com/pantsel/konga/commit/d61535277aced18b5be0313ab2d124f60f649978) 实际修改 Consumer ACL 分页，不能把它当作该权限漏洞的安全修复证明。公开 PoC 只用于理解攻击机制，不在第三方系统执行。

## 2. 权限判定约束

权限 grant 必须作为完整四元组计算：`module × operation × scope_type × scope_value`，并关联集群授权。可合并多个完整 grant 的允许结果，不得从不同 grant 各取一维拼出新权限。`write` 与 `delete` / `approve` / `secrets.read` 是独立权限；自定义角色不能因具有 write 就获得删除、审批或秘密查看权限。

工作区是所有实体读写的上下文约束；`tag_group` 授权标签集合采用 OR，与指定工作区采用 AND。实体的真实 tags 与授权集合无交集时拒绝；不能把工作区条件或用户提供的 tags 当作权限的替代。Kong 查询不支持任意布尔表达式，因此服务端通过原生过滤、逐实体授权和有界续页完成组合逻辑。读取投影索引不能代替读取真实对象和重新授权。

继承规则按以下边界测试：

- Route 的授权可推出它所关联 Service 的必要只读权限，不推出 Service 写权限、其他 Routes、证书或 secrets 权限。
- Service 的 write / delete 可推出其 Routes 与绑定 Plugins 的对应操作。workspace 范围要求目标处于同一工作区；entity 范围可沿授权 Service ID 的真实父子关系推出；tag_group 范围仍要求目标自身 tags 与授权业务标签有交集。
- 组合绑定 Plugin 的每个非空绑定对象都要满足当前操作所需的权限，而且工作区一致；仅有其中一个 Service 的 write 不能控制另一工作区 Consumer 绑定的 Plugin。
- 单独的 Plugin entity grant 不能通过改绑、去掉绑定或修改保留 tags 变成全局 Plugin 权限。共享依赖的秘密不随父子关系授权。
- 身份权限的撤销、用户停用和团队移除对后续 API / 代理请求生效；JWT 中的旧角色或 Redis 中的旧缓存不能继续授权。

Route 推导的 Service 必要读取是显式关系授权。测试必须证明它仅覆盖真实关联 Service 的公开配置，不变成 Service 模块的无范围读取。若回收预检需要读取额外共享依赖而用户没有相应权限，必须在任何 Kong 写入之前拒绝，不能静默扩大 grant。

## 3. 测试数据与判定方法

固定准备两个真实注册集群 C1 / C2，两个工作区 pay / ops，以及默认工作区。Kong 物理标签统一由版本适配层编码，测试业务断言使用逻辑 `workspace:pay`、`team:pay`、`team:shared`、`team:ops`。保留一个同 ID / 同名称但属于其他集群的对象，证明集群条件不可省略。

C1/pay 下准备 Service S-pay、两个 Routes R-pay 与 R-shared，以及另一个 Service S-private 的 Route R-private。业务 tags 分别覆盖 pay、shared、ops、空集合，包含未打标历史实体和外部建立的冲突工作区标签。准备全局 Plugin、Service Plugin、Route Plugin、Consumer Plugin、合法的同区组合 Plugin，以及一条外部建立的跨区组合 Plugin。准备两个 Consumer，各含六种凭证；证书、Target、快照、回收站和变更回执均有可见和不可见样本。

至少使用以下独立账号：super-admin、全局 read-only、pay 工作区管理员、pay 工作区 read-only、pay/shared tag_group 读者、pay tag_group 写者、仅 R-pay entity 读者、仅 S-pay entity 写者、具有 secrets.read 的受限读者，以及提交人、两位审批人与无审批权限的普通用户。所有测试密码和凭证随机生成，证据只记录布尔断言、状态码、脱敏 ID 与请求 ID。

每个拒绝测试同时检查三个结果：HTTP 状态符合约定；没有发出未授权 Kong 写入；目标状态和凭证有效性没有改变。实体无权限返回 403，错误父资源或不存在资源采用 404；不能把未授权对象内容放在错误中。真实 Kong、真实 BFF 与浏览器回归分开标注；合成故障或 policy spy 的单测不冒充真实执行证据。

## 4. M4 高价值测试矩阵

优先级 P0 为阻塞验收，P1 为补充回归。API 路径以现有 M1 接口为基础；未来用户 / 角色接口应按最终 Swagger 注册路径执行，不能为了通过测试添加隐藏绕过路由。

### 4.1 账号和权限管理

| ID | 优先级 | 攻击或操作 | 预期 |
| --- | --- | --- | --- |
| A01 | P0 | 未登录调用任一非 Public API，包括 schema、插件市场、详情、关系、回执、回收站、用户与审批接口 | 401；未发出 Kong 请求或权限管理写入 |
| A02 | P0 | 普通用户更新自身资料，同时注入 `superAdmin/admin/roles/permissions/scope/userId/status` | 403 或严格 DTO 的 400；特权字段不变；重新登录仍为原权限 |
| A03 | P0 | A02 的嵌套、数组、字符串 `"true"`、大小写或属性名别名变体，以及 `__proto__/constructor/prototype` | 不能 mass assignment 或改变原型；无权限提升 |
| A04 | P0 | 普通用户以其他账号 ID 修改密码、重置密码、绑定 LDAP/OIDC 身份或停用账号 | 403；目标原密码仍可登录；原会话状态不被未授权请求改变 |
| A05 | P0 | 有自助改密权限但无用户管理权限，调用批量用户更新 / 管理员重置入口 | 403；不能借不同路由绕过 A04 |
| A06 | P0 | 自助改密缺少原密码 / 再认证，或混入他人的 userId | 拒绝；合法改密后旧 refresh 会话按策略撤销，审计无明文密码 |
| A07 | P0 | 工作区管理员给自己 / 他人分配全局 admin 或跨区角色，克隆高权限角色后绑定 | 403；克隆与编辑角色同样受授权上限约束 |
| A08 | P0 | 编辑团队成员或 IdP group→role 映射，把自己加入高权限角色 | 用户 / 团队 / 映射管理权限均独立校验，不能自助提升 |
| A09 | P0 | 旧 JWT 在角色撤销、用户停用、团队移除、session revoke 后重放 | 后续请求 403 或 401；无需等待 JWT 自然过期 |
| A10 | P0 | 用户资料或登录响应提交 actorId / permissions / superAdmin，自称另一个调用者 | 服务端身份只来自已验证 session；忽略或拒绝客户端身份字段 |
| A11 | P1 | 用户列表按姓名搜索、排序、导出；分页游标混用另一个账号 | 只返回授权字段和账号；不得泄露 bcrypt hash、会话或他人密码恢复材料 |
| A12 | P1 | LDAP/OIDC 同名普通身份尝试自动关联本地管理员，伪造组、issuer、audience、nonce/state | 不能仅按用户名关联高权限账号；SSO 校验失败不建立 session |

### 4.2 四维权限、集群与工作区

| ID | 优先级 | 攻击或操作 | 预期 |
| --- | --- | --- | --- |
| R01 | P0 | read-only 通过直接 HTTP 调用 POST/PATCH/DELETE、健康置位、批量、回收恢复 / purge、导入 / Promote | 403；不能靠前端隐藏按钮代替后端拒绝 |
| R02 | P0 | role 中分别有 `services.read/pay` 与 `routes.write/ops`，请求 `services.write/pay` | 403；不能把两条 grant 维度拼接 |
| R03 | P0 | 有 write 无 delete / approve / secrets.read，分别尝试这些操作 | 全部拒绝；四种操作不是同一布尔写权限 |
| R04 | P0 | 授权 C1，对 URL / body / cursor / job ID 替换 C2 | 403 或不存在资源的 404；无 C2 名称、计数、内容或连接秘密泄露 |
| R05 | P0 | pay 用户访问 ops 实体的 UUID、名称别名、详情关系或凭证嵌套入口 | 403；对象别名解析后再次按真实 ID 与 tags 授权 |
| R06 | P0 | pay 用户不给 workspaceId，给默认区、非法区、其他区，或通过 query 重复参数绕过 | 默认行为不能扩大授权；非法 / 越权工作区拒绝 |
| R07 | P0 | tag_group={pay,shared} 查询 pay 工作区，存在两个标签仅含其一的对象、ops 区同标签对象 | 返回 `(pay 工作区) AND (pay OR shared)`；不是 pay AND shared，也不能返回 ops 区对象 |
| R08 | P0 | tag_group 对无交集对象直接 GET/PATCH/DELETE，即使它关联一个已授权 Service | 403；继承不能跳过目标 tags 交集 |
| R09 | P0 | 把 tags 改为未授权业务标签或其他 workspace，创建时不带授权 tags，移除最后一个授权标签 | 修改前与修改后都检查；拒绝授权范围逃逸；专门迁移操作需双侧权限 |
| R10 | P0 | 保留工作区物理前缀伪装、逻辑 / 物理 tag 混用、重复 workspace tags、数组类型变体 | 经同一编码与保留标签规则处理；不能伪造工作区归属 |
| R11 | P0 | entity whitelist 仅含 C1/R-pay，访问 R-shared、同名对象或 C2 的同 ID | 403；ID 白名单包含 cluster 与 entity type，名称不能替代 ID 授权 |
| R12 | P0 | 页内含大量未授权对象，继续翻页 / 使用 index search / sort / export / inventory | 后端始终过滤；空页有有界续游标；总数和搜索建议也不泄露未授权实体 |
| R13 | P0 | 缓存游标在切工作区、切账号、改 tags / search / sort、撤销 grant 后重放 | 游标拒绝或按新权限重验；不能返回旧缓存授权结果 |
| R14 | P0 | 外部 Admin 把已索引实体迁到 ops，再用旧 index 搜索 | 真实 GET 和当前授权拒绝；不返回 index document 或旧秘密 |
| R15 | P1 | 原始 `offset/next/admin_url/connectionId` 冒充签名 cursor 或业务 query | 400/403；永不跟随浏览器提供的 Admin URL |
| R16 | P1 | 权限服务 / Redis / 数据库故障或缺少 policy provider | fail closed；不使用 allow-all fallback |

### 4.3 继承、组合绑定与嵌套 IDOR

| ID | 优先级 | 攻击或操作 | 预期 |
| --- | --- | --- | --- |
| I01 | P0 | 仅 R-pay read 的 entity grant 读取真实所属 S-pay | 可读取必要公开配置；不能写 S-pay、读取兄弟 Routes 或访问 S-private |
| I02 | P0 | Route 只读权限尝试 `reveal=true`、读取 Service 证书私钥或 Consumer 秘密 | 403；关系授权不推出 secrets.read 或证书模块权限 |
| I03 | P0 | S-pay entity write / delete 管理其实际 Routes 与 Service/Route Plugins | 对应操作允许；伪造 service.id 的其他对象拒绝；write 不单独推出 delete |
| I04 | P0 | Service tag_group write，子 Route / Plugin 没有授权业务标签 | 403；即使父 Service 的 tags 命中也不越过目标自身交集 |
| I05 | P0 | Plugin 绑定授权 Service 与未授权 Consumer / Route，或存在跨区组合绑定 | 403；所有非空绑定都检查，不按第一个 binding 放行 |
| I06 | P0 | 修改授权 Plugin 为全局，或改绑到未授权对象 / 工作区；POST 直接构造相同组合 | 403；existing / proposed bindings 都检查；直接 proxy 写入同样拒绝 |
| I07 | P0 | 使用 other Consumer 的 credentialId，在本 Consumer 的 GET/PATCH/DELETE/reveal 路径调用 | 404；真实 owner 校验先于秘密显示、凭证存储或归档 |
| I08 | P0 | 使用 other Upstream 的 targetId / 历史 ID，更新权重、删除或健康置位 | 404 或 stale 409；原有效 Target 不改变 |
| I09 | P0 | Service / Consumer 级删除级联包含未授权 Plugin / Route / 凭证 | 删除预检拒绝，任何 Kong DELETE 前授权完整闭包；不可部分删后才发现权限问题 |
| I10 | P0 | 回收站 list/preview/restore/purge 替换 cluster/entryId，或节点已迁出授权区 | 403/404；归档中的私钥和原密码不因回收操作变得可见 |
| I11 | P0 | 证书 PATCH `snis` 重新绑定未授权 SNI，foreign ID 取自别区，批量迁移混入未授权对象 | 每个关系与对象独立授权；逐对象结果不隐藏未授权变更 |
| I12 | P1 | entity / tag grant 授权所需共享依赖读权限不足，执行回收操作 | 预检早拒绝；不自动授予共享父对象或秘密权限 |

### 4.4 秘密、连接注册与审计

| ID | 优先级 | 攻击或操作 | 预期 |
| --- | --- | --- | --- |
| S01 | P0 | 有实体 read，无 secrets.read；列表、详情、关系、回收预览、回执、diff、审计、导出各入口读取 | 默认脱敏；不存在备用 raw / debug JSON 泄露 |
| S02 | P0 | 有 secrets.read 但目标实体 / 工作区未授权，调用 `reveal=true` | 403；秘密权限与实体权限共同成立才可显示 |
| S03 | P0 | 可见凭证移区 / grant 撤销后，用原 create idempotency key 重放并 reveal | 重新授权当前实体或安全历史范围；不能从 result_secret 解密缓存绕过撤权 |
| S04 | P0 | 普通 / 工作区管理员注册、改 URL、认证 header、execution_mode，停用或探测连接 | 连接管理权限独立；workspace / entity grant 不能控制注册表或关闭审批模式 |
| S05 | P0 | 数据源 IDOR、未授权 connection/cluster ID、任意 Admin URL、重定向、metadata/link-local、DNS rebinding | URL/registry/网络层共同拒绝；仅已注册集群白名单端点可调用 |
| S06 | P0 | 同一幂等键改 actor / cluster / 类型 / 对象 / payload；伪造已完成 mutation ID | 409 或 403；不同请求不能取得另一个回执或秘密结果 |
| S07 | P0 | 角色、用户密码、凭证、秘密 reveal、工单状态及被拒绝写操作的审计 | 记录真实 actor / 来源 / cluster / requestId / 结果；密码和私钥仅指纹脱敏 |
| S08 | P0 | 通过任何 API 修改或删除审计，runtime DB 执行 UPDATE/DELETE/TRUNCATE/DDL | 无修改 / 删除接口；运行角色被拒绝；链验证能检测不一致 |
| S09 | P1 | 密码或 token 在 Kong message/fields、异常堆栈、插件 URL / headers 中被回显 | 响应、结构化日志及测试附件无明文秘密；错误字段仍可定位 |

## 5. 代理层兜底接口设计

三层分别是前端可见控制、后端业务授权、KongService 代理 policy。业务服务和代理层使用同一 AuthorizationService 判定规则，但代理层不能信任业务服务传入的任意 actor，更不能把白名单路径当作实体授权。

建议引入 request-local AsyncLocalStorage 和延迟安装的 KongPolicyProvider，以避免 KongService 与 AuthorizationService 的依赖循环。上下文仅由后端工厂建立，至少区分以下种类：

| context kind | 建立方与能力 |
| --- | --- |
| request/user | middleware 每请求建立独立上下文；Guard 绑定已验证 session 的真实 actor、requestId、IP 和权限版本。没有 actor 默认拒绝。 |
| internal_read | 权限关系解析的专用上下文，携带原 actor、固定 clusterId、用途、GET-only 路径集合、有限预算与最大深度。仅返回给授权逻辑或加密归档，不能被控制器直接透传。 |
| system_read | 启动探测、索引、监控的显式上下文；按 purpose 允许精确只读路径。后台身份不得写 Kong。 |
| mutation | MutationService 持久化操作与初始审计后建立，绑定 actor、cluster、operationId、实体、动作和允许写入范围；不替代实体授权。 |
| archived_delete | RecycleService 成功提交完整图后建立，绑定 entryId、nodeKey、原 ID、cluster、actor 和已归档指纹；只能删除该 affected node。 |
| approved_execute | 工作流执行器从数据库重新验证 approved 工单、不可变 hash/revision、当前授权、窗口和独占执行 lease 后建立。不可由普通 HTTP 参数创建。 |

`KongPolicyProvider.install(handler)` 只能安装一次；未安装时普通请求 fail closed。启动专用 system_read 可先进行精确只读能力探测。`before(...)` 产生不可变 decision ticket，绑定 cluster/path/method/actor/permissionVersion；`after(ticket,result)` 再验证单实体读取并过滤列表结果。内部授权关系读取不能无限递归 policy，更不能变成任意 path 的“系统模式”。

HTTP 输入中的 `actorId/system/internal/workflowId/approved/skipAuthorization` 等字段或请求头不构成可信上下文。AuthorizationService 的依赖查找可以持有受限内部读取权限；查到一个不应让用户看到的对象不能因此把它作为 API 响应返回。查询和导出路径的游标也要区分用户、内部读取及后台任务的权限域。

M2 真实验证注册了多个指向同一 Admin URL 的集群别名。M4 需用注册表中经过验证的规范化 Admin 端点派生物理传输范围，供变更锁、限流与熔断共享；游标、审计和授权仍绑定控制台集群 UUID。不能仅按 UUID 加锁，让别名绕过同一网关的并发保护。重复端点注册应告警或限制。不同 Admin 节点是否共享 Kong 数据库不能靠直连数据库推断，应明确这项探测局限。

| ID | 优先级 | 代理专项回归 | 预期 |
| --- | --- | --- | --- |
| P01 | P0 | 绕过 EntityService，直接调用 KongService 的 GET/PATCH/POST/DELETE | 请求身份与实体授权仍有效；缺上下文或无 grant 拒绝 |
| P02 | P0 | 两个不同账号并行请求、Promise.all、异常与定时回调交错 | ALS 不串 actor、scope、workflow 或 archive capability；测试包含可见 / 不可见对象 |
| P03 | P0 | internal_read / system_read 内发出写入、跨 cluster、越出路径 / 预算 / 深度 | 403；只读上下文没有隐含管理员能力 |
| P04 | P0 | 业务函数传入 fake super-admin actor，与 ALS session 不一致 | 不能代理授权；身份绑定以真实请求上下文为准 |
| P05 | P0 | 使用 plain JSON 伪造 archived_delete 或 approved_execute，或复制另一个 request 的 context | 403；可信工厂与固定 cluster/node/hash 约束不可绕过 |
| P06 | P0 | 未归档的实体 DELETE，即使用户本身有 delete 权限 | 拒绝；缓存失效这类非实体动作须独立分类及授权，不能成为实体 DELETE 入口 |
| P07 | P0 | Guard 通过后撤销权限 / 停用用户，再发出 Kong 写入；policy 安装缺失 | 重新验证当前权限并 fail closed；不依赖旧 JWT / handler fallback |
| P08 | P1 | 健康检查、公共 metrics、Swagger、索引后台请求触发网关访问 | 不向匿名用户暴露任意管理路径；后台读权限按用途限制 |
| P09 | P0 | 两个已注册集群别名指向同一规范化 Admin 端点，并发修改同一实体或累计限流预算 | 共享物理端点的锁与预算；UUID 别名不能扩大吞吐或并发写入，跨集群权限与审计仍分别校验 |

## 6. M11 审批与执行攻击矩阵

M6 门户凭证申请复用同一状态机和执行器。工单模式不能通过 action 别名、嵌套路由、批量、回收恢复、快照回滚、导入、Promote、门户自动建 Consumer、插件启停或缓存操作绕过。执行许可必须与具体工单内容关联，不能仅检查一个 `approved=true` 或任意 workflowId。

| ID | 优先级 | 攻击或操作 | 预期 |
| --- | --- | --- | --- |
| W01 | P0 | approval 集群普通写入不带工单，或携带随机 / 其他集群 / 别人的 workflowId | 拒绝；无 Kong 写入；返回可定位审批要求 |
| W02 | P0 | pending/rejected/canceled/expired 工单直接执行；普通用户伪造 approved / execution status | 拒绝；状态转移只由授权后端动作执行 |
| W03 | P0 | 无 approve grant，或仅其他 workspace/tag/entity 的 approve grant，提交审批 | 403；读权限或 write 不等于 approve |
| W04 | P0 | 提交人审批自己的工单，多角色账号重复投票，伪造 approverId | 默认分离提交人与审批人；同 actor 不重复计算 quorum；身份来自 session |
| W05 | P0 | 多级审批跳过前一级，会签只完成部分就执行，并发 approve/reject | 状态机 / 行锁保证合法单向转移；所有必需决策完成前不得执行 |
| W06 | P0 | 审批通过后替换 payload、对象ID、集群、workspace、credentialKind、tags 或计划时间 | 变更 hash/revision 失效并重新审批；不能“批准读 payload A、执行 payload B” |
| W07 | P0 | 审批后目标 before fingerprint、注册 Admin URL/版本/mode 或实体依赖变化 | 执行前预检停止并要求重新核验 / 审批；不覆盖漂移后的对象 |
| W08 | P0 | 审批后撤销提交人 / 审批人的授权，停用用户，移出团队 | 执行器重新检查当前权限；历史批准不是永续管理员能力 |
| W09 | P0 | 浏览器请求带 system/workflow header 直接调用代理，或 worker 仅凭客户端 token 执行 | 403；approved_execute 只能由受信执行器验证数据库后签发 |
| W10 | P0 | 同工单重复执行、重复调度、两个 worker 同时拿任务、重复审批请求 | lease / 幂等状态限制一次远端尝试；uncertain 不自动重发 |
| W11 | P0 | 未到计划时间、窗口已过、窗口冲突、UTC/本地时间边界、撤销与调度竞态 | 最终执行时再次校验时间与状态；未许可窗口内零写入 |
| W12 | P0 | 执行前快照持久化失败、图或凭证不完整、Basic 原密码不可恢复 | 在第一步写入前拒绝；快照 ID、工单及 mutation 关联完整 |
| W13 | P0 | 第 N 步中断 / 响应丢失，重复执行 / 回滚 | 持久化逐对象状态；unknown 标记待核验；不会重复生成凭证或盲目扩大 TTL |
| W14 | P0 | 使用曾成功工单 authorize 不同动作 / 对象；把工单回执当成新的批准 | 403/409；批准 token 与不可变 operations 集合绑定，不能复用为通用写权限 |
| W15 | P0 | 已审批门户凭证申请替换申请开发者、应用、工作区或 Consumer | 拒绝；Portal 身份与控制台身份隔离，申请人不能更改管理员角色 |
| W16 | P0 | 审计 / 站内通知 / Webhook 中的 diff、凭证展示链接或重试回执 | 秘密脱敏；接收者按当前 scope 读取详情；不能凭通知 ID 获取他人凭证 |
| W17 | P1 | ticket 撤销后重放旧 cursor / idempotency 结果或计划执行请求 | 展示最终真实状态，不再次写入，不通过缓存跳过授权 |
| W18 | P1 | 冻结工单后修改回滚对象或申请突破窗口的紧急执行 | 有明确受控权限、理由和审计；紧急入口仍不能直接伪造上下文 |

## 7. 证据与交付要求

M4 验证分为 AuthorizationService 单测、真实 BFF + Kong HTTP 攻击回归、浏览器独立用户上下文 E2E，以及代理 context 并发 / 缺失故障测试。M11 追加真实数据库状态机并发、执行器重启 / 超时 / 定时执行及凭证申请完整链路。测试名称与本计划 ID 关联，输出通过 / 失败和证据来源，未实现或未执行项明确列出。

拒绝用例须保存脱敏请求日志与原状态未变的断言；成功用例须从 Kong 回读并验证代理行为。角色矩阵 UI、隐藏 / 禁用按钮只作为交互证据。测试附件、截图和 Playwright HTML / trace 继续经过 `tests/security/check-artifacts.mjs` 秘密扫描，不记录密码填充值、JWT、API Key 或私钥。测试创建的网关实体也遵守回收站删除与确认规则。

Kong 1.5 没有 CAS 或跨实体事务，Redis 锁只协调使用相同控制台写入通道的写者。对象图与审批 fingerprint 可以阻止已检测的漂移，不能宣称完全排除绕开 BFF 的外部 Admin 并发新增子实体。生产部署要求 Admin 网络访问仅允许受控后端，GitOps 等写者纳入同一执行 / 锁流程；这项限制应在验收报告中保留。
