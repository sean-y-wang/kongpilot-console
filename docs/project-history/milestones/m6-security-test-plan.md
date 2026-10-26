# M6 独立安全与真实链路验收计划

状态：仅测试设计。尚未创建 M6 运行时对象、执行 HTTP 请求、安装迁移或验证门户；实施须等待 M5 通过并提交，以及 M6 统一部署与独占测试窗口释放。

本计划对齐 [业务合同](m6-business-contract.md)、[存储合同](m6-storage-contract.md) 和 [Web 合同](m6-web-contract.md)。合同中的接口是实现目标；真实验收前以最终冻结的路由、DTO 和数据库约束为准。

## 真实测试顺序

1. 经正常 BFF 建立两集群、两工作区的隔离 Service/Route，以及独立的既有 API 客户；新增对象和确认键均在首次请求前登记，秘密只进入仓库外 0600 参考文件。
2. 建立公开租户、两个 API 发布项与最小安全文档。原生 Service-bound ACL 使用实际 Kong 1.5 的 `whitelist`，保留已有组和认证位置；未知或不完整认证图必须拒绝发布。
3. 注册两个开发者，验证 pending 状态无法登录；由有当前审核权限且非申请人的控制台管理员激活。门户 Cookie、issuer、audience、CSRF、会话和控制台账号相互独立。
4. 开发者创建本人应用并分别申请 A/B 发布项。审批前不产生可用 Key；批准后查看完整父回执、逐步结果和原始幂等键，显式领取 Key。每个 app × publication 使用不同 Consumer、ACL 和 key-auth UUID。
5. 实际代理验证 A Key 调用 A 为 200、调用 B 和既有 API 为 401/403；B Key 反向验证。控制台数据库 grant 和 tags 不能代替这些请求的证据。
6. 执行轮换、吊销、开发者停用及权限撤销；验证实际代理、秘密领取和原 Cookie 均遵守当前状态。记录吊销响应后的每次实际代理状态和传播时间，不用“立即”概括未测节点的行为。
7. 浏览器完成文档检索、应用、申请、审批、领取、轮换、吊销与移动端流程。然后经 BFF 审计回收测试对象，完成全部截图和清理证据后再扫描、删除私有秘密参考文件。

## 必须独立验证的边界

| 类别 | 实际断言 |
| --- | --- |
| 身份分离 | 门户 token/Cookie 调用控制台接口失败；控制台 JWT 不能冒充开发者；错误 issuer/audience/CID/WID 均失败；客户端提交 superAdmin/roles/developerId/ConsumerId 等未知字段被拒绝 |
| 所有权与 IDOR | 同租户另一开发者的应用、申请、grant、凭证和领取接口不可访问；真正第二集群中的同名或同 UUID 对象不扩权；列表游标不能跨 actor/tenant/filter 使用 |
| 认证与会话 | 无 CSRF、错误 Origin、跨租户 refresh、旧 refresh 重放、已撤销会话、停用开发者和旧 credential epoch 均失败；响应、审计、代理日志和页面无明文密码/Key/token |
| 四维权限 | portal/workflows 的 tag/entity 权限基于当前实际 Service 校验；workspace 纯元数据管理不因粗粒度发现权限扩为全局；不同授权行不拼接 module/action/scope/values |
| 审批执行 | 自审、未批准、旧 revision/hash、过期计划、非当前审批人、撤销权限后的执行失败；审批集群普通 native 写入仍拒绝；HTTP workflowId/approved 标志/伪造对象不创建执行能力 |
| Gateway 授权 | Service/Route/Consumer 同名插件选择、disabled fallback 和 ACL whitelist 实际效果一致；Portal Key 不能被旧 global key-auth 或无 ACL 表面接受 |
| 后续变更 | 删除/关闭 ACL、创建更高优先级覆盖插件、新建或重绑无 ACL 的 key-auth 表面、修改受管 Consumer group、通用实体 CRUD/回收恢复绕过均在首个危险原生包前拒绝 |
| 计划完整性 | 步骤 body/before/parent/ID/CID/WID 必须匹配批准版本；执行前快照存在且受限；每步成功和部分失败真实保留，不能通过重复批准或新 key 重发未确定步骤 |
| 内容安全 | OpenAPI 外部引用、远端 server/试调用 URL、恶意 Markdown/HTML、巨大/深层 YAML、重复键和路径穿越不能触发任意服务器请求、脚本或秘密读取；浏览器 CSP 实际生效 |
| 审计与存储 | 成功配置变更 requestId 全覆盖；开发者审计 actorType 正确且不写控制台用户外键；版本/决定/事件只追加，重复 HTTP 不增加审批票数或原生对象 |

## 故障、并发与预算证据

真实浏览器可丢弃一次已经提交的 HTTP 响应，随后只查询原 actor/CID/WID/key 的父回执；确认结果前禁止重发。真正 native 网络发送后超时、执行 claim 竞争、权限在 DNS await 后撤销和会话在步骤间失效，使用实际私有能力/NativePolicy/Mutation 服务的确定性集成故障注入补充，明确标为模拟，不能声称真实网络故障。

完整认证图采用 native size/offset 分页，共享 100 页、10,000 条、32 MiB、120 秒上限，并设置有效插件组合预算。超预算、缺 schema、不可读依赖或当前图变化必须零危险原生发送。普通列表只使用有限后端分页，不通过全量网关扫描改善 UI 计数。

同一实际 Admin endpoint 的 physical lock 覆盖 pending reservation 和 prospective mutation；测试并行审批与新建危险认证表面，不能只验证 SQL 唯一键。计划执行锁与每步 native 锁不得嵌套同一锁。直接 Admin 并行写入缺少 Kong CAS 的局限单独说明，不作为已解决项。

## 证据与秘密管理

最终报告分别记录单测、集成故障注入、真实 HTTP、真实代理、浏览器、清理和依赖扫描；任何未配置或未执行的外部服务不计通过。安全响应仅保留固定错误码、授权范围内的 UUID、状态、数量和传播耗时。

运行时秘密参考覆盖开发者和控制台密码、原 Key/轮换 Key、门户/控制台 Cookie、CSRF、承载秘密的编码 Authorization，以及继续运行的 M5 采集凭证。参考文件在第一次提交前写入，直到所有截图、归档 ZIP、编译产物和清理报告完成后保留；最终扫描通过才删除。失败响应正文、原生对象图与日志原文只在私有内存中分析，不写公开证据。
