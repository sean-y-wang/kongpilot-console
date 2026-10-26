# M3 工作区真实验证计划

状态：仅为下一里程碑的测试计划，尚未执行，不能作为验收证据。M2 已验证的认证、回执、回收站和脱敏基线继续复用。

## 已约定请求合同

所有集群实体请求通过查询参数 `workspaceId=UUID` 指定范围，包括 schema、单实体、关系、Targets/health、凭证、回收站、插件中心、inventory 和变更回执；未传入时解析为规范默认工作区 UUID。

工作区元数据使用 `GET/POST /clusters/:cid/workspaces`、`GET/PATCH/DELETE /:wid` 和 `POST /:wid/restore`。创建字段为 code/name/owner_user_id/description；修改要求 revision，状态只允许 active/disabled。删除与恢复要求 revision/confirmed/confirm_name；默认工作区受保护，非空工作区删除返回409。

停用工作区保留只读访问，原生配置写入409；默认工作区不能停用。实体访问范围中的未知、跨集群或已删除 workspaceId 返回403；平台管理员的元数据单行 CRUD 查询仍以404隐藏不存在或属于别的集群的记录。

迁移 `POST /clusters/:cid/workspace-migrations/plan` 接受 source_workspace_id、target_workspace_id 和不超过50个 roots（type/id/parent_id/credential_kind），以200返回预览及 conflicts；`GET /:planId` 读取完整 affected/references/conflicts/budget/warnings。`POST /:planId/apply` 要求 confirmed、目标名称和 plan_hash，含冲突的计划返回409且不写网关。查询 workspaceId 与 body 来源范围必须一致，回执绑定原来源工作区。部分完成只能在核验回执及最新指纹后，以新的幂等键显式继续原计划；未知写入先核验回执及实体，不能盲目提交。

全计划共用100页/10,000记录/节点预算，超限返回409且不写入。Target 工作区迁移仅继承 Upstream，`inherited_only=true`，不产生任何原生写入，也不改变历史或有效 ID。六类凭证使用 tags-only PATCH；Basic 的原生密码哈希以及 Key/JWT/HMAC/OAuth 秘密都应原样保持，不触发轮换。

`POST /clusters/:cid/workspace-migrations/:planId/reconcile` 接受 `{plan_hash}`，只核验、不执行网关写入。原生 PATCH 传输结果未知时，后端使用私有可信读取核验每一步的实际标签与未变更的非标签配置，同时检查来源/目标 revision 和最新引用，再记录已解决步骤与 partial/succeeded 终态回执。只有全部未知步骤已解决、上次回执进入终态后，才允许新幂等键显式继续 apply。

已删除工作区的回收站预览与 purge 仅供平台管理员显式传原 workspaceId；恢复必须进入仍处于 active 的合法目标工作区。

## 固定样本与证据

创建两个独立工作区 A / B，并保留一个默认未打标范围。样本使用 `m3-security-*` 独立标签；每次请求显式传递 clusterId 和当前工作区上下文。测试仅连接真实 Kong OSS 1.5.x 的现有端点，先探测 schema 和凭证 tags 能力，再决定支持的字段；不直连 Kong 数据库。

证据只记录对象 UUID、状态、requestId、通过/失败和差异摘要。API Key、原始 Basic 密码、假 Authorization 值及临时证书私钥不写入报告。代理探测仅连接隔离 echo-upstream，不回显查询参数、请求头或凭证。HTTP 写入和浏览器写入串行执行，遵守既有限流与分布式锁。

## 测试矩阵

| 范围 | 计划测试 | 必须满足 |
| --- | --- | --- |
| 工作区元数据 | 创建 A/B；查询、修改、停用只读、软删除；无权限、错误 clusterId/workspaceId 请求 | 集群隔离；原生实体范围403、管理员错误元数据行404且无泄露；停用写入409；元数据删除有恢复记录 |
| 默认工作区 | 未打标历史对象、A 对象、B 对象分别查询 | 默认范围只收容未打标对象，不能成为所有工作区的聚合旁路 |
| 八类核心实体 | A 内分别创建、读取、修改、归档、恢复；在 B 重放各单实体和关系请求 | 自动打保留工作区标签，跨区读写拒绝，真实 Kong 数据保持不变 |
| 嵌套资源 | Target 和六种 Consumer 凭证通过父对象操作 | 工作区由真实父对象推导；伪造父 ID、集群或工作区不能改范围；不发送不支持的 tags 字段 |
| 分页与过滤 | A/B 各至少三页；tags OR/AND、分页第二页；跨范围重放游标、过期 revision 修改、旧 plan_hash apply | 后端过滤完整，无跨区行、漏行或重复；游标绑定过滤、工作区与权限版本；过期变更无写入 |
| 异常标签 | 通过受控测试夹具建立未知工作区标签、多工作区标签 | 所有工作区原生/索引列表排除，任何范围的单实体读取403；M3没有独立读取路由，M10再提供治理处理 |
| 工作区总览 | 检查索引观察时间、实体计数和提供者缺失的流量状态 | 不伪造流量；不支持 tags 的聚合明确补齐范围或标注不可用 |
| 关联迁移 | 迁移 Service、Routes、Plugins、Consumer 与全部凭证、Upstream/Targets、Certificate/SNI 的联合根图 | 预览完整、确认后迁移；Target 仅继承父范围，历史/有效 ID 与权重不变；全部秘密与 Basic 原生哈希保持；API Key / 原始 Basic 代理请求继续可用 |
| 共享引用冲突 | 共享 Service、Consumer、证书或 Upstream 落在冲突工作区 | 计划200返回完整冲突，apply409且无写入；不能静默带走其他工作区引用 |
| 部分失败与未知响应 | 单测模拟原生写入完成后传输失败；真实浏览器/客户端丢失 apply 响应，核验回执、逐对象真实数据，再调用 reconcile | reconcile 不写网关，检查全部步骤和最新引用；未知步骤全部解决且前次回执终态后才能新键继续；恢复跳过已完成项 |
| 回收站边界 | A 对象归档后在 B 恢复；工作区被删除后恢复原对象 | 越区恢复拒绝；删除的目标工作区阻止恢复或要求合法的新迁移计划 |
| 浏览器 | 切换 A/B/default；创建并查看标签；关系详情；迁移预览、确认、结果与软隔离提示 | 全部请求经过 BFF，无直连 8001；真实操作与列表范围一致 |

未知/多标签测试夹具若需要绕过正常 BFF 创建，只能使用后端网络中的独立测试机制，明确记录这是直连 Admin API 可绕过软隔离的受控演示。正常业务请求必须经过统一写入、审计、确认与回收站逻辑。夹具不使用真实外部凭证，不能借此绕过产品安全守卫。

## 后续 M4 攻击计划（尚未执行）

M3 工作区检查不能替代用户权限验收。M4 另行构造 read-only、工作区角色、tag_group 和 entity 白名单账号，覆盖前后端写入拒绝、路径/查询/body 范围冲突、关系继承、直接请求绕过按钮、凭证与回执 IDOR、同一 Admin 端点注册多集群别名，以及分页/索引/总数信息泄露。

对 Konga 已公开的越权/IDOR 方式，使用未授权用户逐一替换集群、工作区、实体和父对象 UUID；要求请求被拒绝且网关状态未变。另以假查询 API Key 检查 Kong proxy 日志不记录查询凭证。此处只定义测试目标，不声称漏洞复现或安全专项已通过。
