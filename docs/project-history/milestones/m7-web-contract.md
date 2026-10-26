# M7 前端合同：审计日志、事件钩子与通知中心

状态：**仅设计，未实施产品代码**。M6 前端源码当前冻结，等待统一部署和真实验收；本文件不授权 M7 迁移、后台投递、部署或外部消息发送。API 路径、DTO 和回执标记为拟议接口，需在 M6 通过并提交后由 Root 与后端所有者冻结。

依据：`docs/milestones/M7-storage-contract.md`、现有 `AuditService` 的 append-only hash 链、Console `api()` / `scopeQuery()`、完整四维 `EffectiveGrant`、原始账号与范围绑定的未知写入恢复机制。后端只对接 Kong OSS 1.5；事件钩子和通知全部由控制台实现。

## 1. 页面结构与当前权限

| 控制台路由 | 页面与入口 | 所需能力 |
| --- | --- | --- |
| `/audit` | 审计查询、脱敏详情、导出任务、完整性验证 | 当前范围 `audit.read`；完整链验证另需完整 cluster/global 范围 |
| `/events` | 渠道、订阅、事件记录、投递日志四个标签 | `events.read`；写、删除与手动投递分别按当前服务端对象能力 |
| `/notifications` | 本人消息、未读筛选、订阅偏好 | 当前账号自己的 `notifications.read`；标记/偏好修改另需实际 write/delete 能力 |
| 页头消息按钮 | 服务器未读角标、最近通知抽屉、进入通知中心 | owner 与当前事件权限共同过滤；无权或查询失败不显示伪造的零条 |

保持 Kong Manager 风格深色导航、中文默认和响应式内容区。列表显示当前工作区，并允许实际授权的全局/集群审计视图；无法证明历史 scope 的旧记录不默认为当前默认工作区。菜单的粗粒度能力只决定入口，行级详情、操作和链接继续使用后端当前范围能力。

`audit`、`events`、`notifications` 已存在于权限模块目录，实施时不创建新绕行模块。完整 grant 按模块、动作、CID/WID、scope_type 与范围值逐行匹配；不将不同授权行拼接。渠道和订阅的共享元数据管理要求 whole-workspace/global 授权；有限 tag/entity 授权仅可读取后端证明属于自身范围的事件或审计，并不能编辑共享目标。个人通知不提供任意 `userId` 参数或跨用户管理入口，平台管理员也不能通过个人页面读取另一个人的消息。

## 2. 拟议只读接口与分页

以下所有接口以 `/api/v1` 为前缀，成功 `{data,meta:{requestId}}`、错误 `{error:{code,message,...},meta:{requestId}}`。集群端点显式 `workspaceId`；跨工作区/完整集群视图必须有明确 `scope` 与对应能力，不能通过省略工作区悄悄扩大范围。

| 方法与路径（待后端冻结） | 请求与响应语义 |
| --- | --- |
| GET `/clusters/:cid/audit` | scope、workspaceId、actorId、entityType、entityId、action、result、workflowId、requestId、from/to、size/cursor；返回授权的安全列表 |
| GET `/clusters/:cid/audit/:id` | 同一已捕获范围；完整安全详情与当前 capabilities，不因知道 ID 而跨范围读取 |
| GET `/audit/global`、`/audit/global/:id` | 可选独立全局审计入口，仅完整 global audit.read；用于登录、全局 IAM 等 CID/WID 为 NULL 的真实记录，是否提供由 Root 冻结 |
| GET `/clusters/:cid/audit/integrity` | chain 及 bounded sequence/time interval；完整集群授权的只读查询，返回完整性报告，不修改审计正文 |
| GET `/clusters/:cid/events/catalog` | 服务器固定事件类型、类型中文说明、支持的条件、渠道类型与能力；未实现检测器不得标为已实时监测 |
| GET `/clusters/:cid/events/records`、`/records/:id` | eventType、sourceKind、nativeType/nativeId、from/to、size/cursor；只安全摘要和真实发生/观察时间 |
| GET `/clusters/:cid/events/channels`、`/channels/:id` | status、search、size/cursor；公开脱敏目标信息和当前 revision，永不返回 token URL 或认证材料 |
| GET `/clusters/:cid/events/subscriptions`、`/subscriptions/:id` | status、channelId、eventType、search、size/cursor；范围条件为固定原 CID/WID |
| GET `/clusters/:cid/events/deliveries`、`/deliveries/:id` | state、eventId、subscriptionId、channelId、from/to、size/cursor；真实投递状态和下次重试时间 |
| GET `/clusters/:cid/events/deliveries/:id/attempts` | size/cursor；只追加尝试历史，不拉取全部重试记录 |
| GET `/notifications`、`/notifications/:id` | 当前用户，read=all/unread、可选已授权 CID/WID 过滤、size/cursor；未读只计当前可读范围 |
| GET `/notifications/unread-count` | 当前用户和显式 scope；`{count,observedAt}`；不以当前页行数代替总未读数 |
| GET `/notifications/preferences` | 当前用户、原 CID/WID、size/cursor；偏好不授予额外业务读取权限 |

统一列表 `{items,nextCursor,size,total:null}`；实际返回可靠总数的通知未读摘要独立展示，其他列表不制造总量。`size` 默认 20、上限 100，时间范围默认最近 7 天。游标绑定 actor、permissionsVersion、完整过滤和范围，前端只维护已访问页缓存，提供上一页/下一页，不全量扫描获得计数或实体名称。

查询键包括 **actor、permissionsVersion、CID、规范 WID、scope、资源、全部过滤及 cursor**。切换账号、工作区、权限版本或过滤清除旧页面数据并中止旧请求，不使用旧数据占位显示新范围。详情抽屉按相同范围 remount，迟到的旧响应不能重新出现。只读可刷新，网络错误不转为“无记录”。

## 3. 审计查询、详情和完整性

列表列：时间、操作人/身份类型、来源 IP、对象类型、操作、结果、集群/工作区、关联工单、requestId。对象 ID 仅在授权安全摘要已提供时显示；失去原生对象权限不影响读取有独立 audit 权限的历史安全摘要，但对象导航仍需当前目标 read 能力。开发者审计标识为门户开发者，不冒充控制台用户。

详情包括元信息、before/after、RFC 6902 JSON patch 和关联工单/父操作。所有数据使用后端当前秘密脱敏投影，再通过现有 `redaction.ts` 防御性处理；JSON pointer 正确解码 `~0`、`~1` 后做秘密字段识别，不能把 `/config/provision_key` 等值作为普通文字。长数组/嵌套 diff 采用有限展示与明确展开限制，不在浏览器取完整 Kong 配置重新算 diff。表格和复制按钮不显示明文私钥、Key、密码、认证头或 token URL。无审计修改/删除/“修复链”按钮。

完整性报告拟议：

```ts
interface AuditIntegrityView {
  status: 'verified' | 'mismatch' | 'partial' | 'unavailable';
  scope: 'cluster' | 'global'; observedAt: string;
  checkedRows: number; complete: boolean;
  verifiedInterval?: { fromSequence: string; toSequence: string };
  reasonCodes: string[];
  firstMismatch?: { eventId: string; reasonCode: string };
}
```

只有有权访问完整链的账号才看到链验证入口和完整序号范围。有限工作区/标签/实体读取不能泄露其他工作区的链头、未过滤计数或全局活动序号；界面说明其详情为脱敏摘要，不能用摘要重新计算原始 hash。状态显示“指定区间验证通过”或“检查未完成”，不能把有限区间通过宣传为完整历史永久防篡改。运行时角色的 append-only 限制和 hash 链可检测异常，数据库 owner 能绕过触发器的部署局限在说明页明确列出。

## 4. 审计导出

拟议 POST `/clusters/:cid/audit/exports` 接收与列表一致的规范过滤、format=`ndjson|csv`、确认；返回异步任务。GET `/audit/exports/:jobId` 读状态，GET `/:jobId/download` 同源授权下载（确切全局/集群路径由 Root 冻结）。导出会读取当前完整权限，每批和下载前复验撤权，不把创建时权限冻结成永久可下载能力。

导出任务安全摘要：`{id,state,format,rowCount,bytesCount,complete,reasonCodes,createdAt,expiresAt,capabilities:{download}}`。默认最多 100k 行 / 32MiB；超限显示“达到导出上限”并标记 incomplete，不能称“全部导出完成”。浏览器不先下载所有列表行组装文件。没有裸存储地址、查询 token、跨域预签名链接；下载走已有身份/CSRF/单次刷新规则的独立受控 Blob helper，账号或权限改变时拒绝迟到结果，并及时 revokeObjectURL。文件名使用服务端固定格式并清除路径、控制字符，内容响应正确 nosniff / attachment。CSV 公式防护由服务器实施；前端不展示导出正文作为日志。

导出任务创建只持久化控制台 job 并审计，不修改 Kong。若丢失创建响应，保留原 key 查询真实 job/IAM receipt，不用新 key 再建任务。已证明 job 创建完成和文件生成完成是两种不同状态。具体回执域、创建动作授权和异步结果字段由后端冻结后接线，不猜测 native operationId。

## 5. 渠道与订阅配置

渠道类型：Webhook、邮件、Slack、飞书。类型来自服务器目录，表单仅实现已启用 provider；缺 SMTP 配置等显示服务器不可用说明，不虚构发送成功。新建填写 name、type、后端固定白名单目标/认证字段和 options。地址、邮箱与 token 只在明确输入表单的临时内存中存在，提交/关闭/切换后清除，不进入 URL、Query 缓存、草稿、审计 diff 或恢复存储。

渠道读取仅公开 `maskedDestination` / `destinationHost`、`authConfigured`、状态、revision、最后测试时间及安全结果；Slack/飞书 token 路径也算秘密。编辑隐藏地址时显示“保留当前目标”，空白默认省略，不能把 masked 值重发为真实 URL。显式改目标由服务器 fresh 出站规则与 generation 策略核验；界面要求重新明确认证选择，不能悄悄继承旧 token 到新 host。M7 不提供未经合同授权的原始目标/秘密 reveal 功能。

订阅表单：名称、同工作区渠道、事件类型多选、可选业务 tags/实体条件、启停。事件类型最多 32、条件最多 256；workspace 标签、目标 CID/WID 或 creator 不可自由改挂。实体条件若需要按名选择，使用后端专用最小授权 identity 接口或已有相同授权的 bounded lookup，不借当前 `services.read` 下载全部配置。不能将订阅条件解释为读取授权，角色撤销后旧订阅不继续发送原范围内容。

拟议写操作：

| 方法与路径（待冻结） | 输入/行为 |
| --- | --- |
| POST/PATCH `/clusters/:cid/events/channels[/:id]` | 固定字段、编辑 revision；当前完整 events.write；保存真实 IAM/workflow 父回执 |
| POST `.../channels/:id/status` | revision、status、confirmed、confirm_name；停用阻止新的发送，不抹除历史 |
| DELETE `.../channels/:id`、POST `.../:id/restore` | revision、typed name 二次确认；进入元数据回收列表，不物理删除 |
| POST `.../channels/:id/test` | revision、confirmed、confirm_name；使用服务器固定无秘密测试模板，仅由用户显式触发 |
| POST/PATCH `.../subscriptions[/:id]` | eventTypes、允许的范围条件、status、revision；同范围渠道 FK |
| DELETE `.../subscriptions/:id`、POST `.../:id/restore` | revision、typed name 二次确认；保留历史 delivery/attempts |
| POST `.../deliveries/:id/replay` | revision 或固定历史标识、confirmed、confirm_name；显式建立新的 replay 版本，保留原 event identity/尝试历史 |

所有配置遵循集群 direct/approval 模式。审批模式返回真实工作流，UI导航到 M6 `/workflows` 并显示待审批，不能同时乐观启用原配置；审批/执行仍由实际当前账号完成。渠道测试和重放会真实对外发送，在页面说明目标的脱敏摘要、模板、范围与至少一次语义；不在页面加载、创建成功、启动验证或源码测试时自动测试外部账号。用户明确点击并确认才属于对应发送授权。

渠道/订阅删除与恢复在 Events 页“回收站”标签可见，并从中央回收站给明确入口；是否复用现有 recycler 或专用 metadata trash 由后端确认，前端不把 native recycle payload 强套在渠道定义。默认不提供永久删除渠道或投递历史按钮。

## 6. 投递状态、日志和未知结果

事件受理、审批决定、原生 ACK、父工作流完成和远端投递成功各有独立状态。事件列表保留真实 `occurredAt`、观察质量和源 operation/workflow/audit ID。未启用的证书/健康/漂移检测器显示“未启用/尚未观测”，不能按接口存在声称已经监测；M10 漂移未落地前不伪造漂移通知。

delivery 状态：待投递、发送中、成功、等待重试、结果不确定、重试耗尽、已取消；attempt 显示次数、开始/结束时间、HTTP 状态、耗时与安全错误码。显示“下一次尝试时间”来自服务器；浏览器不自行轮询重发或修改历史 attempt 为未尝试。HTTP 超时/断开说明“接收方可能已处理”，不能显示“未送达”。固定 delivery/event UUID 与原 Idempotency-Key 由服务端保持，重放新版本仍保留历史关联。

建议后端统一 `GET /clusters/:cid/events/operations/by-key/:key?workspaceId=原WID` 投影真实 IAM/workflow/job/delivery 父结果（DTO 待冻结），避免客户端猜当前集群模式。未知写会保存原账号、CID、WID、原 key、父 ID 与时间到现有安全恢复白名单；没有请求配置、目标、凭证、payload。单个 SQL 出队成功不能证明远端投递成功；单个 HTTP attempt 成功也不能证明复合配置审批全部完成。只有匹配原范围且服务端声明相应父动作已 durable 完成才解除阻止。

`not_sent`/404 不证明未发送；保留原 key，不换 key 盲重发。审批已登记或纯决定完成与执行完成继续使用 M6 独立证明。详细回执安全字段由 backend API pins 后补，不能用任意客户端 state flag 放行执行。完整性验证使用只读 GET，可重新读取；若最终后端改为 POST review，只有冻结的确切路径可归为 NETWORK_REVIEW_INTERRUPTED。普通 metadata/test/replay 写入仍严格锁定未知状态。

## 7. 本人通知与偏好

页头角标由 `/notifications/unread-count` 后端当前授权计数提供；默认每 30 秒按可见页面刷新，隐藏页暂停。首次未读未知/请求失败显示不可用标记与提示，服务器确认 0 后才显示零条。点击消息先读取当前 owner/scope 详情，再按服务器 `link:{kind,id}` 白名单导航；拒绝 raw URL、跨域、Admin URL、任意 userId 或客户端生成权限。目的对象已删除/撤权时提示链接不可用，消息摘要只在后端仍授权的范围呈现。

拟议 POST `/notifications/:id/read` 单条标记；POST `/notifications/read-batch` `{ids,confirmed:true}` 仅当前页最多 100 个实际 ID，二次确认。批量忽略/归档同样显式确认，只有追加 read/dismiss 时间不物理删除正文。不同 scope 混合批量若未冻结可先仅允许同 CID/WID；无“全部已读”浏览器全量遍历。若实现 server bounded whole-owner 标记端点，须清楚展示服务器操作范围并使用真实操作回执。

偏好创建/编辑只本人：选现有可访问集群/工作区、目录事件类型、站内开关和可用范围条件；revision CAS、status softdisabled/deleted。外部订阅渠道需要独立 events 权限，不能由 notifications.write 授予。本人通知无审批代办权限，审批按钮仍在工作流当前服务端能力下显示；门户开发者消息不与控制台用户通知混用，M7 不假造门户通知账号。

标记成功后 invalidate 当前 owner count/list，未知响应保留原安全 key 并只读核验，不乐观清空未读数。后台 SSE 若启用只给 opaque ID 或刷新信号，不携带业务正文/秘密；连接需要独立当前身份验证和断线后 fresh scope 校验，不把 bearer 放在 URL。初版轮询即可验收，不为存在 UI 而假称实时推送已实现。

## 8. 实施文件与验证合同

拟议前端文件（M7 release 后才创建）：`features/AuditPage.tsx`、`features/EventCenterPage.tsx`、`features/NotificationsPage.tsx`、`components/NotificationBell.tsx`、各模块 typed API/helper；复用 Shared QueryError、cursor paginator、MutationConfirm 和 Auth/Permissions/WorkspaceContext，不为通知创建独立高权限客户端。

稳定选择器：`audit-list`、`audit-diff`、`audit-integrity-status`、`audit-export-state`、`event-channel-row-ID`、`event-subscription-row-ID`、`event-delivery-state`、`notification-bell`、`notification-unread-count`、`notification-row-ID`。中文表单 aria：查询操作人、对象类型、对象 ID、审计时间范围、事件类型、通知渠道、订阅范围；确认框使用当前行安全 name。秘密不进入 testid、截图或断言失败文字。

源码聚焦测试：完整授权行与 current actor/permissionVersion 的 query/recovery 隔离、审计 JSON pointer 脱敏、CSV 下载文件名与 URL 回收、未知测试/重放不换原 key、mask URL edit 省略、混合范围批量拒绝、owner-only 未读计数、固定导航白名单。纯前端测试不能替代真实 SSRF/DNS/运行角色不可变和队列崩溃测试。

部署后由 Security 独占 HTTP→browser 窗口：真实网关写入对应 audit/diff/事件/outbox，站内未读与标记闭环，审批模式配置未执行前不发送，Webhook 使用部署明确批准的本地收件器核验真实 payload/同 delivery 重试，不使用真实 Slack/飞书/邮箱外部账号。撤权、跨 workspace/用户 IDOR、原始 key 丢响应、移动端、内容秘密扫描均给实际证据。Frontend 在 Security 交接后做人工视觉与 typed confirmation；新 Cookie/目标 token 只合入仓库外 0600 引用，全部截图/report/source/artifacts 扫描后才销毁。

M7 通过的声明必须区分“审计摘要可查”“指定 hash 链区间验证”“站内已送达”“外部 provider 尚未配置”与“外部真实投递通过”；不将单测或模拟消息当作商用全链路验证。
