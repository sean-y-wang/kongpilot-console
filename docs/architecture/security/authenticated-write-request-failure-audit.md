# KongPilot 已认证写请求失败审计

适用版本：包含 `RequestFailureAuditService` 的构建。该记录用于定位 HTTP 请求失败，和实体、工单、mutation、回收站的业务审计并存。部署前仍须运行生产同源的受控失败请求验收；Source 测试通过不代替真实数据库验收。

## 记录范围

控制台 AuthGuard、门户 PortalGuard、decK DeckSessionGuard 在实际会话认证成功后，捕获服务端当前 HTTP 上下文身份与请求编号。POST/PUT/PATCH/DELETE 后续发生校验、CSRF、范围/权限拒绝、控制器异常、显式 4xx/5xx 响应或连接中断时，追加一个 HTTP 事实。实际 Request 私 WeakMap 以同一 Promise 对异常过滤器、finish、close 去重；请求对象复制不能取得该记录。成功响应和 GET/HEAD/OPTIONS 不增加写失败事实。

异常过滤器等待原业务 Promise/事务拒绝退出后，通过根 AuditService 的独立事务追加，不使用已回滚事务。显式响应或断连的补充记录可能在业务仍运行时发生，其含义仅为观察到 HTTP 响应失败/断连。

## 字段与结果含义

- `action`：`http.request.POST.failed` 等固定方法名。
- `result`：`http_400`、`http_403`、`http_500` 等 HTTP 状态；断连为 `http_disconnected`。
- `actor_type=user` 的 `actor_id` 来自真实绑定的控制台/decK 当前身份。门户使用独立 `actor_type=developer`，`actor_id=null`，`entity_type=portal_developers`、`entity_id` 为已认证开发者 ID，不伪造 users 外键。
- `request_id` 与 IP 来自服务端 HTTP frame；不读取客户端提供的身份、请求号、集群/工作区值。
- `before`/`after` 为 null，`json_patch=[]`。这表示没有在 HTTP 层声明实体快照；不是实体不存在的证明。
- `cluster_id`/`workspace_id` 为 null，使用原全局审计哈希链，仅有完整全局 audit.read 的角色可读取。被拒绝请求的目标集群/工作区是攻击者可控输入，不用于审计租户归属。

这类记录不表示 Native 未发送、KnownNotSent、实体未改变、业务全部失败、回滚成功或结果已确定。部分成功、结果未决以及原 mutation/工单/实体事实保持原状。既有业务审计不替换、不重复统计为多个业务操作；排查时按 request_id 关联不同事实。该 action/result 不映射 entity.changed，不因失败请求误触实体变更事件钩子。

## 查询和运维

具有完整全局 audit.read 权限的管理员可通过既有全局审计查询：`GET /api/v1/audit/global?requestId=<服务端请求编号>`。通过固定 action/result 可进一步过滤，原 cursor 分页与导出/完整性校验规则保持不变。结构化访问日志使用路由模板及相同 request_id，可关联具体入口；新审计不保存 URL、查询串、请求体、header、session/token、异常自由文本、校验 fields 或凭证。

审计表及哈希链仍走原 append-only 写入机制，不增加更新/删除接口，不补造修复前缺失记录或历史时间。历史 prepare 500 的审计遗漏继续保留为已知历史缺口。

如果独立追加失败，保留原 HTTP/uncertain 结果，输出仅含固定 `HTTP_FAILURE_AUDIT_APPEND_FAILED` 与服务端 request_id 的错误告警。该告警不是审计持久化成功证明。应排查控制台数据库连接、只追加权限、容量与连接池，并由运维按保留的真实日志调查；不得修改旧审计链。

## 明确边界

本层不能保证进程硬退出/断电期间持久化，也不能在控制台审计数据库不可用时保证落库。认证成功之前的请求、JSON/body-parser 的提前拒绝、匿名/公开 login、refresh、LDAP、OIDC 回调不在此已认证写请求 observer 范围；它们沿用各自已有身份认证安全审计，不能据此声称已全部覆盖。不得仅按新增 HTTP 事实数量声称所有业务变更审计完整。

验收应分别覆盖普通控制台校验失败、有效会话 CSRF/权限拒绝、门户身份与跨区拒绝、decK 专用错误过滤器、部分成功后 HTTP 错误、原事务回滚、审计数据库故障与 disconnect，并确认无原始凭证进入审计或错误日志。

异常过滤器在独立审计等待结束后再次检查响应是否已结束、已发头或断开；已结束时不重写响应，必要时只安全关闭连接。send/destroy 本身失败在过滤器内收束，避免 Nest 不等待过滤器 Promise 时出现未处理拒绝；不输出传输异常自由文本，也不改变已保存的业务/未决事实。
