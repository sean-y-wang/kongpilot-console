# M7 独立安全审阅与最小集成边界

状态：**设计审阅，尚未实施 M7 产品、测试、SQL010 或投递**。M6 仍由既有 owner 完成部署与真实验收；本文件不授权后台发送、网络请求、运行配置变更或绕过里程碑。

依据：`docs/milestones/M7-implementation-contract.md`、`M7-storage-contract.md`、`M7-web-contract.md`，以及当前 AuditService、AuthorizationService、grant-policy、Workflow/ApprovedWorkflowExecutionService 和 Mutation/Recycle 的真实源码。下面的边界已经 Root 审定；具体 API 名称仍由实施 owner 冻结。

## 1. 历史权限与归属

当前 `AuthorizationService.assertScopedResource` 根据实体当前 tags 调用 WorkspaceResolver。它适合当前配置与监控，不适合作为历史审计授权：对象可能删除，旧工作区可能停用或删除，tags 也可能已迁移。

M7 独立历史 matcher 只读取当前有效账号/grants 和服务器保存的不可变历史 tuple：CID、WID、原生类型、UUID、before/after 物理业务 tags、source phase、质量。不得调用已删除对象的 Admin API、按名字推导权限或把旧的未知归属映射到 default。停用工作区保留授权读取；已删除工作区必须显式使用原归属，具体可访问主体由历史政策确认，不能利用普通 WorkspaceResolver 的隐式选择。

- 创建按 after 授权；删除按 before 授权；修改要求**同一完整 grant**同时覆盖 before 和 after。
- grant 的模块、read 操作、CID/WID ceiling、scope_type、范围值不能从不同授权行拼接。tag_group 在原业务标签集合上匹配；entity 白名单仍要求准确类型和 UUID。
- 原始 NULL/无可信密封 scope 的旧记录仅完整集群/global 或平台权限可读。whole-workspace 不足以证明未知历史属于该工作区。
- 列表、详情、计数、每个导出批次、下载和投递日志首尾复验当前权限版本。完整 cluster/global chain 才公开 sequence/head；受限结果不返回未过滤计数或全局序号分布。
- `audit/events/notifications` 的发现与最小对象选择能力单独注册，不要求或赠送 native configuration.read。各入口应冻结所用的 module/action，不能让一个 coarse cluster check 代替历史资源检查。

## 2. 旧链与新注解的真实性

当前审计 hash 的十九字段保持原样：

```text
id, chain_scope, sequence, actor_id, actor_type, source_ip,
cluster_id, workspace_id, entity_type, entity_id, action,
before, after, json_patch, workflow_id, result, request_id,
prev_hash, occurred_at
```

sequence 用十进制 bigint 字符串；occurred_at 用原 writer 的 UTC 毫秒 ISO。验证真实 PostgreSQL 时间必须先拒绝非毫秒精度，避免 pg Date 丢失篡改后的微秒。JSONB 值通过现有 canonicalJson 重建，不用 SQL jsonb::text、普通 JSON.stringify 或公开脱敏视图替代。

新增 append-only `audit_event_scopes` 绑定原 event_hash，并保存上下文 HMAC，覆盖不可变 CID/WID、类型/ID、before/after tags 与 source phase。注解只来自可信原持久行或已经验证的业务 tuple；公开 HTTP body、当前对象 tags 和聚合名字不能作为密封依据。旧未密封行维持 legacy_unknown。

旧 chain 验证不包含未来注解。界面与完整性报告分别说明“原审计区间链有效”和“历史归属注解有效”，不能声称前者同时证明后者，不能把有限区间通过表述为完整历史永久防篡改。DB owner 能绕过运行时约束的限制仍需明确。

## 3. 审计与事件最小披露

对历史 JSON patch 直接调用普通 Secrets.redact 不够：新增敏感 alias 的秘密可能位于 `value`，其身份却在经过转义的 pointer `path`。安全公开 patch 从**当前再次脱敏的原 before/after**重新 jsonDiff；原持久 patch 仅用于旧链 hash 验证。公开摘要不能修改旧行或旧 hash。

实际 MutationService 的未知/失败结果可能把 callbackResult 存入 after；Recycle 返回的 deleted/restored 子数组含对象身份。这些历史行即使 root scope 合法，也不能证明所有子对象已授权。

- 受限审计默认把 deleted/restored/archived 级联子数组缩为数量，不输出 child IDs。
- 只有每个子对象都有独立密封历史 scope 且当前完整 grant 通过，才能另行开放其身份；初版不必实现此额外遍历。
- whole-workspace 不能替代未证明的 child scope。whole-cluster/platform 读取已审计图仍执行当前秘密脱敏。
- event_records、通知与外部模板不复制 callbackResult/raw audit/config。初版仅显式 root identity、结果、计数和固定安全关联指针，不包含 cascade child IDs。
- URL userinfo、Slack/飞书 token 路径、凭证字段、认证头、错误正文和 CSV 公式字符继续执行专门防护。事件摘要安全不代表原始链字节可以公开。

## 4. event-metadata 与 Portal 能力隔离

当前 SQL008、WorkflowKind/subject allowlist、handler registry 和 ApprovedWorkflowExecutionService 都以 Portal 业务定义为边界。新增 event 配置不能假借 portal-metadata 或仅给 Portal subjects map 加一个表名。

M7 增量引入独立 `event-metadata`，建立明确 kind → subject → `events.*` handler 映射，SQL 与 plan verifier 同时验证：

- 仅固定事件元数据表、metadata steps；native_request_count=0、nativeRequests 全空、generated 原生凭证不存在。
- fixed handler 的 inspect/apply 使用同一实际 SQL 事务，验证 original before/revision/payload HMAC，CAS、audit、event/outbox 原子提交。
- approve 只要求当前匹配范围的 workflows.approve；执行者另需 workflows.write 与事件共享配置的 whole-workspace events.write/delete。批准决定不隐含执行或发送权限。
- direct 不 mint approved proof；approval 不通过普通 IAM 回调直接执行。主体类型、处理器、方法、目标、原 key 和 mode/revision 均不可中途替换。
- `APPROVED_PORTAL_STEP_POLICY` 继续只接受已存在的 Portal 四类原生业务。event-metadata 不获取 Portal managed-object 例外、native operation 或 boundary read permit。
- 渠道 test/replay 的 handler 只持久化受控投递任务；第三方 I/O 在提交后由 worker 执行，不在 metadata SQL 事务或批准 ancestor 中发送。

个人 owner 的 read/dismiss/站内偏好是独立持久元数据操作，允许 direct，不修改共享渠道或网关配置。它们仍需当前 owner、notifications 读写范围、引用源范围、revision CAS、原 key 回执；批量最多100个同 scope ID并二次确认。

## 5. 原子事件与有界 fanout

Audit.append 在原有同连接 SQL 事务内返回安全 audit receipt，DB-only outbox writer 随后写密封 scope/event/outbox。writer 不调用 Authz、Kong、Redis、网络或业务 handler，避免循环依赖与锁倒置。事务回滚不可产生可投递事件。

事件 phase 固定为 requested/node/aggregate/terminal/observation。相同 source occurrence 只有一个 event identity；请求受理、逐节点 ACK、父工作流终态和投递成功分别命名，unknown 不映射为成功。Developer audit 保留 actor_type=developer 与 console actor_id=NULL。

outbox fanout 超过一批时保存固定订阅枚举上界和 continuation，分批生成唯一 delivery。重复认领可重复插入，但唯一 event/subscription version/replay generation 保证相同投递身份。**只有所有批次完成**才把 outbox CAS 为 dispatched；不能在第一批50个订阅后提前完成。枚举版本变化和新订阅的历史接收规则需固定，不能由时间竞争随机决定。

手动 replay 新增显式 replay generation/parent delivery；自动 retry 始终沿用原 delivery UUID 与 Idempotency-Key。业务生产者不在 worker 中重新执行配置 callback。

## 6. durable 发送意图、崩溃与租约

发包前先提交 delivery 的 attempt_no、lease_owner、lease_generation 与发送意图。认领事务保持短暂，提交后再做 DNS/HTTP/SMTP，不持有数据库行锁等待第三方。

append-only attempt table 保存一次最终结果，不使用 INSERT started → UPDATE finished。若进程在发包后、最终记录前崩溃，过期租约恢复者为相同 attempt_no 补 uncertain completion；是否已处理未知，下一次重试仍使用原 delivery/key。UNIQUE(delivery,attempt_no) 和 generation CAS 防止迟到 worker 修改新租约或改写已完成的尝试。

网络超时、掉线和缺失 ACK 均不能证明未送达；至少一次语义要求接收方按稳定标识去重。429/5xx/network 才按预算自动重试，其他4xx为终态失败；重试次数、Retry-After、响应字节和总耗时有明确上限。成功/取消/耗尽不可重开历史，只能显式新 replay。

## 7. worker 的持续授权与最终发包栅栏

组织订阅使用服务器加载的真实 active 配置创建者及当前完整 grants；个人收件人也逐次检查当前 owner 与源事件范围。撤权、停用、目标 revision/generation 变化或配置删除使旧任务停止，状态应有可观察安全原因。不要缓存作者历史 grant、使用退出 JWT、伪造 HTTP session/开发者主体或使用平台万能绕过。

最小 integration adapter `EventAccess` 只负责当前主体与密封历史资源的授权/版本，既不 mint Kong context，也不调用业务 writer。通知读取、外部发送和审计读取分别指定自己的 module/action，避免借链接获得其他模块读取能力。

发送流水线：durable intent → 安全目标/DNS解析并pin → 最终重新加载当前 creator/recipient/source 权限、channel/subscription revision/generation、delivery lease → 同轮次同步 beforeSend → 实际 socket。DNS 与其他 awaits 后必须复验，不使用解析前的授权或租约。HTTP 不重定向、不允许 userinfo/任意敏感头；SMTP使用独立固定目标、证书校验和明确 TLS/STARTTLS 策略，禁止自动降级明文。

目标变更不能把旧隐藏凭证带到新 host/path。日志仅固定 errorCode、状态、耗时与安全 UUID；原 URL、第三方 response body、认证材料和原生配置不进入日志或模板。

## 8. release 后的独立验证重点

本表是未来测试分工建议，不是已执行证据。

| 边界 | 有意义的反例与证据 |
| --- | --- |
| 历史完整 grant | 修改前team:A/后team:B，两个分离授权不得拼接；同一覆盖两侧才可读；current entity迁移/删除不重标旧历史 |
| legacy/归属密封 | NULL旧scope、复制别的event scope、HMAC字段替换、deleted WS/default混淆均拒绝受限读；wholecluster只读旧历史 |
| 原始链 | PostgreSQL JSONB/NULL/BigInt/UTC毫秒往返；微秒改动、缺行、sequence gap、head不匹配；安全视图二次脱敏不改变原hash |
| 公共摘要 | 新secret alias、escaped JSON pointer、root replace、callbackResult child IDs、CSV公式和URL token均不泄漏 |
| 工作流 | event-metadata混入native step/generated/Portal handler、HTTP workflowId、批准者无write、direct mode换为approval均保持精确门禁 |
| outbox | 业务rollback无event；超过50订阅的第二批崩溃恢复无丢失/重复身份；相同source重放只新增显式generation |
| attempt | socket后/记录前崩溃、旧worker迟到、DNS期间lease loss、429与400分类、same-key retry，真实本地收件器核对至少一次 |
| current authority | creator/recipient撤权、停用、gen旋转、目标改变发生在DNS await期间，后续发包次数为0；无console/Portal主体混用 |
| owner/导出 | 他人notification ID、混合scope批量、迟到导出下载、分页中撤权、0与unknown未读状态正确；全部按原actor/scope/key恢复 |

实施后分别报告独立单测、隔离 PostgreSQL、本地 transport fault 与真实 HTTP/浏览器证据。当前仅完成设计审阅，不据此声明 M7 可商用或外部渠道已验证。
