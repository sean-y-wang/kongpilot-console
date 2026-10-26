# M6–M11 审批工作流基础设计草案

本文件仅提出下一里程碑的接口和安全约束，没有新增运行时功能或数据库迁移。M6 使用单级审批并在审批 HTTP 请求中同步执行；M11 增加多级、会签、定时和变更窗口。两阶段使用同一份不可变计划、执行账本和授权模型。当前 M5 测试门禁独立交付。

## 执行授权

集群的 `execution_mode` 始终保留真实值。审批执行不能临时改为 direct，也不能依靠 HTTP body 的 `workflowId`、请求头或普通 operation context 跳过审批检查。

工作流服务在数据库批准事务提交后创建私有 WeakMap 计划能力和步骤能力。能力只存在于服务器可信祖先上下文，不能序列化、拷贝、由客户端参数构造，结束、过期、驳回或撤销后立即失效。MutationService、NativePolicy、KongService 的 approval409 检查分别验证同一能力对应的已提交计划与步骤；只允许计划内指定的 native method/path/body/parent/workspace，普通 API 继续拒绝未审批写入。

审批能力仅解决执行模式门禁。每一步仍需当前数据库账号启用、审批权限和实际写入权限、工作区成员校验、业务标签和实体白名单校验、所有绑定对象权限、物理 transport lock、未决影响范围阻断、变更前指纹及 native before-send 再授权。审批后目标配置或权限变化必须重新规划，不能把原审批当成永久写权限。M6 的真实审批 HTTP 会话可以作为执行身份；M11 后台任务必须使用显式、仅服务器可创建的 approved executor context，核验当前审批账号和 grants，不能假造 console session 或默认成为平台管理员。

## 建议表字段和数据库约束

| 对象 | 关键字段 | 强制约束 |
| --- | --- | --- |
| workflows | id、kind、cluster_id、workspace_id、subject_id、submitted_by、revision、state、plan_hash、payload_secret、policy_version、expires_at、created_at、cancelled_at | 集群/工作区复合 FK；kind 与状态白名单；payload 加密；批准后 plan_hash/payload/范围不可修改；变更重新生成 revision 并撤销原批准 |
| workflow_approvals | workflow_id、plan_revision、plan_hash、level、approver_id、decision、reason、decided_at、request_id | 仅追加；唯一(workflow_id,plan_revision,level,approver_id)；同一次赞成和反对不能覆盖；默认禁止提交人自审；批准账号当时必须具备完整 approve tuple |
| workflow_steps | workflow_id、plan_revision、step_key、order、entity_type、parent_id、entity_id、method、path_hash、body_fingerprint、before_fingerprint、dependencies、state、operation_id | 唯一 workflow+revision+step_key/order；步骤 native 类型及路径严格1.5白名单；实体/parent/workspace不能重绑定；每一步只关联一个 durable mutation operation |
| workflow_executions | id、workflow_id、plan_revision、plan_hash、approved_by、execution_actor_id、state、started_at、completed_at、snapshot_id、request_id | 执行创建时锁定 workflow，revision/hash/status/expiry CAS；每个批准版本只能有一个执行；执行前快照完成后才允许第一步发包 |
| workflow_events | workflow_id、execution_id、step_key、actor_id、action、result、request_id、operation_id、created_at | 仅追加；记录提交、批准、驳回、撤销、执行和回滚；错误只存脱敏 code，不存 Kong 原始秘密回显 |

建议 workflow 状态为 draft/pending/approved/executing/succeeded/failed/uncertain/rejected/cancelled/expired。执行中或 uncertain 不能取消并重建另一份计划绕过未决操作；只能进入受控核验、补充审批或明确的补偿流程。唯一约束和 CAS 防止双击、多审批人和多个执行器同时启动。

计划的 Hash 使用服务器规范化结构及秘密 HMAC；提交 API 不接受 hash 作为授权证明。数据库中的 step 行与加密计划必须一致，不能在步骤缺失、数量不符、类型/父关系被篡改时降级读取另一份未验证计划。idempotency 绑定 actor、cluster、workspace、workflow revision/hash 和操作；同 key 不同内容冲突，换 key 不解除物理未决阻断。

## M6 凭证流程的最小闭环

门户开发者身份与控制台身份分离。申请对象只接受本人拥有的应用、已发布 API 和门户申请字段；Consumer 名称、workspace tag、Credential kind、关联插件和操作顺序由服务器生成。申请人不能提供控制台角色、任意 Consumer/Plugin ID、URL、workspace 保留标签或 raw native JSON。

审批时重新核验开发者/应用状态、目标 API 和原工作区、请求修订号、当前审批权限以及 Consumer/credential 操作权限。计划依次创建受控 Consumer、验证 key-auth 绑定条件、生成凭证、保存密文和应用绑定、通过真实代理请求验证凭证。共享或全局 key-auth 插件变更必须作为可审阅的明确步骤并得到相应写权限，不能隐含扩大另一工作区的认证影响。

密钥由服务端生成。只有被批准的应用所有者通过独立门户权限校验才能查看或领取；审计、diff、通知、步骤列表和执行回执只有脱敏摘要。凭证恢复所需秘密按 CredentialStore 的独立加密语义保存，不能以公开工作流 Hash、审批评论或普通 JSON 字段传递。

创建响应丢失、验证超时或控制台存储失败时，整个相关 Consumer/credential 范围保持 uncertain。不得因门户重新提交、浏览器缓存过期或审批人换账号而发第二把 key。显式核验必须在物理锁内取得可信原生证据和账本 CAS；单次 GET 不存在不能证明先前超时写绝不会完成。

## 同步审批到 M11 的扩展边界

同步批准避免 M6 立即依赖调度器，但不能把数据库批准事务与 Kong 写入视为一个事务。批准提交后、执行认领前进程崩溃时显示 approved/待执行；执行认领后、发包前或响应后崩溃时按账本 remote_started/remote_completed 和实际证据区分。已执行步骤不重发，未决步骤先核验。批准 HTTP 返回丢失时只通过 owner+当前权限的安全回执恢复状态。

M11 为同一执行模型增加 approval policy levels/quorum、not_before、window_start/window_end、时区明确的计划时间、调度租约和超期事件。调度器在执行认领和每一步发包前核验当前审批账号、grants、批准版本、窗口、快照、计划指纹和锁；延期不能隐式延长审批有效期。审批模式、账号禁用、权限撤销或窗口关闭都阻止下一步。

失败补偿不等于隐式删除：新建 Consumer/凭证的回收仍遵守对象图归档和回收站；密钥轮换/吊销必须有具体撤销计划和真实认证结果。回滚需要同样的当前权限、已批准步骤、原 ID/依赖顺序和 before-send 防护。外部不可回滚操作明确呈现人工处置状态。

## 高价值验收

需要真实验证：审批模式中的普通写始终409；未批准/驳回/取消/过期版本不能执行；同时批准和同时执行各仅一次；普通 workflowId/伪造步骤能力无效；计划/归一化 step/parent/ws 篡改零 native 写；审批后降权、配置改变、锁丢失阻止下一步；应用越权和门户账号冒充控制台403；Consumer+key-auth 实际认证成功；轮换后旧 key 拒绝；吊销立即失效；未知创建不能换 key 重发；执行前快照、逐步审计、脱敏和回收补偿完整。网络响应丢失与进程中断测试分别记录为真实故障或受控模拟，不能把 mock 通过写成商用运行证据。
