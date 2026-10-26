# M6 已明确失败的首个 Consumer 创建：修复与收尾计划

状态：源码实施已释放，实际业务写入暂停。原首次凭证执行的元数据恢复已经成功，后续同一应用申请第二个 API 在创建新 Consumer 时发生唯一字段冲突。

真实证据：`artifacts/M6/security-live-pre-fix-second-credential-execution.json` 保留 381/1；`second-credential-execution-failure-proof.json` 保留原新执行键与 terminal failed 回执；`second-credential-custom-id-proof.json` 证明实际 Kong 1.5 Consumer schema 的 custom_id.unique=true、原 Consumer 使用应用 ID、新分配 Consumer 不存在。HTTP 409 属于该次真实证据；数据库保留的是 KONG_VALIDATION_ERROR，而非完整上游 HTTP 状态。

## 改动范围

1. 新编译授权计划使用独立 grant UUID 作为 Consumer.custom_id；应用关联继续使用 portal-app 标签和控制台外键。所有已封存计划、已成功 Consumer 和已有凭证均保留原样。
2. 新增追加迁移 `009_m6_failed_issue_abandonment.sql` 和独立、只追加的失败申请关闭证明。旧 SQL000–008 保持原 checksum；后续 M7–M11 的迁移编号顺延为 SQL010–014。
3. 正式接口 `POST /clusters/:cid/workflows/:id/abandon-rejected-issue` 使用原 execute 的幂等键和明确确认的原 revision、planHash、executionId。当前原执行者的真实控制台会话、已封存且重新读取的关联 Service 的工作流及门户写权限、原封存 Consumer 身份的当前读取权限、当前审批事实及物理端点均需重新校验。门户权限沿用首次申请的 Service 范围规则，tag/entity grant 不被提升为完整工作区。不存在检查只接受由原加密计划、数据库分配及 HMAC 三者一致证明的三个固定 ID，不从客户端提供的 tags/路径或当前名字猜测授权；发现对象存在时停止，不向此接口返回其配置。
4. 仅允许首个 Consumer 创建明确失败、尚无任何成功原生步骤的首次凭证申请：恰好一个绑定该 step 的 failed KONG_VALIDATION_ERROR mutation，后续三个步骤保持原始 pending，grant generation=0、凭证尚未使用、没有任何当前或历史引用/其他相关 mutation。固定 Consumer/ACL/key UUID 必须在原物理端点重新确认不存在；任何未知、部分成功或额外事实都阻止关闭。
5. 同一数据库事务内先执行真实 grant 状态 CAS，再记录实际脱敏审计并插入精确关闭证明；提交时再次核验完整账本与当前权限/租约。原工单、执行、失败原生操作和密钥密文均不修改。grant 为 disabled 且 reservationReleased=true；未发放凭证保留 pending、不能查看或恢复，不冒充已吊销的凭证。
6. 关闭证明是本元数据操作的持久回执；原 execute 回执继续显示 failed。原键和完全相同请求的重复核验返回已提交证明；未知结果只读核验原键，不能换键重发。

该接口无原生写入、普通批准 claim、伪造 IAM direct 操作或 Portal 开发者原生能力。它只关闭已经核验无原生结果的预留身份；下一次正式申请重新分配完整身份，仍须单独审批与执行。

## 自测与实际执行顺序

源码与聚焦安全测试→真实隔离 PostgreSQL 的证据/FK/不可变/回滚/并发验证→独立审阅→三端类型检查→唯一部署者执行仅必要迁移与最小构建/重启→连续性及 API 文档检查→唯一 Security 窗口。

运行时先核验成功的原授权和失败的新执行，私存关闭请求后仅发送一次正式关闭 POST；按原键读取关闭证明并证明旧 failed、原密文、原生和引用计数均保持。随后才提交新的第二个 API 申请，继续剩余代理访问、跨区拒绝、轮换/吊销、生命周期测试。不得重跑已完成的首次元数据恢复或已失败的第二次执行。

所有失败证据、幂等键、请求日志、旧检查点和监控材料继续保存。新增未发放的密钥也纳入私有扫描材料；浏览器、手工操作、清理、最终秘密扫描与 M6 提交仍逐项交接。M7 产品实施继续等待 M6 完整闭环。

## 首次关闭请求的运行账户权限修复

`security-live-pre-fix-failed-issue-continuation.json` 保留491/1：正式关闭请求实际收到503，尚未提交新申请。`failed-issue-abandonment-failure-proof.json` 的原键GET和固定只读SQL确认没有关闭证书、grant仍pending、原failed执行及密钥密文不变；这不是not_sent。`failed-issue-abandonment-database-permission-class.json` 定位本次数据库拒绝为portal_publication_proofs权限不足（SQLSTATE42501）。

具体原因是helper的`FOR SHARE OF p,proof`要求proof表UPDATE权限，而运行角色按设计仅有SELECT/INSERT。已释放的精准源码修复仅锁可变publication的`p`，保持proof表只追加约束、运行角色权限及SQL000–009原checksum。此前正式路径的隔离测试使用迁移owner，未发现这个差异；新增隔离测试必须使用真实非owner、非superuser运行角色执行完整WorkflowService成功、回执重放和数据库约束，先保留旧语句失败基线，再证明修订成功。

为支持故障定位，事务UNKNOWN分支仅记录固定事件、经过校验的UUID和白名单SQLSTATE，不记录原始错误文本、detail、query、请求体、密钥或密文。部署限定API构建及原API进程重启，既有SQL000–009不迁移、不重新授予UPDATE、不重建服务。

原关闭请求的私有started journal与491报告保持。未来独立确认入口须使用新明确handoff：先核验原请求、原键和只读账本；若已有正确关闭证书则只读取核验并继续，若证明仍为未释放且完整事实/原三个固定UUID缺席及当前权限均符合，则独立保存新attempt，最多发送一次完全相同body和原key的关闭请求。它不会重置旧journal、改key、重发原failed执行或重新恢复首个已成功授权。任何新的未知结果继续停止。
