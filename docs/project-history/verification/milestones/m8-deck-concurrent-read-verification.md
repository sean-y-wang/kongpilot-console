# M8 decK 并发读取修复验收

最新状态（2026-10-12）：M8 实际功能、固定官方 decK 1.2.4 diff/sync、12 项浏览器操作、审计、软清理与最终秘密扫描已通过。见 [阶段进展](../../milestones/m0-m8-stage-delivery.md) 与仓库 artifacts/M8/m8-final-acceptance.json。M0–M8 独立生产验收正在执行；下方历史阶段的“待验收”不代表最新结果，生产恢复通过前不宣称生产就绪。

本记录覆盖 decK 1.2.4 读取 BFF 配置协议时发现的连接池耗尽问题。最终工具验收仍要求在固定镜像、正常 BFF 地址上完成实际 diff/sync；诊断代理和隔离测试不替代该验收。

## 原始结果与诊断

- `security-live-deck124-compatibility.json` 保留首次真实失败，SHA `498e34f2e222e898b74f5ececbd433fc31407c9e122ffc71a66f1d8a2e5e186a`。完整 YAML 的 validate 成功；在线 diff 失败，未执行 sync。
- 独立只读诊断 (`artifacts/M8/deck124-diff-readonly-diagnosis.json`, not public) SHA `f55b8f68d32beb11d307a5414ab1fa0840e68835a51972274b1e63b181fa1fa2`：根路径 200、版本 1.5.1；16 类集合同时请求中出现 200/503 混合结果。`mtls-auths` 本地返回 404，不调用 Kong，也不提供该凭证类型 CRUD。
- 窄日志诊断 (`artifacts/M8/deck124-diff-bounded-log-diagnosis.json`, not public) 未提供可用异常原因。未知异常由专用协议过滤器归一为 `DECK_REQUEST_FAILED`；不能从缺失日志推断没有连接池错误。

## 修复前真实数据库复现

隔离 PostgreSQL 复现 (`artifacts/M8/storage-deck-pool-beforefix-postgres-20261011-01.json`, not public) SHA `b38dbf6cb7e0cb6555f5a96faeb752840b855b04ef81a4c998978ad3fe262c16` 使用冻结的修复前源码和真实 DbService、ConfigurationAccess、Authorization、WorkspaceResolver、ConfigurationRepository。固定池上限 10、连接获取超时 5 秒。

16 次 `readDeckSession` 并发请求在屏障处确实占满 10 条事务连接，另外 6 次排队。9 条事务等待同一会话行锁；持锁事务的权限检查却申请全局池的新连接。结果为 9 次成功、7 次真实连接获取超时，耗时 5,797 ms。没有主动取消查询。测试使用自己的结构化账号、会话、角色与比较任务，注册审计回调是显式测试夹具；没有登录、业务 HTTP、Kong 调用或生产数据库变更，测试容器已移除。

## 修复边界与后续验收

权限查询显式接收调用方事务，当前用户、会话、IAM 版本、完整权限集合、集群与工作区查询均复用该连接。权限判断、行锁、令牌、会话期限、SQL 000–011、10 条连接上限及 5 秒超时均保留。

修复后 真实 PostgreSQL 验证 (`artifacts/M8/storage-deck-pool-afterfix-postgres-20261011-01.json`, not public) SHA `dcb23c8c4b6e1ca1df4f96e9f1f228972ad5dd40ae2b2a0b0a43c8c00f4c691c` 的 7 项检查通过。相同屏障、连接池和行锁下 16/16 请求成功，用时 665 ms；真实角色撤销拒绝原句柄、会话令牌和冻结 DAG 读取，撤销原 SID 也会拒绝新句柄。没有 Native 变更，临时容器已清理。

API 类型检查、构建与 89 项相关单元测试通过；完整源码测试 5,890/5,890 通过，无跳过。统一源码冻结 (`artifacts/M8/root-deck-pool-transaction-fix-freeze.json`, not public) SHA `c76114ad109ee0167d7917c0df2ab7b702f797a57a4cb1de74c5c29fe97d8e8d` 绑定全部 222 个 TS/JS 文件，只有上述 3 个提供者变化，其余 219 个 JS 保持一致。前端、门户、SQL、工具和边缘配置保持一致。

实际 API 重载连续性验证 (`artifacts/M8/deck-pool-transaction-api-repair-continuity.json`, not public) SHA `13c50a12d4ef8ce45ae88254eaa4b238f3cd44fc441d59bf1c16c48ee0a7ff3b` 的 36 项检查通过。仅重启现有 API 进程一次，验证 222 个安装文件及健康状态，保留 22 个容器、18 个健康服务、原监控凭据及代际、迁移校验和、Bootstrap、两个固定 decK 镜像和前端/门户资源。

## 标准地址读取与导入差异

修复实际加载后，固定 decK 1.2.4 在标准 `http://console-web:8080` 地址上的真实 `diff` 返回 exit 0，stderr 为零；未经过诊断代理。随后导入预览返回两个修改，严格的单步断言停止了流程，未发出 apply、write-session 或 sync。原失败报告 (`artifacts/M8/security-live-deck-pool-transaction.json`, not public) 为 1,797 通过、1 失败，SHA `e9cb06daab60aa77e69ab665d9cad2bdfe7e499b8bb34037da5cd081b9cd079a`，保留原件与原两步方案。

独立只读诊断 (`artifacts/M8/import-sync-second-change-readonly-diagnosis-continuation.json`, not public) 17/17 通过；原对象与 YAML 核对 (`artifacts/M8/import-sync-optional-null-readonly-proof.json`, not public) 8/8 通过。实际 Upstream 的 `healthchecks.active.https_sni` 为 null，导出和导入 YAML 都省略该可选字段，而且两份 Upstream 内容完全相同。额外方案步骤却移除了该字段。诊断零 Auth、业务、Native 或 CLI 写入。

导入的 `merge` 模式现按实际 schema 递归合并实体 record：保留未提供的子字段，显式 null 仍可清空；数组、set、map 和 foreign reference 仍整体替换。插件原有配置语义和完整快照回滚保持。使用真实 Kong 1.5.1 Upstream schema 的回归测试验证完整导出导入无额外修改、只改 Service 重试次数时严格仅一步、数组替换、显式清空和精确回滚。相关 243 项测试通过、零跳过，API 类型检查和构建通过。新源码冻结 (`artifacts/M8/root-deck-record-merge-fix-freeze.json`, not public) SHA `789d22d72cd7ca11fce9eb9a19a5e5de7d1d8ce6edb7f982dc1d652e4088fe87` 仅改变一个 API JS，其余 221 个、Web、Portal、SQL 和边缘配置一致。

导入修复已实际加载，连续性检查 (`artifacts/M8/deck-record-merge-api-repair-continuity.json`, not public) 36/36 通过，SHA `ec8c727cc50388fb76ff65d02cd59ffcbebc79cd62ad84e4d64716c9004e5570`；最新完整源码测试 (`artifacts/M8/root-whole-source-deck-record-merge-unit.json`, not public)为 5,941/5,941、756 套件、零跳过，SHA `f2f66d9990406edc16e7b1f47b4a1def0d0031de8f64fe076652f69619d45806`。独立新预览、未发送的 sync、代理凭证验证、UI、审计与安全清理仍须完成。已经成功的标准 diff 和旧失败 import 不重放；未完成项不计为验收通过。


## SDK 完整更新对象与初始执行回执

record merge 修复加载后，新的真实导入预览只包含 Service 的 `/retries` 修改，无 Upstream 修改。原 apply 返回 201 并创建 job-local 计划及执行，但初始回执未暴露 driver/executionId，且旧验收 helper 错将源计划 ID 与执行计划 ID 视为相同。该次真实报告 (`artifacts/M8/security-live-deck-record-merge.json`, not public) 为 1,842 通过、1 失败，原件保留，未发出 write-session 或 sync。

独立只读诊断 (`artifacts/M8/running-deck-apply-readonly-diagnosis.json`, not public) 21/21 通过，确认原执行仅有一个 pending 步骤，operationId 为 null，无开始时间、无验证成功。未从 pending 状态推断 Kong 写入成功。原任务需由原账号、原会话、当前权限和服务端过期确认意图进行显式收口；任何 API 重载必须在此之后。

固定 SDK 合成协议证明 (`artifacts/M8/deck-service-put-source-proof.json`, not public) 使用真实 decK 1.2.4 二进制和隔离回环协议服务，证明 Service 更新 PUT 会带上 host、name、protocol、port 和超时等完整字段。旧执行器只匹配 `{retries: 2}`，因此尚未发送的 sync 会被拒绝。合成证明不计入真实 Kong 验收。

新源码为计划步骤增加可选 `deckWirePayload`，由编译器从 schema 规范化后的有效对象生成，存入既有加密计划并纳入计划 HMAC。SDK 提供的每个字段必须与该封存对象相同；计划变更字段仍必须显式提供且相同，包括 null。发往 Kong 的仍是原封存 Native delta。历史计划缺少该字段时保留原严格匹配，不会原地升级。Basic keep-password 的 SDK 校验使用可信恢复材料中的明文，原 Native hash/before 和不重写密码的 delta 保持一致。

初始进度保存通过白名单校验的 driver；回执通过数据库 JOIN 校验 job、cluster、workspace、actor 及完整 job-local plan ID/revision/hash，从真实 execution 行投影 executionId，覆盖进度 JSON 中任何不可信 ID。定向源码测试 (`artifacts/M8/root-deck-wire-second-unit.json`, not public) 135/135 通过，无跳过，API 类型检查和构建退出 0。此时修复尚未加载，真实 sync、M8 浏览器验收及生产验收仍待执行。


原 prepared 执行实际收口 (`artifacts/M8/deck-prepared-execution-close.json`, not public) 42/42 通过，SHA `c93b256159ab4b8486088cf64943054b483bf0ad16a5395969bce402b4dd3498`。原 145 个请求和失败报告字节保持一致，仅新增一次必要的原 SID refresh 与一次 typed abandon；原 job 保留 uncertain、0 completed/1 unresolved，步骤 operationId 仍为 null，current Service retries=0。此“未签发写请求的 prepared 步骤”与先前 C2 的一个 Native 未知结果分别记账，没有宣称 Native 成功，也没有重放 apply/sync。

修复源码冻结 (`artifacts/M8/root-deck-sealed-wire-body-fix-freeze.json`, not public) SHA `99a8c42cacfb65850467886969cf309478b43724715d850a8155e6520ad45152` 绑定 223 个 TS 与 223 个编译 JS，两个 JS 修改、一个查询 JS 新增，其余 220 个保持一致；SQL、Web、Portal 和边缘配置保持一致。完整源码首轮为 6,101 通过、3 个旧测试夹具失败，无跳过；失败夹具缺少真实访问描述中的 actor，已补齐 owner 和持久化 executionId，相关 26/26 测试通过。首轮失败报告保留，最终全量复跑仍待进行，不能把首轮写成全量通过。


修复实际加载连续性 (`artifacts/M8/deck-sealed-wire-body-api-repair-continuity.json`, not public) 36/36 通过，SHA `87329ea75d28601766aeee34326dd2fb47845b85fd683081b4b2e7ba9fab92e4`。安装的 223 个 JS 与冻结一致，仅重启现有 API 进程一次；22 个容器、18 个健康服务、SQL 000–011 的 checksum/applied_at、Bootstrap、12 组监控凭据及代际、Web/Portal/edge 和两个固定工具镜像保持连续。零构建、镜像重建、迁移、其他服务重启、Auth、业务写、Native 或 CLI 执行。真实独立 sync 仍需下一次实际报告，36 项重载检查不计作 sync 通过。
