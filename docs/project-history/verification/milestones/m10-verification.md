# M10 配置治理中心技术验收记录

更新日期：2026-10-13（证据时间为 UTC）。**状态：M10 按本记录的证据范围及保留限制通过技术验收。** 功能链、V8 全量源码回归、真实浏览器、逐笔审计、验收环境模式还原及最终实际秘密扫描均已通过，见 阶段验收清单 (`artifacts/M10/milestone-acceptance.json`, not public)。两个扫描预检失败和其他历史失败均保留，没有把未知响应改成成功。M11 尚未编码。`productionDeployment: false`、`commercialAcceptance: false`；技术验收不代表持久生产环境已部署或平台已具备无条件商用资格。

## 验证环境与版本边界

当前验收环境包含两个物理独立的 Kong OSS 1.5.1 网关、各自独立的网关数据库，以及控制台 PostgreSQL 16、Redis 7 和 BFF。数据位于隔离 RAM 环境，`productionDeployment: false`。原有业务服务未修改或重启。

当前验收实现为 V8，API 源码 SHA256 为 `58935a9d38a6e10d205d149e1c4527db230ce8b8d780bfd7ee3725c367de6dd3`。构建、复制、API 重启均成功，readiness 为 200，见 部署记录 (`artifacts/M10/runtime-deployment.json`, not public)。源码指纹包含 API 相对路径、精确字节及 migration 文件；运行 dist 比对单独核对挂载的 migration 与实库校验和。V6 默认发布 / 自然定时、V7 opt-in / 撤权等历史成功证据保留各自候选归属，不因 V8 部署而声称已经重验。治理文档和验收工具增量另外验证，不据此宣称已包含在某次全量测试之中。

两侧 Admin API 均未发布到宿主机端口，分别只向各自网关与 BFF 开放；BFF 未加入任一 Kong 数据库网络。控制台只通过 Kong 1.5 Admin API 管理配置，没有修改 Kong 源码或数据库。插件 schema 继续使用 `/plugins/schema/{name}`，实体和能力仍受实际 1.5 探测结果限制。

## 当前已核对的证据

| 项目 | 当前结果与证明范围 | 公开证据 |
| --- | --- | --- |
| 全量源码回归 | V8 最终第 3 次：406 个测试文件、7,828 项全部通过，零失败、零跳过，246.99 秒，`--maxWorkers=1`。编译期间 API、全量期间测试文件及设置均未变化；三端类型检查和 API 构建通过。V8 前两次失败及 V7 首次资源超时均保留，不修改超时或覆盖失败日志；后续扫描工具修复增量另行聚焦验证，不能声称已经包含在本次全量中 | V8 最终报告 (`artifacts/M10/source-verification-v8.json`, not public)、V8 首次 (`artifacts/M10/source-verification-v8-first-attempt.json`, not public)、V8 第二次 (`artifacts/M10/source-verification-v8-second-attempt.json`, not public)、V7 历史报告 (`artifacts/M10/source-verification-v7.json`, not public)、V6 历史报告 (`artifacts/M10/source-verification-v6.json`, not public) |
| 定向组件回归 | private verifier 5 文件 / 132 项、真实适配器配对 3 文件 / 118 项、验收账本 CAS 3 文件 / 43 项均有通过及日志摘要。独立复核 151 项为代理报告，公开日志指纹不可用，按该限制记录。各组与全量及彼此存在重叠，**不相加** | 定向汇总 (`artifacts/M10/focused-source-verification.json`, not public) |
| 只读 inventory 与权限 | 权限、覆盖、分页、原生传输围栏、调度来源和 private fingerprint 的源码验证已落盘；其中 private-origin 记录为 4 个文件、74 项通过。没有实际网关写入声明 | inventory 源码 (`artifacts/M10/inventory-source-verification.json`, not public)、private-origin 源码 (`artifacts/M10/inventory-private-origin-verification.json`, not public) |
| SQL000–018 与运行角色 | 隔离 PostgreSQL 16 的 20 项检查通过：全 migration 初始化、重复 migration 字节校验、runtime 启动只校验已有 schema，治理 immutable 版本、范围 FK、原键冲突和 timer/CAS 等。SQL fixture 不证明自然调度或原生写入 | 实库结果 (`artifacts/M10/storage-verification.json`, not public) |
| 双网关隔离拓扑 | 10 项检查通过：两个独立健康网关及数据库、第二网关 bootstrap 成功、Admin 端口不发布、BFF 不连 Kong DB、两侧 Admin 网络独立、BFF 实际读到 1.5.1 | 拓扑结果 (`artifacts/M10/topology-verification.json`, not public) |
| 治理 metadata 审批 | 目标集群规则创建、修改、软归档、恢复共 4 个实际工单；由独立审批人批准、原提交人执行；记录明确 `nativeKongWrites: false`，未改变源定时策略 | 审批结果 (`artifacts/M10/metadata-approval-verification.json`, not public) |
| 默认治理真实 BFF / Kong 核心链路 | 主报告 `passed: true`、`phase: native-m10-core-passed`，记录 47 条**累计断言**、88 个原写请求；包含多次接续的重复检查，不是 47 个独立验收条件，旧失败也保留在请求历史中 | 核心结果 (`artifacts/M10/native-verification.json`, not public) |
| 默认 Promote 实际结果 | V6 全新 comparison → plan → generic M8 apply 完成；Root 已核对目标 2 个实际 native 步骤。目标 Service/Plugin 的安全配置与源一致，目标原生 ID、Route 环境字段及原凭证保留。目标原 API Key 代理返回 200，源 API Key 在目标代理返回 401 | 核心请求与断言 (`artifacts/M10/native-verification.json`, not public) |
| 显式 key-auth 发布 | V7 全新比较与计划，从真实分页资源选择器选择没有普通字段差异的 Consumer；仅复制选定 key-auth，目标分配独立新 UUID，实际 1 个 native 步骤。目标代理接受复制凭证并保留原凭证；源凭证在源代理仍可用。执行关联精确、不可变的执行前目标快照 v1 | key-auth attempt 2 (`artifacts/M10/native-optin-key-auth-attempt-2.json`, not public) |
| 显式秘密插件配置发布 | 禁用的 AWS-lambda 在显式秘密授权下完成 1 个实际 native 步骤，保留目标 UUID 与 Route 绑定；默认插件、比较和计划投影均未输出真实秘密。仅验证配置迁移，不宣称 AWS 运行时或外部服务联调 | 秘密 opt-in (`artifacts/M10/native-optin-sensitive-plugin-attempt-1.json`, not public) |
| 完整执行前快照回滚 | V8 新预览 → 明确确认的 generic M8 apply 完成 2 个实际 native 步骤；复制 key-auth 与后加的 AWS-lambda 进入回收站。还原精确执行前目标快照后，原目标 API Key 代理 200、复制源 Key 在目标代理 401、源 Key 在源代理 200。四个 opt-in phase 均通过，但各报告的累计检查不相加 | rollback attempt 3 (`artifacts/M10/native-optin-rollback-attempt-3.json`, not public) |
| 执行前来源变化拒绝 | 计划封存后修改真实来源秘密，原 generic M8 apply 返回 409；实际只读控制台观察证明该拒绝请求未创建目标 job / mutation / native started / completed。接续只消费原 409，再独立恢复源配置，不重发拒绝请求。该用例验证 apply 前变化，不证明发包中的竞态 | stale-source attempt 2 (`artifacts/M10/native-optin-stale-source-attempt-2.json`, not public) |
| 自然定时正例 | 10 项检查通过：真实 5 分钟巡检和漂移政策自然到期，按原 owner/version/occurrence 唯一运行并封存完整报告；调度来源 SID 为 null，原请求审计关联完整，0 native mutation / 配置 job。未改时钟、强制 tick 或伪造 SID | 自然定时 (`artifacts/M10/timer-verification.json`, not public) |
| 来源撤权与定时负例 | 独立非 super-admin 用户持有两个不相交工作区角色；只撤源绑定后源访问 / 原计划读取与 apply 均被拒绝，目标访问和原安全回执仍可读；实际 0 目标 job / native mutation。原自然到期 occurrence 为 `paused_authority`、无关联分析 run；独立恢复角色不执行旧计划、不重启旧 occurrence | 撤权执行拒绝 (`artifacts/M10/native-authority-verify-attempt-1.json`, not public)、定时拒绝 (`artifacts/M10/native-authority-timer-observe-attempt-1.json`, not public)、独立授权恢复 (`artifacts/M10/native-authority-restore-attempt-1.json`, not public) |
| 实际来源绑定与 SQL018 约束 | 8 项检查、10 次全部回滚的修改试验通过：实际 Promote actor/source/target/material/job/plan 关联，4 个实际 metadata 工单秘密意图及 0 native 行，不可移除 marker / 重绑定 / 修改 / 删除 / truncate，伪造与无效材料拒绝、deferred FK。观察前后摘要相同；只读核验不推断额外 native 成功 | 来源存储专项 (`artifacts/M10/origin-storage-verification.json`, not public) |
| 漂移阈值与 M7 站内通知 | 实际比较越阈值审计 → 唯一 `config.drift` 事件 → dispatched outbox → 当前用户通知，在实际数据库及 BFF 中精确关联，0 native mutation。没有外部渠道投递声明 | HTTP 观察 (`artifacts/M10/drift-notification-http-verification.json`, not public)、实库关联 (`artifacts/M10/drift-notification-verification.json`, not public) |
| 真实浏览器 | 15 项检查、7 张截图通过：真实报告 / findings、规则版本、调度、加载后的 2 条漂移修改、无普通字段差异的 Consumer、凭证选择器、默认排除及确认、明暗 / 移动端；无脚本错误，不直连 Admin。最终周期 0 新浏览器写请求，保留原 2 次实际 login 201 / 0 unknown；真实同 SID 续签在 Root 独立原键账本中完成，经实际 GET `/auth/me` 核验，未伪造 token 或重新登录 | 最终页面验证 (`artifacts/M10/browser-readonly-recheck-attempt2/verification.json`, not public) |
| 逐笔业务审计 | 8 项实库检查通过，98 / 98 个成功业务请求准确关联原 actor / IP / tenant；309 条相关审计逐条 RFC 6902 redacted before→after 校验，30 个已完成 native mutation 独立覆盖，保留 21 个失败原请求、0 个 unknown 业务响应。源 / 目标 / global 共 3 条链和 1,323 条链记录核验，BFF 有界分页完整接续；runtime UPDATE / DELETE / TRUNCATE 的 3 次试验均拒绝并回滚。没有回填历史审计或豁免 M9 历史缺口 | 审计结果 (`artifacts/M10/audit-verification.json`, not public) |
| 原集群执行模式还原 | 通过实际 BFF 读取最新 revision，源集群由 direct 恢复原 approval，revision 8→9，原 HTTP 200，0 native Kong 写；没有用旧 revision 或修改数据库恢复模式 | 模式还原 (`artifacts/M10/environment-mode-restoration.json`, not public) |
| 最终实际秘密扫描 | **通过**，14 项检查，266 个实际保留秘密、881 个字面 / 常见编码模式，318,423,722 字节；仓库 3,775 文件、API dist 262、Web / Portal dist 各 5、10 个自有容器完整 stdout / stderr、1 组两集群及 global 实库审计，共 0 findings。精确控制元数据只在收集器副本规范化，真实凭证字段保留，无泛化 UUID / 失败密码豁免；实际扫描保留合并材料中的 1 个原 M9 auth-only unknown，未解决 / 重发 | 实际扫描结果 (`artifacts/M10/secret-scan-verification.json`, not public)、精确控制元数据来源证明 (`artifacts/M10/secret-control-id-classification-beforefix.json`, not public) |
| 全量后的证据工具增量 | Node IAM 审计工具 5 / 5 独立检查及扫描工具 4 / 4 聚焦检查通过，记录真实退出值与日志 / 文件摘要。均不计入 7,828 全量测试，不修改平台 API / SQL 或补写原审计 | 审计工具补充 (`artifacts/M10/audit-tools-supplemental-verification.json`, not public)、扫描工具补充 (`artifacts/M10/secret-tools-supplemental-verification.json`, not public) |

SQL017 校验和为 `677510dd14357029d4e69933c295472c1600e0c31ff7e75a869a52ca82846ec8`；SQL018 校验和为 `41c60fea0f26f9e2758acdae2c39a71e7945a27c53ed6159e26bff2574ad92d7`。已经部署的 migration 内容未通过“重新编号”或改写旧校验和绕过验证。首次和第二次存储尝试分别保留在 首次记录 (`artifacts/M10/storage-first-verification.json`, not public) 和 第二次记录 (`artifacts/M10/storage-second-verification.json`, not public)，最终 20 项结果作为当前存储证据。

V8 最终测试文件指纹为 `4b30cea1e2fb0f61709950b02b32eb2c9d8ee3f421bfe4f383ac018b57fe1155`；API 指纹与已部署 V8 相同。计数均针对各自证据范围：native completion 30 包含验收夹具及实际变更，并非 30 个独立功能；浏览器 15、审计 8、全量 7,828 与各聚焦套件不得相加。

## 默认核心闭环的实际范围

真实 BFF 请求已验证自定义 Lint 规则直接创建、修改、克隆、软归档、恢复和旧 revision 拒绝；巡检报告与签名游标分页；owner 问题定位 → 实际 M8 修复计划 → native apply → 新巡检确认问题消失；策略创建、暂停、恢复及不可变版本；双环境按逻辑身份比较不同原生 UUID；只读写入、伪造证明、跨工作区和其他调用人的原键读取拒绝。

目标环境 host 在比较后发生变化时，旧 Promote 被新负例实际验证为 409，未生成执行计划；随后通过明确的环境恢复及新比较继续。默认 Promote 不包括凭证、秘密和环境字段，采用目标当前执行模式及真实目标 baseline，保留原对象 ID 和目标未选配置。通过通用配置 apply 入口执行时仍保留 Promote 来源，客户端不能用 `approved` 或 decK driver 绕过该来源围栏。

真实默认 apply 成功请求 ID 为 `57a88a8f-e37b-42c2-8d2c-07fa4b0e3afe`，原响应为 201。它属于全新的比较与发布周期，不是对任一旧失败请求的补写成功。显式 key-auth 执行的实际来源关联、执行前快照与真实回滚已核验；逐笔业务及已完成 native 审计关联另由上述实库审计证据验证。

凭证 opt-in 当前实际网关证据是 key-auth，不扩展为六类凭证已经分别通过跨环境迁移和回滚。秘密插件发布和来源变化两份报告包含先前阶段的累计检查，也不重复计数。

## 保留的原失败与纠错链

原始 HTTP 响应、原 key、持久作业事实和后续独立验证分别保留。错误修复后不把原 500/403 改成 2xx，不延长旧计划、不重新发送未知结果，也不回填历史审计。

| 原请求 / 问题 | 实际持久事实 | 修复后的验证方式 | 证据 |
| --- | --- | --- | --- |
| 巡检 `80ea8a86-4fb4-4a69-8b9c-94e536ef6400` 返回 500；规则元数据含引擎不接受的属性 | 原 run 为 uncertain，实际 native mutation 为 0；原请求与失败两笔审计均有来源 IP | 固定映射到规则引擎六个字段；保留原失败，通过独立新巡检验证。未把旧 run 改为 succeeded | 原失败证明 (`artifacts/M10/native-inspection-beforefix.json`, not public) |
| 比较 `7251b43a-3149-4481-835f-49d9d0118913` 返回 403 / `KONG_INTERNAL_SCOPE_MISMATCH` | 比较已经实际封存，run succeeded、quality complete、native mutation 为 0；材料为 V1 legacy envelope | 修复目标历史权限读取的固定只读桥接；另一个 GET 对原 key 确认已封存事实。原 POST 仍为 403；新的 Promote 采用独立新 V2 比较，不把 V1 追认成新 raw-map 证明 | 原比较 ACK (`artifacts/M10/native-comparison-original-ack.json`, not public) |
| stale-target planning `ef1f171b-1608-4ad1-a946-f9599c5fdfbe` 返回 403 / `KONG_ACTOR_SCOPE_MISMATCH` | 原 promotion 为 blocked，实际控制台只读观察证明 0 configuration job、0 mutation、0 native started/completed | 修复固定 planning bridge 后，以独立新 negative intent 验证目标变化确实阻止发布，原 403 不重放 | 原 planning 证明 (`artifacts/M10/native-target-planning-beforefix.json`, not public) |
| 默认 apply `4ae3ec3a-0557-4852-8ced-93093486cf9a` 返回 403 / `KONG_EXECUTION_CONTEXT_EXPIRED` | 实际只读观察证明 0 job、0 mutation、0 native started/completed | 修复 origin 外层身份锚点后另建执行 intent；旧响应不重写，旧 key 不重放 | 原 apply 证明 (`artifacts/M10/native-apply-origin-beforefix.json`, not public) |
| V5 默认 apply `012e4d52-c20c-4673-96f2-d5fc8779d0c5` 返回 403 / `KONG_EXECUTION_CONTEXT_REQUIRED` | **实际存在 1 个 failed、带来源 marker 的配置作业及其复制计划、execution；不能写成 0 job。** job remote flags 为 false，mutation/native started/completed 均为 0；原 input plan 已实际过期 | V6 的只读 observer 核对真实来源 bindings、执行/快照关联、SQL 校验和及同一只读事务 snapshot digest。V5 失败时源码与 V6 观察时源码分开记录。保留原 failed job 与过期计划；V6 全新 comparison/plan/apply 验证成功 | 新周期前置证明 (`artifacts/M10/native-default-cycle-beforefix.json`, not public)、原 V5 部署 (`artifacts/M10/runtime-deployment-before-m10-candidate-v6.json`, not public) |
| V6 key-auth plan `f3bf1426-9685-4c4b-ba4e-15f015423683` 返回 409 / `CONFIGURATION_ORIGIN_PRIVATE_SOURCE_CHANGED` | 来源六类原生字段指纹、范围、版本和围栏材料核验有效；内部两个真实 1.5 adapter 标识不同，目标未登记执行 job / native mutation | 仅接受两个固定、实际 1.5 内部标识，仍拒绝未知或跨版本组合。新比较与新计划以独立意图在 V7 通过，原 409 不重写 | 适配器原失败 (`artifacts/M10/native-optin-source-adapter-beforefix.json`, not public)、新周期前置证明 (`artifacts/M10/native-optin-key-auth-fresh-beforefix.json`, not public) |
| stale-source apply `cc121f71-05d6-4aaf-b8d2-97ff9488d7b9` 已实际返回 409 后，验收工具对缺失 data 做秘密检查时发生 TypeError | 原拒绝响应与键已保留；接续实际只读观察确认 0 目标 job / native mutation | 工具只修正空数据序列化，接续读取原 409，独立恢复源配置；没有再次 apply | 工具停止记录 (`artifacts/M10/native-optin-stale-source-attempt-1.json`, not public)、接续验证 (`artifacts/M10/native-optin-stale-source-attempt-2.json`, not public) |
| V7 rollback preview `21454f65-9098-4b84-aa1c-3f1afaa6a275` 返回 409 / `CONFIGURATION_DIFF_SCOPE_MISMATCH` | **实际存在 2 个 job**：compare failed、fresh baseline capture succeeded；两者 native flags 均为 false、mutation 为 0。旧快照 v1 与新 baseline v1 的范围、1.5.1 版本、adapter、enabled 集合、完整性、manifest 均有效；15 个实体 schema 和公共插件 schema 相同，只有当前新增 AWS-lambda schema | V8 从旧快照实际期望插件名单，在同一真实有界 baseline capture 加载所需 schema，允许回滚删除当前独有插件；旧快照不改写。新意图独立预览 / apply 已通过，原 409 保留 | 原 rollback attempt (`artifacts/M10/native-optin-rollback-attempt-1.json`, not public)、实库 schema 诊断 (`artifacts/M10/native-rollback-schema-beforefix.json`, not public)、新意图前置证明 (`artifacts/M10/native-optin-rollback-fresh-beforefix.json`, not public)、原 V7 部署 (`artifacts/M10/runtime-deployment-before-m10-candidate-v8.json`, not public) |
| V8 新 rollback preview `4b5b4f25-1bc4-4517-9865-ad6e51fc14ad` 已返回 201 后，工具在 apply 前发现访问会话剩余时间不足 95 秒而停止 | 新 preview 的真实 201 / 原键已登记，尚未发出 apply；未改写成失败预览 | 明确同 SID refresh 201 后串行接续，消费该原成功 preview，不重发预览；新的 apply `42a2acaa-4a36-4f8a-80ef-78fe020db751` 返回 201 并完成回收与实际认证核验 | 工具停止 attempt 2 (`artifacts/M10/native-optin-rollback-attempt-2.json`, not public)、接续通过 attempt 3 (`artifacts/M10/native-optin-rollback-attempt-3.json`, not public) |

前五次核心验收停止记录依次保留为 attempt 1 (`artifacts/M10/native-core-attempt-1.json`, not public)、attempt 2 (`artifacts/M10/native-core-attempt-2.json`, not public)、attempt 3 (`artifacts/M10/native-core-attempt-3.json`, not public)、attempt 4 (`artifacts/M10/native-core-attempt-4.json`, not public)、attempt 5 (`artifacts/M10/native-core-attempt-5.json`, not public)。最终主报告通过默认核心路径，不能据此隐藏这些原始失败。

非 super-admin 撤权 bootstrap 的 首次工具停止记录 (`artifacts/M10/native-authority-bootstrap-attempt-1.json`, not public) 也保留；问题是工具错误要求创建账号后的 `forcePasswordChange` 必须为 true。接续按实际布尔值验证，仍完成真实密码修改、旧会话撤销与重新登录，见 第二次 bootstrap (`artifacts/M10/native-authority-bootstrap-attempt-2.json`, not public)，没有放宽平台权限。

浏览器验收另外保留三个已关闭失败周期：原周期 (`artifacts/M10/browser/verification.json`, not public) 在 4 项检查 / 4 张截图后被 Ant Design readonly combobox 上的选中元素拦截；新 Select 周期 (`artifacts/M10/browser-after-visible-select-fix/verification.json`, not public) 真实报告 / findings 读取成功，但全页背景 spinner 的默认 5 秒等待在首项检查前超时；首次只读复核 (`artifacts/M10/browser-readonly-recheck/verification.json`, not public) 已完成 8 项 / 5 张后，被尚未关闭的 Drawer 拦截主题按钮。三者均为实际工具交互 / 就绪等待问题，原状态、请求及截图不重写。最终使用可见 Select 容器、当前区域 30 秒就绪检查和无 comparisonId 的实际页面关闭 Drawer；检查真实行数据和动画稳定后截图。旧访问 token 已自然过期时，Root 用真实原 refresh Cookie / CSRF 单独执行同 SID refresh 201，再以真实新 Cookie 完成只读复核；没有延长 token、伪造 SID 或重发旧登录。

秘密扫描的 第一次预检失败 (`artifacts/M10/secret-scan-verification.attempt-1.json`, not public) 与 第二次预检失败 (`artifacts/M10/secret-scan-verification.attempt-2.json`, not public) 都是 0 文件 / 0 字节，空 findings 不曾作为零泄漏证据。修复将有精确原键 / 请求 / 字段及固定来源证明的控制元数据从收集器副本的错误秘密上下文中区分，原私有包、原账本和实际 credential 字段保持不变；没有添加一般 UUID 排除或失败密码豁免。第三次真正执行扫描，原失败不被改为 passed。最终报告 SHA256 为 `7047ebd66c1dbee77119620c8d94a71f660e7cafd0ae7274be31d619c4046070`。

## 验收账本并发事件与证明限制

2026-10-13 06:53:45–49 UTC，操作者同时运行撤权验收与手动 refresh，两个进程保存同一私有验收账本。一笔实际 HTTP 201 的 **auth refresh** 回执和该次签发 token 材料被另一进程的旧快照覆盖。平台的原成功审计仍在，业务写请求账本保留，实际 native mutation 为 0；未凭空补回原 HTTP 包或 token。随后按串行操作退出旧会话并重新登录，实库确认旧会话 revoked、新会话 active，见 并发事件核验 (`artifacts/M10/auth-journal-concurrency-verification.json`, not public)。

验收工具现在以私有文件摘要 CAS、短互斥和独占临时文件保存，陈旧写入在请求发出前拒绝，定向结果见上述 CAS 组。后续仍严格单写者执行。**最终秘密字节扫描只能覆盖实际保留的材料**：被覆盖的这一次签发 token 已不可获得，不宣称全历史 token 扫描完整；此限制与平台业务审计覆盖分别判断。不能把平台审计保留当作原测试 HTTP 包或 token 已恢复。

当前 M10 业务审计为 0 unknown 业务响应；实际扫描合并当前与历史材料后仍保留 1 个 **原 M9 auth-only `response_unknown`**，`unknownOriginalResponsesResolved:false`。其原状态未修改，原 HTTP 包未重建，原请求未重放。这个历史未知认证响应与 M10 上述已观察 201、但测试账本被覆盖的 refresh 是分别保留的限制；不能因为 M10 业务审计通过而宣称所有历史 unknown 已解决或全部历史 token 已扫描。

## 阶段结论与后续落盘

| 项目 | 结论与边界 |
| --- | --- |
| 技术阶段 | 功能 / 来源权限 / 定时 / 存储、源码、浏览器、审计、环境还原及实际秘密扫描均通过；按公开清单标记技术 accepted。证据计数不相加，历史失败 / 未知 / token 材料缺口不回填或隐藏 |
| 阶段落盘 | 由 Root 以最终证据清单冻结本地 M10 commit，再按顺序启动 M11；API / SQL 保持 V8，后续证据工具聚焦增量单独记录。阶段技术通过不表示仓库已发布生产镜像或完成持久站点准入 |

## 后续阶段与商用判断

M9 已独立技术验收；M10 按上述证据范围与限制通过技术验收。M11 仍按 [实施计划](../../milestones/m11-implementation-plan.md) 排队，尚未开始编码；本地 M10 commit 落盘后，才进入多级审批、会签、计划执行、变更窗口、执行前快照、逐步日志、回滚及通知的 M11 闭环。

最终商用判断针对 KongPilot 管理平台自身：仍须完成 M11 和整体发布安全回归、正式发布镜像与 CI/CD、持久生产部署、控制台存储与密钥备份及异机恢复、运行监控、运维部署手册和终端用户手册验收。当前隔离 RAM 技术验收不能证明这些生产条件已经具备；外部 LDAP/OIDC、SMTP、Slack、飞书等未获得真实配置的服务，不宣称完成外部商用联调。
