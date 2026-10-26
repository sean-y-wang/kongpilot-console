# KongPilot M11 与整体商用验收执行清单

> **2026-10-26 01:16 UTC+8 最终结论：`commercialClosed=true`（owner 批准）。** 验收对象 `v1.0.0-rc.2`（8ea549e），正式复扫 CI 40200167285（grype 0.120.1，39/39），单次完整回归见[进度 §52/§53](../milestones/checkpoints/2026-10-23-m11-continue-phase1.md)。范围为企业内部部署；写入 SLA 与异地容灾不在范围内，业务/实体定时为可选开关（生产默认关闭），审批人具备集群写权限时可执行自己批准的工单（见 operations/approval-execution-separation.md）。以下历史更新保留原文。

> 2026-10-20 最新检查点：门户自然初次发证/代理 200/独立审批吊销/代理 401 分项通过；519d052 对应独立 CI 全量测试超时，镜像跳过。SQL041/042 尚未合入部署，M11/商用仍未通过。目标、方案、13 项卡点与两批计划见 [全量研发检查点](../milestones/checkpoints/2026-10-20-project-checkpoint.md)。下文历史更新按各自时点读取。

> 2026-10-20 14:33 UTC 更新：当前修复399项专项回归通过；前一提交0484980的独立CI重验为16,335通过/5项超时失败、0跳过，镜像验证被跳过。不能登记完整源码、镜像或商用验收通过。详见[进展 §24.19](../milestones/checkpoints/2026-10-15-m11-continuation.md)。

> 2026-10-20 14:26 UTC 更新：当前部署的新门户工单 `bae65a07` 已完成 Consumer、ACL、Key 三个 Native 写入和回读，最终激活步骤触及原500次调用上限，终态partial。控制台grant/credential仍pending，不能据此认定Kong凭证不存在或已经失效；未揭示凭证、未进行鉴权/吊销验收、未重放原写入或延长claim。原始终态 (`artifacts/M11/runs/20261020-followup/receipt-application-terminal-readonly-original.json`, not public)。下一项修复聚焦最终激活的重复校验读取，完整M11与商用门禁仍未通过。

> 2026-10-20 14:13 UTC 更新：门户激活的 schema 比较阻塞已通过新工单实测解除；首个 Consumer 已有 Native 成功回执，但工单随后因回读误认回执格式而 partial，原事实保留。回执格式修复与 Service 预检查优化联合262项通过、已部署；新的普通Service工单实际Native201及回读通过。门户完整签发/鉴权/吊销仍待。源码CI上一轮16,340项通过，本轮0484980测试阶段15分钟超时，镜像作业未运行，不能登记当前完整CI或商用通过。详见[进展 §24.17](../milestones/checkpoints/2026-10-15-m11-continuation.md)。

> 2026-10-20 11:20 UTC 更新：新Portal申请已跨15分钟完成排程、独立审批与自然领取，但首个Consumer响应后复核失败，原工单/执行/mutation保持uncertain，未发证或重放。CI剩余4文件已作定向修复（145项通过），安全诊断106项及API类型检查通过，均待后续部署/远端复验。按最新要求先完成研发，再集中全面验收；整体商用仍未通过。见[最新进展 §24.15](../milestones/checkpoints/2026-10-15-m11-continuation.md)。

> 2026-10-20 更新：P6 门户修复与失败请求审计已部署至验收实例，联合专项381项通过，真实失败审计及2,192行/3链核验通过；新门户工单已申请，待自然排程、发证与吊销。完整M11和商用门禁仍未通过。详见[最新进展 §24.14](../milestones/checkpoints/2026-10-15-m11-continuation.md)。

> 2026-10-18 13:37 UTC 更新：整体商用仍未通过。实际验收API已部署普通全图回收V3候选 Source `4118a2be`、384JS、SQL000–040共41条，真实五类恢复尚待。V3前固定源码本地完整回归675文件15,981项全部通过；同一checkpoint在GitHub独立环境15,883通过/98失败、无超时，失败不可被本地结果覆盖，正在增加安全诊断并定位。真实PCRE26组代理对照通过；插件required-record修复后Native201及回读通过。原失败prepare发现审计遗漏，新失败审计仍在研发，历史记录不补造。SQL041/042未正式部署，Portal/配置自然执行及生产镜像等门禁继续保持未通过。详见[进展 §24.13](../milestones/checkpoints/2026-10-15-m11-continuation.md)。

更新日期：2026-10-18。**当前结论：M11 整体验收未通过，平台整体商用准入未通过。** 本文是后续执行清单，不是通过证书。实际结果持续追加到 [M11 验证记录](../verification/milestones/m11-verification.md) 和 [本轮进度](../milestones/checkpoints/2026-10-15-m11-continuation.md)。

本次验收对象是 KongPilot 管理平台及其部署、权限、数据与业务闭环。Kong OSS 1.5.x 是兼容验证目标；平台不修改 Kong 源码、镜像或插件实现，不连接 Kong 数据库。Kong 本体历史风险不作为本清单待研发事项，但平台的 Admin API 网络边界、版本兼容和错误处理必须实测。

截至12:04 UTC，最新运行候选为Source `f960006a`、40迁移，Node22联合专项90文件2,529项通过，包含Portal新鲜检查V2与配置材料canonical投影修复；Portal完整引擎仍触发500调用预算，未发证，不能登记闭环。上一张配置长工单因材料subject不一致失败，原失败保留；新修复在实际运行库只读重算已与其原draft一致，新的独立长工单待自然等待后执行。SQL040源码已按四段冻结补片整合，Node22两端类型检查及11文件503项通过；真实恢复副本上DDL/ROLLBACK与另建测试库的12项双连接/权限/回滚检查通过，原运行库仍40条，未登记业务清除通过。真实隔离存储恢复及新最小权限角色通过，全应用密文、业务恢复和切换仍待。通用元数据调度、全图删除恢复与unknown处置继续研发；当前Source/端到端/生产/秘密最终门禁保持未勾选。逐项证据见进度24.9–24.11，下文历史条目须按其时间和固定Source读取。

## 1. 当前基线与判定方法

2026-10-15 最后有实际部署证据的 API 是 b186587f 候选 (`artifacts/M11/runs/20261015-persistent/source-disposition-candidate-source-freeze-original.json`, not public)：418 个输入、376 个 JS 产物、SQL000–039 共 40 条迁移；同一自有验收 API 启动 (`artifacts/M11/runs/20261015-persistent/source-disposition-candidate-runtime-original.json`, not public)于 22:29:39 UTC，ready200。它是历史运行基线，不能证明 10 月 18 日服务已恢复。

10月18日已有新的恢复启动证据 (`artifacts/M11/runs/20261018-resume/api-start-readiness-original.json`, not public)：同一容器于08:33:38 UTC启动，08:34:31观察ready200、旧材料未重新激活，平台PostgreSQL/Redis持久数据保留。恢复前只读核验v2 (`artifacts/M11/runs/20261018-resume/pre-api-console-db-safety-v2-original.json`, not public)确认40条迁移摘要、1,536条审计记录、两条旧issue和一条拒绝事实仍在，未到期运行job/未领取active日程/未到期claimed日程均0；这是行数及持久性观察，不是本轮全审计链验证。随后的监控及新认证结果见下文；新业务与完整灾备验收仍待。

10月18日8个原容器健康检查 (`artifacts/M11/runs/20261018-resume/all-owned-runtime-health-original.json`, not public)均通过，Prometheus原二进制已按官方固定摘要恢复；新登录 (`artifacts/M11/runs/20261018-resume/fresh-console-sessions-original/verification.json`, not public)保留原actor并取得新SID，旧会话及旧意图未改写。以上是同一验收环境恢复，不能代替异机灾备与生产部署验收。

10月15日 Web 隔离构建 (`artifacts/M11/m11-source-disposition-web-isolated-build-20261015-original.json`, not public)退出 1、产物 0 的原失败保留。10月18日新的隔离构建与真实浏览器记录 (`artifacts/M11/runs/20261018-resume/web-rebuild-and-fresh-tab-summary-original.json`, not public)中类型检查、UI专项和Vite构建分别退出0；新会话、空本地事务缓存的真实浏览器10项/2截图通过，旧已登记及已拒绝来源计划均无重复创建或legacy apply入口。浏览器业务写入0，该分项不证明自然配置发布成功。最后完整 14,461 项测试与三端构建仍属于旧 828 冻结输入，不覆盖后续 SQL038/039、原键拒绝与来源计划处分等新字节。

最新Service候选冻结 (`artifacts/M11/runs/20261018-resume/reviewed-service-candidate-source-freeze-original.json`, not public)为`98a4715f808f72b3a10888e919542a723ef95770057118f34fa6ce0de3986fb1`，419输入/377JS/40条迁移，隔离编译0；联合专项 (`artifacts/M11/runs/20261018-resume/root-joined-service-focused-original.json`, not public)26文件978/978，同一API实际部署 (`artifacts/M11/runs/20261018-resume/reviewed-service-candidate-runtime-original.json`, not public)08:59:54 UTC启动ready200。原853d补丁EOF拼接失败及冻结夹具修正均保留。新配置长工单跨原preview期限后登记排程403 (`artifacts/M11/runs/20261018-resume/configuration-new-long-approval-author-vote-activate-original/configuration-natural-verification.json`, not public)；当时新门户仅完成前置申请，随后执行终态见下文，仍无新的Service或门户自然业务成功结论。

截至09:14 UTC，原长工单只读取证 (`artifacts/M11/runs/20261018-resume/long-approval-durable-binding-forensics-original.json`, not public)确认仍pending/revision1、24小时期限保持、无关联日程/claim/配置执行/步骤/mutation；current-version修复`c57e4733`只有Source集成、546项及类型门禁，尚未部署，新独立W acae8927尚未author。门户已完成审批/激活，但自然终态SQL (`artifacts/M11/runs/20261018-resume/portal-new-natural-terminal-sql-original.json`, not public)为单claim、Consumer mutation failed/remoteStarted=true/remoteCompleted=false、工单与执行uncertain，根frame诊断 (`artifacts/M11/runs/20261018-resume/portal-new-natural-terminal-context-diagnostic-original.json`, not public)为120秒到期。不能重试旧case或登记发证通过。当前审计 (`artifacts/M11/runs/20261018-resume/resumed-current-all-audit-chains-original.json`, not public)1,706行/3链通过不代表写入覆盖100%；生产依赖检查 (`artifacts/M11/runs/20261018-resume/production-dependency-audit-original.json`, not public)0漏洞不覆盖OS/容器运行时。

每项门禁须独立记录以下材料，不能把专项用例数相加后替代真实业务成功：

- 固定的 commit、源码/锁文件/镜像/SQL 摘要，实际运行版本与测试版本的一致性。
- 原 actor、集群、工作区、工单、计划修订、日程、执行和请求键的绑定；公开报告仅保存非秘密定位信息。
- 实际 UTC 时间、执行窗口、材料期限和每步退出码；自然 worker 验收不得通过手动 tick、延长原期限或重放原意图取得结果。
- 真实 BFF 请求、独立控制台 SQL、经 BFF/受控后端读取的 Kong 状态、必要的代理请求与浏览器截图；原始材料私有保存并记录摘要。
- 正向结果、故障/拒绝结果和未覆盖范围分别登记。`uncertain`、`pending`、`expired`、未知响应或页面链接存在，均不等于业务成功。
- 任何失败保留原报告；修复后用明确的新意图、新夹具和新报告验收。原回执查询只读，不重发旧业务命令。

## 2. 最短执行顺序

| 顺序 | 执行内容 | 必须取得的结果 | 进入下一步的条件 |
| --- | --- | --- | --- |
| A | 恢复持久验收环境、核对密钥/数据库/Redis/挂载/运行身份 | 恢复前后版本与持久记录一致；旧未知和过期事实不变；新 readiness 证据 | 不能用空库 bootstrap 或重新签发旧授权替代恢复 |
| B | 修复并审阅 Service 关系读取、绑定阶段、SourceP 处分与 Web 构建 | 真实当前权限不被扩大；固定输入专项/类型/隔离编译通过；实际部署一致 | 浏览器验证旧来源计划不开放重复创建或 legacy apply；SQL039 真实并发发布/拒绝竞争另外验收 |
| C | 新普通 Service 配置工单正向自然执行 | 新长时材料等待跨过原短 preview 期限后独立审批、激活、自然单 claim；真实 PATCH、逐步回执、SQL 终态、Admin 回读与代理行为一致 | 原始期限内完成；所有层级 succeeded；变更前快照真实存在；没有重发、越权或未知残留 |
| D | 新门户凭证自然链 | 独立开发者申请→审批→Consumer/key-auth→安全显示→代理认证→轮换/禁用/吊销→回执和通知 | 实际凭证成功与吊销后的失败均有证据；旧失败夹具和未决凭证不接管 |
| E | 新双环境 Promote 自然链 | 新比较、来源/目标绑定、独立审批、自然发布、目标回读；默认秘密/凭证/环境字段保留，显式选入分别验证 | 双边权限和来源漂移、伪造计划、跨范围操作均被拒；源目标拓扑边界如实记录 |
| F | Target 与 DELETE 的变更后状态、回收恢复及回滚 | 先完成固定 poststate 协议，再做真实 Target 0；删除先完成回收站完整归档，再执行原生删除，核验逐步回读/回执与新回滚工单 | 原始网络返回、密封回执、当前真实观测分别可信；旧点位 404 不变成通用跳过权限；0 权重提前阻断在正式支持前保留 |
| G | 会签/撤权/取消/重启/并发/未知恢复/预算 | 各类拒绝无越权写入；双 worker 单 claim；已发送未知不重试；可操作的安全恢复流程；有界批次与真实性能数据 | 不提高全局 Native 调用预算掩盖重复校验；不靠手工解除 unknown 或锁闭环 |
| H | 通知、审计、持久部署和恢复演练 | 业务成功和投递结果分别闭合；关键写入覆盖与链完整性；新环境恢复后核验平台与活动 Kong | 真实启用的外部提供者联调、恢复 RPO/RTO 和值班步骤落盘 |
| I | 最终固定版本全量回归和发布 | 全测试、三端类型/隔离构建、e2e/IDOR、当前审计和完整凭证秘密扫描、手册/版本/仓库发布 | 所有必需门禁独立通过，失败无隐藏；才记录 M11 与整体商用通过 |

可以并行完成 Source 审阅、测试编写、清单与手册草案。真实运行写入、SQL、Docker 及私有验收账本由统一执行人串行协调，防止不同任务同时改动同一原始状态。

## 3. M11 必需验收矩阵

表中“历史分项”仅说明存在旧证据，最终仍需核对当前冻结版本的覆盖范围。

| 编号 | 原始目标/关键边界 | 当前已知事实 | 完成所需证据 |
| --- | --- | --- | --- |
| W01 | 直接/审批模式覆盖所有写入口 | 控制面、身份、监控、说明、实体、凭证、Target 等已有分项与源码接入；不代表每类当前版本全覆盖 | 各类代表性准备/提交/批准/执行/回读/审计；审批模式无工单写入拒绝，直接模式仍需权限、确认、审计 |
| W02 | 单级、多级、人数门槛、会签 | 历史政策与资格分项存在 | 当前版本完整多阶段/会签正向，重复票/自审/伪候选拒绝；执行前停用、换密、移出团队/角色、撤权使旧批准失效 |
| W03 | 长工单与短 preview 分离 | 10月15日两长工单已过期；新W d855跨15分钟后排程403，真实取证仍pending/rev1/J waiting且关联执行计数0；c57e Source修复未部署，新W acae09:11登记尚未author | 修复后用合法新意图完成跨原短preview期限的独立审批与原材料期限内自然成功；零账本不是KnownNotSent，不重放或续旧preview |
| W04 | 原键回执、拒绝与来源计划处分 | SQL039 真实 409/原键 GET/只读恢复/IDOR/历史过期读取通过；10月18日新Web构建及新登录空缓存实际浏览器10项通过 | 最终冻结版本仍须覆盖对应入口；只有严格匹配拒绝回执才能归档对应事务；未知保留；不显示重复创建或 legacy apply |
| W05 | SQL039 disposition 并发互斥 | 8 项真实 rollback 负测 (`artifacts/M11/runs/20261015-persistent/durable-rejection039-rollback-negative-first-original.json`, not public)通过，但没有两个真实 writer 提交竞争 | 新真实合法材料、两个独立运行凭证连接/请求下，发布与拒绝、相同 source 不同 key、同 owner/key 等竞争只能有一个合法终局；审计/图/原键一致，无悬空 issue/job；保留完整原始证据 |
| W06 | 定时委托、变更窗口、冲突与单次执行 | 历史取消、到期、物理影响冲突、单claim分项存在；普通配置旧自然失败保留，当前版本尚无新的自然成功 | 当前版本自然成功；窗口前不执行、窗口后不补执行、取消/停机过期、重启、双 worker、租约失效、重叠范围、跨别名物理冲突逐类验收 |
| W07 | Service 关系与 scope | 历史短case为5秒authorization frame到期，精确调用点未确认；固定关系候选98a4715f已编译/专项/部署，新正向尚未取得，当前新长case在登记排程被拒 | global/workspace/tag_group/entity 当前权限矩阵、Route→Service 与 Plugin 继承、真实关系读取；不得因查询全量 Upstream 候选给 scoped 用户额外读权；跨作用域引用拒绝 |
| W08 | 变更前快照、影响面与回滚 | 历史完整恢复和凭证实测存在；当前业务排程回滚尚待 | 新执行前真实快照、Route/插件/调用量提示或数据不可用状态；新回滚 Diff、重新审批、自然执行、逐对象原 ID/关系/凭证验证；不能重放旧执行 |
| W09 | Target 追加、0 权重和 DELETE poststate | 历史实体工单 Target 生命周期成功不等于嵌套配置 V2 支持；b186配置V2所有Target append显式拒绝，最新Mutation slice保持不支持门禁，不扩大为已验收支持 | 真实追加 75/0、active/history EOF、旧/新 ID 观测、SDK 原始返回与密封回执、每步当前授权；DELETE 先完整归档再原生删除，核验当前缺失/回执/恢复完整闭环；不得仅凭 HTTP 状态或新旧点位 404 绕过 |
| W10 | 门户共用工作流 | 新四类Native201夹具/九前置/author/vote/activate通过，但自然单claim后Consumer mutation failed/remoteStarted且未完成，W/S/E/当前步骤uncertain；根scheduled-workflow frame120秒到期，未确认发证成功 | 全新独立门户夹具完整签发/代理认证/轮换/吊销链；每步真实批准、工单/门户元数据一致、秘密不落日志；旧未知不得重试或借新句柄接管 |
| W11 | Promote 来源/目标工作流 | 双 job/plan 来源修复有 Source 分项，旧激活曾超 30 秒拒绝 | 当前版本新自然发布成功、来源撤权/漂移/目标改变/复制计划拒绝；明确源目标角色与故障域，不能用共享 PG 进程的验收拓扑证明生产灾备隔离 |
| W12 | 未知结果处置与故障恢复 | 旧 unknown 保留，现有只读核验不释放保留；通用产品安全 resolution 尚未完成 | 对已知未发送、已知成功、部分完成、实际未知分别有严格可证明的处理路径；缺证据继续阻断；无通用强制成功/清锁/重放；故障注入与操作者步骤实测 |
| W13 | 审计、通知、日程看板 | 09:14当前1,706行/3链 (`artifacts/M11/runs/20261018-resume/resumed-current-all-audit-chains-original.json`, not public)及JSON patch只读完整性通过，预期关键写入覆盖尚未通过，不外推其后新增写入 | 本次预期关键写入清单与实际审计一一对应，before/after patch、IP/工单/结果/失败事件正确且不可修改；站内未读/订阅与本期启用外部渠道真实投递、失败/重试/幂等、秘密脱敏 |
| W14 | 配置规模与执行预算 | 曾触发 Root 500 次调用上限；Source 次数改善不是性能验收 | 真实代表性小/中/大批次及多审批人测时/调用数/SQL负载；超预算在写前可读阻断或经过验收的有界批次；故障后不重发；记录声明支持容量与资源配置 |
| W15 | 发布工单 UI 完整可用 | 历史看板、只读页面、明暗分项存在 | 当前构建真实浏览器完成发起、Diff、审批/会签、登记/激活、逐步结果、回滚、原键核验；明暗/移动端/侧栏完整、中文、手册入口及 v1.0 版本可见；无浏览器直连 Admin |

## 4. 原始整体验收要求回归矩阵

M0–M10 的技术验收记录继续有效于各自固定范围，不能自动外推到最终 M11 版本。以下各项都必须在最终版本记录当前结果或明确适用范围。

| 原始项 | 覆盖模块 | 最终验收要求 |
| --- | --- | --- |
| 1 | M0/部署 | 一键启动与外接 Kong 两种交付路径；只追加自动迁移、readiness、重启/持久化；真实版本根探测→enabled 插件；Prometheus/Loki 连通性与最后探测时间 |
| 2 | M1/M2 | 八类核心实体、Targets、六类 Consumer 凭证及实际 enabled 1.5 自带插件的 schema/CRUD/绑定/UI 回读；复杂 array/record、条件字段；仅旧风格插件 schema 路径 |
| 3 | M1/M8/M11 | 至少五类对象带完整依赖/原 ID 删除入回收站再恢复；证书、Target、Routes/Plugins、Consumer 及实际凭证认证；保留期和永久删除二次确认，不以只恢复 JSON 代替可用验证 |
| 4 | M3 | 两个工作区、未打标签默认区、自动保留标签、迁移、列表/详情/统计隔离；软隔离提示与后端检查；Admin 网络只向 BFF 开放 |
| 5 | M4/M11 | read-only 前后端禁写；workspace/tag_group/entity/global 权限及继承矩阵；所有路由/批量/关系/原键接口 IDOR 拒绝；会话、刷新、登出、失败锁定与日志脱敏 |
| 6 | M5 | QPS、状态码、延迟分位、带宽、TopN、节点与时间范围；与真实 Prometheus 查询核对，工作区/服务/路由下钻标签能力如实显示；最终写入传播提示 |
| 7 | M6/M11 | 独立门户账号/站点、文档/应用、凭证申请审批/自动 Consumer/插件/凭证、真实代理认证和吊销；不得用 pending/未发证代替成功 |
| 8 | M8/M11 | decK 1.x 的 diff/sync 实际识别 `_format_version: "1.1"` 和实体/凭证；导入逐对象结果、删除入回收、真实快照/新回滚；敏感配置恢复后凭证仍可用 |
| 9 | M10/M11 | 预置孤儿/引用/冲突/owner/基线巡检、规则 DSL 与修复、定时漂移阈值、源目标 Promote；没有 description 的原生实体使用平台元数据，不写 Kong 未知字段 |
| 10 | M11 | W01–W15 完整独立验收，不以批准/激活/Source 测试替代自然业务完成 |
| 11 | M7/全写入口 | 当前版本关键写入审计覆盖 100%，成功/失败与 JSON patch 正确，append-only 权限及篡改负测；与对应工单和原键关联 |
| 12 | M4/全接口 | 当前冻结版本针对 Konga 类越权/IDOR、跨集群/工作区、tag_group/entity、嵌套关系、计划/回执/凭证导出等专项实测；伪造 actor/SID/工单/旧票/句柄拒绝 |
| 13 | 全模块 | 最终固定输入全量/集成/e2e、三端类型/构建通过；README 架构/启动/版本/软隔离、正式部署与用户手册与真实发布功能一致 |
| M9 补充 | M9 | 节点/精确缓存失效、匹配模拟及真实代理探测、插件链、批量逐项结果/二次确认、个人草稿；缓存不可写回和模拟范围如实展示 |

可选 LDAP/OIDC 或外部渠道未启用时，须在站点发布清单明确关闭；声明启用的提供者必须完成真实现场联调。模拟接收器可以验证投递协议，不能冒充实际生产服务商验收。

## 5. 最终发布门禁

- [ ] 最终源码、依赖锁、所有 SQL、三端镜像与前端资源摘要冻结；运行版本、编译输入、测试输入一致。
- [ ] 全仓测试、集成和 e2e 真实退出 0，无未解释失败、跳过或 todo；三端类型检查与隔离构建分别成功。失败重跑保存新旧原始报告。
- [ ] 网关调用白名单、旧插件 schema、分页 size/offset/next、服务端 scope、响应头/CSRF/会话、写入确认、秘密展示授权专项通过。
- [ ] 代表性负载、限流/熔断/分布式锁、多 worker、超时与故障恢复通过；明确容量、告警阈值与运行资源。
- [ ] 实际持久生产安装/升级/回退流程演练；runtime/migrator 分离、备份/密钥、数据库/Redis故障、恢复后 API/worker/门户完整验证；记录 RPO/RTO。
- [ ] 当前全部预期关键写入审计覆盖，当前全链与 JSON patch 完整；数据库 runtime 无 owner/超级权限、不可更新/删除审计与不可变事实。
- [ ] 当前生产依赖处置和镜像扫描有结论；范围限定为平台资产，不将旧依赖报告外推到新发布包。
- [ ] 完整秘密扫描覆盖最终仓库/三端构建/全部自有运行日志/实际审计/本次真实签发凭证材料，实际退出 0、0 泄露且输入闭合；未签发 API Key 的 checkpoint profile 不得用于最终凭证验收。
- [ ] 浏览器入口、版本 v1.0、品牌/明暗/响应式、手册入口及正式手册逐步核对；草案通过对应实测后才合入正式说明。
- [ ] 历史 unknown/failed 不改写，未决影响面有已验收的安全处理方案；上线站点不继承未核验写入权。
- [ ] 交付完整发布记录、剩余已接受限制、运维接手与真实提供者状态；代码及证据推送用户仓库，核对远端 SHA；不以 checkpoint 名义宣布 GA。

所有适用项通过后，另出明确的 M11 验收结论与平台商用准入结论。两者均须引用具体冻结版本与证据；在此之前保持“未通过”。
