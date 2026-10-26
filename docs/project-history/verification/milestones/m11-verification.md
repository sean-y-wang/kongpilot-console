# M11 验证记录

> **2026-10-26 01:16 UTC+8 最终结论：`commercialClosed=true`（owner 批准）。** 验收对象 `v1.0.0-rc.2`（8ea549e），正式复扫 CI 40200167285（grype 0.120.1，39/39），单次完整回归见[进度 §52/§53](../../milestones/checkpoints/2026-10-23-m11-continue-phase1.md)。范围为企业内部部署；写入 SLA 与异地容灾不在范围内，业务/实体定时为可选开关（生产默认关闭），审批人具备集群写权限时可执行自己批准的工单（见 operations/approval-execution-separation.md）。以下历史更新保留原文。

最新状态见 [2026-10-15 后续研发与验收进展第23节](../../milestones/checkpoints/2026-10-15-m11-continuation.md#23-sql039实际部署与原请求拒绝闭环截至2224-utc)。当前隔离验收API为a9471b00，418输入、SQL000–039共40迁移，22:13:33启动ready200；实际NOSU及新rejection表最小权限通过。新独立原请求实际POST409→GET拒绝回执、浏览器只读恢复8项/2图、数据库拒绝/审计与零关联执行一致，当前1,514行/3条审计链核验通过。首轮浏览器JSON键序断言失败及只读工具locator错误均保留，不重发POST。Service定时执行超时仍未完成修复，新Service候选存在具体scoped范围限制，不能以admin正向替代全角色验证。长Wf8393f4e仍pending，22:44:45期限不续，尚未审批/自然执行。新Source/UI仅专项，不由旧828的14,461项全测或旧秘密扫描推导当前通过；最新远端仍d3e1d405。**M11与商用整体验收尚未通过**。

2026-10-14当前进展：实际隔离API为 `7e2e3d895d3df98daa0ffa0a211e8e26bc533e33393d407a7b9d4491f9ce38ae`，368个冻结源码文件、SQL000–029共30条实际迁移；独立只读运行证明核对源码、全部迁移摘要、新触发器及真实app角色9张排程事实表只追加权限通过。业务排程controller/provider已注册，`BUSINESS_SCHEDULES_ENABLED=false`；真实登录后readiness与空日程列表均200，原Target成功终态及已知观察保持，业务命令和原生写入0。原修复隔离源码候选502套件/9,578项全部通过、API类型检查通过、3,895文件前后摘要一致；该候选不覆盖后续业务装配、范围读取桥、身份尾部修复及新页面。新业务排程页面5套件85项、Web类型/构建通过，尚未做实际浏览器或业务执行验收。既有Consumer七节点原ID恢复、五认证/ACL10次真实正负访问、OAuth2完整HTTPS及审批吊销/恢复、新Target100→80→0和原Target0无重发元数据核验等分项保持，原失败、unknown、sent-unknown/null不覆写。真实业务登记→新修订→三票→定时→嵌套执行/原生或门户、Target回滚、真实故障及最终生产回归仍待完成，**M11整体及商用仍未验收**。不改Kong源码、镜像内容或直连其数据库；原生实体变更经Admin API，自有隔离代理的TLS监听/证书配置单独记录。旧候选的统计和未注册状态按下文采集时间保留，不能当作最新运行状态。

## 门禁 1：真实部署与审批事实

验收环境采用既有隔离实验集群，在控制台 PostgreSQL 16 和 API 中应用 SQL019。API 启动健康请求返回 200。SQL000–018 校验和保持不变，SQL019 正式校验和为 `a78c530fa0eb0078ed196217c8ccb5819afbacb1744611c8769da15e421f0fdb`。部署候选源码摘要为 `0d3208ce6a800a272b0eb8bd299a7167895cda4d8db61b2b292b886e3b63c026`；之后的门禁 2 工作树不能冒用该候选的运行证据。

真实 HTTP 使用新建工作区和 5 名真实非超级管理员账号，经过实际登录、密码修改和工作区角色授权。执行了旧 V1 单级治理工单、按旧行政政策审批后生效的新政策，以及包含 any、quorum、all 三个顺序阶段的新治理工单。全部 5 票满足门槛后才生成完整批准集。自审批、非候选人审批、审批前执行及非提交人执行均被拒绝。

另一张工单终审后撤销了一名较早批准人的团队成员资格。即使最后批准人仍有效，执行也返回 `403 WORKFLOW_APPROVER_SELECTOR_REVOKED`，未创建执行 claim。随后通过正式取消接口取消工单，原 5 票及所有已批准阶段仍保留。该验证没有写入 Kong 配置。

数据库验证实际通过 6 项正向检查及 6 项可回滚约束负例：缺失政策必填字段、旧 V1 空门槛、候选名单重复、无票跳级、跨工作区批准集以及执行引用别的工单批准集。所有试验均以最终 ROLLBACK 结束，原始事实和迁移账本摘要保持一致。6 张新增事实表的运行角色仅有 SELECT/INSERT，无 UPDATE/DELETE/TRUNCATE。

实际审计与 outbox 查询确认：每张三阶段工单的前 4 票产生审批进度事件，第 5 票才产生批准终态事件；这 10 条事件均已分发。控制台新建验收工作区的原生 mutation 数为 0。此证据不代表外部邮件、Slack、飞书或站内通知订阅投递已完成验收。

HTTP 共 8 项检查、SQL 6 项正向检查与 6 项负例、只读 outbox 共 5 项检查。它们是不同类别的验收证据，不累加为单测数量。验收后通过正常接口取消无票 SQL 对照工单，并将实验目标集群执行模式恢复为原来的 direct。

| 证据 | 内容 |
| --- | --- |
| 门禁 1 清单 (`artifacts/M11/gate1-acceptance.json`, not public) | 范围、候选版本、精确摘要、限制和清理结果 |
| 启动记录 (`artifacts/M11/runtime-deployment.json`, not public) | 正式迁移、启动和健康响应 |
| DDL 回滚预检 (`artifacts/M11/migration-ddl-trial.json`, not public) | 正式应用前的真实 SQL 预检 |
| HTTP 请求记录 (`artifacts/M11/gate1-http-verification.json`, not public) | 原请求摘要、状态码、实际检查；门禁 1 独立冻结，零原生写入的元数据流程 |
| SQL 约束验证 (`artifacts/M11/gate1-sql-integrity-attempt3.json`, not public) | 真实约束、完整批准集和回滚后原记录摘要 |
| 审计与 outbox 验证 (`artifacts/M11/gate1-outbox-verification.json`, not public) | 进度和批准事件、零 claim 和零原生 mutation |

## 保留的失败记录

SQL019 的未应用候选曾因 CASE 表达式语法失败，修正后预检及正式迁移均通过；未改写已经应用的迁移。原候选和启动失败记录保留在 artifacts/M11。诊断过程还保留了因工具未转发标准输入导致的空环境文件错误，这不是数据库连接配置缺陷，未据此修改平台 DSN。

HTTP 夹具最初使用错误的权限模块名和不适用于取消接口的 planHash 字段，分别得到明确的 400。请求原记录保留；修正测试输入后通过。SQL 验证工具的首轮错误假设 pgcrypto 可用，第二轮因自身 SAVEPOINT 名校验不接受数字而停止；修正工具后第三轮通过，没有安装扩展或修改数据库来迁就测试，前两轮文件均保留。

所有原始密码、登录响应 Cookie 和私有请求留在权限受限的 RAM 账本，公开验证文件不包含明文凭证。最终全平台秘密扫描和发布回归将在全部功能闭环后执行。

## 门禁 2：长期意图、实体范围与回收准备

验收候选源码摘要为 `5b6b77632d21088bb8e49c1a0fd4c5f8c9d14d541687c22ebc5014cf0f132a1b`，已应用 SQL020，API 健康请求返回 200。HTTP 新增 17 项检查，公开报告累计包含门禁 1 的 8 项历史检查，不重复计为本门禁测试。

真实创建意图使用固定预分配 ID，24 小时期限；同一真实用户通过另一次实际登录会话提交时，原 ID、材料摘要和期限均不改变。创建、标签范围修改、仅凭证 ID 白名单修改、Service/Route 完整删除图和已有回收站 Upstream/Target 恢复图共形成 5 张真实工单。审批模式的 4 张经过独立批准；执行入口均保持关闭。只读账号、移除授权标签、跨工作区实体及凭证、跨范围意图读取均被拒绝。

SQL 实库通过 6 项检查及 4 项完整对照负例：缺失 packet、同步更改 manifest 和 packet 的自依赖、跨工作区版本 FK、完整 wrapper 缺失 entity ID。试验全部回滚，原事实、catalog 和 SQL000–020 账本保持不变。5 张新事实表的运行账号仅有 SELECT/INSERT。

收尾正常取消 5 张工单，恢复实验集群原 direct 模式，并通过既有回收站执行恢复独立 Upstream/Target 夹具的原 ID。实际只读查询确认所有 5 张工单均取消，执行、原生 mutation 和短执行 source 数均为 0，成功审计记录存在。专门建立、删除和恢复的原生测试夹具与工单执行分开记录，不宣称整个测试工作区零原生写入。

| 证据 | 内容 |
| --- | --- |
| 门禁 2 清单 (`artifacts/M11/gate2-acceptance.json`, not public) | 精确候选、范围、证据摘要与限制 |
| 启动记录 (`artifacts/M11/gate2-runtime-deployment.json`, not public) | SQL020 正式迁移及运行账号配置 |
| DDL 预检 (`artifacts/M11/gate2-migration-ddl-trial.json`, not public) | 正式应用前完整回滚试验 |
| HTTP 验证 (`artifacts/M11/gate2-http-verification.json`, not public) | 实际提交、独立审批、范围拒绝、取消及夹具恢复 |
| SQL 完整性 (`artifacts/M11/gate2-sql-integrity-attempt1.json`, not public) | 6 项检查、4 项可回滚约束负例 |
| 工单事实只读核验 (`artifacts/M11/gate2-all-workflows-readonly-verification.json`, not public) | 5 张工单无 execution、native mutation 或 source |

## 门禁 2 完成时的后续计划（历史）

门禁 3 的 Core 已部署于隔离验收环境，控制台迁移应用至 SQL022；Service 的独立初审、双人会签、完整对象图基线、真实原生执行与回显已通过。其余实体及回收站、凭证轮换/回滚、后台委托和窗口仍在验证，门禁 3 尚未整体验收。前端政策与阶段进度切片已通过本地构建，浏览器验收尚未进行。后续完成真实执行与新回滚工单、后台委托与执行窗口、工单看板，再进行 M0–M11 回归、平台生产部署和手册更新。

## 门禁 3 当前进展与保留的失败

2026-10-13：首次 Service 执行在基线持久化之前返回 500。实际 SQL 确认基线、attempt、event、原生 mutation 全为 0；原短执行 source 过期后，原用户用原执行键通过受限 `close-unsent` 接口关闭执行，未重发。原始响应、请求摘要及只读证明均保留。第二个全新工单揭示同一数据库函数别名问题，但已修复的失败收尾正确记录终态和审计。

真实 PostgreSQL 日志确认 SQL021 的基线校验函数中，局部行变量 `o` 与子查询别名冲突。SQL021 已应用，原文件及校验和保持不变；追加 SQL022 仅将查询别名改为 `candidate_object`、`previous_object`。源等价测试以及实际完整事务回滚预检通过，回滚后的 catalog 与迁移账本摘要相同。随后正式应用 SQL022，没有访问或修改 Kong 数据库。原未应用的回收站、定时执行候选分别更名 SQL023、SQL024，均尚未应用。

第三个新工单成功保存基线和 attempt，但在发送许可入账时返回 503：只追加表的运行账号没有 UPDATE 权限，因而不能使用 `SELECT FOR UPDATE`。固定 repository 改为事务 advisory 锁及普通读取，保持事实表 SELECT/INSERT 权限。原请求留下 mutation 的早期 `remote_started=true` 标记，不能把此标记当作已经实际发送。只读核验确认没有 send-intent 或实际结果；对部署中的编译文件验证也确认真实 transport spend 必须先完成不可删除的 send-intent。

受限 `reconcile-no-send` 接口使用真实原用户、原执行键、已过期 source、精确 V3 tuple、单一 attempt、零事件、42501 和无返回结果，追加 `rejected-before-send` 事实并关闭 mutation；不登记原生 handle，不执行 Kong 写入。正式 HTTP 返回 201，随后的实际 SQL 确认 mutation 为 failed，send-intent 为 0，早期标记及原 503 保留。该元数据收尾与下一张新工单的实际执行分别记录。

当前稳定 Core 候选摘要为 `995e66e9dee29131ba655c4de759d837a1260d5b6bea08863015e1275dd584b4`；SQL022 摘要为 `8abdc8219e82f3932f0d0bdd7a6c2eddd389e1d29d9fcd6d5e306b50f4f7d5f4`。真实 Service UPDATE 经过新的三票审批后执行成功。没有将旧失败请求改成成功回执，也没有将源码测试冒用为实网关证据。

隔离 API 在清理诊断进程时被操作人员误停，恢复后健康请求返回 200。两个期间的登录未获得响应；实际数据库确认该时间区间未创建会话，之后一次真实登录获得有效新会话。操作错误与平台缺陷分开记录。

| 证据 | 范围 |
| --- | --- |
| 基线别名 DDL 回滚预检 (`artifacts/M11/gate3-baseline-alias-ddl-trial-attempt1.json`, not public) | 实际完整事务及原 catalog/ledger 保持 |
| SQL022 正式部署 (`artifacts/M11/gate3-baseline-alias-runtime-deployment-attempt1.json`, not public) | 控制台专用库、原 TypeScript 不变 |
| 稳定 Core 部署 (`artifacts/M11/gate3-append-only-repair-runtime-deployment-attempt1.json`, not public) | 固定 writer、权限修复和元数据收尾 |
| 首次执行关闭 (`artifacts/M11/gate3-first-execution-no-send-closure.json`, not public) | 原键、零原生发送、原 500 保留 |
| 发送许可失败的元数据收尾 (`artifacts/M11/gate3-third-execution-metadata-no-send-reconciliation.json`, not public) | 原键、真实 HTTP201、实际 rejected-before-send |
| 收尾后 SQL (`artifacts/M11/gate3-third-execution-after-metadata-readonly.json`, not public) | mutation failed、send-intent0、原标记保留 |
| Core HTTP 当前记录 (`artifacts/M11/gate3-core-http-verification.json`, not public) | 累计记录，整体 M11 未验收 |

核心子集实际完成 4 次原生执行：标签范围用户修改 Service，凭证 ID 白名单用户轮换 API Key，以及两张独立、重新三票审批的回滚工单。真实代理验证轮换后新钥匙 200、旧钥匙 401；回滚后原钥匙 200、轮换钥匙 401。实际只读数据库验证通过 5 组检查，每次执行均有完整基线、单一发送事实和真实 2xx 结果。见 核心子集验收清单 (`artifacts/M11/gate3-core-subset-acceptance.json`, not public)。这些结果不能代替回收站、定时执行或最终商用验收。

桌面与手机浏览器使用真实后端会话完成只读验证。视觉修正后的 12 项检查及两张截图确认：页面无横向溢出，无浏览器直连 Admin API，无业务写请求；已完成工单不再显示未执行状态提示，技术明细默认折叠，空审批表单已移除。见 浏览器证据目录 (`artifacts/M11/core-browser-readonly-after-visual-fix-attempt1`, not public)。

## 回收站 SQL023 候选迁移预检

SQL023 尚未应用时，在隔离控制台数据库用真实 owner 角色执行完整 DDL 事务。首次试验发现 PL/pgSQL 的 IF 中 CASE 表达式缺少括号，PostgreSQL 返回 42601；两份失败证据保留，事务已回滚。仅修正未应用候选的表达式括号，SQL000–022 保持不变。

修正候选校验和为 `9960455dd685da0e528f9f6f2280a4a18b80e812090182742341b9e831ea36eb`。第三次完整试验实际通过 5 组检查：四张事实表的只追加保护、八个校验函数和十一条完整 RESTRICT 外键存在；无真实 source 的归档、缺完整对象图的执行包、无真实发送结果的完成回执以及清空事实表均返回 23514。最终回滚后 catalog 和迁移账本摘要与试验前完全一致，提交业务行和 Kong 请求均为 0。见 候选迁移验证清单 (`artifacts/M11/gate3-recycle-ddl-candidate-validation.json`, not public)。这是正式迁移的前置证据，不是回收站原生执行验收。

回收站协调器现采用原始私有执行句柄，绑定完整归档和恢复包；删除 204/null 与 GET404 分别来自真实写入、读取 transport ticket。回调返回空值或抛出 404 不能替代观察结果。首次成功结果、SQL023 回执、回收站状态及审计在同一元数据事务中提交；事务失败保留原生真实结果，不重发。专项单测与类型检查仅证明源码合同，真实删除/恢复仍需独立验收。

## 回收站 HTTP 核心子集验收

SQL023 已正式应用于隔离控制台库，运行角色继续只有事实表的 SELECT/INSERT 权限；Kong 数据库未被访问。候选 `ce4d0d0fb4a16b8f162d20e1939c2c9741293fd71c4724694997d10ba3853633` 启动健康检查实际返回 200。

真实执行中发现并修复两处接线问题，原始响应与只读证明均保留。首次删除的读取观测误触发了 mutation 之前的对象图检查，返回 403；首次恢复的最终图复核将本次恢复 source 误判为外部未完成 source，返回 409。两次实际数据库证明均为终态 failed、发送记录 0、原生 mutation 0。没有重发这些请求；修复后分别创建全新意图并重新完成三票审批。

读取观测现在仅处理具备真实 operation 的验证读取。恢复自核验只从当前私有 packet handle 获取本次 execution/source，不能通过相同 Cookie、用户、工作区或 HTTP Source 字段获得例外；其他 active source 及所有 unknown/uncertain 仍拦截。基线最后复核通过后，真实 mutation 事务内推进回收记录至 restoring，并同事务记录审计。

四次实际执行分别完成 Service/Route/Plugin 图的删除、恢复，以及 Consumer/key-auth 图的删除、恢复。每次独立完成初审和双人会签，均保存完整基线及新 source；共 10 次原生请求，删除为真实 204/null 与 pointGET404，恢复为原 ID 的真实创建响应。Consumer 删除后原 API Key 代理返回 401，恢复后返回 200。

实际只读库验证通过四组检查：完整审批和基线、整图包与 attempt/send/outcome/receipt 的精确闭合、原生结果和删除验证的密文 HMAC、十张事实表的只追加权限及未决变更数 0。见 回收站子集验收清单 (`artifacts/M11/gate3-recycle-subset-acceptance.json`, not public)。该子集不代表其余五种凭证、Target/证书、元数据故障修复、定时执行或整体商用验收已经完成。

## 定时工作流 SQL024 候选迁移预检

SQL024 尚未正式应用。隔离 owner 角色完整执行并回滚候选 DDL；最终通过六组检查、八个无效数据负例，验证源类型互斥约束、只追加事实、精确 claim 外键及旧 HTTP 源校验函数保持。试验后的 catalog、迁移账本及旧函数摘要与之前一致，业务行提交和原生请求均为 0。候选校验和为 `3b918d1d7f328bfa4c1a5ffa72720ad755dc0aaa11cfa3393dd3b4b297f3955f`；见 完整实际回滚结果 (`artifacts/M11/gate4-scheduled-ddl-trial-attempt4.json`, not public)。三次前置试验中的验收脚本参数错误及修复均保留，未改写为通过结果。

后续仍需完整凭证与特殊对象的回收验收、Target 特殊写入、定时委托/窗口、故障恢复和全平台回归；当前不能宣称 M11 或最终商用验收完成。

## 2026-10-13 运行验收续项

SQL024 已于隔离控制台库正式应用，迁移账本包含 SQL000–024 共 25 条；上述“候选未应用”描述为预检时的历史状态。首次部署候选为 `3e2820dd855ff0f44d573a8df7141c867198ae747b640faa00c52fb11b108edb`。实际定时工单完成准备、提交、独立三票审批、激活及提交人退出登录。后台通过真实原始委托认领一次；原生请求发送前被只读 schema 的 HTTP 会话要求拒绝。工单、执行和日程均记录为失败，完整只读查询证明基线、attempt、send 和 mutation 均为 0。原工单及 occurrence 未重放。

随后修复 schema 准备和门户预检对真实定时命名空间的支持，基线 schema 校验留在原调用身份下；修复失败收口的 impact 锁顺序，以及原生成功但元数据失败时的真实 partial 终态验证。出站 DNS 与网络请求分别保留原有超时预算，权限复验不占用尚未建立的网络请求预算；最终同步授权检查、原生发送一次性限制、TLS 与执行总期限保持。候选 `ca0e19f6c262ef6e7b6bf1fa12de83fba9812baba44046d4617470c3ca812619` 已编译、备份后部署，实际就绪为 200。在该候选初次部署时，后台原生成功和持续定时轮询尚未验收；后续结果另见下节，不改写首次失败工单。

控制台停库演练发现旧隔离库使用 tmpfs，容器停止后丢失了演练前最新测试元数据。恢复仅使用演练前真实控制台备份，没有补造事实；Kong 容器及数据库未停止或修改。实验库改为命名数据卷后，第二轮实际停止/启动验证通过：同一 API 进程返回 503 后恢复 200，迁移、来源、基线、尝试、事件和回收回执计数重启前后完全一致。该结果证明容器重启保留，不证明当前 RAM 实验机重启或持久生产部署。较早六凭证循环的 19 条原生运行事实属于恢复点之后的历史记录，不能冒充恢复后数据库中的事实。

已在恢复后的数据卷中新建独立 Consumer B，通过三人审批创建 Consumer 及六类凭证，再通过新工单删除全部七个对象并生成完整回收图。恢复工单前五个对象收到真实 201；第六个 HMAC 对象在权限准备之后、同步原生发送之前超时，最后 ACL 对象未尝试。原请求 503、工作流/执行 partial、五条成功事实和第六条 `failed-known-not-sent` 均保留。其元数据收口的后续结果见下节；整个恢复未通过，原键及已成功对象不重发。

手册 GFM 表格、稳定目录锚点及跨手册章节跳转已落实。实际浏览器完成 12 项检查和 4 张截图，包含真实手册、v1.0、真实日程、无操作终态、移动端不溢出及 BFF 边界；零业务写、零 Admin API 直连。前端类型检查与构建通过。浏览器前两次中文 URL 编码断言错误及 Vite 未运行的原报告保留，修正测试输入后通过。

| 新证据 | 范围 |
| --- | --- |
| SQL024 正式部署 (`artifacts/M11/gate4-scheduled-024-runtime-deployment-attempt1.json`, not public) | 源冻结、真实迁移、角色及启动 |
| 定时准备与退出 (`artifacts/M11/gate4-scheduled-core-http-prepare-attempt1.json`, not public) | 三人审批、激活，原生请求 0 |
| 失败工单只读证明 (`artifacts/M11/gate4-scheduled-core-failed-readonly-attempt1.json`, not public) | 原 occurrence 终态、发送前拒绝及无重放 |
| 控制台恢复 (`artifacts/M11/platform-persistent-console-db-recovery-attempt3.json`, not public) | 真实备份及命名数据卷恢复 |
| 停库重启 (`artifacts/M11/console-db-fault-runtime-attempt2.json`, not public) | 同一 API 503→200、事实保留、不操作 Kong 存储 |
| 独立六凭证创建 (`artifacts/M11/gate3-persistent-credentials-create-credentials-http-original.json`, not public) | 原 ID、私有材料及真实 schema 一致 |
| 独立完整删除 (`artifacts/M11/gate3-persistent-credentials-delete-consumer-http-original.json`, not public) | 七个原生 204 及完整回收图 |
| 部分恢复原记录 (`artifacts/M11/gate3-persistent-credentials-restore-consumer-http-original.json`, not public) | 失败保留，不能计为完整恢复 |
| 修复候选部署 (`artifacts/M11/gate4-scheduled-preflight-fix-runtime-deployment-attempt1.json`, not public) | 该阶段真实部署与就绪；当时后台成功仍待验 |
| 手册与日程浏览器 (`artifacts/M11/manual-schedule-browser-readonly-after-url-encoding-assertion-fix/verification.json`, not public) | 12 项实际检查、4 张截图、零业务写 |

完整源码回归首次运行 8,352 项，其中 8,308 通过、44 失败，集中在四个旧测试文件。共享 fixture 补齐新版历史审批定义读取契约，范围权限旧预期也按当前受限工单范围修正；原负例与首次失败日志继续保留。后续整仓回归的精确版本边界见下节。

## 2026-10-13 后续实测：定时执行与部分恢复收口

该轮实际运行 API 的冻结源码摘要为 `bcd2f9842c515d48a38b36dbb7f211d3b7eefb7c9923ddd25d5e091ed3b7c02e`，范围为已应用 SQL000–024；源码摘要明确排除当时未应用的后续迁移。此段为SQL025正式应用前的历史状态；最新迁移、候选及剩余恢复失败另见后续记录，不能用旧候选证明新能力已通过。

两张新意图分别重新准备、提交、完成独立三票审批、激活并真实退出提交人会话；均未复用首次失败的 intent、执行或 claim。第一张由真实原始 worker 胶囊执行，只有一次 claim、一次发送及一次真实 2xx，工作流/执行/日程均 succeeded。实际库确认提交人在 claim 前已退出、来源没有 HTTP SID、基线包含 Service/Route/Plugin 三对象的一张完整图、成功审计一条、未决变更零。该胶囊结果本身不证明 API 的持续定时器已开启。

随后仅在自有隔离 API 启用 `ENTITY_SCHEDULES_ENABLED`，第二张工单由 API 自然轮询到期执行，没有手动调用 worker tick。实际库确认 scheduled-entity 来源没有 HTTP SID、generation 为 1、三对象完整基线、一次发送和一次真实成功、未决变更零；BFF 只读回显确认 Service 的原 read_timeout 已恢复。此恢复是新工单批准的普通修改，不是重发旧请求或隐式回滚。启用报告的“只改变一个运行变量”只描述环境变量差异，不表示容器全部部署配置一致，也不证明生产部署。

另一张独立新日程完成三票审批和激活，在到期前通过真实接口取消。自然 API 定时器仍开启，没有手动 tick；BFF 回显配置不变，实际库核验日程 cancelled、三票保留，claim/execution/source/baseline/attempt/send-intent/mutation均0。首次只读验收查询误用 attempt/event 的 workflow_id，返回42703；修正为 source 关联的查询后，独立新只读报告通过。失败报告保留，此修正未重复任何原生写入。该分项不覆盖执行中取消竞态。

窗口过期负向使用新的三票批准/激活日程，仅停止自有 console-api，让预定窗口结束后再启动同一容器；数据库、Redis及Kong保持运行。自然 API worker将日程置为 expired、原因 `ENTITY_SCHEDULE_WINDOW_EXPIRED`，实库确认三票保留且claim/execution/source/baseline/attempt/send-intent/mutation均0，没有手动 tick。该停机发生在任何执行认领之前，不证明原生发送中的 crash、结果未知重启或多进程 HA 已通过。

Consumer B 部分恢复的首次元数据收口返回 500：审计查询同时将同一参数用于 text 和 UUID，实际 PostgreSQL 类型检查失败。只读库证明该次请求未改变 mutation、回收节点、回收记录或审计，原十二条事件及五条原生回执保持。修正显式类型转换后，原用户、原执行键和精确原材料的受限收口请求实际返回 200，只推进三项元数据：mutation 为 failed、HMAC 节点为 failed、回收记录为 partially_restored。工作流与执行继续 partial，原 503 和五条成功回执不变，新增失败审计与收口回执真实存在，未决变更零，本次收口发送原生请求零。

第六步的 `remote_started=true` 和 send-intent预约记录均保留；它们不等于实际传输已经发出。该步未发送来自原transport认证结果与精确持久事实，不能推广为所有超时/预约/早期标记都未发送。在此历史阶段HMAC/ACL未恢复；后续fe1的新两对象恢复见最新记录，旧工单与失败事实保持。

| 新证据 | 精确范围 |
| --- | --- |
| 当前运行候选部署 (`artifacts/M11/terminal-metadata-repair-cast-runtime-deployment-attempt1.json`, not public) | 冻结摘要、控制台备份、SQL000–024 迁移/授权与 API 部署 |
| 真实 worker 原始执行 (`artifacts/M11/gate4-scheduled-core-fixed-worker-original.json`, not public) | 一次原始 claim、实际原生成功；不是持续 API 定时器证明 |
| worker 成功只读库 (`artifacts/M11/gate4-scheduled-core-fixed-readonly-original.json`, not public) | 提交人已退出、NULL SID、完整基线、单次发送与成功审计 |
| 隔离 API 定时器启用 (`artifacts/M11/gate4-real-api-scheduled-timer-enable-original.json`, not public) | 自有 API 运行变量开启；配置时原生写入零 |
| 自然定时工单准备 (`artifacts/M11/gate4-scheduled-core-natural-timer-http-prepare-original.json`, not public) | 全新意图/日程/工单、独立三票及真实退出；准备链原生写入零 |
| API 自然轮询结果 (`artifacts/M11/gate4-real-api-natural-timer-readonly-original.json`, not public) | 没有手动 tick；新执行成功、单次发送、未决零 |
| Service BFF 回显 (`artifacts/M11/gate4-natural-timer-restored-service-bff-original.json`, not public) | 原 timeout 已恢复；此检查原生写入零 |
| 到期前取消原 HTTP (`artifacts/M11/gate4-scheduled-cancellation-http-original.json`, not public) | 新日程、独立三票、激活/取消与配置回显；自身不替代 SQL 零发送证明 |
| 到期前取消独立只读库 (`artifacts/M11/gate4-scheduled-cancellation-sql-source-join-readonly.json`, not public) | cancelled、三票保留、所有执行/发送关联计数零 |
| 取消首个 SQL 失败 (`artifacts/M11/gate4-scheduled-cancellation-sql-readonly-original.json`, not public) | 42703 原报告保留；查询修正无原生重试 |
| 窗口负向准备 (`artifacts/M11/gate4-scheduled-window-expiry-http-prepare-original.json`, not public) | 新日程、三票审批、激活；准备链原生写入零 |
| 窗口结束后自然过期 (`artifacts/M11/gate4-scheduled-window-expiry-sql-readonly-original.json`, not public) | 停 API 跨过窗口后重启，expired；零 claim/source/execution/send/mutation |
| 首次收口 500 无效果证明 (`artifacts/M11/terminal-metadata-first500-no-effect-readonly.json`, not public) | 原五条成功回执与十二条事件保留，修复审计零 |
| 受限收口 HTTP200 (`artifacts/M11/terminal-metadata-repair-after-cast-http-original.json`, not public) | 保留 partial 和原 503；原执行不重放、本次原生发送零 |
| 收口后只读库 (`artifacts/M11/terminal-metadata-repair-after-cast-readonly.json`, not public) | 三项元数据状态、失败审计、真实回执、未决零；全图恢复未通过 |

### 源码、浏览器与依赖检查的版本边界

修正旧 fixture 与范围预期后，完整源码回归实际为 **450 文件 / 8,515 项全部通过**，日志见 整仓回归 (`artifacts/M11/full-source-regression-after-terminal-repair.log`, not public)。该次运行在最后审计 SQL 显式类型转换修复之前；最新转换修复另有 **3 文件 / 103 项聚焦测试**、真实 PostgreSQL 查询和上述 HTTP200/只读库证明。两次测试范围有重叠，不相加，也不把旧全测冒充最终待冻结候选已全部回归。首次 8,352 项中的 44 项失败见 原失败日志 (`artifacts/M11/full-source-regression-before-terminal-repair.log`, not public)，继续保留。

手册与日程页的十二项实际只读浏览器检查和四张截图仍以其原运行源为准；本轮文档内容更新不会自动获得新的截图或 UI 写入验收。当前锁文件的平台生产依赖审计各级漏洞计数均为零，见 依赖审计 (`artifacts/M11/platform-dependency-audit-current-lock.json`, not public)；这只是该锁文件对应的依赖公告检查，不涵盖最终镜像操作系统或正式站点部署。

### 此轮结束时的待办（后续进展见下节）

1. 完成剩余 HMAC/ACL 的新意图、当前完整图/历史校验、独立审批与原 ID 恢复，再分别验证六类凭证真实业务认证。
2. 继续定时执行中取消、撤权、逐包窗口、同物理网关预约、多进程 claim、未知结果与发送中重启处置，以及普通/M8/Promote 适配器和通知分别实测；已通过的到期前取消、认领前窗口过期不覆盖这些路径。
3. Target 权重/健康、证书/SNI 及其他未验收入口完成实际写入和恢复；所有用户写入链完成浏览器验收。
4. 最终源码/镜像/SQL 冻结后重新完成 M0–M11 回归、审计覆盖、秘密扫描、持久生产部署、平台备份/密钥与隔离恢复及启用外部提供者的现场联调，再判断商用准入。

上述两次定时成功和一次元数据收口均为分项证据，**M11 整体及平台商用验收仍未通过**。

## 2026-10-13 后续实测：SQL025、审批人换密阻断与剩余恢复失败

### SQL025 预检与正式应用

SQL025 首个未应用候选的完整DDL试验返回42601，初始报告未确认回滚；随后独立诊断确认试验已回滚，候选语法错误与两份原失败报告均保留。只修正未应用候选的CASE表达式括号后，实库完整事务试验通过四组检查：旧25条迁移/owner、完整DDL的七条RESTRICT外键与四个启用trigger、真实TRUNCATE拒绝23514、deferred guards与外层回滚。原catalog、迁移账本及原生证据摘要保持一致，试验事实插入和原生发送均0。这些检查没有模拟或证明真实恢复已完成。

正式SQL025文件 `025_m11_partial_recycle_restore.sql` 的SHA256为 `72b19980dfd3d5cda3370d89a05994f35d557cecf7e8ceb8218315864c419534`。冻结候选 `f9892a065900ffff985e76a3dc9d4dd3378465ec8c02b35b500bb1da62edd973` 在控制台专用库备份后部署，真实readiness返回200。实际账本包含SQL000–025共26条，新事实表运行角色具备SELECT/INSERT，UPDATE/DELETE/TRUNCATE均拒绝。该角色/账本只读报告包含模板残留的旧scheduleId/workflowId；本项证明只使用迁移及角色字段，不能将这两个ID作为新恢复或定时原生执行证据。

### 审批人强制换密阻断

首个撤权试验只预留约60秒，测试操作者赶不上到期条件，密码重置步骤在分配任何HTTP请求前停止。原三票批准的日程随后由自然API定时器真实成功执行，实际库保存一次claim/execution/source/baseline/attempt/send-intent/mutation。此报告的passed只表示如实确认实际成功；`revocationNegativeScenarioAccepted=false`，不能计为撤权拒绝通过。原重置步骤false报告继续保留，没有将实际成功改成零发送。

另一条操作预检因操作者未等待独立登录过程完成，私有账本锁返回 `RELEASE_LEDGER_LOCK_UNAVAILABLE`，没有分配HTTP请求或新命名空间。改为等待登录结束、检查原账本后才启动依赖阶段；该操作错误报告保留，不放宽账本锁或身份条件。

新的延长窗口意图重新准备、提交、三票批准并激活。管理员通过真实IAM密码重置将审批人A置为需要换密，账号保持active、原角色不变。修复前自然API定时器没有创建claim或发送原生请求，但日程错误地保留active、未记录阻断原因，故原负例报告为false。修正资格错误到状态原因的映射后，同一原日程由真实API自然轮询置为blocked、原因 `ENTITY_CHANGE_REVIEWER_INACTIVE`；三票保留，claim/execution/source/baseline/attempt/send-intent/mutation均0，没有手动tick或重新激活。

审批人A随后通过真实受限登录完成密码变更，再实际登录取得新SID；原角色与其他三名参与人保持不变。原blocked日程没有自动重启。换密完成的HTTP报告与原日程的独立只读库证据分别使用；不把HTTP报告中尚待独立SQL验证的epoch/session字段补写成已经验证。这项覆盖强制换密的资格失效，不扩大为所有角色/团队撤权或逐包撤权竞态。

### 仅剩两对象的新恢复工单

SQL025部署后，为Consumer B原七节点归档准备全新剩余恢复意图，服务端准确选出HMAC/ACL两包，重新完成独立三票批准。执行保存完整七对象基线和五条已存在对象观察，没有重发五个已成功对象。但首包发送许可之前返回403 `ENTITY_CHANGE_DELETE_VERIFICATION_INVALID`。实际库确认工作流/执行failed、五条存在观察、一次attempt、一条结果事实、send-intent0；mutation为failed，保留 `remote_started=true`、`remote_completed=false`、null result，回收记录仍为restoring。原HTTP403保留，原生发送为0，剩余HMAC/ACL未创建。

该错误来自恢复当前对象观察被错误要求为删除验证；对应Source修复已有26项聚焦检查，在此轮初次记录时尚未部署。该二包failed来源的受限元数据收口与Reader精确处理随后已部署，实际结果见下节；保留当时失败事实，不用后续收口覆盖原403。不得手改回收状态、将failed source删除或忽略所有外部来源来解锁，不能用新键重新执行同一失败工单。五类正负真实认证助手尚未运行；OAuth2 TLS/token链同样待验证。

| 新证据 | 精确范围 |
| --- | --- |
| SQL025首个DDL失败 (`artifacts/M11/partial-restore-025-ddl-rollback-trial-original.json`, not public) | 未应用候选42601；初始报告未确认回滚 |
| SQL025语法诊断 (`artifacts/M11/partial-restore-025-ddl-rollback-trial-syntax-diagnostic.json`, not public) | 同一失败候选，独立确认回滚；不是通过报告 |
| SQL025修正后完整回滚试验 (`artifacts/M11/partial-restore-025-ddl-rollback-trial-after-case-fix.json`, not public) | 四组实库检查、原catalog/ledger/原生证据保持、试验写入0 |
| SQL025正式候选部署 (`artifacts/M11/partial-025-runtime-deployment-original.json`, not public) | 冻结f9892a候选、专用库备份及正式迁移/授权 |
| SQL025运行就绪 (`artifacts/M11/partial-025-runtime-readiness-original.json`, not public) | 实际API readiness200 |
| 实际账本与运行权限 (`artifacts/M11/partial-025-actual-ledger-and-runtime-role-readonly.json`, not public) | 26条迁移、SQL025摘要、事实表SELECT/INSERT；忽略模板残留的schedule/workflow ID |
| 撤权首个重置步骤停止 (`artifacts/M11/gate4-scheduled-reviewer-credential-revocation-reset-reviewer-http-original.json`, not public) | 没有分配重置HTTP；原false保留 |
| 错过撤权时机后的实际成功 (`artifacts/M11/gate4-credential-revocation-missed-window-state-readonly.json`, not public) | 原日程真实成功及一次发送；不接受为撤权负例 |
| 操作者预检锁冲突 (`artifacts/M11/gate4-credential-revocation-operator-preflight-lock-conflict.json`, not public) | 依赖登录未完成、HTTP分配0；原操作错误保留 |
| 延长窗口新意图 (`artifacts/M11/gate4-scheduled-reviewer-credential-revocation-extended-window-prepare-http-original.json`, not public) | 新三票批准/激活日程，区别于首个已成功日程 |
| 真实审批人密码重置 (`artifacts/M11/gate4-scheduled-reviewer-credential-revocation-extended-window-reset-reviewer-http-original.json`, not public) | 账号active、要求换密、角色保持；不替代后台结果SQL |
| 修复前状态投影失败 (`artifacts/M11/gate4-reviewer-revocation-before-mapping-fix-readonly.json`, not public) | 原active/无原因但零claim/发送，负例false保留 |
| 修复后自然API阻断 (`artifacts/M11/gate4-reviewer-revocation-after-mapping-fix-readonly.json`, not public) | blocked/REVIEWER_INACTIVE、三票及零claim/source/execution/send/mutation |
| 完成换密与新会话 (`artifacts/M11/gate4-scheduled-reviewer-credential-revocation-extended-window-complete-password-change-http-original.json`, not public) | 真实换密、新SID、角色不变，旧blocked日程未重启 |
| 剩余两对象恢复HTTP失败 (`artifacts/M11/gate3-consumer-b-two-remaining-restore-http-original.json`, not public) | 新意图/三票后的原403保留，无原生重试 |
| 失败后实际完整事实 (`artifacts/M11/gate3-two-remaining-restore-first403-actual-facts-readonly.json`, not public) | 七对象基线/五条观察、发送0、failed/mutation早期标记保留、entry仍restoring |

该阶段聚焦测试及Source助手检查不构成新的完整源码回归；先前450文件/8,515项仍为最后审计SQL转换修复之前。后续部署与回归见下节；此阶段HMAC/ACL未恢复，不将后续结果覆写为此前已经通过。

## 2026-10-13 e360快照：双worker单次执行与二包失败元数据收口

### 两个独立原始worker

原始胶囊源码SHA256为 `121160d91fd3dcf971b363115a1e49e23d2b92a9747410bff4e173a75213250b`。首轮操作者创建容器时未保持stdin，两个实例均在manifest验证处失败，tickInvocations均0；自有API恢复运行后，原已批准日程自然执行成功一次。该首轮双worker报告继续为false，不把API后续成功算作多实例竞争通过。

修正stdin编排后，另建独立意图、重新三票审批并真实退出提交人会话。到期前暂停自有API定时器，两个独立Nest实例分别初始化真实原始worker并各调用一次tick，未替换actor、SID或私有执行句柄。实例A实际claimed1/completed1，实例B claimed0/blocked1；执行结束后恢复原API。这项确实有两个原始worker tick，与前述无手动tick的自然API执行分开。

独立SQL及运行证明确认：该新日程succeeded、三票保留，claim/source/execution/baseline/attempt/send-intent/mutation各1，真实原生2xx结果1、工作流成功审计1；scheduled-entity来源SID为NULL、generation1、基线三对象、未决变更0。最初SQL报告携带只读模板的 `manualWorkerTickInvoked=false`，与实际运行不符；保留原报告并由canonical证明明确纠正为 `manualOriginalWorkerTicksInvoked=2`、两个真实独立Nest实例。后续引用以canonical报告为准。该结果证明此有界双worker竞争的单次执行，不代表持续生产HA、网络分区或发送中崩溃恢复通过。

### 二包failed来源的受限收口

冻结候选 `23ff64c255f3b0a6fbf874fceca67be22fd2239d3abdc2547988332a4dc80bbc` 已部署，schema仍为SQL000–025。重启后最早即时fetch遇连接拒绝，随后真实readiness200；该观察为启动瞬态，不能记为已运行API的业务故障。

对新二包原403调用专用元数据收口，首次返回409：HMAC节点实际上已经failed，而回收条目仍restoring，旧收口前提错误地只接受pending。实际库证明409请求无效果，修复审计0、原一条结果事实/五条存在观察不变，workflow/execution/mutation均failed，mutation早期标记保留。

最小状态前提修复后，冻结候选 `e360b23a786ef10b1728dffbaf45dd656cbb00f8bb061e77e4518d731f7774ff` 已正式部署，SQL025原摘要和26条迁移不改。已failed节点只允许精确核验并推进entry CAS，审计before记录真实failed，不将其重新写成pending。使用同一原元数据键和正文的后续核验实际返回HTTP200，原生发送0；回收条目由restoring变为partially_restored，新增真实恢复审计1，workflow/execution/mutation保持failed，原403、原一条结果事实及五条观察保留。原七包partial来源和五条成功原生回执未被修改。这是受限元数据核验，不是原生执行重试，也不表示HMAC/ACL已恢复。

基于当前partial图又准备新的独立两包恢复意图并重新三票审批；该后续结果见下段，未获得恢复成功。五类认证代理助手及OAuth2 TLS/token链仍未运行，不能将源码存在、新工单批准或entry收口视为完整恢复和业务认证通过。

新工单 `f1c82af4-819f-41a9-9ad7-690f31690816` 实际执行返回403 `KONG_EXECUTION_RESPONSE_LIMIT`，见 新两包恢复原HTTP (`artifacts/M11/gate3-consumer-b-two-remaining-restore-after-observer-fix-http-original.json`, not public)。原请求未重发。首个独立事实查询又因不存在列返回42703，原false报告保留；修正节点状态查询后，真实库证明完整七对象基线、五条存在观察、attempt1/outcome1、send-intent0，W/E/mutation均failed、早期remote_started=true及null result保持，HMAC失败且ACL未尝试，认证的零发送结论通过。该结论来自真实传输/持久事实，不是仅凭403推断。

使用同一原执行键通过元数据收口端点实际返回HTTP200、原生0；实际SQL进一步确认恢复审计1、entry为partially_restored，原W/E/mutation仍failed、早期标记/null result/原结果/五条观察不变，原403保留。这是此次新失败自己的收口，不复用前一metadata200作证。Kernel已定位重复完整GraphCapturer读取累计消耗100页预算，Source修复仍待完成，没有盲目增加上限。HMAC/ACL恢复和认证继续待验收。

| 最新预算失败证据 | 精确范围 |
| --- | --- |
| 首个SQL查询失败 (`artifacts/M11/gate3-two-remaining-restore-response-budget-actual-facts-readonly.json`, not public) | 原42703保留，不能算通过证明 |
| 准确节点/执行事实 (`artifacts/M11/gate3-two-remaining-restore-response-budget-node-states-actual-facts-readonly.json`, not public) | 原failed来源、七对象基线、五条观察、零发送及未恢复两节点 |
| 原键元数据HTTP200 (`artifacts/M11/gate3-two-remaining-response-budget-terminal-metadata-http-original.json`, not public) | 此次失败自己的原执行键，原生0、原HTTP403与failed保持 |
| 本次收口后真实库 (`artifacts/M11/gate3-two-remaining-response-budget-terminal-metadata200-readonly.json`, not public) | entry partial、审计1、原W/E/m/标记/结果/观察不变；不证明两凭证恢复 |

| 新证据 | 精确范围 |
| --- | --- |
| 首轮双worker编排失败 (`artifacts/M11/gate4-two-original-workers-runtime-original.json`, not public) | stdin未保留、两个manifest失败/tick0；原false不覆盖 |
| 新独立双worker实际运行 (`artifacts/M11/gate4-two-original-workers-stdin-fix-runtime-original.json`, not public) | 新三票/退出、两个Nest实例各tick1、A完成/B阻断、原API恢复 |
| canonical双worker证明 (`artifacts/M11/gate4-two-original-workers-independent-sql-and-runtime-proof.json`, not public) | SQL与运行精确关联、单claim/send/2xx/audit、NULL SID；明确原模板tick字段纠正 |
| 原SQL模板报告 (`artifacts/M11/gate4-two-original-workers-single-native-sql-readonly.json`, not public) | 原事实保留；manualWorkerTickInvoked字段不能作为实际调用次数证明 |
| 23ff候选部署 (`artifacts/M11/partial-no-send-runtime-deployment-original.json`, not public) | 专用库备份、冻结源码、SQL000–025部署/授权 |
| 启动后readiness (`artifacts/M11/partial-no-send-runtime-readiness-after-startup.json`, not public) | 真实200；最早即时连接失败记录保留 |
| 首个收口请求失败 (`artifacts/M11/gate3-two-remaining-terminal-metadata-http-original.json`, not public) | 原409保留，无自动原生重放 |
| 409后无效果事实 (`artifacts/M11/gate3-two-remaining-metadata409-state-readonly.json`, not public) | 节点已经failed、entry仍restoring、修复审计0、原结果/观察保持 |
| e360节点状态修正部署 (`artifacts/M11/partial-node-state-runtime-deployment-original.json`, not public) | 只修状态前提，迁移范围/SQL025摘要保持 |
| 修正后收口HTTP200 (`artifacts/M11/gate3-two-remaining-terminal-metadata-after-node-state-fix-http.json`, not public) | 同原元数据键/正文，原生0，原workflow仍failed与HTTP403保留 |
| metadata200后实际库 (`artifacts/M11/gate3-two-remaining-terminal-metadata200-readonly.json`, not public) | entry partial、W/E/mfailed不变、原flags/事件/观察保持、恢复审计1；HMAC/ACL未恢复 |

### 本轮回归状态

23ff阶段整仓运行实际为464文件/8,748项，其中8,746通过、两项独立SQL用例超时；原超时保留，不能写为全通过。独立重跑六项SQL用例耗时约36秒并全部通过，只证明该独立复验。

e360候选随后以 `--maxWorkers=2` 完成真实完整源码回归：**464文件 / 8,760项全部通过，耗时222.98秒**。从原私有日志只提取通过计数、耗时并记录整份日志SHA256，公开 源码结果摘要 (`artifacts/M11/full-source-regression-e360-two-workers-summary.json`, not public)，未复制原日志或发布凭证。此独立完成的整仓运行取代“尚在运行”的进展状态，不覆盖旧超时、不相加旧测试数量；后续源码修改需要另行验证。源码全部通过仍不能替代上述真实恢复失败、协议认证或生产部署的验收。

后续先核验新两包真实恢复和原ID/各协议认证，再补剩余预约、窗口、发送中故障及适配器/用户写入链，完成最终冻结回归、审计和秘密扫描及持久部署验证。**本快照仍未接受M11整体或平台商用。**

## 2026-10-13 fe1快照：完整七节点恢复与工单看板

### 修复部署与仅剩两对象的实际恢复

重复全图读取按执行阶段使用独立有界预算，原总限额没有盲目扩大。冻结候选 `fe1f812d24f503b5d51c07b13a1698c5ab44236bc4e95f6c8d9d064397bf539f` 已部署，SQL000–025及已应用摘要不改，后续未应用的迁移未纳入候选。候选还含Target历史适配与未来影响预约源码修复，这些源码存在不等于各自现场写入/冲突专项已经验收。49项Kernel与80项影响域聚焦检查及类型检查通过，范围不相加，也不冒用e360旧全测。

原Python代理readiness工具连续未得到ready，其false报告保留；独立容器内部网络实际HTTP200证明此候选已就绪。两个不同检查路径分别记录，不把代理工具失败改成成功或据此判定API未运行。

恢复另建全新意图、独立三票批准后，工单 `c5000c73-8a61-44f6-9972-011b03265b00` 实际返回HTTP201/succeeded。独立SQL确认来源 `7ace58b0-b22b-4591-a8f3-b0d32fe81962`：完整七对象基线、五条已存在对象观察、attempt/send-intent/outcome各2；两项mutation分别为HMAC/ACL succeeded，真实原生201结果2，成功执行审计1。七节点归档及各节点均restored，原ID保持，旧五对象没有重新创建；原七包partial与此前两个failed工单仍保留原状态。此次证明完整对象图恢复，不代表Basic/JWT/HMAC/ACL/OAuth2业务认证已经通过。

在fe1这一历史阶段，新认证夹具准备在前置核验停止，公开原报告为false、请求写入列表为空，没有新intent或业务写入；原Consumer/材料/政策/归档的只读比对已通过，当时尚未执行正负代理认证。后续修正政策selector集合比较的顺序问题，新独立夹具与10次真实探测已通过，详见下一快照；原false不改，也不借旧Consumer A的结果替代Consumer B验证。

### 看板、侧栏与入口加载

新增「列表 / 看板」切换显示同一服务端游标页。真实后端浏览器通过11项只读检查和两张截图：四列「待审批 / 待执行 / 执行中 / 执行结果」、当前页数量及范围提示、移动端无横向溢出、业务写入0、Admin API直连0、页面错误0。页面的待审批/待执行超期角标只作提醒，不修改后台执行状态；窗口冲突仍由预约/执行专项判定。

独立布局诊断记录viewport高1000px、侧栏976px、导航可视区852px、28个菜单项及导航自身滚动。整页截图中的sticky拉伸属于截图呈现，不能当作实际侧栏高度缺陷；不为截图改变正常布局。手册/Vitals改为按需加载后，Console Web入口JS由约2.78MB降为2.05MB，gzip由约893KB降为635KB；这是构建入口产物比较，不扩展为完整性能/容量验收。

| fe1阶段证据 | 精确范围 |
| --- | --- |
| fe1候选部署 (`artifacts/M11/partial-phase-budget-runtime-deployment-original.json`, not public) | 冻结源码、控制台备份、迁移范围SQL000–025及API部署 |
| 原代理就绪失败 (`artifacts/M11/partial-phase-budget-runtime-ready-original.json`, not public) | 原false保留，不替代内部HTTP结果 |
| 独立内部就绪200 (`artifacts/M11/partial-phase-budget-runtime-ready-direct-internal-original.json`, not public) | 实际容器内部HTTP200及准确候选摘要 |
| 新两对象恢复HTTP (`artifacts/M11/gate3-consumer-b-two-remaining-restore-after-phase-budget-fix-http-original.json`, not public) | 新工单/三票、成功2包、原ID、完整归档restored；认证未运行 |
| 新恢复独立SQL (`artifacts/M11/gate3-two-remaining-phase-budget-restored-two-native-success-readonly.json`, not public) | baseline7/存在观察5/原生201两条/成功审计1/all7 restored/旧五不重建 |
| 认证夹具前置停止 (`artifacts/M11/gate3-restored-credential-probes-create-probes-http-original.json`, not public) | 原false、业务写入0；没有正负认证运行 |
| 看板实际浏览器 (`artifacts/M11/workflow-board-browser-readonly-original/verification.json`, not public) | 11项真实只读检查、两截图、当前游标页、移动端/边界 |
| 侧栏实际布局诊断 (`artifacts/M11/workflow-board-browser-readonly-layout-diagnostic-original/verification.json`, not public) | viewport/sidebar/navigation高度、28项菜单与内部滚动 |

fe1阶段仍有协议认证、Target及其他专项待验证。以下cd70232快照记录新增实际结果；通用业务工单定时foundation在两个阶段均未安装、迁移或执行，不以其文件或SQL026候选宣布M8/Promote/门户定时已交付。

## 2026-10-13 cd70232历史快照：恢复凭证认证与Target权重

### 实际部署边界

冻结运行源码摘要为 `cd70232c772e43bb3ea7de83d144c36a41bf8a31cb17e61f4f1387a73d08c7d7`，本轮只增加Target schema正式暴露修复；真实readiness返回HTTP200。已应用迁移仍为SQL000–025，共26条，原已应用摘要保持。SQL026通用业务调度候选没有应用，相关provider/worker没有在运行服务注册。后续权重0回读修复和专用元数据核验源码均不在此部署的通过范围。

### 五类恢复凭证的真实正负认证

Consumer B完整七节点已恢复后，重新完成原Consumer、原凭证ID、私有原认证材料、当前政策与已登记代理地址的前置核验。三个全新工单各自经过三票审批，分别创建专用Service一项、Routes六项、仅绑定专用Route的Plugins八项，共15次真实原生201；没有修改原echo Service或其Plugin。准备阶段18次BFF写请求与15次原生创建是不同计数，不合并为单测或原生请求数量。

通过正式BFF代理探测入口向真实已登记Kong代理发送10次请求，结果如下。BFF创建探测记录的HTTP201不等于代理状态；表中是实际代理响应。

| 恢复凭证/访问策略 | 正向代理结果 | 负向代理结果 |
| --- | --- | --- |
| key-auth | 原API Key返回200 | 错误Key返回401 |
| basic-auth | 原密码返回200 | 错误密码返回401 |
| JWT | 原签名材料及issuer返回200 | 错误签名返回401 |
| hmac-auth | 原材料签署Digest/date/request-line返回200 | 错误签名返回401 |
| ACL | 原Consumer通过Key认证、原组允许时返回200 | 同一Consumer通过Key认证、组不允许时返回403 |

这证明五类恢复后的真实认证/访问控制，不只比较DAO配置。公开报告仅含状态和受保护摘要，不发布凭证、Cookie、认证头或响应正文；没有重试、跳转、直连Admin API或绕过TLS校验。前一次准备停止的原false报告继续保留。全局插件前置核验仅覆盖已枚举的有效/停用控制台工作区，不扩大为所有未归属或已删除工作区对象的完整盘点。

OAuth2仍只证明凭证对象存储恢复；**真实HTTPS授权、发token、access/refresh token及吊销链未运行**。五类10次探测不能替代OAuth2、浏览器业务写入、持续HA、未知结果恢复或生产站点验收。

### Target 100/80已验证，0保留未决事实

通过新的固定类型准备、三票批准与完整基线，Upstream创建及Target权重100创建各收到真实原生201。随后另一个新三票工单将同一逻辑 `host:port` 权重追加为80，收到真实原生201和新的Target UUID；旧100记录仍在历史中，BFF历史为两行、有效目标为一行80。该子项验证Kong1.5的追加记录行为，不代表原历史行被更新，也没有独立SQL证明本子项全部只追加约束，Target健康/定时/回滚仍待独立验收。

权重0又使用全新三票工单 `a873d69b-2537-4b99-b874-f49c6d490bae`，执行原HTTP503。独立只读核验确认来源 `b10cf921-e277-48c9-b03e-34096f4f5383`，工作流/执行/mutation保持uncertain，完整基线三对象，attempt/send-intent/outcome各一；mutation的 `remote_started=true`、`remote_completed=true` 且真实结果存在，错误为 `KONG_VALIDATION_ERROR`。原发送结果不是零发送，也不是空结果。

另一次独立核验认证原始返回对象：Target ID `1ae620c1-0d9f-4388-a8da-6b2c27f90523`、原Upstream与 `echo:8080`、weight0。结果HMAC与原outcome记录一致，证明Kong已保存0；故障发生在写后使用旧活跃Target点查询回读，Kong返回400。原outcome仍为sent-unknown、nativeStatus为null、metadataComplete=false，不伪造原生201或将原工单改成功。原失败、早期标记及发送/结果事实均保留，没有重发原请求。

未来权重0回读源码修复144项聚焦检查通过，但尚未部署；专用已知结果元数据核验仍在Source开发，本快照没有可供运行使用的Target安全收口。值班应保持原范围阻断，只读保留原键、工单/执行/来源、原目标和新增UUID及真实结果；不能换键补发0、删历史行、复用Consumer收口端点或执行新回滚。专用收口正式部署并完成实际认证核验后，才可闭合原操作；后续业务权重变更仍须按当时状态新准备、新审批，不能当作旧请求重试。

| cd70232阶段公开证据 | 精确范围 |
| --- | --- |
| Target schema候选部署 (`artifacts/M11/target-schema-runtime-deployment-original.json`, not public) | 实际部署摘要，SQL000–025，未应用后续迁移 |
| 真实启动就绪 (`artifacts/M11/target-schema-runtime-ready-original.json`, not public) | HTTP200、准确候选及026未应用边界 |
| 新认证夹具 (`artifacts/M11/gate3-restored-credential-probes-create-probes-after-selector-order-fix-http-original.json`, not public) | 三个新工单各三票，Service1/Routes6/Plugins8，原Service/Plugin不改 |
| 十次真实认证探测 (`artifacts/M11/gate3-restored-credential-probes-probe-auth-after-selector-order-fix-http-original.json`, not public) | 五类正负实际代理200/401或200/403；OAuth2待验收 |
| Target原始创建失败 (`artifacts/M11/target-weight-create-http-original.json`, not public) | schema暴露修复前的原false保留 |
| Target 100创建 (`artifacts/M11/target-weight-after-schema-exposure-fix-create-http-original.json`, not public) | 新Upstream/Target、新三票、原生201及历史/有效视图 |
| Target追加80 (`artifacts/M11/target-weight-after-schema-exposure-fix-update-weight-http-original.json`, not public) | 新三票、新UUID、原生201、旧100历史保留 |
| Target 0原HTTP503 (`artifacts/M11/target-weight-after-schema-exposure-fix-weight0-http-original.json`, not public) | 原false及原工单不改；不据预写80状态断言未写0 |
| 0请求实库未决事实 (`artifacts/M11/gate3-two-remaining-restore-target-weight-zero-503-actual-facts-readonly.json`, not public) | W/E/mutation uncertain、一次发送/结果、真实结果非空 |
| 0原生返回对象核验 (`artifacts/M11/target-weight-zero-original-native-result-readonly.json`, not public) | 原返回weight0及新UUID，认证结果，未重发 |
| 原outcome来源核验 (`artifacts/M11/target-weight-zero-original-outcome-provenance-readonly.json`, not public) | 原结果HMAC一致、remoteCompleted=true、metadata未完成及nativeStatus=null |

cd70232阶段结束时，e360完整源码回归仍仅覆盖此前候选464文件/8,760项；该阶段的Target0收口、OAuth2真实TLS链等尚待完成。后续实际部署和Target闭合见下一节，不能把后续结果改写为当时已通过。**M11整体及平台商用验收仍未通过。**

## 2026-10-13 8a8a33快照：Target结果闭合与正常零权重链

### 冻结运行候选与正式迁移

本阶段采集时，自有隔离API的冻结源码摘要为 `8a8a33e0a48a92946956b419cb47377cf9289f7e97ab1a98dc20c1ea237e4401`，包含344个冻结文件，实际readiness返回HTTP200。正式迁移账本已包含SQL000–027共28条；SQL000–025原文件及校验和不变。SQL026摘要为 `a447e5027a9045d2bd72795ed1892de96f1d01a068960cfe03b41f5ca0f46ca4`，SQL027摘要为 `967ee9e56c57ba7be4f4c558c33ed6a5af8a683a316db234443d04375d8c169f`。

SQL026正式应用只证明通用业务排程的数据库基础，不是M8配置发布、Promote或门户凭证排程已经可用。该候选未注册对应业务provider/worker，也未部署后续候选只读授权与业务上下文源码，不能借已迁移表获得后台网关写许可。现有SQL024实体排程子集继续按前述独立验收范围判断。

实际事务先执行026→027完整DDL回滚预检，通过五组检查：真实PostgreSQL解析、十张事实表只追加及progress不可删除、受限角色不可UPDATE、原Target uncertain不能缺认证观察直接变成功、DDL与授权全部回滚且原账本不变。正式迁移后的Target观察表运行角色具有SELECT/INSERT，UPDATE/DELETE/TRUNCATE均拒绝；该报告在观察插入之前采集，原mutation仍uncertain且观察0是当时事实，不作为最终状态证据。

### 原503的受认证结果核验，没有重发Target

原工单 `a873d69b-2537-4b99-b874-f49c6d490bae`、执行 `9d855342-316f-497b-8965-d2101417c69f`、mutation `d970379e-2a28-4e92-8498-fe76213ffba5` 仍对应原Source、原执行键、三对象基线及单一attempt/send/outcome。原始密文结果及HMAC、生产者的真实201后保存契约与完整审批事实分别认证，不能把旧outcome中的null改写为原生201，也不能用一个空列表猜测原请求成功。

第一版专用元数据核验实际返回502 `TARGET_DISABLED_READBACK_INVALID`。独立SQL确认整笔事务回滚：观察与核验审计均0、四项状态仍uncertain，原source/baseline/attempt/send/outcome/mutation各1，网关发送0。原502报告保留。后续核对Kong1.5原生`clean_history`行为发现：网关会自行清理失效历史，包括最新weight0和同地址旧记录，真实历史及有效目标均为空；控制台没有额外DELETE。修复将原真实POST结果与当前原生历史清理观察分开，并要求稳定的有界完整历史/有效目标EOF核验，不伪造Target GET回显。

修复部署后，原执行人在当前真实会话下沿用原execute键和精确原材料调用受限核验，实际HTTP200。独立SQL确认：workflow/execution/step/mutation均succeeded；仅新增观察 `f6a18b8b-23a1-40ad-9265-7dc25d226407` 与审计 `c580aa30-0ce2-4965-893b-f0ca1b8682fe` 各1，原六类事实计数各仍1，原返回密文HMAC不变。观察v2记录 `historyRetention=native-pruned`、当前有效目标不存在及受契约认证的原201；旧outcome仍为 `sent-unknown`、native_status为NULL、错误 `MUTATION_RESULT_UNCERTAIN`，mutation旧错误 `KONG_VALIDATION_ERROR` 和早期remote标记保留。新增认证观察与旧失败事实共同解释最终状态，不覆盖历史。

该核验事务没有原生写入。随后同一原键、相同材料再次实际HTTP200，`alreadyReconciled=true`；独立SQL确认复用同一观察/审计，计数不增加且网关重发0。只有这组明确完成的原操作解除验收账本中的未决写阻断，不将固定核验推广为通用unknown重试、任意自动收尾或伪造执行证明。

### 全新四工单的正常100→80→0路径

另建Upstream `958e40f4-5714-43f6-a609-5dc49e4472f4`，通过四张独立新工单完成Upstream创建、Target100创建、同地址追加80及追加0。每张均有真实三票审批、独立来源、完整基线、单一attempt/send及真实原生201，workflow/execution/mutation均succeeded；四次发送与四条原生201由独立SQL核对。零权重操作在正常写入路径直接成功，`safe_result`保留真实POST返回，另记原生历史已清理及当前有效目标不存在；未复用或重发原503操作。

这证明新Target正常零权重路径及原已知结果的受限核验，不能扩大为全部健康置位、定时Target、回滚或未知发送故障矩阵已经通过。

| 8a8a33阶段公开证据 | 精确范围 |
| --- | --- |
| 冻结部署 (`artifacts/M11/target-native-cleaner-runtime-deployment-original.json`, not public) | 实际冻结摘要、部署、迁移至027；业务provider未注册 |
| 实际readiness (`artifacts/M11/target-native-cleaner-runtime-ready-original.json`, not public) | 真实HTTP200，当前候选就绪 |
| 026独立DDL回滚预检 (`artifacts/M11/business-scheduled-026-ddl-rollback-trial-after-uniform-column-fix.json`, not public) | 数据库基础约束/运行角色，试验全部回滚 |
| 026→027回滚预检 (`artifacts/M11/target-result-026-027-ddl-rollback-trial-original.json`, not public) | 五组真实实库检查，原账本不变，网关写入0 |
| 正式迁移账本与运行角色 (`artifacts/M11/target-result-runtime-ledger-role-readonly.json`, not public) | 28迁移及027观察表SELECT/INSERT，禁止UPDATE/DELETE/TRUNCATE；观察插入前状态 |
| 原生产者编译契约核验 (`artifacts/M11/target-weight-zero-producer-contract-compiled-readonly.json`, not public) | 原部署真实结果保存位置与201契约，不改旧null回执 |
| 首版核验502 (`artifacts/M11/target-zero-original-result-metadata-reconcile-http-original.json`, not public) | 原false保留，没有Target重发 |
| 502零效果独立SQL (`artifacts/M11/target-original-metadata502-zero-effects-readonly.json`, not public) | 事务回滚、观察/审计0、原状态与六类计数保持 |
| 修复后原键HTTP200 (`artifacts/M11/target-zero-original-result-metadata-reconcile-after-native-cleaner-fix-http-original.json`, not public) | 原账号/原键、认证观察及审计、网关发送0 |
| 核验后独立SQL (`artifacts/M11/target-zero-result-reconciled-independent-sql-readonly.json`, not public) | 四态succeeded、观察/审计各1、旧sent-unknown/null错误与原结果不变 |
| 原键再次核验HTTP200 (`artifacts/M11/target-zero-certified-metadata-idempotent-http-original.json`, not public) | alreadyReconciled、同一观察及审计、网关发送0 |
| 再次核验后独立SQL (`artifacts/M11/target-zero-result-reconciled-after-idempotent-independent-sql-readonly.json`, not public) | 计数不增加、原结果不变、没有重发 |
| 新四工单独立SQL (`artifacts/M11/target-native-cleaner-four-original-native-sql-readonly.json`, not public) | 各三票/单一发送、四次真实原生201，0正常路径成功 |
| 正常0原HTTP记录 (`artifacts/M11/target-weight-after-native-cleaner-fix-weight0-http-original.json`, not public) | 新工单独立正常执行，不重试旧503 |
| 当前历史/有效目标核验 (`artifacts/M11/target-weight-after-native-cleaner-fix-readonly-http-original.json`, not public) | 新逻辑目标真实停用及原生历史清理观察 |

### 此轮可信HTTPS历史前置与看板

此轮先在自有隔离代理增加SSL监听、短期测试证书与独立边缘网络，受信任CA、正确SAN/主机名连接`authorized=true`并得到真实404，错误SAN被拒绝。后续确认这对应另一自有实验网关，未命中本次OAuth2目标集群；原404及错误SAN证据仅保留为该入口的历史传输前置，不作为目标OAuth2工作区的协议证明。纠正实际clusterId对应`stage-kong-admin`的网关后，原另一网关还原HTTP-only；目标代理网络与协议结果详见下一节。镜像内容、Kong源码均未更改，也没有直连Kong数据库。

可信HTTPS证据见 实际TLS及错误SAN拒绝 (`artifacts/M11/oauth2-business-https-trust-after-explicit-edge-original.json`, not public)。最新工单看板 14项只读浏览器验证 (`artifacts/M11/workflow-board-browser-readonly-after-compact-height/verification.json`, not public) 另确认桌面分页可见、列独立滚动、侧栏完整可用及手机无横向溢出，写入/Admin直连/页面错误均0；与旧11项报告分别保留，不累加计数或称为浏览器写入链通过。

此历史阶段仍待OAuth2完整HTTPS业务链，其后实际结果见下一节。其余特殊对象和Target健康/回滚、影响预约与逐包撤权/窗口、发送中故障及未知结果恢复、通用M8/Promote/门户业务排程、实际浏览器写入链仍待验证。最终冻结发布候选后再做完整源码/镜像回归、审计/秘密扫描及持久生产部署和恢复验证；e360的8,760项只覆盖其原冻结版本。**M11整体及平台商用验收仍未通过。**

## 2026-10-14 OAuth2：真实HTTPS协议与审批回收恢复验收

### 实际目标与传输边界

本次通过的汇总为 OAuth2 HTTPS协议及审批回收恢复验收 (`artifacts/M11/oauth2-https-approved-recycle-restore-protocol-acceptance-original.json`, not public)。实际clusterId `095b11dd-a414-4f76-b591-9fdfa4a29d83` 的Admin注册主机为`stage-kong-admin`，TLS代理为同一物理目标的自有隔离网关。独立边缘网络仅连接该目标代理，业务8443经5463进入验收入口；Admin端口没有发布。此前另一自有网关已还原HTTP-only，原1.5.1镜像内容、内部Admin/数据库网络不变，无Kong源码修改或数据库直连。

正确目标上的只读HTTPS检查缺token返回401，socket已通过CA、SAN、主机名校验；错误SAN返回 `ERR_TLS_CERT_ALTNAME_INVALID`。协议请求继续严格校验证书，不使用HTTP终止头绕过，不重试POST、不跟随重定向。授权码及token请求走真实Kong代理OAuth2端点；token Admin API及不存在的代理revoke端点请求均0。这是隔离协议验收，不能代替正式站点TLS部署或浏览器写入链。

### 新鲜同一令牌的完整生命周期

前置只读检查复用已经创建的专用Service/Route/route-only OAuth2 Plugin，不再创建或执行其原工单。每阶段核验原Consumer、原OAuth凭证、私有原client_id/client_secret材料、其余五类凭证ID及实际三审批人政策，其他五类凭证没有删除或重建。

新的授权码/token/refresh阶段以可信HTTPS实际得到正确授权码、access token及单次轮换refresh；正向请求200，缺失/错误token401，刷新后原access401，旧refresh重复使用400。之后两个全新工单各自重新三票审批并执行：先将原OAuth客户端凭证删除进回收站，后用完整两节点归档恢复原凭证ID `7ac51421-2063-46fe-96fa-8fab726329ce`、client_id及原client_secret。它们是独立新意图、新审批和新执行，不重放此前配置工单。

| 实际协议观察 | 实际响应 | 证明条件 |
| --- | --- | --- |
| 吊销前使用当前access token | 200 | 同一个之后被核验的access token仍未自然过期 |
| 三票删除凭证后使用该access token | 401 | 原Consumer保持，原凭证进入回收站；同一token仍未过期 |
| 删除凭证后使用对应refresh token | 400 | 同一次令牌生命周期，未用自然过期替代吊销 |
| 原ID/client_id/秘密恢复后使用旧access token | 401 | 同一旧token仍未过期，恢复没有令其复活 |
| 原客户端恢复后使用旧refresh token | 400 | 旧令牌与授权码不属于可恢复凭证归档 |
| 原客户端恢复后重新授权、换token并访问 | 200 | 实际身份观察确认为原Consumer |

独立SQL覆盖此前五个真实配置工单及本次两个新工单：七张均succeeded，每张三票、单一attempt/send/native成功，共21票、5次原生201及2次原生204。前五张为专用Service/Route/Plugin创建及此前一次凭证吊销/恢复；新两张仅为新鲜周期的OAuth凭证删除204和原ID恢复201。协议HTTPS请求、BFF元数据请求、投票及原生配置包是不同计数，不合并为测试数或假称七次授权请求。公开报告不含token、client_secret、provision key、Cookie或响应正文。

### 原失败、令牌自然过期与只读未知仍保留

首次协议阶段误指另一自有实验网关，缺tokenGET实际404而停止，OAuth POST0；纠正目标后，授权与token两个POST实际200，资源GET也200，但原echo夹具未提供Consumer身份观察，整阶段保持false并停止，未重放这两个POST。随后仅更新自有测试echo，加入来自真实上游请求的`X-Consumer-ID`观察，保留原method/path/host/health字段；没有修改OAuth认证、Kong网关逻辑或伪造Consumer身份。

此前一轮吊销的同一未过期token失效已实际观察；用户暂停期间经过约四小时，旧token在原客户端恢复前已自然过期。恢复工单的原生201确已成功，但本地验收转发进程失去连接，后续只读GET发生 `ECONNREFUSED` 并保持 `response_unknown`，不能将其改成401、补响应或重执行恢复。独立五工单SQL与固定只读GET语义证明分别核实已成功配置及该未知GET的只读性质，原未知状态不变。新鲜周期使用另两张工单及新令牌，在同一令牌仍未过期时完整验证吊销、恢复不复活与新授权成功；自然过期后的拒绝没有充当本次吊销证明。

| OAuth2公开证据 | 精确范围 |
| --- | --- |
| 完整协议及回收恢复汇总 (`artifacts/M11/oauth2-https-approved-recycle-restore-protocol-acceptance-original.json`, not public) | 实际完整链通过，7原生配置/21票；M11整体和生产部署仍false |
| 正确物理集群TLS部署 (`artifacts/M11/oauth2-business-tls-original-cluster-corrected-runtime-original.json`, not public) | 原另一网关还原、仅目标代理在边缘网络、无Admin发布/Kong源码修改/数据库直连 |
| 正确目标TLS只读核验 (`artifacts/M11/oauth2-original-cluster-https-route-trust-readonly-original.json`, not public) | 真实缺token401、socket受信任、错误SAN拒绝 |
| 原专用夹具创建 (`artifacts/M11/gate3-restored-oauth2-https-create-probes-http-original.json`, not public) | 三个实际新配置工单，不据此认为协议已通过 |
| 已有夹具只读复用 (`artifacts/M11/gate3-restored-oauth2-https-verify-original-fixtures-http-original.json`, not public) | Service/Route/Plugin当前配置核验，创建重放0 |
| 新鲜授权与刷新 (`artifacts/M11/gate3-restored-oauth2-https-fresh-issue-refresh-http-original.json`, not public) | 真实HTTPS正负访问、授权/token及单次refresh，旧令牌失效 |
| 新鲜三票吊销 (`artifacts/M11/gate3-restored-oauth2-https-fresh-revoke-client-http-original.json`, not public) | 独立新工单删除204，仍未过期同一access401/refresh400 |
| 新鲜三票恢复 (`artifacts/M11/gate3-restored-oauth2-https-fresh-restore-client-http-original.json`, not public) | 独立新工单原ID/原秘密恢复201；旧token不复活，新grant200 |
| 前五原工单独立SQL (`artifacts/M11/oauth2-five-original-native-before-fresh-cycle-sql-readonly.json`, not public) | 4次201/1次204，各三票/单次发送/成功；没有重放原恢复 |
| 新两工单独立SQL (`artifacts/M11/oauth2-fresh-unexpired-cycle-two-original-native-sql-readonly.json`, not public) | 1次201/1次204，各三票及单次发送，原五工单未重放 |
| 首次错误目标404 (`artifacts/M11/gate3-restored-oauth2-https-issue-refresh-http-original.json`, not public) | 原false、只读GET404、OAuth POST0 |
| 缺少身份观察的原阶段 (`artifacts/M11/gate3-restored-oauth2-https-issue-refresh-after-original-cluster-tls-fix-http-original.json`, not public) | 原false、两个OAuth POST200及GET200保留，阶段停止 |
| 真实echo身份观察修正 (`artifacts/M11/oauth2-echo-consumer-observation-fixture-original.json`, not public) | 仅自有echo夹具，真实上游Consumer ID观察，不重放token请求 |
| 原令牌过期边界 (`artifacts/M11/oauth2-original-unexpired-revocation-and-expired-restore-boundary-readonly-original.json`, not public) | 此前吊销有效，但恢复前已自然过期；当时新鲜周期尚待 |
| 原恢复成功但只读GET未知 (`artifacts/M11/gate3-restored-oauth2-https-restore-client-after-original-token-expiry-http-original.json`, not public) | 原生201成功，后续GET未知不改，原false保留 |
| 固定未知GET只读语义证明 (`artifacts/M11/oauth2-unknown-fixed-get-semantics-readonly-certificate-original.json`, not public) | 原response_unknown保持、无原生/token POST、不伪造响应或重执行恢复 |

### 业务排程源码桥与剩余发布工作

此阶段工作树的配置排程、审批嵌套执行、故障账本、执行来源、后台上下文与逐包验证读取桥分别通过聚焦源码检查；这些分项会重叠，不合计为一次完整回归，在当时6c24 API尚未注册业务provider/worker。最新7e2e3d的注册与只读启动证据见后节，实际后台M8 apply、Promote及门户凭证排程的准备、审批、激活、执行、失败恢复链仍待联调验收，不能延长旧计划、借只读调度或复制旧HTTP会话来开放写入。

OAuth2协议子项已闭合，但Target健康/回滚与其他特殊对象、逐包窗口/撤权、影响预约、发送中故障/重启及未知结果恢复、浏览器写入链、完整M0–M11回归、最终审计/秘密扫描、持久生产部署与恢复验证仍待完成。**M11整体与平台商用验收仍未通过，生产版本尚未发布。**

## 2026-10-14 6c24d1历史快照：Target已知结果展示与首次新整仓回归

### 实际部署与历史投影

本快照采集时，隔离API由8a8更新为冻结候选 `6c24d1c0234de7941aaf0a52cd1137fb5dadb0b85ff0fe90d4c2d5e99b177a25`，仍为344个冻结文件，只有两个Target历史结果投影相关源码文件变更；业务排程桥不在本候选，provider/worker未注册。独立运行核对两个实际编译文件与冻结材料一致，readiness为真实200，实际迁移账本仍28条且全部摘要一致，本次未重执行迁移或原部署。后续7e2e3d及30条迁移的证据另列，不改写本次历史统计。

原部署动作完成后，公开部署日志落盘因候选目录未包含artifacts/M11而失败；该false报告保留，未据此重放部署。随后只读路径诊断和独立运行证明确认实际候选及健康状态，不能把最初报告的`actualRuntimeProofPending=true`当作最终服务未启动，也不把后续证明改写进原失败文件。

原Target0工单的真实认证BFF历史GET已通过。原逐包状态仍为 `sent-unknown`、nativeStatus为NULL、错误 `MUTATION_RESULT_UNCERTAIN`；另附受当前范围认证的已知结果观察、原审计关联、观察时间与operationState=succeeded，工单终态为succeeded。它是只读解释已有认证闭合记录，不改原错误、不投影秘密、不制造原生201，不重发Target写入。观察ID仍为 `f6a18b8b-23a1-40ad-9265-7dc25d226407`，对应原元数据核验新增的同一不可变记录。

### 原窗口确认链与跨设备只读边界

页面为固定条件的原Target0工单提供「Target结果核验」。原窗口保留的真实execute键仅用于定位，先在当前真实会话/账号/集群/工作区读取原工单及actor-bound原回执；本地记录、复制DTO或按钮本身不授予写权。服务端允许且当前权限/原版本仍匹配后才开放「仅核验结果元数据」，输入`native-change`确认，临发前重新读取原详情和回执，沿用原execute键提交一次metadata。确认期间范围/账号/权限变化即重新核验，401或未知响应不静默换会话/自动重发POST。完成后仍须核对完整原回执与认证观察，不能只凭绿色标签消除本地未决写阻断。

跨设备或不保留原execute记录的窗口只读显示已有「原结果已核验」记录，不生成原键或替代键，不提供元数据写按钮；尚未闭合时提示返回原操作窗口，不能换键重执行原网关步骤。原窗口确实不可用或证据不足时继续由运维核对原事实，不伪造浏览器journal。

真实后端桌面/手机浏览器8项检查通过：当前真实会话、已知结果与同一观察ID、原unknown明确保留、跨设备无新键或元数据写按钮、手机无横向溢出、写入/Admin直连0及页面错误0。另一次独立2项检查确认桌面截图中已知结果卡片完整可见、写入及Admin直连0。两个报告分开保留，不累加为源码测试数，不称为浏览器确认metadata写入实测；受限后端原键HTTP200及幂等复用仍引用此前独立原请求证据。

| 6c24d1公开证据 | 精确范围 |
| --- | --- |
| 隔离候选冻结 (`artifacts/M11/target-historical-projection-isolated-source-freeze-original.json`, not public) | 344文件、两个历史投影文件变更，生成时待部署字段保留，排程桥排除 |
| 原部署日志落盘失败 (`artifacts/M11/target-historical-projection-deployment-journal-write-failure-original.json`, not public) | 原false保留，没有重放已执行部署动作 |
| 运行路径只读诊断 (`artifacts/M11/target-historical-projection-runtime-source-path-diagnostic-original.json`, not public) | 独立查明实际运行文件路径，不重部署 |
| 部署后独立运行证明 (`artifacts/M11/target-historical-projection-deployed-independent-after-path-fix-readonly-original.json`, not public) | 真实6c24编译文件/344文件、readiness200、原28迁移及全部摘要保持 |
| 认证历史GET (`artifacts/M11/target-result-authenticated-historical-projection-http-readonly-original.json`, not public) | 原sent-unknown/NULL/错误不变，另附认证观察与成功operation，秘密不投影、Native0 |
| 桌面/手机8项只读检查 (`artifacts/M11/target-result-historical-browser-readonly-original/verification.json`, not public) | 实际已知结果/原unknown/跨设备边界，HTTP业务写入/Admin直连0 |
| 桌面已知卡片可见2项 (`artifacts/M11/target-known-observation-visible-browser-readonly-original/verification.json`, not public) | 原卡片完整可见，写入/Admin直连0，不替代metadata写入验收 |

### 首次新整仓失败与修复的真实边界

此次完整源码冻结为 `d4e79daf325cdebf21b45c661d0916e8176ab751f3d5ef41f25ecfcd4c0dc041`，包含1,348个源码/测试文件，范围含尚未注册的业务排程桥；它与实际隔离API的344文件运行候选是不同统计范围。首次真实整仓运行502个测试套件，9,538项通过、40项失败；原失败与日志保留，不能因后续修复将这次全测改成通过。

其中38项来自旧Workflow依赖fixture缺新增Repository接口，1项来自M10回滚fixture缺新增Access方法；只补齐对应测试替身契约，没有放宽生产权限。独立源码报告确认两受影响套件55项通过、配置相关12套件345项通过及API类型检查通过，均是有重叠的聚焦验证，不相加为新整仓计数。

剩余1项是真实Context缺陷：普通HTTP祖先已关闭后，合法独立私有配置作业被错误地纳入该闭合链，导致fresh job无法启动。源码修复将独立作业的真实私有句柄校验与普通已关闭HTTP调用方分开，不继承旧HTTP身份；真正关联规划、候选读取、排程或验证读取品牌的祖先仍受闭合检查，不能借独立作业绕过其约束。Root实际聚焦运行4套件55项通过；该源码修复不在当时6c24运行候选，不以其聚焦结果宣称已部署或全部安全故障路径通过。

源码冻结见 本次整仓manifest (`artifacts/M11/current-source-regression-freeze-20261014-original.json`, not public)，该文件只证明冻结范围及摘要，不包含全测完成回执。原40项失败的分布与fixture修复结果见 聚焦fixture补齐检查 (`artifacts/M11/scheduled-configuration-regression-fixture-completion-source-checks.json`, not public)。本阶段采集时修复后完整回归尚待结果；随后原修复隔离候选9,578项通过见后节，原失败不改写。旧e360的8,760项、本次聚焦55项/345项或后续隔离修复全测均不能替代最终冻结发布候选全测。

### 此轮剩余工作

继续联调真实后台M8 apply、Promote与门户业务排程、Target回滚与其余特殊对象、逐包撤权/窗口/影响预约、发送中故障与重启恢复、浏览器业务写入链。随后按最终冻结源码/镜像/SQL完成完整回归、审计/秘密扫描、持久生产部署与恢复及启用外部提供者的现场联调。**当前仍为分项验收，M11整体和平台商用发布尚未完成。**

## 2026-10-14 7e2e3d装配：30条迁移、业务服务接入与隔离修复全测

### 原修复候选的完整源码回归

在首次9,538通过/40失败之后，原fixture契约及Context缺陷修复形成独立隔离候选。其首次隔离全测另发现两条生产启动正向夹具依赖调用目录，原失败报告保留；只将这两个夹具的公共目录参数改为不依赖cwd的路径，没有放宽生产路径白名单或权限。随后实际502套件、9,578项全部通过，`maxWorkers=2`，281.56秒；冻结API类型检查退出0，3,895个源码/依赖文件前后摘要全部一致。公开报告只给原日志摘要，不公开私有日志正文。

这个完整回归的范围是**原修复隔离候选及上述两个测试参数**；它没有部署，也不覆盖此后的7e2e3d业务装配、workspace/tag_group/entity范围读取、新身份尾部修复或业务排程前端。不能把9,578项通过标成最新整个工作树或生产版本通过，也不把有重叠的聚焦套件计数相加。

| 回归证据 | 范围 |
| --- | --- |
| 原修复隔离全测最终结果 (`artifacts/M11/full-current-source-regression-isolated-original-fixes-20261014-second-result.json`, not public) | 502套件/9,578项通过、类型检查、3,895文件摘要一致；排除后续装配与运行验收 |
| 首次整仓失败 (`artifacts/M11/full-current-source-regression-first-failure-20261014-original.json`, not public) | 原9,538通过/40失败保持，不覆盖为成功 |
| 首次隔离修复候选结果 (`artifacts/M11/full-current-source-regression-isolated-original-fixes-20261014-first-result.json`, not public) | 两条正向夹具目录问题的原失败保留 |

### SQL028/029实际预检与正式运行事实

新增SQL028 `028_m11_scheduled_execution_permission.sql` 摘要为 `45a3e58fa1dc6ba94408af1abf9090c77e0ecda71c385fc6b09790e5f67a512f`；SQL029 `029_m11_business_schedule_revisions.sql` 摘要为 `1f7beb3f6b2a3beea3edf85c262c5626a3f060e2dcb1b6cfe411999ee0663156`。最初SQL029大小写/语法预检失败，随后SQL已修正但Root检查器用了错误的revision触发器名，第二报告仍为false；两份原始报告均保留。第三次按真实触发器名独立检查通过，实际控制台运行角色测试权限字段、不可变来源及新revision约束，ROLLBACK后仍是原28条迁移，旧执行来源permission version为空且不能事后补写，没有网关发送。

之后正式隔离装配已部署 `7e2e3d895d3df98daa0ffa0a211e8e26bc533e33393d407a7b9d4491f9ce38ae`，368个冻结源码文件；SQL000–029共30条实际迁移已独立核对，原000–027文件及摘要不变。真实app角色 `kongpilot_lab_app` 对9张排程事实表均只有SELECT/INSERT，UPDATE/DELETE/TRUNCATE全部为false；新权限/revision触发器实际存在。Source冻结报告本身的sourceOnly字段不作为部署证明，部署事实引用后续独立运行源码及SQL只读报告。

运行服务已注册业务排程controller/provider，`BUSINESS_SCHEDULES_ENABLED=false`。真实新登录后的BFF核对readiness200、原目标集群登记正确、业务日程列表200且为空；旧Target0成功终态及同一已知观察保持。Root第一次只读检查用错Target摘要投影路径，原false诊断保留；改用实际 `nativeChange.packets[0].targetResultObservation` 路径后独立只读验证通过，没有重新执行原网关请求。本轮业务命令0、原生写入0，只证明装配启动、身份认证及读取路径，尚不证明后台业务执行。

| 装配公开证据 | 精确范围 |
| --- | --- |
| 首次DDL回滚预检失败 (`artifacts/M11/business-028-029-console-only-rollback-role-trial-original.json`, not public) | 原失败、旧SQL029摘要保留，未持久迁移、Native0 |
| 第二次触发器校验false (`artifacts/M11/business-028-029-case-corrected-console-only-rollback-role-trial-original.json`, not public) | 实际SQL已修正，检查器错误触发器名称造成false，原28迁移回滚保持 |
| 实际触发器名回滚预检 (`artifacts/M11/business-028-029-actual-trigger-name-console-only-rollback-role-trial-original.json`, not public) | 新字段/触发器、历史权限不可补写、实际app角色及ROLLBACK通过 |
| 368文件/30迁移Source冻结 (`artifacts/M11/business-runtime-original-assembly-isolated-source-freeze-original.json`, not public) | 7e2e3d初次装配范围；不含后续scoped桥，不单独证明部署 |
| 独立运行源码与SQL只读证明 (`artifacts/M11/business-runtime-original-assembly-independent-source-sql-readonly-original.json`, not public) | 实际7e2e3d、30条摘要、新触发器、9事实表运行角色只追加权限通过 |
| 原只读投影路径false (`artifacts/M11/business-runtime-original-assembly-readonly-projection-path-diagnostic-original.json`, not public) | 原观察未丢失，检查器路径错误；业务命令/Native0，无原请求重放 |
| 路径纠正后真实认证BFF只读 (`artifacts/M11/business-runtime-original-assembly-after-summary-path-fix-authenticated-bff-readonly-original.json`, not public) | readiness/空日程列表200、登记正确、旧Target成功与观察保持；业务命令/Native0 |

### 后续源码专项与页面边界

后续范围读取桥处理workspace/tag_group/entity下的实际对象授权和封存材料，不要求为编辑少量实体获得全工作区快照权限；专用SDK404观察区分真实解析的原404与调用方伪造、超时、401/403/429/5xx或不完整集合。相关 [范围读取用例](../../../../tests/unit/m11-workflow-business-scoped-read.test.ts) 与 [原SDK404观察用例](../../../../tests/unit/m11-scheduled-read-absence-sdk.test.ts) 属于后续源码专项，未纳入上述7e2e3d运行候选，也不能把模拟transport的源码验证称为真实网关404联调。

后台当前身份桥的后续尾部检查重复核对门户申请人、最新政策指针、集群/工作区登记及原lease边界，保留每个审批人的自身epoch/权限版本，不借执行人身份。最终源码摘要 `e57ab67cd6f7841826d4e4db0de952308afae0025afa08bec057a6d638fc4930` 晚于7e2e3d冻结，运行快照仍是该服务此前的965bee版本；其聚焦源码结果不作为已部署证明。format1旧批准集没有完整冻结审批人epoch，后台业务执行保持拒绝；format2必须在首票前登记新排程修订，再按新版本审批。原SQLlease/计划期限不能静默延长，Redis所有权续租不等于原审批期限续期；超过原14分钟有效期的M8作业必须重新准备新作业和工单。

新增「业务排程」Tab及详情接入已有5套件85项源码检查通过，其中新3套件50项；Web类型检查及Vite生产构建退出0。此前4个WorkflowsPage类型错误已由Root修复，原失败在报告中保留；现有入口包超过1,500kB阈值的构建提示也保留。报告见 业务排程前端源码检查 (`artifacts/M11/business-schedules-web-source-checks.json`, not public)。此页使用固定同源BFF、服务端游标、当前真实会话与权限、确认前后重新核对计划、原键一次提交及未知结果只读核验；这些是源码范围，没有做真实浏览器登记/投票/激活/取消或后台执行验收。元数据命令完成不代表网关执行成功，新页面也不归入原9,578项冻结全测。

### 当前待验收工作

先冻结并部署后续业务材料、范围读取及身份桥，联调真实登记→新revision→三票审批→定时器→嵌套配置执行来源/原生结果或门户凭证完整链；再覆盖逐包撤权/窗口、预约竞争、未知结果、取消、发送中故障与重启，以及Target回滚和特殊对象。随后按最终冻结源码/镜像/30条或后续正式迁移完成整仓回归、实际浏览器写入、最终审计/秘密扫描、持续性能与容量、持久部署/备份恢复及本期LDAP/OIDC和真实外部通知联调。**当前装配只读启动通过；M11整体、商用和生产总体验收均未通过。**


## 2026-10-15 后续整合与新持久验收 run

本节追加后续事实指针，以上历史运行候选、原失败及未知记录保持不变。详细当前状态见 [2026-10-15 M11 后续进展](../../milestones/checkpoints/2026-10-15-m11-continuation.md)，此前 [2026-10-14 检查点](../../milestones/checkpoints/2026-10-14-m11-checkpoint.md) 保留。

旧 RAM 工具 OOM 退出（255）且原内存数据库/私密账本未保留，见 环境丢失观察 (`artifacts/M11/environment-loss-observation-20261015-original.json`, not public)。未重建旧 SID、审批、claim 或重放旧 occurrence；新 run 采用新材料、磁盘私密目录、各自 PG 命名卷与 Redis AOF，不作为正式生产或异机灾备证明。

本轮先运行 404 源文件/36 迁移候选，之后因真实 Native 基线别名缺陷追加 SQL036，SQL036 后曾运行 **405 个源文件**、SHA256 **`211ea998f65ab6ab5f887550533f3329d0c87e6324a9358a31b412d8e7719fe7`**，SQL000–036 共 **37** 条，见 最新冻结 (`artifacts/M11/runs/20261015-persistent/integrated-036-source-freeze-original.json`, not public)、编译 (`artifacts/M11/runs/20261015-persistent/integrated-036-compile-original.json`, not public) 和 正式迁移/验收 API 启动 (`artifacts/M11/runs/20261015-persistent/integrated036-runtime-deployment-original.json`, not public)。SQL035 试验 (`artifacts/M11/runs/20261015-persistent/035-console-only-rollback-trial-original.json`, not public) 验证真实会话/revision/发行时钟与只追加角色；SQL036 试验 (`artifacts/M11/runs/20261015-persistent/036-console-only-rollback-trial-original.json`, not public) 仅修正两处别名、保留 OID 和错误身份拒绝，两项均真实回滚且非工单执行证明。新 Upstream (`artifacts/M11/runs/20261015-persistent/target-upstream-after036-native/native-verification.json`, not public) 与 Target (`artifacts/M11/runs/20261015-persistent/target-create-native/native-verification.json`, not public) 真实 201 另行证明修复后的原生成功链，原失败不重发。

新工作区创建 prepare/submit/独立审批/execute 成功，Native0；独立 SQL 实际表核验 (`artifacts/M11/runs/20261015-persistent/integrated035-runtime-control-independent-sql-actual-table-query.json`, not public) 证明三层 succeeded、同一原会话、epoch 精确增加268、3角色/265权限/0绑定。原 view400 与两次错误 SQL 查询报告保留，纠正查询不重执行。实体说明 set/remove/restore 也均完成真实独立审批、执行与回执，三操作独立 SQL 核验 (`artifacts/M11/runs/20261015-persistent/annotation-three-operation-independent-sql-original.json`, not public) 证明 revision1/2/3、原 SID、业务审计及工单/执行/步骤全部 succeeded，三个说明工单 Native0；前置 Service 夹具的 Native 写入不混算。

Target100→80自然定时终态 (`artifacts/M11/runs/20261015-persistent/target-natural-weight-terminal-original/native-verification.json`, not public) 通过：单 claim、真实新有效 UUID、没有手动 tick。Prometheus 数据源真实创建工单及 连通测试 (`artifacts/M11/runs/20261015-persistent/prometheus-source-test/native-verification.json`, not public) 通过，该阶段仅证明登记/连通，后续数值结果见下文；磁盘容量降低后只停止并删除本 run 临时 Prometheus 容器，空间恢复报告 (`artifacts/M11/runs/20261015-persistent/temporary-monitoring-container-space-recovery-original.json`, not public) 确认命名卷/数据库/私密证据未删，不把历史连通通过视作当前在线。

真实只读浏览器 (`artifacts/M11/runs/20261015-persistent/browser-metadata-capability-read/verification.json`, not public) 10项/3截图通过，业务写0/Admin0，包含一次只读能力查询POST；前两次脚本标签与能力POST误拦失败保留。Target 245项源码专项 (`artifacts/M11/target-workflow-web-source-checks-20261015-health-wording-final.json`, not public) 与说明/共享回调 227项专项 (`artifacts/M11/m11-annotation-and-callback-boundary-source-checks-20261015-frozen.json`, not public) 不累加。随后实际 固定1,742输入整仓 (`artifacts/M11/m11-integrated-full-source-regression-20261015-final-fixed-input-original.json`, not public) 12,778项全部通过、失败/跳过0，三端类型检查0，输入前后摘要不变；首次工具缺失/输入变化报告仍保留。

**上述12,778全测不覆盖后续健康兼容修复字节。** 之后健康 data 修复候选 **`8d4a16553de44e310e8e39cea39630006437894eb118cdb3d128de3c2996eaa3`**（405源文件/37迁移）已 冻结 (`artifacts/M11/runs/20261015-persistent/integrated-health-data-source-freeze-original.json`, not public)、编译 (`artifacts/M11/runs/20261015-persistent/integrated-health-data-compile-original.json`, not public) 并 实际部署 (`artifacts/M11/runs/20261015-persistent/integrated-health-data-runtime-deployment-original.json`, not public)。原健康 `data` 拒绝 失败 (`artifacts/M11/runs/20261015-persistent/target-health-native-shape-failure-readonly-original.json`, not public) 保留；另行新工单先 unhealthy (`artifacts/M11/runs/20261015-persistent/target-health-unhealthy-after-data-native/native-verification.json`, not public) 后 healthy (`artifacts/M11/runs/20261015-persistent/target-health-healthy-after-data-native/native-verification.json`, not public) 均收到真实Native204。纠正查询别名后的独立SQL (`artifacts/M11/runs/20261015-persistent/target-natural-and-health-independent-sql-corrected-alias.json`, not public) 证明自然权重单claim/NULL-SID来源及两张健康三层succeeded、各一次尝试/成功审计、原HTTP会话与不可逆基线，不重发原失败。

IAM 角色创建 真实执行 (`artifacts/M11/runs/20261015-persistent/iam-role-execute/native-verification.json`, not public) 通过，工单 `2035ad69-e37b-4e9a-822b-041826471069` succeeded、Native0。监控设置工单 `fdffcee8-58bb-4660-bb58-e97f086d40da` 的 执行 (`artifacts/M11/runs/20261015-persistent/metrics-native-setup-execute/native-verification.json`, not public) 则为403 `APPROVED_MUTATION_MISMATCH`，只读SQL (`artifacts/M11/runs/20261015-persistent/metrics-original-failed-no-native-readonly-sql-original.json`, not public) 证明工单/执行failed、mutations0/nativeAttempts0。原失败和零发送证明保留。之后Metrics CREATE逻辑身份窄修复 334项源码检查 (`artifacts/M11/metrics-native-create-logical-source-checks-20261015.json`, not public) 通过，实际编译/dist对照纠正后新工单 `e2ca9c65-1a52-436b-ae96-152cf3d15258` 执行 (`artifacts/M11/runs/20261015-persistent/metrics-create-fix-execute/native-verification.json`, not public) 及 原回执 (`artifacts/M11/runs/20261015-persistent/metrics-create-fix-receipt/native-verification.json`, not public) 成功；独立SQL (`artifacts/M11/runs/20261015-persistent/metrics-create-fix-independent-sql-corrected-schema-original.json`, not public) 证明真实native/metadata及mutation成功、原SID、设置rev2→3/generation1，原错误schema查询保留。随后 抓取up1 (`artifacts/M11/runs/20261015-persistent/metrics-prometheus-scrape-readonly-original.json`, not public)、75次业务200 (`artifacts/M11/runs/20261015-persistent/metrics-native-traffic-entity-dto/verification.json`, not public) 和 12个正QPS点与原始查询逐点一致 (`artifacts/M11/runs/20261015-persistent/metrics-native-numeric-compare/verification.json`, not public) 通过，仅覆盖本次工作区原生QPS子集，不代表所有Vitals/collector指标验收。

浏览器说明写入 (`artifacts/M11/runs/20261015-persistent/browser-annotation-write-original/verification.json`, not public) 等待提交按钮超时failed、业务POST0/Admin0，原记录保留。之后说明/Target/凭证三个组件五处effect补回setup active=true，保留cleanup与全部授权栅栏/StrictMode，15项离线浏览器专项及相关280项 (`artifacts/M11/m11-strict-lifecycle-source-checks-20261015-original.json`, not public) 通过，计数不相加；修复后的真实说明UI链 (`artifacts/M11/runs/20261015-persistent/browser-annotation-write-after-lifecycle-fix/verification.json`, not public) 8项/4次预期写入通过，工单3389cde6-ff34-4d6e-b2ad-2cb09f02544e由原会话提交/执行、独立审批，无额外写入或Admin直连。后续 健康data整合全量 (`artifacts/M11/m11-health-data-integrated-full-regression-and-build-20261015-original.json`, not public) 固定1,748输入，12,878项中12,877通过/1项M9路由模拟失败/跳过0；三端类型检查和构建均0，手册SSR7项通过，但整合报告仍false。该轮M9失败及后续专项另行保留，不预写新整仓通过，也不把该结果赋予后续监控/StrictMode/政策派生修复字节。

第一轮配置自然工单bef24959-d4a9-4c93-a5db-0f2254a53480 failed，原因WORKFLOW_SCHEDULE_CONFIGURATION_FULL_APPROVAL_REQUIRED，硬编码三票与原政策不符；早期 active观察失败 (`artifacts/M11/runs/20261015-persistent/configuration-natural-observe/configuration-natural-verification.json`, not public) 保留。改为原完整批准政策派生校验的 131项窄专项 (`artifacts/M11/m11-scheduled-configuration-policy-derived-approval-source-only-20261015-original.json`, not public) 通过，最新405源文件/37迁移候选 **`8f44a2b149d6e819cee4dc558291582178b35e8a16021384156641e439def1d9`** 已 冻结 (`artifacts/M11/runs/20261015-persistent/integrated-policy-derived-source-freeze-original.json`, not public) 并 真实部署 (`artifacts/M11/runs/20261015-persistent/integrated-policy-derived-runtime-deployment-after-buffer-correction-original.json`, not public)。第二工单8349a1ea-a115-480a-a177-102c52fb280e/日程b338c761-852d-4adf-9e0c-4ddbf20f718b 登记激活 (`artifacts/M11/runs/20261015-persistent/configuration-natural-policy-fixed-prepare/configuration-natural-verification.json`, not public) 后也failed，原因WORKFLOW_SCHEDULE_NAMESPACE_EXPIRED。两次失败独立SQL (`artifacts/M11/runs/20261015-persistent/configuration-natural-two-failures-independent-sql-original.json`, not public) 已证明各单claim、child执行/来源0、mutations0，原失败不重放，均不计功能通过。之后三个生产源码文件的单次当前Authority检查优化 205项专项 (`artifacts/M11/m11-business-single-fresh-authority-source-only-20261015-original.json`, not public) 通过，现已随cde32候选部署，但自然完成/性能证明仍待；门户/Promote新runner仍仅Source，未真实执行。

平台库37迁移 原独立恢复 (`artifacts/M11/runs/20261015-persistent/console-037-independent-restore-proof-original.json`, not public) false与 VFS initdb ENOSPC诊断 (`artifacts/M11/runs/20261015-persistent/restore-startup-capacity-diagnostic-original.json`, not public) 保留。容量之后，同实例新空DB的 未修改标准pg_restore (`artifacts/M11/runs/20261015-persistent/console-037-separate-database-logical-restore-proof-original.json`, not public) 仍失败audit_event_scopes_scope_check，因此真正阻塞不只是空间。原库381行只读/回滚试验 (`artifacts/M11/runs/20261015-persistent/console-restore-search-path-readonly-and-rollback-trial-original.json`, not public) 证明默认path381有效、空path0有效，仅事务固定m7_historical_scope后381有效再ROLLBACK。之后SQL037已完成真实回滚正负试验和正式迁移，见 cde32/037部署 (`artifacts/M11/runs/20261015-persistent/integrated-single-authority-037-runtime-deployment-original.json`, not public)：381scope/75event有效，非法材料仍拒，四函数OID/主体保持且ROLLBACK精确；独立owner进程标准DbService/provisioner应用037，摘要77c78d6b2cf0ef051a71ebed078c532363ab410ce4040501ce14377861c370bd，38条迁移/ready200/Kong不变。

新dump的未修改pg_restore--exit-on-error本体已退出0，原后验报告 (`artifacts/M11/runs/20261015-persistent/console-after-037-standard-logical-restore-proof-original.json`, not public) 只是ORDER BY歧义42702失败；改为只读限定a.chain_scope/a.sequence后 完整后验通过 (`artifacts/M11/runs/20261015-persistent/console-after-037-standard-restore-qualified-readonly-verification-original.json`, not public)，没有重做restore或改dump/session搜索路径。还原库38迁移/22WF/382审计/2链hash与patch有效、2份AEAD/HMAC有效，runtime非SU、管理员与runtime的正常审计修改被拒。旧dump/部分恢复库保留。这个标准同实例新空库恢复分项已通过，不能用历史改prologue助手补算；恢复API/worker未启动，也未证明独立主机/进程、异机DR或RPO/RTO。

随后 统一源码/类型/隔离构建报告 (`artifacts/M11/m11-unified-final-regression-typecheck-and-build-20261015-original.json`, not public) 已完成：1,755固定输入（含5手册）、摘要 **afc66bc09377da30602ce03365438d5fcbc5bbfafd6537f2ebd49e2b5a9e37da** 前后相同，13,051/13,051项、1,377suite通过、失败/跳过0，三端type与三端隔离build均0；原12,878轮失败保留。全测与后续构建是分开记录的相同输入阶段，运行/商业验收仍false。其后205项性能源码变化及SQL037不属于本轮全量范围，不能用此通过补算自然排程或恢复。

先前 cde32冻结 (`artifacts/M11/runs/20261015-persistent/integrated-single-authority-037-source-freeze-original.json`, not public) 为406源文件/38SQL，API摘要cde32b59cdf244a49a294b1db9b571b478d13edf24418becaa3d88f60ecddb07，已编译0并真实部署；该新增字节不属于afc66的13,051项旧全量。第三工单7a981b68-f81e-4aec-ae98-a17e407ef6ed/日程81cca81b-eaa7-419f-a725-05bba2487fd9在原 审批激活 (`artifacts/M11/runs/20261015-persistent/configuration-single-authority-prepare-schedule/configuration-natural-verification.json`, not public) 后终态failed/KONG_EXECUTION_CONTEXT_EXPIRED。第三轮独立SQL (`artifacts/M11/runs/20261015-persistent/configuration-third-failure-independent-sql-original.json`, not public) 证明唯一claim cb99def0-5eaa-4a79-8bff-1380168e4f97原期限上海21:34:17.386→21:39:17.386，执行bd5c7943-d0df-40d4-874b-58f5792239fb快照ready但metadatafailed，0childExec/0childOrigin/0mutation、原1票、original-execution failed。报告passed是安全失败观察通过，功能验收仍false，没有手动tick或重放。

本次自然执行中 8.281523秒/5669样本CPU诊断 (`artifacts/M11/runs/20261015-persistent/configuration-third-natural-cpu-sampling-original.json`, not public) 与 caller stacks (`artifacts/M11/runs/20261015-persistent/configuration-third-natural-cpu-caller-stacks-original.json`, not public) 定位fresh grants sort comparator重复whole-row HMAC。Inspector只绑容器loopback且采样后确认关闭，没有改原期限/业务状态。每行当次只计算一次原hash的四处稳定排序 247项Source检查 (`artifacts/M11/m11-fresh-grant-fingerprint-sort-source-only-20261015-original.json`, not public) 通过，已随后续f591ea部署；第四轮仍未完成，不能记性能PASS。

独立Service2bab98b3-8c6c-49fd-86c2-4bd218f504dd经c268351d-b4e7-4118-897a-5ea32a65acfd工单 真实Native201创建 (`artifacts/M11/runs/20261015-persistent/configuration-independent-service-original/native-verification.json`, not public)，保留门户固定Service指纹。此前 f591ea冻结 (`artifacts/M11/runs/20261015-persistent/integrated-fresh-grant-sort-source-freeze-original.json`, not public) 与 运行部署 (`artifacts/M11/runs/20261015-persistent/integrated-fresh-grant-sort-runtime-deployment-original.json`, not public) 为407src/38SQL、API摘要f591ea181638fb74090cbd98df34b87ae79f96057d76f055ec159a1facbdc4c6、ready200/Kong不改。

第四工单792763dc-fdcd-42df-b4c1-a57dd24feb31/日程da599917-886e-4b2f-bfa8-8707f30c7142已终止wrapper但未闭环：只读SQL/回读报告 (`artifacts/M11/runs/20261015-persistent/configuration-fourth-failure-child-claim-readonly-original.json`, not public) passed=false/observationVerified=true，原claim上海21:49:15.870→21:54:15.870，wrapperfailed/snapshotready/namespaceexpired，子76f678cb-f493-4fc3-b544-676356c0a844和日程仍claimed、1origin/0mutation/0outcome，Service retries仍5；不补旧claim、不借新句柄或重放。同期 Kong访问计数 (`artifacts/M11/runs/20261015-persistent/configuration-fourth-native-access-counts-original.json`, not public) 中Service schema/点读各158，但含其他后台请求不能全归工单；6.437980秒/4515CPU样本 (`artifacts/M11/runs/20261015-persistent/configuration-fourth-natural-cpu-sampling-original.json`, not public) 约45%idle只是诊断，不是性能验收。

门户从 preflight (`artifacts/M11/runs/20261015-persistent/portal-natural-preflight-original/portal-natural-verification.json`, not public) 到settings/policy/publication/developer/application/request/author/vote和 activate (`artifacts/M11/runs/20261015-persistent/portal-natural-activate-original/portal-natural-verification.json`, not public) 12阶段实际passed，原工单f41d7a63-3fdd-44da-bb2a-53e3edf21e4e/日程da60ce1d-fe44-429b-881c-a7a1b80f1e1d，原SID与独立reviewer分离，v1→v2保留期限。新增独立SQL (`artifacts/M11/runs/20261015-persistent/portal-first-expired-claim-readonly-original.json`, not public) passed=false/observationVerified=true：原claim8e10be79-9782-4b84-a979-c5eb331c3726上海22:07:11.562→22:12:11.562已过期，22:25:54时工单仍executing/日程claimed/首native步running，snapshotready、后续native/metadata pending、0mutation/0outcome。终态/凭证可用性未闭环，不能因零mutation或runner未直接POSTexecute改写为未发证已知事实；不能用新句柄/SID接管旧claim。public origin为null、外部联调未完成；此为当时门户观察，Promote后续真实拓扑及前置结果见本节后文。

后续初始化失败收尾 221项Source/API0 (`artifacts/M11/m11-configuration-initialization-failure-source-only-20261015-original.json`, not public)、preclaim107项 (`artifacts/M11/m11-business-preclaim-current-authority-source-only-20261015-corrected.json`, not public)、typed snapshot8文件384不同用例/API0 (`artifacts/M11/m11-validation-principal-single-snapshot-source-only-20261015-original.json`, not public) 不属于afc66旧全量；最新运行范围以76ce04冻结清单为准，不把专项用例计数作为自然运行验收。Root在 真实PG双actor等价核验 (`artifacts/M11/runs/20261015-persistent/validation-principal-real-typed-snapshot-equivalence-original.json`, not public) 中各145完整grants/CJ-HMA一致，三个bigint epoch均string，计时一快一慢不算benchmark通过。之后 ledger-only窄拆分 (`artifacts/M11/m11-ledger-only-current-principal-source-checks-20261015-original.json`, not public) 14文件499项/API类型及API构建0；固定Root当前principal/原Namespace、SQL完整grants等来源保留，Native的claim/capture/step/packet/before-send完整检查不变。未来原回调过期receipt探测catch (`artifacts/M11/m11-business-expired-receipt-probe-source-only-20261015-original.json`, not public) 37项/API0，探测异常保持原错误及unknown=true、走原uncertain账本，不造读取许可或已知未发送。这些专项晚于f591；76ce04已随后整合部署，仅取得启动及重启即时观察，没有自然/性能结论，也不能修复已退出的历史claim。

此前 ledger整合候选冻结 (`artifacts/M11/runs/20261015-persistent/integrated-ledger-candidate-source-freeze-original.json`, not public) 为410源文件/38SQL，API摘要76ce04d1ad5542eed4264fed45589dc6e4f21d21ea50f795e95bd2ea89148168、隔离编译0。原部署观察器报告 (`artifacts/M11/runs/20261015-persistent/integrated-ledger-runtime-deployment-original.json`, not public) false来自停止API前误用workflow_steps.execution_id，当次未停止/更新API；改为workflow_id后，正式受控部署及即时观察 (`artifacts/M11/runs/20261015-persistent/integrated-ledger-runtime-deployment-corrected-observer-original.json`, not public) passed=true、上海22:37:14 ready200，仅重启自有验收API，Kong不变。两条旧过期claim、两条origin及原工单/日程/子执行的状态和revision前后即时一致，mutations=0、outcomes=0；门户首native步仍running，第四轮子执行/日程仍claimed。未改SQL业务状态或延长期限，没有接管或修复旧claim；报告oldClaimsRepairedOrClosed=false/naturalPerformancePassed=false/wholeM11Accepted=false。随后 原两claim延后只读观察 (`artifacts/M11/runs/20261015-persistent/integrated-ledger-delayed-restart-non-replay-original.json`, not public) true，上海22:38:21约67秒后仍2claim/2origin/0mutation/0outcome、无新句柄/重试；不是90秒，也不证明旧claim收口、持续无重放或性能通过。

本轮 实际秘密扫描原报告 (`artifacts/M11/runs/20261015-persistent/current-checkpoint-secret-scan-original/m11-current-secret-scan-2026-10-15T14-35-52-190Z-33fa42a2-eb20-48e6-a2e6-80277a62f811.json`, not public) false，前置校验错误SCAN_SHORT_EXPLICIT_SECRET_REQUIRES_REVIEW；actualSecretCount=0、byteCount=0、findingCount=0表示尚未扫描，不是无泄露PASS，也不据此判定有泄露。该前置失败保留，后续实际扫描见本节最新补充，不改写原报告。

全新独立Service3 eb562717-0621-4885-b540-42b0554270d5经独立原生审批工单 创建201 (`artifacts/M11/runs/20261015-persistent/configuration-ledger-fixed-service-original/native-verification.json`, not public)。第五自然工单cbd50b28-f0a0-4ae1-88fc-6c46e9272d79/日程0a1ea9d6-11f2-4078-a5f9-5ca15aae872c却提前failed/CONFIGURATION_SCHEDULE_ORIGINAL_EXECUTION_REQUIRED，独立SQL (`artifacts/M11/runs/20261015-persistent/configuration-fifth-init-boundary-failure-independent-sql-original.json`, not public) passed=false/observationVerified=true，单claim/ready snapshot/0child/0mutation、一条original-execution failed outcome。新init helper在pre-child就要求generic packet，尚未到子执行或权限过期；后续真实access边界窄修复已部署507cd795，但尚无新自然完成，不写初始化真实闭环通过。原作者SID读取日程 (`artifacts/M11/runs/20261015-persistent/configuration-ledger-fix-observe-original/configuration-natural-verification.json`, not public) 曾403 CONFIGURATION_APPROVED_WRAPPER_INVALID；9236安全读取实证见下，原自然失败与旧403均保留，不重放。

另 新独立门户Service/Route (`artifacts/M11/runs/20261015-persistent/portal-ledger-fix-fresh-fixture-original/native-verification.json`, not public) 均经独立审批收到201，仅fixture就绪，没有新发证/凭证可用证明。第二个未修改镜像的Kong完成独立DB/非SU角色、migration/bootstrap及健康启动；仍共用PG11/存储、非独立故障域。首次proxy地址撞既有API造成 未启动失败 (`artifacts/M11/runs/20261015-persistent/promote-target-initial-provisioning-original.json`, not public)，仅改目标proxy地址后 启动通过 (`artifacts/M11/runs/20261015-persistent/promote-target-proxy-ip-correction-original.json`, not public)，源API/网关未重启。此为早期准备状态；BFF接入与实际拓扑后续结果见下，不将启动通过算作Promote实际业务通过。

ledger Source构建独立勘误 (`artifacts/M11/m11-ledger-only-source-build-dist-correction-20261015-original.json`, not public) 确认workspace build实际曾写仓库原dist，并非先前描述的隔离输出；原报告不覆盖。随后 旧绑定容器只读影响观察 (`artifacts/M11/runs/20261015-persistent/old-bind-dist-build-impact-readonly-original.json`, not public) 记录上海08:44:33（UTC00:44:33）启动/restart0/当前unhealthy，历史模块或功能影响unknown，未重启/恢复产物/修改旧服务。当前验收候选构建隔离，不能外推旧服务无影响。

pre-child真实access边界修复 6文件166项/API类型0 (`artifacts/M11/m11-configuration-initialization-real-access-source-only-20261015-original.json`, not public) 通过。Root以原76ce04加精确一项修复 冻结507cd795候选 (`artifacts/M11/runs/20261015-persistent/initialization-boundary-candidate-source-freeze-original.json`, not public)：410源文件/38SQL、API摘要507cd7956b6ab9734500afe0ef77ff64bbcfe90b71f523720cf04e825971b668、隔离编译0。磁盘条件下先stop/rm自有API，再up新容器的 真实部署 (`artifacts/M11/runs/20261015-persistent/initialization-boundary-target-admin-runtime-deployment-original.json`, not public) true/ready200，SID/数据保留、不改业务SQL或旧claim；接入目标Admin但未加入Kong数据库网络，Kong源码/镜像不改。此为507历史部署，尚无新自然初始化完成；后续9236整合及safe receipt实际读取见下。

当前双网关拓扑 (`artifacts/M11/runs/20261015-persistent/current-promote-shared-pg-distinct-databases-topology-original.json`, not public) 实际passed：均1.5.1、不同NodeID/DB OID/角色OID，专用Admin网络可达且BFF不连Kong库。仍同一PG11进程/卷、源SU/目标非SU，roleIsolationVerified=false、independentFailureDomains=false，不是完整角色隔离或独立灾备。preflight (`artifacts/M11/runs/20261015-persistent/current-promote-original/preflight-original.json`, not public)、register (`artifacts/M11/runs/20261015-persistent/current-promote-original/register-original.json`, not public)、policy requests (`artifacts/M11/runs/20261015-persistent/current-promote-original/policy-requests-original.json`, not public)、policy approval (`artifacts/M11/runs/20261015-persistent/current-promote-original/policy-approval-original.json`, not public)、source fixture (`artifacts/M11/runs/20261015-persistent/current-promote-original/source-fixture-original.json`, not public)、target fixture (`artifacts/M11/runs/20261015-persistent/current-promote-original/target-fixture-original.json`, not public) 六前置阶段真实通过，尚无compare/promote/自然apply结果。

门户ledger-fix-20261015 case前9阶段通过后，Root注册目标集群/默认IAM令冻结PV变化，author选择POST前 正确拒绝 (`artifacts/M11/runs/20261015-persistent/portal-ledger-fix-author-pretransport-permission-change-original.json`, not public)：passed=false/observationVerified=true，schedule/execution/operation均0，不改旧PV、不重放。拓扑后另以独立审批创建 post-topology新Service/Route201 (`artifacts/M11/runs/20261015-persistent/portal-post-topology-fresh-fixture-original/native-verification.json`, not public)，新case随后实际12阶段通过并收为uncertain，最新终态见下；夹具或前置通过不证明自然发证/凭证可用。

扫描器 固定profiles专项58/58 (`artifacts/M11/m11-current-secret-scan-fixed-profiles-source-only-20261015-original.json`, not public) 通过，新增checkpoint-api-key-not-issued，默认完整五类要求保留。真实checkpoint扫描 (`artifacts/M11/runs/20261015-persistent/current-checkpoint-secret-fixed-profile-original/m11-current-secret-scan-2026-10-15T14-56-00-349Z-26514571-bb17-45a3-ad46-bb2142f5eabc.json`, not public) 已扫描373,275,850字节、actualSecretCount=197、0发现，但末尾SCAN_PUBLISHABLE_FILE_CHANGED使整体false（Source并发变化），不能记无泄露PASS。API Key材料0、发行验收false、finalCredentialComplete=false，Source冻结后需重扫，本阶段profile不替代最终完整凭证扫描。

post-topology-20261015门户case的前12阶段现已实际通过，从 preflight (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-preflight-original/portal-natural-verification.json`, not public)、settings (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-settings-original/portal-natural-verification.json`, not public)、policy (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-policy-original/portal-natural-verification.json`, not public)、publication create (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-publication-create-original/portal-natural-verification.json`, not public)、publish (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-publication-publish-original/portal-natural-verification.json`, not public)、developer register (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-developer-register-original/portal-natural-verification.json`, not public)、approve (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-developer-approve-original/portal-natural-verification.json`, not public)、application (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-application-original/portal-natural-verification.json`, not public)、request (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-request-original/portal-natural-verification.json`, not public)、author (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-author-original/portal-natural-verification.json`, not public)、vote (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-vote-original/portal-natural-verification.json`, not public) 到 activate (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-activate-original/portal-natural-verification.json`, not public)。工单c7d3d64d-b76e-4bad-84c1-122da9acfd2b/日程a60ce24b-f9d9-4670-a74d-9e00674875cf的原5分钟claim上海23:00:39.623→23:05:39.623耗尽前0mutation；独立SQL终态 (`artifacts/M11/runs/20261015-persistent/portal-post-topology-expiry-conservative-completion-independent-sql-original.json`, not public) passed=false/observationVerified=true，首Native步KONG_EXECUTION_CONTEXT_EXPIRED，W/E/schedule均uncertain、一条original-execution uncertain outcome。原catch保守收尾已真实生效，但自然发证仍false，不将0mutation当成已知未发送，不补旧claim/期限；原observe失败 (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-observe-original/portal-natural-verification.json`, not public) 保留。6.240503秒/4988样本CPU采样 (`artifacts/M11/runs/20261015-persistent/portal-post-topology-native-cpu-sampling-original.json`, not public) 和 调用栈 (`artifacts/M11/runs/20261015-persistent/portal-post-topology-cpu-caller-stacks-original.json`, not public) 只是诊断，Inspector限loopback、采完关闭，不算性能PASS。

真正主console库审计核验 (`artifacts/M11/runs/20261015-persistent/current-audit-all-chains-and-json-patches-readonly-original.json`, not public) true：runtime角色只读独立验证681行/3链及全部JSON patch正确；不扩大为全部写入审计覆盖或最终商用。三个Safety Service独立审批201 (`artifacts/M11/runs/20261015-persistent/business-safety-fresh-services-original/native-verification.json`, not public) 后，取消case六个写入/准备阶段及 原窗口后HTTP观察 (`artifacts/M11/runs/20261015-persistent/business-safety-cancel-before-due-observe-original/business-schedule-safety-cancel-before-due-observe.json`, not public) 实际通过：原窗口上海23:22:10.396–23:24:10.396结束后仍cancelled/claimId=null，独立SQL零claim/Native仍待，不由HTTP外推。

restart-expiry原日程0ec7f983-89cd-4680-aec7-5d51d4434fec/工单0eef2c0a-d08f-45ed-99cc-645f164d53d1的原窗口上海23:28:23.967–23:30:23.967不变。Root在 23:28:01停止自有API (`artifacts/M11/runs/20261015-persistent/business-expiry-own-api-stopped-before-original-window-original.json`, not public)，停止前active/claim0/执行0/mutation0。窗口结束后23:31:22 启动同一API容器并升级507→9236 (`artifacts/M11/runs/20261015-persistent/combined-candidate-runtime-and-original-expiry-restart-original.json`, not public)：ready200，独立SQL确认expired/claim0/执行0/mutation0；原HTTP观察 (`artifacts/M11/runs/20261015-persistent/business-safety-restart-expiry-observe-original/business-schedule-safety-restart-expiry-observe.json`, not public) true、expired/WORKFLOW_SCHEDULE_WINDOW_EXPIRED。没有手动tick、改时钟、延长原期限或修补旧claim；该分项是跨二进制升级/重启的过期不补跑证明，不是相同二进制重启或正向业务完成。原overlap只preflight/prepare、未author，不能改其deadline或复用旧夹具；新独立case的Source支持和实际冲突验证仍待。

当前 9236整合候选冻结 (`artifacts/M11/runs/20261015-persistent/combined-receipt-facts-memo-sort-candidate-source-freeze-original.json`, not public) 输入410个（370 TS、38 SQL、package/tsconfig），API摘要9236ddf0adf4e35e565efcaa1dbadb103b4a10176ce09dd53929f40679c4d09b、输入前后稳定、隔离编译0；上述真实启动核对38条SQL摘要，保留原存储/密钥/会话，仅启动自有验收API、未改Kong源码/镜像，不是生产发布。对应专项分别为 safe receipt 5文件204项/API类型及临时编译0 (`artifacts/M11/m11-schedule-safe-receipt-source-final-20261015-original.json`, not public)、pre-Namespace facts 10文件312项/API类型及隔离编译0 (`artifacts/M11/m11-pre-namespace-approval-facts-source-final-20261015-original.json`, not public)、Factory immutable memo 9文件327项/API类型及隔离编译0 (`artifacts/M11/m11-factory-immutable-fingerprint-memo-source-only-20261015-original.json`, not public)、第五处CandidateRead排序4文件154项/API类型0 (`artifacts/M11/m11-candidate-read-fifth-fresh-sort-source-only-20261015-original.json`, not public)。facts独立Source审阅 (`artifacts/M11/m11-scheduled-eligibility-facts-independent-source-review-20261015-original.json`, not public) 与 memo独立Source审阅 (`artifacts/M11/m11-factory-immutable-fingerprint-memo-independent-source-review-20261015-original.json`, not public) 分开保留。专项有交叠，不求和为新的全量，afc66的13,051项/三端类型与隔离构建不覆盖这些新字节。

safe receipt部署后，上海23:36:14实际原第五轮GET (`artifacts/M11/runs/20261015-persistent/safe-original-failed-schedule-readonly-original/safe-receipts-verification.json`, not public) HTTP200、state=failed、nativeAuthority=false，原状态未改；报告首个control标记notKnownOriginalPointer，不计为另一已知原case通过。这关闭该原第五轮终态读取403的运行验证，不关闭其自然执行失败，也不授予历史Native执行权限。pre-Namespace优化仅context=null路径，已有Namespace/HTTP/public/V1完整校验保留；memo只缓存同一Factory深冻结根引用/同一SecretService实例的纯HMAC计算，不缓存权限、SQL当前事实或新引用。尚无五分钟内正向完成或性能通过结论。

后续需在当前9236用新意图/原期限完成自然配置、门户发证/可用/吊销及Promote实际比较发布；原post-topology门户在507下已收为uncertain但发证仍false，旧PV变化case不重放。继续取消独立SQL、新overlap、撤权/多级会签/通知、其余Target/UI/监控维度、新固定字节完整回归、全部关键写入审计覆盖、实际秘密扫描、旧产物影响处置及恢复API/独立主机灾备。checkpoint扫描0发现仍因发布文件变化整体false，API Key未签发，不替代最终完整凭证扫描。旧账本不补claim、延时或借新句柄。**M11 整体与平台商用验收未完成。**

### 2026-10-15 追加：安全排程分项SQL通过，Promote与配置仍有未完成节点

本追加以公开报告截至上海23:53:41的观察为准，补充前述“独立SQL/overlap仍待”状态，原失败不覆盖，M11及商用仍false。

取消/过期独立SQL (`artifacts/M11/runs/20261015-persistent/business-cancel-expiry-independent-sql-original.json`, not public) passed=true，两原日程分别cancelled/expired且claims、executions、mutations、origins、outcomes均0，原窗口不变。取消HTTP与独立账本计数分项现已相互核对；零mutation行不是独立抓包。

新独立named overlap `post-restart-20261015`的 preflight (`artifacts/M11/runs/20261015-persistent/business-safety-overlap-post-restart-20261015-preflight-original/business-schedule-safety-overlap-post-restart-20261015-preflight.json`, not public)、prepare (`artifacts/M11/runs/20261015-persistent/business-safety-overlap-post-restart-20261015-prepare-original/business-schedule-safety-overlap-post-restart-20261015-prepare.json`, not public)、author (`artifacts/M11/runs/20261015-persistent/business-safety-overlap-post-restart-20261015-author-original/business-schedule-safety-overlap-post-restart-20261015-author.json`, not public)、approve (`artifacts/M11/runs/20261015-persistent/business-safety-overlap-post-restart-20261015-approve-original/business-schedule-safety-overlap-post-restart-20261015-approve.json`, not public) 和 overlap-check (`artifacts/M11/runs/20261015-persistent/business-safety-overlap-post-restart-20261015-overlap-check-original/business-schedule-safety-overlap-post-restart-20261015-overlap-check.json`, not public) 实际通过：A激活200，B激活409/WORKFLOW_SCHEDULE_PHYSICAL_IMPACT_CONFLICT且Bstate/revision不变，A/B取消均200。首次 observe (`artifacts/M11/runs/20261015-persistent/business-safety-overlap-post-restart-20261015-observe-original/business-schedule-safety-overlap-post-restart-20261015-observe.json`, not public) 在原窗口结束前约5秒被Source前置拒绝、未建立runs.observe且未HTTP；原失败保留。窗口上海23:49:47.226–23:51:47.226结束后的 原日程HTTP观察 (`artifacts/M11/runs/20261015-persistent/business-safety-overlap-post-restart-20261015-observe-after-original-window-original/business-schedule-safety-overlap-post-restart-20261015-observe.json`, not public) true，两日程均cancelled/claimId=null；原两日程独立SQL (`artifacts/M11/runs/20261015-persistent/business-overlap-post-restart-independent-sql-original.json`, not public) true，各自claim/执行/mutation/origin/outcome均0。SQL报告restartTimelineReport是通用复制字段，不作为overlap重启证据；旧未author case不复用、不续期。

Promote compare (`artifacts/M11/runs/20261015-persistent/current-promote-original/compare-original.json`, not public)/plan (`artifacts/M11/runs/20261015-persistent/current-promote-original/promote-original.json`, not public) actualPASS；原apply (`artifacts/M11/runs/20261015-persistent/current-promote-original/apply-original.json`, not public) actual201/waiting_approval但报告false，原因是runner误将合法冻结的新执行planId要求为旧导入planId。Root恢复原201回执、不重发apply；后续author (`artifacts/M11/runs/20261015-persistent/promote-original-201-fork-recovery-author-stopped-contract-original/promote-original-continuation-verification.json`, not public) actual403 WORKFLOW_BUSINESS_PROMOTION_STORAGE_CHANGED，原工单/导入计划/执行计划及失败状态保留。两个前置回执观察器失败 (`artifacts/M11/runs/20261015-persistent/promote-original-201-fork-recovery-author-original/promote-original-continuation-verification.json`, not public) 及 stopped/failed断言失败 (`artifacts/M11/runs/20261015-persistent/promote-original-201-fork-recovery-author-cookie-contract-original/promote-original-continuation-verification.json`, not public) 也保留。runner22项Source修复 (`artifacts/M11/m11-current-promote-apply-plan-fork-source-only-20261015-original.json`, not public) 通过不改变旧stage，不是产品运行证明；双job/plan来源产品修复仍在Source、未部署，Promote未通过。

9236普通Service范围自然配置 准备 (`artifacts/M11/runs/20261015-persistent/configuration-natural-service-scope-9236-prepare-original/configuration-natural-verification.json`, not public) true，工单e347d08e-7fd5-44dd-8658-e4e9462112f4、日程e021ee41-4d3f-4be3-834a-120ec58eec16由自然worker单次认领。23:52:46实际SQL (`artifacts/M11/runs/20261015-persistent/configuration-service-scope-9236-natural-progress-fourth-original.json`, not public) 及 23:53:41后续SQL (`artifacts/M11/runs/20261015-persistent/configuration-service-scope-9236-natural-progress-fifth-original.json`, not public) 均确认nestedOrigin1、子执行executing、jobrunning、0mutation。这证明真实初始化节点已进入子执行，不代表Native成功、retries变更完成或五分钟性能通过；继续等待原自然终态，不补期限/claim/新句柄。

配置/门户正向自然闭环、Promote修复后的新意图验证及最终固定输入全测/三端构建、审计覆盖、完整凭证秘密扫描、恢复与部署验收仍待。旧afc66全量及checkpoint扫描false范围保持，**M11 整体及商用验收未完成**。

### 最新终态补充：9236配置子执行已安全失败收尾，正向发布未通过

上海23:55:32的 原执行到期后独立SQL (`artifacts/M11/runs/20261015-persistent/configuration-service-scope-9236-after-original-execution-expiry-observation-original.json`, not public) 已取得终态：同一原日程、工单、wrapper执行、configuration job与配置子执行全部failed；job错误WORKFLOW_SCHEDULE_NAMESPACE_EXPIRED，子步骤CONFIGURATION_NOT_STARTED/operationId=null，nestedOrigins=1、mutation0，恰有一条original-execution failed outcome。此前23:53:41的executing是中间观察，现以该终态补充，原报告保留。

本次初始化实际进入了真实子来源，且原回调在到期后正确收口新子执行，不再停留为第四轮历史子claim那样的未决状态；这仍是自然配置失败，五分钟执行预算与正向发布验收均未通过。不能将安全失败收尾写成Service retries已变更、性能或M11通过，不能借新句柄补原请求。

Promote双job/plan来源修复另有 独立Source审阅 (`artifacts/M11/m11-promotion-apply-fork-lineage-independent-source-review-20261015-original.json`, not public) 无阻断发现；报告所列173项为实现者提供的测试结果，审阅者未重跑，API编译及正式Source汇总仍待独立记录。该产品修复未部署，9236运行结论及旧author403保持。**M11及商用整体验收仍未通过。**

### 当前checkpoint：fac38已部署、固定源码全量通过，正向自然执行仍阻塞

本节固定当前checkpoint，不继续追随新增运行结果；前述摘要及待办按各自观察时间保留。**M11及商用验收仍未通过，主要阻塞是自然执行中的重复校验放大与超时。**

- 当前API为 `fac38e7acf0b42e8bd08f1b2ce3568d92654d74d4646d81bb586e571aca1a2bd`，冻结 (`artifacts/M11/runs/20261015-persistent/promote-fork-single-step-candidate-source-freeze-original.json`, not public) 410个输入/38条SQL、隔离编译0。首次启动失败 (`artifacts/M11/runs/20261015-persistent/promote-fork-single-step-candidate-runtime-original.json`, not public) 原因是只读dist缺少空的嵌套迁移挂载目标；只补自有停止API的空目录后，同容器启动ready200 (`artifacts/M11/runs/20261015-persistent/promote-fork-single-step-candidate-runtime-after-mountpoint-original.json`, not public)，未改原计划/窗口/会话、未重放旧日程、未改Kong镜像或源码。370个API编译产物 (`artifacts/M11/runs/20261015-persistent/fac38-runtime-candidate-equal-full-api-build-original.json`, not public) 与本次全量构建字节相同。
- 新固定输入全量报告 (`artifacts/M11/m11-frozen-full-source-typecheck-isolated-build-20261015-5azk2xlc-original.json`, not public) 为1,792个输入（含5份手册），前后SHA256同为 `08aaf0d7f29ac9749c7ce68431675c32c90dcad4430d14efef5402bd47057b17`；604文件、1,446suite、13,976/13,976项通过，失败/跳过/todo均0。完整测试、三端类型检查、三端/tmp隔离构建共七步退出均0；仓库原三端dist的454项metadata保持，手册chunk仍为ae311b1cc492353102b9c33f2f5699a1fd6641e56eeda03c9fe5637a1da79a16。它取代afc66作为当前源码/类型/构建门禁，但不证明真实自然执行或商用通过。期间一次瞬时mkdir ENOSPC与原日志保留，没有据此隐藏失败或跳过用例；固定输入及原dist边界仍保持。
- Promote双job/plan来源修复173项/API类型及隔离编译0 (`artifacts/M11/m11-promotion-apply-fork-lineage-source-only-20261015-original.json`, not public) 与独立Source审阅已整合部署；step首段Authority专项58项 (`artifacts/M11/m11-business-step-first-authority-source-only-20261015-original.json`, not public) 及独立审阅也已整合。旧Source对照仅三条调用次数/路径计数断言不同，其余权限与拒绝语义保留；专项不额外相加为全量，也不等于自然性能达标。
- 第四个独立门户case `single-step-fork-20261015` 的 新Service/Route夹具 (`artifacts/M11/runs/20261015-persistent/portal-single-step-fork-fresh-fixture-after-capacity-original/native-verification.json`, not public) 经独立审批201；Service75c2b5a6-58c3-47cd-b1e0-880666f83edd/Routea72e2f8f-661f-4988-bf9d-6f4bfc0a6ac6，前12阶段至 激活 (`artifacts/M11/runs/20261015-persistent/portal-single-step-fork-natural-activate-original/portal-natural-verification.json`, not public) 实际通过。工单0bc581f3-0a17-48d9-be72-5202229806b8/日程31a5f0bb-48b7-4e67-8daf-33c553f0f6d7自然单claim bda6d6aa-e826-497f-bc75-0ae6bdd2fc10后，实际SQL终态 (`artifacts/M11/runs/20261015-persistent/portal-single-step-fork-natural-progress-third-original.json`, not public) 为W/E/schedule均uncertain、snapshotready、首Native KONG_EXECUTION_CONTEXT_EXPIRED、mutation0、单条original-execution uncertain outcome；grant/credential仍pending。HTTP observe失败 (`artifacts/M11/runs/20261015-persistent/portal-single-step-fork-natural-observe-original/portal-natural-verification.json`, not public) 保留，尚无issued、revoke或凭证代理可用验证；0mutation不将未知改为已知未发送，不重放旧case。
- 修复后Promote新同名独立 源Service (`artifacts/M11/runs/20261015-persistent/promote-after-fork-fix-source-fixture-original/promote-after-fork-fix-source-fixture-original.json`, not public) 与 目标Service (`artifacts/M11/runs/20261015-persistent/promote-after-fork-fix-target-fixture-original/promote-after-fork-fix-target-fixture-original.json`, not public) 夹具实际通过；Root新拓扑证明 (`artifacts/M11/runs/20261015-persistent/current-promote-after-fork-fix-fresh-topology-original.json`, not public) 确认节点/数据库OID不同、Admin未暴露且BFF不连Kong库，仍共享PG进程/存储/故障域、roleIsolationVerified=false。截至该checkpoint时尚未准备/author新的Promote工单；后续准备与激活拒绝见下一追加记录，不将当时的修复部署或夹具成功写成运行正向通过。
- 容量回收 (`artifacts/M11/runs/20261015-persistent/narrow-unused-image-capacity-recovery-original.json`, not public) 仅删除3个无标签且无任何运行/停止容器引用的镜像，回收105,459,712字节，容器ID、卷及bind文件未动。实际重复校验放大的 只读Source诊断 (`artifacts/M11/m11-business-schedule-validation-amplification-source-review-20261015-original.json`, not public) 及优化方向仍不是新修复或性能验收，后续需在保持当前权限、原期限及packet/before-send门禁下实施并用全新意图验证。

本轮实际检查点秘密扫描 (`artifacts/M11/runs/20261015-persistent/current-fac38-checkpoint-secret-scan-original/m11-current-secret-scan-2026-10-15T16-24-43-223Z-7b14563c-4da9-4c62-9528-be9edcfd7728.json`, not public)已通过：310份实际秘密材料、383,068,615字节、0发现、真实进程退出0，文件与材料栅栏保持。扫描包含新三端产物、待发布文件、8个自有容器完整日志、原API归档日志及966条实际审计记录；日志截止16:23:40 UTC。采用固定 `checkpoint-api-key-not-issued` profile，API Key材料数0，`finalCredentialComplete=false`，不代表已发证或完整凭证验收。旧false报告保留。本checkpoint后仍须处理自然配置/门户性能阻塞、Promote新意图验证及余下生产验收；本次源码与扫描通过不改变M11/commercial=false。

### 远程检查点与Promote激活拒绝的后续事实

本节补充前一checkpoint之后的已证事实；旧报告、旧失败与原截止时间保持。**当前仍未完成M11或商用验收。**

检查点已实际推送至远程仓库：[938d41e](https://github.com/sean-y-wang/kongpilot-console/commit/938d41e)、[7077df8](https://github.com/sean-y-wang/kongpilot-console/commit/7077df8)，HEAD为 [6824f312aecc2b82aa1579e53500c343be74f8f2](https://github.com/sean-y-wang/kongpilot-console/commit/6824f312aecc2b82aa1579e53500c343be74f8f2)。这是研发检查点，不是GA发布、生产合并或商用准入。

fac38当前主库审计只读核验 (`artifacts/M11/runs/20261015-persistent/fac38-current-audit-all-chains-readonly-original.json`, not public) passed=true：使用实际runtime角色及repeatable-read快照，验证983行/3条审计链及全部JSON patch正确；无写入、未打印审计正文或凭证。该结果更新已有审计完整性观察，不外推所有关键写入审计覆盖100%或商用通过。

修复后新Promote case的 prepare-plan (`artifacts/M11/runs/20261015-persistent/promote-after-fork-fix-prepare-plan-original/promote-after-fork-fix-prepare-plan-original.json`, not public) 真实通过：比较、promote-plan及apply登记均201，保留原导入计划62d59b1d-937c-4665-8534-abdf3ecfada2→新执行计划cf7c60d1-e063-40e4-965b-047a5f328076/作业1dae0b1f-aa69-417f-8582-7411c892ace3，工单e3c79cbe-3e8f-4a7d-8339-04a9eb3de19c。Root实际只读SQL (`artifacts/M11/runs/20261015-persistent/promote-after-fork-fix-original-sql-deadlines-original.json`, not public) 核对原导入/执行作业、两个计划、两条authority及workflow七个截止约束，均未续期或写入。这证明新case越过旧来源绑定拒绝节点，不等于发布完成。

随后 author-activate原报告 (`artifacts/M11/runs/20261015-persistent/promote-after-fork-fix-author-activate-original/promote-after-fork-fix-author-activate-original.json`, not public) 整体false：日程创建201、独立审批201，激活403 `WORKFLOW_CANDIDATE_EXPIRED`。上海次日00:42:49（UTC16:42:49）的 独立SQL (`artifacts/M11/runs/20261015-persistent/promote-after-fork-fix-original-activation-denial-independent-sql-original.json`, not public) observationVerified=true/functionalAcceptancePassed=false：日程176d3a23-ae2d-469e-94a9-bcee1febacde仍pending-approval/revision1，activations、claims、outcomes均0；workflow approved/revision2，revision1和2各只有一项pending步骤，配置执行、workflow执行及mutation均0。未激活、未执行不能登记自然Promote成功；零mutation账本行不是独立网络抓包。原意图不重试、不延寿，不为获取通过结果更换请求键或重新提交旧stage。

实际结构化HTTP日志 (`artifacts/M11/runs/20261015-persistent/promote-original-activation-http-timing-original.json`, not public) 进一步核对原激活请求耗时31,405ms后403，超过独立候选读取胶囊30,000ms预算；当时原job/plan截止与windowEnd仍在未来，支持高置信归因于30秒读取胶囊耗尽。候选胶囊及原期限校验共用该错误码，生产安全日志不暴露精确throw site；该结论不是取得栈trace的精确定位，也不授权延长胶囊或重放原意图。fixedReader只读分层性能改造正在Source阶段，尚未冻结、部署或完成新的全量验收，不能使用fac38的13,976项通过覆盖这些新修改。后续仍须验证保持当前权限/原截止/packet门禁的性能修复，再以全新意图完成自然配置、门户与Promote正向链及余下生产门禁。

### ac6 fixedReader实际运行：Source计数改善，调用预算及未知传播仍阻塞

本节继续保留前述检查点与失败，当前API已变为ac6候选；**M11、正向自然执行及商用验收仍未通过**。

fixedValidationReader最终Source报告 (`artifacts/M11/m11-fixed-validation-reader-source-final-20261015-original.json`, not public) 验证三份产品文件及固定16项输入，4个测试文件245/245项通过（新35、原210），两份独立审阅无阻断。受控双GET组的完整current调用由旧17次降至2次；这是Source计数，不是实际耗时、Native GET数量减少或权限等价的无限外推。ac6冻结 (`artifacts/M11/runs/20261015-persistent/fixed-reader-candidate-source-freeze-original.json`, not public) API摘要 `ac6e5c58d390220b399a082c826277c0c59f8739ded9823043dae9aa9b8d3b1a`，410个输入/38条SQL不变、隔离编译0。Root备份并只重启自有验收API，UTC16:46:57实际启动ready200 (`artifacts/M11/runs/20261015-persistent/fixed-reader-candidate-runtime-original.json`, not public)，原数据/会话/计划窗口保持，不重放旧日程、不改Kong源码/镜像。fac38的13,976项全量不覆盖ac6这些新字节，尚无ac6新固定输入全量通过。

新 Service夹具 (`artifacts/M11/runs/20261015-persistent/configuration-service-scope-fresh-service-fixed-reader-original/native-verification.json`, not public) 经独立审批及Native201；新工单准备/author/独立vote/激活 (`artifacts/M11/runs/20261015-persistent/configuration-natural-service-scope-fixed-reader-prepare-original/configuration-natural-verification.json`, not public) passed，原工单f3d78f35-dd2f-48f4-91df-39ae92520319/日程b23cf628-6d73-4ca4-bd19-622ceffcb4b6。到期前观察 (`artifacts/M11/runs/20261015-persistent/configuration-fixed-reader-before-due-original.json`, not public) active/claim0；原notBefore为UTC16:50:00.697，自然认领后 (`artifacts/M11/runs/20261015-persistent/configuration-fixed-reader-after-natural-due-original.json`, not public) 恰1claim，原authority截止16:55:09.072，未手动tick或延长。

后续真实 第一次 (`artifacts/M11/runs/20261015-persistent/configuration-fixed-reader-natural-progress-first-original.json`, not public)、第二次 (`artifacts/M11/runs/20261015-persistent/configuration-fixed-reader-natural-progress-second-original.json`, not public)、第三次 (`artifacts/M11/runs/20261015-persistent/configuration-fixed-reader-natural-progress-third-original.json`, not public) 及 原authority到期后独立SQL (`artifacts/M11/runs/20261015-persistent/configuration-fixed-reader-after-original-authority-expiry-original.json`, not public) 记录：初始化建立nestedOrigin1，但配置job/子执行/子步骤为uncertain，错误 `KONG_EXECUTION_CALL_LIMIT`、operationId=null、mutation0；外层workflow/执行及revision2步骤却为failed。日程仍claimed、outcome0，**不是已正确收口或配置成功**。原HTTP终态观察 (`artifacts/M11/runs/20261015-persistent/configuration-natural-service-scope-fixed-reader-terminal-http-original/configuration-natural-verification.json`, not public) false（claimed而非succeeded）保留。零mutation不把未知降为已知未发送，不重放、改写或用新句柄补旧意图。

本次 实际CPU采样 (`artifacts/M11/runs/20261015-persistent/configuration-fixed-reader-natural-cpu-sampling-original.json`, not public) 6.395336秒/4,595样本，idle2,456约53.45%；Inspector仅容器loopback且采后关闭、没有Debugger暂停。调用栈 (`artifacts/M11/runs/20261015-persistent/configuration-fixed-reader-cpu-caller-stacks-original.json`, not public) 仍见fresh grants/HMA及Material校验热点，仅用于诊断，不由17→2的Source计数宣称wall-clock或五分钟性能通过。新Portal Service/Route夹具 (`artifacts/M11/runs/20261015-persistent/portal-fixed-reader-fresh-fixture-original/native-verification.json`, not public) 经独立审批201；尚未建立该夹具的Portal工单，未发行API Key，不能记发证成功。

当前另三项Source工作分别处理validation支撑GET的local预算归属、配置原账本unknown向wrapper传播、以及仅configuration Namespace的canonical重复reviewer扫描；均尚未冻结、部署或完成验收，不预写通过。用epoch替换完整fresh grants的方案已 只读审阅明确拒绝 (`artifacts/M11/m11-fixed-reader-epoch-only-rejected-source-review-20261015-original.json`, not public)：合法绑定自然expires_at到期可以不触发任何epoch变更，不能证明权限保持；该替换未实施。继续保留完整当前权限与原截止约束，在新修复冻结后用全新意图验证，旧全量/旧秘密扫描范围及M11/commercial=false保持。

### 6438当前检查点：14,346项全量通过；源集群激活冲突保留

本节记录截至19:27:18 UTC的公开观察事实与进行中的工作，更新当前摘要；历史候选、失败及原期限保持。**M11、实际正向自然执行及商用整体验收仍未通过。**

- 本轮完整固定输入回归 (`artifacts/M11/m11-frozen-full-source-typecheck-isolated-build-combined-checkpoint-20261015-original.json`, not public)：1,807输入（1,802份Source/config及5份手册）、前后SHA256均`a1bf34365f65c96de1594f199923d1ea691fad4b8390d1da64a764d7dbfe93d7`，613测试文件/1,468个suite、14,346/14,346项通过，0失败/跳过/todo；三端类型与三端隔离构建均实际退出0。原仓库dist的454项元数据及decK二进制保持。两份主手册在本轮后另改，新增文档字节待独立验证，不能宣称此轮已覆盖。
- 普通配置组合门禁经独立Source复核 (`artifacts/M11/m11-combined-origin-canonical-checkpoint-independent-source-review-20261015-original.json`, not public)、访问器兼容性窄复核 (`artifacts/M11/m11-combined-origin-facade-accessor-independent-source-review-20261015-original.json`, not public)、396项专项 (`artifacts/M11/m11-combined-origin-facade-accessor-focused-source-20261015-original.json`, not public)及67项真实组件受控整合/195项相关回归 (`artifacts/M11/m11-origin-canonical-backend-integrated-source-tests-20261015-original.json`, not public)通过；已收集入新全量，不重复相加。初轮86项中41项失败及其后测试断言勘误原件保留；受控SQL/SDK测试不代表真实事务、Native写入或性能通过。
- 6438候选冻结 (`artifacts/M11/runs/20261015-persistent/combined-checkpoint-candidate-source-freeze-original.json`, not public)为`6438d338852f559f2440bc9a0e3bebf0f434c8e39e796cf1fbefc133dc0df0ad`，410个API输入/38迁移，复用已通过全量的370份隔离编译产物。实际部署 (`artifacts/M11/runs/20261015-persistent/combined-checkpoint-candidate-runtime-original.json`, not public)在安全计数全0及备份后仅重启自有验收API同一容器，19:15:17.242 UTC启动、ready200；未改Kong源码/镜像、原计划窗口/会话或旧未知结果。该部署已包含门户local4预检计数修复，尚无修复后新case发证实证。
- 全新源集群工单`3b6cc0ed-0e74-4932-af67-33d6597202ab`、日程`bf076892-6ea0-4106-84da-f85a69d01a06`预期retries 5→4。原准备/激活报告 (`artifacts/M11/runs/20261015-persistent/configuration-natural-service-scope-combined-checkpoint-prepare-original/configuration-natural-verification.json`, not public)为false，激活409 `WORKFLOW_SCHEDULE_PHYSICAL_IMPACT_CONFLICT`；不重发该stage或修改原窗口。19:20:01 UTC实际只读SQL (`artifacts/M11/runs/20261015-persistent/configuration-combined-checkpoint-before-natural-due-original.json`, not public)确认schedule pending-approval、workflow approved/revision2、job waiting_approval，claim/outcome/执行/mutation/nestedOrigin均0。文件名虽含before-natural-due，实际时间晚于notBefore，不当作到期前证明。
- 19:25:31 UTC实际影响面核验 (`artifacts/M11/runs/20261015-persistent/combined-checkpoint-activation-conflict-target-scope-readonly-original.json`, not public)证实与旧`592cfbaa-7c1a-459e-9f23-060b912ae6b4` uncertain日程共享影响面。该安全拒绝不等于正向apply通过；旧未知不因0 mutation行被改成已知未发送，也不通过清旧保留或地址别名绕过。真正不同目标Kong节点健康1.5.1/approval、format2定义active，观察时无未决schedule/mutation。随后其上新case准备/独立审批/激活通过 (`artifacts/M11/runs/20261015-persistent/configuration-natural-service-scope-target-combined-checkpoint-prepare-original/configuration-natural-verification.json`, not public)，新工单`960b76cf-1c4c-4428-a6af-1e355c84dd06`/日程`a09d2ba3-d205-4e1b-b41e-cbcb33785c44`。19:27:18 UTC到期前SQL (`artifacts/M11/runs/20261015-persistent/configuration-target-combined-checkpoint-predue-readonly-original.json`, not public)为active、claim/outcome/执行/mutation均0，原notBefore 19:28:55.991、windowEnd 19:34:05.991 UTC。仅记录等待自然执行，不预写apply成功；共享PG11进程/存储与故障域限制保持。
- 当前组合优化只覆盖普通配置，Promote/sourceScopes仍走原检查；双来源组合支持仅TEMP设计、未入产品Source。下一步继续目标新case自然完成/回读、门户发证与吊销、Promote新意图，以及撤权/回滚/故障/通知、当前完整审计/真实凭证扫描、生产部署/恢复门禁。既有检查点秘密扫描不覆盖其后新字节，也不具备已发API Key完整性结论。

### 6438目标配置终态补录：原窗口到期，单claim一致uncertain

本节补录19:34:21–19:35:55 UTC的真实终态，不改写前节19:27:18 active/claim0的原采样。**正向配置apply、M11及商用整体验收均未通过。**

- 到原期限后实际SQL (`artifacts/M11/runs/20261015-persistent/configuration-target-combined-checkpoint-after-original-expiry-original.json`, not public)：日程`a09d2ba3-d205-4e1b-b41e-cbcb33785c44`自然claim恰1、nestedOrigin为1，schedule/workflow、外层执行/步骤及配置子job/执行/步骤均uncertain，单条`original-execution` uncertain outcome；错误`WORKFLOW_SCHEDULE_VALIDATION_EXPIRED`。原authority/lease 19:34:05.589、windowEnd 19:34:05.991 UTC已过，未续期、补claim或重放旧case。子执行单独expiresAt更晚不能延长外层原期限。
- mutation `1690fc7a-b7bc-4b95-b1a9-58dbb9fc50d7`实际failed、remoteStarted=true/completed=false，不作已知未发送证明。原BFF终态观察 (`artifacts/M11/runs/20261015-persistent/configuration-natural-service-scope-target-combined-checkpoint-terminal-http-original/configuration-natural-verification.json`, not public)false，实际uncertain而非succeeded，保留原失败。
- 目标节点日志/Service实际回读 (`artifacts/M11/runs/20261015-persistent/configuration-target-combined-checkpoint-expiry-native-diagnostic-original.json`, not public)：retries仍5而非期望4。19:28:50–19:35:55 UTC整节点日志区间有686条GET/200，不能精准因果归属于该工单或某检查点，亦不是nosend证书、原生写入成功或性能通过。
- Source成本审查定位重复Native校验链，修复待实施/冻结验证，不将本次不同目标的失败测试当作源集群409修复。Promote组合支持仍仅TEMP、未入产品Source；TEMP专项初轮适配器错误28通过/36失败，保留原失败，不计产品回归通过。
- unknown配置影响面尚无完整产品安全resolution流程，现有只读reconcile不释放保留；正式、可审计的故障恢复及其权限/并发/证据核验列为生产待办。禁止以清旧保留、改写unknown或地址别名替代恢复。随后仍须完成新合法配置、门户/Promote正向链与其余撤权/回滚/通知、当前审计/完整凭证扫描和部署/恢复门禁。

### 19:53 UTC Source整合检查点：成本修复与Promote组合待新全量门禁

运行仍为6438d338，前述目标配置uncertain、源激活409及旧原期限不变；**新增Source未部署，M11及商用仍未整体验收**。

- 配置Native单次load专项 (`artifacts/M11/m11-configuration-native-single-load-focused-source-20261015-original.json`, not public)165/165（含24新增）、固定输入无漂移、退出0，独立复核 (`artifacts/M11/m11-configuration-native-single-load-independent-source-review-20261015-original.json`, not public)无必须修复阻断。保留原私有proof/阶段授权和完整Native verifier/current-before/Target append GET/最终step；受控Source直接load 2→1及3→2，不作实际Native调用数或时延验收。
- scheduled V2 kind hint专项 (`artifacts/M11/m11-scheduled-step-kind-hint-focused-source-20261015-original.json`, not public)355/355（含54新增）、固定输入无漂移，独立复核 (`artifacts/M11/m11-scheduled-step-kind-hint-independent-source-review-20261015-original.json`, not public)无阻断。hint自身不授权，完整原材料/上下文/状态/依赖及全部审批人检查在返回前保持；包含门户步骤与外层配置metadata wrapper，HTTP/V1/嵌套配置保持原分支。
- Promote组合六产品经独立Source审阅 (`artifacts/M11/m11-promote-combined-origin-independent-source-review-20261015-original.json`, not public)无阻断，隔离诊断/应用记录 (`artifacts/M11/m11-promote-combined-origin-source-diagnostic-and-application-20261015-original.json`, not public)64/64通过、CLI测试wall cap 30秒、退出0，六产品及四测试已进Source。正式新36case显式30秒只调整测试wall cap，产品预算、业务期限及断言不改；初轮adapter 28通过/36失败，以及后轮exit130中断、部分23通过/3超时失败、无完整组结果均保留。当前完整整合验证尚在运行，诊断不是正式全量或自然发布通过。旧源连接身份仅比较当前open-to-close，历史inventory未封存author时revision/secret；至少六次完整SQL/AEAD材料观察的实际成本仍待验。
- 手册后改专项 (`artifacts/M11/m11-operator-manual-followup-focused-20261015-original.json`, not public)7/7与独立Console Web构建0，原115个标题/22个支持链接及raw入口核验通过；原独立副本漏Portal依赖构建失败保留。本专项不追溯扩大旧14,346冻结范围。
- 19:39:28 UTC实际全审计链 (`artifacts/M11/runs/20261015-persistent/combined-checkpoint-target-expiry-current-audit-all-chains-readonly-original.json`, not public)runtime角色只读验证1,193行/3链/全部JSON patch正确、退出0，不覆盖其后新写入。共享key精确核对 (`artifacts/M11/runs/20261015-persistent/configuration-shared-impact-reference-source-confirmation-original.json`, not public)确认原409对应Service.host=echo的Upstream.name引用，不是全cluster锁，Native0且旧physical locks不变。
- 新专属Upstream名称及相关Upstream (`artifacts/M11/runs/20261015-persistent/configuration-distinct-upstream-native-load-fixture-upstream-original/native-verification.json`, not public)、Target (`artifacts/M11/runs/20261015-persistent/configuration-distinct-upstream-native-load-fixture-target-original/native-verification.json`, not public)、Service (`artifacts/M11/runs/20261015-persistent/configuration-distinct-upstream-native-load-fixture-service-original/native-verification.json`, not public)三张独立审批工作流均执行201，仅是新验收夹具；旧scope/claim/lock/endpoint与既有Service不改，不是旧意图重放或定时apply通过。
- Root19:52:50 UTC开始1,813输入新固定整合全量，目录`/tmp/kp-m11-full-20261015-fsjl6udx`，仍进行中，未预写结果。须完整测试、三端类型/隔离构建通过后部署新候选，再做全新配置自然执行→门户→Promote；unknown正式安全resolution及最终撤权/回滚/通知、审计/凭证扫描、生产部署/恢复仍待。

### 20:18 UTC 828检查点：14,461项全量与部署通过，配置总调用预算仍未闭合

本节补录前节进行中的新全量及后续实际运行，历史失败、期限与采样保持。**M11及商用整体验收仍未通过。**

- 新固定输入全量 (`artifacts/M11/m11-frozen-full-source-typecheck-isolated-build-native-load-promote-20261015-original.json`, not public)实际通过：1,813输入（1,808份Source/config及当前5份手册），前后SHA256均`27533fb9c4b687415ea21387d114c784abceae815757fc51e01c092436b9aad6`；616测试文件/1,474个suite、14,461/14,461项、0失败/跳过/todo，三端类型及三端隔离构建退出均0，既有仓库dist与decK保持。本轮已覆盖当前手册及新增Source，但只是Source门禁，不替代实际HTTP/Native/自然worker或性能验收。
- 828候选冻结 (`artifacts/M11/runs/20261015-persistent/native-load-promote-candidate-source-freeze-original.json`, not public)为`828f33504a10704aa881641cf373e3f4dccbdef52ebcc3ed04f2b013700a4890`，410个API输入/38迁移、复用通过轮的370份隔离编译产物。实际部署 (`artifacts/M11/runs/20261015-persistent/native-load-promote-candidate-runtime-original.json`, not public)确认备份及安全计数全0后，仅重启同一自有验收API，20:05:19.566 UTC启动、ready200；旧failed/uncertain日程、原窗口/会话与Kong源码/镜像不改。配置单次load、V2 kind hint和Promote组合支持已部署，部署不代表业务完成。
- 20:14:23重连原观察 (`artifacts/M11/runs/20261015-persistent/native-load-promote-environment-reconnect-readonly-original.json`, not public)的false是按旧6438输入假设核对不匹配；它仍记录同一容器、新20:05启动、ready200、38迁移。后续已核对新828及原冻结/部署报告，不把这份原false解释为环境损坏，也不据环境重连宣称DR通过；原报告保留。
- 全新独立Upstream case 准备/独立审批/激活 (`artifacts/M11/runs/20261015-persistent/configuration-natural-distinct-upstream-native-load-prepare-original/configuration-natural-verification.json`, not public)通过，W=`254ea5f8-c8aa-4398-9cde-c559f1dff93d`、S=`8ba604ab-1b4f-49d0-9b54-469f610c1434`、J=`9ba2acaa-eb8c-4320-a07d-959519a111f3`，原window 20:10:03.442–20:15:13.442 UTC。20:14:59实际SQL (`artifacts/M11/runs/20261015-persistent/configuration-distinct-upstream-native-load-current-readonly-original.json`, not public)自然claim恰1、nestedOrigin1，日程/工单、外层执行/步骤、配置子job/执行/步骤一致uncertain，单条`original-execution/uncertain` outcome；子job/步骤错误`KONG_EXECUTION_CALL_LIMIT`，原authority/lease 20:15:09.189 UTC未续期。mutation `b8197c5d-220b-4419-be83-6ce34ef2116d` failed、remoteStarted=true/completed=false，不能据此证明未发送。
- 原HTTP终态观察 (`artifacts/M11/runs/20261015-persistent/configuration-natural-distinct-upstream-native-load-terminal-http-original/configuration-natural-verification.json`, not public)因uncertain而非succeeded保持false；其afterRetries是计划值。实际预算/回读诊断 (`artifacts/M11/runs/20261015-persistent/configuration-distinct-upstream-native-load-budget-diagnostic-original.json`, not public)记录Root scheduled-workflow/configuration calls上限500/当前501，Service实际retries 5而非期望4、knownNotSentCertified=false。未手动tick、重放或续窗口，正向apply未通过。
- Source尺度复核：N个不同Service普通更新、R名审批人，每次full-scope至少N+1项，支撑GET下界`N × (2R + 3) × (N + 1)`全部计入同一Namespace500预算。R=1时N=10至少550，N=100至少50,500，尚未计其他必要调用。这是所述Source形态的成本下界，不是实际时延/压测或本case逐次因果证明，也不是把先前整节点686条GET日志归属于该工单。普通配置尚无预算预判/分批continuation，架构收敛与显式批次只读研究中，不预写实现；不增加预算、续原授权/窗口或伪造proof。
- 当前平台生产依赖公告审计 (`artifacts/M11/m11-platform-production-dependency-advisory-audit-20261015-original.json`, not public)实际退出0、各级及total公告0，复制的6份平台manifests/lock保持；仅覆盖当前npm生产lock公告，不包含Kong、基础OS、运行配置或授权逻辑。正向新门户发证、Promote发布、unknown安全resolution及执行中撤权/回滚/故障/通知、最终审计/完整已发凭证扫描、生产部署/恢复仍待，M11/commercial=false。

### 20:25 UTC 当前828重连证明及架构评估补录

当前828只读重连原报告 (`artifacts/M11/runs/20261015-persistent/native-load-promote-current-828-reconnect-readonly-original.json`, not public)于20:25:36 UTC验证通过：410个运行输入匹配828、同一API容器及原20:05:19启动、ready200/38迁移；activeUnclaimedSchedules、unexpiredClaimedSchedules、unexpiredRunningJobs均0，旧意图未重放、私密账本保留。基于旧6438假设的false原报告保持；本次`hostRebootOrDrProven=false`，不是DR、主机重启恢复或配置成功证明。

架构路线评估当前优先固定复合校验及私有`StepReadInput`，保留V2；V3长期桥接需要新的来源、DAG及快照/回收合同。均尚未实现或验收，不把方案评估写成产品完成，M11/commercial=false保持。

### 20:29 UTC 当前全审计链核验补录

当前审计原报告 (`artifacts/M11/runs/20261015-persistent/native-load-promote-terminal-current-audit-all-chains-readonly-original.json`, not public)于20:29:50 UTC实际退出0：当前runtime角色、`REPEATABLE READ READ ONLY`事务核验1,248行/3条链及全部有效JSON patch。只证明该采样已有审计行的完整性，不覆盖其后写入，不推导关键写操作100%覆盖，也不改变M11/commercial=false。

### 828候选当前秘密扫描检查点

434份当前保留秘密材料分4批由原扫描器执行，全部退出0、0发现；原整组匹配预算失败保留。每批覆盖当前三端隔离构建、当前与归档17份自有日志和1,248条审计；新增文档/报告的全批次增量关闭与原集合覆盖以聚合报告 (`artifacts/M11/runs/20261015-persistent/native-load-promote-terminal-current-secret-scan-aggregate-original.json`, not public)为准。API Key材料0、finalCredentialComplete=false。普通配置预算前置判断、小时级配置审批/远期定时和未知结果安全恢复继续待验；M11及商用仍false。


## 19. 显式SQL阶段候选与新自然配置终态（截至21:02 UTC）

[研发检查点d3e1d405](https://github.com/sean-y-wang/kongpilot-console/commit/d3e1d40572336fe8ff4e5975289c2bed480208bf)已于20:36:56 UTC推送至`work/m11-checkpoint-20261014`，Root实际ls-remote核对同SHA；其后的Source和运行结果另记，不能追溯计入该提交。**M11、正向配置发布及商用整体验收仍未通过。**

- Web两份产品及相关测试已集成：服务端期限专项 (`artifacts/M11/m11-business-schedule-server-deadline-web-focused-20261015-original.json`, not public)4文件63/63、Web类型退出0，独立Web构建 (`artifacts/M11/m11-business-schedule-server-deadline-web-isolated-build-20261015-original.json`, not public)退出0。页面仅采用服务端`expiresAt`上限，不虚构材料期限；未做本改动的真实浏览器验收。最初隔离副本缺共享/Portal依赖的失败按原报告保留。
- 显式SQL阶段7份产品及4份新增测试已进入Source，13文件专项 (`artifacts/M11/m11-explicit-configuration-sql-phase-focused-source-20261015-original.json`, not public)314/314、API类型退出0，独立审阅未报后续静态阻断；完整SQL/AEAD/当前绑定准备与最终Native门禁分别保留。隔离编译/冻结 (`artifacts/M11/runs/20261015-persistent/explicit-sql-phase-candidate-source-freeze-original.json`, not public)退出0、410输入/38迁移，API摘要`681b354cbf616b4580e44a7ddab85af7c9c8ab6aed017e866a6ed646eb71796b`。实际部署 (`artifacts/M11/runs/20261015-persistent/explicit-sql-phase-candidate-runtime-original.json`, not public)在备份及安全计数全0后仅重启同一自有验收API，20:50:54.075 UTC启动、ready200，原Kong源码/镜像、会话与旧意图不改。当前运行681b。最后14,461项/三端类型及构建完整门禁只覆盖旧828，不能作为681b或其后工作树已全量通过。
- 全新配置准备/独立审批/激活 (`artifacts/M11/runs/20261015-persistent/configuration-natural-explicit-sql-phase-prepare-original/configuration-natural-verification.json`, not public)对应W=`21562bc5-f297-4e28-83b6-aaaf7c7a201b`、S=`9e6fe575-85da-4241-9377-346414f28831`、J=`3bc8c4c1-1819-4591-9038-a4bc5ab92239`。原window 20:53:36.067–20:58:46.067 UTC，20:52:14到期前SQL (`artifacts/M11/runs/20261015-persistent/configuration-explicit-sql-phase-before-original-due-readonly-original.json`, not public)active/claim0；20:55:02 (`artifacts/M11/runs/20261015-persistent/configuration-explicit-sql-phase-first-natural-progress-readonly-original.json`, not public)和20:56:18 (`artifacts/M11/runs/20261015-persistent/configuration-explicit-sql-phase-second-natural-progress-readonly-original.json`, not public)均仅1个自然claim、当前执行中。20:57:44原SQL (`artifacts/M11/runs/20261015-persistent/configuration-explicit-sql-phase-third-natural-progress-readonly-original.json`, not public)记录日程/工单、外层执行与当前步骤、配置子job/执行/步骤一致uncertain，错误`KONG_EXECUTION_CONTEXT_EXPIRED`。原authority/lease截止20:58:38.837 UTC未延长；不能据该错误直接判定哪个局部frame到期。
- 原HTTP终态观察 (`artifacts/M11/runs/20261015-persistent/configuration-natural-explicit-sql-phase-terminal-http-original/configuration-natural-verification.json`, not public)因实际uncertain而非succeeded保持false。终态一致性及实际回读 (`artifacts/M11/runs/20261015-persistent/configuration-explicit-sql-phase-terminal-concordance-original.json`, not public)确认Service仍retries5而非期望4；mutation `bac364c9-625b-4274-be18-d02ace75f253` failed、remoteStarted=true/completed=false，`knownNotSentCertificate=false`。无手动tick、重放或改原窗口/期限；不将unchanged值、failed或一致unknown当作未发送证明或apply通过。
- Root后改的结构化超时诊断专项 (`artifacts/M11/m11-context-expiration-structural-diagnostic-focused-source-20261015-original.json`, not public)5文件55/55、API类型退出0，已应用Source但未部署；仅增加安全frame诊断字段，原guard/期限/预算不改，真实超时frame原因仍未证实。固定CurrentBefore provider及耐久配置材料仍仅TMP开发、未集成；Source复核另发现NativePolicy.fresh的5秒局部授权窗及ConfigVerifier的10秒窗，后续需连同精确before读取验证，不能预写修复或实际根因。
- 21:01:47 UTC当前审计链 (`artifacts/M11/runs/20261015-persistent/explicit-sql-phase-terminal-current-audit-all-chains-readonly-original.json`, not public)实际runtime角色、REPEATABLE READ READ ONLY，退出0，1,302行/3链及全部JSON patch有效；不代表预期关键写入100%覆盖。先前828检查点扫描只覆盖其原截止字节/材料，新字节及日志审计仍须再扫描。M8 Job/Plan的15分钟材料上限仍约束M11，小时级审批/远期定时、预算准入、unknown安全resolution、门户/Promote正向执行及余下生产门禁仍待。


## 20. 固定CurrentBefore已集成并部署，新自然执行待证（21:23 UTC阶段）

CurrentBefore源码专项原报告 (`artifacts/M11/m11-fixed-current-before-source-focused-20261015-original.json`, not public)确认冻结补丁`847492b2dfc4dc03d25d9db9498d1a41cc423b6c6c7129976ae1b223cf3ba74e`的11份文件已应用且匹配清单，原始raw归档已按摘要核验；441项既有检查及80项新增组件检查均退出0，共521项，API类型检查实际退出0。独立Source审阅无新增静态阻断，审阅结果SHA256为`73467c94f05d01ff7f9f413f6f7b147cc5e7d6265065ae2b2e33b71074b036bb`；它是条件性源码结论，不证明原始Root claim或真实自然执行。随后已取得下述本候选编译及实际部署报告，不能因此登记自然发布成功。

7份产品改动仅替换scheduled primary PATCH及最终before-send两处旧短帧current-before读取；新固定调用使用30秒单调时钟上限，原deadline只可收紧、返回收口保持。完整fresh grants、全部reviewer检查、Root500及全部聚合计数、最终Native校验和返回closing不减少；读取结果是当前数据观察，不是Native发送许可。该30秒是新调用自身的有界合同，不延长旧窗口、claim、材料或批准事实，也不凭Source专项宣称真实预算或时延通过。

Target历史ID缺失仍不能由active集合EOF或旧optional点查404证明。当前V2 Target append在author/revision、activate及preclaim阶段明确拒绝`WORKFLOW_SCHEDULE_CONFIGURATION_TARGET_APPEND_UNSUPPORTED`；并行补齐工作尚未集成/验收，不能宣称该能力支持或完整Target商用闭环。

隔离API编译/冻结 (`artifacts/M11/runs/20261015-persistent/fixed-current-before-candidate-source-freeze-original.json`, not public)实际退出0，410输入/38迁移、370份编译产物，输入保持；候选摘要`17178482215db4dcd4bfcd118a1d9f2c74b195b6fe8db7e283f6adfdbfc27aaf`。实际部署 (`artifacts/M11/runs/20261015-persistent/fixed-current-before-candidate-runtime-original.json`, not public)在备份及安全计数全0后，仅重启同一自有验收API，于21:23:28.108 UTC启动、ready200，未改Kong源码/镜像、原窗口/会话或重放旧意图。当前运行1717848。全新独立夹具的Service自然配置日程阶段仍在执行，本节尚无其完成结果；须另记录原author/批准/激活、自然单claim、终态和实际回读，不预写通过。原681b失败、原窗口/期限及全部旧unknown保持。最后14,461项全量、d3e1d405远端检查点及434材料扫描均只覆盖各自原截止范围，不能扩大到本批后改字节。

耐久配置材料域仍仅TMP开发：207项受控检查、API类型/emit退出0，SQL038未在真实库执行，真实超过15分钟审批/定时未验。草稿拒绝Target/Promote、要求同author SID；为防旧preview已被legacy apply派生job消费，查询LIMIT 5001并扫描/解密历史derived configuration_jobs，超过5,000条即fail-closed。这是历史派生job记录数上限，不是对象或packet数。这些均为尚未产品集成的合同边界，不是生产承诺。相关Web新入口尚未冻结。现有M8 Job/Plan的15分钟材料缺口、完整预算准入、unknown安全resolution及门户/Promote和其余生产验收仍待，M11/commercial=false。


## 21. 1717848自然配置终态与后续Source边界（截至21:34 UTC）

全新配置排程准备/独立审批/激活 (`artifacts/M11/runs/20261015-persistent/configuration-natural-fixed-current-before-prepare-original/configuration-natural-verification.json`, not public)原阶段通过；W=`5a61a9dc-63f9-42d7-95b4-c08ce3014f39`、S=`9fbcc96b-56a5-443b-bf39-f62f6ce25d32`、J=`f48b4fad-e647-4446-beb1-76c0b4d3b44d`。原window 21:26:03.999–21:31:13.999 UTC，到期前只读SQL (`artifacts/M11/runs/20261015-persistent/configuration-fixed-current-before-before-original-due-readonly-original.json`, not public)active/claim0。实际BFF/SQL终态及回读 (`artifacts/M11/runs/20261015-persistent/configuration-fixed-current-before-terminal-concordance-original.json`, not public)保持passed=false：只有一个原自然claim `b47d3d17-963f-4d9c-a1f6-3e394538c897`，日程/工单、外层执行`2557c538-7fdb-43e4-81d7-fdfa870d6fd4`与当前步骤、配置子job/执行`2f6ea38d-4284-4172-9a4d-81499a55df12`与步骤均uncertain，错误`KONG_EXECUTION_CONTEXT_EXPIRED`，单条original-execution/uncertain outcome。原authority/lease 21:31:06.925 UTC及window均未延长，子执行较晚期限不续外层授权。mutation `c99d2973-bff0-4ca9-8663-ffcc3a9c7417` failed、remoteStarted=true/completed=false；Service实际retries5、预期4。无手动tick、旧或本次失败意图重放，未观察到KnownNotSent证书，不将配置值未变推导为未发送或发布完成。

原日志修正解析后的结构诊断 (`artifacts/M11/runs/20261015-persistent/fixed-current-before-natural-terminal-context-expiration-diagnostic-v2-original.json`, not public)记录实际frame kind=`actor`、purpose=null、reason=deadline、timeoutMs=120000、overdueMs=1；首次单行解析不足的原报告保留。该日志确认到期frame类型与期限，不确认产生它的模块或调用点。只读Source正在核对MutationService两处runActor及runOperation的默认预算；针对私有job和originalStep绑定的严格预算slice仍仅TMP，祖先/claim期限及Root500不减，不能先写已修复、已部署或新业务通过。

前端新建配置工单入口12份文件已集成，Source专项 (`artifacts/M11/m11-configuration-workflow-web-focused-source-20261015-original.json`, not public)4文件121/121、Web类型退出0；首次隔离副本遗漏index.html导致构建失败的原事实保留，Root随后独立构建 (`artifacts/M11/m11-configuration-workflow-web-isolated-build-20261015-original.json`, not public)实际退出0、输入保持、未写仓库dist。无真实浏览器/业务验收；原请求键遭明确拒绝时的持久回执缺口仍未补齐。121项、521项或编译构建通过均不代表功能闭环，最后14,461项整合全量仍仅旧828。

耐久配置材料及其跨作者修复仍未集成，独审四项整改为cross-author lineage、provider fallback、issuance尾部短期限及source SQL互斥，尚不能登记整改完成。SQL038未在真实库执行，明确拒绝的receipt缺口未补；5,000上限仍是全CID/WID范围历史derived configuration_jobs扫描记录数，不是实体或packet数。新长审批专属Upstream (`artifacts/M11/runs/20261015-persistent/configuration-durable-long-approval-fixture-upstream-original/native-verification.json`, not public)、Target (`artifacts/M11/runs/20261015-persistent/configuration-durable-long-approval-fixture-target-original/native-verification.json`, not public)、Service (`artifacts/M11/runs/20261015-persistent/configuration-durable-long-approval-fixture-service-original/native-verification.json`, not public)三张独立夹具工作流各执行201；尚未登记新durable issue、未开始真实超过15分钟等待，夹具不替代长审批验收。最后已核对远端仍d3e1d405；后续Source、报告及秘密/日志字节未重新扫描或提交。预算准入、unknown安全resolution、门户/Promote正向链及全部剩余生产验收保持待办，**M11/commercial=false**。

## 22. 652耐久域实库/页面分项与自然配置失败（截至22:08 UTC）

详细事实及手册待发布提纲见[续项进展第22节](../../milestones/checkpoints/2026-10-15-m11-continuation.md#22-耐久材料已实际登记短材料自然发布仍未通过截至2208-utc)。本节只追加新证据，不改写上述历史候选和原失败。

| 验收项 | 当前真实结果与边界 |
| --- | --- |
| Source/隔离编译 | 耐久域专项 (`artifacts/M11/m11-durable-configuration-reviewed-source-focused-20261015-original.json`, not public)461项、API类型检查退出0；652冻结/隔离编译 (`artifacts/M11/runs/20261015-persistent/durable-configuration-candidate-source-freeze-original.json`, not public)416个API输入、375编译产物、输入不变；不代替新全量 |
| SQL038/实际启动 | DDL回滚 (`artifacts/M11/runs/20261015-persistent/durable-configuration-sql038-rollback-dryrun-original.json`, not public)后，正式迁移/部署 (`artifacts/M11/runs/20261015-persistent/durable-configuration-candidate-runtime-original.json`, not public)至SQL000–038共39条，652465e6、21:43:36 UTC同一自有API启动、ready200；无旧意图重放、旧窗口/SID变更或Kong源码/镜像修改 |
| runtime最小权限 | 真实运行凭证SQL (`artifacts/M11/runs/20261015-persistent/durable-configuration-runtime-nosu-privileges-original.json`, not public)确认非superuser、0成员、无CREATE DB/ROLE/BYPASSRLS/REPLICATION/schema CREATE；两张durable事实表只有SELECT/INSERT、非owner，五个函数固定search_path且非security definer；不证明并发约束 |
| 长时新材料登记 | 21:44:52真实提交 (`artifacts/M11/runs/20261015-persistent/configuration-durable-long-approval-prepare-submit-original/configuration-natural-verification.json`, not public)W=`f8393f4e-ec5e-4d9b-b5ac-1e35fb7b1e9e`、新P=`cbd4422c-001c-45d0-a363-13887955f031`；新材料至22:44:45.961、旧preview原期限21:58:43.827不变；未登记schedule、尚未审批/激活或发布成功 |
| 原键/页面只读 | 真实receipt与新Plan matcher (`artifacts/M11/runs/20261015-persistent/durable-configuration-original-key-model-readonly-v2-original/registration-model-verification.json`, not public)通过、无新POST；首次connection-refused失败 (`artifacts/M11/runs/20261015-persistent/browser-durable-configuration-plan-readonly-original/verification.json`, not public)保留，后续浏览器v2 (`artifacts/M11/runs/20261015-persistent/browser-durable-configuration-plan-readonly-v2-original/verification.json`, not public)实际7项/3截图、业务写0/Admin0/页面错误0，22:00仍等待审批；不替代超过15分钟后审批/执行闭环 |
| 独立短材料自然执行 | W=`78dd2050-aeeb-4d38-b005-7a876a48c7c6`、S=`bf7b6b07-d17c-4f70-bd94-f9b987a53a21`、J=`c391d347-f9fd-4c6a-8fe0-07841e637063`，准备/批准/激活 (`artifacts/M11/runs/20261015-persistent/configuration-natural-private-mutation-envelope-prepare-original/configuration-natural-verification.json`, not public)不等于发布完成；原HTTP终态 (`artifacts/M11/runs/20261015-persistent/configuration-natural-private-mutation-envelope-terminal-http-original/configuration-natural-verification.json`, not public)为false |

独立BFF/SQL/回读终态 (`artifacts/M11/runs/20261015-persistent/configuration-private-mutation-envelope-terminal-concordance-original.json`, not public)证明短材料日程只有原claim `ea6c4e9c-8e5d-48c8-9c10-468770079ab0`、一条original-execution/uncertain outcome；日程、工单、内外执行及当前步骤均uncertain，旧revision1步骤保持pending。mutation `31a01bb6-1295-4347-bb3a-0ff27f20e9d3` failed、remoteStarted=true/remoteCompleted=false，Service.retries实际5非目标4。真实日志 (`artifacts/M11/runs/20261015-persistent/private-mutation-envelope-natural-terminal-context-expiration-diagnostic-original.json`, not public)记录internal-read/authorization、5000ms、逾期1ms，精确调用点未确认；原authority/lease的21:53:24.963及windowEnd的21:53:28.265均不续，子执行较晚期限不续外层授权。无手动tick、无原意图重放，未取得KnownNotSent证书；**不以未变回读推导NOSEND或发布成功**。

SQL039 DDL回滚试验 (`artifacts/M11/runs/20261015-persistent/durable-configuration-sql039-rollback-dryrun-original.json`, not public)退出0，回滚后仍39迁移、新表不存在、SQL038摘要不变；`appliedToRuntime=false`、真实约束竞争未验。22:07:44拒绝回执候选Source已集成 (`artifacts/M11/m11-durable-configuration-rejection-039-source-focused-20261015-original.json`, not public)，c94934c5补丁10文件逐hash吻合，17文件525项及API类型检查退出0、1,132输入保持；不与既有专项相加。正式SQL039迁移、runtime部署、原键拒绝回执和约束竞争尚待，固定Service引用/绑定预算修复也不登记运行通过。

22:08:35pre-INSERT绑定阶段候选Source已集成 (`artifacts/M11/m11-mutation-binding-sql-reviewed-source-focused-20261015-original.json`, not public)，244f00ca补丁2文件逐hash吻合、独审3cdf8120；最终33项及55项共88项、API类型检查退出0，旧撤回候选与原失败/探索报告保留。该阶段保留完整SQL/AEAD/current-party验证，实际读取、INSERT、最终Native检查在阶段外；未证明652故障的精确原因、修复或真实自然执行，`actualRuntimeDeployed=false`，当前仍为652/39条。

最后完整门禁14,461项及秘密扫描仍仅覆盖原828截止范围，最后已核对远端`d3e1d405`；当前Source/SQL/文档与后续日志审计尚未重新全量、扫描或提交。新长时工单独立审批与自然执行、预算准入、unknown安全resolution、门户/Promote正向链及其余生产门禁仍待，**M11及商用整体未验收**。两本正式手册本轮不变，耐久域拟补说明仅保存在进度记录草案，待实际流程通过后再发布。

## 追加验证：SQL039原键拒绝（22:24 UTC）

实际Source、正式迁移、NOSU、唯一UI命令与真实拒绝、只读恢复、零关联执行SQL和当前审计链证据，统一见[进度第23节](../../milestones/checkpoints/2026-10-15-m11-continuation.md#23-sql039实际部署与原请求拒绝闭环截至2224-utc)。本项不代表Service正向自然发布、SQL跨事务发布竞争或整体验收；旧失败与所有未决仍保留。

## 2026-10-18 续作基线与完整验收门禁

**M11整体验收与平台整体商用准入仍未通过。** 10月18日恢复起点为临时目录清空、8个自有容器Exited255；随后已取得同一API恢复ready200 (`artifacts/M11/runs/20261018-resume/api-start-readiness-original.json`, not public)与持久数据库只读核验v2 (`artifacts/M11/runs/20261018-resume/pre-api-console-db-safety-v2-original.json`, not public)：原b186/418输入/376JS摘要保持，40条迁移摘要一致，平台PostgreSQL/Redis数据保留，旧过期材料没有重新激活。1,536条审计为行数观察，不是新的全链验证；首次观察器假表名SQL失败仍保留。完整时间线见进度24.3，监控恢复、新认证/业务、异机灾备与生产部署仍未验收。

第23节后的原证据补录统一见[进度第24节](../../milestones/checkpoints/2026-10-15-m11-continuation.md#24-2026-10-18-恢复续项与完整验收计划)：最后有据运行版本是b186部署 (`artifacts/M11/runs/20261015-persistent/source-disposition-candidate-runtime-original.json`, not public)，418输入/376JS/40条迁移；SourceP处分专项 (`artifacts/M11/m11-source-plan-disposition-reviewed-source-focused-20261015-original.json`, not public)API209/209、Web231/231与类型检查通过，但Web隔离构建 (`artifacts/M11/m11-source-disposition-web-isolated-build-20261015-original.json`, not public)退出1、产物0仍待修复。旧828完整回归不覆盖这些后续字节。

SQL039双连接8项rollback负测 (`artifacts/M11/runs/20261015-persistent/durable-rejection039-rollback-negative-first-original.json`, not public)真实通过，历史拒绝回执过期后读取 (`artifacts/M11/runs/20261015-persistent/durable-rejection039-readonly-historical-after-expiry-original/verification.json`, not public)2项通过，但真实两个writer合法图发布/拒绝提交竞争仍未验。新工单W=`fb886ce1-f267-49ca-a37f-7dabf693d657`22:28:27登记 (`artifacts/M11/runs/20261015-persistent/configuration-durable039-long-approval-prepare-submit-original/configuration-natural-verification.json`, not public)及模型只读匹配 (`artifacts/M11/runs/20261015-persistent/durable039-registration-model-readonly-original/registration-model-verification.json`, not public)通过，原材料23:28:21.831期限未续、未完成审批/激活；它与旧Wf839现均已自然过期，不得继续旧意图。

后续按[完整验收清单](../../acceptance/m11-commercial-acceptance-checklist.md)分别取得恢复、Service自然成功、门户、Promote、Target0/DELETE poststate/回滚、会签/撤权/并发/unknown/预算、通知/审计/DR与最终固定版本发布证据。清单覆盖原始13项验收及M9–M11，单测/SQL/页面通过均不替代业务终态。[手册增补草案](../../milestones/drafts/m11-manual-additions.md)独立保存，两本正式手册尚不新增未验收能力。当前结论保持false，完成全部适用门禁后另出版本化验收结论。

### 09:00 UTC 最新候选与业务阶段

10月18日已恢复全部8个原容器healthy (`artifacts/M11/runs/20261018-resume/all-owned-runtime-health-original.json`, not public)，新会话 (`artifacts/M11/runs/20261018-resume/fresh-console-sessions-original/verification.json`, not public)保留原actor；Web重新类型检查/专项/构建 (`artifacts/M11/runs/20261018-resume/web-rebuild-and-fresh-tab-summary-original.json`, not public)均退出0，真实新会话空缓存浏览器10项/2图通过、业务写入0。旧构建失败保留，新增结果不等于业务完成或异机灾备。

Service联合专项 (`artifacts/M11/runs/20261018-resume/root-joined-service-focused-original.json`, not public)26文件978/978及419输入API隔离编译 (`artifacts/M11/runs/20261018-resume/reviewed-service-candidate-source-freeze-original.json`, not public)通过；实际运行候选 (`artifacts/M11/runs/20261018-resume/reviewed-service-candidate-runtime-original.json`, not public)为`98a4715f808f72b3a10888e919542a723ef95770057118f34fa6ce0de3986fb1`、377JS/40条迁移，同一API于08:59:54 UTC重启ready200、保留旧期限/会话/unknown。原853d补丁EOF拼接失败 (`artifacts/M11/runs/20261018-resume/service-core-initial-patch-eof-concordance-original.json`, not public)与冻结夹具修正事实保留，不能把首轮摘要检查记为成功；当前978不是新整仓全量。

新门户独立四类Native201夹具及preflight至request九阶段实际通过，取得工单W=`9a277756-cc98-4b5e-b15f-c523e69c8bbf`；申请报告 (`artifacts/M11/runs/20261018-resume/portal-new-natural-request-original/portal-natural-verification.json`, not public)明确尚未排程/领取/执行、未发证，不能写完整门户闭环。新配置工单W=`d855a24a-4e4f-4c90-8de3-4c9a5f8d2ce4`等待超过15分钟、原短preview自然过期后，登记排程阶段实际403 (`artifacts/M11/runs/20261018-resume/configuration-new-long-approval-author-vote-activate-original/configuration-natural-verification.json`, not public)`CONFIGURATION_DURABLE_BINDING_INVALID`，passed=false/scheduleId=null；未取得审批/激活或自然发布成功证据，HTTP拒绝也不单独证明所有SQL副作用为0。完整补录见[进度24.5](../../milestones/checkpoints/2026-10-15-m11-continuation.md#245-0900-utc-固定service候选部署门户前置与长审批拒绝)，M11与整体商用结论继续false。

### 09:14 UTC 后续终态与独立分项

原长工单实际只读取证 (`artifacts/M11/runs/20261018-resume/long-approval-durable-binding-forensics-original.json`, not public)确认W d855仍pending/revision1、J waiting_approval，原24小时期限保持；当前durable job及已存base workflow仓库验证通过，schedules/delegations/claims/配置执行/步骤/mutation各0。零账本记录不是KnownNotSent证书，不重试原author。随后current-version Source修复 (`artifacts/M11/runs/20261018-resume/durable-scheduled-current-version-source-integration-original.json`, not public)`c57e4733`三文件已集成、实现者546项/API类型0，SQL038/039不改，但尚未部署或取得新运行成功；新独立W=`acae8927-bd70-476d-94bb-05d3832d12bb`09:11:39登记 (`artifacts/M11/runs/20261018-resume/configuration-after-revision-new-prepare-submit-original/configuration-natural-verification.json`, not public)，来源preview至09:25:33.229、超过15分钟门槛09:26:54.597，尚未author。

新门户author (`artifacts/M11/runs/20261018-resume/portal-new-natural-author-original/portal-natural-verification.json`, not public)/vote (`artifacts/M11/runs/20261018-resume/portal-new-natural-vote-original/portal-natural-verification.json`, not public)/activate (`artifacts/M11/runs/20261018-resume/portal-new-natural-activate-original/portal-natural-verification.json`, not public)通过，S=`17061d84-4d39-4f22-9e52-4e2ab4421fd0`；原observe (`artifacts/M11/runs/20261018-resume/portal-new-natural-observe-original/portal-natural-verification.json`, not public)仍false。真实SQL终态 (`artifacts/M11/runs/20261018-resume/portal-new-natural-terminal-sql-original.json`, not public)为单自然claim d8b0、E651ff518/W/S/current Consumer step均uncertain，mutation78c96e49 failed/remoteStarted=true/remoteCompleted=false，其余三个当前步骤pending。原API结构诊断 (`artifacts/M11/runs/20261018-resume/portal-new-natural-terminal-context-diagnostic-original.json`, not public)确认scheduled-workflow根frame 120000ms到期、逾期123ms，不是原claim到期或先前5秒frame；未确认成功发证，不重试旧case。首次观察工具错列失败 (`artifacts/M11/runs/20261018-resume/portal-new-natural-first-progress-sql-original.json`, not public)及改用started_at的v2只读结果 (`artifacts/M11/runs/20261018-resume/portal-new-natural-first-progress-sql-v2-original.json`, not public)均保留，池idle采样不外推全程无锁。

平台生产依赖检查 (`artifacts/M11/runs/20261018-resume/production-dependency-audit-original.json`, not public)0漏洞/退出0不覆盖OS/容器运行时；当前审计全链 (`artifacts/M11/runs/20261018-resume/resumed-current-all-audit-chains-original.json`, not public)1,706行/3链/JSON patch有效，但关键预期写入覆盖仍未验。完整事实及边界见[进度24.6](../../milestones/checkpoints/2026-10-15-m11-continuation.md#246-0914-utc-长材料核验门户自然失败与当前审计)。当前运行仍98a4715f，M11/commercial继续false，正式手册不新增未验功能。
