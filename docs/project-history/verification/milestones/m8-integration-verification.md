# M8 集成与验证记录

最新状态（2026-10-12）：M8 实际功能、固定官方 decK 1.2.4 diff/sync、12 项浏览器操作、审计、软清理与最终秘密扫描已通过。见 [阶段进展](../../milestones/m0-m8-stage-delivery.md) 与仓库 artifacts/M8/m8-final-acceptance.json。M0–M8 独立生产验收正在执行；下方历史阶段的“待验收”不代表最新结果，生产恢复通过前不宣称生产就绪。

当前状态：M8 API/Web 已实际部署，SQL011 已执行，真实 Kong 验收进行中。五类对象（Plugin、Consumer、Service、Upstream、Certificate）已实际删除恢复，原 Target ID、SNI 关系和恢复后的六类凭证代理认证通过；OAuth2 使用原 Certificate/SNI 校验真实 TLS 后签发并验证 token。完整快照已捕获 26 个对象、28 条记录，观察 17 个捕获分页及终点。原导出已提交但结果投影返回 500，修复后原回执为 succeeded、过期下载能力为 false，未重发原 POST。新独立导出和下载已成功，15,722 字节 YAML 已私有持久化；原定时策略已自然成功捕获完整快照并通过 BFF 暂停。首次直接 apply 的修订号故障及零 Native 事实保留。CAS 修复后的新独立导入和 apply 已实际成功，Service.retries=1 及六类凭证代理认证通过；新回滚预览的 schema 摘要差异已定位并修复，独立新回滚及六类凭证验证通过。审批首次初始化的事务修复已通过 223 项源码回归及 47 项隔离 PostgreSQL 验证，已实际部署。随后新申请获批准，但执行返回 503；原 uncertain 事实保留，配置执行和 Native 写入均为零。限定 SQL 列归属与失败捕获快照软归档的修复已通过 218 项相关源码回归，正在隔离 PostgreSQL 验证。CLI、浏览器及最终安全验收尚未完成。此记录不代表 M8 端到端完成或整体商用就绪。M9–M11 尚未实现。

## 实际实现

`modules/configuration` 提供固定 BFF 路由、当前身份与范围授权、只读后台捕获、封存计划执行、独立元数据审批和 decK 权限桥接。`config-storage` 持久化加密材料、快照、计划、作业与步骤回执，`config-capture` 按 Kong 游标捕获完整对象图，`config-transfer` 解析并输出固定 decK 1.1 格式、计算 diff 和拓扑步骤。`deck-adapter` 提供固定协议转换；它不会开放 Kong Admin API 的网络访问。

控制台增加快照列表/详情、导入与 diff、计划、作业和 GitOps 页面。查询带明确集群与工作区，可选完整集群或有限 Service 集合；游标绑定实际范围、账号、权限和查询条件。部署文件中的 Target 与 SNI 分别嵌套于 Upstream 与证书，包含六类 Consumer 凭证。快照保留原生 null；decK 1.1 不支持的可选 null 有明确格式省略报告。

写入使用已封存的实际 Native body、原始幂等键、当前权限、实际 before 和私有执行证明。审批模式使用原工作流批准与执行上下文。所有 Native 删除进入回收站。Target 权重变更采用一次追加，分别记录原 ID 和实际新 ID。未知结果停止后续写入；只读核验记录当前观察，不改写原未知回执，不推断因果成功。

下载许可消耗、审计和安全回执在同一事务提交。文件使用 no-store，传输前和每个数据块重新授权；记录“交付未确认”，不伪造文件已送达。CLI 会话区分读写，写会话只匹配唯一就绪步骤，实际隐藏读取、重试和回读计入预算。定时任务重新检查实际策略、策略所有者及权限，仅获得无登录 SID 的只读捕获权限。

## 当前证据

| 验证 | 结果 | 证据边界 |
| --- | --- | --- |
| 全量源码测试 | 4,923 通过，0 失败、0 跳过 | `artifacts/M8/root-whole-source-unit.json`；包括临时 PostgreSQL 函数断言，不能代替实际网关验收 |
| 当前修复后全量源码复验 | 5,059 通过，0 失败、0 跳过 | `root-whole-source-current-repairs-unit.json`；659 个测试套件，仍与真实业务验收分别记录 |
| API、Console Web、Portal Web 类型检查 | 通过 | 三个 workspace 的实际 TypeScript 检查 |
| API 编译与 diff 检查 | 通过 | 实际编译；尚未作为部署成功证据 |
| M8 独立 PostgreSQL 存储 | 32/32 | `storage-isolated-postgres.json`；实际 SQL，生产 Access/审计为明确合成参与者 |
| SQL000–011 后原 SQL 安全断言 | 6/6 | `storage-original-sql-full-migrations-validation.json`；临时本地 PG、无网络、内存数据目录 |
| 加密 | 20/20 | `storage-crypto-unit.json` |
| Root 当前授权、历史权限、事务和 CLI 桥接/执行 | 67 项 | 独立源码用例，数据库/网关参与者为明确合成 fixture |

原全量测试中的前端 VM 加载器不兼容和 SQL fixture 启动失败报告保留在 `root-whole-source-unit-failure01.json`；修复后的结果来自重新执行，未回填旧失败或未执行结果。SQL fixture 只使用本地 Docker，清理仅限自身临时容器和匿名卷。

## 真实部署及修复中的证据

实际核心部署完成 API/Web 编译、SQL011 一次迁移和原 API/Web 进程重启。启动、部署、Admin 网络、监控、门户和投递验证分别为 15、27、37、54、79、30 项通过；独立核心放行为 `root-core-runtime-release.json`。第一次容器连续性检查错误地把重启后的动态 IP 视为固定值，原失败保留，限定可变属性后的实际接续为 40/40。可选 decK 容器的构建、运行问题独立保留，不能用核心健康结果替代其验收。

真实捕获首先返回 `CONFIGURATION_ACTOR_INACTIVE`：PostgreSQL bigint 由驱动返回字符串，而身份与审批校验原来只接受数字。修复仅规范化有限范围的正整数；151 项源码回归和部署后 37 项检查通过。原 403 保留，不改写为成功。

接续捕获返回 `CONFIGURATION_SCHEMA_FIELD_MISMATCH`，失败作业 `a109c9ef-2363-4596-bd77-fe8e62efed91` 已持久化为终态，不能重发同一失败作业并改写结果。实测证书响应包含 Admin 路由附加的 `snis`，而原生 DAO schema 没有此字段。修复单独校验证书关系并保留原始加密观察，导出/恢复使用各 SNI 原 ID 和归属，不使用名称去改动跨工作区关联。同时在不可变对象暂存前统一冻结完整 schema bundle，匹配配置计划的绑定合同。相关捕获/传输/Facade 源码 90 项和当前授权回归 136 项通过，实际 API 修复部署连续性 36/36 通过。新捕获作业 `e44dcbdb-793b-4ffc-bae1-aeb8038c1c7e` 已成功，快照 `2fb9b46e-afb3-442d-b06d-e9112603e00f` 完整，实际保护后的展示使用 size=2、13 页至终点。

为验证 OAuth2，C1 已实际增加真实 `8443 ssl` 监听及仅本机的测试入口；没有伪造可信 X-Forwarded-Proto，也没有关闭 TLS 校验。43 项运行连续性和 11 项监听/Admin 边界检查通过，其余 21 个容器、SQL000–011、12 类加密监控材料及版本未变。安全验收随后使用原 Certificate/SNI 验证 TLS，实际 OAuth2 token POST 和 bearer 代理请求均返回 200。入口检查与业务请求分别记录。

## 待实测与限制

正式验收仍须检查原工作流执行、真实 decK diff/sync、页面交互及最终秘密扫描。启动、SQL011 一次迁移、七类子实体 schema、完整游标捕获、五类对象恢复、恢复后的六类凭证和自然定时快照的证据已取得。生产 Portal/监控对象的历史所有权继续受保护，普通导入或回滚不能重新启用旧 Portal 凭证或复制监控私有配置。OAuth2 客户端配置备份不包含活动 token；无法取得原 Basic 密码的历史对象不得假称可恢复。

定时快照的保留期不会自动销毁加密密钥；彻底清除仍需明确确认。在线密钥销毁不承诺已独立保留的备份副本也被销毁。Kong 1.5 与历史数据库的维护状态，以及 M0–M7 已公开的验收限制，继续列入最终商业条件评估。

真实五分钟策略未触发的固定范围日志显示 SQLSTATE 42501。普通运行账户对历史策略版本只有 SELECT/INSERT，旧 `FOR SHARE OF s,v` 还要求其 UPDATE 权限。修复只锁可变策略 `s`，继续读取并校验原所有者、当前版本、物理范围和不可变摘要。84 项源码及 38 项隔离 PostgreSQL 检查通过，包含旧错误复现、精确修复查询、版本更新拒绝及并发策略修改锁保护；SQL000–011 和授权不变。实际 API 部署连续性 36/36、健康接口 200，证据为 `schedule-mutable-policy-lock-repair-continuity.json`；后文记录了实际自然定时触发。

导出修复从对应加密材料读取真实版本，关联检查覆盖集群、工作区、作业、产物、所有者、状态和有效期，SQL011 保持不变。82 项源码回归及 39 项隔离 PostgreSQL 检查通过；实际 API 修复部署连续性 36/36 通过，证据为 `export-material-revision-repair-continuity.json`。原导出 500 后的提交事实与原 HTTP 失败分别保留，不重发原 POST，不延长过期时间。可选固定 decK 容器已通过真实隔离工具链验证，实际 BFF diff/sync 仍待执行。

前端默认 workspace/cluster 表单未挂载 Service 选择器时，真实 rc-field-form.validateFields 不返回 serviceIds。最窄修复将这两类缺字段规范为 []，services 缺 ID 和非法数组仍拒绝；实际 FormStore 生产者回归和全部 17 项 Web 策略测试通过。独立 Web 静态部署连续性 36/36，页面及实际新 JS/CSS 均 200 且内容摘要与构建文件相同，证据为 `web-form-scope-repair-continuity.json`。实际浏览器十二步仍待专属窗口执行。

原定时策略 `81c063d9-025d-4692-99f0-a1612b12cf60` 在修复后自然执行原到期时间的任务。运行 `8a4a6a51-3940-4bb4-9b82-c33a51057eb1` 和作业 `c9b7986d-8d10-4516-8aea-51e75138bed7` 均 succeeded；快照 `148fa9f3-8b5a-4dc9-923b-9ddaf7d3cda7` 为 ready/complete，实际 26 个对象、28 条记录、17 页。执行来源为 schedule，origin_session_id 为 null，原所有者一致；无手动触发、改时钟或修改到期时间。只读事实见 `original-timer-after-lock-repair-natural-watch.json`。后续受保护 BFF 展示和逐项审计核对仍单独记录。

下载原 HTTP 合同为 POST 默认 201。第一次新下载已消费许可但验收脚本错误地只接受 200，原失败保留，不重发同键；随后独立新下载取得同一导出材料，先将原始字节以 0600 和 fsync 私有持久化再执行断言。公开产物不包含 YAML 或凭证明文。导出和下载的成功不代替实际 decK diff/sync 验证。固定 CLI 的 14 项源码反例检查已通过，尚未执行实际 CLI。

真实插件删除与原 ID 恢复已完成。Consumer 及六类凭证删除后，存档仍为 deleted、七个节点 restore_state=pending；原恢复请求在 Mutation 和 Native 之前返回父对象 404，没有恢复操作账本或审计记录。修复新增只供服务端解密图调用的归档授权：当前授权/SID/版本照常检查，仅 affected 且真实 404 的父对象允许使用归档身份；现存共享对象使用当前 tags，403/超时/5xx 不当作不存在。Route 对 Service 的必要 read 继承也按当前授权和归档关系保留，不扩大 write/delete。

同时修正整 Upstream 恢复的 Target ID：仅在受影响 Upstream 已按原配置恢复、精确原 Target GET=404 时重建原 UUID；单独 Target 删除仍保留历史并追加新物理记录。底层代理独立检查归档依赖、真实父对象、原 Target 是否存在及 exact body，恢复后核验 ID、父 ID、地址和权重。Root 授权/代理 125 项及回收站 143 项源码回归通过，API 编译和类型检查通过。窄部署冻结见 `root-recycle-archived-authority-original-target-fix-freeze.json`；实际 Consumer 和余下三类恢复仍须接续验证。

上述修复已实际部署，连续性 36/36 通过。随后原 Consumer 和七个节点按原 ID 恢复，余下 Service、Upstream、Certificate 的删除恢复也完成；原 Target UUID、地址和权重、SNI 关系以及恢复后的六类凭证均经实际 BFF 和代理核验。`security-live-consumer-typed-preview-unused-tail.json` 记录这五类成功，同时保留随后直接 apply 的失败；该报告整体为 828 通过、1 失败，不能称整体 GREEN。原插件恢复和 Consumer 删除未重播。

首次直接 apply 请求 `c4e3cfff-fbd1-45be-8528-8234444d6dc9` 返回 500。按原幂等键及固定只读控制台查询核实，作业 `5a78a3fc-21a7-4975-881e-48ba8be901e5` 为 failed/error_code=23514；execution、step、Native operation 均为零，开始与失败终态审计均存在。原错误是已封存计划后更新 safe_progress 没有推进 revision，违反 SQL011 的原身份保护触发器。证据为 `original-direct-apply-readonly-diagnosis.json`，不修改原失败作业或再次发送原键。

修复将进度初始化放入当前授权的 Repository 事务：锁定真实作业、检查 pending/apply 或 rollback、已绑定计划和预期 revision，再用完整集群/工作区/计划/修订号 CAS 将 revision 增加一次，提交前重新授权。原约束、权限和 SQL000–011 保持不变。相关源码 97/97、当前全量源码 5,186/5,186、API 类型检查与编译通过。独立 PostgreSQL 40/40 包含原错误复现、精确绑定拒绝、并发单赢、二次授权失败的真实事务回滚与初始化阶段零 Native 账本；授权参与者为明确合成 provider。四份测试期待失败报告保留，最终成功报告为 `storage-execution-progress-postgres-continuation-20261011-05.json`，安全汇总为 `storage-execution-progress-continuation-validation-20261011-01.json`。冻结为 `root-execution-progress-revision-cas-fix-freeze.json`；实际 apply/回滚仍须部署后独立验证。

CAS 修复已实际部署，`execution-progress-revision-cas-repair-continuity.json` 的 36/36 检查通过；两份运行编译文件匹配冻结摘要，其余 215 份编译文件、其他 21 个服务和受保护材料保持。仅重启原 API 进程，SQL、授权和原失败作业未改。实际业务验收接续检查原计划有效期，再提交新的明确 apply 申请；此部署结果不代替实际 apply/回滚结果。

新的独立导入与 apply 已在修复部署后实际成功，Service 的 retries 回显为 1，六类凭证认证仍通过。`security-live-direct-apply-unused-tail.json` 记录 894 项通过及随后回滚预览的一项失败，整体不为 GREEN。失败回滚作业 `77a2fd55-ddfc-474f-b216-2ad04baf8aa0` 没有 execution、step、mutation 或 Native operation。对应只读事实 `original-rollback-plan-readonly-diagnosis.json`、`original-rollback-schema-facts.json` 显示两份完整快照的集群、工作区、范围、Kong/适配器版本一致，唯一不等的绑定是 schema_hmac。正在加入当前双份历史图授权下的只读 schema 比较，只返回名称和结构等价布尔值；原回滚保护、原失败作业和 SQL 保持。

当前账号经固定 BFF schema 比较的 17 项验证通过，进一步只读路径诊断 6 项通过。实际差异仅为 11 个实体的字符串字段缺失 `len_min`，插件 schema 均相同，没有类型、枚举、默认值或数组顺序变化。对应运行中 Kong 1.5.1 原生 `kong/db/schema/init.lua` 摘要为 `2a9a4c690d5f94a24cbf0141fb03c4c2b3ac119f9e743317eb53ea94a8a28dc3`，第 916–923 行的字符串验证会现场将缺失 `len_min` 写为 1。实际源码证明为 `kong15-native-string-validator-source-proof.json`；两份原诊断及原失败作业均保留。

窄修只在同 Kong 1.5 版本、适配器和启用插件集合下，将字符串缺失最小长度与显式 1 视为相同验证规则；其他最小长度和全部实际字段约束仍精确比较。历史快照、对象摘要和加密材料不重写，执行计划继续绑定当前 before 快照摘要。规范化校验同时使用实际 Kong 的默认最小长度和 UTF-8 字节长度，类型化配置校验错误返回 400/409，非预期数据库错误仍保留失败。293 项相关源码、API 编译和 diff 检查通过，冻结为 `root-kong15-lazy-string-minimum-fix-freeze.json`；新的实际回滚与审批接续仍待验证。

上述兼容修复已通过真实 API 窄部署，`kong15-lazy-string-minimum-repair-continuation-continuity.json` 36/36 通过，实际四份编译文件与冻结内容一致，其余 214 份编译文件及所有受保护服务、SQL 和材料未变。首次冻结核对停止的报告另行保留，未触发 API 重启或业务写；恢复原冻结字节后独立部署。当前全量源码复验为 5,296 通过、0 失败、0 跳过、693 个套件，见 `root-whole-source-kong15-schema-compatibility-unit.json`。新的实际回滚与原 C2 审批验收正在接续；源码与部署结果不替代业务结果。

真实新回滚计划与 apply 已成功，Service.retries 回到 0，六类凭证代理认证继续通过。之后 C2 保持审批模式，新 17-Service 导入计划成功；首次审批 apply 请求 `aa88acc0-2e59-40a0-a4b6-c4f7fe7d4c67` 返回 500，作业 `dc9f495e-b8af-442c-ac67-51fe8a3c3b16` failed/error_code=23503，workflow、execution、step、Native operation 均为零。证据为 `original-v2-apply-readonly-diagnosis.json` 和 `security-live-rollback-unused-tail.json`，后者 987 通过、1 失败，整体不为 GREEN。原回滚与成功 apply 不重复，原失败继续保留。

已修正审批定义首次初始化的事务：默认定义的根记录、不可变版本和阶段需要满足原 deferred FK，不能分次自动提交；独立初始化现在自动开启事务，并用 CID/WID 事务锁避免并发初始化冲突。V2 和配置元数据提交将定义初始化、封存 wrapper、原 job/plan CAS 放在同一事务，前后检查当前权限；原 SQL、审批规则、原账号和所有失败记录保持。223 项相关源码及 API 编译/类型检查通过，冻结为 `root-workflow-definition-atomicity-source-freeze.json`。隔离 PostgreSQL 与新的实际审批接续仍在验证。

审批定义事务修复的实际隔离 PostgreSQL 接续为 47/47（原 40 项加 7 项），见 `storage-workflow-definition-atomicity-continuation-validation-20261011-01.json`。旧自动提交 INSERT 确实触发 `workflow_definitions_current_version_fk` 的 23503 并留下零部分行；修复后的正式初始化方法、三个并发初始化、旧定义复用，以及正式 V2/元数据 facade 的整体提交和外层失败回滚均通过。运行者为独立非 owner/非 superuser/非 bypass 角色，权限、审计和展示参与者明确标记为合成，不能替代生产审批证据。最终冻结为 `root-workflow-definition-atomicity-fix-freeze.json`；仅两份 API 产品源变化，SQL000–011 保持，实际审批仍待部署后续接。

审批定义修复已实际加载，`workflow-definition-atomicity-repair-continuity.json` 的 36/36 连续性检查通过，API 健康接口为 200。仅两份运行编译模块变化，其余 216 份编译文件、21 个服务、SQL000–011、原用户和 12 类加密监控材料保持；没有业务请求或执行模式变更。实际 C2 审批验收使用原完整历史和真实当前计划有效期继续，部署成功不替代审批成功。

新 C2 申请已批准，执行请求 `01514f40-ccd8-4f85-829b-0f67ae15da64` 返回 503/WORKFLOW_EXECUTION_FAILED。`security-live-submitted-v2-approval-tail.json` 为 1,073 通过、1 失败，不能宣称 GREEN。`original-v2-execution-readonly-diagnosis.json` 显示原工作流、执行和元数据步骤为 uncertain，配置作业仍 waiting_approval、计划仍 pending_approval；配置 execution、step 和 Native mutation 均为零。不重新执行原键或把 uncertain 改成成功。源码发现关联 UPDATE 同时包含两个 revision 列，修复仅将计划赋值明确为 `p.revision+1`，完整工作流、身份、范围、版本与摘要条件保持。

独立只读生命周期诊断发现一份原失败捕获快照仍为 capturing，currentVersion 为 null、版本数为零，原捕获作业已 failed/CONFIGURATION_SCHEMA_FIELD_MISMATCH。修复允许在精确同所有者、物理范围、唯一原终态捕获作业和现存加密材料证明下软归档；正在捕获或存在其他关联作业时继续拒绝，无版本快照仍不可恢复成 ready。原失败作业和材料不重写。`root-approval-plan-snapshot-lifecycle-source-unit.json` 为 218 通过、0 失败；API/Web 类型检查与构建通过。`root-approval-plan-snapshot-lifecycle-source-freeze.json` 是源码冻结，尚不代表实际部署或审批成功。四处 Web 文案同步说明基础审批范围，GitOps 下载示例使用实际 exportRevision；未改权限或审批行为。

审批计划列归属与失败快照生命周期的独立 PostgreSQL 接续实际为 61/61，见 `storage-approval-snapshot-continuation-validation-20261011-01.json` 与原始 `storage-approval-snapshot-postgres-continuation-20261011-02.json`。原歧义 SQL 触发 42702；精确修复 CAS、完整 tuple 错误拒绝、并发单赢及正式 prepareWrapper 到受控 dispatch 边界均通过。正式捕获根、加密分页和失败作业的软归档通过，运行中、跨范围、第二次授权或审计失败、无版本恢复继续拒绝。审批和授权参与者中明确使用合成结构/fixture，不代表实际审批已执行。首次测试误用 staging 列名触发 42703 的 -01 报告保留，产品和 SQL 没有因此修改。Root 独立核对 61 个结果和全部冻结源码，最终修复冻结为 `root-approval-plan-snapshot-lifecycle-fix-freeze.json`；实际部署与新独立审批正在继续。

上述修复已实际加载，`approval-plan-snapshot-lifecycle-repair-continuity.json` 为 36/36。原 API 进程重启，219 份运行 JS 与最终冻结一致（2 份旧模块变化、1 份新增，其余 216 不变）；现有只读 Web 挂载的 HTML、JS/CSS 均为 200 且摘要一致。22 个容器、18 个健康服务、SQL000–011、原用户和加密监控材料保持。新独立真实审批正在接续，原 uncertain 工作流未重执行。

本次全量源码检查曾取得 5,419 通过、1 失败，见 `root-whole-source-approval-snapshot-lifecycle-unit.json`。唯一失败来自验收测试仍期待旧私有 DTO 的错误消息，而现在使用公开 wrapper 合同。测试窄修保留错误 Native/V1/handler 拒绝，并额外核对仅一次 GET、零 POST；相关 40 项源码检查通过。产品和实际业务入口未因此改变，旧失败报告保留；新的全量复验独立执行。

新的独立 17-Service 审批执行返回 403/PERMISSION_DENIED，原请求 `9b49c650-4996-46fb-9359-3491bdd12bd8` 与工作流 `08290eab-745f-4e1e-8867-79d06eba5eea` 保留。`security-live-approval-preparation-repair.json` 为 1,152 通过、1 失败。只读 `approval-preparation-permission-readonly-diagnosis.json` 显示配置计划已 approved，配置 execution 已创建并失败，17 个步骤全 pending、operation/receipt 为空，Native mutation 为零。源码定位为 V2 校验另一位审批人的当前权限时调用了要求当前执行账号一致的 Authorization.snapshot，触发身份保护。修复限定服务端持久审批记录所对应的当前只读完整工作区授权核验，不更换执行账号、SID 或放松普通身份检查；旧失败不重执行。

同时补齐非事件工作流元数据成功审计的原 requestId、IP、workflowId，仅为 M8 两类处理器提供真实配置资源的 snapshots/gitops 范围证明。相关 122 项源码回归通过，包含配置 wrapper 零 Native、真实 job 范围与审计失败回滚；旧审计没有更新。此前全量源码接续 5,420/5,420 通过，见 `root-whole-source-approval-snapshot-lifecycle-continuation-unit.json`；它是上述权限/审计新修复之前的结果，不代替最终全量检查。

当前审批人授权修复和元数据审计关联已实际加载，`current-approver-grants-metadata-audit-repair-continuity.json` 为 36/36，原 22 个容器、18 个健康服务及 Web/Portal 不变。对应全量源码测试 `root-whole-source-current-approver-metadata-audit-unit.json` 为 5,486/5,486 通过；这是下一处 CREATE 修复之前的结果。

新独立审批请求 `0a9eaadc-ae9c-4e02-95bd-0d2eb843b3de` 仍返回 403；`security-live-current-approver-repair.json` 为 1,231 通过、1 失败，原失败保留。只读 `current-approver-execution-readonly-diagnosis.json` 确認实际计划已批准、首步骤 failed、其余 16 步 pending，所有 operation/receipt 均空，零 Native mutation。已终态的工作流不重执行。源码定位为已封存 CREATE 的 before=null 被通用 MutationService 当成旧资源校验而拒绝。

修复只在 ConfigurationNativeService 的已封存 CREATE 且 before===null 时传入 undefined；原 null 摘要与密文、更新/删除、通用 MutationService、AuthorizationService 和审批验证均保持。`root-native-create-before-final-source-unit.json` 为 179/179 通过，包含真实 NativeService、MutationService、AuthorizationService、WorkspaceResolver 的创建/回执/幂等/密文 null 及越权拒绝回归。第一次测试 fixture 的标签顺序不符合真实 prepareCreate，原 91 通过、4 失败报告保留，只修 fixture。API 类型检查和构建通过；冻结为 `root-sealed-create-before-fix-freeze.json`，仍需实际部署及新的独立审批验证，不能将 SOURCE 结果算作 M8 闭环。

CREATE 修复已实际加载，`sealed-create-before-repair-continuity.json` 为 36/36；219 份 JS 仅对应 NativeService 的一份变化，其余 218 份、Web/Portal、12 份 SQL 和受保护材料保持。该版本全量源码 `root-whole-source-sealed-create-before-unit.json` 为 5,535/5,535，通过结果早于下一处关联修复。

新的独立审批执行请求 `fd41544c-7bc3-4b13-85c0-bbf30a4ff672` 返回 `CONFIGURATION_NATIVE_BINDING_CHANGED`；`security-live-null-create-before-repair.json` 为 1,304 通过、1 失败。只读 `v2-native-binding-readonly-diagnosis.json` 显示首步 failed、其余 16 步 pending、操作和回执均空，Mutation INSERT 与关联整笔回滚，零 Native 写入。原 115 个已知请求、终态工作流和原失败报告保留，不重执行旧包。

修复限定两个审批验证模块：私有 proof/绑定校验后，在同一 INSERT 事务以完整 22 参数 CAS 建立步骤与操作的相互关联，再执行完整当前授权、租约、不可变计划和密文/HMAC 验证。任何后续拒绝使 INSERT 和关联一起回滚，普通未关联操作仍返回 403；Root Access、通用 Mutation、Native 策略和 SQL000–011 不变。`configuration-reciprocal-binding-regression-source-unit.json` 为 236/236；隔离 PostgreSQL `storage-operation-binding-continuation-validation-20261011-01.json` 为 39/39（原 32 条重跑及新增 7 条）。首次数据库运行的新增七条已通过，但末项清除正确拒绝仍执行中的合成 fixture；原 38/1 报告保留，仅修测试 fixture 生命周期后重新执行。API 类型检查和构建通过；最终冻结 `root-reciprocal-binding-fix-freeze.json` 的 219 份 JS 仅两份改变，其余 217 份、Web 三个产物和迁移保持。真实部署和新独立审批仍单独验证。

最新修复及生产配置策略的全量源码检查为 **5,627/5,627，通过 727 个套件，零失败、零跳过**，见 `root-whole-source-reciprocal-binding-production-policy-unit.json`。该结果覆盖最新关联修复及生产 Compose/helper 的源码合同；它不代表真实审批、生产启动、负载或灾备已通过。

最新审批关联修复已实际部署，`reciprocal-binding-repair-continuity.json` 为 36/36。219 份运行 JS 的两处变更与最终冻结相同，其余 217 份、Web/Portal、原 22 个容器和 18 个健康服务、迁移及受保护材料保持；没有新迁移、身份或业务请求。新的独立审批正在实际验证，此部署结果不替代业务成功。


## 审批执行超时与原事实收口（2026-10-11，验收仍进行中）

原 121 包实际执行在约 121 秒时超过后端 120 秒执行上限，边缘代理先在约 35 秒返回 504。16 个步骤及其原 Native 操作成功，最后一步的 Native 操作记录为 `KONG_EXECUTION_CONTEXT_EXPIRED`；配置父作业与执行记录仍显示运行中。原工单已失败，不能重放、改为成功或删除原事实。修正只读诊断按实际对象名称核对，保留先前按数组序号配对错误的诊断报告。最后一次 fence 和随后 404 只能证明当时观测，不能证明请求从未发送。

- 原执行及只读回执：超时诊断 (`artifacts/M8/v2-edge-timeout-readonly-diagnosis.json`, not public)，SHA `553bf8a503b9f89dbe99c18c71543faec1885a35f56dae494be9531cf75d4b7d`。
- 修正时序：原对象与时序 (`artifacts/M8/v2-edge-timeout-objects-timing-corrected-readonly.json`, not public)，SHA `9d9946184caab871e3ed0f7e8d962905cdc1cd309c5f9d5edd42e645c1999076`。只读观察不新增身份、配置或 Native 写入。

正在实施三个相互独立的修复：权限版本检查保留当前用户、会话及 IAM 版本核验，但不重复拉取完整授权列表；M8 配置执行单独采用 300 秒有限时间、租约最多 305 秒且受原身份/计划有效期约束、固定边缘等待 310 秒；失败记账仅能记录原执行事实，不取得 Native、重试或恢复能力。普通工单及门户保持 120 秒，Native 调用、分页、条数和字节预算及逐阶段授权不变。旧过期执行只允许原当前身份/会话、完整元组与二次确认后的只记账收口；未证明结果保守标记未决，成功步骤和原工单/Native 回执保持原样。

权限版本查询的 127 项当前源码回归通过；配置预算、当前审批和真实服务装配的 182 项源码回归通过。隔离 PostgreSQL 的新租约预算 6 项与原 32 项回归通过（38/38），验证真实事务、并发单赢家、期限截断与授权拒绝回滚；授权测试端口的模拟性质单独标注。这些源码和隔离数据库结果不代替修复后真实审批、CLI、浏览器与最终秘密扫描，当前 M8 尚未闭环。

失败记账源码已冻结，并通过独立 82 项检查；当前会话下的未决作业投影另有 15 项独立检查。新增的正常产品收口接口要求原操作人、原 SID、当前权限、完整执行元组、已过期租约及 `abandon:<原作业 ID>` 二次确认。收口不调用 Kong、不重试旧步骤；未知 Native 结果保持 `uncertain`，原成功步骤、工单和回执不改写。前端相关 26 项测试与类型检查通过，详细中文使用手册已补充同一流程。

真实隔离 PostgreSQL 的失败记账接续为 **40/40**：31 项基础检查重跑、9 项新增检查，见 安全摘要 (`artifacts/M8/storage-failure-ledger-continuation-validation-20261011-01.json`, not public)，SHA `6f86c7cbaaaa1d81e0f5ff03566ad8118d0c74fb70316082ce400abcc649ab58`。真实非 owner 角色、AuthorizationService、AuditService/outbox 和本地执行上下文验证了完整元组 CAS、并发单赢家、审计失败整笔回滚、原 SID/当前权限/epoch 校验和历史成功记录保持。Root Access 的私有句柄与历史 17 步为明确标注的合成 SQL 夹具，零 Native/HTTP/生产触碰；不能替代原实际业务闭环。未决执行正确阻止基础快照永久清除，验收保留该引用，不将历史未决改为失败以绕过约束。

收口页面与后端合并后的全量源码检查为 **5,832/5,832，740 个套件，零失败、零跳过**，见 `root-whole-source-bounded-failure-ledger-unit.json`，SHA `96d1cbe6303508fdcf26b5f21a32d3b97764ff7a779b9b12b10e7f50823c7588`。三个应用类型检查、API/Web 构建和差异检查通过。统一源码与编译产物冻结为 `root-bounded-failure-ledger-fix-freeze.json`，SHA `68083a8d6247222d28046cb3d5188a06a1e34a90d122cf53158a0b11ca9ec01f`：222 份 API JS 相对上次部署有 11 份变化、3 份新增、208 份保持，Web 为 `index-K5Ciobne.js`，Portal 和 SQL000–011 保持。实际加载、原过期作业收口、新独立 17 步审批及剩余验收仍分别记录，不把源码冻结算作实际业务通过。

该冻结版本已实际加载，`bounded-failure-ledger-repair-continuity.json` 为 **36/36**，SHA `1520a92168b56b64f97d56a2ec9da5988149456c9e2d9304db86e354492ad423`。原 22 容器、18 个健康服务、SQL000–011 及执行时间、原环境/账号和十二类加密监控材料保持。222 份 API JS 实际挂载精确，Web 三个文件均返回 200 且摘要一致，Portal 不变；原 API 进程重启一次、原 Nginx 通过配置检查并在同 master 下重载一次。固定 310 秒路径及普通 35 秒等待、错误方法 405 和 Portal 404 已实际核对。部署窗口零业务/Auth/Native/CLI、零镜像构建或容器重建，因此它是修复加载证据，仍不是生产镜像或真实审批通过证据。

### 原执行收口与新的审批执行

修复加载后，原账号和原 SID 通过正常产品接口、当前权限与完整执行元组，明确确认原过期作业收口。原 16 个成功步骤及原工单/Native 回执保持；最后一步仍为 `uncertain`，没有重试或改写为成功。收口请求 `e56f55fd-09ab-4b6d-9387-9a0feaa7debc` 的单条 201 审计单列为失败记账写入，不计入 Native 成功数。

另建的 17-Service 变更由另一位当前审批人批准，实际执行完成全部 17 步，并按当前字段核验终态。新作业 `6eb44a77-3447-42fe-b54f-7c42b3419075`、工作流 `91f7b7d6-71ab-41b6-b87b-f8b9918a1237` 与旧失败执行相互独立；元数据审批也实际通过。报告 真实收口及新审批结果 (`artifacts/M8/security-live-expired-execution-recovery.json`, not public) 为 **1,698 通过、零失败**，SHA `8bb237ab057b1cf90efcdbab589c8624a972d050fcca5dfd6c3ab9025e069d69`。该报告尚不包含最终 CLI、RBAC、浏览器、审计清理及秘密扫描。

### 固定 decK 工具兼容修复

随后固定 decK 1.1.0 的第一次真实离线 `validate` 返回 exit 1。原结果 验收尾部失败 (`artifacts/M8/security-live-final.json`, not public) 为 **1,711 通过、1 失败**，SHA `44b215d5189c9742e6d4b7bea2c4d0dfe5bee340c6c16dd8a68b07bc4c510456`，保留原已知执行，不重复原 CLI intent。独立离线只读诊断使用原 YAML、禁用网络，确认其旧 schema 不接受合法的 `upstreams[0].healthchecks.passive.type`；见 工具诊断 (`artifacts/M8/deck-validate-offline-readonly-diagnosis.json`, not public)，SHA `7e775841a348104507fc063e18ec0732d601d683ef45987658b0e335aa4874da`。原第一次 stderr 未保存，诊断只证明新独立诊断的具体错误，不伪称保留了原错误文本。

固定工具改用官方 decK **1.2.4 / 8e68931**，继续使用 `_format_version: "1.1"`，保留完整健康检查和六类凭证。官方归档/二进制摘要已核验，见 公共工具来源 (`artifacts/M8/deck124-public-tool-download.json`, not public)。BFF 对该 SDK 可选的精确 `GET /mtls-auths` 探测，在当前请求和响应权限校验之间本地返回 404；不向 Kong 发出企业端点请求，也不开放该实体 CRUD。非法方法、路径、查询、正文及撤权均拒绝。

相关真实 CLI 对合成 BFF 的源码回归 **42/42**，阶段工具计划 **7/7**，当前全量源码 **5,838/5,838、740 套件、零跳过**。API 类型检查、构建和差异检查通过。统一冻结 工具兼容修复 (`artifacts/M8/root-deck124-compatibility-fix-freeze.json`, not public)，SHA `683def101b95a8d874a415d12586a9d1a1a14b613d7f046381bc7acfe878797d`，222 份编译 JS 仅两份变化，其余 220 份、Web/Portal、边缘配置与 SQL000–011 保持。固定新镜像及真实 BFF diff/sync 仍须分别验收，当前 M8 整体验收尚未通过。

工具适配 API 已窄重启加载，实际连续性 (`artifacts/M8/deck124-api-repair-continuity.json`, not public) **36/36**，SHA `8569de0c340abf808ae73d7378de52055d9e4a1ca1a906943d148a62d1e66f99`。222 份编译文件与冻结精确对应；原 22 个容器、18 个健康服务、Web 三个实际 200 响应摘要、Portal、边缘配置、SQL 及受保护材料保持。部署阶段零业务、Auth、Native、CLI、迁移、镜像构建和容器重建。随后单独进行固定工具镜像构建，不能把 API 加载证据当作 CLI 或生产镜像通过。

新固定镜像 `sha256:f9502473fd3c3fbd9f93535df86897fcaafe05c0a2d8e3def142b53a7b9df959` 已完成含非空健康检查字段及六类凭证的完整合成图离线校验。UID1000、只读、禁网、noexec、权限及工具来源检查通过，保护连续性 **35/35**；见 固定镜像结果 (`artifacts/M8/deck124-fixed-runner-runtime-ready.json`, not public)，SHA `971658833a44e250a03b9cd9f996d254cdae812e348c1d40df94be743da7dc73`。包装脚本前次未附加 stdin 的已知 pre-CLI 失败原样保留，新独立校验没有重建或重启。实际 BFF diff/sync 仍待原验收窗口接续。

实际原捕获已按精确非 owner 只读元组证明自然过期，随后创建的新独立捕获 `0d420e8a-2dc8-44db-ae9c-eecf282700ac` 成功。固定 1.2.4 对原完整 YAML 的新独立 `validate` 实际 exit 0、stderr 0，健康检查和六类凭证没有删减。专用只读会话登记成功，首次在线 `diff` 在 BFF 读取阶段 exit 1，尚未提交 import/apply/sync，也没有新增 Native 写入；新尾部报告 (`artifacts/M8/security-live-deck124-compatibility.json`, not public) 当前为 **1,745 通过、1 失败**，SHA `498e34f2e222e898b74f5ececbd433fc31407c9e122ffc71a66f1d8a2e5e186a`。原 136 个 HTTP 包结果已知、未知为零，旧 133 包及旧 CLI 失败保持。原 diff stderr 仅安全字节数 71 被保留，不能伪称拥有原错误全文；新的独立只读诊断将单独记录具体原因。当前 M8 仍未闭环。

## decK 16 类并发读取的事务连接修复

实际只读诊断根路径返回 1.5.1，但集合读取出现混合 200/503，原失败报告不覆盖。真实隔离 PostgreSQL 在修复前复现 16 次请求中 7 次连接获取超时；显式事务连接复用后 16/16 成功，用时 665 ms，当前角色撤销和原 SID 吊销仍拒绝旧授权。相关单测 89/89、全量源码 5,890/5,890、749 套件、零跳过。实际 API 重载连续性 36/36 通过，前端、门户、SQL 与固定工具镜像保留。标准地址 diff/sync 及最终 UI/审计/安全清理尚未通过时，M8 不计为完成。详细原始报告与 SHA 见 [并发读取验收记录](m8-deck-concurrent-read-verification.md)。

### 标准 decK diff 与可选空字段回归

连接池修复后，标准 BFF 地址上的真实 decK 1.2.4 `diff` exit 0。后续 merge import 预览出现额外 Upstream 修改，单步断言停止执行，sync 尚未发送。独立只读诊断确认导出省略的 `healthchecks.active.https_sni: null` 被导入识别为删除。已修复 schema-record merge，并通过 243 项相关源码测试；实际加载、独立预览与 sync 待完成，原失败报告保留。完整证据与冻结摘要见 [并发读取及导入验证](m8-deck-concurrent-read-verification.md)。
