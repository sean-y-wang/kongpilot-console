# KongPilot M11 后续研发与验收进展 · 2026-10-15

> 最新全量目标、卡点与后续计划见 [2026-10-20 项目检查点](2026-10-20-project-checkpoint.md)。本文各“当前”状态仅对应原记录时点。

最新门户闭环进展见 [2026-10-20 专项记录](2026-10-20-m11-portal-closure.md)。下文保留各历史采样时点，不以旧状态替代最新候选验收结论。

本记录承接 [2026-10-14 开发检查点](2026-10-14-m11-checkpoint.md)，保留此前提交、失败和未决事实。用户可见日期按 Asia/Shanghai。**M11 整体验收、正式生产发布及商用准入尚未通过**；本轮源码专项、隔离环境运行和最终发布验收分别记录。

- 产品：KongPilot / 〔former working name〕 - Kong 管理平台；页面显示 v1.0，正式发布版本与标签仍待最终验收后统一。
- 仓库：<https://github.com/sean-y-wang/kongpilot-console>。本轮研发检查点d3e1d405已于20:36 UTC推送，远端同SHA；不是GA发布，后续未提交字节不属于该检查点。
- M0–M10 已有的技术阶段证据保持原范围；本轮不能用旧全测、旧镜像、旧浏览器截图或历史子集替代整合版验证。
- 平台继续仅通过 Kong 1.5.x Admin API 管理授权配置，不修改 Kong 源码或镜像，不将控制台后端连接到 Kong 数据库。

## 当前真实状态摘要

| 范围 | 当前状态 |
| --- | --- |
| 正在运行的验收 API | a9471b00（SQL039拒绝回执与绑定244），418个API输入/40迁移，同一自有容器于22:13:33 UTC启动、ready200；实际runtime NOSU及新表仅SELECT/INSERT已核验。仍不包含Service完整destination修复，不是生产发布 |
| 自然配置发布 | 652新短材料Service日程单个原claim后，日程/工单及内外执行和当前步骤一致uncertain，KONG_EXECUTION_CONTEXT_EXPIRED；mutation failed、remoteStarted=true/completed=false，回读5非4。真实internal-read/authorization frame 5000ms到期/逾期1ms，精确调用点未确认。原期限不续、无重放，未取得KnownNotSent证书，正向apply未通过 |
| 耐久配置材料与页面 | 新Wf8393f4e已于21:44:52 UTC真实提交，新Pcbd4422c材料期限22:44:45，旧preview期限21:58:43保持；截至22:00只读浏览器，原工单仍pending、未审批/排程激活。原键receipt/newP matcher通过，只读浏览器v2的7项/3截图通过；首轮connection-refused保留。尚不证明长审批后执行或自然发布成功 |
| 门户自然发证 | 3dd8原case预检local4/5失败及pending凭证保留。计数修复已进入828及后续652；修复后全新门户发证尚未验证，不由旧Source全量推导完成 |
| Promote目标准备 | 双来源组合支持已随828及后续652部署，828轮全量收集相关专项；当前候选及修复后全新自然发布仍未整体验收。耐久新域仍不支持Promote；首轮适配器及中断超时原失败保留，共享PG11/存储及角色隔离限制保持 |
| 标准恢复 | 同实例新空库标准pg_restore及完整后验分项通过；恢复API/worker、异机DR/RPO/RTO仍待。配置unknown影响面尚无完整产品安全resolution流程，只读reconcile不释放保留，列为生产恢复待办 |
| 审计链当前核验 | 22:20:47 UTC，以当前runtime角色只读核验1,514行/3链及全部JSON patch正确；这仍不等同于预期关键写入100%覆盖或后续写入验收 |
| 业务安全排程 | 取消、停机跨原窗口自然expired、全新影响面重叠409已有实际HTTP与独立SQL分项证据；执行中撤权/窗口及故障路径仍待 |
| 最新完整源码/构建门禁 | 最后完整门禁仅覆盖旧828：1,813固定输入、616文件14,461/14,461及三端类型/隔离构建0，摘要27533fb9不变。681b与其后工作树尚未新全量；CurrentBefore521项、配置工单Web121项、耐久域461项及各自类型/隔离构建为专项，不累加、不替代当前全量或业务执行验收 |
| 平台生产依赖公告检查 | 当前平台lock/manifests的npm生产依赖审计退出0、各级公告数均0；不包含Kong、基础OS、运行配置或应用授权逻辑 |
| 秘密扫描 | 828检查点434份保留秘密材料分4批执行原扫描器，全部退出0、零发现，增量关闭已完成；覆盖该轮三端产物、17份日志及1248条审计固定快照，不覆盖后续681b等新增字节/材料。API Key材料0、finalCredentialComplete=false |
| M11及商用 | 仍未整体验收；源码专项、重启即时观察和阶段激活不替代实际自然完成 |

## 1. 环境连续性与新验收 run

旧 RAM 验收工具容器实际退出，退出码 255、`oomKilled=true`；其内存后端 Docker 数据及原私密账本目录未保留。此前公开报告继续保留。丢失后的原会话、审批、claim 和未知请求不能由新材料重建，不能据此宣称原定时请求成功或零发送，也不能重放旧 occurrence。

已建立全新 `20261015-persistent` 验收 run：私密材料改为工作区磁盘目录并限制权限，平台 PostgreSQL 与隔离网关数据库使用各自命名卷，Redis 使用 AOF 命名卷。只处理自有验收项目，未采用旧账本、SID 或批准事实。新 run 使用新账号、会话、原请求键和独立夹具；新结果不改写旧结果。

新环境仍是隔离验收环境，使用验收配置；`compose.release-persistent.yml` 不能作为正式生产配置。命名卷、备份命令或健康状态不等于主机重启、异机恢复与生产 RPO/RTO 已验收。原启动过程中出现的失败报告均保留，不覆盖为最终成功。

证据：环境丢失观察 (`artifacts/M11/environment-loss-observation-20261015-original.json`, not public)、新 run 准备 (`artifacts/M11/runs/20261015-persistent/preparation.json`, not public)、原初始启动失败 (`artifacts/M11/runs/20261015-persistent/baseline-persistent-startup.json`, not public)、后续编译迁移挂载准备 (`artifacts/M11/runs/20261015-persistent/serial-compiled-migration-mountpoint-original.json`, not public)。

## 2. 已部署的整合 API 候选

本节保留9236候选的历史采集事实，652465e6/SQL038的历史部署见第22节，最新a9471b00/SQL039见第23节。

| 项目 | 已落盘事实 |
| --- | --- |
| API 冻结输入 | 410 个（370个TS、38个SQL及package/tsconfig）；不是整仓或三端总文件数 |
| API Source SHA256 | `9236ddf0adf4e35e565efcaa1dbadb103b4a10176ce09dd53929f40679c4d09b` |
| SQL | SQL000–037，共38条迁移；037追加固定四个CHECK wrapper搜索路径，历史迁移摘要保持 |
| 编译 | 本冻结候选隔离编译退出 0 |
| 部署 | 上海23:31:22启动同一自有API容器、ready200，38条SQL摘要匹配；原数据/密钥/会话保留，不加入Kong数据库网络 |
| 运行边界 | 停机跨原窗口并升级507→9236后，原expiry日程自然expired且claim/执行/mutation均0；未修补旧claim，新正向自然完成/性能仍待验 |

此前已运行 404 文件/36 迁移的 `0facd598d2794eb2a0ec3807ade094435fb92a03a54f0f94ec8af5169d460189`，之后以追加 SQL036 修复基线别名，形成 405 文件/37 迁移的 `211ea998f65ab6ab5f887550533f3329d0c87e6324a9358a31b412d8e7719fe7` 候选。随后依次部署健康 data 候选 `8d4a16553de44e310e8e39cea39630006437894eb118cdb3d128de3c2996eaa3`、Metrics CREATE 候选 `81eb5e863509127e864008843cfd557dbd94feb0ae06ffa219115456b1cd3108`，再部署政策派生校验候选 `8f44a2b149d6e819cee4dc558291582178b35e8a16021384156641e439def1d9`。其备份观察器曾在API停止前触发默认缓冲上限，纠正后完成部署，没有重放业务变更。随后单次当前Authority检查优化与SQL037合并为cde32候选并正式迁移。fresh grants原hash稳定排序helper与四处调用点247项源码检查通过后，曾部署407源文件的f591ea候选；随后冻结并部署410源文件的76ce04 ledger整合候选；第五轮暴露pre-child真实边界后，以原76ce04加精确一项修复组成507cd795候选。随后整合safe receipt、pre-Namespace facts去重复、Factory immutable纯计算memo及第五处CandidateRead排序，形成当前9236ddf0候选，410个API输入/38迁移、隔离编译0、输入前后稳定。SQL037后没有新控制台迁移；Kong源码/镜像及既有网关业务配置不因API升级改变。目标网关的新数据库/bootstrap由隔离验收运维另行记录。后续源码专项不等于正向自然功能或性能验收，旧候选及原失败保留。

证据：当前9236冻结 (`artifacts/M11/runs/20261015-persistent/combined-receipt-facts-memo-sort-candidate-source-freeze-original.json`, not public)、实际启动及跨窗口到期SQL (`artifacts/M11/runs/20261015-persistent/combined-candidate-runtime-and-original-expiry-restart-original.json`, not public)；前次 507cd795冻结 (`artifacts/M11/runs/20261015-persistent/initialization-boundary-candidate-source-freeze-original.json`, not public)、自有API重建及目标Admin接入 (`artifacts/M11/runs/20261015-persistent/initialization-boundary-target-admin-runtime-deployment-original.json`, not public)；前次 76ce04冻结 (`artifacts/M11/runs/20261015-persistent/integrated-ledger-candidate-source-freeze-original.json`, not public)、纠正观察器后的真实部署 (`artifacts/M11/runs/20261015-persistent/integrated-ledger-runtime-deployment-corrected-observer-original.json`, not public)、停止API前的原观察器失败 (`artifacts/M11/runs/20261015-persistent/integrated-ledger-runtime-deployment-original.json`, not public)；前次 f591ea冻结 (`artifacts/M11/runs/20261015-persistent/integrated-fresh-grant-sort-source-freeze-original.json`, not public)、实际部署 (`artifacts/M11/runs/20261015-persistent/integrated-fresh-grant-sort-runtime-deployment-original.json`, not public)、四处fresh排序247项源码检查 (`artifacts/M11/m11-fresh-grant-fingerprint-sort-source-only-20261015-original.json`, not public)；前次 cde32/SQL037冻结 (`artifacts/M11/runs/20261015-persistent/integrated-single-authority-037-source-freeze-original.json`, not public)、真实回滚/正式迁移/部署 (`artifacts/M11/runs/20261015-persistent/integrated-single-authority-037-runtime-deployment-original.json`, not public)；前次 政策派生候选冻结 (`artifacts/M11/runs/20261015-persistent/integrated-policy-derived-source-freeze-original.json`, not public)、缓冲修正后的真实部署 (`artifacts/M11/runs/20261015-persistent/integrated-policy-derived-runtime-deployment-after-buffer-correction-original.json`, not public)；前次 健康 data 候选冻结 (`artifacts/M11/runs/20261015-persistent/integrated-health-data-source-freeze-original.json`, not public)、编译 (`artifacts/M11/runs/20261015-persistent/integrated-health-data-compile-original.json`, not public)、实际部署 (`artifacts/M11/runs/20261015-persistent/integrated-health-data-runtime-deployment-original.json`, not public)；前次 SQL036 冻结 (`artifacts/M11/runs/20261015-persistent/integrated-036-source-freeze-original.json`, not public)、SQL036 部署 (`artifacts/M11/runs/20261015-persistent/integrated036-runtime-deployment-original.json`, not public)、404 文件冻结 (`artifacts/M11/runs/20261015-persistent/integrated-035-source-freeze-original.json`, not public) 与 035 部署 (`artifacts/M11/runs/20261015-persistent/integrated035-runtime-deployment-original.json`, not public) 保留。

## 3. 真实数据库与控制面工单分项

SQL035 在控制台 PostgreSQL 中完成真实事务回滚试验：延迟后的原作者插入可接受；使用另一真实审批人会话、无对应备注 revision、发行时间超前 2 秒均被拒绝；真实运行角色的 UPDATE/DELETE/TRUNCATE 被拒绝。试验已回滚，原生发送为 0。该试验验证数据库约束及最小权限，不能当作真实工单执行证明。

新 run 的工作区创建控制面工单已完成真实 prepare → submit → 独立审批 → execute，执行成功；该链不发送 Kong 原生变更。完成后读取终态时，一次列表 GET 使用不支持的 view，原 400 及失败报告保留；改为当前支持的 `submitted` 查询后只读观察成功，没有重发创建或执行请求。

独立只读 SQL 进一步证明同一工作区创建工单/执行/步骤均 succeeded，审计关联原作者及真实会话；IAM epoch 由 565 到 833、精确增加 268，实际新建 3 个内置角色、265 条权限，用户/团队绑定为 0。两次前置 SQL 检查器使用错误表名/查询的原失败保留，之后按实际表查询通过；它们不是重执行工作区创建。

以上证明新工作区创建分项，不能扩展为集群地址/模式变更、停用/归档/恢复、目标工作区专有权限、IAM 全操作或所有控制面 UI 已通过。数据源创建另有下节独立证明。整个 run 有前置 Service 夹具原生创建，不能把控制面这张工单的 Native0 外推为全 run 从未写入。

另一次真实 Upstream 创建在恢复基线处失败，独立核验尚无原生发送。原因是 SQL031 重引入了旧函数中的 `o`/`old` 别名问题。新增 SQL036 仅修正两处别名、保留函数 OID 与全部原身份/范围约束；真实回滚试验证明合法缺失基线可接受、错误原生身份仍拒绝，回滚后原函数恢复。正式应用 SQL036 后，新独立 Upstream 和 Target 工单分别收到真实 201，不重放原失败。

证据：SQL035 回滚与运行角色试验 (`artifacts/M11/runs/20261015-persistent/035-console-only-rollback-trial-original.json`, not public)、控制面准备 (`artifacts/M11/runs/20261015-persistent/control-prepare/native-verification.json`, not public)、提交 (`artifacts/M11/runs/20261015-persistent/control-submit/native-verification.json`, not public)、独立审批 (`artifacts/M11/runs/20261015-persistent/control-vote/native-verification.json`, not public)、执行 (`artifacts/M11/runs/20261015-persistent/control-execute/native-verification.json`, not public)、原终态查询失败 (`artifacts/M11/runs/20261015-persistent/control-terminal-observe/native-verification.json`, not public)、纠正查询后的只读观察 (`artifacts/M11/runs/20261015-persistent/control-terminal-observe-corrected-query/native-verification.json`, not public)、工作区独立实际表 SQL 核验 (`artifacts/M11/runs/20261015-persistent/integrated035-runtime-control-independent-sql-actual-table-query.json`, not public)、原 SQL 查询失败 (`artifacts/M11/runs/20261015-persistent/integrated035-runtime-control-independent-sql-original.json`, not public)、第二次查询失败 (`artifacts/M11/runs/20261015-persistent/integrated035-runtime-control-independent-sql-corrected-query.json`, not public)、原 Upstream 失败且未发送核验 (`artifacts/M11/runs/20261015-persistent/target-upstream-original-failed-no-native-sql-proof.json`, not public)、SQL036 回滚试验 (`artifacts/M11/runs/20261015-persistent/036-console-only-rollback-trial-original.json`, not public)、新 Upstream 成功 (`artifacts/M11/runs/20261015-persistent/target-upstream-after036-native/native-verification.json`, not public)、新 Target 成功 (`artifacts/M11/runs/20261015-persistent/target-create-native/native-verification.json`, not public)。

## 4. 实体说明、Target、监控与页面分项

实体说明 set、remove、restore 已分别完成真实准备、提交、独立审批、执行及终态回执。独立 SQL 证明三张工单/执行/步骤均 succeeded，同一原作者真实会话与创建/删除/恢复成功审计精确关联；revision 依次为 1、2、3，最终说明为 active。三个说明工单的原生写入均为 0；run 内已有的前置 Service 夹具写入单独保留。运行角色对三张说明事实表及审计表仍只追加，不授予 UPDATE/DELETE/TRUNCATE。说明三操作后端链不再列为待办；后续说明更新的双身份真实浏览器写入也已通过，仍不扩展为所有类型/页面已验收。

证据：说明 set 执行 (`artifacts/M11/runs/20261015-persistent/annotation-set-execute/native-verification.json`, not public)、remove 执行 (`artifacts/M11/runs/20261015-persistent/annotation-remove-execute/native-verification.json`, not public)、restore 执行 (`artifacts/M11/runs/20261015-persistent/annotation-restore-execute/native-verification.json`, not public)、三操作独立 SQL/审计/会话及最小权限核验 (`artifacts/M11/runs/20261015-persistent/annotation-three-operation-independent-sql-original.json`, not public)。

### Target 自然定时与健康观察边界

新的 Target 权重 100→80 定时工单完成审批、激活后，由 API 自然 worker 执行；只有一个真实 claim，执行成功并取得新有效 UUID，未调用手动 tick。该证明覆盖本次权重定时成功路径，不扩大为定时健康置位、所有适配器、多副本 HA 或发送中故障恢复通过。

原手动置为不健康工单因真实 `/health` 诊断 `data` 被拒绝而失败，错误 `TARGET_HEALTH_NATIVE_ROW_INVALID`、基线和包清单为空；原失败不重发。8d4a 候选部署后，另行提交和审批两张新工单，先 unhealthy 再 healthy，均取得真实 Native 204 空体。

独立 SQL 证明这两张健康工单/执行/步骤均 succeeded，各只有一次实际尝试和一个成功审计，真实 HTTP 来源绑定原提交会话；基线记录当前节点与实际先前健康状态，`overrideRecoverable=false`。同份报告还确认前述权重日程 succeeded、claim 恰为 1、来源为 scheduled-entity 且 SID 为 NULL、新权重 Native201 与新有效 UUID 一致。首次独立 SQL 查询别名错误报告保留，纠正查询不重执行健康或权重。

这证明本轮当前节点的两次手动健康操作，不扩展为全节点健康、自动回滚、定时健康或全部故障路径。

证据：自然定时激活 (`artifacts/M11/runs/20261015-persistent/target-natural-weight-schedule-activation/native-verification.json`, not public)、自然执行终态 (`artifacts/M11/runs/20261015-persistent/target-natural-weight-terminal-original/native-verification.json`, not public)、真实健康行拒绝诊断 (`artifacts/M11/runs/20261015-persistent/target-health-native-shape-failure-readonly-original.json`, not public)、新 unhealthy 成功 (`artifacts/M11/runs/20261015-persistent/target-health-unhealthy-after-data-native/native-verification.json`, not public)、新 healthy 成功 (`artifacts/M11/runs/20261015-persistent/target-health-healthy-after-data-native/native-verification.json`, not public)、自然定时与两次健康独立 SQL (`artifacts/M11/runs/20261015-persistent/target-natural-and-health-independent-sql-corrected-alias.json`, not public)、原 SQL 别名查询失败 (`artifacts/M11/runs/20261015-persistent/target-natural-and-health-independent-sql-original.json`, not public)。

### Prometheus 数据源与容量处理

Prometheus 数据源创建完成真实控制面 prepare、submit、独立 vote、execute 和连通测试；之后完成监控 CREATE 新工单、真实抓取和本次工作区 QPS 原始数值对照，具体范围见下节。数据源创建本身仍不能代替插件或指标证明。

由于本轮临时 Prometheus 容器在 VFS 下占用空间，主盘可用空间降至 63,832,064 字节，只停止并移除本 run 的该临时容器后恢复至 674,111,488 字节；命名卷、数据库和私密证据未删除。后续健康候选部署已另行启动小运行时承载的固定 Prometheus 二进制及私有桥接；容量回收报告只描述先前临时容器，不能据此判断新服务的指标正确。后续另取得真实抓取与数值证据；不能用此次容量回收推断生产容量或持续运行 SLA。

证据：数据源准备 (`artifacts/M11/runs/20261015-persistent/prometheus-source-prepare/native-verification.json`, not public)、提交 (`artifacts/M11/runs/20261015-persistent/prometheus-source-submit/native-verification.json`, not public)、独立审批 (`artifacts/M11/runs/20261015-persistent/prometheus-source-vote/native-verification.json`, not public)、执行 (`artifacts/M11/runs/20261015-persistent/prometheus-source-execute/native-verification.json`, not public)、连通测试 (`artifacts/M11/runs/20261015-persistent/prometheus-source-test/native-verification.json`, not public)、限定临时容器空间回收 (`artifacts/M11/runs/20261015-persistent/temporary-monitoring-container-space-recovery-original.json`, not public)。

### IAM 角色创建与监控设置修复后的实际结果

新的 IAM 角色创建完成真实准备、提交、独立审批与执行，工单 `2035ad69-e37b-4e9a-822b-041826471069` succeeded，Native0。该结果只覆盖本次角色创建，不代替角色权限替换、成员/绑定、权限自变更或所有 UI 写入验收。

监控设置工单 `fdffcee8-58bb-4660-bb58-e97f086d40da` 已准备、提交和批准，但执行返回 403 `APPROVED_MUTATION_MISMATCH`。独立只读 SQL 证明原工作流及执行 failed，插件步骤 failed、设置步骤 pending、mutations=0、nativeAttempts=0。因此此张原请求没有发送插件变更；它不能被登记数据源/连通测试通过或已经完成 enrollment 掩盖。原失败和零发送证明继续保留，不重发原工单。随后窄修复规范化 Metrics 原生插件 CREATE 的逻辑身份，334 项相关源码检查通过；运行编译依赖/实际 dist 对照纠正后，另行新建并审批工单 `e2ca9c65-1a52-436b-ae96-152cf3d15258`，实际执行和原回执均成功。独立 SQL 证明 native/metadata 两步骤及原生 mutation succeeded、同一作者真实会话、设置 revision2→3、凭证 generation1；最初使用错误 schema 列的只读观察失败保留，不重执行新工单。

证据：IAM 准备 (`artifacts/M11/runs/20261015-persistent/iam-role-prepare/native-verification.json`, not public)、提交 (`artifacts/M11/runs/20261015-persistent/iam-role-submit/native-verification.json`, not public)、独立审批 (`artifacts/M11/runs/20261015-persistent/iam-role-vote/native-verification.json`, not public)、执行 (`artifacts/M11/runs/20261015-persistent/iam-role-execute/native-verification.json`, not public)、监控原执行失败 (`artifacts/M11/runs/20261015-persistent/metrics-native-setup-execute/native-verification.json`, not public)、原监控失败零发送独立 SQL (`artifacts/M11/runs/20261015-persistent/metrics-original-failed-no-native-readonly-sql-original.json`, not public)、Metrics CREATE 334 项源码检查 (`artifacts/M11/metrics-native-create-logical-source-checks-20261015.json`, not public)、运行编译/dist 纠正证明 (`artifacts/M11/runs/20261015-persistent/integrated-metrics-create-compiled-runtime-correction-original.json`, not public)、新工单执行 (`artifacts/M11/runs/20261015-persistent/metrics-create-fix-execute/native-verification.json`, not public)、原回执 (`artifacts/M11/runs/20261015-persistent/metrics-create-fix-receipt/native-verification.json`, not public)、纠正 schema 后的独立 SQL (`artifacts/M11/runs/20261015-persistent/metrics-create-fix-independent-sql-corrected-schema-original.json`, not public)、原 schema 列观察失败 (`artifacts/M11/runs/20261015-persistent/metrics-create-fix-independent-sql-original.json`, not public)。

随后真实 Prometheus 抓取 `up=1`；75 次受控业务代理请求均返回200，本阶段不发送 Admin 原生写入。首次流量检查器误取实体 DTO 导致失败，纠正后重新独立运行并保留原失败。按同一工作区、当前授权 epoch、同一五分钟窗口、15秒步长和60秒 rate 窗口，BFF 与 Prometheus 原始查询取得12个非空且正QPS点，逐点一致，卡片与原始序列一致。

这只验收本次工作区原生 QPS 数值子集；Consumer collector 仍显示不可用原因，不把12点对照扩大为所有监控维度、历史范围、延迟分位数、Loki 或容量验收。

证据：真实抓取 up1 (`artifacts/M11/runs/20261015-persistent/metrics-prometheus-scrape-readonly-original.json`, not public)、原流量 DTO 失败 (`artifacts/M11/runs/20261015-persistent/metrics-native-traffic/verification.json`, not public)、75 次业务200 (`artifacts/M11/runs/20261015-persistent/metrics-native-traffic-entity-dto/verification.json`, not public)、12 点 QPS 数值逐点对照 (`artifacts/M11/runs/20261015-persistent/metrics-native-numeric-compare/verification.json`, not public)。

### 真实浏览器只读与说明写入分项

真实后端浏览器检查 10 项通过，保存 3 张截图，覆盖已完成说明工单、恢复后说明、用户菜单手册/v1.0、站内手册与手机无横向溢出；业务写入 0、Admin 直连 0、页面未处理错误 0。检查包含一次只读实体能力查询 POST，它不属于业务写入，不能把方法为 POST 一概视作执行变更。

最初脚本标签断言失败、随后误拦只读能力 POST 的夹具失败分别保留；修正检查器后的通过报告不覆盖原失败。这些均为只读页面证明，不代表浏览器已完成创建、投票、执行、回收或定时激活写入。

证据：原标签检查失败 (`artifacts/M11/runs/20261015-persistent/browser-metadata-original/verification.json`, not public)、原只读能力误拦失败 (`artifacts/M11/runs/20261015-persistent/browser-metadata-corrected-label/verification.json`, not public)、真实只读浏览器通过 (`artifacts/M11/runs/20261015-persistent/browser-metadata-capability-read/verification.json`, not public)。

原浏览器说明写入链曾等待「提交审批」超时，failed、业务 POST0/Admin0。查明 React18 StrictMode 的 setup→cleanup→setup 重放使五处 effect 的 active 标记仅置 false、未在 setup 恢复。对说明、Target、Consumer 凭证三个组件仅补 setup 的 active=true，保留真实卸载时 active=false、表单清理及全部范围/权限栅栏；没有关闭 StrictMode。

修复后离线真实浏览器专项15项通过，包含在相关280项源码回归中，计数不相加。另用真实后端、真实原作者与独立审批人的浏览器完成新工单 `3389cde6-ff34-4d6e-b2ad-2cb09f02544e`：从实体页准备/提交、独立审批、原会话执行、详情回读，8项检查通过，4次预期业务写入各一次、Admin0、无额外写入/页面错误。原超时不被覆盖；这证明说明更新的本次双身份UI链，不代表所有Target/凭证或所有说明动作浏览器链均通过。

证据：原浏览器说明写入失败 (`artifacts/M11/runs/20261015-persistent/browser-annotation-write-original/verification.json`, not public)、StrictMode 5处effect/15项专项/相关280项 (`artifacts/M11/m11-strict-lifecycle-source-checks-20261015-original.json`, not public)、真实双身份浏览器8项/4次写入 (`artifacts/M11/runs/20261015-persistent/browser-annotation-write-after-lifecycle-fix/verification.json`, not public)。

### 配置业务自然排程与政策派生校验

第一轮配置自然排程工单 `bef24959-d4a9-4c93-a5db-0f2254a53480` 已终态 failed，精确原因为 `WORKFLOW_SCHEDULE_CONFIGURATION_FULL_APPROVAL_REQUIRED`。原检查器硬编码“三票且跨阶段全不同”，与该工单真实 format2 政策不符；早期 active 观察失败及原终态均保留。后续独立只读 SQL 已证明这一轮只有一个 claim，工单/执行/步骤/日程均 failed，childExecutions=0、childOrigins=0、mutations=0，不以准备或激活成功计为功能验收。

窄修复改为从原批准政策与当前完整批准集派生要求，保留同阶段用户/批准唯一性、真实原始命名空间、SQL/HMAC/claim/材料与当前身份栅栏，131项源码检查通过并部署8f44。之后新工单 `8349a1ea-a115-480a-a177-102c52fb280e`、日程 `b338c761-852d-4adf-9e0c-4ddbf20f718b` 也已终态 failed，原因 `WORKFLOW_SCHEDULE_NAMESPACE_EXPIRED`。同份独立 SQL 证明这次也只有一个 claim、childExecutions=0、childOrigins=0、mutations=0，快照ready不代表嵌套业务执行成功。**两次配置自然排程均不计功能通过**，没有手动tick或旧请求重放。

随后仅在三个生产源码文件中优化每个业务检查点的完整当前 Authority 检查，避免同一检查点重复放大；保留原私有句柄、完整材料绑定、当前权限/Redis栅栏、后续检查点重新核验，不延长任何原窗口或期限。相关205项源码检查通过（包含34项新用例），API类型检查0；变化晚于13,051项统一冻结，现已随cde32候选部署，但自然完成和性能验收仍待，不能断言已经消除NamespaceExpired。

第三轮工单 `7a981b68-f81e-4aec-ae98-a17e407ef6ed`、日程 `81cca81b-eaa7-419f-a725-05bba2487fd9` 现已真实终态failed，错误 `KONG_EXECUTION_CONTEXT_EXPIRED`。独立SQL证明唯一claim `cb99def0-5eaa-4a79-8bff-1380168e4f97` 的原期限为上海时间21:34:17.386→21:39:17.386、严格5分钟；执行 `bd5c7943-d0df-40d4-874b-58f5792239fb` 快照ready、metadata步骤failed，childExecutions=0、childOrigins=0、mutations=0，原批准1票、outcome为original-execution failed。无手动tick或旧请求重放。

该报告的passed仅表示安全失败事实观察通过，`functionalScheduleAcceptancePassed=false`。**第三次配置自然排程仍不计功能通过**，不能用快照ready或单次Authority源码专项推断性能已达标。

在第三次自然执行期间实际采样8.281523秒、5,669个CPU样本，调用栈定位到fresh grants排序比较器反复对完整行执行canonical JSON/HMAC；Inspector只绑容器loopback，未改原截止时间/业务状态，采样后关闭。随后完成当次fresh读取每行只计算一次原hash再稳定排序，247项源码检查通过，已随f591ea部署。它保留每次SQL读取与完整grants校验，不缓存跨读取结果；第四轮实际仍未在期限内完成，不能据此称性能PASS。

证据：第一轮排程激活 (`artifacts/M11/runs/20261015-persistent/configuration-natural-finish-schedule/configuration-natural-verification.json`, not public)、原早期active观察失败 (`artifacts/M11/runs/20261015-persistent/configuration-natural-observe/configuration-natural-verification.json`, not public)、政策派生131项源码检查 (`artifacts/M11/m11-scheduled-configuration-policy-derived-approval-source-only-20261015-original.json`, not public)、8f44实际部署 (`artifacts/M11/runs/20261015-persistent/integrated-policy-derived-runtime-deployment-after-buffer-correction-original.json`, not public)、第二轮原准备/激活记录 (`artifacts/M11/runs/20261015-persistent/configuration-natural-policy-fixed-prepare/configuration-natural-verification.json`, not public)、两次自然失败独立 SQL (`artifacts/M11/runs/20261015-persistent/configuration-natural-two-failures-independent-sql-original.json`, not public)、后续单次当前 Authority 205项源码专项 (`artifacts/M11/m11-business-single-fresh-authority-source-only-20261015-original.json`, not public)、cde32实际部署 (`artifacts/M11/runs/20261015-persistent/integrated-single-authority-037-runtime-deployment-original.json`, not public)、第三轮原审批/激活阶段 (`artifacts/M11/runs/20261015-persistent/configuration-single-authority-prepare-schedule/configuration-natural-verification.json`, not public)、第三轮安全失败独立SQL (`artifacts/M11/runs/20261015-persistent/configuration-third-failure-independent-sql-original.json`, not public)、原自然执行CPU采样 (`artifacts/M11/runs/20261015-persistent/configuration-third-natural-cpu-sampling-original.json`, not public)、采样调用栈 (`artifacts/M11/runs/20261015-persistent/configuration-third-natural-cpu-caller-stacks-original.json`, not public)、门户真实preflight (`artifacts/M11/runs/20261015-persistent/portal-natural-preflight-original/portal-natural-verification.json`, not public)。

### 第四轮已进入子claim，但自然配置仍未闭合

独立新Service `2bab98b3-8c6c-49fd-86c2-4bd218f504dd` 经新工单 `c268351d-b4e7-4118-897a-5ea32a65acfd` 独立审批/执行、单次Native201创建成功，用于配置自然验证，避免改动门户固定Service指纹。随后第四工单 `792763dc-fdcd-42df-b4c1-a57dd24feb31`、日程 `da599917-886e-4b2f-bfa8-8707f30c7142` 虽已激活，但原claim上海21:49:15.870→21:54:15.870的5分钟到期后，wrapper failed、snapshot ready、错误 `WORKFLOW_SCHEDULE_NAMESPACE_EXPIRED`。

独立只读证据显示日程仍claimed、唯一claim、子执行 `76f678cb-f493-4fc3-b544-676356c0a844` 也仍claimed，childOrigins=1、mutations=0、outcomes=0。实际BFF回读独立Service retries仍5，未达到计划4。报告总体passed=false、observationVerified=true、functionalScheduleAcceptancePassed=false；安全事实得到观察，不表示终态收尾或功能通过。**该子claim和日程尚未闭环，不补旧claim、不借新句柄接管、不重发旧原生请求。**

同五分钟Kong访问窗口中，`/schemas/services` 和 `/services/{id}` GET各158次；窗口还包含采集/后台请求，不能把全部访问都归因该工单。第四轮CPU诊断6.437980秒/4,515样本，其中2,030样本idle约45%；这是单次现场诊断，不是端到端性能或容量验收。

证据：独立Service原生创建 (`artifacts/M11/runs/20261015-persistent/configuration-independent-service-original/native-verification.json`, not public)、第四轮准备/激活 (`artifacts/M11/runs/20261015-persistent/configuration-fresh-grant-sort-prepare-schedule/configuration-natural-verification.json`, not public)、原观察失败 (`artifacts/M11/runs/20261015-persistent/configuration-fresh-grant-sort-observe-original/configuration-natural-verification.json`, not public)、第四轮子claim未闭合独立SQL (`artifacts/M11/runs/20261015-persistent/configuration-fourth-failure-child-claim-readonly-original.json`, not public)、同窗Kong访问计数 (`artifacts/M11/runs/20261015-persistent/configuration-fourth-native-access-counts-original.json`, not public)、第四轮CPU样本 (`artifacts/M11/runs/20261015-persistent/configuration-fourth-natural-cpu-sampling-original.json`, not public)。

### 第五轮新夹具创建成功，自然配置在初始化边界提前失败

全新独立Service3 `eb562717-0621-4885-b540-42b0554270d5` 已经独立原生审批工单创建成功、收到201。随后新自然配置工单 `cbd50b28-f0a0-4ae1-88fc-6c46e9272d79`、日程 `0a1ea9d6-11f2-4078-a5f9-5ca15aae872c` 提前failed，原因CONFIGURATION_SCHEDULE_ORIGINAL_EXECUTION_REQUIRED；这次不是原期限超时。

真实独立SQL保留单claim、snapshot ready、0child、0mutation，及一条original-execution failed outcome。错误来自新初始化helper在子执行创建前就要求generic packet，尚未到子执行或权限期限过期。专门真实access边界Source修复6文件/166项及API类型0，已作为原76ce04加精确一项修复的507cd795候选部署；尚无新自然完成，不能写初始化真实链已闭环。原作者使用原SID读取该日程曾返回403 CONFIGURATION_APPROVED_WRAPPER_INVALID；safe receipt专项5文件204项、API类型/隔离临时构建0后，已整合部署9236。上海23:36:14实际只读GET确认原第五轮日程HTTP200、state=failed、nativeAuthority=false，未更改原状态。报告首个control指针标记notKnownOriginalPointer，不计为另一个已知原case通过。原自然失败与读取403保留，不重放原工单或换句柄补执行。

证据：新Service3原生创建 (`artifacts/M11/runs/20261015-persistent/configuration-ledger-fixed-service-original/native-verification.json`, not public)、第五轮初始化边界失败独立SQL (`artifacts/M11/runs/20261015-persistent/configuration-fifth-init-boundary-failure-independent-sql-original.json`, not public)、原SID终态读取失败 (`artifacts/M11/runs/20261015-persistent/configuration-ledger-fix-observe-original/configuration-natural-verification.json`, not public)、真实access边界Source专项 (`artifacts/M11/m11-configuration-initialization-real-access-source-only-20261015-original.json`, not public)、507cd795冻结 (`artifacts/M11/runs/20261015-persistent/initialization-boundary-candidate-source-freeze-original.json`, not public)、实际重建部署 (`artifacts/M11/runs/20261015-persistent/initialization-boundary-target-admin-runtime-deployment-original.json`, not public)、9236下原第五轮安全读取 (`artifacts/M11/runs/20261015-persistent/safe-original-failed-schedule-readonly-original/safe-receipts-verification.json`, not public)。

### 门户原claim过期仍未闭环，不能用新句柄接管

门户从preflight、settings、policy、publication create/publish、developer register/approve、application、request，到author、独立vote、activate共12个真实阶段均有passed报告。原工单 `f41d7a63-3fdd-44da-bb2a-53e3edf21e4e`、日程 `da60ce1d-fe44-429b-881c-a7a1b80f1e1d` 的计划由v1→v2且保留原期限；原会话与独立审批人分别使用真实身份，没有丢失RAM会话重建。

新增独立只读SQL已确认原claim `8e10be79-9782-4b84-a979-c5eb331c3726` 原期限为上海22:07:11.562→22:12:11.562；至22:25:54观察时已过期，但原工单仍executing、日程claimed，执行 `a7fb3bc6-1f8b-4603-9190-61c7fa6284fb` snapshotready/执行中，首个native步骤running，后续两个native及metadata步骤pending，mutations=0、outcomes=0。

报告passed=false而observationVerified=true，只证明准确观察到未决事实，不是门户发证功能通过。过期、零mutation或runner没有直接调用issue execute，都不证明凭证可用，也不授权用新句柄/SID/预算补旧claim、重试原执行或手工完成。站点public origin仍null、未真实外部联调；不发布“凭证可用”结论。Promote最新拓扑和前置阶段见后节，尚无比较、发布或自然apply结果。

这两个过期claim已在76ce04部署时保留，自有API重启即时及约67秒后的只读状态保持一致，详情见下一节；这不等于旧任务已收口。其后独立门户Service和Route均经独立审批创建201。ledger-fix-20261015 case完成前9阶段，但Root注册目标集群/默认IAM后，冻结permissionVersion变化；author在选择POST前正确拒绝，独立只读证明schedule/execution/operation均0。该报告functional=false、observationVerified=true，只证明发送前拒绝，不证明发证成功；旧case不改PV、不重放。

拓扑完成后又经独立审批创建post-topology全新Service/Route夹具，二者201。post-topology-20261015新case前12阶段已全部真实通过，工单 `c7d3d64d-b76e-4bad-84c1-122da9acfd2b`、日程 `a60ce24b-f9d9-4670-a74d-9e00674875cf`。原claim上海23:00:39.623→23:05:39.623的5分钟耗尽前mutations=0；首Native步骤KONG_EXECUTION_CONTEXT_EXPIRED。原catch保守收尾已在真实运行中生效：工单/执行/日程均uncertain，记录一条original-execution uncertain outcome。它准确保留未知，不证明未发送或发证成功；自然发证仍false，原observe失败报告保留。不能因0mutation将未知写成已知未发证，也不补原claim或延长原期限。

本轮只在容器loopback Inspector采样6.240503秒、4,988个CPU样本，采样后关闭。调用栈为现场性能诊断，没有改变原期限或证明性能/容量通过。

证据：settings (`artifacts/M11/runs/20261015-persistent/portal-natural-settings-original/portal-natural-verification.json`, not public)、policy (`artifacts/M11/runs/20261015-persistent/portal-natural-policy-original/portal-natural-verification.json`, not public)、publication创建 (`artifacts/M11/runs/20261015-persistent/portal-natural-publication-create-original/portal-natural-verification.json`, not public)、publication发布 (`artifacts/M11/runs/20261015-persistent/portal-natural-publication-publish-original/portal-natural-verification.json`, not public)、开发者注册 (`artifacts/M11/runs/20261015-persistent/portal-natural-developer-register-original/portal-natural-verification.json`, not public)、开发者审核 (`artifacts/M11/runs/20261015-persistent/portal-natural-developer-approve-original/portal-natural-verification.json`, not public)、应用 (`artifacts/M11/runs/20261015-persistent/portal-natural-application-original/portal-natural-verification.json`, not public)、申请 (`artifacts/M11/runs/20261015-persistent/portal-natural-request-original/portal-natural-verification.json`, not public)、author (`artifacts/M11/runs/20261015-persistent/portal-natural-author-original/portal-natural-verification.json`, not public)、vote (`artifacts/M11/runs/20261015-persistent/portal-natural-vote-original/portal-natural-verification.json`, not public)、activate (`artifacts/M11/runs/20261015-persistent/portal-natural-activate-original/portal-natural-verification.json`, not public)，preflight见前节原报告；原门户claim过期仍执行中的独立SQL (`artifacts/M11/runs/20261015-persistent/portal-first-expired-claim-readonly-original.json`, not public)、ledger-fix独立门户Service/Route夹具 (`artifacts/M11/runs/20261015-persistent/portal-ledger-fix-fresh-fixture-original/native-verification.json`, not public)、权限版本变化发送前拒绝 (`artifacts/M11/runs/20261015-persistent/portal-ledger-fix-author-pretransport-permission-change-original.json`, not public)、post-topology新独立门户夹具 (`artifacts/M11/runs/20261015-persistent/portal-post-topology-fresh-fixture-original/native-verification.json`, not public)；新case preflight (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-preflight-original/portal-natural-verification.json`, not public)、settings (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-settings-original/portal-natural-verification.json`, not public)、policy (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-policy-original/portal-natural-verification.json`, not public)、publication create (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-publication-create-original/portal-natural-verification.json`, not public)、publication publish (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-publication-publish-original/portal-natural-verification.json`, not public)、developer register (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-developer-register-original/portal-natural-verification.json`, not public)、developer approve (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-developer-approve-original/portal-natural-verification.json`, not public)、application (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-application-original/portal-natural-verification.json`, not public)、request (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-request-original/portal-natural-verification.json`, not public)、author (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-author-original/portal-natural-verification.json`, not public)、vote (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-vote-original/portal-natural-verification.json`, not public)、activate (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-activate-original/portal-natural-verification.json`, not public)、原observe失败 (`artifacts/M11/runs/20261015-persistent/portal-post-topology-natural-observe-original/portal-natural-verification.json`, not public)、过期后保守uncertain收尾独立SQL (`artifacts/M11/runs/20261015-persistent/portal-post-topology-expiry-conservative-completion-independent-sql-original.json`, not public)、CPU采样 (`artifacts/M11/runs/20261015-persistent/portal-post-topology-native-cpu-sampling-original.json`, not public)、CPU调用栈 (`artifacts/M11/runs/20261015-persistent/portal-post-topology-cpu-caller-stacks-original.json`, not public)。

### 新ledger候选重启与约67秒延后观察，旧claim仍未闭环

上海22:37:14，新76ce04候选隔离编译退出0，备份后只停止/启动自有验收API，ready200。纠正观察器后的报告passed=true：重启前后两条原claim、两条origin、子执行/日程及工单的状态和revision均保持，mutations=0、outcomes=0；门户首步仍running，第四轮配置子执行及两张日程仍claimed。未改SQL业务状态、未补会话/claim/期限，没有将旧任务转交新句柄。

随后上海22:38:21的延后只读观察仍保持同样两条原claim、两条origin、0mutation/0outcome，没有新句柄或重试。该观察距ready约67秒，不是90秒；即时及此延后观察都不能外推持续无重放、旧claim终态、自然功能或性能通过。部署报告oldClaimsRepairedOrClosed=false、naturalPerformancePassed=false、wholeM11Accepted=false，延后报告也明确没有修复/关闭旧claim。全新Service3及第五轮自然失败另见前节。

首次部署报告false来自停止API前观察器误用workflow_steps.execution_id；该次尚未停止或更新运行API。改为实际workflow_id后才完成上述部署；原失败保留，不写回为成功。

证据：410源文件/38SQL冻结与隔离编译 (`artifacts/M11/runs/20261015-persistent/integrated-ledger-candidate-source-freeze-original.json`, not public)、原观察器字段失败 (`artifacts/M11/runs/20261015-persistent/integrated-ledger-runtime-deployment-original.json`, not public)、纠正观察器后的部署及即时前后核验 (`artifacts/M11/runs/20261015-persistent/integrated-ledger-runtime-deployment-corrected-observer-original.json`, not public)、原两claim约67秒后无重放只读观察 (`artifacts/M11/runs/20261015-persistent/integrated-ledger-delayed-restart-non-replay-original.json`, not public)。

### 后续源码合同与真实SQL等价证明，不替代自然运行验收

下表保留各专项的Source验证范围；当前运行候选以9236ddf0冻结清单为准。部署启动及旧账本即时观察不把专项用例计数转为业务自然完成或性能结论。

| 更新 | 已有验证 | 当前边界 |
| --- | --- | --- |
| 初始化失败收尾 | 221项Source检查及API类型0 | 新失败预留与原请求/SID约束；不补旧子claim，无自然完成证明 |
| preclaim当前权限阻断 | 3个文件107项Source检查通过 | 该专项未另跑API类型；未取得自然执行验证 |
| 单次typed principal snapshot | 8个不同文件、384个不同已观察通过用例，最终API类型0 | 分阶段有重叠，不能把219+199直接相加；不是全仓固定输入验收 |
| ledger-only当前principal窄拆分 | 14个文件499项Source通过，API类型/API构建0 | 晚于f591；本轮76ce04整合部署仅有启动/即时观察，Native完整current checkpoints保留 |
| 过期receipt探测异常处理 | 2个文件37项Source通过，API类型0 | post-topology门户原catch已真实保守收为uncertain；不修复先前已退出的旧claim |
| safe receipt终态读取 | 5文件204项Source通过，API类型/临时隔离构建0 | 已部署9236；原第五轮安全GET200已核验，不授予历史执行权限 |
| pre-Namespace Authority facts去重复 | 10文件312项及API类型/隔离编译0，含独立Source审阅 | 仅context=null；NS/HTTP/public/V1完整权限检查保留，无正向性能结论 |
| Factory immutable HMAC纯计算memo | 9文件327项及API类型/隔离编译0，另有独立Source审阅 | 仅同一Factory深冻结根引用、同一SecretService实例；不缓存权限或SQL当前事实 |
| 第五处CandidateRead排序 | 4文件154项、API类型0；另纳入312项轮次 | fresh结果每行一次原hash，查询/完整字段/拒绝规则保持；计数不叠加为全量 |

Root另在真实控制台PG只读对两个真实actor分别核对145条完整grants，旧三查询与拟单次typed snapshot的canonical JSON/HMA一致，credential/permission/IAM三个bigint epoch均保持string。两次单次计时一快一慢，只证明本次材料等价，不作为延迟benchmark通过，也不独立证明运行候选功能完成。

ledger-only固定Root当前principal校验保留真实Context/原Namespace引用、SQL当前身份及全部executor/reviewer完整grants等来源约束，只跳过账本额外的Native材料扫描；claim/capture/step/packet/before-send完整检查与Native permit门禁保留。receipt探测catch仅在未来原活跃回调中保留初始错误、receipt=null且unknown=true，再走原uncertain事务/审计/私有完成路径；不会因零operation将未知降级为已知未发送，不吞掉下游SQL/CAS/完成校验异常。76ce04曾部署并完成上述重启观察，507cd795完成初始化窄修复，9236随后整合上述后续更新；post-topology门户另有原catch保守uncertain收尾实证，但仍未取得自然发证成功或性能通过，也不修复先前历史未决claim。

证据：初始化失败221项 (`artifacts/M11/m11-configuration-initialization-failure-source-only-20261015-original.json`, not public)、preclaim107项纠正报告 (`artifacts/M11/m11-business-preclaim-current-authority-source-only-20261015-corrected.json`, not public)、typed snapshot384不同用例/API类型 (`artifacts/M11/m11-validation-principal-single-snapshot-source-only-20261015-original.json`, not public)、两个真实actor的PG等价核验 (`artifacts/M11/runs/20261015-persistent/validation-principal-real-typed-snapshot-equivalence-original.json`, not public)、ledger-only14文件499项/API类型构建 (`artifacts/M11/m11-ledger-only-current-principal-source-checks-20261015-original.json`, not public)、过期receipt探测37项/API类型 (`artifacts/M11/m11-business-expired-receipt-probe-source-only-20261015-original.json`, not public)、safe receipt终态读取Source (`artifacts/M11/m11-schedule-safe-receipt-source-final-20261015-original.json`, not public)。

新专项均已有原始报告：pre-Namespace 312项 (`artifacts/M11/m11-pre-namespace-approval-facts-source-final-20261015-original.json`, not public)、独立Source审阅 (`artifacts/M11/m11-scheduled-eligibility-facts-independent-source-review-20261015-original.json`, not public)、memo 327项 (`artifacts/M11/m11-factory-immutable-fingerprint-memo-source-only-20261015-original.json`, not public)、memo独立审阅 (`artifacts/M11/m11-factory-immutable-fingerprint-memo-independent-source-review-20261015-original.json`, not public)、CandidateRead 154项 (`artifacts/M11/m11-candidate-read-fifth-fresh-sort-source-only-20261015-original.json`, not public)。它们有交叠，不相加为新全量。9236已部署对应产品字节；尚无五分钟内正向自然执行或端到端性能通过结论。

### Promote拓扑及六个前置阶段通过，尚未比较或发布

第二个未修改镜像的Kong已使用新数据库及非superuser角色完成migration/bootstrap，健康检查通过。它与源环境仍共用PG11服务及存储，不是独立故障域。首次目标proxy地址与既有API地址冲突，启动失败且未实际启动；仅纠正目标proxy地址后启动成功，两个原报告分别保留，未重启源API/网关。

507cd795重建自有API后接入新目标Admin网络，未加入Kong数据库网络。当前真实拓扑证明通过：两端均1.5.1，Node ID、数据库OID及角色OID分别不同；数据库仍共用一个PG11进程和卷，源角色为SU、目标非SU，roleIsolationVerified=false、independentFailureDomains=false。它证明本次不同数据库/节点的可达拓扑，不证明完整角色隔离或独立容灾。

当前Promote的preflight、register、policy requests、policy approval、source fixture、target fixture六阶段已分别真实通过；尚未执行compare/promote/自然apply，不预写diff、发布、回滚或完整Promote通过。

证据：目标初始启动失败 (`artifacts/M11/runs/20261015-persistent/promote-target-initial-provisioning-original.json`, not public)、仅纠正目标proxy地址后的启动 (`artifacts/M11/runs/20261015-persistent/promote-target-proxy-ip-correction-original.json`, not public)、当前共享PG/不同数据库拓扑 (`artifacts/M11/runs/20261015-persistent/current-promote-shared-pg-distinct-databases-topology-original.json`, not public)、preflight (`artifacts/M11/runs/20261015-persistent/current-promote-original/preflight-original.json`, not public)、register (`artifacts/M11/runs/20261015-persistent/current-promote-original/register-original.json`, not public)、policy requests (`artifacts/M11/runs/20261015-persistent/current-promote-original/policy-requests-original.json`, not public)、policy approval (`artifacts/M11/runs/20261015-persistent/current-promote-original/policy-approval-original.json`, not public)、source fixture (`artifacts/M11/runs/20261015-persistent/current-promote-original/source-fixture-original.json`, not public)、target fixture (`artifacts/M11/runs/20261015-persistent/current-promote-original/target-fixture-original.json`, not public)。

### 标准平台库恢复分项通过，异机灾备仍待

平台库37迁移恢复试验保留了原备份，但独立目标数据库未就绪，报告为false、`RESTORE_PG_NOT_READY`。后续容量诊断证明临时VFS目标容器在 initdb 创建 pg_wal 时遭遇 ENOSPC，并未完成恢复。只移除了本次自有临时容器以恢复空间，原备份、失败目标卷及业务平台/Kong数据未修改或删除。

容量问题之后，改用同一隔离 PostgreSQL 实例中的新空数据库执行未修改的标准 custom-format `pg_restore`，仍失败，触发 `audit_event_scopes_scope_check`。这次已经进入逻辑恢复，不能再将恢复阻塞仅归因为VFS空间。

对原库同一381条实际有效审计scope只读核对：正常搜索路径下381/381有效，`search_path=''` 时0/381有效；事务内只给 `m7_historical_scope` 固定可信搜索路径后，又恢复为381/381，随后ROLLBACK确认函数配置还原。此试验证明搜索路径依赖根因，不改行数据、不删CHECK、不接触Kong库，也不是实际恢复通过。

现已正式追加 `037_m11_restore_check_function_search_path.sql`，SHA256 `77c78d6b2cf0ef051a71ebed078c532363ab410ce4040501ce14377861c370bd`，只为上述四个CHECK可达wrapper固定可信搜索路径。真实事务试验中381条scope、75条event payload全部有效，非法scope/filter/observation/payload仍拒绝；函数OID与主体不变，ROLLBACK后配置精确恢复。然后由独立owner进程使用标准DbService及runtime provisioner正式应用，账本38条、固定函数4个、API ready200；原约束、历史迁移和审计行不改。

之后捕获新dump，向同一隔离PG实例的另一个新空库执行未修改 `pg_restore --exit-on-error`，实际退出0，未改dump或会话搜索路径。最初后验观察器的 `ORDER BY sequence` 与别名歧义产生42702，原false报告保留；只读改为 `ORDER BY a.chain_scope,a.sequence` 后完整核验通过，没有重复恢复。

还原库实测38条迁移、22张工单、382条审计及2条审计链的hash/JSON patch全部有效；两份AEAD/HMAC材料验证通过，运行角色非superuser且只能按需追加，正常管理员连接和运行角色对审计的修改尝试都被拒绝。原备份、旧dump及旧部分恢复库保留，不把新dump成功补算为旧dump已可恢复。

这次是真实未修改标准pg_restore及只读后验通过，区别于历史改写SQL prologue再psql导入的助手。**同实例新空库的标准逻辑恢复分项已通过**；恢复库未启动API或worker，没有做独立主机/进程故障恢复，不宣称异机灾备、完整RPO/RTO或正式生产总门禁通过。原库/Kong数据未改，运行密钥未导出。

证据：独立恢复原失败 (`artifacts/M11/runs/20261015-persistent/console-037-independent-restore-proof-original.json`, not public)、恢复启动容量诊断 (`artifacts/M11/runs/20261015-persistent/restore-startup-capacity-diagnostic-original.json`, not public)、同实例新空库标准逻辑恢复原失败 (`artifacts/M11/runs/20261015-persistent/console-037-separate-database-logical-restore-proof-original.json`, not public)、381行搜索路径只读/回滚试验 (`artifacts/M11/runs/20261015-persistent/console-restore-search-path-readonly-and-rollback-trial-original.json`, not public)、四wrapper窄修复源码审查 (`artifacts/M11/m11-pgrestore-check-function-search-path-source-review-20261015-original.json`, not public)、SQL037真实回滚/正式迁移 (`artifacts/M11/runs/20261015-persistent/integrated-single-authority-037-runtime-deployment-original.json`, not public)、标准pg_restore退出0但后验观察失败 (`artifacts/M11/runs/20261015-persistent/console-after-037-standard-logical-restore-proof-original.json`, not public)、只读纠正观察后的完整验证 (`artifacts/M11/runs/20261015-persistent/console-after-037-standard-restore-qualified-readonly-verification-original.json`, not public)。

### 聚焦源码检查

以下聚焦结果来自不同源码范围，存在重叠，**不相加为整仓测试总数**：

| 源码专项 | 已记录结果 | 范围限制 |
| --- | --- | --- |
| Target 即时审批 UI | 6 个测试文件、245 项通过，Web 类型检查退出 0，测试期间冻结输入保持 | 创建、权重/业务标签、健康/不健康和回收删除入口；尚无本新增 UI 的真实完整业务验收 |
| 实体说明与共享路由、回调边界 | 10 个选定测试文件、227 项通过，API/Web 类型检查退出 0 | 固定 Annotation 注册、当前范围与真实来源约束；不代表整仓回归 |
| 实体说明前端 | 4 个文件、123 项通过，Web 类型检查退出 0 | 含受控表单与原请求恢复；不是浏览器写入实测 |
| 后台业务回调边界 | 133 项源码检查通过 | 受控夹具验证原始回调/NULL-SID 边界，不能当作实际自然业务定时成功 |

Target 新入口支持即时添加、修改权重/业务标签、当前 Admin 节点健康置位与回收删除；编辑地址锁定，权重 0–1000，追加权重产生新 UUID。健康须启用主动或被动检查且有匹配的真实 HEALTHY/UNHEALTHY 行；手动置位不可自动回滚、不支持定时。未知准备或提交只读核验原键，未观察到记录不授权重发。上述为当前源码合同；本轮当前节点健康及自然权重已有独立运行证明，其余入口、范围和故障路径仍须分别验证。

本轮已同步 [用户手册](../../../manuals/console-user-guide.md)、[部署与运维手册](../../../manuals/production-operations-guide.md)、[技术参考](../../../manuals/technical-operations-reference.md) 和 [手册目录](../../../manuals/README.md)。用户手册保留页面任务和必要安全限制，历史测试计数、环境事故与技术验证边界由进度及技术材料承载。

证据：说明准备 (`artifacts/M11/runs/20261015-persistent/annotation-set-prepare/native-verification.json`, not public)、说明提交 (`artifacts/M11/runs/20261015-persistent/annotation-set-submit/native-verification.json`, not public)、说明独立审批 (`artifacts/M11/runs/20261015-persistent/annotation-set-vote/native-verification.json`, not public)、Target UI 冻结检查 (`artifacts/M11/target-workflow-web-source-checks-20261015-health-wording-final.json`, not public)、说明及共享接线冻结检查 (`artifacts/M11/m11-annotation-and-callback-boundary-source-checks-20261015-frozen.json`, not public)、说明前端检查 (`artifacts/M11/annotation-workflow-web-source-checks-20261015-metadata-corrected.json`, not public)、后台回调边界 (`artifacts/M11/m11-business-callback-boundary-source-only-20261015-original.json`, not public)。

### 当前主console库审计链完整校验通过，取消观察及停机跨窗口到期取得实证

实际主console库使用runtime角色、只读事务独立核验当前681行审计/3条链，全部链hash及JSON patch正确；未发布审计内容或凭证。这证明当前已有审计行的完整性，不等于最终候选所有关键写入100%审计覆盖或商用总体验收。

另通过独立原生审批创建三个全新Safety Service，均201。cancel-before-due case七阶段实际通过，原窗口上海23:22:10.396–23:24:10.396结束后，23:32:22只读HTTP观察仍为cancelled、claimId=null，工单approved/作业waiting_approval；独立SQL零claim/Native计数尚待，不能由HTTP单独外推。

restart-expiry原窗口上海23:28:23.967–23:30:23.967，Root于23:28:01停止自有API，停止前active且claim/执行/mutation均0；23:31:22在窗口结束后启动同一容器并升级507→9236。独立SQL确认同一原日程expired、原窗口不变、claim/执行/mutation均0，HTTP于23:32:46观察expired及WORKFLOW_SCHEDULE_WINDOW_EXPIRED。没有手动tick、改时钟、延长原期限或接管旧claim。这证明跨二进制升级/重启的本次过期不补跑，不能称同一二进制重启或正向业务执行成功。

原overlap case仅preflight/prepare，未author；原期限已不足完成固定提前量/窗口，不续期、不复用夹具或旧case。新独立case的Source支持正在准备，实际重叠预约冲突与零发送仍待。

证据：当前主库全审计链/JSON patch只读核验 (`artifacts/M11/runs/20261015-persistent/current-audit-all-chains-and-json-patches-readonly-original.json`, not public)、三个新Safety Service (`artifacts/M11/runs/20261015-persistent/business-safety-fresh-services-original/native-verification.json`, not public)、取消case preflight (`artifacts/M11/runs/20261015-persistent/business-safety-cancel-before-due-preflight-original/business-schedule-safety-cancel-before-due-preflight.json`, not public)、prepare (`artifacts/M11/runs/20261015-persistent/business-safety-cancel-before-due-prepare-original/business-schedule-safety-cancel-before-due-prepare.json`, not public)、author (`artifacts/M11/runs/20261015-persistent/business-safety-cancel-before-due-author-original/business-schedule-safety-cancel-before-due-author.json`, not public)、approve (`artifacts/M11/runs/20261015-persistent/business-safety-cancel-before-due-approve-original/business-schedule-safety-cancel-before-due-approve.json`, not public)、activate (`artifacts/M11/runs/20261015-persistent/business-safety-cancel-before-due-activate-original/business-schedule-safety-cancel-before-due-activate.json`, not public)、cancel (`artifacts/M11/runs/20261015-persistent/business-safety-cancel-before-due-cancel-original/business-schedule-safety-cancel-before-due-cancel.json`, not public)、窗口后取消HTTP观察 (`artifacts/M11/runs/20261015-persistent/business-safety-cancel-before-due-observe-original/business-schedule-safety-cancel-before-due-observe.json`, not public)、原窗口前停止API (`artifacts/M11/runs/20261015-persistent/business-expiry-own-api-stopped-before-original-window-original.json`, not public)、窗口后启动/到期SQL (`artifacts/M11/runs/20261015-persistent/combined-candidate-runtime-and-original-expiry-restart-original.json`, not public)、到期HTTP观察 (`artifacts/M11/runs/20261015-persistent/business-safety-restart-expiry-observe-original/business-schedule-safety-restart-expiry-observe.json`, not public)。

### Source构建输出勘误：旧服务影响仍未知

ledger-only专项中的workspace build实际退出0，但曾写入仓库原dist，并未使用先前描述的隔离临时输出目录；原Source报告保留，另有独立勘误。旧绑定产物的容器启动时间为上海08:44:33（UTC00:44:33）、restartCount=0、当前unhealthy；只读观察不能由运行时长或当前健康状态推断其历史已加载模块或功能影响，影响仍unknown。没有为掩盖此事重启、恢复/删除dist或修改旧服务；当前验收候选的构建独立隔离，不据此宣称旧服务无影响。

证据：Source构建输出勘误 (`artifacts/M11/m11-ledger-only-source-build-dist-correction-20261015-original.json`, not public)、旧绑定容器影响只读观察 (`artifacts/M11/runs/20261015-persistent/old-bind-dist-build-impact-readonly-original.json`, not public)。

### checkpoint秘密扫描实际执行，但发布文件变化使整体验证失败

首次扫描的SCAN_SHORT_EXPLICIT_SECRET_REQUIRES_REVIEW/0字节前置失败保留。扫描器对非秘密字段的精确判定及固定profile专项58/58通过；新增checkpoint-api-key-not-issued，仅用于尚未发行API Key的本阶段，默认完整五类材料要求保持不变。

随后该checkpoint profile已实际扫描373,275,850字节、actualSecretCount=197，发现数0；但最后因并发Source编辑触发SCAN_PUBLISHABLE_FILE_CHANGED，整体passed=false。该profile API Key材料0、apiKeyIssuanceAcceptance=false、finalCredentialComplete=false，不能登记为最终全凭证扫描或无泄露PASS，也不根据文件变化判定有泄露。需Source冻结后重扫，最后发布候选仍须满足完整扫描门禁。

证据：首次扫描前置失败 (`artifacts/M11/runs/20261015-persistent/current-checkpoint-secret-scan-original/m11-current-secret-scan-2026-10-15T14-35-52-190Z-33fa42a2-eb20-48e6-a2e6-80277a62f811.json`, not public)、固定profiles Source专项 (`artifacts/M11/m11-current-secret-scan-fixed-profiles-source-only-20261015-original.json`, not public)、实际扫描后发布文件变化失败 (`artifacts/M11/runs/20261015-persistent/current-checkpoint-secret-fixed-profile-original/m11-current-secret-scan-2026-10-15T14-56-00-349Z-26514571-bb17-45a3-ad46-bb2142f5eabc.json`, not public)。

## 5. 仍需完成的闭环与顺序

1. 继续控制面其余操作、IAM其余动作、凭证/Target页面与原键恢复；说明三操作、角色创建和说明更新双身份UI链已有独立证明，不扩大为全部类型/页面通过。
2. 在当前节点 unhealthy/healthy 两次真实204通过后，补齐检查关闭等拒绝场景、即时权重/标签、0权重确认、回收删除、新权重回滚及真实UI；不把本轮两张健康工单扩展为全部故障路径。
3. 保留第四轮配置子claim及门户过期原claim，76ce04重启即时及约67秒延后观察已完成但旧任务未收口。pre-child及safe receipt已整合部署9236，原第五轮终态GET200已验证，但仍须全新意图/审批的正向自然配置结果；门户post-topology case已保守收为uncertain、发证仍未通过，旧PV变化case不重放。取消窗口后HTTP通过、独立SQL仍待，跨窗口停机重启expired/零claim/执行/mutation与HTTP均已核验，新overlap case仍待。旧账本不补claim/延时/借新句柄。
4. 在新Promote目标/BFF真实拓扑及六前置阶段通过后，继续真实compare/promote/自然apply；在本次12点QPS通过后继续其他监控维度、Consumer/collector/Loki及授权下钻，并完成本期通知/身份提供者联调。
5. 对同一最终候选完成三端构建、M0–M11 单测/集成/e2e、越权/IDOR、全部关键写入审计覆盖及不可变约束、最终日志/审计/产物秘密扫描。
6. 在SQL037标准新空库恢复分项通过后，继续恢复API/worker受控启动、独立主机/进程与密钥恢复、真实业务核验、RPO/RTO及生产持久部署/容量；保留旧归档/部分恢复库，最后登记正式版本与远程提交。

本轮整仓在恢复并核验固定 decK 1.2.4 工具后，重新冻结 1,742 个输入文件，以两个 worker 实际运行：12,778 项全部通过、失败/跳过均 0，三端类型检查退出 0；输入前后摘要同为 `65393c6bfa2633b8aa6f18cb4724e3b30c763e86f3ac975501a50decb07076d4`。首次缺工具、部分用例未执行以及冻结期间新增测试导致输入变化的原报告仍保留。

**12,778 项仅是健康兼容修复前固定输入的历史通过记录。** 后续含健康 data 修复的整合轮次冻结 1,748 个输入，前后摘要一致；实际 12,878 项中 12,877 通过、1 项 M9 路由模拟失败、跳过 0，三端类型检查和构建均退出 0，但整合验收报告为 false。失败用例涉及 matched-regex 与 plain path 的优先级断言，该轮M9原失败保留，后续专项与整仓新结果分别记录，不预写修复后的全量通过。

该轮12,878项的失败记录继续保留，不将后续结果写回原报告。随后统一冻结 **1,755个输入**（1,750个源码/配置/测试等输入及5份手册），摘要 **`afc66bc09377da30602ce03365438d5fcbc5bbfafd6537f2ebd49e2b5a9e37da`**，实际 **13,051/13,051项、1,377个suite全部通过，失败/跳过0**；三端类型检查和三端隔离构建均退出0。全测与后续类型/构建是分开的真实记录阶段，前后输入摘要一致、变更清单为空，隔离构建没有替换活动API运行产物。

该统一报告对源码/类型/隔离构建门禁为通过，runtime/commercial仍为false。五份手册输入保持冻结，ManualPage既有7项SSR和两本实际raw-import产物核对属于对应源码/构建范围。**之后的三个性能源码文件/205项专项及已正式应用SQL037，不在afc66这轮13,051项证明内。** f591ea及76ce04部署、标准恢复另有真实证据，但重启即时及约67秒延后观察没有闭合第四轮配置/门户旧claim，第五轮初始化仍失败；后续初始化失败/preclaim/typed snapshot/ledger-only/receipt探测catch也不在旧全量内，须按最终冻结重新完整回归及自然验证。9236整合候选已有冻结、隔离编译、实际启动、安全历史读取及跨窗口到期证明，但仍无新正向自然配置/门户/Promote完成；204/312/327/154项专项也不属于afc66全量。实际checkpoint扫描因发布文件变化整体失败，不能外推M11商用通过。

证据：首次整仓与限制分类 (`artifacts/M11/m11-integrated-full-source-regression-20261015-original-classification.json`, not public)、固定工具恢复 (`artifacts/M11/runs/20261015-persistent/verified-deck124-tool-prerequisite-restoration-original.json`, not public)、1,742 输入/12,778 历史通过及三端类型检查 (`artifacts/M11/m11-integrated-full-source-regression-20261015-final-fixed-input-original.json`, not public)、1,748 输入/12,878 后续整合原失败及三端构建 (`artifacts/M11/m11-health-data-integrated-full-regression-and-build-20261015-original.json`, not public)、afc66统一13,051项/类型/隔离构建通过 (`artifacts/M11/m11-unified-final-regression-typecheck-and-build-20261015-original.json`, not public)。

## 6. 后续记录原则

新结果追加实际报告、真实运行候选和精确范围，不改写 2026-10-14 检查点、旧失败或旧未知事实。未收敛的原生结果继续阻断相关写入，不通过重建 SID、claim、批准、expiry 或新键“恢复”。远程提交与推送完成后再登记实际 commit，不预写。

完整历史与分项记录见 [M11 验证记录](../../verification/milestones/m11-verification.md)。当前结论仍为 **M11 分项交付中，整体验收与商用发布未完成**。

## 7. 追加观察：取消与重叠预约核验完成，Promote暴露来源绑定，配置子执行仍待终态

本节是上海23:53:41前已落盘的后续观察，补充前文摘要中的待办状态；不覆盖原失败、旧claim或旧case。当前API仍为9236ddf0，M11及商用整体验收仍未通过。

### 取消、停机过期与新独立overlap的实际安全结果

取消/过期原日程独立SQL (`artifacts/M11/runs/20261015-persistent/business-cancel-expiry-independent-sql-original.json`, not public) passed=true：取消原日程仍cancelled、跨窗口停机原日程仍expired；两者claims、executions、mutations、origins及outcomes均0，原窗口保持。它补齐前文取消case的独立账本计数，过期重启时间线仍以原停止/启动报告为准；零mutation行不是独立网络抓包证明。

另建独立夹具的新named case `post-restart-20261015`，其 preflight (`artifacts/M11/runs/20261015-persistent/business-safety-overlap-post-restart-20261015-preflight-original/business-schedule-safety-overlap-post-restart-20261015-preflight.json`, not public)、prepare (`artifacts/M11/runs/20261015-persistent/business-safety-overlap-post-restart-20261015-prepare-original/business-schedule-safety-overlap-post-restart-20261015-prepare.json`, not public)、author (`artifacts/M11/runs/20261015-persistent/business-safety-overlap-post-restart-20261015-author-original/business-schedule-safety-overlap-post-restart-20261015-author.json`, not public)、approve (`artifacts/M11/runs/20261015-persistent/business-safety-overlap-post-restart-20261015-approve-original/business-schedule-safety-overlap-post-restart-20261015-approve.json`, not public) 及 overlap-check (`artifacts/M11/runs/20261015-persistent/business-safety-overlap-post-restart-20261015-overlap-check-original/business-schedule-safety-overlap-post-restart-20261015-overlap-check.json`, not public) 均真实通过。A激活200后，B激活精确返回409 `WORKFLOW_SCHEDULE_PHYSICAL_IMPACT_CONFLICT`，B原state/revision未变；随后A/B取消分别200。旧overlap仅准备的原case不改写或续期。

首次observe早于原windowEnd约5秒，被Source前置门禁拒绝，未建立runs.observe、没有HTTP请求，原失败 (`artifacts/M11/runs/20261015-persistent/business-safety-overlap-post-restart-20261015-observe-original/business-schedule-safety-overlap-post-restart-20261015-observe.json`, not public) 保留。原窗口上海23:49:47.226–23:51:47.226结束后，用新报告目录执行同一原日程的 只读观察 (`artifacts/M11/runs/20261015-persistent/business-safety-overlap-post-restart-20261015-observe-after-original-window-original/business-schedule-safety-overlap-post-restart-20261015-observe.json`, not public) passed=true，两日程均cancelled/claimId=null。独立SQL (`artifacts/M11/runs/20261015-persistent/business-overlap-post-restart-independent-sql-original.json`, not public) passed=true，两日程各自claims/executions/mutations/origins/outcomes均0。该SQL报告的restartTimelineReport是通用复制字段，**不作为本次overlap经历API重启的证据**；case名也不意味着对这两日程执行过重启。

### Promote：真实201的合法计划分叉保留，author403仍待产品修复

compare (`artifacts/M11/runs/20261015-persistent/current-promote-original/compare-original.json`, not public) 及 promote-plan (`artifacts/M11/runs/20261015-persistent/current-promote-original/promote-original.json`, not public) 真实passed。原 apply报告 (`artifacts/M11/runs/20261015-persistent/current-promote-original/apply-original.json`, not public) 仍false，但其中实际POST收到201、已登记waiting_approval；失败来自runner错误要求返回的执行planId等于原导入planId。平台按原manifest合法冻结新计划，不能重发apply或把这条201改为零副作用。

Root只恢复原201的独立回执、未重放apply，随后 author实际403 (`artifacts/M11/runs/20261015-persistent/promote-original-201-fork-recovery-author-stopped-contract-original/promote-original-continuation-verification.json`, not public) `WORKFLOW_BUSINESS_PROMOTION_STORAGE_CHANGED`：原导入计划86554371-a244-4790-9bdf-f203092e228e、新执行计划d7b254f3-1e45-416a-8b55-d0e0249bbb51、原工单45a49eb8-3899-4103-9d06-8cb31e298e6b均保留，尚无日程激活或自然apply成功。此前回执观察器的 Cookie形状错误 (`artifacts/M11/runs/20261015-persistent/promote-original-201-fork-recovery-author-original/promote-original-continuation-verification.json`, not public) 与 stopped/failed断言错误 (`artifacts/M11/runs/20261015-persistent/promote-original-201-fork-recovery-author-cookie-contract-original/promote-original-continuation-verification.json`, not public) 也保留。

runner计划分叉专项22项 (`artifacts/M11/m11-current-promote-apply-plan-fork-source-only-20261015-original.json`, not public) 已通过，仅修改验收工具及测试，不重置旧失败stage、不属于产品运行修复。产品双job/plan来源绑定修复仍在Source阶段、未部署；不得写Promote或自然发布闭环通过。

### 9236普通Service范围自然配置已进入真实子执行

新独立Service范围工单 e347d08e-7fd5-44dd-8658-e4e9462112f4及日程e021ee41-4d3f-4be3-834a-120ec58eec16准备通过 (`artifacts/M11/runs/20261015-persistent/configuration-natural-service-scope-9236-prepare-original/configuration-natural-verification.json`, not public)，预期retries 5→4。自然worker已认领；上海23:52:46独立SQL (`artifacts/M11/runs/20261015-persistent/configuration-service-scope-9236-natural-progress-fourth-original.json`, not public) 确认nestedOrigins=1、configurationJob=running、真实配置子执行executing、mutation0；23:53:41后续观察 (`artifacts/M11/runs/20261015-persistent/configuration-service-scope-9236-natural-progress-fifth-original.json`, not public) 仍相同。它证明初始化节点已越过并建立真实子来源，**不证明配置完成、Native成功、性能或M11通过**；等待原期限内自然终态，不延长、手动tick或借新句柄接管。

随后仍须完成配置及门户正向自然闭环、Promote来源修复后的新意图验证、撤权/多级会签/通知、最终固定输入全测/三端构建、关键写入审计覆盖与完整凭证秘密扫描、恢复与生产部署验收。afc66旧13,051项范围及checkpoint扫描整体false保持，不预写新的全量通过。

### 最新终态补充：9236配置子执行已安全失败收尾，正向发布未通过

上海23:55:32的 原执行到期后独立SQL (`artifacts/M11/runs/20261015-persistent/configuration-service-scope-9236-after-original-execution-expiry-observation-original.json`, not public) 已取得终态：同一原日程、工单、wrapper执行、configuration job与配置子执行全部failed；job错误WORKFLOW_SCHEDULE_NAMESPACE_EXPIRED，子步骤CONFIGURATION_NOT_STARTED/operationId=null，nestedOrigins=1、mutation0，恰有一条original-execution failed outcome。此前23:53:41的executing是中间观察，现以该终态补充，原报告保留。

本次初始化实际进入了真实子来源，且原回调在到期后正确收口新子执行，不再停留为第四轮历史子claim那样的未决状态；这仍是自然配置失败，五分钟执行预算与正向发布验收均未通过。不能将安全失败收尾写成Service retries已变更、性能或M11通过，不能借新句柄补原请求。

Promote双job/plan来源修复另有 独立Source审阅 (`artifacts/M11/m11-promotion-apply-fork-lineage-independent-source-review-20261015-original.json`, not public) 无阻断发现；报告所列173项为实现者提供的测试结果，审阅者未重跑，API编译及正式Source汇总仍待独立记录。该产品修复未部署，9236运行结论及旧author403保持。**M11及商用整体验收仍未通过。**

## 8. 当前checkpoint：fac38已部署、固定源码全量通过，正向自然执行仍阻塞

本节固定当前checkpoint，不继续追随新增运行结果；前述摘要及待办按各自观察时间保留。**M11及商用验收仍未通过，主要阻塞是自然执行中的重复校验放大与超时。**

- 当前API为 `fac38e7acf0b42e8bd08f1b2ce3568d92654d74d4646d81bb586e571aca1a2bd`，冻结 (`artifacts/M11/runs/20261015-persistent/promote-fork-single-step-candidate-source-freeze-original.json`, not public) 410个输入/38条SQL、隔离编译0。首次启动失败 (`artifacts/M11/runs/20261015-persistent/promote-fork-single-step-candidate-runtime-original.json`, not public) 原因是只读dist缺少空的嵌套迁移挂载目标；只补自有停止API的空目录后，同容器启动ready200 (`artifacts/M11/runs/20261015-persistent/promote-fork-single-step-candidate-runtime-after-mountpoint-original.json`, not public)，未改原计划/窗口/会话、未重放旧日程、未改Kong镜像或源码。370个API编译产物 (`artifacts/M11/runs/20261015-persistent/fac38-runtime-candidate-equal-full-api-build-original.json`, not public) 与本次全量构建字节相同。
- 新固定输入全量报告 (`artifacts/M11/m11-frozen-full-source-typecheck-isolated-build-20261015-5azk2xlc-original.json`, not public) 为1,792个输入（含5份手册），前后SHA256同为 `08aaf0d7f29ac9749c7ce68431675c32c90dcad4430d14efef5402bd47057b17`；604文件、1,446suite、13,976/13,976项通过，失败/跳过/todo均0。完整测试、三端类型检查、三端/tmp隔离构建共七步退出均0；仓库原三端dist的454项metadata保持，手册chunk仍为ae311b1cc492353102b9c33f2f5699a1fd6641e56eeda03c9fe5637a1da79a16。它取代afc66作为当前源码/类型/构建门禁，但不证明真实自然执行或商用通过。期间一次瞬时mkdir ENOSPC与原日志保留，没有据此隐藏失败或跳过用例；固定输入及原dist边界仍保持。
- Promote双job/plan来源修复173项/API类型及隔离编译0 (`artifacts/M11/m11-promotion-apply-fork-lineage-source-only-20261015-original.json`, not public) 与独立Source审阅已整合部署；step首段Authority专项58项 (`artifacts/M11/m11-business-step-first-authority-source-only-20261015-original.json`, not public) 及独立审阅也已整合。旧Source对照仅三条调用次数/路径计数断言不同，其余权限与拒绝语义保留；专项不额外相加为全量，也不等于自然性能达标。
- 第四个独立门户case `single-step-fork-20261015` 的 新Service/Route夹具 (`artifacts/M11/runs/20261015-persistent/portal-single-step-fork-fresh-fixture-after-capacity-original/native-verification.json`, not public) 经独立审批201；Service75c2b5a6-58c3-47cd-b1e0-880666f83edd/Routea72e2f8f-661f-4988-bf9d-6f4bfc0a6ac6，前12阶段至 激活 (`artifacts/M11/runs/20261015-persistent/portal-single-step-fork-natural-activate-original/portal-natural-verification.json`, not public) 实际通过。工单0bc581f3-0a17-48d9-be72-5202229806b8/日程31a5f0bb-48b7-4e67-8daf-33c553f0f6d7自然单claim bda6d6aa-e826-497f-bc75-0ae6bdd2fc10后，实际SQL终态 (`artifacts/M11/runs/20261015-persistent/portal-single-step-fork-natural-progress-third-original.json`, not public) 为W/E/schedule均uncertain、snapshotready、首Native KONG_EXECUTION_CONTEXT_EXPIRED、mutation0、单条original-execution uncertain outcome；grant/credential仍pending。HTTP observe失败 (`artifacts/M11/runs/20261015-persistent/portal-single-step-fork-natural-observe-original/portal-natural-verification.json`, not public) 保留，尚无issued、revoke或凭证代理可用验证；0mutation不将未知改为已知未发送，不重放旧case。
- 修复后Promote新同名独立 源Service (`artifacts/M11/runs/20261015-persistent/promote-after-fork-fix-source-fixture-original/promote-after-fork-fix-source-fixture-original.json`, not public) 与 目标Service (`artifacts/M11/runs/20261015-persistent/promote-after-fork-fix-target-fixture-original/promote-after-fork-fix-target-fixture-original.json`, not public) 夹具实际通过；Root新拓扑证明 (`artifacts/M11/runs/20261015-persistent/current-promote-after-fork-fix-fresh-topology-original.json`, not public) 确认节点/数据库OID不同、Admin未暴露且BFF不连Kong库，仍共享PG进程/存储/故障域、roleIsolationVerified=false。截至该checkpoint时尚未准备/author新的Promote工单；后续准备与激活拒绝见下一追加记录，不将当时的修复部署或夹具成功写成运行正向通过。
- 容量回收 (`artifacts/M11/runs/20261015-persistent/narrow-unused-image-capacity-recovery-original.json`, not public) 仅删除3个无标签且无任何运行/停止容器引用的镜像，回收105,459,712字节，容器ID、卷及bind文件未动。实际重复校验放大的 只读Source诊断 (`artifacts/M11/m11-business-schedule-validation-amplification-source-review-20261015-original.json`, not public) 及优化方向仍不是新修复或性能验收，后续需在保持当前权限、原期限及packet/before-send门禁下实施并用全新意图验证。

本轮实际检查点秘密扫描 (`artifacts/M11/runs/20261015-persistent/current-fac38-checkpoint-secret-scan-original/m11-current-secret-scan-2026-10-15T16-24-43-223Z-7b14563c-4da9-4c62-9528-be9edcfd7728.json`, not public)已通过：310份实际秘密材料、383,068,615字节、0发现、真实进程退出0，文件与材料栅栏保持。扫描包含新三端产物、待发布文件、8个自有容器完整日志、原API归档日志及966条实际审计记录；日志截止16:23:40 UTC。采用固定 `checkpoint-api-key-not-issued` profile，API Key材料数0，`finalCredentialComplete=false`，不代表已发证或完整凭证验收。旧false报告保留。本checkpoint后仍须处理自然配置/门户性能阻塞、Promote新意图验证及余下生产验收；本次源码与扫描通过不改变M11/commercial=false。

## 9. 远程检查点与Promote激活拒绝的后续事实

本节补充前一checkpoint之后的已证事实；旧报告、旧失败与原截止时间保持。**当前仍未完成M11或商用验收。**

检查点已实际推送至远程仓库：[938d41e](https://github.com/sean-y-wang/kongpilot-console/commit/938d41e)、[7077df8](https://github.com/sean-y-wang/kongpilot-console/commit/7077df8)，HEAD为 [6824f312aecc2b82aa1579e53500c343be74f8f2](https://github.com/sean-y-wang/kongpilot-console/commit/6824f312aecc2b82aa1579e53500c343be74f8f2)。这是研发检查点，不是GA发布、生产合并或商用准入。

fac38当前主库审计只读核验 (`artifacts/M11/runs/20261015-persistent/fac38-current-audit-all-chains-readonly-original.json`, not public) passed=true：使用实际runtime角色及repeatable-read快照，验证983行/3条审计链及全部JSON patch正确；无写入、未打印审计正文或凭证。该结果更新已有审计完整性观察，不外推所有关键写入审计覆盖100%或商用通过。

修复后新Promote case的 prepare-plan (`artifacts/M11/runs/20261015-persistent/promote-after-fork-fix-prepare-plan-original/promote-after-fork-fix-prepare-plan-original.json`, not public) 真实通过：比较、promote-plan及apply登记均201，保留原导入计划62d59b1d-937c-4665-8534-abdf3ecfada2→新执行计划cf7c60d1-e063-40e4-965b-047a5f328076/作业1dae0b1f-aa69-417f-8582-7411c892ace3，工单e3c79cbe-3e8f-4a7d-8339-04a9eb3de19c。Root实际只读SQL (`artifacts/M11/runs/20261015-persistent/promote-after-fork-fix-original-sql-deadlines-original.json`, not public) 核对原导入/执行作业、两个计划、两条authority及workflow七个截止约束，均未续期或写入。这证明新case越过旧来源绑定拒绝节点，不等于发布完成。

随后 author-activate原报告 (`artifacts/M11/runs/20261015-persistent/promote-after-fork-fix-author-activate-original/promote-after-fork-fix-author-activate-original.json`, not public) 整体false：日程创建201、独立审批201，激活403 `WORKFLOW_CANDIDATE_EXPIRED`。上海次日00:42:49（UTC16:42:49）的 独立SQL (`artifacts/M11/runs/20261015-persistent/promote-after-fork-fix-original-activation-denial-independent-sql-original.json`, not public) observationVerified=true/functionalAcceptancePassed=false：日程176d3a23-ae2d-469e-94a9-bcee1febacde仍pending-approval/revision1，activations、claims、outcomes均0；workflow approved/revision2，revision1和2各只有一项pending步骤，配置执行、workflow执行及mutation均0。未激活、未执行不能登记自然Promote成功；零mutation账本行不是独立网络抓包。原意图不重试、不延寿，不为获取通过结果更换请求键或重新提交旧stage。

实际结构化HTTP日志 (`artifacts/M11/runs/20261015-persistent/promote-original-activation-http-timing-original.json`, not public) 进一步核对原激活请求耗时31,405ms后403，超过独立候选读取胶囊30,000ms预算；当时原job/plan截止与windowEnd仍在未来，支持高置信归因于30秒读取胶囊耗尽。候选胶囊及原期限校验共用该错误码，生产安全日志不暴露精确throw site；该结论不是取得栈trace的精确定位，也不授权延长胶囊或重放原意图。fixedReader只读分层性能改造正在Source阶段，尚未冻结、部署或完成新的全量验收，不能使用fac38的13,976项通过覆盖这些新修改。后续仍须验证保持当前权限/原截止/packet门禁的性能修复，再以全新意图完成自然配置、门户与Promote正向链及余下生产门禁。

## 10. ac6 fixedReader实际运行：Source计数改善，调用预算及未知传播仍阻塞

本节继续保留前述检查点与失败，当前API已变为ac6候选；**M11、正向自然执行及商用验收仍未通过**。

fixedValidationReader最终Source报告 (`artifacts/M11/m11-fixed-validation-reader-source-final-20261015-original.json`, not public) 验证三份产品文件及固定16项输入，4个测试文件245/245项通过（新35、原210），两份独立审阅无阻断。受控双GET组的完整current调用由旧17次降至2次；这是Source计数，不是实际耗时、Native GET数量减少或权限等价的无限外推。ac6冻结 (`artifacts/M11/runs/20261015-persistent/fixed-reader-candidate-source-freeze-original.json`, not public) API摘要 `ac6e5c58d390220b399a082c826277c0c59f8739ded9823043dae9aa9b8d3b1a`，410个输入/38条SQL不变、隔离编译0。Root备份并只重启自有验收API，UTC16:46:57实际启动ready200 (`artifacts/M11/runs/20261015-persistent/fixed-reader-candidate-runtime-original.json`, not public)，原数据/会话/计划窗口保持，不重放旧日程、不改Kong源码/镜像。fac38的13,976项全量不覆盖ac6这些新字节，尚无ac6新固定输入全量通过。

新 Service夹具 (`artifacts/M11/runs/20261015-persistent/configuration-service-scope-fresh-service-fixed-reader-original/native-verification.json`, not public) 经独立审批及Native201；新工单准备/author/独立vote/激活 (`artifacts/M11/runs/20261015-persistent/configuration-natural-service-scope-fixed-reader-prepare-original/configuration-natural-verification.json`, not public) passed，原工单f3d78f35-dd2f-48f4-91df-39ae92520319/日程b23cf628-6d73-4ca4-bd19-622ceffcb4b6。到期前观察 (`artifacts/M11/runs/20261015-persistent/configuration-fixed-reader-before-due-original.json`, not public) active/claim0；原notBefore为UTC16:50:00.697，自然认领后 (`artifacts/M11/runs/20261015-persistent/configuration-fixed-reader-after-natural-due-original.json`, not public) 恰1claim，原authority截止16:55:09.072，未手动tick或延长。

后续真实 第一次 (`artifacts/M11/runs/20261015-persistent/configuration-fixed-reader-natural-progress-first-original.json`, not public)、第二次 (`artifacts/M11/runs/20261015-persistent/configuration-fixed-reader-natural-progress-second-original.json`, not public)、第三次 (`artifacts/M11/runs/20261015-persistent/configuration-fixed-reader-natural-progress-third-original.json`, not public) 及 原authority到期后独立SQL (`artifacts/M11/runs/20261015-persistent/configuration-fixed-reader-after-original-authority-expiry-original.json`, not public) 记录：初始化建立nestedOrigin1，但配置job/子执行/子步骤为uncertain，错误 `KONG_EXECUTION_CALL_LIMIT`、operationId=null、mutation0；外层workflow/执行及revision2步骤却为failed。日程仍claimed、outcome0，**不是已正确收口或配置成功**。原HTTP终态观察 (`artifacts/M11/runs/20261015-persistent/configuration-natural-service-scope-fixed-reader-terminal-http-original/configuration-natural-verification.json`, not public) false（claimed而非succeeded）保留。零mutation不把未知降为已知未发送，不重放、改写或用新句柄补旧意图。

本次 实际CPU采样 (`artifacts/M11/runs/20261015-persistent/configuration-fixed-reader-natural-cpu-sampling-original.json`, not public) 6.395336秒/4,595样本，idle2,456约53.45%；Inspector仅容器loopback且采后关闭、没有Debugger暂停。调用栈 (`artifacts/M11/runs/20261015-persistent/configuration-fixed-reader-cpu-caller-stacks-original.json`, not public) 仍见fresh grants/HMA及Material校验热点，仅用于诊断，不由17→2的Source计数宣称wall-clock或五分钟性能通过。新Portal Service/Route夹具 (`artifacts/M11/runs/20261015-persistent/portal-fixed-reader-fresh-fixture-original/native-verification.json`, not public) 经独立审批201；尚未建立该夹具的Portal工单，未发行API Key，不能记发证成功。

当前另三项Source工作分别处理validation支撑GET的local预算归属、配置原账本unknown向wrapper传播、以及仅configuration Namespace的canonical重复reviewer扫描；均尚未冻结、部署或完成验收，不预写通过。用epoch替换完整fresh grants的方案已 只读审阅明确拒绝 (`artifacts/M11/m11-fixed-reader-epoch-only-rejected-source-review-20261015-original.json`, not public)：合法绑定自然expires_at到期可以不触发任何epoch变更，不能证明权限保持；该替换未实施。继续保留完整当前权限与原截止约束，在新修复冻结后用全新意图验证，旧全量/旧秘密扫描范围及M11/commercial=false保持。

## 11. 3536全量回归通过，新配置自然执行仍待终态

本节记录2026-10-15 17:45 UTC的检查点，不预写自然执行结果。当前候选`3536a33439cfd9c7997f8dc99bc66f113f8010441185d454388829e9220a9cf9`修复真实私有validation支持读取误占单次业务GET预算，以及未知失败的安全状态传递；configuration Namespace的重复canonical读取收敛保留完整SQL条件和最终Native检查，未改变原窗口、30秒Candidate期限、5分钟claim或聚合预算。

本轮固定输入全量报告 (`artifacts/M11/m11-frozen-full-source-typecheck-isolated-build-meter-closure-v2-20261015-original.json`, not public)：输入摘要`c04a7bb2bcfd6a6e4183181bbebf11abb892c4994298be8160c3953fa3b7c744`，1,801份输入（1,796份Source/config及5份手册），608测试文件、14,100/14,100通过、0失败/跳过/todo；三端类型检查和三端隔离构建真实退出均0。Source前后、服务正在使用的repo dist元数据及decK二进制保持，手册构建入口和M11章节已采集。该轮不代表真实定时或生产验收，也不覆盖其后合入的Candidate固定读取三文件和新测试。

前轮全测原失败 (`artifacts/M11/m11-meter-closure-first-full-regression-failure-20261015-original.json`, not public)保留：63项旧fixture缺少新bootstrap适配、15项因Chromium临时Unix socket路径过长未执行。两组闭合fixture适配 (`artifacts/M11/m11-legacy-read-fixture-adapters-frozen-source-20261015-original.json`, not public)64项通过、保留全部旧断言及完整generic路径；新轮仅缩短验收TMPDIR，浏览器启动诊断 (`artifacts/M11/m11-meter-closure-first-browser-harness-diagnosis-20261015-original.json`, not public)未修改或跳过浏览器测试，完整新轮现已通过。

3536实际部署 (`artifacts/M11/runs/20261015-persistent/meter-closure-candidate-runtime-original.json`, not public)前核对410份API输入和38条迁移，未过期执行安全计数全0并备份；仅停止/启动自有API同一容器，ready200。未修改Kong镜像/源码、旧失败意图或原期限。原SID显式刷新 (`artifacts/M11/runs/20261015-persistent/original-console-sid-refresh-before-meter-closure-original/native-verification.json`, not public)仅刷新当前浏览器会话，未续授权期限。

全新独立审批Service夹具实际201 (`artifacts/M11/runs/20261015-persistent/configuration-service-scope-fresh-service-meter-closure-original/native-verification.json`, not public)。新自然配置准备 (`artifacts/M11/runs/20261015-persistent/configuration-natural-service-scope-meter-closure-prepare-original/configuration-natural-verification.json`, not public)通过，工单`6065e959-4b22-4121-a655-360120b96707`、日程`592cfbaa-7c1a-459e-9f23-060b912ae6b4`，retries预期5→4；原窗口17:45:01.413–17:50:11.413 UTC。到期前只读SQL (`artifacts/M11/runs/20261015-persistent/configuration-meter-closure-before-natural-due-original.json`, not public)为active且claim/执行/mutation均0；自然到期后只读SQL (`artifacts/M11/runs/20261015-persistent/configuration-meter-closure-after-natural-due-original.json`, not public)为claimed、恰一claim，原authority/lease截止17:50:05.816 UTC，尚无执行/mutation。必须继续观察原期限内终态、真实Kong回读和审计，不手动tick、不重放或延时。

Promote的固定Candidate私有void读取草稿独立审阅 (`artifacts/M11/m11-fixed-candidate-read-group-independent-draft-review-20261015-original.json`, not public)未发现具体Source安全阻断，三份审阅产品字节已合入工作区，未测试或部署。保持每个实际响应完整Material授权、显式完整closing及原HTTP/Redis尾部；不承诺相同的中间GET轨迹或元数据原子观察。新测试、真实30秒内完成及全新Promote意图均仍待。

下一步按顺序完成本次配置自然终态及真实回读、全新门户发证/代理验证/吊销、新Candidate完整Source测试与独立构建后部署、全新Promote发布，再补审批撤权/故障/通知/回滚及最终审计、完整凭证扫描与生产部署验证。所有旧失败/uncertain/claimed保留，**M11与commercial仍为false**。

## 12. 当前真实终态及下一修复：总预算与预检局部预算分别记录

3536的HTTP终态观察 (`artifacts/M11/runs/20261015-persistent/configuration-natural-service-scope-meter-closure-terminal-http-original/configuration-natural-verification.json`, not public)为false，独立原窗口后SQL (`artifacts/M11/runs/20261015-persistent/configuration-meter-closure-after-original-window-original.json`, not public)和状态一致性核验 (`artifacts/M11/runs/20261015-persistent/configuration-meter-closure-terminal-concordance-original.json`, not public)确认：一claim、一条original-execution uncertain outcome；日程、外层工单/执行/当前步骤、配置作业/子执行/步骤均uncertain，Service原值5保持，未达到预期4。此前外层failed/内层uncertain、日程滞留claimed的问题已在新case实证收口；这不代表配置发布成功。持久mutation行0也不能证明从未尝试INSERT，事务中的互绑校验可能回滚。

原完整API日志私有保存；首次结构抽取 (`artifacts/M11/runs/20261015-persistent/configuration-meter-closure-budget-structural-diagnostic-original.json`, not public)因控制台ANSI颜色未取到字段，后续只移除ANSI的抽取勘误 (`artifacts/M11/runs/20261015-persistent/configuration-meter-closure-budget-ansi-corrected-diagnostic-original.json`, not public)核定原frame为scheduled-workflow/purpose configuration，calls=501、limit=500。这里是聚合预算，不是此前maxCalls1观察者；原预算没有增大。固定输入后的短期CPU采样 (`artifacts/M11/runs/20261015-persistent/configuration-meter-closure-natural-cpu-sampling-original.json`, not public)仅用于定位重复序列化/SQL工作，容器内loopback inspector已关闭，不作功能或性能通过结论。

Candidate固定void读取三文件及54新例完成583项专项、API类型/隔离构建 (`artifacts/M11/m11-fixed-candidate-read-group-focused-source-20261015-original.json`, not public)。首轮355/378因新测试缺少Runtime.secrets注入失败保留，修正仅测试布线；审阅产品字节保持。Root全API冻结/编译 (`artifacts/M11/runs/20261015-persistent/candidate-fixed-group-candidate-source-freeze-original.json`, not public)及同一自有API实际部署 (`artifacts/M11/runs/20261015-persistent/candidate-fixed-group-candidate-runtime-original.json`, not public)通过，当前摘要`3dd8b422f499b8f3dada99a54520bc0e38a048ec0fdea040c1d9ecd438607c5e`，38迁移、ready200。该专项及实际启动不替代全量；本轮1,802输入摘要`95b41af2931abc0e564969212c87852072f3c41b9405a66e34750116a11d2fe6`的全测/三端类型/隔离构建正在运行，未提前记通过。

新Portal case `meter-closure-20261015`的preflight至activate前12阶段通过，工单`6af495cf-21f7-490d-981c-43aecfb47ae9`、日程`96533ea0-bd14-4a5d-955c-f56eb157bc89`，原窗口18:04:13.323–18:10:13.323 UTC，自然claim的原授权截止18:09:26.040 UTC。首份SQL观察 (`artifacts/M11/runs/20261015-persistent/portal-meter-closure-before-natural-due-original.json`, not public)文件名为before-due，但实际采集18:04:34已过due、状态claimed；以报告真实时间和事实为准，不当作到期前证明。后续SQL (`artifacts/M11/runs/20261015-persistent/portal-meter-closure-natural-progress-second-original.json`, not public)为failed且有一条原执行failed outcome；首Consumer操作错误 (`artifacts/M11/runs/20261015-persistent/portal-meter-closure-failure-code-original.json`, not public)为KONG_EXECUTION_CALL_LIMIT，remoteStarted=true、remoteCompleted=false，尚不能据此声称零发送。内部结构诊断 (`artifacts/M11/runs/20261015-persistent/portal-meter-closure-budget-structural-diagnostic-original.json`, not public)核定为internal-read/purpose entity-preflight，local calls=5、limit=4；不是配置case的聚合500。这次未发证，API Key代理成功/吊销仍待，不重放旧case。

当前审计全链 (`artifacts/M11/runs/20261015-persistent/candidate-fixed-group-current-audit-all-chains-readonly-original.json`, not public)以当前runtime角色在REPEATABLE READ READ ONLY事务核验1,118行/3链、序号/前后哈希/JSON patch全部正确；不覆盖其后新增写入，不等于关键写入100%关联覆盖。

下一候选同时准备两项独立修复：只将真实单路径entity-preflight/maxCalls4纳入私有validation支持读取的局部计数区分，业务自身4次重试、所有聚合/validation额度及权限不变；配置只合并同一phase的原job/execution重复检查，保留不同step/packet、初始完整Native复核和最终正式canonical SQL，claim/capture/Promote保持原路径。独立审查已拒绝以普通ledger身份观察替代正式审批，发现并修正开头await后异常丢失witness释放的草稿问题，另检查窄SQL facade、原Context证明expiresAt稳定及真实授权自然到期。新Witness只作一次比较材料，不缓存授权或生成Native许可。以上仍是TEMP草稿，没有部署或实测结论。

**当前M11及商用验收仍未通过**。继续顺序为临时补丁独立复核→针对性真实组件测试→完整输入回归/构建→新候选部署→全新配置/Portal/Promote意图自然执行→撤权/故障/回滚/通知及最终审计、完整凭证扫描、生产部署验证。旧失败、原期限和发送未知记录均保持。

## 13. 复连核验与整合源码回归

3dd8对应完整冻结回归 (`artifacts/M11/m11-frozen-full-source-typecheck-isolated-build-candidate-fixed-group-20261015-original.json`, not public)已于18:15 UTC通过：1,802输入、609文件14,154/14,154测试、0失败/跳过、三端类型和隔离构建全部退出0。此后新增的预检计数、Origin组合及canonical比较witness不在该轮范围，需另做新固定输入全量。

环境重新连通后的只读核验 (`artifacts/M11/runs/20261015-persistent/current-environment-reconnect-readonly-original.json`, not public)确认当前API仍为同一容器、原17:58:21 UTC启动，410份绑定Source与原3dd8摘要逐份匹配、health ready200；8个自有验收容器健康。原Portal工单复连后SQL (`artifacts/M11/runs/20261015-persistent/portal-meter-closure-after-environment-reconnect-original.json`, not public)保持failed及一条original-execution failed outcome，未重发旧申请、未发证。连接恢复不作为主机重启、异机灾备或原失败恢复成功证明。

单路径预检局部计数修复 (`artifacts/M11/m11-portal-preflight-four-meter-source-verification-20261015-original.json`, not public)完成715/715专项、API类型及隔离构建；保留旧Source4/5拒绝的反例与首轮fixture断言失败。此处仅分离真实私有validation支持读取与既有单路径业务预检额度，业务4次、聚合500次及所有期限不增大。未部署或完成新门户发证。

组合检查点六文件经独立Source复核 (`artifacts/M11/m11-combined-origin-canonical-checkpoint-independent-source-review-20261015-original.json`, not public)后首次实跑86项，45通过/41失败，定位为冻结SQL门面与CurrentIdentity内层Proxy的JS描述符兼容性问题。只把四个方法改为稳定get-only访问器、保留null原型/冻结/原拒绝闭包，独立窄复核 (`artifacts/M11/m11-combined-origin-facade-accessor-independent-source-review-20261015-original.json`, not public)核对其余权限、范围、lease、期限、顺序和额度字节未改；396项专项 (`artifacts/M11/m11-combined-origin-facade-accessor-focused-source-20261015-original.json`, not public)全部通过。原失败、测试自身同步/异步断言勘误均保留。新的canonical/真实组件整合专项仍在运行，不把旧Source审阅或类型通过作为该整合功能通过。

真实PostgreSQL绑定到期回滚试验 (`artifacts/M11/runs/20261015-persistent/console-binding-wall-clock-expiry-rollback-trial-v3-original.json`, not public)证实事务视图仍返36项、实际绑定已按墙钟到期且补充过滤返0，试验后绑定/用户/全局epoch与原值相同。此证据验证SQL时钟边界，不代表新witness已在业务执行中通过；未修改历史SQL005或Kong数据库。

当前仍须完成新整合Source专项/全量与隔离构建、新候选启动及全新配置/Portal/Promote自然执行，再验证余下撤权/回滚/通知/故障及最终商用准入。**M11、真实正向链及商用整体验收仍未通过**。

## 14. 6438组合检查点已部署；全量通过，源集群新激活被旧未知影响面阻断

本节记录截至19:27:18 UTC的公开观察事实，并列明进行中工作。历史失败、原窗口、原批准及发送未知记录均保留；**M11整体验收、生产发布与商用准入仍未通过**。

### 本轮源码、类型与隔离构建

新固定输入完整报告 (`artifacts/M11/m11-frozen-full-source-typecheck-isolated-build-combined-checkpoint-20261015-original.json`, not public)于19:14:18 UTC落盘：1,807份输入（1,802份Source/config及5份手册），前后摘要均为`a1bf34365f65c96de1594f199923d1ea691fad4b8390d1da64a764d7dbfe93d7`；613测试文件、1,468个suite、14,346/14,346项通过，失败/跳过/todo均0。完整测试、三端类型检查、三端隔离构建七步实际退出均0；正在服务的仓库dist共454项元数据及decK二进制保持。该轮取代3dd8的14,154项作为本候选源码/构建门禁，不代表真实业务自然执行或商用通过。两份主手册在这轮后另有内容更新，新增文档字节及其构建需单独验证，不能记入这份冻结报告。

普通配置组合检查点经过六文件独立Source复核 (`artifacts/M11/m11-combined-origin-canonical-checkpoint-independent-source-review-20261015-original.json`, not public)、访问器兼容性窄复核 (`artifacts/M11/m11-combined-origin-facade-accessor-independent-source-review-20261015-original.json`, not public)和396项专项 (`artifacts/M11/m11-combined-origin-facade-accessor-focused-source-20261015-original.json`, not public)。后续真实组件受控整合专项 (`artifacts/M11/m11-origin-canonical-backend-integrated-source-tests-20261015-original.json`, not public)新增67项及相关195项回归全部通过、固定输入无漂移；这些专项已被新全量收集，不与14,346重复相加。测试保留完整执行人与全部审批人的权限/绑定、真实时钟到期、原上下文/句柄、两端门禁及失败关闭约束；受控SQL行和传输适配器不能替代真实PostgreSQL事务、Native写入或性能验收。首次86项中41项失败及后续测试自身断言勘误原件继续保留。

### 自有验收API部署

6438冻结报告 (`artifacts/M11/runs/20261015-persistent/combined-checkpoint-candidate-source-freeze-original.json`, not public)确认API Source摘要为`6438d338852f559f2440bc9a0e3bebf0f434c8e39e796cf1fbefc133dc0df0ad`，410份API输入、38条SQL迁移，复用本轮通过的370份隔离API编译产物，输入及复制产物前后稳定。实际部署报告 (`artifacts/M11/runs/20261015-persistent/combined-checkpoint-candidate-runtime-original.json`, not public)确认未过期执行安全计数全0并完成控制台备份后，仅重启自有验收API的同一容器；19:15:17.242 UTC启动、ready200、迁移仍38条。未修改Kong源码/镜像、旧失败或未知日程、原计划窗口和会话。

该候选已包含门户单路径预检local4预算归属修复，但尚无修复后全新门户发证实证。当前普通配置组合路径保留Promote/sourceScopes的原有检查；Promote双来源组合支持仍在TEMP设计阶段，未进入产品Source，不能宣称已获得相同优化或发布通过。

### 新源集群配置case：激活409，无自然执行

全新源集群工单`3b6cc0ed-0e74-4932-af67-33d6597202ab`、日程`bf076892-6ea0-4106-84da-f85a69d01a06`原计划将新Service的retries从5改为4。原准备/激活报告 (`artifacts/M11/runs/20261015-persistent/configuration-natural-service-scope-combined-checkpoint-prepare-original/configuration-natural-verification.json`, not public)为false：准备与独立批准后，激活返回409 `WORKFLOW_SCHEDULE_PHYSICAL_IMPACT_CONFLICT`。该原stage不重发，不通过更换请求键、延长窗口或改写旧未知结果取成功。

19:20:01 UTC只读SQL (`artifacts/M11/runs/20261015-persistent/configuration-combined-checkpoint-before-natural-due-original.json`, not public)确认该日程仍pending-approval，claim/outcome、workflow执行、配置执行、mutation及nestedOrigin均0；workflow为approved/revision2，配置作业waiting_approval。该文件名含`before-natural-due`，但实际采样晚于原notBefore 19:19:37.345 UTC，只能按报告实际时间解释，不能称为到期前观察。

19:25:31 UTC影响面与目标范围只读核验 (`artifacts/M11/runs/20261015-persistent/combined-checkpoint-activation-conflict-target-scope-readonly-original.json`, not public)确认：该源日程与旧`592cfbaa-7c1a-459e-9f23-060b912ae6b4`共享实际影响面，旧日程仍uncertain，故拒绝新激活。旧unknown的保留与冲突拒绝是本次实际安全行为，不等于正向配置发布验收；0 mutation账本行也不将旧未知改为已知未发送。未清理旧保留、改URL别名或transport scope来绕开冲突。

同份只读核验确认已登记的真实独立目标Kong节点健康、版本1.5.1、approval模式，两类format2定义active，观察时目标未决schedule/mutation均0。随后真实不同网关上的全新普通配置case完成准备/独立审批/激活 (`artifacts/M11/runs/20261015-persistent/configuration-natural-service-scope-target-combined-checkpoint-prepare-original/configuration-natural-verification.json`, not public)：新工单`960b76cf-1c4c-4428-a6af-1e355c84dd06`、日程`a09d2ba3-d205-4e1b-b41e-cbcb33785c44`、作业`81f7bb2c-889a-4e7f-be45-2b81fbdf92ef`，预期新Service retries 5→4。19:27:18 UTC到期前只读观察 (`artifacts/M11/runs/20261015-persistent/configuration-target-combined-checkpoint-predue-readonly-original.json`, not public)为active且claim/outcome/执行/mutation均0，原notBefore为19:28:55.991、windowEnd为19:34:05.991 UTC。此case不是源网关的地址别名，不接续或补发原失败；当前仍在等待自然执行，不能由激活成功预写claim或apply成功。目标与源仍共享PG11进程/存储和故障域，既有隔离限制不变。

### 余下闭环顺序

继续完成目标网关全新普通配置自然终态与Admin API回读；再以新材料验证门户发证/凭证代理可用/吊销及Promote自然发布。随后补齐执行中撤权、回滚、窗口和故障路径、通知实际投递、当前全审计链、包含真实已发API Key的完整秘密扫描及生产部署/恢复验证。手册后续新增字节另做专项与隔离构建；新Source变更另建冻结门禁。所有新结果单独落盘，历史失败与未决事实不覆盖。

## 15. 目标配置自然单claim后uncertain：未发布成功，原到期和未知影响面保持

本节补录19:34:21–19:35:55 UTC的真实终态，承接第14节19:27:18的active/claim0采样。前一采样当时成立，保留原文；它不是当前终态，也不作为成功证据。**M11、正向配置发布及商用整体验收仍未通过。**

原期限到期后的实际只读SQL (`artifacts/M11/runs/20261015-persistent/configuration-target-combined-checkpoint-after-original-expiry-original.json`, not public)确认：目标日程`a09d2ba3-d205-4e1b-b41e-cbcb33785c44`只有一个自然claim `ee628a90-e88c-49fb-a958-420cbfdbb9db`，日程、工单、外层执行/步骤及配置子作业/执行/步骤均为uncertain，nestedOrigin为1；日程有一条`original-execution`来源的uncertain outcome。配置错误为`WORKFLOW_SCHEDULE_VALIDATION_EXPIRED`。原authority/lease截止19:34:05.589 UTC、原windowEnd 19:34:05.991 UTC均已到期，未延长或借新句柄续原授权；子执行自身更晚的expiresAt不改变外层原授权和窗口。

原mutation `1690fc7a-b7bc-4b95-b1a9-58dbb9fc50d7`为failed，`remoteStarted=true`、`remoteCompleted=false`。这些字段不能改写为已知未发送，也不能用补偿新请求悄然补发。原case不重试、不更换请求键或重建原审批。后续实际BFF终态观察 (`artifacts/M11/runs/20261015-persistent/configuration-natural-service-scope-target-combined-checkpoint-terminal-http-original/configuration-natural-verification.json`, not public)整体false，因为实际uncertain而非预期succeeded；原失败报告保留。

诊断与实际Service回读 (`artifacts/M11/runs/20261015-persistent/configuration-target-combined-checkpoint-expiry-native-diagnostic-original.json`, not public)证实retries仍为5，未达到期望4，因此不是配置发布完成。目标节点19:28:50–19:35:55 UTC日志区间累计686条GET/200；这是该节点整个时间区间的计数，不能精确归属于某个检查点或该工单，也不构成原生写入已知未发送的证书。读取密集度支持继续检查校验成本，不能由日志计数或源码专项断言性能已经通过。

当前Source成本审查已定位重复Native校验链，修复仍待实施和新固定输入验证；这不是源集群409的修复，也不是用不同目标重新提交旧意图。Promote组合支持仍为TEMP设计、未进入产品Source；其TEMP专项初轮因适配器错误28通过/36失败，原失败保留，不计产品回归通过或部署成功。

配置unknown影响面目前尚无完整的产品安全resolution流程；现有只读reconcile不释放保留。该能力列为生产故障恢复待办，不能通过直接清表、改写旧unknown或改地址别名绕开。后续需保留原事实，完成可审计、按真实发送和远端状态证据决策的正式恢复路径，再做相应权限、并发和故障验收。

下一步先修复重复校验成本并完成独立审阅、专项/完整冻结门禁，再在不续原窗口、claim或批准事实的前提下安排新的合法验收材料。门户发证/吊销、Promote自然发布及撤权/回滚/通知、当前完整审计/凭证秘密扫描、生产部署/恢复仍待；不因本次未知一致收口而宣布商用通过。

## 16. 校验成本修复与Promote组合已进入Source；新整合全量进行中

本节记录19:53 UTC阶段检查点。运行API仍为6438d338，旧目标配置uncertain和源集群409保持；新增Source尚未部署，新整合全量尚无完成结论。**M11整体验收、生产发布和商用准入仍未通过。**

### 两项校验成本窄修复

配置Native重复load专项 (`artifacts/M11/m11-configuration-native-single-load-focused-source-20261015-original.json`, not public)7文件165/165项通过，含24项新增，固定输入无漂移、实际退出0；独立Source复核 (`artifacts/M11/m11-configuration-native-single-load-independent-source-review-20261015-original.json`, not public)无必须修复阻断。仅在原私有proof/阶段授权绑定下去除重复step load，受控Source计数prepare/response由2到1、before-send由3到2；完整当前权限、Native verifier、current-before/Target append GET及最终step检查保持。这是Source直接load计数，不能当作实际Native GET减少数量、总预算或时延通过。

定时V2步骤类型发现专项 (`artifacts/M11/m11-scheduled-step-kind-hint-focused-source-20261015-original.json`, not public)11文件355/355项通过，含54项新增，固定输入无漂移；独立复核 (`artifacts/M11/m11-scheduled-step-kind-hint-independent-source-review-20261015-original.json`, not public)无阻断。仅用精确关联的SQL kind hint选择后续验证分支，该hint不授予权限或返回能力；返回前仍以原step/trusted/Namespace完整认证AEAD、规范化材料、依赖、运行状态与全部当前审批人。范围包含所有真实scheduled V2调用方（门户步骤及外层配置metadata wrapper），HTTP、V1及嵌套配置原分支保持。专项不相加到上一轮14,346，也不替代新运行性能验收。

### Promote双来源组合：已合入，正式整合验证待完成

独立Source审阅 (`artifacts/M11/m11-promote-combined-origin-independent-source-review-20261015-original.json`, not public)核对双AEAD的J0/P0→不同J1/P1来源、完整执行人/全部审批人权限和自然绑定到期、两端registry、原期限及最后单调时钟、原Native逐响应/parent/workspace/secret/源fingerprint与membership/EOF检查；无必须修复阻断，不在组合失败后降级重试。

受控诊断与应用记录 (`artifacts/M11/m11-promote-combined-origin-source-diagnostic-and-application-20261015-original.json`, not public)确认隔离Source两文件64/64通过，使用CLI每case 30秒测试wall cap、实际退出0、产品摘要无漂移；六份产品与四份测试已进入仓库Source。正式新增36case组合provider专项显式使用同样30秒测试wall cap，只调整测试等待上限，未改断言、夹具业务期限或产品Candidate/claim/window/调用预算。初轮适配器草稿28通过/36失败保留；后续10秒测试cap下的原中断进程exit130、部分23通过/3超时失败及无完整组结果也保留，不改记通过。当前新整合全量将核验正式应用后的字节，诊断64项不替代该轮结果。

旧inventory没有封存历史源连接revision/secret，因此此扩展比较的是当前检查点open-to-close身份，不能外推author-to-execution历史身份已认证；每组合组仍至少六次完整SQL/AEAD Promote材料观察，真实时延和预算待验。6438运行候选未包含这六份新产品，不能宣称已部署或已发布成功。

### 手册、审计与新专属验收对象

手册后续专项 (`artifacts/M11/m11-operator-manual-followup-focused-20261015-original.json`, not public)7/7通过，原有标题行保持、115个标题无重复最终ID、22个支持的文档链接无缺失，新两主手册内容均进入独立Console Web产物；修正独立副本遗漏Portal引用文件后构建退出0。首轮独立副本构建失败保留；本专项不改写原14,346冻结输入，不宣称实际浏览器业务或生产部署通过。

19:39:28 UTC当前审计链只读核验 (`artifacts/M11/runs/20261015-persistent/combined-checkpoint-target-expiry-current-audit-all-chains-readonly-original.json`, not public)实际runtime角色、REPEATABLE READ READ ONLY下验证1,193行/3链及全部JSON patch正确，退出0。该采样不覆盖其后的夹具或其他新写入，不外推关键写入覆盖率100%。

原共享影响面key核对 (`artifacts/M11/runs/20261015-persistent/configuration-shared-impact-reference-source-confirmation-original.json`, not public)确认原409共享key精确对应Service.host=`echo`对Upstream.name的引用，并非整个cluster被一把锁占用。核对没有发送Native请求或改变physical locks，旧uncertain保留不动。后续准备了新专属Upstream名称及绑定的Target、Service作为独立新验收对象：Upstream (`artifacts/M11/runs/20261015-persistent/configuration-distinct-upstream-native-load-fixture-upstream-original/native-verification.json`, not public)、Target (`artifacts/M11/runs/20261015-persistent/configuration-distinct-upstream-native-load-fixture-target-original/native-verification.json`, not public)、Service (`artifacts/M11/runs/20261015-persistent/configuration-distinct-upstream-native-load-fixture-service-original/native-verification.json`, not public)三张新独立审批工作流执行均实际201。它们不修改旧scope/claim/lock/endpoint或既有Service，也不接续旧意图；夹具创建不等于新候选定时配置已成功。

### 当前门禁与下一步

Root于19:52:50 UTC开始新的1,813份固定输入整合全量，运行目录`/tmp/kp-m11-full-20261015-fsjl6udx`；当前只记录进行中，不预写测试、类型或构建通过。待新候选完整测试、三端类型/隔离构建通过并核对固定字节后，才部署自有验收API，再以新专属对象建立全新合法配置case，验证自然claim/终态及Admin API回读，然后推进新门户发证/吊销与Promote自然发布。

unknown配置保留的正式安全resolution、撤权/故障/回滚/通知、最终当前审计与真实已发凭证秘密扫描、生产部署/恢复仍是商用待办。新Source专项和夹具201不释放旧unknown、不延长旧授权，也不改变M11/commercial=false。

## 20:18 UTC 检查点：828候选部署，全量通过但自然配置仍触发总调用预算

本节补录新全量、部署与20:17:59 UTC前的实际观察，承接前节进行中状态，不改写任何旧失败。**M11及商用整体验收仍未通过。**

### 最新固定Source门禁与实际运行候选

新完整回归原报告 (`artifacts/M11/m11-frozen-full-source-typecheck-isolated-build-native-load-promote-20261015-original.json`, not public)已完成：1,813份固定输入，包括1,808份Source/config及当前5份手册，前后SHA256均为`27533fb9c4b687415ea21387d114c784abceae815757fc51e01c092436b9aad6`；616测试文件、1,474个suite、14,461/14,461项通过，失败/跳过/todo均0。API、Console Web、Portal三端类型检查及三端隔离构建均实际退出0，仓库既有dist元数据与decK保持。当前手册字节已纳入本轮，无需将较早14,346轮的范围追溯扩大。本轮仅验证配置的Source/受控测试与构建，不是实际HTTP、自然worker、Native写入、性能或商用准入证明。

新API冻结 (`artifacts/M11/runs/20261015-persistent/native-load-promote-candidate-source-freeze-original.json`, not public)摘要为`828f33504a10704aa881641cf373e3f4dccbdef52ebcc3ed04f2b013700a4890`，410个API输入/38迁移，复用上述通过轮的370份隔离编译产物。包含配置Native单次load、scheduled V2 kind hint及Promote双来源组合支持。实际部署原报告 (`artifacts/M11/runs/20261015-persistent/native-load-promote-candidate-runtime-original.json`, not public)确认：安全计数均0、控制台库备份后，仅重启同一自有验收API容器，于20:05:19.566 UTC启动、ready200；未重放旧failed/uncertain日程，未改原计划窗口或会话，未改Kong源码或镜像。部署和健康通过不等于Promote或门户业务通过。

20:14:23 UTC重连原观察 (`artifacts/M11/runs/20261015-persistent/native-load-promote-environment-reconnect-readonly-original.json`, not public)的`verified=false`来自继续按旧6438输入核对，`runtimeOld6438InputsMatch=false`；同份报告仍记录同一API容器、新20:05启动时间、ready200及38迁移。后续核对新828摘要与上面原冻结/部署报告，确认已部署新候选；不能将旧候选假设不匹配解读为环境损坏，也不将环境重连、命名卷或ready200当作灾备恢复验收。

平台生产依赖公告原审计 (`artifacts/M11/m11-platform-production-dependency-advisory-audit-20261015-original.json`, not public)实际退出0，info/low/moderate/high/critical及total均0，6份复制的当前平台manifests/lock前后保持。范围仅为该锁文件当前报告的npm生产依赖公告，不包含Kong、基础OS、运行配置或应用授权逻辑，不独立证明平台可商用。

### 新独立Upstream配置case的原始终态

新专属Upstream/Target/Service夹具分别独立审批201后，以全新意图完成配置准备、独立审批及激活 (`artifacts/M11/runs/20261015-persistent/configuration-natural-distinct-upstream-native-load-prepare-original/configuration-natural-verification.json`, not public)。工单`254ea5f8-c8aa-4398-9cde-c559f1dff93d`、日程`8ba604ab-1b4f-49d0-9b54-469f610c1434`、配置job`9ba2acaa-eb8c-4320-a07d-959519a111f3`，原window为20:10:03.442–20:15:13.442 UTC；不是源共享echo引用冲突的原工单重放，也没有释放旧影响面保留。

20:14:59 UTC实际只读SQL (`artifacts/M11/runs/20261015-persistent/configuration-distinct-upstream-native-load-current-readonly-original.json`, not public)确认自然claim恰1、nestedOrigin为1，schedule/workflow、外层执行/步骤、配置子job/执行/步骤一致uncertain，单条outcome为`original-execution/uncertain`，子job及步骤错误`KONG_EXECUTION_CALL_LIMIT`。原authority/lease截止20:15:09.189 UTC，子执行较晚的期限不延长它；未手动tick、续期、补claim或重放。

mutation `b8197c5d-220b-4419-be83-6ce34ef2116d`为failed、`remoteStarted=true/remoteCompleted=false`。这些早期标记与失败状态不能证明已知未发送。原HTTP终态报告 (`artifacts/M11/runs/20261015-persistent/configuration-natural-distinct-upstream-native-load-terminal-http-original/configuration-natural-verification.json`, not public)因实际uncertain而非succeeded保持false；其`beforeRetries/afterRetries`是计划值，实际回读依据下份诊断。实际结构化预算及回读报告 (`artifacts/M11/runs/20261015-persistent/configuration-distinct-upstream-native-load-budget-diagnostic-original.json`, not public)记录Root `scheduled-workflow`、purpose=`configuration`、calls上限500/当前501，Service实际retries仍5、期望4，`knownNotSentCertified=false`。正向apply仍未通过，不把一致保守终态当作发布成功。

### 剩余Source尺度缺口与后续顺序

只读Source成本复核还发现，普通配置计划含N个不同Service更新、R名审批人时，每次full-scope至少读取N+1项，完整执行的支撑GET下界为`N × (2R + 3) × (N + 1)`，全部计入同一个Namespace的500次总预算。仅R=1、N=10下界已为550次，N=100为50,500次，尚未包括其他必要调用。这是所述普通更新形态的Source成本下界，不是本case逐请求因果归属、实际耗时或压测结论，也不是从先前整节点686条GET日志换算所得。

当前没有普通配置的预算预判或显式分批continuation产品闭环。架构收敛与显式批次两条方案仍在只读研究，尚未预写实现或验收；不能通过增加500预算、续原窗口/授权或伪造proof消除该缺口。下一步须先明确并验证可扩展的执行合同，再以全新合法意图完成配置自然发布、门户发证/吊销及Promote发布；旧unknown的正式安全resolution、执行中撤权/故障/回滚/通知、最终当前审计与完整已发凭证秘密扫描、生产部署/恢复仍待。远程检查点提交与扫描结果另由真实完成记录，不预写通过。

### 20:25 UTC 当前候选重连复核与架构路线评估

按当前828候选重新只读核验 (`artifacts/M11/runs/20261015-persistent/native-load-promote-current-828-reconnect-readonly-original.json`, not public)于20:25:36 UTC记录`verified=true`：410个运行输入与828摘要匹配，同一API容器、原20:05:19启动、ready200、38迁移；activeUnclaimedSchedules、unexpiredClaimedSchedules、unexpiredRunningJobs均0，私密账本仍在，旧意图未重放。前述基于6438假设的false原报告继续保留。这只是当前运行连续性及采样事实，`hostRebootOrDrProven=false`，不证明主机重启恢复、DR或业务成功。

两条架构路线仍处于评估：当前优先保留V2，研究以固定复合校验及私有`StepReadInput`收敛重复读取；V3长期桥接路线需要新的来源、DAG以及快照/回收合同，不能直接套用现有执行证明。两者均尚未实现或验收，不改变当前828实际失败、原预算/期限及M11/commercial=false。

### 20:29 UTC 当前全审计链只读核验

最新审计原报告 (`artifacts/M11/runs/20261015-persistent/native-load-promote-terminal-current-audit-all-chains-readonly-original.json`, not public)于20:29:50 UTC实际退出0：使用当前runtime角色及`REPEATABLE READ READ ONLY`事务，验证当前1,248行/3条链，全部JSON patch有效。该结果证明采样中已有审计行的链完整性，不覆盖之后新增写入，也不能推导全部关键写操作100%审计覆盖；M11及商用验收仍未通过。

## 18. 828候选检查点安全扫描与下一轮范围

完整当前材料首次扫描因匹配模式预算拒绝，尚未扫描任何文件，原失败报告保留。434份实际保留秘密材料随后按完整集合分为4批，分别由未修改的原扫描器执行；四批均退出0、0发现，每批覆盖相同代码、三端隔离构建、17份当前/归档自有容器日志及1,248行实际审计。分批没有提高扫描器预算或排除秘密；最后追加文档/报告的增量字节仍需全部批次匹配器关闭核验，最终结果以聚合关闭报告 (`artifacts/M11/runs/20261015-persistent/native-load-promote-terminal-current-secret-scan-aggregate-original.json`, not public)为准。checkpoint profile的API Key材料0、finalCredentialComplete=false，不证明发证、吊销或商用通过。

后续独立Source检查确认，普通配置缺少完整执行预算前置判断；现有Promote估算没有完整覆盖全部审批人与执行开销。原M8配置Job/Plan的15分钟材料期限继续约束M11审批和定时，小时级审批/远期窗口尚未闭环。本轮优先实施显式SQL阶段合同以消除重复全计划Native读取，保持最终发送前及响应校验；预算准入、耐久配置意图和未知结果恢复仍需独立实现及真实验收，不能由这一检查点推导完成。


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

## 22. 耐久材料已实际登记，短材料自然发布仍未通过（截至22:08 UTC）

本节追加第21节之后的实际结果，旧Source、原期限、失败与unknown均保留。**耐久材料登记、只读页面、源码检查和自然发布是独立验收项；当前M11/commercial仍为false。**

### 22.1 652465e6与SQL038的真实部署、最小权限

耐久域Source专项 (`artifacts/M11/m11-durable-configuration-reviewed-source-focused-20261015-original.json`, not public)记录27份集成文件、16个专项文件461/461项、API类型检查退出0，输入保持；该专项本身没有执行实际SQL或业务。随后隔离冻结/编译 (`artifacts/M11/runs/20261015-persistent/durable-configuration-candidate-source-freeze-original.json`, not public)实际退出0，416个API输入、375份编译产物，Source SHA256为`652465e68dbcaf6fa5d5fa70f4ddbab2effb085655a6f5f63315b2b1699fbb6f`，前后输入不变，未写仓库dist。

SQL038真实DDL回滚试验 (`artifacts/M11/runs/20261015-persistent/durable-configuration-sql038-rollback-dryrun-original.json`, not public)退出0后，实际迁移/部署 (`artifacts/M11/runs/20261015-persistent/durable-configuration-candidate-runtime-original.json`, not public)先核验未到期运行job、未领取active日程和未到期claimed日程均0，备份控制台库，仅停止并重启同一自有验收API；SQL000–038正式记录共39条，于21:43:36.756 UTC启动、ready200。没有重放旧失败/未知日程，没有修改旧计划窗口、会话或Kong源码/镜像；这是隔离部署，不是生产发布。

真实runtime凭证只读SQL (`artifacts/M11/runs/20261015-persistent/durable-configuration-runtime-nosu-privileges-original.json`, not public)确认`kongpilot_lab_app`非superuser，CREATE ROLE/DB、BYPASSRLS、REPLICATION、schema CREATE均false，成员关系0；`configuration_durable_bindings`和`configuration_durable_issues`均仅有SELECT/INSERT，UPDATE/DELETE/TRUNCATE/TRIGGER/REFERENCES为false、运行角色不是owner。五个校验函数使用固定`search_path=public, pg_temp`且`securityDefiner=false`。该证明验证实际角色与DDL，不代表业务图、并发互斥或执行链已通过。

### 22.2 新长时工单与新计划已登记，原短预览没有续期

真实prepare/submit (`artifacts/M11/runs/20261015-persistent/configuration-durable-long-approval-prepare-submit-original/configuration-natural-verification.json`, not public)于21:44:52.120 UTC观察到新工单`f8393f4e-ec5e-4d9b-b5ac-1e35fb7b1e9e`的提交回执，`scheduleId=null`。其新耐久计划为`cbd4422c-001c-45d0-a363-13887955f031`，材料期限`22:44:45.961 UTC`；来源preview的原期限仍为`21:58:43.827 UTC`。这是一份新的材料域与新工单，不是给旧preview续期；本张约一小时的材料期限不外推为所有类型、任意时长或已批准的生产上限。

原键receipt与新Plan matcher只读核验 (`artifacts/M11/runs/20261015-persistent/durable-configuration-original-key-model-readonly-v2-original/registration-model-verification.json`, not public)于21:49通过：使用真实BFF原键回执及真实前端matcher，没有发新POST。该报告不是浏览器或业务执行验收。

首次浏览器原报告 (`artifacts/M11/runs/20261015-persistent/browser-durable-configuration-plan-readonly-original/verification.json`, not public)因`127.0.0.1:5455`连接被拒绝而失败，原报告保留。随后实际只读浏览器v2 (`artifacts/M11/runs/20261015-persistent/browser-durable-configuration-plan-readonly-v2-original/verification.json`, not public)于22:00:31通过7项检查、产生3张截图：新计划显示真实工单材料期限、没有legacy apply或重复提交入口，展示真实工单链接、retries差异以及等待审批状态。业务写入0、直连Admin请求0、未处理页面错误0；计划页面 (`artifacts/M11/runs/20261015-persistent/browser-durable-configuration-plan-readonly-v2-original/durable-plan-light.png`, not public)、差异 (`artifacts/M11/runs/20261015-persistent/browser-durable-configuration-plan-readonly-v2-original/durable-plan-diff.png`, not public)、等待审批工单 (`artifacts/M11/runs/20261015-persistent/browser-durable-configuration-plan-readonly-v2-original/durable-workflow-awaiting-approval.png`, not public)各自保留。

该次只读观察发生在来源短preview原deadline之后，新工单仍pending、尚未审批或激活排程。**真实等待已跨旧preview期限，但等待超过15分钟后的独立审批、原材料核验、定时执行及代理回读仍未通过整链验收。** 不以只读页面通过代替发布成功，也不沿用旧票、SID或过期窗口。

### 22.3 652独立短材料自然执行为uncertain，未取得未发送证明

另一个全新短材料配置日程prepare/审批/激活 (`artifacts/M11/runs/20261015-persistent/configuration-natural-private-mutation-envelope-prepare-original/configuration-natural-verification.json`, not public)对应W=`78dd2050-aeeb-4d38-b005-7a876a48c7c6`、S=`bf7b6b07-d17c-4f70-bd94-f9b987a53a21`、J=`c391d347-f9fd-4c6a-8fe0-07841e637063`；它不等同于上一小节仍pending的长时工单。原window为21:48:18.265–21:53:28.265 UTC，仅自然领取一个原claim `ea6c4e9c-8e5d-48c8-9c10-468770079ab0`，没有手动tick。

原终态HTTP (`artifacts/M11/runs/20261015-persistent/configuration-natural-private-mutation-envelope-terminal-http-original/configuration-natural-verification.json`, not public)保持passed=false。独立实际BFF/SQL/回读一致性报告 (`artifacts/M11/runs/20261015-persistent/configuration-private-mutation-envelope-terminal-concordance-original.json`, not public)确认日程、工单、外层执行`ecf73fab-79f0-497f-8e28-3796eac9b6f1`及当前步骤、子job/执行`7623ef26-4faf-4bad-b652-d9fee4a89eff`与步骤均uncertain，错误`KONG_EXECUTION_CONTEXT_EXPIRED`；原revision1步骤仍pending，新revision2步骤uncertain，只有一条`original-execution/uncertain` outcome。mutation `31a01bb6-1295-4347-bb3a-0ff27f20e9d3`为failed、`remoteStarted=true/remoteCompleted=false`，实际Service.retries仍为5、目标4。**配置未变化不是未发送证明；没有KnownNotSent证书，不登记NOSEND、不重发原意图。**

真实结构日志 (`artifacts/M11/runs/20261015-persistent/private-mutation-envelope-natural-terminal-context-expiration-diagnostic-original.json`, not public)定位到`internal-read`、`purpose=authorization`、deadline、5000ms、逾期1ms；尚未确认精确调用点，不能把这次错误写成旧120000ms actor frame或提前认定已修复。原authority/lease均止于21:53:24.963 UTC；子执行较晚的22:00:16.173期限不延长外层授权，原window和全部unknown保持。

### 22.4 后续Source、SQL039与剩余门禁

后续固定Service引用/绑定预算修复未登记运行通过。22:08:35已集成独立pre-INSERT绑定阶段Source (`artifacts/M11/m11-mutation-binding-sql-reviewed-source-focused-20261015-original.json`, not public)，补丁摘要`244f00cab6f31d43974645672d11407b900938d49ea00f24dc6f31521cce55fc`，2文件逐摘要吻合；最终33项与55项分别通过，共88项，API类型检查退出0，独审摘要`3cdf812055047ff0e342c9576c492336e854560b64e5d3dc34ee32d799b95b2c`。已撤回候选和既有失败/探索报告完整保留，不改为成功。新阶段保留完整SQL/AEAD/current-party验证，实际读取、INSERT与最终Native校验在阶段外；该报告明确不证明652的authorization 5秒故障原因或已修复，不证明真实自然claim、共享物理事务、Root500预算或生产验收。实际部署仍待。

SQL039的真实控制台DDL回滚试验 (`artifacts/M11/runs/20261015-persistent/durable-configuration-sql039-rollback-dryrun-original.json`, not public)于22:06退出0：事务内新表、索引、固定搜索路径、invoker及4个disposition触发器存在；回滚后仍39条迁移、新表不存在，SQL038摘要前后不变。该试验明确`appliedToRuntime=false`、`actualConstraintRaceAccepted=false`，不是正式迁移或并发竞争验收。

22:07:44已集成SQL039拒绝回执候选Source (`artifacts/M11/m11-durable-configuration-rejection-039-source-focused-20261015-original.json`, not public)，补丁摘要`c94934c535772eb7387b46b12134f0f9b4684e353afa97281418cfd6bf78fe35`，10文件逐摘要匹配；17个专项文件525/525、API类型检查退出0，1,132冻结输入保持。该Source结果包含既有用例，不与461、521、121项相加；真实SQL039迁移、runtime部署、原键被拒绝回执及约束竞争仍待，当前runtime依然652/39条。新域仍拒绝Target append与Promote，不将候选修复扩大为已支持。

最后14,461项整合全量仍只覆盖旧828冻结范围，最后已核对远端仍`d3e1d405`。后续Source、SQL、文档、日志及审计新增字节尚未做最终统一全测/构建/秘密扫描或提交；新长时工单的独立审批和自然完成、预算准入、unknown安全resolution、门户/Promote正向链以及生产恢复/容量等门禁保持待办。

### 22.5 两本手册拟补内容（待实际流程验收后发布）

以下为后续手册编写提纲，**本轮不修改正式用户手册或运维手册，不作为已验收功能说明**。

- 用户手册：区分导入preview与新配置工单的材料期限；提交后使用真实新Plan/工单入口审阅差异和当前状态，不从新域页面再次legacy apply或重复提交。将提交、独立审批、登记排程、激活、自然执行与业务回读分开说明；页面等待审批或材料仍有效均不表示配置已生效。过期或变化后按当前能力生成新材料并重新审批；结果未知先核验原键/原回执，不换键绕过阻断。具体支持类型、期限和成功截图在实际完整链通过后填入。
- 运维手册：补充新旧材料域及不可变期限的区别，部署前控制台库/密钥备份、迁移操作者与runtime角色分离、实际Source/SQL摘要核对及两张事实表只追加权限检查。监控材料到期、排程窗口、claim/lease与执行上下文各自的期限，记录真实等待和自然执行证据；不能通过续旧期限、换SID、删除unknown或单纯加大全局超时恢复任务。SQL039正式升级、拒绝回执核验与并发约束操作须待真实迁移和流程验收后再写入正式步骤。

## 23. SQL039实际部署与原请求拒绝闭环（截至22:24 UTC）

候选冻结与隔离编译 (`artifacts/M11/runs/20261015-persistent/durable-rejection-candidate-source-freeze-original.json`, not public)退出0：Source `a9471b00e019849e63fd9847bf930981ebd8b4d2cb5dfdef91652830a9c41516`，418个API输入、376个JS产物，输入保持。该候选包含039 c949与绑定244，不包含Service完整destination修复。实际升级 (`artifacts/M11/runs/20261015-persistent/durable-rejection-candidate-runtime-original.json`, not public)先验证无未到期执行/active待领取日程，保留控制台完整备份，通过真实migrator应用SQL039；迁移共40条、摘要匹配。同一自有API于22:13:33启动、ready200；原会话、长工单期限、失败和unknown不变，没有修改Kong源码/镜像或连接Kong数据库。runtime真实连接 (`artifacts/M11/runs/20261015-persistent/durable-rejection039-runtime-nosu-original.json`, not public)确认NOSU/无成员关系、无schema CREATE，新rejection表仅SELECT/INSERT，函数invoker与固定search_path正确。

039独审 (`artifacts/M11/m11-durable-rejection-039-independent-review-20261015-original.json`, not public)及前端7文件188项专项 (`artifacts/M11/m11-configuration-rejection-ui039-reviewed-source-focused-20261015-original.json`, not public)已落盘。POST的内部exception虽带receipt，公共ErrorFilter只返回typed409 code/message；必须GET原键取得严格回执才允许归档。旧038写入副本不认识已拒源，生产升级须先排空全部旧配置writer，不宣称混合写版本兼容。

独立新fixture的Upstream/Target/Service通过三次实际独立审批和Native201后，生成新预览 (`artifacts/M11/runs/20261015-persistent/configuration-durable-rejection-prepare-preview-original/durable-rejection-verification.json`, not public)，再经独立审批真实PATCH (`artifacts/M11/runs/20261015-persistent/configuration-durable-rejection-drift-native-original`, not public)将该Service.retries由5改3。随后真实UI显式确认拟改4的原预览，通过一对一release-harness代理原body/key/actor发送唯一BFF命令；实际POST409 `CONFIGURATION_DURABLE_FRESH_DIFF_CHANGED`，实际原键GET返回匹配拒绝事实，没有以状态码单独判定。

首轮浏览器 (`artifacts/M11/runs/20261015-persistent/browser-durable-rejection-original/verification.json`, not public)前三检查通过，第四因Root工具使用JSON.stringify比较对象键顺序而失败；原失败保留，不重发POST。只读恢复浏览器 (`artifacts/M11/runs/20261015-persistent/browser-durable-rejection-readonly-recovery-original/verification.json`, not public)从真实首轮捕获的unknown journal恢复，实际GET后按深相等核验，8项/2截图通过，明确证明内容相同而JSON键序不同；原tuple/key与回执先归档，再只释放对应active事务，刷新仍保留拒绝，旧源不显示创建或legacy apply。恢复过程业务POST为0，未重放原命令。数据库一致性 (`artifacts/M11/runs/20261015-persistent/durable-rejection039-real-http-db-concordance-original.json`, not public)确认拒绝1、正确范围审计1、原源版本1、原源执行/步骤/mutation均0、原键新job及新issue均0；fresh baseline capture确实存在，不能宣称所有控制台元数据写入均0。

越权只读v2 (`artifacts/M11/runs/20261015-persistent/durable-rejection039-readonly-negative-v2-original/verification.json`, not public)4项通过：另一已授权actor读取原键404，跨集群/工作区无回执，未知键404，原owner/范围仍返回原事实。首轮只完成1项后因工具错用不存在的目标locator字段失败，原报告保留；纠正实际目标locator只重做GET。当前审计链 (`artifacts/M11/runs/20261015-persistent/durable-rejection039-terminal-current-audit-all-chains-readonly-original.json`, not public)于22:20:47以runtime只读核验1,514行、3链与全部JSON patch正确，不外推写入覆盖率。

后续仍须实际SQL039两连接锁/约束负测及真正发布正向竞争、过期后的历史原键读取。Source已处分原P的服务端capability投影/新tab旧入口修复正在TEMP，不写成已部署。Service固定destination方案尚未完成；未过滤Upstreams集合的scoped限制 (`artifacts/M11/m11-service-scoped-read-product-boundary-review-20261015-original.json`, not public)是拟部署候选的具体缺口，不能靠super-admin正向推导workspace-admin/tag_group/entity全角色通过。长工单Wf8393f4e仍未审批/激活，其22:44:45原期限不续；自然执行、门户、Promote、完整恢复、最终全测/秘密扫描与正式手册更新仍待。最后远端仍d3e1d405，M11/commercial仍false。

## 24. 2026-10-18 恢复续项与完整验收计划

本节补录第23节之后已经存在的原始证据，并记录本次续作的起点。**M11及平台整体商用准入仍未通过。** 恢复开始时Root观察到`/tmp`临时产物已清空、8个自有`m11-20261015`容器处于Exited255；持久仓库、元数据与备份仍在。该初始观察不等于恢复通过，随后08:34取得的实际API恢复分项见24.3；新业务、监控及完整灾备验收仍分别判断。

### 24.1 10月15日后续原证据补录

- SourceP处分专项 (`artifacts/M11/m11-source-plan-disposition-reviewed-source-focused-20261015-original.json`, not public)记录`f499b215`补丁6文件逐摘要匹配，API专项209/209、Web专项231/231及两端类型检查退出0；不与旧专项相加、不等于真实新tab浏览器通过。随后API冻结 (`artifacts/M11/runs/20261015-persistent/source-disposition-candidate-source-freeze-original.json`, not public)为`b186587f1685c1f45f1cdf40c7434a047f53edcb277c3b2a331506fd5d657539`，418输入/376份编译产物/40条SQL，输入保持、隔离编译0；实际同容器部署 (`artifacts/M11/runs/20261015-persistent/source-disposition-candidate-runtime-original.json`, not public)于22:29:39 UTC启动ready200，保存6,927,789字节备份，没有改旧窗口/SID、重放旧日程或修改Kong源码/镜像。这是10月15日最后有据的运行基线，不是10月18日当前健康证明。
- SQL039真实双连接rollback负测 (`artifacts/M11/runs/20261015-persistent/durable-rejection039-rollback-negative-first-original.json`, not public)于22:26:46通过8项，runtime为`kongpilot_lab_app`，88次查询、两连接，真实观察advisory等待及对应锁、全部显式回滚，无新业务行提交。报告明确`freshTwoWriterCommitRaceAccepted=false`：只持互斥锁的连接不是竞争writer，own-J仅进到既有主键拒绝，不证明合法新图发布、AEAD/HTTP来源或两writer提交竞争。相同source/key的真实发布与拒绝竞争仍待。
- 新SQL039长工单登记 (`artifacts/M11/runs/20261015-persistent/configuration-durable039-long-approval-prepare-submit-original/configuration-natural-verification.json`, not public)于22:28:27.335 UTC取得回执，W=`fb886ce1-f267-49ca-a37f-7dabf693d657`、scheduleId=null，拟将独立Service.retries由3改2；来源preview原期限为22:42:18.604。真实原键/新Plan模型只读 (`artifacts/M11/runs/20261015-persistent/durable039-registration-model-readonly-original/registration-model-verification.json`, not public)通过，材料期限为23:28:21.831，`browserAcceptance=false`。该工单与旧W=`f8393f4e-ec5e-4d9b-b5ac-1e35fb7b1e9e`均未在原期限内完成审批/激活，现已自然过期；不得续期、沿用旧票或补执行。后续正向用例必须从当前真实配置准备全新独立意图。
- 原拒绝回执过期后只读 (`artifacts/M11/runs/20261015-persistent/durable-rejection039-readonly-historical-after-expiry-original/verification.json`, not public)于22:30:20通过2项，业务POST0，确认原preview实际过期后仍可读取匹配历史拒绝事实；不代表可以再发布原预览。
- 最新Web隔离构建 (`artifacts/M11/m11-source-disposition-web-isolated-build-20261015-original.json`, not public)于22:30:23退出1、产物0，158输入保持，原报告保留；修复隔离构建缺失依赖文件后须另存新结果，不能将Source专项通过代替构建成功。最后14,461项完整回归与秘密扫描仍只覆盖旧828范围，不覆盖本节新增字节、日志或审计。

### 24.2 本次完整闭环顺序

新增[完整验收执行清单](../../acceptance/m11-commercial-acceptance-checklist.md)，按独立门禁执行：恢复持久环境与原记录→修复并核验当前Source/构建/权限→全新长材料Service独立审批及自然成功→全新门户签发与吊销→新双环境Promote→Target0/DELETE变更后状态、回收恢复及新回滚→会签/撤权/取消/重启/并发、unknown安全处置与预算→通知/当前审计/恢复演练→最终固定版本全测试、三端类型/隔离构建、e2e/IDOR、完整凭证秘密扫描及生产准入。详细矩阵同时覆盖原始13项整体验收要求及M9补充，不将单测、SQL负测、页面或已激活状态相加登记业务成功。

[手册增补草案](../drafts/m11-manual-additions.md)单独持久保存，包含新旧材料期限、创建配置工单、原键拒绝/未知、SQL038/039升级、旧writer排空、runtime最小权限、恢复与值班提纲。两本正式手册本次不改，待最终实际流程、截图与部署/恢复演练通过后合入；未验收功能不预写为可用。最后已核对远端仍是10月15日的`d3e1d405`，后续Source与证据尚未登记新的实际推送，本节不声明GA发布。

### 24.3 08:34 UTC 原API及持久状态恢复分项

本小节更新本节起点之后的真实恢复结果：08:30初始观察 (`artifacts/M11/runs/20261018-resume/recovery-initial-observation-original.json`, not public)逐份核对原418输入，全部匹配b186摘要，原容器Exit255且OOMKilled=false；支持服务启动 (`artifacts/M11/runs/20261018-resume/support-services-start-original.json`, not public)退出0，原376份编译产物摘要保持，没有重放旧意图。

首次API启动前只读SQL观察 (`artifacts/M11/runs/20261018-resume/pre-api-console-db-safety-original.json`, not public)因观察器错误引用不存在的`workflow_schedule_versions`表而退出3，原失败保留；用既有实际安全查询取得的v2 (`artifacts/M11/runs/20261018-resume/pre-api-console-db-safety-v2-original.json`, not public)退出0，40条迁移摘要全部匹配持久Source，记录1,536条审计、两条旧durable issue、一条旧rejection，未到期running job、未领取active日程、未到期claimed日程均0。该查询只验证记录及安全计数，**不等于本轮全部审计链或预期写入覆盖率验收**。

原API实际启动及ready (`artifacts/M11/runs/20261018-resume/api-start-readiness-original.json`, not public)证明容器ID仍为`b6b219eaf7d1d7896c6de23aa0f41ddecd74172d5fe352e3a61da71fd076b684`，于08:33:38.744 UTC启动，08:34:31观察ready200，Source仍b186、平台PostgreSQL/Redis持久数据保留；旧过期材料未重新激活，Kong源码/镜像不变。这补齐同一验收环境的运行恢复分项，**不代表异机灾备、生产持久部署或新业务成功**。Root仍在处理Prometheus丢失旧`/tmp`二进制bind的问题，不能写监控healthy；新认证、新Service自然执行、门户与Promote尚未开始本轮验证。

### 24.4 08:45 UTC 恢复完成、新会话与新长审批材料

固定官方二进制恢复及原Prometheus启动 (`artifacts/M11/runs/20261018-resume/prometheus-binary-mount-repair-and-start-original.json`, not public)保留了首次下载后因原临时挂载目录权限失败的事实；随后仅恢复经固定摘要验证的同版二进制，没有改Kong或持久业务数据。08:44全部自有容器检查 (`artifacts/M11/runs/20261018-resume/all-owned-runtime-health-original.json`, not public)确认原8个容器均running/healthy。新登录 (`artifacts/M11/runs/20261018-resume/fresh-console-sessions-original/verification.json`, not public)实际取得新SID、原管理员和审批actor不变，旧会话与原请求保留，没有重发旧业务。

新的Web隔离类型/专项/构建与实际浏览器摘要 (`artifacts/M11/runs/20261018-resume/web-rebuild-and-fresh-tab-summary-original.json`, not public)分别退出0；实际空缓存、新会话浏览器 (`artifacts/M11/runs/20261018-resume/existing-plan-fresh-tab-readonly-original/verification.json`, not public)10项/2截图通过。已登记和已拒绝来源计划均由真实BFF状态阻止重复创建及legacy apply，无需本地归档缓存，业务写入0。10月15日失败原报告保留；该结果不代替Native执行、最终全量或凭证验证。

新配置策略版本 (`artifacts/M11/runs/20261018-resume/configuration-policy-24h-new-version-original/configuration-natural-verification.json`, not public)通过独立审批工单`c3ac0414-e694-44d3-9572-79d8e13b6194`正式执行，后续新configuration_v2材料期限改为24小时；旧材料原期限完全不变。新的独立Upstream、Target、Service分别经独立审批实际Native201后，新工单登记 (`artifacts/M11/runs/20261018-resume/configuration-new-durable-prepare-submit-original/configuration-natural-verification.json`, not public)于08:45:01.760 UTC取得W=`d855a24a-4e4f-4c90-8de3-4c9a5f8d2ce4`，计划将独立Service.retries由5改4。来源短preview原期限08:58:55.673，不续期；实际等待门槛为09:00:16.760，届时才允许进行超过15分钟的审批。当前尚未批准、激活或自然执行，修复后的Source联合审查与真实成功均待，**M11/commercial仍false**。

### 24.5 09:00 UTC 固定Service候选部署、门户前置与长审批拒绝

Mutation envelope整合 (`artifacts/M11/runs/20261018-resume/mutation-envelope-v3-source-integration-original.json`, not public)记录`70faa9c0`两文件逐摘要匹配，原编译失败保留、Target不支持门禁未变。Service联合整合 (`artifacts/M11/runs/20261018-resume/service-profile-joined-source-integration-original.json`, not public)记录固定关系/窄观察组等Source进入仓库；首轮`853d9d5b`补丁虽应用退出0，事后摘要检查 (`artifacts/M11/runs/20261018-resume/service-core-initial-patch-eof-concordance-original.json`, not public)明确失败：补丁生成器缺EOF换行，将下一diff头拼入测试夹具末行。Root只用冻结的正确夹具副本恢复预期摘要，后续联合记录保留原失败及修正事实，不把首次拼接错误写为通过。

Root联合专项 (`artifacts/M11/runs/20261018-resume/root-joined-service-focused-original.json`, not public)实际退出0，26个测试文件978/978、失败/待办均0，1,544份输入前后不变；不与旧专项相加，也不等于全量或业务成功。API冻结/隔离编译 (`artifacts/M11/runs/20261018-resume/reviewed-service-candidate-source-freeze-original.json`, not public)退出0，Source=`98a4715f808f72b3a10888e919542a723ef95770057118f34fa6ce0de3986fb1`，419输入/377JS/40条SQL、输入保持且未写仓库dist。实际部署 (`artifacts/M11/runs/20261018-resume/reviewed-service-candidate-runtime-original.json`, not public)先核对未到期running job/active未领取/未到期claimed均0、备份7,400,656字节，仅停止和重启同一API；08:59:54.927 UTC启动ready200，SQL仍40条。旧失败/unknown不重放，原计划窗口/会话与Kong源码/镜像不变；这是新运行候选，不是生产发布或自然执行通过。

新门户case=`new-20261018`使用独立的Upstream (`artifacts/M11/runs/20261018-resume/portal-new-fixture-upstream-original/native-verification.json`, not public)、Target (`artifacts/M11/runs/20261018-resume/portal-new-fixture-target-original/native-verification.json`, not public)、Service (`artifacts/M11/runs/20261018-resume/portal-new-fixture-service-original/native-verification.json`, not public)、Route (`artifacts/M11/runs/20261018-resume/portal-new-fixture-route-original/native-verification.json`, not public)夹具，各自独立审批及Native201。门户真实BFF九个前置阶段均通过：preflight (`artifacts/M11/runs/20261018-resume/portal-new-natural-preflight-original/portal-natural-verification.json`, not public)、policy (`artifacts/M11/runs/20261018-resume/portal-new-natural-policy-original/portal-natural-verification.json`, not public)、settings (`artifacts/M11/runs/20261018-resume/portal-new-natural-settings-original/portal-natural-verification.json`, not public)、开发者注册 (`artifacts/M11/runs/20261018-resume/portal-new-natural-developer-register-original/portal-natural-verification.json`, not public)、开发者审核 (`artifacts/M11/runs/20261018-resume/portal-new-natural-developer-approve-original/portal-natural-verification.json`, not public)、应用 (`artifacts/M11/runs/20261018-resume/portal-new-natural-application-original/portal-natural-verification.json`, not public)、publication创建 (`artifacts/M11/runs/20261018-resume/portal-new-natural-publication-create-original/portal-natural-verification.json`, not public)、publication发布 (`artifacts/M11/runs/20261018-resume/portal-new-natural-publication-publish-original/portal-natural-verification.json`, not public)、凭证申请 (`artifacts/M11/runs/20261018-resume/portal-new-natural-request-original/portal-natural-verification.json`, not public)。最后于08:55:20产生工单W=`9a277756-cc98-4b5e-b15f-c523e69c8bbf`，Service=`707696bb-04eb-4bca-b3d8-e0d78388f7cb`、Route=`0751a2f7-6f82-4806-bd06-41baf29918e9`。原报告`credentialsPublished=false`、`issueExecuteRequestInvoked=false`，schedule/claim/execution均null，尚未排程、发证或完成代理认证/吊销；前置通过不能登记门户自然闭环。

另一张配置长工单W=`d855a24a-4e4f-4c90-8de3-4c9a5f8d2ce4`的来源短preview按08:58:55原期限自然过期，实际等待超过15分钟后，author-approve-activate阶段 (`artifacts/M11/runs/20261018-resume/configuration-new-long-approval-author-vote-activate-original/configuration-natural-verification.json`, not public)于09:00:31.545结束，**passed=false**：实际`POST /workflow-schedules`返回403 `CONFIGURATION_DURABLE_BINDING_INVALID`，报告scheduleId=null。该证据仅证明阶段在登记排程入口被拒绝，不能写审批/激活或自然执行成功，也不能仅凭HTTP403或runner中的null推导所有SQL副作用为0、KnownNotSent或安全重试。实际原状态与拒绝原因需Root独立核验；不重放原stage、不延长原preview/窗口、不改写旧失败。Service正向、门户发证、Promote、poststate/回滚、unknown/预算及最终整体验收仍待，**M11/commercial=false**。

### 24.6 09:14 UTC 长材料核验、门户自然失败与当前审计

长工单原状态只读取证 (`artifacts/M11/runs/20261018-resume/long-approval-durable-binding-forensics-original.json`, not public)于09:03:12退出0：使用实际`kongpilot_lab_app`、`REPEATABLE READ READ ONLY`，W=`d855a24a-4e4f-4c90-8de3-4c9a5f8d2ce4`仍pending/revision1、历史版本1，job仍waiting_approval，job及workflow计划原期限均为10月19日08:44:57.791 UTC；真实`currentDurableJob`和已存base workflow仓库验证分别通过。schedules、delegations、claims、configuration executions、configuration steps和mutations各0。该查询补齐原403之后的实际账本状态，观察器没有发送Native请求；**零账本行不是KnownNotSent证书，也不授权重试原author命令**。原失败、来源短preview期限及24小时新材料期限不改。

门户W=`9a277756-cc98-4b5e-b15f-c523e69c8bbf`随后author (`artifacts/M11/runs/20261018-resume/portal-new-natural-author-original/portal-natural-verification.json`, not public)、独立vote (`artifacts/M11/runs/20261018-resume/portal-new-natural-vote-original/portal-natural-verification.json`, not public)、activate (`artifacts/M11/runs/20261018-resume/portal-new-natural-activate-original/portal-natural-verification.json`, not public)真实通过，日程S=`17061d84-4d39-4f22-9e52-4e2ab4421fd0`、计划由revision1变revision2、原deadline保留。但原HTTP observe (`artifacts/M11/runs/20261018-resume/portal-new-natural-observe-original/portal-natural-verification.json`, not public)于09:08:27保持false，不能把激活通过写为发证成功。

独立终态SQL (`artifacts/M11/runs/20261018-resume/portal-new-natural-terminal-sql-original.json`, not public)于09:08:35退出0：只有一个原自然claim=`d8b0d17b-7c05-452e-91bf-bfbdbf7531c8`、generation1，原authority至09:10:45.032；执行E=`651ff518-1710-4ece-abd2-65bfae665efb`及W/S进度均uncertain。revision2首个Consumer创建步骤uncertain，mutation=`78c96e49-aea4-4509-8d68-066374f5fdcb` failed、`remote_started=true/remote_completed=false`，错误`KONG_EXECUTION_CONTEXT_EXPIRED`；其余三个当前步骤及旧revision1四步骤仍pending。没有手动tick或重发原发证请求，未确认凭证成功、代理认证或吊销；真实发送结果不能仅凭failed或未发证状态改写为已知未发送。

原API完整日志结构诊断 (`artifacts/M11/runs/20261018-resume/portal-new-natural-terminal-context-diagnostic-original.json`, not public)捕获一条`scheduled-workflow`根上下文到期事件，`purpose=null/reason=deadline/timeoutMs=120000/overdueMs=123`。这确认本次到期frame类型与120秒预算，不能写成此前Service的5秒authorization frame、原5分钟claim到期或已取得精确业务throw site。首次中间SQL观察 (`artifacts/M11/runs/20261018-resume/portal-new-natural-first-progress-sql-original.json`, not public)因工具错用execution的`created_at`列退出1，原失败保留；v2 (`artifacts/M11/runs/20261018-resume/portal-new-natural-first-progress-sql-v2-original.json`, not public)改用实际`started_at`后只读退出0，09:07:43记录的executing/running被上述真实uncertain终态补充。连接池采样 (`artifacts/M11/runs/20261018-resume/portal-new-claim-console-pool-states-original.json`, not public)仅显示当时连接idle、未出现Lock等待，不能外推全程从无锁等待或单独证明超时根因。旧Portal case不重试、不续权、不借新句柄接管。

current-version局部修复Source (`artifacts/M11/runs/20261018-resume/durable-scheduled-current-version-source-integration-original.json`, not public)于09:12:35集成`c57e4733`三文件、Root核对摘要匹配；实现者15专项文件546项与API类型检查退出0，SQL038/039原字节未改，报告明确`runtimeDeployment=false`。这些是实现者Source门禁，不能当作Root新全量、已部署、原403已修复或自然成功；后续须冻结并部署，再以独立新case实测，原author命令未重试。

新专属Upstream/Target/Service经各自独立审批和Native201后，新工单登记 (`artifacts/M11/runs/20261018-resume/configuration-after-revision-new-prepare-submit-original/configuration-natural-verification.json`, not public)于09:11:39.597 UTC取得W=`acae8927-bd70-476d-94bb-05d3832d12bb`，计划retries5→4，沿用已经正式发布的24小时策略；scheduleId=null，未author。其来源短preview原期限09:25:33.229保持，真实超过15分钟等待门槛为09:26:54.597；本节不提前登记审批或排程成功。

当前平台生产依赖公告检查 (`artifacts/M11/runs/20261018-resume/production-dependency-audit-original.json`, not public)于09:11:16退出0、漏洞计数0、lockfile摘要保持，仅覆盖生产依赖，明确不覆盖OS或容器运行时。09:14:25本轮当前全审计链 (`artifacts/M11/runs/20261018-resume/resumed-current-all-audit-chains-original.json`, not public)以实际runtime只读核验1,706行/3链、全部JSON patch有效，退出0；`expectedCriticalWriteCoverageAccepted=false`，不登记关键写入100%覆盖或其后新增写入已验。自然Service、Portal及Promote正向、poststate/回滚、unknown/预算、生产恢复与最终冻结版本全量/秘密扫描仍待；正式两手册不新增未验功能，**M11/commercial=false**。

### 24.7 10月18日绝对授权期限修复部署与新业务验证（09:42 UTC）

最终目标仍是全部 M0–M11 研发与平台整体验收，当前 **M11 / 整体商用均未通过**。本轮没有修改 Kong 源码、镜像、插件或连接 Kong 数据库。

- 新的 联合 Source 回归 (`artifacts/M11/runs/20261018-resume/root-joined-approved-deadline-focused-original.json`, not public) 54 文件 1,833/1,833、实际退出0，覆盖 current-version、真正 scheduled Namespace/Approved 原始绝对期限、原键下层处分与 Service 关系等；不把该专项当全仓回归。
- 独立审查 (`artifacts/M11/runs/20261018-resume/approved-original-deadline-independent-review-original.json`, not public) 7文件146项及API类型检查实际退出0，新增较短 proof、异步闭合、当前reviewer/lease/developer撤销等边界；普通HTTP与recovery字节不变。这是 Source 结论。
- 候选冻结 (`artifacts/M11/runs/20261018-resume/approved-original-deadline-candidate-source-freeze-original.json`, not public) `6580accabb5f83166c89c6bf717e0dc61e20bab9834bfbb7489cd3a4cd47f0c6`，419输入/377JS/40条SQL，编译0；同一API部署 (`artifacts/M11/runs/20261018-resume/approved-original-deadline-candidate-runtime-original.json`, not public)09:36:35 UTC启动、ready200，部署前持久备份，未重放旧工单。未部署的8e1a候选不作为运行版本。
- 新配置 W `acae8927` 在原preview自然到期后成功author新rev2、独立审批成功，说明上次current-version拒绝路径已前进；但激活403 (`artifacts/M11/runs/20261018-resume/configuration-after-revision-new-long-author-vote-activate-original/configuration-natural-verification.json`, not public) `WORKFLOW_BUSINESS_SERVICE_HOST_LOOKUP_AMBIGUOUS`，仍不算自然发布通过。运行身份只读取证v2 (`artifacts/M11/runs/20261018-resume/configuration-after-revision-activation-rejection-readonly-v2-original.json`, not public)显示W approved、日程pending-approval、claim/E/config步骤/M均0。首个只读观察器误用execution.error_code列失败，原失败单独保留，未产生写入。
- 真实已有Service.host为67字符单label，Kong1.5已接受，平台helper错误增加63字符DNS限制；正在按1.5官方实际schema/validator修复，不重发该失败激活。新独立夹具已开始准备。
- 新门户 `after-namespace-20261018` author/vote/activate均通过；09:40:18 UTC自然领取唯一claim，原到期09:45:18，当前进入执行；尚无发证或代理认证成功结论。观察器不执行worker tick、不修改窗口。
- 独立全目标盘点识别33项当前/历史覆盖差异；必须完成的Source缺口含审批全实体回收/永久清除、授权内总览统计、平台专用备份恢复等，已并行研发。Target/删除poststate A/B仍在联合接线，未撤早期支持门禁。

后续依次取得新配置/门户/双环境Promote自然成功、Target/全图删除恢复及回滚、审批故障/撤权/双worker/容量、最终持久生产部署与灾备、当前全仓/IDOR/e2e/审计覆盖/完整秘密扫描，再校对正式手册和推送用户仓库。任何 unknown、失败或过期记录均保留；不能用Source分项通过代替整体商用结论。

### 24.8 当前全仓回归、门户预算失败与恢复验证（10:20 UTC）

当前实际 API 为 Kong 1.5 host 规则修复候选 (`artifacts/M11/runs/20261018-resume/kong15-host-reference-candidate-runtime-original.json`, not public)，Source `02b26a6aa40f5ac2372b64d2e9639b730acc98f5963a4b1d82aacca77059ab5c`，09:48:01 UTC 同容器启动、ready200，419输入/377JS/40条SQL。67字符单label不再被平台自创的63字符限制拒绝；此结论不表示全部 Service 创建、引用或大规模配置均验收通过。

门户 `after-namespace-20261018` 实际自然执行失败，不能沿用上一节的运行中状态。原 claim `d74b5f4c-aa3c-49ae-b3ae-423f88aa6180`、execution `641f7ea3-f78c-43cf-a2e4-ffe2e22bb927` 的首个 Consumer mutation `817cceb9-849e-45f4-a76f-63d1acdc71c5` 为 failed、remote_started=true、remote_completed=false，09:43:39 W/E/S 均 failed。原 API 日志 完整结构诊断v2 (`artifacts/M11/runs/20261018-resume/portal-after-namespace-terminal-context-diagnostic-v2-original.json`, not public)确认调用预算 limit500/current501，而公共边界将其掩为 `PORTAL_MANAGED_OBJECT`；没有发证、代理认证或吊销成功。旧case不重试，不调高全局500预算。精确对象读取优化及安全错误归一化已集成 Source，尚未部署；原失败保留。

冻结全仓检查 (`artifacts/M11/runs/20261018-resume/interim-full-source-typecheck-build-original.json`, not public)使用5,500项冻结输入，652个测试文件、15,501项：15,443通过、51失败、7 pending、0 todo，测试实际退出1；三端类型检查和三端隔离构建各实际退出0。全部原始失败和冻结输入保留。缺失的固定 decK 1.2.4 已按既定 archive/binary 双 SHA 恢复，原冻结Source三文件复验 (`artifacts/M11/runs/20261018-resume/restored-deck-source-focused-original.json`, not public)12/12、pending0；这不修改原全仓结果。另发现普通上下文短期限被扩大的真实产品回归，修复候选须经独审和联合验证，不以修改测试预期掩盖。

六个测试夹具修复片 (`artifacts/M11/runs/20261018-resume/full-regression-test-only-source-integration-original.json`, not public)覆盖12个测试文件，输入/输出逐 SHA 匹配、产品和runtime零改动，保留原权限、审计、SQL拒绝和实际transport状态断言；Root联合复验仍待。Promote个别30秒Source用例在CPU竞争时出现超时，失败位置会变化，暂未据此判定产品问题或放宽产品期限，必须完成受控调度复验和真实业务验证。

09:57一次认证refresh实际HTTP201和原requestId可见，但私有runner最终ledger仍为prepared，不能按零账本写入推断未发送。原packet保持，后续实际只读 `/auth/me` 通过；新会话替换与原会话吊销 (`artifacts/M11/runs/20261018-resume/auth-session-replacement-after-refresh-original/auth-session-replacement-verification.json`, not public)10:09实际通过，同actor新SID认证成功，原access401。未重放原refresh或任何业务命令。

全新独立 Service 夹具后，配置工单登记 (`artifacts/M11/runs/20261018-resume/configuration-fresh-auth-new-prepare-submit-original/configuration-natural-verification.json`, not public)于10:14:03.199取得W `226a3c97-684c-4fee-92bb-b40ef652ac5f`，计划retries5→4、24小时材料。原preview期限10:27:55.428保持，严格超过15分钟门槛为10:29:18.199；当前尚未author/vote/activate，不提前登记自然成功。

运行库只读恢复检查 (`artifacts/M11/runs/20261018-resume/platform-recovery-actual-nosu-readonly-original.json`, not public)10:18:42实际退出0：真正NOSU身份和REPEATABLE READ READ ONLY、40迁移/40列契约一致、1,834条审计/3链通过、90个mutation-before AEAD样本可解密；clusters和recycle样本各0，不能算三域覆盖。没有备份/恢复或session吊销写入，没有联系Kong；完整DR、生产发布、最终全仓/安全/容量/手册及提交仍待。**M11/commercial=false**。

### 24.9 11:12 UTC 当前运行版本、真实恢复与仍然阻断的业务链

联合专项 (`artifacts/M11/runs/20261018-resume/root-joined-all-role-points-focused-original.json`, not public)81文件2,373/2,373、实际退出0；冻结候选 (`artifacts/M11/runs/20261018-resume/all-role-points-candidate-source-freeze-original.json`, not public)Source `46ea8cd1e1f93db70d4e44b5bb8d877278d42f46a73909ad81f2141f059d75b1`、419输入/377JS/40迁移、隔离编译退出0，普通上下文维持原120秒或更短父期限，只有真正私有Native授权链可使用原批准绝对期限。同容器部署 (`artifacts/M11/runs/20261018-resume/all-role-points-candidate-runtime-original.json`, not public)后，最近一次备份恢复运行停启于10:42:31 UTC，ready200。该版本仍是验收候选，非生产GA；专项通过不覆盖全量测试。

配置W `226a3c97`按原短preview自然到期且真实超过15分钟后，author与独立审批成功，但激活实际409 (`artifacts/M11/runs/20261018-resume/configuration-fresh-auth-new-long-author-vote-activate-original/configuration-natural-verification.json`, not public) `WORKFLOW_SCHEDULE_PHYSICAL_IMPACT_CONFLICT`。只读取证 (`artifacts/M11/runs/20261018-resume/configuration-fresh-auth-activation-conflict-readonly-original.json`, not public)确认与旧uncertain日程共享物理影响键；保持冲突保护、原窗口和unknown，不重试该工单。后续正向验证另建专属Upstream/Target/Service，不能把新的独立用例当旧请求重试。

新门户 `after-exact-domain-20261018`完成独立四实体Native201前置、开发者/应用/发布/申请及author/vote/activate。自然claim唯一，但W `5c4aadd8`、E `6e74ed4a`于10:40:03失败，首个Consumer Mutation `6685127f`仍是failed、remote_started=true、remote_completed=false，原终态 (`artifacts/M11/runs/20261018-resume/portal-after-exact-domain-fifth-natural-progress-sql-original.json`, not public)错误 `KONG_EXECUTION_CALL_LIMIT`。没有取得凭证或完成认证/吊销。Source诊断发现同一检查点重复全参与方权限读取；私有单次新鲜检查证明修复正在联合复核，**未部署**。独审另发现短期用户/团队绑定自然到期不改变IAM epoch，transaction-stable `now()`可能错误放行；4条独立拒绝用例在原候选真实失败，必须修复并通过复验，不能以既有206项绿结果覆盖。

平台恢复脚本第一轮备份因其他数据库client存在而拒绝，后续同API安全恢复。固定有界等待后，真实加密备份 (`artifacts/M11/runs/20261018-resume/platform-v4-actual-backup-original.json`, not public)成功，8,331,050字节，backup ID `1fe20df3-3fca-4e1c-948f-7e9cdebdc1f9`。前两次全新隔离恢复分别因磁盘不足、官方PostgreSQL临时初始化服务器被误判ready失败，所有原失败保留。仅清理经证明为空的失败临时容器，保留其卷/网络/日志；已完成Source副本先逐文件SHA归档再删除重复副本，未清理任何原业务卷、运行二进制或Kong数据。

readiness修复 (`artifacts/M11/runs/20261018-resume/platform-postgres-readiness-v5-source-integration-original.json`, not public)和Root58项复验 (`artifacts/M11/runs/20261018-resume/root-platform-readiness-v5-focused-original.json`, not public)通过后，第三个全新隔离项目真实恢复 (`artifacts/M11/runs/20261018-resume/platform-v5-actual-isolated-restore-third-original.json`, not public)11:10:18–33实际退出0：40迁移/原checkpoint一致、1,921审计/3链、97密文样本可解密、旧console/portal会话active均0、Redis新建且为空；没有启动API/worker/投递，没有联系Kong。仅完成隔离存储恢复；生产最小角色、全应用密文、业务凭证、切换/离机RPO/RTO仍待，不算完整DR或整体商用通过。

同一隔离库上的SQL040真实DDL回滚验证 (`artifacts/M11/runs/20261018-resume/c04-040-real-postgres-rollback-first-original.json`, not public)实际退出0：10函数/12触发器/原40迁移摘要通过，TEMP同名表不能替换public对象；显式ROLLBACK后新连接独立确认完整catalog和ledger不变。没有提交040、插迁移ledger或变更原运行库；RC/RR双连接竞争、正式迁移与业务审批链仍待。M9完整PCRE语义、全对象图删除恢复、通用元数据定时工单、unknown安全裁决和最终全量/IDOR/e2e/容量/生产部署仍在研发验收，**M11 / commercial均false**。

### 24.10 11:24 UTC 固定Node22与提交前秘密检查

固定Node22来源 (`artifacts/M11/runs/20261018-resume/fixed-node22-runtime-tool-original.json`, not public)为当前API镜像中只读复制的22.23.3，原容器/镜像未改。三端固定Source类型与隔离构建 (`artifacts/M11/runs/20261018-resume/checkpoint-node22-three-builds-original.json`, not public)各退出0、1,969份输入保持；Node22专项 (`artifacts/M11/runs/20261018-resume/checkpoint-node22-focused-original.json`, not public)10文件342/342，失败/pending均0。CI脚本、UI工单控制和平台恢复分项均在本次范围，不能替代最终全仓与e2e。

完整历史验收账本338,192个结构节点首次秘密提取触发原结构预算；初次二分后又触发原pattern预算，全部失败报告保留。精确分片覆盖证明 (`artifacts/M11/runs/20261018-resume/current-checkpoint-bounded-cohorts-exact-coverage-original.json`, not public)保留完整非requests原对象，928个原始完整请求按原序各覆盖一次，Cookie/正文/响应/YAML不裁剪；每片重复当前管理员认证材料和全部15份实际环境材料，未改提取器/匹配器/预算或添加值排除。11轮完整检查 (`artifacts/M11/runs/20261018-resume/current-checkpoint-bounded-cohort-secret-scan-original.json`, not public)各实际退出0、0泄露，覆盖当前可发布仓库、三端新构建、26份自有完整当前/历史API日志及实际1,964条审计快照。原输入逐文件SHA验证后加密材料按私有权限归档保存；本轮没有成功签发API Key，使用checkpoint profile，**不算最终凭证完整秘密验收**。后续新增Source、凭证与运行日志仍须在最终发布前重新检查。

此处作为进度checkpoint保存，未集成或部署的Portal新鲜检查V2（含短binding到期修复）、Target/全图、SQL040/041/042不得计入已交付运行功能。独立V2源码复核及20例同链测试通过后，Root将按分片SHA重新整合、联合测试、冻结和部署，再以全新门户申请验证真实自然签发；所有旧501/unknown/原期限保持。另一个专属Upstream/Target/Service的新配置材料于11:14:20.330登记W `55853901`，原短preview11:28:06.824到期，严格超过15分钟门槛11:29:35.330，尚未批准或激活。本checkpoint明确 **M11 / commercial=false**，不创建GA标签。

### 24.11 12:04 UTC 新运行候选、实际材料根因与SQL040整合

checkpoint `79fcae8f19790f3f956548b3cdb1fce50747f3a4` 已于11:25推送并核对用户远端分支，见推送证据 (`artifacts/M11/runs/20261018-resume/checkpoint-1124-remote-push-original.json`, not public)。它保存当时源码、原始失败及进度，不是GA；本节后续变更尚未包含在该commit。

Portal V2按逐文件SHA整合后，首轮Root联合89文件2,510通过、2失败；两处失败均为同一旧测试spy仍预期三个参数，产品现增加真实私有execution/Step证明参数。原失败保留，单行测试断言补齐并维持所有关联拒绝断言，54项复验通过。随后加入配置canonical修复的Node22联合90文件 (`artifacts/M11/runs/20261018-resume/root-joined-canonical-origin-focused-original.json`, not public)2,529/2,529，失败/pending均0、1,563份输入保持。冻结编译 (`artifacts/M11/runs/20261018-resume/canonical-origin-candidate-source-freeze-original.json`, not public)Source `f960006a100c4a616e790e48cdcbc35368fcb5b0c2fd053e01a76cf670f0d5e4`，420输入/378JS/40迁移、退出0；实际同容器部署 (`artifacts/M11/runs/20261018-resume/canonical-origin-candidate-runtime-original.json`, not public)前活跃执行安全计数均0并备份8,939,752字节，12:00:55 UTC启动ready200。没有改Kong源码、镜像、插件或连接其数据库，没有重试旧意图。

配置W `55853901`在实际超过15分钟后author/独立审批/activate成功，但自然终态 (`artifacts/M11/runs/20261018-resume/configuration-dedicated-third-natural-progress-readonly-original.json`, not public)仍失败：`WORKFLOW_SCHEDULE_CONFIGURATION_SUBJECT_CHANGED`，唯一原claim和W/E/S失败事实保持，嵌套配置执行/M均0。实际产品只读诊断 (`artifacts/M11/runs/20261018-resume/configuration-dedicated-subject-guard-readonly-diagnostic-original.json`, not public)确认PV一致，差异来自Origin旧projection漏掉durable字段，不能用更改PV或延长窗口处理。修复复用同一canonical projection并验证durable封套，不改期限、claim或门禁。独审690项通过；新运行版本的实际NOSU只读重算v2 (`artifacts/M11/runs/20261018-resume/configuration-original-subject-after-fix-readonly-v2-original.json`, not public)确认materialHmac、完整subject与原draft/schedule相同，旧W/S仍failed、claim仍1、Native0。首次观察器误引用claim表不存在的subject列而SQL42703，原件另存，修正后只读通过；未把观察失败改写成业务成功。

新的独立Upstream/Target Native201通过后，Service夹具初次prepare/submit201、后续只读断言失败；原通用helper没有保留该异常的详细原因，不能据此指定根因。原提交后只读观察 (`artifacts/M11/runs/20261018-resume/configuration-origin-aligned-fixture-service-submitted-readonly-original/verification.json`, not public)确认pending且尚无票/执行后，以新键进行第一次审批/执行，Native201通过，没有重发prepare/submit。随后新长材料 (`artifacts/M11/runs/20261018-resume/configuration-origin-aligned-new-prepare-submit-original/configuration-natural-verification.json`, not public)11:50:30.322登记W `6d9816f6-e9ec-4c3a-945f-9bda01c36de5`、retries5→4，原preview12:04:18.898自然到期，严格等待门槛12:05:45.322。当前尚未author，不提前登记自然成功。

恢复库实际最小角色 (`artifacts/M11/runs/20261018-resume/recovery-v5-actual-runtime-role-original.json`, not public)使用真实产品provisionRuntimeRole/DbService通过：新NOSU角色无角色成员、建库/建角色/schema CREATE等权限，7类审计/ledger/schema越权实际42501；原40迁移、1,921审计和sessions0保持。SQL040真实组件测试 (`artifacts/M11/runs/20261018-resume/c04-real-postgres-runtime-fixture-first-original.json`, not public)只在隔离恢复PG新建的测试逻辑库运行，真实DbService40→41及运行角色配置、RC双连接两种锁顺序、RR/Serializable25001、未知M/live父job保护、延期约束、审计异常回滚及TEMP影子均通过，共12项actual0。原恢复库完整catalog/40ledger不变；SQL形状夹具不是业务审批或Native回执证明。

SQL040最终四片与独立9个反例已合入源码。初次合入校验 (`artifacts/M11/runs/20261018-resume/c04-reviewed-source-integration-original.json`, not public)应用六片均0，但把独审增强后的test误与owner增强前SHA比较而报告失败；逐字节复核 (`artifacts/M11/runs/20261018-resume/c04-reviewed-source-concordance-after-independent-test-original.json`, not public)按冻结独审test及原产品SHA全部匹配，未重放补片或改产品。Root固定Node22复验 (`artifacts/M11/runs/20261018-resume/root-c04-origin-focused-original.json`, not public)API/Web类型检查0、11文件503项/失败及pending0、1,898输入保持，SQL000–039不改。当前运行库仍40条，040未部署；正式迁移、真实直接/审批清除、浏览器确认、整图子权限与审计业务验收仍待。

完整Portal引擎的Source根meter仍501、Native0；P1/P2虽各自Source安全回归通过，仍不能突破整链阻塞。后续只缩减真实私有调用阶段内的重复读取，保留最终全参与方当前SDK/SQL及原500预算。M9 PCRE安全/包装片已冻结待Root整合，SQL041通用元数据调度及042未知安全处置、全图删除恢复继续研发。**M11 / commercial=false**，最终全仓、IDOR/e2e、生产持久部署/灾备、秘密扫描、两本正式手册和商用发布仍未完成。

### 24.12 真实期限失败、SQL040部署、原生PCRE与完整密文恢复（12:57 UTC）

最终交付目标保持全部 M0–M11 研发及整体商用验收，当前 **M11 / 商用仍未通过**。阶段结果不替代完整业务成功，未修改 Kong 源码、镜像或插件实现，控制台不连接 Kong 数据库。

1. 新配置长工单 `6d9816f6-e9ec-4c3a-945f-9bda01c36de5` 跨过原短 preview 后，真实 author / 独立审批 / activate 已通过；但自然领取唯一 claim 后，在原五分钟截止处以 `WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_SQL_BINDING_CHANGED` 结束。W/E/configuration job 为 uncertain，S progress 仍 claimed；mutation `79480585-ee4a-45ca-8e5b-6de305f62782` failed 且 remote_started=true / remote_completed=false。当前 Service.retries 仍5，不能据此推导未发送或安全重试。所有原窗口、claim、历史失败保持，未重放原业务；新 SQL042 的严格安全处置候选也不会把 claimed 或失败的已开始 mutation 认作成功证据。见终态实际BFF观察 (`artifacts/M11/runs/20261018-resume/configuration-origin-aligned-terminal-bff-observe-original/configuration-natural-verification.json`, not public)。
2. SQL040与PCRE候选部署 (`artifacts/M11/runs/20261018-resume/c04-m9-candidate-runtime-original.json`, not public)于12:27:44 UTC在同一自有验收API启动、ready200：冻结Source `159b6fa669014d7013587d56760e38291acd7d772cf4f116c75bd9865364ed5b`、2,020输入、380JS、41条SQL（000–040）。真实DbService迁移/配权和NOSU运行身份通过；持久备份8,975,163字节，全部原claim/schedule/未完成发送事实前后相同。该容器仍是可写Node22验收容器，**不是已验证的不可变生产镜像**。
3. SQL040 空库安装与幂等迁移 (`artifacts/M11/runs/20261018-resume/c04-real-fresh-install-first-original.json`, not public)真实通过41个摘要、bootstrap、NOSU readiness、6条42501拒绝，旧40条SQL运行版本拒绝新41库。另实际PostgreSQL组件专项 (`artifacts/M11/runs/20261018-resume/c04-real-postgres-runtime-fixture-first-original.json`, not public)包含RC双向锁竞争、RR/serializable拒绝、unknown/live-parent保护、deferred约束与全事务回滚。组件中的合成业务事实不能当完整工单授权验收。
4. 新原生PCRE1 8.45使用固定官方归档/源码/二进制摘要、资源限制和Linux syscall沙箱。Node22专项 (`artifacts/M11/runs/20261018-resume/root-m9-pcre1-node22-focused-original.json`, not public)真实15项native及123项Source、API类型检查通过；三端类型/隔离构建 (`artifacts/M11/runs/20261018-resume/c04-m9-node22-three-builds-original.json`, not public)均退出0；实际API中的helper smoke通过。真实Kong独立Upstream/Target/Service/含12种PCRE路径Route均经工单得到Native201，测试插件prepare返回500，原失败保留；26条代理语料尚未录制，不能把helper测试写成真实路由对照通过。已发现并正在修复平台对Kong1.5 required record默认值处理不足及插件错误漏转400，Kong本身不改。
5. C28完整66字段扫描 (`artifacts/M11/runs/20261018-resume/c28-all-cipher-66-domain-totals-original.json`, not public)在独立恢复环境真实通过：3,371个字段值中848个空值、2,523个非空密文全部按真实产品codec/AAD校验解密，失败0；原恢复库40条迁移/目录/会话撤销状态前后完全一致。V1 IP CIDR格式、V2历史会话总行数假设导致的原失败均保留，V3只修观察器，未修改恢复数据。此结果仅覆盖**同宿主隔离恢复及现存密文可解**，不代表异地恢复、RPO/RTO或凭证真实认证可用。
6. 新 SQL041 V2 与 SQL042 V2 已完成独立静审和实际DDL/TEMP影子表/显式ROLLBACK预审 (`artifacts/M11/runs/20261018-resume/041042-real-ddl-rollback-v2-second-original.json`, not public)：28个函数固定invoker/search_path、11新表可在独立clean41库建立，原41账本/目录及原恢复40库不变。首轮检查器误把两个历史NOT VALID外键当新迁移缺陷，失败原件保留；第二轮只允许原始精确OID，新增约束仍要求validated。**未插041/042 ledger、未正式部署**；运行身份配权、真实Core/Main授权、期限与事务并发验收仍待。期限表述为最终约束实际执行时检查原授权，不声称任意raw SQL会话都能受物理COMMIT墙钟限制。
7. Node22全量首次 (`artifacts/M11/runs/20261018-resume/root-current-full-node22-original.json`, not public)674测试文件，15,680通过、80失败、0pending，原报告保持。多数失败来自Root冻结副本漏带公开历史fixtures、`.env.example`和Playwright配置；补齐公开输入、修正旧回收站UI权限夹具后，18个失败文件复验 (`artifacts/M11/runs/20261018-resume/root-full-failure-inputs-v2-original.json`, not public)353/353退出0。另16项旧测试错误假定合法PCRE不支持，已按真实原生引擎独立修正测试并复验50项；Promote三项30秒超时继续在原冻结Source单独复验，不加测试/产品期限。最终固定版本全量仍待，不能把分项结果相加改写原全量。

Portal P1–P5、完整Target/对象图all-missing与5-present/2-new恢复、metadata九域排程、严格unknown处置仍在Source联合研发/独审，尚未进入上述运行版本。后续必须完成真实新配置和Portal发证/代理认证/吊销、完整恢复及Promote/回滚、当前IDOR/审计写覆盖/秘密扫描、不可变生产镜像、持久部署/外部联调/灾备与正式运维和用户手册，才可记录整体商用通过。

### 24.13 本地完整回归通过、独立CI失败与V3运行候选（13:37 UTC）

当前仍以全部M0–M11研发和整体商用验收为目标，**M11 / commercial=false**。用户远端已核验保存checkpoint `c1bfe28f7489575814620b1cf55e5cd4d7d96234`，另建[草稿PR #1](https://github.com/sean-y-wang/kongpilot-console/pull/1)供持续复核；没有merge、GA标签或商用通过声明。本节V3与后续诊断尚不属于该checkpoint。

1. 本地Node22完整回归 (`artifacts/M11/runs/20261018-resume/root-complete-full-v2-node22-original.json`, not public)于13:23:08完成：5,654项冻结输入保持，675测试文件、15,981通过、失败/pending/todo均0、实际退出0，真实原生PCRE和固定decK前置均就绪。此前80失败原件保留。此结果覆盖V3整合**之前**的固定Source `e0af94ecb1e92ce3448c976077dc02821bea55b64538a28df0487be9947e369c`，不是V3或未来P6/041/042最终回归。排查CI时发现该本地副本还包含17个未跟踪的本机`deploy/private`测试材料；它们从未提交到Git，不应上传或作为CI必需输入。此结果因此也不能代替仅仓库公开资产、隔离环境的干净安装回归；保留原结果，后续必须用干净Git输入复验。
2. 同一checkpoint的GitHub独立CI原结果 (`artifacts/M11/runs/20261018-resume/github-source-quality-first-original.json`, not public)不能略过：[run39130316588](https://github.com/sean-y-wang/kongpilot-console/actions/runs/39130316588)真实测试15,883通过、98失败、0跳过，测试退出1；各阶段均未超时。固定decK、原生PCRE15项、三端typecheck/build、生产依赖0漏洞及lock未变分别通过。原管线仅保留脱敏计数，未上传原始测试报告，因此尚不能指定98项根因；现补安全诊断，只允许仓库已有测试路径、固定错误类别和有效整数行号，不发布测试名称/异常/stack/diff/凭证。不用提高业务调用预算或本地通过覆盖远端失败。
3. V3已审核Source整合 (`artifacts/M11/runs/20261018-resume/ordinary-v3-joint-reviewed-root-integration-original.json`, not public)精确45文件，产品patch `4a3a0f510d8bb6541111ee0b93eb358777b929906da746aede8d8f06d4d61f7f`；独审26文件507项退出0。它包含当前图/前缀/全参与方READ与secret权限、真实SDK回执和私有authority检查，不复用过去的允许决策。Source全图all-missing360calls/14pages，partial231calls/98pages，仍使用原500calls/100pages上限；受控Source事实不能作为真实SQL/Kong业务通过。新冻结编译 (`artifacts/M11/runs/20261018-resume/ordinary-v3-joint-isolated-api-build-original.json`, not public)与同容器部署 (`artifacts/M11/runs/20261018-resume/ordinary-v3-joint-candidate-runtime-original.json`, not public)退出0，Source `4118a2be8d75156c58da71dfed39b01c2cf2a32f67441c32a6ebbb1924ac11ae`、427API输入、384JS、41SQL，13:19:53启动ready200。部署前备份9,208,518字节，原claim/schedule/未完成发送事实摘要前后不变；真实五类完整图delete/restore及凭证认证另行验收。当前容器仍不是不可变生产镜像。
4. 26组真实PCRE路由对照 (`artifacts/M11/runs/20261018-resume/m9-pcre-native-26-corpus-first-original/m9-pcre-native-verification.json`, not public)全部通过，BFF模拟仍标simulated，每组与实际代理及预期匹配一致。required-record缺省修复后新插件经真实工单Native201，只读回读 (`artifacts/M11/runs/20261018-resume/m9-plugin-post-default-readonly-original/m9-plugin-post-default-readonly-original.json`, not public)确认嵌套record默认值和Route绑定。原prepare500、原request/key与原失败仍保留，没有重发原键。未修改Kong源码/镜像/插件实现，也未连接其数据库。
5. 原失败prepare审计只读核验v2 (`artifacts/M11/runs/20261018-resume/m9-failed-prepare-audit-readonly-v2-original.json`, not public)实际发现该请求无审计事件。首个观察器误用不存在的created_at列失败原件保留，v2只修为occurred_at。新的可信Guard身份→失败响应独立追加审计正在研发，不能以此补造过去记录或登记100%关键写覆盖。审计失败、未知Native结果和原业务错误必须分别保留。
6. [平台备份恢复手册](../../../manuals/platform-recovery-runbook.md)已按实际C28恢复路径补齐，明确66列现存密文验证、历史会话保留并撤销、最小权限、异地/RPO/RTO与接管边界。候选041/042新增三个密文域，总69列，未来正式迁移后须形成新业务数据并重做新备份/恢复；旧66列结果不外推。真实镜像构建、运行Node/PCRE ABI、OCI provenance/SBOM和三端只读nonroot启动的独立CI仍在研发，未把Source测试当作镜像通过。

后续优先完成真实五类回收恢复与六类凭证、Portal完整P6/元数据尾提交及新自然签发、configuration_v2 Target/DELETE、九域元数据Core/Main与SQL041/042真实授权处置、当前Promote/回滚和故障/容量测试，然后冻结最终源码/镜像进行完整回归、IDOR、审计覆盖、秘密扫描和灾备/手册校验。每项独立保存原始成败；不重放未知请求、不延长旧claim、不将未测试边界记为商用通过。

### 24.14 10月20日环境恢复、门户 P6 部署与失败审计实测

当前 **M11 / 整体商用验收仍未通过**。本轮恢复中发现 M11 验收容器因环境重启停止，`/tmp` 测试工具丢失；持久卷、原始请求账本及源码仍在。恢复固定 Node 22.23.3 后核对二进制 SHA 与原记录一致。恢复自有验收 PostgreSQL/Redis/Kong/代理，不修改 Kong 源码、镜像或插件；控制台仍不连接 Kong 数据库。Prometheus 初次启动因临时挂载文件丢失失败，恢复原官方归档和二进制摘要后启动；仅移除 Docker 创建的空挂载目录，未删除数据卷。恢复记录 (`artifacts/M11/runs/20261020-resume/prometheus-binary-recovery-original.json`, not public)。

- **门户执行修复已部署。** 已按独立审查的原始 SHA 合入 P6 七个产品文件及测试；每个检查点只共享不可变 SDK 原始观测，每位参与方仍独立校验当前权限，保留原期限、500 调用和 100 页限制。联合回归 (`artifacts/M11/runs/20261020-resume/portal-audit-joined-source-original.json`, not public) 381/381、失败/跳过 0、输入保持；隔离编译 (`artifacts/M11/runs/20261020-resume/p6-audit-build-original.json`, not public)退出0，429输入、386编译文件、41条迁移。Source 测试使用受控数据库/网络适配器，不代替实际业务成功。
- **实际验收 API 恢复就绪。** 部署记录 (`artifacts/M11/runs/20261020-resume/p6-audit-runtime-original.json`, not public) Source `46506a31bb4aec536a42207a20af013a7079e7a50f3435e1c347d7c78c667ddd`，10:53:16 UTC 启动、ready200。部署前持久备份9,638,591字节；当前有效日程、claim、普通执行和配置任务均为0；原claim、日程及未完成发送事实前后不变。该实例仍为验收容器，尚非已验收的不可变生产部署。
- **新的真实门户用例已进入待审批。** 独立专属 Route 经工单 Native201；新 case `after-p6-current-20261020` 已通过 preflight、策略、门户设置、开发者注册/审核、应用、API创建/发布及凭证申请。工单 `31242830-b23c-4918-9bb7-d85fd72b519d` 原期限为10月21日10:56:30 UTC；11:11:33 UTC后再登记排程，验证跨过15分钟短材料期限。当前尚未取得真实发证、认证或吊销成功结论。申请原记录 (`artifacts/M11/runs/20261020-resume/portal-after-p6-natural-request-original/portal-natural-verification.json`, not public)。
- **失败请求审计已实际验证。** 新认证请求返回400，最小权限只读核验得到恰好一条 `http.request.POST.failed / http_400`；可信操作人匹配、全局范围、before/after为空、diff为空、无实体变更事件、无请求中秘密标记。当前2,192行/3条审计链全部通过。最终只读记录 (`artifacts/M11/runs/20261020-resume/authenticated-http-failure-audit-actual-v3-original.json`, not public)。前两次只读观察器分别误用 `host(text)`、未限定同名 sequence 列，原失败保留；只修观察器，没有重发业务请求。历史遗漏不补造，也不据此宣称所有关键写入100%覆盖。
- **CI 修复与镜像安全脚本已集成。** 前次 GitHub 95项失败已定位到6个测试文件；仓库相对路径、测试UID/GID及进程结束观察修复在干净Git输入中120/120通过。镜像/OS/native漏洞检查脚本当前114/114、实际退出0，包含库存缺失与已知漏洞控制项；实际三端镜像构建和漏洞扫描仍待，不能把脚本测试当作0漏洞证明。镜像检查脚本回归 (`artifacts/M11/runs/20261020-resume/image-scanner-source-original.json`, not public)。

后续优先完成新门户自然审批执行、凭证可用与吊销，继续修复普通六类凭证批量操作的预算问题，完成五类完整图删除恢复、configuration_v2 Target/DELETE、九域元数据排程及SQL041/042正式验收，再以固定源码/镜像完成全量CI、Promote/回滚、浏览器、安全与灾备验证，并校准正式部署及使用手册。未通过项继续保留阻断，不发布GA或商用通过标签。

### 24.15 10月20日研发节奏调整、Portal 实际终态与 CI 收敛

按用户最新要求，研发阶段以集中实现、定向测试和必要真实业务检查推进；全部功能闭环并冻结候选后，再集中进行完整回归、安全、镜像、容量和灾备验收。此调整不降低权限、审计或未知结果保护，也不把专项通过计为商用通过。当前 **M11 / commercial=false**。

1. **Portal 长材料排程部分通过，签发仍失败。** 新工单 `31242830-b23c-4918-9bb7-d85fd72b519d` 在请求完成超过15分钟后完成原版本排程登记、独立审批、激活。执行器11:13:58自然领取唯一claim，原期限11:18:58保持。11:15:46首个Consumer步骤进入uncertain，错误 `KONG_WRITE_AUTHORIZATION_CHANGED`；mutation `c22b5016-ae0a-4e28-a035-991100e643d7` 的 remote_started=true / remote_completed=false，后续ACL、Key和元数据步骤未执行。未发放或展示凭证，未执行吊销阶段；原请求未重放，未知记录未改写。原只读数据库终态 (`artifacts/M11/runs/20261020-resume/portal-after-p6-terminal-sql-original.json`, not public)。不能据该包装错误推断具体根因或判定未发送。
2. **远端 CI 失败已收敛到4个文件。** 提交 `75173e2` 的 GitHub [39412063198](https://github.com/sean-y-wang/kongpilot-console/actions/runs/39412063198) 为16,277通过 /17失败 /15因浏览器初始化失败未运行。三端typecheck/build及生产npm依赖审计通过；镜像作业被阻断，尚无镜像漏洞扫描结论。修复旧夹具绕过构造器导致私有方法缺失、回收图当前权限桥未接入、旧Portal回读用例缺少原批准步骤，以及硬编码本机浏览器路径。浏览器改由锁文件对应Playwright CLI显式安装，安装失败阻断测试；不跳过浏览器用例。修复后145项定向检查 (`artifacts/M11/runs/20261020-resume/ci-targeted-fix-original.json`, not public)通过、无失败/跳过，原69/86失败复现保留。成功Portal回读仍由完整Core测试覆盖；旧仅namespace夹具现在明确验证不能越过原步骤要求。
3. **未知写入安全诊断已开发，未部署。** 在原Native策略与SDK响应包装处记录固定结构的内部错误码、合法UUID操作归属和禁止重试标记；不记录错误正文、堆栈、请求/响应、地址或凭证。原公开unknown错误不变，日志失败也不改变结果或造成重发。106项定向检查 (`artifacts/M11/runs/20261020-resume/write-diagnostics-source-original.json`, not public)与API类型检查 (`artifacts/M11/runs/20261020-resume/diagnostics-api-type-original.json`, not public)通过。该诊断尚不能解释已发生的旧错误；后续需新合法用例取证。
4. **普通凭证预检查优化及独立验收批次已开发，未部署。** 六类凭证的普通创建/恢复仅在完整证明对象不影响受管门户认证图后减少编译预检查；最终Native发送前全图授权保持。66项定向检查 (`artifacts/M11/runs/20261020-resume/ordinary-preflight-joined-original.json`, not public)通过，但高密度风险对象规模仍待验证。验收驱动新增独立case/fixture绑定，拒绝覆盖原失败批次、重复阶段或复用已发生删除尝试的对象图；45项测试 (`artifacts/M11/runs/20261020-resume/ordinary-new-cohort-source-original.json`, not public)通过。尚未宣称真实六类凭证批量及五类完整图恢复通过。

当前实际API仍运行§24.14的P6/AuditV2源码；本节新补丁未替换运行实例。下一步顺序：部署已验证候选并定位Portal响应后复核根因；新独立用例完成发证/鉴权/吊销；普通凭证与完整图回收恢复；configuration_v2 Target/DELETE；九域元数据调度与SQL041/042安全处置；然后冻结整体候选，完成干净CI、实际镜像及安全/浏览器/Promote回滚/容量/灾备验证，并复核正式部署手册和用户手册。未发布GA、未合并主分支。

### 24.16 10月20日下午：镜像失败定位与诊断候选实际部署

GitHub连接器取得原作业完整日志：提交`38dc070`对应PR合并候选的源码CI **16,340/16,340通过**，无失败/跳过；镜像作业构建API后在OCI校验阶段报`IMAGE_OCI_PROVENANCE_MISSING`，清理也未通过。两份原始安全摘要已保存：源码 (`artifacts/M11/runs/20261020-followup/previous-source-ci-success-original.json`, not public)、镜像 (`artifacts/M11/runs/20261020-followup/previous-image-ci-result-original.json`, not public)。不能把源码通过扩大为镜像或商用通过。

镜像校验器原先错误地让SLSA v1和v0.2使用相同buildType。已按[BuildKit v0.34.0官方类型定义](https://github.com/moby/buildkit/blob/v0.34.0/solver/llbsolver/provenance/types/types.go)分别匹配精确标识，仍要求完整blob摘要、实际镜像配置、来源revision、依赖清单及SBOM绑定；不接受任意buildType。清理器误用Buildx inspect不存在的`--format`，按[Buildx v0.38.0官方实现](https://github.com/docker/buildx/blob/v0.38.0/commands/inspect.go)改为检查原私有配置中builder头部的精确Name和Driver，再仅删除本次builder。CI新增只上传安全summary.json的归档步骤。121项定向测试 (`artifacts/M11/runs/20261020-followup/image-ci-fixes-source-original.json`, not public)通过，实际新镜像作业待复验。

诊断与普通凭证预检查候选编译 (`artifacts/M11/runs/20261020-followup/diagnostic-candidate-build-original.json`, not public)430输入/387JS通过，13:40:27实际部署 (`artifacts/M11/runs/20261020-followup/diagnostic-candidate-runtime-original.json`, not public)ready200；SQL000–040保持41条。部署前备份9,778,232字节，原工单/claim/未完成发送事实前后不变。Source `f5f1e103aafa223c5ddd37ca20535e00d43634605d4b499b5bd591ca3cb09c35`，仍为验收实例而非不可变生产部署。

真实业务检查继续暴露阻塞，不能登记Portal闭环：新独立Upstream/Target分别Native201，但Service工单`76e886f7-857e-481a-8c42-c77953bdfcc8`执行403 `KONG_EXECUTION_RESPONSE_LIMIT`；原日志显示actor总pages达到101/100，停止后续Route创建，未提高预算或重放。随后改用正常业务场景“同一已发布API的新应用订阅”定位发证，不改旧publication或旧unknown工单；新应用`5fa2a7b5-aeca-4a4a-94fd-005e334cf2ef`、新工单`9d911e20-d102-4e7d-9201-59eb6a2b1fa1`申请/排程登记/独立审批通过，但激活403 `WORKFLOW_BUSINESS_MATERIAL_CHANGED`，未启动自然签发。原case内容摘要保持。两条失败及私有原请求账本均保留，未生成新的发证成功结论。

后续先修复当前材料比较与普通图重复读取的真实阻塞，完成Portal签发/鉴权/吊销，再继续§24.15剩余M11范围；最终统一验收仍未开始，M11/commercial=false。

### 24.17 10月20日下午：schema 激活修复、Service 实测与原始回执兼容

镜像校验修复与前一轮证据已提交并推送 `0484980508ea291b310df66fb230a14c57aef3de`，主分支和草稿PR状态未改。其独立CI原摘要 (`artifacts/M11/runs/20261020-followup/ci-0484980-timeout-original.json`, not public)保留：三端类型/构建、工具链和生产npm依赖审计通过，但测试阶段达到原15分钟上限，被终止且没有完整测试总数；镜像作业因此跳过。不能把上一轮16,340项通过外推为本轮通过，也不声称镜像修复已经实测成功。

1. **门户激活阻塞已定位并实测解除。** 在原加密数据和只读事务中核验，失败日程的计划、主体seal及执行人当前SQL权限均匹配，且没有claim；BFF实际读取三个schema后与发布证明比较，唯一差异是字符串定义的`len_min`由省略变为1。原只读比较 (`artifacts/M11/runs/20261020-followup/portal-schema-compare-readonly-original.json`, not public)。[Kong 1.5.1官方源码](https://github.com/Kong/kong/blob/1.5.1/kong/db/schema/init.lua#L921)确实在校验字符串时写入该默认约束。复用现有有界定义比较器，仅在当前1.5.x注册版本下接受等价定义；显式0/2/null/false/字符串值、真实required/default/类型/限制变化仍拒绝，不改已签名材料或Native请求。169项专项 (`artifacts/M11/runs/20261020-followup/portal-schema-focused-original.json`, not public)通过；候选部署 (`artifacts/M11/runs/20261020-followup/portal-schema-runtime-original.json`, not public)13:59:45启动ready200、原SQL000–040及历史事实保持。
2. **新的独立门户工单完成激活，终态仍为partial。** 工单`e3716402-549d-4054-bd5d-313d36160c80`通过新应用申请、排程、独立审批、激活和自然领取，执行前快照ready。Consumer mutation `fb169993-4824-4cca-856a-ad75e4f2a34e`为succeeded、remote_started/remote_completed均true；步骤回读报`WORKFLOW_BUSINESS_PORTAL_READBACK_RECEIPT_REQUIRED`，其余ACL、Key、元数据未执行。实际终态 (`artifacts/M11/runs/20261020-followup/portal-schema-terminal-readonly-original.json`, not public)。只读回执诊断 (`artifacts/M11/runs/20261020-followup/portal-receipt-shape-readonly-original.json`, not public)中17项归属/材料检查均匹配，原始结果直接含entity ID，未包在`entity`属性下；因此已定位为平台回读格式判断错误，不是远端结果未知。原工单未重新执行。
3. **原始/包装回执兼容修复已部署。** 抽出严格回执比较器，保留原claim/步骤上下文门禁、执行/actor/集群/工作区/计划/步骤/对象/凭证归属，以及原payload/before的AEAD与摘要验证；额外检查当前step行绑定的operation ID。允许真实MutationService保存的原始实体或既有包装实体，仍逐字节摘要对照实际回读，格式错误、被篡改及错归属均拒绝。联合262项专项 (`artifacts/M11/runs/20261020-followup/receipt-service-joined-original.json`, not public)通过、无失败/跳过；部署 (`artifacts/M11/runs/20261020-followup/portal-receipt-runtime-original.json`, not public)14:09:35 ready200，Source `206f91bd4dc7cd60eb08aa1b9ab10cc92986cdfbd784a1ffd9ccc9212ac9fb45`、388JS、41条SQL；备份9,941,666字节、历史claim/日程/未完成发送事实不变。仍是验收容器，不是不可变生产部署。
4. **普通新Service读取预算阻塞已通过新工单实测。** 编译预检查仅对普通HTTP上下文、create/POST、新UUID且原before为null、无父对象、无发布归属的Service，在真实SDK点读404并再次核验当前ownership后减少重复全图读取；不缓存权限或图，不提高500调用/100页上限，最终Native发送前仍走完整认证图校验。52项针对性测试通过。新工单初次在独立审批前遇到验收SID过期，原失败保留；用同一账号新登录，确认无旧审批/执行请求后，首次审批与执行完成，工单`d6a2ad78-bbb8-4221-bbaf-5d168257c14c`得到Native201并回读一致。实际Service结果 (`artifacts/M11/runs/20261020-followup/service-preflight-first-execution-original/summary.json`, not public)。没有重放prepare/submit，未将此结果外推为六类凭证或完整回收图通过。

当前 **M11 / commercial=false**。继续用新应用/新工单验证当前回执修复后的自然签发、鉴权及吊销；随后仍须完成六类凭证与五类对象图恢复、configuration_v2 Target/DELETE、SQL041/042及九域元数据调度、Promote/回滚/故障并发、安全/浏览器/容量/灾备、不可变镜像和部署/用户手册最终复核。源代码专项通过、部分业务步骤成功、完整业务闭环与整体商用验收分别记录。

### 24.18 10月20日14:26：回执修复实测生效，最终激活预算仍阻塞

独立新应用`5626bf85-a510-4ac6-9d77-85fc75918e24`的工单`bae65a07-67e7-4c87-9f5f-0e5ff768d77f`正常经过申请、排程、独立审批、激活和自然领取。执行`311ddd71-70bc-4af3-a446-2ee6741164a6`快照ready，Consumer、ACL、Key三个步骤均succeeded，三个原mutation均为remote_started/remote_completed=true，说明本轮原始回执兼容修复已在真实业务中生效。最终`portal.credential.activate`步骤报`KONG_EXECUTION_CALL_LIMIT`，自然终态partial；原日志显示scheduled-workflow尝试第501次调用时被500上限拒绝。原始阶段结果 (`artifacts/M11/runs/20261020-followup/receipt-application-observe-original/summary.json`, not public)、只读数据库终态 (`artifacts/M11/runs/20261020-followup/receipt-application-terminal-readonly-original.json`, not public)均保留。

控制台grant仍pending/generation=0、credential仍pending/generation=1，未展示密钥、未执行后续鉴权/吊销验收。Kong侧Key已有确认写入，**pending不是远端凭证已撤销的证明**。原执行的截止时间仍为14:20:50.387 UTC；未延长claim、未提高调用预算、未手工补激活、未重放任何原Native写入。本轮不能登记发证闭环成功，也不能用一次新的申请覆盖旧partial或unknown。

下一项修复需要测量最终激活路径的实际读取分布，针对重复的完整范围观察做有边界的合并或缩小支持读取。必须保留原计划/claim/步骤/权限、事务前后材料检查、真实SDK回读与审计；不复用跨步骤的授权，不把未完整读取的结果当作完整证明。修复后先跑越权、撤权、材料漂移、超时和原预算回归，再以新独立业务用例验证自然发证→授权展示→代理鉴权→审批吊销→失效。旧partial的受控补偿/回收同样需要正式流程与证据，不能直接修改SQL状态或物理删除远端对象。

本轮提交前补跑12文件399项回归 (`artifacts/M11/runs/20261020-followup/portal-closure-security-regression-original.json`, not public)，实际退出0、399通过、0失败/跳过，覆盖原始回执、schema等价边界、Service预检查、原调用预算、多审批人观察隔离、Native准备SQL和支持读取路径。此结果只证明所列源码回归，不覆盖尚未成功的门户最终激活及平台全量商用验收。

### 24.19 10月20日14:33：独立CI重验结果与源码检查点

本轮门户schema/回执及Service修复已保存为源码检查点`d588a9a477eb770c398945eeb3d8057c750f61ef`。提交前当前私有材料扫描 (`artifacts/M11/runs/20261020-followup/precommit-portal-receipt-original.json`, not public)覆盖40个待发布文件、1,110条原请求、13个材料批次，发现0项；它不是全仓库/构建输出/日志或最终商用秘密验收。

前一提交`0484980`的[独立CI第二次运行](https://github.com/sean-y-wang/kongpilot-console/actions/runs/39434477949/attempts/2)已结束，保留完整安全摘要 (`artifacts/M11/runs/20261020-followup/ci-0484980-attempt2-original.json`, not public)：16,340项中16,335通过、5失败、0跳过；本次测试进程未触发15分钟总截止，实际887,356ms、退出1。5项失败均归类为测试超时，分布在`m11-origin-canonical-sql.test.ts`（1项）和`m11-promote-combined-origin-canonical-sql.test.ts`（4项）；尚未证实其根因，不能直接称为偶发CI噪声或用本地成功覆盖。三端类型检查/构建及生产npm依赖审计通过，镜像任务依赖源码门禁而被跳过。

下一轮先定位这两份测试的执行耗时及异步等待，再推进门户最终激活预算优化；不以提高生产claim或调用上限规避问题。等待本次独立运行自然终止后再更新开发分支，避免新提交取消旧运行。主分支、GA与商用通过状态均保持不变。

14:40本地按相同`--maxWorkers=2`复验两份文件：103/103通过 (`artifacts/M11/runs/20261020-followup/ci-timeout-pair-local-original.json`, not public)，没有提高测试阈值；Origin文件约179.7秒、最慢单项6.8秒，Promote文件约296.5秒、最慢单项21.4秒。测试运行时观测到工作进程持续使用CPU，后段单个进程RSS约2GB；执行耗时/资源压力是后续性能诊断方向，尚不能由本地通过推定CI超时根因或豁免独立门禁。原103项断言与真实Provider调用保留，不删测、不改为无条件mock通过。
