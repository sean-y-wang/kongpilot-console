# M6 独立验收证据

状态：**M6 产品、部署、HTTP、浏览器主流程及手工复核已通过；测试资源清理及最终秘密扫描已通过，M6交付闭环。** 实际 HTTP 为1057/0，145次成功写入均有对应审计requestId；组合浏览器为1/0，10次成功写入均有审计requestId，新发放Key已纳入私有扫描材料。最新全量3,798/3,798与API/Console/Portal类型检查通过。手工五份停止报告均原样保留，聚合验证77/0、18张截图；全部七项原计划写入成功，原九次手工成功请求的审计存在性9/9，独立正常会话续期两次另列2/2。最后只读检查发现审批账号工作区实体发现缺陷，已通过一行授权修复、18项范围反例测试及API实际部署解决；原SID实际GET返回403，界面拒绝且不暴露计划或执行按钮。原登录、创建和发布没有重发。direct metadata成功终态before/after审计仍由M7补齐，不将仅requestId匹配计为原标准11通过。

M7–M11 未在此验收中实现或认证。whole Consumer 历史回收恢复的发送前预检仍是 M8 明确补缺；多级/会签/计划执行属于 M11。

| 门禁 | 当前证据 | 状态 |
| --- | --- | --- |
| 统一源码与实际数据库事务 | 原始 `source-release-gate.json` 保留初次放行；发布路径修复后的 `source-unit-post-native-path-repair-final.json`：全量 1,954/1,954 测试、295 suite、129 文件通过。API/Console/Portal 三端类型检查通过；实际隔离 PostgreSQL 66/66，含并发释放事实、真实 PortalAuth 账户关闭与失败回滚。原先超时和 BIGINT 夹具失败均单独保留 | 已通过（源码与隔离数据库，不替代运行时） |
| 测试基座与日志检查安全 | `artifacts/M6/security-harness-unit.json`，128/128 离线测试、8 文件：部署前禁发请求、请求前私存原键与租户、未知结果不自动重发、保留监控材料、0600/属主/符号链接校验、独立 cookie 与租户范围、无原生 Admin/SQL 清理出口；日志 stderr 秘密检查、六个实际服务发现规则、实际对象与独立成功回执、未发放预留记录的完整事实、特定 not_sent 受控继续、相同 actor/SID 的一次刷新；另验证新 C3 固定地址、完整旧检查点 SHA 与八用途材料不变、重新登记/探测未知即停止、所有历史 run 的清理复制与密码/cookie/Key 扫描覆盖。含独立 transition 45 项和独立部署策略 47 项，均为合成离线夹具 | 已通过（离线） |
| 脚本可加载 | Node 语法检查与 Playwright `--list`；发现一个 M6 浏览器场景 | 已通过（非真实验收） |
| 真实双集群凭证与门户身份隔离 | 前三次失败证据为 50/1、69/1、194/1；原凭证执行 269/1 和两次发包前的测试问题 364/1、335/1 均保留。`security-live-pre-fix-second-credential-execution.json` 保留 381/1：原元数据恢复成功、原 Key/ID 保持，但第二个发布对象 Consumer 的 custom_id 唯一性冲突。`second-credential-execution-failure-proof.json` 为该新执行的 failed 终态、首步骤 failed、后三步 pending、未决原生操作 0；不据此宣称零请求发送。后续 750/1 已通过双集群发放、隔离、轮换和退役；历史 Key 恢复的已知父依赖 404 另由 `retired-parent-restore-denial-proof.json` 证明。1012/1 已完成全部剩余生命周期，唯一停止点为已证明的审计脱敏标记误分类 | 十次停止保留；实际 HTTP 1057/0，组合浏览器 1/0 已通过 |
| 浏览器实际闭环 | 两份原失败JSON与报告封存保持；独立 tail 已实际一次通过，从原 SID 和已创建应用继续新申请、Console 登录、批准与执行、遮蔽桌面/移动截图，累计10次成功写10个独立requestId全部审计。原登录、应用创建和Key查看均未重放 | 已通过（组合证据1/0，保留旧失败）；人工、清理与最终扫描仍待独立窗口 |
| 实际启动、入口与网络边界 | `startup-final-verification.json` 15/15、`deployment-boundary-final.json` 27/27、双集群 Admin 37/37、监控边界 54/54、门户边界 79/79；私网仅 API/Portal，独立入口仅 Portal，两个 IP 均受保护。相同工具两个正向 TCP 控制通过，固定 IP 的受保护端口均不可连通 | 已通过（实际部署） |
| 当前原生配置与监控连续性 | `runtime-continuity.json` 13/13：10 个原运行服务、网络、卷及材料保持；C1 generation 2/C2 generation 1、1,760 条归属 epoch 保持。现有四用途材料已受信任只读捕获，没有重新登记或轮换，捕获引用在入口修复中保持不变 | 已通过（实际连续性，不代替业务验收） |
| 独立 C3 的实际部署与边界 | `portal-acceptance-deployment-verification.json` 42/42、`portal-acceptance-runtime-continuity.json` 21/21。真实 Kong 1.5.1 与独立 PostgreSQL11，Admin/DB 无公开端口；原 12 个服务保持，API 仅增加指定私网；八类原生实体初始为空。只在验收阶段使用 opt-in compose profile | 已通过（不替代凭证业务验收） |
| 人工视觉与交互复核 | 原浏览器组合验收和 Root 截图复核已通过；手工五次停止分别为0/1、2/1、25/1、50/1、71/1，均单独保留。聚合77/0、18张安全截图；Markdown创建/发布/回收恢复、管理详情和原审批身份权限拒绝实际验证完成 | 已通过，所有旧停止证据与原请求保留 |
| 测试资源清理 | 门户受管对象仅通过批准的 revoke/retireConsumer 工作流归档；公开发布、应用、工作区与 IAM 元数据走普通 BFF 软删除。清理覆盖原失败 run 与新独立 run，逐个验证原 workspace/tag 和检查点 SHA，使用副本避免刷新会话改变旧快照；七条历史认证面不在清理范围 | 已通过，聚合298/0；原295/1和只读审计收口证据保留 |
| 最终秘密扫描 | `finalize-m6-secret-scan.mjs --evidence-complete`：源码、未跟踪源码、Console/API/Portal dist、所有截图、ZIP/HTML 嵌入报告、环境（含 `.env.portal-acceptance`）与可选认证提供者秘密、所有新旧检查点的开发者/控制台密码及 cookie、API Key、当前监控四用途原材料和 ingest Basic 编码 | 已通过：1,710文件、6嵌入文件、145编译文件、7实际服务日志，泄漏0 |

## 历史过程记录

状态：统一源码、启动、连续性与网络门禁已通过。十次真实停止报告分别保留为 50/1、69/1、194/1、269/1、364/1、335/1、381/1、491/1、750/1、1012/1，阶段动态扫描均为 0 泄漏。独立 C3 与现有 C2 已实际发布 API，原首次元数据以一次原键恢复成功，原 Key/三个原生 ID 保持。失败的第二次申请已取得不可变关闭证书，总关闭 POST 为 2（原 503 一次，资格复核后同原键、同请求体一次），随后新的双集群批准发放、代理访问隔离、轮换与退役检查已通过。750/1 的历史 Key 恢复因父 Consumer 已退役而返回已知 failed 404，独立回执和只读账本证明没有成功恢复或未知操作，旧 Key 均仍 401。限定续跑已完成新申请、取消/驳回后重新申请和受管历史 UUID 的普通创建拒绝，随后在审计值分类检查停止。实际编译 SecretService 的只读证明确认 8/8 命中为真实 Key 的 canonical HMAC 脱敏标记，明文 Key 匹配 0；测试将响应标记误收为秘密，145 次成功写入均有审计。新独立只读收尾已实际通过 1057/0：145/145 成功写入 requestId 有审计、运行角色对五张不可变表的 15 次 UPDATE/DELETE/TRUNCATE 回滚探针全部拒绝、七个真实服务的 stdout/stderr 均未发现已捕获秘密；阶段扫描 0 泄漏，原 1012/1 报告及私有引用字节保持。浏览器尾段随后已实际通过组合1/0，累计10次成功写全部审计；浏览器新发放Key另经一次正常owner查看纳入私有扫描材料，审计匹配、原生写0。人工复核、清理和最终扫描仍待完成，端到端尚未闭环。

`M6_DEPLOYMENT_READY=true` 仅在 Root 与 DevOps 明确交接唯一真实写入窗口后设置。首个请求前私存原幂等键、当前 actor、clusterId、workspaceId 与原请求；未知结果保留原记录，不运行完整脚本重发。HTTP 成功后仍保留 `/tmp/kongos-m6-runtime-secrets.json` 至全部人工截图与清理结束。最终扫描通过才删除测试捕获引用，正式最小权限监控材料继续保留。

异常退出时保留当前阶段、所有原请求及已观察响应。先按原身份、原租户、原键读取对应 Portal / Workflow / Mutation / IAM 回执；HTTP 错误本身不能证明原生变更没有发送。运行中、未知或部分结果保持停止状态，不换键重发、不清空数据库记录，也不完整重跑脚本。只有真实回执与当前对象事实证明终态后，才按明确的修复交接继续尚未执行的步骤；清理同样需要独立写入窗口。

首轮发布失败来自业务层读取 `/services/{id}/plugins`，该路径不在约定的 Kong 1.5 对接白名单内；修复应使用有界 `/plugins` 游标列表并按真实 Service UUID 过滤，保持白名单不变。`publication-initial-receipt-proof.json` 保留原工作流回执不存在的观察；`publication-initial-ledger-proof.json` 另证明原键 Portal 操作核验为 `not_sent`、发布仍是 draft revision 2、匹配 workflow/IAM/native mutation 均为 0，且当前集群没有 running/uncertain 操作。该证据支持修复后的明确受控继续，不等于凭 HTTP 403 推断未发送。

受控继续入口另需 `M6_PUBLICATION_CONTINUATION_READY=true`，只适用于这一次特定的完整已知未发送事实。它复用现有三个工作区、原账号与所有原生测试对象，先只读复核当前身份、原修订、门户设置、Service/Route/legacy 插件、原键回执及双集群未决账本，再使用同一原发布键与原请求验证修复。任何事实变化都会停止；不会重新执行整个初始化脚本，也不能用于其他未知写入。

第一次继续验证了预期的 `PORTAL_UNMANAGED_AUTH_BOUNDARY` 和原发布键的 durable failed 回执：三个步骤 failed/pending/pending，均未完成；独立 mutation 完成/未决计数均为 0。随后添加独立历史 ACL 的新操作仍被同一边界拒绝；`legacy-acl-initial-ledger-proof.json` 保存该 ACL 原键的 failed mutation（remote_completed=false，remote_started 仅是 callback 标记）、双集群未决计数 0、原发布 pending revision 3，以及真实单页完整插件列表仅含原 key-auth、未出现 ACL。当前 pending 发布详情还观察到 HTTP 500，并单独记录，不把 failed 误写成 not_sent，也不重复提交旧失败键。

追加的 `auth-topology-readonly-diagnostics.json` 使用普通 BFF 对 23 个 active 工作区做有界读取，48 页、174 条实体，未保存原始 config 或请求匹配秘密。实际存在 8 个启用的 key-auth（7 个历史 Route、1 个当前测试 Service），没有启用 ACL；因此不能只据新 ACL 请求的拒绝推断守卫错误，也不能放宽发布认证边界。`older-keyauth-provenance-review.json` 只确认其中两个旧插件属于 M3/M4 演示夹具，其余五个来源未证实，全部七个旧认证面保持原状。`c2-auth-topology-readonly-diagnostics.json` 对 C2 的 9 个工作区、19 页、13 条记录完成检查，启用的 key-auth/ACL 均为 0；后续独立门户验收使用新 C3 与现有 C2，固定的 C1/C2 四用途监控材料不变。旧失败请求和对象保留完整私有检查点，不通过重置账本或重放旧 POST 开始新测试。

新入口 `start-m6-isolated.mjs` 还需明确的 `M6_ISOLATED_FIXTURE_READY=true` 交接。先核验旧工作流/ACL 原键的 failed 回执、保存的三个 workspace/tag，以及没有发放凭证、对应失败操作没有完成变更且双集群没有未知操作的事实；这里的完成计数只针对失败发布/ACL，不把已有原生夹具创建误称为零写入。随后仅登记一次 `http://kong-portal-admin-endpoint:8001`，再以另一预存原键显式探测一次，取得真实版本后才建立新 tag 和新活动检查点。完整旧引用深拷贝并记录可重算 SHA；原请求、原会话、密码、审计请求 ID 与监控材料继续聚合保存。物理 C3 独立性由实际部署的容器、网络和专用数据库卷及后续跨节点代理测试证明，不只依赖地址字面不同。

重复物理端点登记的实际测试预期为 `409 CLUSTER_ENDPOINT_EXISTS`，不创建 alias 或 alias 工作区。受管 Consumer 的普通 CID 写入拒绝另行实际验证；物理 scope/alias 所有权的独立集成测试为离线证据，报告不会声称创建过真实 alias。

`isolated-publication-request-proof.json` 保存第三次停止后的原申请键、failed receipt、当前 published revision 和只读事实：登记的 nullable transport_scope 为 NULL，权威计算值与发布证明匹配，cluster/workspace revision 均匹配且 workspace active，grant/credential/未决变更均为 0。精确修复使用统一的权威 transport scope 计算，不回填登记记录或放宽认证图。

精确继续入口 `continue-m6-credentials.mjs` 需另行 `M6_CREDENTIAL_CONTINUATION_READY=true` 交接。它保留原 failed 申请键，重新核验同一账号/租户/原 SID、已有原生配置和已发布证明、两个既有应用与独立零效果事实，再预存一个明确的新申请键及原请求，仅从第一次 grant 提交继续。不会重新初始化、登记、探测或发布。`credential-continuation-unit.json` 的 8/8 离线测试另验证未知结果不继续、当前事实改变即停止、原 Portal 会话的一次刷新及更新后的 CSRF token。Portal 的 failed DB 回执 remoteCompleted=true 表示终态数据库结果，不等于原生凭证已完成；零效果由无 workflow/result/grant/credential 的独立事实证明。

这次继续的最后一步观察到 `WORKFLOW_EXECUTION_FAILED`，原工作流和 execution 均保留 uncertain，门户 grant/credential 仍 pending。三个已成功原生步骤及两个 active credential_refs 保持原 ID。实际隔离 PostgreSQL 的 `portal-credential-activation-baseline-postgres-2026-10-10T23-16-38-425Z.json` 以 8/8 检查复现 `23514`：激活试图改写 SQL008 明确不可修改的 `key_secret`。修复与恢复必须保留此密文身份及原执行，不重发 Consumer/ACL/Key。诊断阶段之后的两个 BFF GET 因原 access token 到期返回 401，报告保留该事实，没有把它误写为对象不存在。

`pending-credential-secret-capture.json` 记录单独获授权的扫描材料捕获：固定的只读 Console 事务核验原 grant、credential、execution、三个已成功 native 操作和两个 typed credential_refs，使用原 AEAD context 解密并比对成功回执。一次性传输密钥仅走 stdin，stdout 仅 GCM 密文，原 Key 只加入保留的 0600 私有扫描引用；没有门户 reveal、激活、原生写入或 SQL 业务变更。自有 5 项和独立实际程序 12 项离线测试通过。`pending-credential-interim-secret-scan.json` 为阶段扫描，1,197 文件、2 个嵌入文件、0 泄漏，含此已创建 Key、全部新旧捕获材料与四个环境文件；不是最终验收扫描。初次四项误报另保存：诊断中的原幂等键被旧提取器当作秘密，修订仅排除与已保存 HTTP 请求记录相匹配的原 request/execution 键，真实 UUID Key、未关联值和显式秘密数组仍被扫描。

受控元数据恢复入口是 `continue-m6-metadata.mjs`，还需要明确的 `M6_METADATA_RECOVERY_READY=true` 实际部署交接。源码自有 7/7、独立 19/19 检查验证当前原身份/SID、不可变计划、原三个成功回执、现存配置及服务端恢复资格；三个相关脚本测试文件的组合回归另通过 27/27，报告为 `metadata-continuation-harness-final-unit.json`。只向正式 `reconcile-metadata` 发一次原 execution key 的请求，随后 GET 原回执与只读数据库校验保持三个原生操作、原凭证密文及指纹不变。再通过正常门户 GET/reveal 观察已激活的第一份 grant，仅继续其余尚未运行的业务；不重复其申请、审批、执行。恢复未知、旧事实改变或重复入口均停止。

首次实际恢复入口在发送恢复请求前停止：测试数据库指纹查询使用可选 `pgcrypto.digest`，当前 PostgreSQL 16 没有该函数，SQLSTATE 为 `42883`。`metadata-proof-query-diagnostics.json` 和 `metadata-proof-query-state-proof.json` 分别保留失败与独立只读状态核验：实际版本 160015、内置 `sha256(bytea)` 可用且与 Node SHA-256 一致；原 grant/credential 仍 pending，workflow/execution 仍 uncertain，原三个 native 操作全部完成、两个引用保持 active，正式恢复 POST 为 0、私有恢复日志尚未建立。测试查询改为内置 `encode(sha256(convert_to(key_secret,'UTF8')),'hex')`，只返回指纹，不输出密文；没有安装扩展或执行迁移。修订后的自有与独立 helper 测试 26/26 通过，证据为 `metadata-proof-query-fixed-helper-unit.json`；追加独立回归 `metadata-continuation-core-sha256-independent-unit.json` 为 20/20，含查询失败发生在任何恢复日志与 POST 之前。隔离 PostgreSQL 16.15 的 `portal-credential-cipher-fingerprint-postgres-2026-10-10T23-45-01-694Z.json` 为 10/10，使用实际导出的查询、SQL000–008 表和八个绑定参数，验证无 pgcrypto、旧查询 `42883`、内置 SHA 与 Node 对 ASCII/Unicode/空串和真实 AEAD 密文一致；其初次夹具失败另保留。该数据库测试不调用正在运行的业务或原生 API。这次修订尚不代表恢复成功，需新的明确继续交接。

第二次实际恢复脚本通过上述数据库指纹核验后，错误请求 `entities/consumers/:id/credentials/acls/:id`，返回未匹配路由的 404；控制器实际凭证路径是 `consumers/:id/credentials/:kind/:id`，父 Consumer 本身仍使用 `entities/consumers/:id`。这不是对象缺席的证明，此次原恢复日志和恢复 POST 仍为 0。精确修订仅移除子实体 URL 的错误前缀；`metadata-native-controller-contract-owned-unit.json` 的 9/9 离线回归直接读取实际 Nest `PATH_METADATA` 与 `METHOD_METADATA`，核验全部新增 guard、恢复、原回执、门户 grant/credential 查询与正常 reveal 的路径及方法。独立回归为 `metadata-continuation-native-child-route-independent-unit.json` 21/21，组合 30/30 记录于 `metadata-native-controller-contract-final-unit.json`；旧错误路径不能被 mock 接受。初次测试加载失败保留于 `metadata-native-child-path-owned-unit-pre-loader-fix.json`，只通过 API 工作区依赖解析修复，没有改依赖或产品配置。

再次明确交接后的正式恢复已成功：`original-metadata-recovery-proof.json` 记录一次原 execution key 的恢复 POST HTTP 201、原执行回执 succeeded、grant/credential active generation 1，原生操作数前后均为 3、凭证密文 SHA 与 Key 指纹保持；正常门户 reveal 返回的 Key 与先前私有捕获匹配，原三个 ID 保持，没有重复申请、审批或执行。当前 381/1 的新失败属于第二个 API 发放：实际 Kong `custom_id` 字段具有唯一性，原第一份 Consumer 的 custom_id 等于同一 app ID，而编译器给第二份 Consumer 仍使用该 app ID。`second-credential-custom-id-proof.json` 保存实际 schema 唯一性和仅布尔值的身份比对；新 Consumer 按原分配 ID 查询为 404，原执行回执是 failed，首个 mutation remote_completed=false，后续 ACL/Key/激活未执行。原键与已失败计划保留，不换键重试或把失败回执写成未发送，后续继续必须独立修复与交接。

该失败申请在 Console 中已生成加密 Key，尚未实际创建原生 key-auth，也未执行门户 reveal。专用 `capture-m6-failed-issue-key.mjs` 经单独扫描授权已实际执行一次：固定只读事务要求原失败 Consumer 操作、后三个步骤完整 pending、无原生结果/凭证引用，并比对不可变计划与原 Portal AEAD envelope 的同一 Key/类型/ID；转移仅走 stdin 与 GCM 密文 stdout，私有引用以 0600 和内容 CAS 合并。自有 5/5 和独立实际程序 VM 的 18/18 离线测试通过，报告为 `failed-issue-key-capture-owned-unit.json`、`failed-issue-key-capture-independent-unit.json`。实际证据 `failed-issue-credential-secret-capture.json` 记录仅捕获扫描材料，没有业务/原生写入、门户 reveal 或关闭申请；`failed-issue-interim-secret-scan.json` 覆盖 1,275 文件与 2 个嵌入文件，0 泄漏，私有引用继续保留。这是阶段扫描，不替代全部截图与清理后的最终验收。

后续失败申请继续器目前只完成源码准备：`failed-issue-continuation-owned-unit.json` 的 13/13 离线测试和 `failed-issue-continuation-compat-unit.json` 的 73/73 兼容测试通过。守卫在原首份凭证密文与三条原生操作保持不变、第二份计划明确失败且后三步未执行、原分配 ID 全部缺席后，才保存一次原执行键的关闭请求；只有原回执与独立不可变证书均证明释放后，才保存新的申请键。关闭及新申请均在发包前锁定私有状态，响应未知时不能重发。清理分别处理无执行的取消/驳回预留与该精确已证明的失败申请历史，保留 pending Key 和原失败账本，不把它们视为已发放或已吊销。以上离线验证不能替代实际闭环。随后执行过一次正式关闭，但其事务返回未知错误，证书未观察到、新申请尚未发送。

不可变密钥修复的源码门禁已经通过，尚不代表原运行中的发放已恢复。`source-unit-immutable-activation-repair.json` 保存全量 2,307/2,307 测试、333 suite、146 文件通过；新增 Swagger 和完整认证图补充为 `activation-recovery-root-unit.json` 52/52。`credential-activation-owned-unit.json` 为 105/105，`activation-recovery-independent-final-unit.json` 为 73/73。实际隔离 PostgreSQL 的最终 `portal-credential-activation-recovery-postgres-2026-10-10T23-26-16-204Z.json` 为 25/25、零原生写入，涵盖完整当前会话与授权、真实私有恢复能力、实际工作流和数据库触发器；Gateway 只读响应与 Redis 租约采用显式夹具，不替代真实 Kong 端到端测试。SQL000–008 校验和记录于该报告，原 SQL23514 失败证据保留。

`portal-immutable-key-metadata-deployment.json` 记录恢复修复的实际最小部署：七个步骤均成功，启动 15、部署边界 27、Admin 37、监控 54、门户 79、Swagger 8、连续性 23 项全部通过。仅现有 API 容器内进程重启，Console 静态资源通过原只读挂载更新；原生对象、C3 与原集群进程、监控 generation/materials/epochs、私有捕获引用均保持。部署通过与实际凭证恢复分别验收。

正式恢复入口为 `POST /clusters/:cid/workflows/:id/reconcile-metadata?workspaceId=:wid`，请求必须使用原执行者的当前有效会话、原 execute 的 `X-Idempotency-Key`、当前 revision、原 planHash 和 executionId，显式确认 `portal-credential-issue`。只有首次发放的三个原生成功 ACK 与最后一个无原生操作的 uncertain 激活步骤满足资格；恢复仅以单事务将门户记录、最后步骤、execution 和 workflow 提交为成功，永不重新打开执行步骤或发包。恢复能力与普通 approved/native 能力完全分开，所有原生入口在恢复上下文中拒绝。原执行未持久化最初 SID，因此校验当前会话与原执行人/原键，不宣称还原原 SID。重复相同恢复请求只返回经持久化 request HMAC 核验的原成功回执。

门户开发者只能在自己的租户与应用内提交申请；原生执行由当前真实控制台会话完成。审批权限不等于执行权限，HTTP 的 workflowId、approved、handle、system 字段不能构造私有能力。正式接口以当前控制器为准：开发者审核使用 `POST .../developers/:id/review`；凭证轮换/吊销二次确认字符串分别是 `轮换 <credentialUUID>` 与 `吊销 <credentialUUID>`。

初次直接创建 settings、publication、page 的响应合同是 `{entity: 实际门户对象, workflowId, receipt}`。后续请求只能使用实际对象 ID，脚本在响应仍是工作流摘要或回执未成功时停止，避免把工作流 UUID 当成发布对象 UUID。

生命周期验收还覆盖取消、驳回未执行申请后重新申请，以及正常吊销后重新申请：每次使用新的 grant、Consumer、ACL、key-auth UUID 与 Key，旧 UUID 仍受历史所有权保护。取消或驳回的预留记录不能伪装成已吊销凭证；清理仅在独立读取确认终态、已释放、无执行、无原生绑定、无发放事实及实际 Consumer 不存在后保留该历史记录。

真实代理验收区分两种拒绝：同一 Kong 内有效 Key 访问其他发布 API 或无该 ACL 组的历史 Service，应为 403；向另一台独立 Kong 发送其未知 Key，应为 401。Kong 1.5 配置传播可能延迟；报告保存实际观察，不把有界读探测后的成功描述成跨节点即时一致性。

显式 Key 查看期间关闭 Playwright 自动截图、视频及 trace。只在查看框关闭、DOM 清除后生成公开截图，断言使用布尔结果避免在失败日志打印临时 Key。丢失应用创建响应的场景只发送一次原 POST，随后按原租户、原 actor 与原幂等键读取操作回执。

本里程碑采用单级审批和同步执行基础；多级、会签、定时窗口及完整工单治理仍属于 M11，不在 M6 验收中提前宣称完成。

正式关闭尝试的失败另保留为 `security-live-pre-fix-failed-issue-continuation.json`：491 项通过、1 项失败、动态扫描 0 泄漏；没有重发 POST、产生新申请键或进入浏览器。`failed-issue-abandonment-failure-proof.json` 记录原键 GET 200/state failed、certificate 0、grant 未释放、Key pending generation 1/原密文保持、原 native 操作仍为一条 failed、refs 0、未决数 0。`failed-issue-abandonment-database-permission-class.json` 只从日志提取数据库权限错误及安全表名，未发布原日志、SQL 或参数；当前请求对应 `portal_publication_proofs`，SQLSTATE 42501 为权限错误分类推导，原日志未显式给出代码。源复核定位 `FOR SHARE OF p,proof` 对不可变 proof 表要求 UPDATE 权限，修复应保留 publication 行锁与 proof 不可变权限。证书未出现并不表示原关闭请求没有发出，原键和 started 私有日志继续保留，后续须再次明确交接。

再次核验采用独立入口 `continue-m6-abandonment-ack.mjs` 与新交接标志 `M6_ABANDONMENT_ACKNOWLEDGMENT_READY=true`，目前仅完成源码验证。自有 37/37、兼容 71/71，以及独立新增 25/25 测试通过；独立合并报告 `failed-issue-proof-read-lock-final-independent-unit.json` 为 190/190。守卫保留原 503 请求与 started 日志的完整快照和 SHA，核验对应权限错误时间、原请求键和请求体、当前完整对象与账本事实。若原证书已经完成，仅 GET 观察，总关闭 POST 数仍为 1；若完整事实仍证明资格且证书为 0，新的明确交接只允许一次同原键、同请求体的核验关闭，总 POST 数为 2。任何未知结果、证书或密文变化都会锁定，不重置旧日志、不换键、不重放已成功的首次恢复或已失败的执行。真实继续、浏览器、清理和最终扫描仍待实际交接。

发布证明读取锁的最终源码门禁为 `source-proof-read-lock-repair-release-gate.json`：全量 2,684/2,684、独立复核 190/190、部署工具 200/200、新核验入口兼容 71/71 通过。隔离 PostgreSQL 16.15 最终报告 `portal-failed-issue-abandonment-postgres-2026-10-11T00-31-22-521Z.json` 为 53/53，正式业务调用全部使用实际非 owner、非 superuser 运行角色（12 次，owner 0 次）；成功、原键重放及证书插入后的提交前故障均验证。会话故障使用真实同事务 SQL，租约和权限版本故障为明确夹具；真实网关仍由后续端到端验证覆盖。SQL000–009 与迁移器未变，proof 和 certificate 表仍只授予 SELECT/INSERT。新标签 `portal-proof-read-lock` 的部署仅构建 API 工作区并重启同一 API 进程，六步计划及前后连续性验证另行保留，不代表业务关闭已成功。

历史 Key 的实际恢复拒绝证据保留于 `security-live-pre-fix-abandonment-ack-remaining-http.json`（750/1、动态泄漏 0）和 `retired-parent-restore-denial-proof.json`。原 restore Mutation 已知 failed / KONG_VALIDATION_ERROR，remote_started=true 是 callback 标志，remote_completed=false、result 缺席；归档仍 deleted、1 个 affected Key 节点与 1 个 shared Consumer 节点、恢复节点 0、active refs 0、原生/门户未决 0。实际父 Consumer GET404，原 Key 和退役第二代 Key 代理均401，其他发布对象及另一集群有效 Key 均200。初次只读诊断因误限 reveal 历史响应为200而实际 Nest POST 为201停止，单独保留为 `retired-parent-restore-diagnostics-pre-key-selector.json`；未发送业务请求或公开 Key。

剩余继续入口 `continue-m6-retired-lifecycle.mjs` 需新的 `M6_RETIRED_LIFECYCLE_CONTINUATION_READY=true` 交接，只从此已证明拒绝之后继续，不调用原发放、元数据恢复、关闭、轮换、吊销或临时 reveal。它保留原750报告、restore请求快照/SHA和已完成证书，当前首份 grant/两代凭证为 revoked，另外两份为 active；新原键 GET、固定只读 SELECT、遮蔽查询和当前代理结果共同守门。完整脚本未来遇同类404也必须满足全部限定事实，不能只放宽状态码。

当前 whole Consumer 回收恢复路径会把原生发送前的受管所有权403包为503，可能产生 uncertain 回执，故本阶段不发送该已知会进入未知状态的额外探针。剩余测试改为普通 Consumer CREATE 使用同一已退役受管 UUID，要求精确403 PORTAL_MANAGED_OBJECT、原键 knownfailed/no completed result、当前 Consumer 缺席和旧 Key401。证据会明确其方法和入口，不称已验证 whole Consumer 回收恢复。M8 的 restore/import 预检必须在任何 callback/native发送之前，以数据库历史归属拒绝全部 Portal 受管身份，再实际复验 Consumer整图和Key历史恢复403及凭证始终不可复活；不放宽历史所有权，也不将该限制遗漏为已完成能力。

审计只读收尾的测试修订只影响秘密来源分类与验收脚本，未改变产品脱敏或重新部署。`audit-readonly-source-summary.json` 自有 80/80、`audit-readonly-independent-source-gate.json` 独立 48/48、组合 113/113 均通过；Root 核验原冻结 290 文件中只有已审阅的 `live-m6.mjs` 测试变更，139 个 API 编译文件和 3 个 Console 静态文件保持。`runtime-audit-readonly-verification-release-gate.json` 放行独立的新入口，未重放任何已完成生命周期、原执行或 Key 查看。实际 `security-live.json` 1057/0 和 `http-secret-artifact-scan.json` 零泄漏记录业务 HTTP/Native 写入 0、私有引用不变；原 1012/1 继续作为失败历史保留。日志范围包括实际第三台 `kong-portal`；不是只检查未承载门户流量的前两台网关。

浏览器首次实际验收单独保留为 `browser-first-masked-credential-attempt.json`：0/1，停止在登录后的既有应用详情，只有一次门户登录成功，未进行刷新、临时 Key 查看、新应用、新申请、审批或原生执行。`browser-first-readonly-application-diagnosis.json` 使用原浏览器会话进行 4 次限定 BFF GET，原账号/租户、既有应用、四份真实历史授权均存在，全部 200，私有引用字节不变。源码缺口为 `?tenant=` 初始选择没有写入会话存储，无参数整页导航重建门户时回到选择页；不能通过给测试的全部地址补参数掩盖用户刷新问题。产品窄修在成功解析当前公开租户后保存已匹配 slug，迟到结果、无效范围和存储异常有明确处理；自有 27/27 和 Portal 类型检查是源码证据，实际部署与剩余浏览器步骤仍待独立门禁。原登录及原失败必须保留，后续不能完整重播。

租户持久化产品修复的独立源码门禁为 `portal-tenant-selection-independent-source-gate.json`：独立真实 helper/实际 PortalRoot 的受控 hook/query/storage 验证 21/21，联合自有、PortalClient 与 Provider 竞态验证 61/61。三个产品/自有测试源码 SHA 与独立复核匹配，URL 成功解析后才保存、无参数详情整页重建、迟到 A 结果不覆盖 B、异常存储和显式范围清理均通过。手工脚本也改为凭证 UUID 的唯一真实表格行与所属卡片定位，避免同一出版 API 的失败历史授权造成双卡命中；尚未运行手工窗口。以上不替代实际静态部署和浏览器后续验收。

门户深链修复后的完整源码验证为 `source-unit-portal-tenant-repair-final-summary.json`：3,090/3,090、401 suites，通过 API、Console、Portal 三个工作区的类型检查。原浏览器会话读取程序的实际隔离数据库报告 `portal-browser-session-reader-postgres-2026-10-11T01-42-59-202Z.json` 为29/29：使用冻结 helper 的实际导出 SQL/program 与真实 PortalAuth/Audit、非 owner/非 super 角色；23 次读取进程中21条拒绝路径均不输出秘密。旧 text/UUID 与审计时间列错误在隔离库分别复现为42883、42703，当前运行库和历史会话未修改。独立一致性复核通过。新 `source-portal-tenant-deep-link-release-gate.json` 仅释放门户静态资源构建与前后连续性检查；API/Console构建、迁移及容器重启不在此窗口。剩余浏览器仍须实际部署通过后的独立窗口，不能从这些源码或数据库测试推断UI闭环。

门户静态部署两次在 before 阶段停止，分别保留 `portal-tenant-deep-link-deployment.json` 与 `portal-tenant-deep-link-coverage-corrected-deployment.json`。第一次是 Root 将可比较的冻结清单从290扩大到343，旧清单未覆盖的稳定文件被误认为变更；原 gate 已逐字封存，修正版保留308项可比较源与独立完整清单。第二次已创建六份旧门禁的 wx 档案，但尚未写 baseline，更未构建门户：只读诊断 `portal-tenant-deep-link-snapshot-diagnostic.json` 明确为 business-first / GRANT_UNAVAILABLE。原 grant 的 workflow_id 会在 rotate/revoke 时变化，当前窄修改用原 issue 工单不可变 subject_id、类型及 CID/WID JOIN，原工单/执行/版本/操作/审计仍保留历史身份。`portal-tenant-grant-resume-unit.json` 为79/79；`portal-tenant-history-reader-postgres-2026-10-11T02-00-07-099Z.json` 为真实隔离 PG9/9，11次实际导出程序运行，7条拒绝路径，使用非 owner/非 super 角色；pending/gen0 的合法指针回归不声称完整 generation2 吊销生命周期。源码工具、类型检查通过，产品及000–009未修改。后续执行须先独立复核、新冻结源，再从已完整封存的 before 档案检查点继续，禁止覆盖失败或旧档案。

新增浏览器 Key 扫描材料入口已有33项自有与21项独立源码检查（联合54/54）；实际 CREATE 步骤 logical entity_id 为NULL、原生UUID来自 sealed native_requests，以及真实 X-Portal-CSRF 合同已验证。`browser-key-scan-sql-handoff.json` 的6项仅为源码合同/编译检查，实际数据库验证明确 PG_PENDING。该工具未执行查看、未捕获新Key；原浏览器 firstFAIL、known login、续验三份源与原账本不变。两批规划交付时，实际部署、remaining browser、材料查看、manual、cleanup 与最终扫描仍未放行；后续按第一批 M6→M7→M8 顺序继续。

继续第一批后，门户静态修复的实际四个步骤全部成功，启动15、部署边界27、Admin37、监控54、门户79、连续性37项通过，API139和Console3个文件保持。独立 `portal-browser-session-reader` 的29项实际隔离数据库证据支持原会话恢复，不是重新登录。一轮 remaining 浏览器从唯一原 SID 继续：两次正常刷新、既有 Key 查看后清除、一次新应用创建与原键成功回执已完成。`browser-remaining-stop.json` 为0/1，停止位置是原键回执弹窗按钮：页面实际为“知道了”，旧测试期待“确定/OK”。该轮5次成功写的 requestId 和完整原键/会话记录保留；没有新凭证申请、Console登录、审批或执行。`browser-remaining-receipt-close-attempt/manifest.json` 封存该轮 Playwright 报告及结果，原首次32d764…和第二次3d9aab…失败JSON不改写。

新尾段入口 `run-m6-browser-tail.mjs` 还需独立的 `M6_BROWSER_TAIL_READY=true` 运行门禁。`browser-tail-owned-final-unit.json` 自有49/49离线检查通过，只使用合成会话和原公开失败字节；Node与TypeScript语法检查通过。它核验原5次成功写、四个已完成原始尝试、原应用的成功原键回执、唯一最新Portal具名cookie及真实只读会话程序，然后仅进行未开始的新申请、Console登录、审批执行和遮蔽截图。过期access最多一次原SID正常bootstrap刷新，不再测缺cookie刷新、不重放原登录/应用创建/Key查看。每次新写前同步保存完整原键/请求/actor/租户；网络中断立即标未知并禁止后续发包。Console登录还须确认返回原管理员ID及页面身份已加载，才导航工作流。该尾段尚未实际执行，不将源码检查描述为浏览器通过。

新增Key扫描工具另获真实隔离PostgreSQL16.15证据 `browser-key-scan-postgres-2026-10-11T04-18-17-139Z.json`：12/12通过，实际非owner运行角色、编译器、计划持久化、激活事务与认证/审计参与；Gateway成功ACK和读取响应是显式合成夹具。原6项SOURCE/PG_PENDING交接证据保持。这个12项数据库报告不替代浏览器或新Key的实际扫描材料查看；该工具仍待浏览器完成后单独放行。

`runtime-browser-tail-release-gate.json` 明确放行一次新 tail 后，`browser-verification.json` 实际1/0通过（SHA3349d7…341）。当前原SID仅额外一次正常bootstrap刷新，没有再创建应用或查看旧Key；新申请、当前真实管理员登录、单级批准和执行完成，4张新 `portal-tail-*` / `console-tail-*` 桌面与移动截图均在遮蔽状态生成。组合报告保留前一轮3张成功机制截图的路径与SHA以及两份失败JSON SHA；10次成功写、10个独立requestId与10个实际审计匹配。原具名jar继续存于历史快照，当前恰一份Portal和一份Console具名jar保留，Portal仍为原SID。自有49与既有remaining/scanner兼容回归组合114/114、Root独立58检查是源码证据，实际浏览器通过由此单独运行证明。

随后单独 `runtime-browser-key-scan-release-gate.json` 放行一次扫描材料查看，`browser-issued-key-scan-material.json` 实际通过（SHA2cee56…bac）：原Portal owner当前有效同SID、浏览器新应用/工单的成功原执行回执、generation1凭证、三个原生成功操作与两个typed refs经固定只读核验；仅一次该新Key的正常BFF reveal，实际requestId审计匹配，原生写入0、刷新/登录0。新Key只合并到原0600扫描引用，未生成截图或公开值；原密文与原生ID保持。该动作补齐浏览器新发放Key的最终扫描材料，不代替人工、资源清理或最终全范围扫描。当前运行窗口已暂停，私有引用继续保留。

`runtime-manual-read-features-release-gate.json` 放行一次手工测试后，原脚本在preflight停止：`UI-review-pre-launch-attempt.json`（SHAeb7a57…1f4b）保留0/1、plannedWrites0、actions空、截图0与Error分类。源码首个浏览器调用为裸 `chromium.launch()`，未使用Playwright配置中的系统浏览器路径；只读路径存在性检查确认默认bundled Chromium不存在、`/usr/bin/chromium`存在，没有再次启动浏览器或发出诊断HTTP。私有manualJournal仍保留stopped状态，不能清空或重跑旧脚本；后续需限定零发包事实守卫、原失败保留和独立新窗口。此停止不是手工交互验证完成，清理与最终扫描仍未开始。

分类分页与管理详情补缺已经部署。`source-unit-portal-read-features-final.json` 为全量3437/3437、430 suites，三个工作区类型检查通过；`portal-admin-catalog-postgres-2026-10-11T04-41-43-591Z.json` 为隔离 PostgreSQL 的32/32，使用实际非owner角色和当前权限，原生读取/ACK明确为合成夹具。`portal-catalog-admin-details-deployment.json` 的七条实际命令全部成功，启动15、部署边界27、Admin37、监控54、门户79及连续性27项通过。349项冻结源、000–009、原15个服务及全部门户历史/凭证/密钥材料保持；仅更新三端构建和重启原API进程。部署检查不替代新版UI的实际分类筛选及详情关系验收，手工脚本正为这些只读步骤补充核验。

手工零请求启动修复的限定续行真实启动了 Chromium，目录 GET 与安全 DTO 已通过。随后脚本按 textbox 角色寻找 Ant Design Input.Search；实际组件明确使用 type=search，其隐式角色为 searchbox，导致定位停止。`UI-review-pre-catalog-filter-attempt.json` 保留2/1、计划写入0、唯一已知401匿名启动刷新和实际目录 requestId；并无成功登录、内容变更或未知写入。此结论来自已保存报告与实际组件离线渲染，不冒称读取了原异常的详细消息。定位修正不改产品字段或降低 DTO 验收。

第三次手工实际报告原样封存为 UI-review-third-attempt.json（SHA85df06…91b9）：25/1、5张遮蔽截图、3次安全DTO读取。Portal owner与Console administrator两个登录均为201，原requestId保留；nextIndex2、inFlight空、未知操作0、四项Markdown及approver登录均未发。原脚本将包含外层Drawer选择器的inner locator传入Descriptions行的相对has过滤，源码核对确认定位机制不当；不据此声称产品详情缺失，也不重跑已有登录。后续只恢复两个经签名、当前会话及原审计证明的原SID，接续详情和五项未执行步骤。

审批模式元数据恢复的最终源码门禁 approved-metadata-restore-final-source-gate.json 为107/107聚焦与兼容检查、API与严格测试类型检查通过；portal-approved-metadata-restore-postgres-2026-10-11T05-28-22-307Z.json 为真实非owner PostgreSQL21/21。实际服务编译、get、独立审批、execute及原键重放均通过，撤权/full-before/版本/seal/晚租约回滚保持；原生Service只读和Redis租约为显式合成adapter，原生线上发包0，不替代部署后的通用HTTP审批模式验收。新 API-only 部署门禁保持000–009与原15服务/私有材料/全部历史事实，只允许该产品文件修复重编译与同容器API进程重启。

当前修复后的全量源码报告 source-unit-metadata-restore-manual-compatible-final.json 为 3,760/3,760、467 suites、零失败（SHA760102…458）。之前 3,751/9 的报告保持，九项失败均在旧 VM/AST 测试夹具兼容新续验入口时修正，未放宽安全断言或修改产品源码。三个工作区类型检查见 source-metadata-restore-three-workspace-typecheck.json。

API-only 修复的五个实际步骤前四项成功，第五项原连续性检查为 28/29：C2 catalog 79→80、epoch 2,335→2,342；其余服务、材料、历史凭证、迁移与静态文件均保持。portal-metadata-restore-metrics-readonly-diagnostic.json 的实际非 superuser READ ONLY 事务精确匹配原 after 哈希，并只移除七条已证明的续验记录及还原对应旧 closed_at 后精确重建 before 哈希；完整不可变 tuple、严格过期时间及合法关闭原因均通过。该诊断仍为 false，原因是窗口内一条尚待分类的审计记录；不能将精确 epoch 证明写成整体部署全绿，也不重跑已完成部署。

部署窗口审计分类已实际通过：deployment-window-audit-classification.json 为 1 行 system cluster/probe/success，时间位于已授权 API 重启期间，固定字段与启动源码相符；读取不包含 before/after/diff，未读 epoch 或秘密。portal-metadata-restore-deployment-closure.json 追加将此分类与七条过期续验的精确哈希证明组合，原部署、连续性和诊断 false 均保持，不回放部署。新 runtime-manual-detail-remaining-release-gate.json 仅放行原两个 SID 的详情与五项未执行手工步骤；实际结果仍须由新报告证明。

剩余手工窗口实际为50/1、11截图，原报告完整归档 UI-review-pre-publish-receipt-attempt.json（SHA707dcb…211）。原两个SID各进行一次正常刷新后，开发者/应用配置、授权/申请详情、二次确认与真实create父工单均通过。发布POST已201，脚本却对existing direct IAM实体错误要求Workflow回执而停止。manual-publish-original-receipt-readonly-diagnostic.json（SHA82b89a…abc）以原SID一次READ ONLY事务及两个普通BFF GET，证明原key实际IAM成功、remote_completed、page published revision3/documentRevision2，scope/actor一致；不重发发布。此记录也明确原publish目前仅有 iam.write.requested/pending 审计，不能冒称终态success审计或标准11已通过；M7须补齐direct metadata成功后的真实before/after/result与事务outbox。下一尾段只执行归档、恢复和审批者首次登录，所有原50PASS、11PNG、历史与已用两次刷新预算保持。Root另实际检查八张安全PNG，见 manual-publish-attempt-root-visual-review.json。


## 最终手工收口与工作区发现修复（2026-10-11）

`UI-review-pre-approver-read-attempt.json` 原第五停止报告为71/1、17截图：全部7项计划请求已成功，但仅有workflows权限的审批账号无法发现已授权工作区，前端未发工单详情GET。`AuthorizationService.permits` 的workspaces read分支改为复用既有discoverableModules，仍用同一个完整grant与CID/WID范围校验；四种运营模块的实际实体读取与列表过滤、跨集群/工作区、写入和原生实体拒绝18/18通过。`portal-operational-discovery-api-deployment.json` 实际5步全部exit0、健康3/3、连续性6/6，源与容器compiled Authorization SHA相同，其余19服务、两前端静态文件、私有材料与SQL000–009记录均未变。

`manual-readonly-closure-verification.json` 使用原审批SID，一次READ ONLY事务核验真实签名/当前会话/hash/原登录审计及九次手工请求审计；浏览器一次原工单GET实际403 PERMISSION_DENIED，工作区发现已可用，页面显示权限错误且无计划/执行入口。此次无业务写入、登录、刷新或Admin API请求。`UI-review.json` 聚合77/0、18截图，继承检查和原五份停止档明确链接；原七个计划意图及其幂等键不重发。原两次手工接续刷新加上独立正常续期两次分别记录，后者见`manual-tail-normal-session-renewal.json`；总11个成功请求审计存在性11/11，不等同于before/after终态完整性。

Root已实际查看全部18张手工截图，新尾段六图与最后审批拒绝图分别见`manual-publication-tail-root-visual-review.json`和`manual-readonly-root-visual-review.json`。全量源码最终`source-unit-workspace-discovery-repair-final.json`为3,782/3,782、473 suite通过；原失败测试和连续性报告保持。测试数据清理及清理后的最终秘密扫描另行记录，不由本节推定成功。


## 清理与只读审计收口（2026-10-11）

`failed-fixture-cleanup.json` 现聚合298/0，14个根对象进入回收站、24项元数据软归档；保留原七条历史认证面、集群基础设施和监控用途材料。原295/1停止报告另存`failed-fixture-cleanup-before-audit-closure.json`，当时全部清理操作成功，最后审计秘密来源扫描因完整历史副本超过遍历预算停止。纯RAM诊断明确该原因，无数据库或HTTP请求。

扫描来源算法使用有物理对象/字节/深度预算的结构摘要与上下文去重，未移除任何真实候选或增加语义访问上限；重复历史、POST正文/查看响应/未知副本、唯一超预算、环和深度反例均通过。Owner29/29、独立8/8通过。`cleanup-audit-readonly-closure.json`只用一次READ ONLY事务核验全部239个成功请求：239个独立requestId均有审计、patch均为数组、实际凭证候选未见于before/after/patch；仅排除两个经运行时compiled SecretService证明的脱敏指纹，未知指纹和UUID未排除。未重发任何清理、登录、刷新或原生写。原失败与完整请求历史保留，私有阶段现为cleanup-complete。终态before/after审计验收仍明确false，由M7解决。最新全量`source-unit-cleanup-provenance-final.json`3,798/3,798通过。

## 最终秘密扫描与交付闭环（2026-10-11）

`runtime-secret-artifact-scan.json` 的 SHA-256 为 `797580a72d6d722c27736cee8a073ed67c40f3b05012b71929a48362c28ec0d5`，allPassed=true。实际扫描1,710个文件、6个嵌入文件和145个编译文件；7个运行服务的新stdout/stderr均成功采集，泄漏0，原始日志未公开。扫描包括全部新旧测试证据、源码与未跟踪源码、三个应用编译结果、截图、嵌入报告、环境及可选提供者秘密和当前四用途监控材料。

生产材料保留；两份指定测试临时私有引用在完整报告安全落盘后已删除。扫描后仅更新本节和交付状态的非秘密文字与计数，源码及扫描范围不变。最新全量源码3,798/3,798通过，独立分类器另增加旧算法差分断言后8/8通过。M6的产品、部署、HTTP、浏览器、手工、清理与秘密扫描至此闭环。原标准11的终态diff缺口仍明确交由M7补齐，并需新实际证据，不以本里程碑完成推定全部13项验收通过。
