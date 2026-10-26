# KongPilot v1.0 平台发布闭环实施清单

审阅时间：2026-10-13 UTC。状态：**只读源码与既有证据审阅、后续实施契约；本文件没有执行生产验收**。

本清单覆盖 KongPilot Console/BFF、Portal、平台 PostgreSQL/Redis、实际启用的监控与受控发布工具。按用户确定的范围，不把 Kong 二进制及其数据库的历史版本风险作为平台商用阻断项，不修改 Kong 源码，不连接、备份或恢复用户的 Kong 数据库，不停止用户网关。平台仍须验证 Kong 1.5.x Admin API 兼容、当前授权与配置变更安全。

M9 的阶段验收已提交于 `0f03f50`；M10 当前在独立真实环境补齐阶段验收，M11 未交付。本文件不能代替 M10/M11 验证记录，也不能将 RAM 实验宣布为持久生产站点。先完成原需求 M10/M11，再按下列顺序冻结 v1.0 和验收平台发布。

## 1. 本次已核实的现状

| 项目 | 已有依据 | 尚未闭合 |
| --- | --- | --- |
| 应用依赖 | 当前 lock SHA256 为 `e6152e73e1a091bcdd22eb53ca87d0d4a6c11509f99e2294425c76b691be49e2`，与上一轮全依赖/生产依赖 npm 公告零发现所用锁文件一致 | 本次没有重新查询公告；最终镜像、系统包和前端 bundle 仍需新扫描 |
| 运行镜像 | API/collector 固定 distroless Node 22 基础 digest、UID 1000；Web/Portal 固定 Nginx 基础 digest、UID 101 | 构建 Node、平台 PostgreSQL/Redis、Prometheus/Loki 与 runner 仍有可变 tag；Web 的 `apk upgrade` 使实际输出随构建时仓库变化 |
| 历史镜像扫描 | M8 sec4/sec5/sec6 的部分旧 API/Web/Portal/collector 镜像实际扫描高危/严重为零；具体 digest 和扫描时点见历史报告 | 不能沿用为新品牌或 M11 发布镜像的结论；旧平台 PostgreSQL/Redis 等扫描结果仍有发现，需要按最终选择的 digest 处置 |
| 生产 Compose | 生产 overlay 已包含 HTTPS、只读根文件系统、非 root、capability 收缩、资源限制和日志轮转；基础配置包含平台持久卷 | 本次尚无最终版本的持久冷启动、重启、真实域名/TLS、容量和恢复证明 |
| 已有 Kong 接入 | `compose.external-kong.yml` 移除启动网关依赖；`production-policy.mjs` 的 `externalKong=true` 分支可拒绝 Kong/KongDB 服务 | 组合策略只返回 `runtimeVerified:false`；实际网络、TLS 和最终镜像需现场核验 |
| 数据库校验 | `SKIP_MIGRATIONS=true` 的运行路径比较镜像 SQL 名称/真实字节 SHA256 与迁移账本，发现不一致拒绝启动 | 最终迁移集及生产运行角色需实际验证；不得以源码测试代替真实数据库启动 |
| 备份恢复 | 现有联合实验工具有加密归档、checkpoint、会话撤销和 fresh Redis 逻辑 | 旧工具会停止/备份/恢复 Kong/KongDB，不适合作为本次平台专用生产入口；异机存储与密钥分离没有现场证据 |
| 密钥 | 原主密钥用于 AES-GCM、快照 DEK 包装及长期 HMAC/fingerprint | 无版本化 keyring 或可直接使用的全库轮换工具；直接改主密钥会破坏历史数据/校验 |
| 版本与仓库 | 产品 UI 显示 `v1.0`；origin 为 `sean-y-wang/kongpilot-console` | root/API/Web/Portal/contracts 的 npm 版本及 Swagger 仍为 `0.1.0`；未声明 Node/npm engines；不存在 `.github` 流水线 |

历史平台依赖结果需要正确保留：2026-10-12 初次扫描的旧 PostgreSQL 16 digest 为 1 Critical / 24 High，旧 Redis 7 digest 为 2 High；这是**旧产物的观察结果**，不是对当前未知生产实例的结论。Prometheus/Loki/旧 runner 的发现也不能因它们是可选组件而忽略：启用哪个组件，就扫描并处置其最终产物；未启用项不纳入该部署的运行结论。

可复用的公开扫描工具仍在 `/dev/shm/kongos-production-public-tools`：Trivy `v0.75.0`、Syft `v1.54.1` 的实际二进制 SHA256 与历史官方下载记录一致。本地 Trivy DB 的 `UpdatedAt=2026-10-11T13:06:05Z`、`NextUpdate=2026-10-12T13:06:05Z` 已过更新期；最终扫描需更新数据库并保存新的元数据。本次没有执行扫描、下载、安装或 Docker 服务操作。

## 2. 最小完整实施顺序

| 顺序 | 实施内容 | 完成证据 |
| --- | --- | --- |
| 1 | 完成 M10 的真实双环境发布/凭证/回滚/自然调度/审批/浏览器/审计/秘密扫描；按原方案实现并验收 M11 | 独立阶段报告、原请求与逐步回执、失败历史、源码回归、实际 Kong 1.5.x 结果；不得以 mock 结果替代 |
| 2 | 统一 `1.0.0` 软件版本与 `v1.0` 产品展示，固定接受的 Node/npm 工具链，建立 CI | 五个 manifest、lock workspace 版本、Swagger/产品版本一致；生产 Node 版本下构建与测试通过 |
| 3 | 实现平台专用备份/恢复与固定恢复闸，明确主密钥保全/轮换契约 | 只操作明确的平台项目；恢复不会启动旧任务、外发通知或写入现有网关；负面测试和隔离真实恢复通过 |
| 4 | 冻结 final commit、SQL、lock、各平台镜像；完成新 SBOM/OS/应用/秘密扫描 | 每个最终 digest 对应独立报告；扫描 DB/tool 时点、处置结论及保留风险明确；失败不覆盖 |
| 5 | 使用已有 Kong 模式，在独立持久平台项目启动最终镜像并验证 TLS/边界/重启/容量 | 实际卷来源、健康、TLS、Cookie、权限、网络拒绝、重启前后业务回执；不是 RAM 或 `NODE_ENV=test` |
| 6 | 在另一独立主机恢复平台备份，真实取回分离保管的恢复密钥，验证完整 RPO/RTO | 新项目、新卷、旧令牌拒绝、审计链/原账本一致、密文可用、自然周期零写入/零投递；未触碰用户 Kong/KongDB |
| 7 | 完成该站点实际启用 provider 的联调、操作手册和发布交接，发布 GitHub v1.0 | 源码/镜像/证据/手册同 revision，发布资产无秘密，运行参数有受控管理位置，维护与恢复责任明确 |

步骤 2/3 可以在 M11 期间由独立负责人按文件归属准备；最终产物冻结和商用结论必须在功能代码稳定后执行。没有实际异机资源或 provider 联调对象时，只能交付工具与验证方案，并明确现场项待完成，不能标记为已验证。

## 3. 发布资产与流水线契约

以下路径为**建议新增的实现归属**，当前不存在的文件不是可运行命令：

| 文件/范围 | 最小契约 |
| --- | --- |
| `package.json`、各 workspace manifest、`package-lock.json`、`packages/contracts/src/branding.ts`、API Swagger metadata | 版本来自同一发布输入；root/API/Web/Portal/contracts 为 `1.0.0`，UI 为 `v1.0`；选择并记录生产 Node 22 实际 patch 和兼容 npm 版本，不虚构上游最新版本 |
| `.github/workflows/ci.yml` | PR 使用锁文件安装、严格 TLS、类型检查、全源码测试、三个 build、迁移/权限/security source checks；只读默认权限、固定 action revision；不向 fork/PR 提供生产秘密 |
| `.github/workflows/release.yml` | 冻结发布 revision；隔离真实兼容/浏览器验收、镜像构建、SBOM、扫描、秘密扫描和恢复测试；镜像发布后重新按 registry digest 核验；不连接生产 Admin API，不打印展开 environment |
| `deploy/releases/v1.0.0/manifest.json` | 记录 commit、版本、lock SHA256、SQL 名称+SHA256、平台组件的 registry digest/本地 image ID/平台架构、Dockerfile/Compose 摘要、测试报告/SBOM/扫描报告摘要与时点、启用 profile、已知限制；不含 endpoint 凭证、环境秘密或原恢复材料 |
| `deploy/compose/compose.release-platform.yml` | 仅 pin 平台 PostgreSQL/Redis 及实际启用辅助组件的 digest，应用镜像从冻结清单选择；不能因平台发布升级或改写用户 Kong/KongDB |
| `artifacts/ReleaseV1_0/` | 每次验证使用新 attempt 文件，保留旧失败；最终 index 只链接实际完成的证据；区分 source-only、isolated-runtime、persistent-site、offhost-recovery |

image ID 不是 registry manifest digest；发布清单记录两者的实际对应，不能把历史 `sha256:<image-config>` 直接写成 registry pin。固定基础 digest 也不证明整个构建完全可复现；保存实际构建产物与包清单，刷新基础镜像时重新扫描、启动和记录。

流水线不应直接搬用当前硬编码 RAM 地址/私有 journal 的 native runner。需由新的 CI 适配器创建独立项目、临时秘密和 private ledger，绑定实际项目/容器/tuple；沿用原请求先落盘、未知写入不重发、证据脱敏的规则。现有真实验收脚本可作为契约参考，不能通过跳过环境闸让它连接不明目标。

## 4. 平台专用备份与恢复契约

建议新增 `deploy/scripts/platform-backup.mjs`、`platform-restore.mjs`、`platform-recovery-policy.mjs`，独立于旧联合实验脚本。备份和恢复都先验证明确 Compose project/service/volume 所有权、输入目录与权限；拒绝 symlink、覆盖原材料、生产卷复用、任意命令及任何 Kong/KongDB 服务。每次操作有受保护原 ledger 和公开安全摘要，摘要不能包含解密钥匙。

**备份：** 暂停平台入口及全部平台 writer/worker，在该项目的 PostgreSQL 主版本匹配工具下导出整个平台库并保留实际约束/触发器/迁移校验。记录 UTC 备份窗口、SQL/checkpoint/审计链头/未完成作业和导出摘要。Redis 可私有归档以便调查，但恢复使用 fresh Redis，不能重新激活旧锁、OAuth 状态或令牌。平台配置、必要 TLS 材料、原加密密钥或受管 keyring 一并纳入受控材料；备份归档的认证加密密钥独立生成、异机分离保管。

**恢复：** 新建独立平台项目与持久卷，先不开 API、worker、公共入口或外发链路。验证归档认证、完整摘要、版本/SQL/checkpoint，再整库事务式恢复；不得删约束或重算历史 HMAC 使导入成功。原 audit、幂等账本、工单计划、configuration 来源与回收 component 必须原样保留。离线撤销旧 Console/Portal/decK session 与未消费敏感下载 grant，并保存合法恢复事件；保留原会话关联行。APP/PORTAL 签名秘密可以按会话策略单独更新，数据加密/HMAC 主密钥不能直接替换。

**恢复闸：** 建议新增统一 `PlatformRuntimePolicyService`，使用固定 `PLATFORM_OPERATING_MODE=normal|maintenance|recovery` 受控启动策略；无效值拒绝启动，不从 HTTP 请求动态关闭。maintenance/recovery 都暂停后台业务生产者、通常业务写入和外部 side effect；recovery 默认再禁止一切 Kong/外部 provider 请求，只有明确后续正常恢复步骤才接通。允许受控本地账号 login/refresh/logout、健康与确实只读取平台库的已授权 Console 查询；登录产生的合法新 session/审计单独记录，不伪造或覆盖恢复前历史。不能泛化放行所有 GET，也不能把 LDAP/OIDC 请求算作本地认证。

最小代码落点为 `apps/console-api/src/infrastructure/platform-runtime-policy.service.ts` 与 `app.module.ts` 的共享 provider、固定前端 HTTP 业务入口守卫、KongExecutionContext/KongService 的真实传输前检查、各独立出站 transport。worker 在启动、claim 和执行前都校验，避免手工调用 tick/runOnce 绕过“未注册 timer”。metrics 的独立 TCP listener、provider auth、工具箱代理 probe、Prometheus/Loki 查询与 SMTP/HTTP delivery 不经过通常 Console controller，必须在各自传输入口覆盖。

| 当前生产者/旁路 | 必须停止的入口 | 源文件 |
| --- | --- | --- |
| 定时快照/治理 | timer 注册、tick/claim、occurrence 和 capture；未来 M11 executor 一并纳入 | `modules/configuration/configuration-scheduler.service.ts`、`modules/governance/governance-scheduler.service.ts` |
| 事件观察 | 启动调度、tick/sample、观察事实与通知生产 | `modules/event-observers/event-observer.service.ts` |
| 审计导出 | 2 秒后台 worker、claim 和生成文件；只读审计列表/完整性检查可保留 | `modules/audit/audit-export.service.ts` |
| 实体索引 | 启动立即 tick、20 秒轮询、手动同步和 SQL index 更新 | `modules/entities/entity-index.service.ts` |
| 指标归属/桥接 | 5 秒 catalog、ensureFresh/scan、独立 scrape/catalog/validate listener | `modules/vitals/bridges/metrics-catalog.service.ts`、`metrics-bridge.service.ts` |
| 事件 outbox/投递 | 注册 poll、runOnce/claim、fanout/receipt、HTTP/SMTP 发送 | `modules/event-core/outbox-worker.service.ts`、`modules/event-delivery/delivery-worker.service.ts` 及其 transport |
| 集群启动初始化 | bootstrap 元数据与异步 Admin probe；不能恢复后自动创建默认集群 | `modules/clusters/clusters.service.ts` 的 `onModuleInit` |

现有 scheduler、observer、导出、索引没有统一总闸；`EVENT_OUTBOX_WORKER_ENABLED=false` 与 `EVENT_DELIVERY_WORKER_ENABLED=false` 只覆盖对应 worker。网络隔离是独立兜底，不能用网络错误代替恢复闸，也不能只撤销 SID 来阻断无 SID 的调度。

离线恢复先核验原 checkpoint；随后在恢复闸下开放受控本地认证、schema 与平台库只读检查。完成授权的当前只读比对后，按明确恢复步骤分别开放只读网关访问、writer 与外发。`running/partial/uncertain` 或 `remote_started && !remote_completed` 的原 job/mutation/workflow/delivery 保留原事实，不 SQL 改成功、续期、清空 key 或自动重发。用户网关在平台故障期间继续工作；恢复平台元数据不等于回退网关配置。需要网关回滚时另行生成当前 Diff/确认/审批操作。

平台库含集群/数据源连接密文、credential_refs、回收对象图、mutations/IAM/迁移意图、门户凭证与文档、workflow 版本/回执、通知渠道版本、审计导出、快照 DEK 与对象/计划密文、M9 草稿、M10 报告/比较/Promote 原材料。不能只备份 YAML 或挑表导出；密码 hash、token hash、审计链、plan/HMAC/origin 绑定也需保留原值。

最小真实恢复验收：

- 原 SQL checksum、约束/不可变权限、审计行/链头、关键密文 digest 和原 job/key 事实一致。
- 凭证、回收图、快照 DEK/对象、工单回执、通知渠道、M10 比较可在受控验证器中解密，验证器只输出结果/计数，不输出秘密。
- 旧 Console/Portal/decK/download 令牌拒绝；fresh Redis 未导入旧锁和 token。
- 等待至少一个已登记调度的自然到期周期；恢复闸下不产生新的调度 occurrence、Kong 写入或外部投递，不伪造时钟、SID 或 lease。
- 原未知任务不重放；用户 Kong 的容器/进程/数据库未被恢复工具触碰。
- 备份与恢复钥匙确实从不同权限域的异机位置取回；记录备份数据时点、恢复完成时点、实际 RPO/RTO，不能只报告 `pg_restore` 耗时。

建议真实 HTTP 验证矩阵，前缀均为 `/api/v1`，CID/WID/key 使用原授权 tuple，而非虚构管理员或 SID：

| 请求/场景 | 恢复闸下预期 |
| --- | --- |
| `GET /health/live`、`GET /health/ready`；本地 `POST /auth/login`、`GET /auth/me`、`POST /auth/refresh`、`POST /auth/logout` | 正常可用；登录/会话行为记录合法新事实，不能隐式打开外发 |
| `GET /clusters`、`GET /clusters/{cid}`、`GET /clusters/{cid}/audit`、`GET /clusters/{cid}/audit/integrity` | 当前权限下安全返回、0 Kong/外部请求；越权仍 403 |
| `GET /clusters/{cid}/governance/reports`、原 job/workflow/by-key 查询 | 逐条证明 SQL-only 后允许；若读路径需要重新采集或验证来源网络，应拒绝，不能放宽 origin 验证 |
| 集群/数据源 probe、`GET /clusters/{cid}/toolbox/status`、proxy probe、Vitals overview、LDAP/OIDC | recovery 下拒绝，0 DNS/连接/网关 packet/外部投递；不能只看请求返回码 |
| 创建/修改/删除实体、缓存失效、configuration apply/rollback/export、审计 export、workflow execute、Promote、Portal credential request/rotate | 拒绝且无 business job/claim/native/外发副作用；不改变原 key 对应历史终态 |
| 恢复库包含自然 due schedule、queued export、outbox、delivery 以及未来 M11 scheduled intent | 等待实际到期周期；记录 baseline 与之后 ledger/独立接收器的事实，0 新 occurrence/claim/导出/投递/native packet |
| 直接调用内部 worker tick/runOnce、独立 metrics bridge 请求、已进入请求的传输前检查 | 仍受相同固定 policy；不能通过跳过 UI/HTTP 守卫发送 |

恢复闸拒绝码应统一为可读平台维护/恢复状态，UI 提供状态与可用只读入口；不把“关闭按钮”或来源授权缺失伪装成维护策略。

## 5. 主密钥保全与轮换

`SecretService` 的现有 `CONSOLE_ENCRYPTION_KEY` 同时用于 AES-GCM 和长期 HMAC/fingerprint，`SnapshotCryptoService` 还用它包装 DEK。原平台迁移/审批/来源校验依赖这些值；品牌更名不得改变原 AAD/domain。当前没有版本化 keyring，不能以改 `.env` 后重启冒充轮换，也不能为轮换 UPDATE 只追加历史表或重写已冻结 payload/hash。

可执行的最小轮换设计应先区分**加密包装密钥**、**数据加密密钥**和**稳定历史校验密钥**：保留旧格式解密和旧 HMAC 语义，新增材料采用明确 key ID；用版本化外部 keyring/KMS 包装内部密钥，轮换外层 KEK 时验证旧密文仍可解密、旧 plan/HMAC 仍匹配。工具必须有 dry-run、精确材料清单、原/新密钥可恢复副本、CAS/未知结果账本、完整验证及失败回滚，不发布 key、plaintext 或密文正文。

外层 KEK 轮换不等于消除已泄露的旧 DEK/HMAC 风险；如果要求吊销旧数据密钥，需要另外设计历史材料保留、重加密与不可变审计的协议，不能含糊宣称全库已轮换。本次首次商用至少完成主密钥分离保管、异机取回、加密数据验证与事故处置手册；是否交付在线全库轮换按已确定的运维策略纳入正式发布范围，不增加凭空的审批流程。

## 6. 持久站点与最终使用手册

正式站点使用 `compose.production.yml` + `compose.external-kong.yml` 及实际启用的 metrics/gitops overlay，不使用 development/release-lab RAM overlay；数据库与 Redis 采用已记录的持久 volume。只在内存中校验展开配置，公开报告仅保留安全形状/摘要。检查 API/migrator 同镜像、非 owner 运行角色、生产 Cookie、精确 HTTPS Origin、独立 Console/Portal hostname、可信代理层、最小出站主机与真实 TLS 证书。

需要实际验证：重建应用容器/重启平台存储后 RBAC、审计链、回收对象、快照、门户、工单和原操作回执保留；入口证书/完整链/Host/Cookie/安全头正确；浏览器/Portal/collector/runner 均无法越过 BFF 访问 Admin 或平台存储；锁/限流/并发与失败恢复符合记录的容量目标。单节点 Compose 不承诺 HA/SLA；历史有限并发只读测试不是最终业务容量证明。

最终更新 [部署与运维手册](../../manuals/production-operations-guide.md) 和 [用户使用手册](../../manuals/console-user-guide.md)，同步 M10/M11 实际能力、审批时限/计划执行、原回执查询、故障不重放、备份恢复和版本/升级步骤；平台用户菜单文档入口应加载同一冻结 revision。没有真实联调的 LDAP/OIDC/SMTP/Slack/飞书等 provider 保持关闭，并明确该站点未启用；本地模拟接收器只证明协议链路，不证明生产渠道。

## 7. 证据来源

- [平台前置审阅](release-v1.0-platform-prerequisites.md)：之前的 npm 公告与源码校验；不是最终镜像验收。
- 平台只读审阅摘要 (`artifacts/planning/kongpilot-platform-prerequisites-review.json`, not public)、公开扫描工具记录 (`artifacts/planning/production-scan-tool-download.json`, not public)、公开漏洞库记录 (`artifacts/planning/production-vulnerability-db-download.json`, not public)。
- 旧平台 runtime 扫描 (`artifacts/Production/root-production-security-runtime-v4-scan.json`, not public)、旧 API/Web 扫描 (`artifacts/Production/root-production-oauth-ttl-sec5-image-scan.json`, not public)、旧 API sec6 扫描 (`artifacts/Production/root-production-route-scope-sec6-scan.json`, not public)。
- 旧平台基础设施风险登记 (`artifacts/Production/root-production-infrastructure-risk-register.json`, not public)：历史范围还包含 Kong；本清单仅采用平台相关观察，不据此改动 Kong。
- [生产组合策略](../../../deploy/scripts/production-policy.mjs)、[外部 Kong overlay](../../../deploy/compose/compose.external-kong.yml)、[原加密服务](../../../apps/console-api/src/infrastructure/secret.service.ts)、[快照加密服务](../../../apps/console-api/src/modules/config-storage/snapshot-crypto.service.ts)。

以上证据明确分开历史观察、当前源码与未来现场验收。本次只新增本清单，未修改应用/部署源码、读取私有环境凭证、安装工具、拉取镜像、连接服务或执行外部通信。
