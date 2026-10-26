# KongPilot v1.0 平台生产准入前提

检查时间：2026-10-12 UTC。范围仅包括 KongPilot 的应用、平台数据库、Redis、前端入口及启用的辅助组件。按用户要求，**不将 Kong 本体及其数据库的版本风险作为平台商用阻断项，也不修改现有 Kong**。

本次完成只读依赖/部署审阅，并按 Root 分配补充平台 API 启动时的只读 schema 校验；没有构建、部署、重启现有服务、读取私有部署环境文件或执行网关写入。M9 原执行的未知终态仍需其独立恢复证据；M10/M11 及最终商用验收不能由本报告替代。

## 已确认的基础

- 对当前锁文件分别执行全依赖与 `omit=dev` 公告查询：均为 **0 个已报告 npm 漏洞**。指定 `https://registry.npmjs.org/`、严格 TLS、`package-lock-only`、禁用安装脚本及 fetch 重试；没有安装或更新依赖。锁文件 SHA256 为 `e6152e73e1a091bcdd22eb53ca87d0d4a6c11509f99e2294425c76b691be49e2`。这不等于镜像系统包、前端 bundle 或所有可利用性已验证。
- [API Dockerfile](../../../apps/console-api/Dockerfile) 与 [collector Dockerfile](../../../deploy/metrics-collector/Dockerfile) 已固定 distroless Node 22 / Debian 13 基础摘要，运行用户为 `1000:1000`；[Console](../../../apps/console-web/Dockerfile) 与 [Portal](../../../apps/portal-web/Dockerfile) 固定 Nginx 基础摘要并以 `101:101` 运行。旧依赖清单中“所有镜像均未固定 digest”的表述不适用于当前源码。
- [生产 overlay](../../../deploy/compose/compose.production.yml) 提供只读文件系统、capabilities 收缩、进程/内存限制、HTTPS 与日志轮转；[基础 Compose](../../../docker-compose.yml) 为平台 PostgreSQL、Redis 定义持久卷，迁移进程完成及存储健康后才启动 API。前端没有 Admin API 或平台数据库网络权限。
- [生产环境模板](../../../deploy/production.env.example)、`.dockerignore` 和 `.gitignore` 保护部署秘密；[运维手册](../../manuals/production-operations-guide.md) 已区分正式站点、RAM 实验、外部 Kong 与备份材料责任。
- 已补 [DbService](../../../apps/console-api/src/infrastructure/db.service.ts) 的 runtime 校验：`SKIP_MIGRATIONS=true` 时，以应用镜像内的全部有效 SQL 文件名称及真实字节 SHA256 对比 `schema_migrations`。缺失、修改、意外未来版本或无效 ledger 会拒绝启动；运行角色只执行 SELECT，不执行 DDL、初始化或修复。错误仅含安全 code 和合法 SQL 文件名。**17 项新增测试与 6 项原存储测试均通过**；这是源码证据，部署验收由 Root 执行。

## 正式发布前需闭合的事项

| 优先级 | 具体发现与来源 | 建议修复及验收证据 |
| --- | --- | --- |
| P0 | 当前功能联调使用 RAM / 独立 release lab；持久平台站点尚无本次 v1.0 完整证据。持久卷的源码声明不能证明实际数据会保留。 | 在目标主机使用独立生产 project、持久卷和真实域名/TLS。验证断电或重启后的 RBAC、会话策略、审计、回收图、快照、门户与原操作回执。保存最终镜像摘要、有效配置安全摘要、实际 volume 来源、健康与网络边界证据。 |
| P0 | 当前 npm 公告查询为零，但没有为最终 v1.0 发布镜像执行本次新 SBOM/系统包扫描。Node/React 编译通过与历史镜像扫描均不能替代。 | 冻结 commit/lock/SQL/各平台镜像 digest，生成最终 API、Web、Portal、平台 PostgreSQL、Redis及实际启用的 collector/runner/Prometheus/Loki 的 SBOM和扫描。对可利用项修复或记录具体处置；不要将 Kong 本体纳入此平台结论。 |
| P0 | [联合备份脚本](../../../scripts/verification/coordinated-backup.mjs) 与 [恢复脚本](../../../scripts/verification/lab-restore.mjs) 显式限制旧 RAM 联合实验，并包含停止 Kong / 导出 Kong 数据库。它们不是“只管理已有 Kong”的生产备份入口。 | 新增平台专用备份/恢复工具：仅操作平台 PostgreSQL、受控 Redis 策略及平台密钥/配置；网关配置通过已授权的控制台快照协调，现有 Kong 数据库由其运维方维护。异机恢复前阻断旧会话、外部投递和定时执行，保持未知写入事实，验证审计链、凭证解密、回收图及完整 RPO/RTO。禁止照搬联合脚本停用户网关。 |
| P0 | 联合备份脚本将加密归档与恢复钥匙写入同一受保护输出目录；已有手册要求独立权限域，但异机存储和密钥分离未现场验证。 | 为备份建立独立存储、访问策略与保留期，恢复密钥单独保管；验证丢失主机后的完整恢复及无旧任务重发，保存时间和数据一致性证明。 |
| P1 | [平台运行镜像](../../../docker-compose.yml) 中 PostgreSQL 16、Redis 7 与可选 Prometheus/Loki 使用可变 tag；API/Web/Portal build 以及 [decK runner](../../../deploy/deck-runner/Dockerfile) 的 Node 基础也未固定摘要。Web/Portal 的 `apk upgrade` 会随构建时仓库变化。 | 发布清单使用具体镜像 digest，并建立有记录的基础镜像刷新流程；扫描实际构建产物而不是只扫描基础 tag。保留中间构建工具链版本与最终包清单，不以“固定基础摘要”宣称整个构建已经完全可复现。 |
| P1 | API/构建使用 Node 22，当前开发工具为 Node `v24.19.0` / npm `11.9.0`；工作区没有声明 `engines`。本轮没有读取运行镜像实际 patch，也未成功获取最新官方生命周期表。 | 在 CI 中固定项目接受的 Node/npm 版本，并针对生产 Node 版本执行构建与关键测试；发布时核对 [Node 官方生命周期](https://github.com/nodejs/Release#release-schedule) 和镜像 patch。Node 22 的常规维护期限为 2027-04-30，需制定平台升级时间，不能无限沿用旧 digest。 |
| P1 | 仓库当前没有 `.github` 工作流，无法证明每次合并和发布都会自动执行现有验证及产物扫描。 | 增加 PR 的锁文件安装、类型检查、单元/安全测试与构建；发布流水线执行独立真实 Kong 兼容验收、浏览器、安全扫描、SBOM、迁移/恢复、秘密扫描并冻结发布清单。CI 使用临时私有测试秘密，不连接实际生产 Admin API。 |
| P1 | [运维手册的密钥轮换章节](../../manuals/production-operations-guide.md#14-密钥轮换与凭证维护) 明确：加密主密钥参与密文与历史指纹，尚无可直接使用的全库重加密工具。 | 明确密钥保管与事故处置；若商用策略要求在线轮换，补充版本化密钥、全库重加密/校验和回滚工具，并在隔离恢复副本验证。不得通过改环境变量后重启冒充轮换。 |
| P1 | [生产 composition policy](../../../deploy/scripts/production-policy.mjs) 校验部署合同，但返回 `runtimeVerified:false`；基础 Compose 的出站允许列表含开发目标，外部入口和 provider 的实际配置仍由现场决定。 | 生产配置使用精确集群/数据源/通知/IdP 主机，禁用未联调 provider，并现场验证 BFF 唯一管理出口、数据库私网和拒绝路径。只输出安全配置摘要，禁止发布展开后的完整 Compose environment。 |

P0 项作为正式平台站点准入证据，P1 项纳入发布与持续维护流程；是否需在首次交付前完成具体密钥轮换能力，应由组织的实际运维策略决定，不凭假设新增审批阻断。M10/M11 的实际功能与原需求安全验收仍按其里程碑完成。

## 推荐的交付顺序

先完成 M9 原执行终态的安全闭合，再交付 M10/M11。冻结 v1.0 后完成平台镜像/依赖扫描、生产配置核验、持久冷启动及异机恢复；最后验证实际启用的外部 provider、业务容量、审计覆盖和用户操作，再形成平台商用结论与 GitHub 发布。

本次安全摘要及源文件 hash：platform prerequisites review (`artifacts/planning/kongpilot-platform-prerequisites-review.json`, not public)；启动校验测试：runtime schema source (`artifacts/planning/platform-runtime-schema-source.json`, not public)。两份证据没有包含私有环境内容，不能替代现场生产验收。
