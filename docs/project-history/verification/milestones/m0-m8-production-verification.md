# M0–M8 生产阶段验收记录

当前状态：**M0–M8 阶段技术验收已执行，功能与恢复实测通过；生产商业放行门槛未通过。**本文件登记本次阶段交付范围与结果落盘位置，不预填通过。M8 当前证据见 [集成验证记录](m8-integration-verification.md)；执行计划见 [生产验收计划](../../milestones/m0-m8-production-acceptance-plan.md)。

## 验证对象与结果分类

本次交付限于 M0–M8。M9–M11 和原标准 9、10 明确推迟，不能视为本轮已实现。最终结果分别记录 `passed`、`failed`、`not-tested`、`deferred` 和有原因的 `not-applicable`。实际测试带源码/镜像摘要、UTC 时间、环境、测试规模与证据文件；历史证据不会冒充本次新执行。

| 验收域 | 本次要求 | 当前状态 | 结果落盘 |
| --- | --- | --- | --- |
| M8 端到端 | 完整配置、六类凭证、直接/审批、decK、浏览器、审计、清理及秘密扫描 | 真实阶段验收已闭环 | `artifacts/M8/` |
| 当前全量源码 | 适用单测/集成故障测试、API、Console Web 与 Portal Web 类型检查和编译 | 6290 项全量测试及三端编译已执行；最终 API 再次编译通过 | `artifacts/Production/` |
| 独立生产镜像 | 最终源码构建，无开发绑定，准确镜像摘要与版本 | sec4 四个应用与 sec5 API/Web 已构建、扫描，均无高危/严重漏洞 | `artifacts/Production/` |
| 新环境启动 | 一次迁移、受限运行角色、服务 health/readiness、重复启动不清空 | 独立项目七个运行服务健康、SQL000–011 与受限运行角色已实测 | `artifacts/Production/` |
| 网络与入口 | Admin 私有、BFF 专属来源、存储隔离、生产 HTTPS、Cookie/CSRF/安全头 | HTTPS 正向及错误域名/过期/未知 CA 负例、安全头、27 个实际 Cookie、四个非 BFF 网络探针通过 | `artifacts/Production/` |
| 功能回归 | M0–M7 既有证据与 M8 后连续性，新增范围的 RBAC/IDOR | 178 项 UI、对象图/凭证/权限、门户、监控与通知实测已完成 | `artifacts/Production/` |
| 备份恢复 | 控制台数据库与加密材料、独立 Kong 配置、恢复后凭证与审计验证 | 已执行，见下方实测结果 | `artifacts/Production/` |
| 有界容量 | 明确并发、持续时间、流量、资源、限流/锁与错误率 | 已执行，见下方实测结果 | `artifacts/Production/` |
| 依赖与镜像 | 新鲜依赖公告、实际镜像扫描/SBOM及历史版本问题 | 实际镜像扫描与 SBOM 已执行，基础组件风险保持未通过 | `artifacts/Production/` |
| 最终秘密检查 | 文件、编译内容、嵌入归档及实际运行日志 | M8 和独立生产当前文件/日志扫描均通过 | `artifacts/M8/` 与 `artifacts/Production/` |
| 文档与操作 | 详细中文部署/使用/故障/恢复手册与实际接口核对 | 两份详细手册及实际部署/恢复限制已对账 | `docs/manuals/` |

## 恢复与安全判断规则

恢复验收必须从实际生成的备份在独立目的地还原，证明配置、秘密解密、权限、审计链和凭证可用。只生成 `pg_dump`、只查看文件大小、只启动空数据库或仅成功解密单个示例都不足以宣称灾备通过。生产 Console 与 Kong 库由各自管理员独立备份，BFF 不获得 Kong 数据库权限。

容量结果仅适用于记录的机器、镜像、并发和测试时长，不能外推不存在的 SLA。入口限流/健康探测与实际配置读写的压力结果分别记录。锁、熔断或故障试验使用明确独立对象，未知操作不自动重复执行。

扫描结果包括实际工具版本、漏洞数据库时间、目标摘要与失败原因。npm 零公告不等于镜像零漏洞；历史 Kong 1.5 和 PostgreSQL 11 的维护状态与实际扫描问题应明确出现在上线结论。外部 LDAP/OIDC、邮件、Slack/飞书或业务上游尚未配置时，不得用本地协议或离线夹具结果填为外部联调通过。

## 最终交付要求

完成后在此登记版本提交、生产镜像摘要、有效启动命令、实际地址、验收结果、资源/容量、恢复耗时及实际限制。只登记可公开信息，密码、原始 YAML、私钥、API Key、Cookie、备份和加密密钥留在受控存储，不能进入交付报告。

本次明确不作无条件生产就绪结论：历史基础组件存在实际 HIGH/CRITICAL 漏洞，RAM 实验没有生产持久性，外部提供者和离机备份未联调。阶段交付仍以 [整体进展](../../milestones/m0-m8-stage-delivery.md) 与实际验收证据为准。


## 当前已完成的独立生产证据

- `artifacts/Production/root-production-runtime-role-migrations-actual.json`：实际受限运行角色、审计追加权限与十二个 SQL 校验和。
- `root-production-network-boundary-actual.json`：Admin 无宿主发布，非 BFF 网络无法访问 Admin/Kong 数据库，应用只读和最小权限。
- `root-production-browser-node-tls-text-checked.json`、`root-production-untrusted-expired-tls-node-address-corrected.json`：真实浏览器/Node TLS 验证，原失败报告保留。
- `root-production-https-response-cookie-headers-actual.json`：实际安全响应头及服务端 Cookie 属性。
- `root-production-oauth-ttl-sec5-image-build.json`、`root-production-oauth-ttl-sec5-image-scan.json`、`root-production-oauth-ttl-sec5-actual-sbom.json`：OAuth 数值 TTL 脱敏修复后的真实 API/Web 镜像。Portal/collector 镜像及 SBOM 沿用实际未变的 sec4 摘要。
- `root-production-sec5-original-full-overlay-activation.json`：新应用健康启动。升级沿用原项目完整 Compose overlays；遗漏 metrics overlay 导致网络配置不一致的失败证据保留。只退役本次两个已停止且无数据卷的应用容器，原开发环境和存储未删除。
- `root-production-original-auth-transport-no-commit-proven.json`：停机期间一笔刷新未收到响应。实际签名和只读数据库核对证明旧 refresh/CSRF 哈希及代数未变；原未知包保留，未重放，后续采用新的正常刷新请求。

UI 已完成 178 项原始操作、174 张截图。最终全量源码 6290 项通过；容量、故障、联合备份、第三项目恢复及最终 sec7 运行时兼容恢复验证已完成。详细结果见下表。

一次诊断误输出了尚未提交的测试 OAuth provision 值；旧值已废弃，更换后才创建实例。该事件不作为生产凭证泄露，但保留事实，最终秘密检查结论仅针对明确扫描的文件、镜像和日志范围。

## 本轮最终结果（2026-10-12，证据时间为 UTC）

| 项目 | 结果 | 证据 |
| --- | --- | --- |
| 全量源码 | 6290/6290，零失败、零跳过；另有 3 项秘密扫描来源证明用例 | `root-production-final-portal-audit-all-source.json` |
| 实体与插件 UI | 178 项操作、174 张截图；8 类实体及实际 34 个插件 | `artifacts/production/ui-lifecycle-unused-tail-19.json` |
| UI 审计与原生回显 | 178 条原请求核对；40 个在线对象一致、2 个归档对象原生 404 与完整回收图一致 | `root-production-ui-all-original-audit-native-actual.json` |
| 生产对象图与 RBAC | 五类图恢复、两轮六类真实凭证、只读写入与跨区 IDOR 拒绝，196 项通过 | `root-production-core-regression-actual.json` |
| Vitals | 15 组 Service 指标及 Route QPS 与实际同窗 Prometheus 数值一致 | `root-production-metrics-same-window-numeric-actual.json` |
| 门户 | 审核、发布、申请、审批、发证、轮换、吊销；旧 Key 实际 401 | `root-production-portal-issue-rotation-revocation-actual.json` |
| 门户应用审计修复 | 新镜像的创建/编辑/归档/恢复四项事务内终态审计通过 | `root-production-portal-application-four-terminal-audits-actual.json` |
| 通知 | 原生变更产生终态事件及站内通知，所有者可读，其他用户 404 | `root-production-native-event-notification-actual.json` |
| 容量与故障 | 10 并发×20 次有界分页读取；37 次正常限流，P95=1769 ms；Kong、Redis 原容器恢复且 UUID 不变 | `root-production-bounded-capacity-fault-actual.json` |
| 备份 | 联合停写，PG16/PG11 匹配 dump、Redis SAVE、AES-256-GCM 持久化；篡改和错钥匙均拒绝 | `root-production-coordinated-encrypted-backup-actual.json` |
| 恢复 | 原 901 条审计与链头、完整快照及秘密解密；成功轮基础启动 28.339 秒；六类原凭证有效 | `root-production-third-project-restore-actual.json` |
| 最终镜像恢复兼容 | 实际已恢复数据库升级到最终 sec7，六类凭证、两个已吊销门户 Key、全局及集群审计链通过 | `root-production-final-sec7-restored-credentials-and-integrity-actual.json` |
| 镜像安全 | 最终 API sec7、Web sec5、Portal/collector sec4 的实际扫描无 HIGH/CRITICAL/秘密匹配；基础组件仍有漏洞 | 各镜像扫描、SBOM 与风险登记 |
| 关键写请求对账 | 261 条终态审计匹配；1 条修复前测试应用只有 pending 受理审计，保留为历史遗漏 | `root-production-final-critical-write-audit-actual.json` |

恢复备份点来自 sec6，最终 sec7 没有改变 schema 或加密格式，已在真实恢复后的数据库上验证。28.339 秒仅是修正后成功轮的基础启动时间；诊断失败、约束校验、凭证与监控验证另有时间，不作为业务 RTO/SLA。原失败证据、失败副本和原加密备份未改写。

本轮发现并修复 OAuth 数值 TTL 误脱敏、Service+Route 指标下钻范围、首次 Prometheus 卷属主、PostgreSQL 恢复搜索路径，以及门户应用终态审计。历史审计缺失不追填成成功：新事务已修复，旧测试事实仍保留。

最终阶段清单：验收 JSON (`artifacts/Production/m0-m8-phase-acceptance.json`, not public)。最终发布镜像已经保存到工作区持久归档，未推送外部 registry；RAM 环境只能用于验收。M9–M11 保持延期。

最终秘密扫描：3561 个文件、20 个当前运行服务及 4 份可用退役应用日志，零已知秘密匹配。`token_type=bearer` 仅在完整原始、成功 TLS OAuth 交换证明下分类为公开元数据；真实令牌、密码、私钥与备份钥匙继续检查，原 180 项误报记录保留。最终扫描范围不包括聊天工具诊断输出；曾误输出的未提交测试值已废弃并单独记录。详细范围以最终扫描报告为准。

当前交付扫描覆盖 229 个编译文件、63 份当前/历史测试私有记录以及全部 20 个当前运行服务。绿灯报告和镜像/加密备份持久保存后，仅清理 63 份测试私有记录、测试 PEM/负例 TLS 目录，并移除本次临时浏览器信任；生产 env、TLS、metrics 材料、独立恢复钥匙及原有四个信任根保留。
