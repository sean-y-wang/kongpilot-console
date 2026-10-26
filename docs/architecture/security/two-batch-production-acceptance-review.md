# 两批交付的商用验收复核

> 当前范围：用户于 2026-10-11 要求 M8 闭环后验收并交付 M0–M8，M9–M11 后续研究。本文保留完整原十三条标准的审阅，标准 9、10 本次明确推迟；不要求实现后续模块作为本次交付门槛。当前范围见 [阶段交付记录](../../project-history/milestones/m0-m8-stage-delivery.md)。

状态：**源码与文档规划审阅，不是运行验收报告**。审阅基线为 2026-10-11 的 [两批规划](../../project-history/milestones/remaining-two-batches.md)、M7/M8 合同、M9–M11 候选合同与现有里程碑证据。此文未执行测试、构建、部署、数据库或外部消息操作。原任务共有 **13 条编号验收标准**，下表全部保留。

分批减少同时集成的模块；M8 的配置恢复、M10 的双环境发布与 M11 的可信调度仍有实际依赖，不能靠拆批省略。

## 已有证据与待交付边界

| 范围 | 已记录的证据 | 本次不能据此宣称完成的内容 |
| --- | --- | --- |
| M0–M2 | [M0 部署](../../project-history/milestones/m0-deployment.md)、[M1 验证](../../project-history/verification/milestones/m1-verification.md)、[M2 验证](../../project-history/verification/milestones/m2-verification.md)：真实 1.5.1、八类实体/六类凭证、五类恢复图、34 个实际安装插件的 HTTP 生命周期；部分真实 UI 与代理认证 | 每个安装插件均完成 UI 覆盖、六类凭证均完成恢复后的真实协议认证、最终生产镜像验证 |
| M3–M4 | [工作区](../../project-history/verification/milestones/m3-verification.md)、[RBAC](../../project-history/verification/milestones/m4-verification.md)：真实软隔离、四维权限/继承、双集群 IDOR、网络边界、写入审计与浏览器 | 新增审计导出、快照、工具、Promote、后台投递/调度自动继承了这些安全结果 |
| M5 | [监控验证](../../project-history/verification/milestones/m5-verification.md)：双集群真实 Prometheus/Loki 同窗数值、范围授权、浏览器、清理与最终扫描 | 后续模块改变归属、网络、密钥或节点注册后无需验证连续性；未配置的外部提供者已联调 |
| M6 | [当前验证记录](../../project-history/verification/milestones/m6-verification.md)：真实 HTTP 1,057/0，145/145 次成功写入匹配审计；实际浏览器闭环及手工 77/0、18 张截图；BFF 清理 298/0，原 239 个成功清理请求审计对账通过；最终源码 3,798/3,798，最终秘密扫描 1,710 个文件及 7 个实际服务日志，泄漏 0。交付提交 `28c0933`，旧失败报告保留 | 原 direct metadata 只有请求审计，完整终态 before/after/result 的补缺在 M7 实施并重新实际验证；M6 证据不代替新增模块验收 |
| M7 | [验证记录](../../project-history/verification/milestones/m7-verification.md)：SQL010已应用；最终源码4,546/4,546、真实HTTP4,561/4,561、证书/健康生产者4,469/4,469。十二项浏览器业务写成功、21/21只读接续与十二张实际截图完成；清理8,985/8,985、155项软归档，451/451累计成功写入关联终态审计，439次requestId匹配、十二次旧提交缺ID/IP分列。最终2,162文件与九个实际服务新日志扫描泄漏零，临时敏感材料删除 | 十二条旧提交已有完整原请求字段；原settings聚合连续性限制已消失；本地协议收件器证明外部真实账号联调；M10漂移生产者已通过；未完成M8–M11即可整体商用 |
| M8 | [集成记录](../../project-history/verification/milestones/m8-integration-verification.md)：API/Web 已部署，SQL011 已应用；完整游标快照、五类原 ID 删除恢复、恢复后六类凭证代理认证、新导出下载及自然定时快照通过。首次 apply 的修订号故障已保留，CAS 修复经 97 项相关源码、40 项隔离 PostgreSQL 及 36 项部署连续性验证；新独立 apply 和 schema 兼容修复后的回滚及六类认证已实际成功。全量源码复验 5,296 项通过；随后审批初始化事务故障修复另经 223 项源码及 47 项隔离 PostgreSQL，真实审批、CLI 和浏览器仍待续接 | 实际 apply/回滚、审批、decK diff/sync、浏览器与最终扫描已全部闭环；源码或部署结果代表商业总验收 |
| M9–M11 | 存在设计合同、协议调查和规划 | 产品已实现、后续迁移已应用、治理或多级定时审批已通过 |

已统一的说明：根探测只读取 `GET /` 的 `version` 与可选 `endpoints`，不新增 `GET /endpoints`；旧录制事实保留。`docs/security/M5-M11-test-plan.md` 的 M11 条目已统一为自动创建执行前快照、显式受控回滚；未知结果先核验，不要求自动补偿。以上为文档澄清，现有产品白名单和执行规则未扩大。

## 第一批：M6 → M7 → M8

每行在对应阶段闭环；M6、M7 已完成阶段交付，M8 按原授权进入实施；各阶段仍须实际闭环。责任人沿用现有 owner 分工，测试失败保留原报告与原始键，不完整重跑已执行流程。

| 门禁 | 责任人与时点 | 必须产生的证据 / 当前缺口 |
| --- | --- | --- |
| B1-1 门户实际闭环 | Security、Frontend、Root；M6 提交前 | 已完成真实 HTTP、浏览器、人工截图、BFF 清理、最终扫描及证据交付。M7 补齐 direct metadata 终态审计，M11 扩展审批引擎后再次验证门户链路 |
| B1-2 正式数据库调用者 | Storage、业务 owner、Reviewer；M7/M8 源码门禁 | 正式成功、原键重放、最后授权/租约失效的事务回滚均由实际非 owner、非 superuser 运行角色调用服务；迁移账号只预置。不可变证明/历史保持 SELECT/INSERT，不能为 JOIN 行锁增授 UPDATE。M6 已检出的正式路径角色差异必须转为后续验收用例 |
| B1-3 审计与历史权限 | Root、Storage、Security；M7 | 当前身份与同一完整 grant 覆盖可信历史 before/after；受限分页、导出、下载及撤权通过。实际业务、审批、元数据和清理写操作逐 requestId/operationId 对账；diff 正确且脱敏，运行角色拒绝 UPDATE/DELETE/TRUNCATE。验证原十九字段链及新增 scope 注解，区间/预算/捕获 head 如实显示；生产外部检查点如何保存与恢复有可执行说明 |
| B1-4 事件、检测与通知 | Storage、Kong/Workflow、DevOps、Security；M7，漂移源在 M10 后补验 | 同事务 outbox、分页 fanout、个人偏好/未读隔离、实际 HTTPS Webhook 与强制 STARTTLS 邮件、429/5xx/断开/崩溃/撤权/租约变化通过；意图和尝试只追加，未知送达不写成未发送。**证书预警、Upstream 健康变化需真实有界检测生产者**，catalog 名称或“未启用”显示不能代替；漂移事件最终由 M10 真实比较作业触发 |
| B1-5 完整导出与可信恢复材料 | Kong/配置 owner、Storage、Security；M8 | 八类核心对象、有效 Targets、SNIs、CA 和六类 Consumer 凭证均在非空、至少第二页的真实 capture/manifest 中；使用 size/offset/next，不先全量收集再分页。原 ID/关系/schema/null 语义与秘密能力保留；SNI/Target 在 decK 1.1 中嵌套，无假顶层字段。完整性不足不得 ready/apply |
| B1-6 实际 decK 与受控 apply | 配置 owner、Root、DevOps、Security；M8 | 固定 decK v1.1.0 的 validate **及实际 BFF adapter diff/sync**；分别录制 CLI 结果、控制台父回执与逐对象状态。全局凭证协议路径仅在 BFF 转为 Consumer 下分页；CLI 无 Admin 网络权限。额外 packet、未批准写、通用 upsert、越范围删除被拒；所有 DELETE 先有完整回收图。原版 CLI 的退出 0 不能替代 Basic 密码对齐 |
| B1-7 快照回滚与六类凭证 | 配置 owner、Storage、Security；M8 | 手动/定时快照、diff、恢复依赖顺序、引用冲突、权限撤销和未知停机实际通过；回滚是新 current-before diff。Key-auth、Basic、JWT、HMAC 原凭证与 ACL 允许/拒绝经真实代理验证；OAuth2 恢复 client 后重新取有效 token，不宣称旧 token/session 恢复；SNI/证书及 Target 权重/新 effective ID 核验 |
| B1-8 第一批整体场景 | Root、Security、Frontend；M8 收尾 | 一次 direct 和一次 approval 配置变更→脱敏审计→真实通知→完整快照→确认回滚→实际认证。原始键、父/子回执、权限、删除回收一致；只读、tag_group、entity 账号在新增模块中重验；源码/类型/适用测试与浏览器、扫描证据归档后提交 |

恢复限制必须进入 blocker：历史 Basic hash 没有可信原密码不能无损重建；OAuth2 token/session 不属于 client 备份；原生 TTL 不明不能静默延长。Portal 已吊销历史 Key、受管监控秘密与业务关联不能被 generic import/rollback 复活。对象不可恢复时先阻断破坏性计划或采用明确轮换步骤，不能先删再承诺回滚。

M8 配置 DAG/私有批准版本是第二批执行基础：不得直接放宽 M6 v1 的 16 步/32 packet 限制，也不得拆为自动自审的多个工单。定时快照的只读当前主体必须实现，不能因为已有时间列就视为后台调度已完成。

## 第二批：M9 → M10 → M11 → 生产总验收

| 门禁 | 责任人与时点 | 必须产生的证据 / 当前缺口 |
| --- | --- | --- |
| B2-1 工具箱与批量闭环 | Kong/配置 owner、Root、Security、Frontend；M9 | 真实 `/status`、精确 key 缓存查看/确认失效、路由规则对照与受控 proxy probe；模拟 PCRE/部分授权限制可见，不能声称完整真实命中或虚构阶段耗时。批量标签/插件启停/迁移/删除复用当前策略，逐对象审计与回收，partial/unknown 停止；草稿 owner IDOR、秘密不落持久表单、重新提交 fresh before 通过 |
| B2-2 治理准确性与事件源 | 配置 owner、Storage、Security；M10 | 合法 API 可构造的问题用真实数据；DAO 禁止的孤儿/无效引用用明确 synthetic fixture，绝不改 Kong 数据库。真实缺 owner/命名/安全基线、Lint 与修复后复检通过；合法 DNS/IP host、无 SNI 的 mTLS 证书、不存在的 1.5 字段不误报。规则执行有界、无 eval；漂移阈值触发 M7 真实通知 |
| B2-3 双环境 Promote | 配置 owner、Root、Security、Frontend；M10 | 源 read 与目标 write/secret 权限独立；默认排除凭证和环境秘密，ID/工作区标签/共享引用/覆盖项在 diff 展示。目标执行模式、前置快照与审批有效；源或目标漂移/撤权阻断；逐对象结果、回收、未知原键、受控回滚及真实代理认证通过 |
| B2-4 多级、会签与可信调度 | Root、Kong/Workflow、Storage、DevOps、Security；M11 | 同一引擎的两级/all/quorum、同人多团队不重复票、无自批、计划变更旧票失效、批准人/执行人当前撤权通过。真实窗口、IANA/UTC/DST、跨物理 scope 冲突、单一到期 claim、崩溃/锁失/未知终态验证；专用背景主体/能力不得伪造 HTTP session 或复制旧批准权 |
| B2-5 工单全链路 | 全体 owner，Security 独占业务写入；M11 | approval 集群所有配置写路径无工单/未批准零变更；真实执行前可恢复快照、影响面与流量权限、每步日志、计划执行、拒绝/撤销/逾期、M7 通知、显式受控回滚通过。M6 门户申请继续共用引擎；批准、入队、Native ACK、父成功、通知送达分别记录 |
| B2-6 独立生产部署 | DevOps、Storage、Security、Reviewer；M11 功能完成后 | 完整 API/Web/Portal 镜像在**独立 Compose 项目与卷**启动，未使用开发代码绑定；迁移从空库及已有 schema 升级、重复启动/恢复均验证。实际 health/readiness、版本/插件探测、TLS/Cookie/Origin/代理信任/安全头、Admin 仅 BFF 可达、API 无 Kong 数据库凭据和网络权限通过；测试 receiver 不进入默认生产 |
| B2-7 协调灾备与运营容量 | DevOps、Storage、Root、Security；独立生产总验收 | 加密备份/恢复控制台库、必要密钥版本与 Kong 配置/基础设施库；基础设施备份作业使用专用权限，控制台仍不连接 Kong 数据库。恢复 RBAC/Portal/工单/审计/outbox/配置归属，保留吊销边界、未知发送与历史证明；旧浏览器会话不自动恢复执行权。测量并公开 RPO/RTO；测试 BFF/网关限流、锁/熔断、provider 不可用、积压与重启恢复，记录对象规模/并发/时延/资源及实际适用范围 |
| B2-8 商用结论与全部标准 | Root、Reviewer；最终交付 | 当前源码全部适用测试、最终 UI/IDOR 专项、容器与依赖扫描/SBOM、秘密扫描、五类恢复图、六类认证、实际 decK、治理与工单证据统一对账。README/Swagger、架构、部署/升级/回滚/备份步骤与软隔离限制同步；逐条标记已通过、明确不适用或未验证，不能用单测数量替代缺失的端到端证据 |

灾备文件需区分 Native YAML 与整个控制台备份：前者不含 RBAC、Portal、审计链、工作流及秘密管理。恢复演练在独立库/网关执行，不覆盖当前验收集群；不把回滚配置变成旧吊销状态、旧 secret generation 或历史身份的时间倒退。

## 原 13 条验收标准的最终落点

| 原编号 | 可复用基线 | 必须补齐的最终门禁 / owner |
| --- | --- | --- |
| 1 一键启动与数据源 | M0/M5 | B2-6 的独立生产 Compose、探测、连接状态与升级 readiness；DevOps |
| 2 全实体/自带插件 UI CRUD | M1/M2 | 实际探测清单的 34 个插件以及八类实体、Targets/六类凭证的 UI 操作覆盖矩阵，复杂表单/绑定真实回显；新增或缺失插件按探测标能力，不能冒称 grpc-gateway 等在基线内；Frontend/Security，最终总验收 |
| 3 五类对象图完整恢复 | M1 | B1-7/B2-8 下随机五类删除→回收→依赖恢复→真实认证/证书/权重，Target effective ID 例外明确；配置 owner/Security |
| 4 两工作区软隔离 | M3/M4 | 新增审计/通知/快照/治理/工单与后台路径同样不可跨区，global runtime 局限明确；Root/Security |
| 5 四维 RBAC 与继承 | M4 | 新增模块 read-only、tag_group、entity/typed parent、Service/Route/Plugin 继承及 await 期间撤权；Root/Security，各阶段 |
| 6 监控数值与下钻 | M5 | 改动后既有数值/归属 epoch、数据源与用途 secret generation 连续性；Promote/审批影响面无权限不给假 0；DevOps/Security |
| 7 门户发证/吊销 | M6 已交付，真实 HTTP/浏览器/人工检查/清理及最终扫描通过 | M11 复用审批引擎后再次验证；Kong/Workflow/Security |
| 8 decK/快照与凭证恢复 | 仅离线 decK 调查 | B1-5–7 实际 diff/sync/回滚及六类认证，完整导出与恢复 blocker；配置 owner/Storage/Security |
| 9 治理/Lint/漂移/Promote | 仅设计 | B2-2–3 实际与 synthetic 明确区分、准确性及目标发布闭环；配置 owner/Security |
| 10 工单多级/定时/回滚 | M6 单级基础 | B2-4–5 无工单零写、多级/会签/计划窗口/前置快照/回滚/通知；Workflow/Storage/Security |
| 11 所有关键写审计与不可修改 | M4/M5 已对账写入 | B1-3、B2-8 对新增成功/失败/部分结果及后台写逐真实操作对账；before/after/diff、工单关联与 append-only；Root/Storage/Security |
| 12 越权/IDOR 专项 | M4 Konga 类攻击基线 | 每个新增入口、游标/导出/通知/draft/job/双 scope/worker 的前端、API、原生最后栅栏专项；Security/Reviewer |
| 13 全部测试与 README | 历史逐阶段报告 | B2-8 当前源码的统一结果、失败历史保留、真实与 mock 标签、商用部署和恢复文档；Root/全体 owner |

## 最终商用报告必须准确陈述的条件

- 固定 Kong OSS 1.5.1 与配套 PostgreSQL 11 已停止上游维护。完成控制台功能不能消除该事实；报告提供实际镜像/组件漏洞结果、不可消除项、网络部署条件与维护/迁移策略，不写“已获商业安全认证”或“无漏洞”。不为此另设用户确认流程。
- 工作区是 tag 软隔离，共享原生名称空间和全局插件影响仍存在；网络封闭与 BFF 当前权限是必要条件，不提供 Enterprise 原生隔离保证。
- LDAP/OIDC、外部 Slack/飞书/邮件等没有真实配置时，明确“未配置/未联调”；本地收件器或协议夹具证明实现边界，不能冒充外部账户联调，也不自动联系外部账号。
- 完整快照仍是 `console_fenced_best_effort`，受不可恢复 Basic/TTL/OAuth 会话及 Portal 私有生命周期限制。实际失效/传播时间按受管节点观察记录，不用“立即”掩盖 Kong DB 模式的传播窗口。
- 最终结论基于上述 13 条标准、独立生产部署与实测灾备/容量范围；未通过项明确保持未完成，不把两批规划、离线验证或修复部署成功当作商用验收。
