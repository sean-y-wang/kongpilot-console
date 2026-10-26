# KongPilot 开发进度检查点 · 2026-10-14

本记录对应用户要求的“先提交当前代码和进度”。开发于本检查点暂停，所有协作代理已冻结编辑。当前为 **M11 开发快照**，不是生产发布验收。M0–M10 的历史验收、后续新增代码的 Source 测试、真实环境测试分别记录，不互相替代。

- 产品：KongPilot / 〔former working name〕 - Kong 管理平台；前端显示 v1.0，npm / Swagger 的发布版本还需在正式发布时统一。
- 远程仓库：<https://github.com/sean-y-wang/kongpilot-console>。
- 已验收基线：M9 `0f03f50`；M10 `4434d31`。保留 `master` 基线，当前开发快照保存于 `work/m11-checkpoint-20261014`。
- 当前整体状态：M11 未整体验收；商用验收未通过。Kong 源码、镜像内容和数据库未被平台改写；平台通过 Admin API 管理配置。
- 真实验收采用自有隔离实验环境。平台 PostgreSQL 已使用持久命名卷，但 RAM / Docker-in-Docker 环境不证明宿主机重启、异机灾备或正式站点的持久性。

## 里程碑状态

| 里程碑 | 已有结果 | 当前边界 |
| --- | --- | --- |
| M0–M8 | 多集群、实体/插件、工作区/RBAC、监控/门户、审计通知、快照与 GitOps 的历史技术验收 | 不将历史构建、截图或测试当作本次 M11 快照的生产验收 |
| M9 | 运维工具箱阶段验收；新增路由模拟排序修复 48 项 Source 测试通过 | 新修复仍需与真实 Kong 路由命中对照，整合版本须回归 |
| M10 | 巡检、Lint、漂移、Promote、回滚阶段验收，基线为 `4434d31` | 最终 M0–M11 整合版的生产验证仍待完成 |
| M11 | 多级 / 会签审批、不可变意图、批准集、实体执行与恢复、自然定时、业务排程和多个元数据审批适配器已实现 | 若干真实链路已通过；仍有 Source 草稿、待联调入口和失败 / 未知执行记录 |

## 新增真实环境证据

1. 身份变更：新工作区角色的准备、提交、独立超级管理员审批、执行均成功。同一原始登录会话保存至执行，SQL 独立核验工单 / 执行 / 步骤 / 业务操作全部 succeeded，IAM epoch 精确增加 1，业务与工作流成功审计各存在，Kong mutation 为 0。另一次跨登录会话提交被 403 拒绝，保留原失败记录，不重放。
2. 既有恢复分项：Consumer 对象图 / 凭证恢复、五种认证与 ACL 的真实访问正负例、OAuth2 HTTPS 签发 / 轮换 / 吊销 / 回收恢复、Target 100→80→0 及原 Target 0 元数据核验已有证据。它们是分项验收，不代表 M11 或全部生产验收完成。
3. 部分自然定时分项：Service 自然定时执行及取消、过期、审批人凭证撤销有真实证据。定时配置发布、定时 Target 新适配器和执行中故障矩阵仍需验收。
4. 最新实际 API 候选摘要：`446be57839f334a50981ac2704e889c3cfbe66491de0db62a76e187ef298e411`，380 个 API 源文件；SQL000–031 共 32 条已应用迁移。独立 Source / SQL 校验与 readiness 通过。当前工作树另有 SQL032、SQL033 和新增适配器，不能将该运行候选的结果赋给整个工作树。

## 已通过的 Source 分项与未验证差异

| 分项 | 最后已确认的结果 | 未完成事项 |
| --- | --- | --- |
| 控制面后端审批 | 集群更新 / 模式切换 / 停用、数据源 CRUD、工作区创建 / 更新 / 归档 / 恢复；710 项专项、API 类型检查通过；SQL033 Source 冻结 | 真实 SQL033 约束试验、部署与 HTTP 联测尚未完成；Root 共享路由接线新增后须独立回归 |
| 控制面 UI | 最后完整版本相关 10 套 / 280 项通过，Web 类型检查通过 | 最后 auth-mode / workspace-seed 补丁可能部分应用；最终 281 项测试未启动、构建结果未观察，最新字节未验 |
| Root 控制面路由 | 5 条真实 Source 流程通过；UI selector / 回执相关 110 项通过 | 新读取 / 列表测试 21 项未观察结果；终态工单在 scope 变更后列表可能 409，尚待修复 |
| 定时配置校验 | 去重与资源预算相关 407 项通过，最终新增 28 项通过；统计重叠 | 当前真实自然执行结果尚未验收，不能据此断言性能或故障恢复符合生产要求 |
| 监控配置审批 | 后端相关 559 项、前端相关 82 项通过；SQL032 Source 完成 | 真实数据源注册 / SQL032 试验 / 审批启用插件 / Prometheus 数值对照未完成 |
| Target 健康 / 权重恢复 | 后端相关 583 项；SQL031 已在实际 API 应用；定时 Target 适配相关 182 项、UI 219 项通过 | 真实健康 204 空响应、权重恢复与新 UUID、定时 Target 自然执行须进一步验收；手动健康置位明确不支持自动回滚 |
| 原准备键查询 | 实体意图原 prepare-key 查询相关 99 项、API 类型检查通过 | 需部署并验证真实未知请求的只读恢复；查询缺失不证明写请求未发生，不允许自动重发 |
| Consumer 凭证 UI | 创建 / 更新 / 回收删除审批相关 6 套 / 158 项通过（其中 focused 65 项），Web 类型检查通过 | 最后 recover-running 小改动未重新验证；编辑默认 tags 尚未过滤保留工作区标签；最终构建及浏览器验收待完成 |
| 实体备注审批 | 已写 types、strict plan、权限继承 checker、business service、原 EntityAnnotationsService 固定 SPI，共 5 个 Source 文件 | WorkflowService、Controller、SQL034、新测试、Root 注册均未实现；已有草稿的兼容与类型检查未确认 |

Source 测试数量来自不同候选并有重叠，禁止相加成“最终版本全部通过”。早期修复快照的 502 套 / 9,578 项全通过不覆盖之后新增的控制面、监控、备注、凭证页面和共享接线。

## 保留的失败和未知记录

- 定时配置发布曾出现原执行权限上下文错误、命名空间预算错误和校验期限到期。原工单、窗口、claim、日志和审计保留，不改写成成功，不用新幂等键重放旧 Native 请求。
- 有一条早期 claim 未形成执行记录且未自动闭合，恢复方案仍待验证；不手工伪造 outcome 或批准。
- 最新定时配置试验完成准备、三名非超级管理员的新票和激活，随后只读观察遭遇 transport unknown。后台任务可能独立继续，实际状态必须由新的只读 SQL 核验，不能宣称成功或零 Native。
- Prometheus 数据源登记被 `OUTBOUND_HOST_FORBIDDEN` 拒绝。实验集群已恢复原 approval 模式；指定监控地址的允许规则和真实服务尚待配置 / 联调。
- 执行器曾报告 load average 156.14 / 73.42 / 36.22，随后 `exec-server transport disconnected`。暂停新增并行构建后恢复连接。这是环境事件，不替代容量 / 高负载验证。
- 未完成工具调用不计为测试通过；失败、未知和 partial patch 记录均保留。

## 商用闭环剩余工作与顺序

1. 核对本快照的局部补丁，修复控制面终态列表 / UI 契约和凭证 tags 问题；实现完整备注审批适配器。
2. 以固定 Source 摘要构建候选，对 SQL032–034 做平台库事务回滚试验、最小权限核验和正式迁移；禁止连接 Kong 数据库。
3. 真实验证全部写入口的审批模式与防绕过：集群模式 / 地址、数据源、工作区、IAM、监控插件、实体备注、凭证创建 / 更新 / 回收删除。
4. 验证定时配置及 Target 的自然执行、取消、窗口过期、权限 / 凭证撤销、重启、并发 / 锁丢失 / 执行中故障；准确闭合未知与部分执行。
5. 补齐健康置位、权重回滚、真实路由匹配、Prometheus 指标对照、通知投递 / 重试和完整浏览器操作证据。
6. 对同一最终候选完成 M0–M11 单测 / 集成 / e2e、越权 / IDOR、敏感信息扫描、审计覆盖、备份恢复 / 升级迁移和持久部署 / 容量验证。
7. 更新生产部署手册与用户手册覆盖 M11，统一 npm / Swagger / UI 版本，发布独立正式版本与验收清单。未完成上述门禁前不打生产 v1.0 发布标签。

## 主要证据入口

- [M11 历史与分项验证](../../verification/milestones/m11-verification.md)
- IAM 原会话执行 SQL 核验 (`artifacts/M11/iam-original-session-role-workflow-independent-sql-readonly.json`, not public)
- 控制面 Source 冻结 (`artifacts/M11/control-metadata-source-checks-original.json`, not public)
- 最新实际 Source / SQL 核验 (`artifacts/M11/business-checkpoint-budget-independent-source-sql-readonly-original.json`, not public)
- 定时校验 Source 记录 (`artifacts/M11/business-scheduled-validation-checkpoint-budget-source-checks-original.json`, not public)
- 监控 Source 记录 (`artifacts/M11/metrics-setup-api-source-checks-frozen-original.json`, not public)
- 原准备键 Source 记录 (`artifacts/M11/entity-prepare-key-api-source-checks-frozen-original-wx.json`, not public)
- [部署与运维手册](../../../manuals/production-operations-guide.md) / [用户手册](../../../manuals/console-user-guide.md)

所有 Cookie、JWT、密码、私钥、API Key、原始请求账本及数据库备份保留在权限受限的私有目录，不能提交到 Git。公开记录仅保存状态、统计、必要对象标识及摘要。Git 检查点验证结果见 [当前检查结果](2026-10-14-checkpoint-validation.json)，不冒充生产验收。

本次提交前 API / 控制台 / 门户三端类型检查与 diff 检查通过，553 个源码文件的检查前后摘要一致。候选 Git 材料扫描覆盖 4,580 个文件、308,215,278 字节，对保留 M11 实验材料抽取的 1,357 个敏感值候选及常见编码变体，发现数为 0。最初的节点预算错误、39 条幂等账本标识误分类及中间校验失败均保留；最终扫描只对已关联原账本、且不与实际凭证叶子冲突的标识做精确分类，没有泛化排除 UUID。扫描不包含当前运行日志、数据库或截图 OCR，仍须在生产验收时重新完成全范围验证。详见 检查点扫描 (`artifacts/M11/checkpoint-source-secret-scan-linked-final-20261014.json`, not public)。
