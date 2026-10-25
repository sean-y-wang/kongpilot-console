# KongPilot 产品手册

**Kong 网关管理平台** · 仓库 `kongpilot-console`

KongPilot 为 Kong OSS 1.5.x 提供独立的管理入口。本套手册以产品任务组织，分别服务部署运维和日常使用。

| 读者 | 手册 | 阅读目标 |
| --- | --- | --- |
| 部署与运维人员 | [部署与运维手册](production-operations-guide.md) | 独立接入已有 Kong、生产配置、TLS、持久化、发布、监控、备份恢复、值班和准入 |
| 备份与恢复操作人员 | [平台备份与恢复操作手册](platform-recovery-runbook.md) | 加密恢复点、隔离存储恢复、最小权限、完整密文检查、未知工单与接管边界 |
| 管理员、运维与业务使用者 | [用户使用手册](console-user-guide.md) | 登录、范围、实体与插件、权限、监控、门户、审批、回收站、审计、快照与 GitOps |
| 发布与验收人员 | M0–M8 阶段验证、M9 验证、M10 验证、M11 进展 | 各阶段证据与限制；新站点仍需正式准入 |
| 集成与高级操作人员 | [高级配置参考](advanced-configuration-reference.md)、[技术运维参考](technical-operations-reference.md) | 历史技术合同、复杂作业与恢复注意事项；当前操作以主手册为准 |

本套手册覆盖 M0–M10 已有能力及 M11 当前操作入口，含 Targets 即时审批、权重/业务标签、当前节点健康置位与回收删除；**配置导入/回滚生成的耐久配置工单**在封存包完整时允许 Target 权重追加（Kong 1.5 POST + 新物理 ID），路径为签发 → 第二人批准 → 原提交人执行 → Kong 只读回读新 ID/权重；**业务排程**对完整封存的 configuration_v2 Target 权重追加可登记定时；lab 已验证自然 claim→自然 execute（Kong weight=55，定时预算 1000）；高争用下仍可能窗口到期 fail-closed。**未知结果**：已发送 mutation reconcile/双人 abandon（SQL049/050）；从未发送无 mutation 的 unsent settle（SQL051）。须站点开启业务排程并完成浏览器/生产 compose 验收，**未**宣称 commercialClosed。Target 实体定时仅支持已开放的创建/权重适配器，健康不可定时或自动回滚。

M9/M10 已完成技术阶段验收，M11 正在完成最终集成与验收；功能是否开放，以本站正式发布范围和服务端能力为准。用户菜单显示 v1.0 不代表已创建正式发布标签，也不能替代生产准入。**未宣称 `commercialClosed`。**

当前 M11 状态、已验证子集和待验项见 M11 验证记录，最新开发与验收进展见 2026-10-23 M11 continue 阶段进展 与 2026-10-20 全量检查点。历史验收与新源码验证分别保留。生产安装使用部署手册的正式入口；release 实验 Compose、RAM daemon 和 `NODE_ENV=test` 不作为生产配置。

KongPilot 不修改 Kong 源码，生产接入可以只部署管理平台。已有网关维护与平台自身准入分别管理。

产品统一名称与历史兼容标识见 [品牌规范](../design/brand-identity.md)。浅色采用灰白基底、纯白实体侧栏、轻磨砂卡片、三级灰度和低饱和靛蓝，深色采用对应的石墨面板；玻璃 K Logo 保持不变。实页截图见 视觉预览。SQL、认证、加密、审计以及现有卷名称保持兼容。


## KP-011 截图槽位（2026-10-25）

文案已按最终行为写好；秘密须打码。文件：`docs/manuals/shots/<slot-id>.png`。**未**宣称 KP-011 closed / `commercialClosed`。

| 槽位 ID | 手册位置 | 拍摄要求 | 状态 |
| --- | --- | --- | --- |
| `U-login-light` | 用户手册 · 登录 | 浅色登录页，品牌/版本可见 | **已捕获** → `shots/U-login-light.png` |
| `U-login-dark` | 用户手册 · 登录 | 深色登录页 | **已捕获** → `shots/U-login-dark.png` |
| `U-sidebar-nav` | 用户手册 · 导航 | 侧栏完整模块（实体/审批/监控/门户/审计） | **已捕获** → `shots/U-sidebar-nav.png` |
| `U-entity-service-detail` | 用户手册 · 实体 | Service 详情含插件/路由摘要 | **已捕获** → `shots/U-entity-service-detail.png` |
| `U-diff-review` | 用户手册 §23 | 配置 Diff 审阅（脱敏） | **已捕获** → `shots/U-diff-review.png` |
| `U-approval-vote` | 用户手册 §23 | 第二审批人投票界面 | **已捕获** → `shots/U-approval-vote.png` |
| `U-schedule-register` | 用户手册 §23.9 | 业务排程登记表单（本地时区提示可见） | **已捕获** → `shots/U-schedule-register.png` |
| `U-schedule-board` | 用户手册 §23.9 | 业务排程看板/列表终态 | **已捕获** → `shots/U-schedule-board.png` |
| `U-unknown-verify` | 用户手册 · 原请求核验 | 「原排程请求尚未核验」提示 + 「核验原回执」按钮 | **已捕获** → `shots/U-unknown-verify.png`（lab 代理故障注入下的真实中断排程路径） |
| `U-unknown-verify-resolved`（附加） | 用户手册 · 原请求核验 | 回执服务恢复后点「核验原回执」→「原排程请求已确认」 | **已捕获** → `shots/U-unknown-verify-resolved.png` |
| `U-recycle-restore` | 用户手册 · 回收站 | 五类之一恢复确认 | **已捕获** → `shots/U-recycle-restore.png` |
| `U-portal-reveal` | 用户手册 · 门户 | 临时揭示面板（**打码**秘密） | **已捕获** → `shots/U-portal-reveal.png`（秘密已打码） |
| `U-vitals-overview` | 用户手册 · 监控 | 概览 QPS/延迟卡片 | **已捕获** → `shots/U-vitals-overview.png` |
| `O-tls-edge` | 运维手册 · TLS | 生产 edge 证书/监听示意（可非生产 SAN） | **ops 证据**（无 UI；CLI/HTTP 实测）→ `artifacts/M11/runs/20261025-O-tls-edge-ops/` |
| `O-ready-probe` | 运维手册 · 健康 | `/api/v1/health/ready` 200 响应或探针面板 | **已捕获** → `shots/O-ready-probe.png` |
| `O-recovery-gate` | 恢复手册 | 恢复闸下只读入口/维护提示 | **ops 证据**（无 UI；恢复 fence + 隔离存储实测）→ `artifacts/M11/runs/20261025-O-recovery-gate-ops/` |
| `R-brand-manual-link` | 任意登录后页脚/帮助 | 手册入口与 v1.0 版本可见 | **已捕获** → `shots/R-brand-manual-link.png` |

汇总：已捕获 **14**/16（另 +1 附加 `U-unknown-verify-resolved`）；仍需浏览器 **0**；ops 证据替代 UI **2**（`O-tls-edge`、`O-recovery-gate`），即 16/16 槽位均有真实证据。所有者：浏览器 E2E / computerUse（用户）。
