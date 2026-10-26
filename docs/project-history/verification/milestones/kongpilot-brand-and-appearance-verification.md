# KongPilot 品牌、明暗外观与导航交付记录

日期：2026-10-12。原始业务验收基线：`a44cffa`；历史 M0–M8 验收记录不覆盖、不重写。

## 交付范围

英文名称 **KongPilot**，中文名称 **Kong 网关管理平台**，仓库 `kongpilot-console`，npm 工作区 `@kongpilot/*`。登录、控制台、门户、浏览器标题、favicon、Swagger、通知、导出提示和新构建镜像标识已统一。

按最新反馈，取消大面积浅蓝铺色：浅色使用白色、石墨文字和深墨蓝；深色使用分层石墨面板。采用克制的玻璃边缘高光与阴影，保留已认可的透明蓝色玻璃 K Logo。控制台、登录、门户、抽屉、确认窗与 Vitals 图表随外观同步；首次跟随系统，选择在当前浏览器保存，存储被禁用时仍可切换。

侧栏固定 Logo 和底栏，菜单独立滚动、分组可折叠，底栏箭头支持翻看。桌面 720px 高度与手机可到达最后一个入口；当前项自动展开并完整进入可见区域，不滚动主页面。没有删去功能入口，权限过滤与只读按钮仍按原规则执行。

主手册按 KongPilot 重新编写：[部署与运维](../../../manuals/production-operations-guide.md)、[用户使用](../../../manuals/console-user-guide.md)。此前复杂技术细节单独保留为带历史说明的技术参考。新建 `compose.external-kong.yml`，可单独部署平台并接入已有网关；本次只验证最终 Compose 配置，没有启动该新组合。

## 验证与证据

最终机器摘要：verification-summary.json (`artifacts/Rebrand/verification-summary.json`, not public)。

| 检查 | 结果与证据 |
| --- | --- |
| TypeScript | API、Console、Portal 通过；日志 (`artifacts/Rebrand/typecheck.log`, not public) |
| 正式编译 | 三个工作区构建通过；日志 (`artifacts/Rebrand/build.log`, not public) |
| 源码单测与安全回归 | 6309/6309 通过，零失败、零待执行；源码摘要 (`artifacts/Rebrand/source-verification.json`, not public) |
| 浏览器渲染与交互 | 11/11 场景通过，零跳过、零 flaky；报告 (`artifacts/Rebrand/browser-verification.json`, not public) |
| 侧栏加强检查 | 短屏完整露出底部菜单、固定品牌/底栏、折叠后通过页面内导航自动展开并定位；1/1；报告 (`artifacts/Rebrand/navigation-verification.json`, not public) |
| Compose 合同 | 自带网关 9 服务与外部网关 6 服务均通过；Admin 不发布；报告 (`artifacts/Rebrand/compose-configuration-check.json`, not public) |
| 更名兼容 | 依赖版本与 SQL000–011 不变；门户 PortalRoot 和租户 helper 不变；文档/迁移 (`artifacts/Rebrand/documentation-and-migration-check.json`, not public)、门户比较 (`artifacts/Rebrand/portal-root-compatibility-review.json`, not public) |
| 公共产物 | 新候选文件无私有环境文件或嵌入 PEM 私钥材料；检查范围 (`artifacts/Rebrand/public-artifact-check.json`, not public) |

26 张实页截图见 [视觉预览](../../../design/visual-preview.md)。它们使用真实 React 组件与隔离的示例 BFF 响应，验证外观与交互；没有执行新的网关写操作，没有作为真实 Kong、监控准确性或生产部署验收证明。

构建保留已有的大包体积、静态/动态混合 import 警告，没有提高警告阈值掩盖它们。早期选择器、fixture、品牌期望与 TypeScript 问题，以及并行验证时的超时均在 尝试历史 (`artifacts/Rebrand/verification-attempt-history.json`, not public) 保留，最终通过结果单独记录。

## 兼容与运行边界

- 未修改 Kong 源码、网关镜像实现、数据库或 Admin API 白名单；后端仍只通过 1.5 适配层管理网关。
- 既有 Cookie/JWT、加密 AAD、Redis/恢复键、`KONGOS_*` 参数、数据库名称与 SQL 校验值保留；产品文本更名不强行迁移数据协议。
- 原仓库路径保留兼容链接。已有生产升级继续使用原 Compose project、卷与密钥；新项目采用 `kongpilot-production`，不能因产品更名创建空数据卷。
- 仅清理已确认可重建的 npm 下载缓存，释放约 529MiB；没有删除数据库卷、历史审计、验收记录、镜像恢复包或加密备份。
- 本次已完成源码构建与视觉回归，未重建/扫描品牌版 Docker 镜像，未完成新持久生产站点冷启动或异机灾备。本次不改变原生产准入结论。

## 后续计划

按部署手册在目标持久站点构建品牌版镜像，记录摘要与扫描结果，完成平台依赖处置、TLS/Origin、权限、备份恢复和真实业务接入验收，再发布。已有 Kong 的维护由网关运营方独立管理。

M0–M8 既有技术闭环保持，详细业务证据见 [阶段验证](m0-m8-production-verification.md)；M9–M11 按用户决定继续延期，不在本次视觉升级中扩展。
