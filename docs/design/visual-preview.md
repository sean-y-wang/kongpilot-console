# KongPilot 实页视觉预览

**Kong 网关管理平台** · 2026-10-12

以下是实际 React 页面在 Chromium 中的截图，页面数据来自隔离的示例 BFF 响应。它们用于验证外观、导航、表单和权限按钮，不代表真实生产数据、新镜像部署或 Kong 全量业务验收。历史生成效果图不作为当前 UI 结果。

## Services 资源列表

按最新规范统一 8px 圆角、三级灰度、2px 线性图标、短竖线选中态、文字操作、淡灰标签和无多余描边的分页。搜索、列表、操作和原有业务内容完整保留；移除装饰性英文眉题、重复说明、阶段标签与实现说明页脚。

`artifacts/VisualRefinement/services-desktop.png` (screenshot not public)

`artifacts/VisualRefinement/services-dark.png` (screenshot not public)

行悬停效果 (`artifacts/VisualRefinement/services-hover.png`, not public) · [CSS 变量清单](css-variables.md)

上一版截图仍保存在 artifacts/Rebrand，本页使用此次新路径，不覆盖旧证据。

## 浅色与深色总览

浅色以灰白基底、白色轻磨砂卡片、纯白实体侧栏和低饱和靛蓝为主；深色使用对应的石墨面板。玻璃 K Logo 使用低饱和蓝灰配色，与按钮和中性灰层次协调。登录、控制台和独立门户均提供月亮/太阳切换按钮，首次跟随系统，手动选择后在当前浏览器保存。

`artifacts/VisualRefinement/overview-desktop.png` (screenshot not public)

`artifacts/VisualRefinement/overview-dark.png` (screenshot not public)

## 完整侧栏

Logo 与底栏固定，只有菜单区域滚动。三个分组可展开/收起；底栏的箭头可向上或向下翻看菜单，当前项自动进入可见区域。菜单数量以当前授权为准，小屏幕保留较大的触摸行高。

下图折叠「控制台」「网关实体」后，完整展示已交付的「平台管理」入口。

`artifacts/VisualRefinement/navigation-platform-desktop.png` (screenshot not public)

720px 高度桌面可滚动到末尾：底部入口 (`artifacts/VisualRefinement/navigation-desktop-bottom.png`, not public)。移动端同样支持滚动与关闭：移动导航 (`artifacts/VisualRefinement/navigation-mobile.png`, not public)。

## 更多页面

| 页面 | 浅色 / 默认 | 深色 / 其他视图 |
| --- | --- | --- |
| 登录 | 桌面 (`artifacts/VisualRefinement/login-desktop.png`, not public) | 深色 (`artifacts/VisualRefinement/login-dark.png`, not public)、手机 (`artifacts/VisualRefinement/login-mobile.png`, not public) |
| Services | 列表 (`artifacts/VisualRefinement/services-desktop.png`, not public) | 深色 (`artifacts/VisualRefinement/services-dark.png`, not public)、手机 (`artifacts/VisualRefinement/services-mobile.png`, not public) |
| 表单与确认 | 创建抽屉 (`artifacts/VisualRefinement/service-create-drawer.png`, not public) | 回收确认 (`artifacts/VisualRefinement/delete-confirmation.png`, not public) |
| 授权 | 只读按钮 (`artifacts/VisualRefinement/readonly-services.png`, not public) | — |
| 集群 / 插件 | 集群 (`artifacts/VisualRefinement/clusters-desktop.png`, not public) | 插件中心 (`artifacts/VisualRefinement/plugins-desktop.png`, not public) |
| 配置快照 | 快照 (`artifacts/VisualRefinement/snapshots-desktop.png`, not public) | — |
| Vitals | 图表 (`artifacts/VisualRefinement/vitals-charts-desktop.png`, not public) | 深色 (`artifacts/VisualRefinement/vitals-charts-dark.png`, not public)、未配置 (`artifacts/VisualRefinement/vitals-unconfigured.png`, not public) |
| 门户 | API 目录 (`artifacts/VisualRefinement/portal-api-catalog.png`, not public) | 深色 (`artifacts/VisualRefinement/portal-api-catalog-dark.png`, not public)、登录 (`artifacts/VisualRefinement/portal-login.png`, not public) |
| 门户空间选择 | 桌面 (`artifacts/VisualRefinement/portal-tenant-picker.png`, not public) | 手机 (`artifacts/VisualRefinement/portal-tenant-picker-mobile.png`, not public) |

Logo 原图：[透明蓝灰玻璃 K](kongpilot-logo-glass.png)。颜色、材质和兼容边界见 [品牌规范](brand-identity.md)。操作与部署见 [用户使用手册](../manuals/console-user-guide.md)、[部署运维手册](../manuals/production-operations-guide.md)。
