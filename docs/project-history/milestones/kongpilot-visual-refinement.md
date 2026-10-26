# KongPilot 简约磨砂视觉优化

日期：2026-10-12。基线：`6ce3af3`。本次按用户的新规范优化 Services 和共享组件外观，保留业务内容、菜单、权限、分页与明暗切换。

## 视觉实现

- 页面基底 `#F7F8FA`，不模糊、不添加背景渐变或光效；侧栏纯白实体背景。
- 卡片/顶栏白色透明度 75%、backdrop blur 10px，边框 `rgba(0,0,0,.08)`，柔和低透明度阴影。
- 标题 `#1D2129`、正文 `#4E5969`、辅助文字 `#86909C`；字体使用 Inter/系统无衬线栈。
- 控件/容器统一 8px 圆角，业务标签 4px；主按钮低饱和靛蓝、白字与微弱内高光。
- 菜单选中态采用 2px × 16px 左侧短竖线与淡背景；菜单图标保持中性灰，hover 时使用主题色。
- 导航、Services 操作、搜索、分页和外观切换使用本地 2px SVG 线性图标，不请求外部图标或字体。
- 表头浅灰白底、600 字重；无斑马纹，仅 hover 单行淡变色；编辑/删除为低饱和文字操作，分页保留禁用与键盘焦点。
- 深色沿用对应深色变量，侧栏同样为实体表面；减少透明度与无 backdrop-filter 时降级为清晰实色。

玻璃 K Logo 沿用已认可的轮廓和玻璃层次，按最新反馈降低饱和度，使用与界面靛蓝操作色协调的蓝灰材质。控制台、登录、门户与 favicon 使用同一透明 PNG。配置与用法见 [CSS 变量清单](../../design/css-variables.md)、[品牌规范](../../design/brand-identity.md)、[实页预览](../../design/visual-preview.md)。

## 正式产品文案

按后续反馈审核 24 处页面标题，去除装饰性英文眉题与重复说明。侧栏移除「按授权范围管理」、M8 和 Gateway 标签；主界面移除实现说明页脚，隐藏未交付的工具箱菜单。总览取消 BFF/端点来源等实现介绍和宣传性副文案，保留当前状态、实际版本、资源数量与更新时间。分页只显示本页数量，不假设已知总数。登录保留品牌、账号与企业认证入口，移除口号、阶段版本和重复页脚。

必要的删除确认、密码/凭证提示、软隔离说明、审批后执行和真实错误保留。门户用户自定义欢迎内容与页面链接保留；未更改任何业务权限或执行流程。

## 验证证据

机器摘要：verification-summary.json (`artifacts/VisualRefinement/verification-summary.json`, not public)。

| 验证 | 证据 |
| --- | --- |
| 前端 TypeScript | [日志](../verification/evidence/visualrefinement/frontend-typecheck.txt) |
| API 与两端构建 | [构建](../verification/evidence/visualrefinement/build-verification.txt)、[最终前端构建](../verification/evidence/visualrefinement/frontend-build-verification.txt) |
| 浏览器交互 | 11/11，零失败、零跳过、零 flaky；报告 (`artifacts/VisualRefinement/browser-verification.json`, not public) |
| 外观/租户/权限回归 | 74/74；摘要 (`artifacts/VisualRefinement/targeted-tests.json`, not public) |
| 实际样式读取 | 白色实体侧栏、75%/10px 卡片、指定文字色阶、8px 圆角、2px 图标；浏览器 CSS (`artifacts/VisualRefinement/computed-style-evidence.json`, not public) |
| Logo 配色与透明资产 | 低饱和蓝灰、透明背景、尺寸沿用 1254px；控制台/门户/文档 PNG 字节一致；检查 (`artifacts/VisualRefinement/logo-verification.json`, not public) |
| 业务兼容 | PortalRoot、分页状态/重置和实体请求/变更逻辑的函数内容与基线相同；比较 (`artifacts/VisualRefinement/compatibility-review.json`, not public) |
| 文档链接与证据保留 | 检查 (`artifacts/VisualRefinement/documentation-check.json`, not public)、尝试历史 (`artifacts/VisualRefinement/attempt-history.json`, not public) |

浏览器检查使用实际 React 页面与隔离的示例 BFF 数据；包括鼠标与回车搜索、创建抽屉、删除名称确认、只读禁写、手机无横向溢出、短屏到达底部菜单、选中项自动展开定位、主题保存/受限存储、门户边界和 ECharts 渲染。没有发送新的网关写操作。

本次运行相关 74 项源码回归，没有重新声称全量 6309 是本次新运行；上一版全量记录仍保留。构建保留已有大包体积及 Portal 混合 import 警告，没有提高阈值或关闭提示。

## 变更边界

后端、部署文件、数据库迁移、依赖锁文件与网关未改动。Logo 仅进行已授权的低饱和配色调整，保留 K 造型与透明玻璃材质。首次图标替换的缺失引用、搜索测试角色选择错误及 Node 经典 JSX 导入兼容问题均已修复，并保留尝试摘要；未通过放宽权限或删除测试来解决。

此次 27 张截图及新记录保存在 `artifacts/VisualRefinement`。此前 `artifacts/Rebrand` 和 M0–M8 原始验收证据保持原样。源码/渲染验证不代表新生产镜像部署或真实网关重新验收；当前业务范围仍为 M0–M8，M9–M11 继续延期。
