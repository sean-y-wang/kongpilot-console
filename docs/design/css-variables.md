# KongPilot 简约磨砂视觉变量

2026-10-12。以用户提供的 agent.xfyun.cn 简约企业控制台方向为准。浅色以灰白基底、白色容器和中性灰文字为主，靛蓝只点缀交互；不添加背景渐变、光效或大面积模糊。

当前实现：[CSS 变量与组件样式](../../packages/contracts/src/pilot-appearance.css)、[Ant Design 主题](../../packages/contracts/src/pilot-theme.ts)、[2px 线性图标](../../packages/contracts/src/PilotIcon.tsx)。以下是可直接使用的浅色变量清单：

```css
html[data-appearance='light'] {
  --kp-canvas: #F7F8FA;                   /* 页面基底，不做玻璃 */
  --kp-panel: #FFFFFF;                   /* 侧栏实体白色 */
  --kp-surface: rgba(255,255,255,.75);    /* 卡片与顶栏 */
  --kp-control: rgba(255,255,255,.65);    /* 输入控件 */
  --kp-border: rgba(0,0,0,.08);
  --kp-divider: rgba(0,0,0,.04);
  --kp-text: #1D2129;                    /* 主标题、选中项 */
  --kp-body: #4E5969;                    /* 正文、表格、菜单 */
  --kp-muted: #86909C;                   /* 描述、时间、备注 */
  --kp-blue: #59668D;                    /* 低饱和靛蓝 */
  --kp-blue-hover: #68769B;
  --kp-danger: #B95C63;
  --kp-danger-hover: #A24C53;
  --kp-selected: rgba(89,102,141,.06);
  --kp-row-hover: rgba(89,102,141,.025);
  --kp-radius: 8px;
  --kp-glass-blur: 10px;
  --kp-shadow: 0 2px 12px rgba(0,0,0,.06),
               0 1px 2px rgba(0,0,0,.02);
}
```

字体栈：`Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif`。优先使用本机可用字体，本次不引入外部字体下载。

主卡片和顶栏使用 `background: var(--kp-surface)`、`backdrop-filter: blur(var(--kp-glass-blur))`、1px 细描边和柔和阴影。侧栏使用 `var(--kp-panel)`，显式关闭 backdrop-filter；页面和主布局不模糊。

标题字重 600、正文 400、按钮与菜单选中态 500。表头使用浅灰白半透明底和 600 字重，普通行不使用斑马纹，仅 hover 单行淡变色。业务标签使用浅灰底、辅助文字色和 4px 小圆角；插件/危险等语义状态标签保留状态色。

主按钮白字、8px 圆角，仅有 `inset 0 1px 0 rgba(255,255,255,.12)` 微弱高光。编辑/删除为文字操作，分别使用靛蓝/低饱和红；输入 focus 是细靛蓝边框，无扩散光效。分页去除多余边框，保留禁用状态、键盘焦点及原有 size/offset 游标行为。

菜单选中态为 2px × 16px 左侧短竖线与极淡背景，不使用大块深蓝。导航、Services 操作、搜索、分页和外观开关使用本地 SVG 2px stroke，尺寸与间距统一；装饰图标不干扰按钮/菜单的读屏名称。

页面按正式产品呈现：标题直接使用功能名称，不附英文装饰眉题或重复教程。侧栏底部仅保留滚动操作，不展示授权宣传语、Gateway 标签或 M0–M8 阶段标记；主页面不展示实现说明页脚。必要的确认、风险、软隔离和审批执行提示按实际操作保留，门户用户自定义内容与页面链接不删除。

深色继续支持切换，使用对应深色变量和实体侧栏，保持可读性。租户自定义门户主题色仍生效。减少透明度偏好或不支持 backdrop-filter 的浏览器降级为清晰实体面板。表格固定操作列使用不透明表面，避免横向滚动时文字透叠。

实页截图 · 本次验证记录
