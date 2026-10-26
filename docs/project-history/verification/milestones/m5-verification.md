# M5 监控验收记录

状态：M5 全部验收通过。修复后真实 HTTP 验收完成 2,630 项检查、0 失败；浏览器 1/1 通过并生成 9 张截图，手工界面验收 39/39 通过并生成 6 张截图，BFF 清理 341 项检查通过。启动 15 项、部署边界 27 项、Admin 网络 37 项、监控运行环境 52 项及修复连续性 18 项均通过（首次监控部署为 41 项）。两集群各 15 条原生序列、Consumer counter 和 Loki 15 条序列均已完成独立数值核对。最终扫描 870 个文件和 2 个嵌入内容，0 秘密泄漏，临时私有参考已删除。

首次证据保存在 `artifacts/M5/security-live-initial.json`，运行时秘密扫描 0 泄漏。历史 Consumer restore 经完整 8 节点只读核验结案为 `succeeded/completely_applied`；历史 Certificate delete 经 2 节点核验结案为 `failed/partially_applied`，随后显式确认恢复原归档成功。首个原生 Prometheus 配置及原幂等键的完整专用回执已通过。collector 配置返回 `PROTECTED_PROXY_DESTINATION`，失败不会计为已完成，也不会自动重发。

首次 collector 原始幂等键未在进程退出前保存，无法从单向派生的步骤键重建。只读控制台账本证据 `collector-initial-failure-ledger-proof.json` 确认 Prometheus 步骤已完成、http-log 步骤终态为失败且无实体 ID、`remote_completed=false`，集群未残留 running/uncertain 原生操作。`remote_started` 表示步骤回调开始，不能当作已发送网关请求的证明。后续已修订脚本，在任何 setup POST 前先将原始键与 CID/WID/mode/sourceId 存入仓库外 0600 参考文件；已知部分完成的修复与未知结果重发分别处理。

第二次证据保存在 `security-live-second-attempt.json`，1,220 项通过、1 项失败、0 秘密泄漏。两个真实集群的 15 条原生序列和 Consumer counter 独立计算已通过；原始稳定流量包含 588 次实际 200/404/500 代理响应。Loki 查询返回 200，但严格采样校验使整份 overview 显示 `METRICS_SOURCE_QUERY_FAILED`，未将其计为可用数据。

只读诊断确认两处真实兼容性缺陷：Loki 按 Unix step 对齐采样，未对齐请求产生 14 秒网格偏差及超出请求结束时间的样本；将边界向内对齐后的单次实际查询全部满足边界和严格网格。另有 195 条真实净化事件的 ingress/egress 字节字段全部为 null：Kong 1.5 serializer 的 `ngx.var` 字节字段是十进制字符串，采集器此前仅接受 number。证据为 `loki-template-shape-diagnosis.json`、`loki-inward-aligned-window-diagnosis.json` 和 `loki-bandwidth-diagnosis.json`，只保留范围、时间、类型和数量，不公开原始事件或查询字符串。

实际两节点 Lua 源码的版本、路径、SHA256 与两处字段赋值证据保存在 `kong-1.5-serializer-byte-compatibility.json`；此证据来自只读源码，不是模拟日志。严格规范化仅针对这两个字节字段，缺失值仍为空，拒绝指数、符号、空白、前导零和溢出；不会将其他字段宽松转换或将缺失填零。完整源码回归为 1,349/1,349 用例、222 suites、98 个实际测试文件，API/Web 类型检查通过；仍须以修复后运行时实际流量验证通道。

修复后的验收采用受控 checkpoint continuation，复用现有对象、账户、凭证、代次与 epoch，不重跑 setup/轮换/恢复，也不补写旧 null 日志。采集器修复部署后，重新生成至少 80 秒稳定流量，在新的 requested window 与 Loki 明确的 inward effective window 分别进行完整真实数值核对。旧失败报告保留，不覆盖为成功。

实际 continuation 产生 624 次真实代理响应，稳定流量持续 80,155 毫秒；冻结结束时间后等待 15 秒交付与抓取稳定，再查询同一固定窗口。原生/Consumer requested window 为 20:29:28–20:34:28 UTC，Loki effective window 为 20:29:30–20:34:15 UTC。174 条实际净化事件独立计算了全部 15 条 Loki 序列，每条 5 个数值点与 15 个明确空值均一致。原始 HTTP 写入与 continuation 的 97 个成功请求 ID 均在追加审计中找到。

数值核对完成后发生两次辅助脚本配置中断，分别因 `docker compose logs` 缺少监控/多集群 overlay，以及未加载 `.env.multicluster`；产品和真实数值核对未失败。保留报告 `security-live-continuation-log-harness.json`（2,596 项通过）与 `security-live-continuation-log-env-harness.json`（2,605 项通过）；修正只读日志命令后，仅补执行剩余日志、集群、撤销、浏览器测试账户与审计检查，没有重跑原生配置或数值窗口。

浏览器证据 `browser-verification.json` 为 1 项通过、0 失败，9 张实际截图；页面错误、直连 Admin API、监控账户读取原生配置及漏传 workspaceId 均为 0。浏览器阶段保持 216 次认证代理请求，7 个成功 HTTP 写请求 ID 全部有审计。此前两次选择器脚本中断发生在产品写入之前：测试未搜索后续游标页的目标实体，以及错误地假设切换数据源后仍保留 Service 筛选。修订脚本以当前选择状态关联响应，记录保存在 `browser-first-selector-attempt.json` 和 `browser-second-source-selector-attempt.json`，没有修改产品行为。

手工验收证据 `UI-review.json` 为 39 项通过、0 失败，6 张实际截图。8 个成功 HTTP 写请求均有审计，其中 7 个登录请求、1 个同 source/mode 的 setup 请求。刻意丢弃已成功的 setup 响应后，提交保持锁定；仅用已私存的原始父幂等键查询专用回执，确认父状态成功、3 个步骤均 remoteCompleted，没有恢复 POST 或自动重发。手工验收未生成新配置对象或新合成凭证。Root 已亲自检查全部 15 张浏览器/手工截图，证据分别为 `root-visual-review.json` 与 `root-manual-visual-review.json`。

测试清理证据 `failed-fixture-cleanup.json` 为 341 项检查通过：合并全部保留尝试的两个唯一测试标签，9 个原生根对象经正常 BFF 确认进入回收站，20 个子对象已随归档图级联移除；撤销 7 个剩余绑定，软删除 9 个测试用户、9 个角色和 6 个工作区。清理的 41 个成功 HTTP 请求 ID 均有审计，直接原生清理写入与 Kong 数据库写入均为 0。原 C1 数据源、新增后明确保留的 C2 Prometheus/Loki 数据源、两集群全局监控插件、四用途材料和当前设置继续作为监控基础设施保留；历史回收归档和审计不重置。

## 验证范围

真实环境使用两个独立 Kong 1.5.1 集群、现有 Prometheus 和 Loki；集群间创建相同 Service/Route UUID，验证查询始终绑定当前集群和工作区。原生 Prometheus 插件版本为 0.6.0，保留 `kong_http_status`、`kong_latency_bucket` 和 `kong_bandwidth` 原始指标名，延迟单位为毫秒。

`tests/security/live-m5.mjs` 先通过正常 BFF 建立隔离工作区、认证 Consumer 和 200/404/500 流量路由。安装采集通道、四用途凭证轮换、标签变更和工作区迁移均在最终流量窗口之前完成。原生配置写入会关闭旧归属 epoch，因此最终图表采用独立稳定的对象与固定时间窗口。

独立计算工具不导入 BFF 查询生成器。它们读取真实 Prometheus HTTP API 的原始计数器速率，按当前 epoch 和年龄过滤后计算 QPS、状态码及带宽；P50/P95/P99 使用实际毫秒直方图桶作线性插值。Consumer TopN 独立核对当前 Consumer epoch 和当前同工作区 Route-pair epoch；Consumer 监控权限不会授予原生配置读取、Route 选择器或 Service 流量读取。

Loki 必须有实际 `http-log` 流量和已净化事件，单纯连通成功不能验收。脚本读取相同时间窗口内的净化事件，独立计算请求率、状态码、字节率和延迟分位数。Loki 日志分位数与原生桶插值分别验证；两者不承诺完全相同的估计值。Consumer 和日志通道明确采用至少一次投递的近似语义，两个完全相同的合法事件应分别计数，不宣称恰好一次。

## 真实验收结果

| 项目 | 验证方式 | 状态 |
| --- | --- | --- |
| 双集群真实通道 | 两个原生集群分别启用 Prometheus/http-log；四种凭证绑定集群、用途、受众和代次 | 已通过 |
| 固定时间窗数值 | 两集群各 15 条原生序列与独立原始速率/桶计算一致 | 已通过 |
| Consumer 通道 | 实际 API Key 认证；自身 TopN 与原始 collector rates 一致，跨工作区事件排除 | 已通过 |
| Loki 备选通道 | 实际净化事件与 15 条指标的独立同窗计算一致 | 已通过 |
| 当前归属与空值 | 标签变更、联合迁移、旧归属历史不重标；新 epoch/缺样本为 null；原凭证仍可代理认证 | 已通过 |
| 权限边界 | workspace/tag/entity/global 四维完整授权行、Service/Route/Consumer 独立范围、立即撤销 | 已通过 |
| 输入与预算 | 任意查询、URL、未知字段、错误时间和超预算请求在调用指标源前拒绝；实际请求计数不增加 | 已通过 |
| 内部入口 | 错用途/错集群/旧代次拒绝；平台 Cookie/JWT 无法替代内部用途凭证；Admin ACL 保持 | 已通过 |
| 浏览器 | 实际图表、Service/Route 下钻、Consumer-only 空原生图、7 天历史缺口、移动端与撤销现有会话 | 已通过，9 张截图 |
| 手工界面 | 全集群节点、Prometheus/Loki、时间与自动刷新、移动端、类型确认和未知结果专用回执 | 已通过，39 项、6 张截图 |
| 审计与清理 | 成功产品写入 requestId 对应审计；测试对象经 BFF 回收/软删除，历史不重置 | 已通过，清理 341 项 |
| 最终秘密扫描 | 环境及运行时密码、API Key、四用途 token、Cookie 覆盖源码、编译产物、截图及 ZIP | 已通过，870 文件、2 个嵌入内容、0 泄漏 |

## 离线证据与实际证据的界限

独立计算工具单测 9/9 已通过，覆盖 NaN/缺失值保留 null、真实零值保留、时间网格与遗漏检查、计数器聚合、实际桶插值、Loki 经验分位数与窗口边界、关闭 epoch 排除。脚本语法检查通过；Playwright `--list` 发现 1 项验收测试。离线单测、语法检查与测试发现只证明脚本可执行，不证明真实数据通道已经通过。

测试秘密曾仅保留于仓库外权限 0600 的临时参考文件；原始日志事件未持久化至宿主机。所有最终截图、手工验收和清理证据完成后，已执行 `finalize-m5-secret-scan.mjs --evidence-complete`，报告 `runtime-secret-artifact-scan.json` 覆盖两份部署环境文件的秘密、可选认证供应商秘密、原始及 Basic 编码的采集 token、账户密码、API Key 和 Cookie。870 个源码/编译产物/证据文件及 2 个 ZIP 嵌入内容均无泄漏，临时运行时参考和 continuation checkpoint 已删除。正式运行需要的权限 0400 采集材料继续保留，未配置的外部指标服务和供应商不计为通过。
