# M5 实施计划：真实 Kong 1.5 监控

状态：M4 收尾期间的设计准备；本文件不表示 M5 已实现或验证。按用户已授权的顺序，M4 完成验证和提交后执行本计划，无需再次确认。

## 数据通道

Kong 1.5.1 自带 Prometheus 0.6.0。原生请求指标按 Service/Route 标签区分，延迟单位为毫秒，没有 Consumer 或工作区标签。固定只读采集桥在 BFF 独立内部 TCP 9092 监听，只有桥的后台执行上下文可以获取 `/metrics`；Prometheus 和采集器不接入 Admin 网络，不增加 Admin ACL 来源。

独立 Node 采集器处理真实 `http-log` 数据，立即只提取 Consumer/Service/Route ID、状态码、时间、毫秒耗时和字节数，丢弃请求头、请求参数、Cookie、正文和凭证。Consumer 通道标记为至少一次投递的近似计数，不能冒充原生准确指标。Loki 备选通道只保存上述净化数据。

采集器固定内部地址为 `telemetry-collector:9093`，只开放受控的 `/ingest/{clusterId}`、`/metrics/{clusterId}` 与健康检查路径，不发布宿主端口。每批日志通过 BFF 内部 `POST /catalog/{clusterId}/validate` 校验最多 256 个实体引用和整个事件时间区间；该入口只执行只读目录核验，不接受原生写操作。目录认证凭证与采集、入站日志凭证分开，代次轮换时按新鲜数据库状态拒绝旧代次。

每个集群登记完成后，由可信 enrollment 命令分别生成 native_scrape、collector_scrape、collector_catalog、collector_ingest 四种凭证。凭证限定集群、用途、受众和代次；数据库加密保存，校验使用高熵秘密的 SHA256 摘要，轮换通过只读目录挂载更新，不复用管理员密码或 JWT 密钥。

## 归属与权限

SQL007 保存节点、监控设置、独立凭证、不可变归属 epoch 和原生写入 fence。新的配置写入在发送前持久化关闭旧 epoch；同一操作重复准备发送仍幂等。运行中或结果不确定的变更保持阻断，只有明确终态和新鲜原生目录共同成立后才能建立新 epoch，不重新开启旧 epoch。

目录通过有界原生分页和新鲜对象证据核验，带目录版本 CAS。标签冲突、无法归属、跨区关系和不完整扫描都明确标记不可用。指标样本包含已验证的集群、节点、工作区、实体和 epoch；查询同时匹配当前授权对象、已记录工作区和当前 epoch，不能把旧归属历史重新映射给新负责人。

监控权限独立于原生配置读取权限。按完整的功能模块、操作、范围类型、范围值授权行核验实际对象；Service/Route/Consumer 仅返回获授权的最小 ID/名称。集群级节点指标需要覆盖整个集群。请求开始、查询前和返回前检查当前授权版本，撤销期间拒绝响应，不能降级成可用的空图。

## API 与界面

- `GET /clusters/:cid/vitals/capabilities`：真实插件能力、可用数据源、安全连接状态和数据质量。
- `GET /clusters/:cid/vitals/overview`：5 分钟至 7 天窗口、QPS、状态码、P50/P95/P99、带宽、TopN、节点状态及服务/路由下钻。
- `GET /clusters/:cid/vitals/entities`：带作用域、游标和搜索的最小实体选择器。
- `POST /clusters/:cid/vitals/setup`：平台管理员确认后，经现有变更账本安装/启用插件和选择数据源，保留审批模式的限制。

React 页面采用 ECharts 展示真实序列，缺样本显示不可用或等待采样，不填造零值。服务端固定查询模板，浏览器不能提交 PromQL、LogQL、上游 URL 或任意管理路径。单次最多 18 次上游调用、800 时间点、64 序列、256 归属选择器，上游累计 8 MiB，公开响应 2 MiB；超预算明确报错。

Loki 指标按 Unix 时间步长边界求值。后端先校验原始 5 分钟至 7 天请求，再将 Loki 起点向上、终点向下对齐，所有范围和即时查询使用同一实际窗口。响应的 `timeWindow` 与 `evaluationAt` 表示实际求值范围；发生对齐时另给 `requestedWindow` 和 `LOKI_EVALUATION_GRID_ALIGNED`，不移动响应样本的时间戳。例如 20:12:01–20:17:01、步长 15 秒的实际范围是 20:12:15–20:17:00。请求范围内没有采样点时返回 `LOKI_EVALUATION_WINDOW_EMPTY`，不伪造空的有效窗口。Prometheus 仍使用原始请求窗口。

## 验证与交付

先完成 SQL/服务端/采集器/界面，统一构建后启动真实双集群、Prometheus 和 Loki。生成不同状态码、认证 Consumer、延迟和带宽流量；使用同一评估时间窗逐项对照 Prometheus 原始 HTTP API。验证 Consumer 独立通道、工作区/服务/路由下钻、当前权限、归属变更及缺数据行为。

检查错用途/错集群/撤销 token、公网采集入口拒绝、采集器和 Prometheus 不能访问 Admin、原有精确 Admin ACL、累积响应预算、原始日志不留存以及全部测试凭证的最终证据扫描。分别记录真实容器结果与受控故障测试，不把未配置的外部供应商视为验收成功。通过后形成 M5 证据并提交，再进入 M6。
