# M5 真实 Prometheus0.6 接入准备

本文件记录 M4 开发期间获授权进行的只读研究，不表示监控模块已经实现。没有修改 Compose/API、创建插件或改变现有监控数据源。真实探测及源代码摘要见 `artifacts/planning/M5-prometheus-live-capabilities.json`。

## Kong1.5.1 实际能力

镜像中的 `kong/plugins/prometheus/handler.lua` 声明插件版本0.6.0。旧路径 `/plugins/schema/prometheus` 实际响应 `{ "fields": [] }`，没有现代版本的 consumer/status/latency 开关。`/metrics` 是该插件在 Admin API 注册的真实只读端点，不是 Enterprise Vitals；M5接入时须在版本适配层单独登记此经过实际探测的插件扩展，不能开放任意 Admin 路径。

现有两节点 `/metrics` 经 BFF 管理网络请求均200，当前各32行样本仅含连接数、datastore、内存和 metric-error 指标。未启用全局插件且未生成有效测量流量时，不能把缺失的请求曲线当作零流量或声称延迟已经实测。

| 原生指标 | 标签 | 语义 |
| --- | --- | --- |
| `kong_http_status` | `code,service,route` | counter；名称没有现代 `_total` 后缀 |
| `kong_latency_bucket/count/sum` | `type,service,route`，bucket另含`le` | histogram；type=`request/upstream/kong`，单位毫秒 |
| `kong_bandwidth` | `type,service,route` | counter；type=`ingress/egress`，单位字节 |
| `kong_nginx_http_current_connections` | `state` | 连接状态；accepted/handled/total虽命名为gauge但为累计值 |
| `kong_datastore_reachable` | 无 | datastore连通1/0 |
| 内存指标 | `pid`或`shared_dict` | node级全局gauge |

exporter 使用的有限 latency buckets 是 `[1,2,5,7,10,15,20,25,30,40,50,60,70,80,90,100,200,300,400,500,1000,2000,5000,10000,30000,60000]`，另有`+Inf`，不能套用 vendored Prometheus库的秒级默认桶。P50/P95/P99使用实际bucket做`histogram_quantile`，若产品采用秒单位需显式除以1000。

原生不含 consumer/workspace/node_id 标签。Service标签是`name`，缺名时退化为`host`；Route是`name`，缺名时为`id`。多个无名Service共享host时不能从合并计数反推某个Service：标记归属不明，避免伪造工作区或错误下钻。

## 保持精确 Admin ACL 的抓取桥

Prometheus继续仅加入 observability网络，不能增加它的 Admin ACL 来源或加入 KongAdmin/storage网络。已确定使用 console-api 的独立内部 Node HTTP 监听端口9092，脱离 MainHTTP 的 ALS/AuthGuard，不在3000或公网Nginx增加监控系统入口；此时仍只是实施契约，尚未启动监听器：

1. Prometheus请求 telemetry-only DNS 别名`metrics-bff:9092/scrape/:clusterId`，每个已登记真实集群对应固定只读路径；输入仅为受控 clusterId，不接受目标URL/任意path。API多网的`console-api` DNS可能解析到其他接口，不用于绑定独立telemetry IP的9092。适配层只允许该节点的`GET /metrics`，文本响应限制2MiB/5秒，并提供限流、缓存、熔断和失败状态，不经过 Kong数据库。
2. 入口使用独立高熵、可轮换且限定集群的 scrape token；不得复用管理员密码/JWT/APP_SECRET。禁用cookie认证和普通用户权限兜底，拒绝无token与错token。公网Nginx显式拒绝此内部路径；内部API也独立验token。
3. Prometheus用`bearer_token_file`读取只读秘密文件。集群注册和探测后，由独立可信bootstrap命令按clusterId生成秘密，不把未知集群的token放进全局迁移seed。宿主秘密目录0700，生成器不覆盖；只读挂载给API/Prometheus的最小必要文件，运行UID的可读权限在真实容器中验证。秘密文件/目录需同时gitignore/dockerignore，扫描秘密值而不是导出文件内容。
4. M5最终契约使用稳定`cluster_id`与物理`transport_scope`的64hex SHA256作为指标`node_id`；另记录真实探测的 Kong worker ID用于节点重建后关闭旧epoch，不把两者混用。服务/路由/工作区映射基于有界、经过fresh验证的不可变assignment epochs。编码标签需完整转义，旧tag软隔离和不明归属要显式表达。节点全局gauge不能伪造workspace维度。
5. QPS=`rate(kong_http_status[窗口])`，状态码分类按`code`汇总，延迟按真正type/bucket计算，带宽用counter rate，节点状态结合Prometheus`up`与`kong_datastore_reachable`。真实验收生成200/404/500及带认证请求，与Prometheus原始HTTP API结果按同一时间窗口对照。

## Consumer通道的原生限制

Consumer TopN无法从0.6原生指标取得。若M5要完整提供此能力，需自建独立日志/指标采集通道，明确来源，不能把service请求数冒充consumer请求数。

实际1.5 http-log schema没有`headers`或`custom_fields_by_lua`，只有`http_endpoint/method/content_type/timeout/keepalive/retry_count/queue_size/flush_timeout`。handler可从URL userinfo生成Basic Authorization，但TLS握手硬编码verify=false；不可宣称它验证了外部HTTPS证书。

已确定独立内部 Node collector，只加入必要代理/监控网络，用每集群独立秘密认证；collector只能使用另外的只读token请求`metrics-bff:9092/catalog/:clusterId`及`POST /catalog/:clusterId/validate`取得最小fresh归属映射，不持有管理写权限、JWT或原始scrape token，不加入Kong Admin网络，避免把控制台管理入口直接作为业务上游。插件原生完整serializer包含请求/响应头等信息，collector进入处理流程后立即只提取经过验证的consumer/service/route标识、状态、耗时和字节数，丢弃headers/query/body/凭证，不打印原始payload，不把原始日志写入Loki/磁盘。现有脱敏器会删除URL userinfo；创建及后续插件编辑必须保持隐藏凭证语义，并进行真实漏密扫描。此为M4期间只读研究基线；M5源码/启动状态与最终证据见 [部署说明](../../project-history/milestones/m5-deployment.md)，不能从本计划推断真实流量验收已完成。
