# M5 独立监控审核与测试契约

这是 M4 部署期间的只读测试准备，不表示 M5 已实现或验收。真实 Kong 1.5.1 / Prometheus 0.6 指标事实见 [接入准备](m5-prometheus-integration-plan.md)。M5 源码须在 M4 提交后开始；本文件只约定测试重点。

已由 Kong owner 确认的接口边界：用户监控接口只接受当前集群的 active `sourceId` UUID（省略时采用 settings 的 active source），时间是严格 UTC ISO 字符串，窗口 5 分钟–7 天，每条曲线最多 800 点，rate window 由服务端决定。范围授权使用独立 `assertScopedResource/filterScopedResources`，把模块 `monitoring`、实际 native type、当前对象 tags/父关系/typed IDs 作为完整权限目标；不要求调用方具备 native 配置 read。

内部通道是独立监听器 9092 的 `GET /scrape/:clusterId` 和 `GET /catalog/:clusterId`，不挂入公网/main HTTP 的 ALS/AuthGuard 路由。四种 token purpose 为 `native_scrape`、`collector_scrape`、`collector_catalog`、`collector_ingest`，分别校验 cluster、audience、purpose、generation，使用不同原始密钥，不能互相替代。collector 的指标抓取目标独立于原生抓取桥。Kong text 适配器只允许已探测的 1.5 Prometheus 扩展 `GET /metrics`，2 MiB/5 秒预算和共享物理 transport scope 限流/熔断，无重定向。

## 四维授权和最小返回

| 测试 | 设置/攻击 | 必须观察的结果 |
| --- | --- | --- |
| Monitoring-only 正向 | 当前用户只有 `monitoring.read`，没有 Services/Routes/Consumers 配置 read | 合法范围指标可查询；API 只返回 ID/显示名/必要父名称，不返回 host、config、证书、地址或凭证 |
| 完整 row | 将 read、workspace、业务标签、实体 ID 放在不同 grant row，任何单条都不完整 | 403；不能拼接四维授权，零 Prometheus 查询 |
| Global | 集群/工作区上限仍来自当前绑定，不以 JWT 的 global/admin 字段扩大 | 越过上限 403；全局 node gauge 仅给具备相应全局 monitoring 范围的用户 |
| Workspace | 同一个 cluster 两工作区；用另一工作区/另一 cluster 的对象、source 或缓存 cursor | 403/404 按最终契约；返回和缓存不得含另一范围数据 |
| Tag group | `team:pay OR team:ops` 与 workspace 上限同时存在；对象只命中第三个标签 | 标签组内部 OR，workspace AND；无交集的显式对象 403，聚合由后端过滤 |
| Typed entity | Service 白名单 ID 与同 UUID 的其他类型、兄弟 Service 或任意名称 | 只接受正确 native type/ID；ID 显式输入不能代替服务端实际对象校验 |
| Route/Service/Consumer | 多级下钻或 Plugin/Route 等父关系跨区 | 监控范围继承必须单独约定，不能借 native 路由 read 或单个父授权获得其他对象指标 |
| 即时撤权 | 查询第一请求后撤销角色、停用账号/工作区、改变权限版本；继续使用原 cookie/查询 cache | 当前授权重新核验；旧结果不被新范围 cache 返回；前端取消/清除旧范围展示 |
| Secret 权限 | 只有 monitoring 与必要范围权限，没有 secrets.read | 指标/目录/错误/审计均不包含私钥、API Key、collector token、provider credential |

权限目录/名称发现使用监控自己的最小对象 DTO。为了核对当前 tags/父关系的内部读能力只能由可信服务创建，不能从前端 `system/purpose/module/approved` 字段提升。测试直接调用 provider/adapter，绕过监控 controller/domain，仍应被私有执行策略拒绝。

对正在进行的查询，至少在发送 provider 请求前以及缓存返回前核验当前 scope/version。权限变化时不能复用旧 actor、cluster、workspace、tags、source 或 selector 的缓存项。并发两个 actor/scope 的查询需要 ALS 隔离回归。

## 时间、PromQL 和资源预算

已批准的查询白名单分别是 overview 的 `workspaceId/sourceId/serviceId/routeId/start/end/step`、caps 的 `workspaceId/sourceId`、entities 的 `workspaceId/type/size/cursor/search`。caps 返回当前集群中安全的 active provider 选项；跨集群、停用/删除的 source 或 provider 凭证不可通过选项、默认源与错误响应泄露。

| 测试输入/上游行为 | 必须结果 |
| --- | --- |
| 非 UTC、缺 Z、错误月份/日期、NaN、start≥end、窗口不足 5 分钟或超过 7 天、end 超过服务端 now+5 秒 | 查询前 400，不能让 JavaScript 日期纠正成另一时间 |
| 自定义 `query/promql/consumerId/rateWindow/url/path/template`、重复 query 参数、数组/对象值、超长 selector | 拒绝未知字段；PromQL 只能由服务端固定模板生成，不提供通用查询代理 |
| step 非整数、小于 15 秒，或时间窗/step 组合产生超过 800 点 | 查询前 400；合法 step 只影响固定模板采样，不提供 PromQL 或 rateWindow 注入，服务端 rateWindow=max(60 秒,2×step) |
| service/route/consumer 名称包含引号、反斜杠、换行、正则元字符 | 使用授权的稳定 ID/完整转义标签，不扩大 matcher；内容不进入未脱敏日志 |
| 7 天趋势、最小窗口、时间跨度切换 | 每条曲线≤800 点，省略 step 时服务端推导；UI 与原始 Prometheus 查询使用同一边界和单位 |
| 超多 series、长 label、巨大矩阵、慢响应、gzip 解压放大、重定向、反复 retry | 有硬 byte/series/sample/deadline 预算；失败明确显示不可用，不能全量返回、无限重试或记作零 |
| 出站超时或 Prometheus error 响应 | 统一可读错误，禁止 echo endpoint credentials、原始响应体或未经授权 label |
| 切换/停用 source、source revision 改变、跨 cluster sourceId | 原 transport/auth/query cache 失效，不能把旧结果赋给新数据源；错误时没有另一个源的隐式 fallback |

Root 已批准一次查询最多 18 个固定 Prometheus/Loki 请求、64 条公开 series、总 51,200 点、2 MiB 公开 JSON、8 MiB 上游累计响应，以及最多 256 个当前已授权 assignment refs。所有计数须跨子查询累计，越界明确 409/不可用，不能截断后宣称完整。实际 query deadline、并发数以及 collector batch 上限仍由实现契约明确。

原生 counter 名称是 `kong_http_status`、`kong_bandwidth`；latency bucket 单位毫秒，type 为 request/upstream/kong。QPS/带宽必须用 rate，P50/P95/P99 用实际 histogram buckets；不能套用现代 exporter 字段或默认秒级桶。native Consumer/workspace 标签不存在，不得伪造对应 TopN/下钻。

## 归属和历史标签

采集目录只能返回稳定 IDs、native labels、workspace_id、业务标签 epoch、quality、expiry；不返回 raw config/URL/credentials。目录项候选结构为 `{epochId,clusterId,transportScope,nodeId,serviceId,routeId,workspaceId,businessTags,serviceLabel,routeLabel,verifiedAt,validUntil,closedAt?,quality:'verified'}`；Consumer 同样使用稳定 ID/membership epoch。签名分页 cursor 绑定当前目录 revision/expiry，最长有效 15 秒。测试以下状态，不能用当前索引把历史流量重新赋给新负责人：

1. Service 由工作区 A 迁移到 B、业务标签由 pay 改 ops，分别在变更前后采样，查询跨越迁移的时间窗。已采集的旧样本归属保持原 scope/epoch；新样本只属于新 scope。显式对象查询还须核验调用方当前范围，失效归属不可当作新授权。
2. Service/Route 重命名或删除重建，同 name 不同 UUID。旧 series 不能归入新对象；删除的工作区也不能重标为 default。
3. 两个无名 Service 共用 host；一个有名 Service 的 name 恰好等于另一个无名 Service 的 host。service-only native label 歧义不可猜测；存在已核验 route UUID 与真实 route.service UUID 的配对时可以据此解歧义，缺少可信配对时标记 unassigned/partial。
4. 存在未知、多重/过期 workspace 标签，或 catalog epoch/expiry 落后。归属标记 unavailable/unassigned，不能扩大受限查询；不得在受限响应里附带全局未归属标签或流量总数。
5. Kong 重建后的真实 node_id 改变，cluster_id 保持注册值。旧 node series 不被当作当前在线节点；counter reset 正常处理。

角色/标签变化的历史可见性契约为：非平台用户同时满足当前对象授权、当前 epoch 和样本记录的工作区；平台全部历史必须显式选择。同工作区内业务标签转移也开新 epoch，不能因 workspace 相同复用旧标签归属。首次 counter sample 仅建 baseline，少于有效 rate samples 或窗口跨越 epoch 打开时间时返回 null，不能制造零。

在真正原生 Service/Route/Consumer 写入的 beforeSend 阶段关闭旧 assignment epoch；写入响应不确定时保持 blocked，直到可信证明完成。缓存 catalog 只提供查找提示：每个 collector batch 还须向 BFF 做 fresh DB active/blocked/epoch 核验，不能拿 15 秒缓存绕过刚完成的迁移或撤权。

## Token 和真实监听器/网络边界

拟定错误码为 `METRICS_TOKEN_INVALID` 401、`METRICS_TOKEN_SCOPE_DENIED` 403、`METRICS_EXTENSION_UNAVAILABLE` 409、`METRICS_RESPONSE_TOO_LARGE` 502。歧义通过 quality/unassigned 表示，不返回另一范围的原始值。

真实容器验收必须从 Nginx 公网入口、console main HTTP、Prometheus 容器、collector 容器和 API 内部 listener 分别发请求，记录 status/服务身份/固定路径，不打印 token：

- main/public 不存在 scrape/catalog/ingest 的系统身份 fallback；匿名、普通 cookie、管理员 JWT 均不能代替专用 token。
- 四种 purpose/audience 的完整互换矩阵、错 cluster、旧 generation、错误 token、重复 Authorization/编码 path、非允许 method/任意 URL 路径被拒绝且零 Kong 管理请求。
- token 轮换后旧 token 失效，重启/缓存/文件挂载不能复活旧 generation；一个 cluster 的 token 不能访问第二真实 cluster。
- Prometheus 与 collector 不加入 Admin/storage 网络，直接 `:8001` 访问失败；专用内部 token 不能在公网 BFF 上转换成 native 写权限。
- token file 的宿主目录、只读挂载和真实运行 UID 权限正确；git/docker build context/artifact/log/UI 泄密扫描按实际秘密值检测，不输出秘密内容。

Kong `/metrics` 适配器以实际版本/插件能力探测为前提，版本不符或 exporter 未安装时停止；不能为了它开放任意 plugin Admin 扩展。

## Collector 白名单和 Consumer 通道

原生 http-log serializer 会发送完整请求/响应信息，入口必须在有界 parsing 后立即生成最小统计对象，仅提取验证过的 native UUIDs、status 100–599、started_at 毫秒、request/kong/proxy 毫秒耗时、request/response bytes。禁止保存原始 JSON、请求/响应 headers、query/body、cookie、Authorization、证书、API Key 或完整 URL。

事件整个区间 `[started_at, started_at+requestLatency]` 必须落入同一已核验归属区间。覆盖请求在迁移前开始、迁移后完成；旧事件排队到新工作区后送达；同工作区标签 epoch 变化；刚过期/blocked 目录等情形。未知/歧义/过期身份只允许安全诊断计数，不赋给当前工作区或伪造匿名 Consumer。Collector 请求建议限制 2 MiB、最多 1,000 events；目录遍历建议 100 页/10,000 对象/32 MiB，最终限值以 Root 契约为准。

独立测试须在字段的每一种位置放入唯一 canary（header/query/body/URL userinfo、嵌套 config、数组、原型属性、验证错误消息），验证内存 DTO、Redis/PG/Loki、stdout、异常/审计和 artifacts 均没有原始内容。处理 malformed/超大/batch payload 时也禁止输出原始内容。HTTP 请求成功只代表采集已接受，不能伪造 Prometheus 已出现统计样本。

collector/catalog/scrape 的凭证和授权独立。http-log URL userinfo 隐藏凭证必须保持编辑语义：无关字段修改不能用已脱敏 URL 覆盖原 token，host/path 改变不能把原 token 带给新目标，只有明确授权重新配置/轮换才改变凭证。http-log 1.5 的外部 TLS verify=false 限制必须显式说明；不能宣称该插件验证外部证书。

Consumer TopN/Service 对比时标注实际通道，不把 service 请求数当作 consumer 请求数。Kong 1.5 serializer 若不能提供经源代码/实测证明的唯一事件 ID，不能把 IDs/time/status/bytes 的哈希当作唯一键：两次合法且相同的请求可能被错误折叠。测试必须保留这种重复合法事件，并明确至少一次投递/重试可能影响日志计数的语义；不能虚称精确一次统计。真实 Prometheus counter reset/baseline 不受这种日志去重推测影响。log 投递失败、时钟偏差、抽样/丢失、匿名 Consumer、metric availability 和 unavailable/partial 格式须有可验证契约。

## 证据门禁

纯 helper/真实 authorization unit、provider response-budget tests、真实第二集群 listener/ACL/token tests、真实 exporter 流量与 Prometheus HTTP API 同窗比对、完整 UI 下钻分别归档。200/401/404/500、counter reset 与 latency 分位数必须来自明确的测试流量。mock、缺失序列、端口可连接均不能作为流量/隔离/数值正确的实测证明。
