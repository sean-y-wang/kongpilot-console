# Kong OSS 1.5.x 兼容性契约

本文锁定 Kong OSS 1.5.x。当前真实响应基线是 **Kong OSS 1.5.1**，由 `deploy/scripts/capture-kong-fixtures.mjs` 从 Docker 中的 Kong Admin API 录制。`tests/fixtures/kong-1.5.1/manifest.json` 记录 54 个响应的请求路径、文件名、来源与录制时间；根响应中的连接密码等敏感值已脱敏。

`tests/unit/fixture-contract.test.ts` 是离线响应契约及适配层回归测试。它读取真实录制文件，验证字段、插件清单、路径限制及 schema 递归。它没有发起网络请求，不能代替真实 Kong CRUD、凭证登录、Target 历史、跨节点传播、分页第二页、decK diff/sync 或 E2E 验证。mock server 中的分页与故障响应为合成数据，必须在测试证据中单独标注。

## 版本与路径

启动探测按集群执行，先 `GET /` 读取版本和可选的根响应 `endpoints`，再获取 `/plugins/enabled` 与白名单允许的实体 schema。根响应没有端点清单时保留未探测状态，不扩大请求白名单。探测到非 `1.5.x` 或尚未完成版本探测时，配置写入关闭。版本号不是全部能力的替代品：发行镜像、额外插件、启用配置和各实体 schema 都会影响可用能力。

| 契约 | Kong 1.5.1 的实际行为 | 控制台处理 |
| --- | --- | --- |
| 根响应 | 有 `version`，没有 `endpoints` | 从 `/` 获取版本；缺少 `endpoints` 不算协议错误 |
| 历史端点录制 | 历史基线录制中 `/endpoints` 返回 `{ data: string[] }` | 此路径不在产品白名单内，当前启动探测与业务均不调用；历史录制不能授权新路径 |
| 旧插件 schema | `GET /plugins/schema/{name}` 返回 **config 内部的 fields** | 表单按 config schema 渲染，提交时再包入插件的 `config` |
| 新插件 schema 别名 | `/schemas/plugins/{name}` 在 1.5.1 已存在，旧路径在源码中标为 deprecated | 按本产品约束继续禁止调用新路径；不要误记为“2.x 才出现” |
| 实体 schema | `GET /schemas/{entity}` 的录制响应以 `fields` 为根 | 解析 Lua schema 的单字段对象数组，不能当作标准 JSON Schema |
| 插件 enabled 清单 | 表示服务器加载的插件，不表示全部已有实例 | 插件市场以真实清单为准；实例数量必须独立查询 |
| metrics | `/metrics` 来自 Prometheus 插件 Admin 路由 | 需显式启用监控路径；端点发现不自动扩张写入白名单 |

发现的 `/config`、OAuth token、session、插件专用缓存等路径也不自动获准代理。BFF 只使用版本适配层显式允许的路径、方法和查询参数，禁止任意 Admin API passthrough。所有业务请求携带受权限校验的 `clusterId`，不接受浏览器提供的 Admin URL。

来源：[Kong 1.5.1 根路由与 schema 路由](https://github.com/Kong/kong/blob/1.5.1/kong/api/routes/kong.lua)、[插件旧 schema 路由](https://github.com/Kong/kong/blob/1.5.1/kong/api/routes/plugins.lua)。

## 字段与原生能力边界

| 对象 | 需要特别处理的 1.5.1 边界 |
| --- | --- |
| Service | 没有 `tls_verify`、`tls_verify_depth`、`ca_certificates`。仅发送实际 schema 允许的字段；`client_certificate` 为证书引用 |
| Route | `path_handling` 支持 `v0/v1`，真实默认值为 `v1`。没有表达式路由的 `expression/priority` 字段；保留 `regex_priority` |
| Route 协议 | HTTP/HTTPS、TCP/TLS、GRPC/GRPCS 为互斥协议组；sources/destinations 是 `set` of `record`，不能漏掉递归校验 |
| Plugin | `enabled` 是合法布尔字段。service/route/consumer 可组合绑定，不能把插件范围误建模为只允许单选的四个枚举 |
| Certificate | 核心 schema 为 cert/key/tags 等字段；SNI 是单独实体。Admin 证书路由支持 SNI 关联操作，不代表 `snis` 是核心 schema 字段，适配时需拆成受控关系写入 |
| Upstream | 支持 round-robin、consistent-hashing、least-connections；active/passive 全套健康检查来自嵌套 record schema。默认探测 interval 为 0，不能把默认配置显示为已启用主动健康检查 |
| Target | 权重修改使用 POST 新 Target 历史；不是普通 PATCH 实体。weight=0 是退出负载均衡，不是通用 enabled 字段 |

除了 Plugins，核心 Services、Routes、Consumers、Upstreams、Certificates、CA、SNIs 没有通用 `enabled` 字段。Consumer 凭证也不能假定有 `enabled=false`。启停凭证需采用归档后移除、轮换或经验证的插件策略。

Workspaces、控制台用户与 RBAC、Vitals、Event Hooks、通知、门户、工单、快照、治理全部是控制台功能。Kong OSS 1.5 不提供本产品所需的这些企业接口；禁止发送 `/workspaces`、`/rbac`、`/vitals`、`/vaults`、`/keys`、`/key-sets`、`/event-hooks`、`/clustering` 或表达式路由配置。

schema 响应不包含所有 Lua 自定义校验函数及顶层条件规则；部分嵌套 `entity_checks` 会被保留。控制台 schema 校验负责拒绝未知字段、辅助表单和显示校验提示，Kong 仍是字段取值与组合规则的权威。嵌套 array、set、record、map 均需要递归；foreign 只接受 `{ id }` 引用。不要以“通过本地字段预检”代替完整 Kong 校验。

来源：[Services](https://github.com/Kong/kong/blob/1.5.1/kong/db/schema/entities/services.lua)、[Routes](https://github.com/Kong/kong/blob/1.5.1/kong/db/schema/entities/routes.lua)、[Upstreams](https://github.com/Kong/kong/blob/1.5.1/kong/db/schema/entities/upstreams.lua)、[Plugins](https://github.com/Kong/kong/blob/1.5.1/kong/db/schema/entities/plugins.lua)。

## 标签编码、隔离与分页

1.5.1 的标签字符只允许英数字及 `. - _ ~`。真实 schema 中的 Lua pattern 是 `^[%w%.%-%_~]+$`，因此 `workspace:pay`、`team:pay` 不能原样提交。

控制台展示逻辑标签，版本适配层写入合法物理标签：

- `workspace:pay` → `kos-ws-pay`；工作区编码由 `workspaceTag()` 校验。
- `team:pay` 等含不合法字符的标签 → `kos-tag-` 加 UTF-8 base64url；`decodeTag()` 恢复展示值。
- 用户输入以 `kos-ws-` 或 `kos-tag-` 开头的普通标签也编码，避免与控制台保留前缀碰撞。逻辑标签与物理标签不可混用，导入和迁移必须走同一编码器。
- 历史实体可能已存在保留前缀标签；接管时需要显式检查，不能仅凭字符串前缀认定归属。空标签与无工作区标签的默认工作区只是一种控制台归属约定。

| Kong 查询 | 含义 |
| --- | --- |
| `tags=a,b` | 必须同时具有 a 和 b，即 AND |
| `tags=a/b` | 具有任意一个，即 OR |
| `size` | 请求页大小，最大 1000 |
| `offset` | 服务端产生的续页标记，不当作通用页码 |
| 响应 `next` | 下一页路径或 null；真实空列表只有 `{ data: [], next: null }`，没有 total/offset 保证 |

不能把 `(工作区 W) AND (业务标签 A OR B)` 塞成一个未经验证的 tags 表达式。BFF 需组合原生过滤、实体权限检查与受限续页读取；预算耗尽时返回续游标，不能无限扫描。授权必须在后端执行，不能把未授权列表发给前端再隐藏。

浏览器只接收控制台签名游标，不得跟随原始 `next`。BFF 取出 offset，再向已登记的 Kong 地址发起白名单请求。游标绑定集群、资源路径、查询条件和调用者；权限变更后仍重新授权。前端维护已访问页的游标缓存，提供上一页/下一页，不承诺任意跳页或准确总数。

通用 `search/sort/page` 不是 Kong 1.5 列表参数。跨页全文搜索和全局排序需要单独的控制台投影索引，并显示同步时效；当前页排序不能冒充全局排序。列表不得全量抓取后分页。对象图归档、快照、导出与治理是显式批处理任务，也必须按游标分页流式处理、限制内存和请求速率，不能发送无界单次抓取。

标签工作区属于软隔离，Admin API 可绕过；必须同时封闭网络访问与 BFF 权限。跨工作区引用、共享证书或全局插件需专门授权，tags 本身不能保证它们隔离。

来源：[标签类型](https://github.com/Kong/kong/blob/1.5.1/kong/db/schema/typedefs.lua#L348)、[tags 查询运算](https://github.com/Kong/kong/blob/1.5.1/kong/api/endpoints.lua#L132)。

## 真实插件清单

本次 1.5.1 镜像的 `/plugins/enabled` 录制 **34 个**插件。类别用于浏览；能否绑定 Consumer、协议及具体配置仍以插件能力为准。

| 类别 | 录制可用插件 |
| --- | --- |
| 认证与会话 | basic-auth、hmac-auth、jwt、key-auth、ldap-auth、oauth2、session |
| 安全与访问控制 | acl、bot-detection、cors、ip-restriction |
| 流控与终止 | rate-limiting、response-ratelimiting、request-size-limiting、request-termination |
| 转换与关联 | request-transformer、response-transformer、correlation-id |
| 日志 | file-log、http-log、tcp-log、udp-log、syslog、loggly |
| 指标与追踪 | prometheus、zipkin、datadog、statsd |
| 缓存 | proxy-cache |
| Serverless 与集成 | aws-lambda、azure-functions、pre-function、post-function、kubernetes-sidecar-injector |

`grpc-gateway`、`degraphql`、`kafka-log` 不在此镜像的实际清单中，不能标为 1.5.1 默认插件或伪造 schema。部署增加自定义插件后，重新探测实际清单并验证兼容性；全部内置插件验收必须覆盖这 34 个 schema，不能只覆盖任务示例列表。新版文档中的参数不得复制进老版本表单。

旧 schema 路径对本次 Prometheus 插件返回 `{ fields: [] }`，因此空配置是合法的；`consumer_metrics/latency_metrics/bandwidth_metrics` 等现代开关在此基线中不能提交。

来源：[Kong 1.5.1 bundled 清单](https://github.com/Kong/kong/blob/1.5.1/kong/constants.lua)及仓库真实录制。

## 监控数据通道

Kong 1.5.1 依赖的历史 Prometheus 插件提供 Service/Route 状态码、延迟、带宽及节点进程指标，历史 exporter 不提供 Consumer、tags、workspace 标签。工作区下钻由控制台关联实体标签与 Service/Route label；Service label 使用 name 或 host，Route label 使用 name 或 ID，因此应避免无名 Service 的 host 冲突，并保存实体改名、迁移后的历史映射。Consumer TopN 需要 `http-log/file-log` 等日志数据通道，数据源未接入时显示不可用，不制造 Prometheus 指标。

Prometheus 经 BFF 内部 exporter 获取各受管 Kong 节点的 `/metrics`，Kong 8001 仍仅对控制台后端开放。为集群收集多个节点时必须显式登记每个节点，不能把负载均衡后的单 Admin URL 当作所有节点。BFF exporter 返回成功只证明 exporter 可达；代理抓取失败应体现为节点采集失败，不能由 Prometheus `up` 误判 Kong 正常。

节点 `/status`、健康检查和 metrics 以响应所在节点为准。配置写入、凭证吊销与手动健康置位存在 DB 模式传播延迟，操作结果需区分“Admin 接受”“生效核验中”“受管节点已验证”。不可达节点不能算验证通过。

来源：[Kong 1.5.1 Prometheus 依赖](https://github.com/Kong/kong/blob/1.5.1/kong-1.5.1-0.rockspec#L44)、[历史 exporter](https://github.com/Kong/kong-plugin-prometheus/blob/0.6.0/kong/plugins/prometheus/exporter.lua)、[插件 metrics 路由](https://github.com/Kong/kong-plugin-prometheus/blob/0.6.0/kong/plugins/prometheus/api.lua)。实际镜像插件版本和输出仍需 M5 真实录制确认。

## M1 对象图、回收与恢复契约

Kong 不提供本产品回收站。用户的“软删除”由控制台实现为 **先完整加密归档、再从网关活动配置移除**；未经成功归档不得执行 Admin DELETE。仅在控制台库写 tombstone 而保留活动 Route 会继续转发流量，不能声称已经删除。

图采集应区分 `affected`（选定对象及明确授权要移除的子对象）和 `referenced`（恢复所需共享父对象）。保存原 ID、类型、集群、工作区、依赖边、版本、凭证恢复能力及对象指纹。不能因 Service 引用了 Upstream 或证书就顺带删除这些共享对象，也不能删除 Plugin 所绑定的共享 Consumer。

| 选定对象 | 必须核对的对象图 |
| --- | --- |
| Service | 本体、关联 Routes、绑定 Service 或这些 Routes 的 Plugins、client_certificate 引用、匹配的受管 Upstream 引用 |
| Route | 本体、所属 Service 的引用与指纹、绑定 Route 的 Plugins；有 Consumer 绑定的 Plugin 同时保存 Consumer 引用 |
| Consumer | 本体、绑定 Consumer 的 Plugins、key-auth/basic-auth/jwt/oauth2/hmac-auth/acls 的各页凭证；Plugin 的 Service/Route 引用 |
| Upstream | 本体、有效 Targets、必要的 Target 历史说明、引用它的 Services 影响提示；不自动删除这些 Services |
| Certificate / SNI | 本体、SNI 关联、Service.client_certificate 入站引用；共享引用存在时拒绝或要求显式批准受影响变更 |
| Plugin / 凭证 | 本体及所有绑定父对象引用；敏感字段加密归档并按权限脱敏展示 |

绑定 Plugin 及入站 client_certificate 等关系在限定查询参数下未必有可用的直接过滤端点。图采集需服务端游标流式扫描允许的集合并过滤，设置完整性预算；扫描不完整、依赖不可读或引用漂移时，拒绝删除而非生成部分备份。图内每个对象均需授权，跨区共享引用不能通过级联流程绕过权限。

Kong API 没有跨多个实体的事务。归档先在控制台 PostgreSQL 提交，随后按反向依赖移除；每步持久化状态与审计，处理部分失败、重复请求、未知写入结果。读取对象指纹与执行前再次核对避免覆盖外部变更，Redis 锁只协调受管控制台写入，不代表原生 Kong 支持 CAS。

恢复使用拓扑排序：证书/CA/SNI 引用 → Upstream/Targets → Service → Route；Consumer 在绑定它的 Plugins 与凭证之前。全部 Plugin 父对象存在后才恢复 Plugin。用户示例中的 `Plugins → Consumer` 对 Consumer 绑定插件不可用。先预检 ID/名称冲突与共享引用，冲突时停止并展示原因，不能自动覆盖现存对象。

可重建实体尽量保留原 ID。**单 Target 是例外**：1.5.1 的 DELETE 追加新的 `weight=0` 记录，旧 ID 通常仍存在；恢复需 POST 新的有效权重历史并记录 `original_id → effective_id`，否则会 ID 冲突或继续被较新的零权重记录覆盖。`/targets` 返回每个 host:port 最新且 weight>0 的有效项，`/targets/all` 返回包含覆盖项与零权重项的历史；不能把 history 的每一行都当作独立活动 Target 恢复。运行时健康置位不是可靠的配置快照内容，恢复后重新核验当前节点健康。

M3 实测补充：按地址调用通用嵌套 Target GET 会受全局 `endpoint_key` 选择影响，可能选到其他 Upstream 或历史记录后返回404，不能证明当前有效 ID。写前检查、归档和恢复统一分页读取所选 Upstream 的 `/targets` 有效集合，核验父 ID、地址、唯一性及当前 UUID；旧 UUID 仍可读取并不代表可修改或删除。此检查使用共享分页、记录和内存预算，集合不完整时停止变更。权重修改后回读新 UUID，不能回读地址。实现和回归位于 `effective-target.ts`、`effective-target.test.ts` 和 `m3-recycle-mutation-scope.test.ts`。

来源：[Targets 历史与删除语义](https://github.com/Kong/kong/blob/1.5.1/kong/db/dao/targets.lua#L105)、[健康状态 API](https://github.com/Kong/kong/blob/1.5.1/kong/api/routes/upstreams.lua)。这些行为来自固定版本源码；当前 54 个 GET 基线尚未包含真实 Target 删除恢复证据。

## 凭证与导出的恢复限制

| 凭证 | 归档与恢复要求 |
| --- | --- |
| Basic-auth | Admin 读到 password hash，重新 POST 会再次 hash。只有控制台创建/轮换时加密保存原密码，或操作者补录原密码，才能保持原登录密码；历史 hash 无法逆推出原密码 |
| Key-auth / HMAC / JWT | 需保存确切 key/secret、算法、公钥和父 Consumer。不得用默认生成值替换原密钥再宣称无损恢复；具备 TTL 时不得因恢复延长原有效期 |
| OAuth2 | `/consumers/{id}/oauth2` 是 client credentials。client_id/client_secret/redirect_uris 的配置恢复与已签发 access/refresh token 会话恢复分开 |
| ACL | 凭证图包含 groups 与 tags，先重建 Consumer 再重建关联 |

Basic-auth DAO 明确 `db_export=false`，不是遗漏字段：hash 不能直接导入恢复。配置归档需标注 `restorable/requires-secret-input/requires-rotation`，存在不可无损恢复凭证时，删除预检必须告知并要求补齐材料或显式接受轮换；未补齐不得承诺原凭证恢复可用。原密码只能存加密秘密存储，不能进入审计 before/after、普通日志或脱敏导出。

OAuth2 授权码本身没有生成 Admin API；token/session 路径即使在端点清单中也不自动获得本产品白名单授权。恢复 OAuth client 后验证能够重新申请有效令牌，不承诺历史授权码、过期令牌或会话复活。

decK `_format_version: "1.1"` 只是格式标记，不能证明每个凭证、CA 或对象图都被任意 decK 1.x 版本接受。M8 必须固定确切 decK 版本，使用真实导出执行 diff/sync 并验证恢复凭证。普通脱敏导出用于 review，含秘密的受控加密归档用于恢复；两种产物需显式标注。完整性不能通过输出 `[REDACTED]` 后声称可直接 sync 达成。

来源：[Basic-auth 不可直接导出与写时哈希](https://github.com/Kong/kong/blob/1.5.1/kong/plugins/basic-auth/daos.lua)、[OAuth2 凭证、授权码与 token](https://github.com/Kong/kong/blob/1.5.1/kong/plugins/oauth2/daos.lua)。凭证创建/登录/轮换/删除恢复与 TTL 证据须在 M1/M6/M8 补录，当前 fixture 契约测试没有覆盖这些验收。

## 治理与后续验收

Service.host 可以是合法 DNS 主机，没有同名 Upstream 并不自动构成无效引用。无 SNI 的证书可能由 Service.client_certificate 引用；巡检必须先检查引用图，不能直接报孤儿。1.5.1 不存在的 TLS 配置字段不能变成“必须配置”的治理规则。

后续真实验收至少补充：非空实体与第二页游标、tags 的 AND/OR、6 类 Consumer 凭证 schema 与有效认证、5 类对象完整删除恢复、Target 权重历史、共享引用冲突、审批模式拒绝直接写入、跨集群/工作区 IDOR、真实指标 label 和 decK diff/sync。每份证据标明来自真实 Kong、真实 BFF 请求、fixture 离线测试或合成故障测试，避免以 mock 通过替代现场验证。
