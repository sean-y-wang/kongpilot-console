# M0–M8 生产 UI 补充验收：八类实体与 34 个插件

本文件是源码准备清单，尚未执行，不表示生产验收已经通过。先完成现有 M8 手工 12 步，再由 Root 交接独立生产验收窗口。M9–M11 不在本批范围。历史 HTTP 证据与本批 UI 证据分别列示，API 创建不能计为 UI 创建。

## 执行范围和交接

新增入口为 `tests/security/production-ui-lifecycle.mjs`，命令为：

```sh
PRODUCTION_UI_EXCLUSIVE_READY=true node --import tsx tests/security/production-ui-lifecycle.mjs
```

源码阶段不能执行该命令。实际运行前，Security 准备新的 HTTPS 控制台来源、隔离的 Kong OSS 1.5.1 验收集群、全新非默认工作区、平台管理员当前会话和合成 PEM 材料。只复用本次生产验收的受信会话，不复用 M2/M7/M8 账号、工作区或私有材料，不登录或刷新。入口只接受：

- `/tmp/kongos-production-ui-runtime-secrets.json`：0600、当前 UID、非符号链接、32 MiB 上限。
- `version=1`、`milestone=M0-M8-production-ui`、`phase=ready`；没有已有 UI journal/history 或未知请求。
- `uiHandoff.version=1/phase=ready/exclusiveRuntimeOwner=production-ui`；精确 HTTPS `origin`、当前 CID/WID、`executionMode=direct`、`isolatedAcceptanceCluster=true`。
- `uiHandoff.securityReportPath=artifacts/production/production-ui-handoff.json` 和原字节 SHA256；实际报告 `allPassed=true/failed=0/unknownWrites=0`、同 testTag/origin/CID/WID，且 `m8ClosureComplete/productionHttpsVerified/freshScopeVerified=true`。
- testTag 为 `prod-ui-xxxxxxxx`，`approvedActions` 必须与纯 fixture 模块的完整 178 项数组一致。
- `session` 含本次原 actor/SID、cookie/CSRF、真实 `expiresAt`、`currentSessionVerified/signedAccessVerified/currentUserProven=true` 和平台管理员能力；首次入口要求剩余 840–900 秒，同安全报告的 actor/SID/真实 expiresAt 完全一致。每个写包再次检查过期时间；不伪造延长时间、不通过不存在的 TTL 环境变量绕过 15 分钟限制。
- `pem.certificate/privateKey/caCertificate` 仅私有短期材料；`requests/secrets` 为本次 Security 原流水和累计扫描材料。

交接还需真实 `clusterLabel/workspaceName`。来源、Cookie 与秘密不写入 URL、查询参数、公开报告或截图。实际浏览器保持 TLS 验证，禁止 `ignoreHTTPSErrors`。源码准备不读取上述引用或运行 HTTP、浏览器、Docker、登录、Native。

## 操作数及顺序

基础覆盖 UI 意图共 **169** 次：辅助 carrier Service 创建 1 次、八实体各创建/编辑/归档/恢复 32 次、34 插件各创建/编辑/归档/恢复 136 次。carrier 最后再经名称二次确认移入回收站，作为 **独立清理意图 1 次**；不混入实体/插件覆盖数。另有下述四级绑定和开关代表 **8 次**，完整合同为 **178 = 169 基础覆盖 + 8 代表 + 1 carrier 清理**。其他对象由 Security 后续固定清理合同处理，本脚本禁止永久删除。

所有创建/编辑均点击真实表单“保存配置”；归档/恢复点击当前 UUID 行按钮并正确填写“确认名称”。先证明错误名称不能提交，再正确确认。前端原 UUID 幂等键、完整原正文、Headers、actor/SID、CID/WID，在 `BrowserContext.route` 的 `continue` 之前原子写入 0600 journal 并 fsync。任何未知、错范围、变身份、重复包、未计划写或持久化失败立即停止全部后续非 GET；不能自动续跑或换键。下面的独立续行仅支持主动停止的完整成功前缀，不支持上述未知或失败状态。

## 15 分钟会话与独立未执行尾部

178 个远端写及约 177 张截图没有固定 `sleep/waitForTimeout`；每一步只等待真实控件、loading 消失、原 ACK、原键终态回执和当前回读。耗时取决于 Kong 配置传播、对象图、表单控件和机器性能；不能保证一次 900 秒会话内完成。首次执行临近交接时由 Security 获得真实新签名 access，浏览器没有登录/刷新预算。

每个完整 DOM 意图（包括回读、绑定记录和截图）结束后，下一意图前检查真实 expiresAt。余时少于 120 秒时，仅当全部前缀 `succeeded`、原 receipt 已核证、没有 armed/inFlight/unknown、只读授权请求也已完成，封存 `paused-safe-prefix` checkpoint；不发送下一意图。异常停止或过期中的请求不能套用该 checkpoint。

Security 独占维护窗口执行一次标准同 actor/SID 的正常 refresh，并 GET/me/签名/当前权限核证。它保留所有既有 UI 请求、正文、键、旧 Headers/Cookie、检查和截图；只更新受信引用中的当前会话。新的安全报告固定为 `artifacts/production/ui-original-session-maintenance-N.json`，N 为严格下一代序号（1–32）。报告须实际 allPassed/failed0/unknown0/authWrites1/business0/login0/native0，同 origin/CID/WID/actor/SID、当前真实 expiresAt，绑定原私有 UI journal SHA。这里只设计交接合同，没有执行 Auth。

独立入口（源码阶段禁止执行）：

```bash
PRODUCTION_UI_UNUSED_TAIL_READY=true node --import tsx tests/security/continue-production-ui-unused-tail.mjs
```

引用的 `uiUnusedTailHandoff` 必须为 version1/ready/exclusiveRuntimeOwner=production-ui，包含精确 generation、当前 actor/SID/origin/CID/WID/testTag、nextIndex、原 journal/报告字节 SHA、仅剩余 `approvedActions=完整178数组.slice(nextIndex)`，以及固定维护报告 path/SHA。当前重新验证过的同 SID access 剩余至少 300 秒、最多 900 秒。原 Security 请求前缀 count/SHA 必须保持；存在任意 prepared/unknown 则拒绝。

在恢复会话或启动浏览器之前，将完整旧 journal/完整旧报告 wx+fsync 保存到 `/tmp/kongos-production-ui-unused-tail-N-history.json`，新一次性 marker 绑定封存 SHA。没有显式尾入口、同代重入、改旧正文、外范围/外身份、缺维护证明、旧失败报告或非零未知都不能继续。旧成功动作连 DOM callback 都跳过，不重发、不重新截图、不重放启停。未用配置的 RAM 工厂值保存在原私有 journal，不能续行时重新生成秘密或改正文。累计业务仍 178；Frontend login/refresh 保持 0，Security 正常维护 Auth 独立计数。

原报告及 PNG 保持字节，续行只写新 `artifacts/production/ui-lifecycle-unused-tail-N.json`，继承条目明确列出 priorReports SHA 和历史封存。最终纯 UI 通过后仍需 Security Native 回读、全写审计、秘密扫描及独立固定清理才能宣称生产补验闭环。

自动 `POST authorization/entity-capabilities` 单独记为只读授权审查，不计 CRUD。只允许当前 CID/WID、精确 `{entities:[{type,id}]}`、八类白名单和每包 1–50 个 UUID，最多 1024 包；原键和正文仍需提前留证。Auth、除代表的两个精确开关外的插件 toggle、审批执行、健康置位、Native、批量删除、purge 等未列意图全部拒绝。

### 八类实体

先创建 carrier；再按下表创建与编辑，反序逐个归档，再按原顺序恢复。每次归档验证原 UUID 已不可读取及回收站根对象/节点归属；每次恢复验证受影响节点的原 UUID，保留共享引用。前后关系不能仅靠 Toast 判定。

| 实体 | 创建及绑定 | 编辑内容 | UI 证据 |
| --- | --- | --- | --- |
| Certificates | 合成 PEM 证书与匹配私钥，owner/test 标签 | 标签修改，留空保持私钥 | Configuration、证书元数据、归档对象图、原 ID 恢复 |
| CA Certificates | 独立 CA PEM；不虚构 1.5 Service CA/TLS 校验字段 | 标签修改 | Configuration、归档、原 ID 恢复 |
| Upstreams | 唯一名称，round-robin | consistent-hashing 和标签 | Configuration；Targets & Health 是独立子功能，不能假称本批已执行 Target 写入 |
| Services | 专供插件扫测，host 指向新 Upstream，client_certificate 指向新证书；始终没有 Route | read_timeout=61001 和标签 | Configuration、真实引用按钮、Routes 空关系、原 ID 恢复 |
| Consumers | 唯一 username/custom_id | custom_id 和标签 | Configuration；认证凭证属于额外子功能，本批不能虚报六类凭证 UI 写入 |
| SNIs | 唯一 `.invalid` 主机，选择新 Certificates UUID | 标签修改 | Configuration 的真实 certificate 绑定和原 ID 恢复 |
| Routes | 唯一 host/path、HTTPS，真实选择 carrier Service | preserve_host=true 和标签 | Configuration、Service 关联、原 ID 恢复 |
| Plugins | disabled rate-limiting，真实选择 carrier/Route/Consumer 三重绑定 | minute=11，停用，标签 | Configuration 三重绑定、原 ID 恢复；与下表独立实例分别统计 |

Kong 1.5.1 Service 不支持 `tls_verify/tls_verify_depth/ca_certificates`；使用实际 schema 的 `client_certificate`。证书/SNI 的 TLS 含义按真实证书和绑定核验，不添加不存在的表单字段。

### 实际安装的 34 个 OSS 插件

配置值只复用 `live-m2.mjs` 内的纯 `configurations()` 工厂，源码测试核对二者完全一致。禁止导入或执行该历史脚本，也不加载历史 `.env`、账号、报告或 runtime。各秘密由本次 RAM 随机分配器生成。

33 个插件绑定新建且无 Route 的隔离 Service；`kubernetes-sidecar-injector` 实际 schema 禁止 Service/Route/Consumer，只使用全局绑定。**全部实例在创建、编辑、恢复和最终回读中保持 enabled=false**，全局实例不能启用，外部日志、LDAP、脚本、云函数没有执行测试。已有同名/同绑定冲突会停止，不会删除别人的实例。

| 插件 | 真实动态控件 / 编辑检查 |
| --- | --- |
| correlation-id | header_name 文本 |
| pre-function | functions 数组逐项 textarea；仍停用 |
| cors | origins 数组、max_age 数字、credentials 开关 |
| ldap-auth | 主机/端口/base_dn/attribute，timeout 数字 |
| loggly | 新 key 仅输入不回显，tags 数组 |
| hmac-auth | clock_skew 数字 |
| zipkin | http_endpoint，sample_ratio 数字 |
| request-size-limiting | allowed_payload_size 数字 |
| azure-functions | appname/functionname/apikey，timeout |
| request-transformer | 嵌套 remove/rename/replace/add/append record，add.headers 数组 |
| oauth2 | provision_key 秘密、enable_client_credentials/enable_password_grant、token_expiration |
| response-transformer | 嵌套 record，add.headers 数组 |
| ip-restriction | whitelist 集合 |
| statsd | metrics **array of record**：name/stat_type/sample_rate；prefix |
| jwt | run_on_preflight、secret_is_base64 |
| proxy-cache | strategy 枚举、memory record、cache_ttl |
| basic-auth | hide_credentials |
| key-auth | hide_credentials |
| http-log | http_endpoint、timeout |
| datadog | host/port、prefix |
| tcp-log | host/port、timeout |
| rate-limiting | minute、policy 枚举 |
| post-function | functions 数组逐项 textarea；仍停用 |
| prometheus | 无配置变化的 `{}`；真实编辑 tags，不能声称更改了不存在的配置字段 |
| acl | whitelist、hide_groups_header |
| kubernetes-sidecar-injector | 全局且停用，imagePullPolicy 枚举 |
| syslog | log_level 枚举 |
| file-log | path、reopen；停用，不写文件 |
| udp-log | host/port、timeout |
| response-ratelimiting | limits **map → record → minute**，policy |
| aws-lambda | aws_key/aws_secret 仅 RAM、aws_region/function_name/timeout |
| session | secret 仅 RAM、cookie_name |
| bot-detection | blacklist 数组 |
| request-termination | status_code 数字、message |

动态控件按当前 BFF `form_schema` 和实际 `schema-field-<path>` 操作：枚举实际 option、boolean Switch、数字 InputNumber、record Collapse、map 增删键值行、array-of-record 增删记录行。只使用 DOM `fill/click/press`，不调用 `setFieldsValue`、浏览器内部 React 实例或隐藏 API 写入。表单预计正文使用真实产品 `prepareFormValues/formPayload/omitUnchangedHiddenMaps` 计算并对原包做精确比较。

每个插件进入市场“配置 名称”，创建后查看 Configuration，再从真实详情“编辑”并修改配置/标签，然后通过真实名称确认归档和原 ID 恢复，恢复后再次确认 enabled=false。33 个实例必须回读同 Service UUID 且没有 Route/Consumer；全局插件必须没有三类绑定。Ant Design 两字按钮按实际空格匹配（编 辑/删 除/恢 复），搜索用实际 aria-label，不把 Input.Search 假定为 textbox。

## 四级绑定与开关的八个明确代表意图

使用同名 rate-limiting 验证四种独立层级：Service-only 是上述 34 扫测的已有原 ID；额外新建 Route-only、Consumer-only、global 三个实例（3 次），全部配置 `policy=local` 且保持 disabled，互不伪造组合绑定。之后只对没有 Route 的隔离 Service 上已有 rate-limiting 原 ID 执行真实开关 enable→disable（2 次），每次点击前 protected GET 重证同 Service 的 Routes 为空、同原 CID/WID，原 actor/SID/目标/键/正文留证。只允许这个精确原 ID 和局部本地插件，不能启用全局、Route、Consumer、日志、脚本或外发型实例。最后三个额外实例经名称二次确认移入回收站（3 次）。

这八项分别是 `bindings.route.create`、`bindings.consumer.create`、`bindings.global.create`、`bindings.service.enable`、`bindings.service.disable`、`bindings.route.archive`、`bindings.consumer.archive`、`bindings.global.archive`，在 carrier 最终归档之前执行。其他 34 插件的生命周期始终停用；所有恢复保持 disabled。此处开关是无路由的配置状态验收，不声称限流运行时行为已经测试。

## 证据与闭环

公开报告 `artifacts/production/ui-lifecycle.json` 按实体/插件记真实 DOM 路径、原请求 ID、幂等键、正文 SHA、原 mutation receipt ID、当前 scope 和操作数，不保存配置正文或 token。每个写响应只是 ACK，必须再 GET 当前用户原 `/mutations/by-key/<originalkey>?workspaceId=<originalWID>`，核对 actor/CID/WID/type/action/target、`succeeded/remote_started/remote_completed`，然后才推进下一个意图。

列表每页为服务器 20 条，只走真实下一页游标，最多 12 页；不全量拉取，不模拟跳页。截图按新 `artifacts/production/ui-*` 文件名 wx 保护，不覆盖历史 PNG。八实体每类四张（created/edited/archived-graph/restored），34 插件每个 created/edited/archived-graph/restored 四张，代表绑定和开关八张，另优先级移动端一张；必须等待实际数据及 loading 消失，禁止未关闭的秘密表单、credential reveal 或可见秘密。

私有日志为 `/tmp/kongos-production-ui-original-journal.json`；完整原 handoff 另 wx 封存在 `/tmp/kongos-production-ui-original-handoff.json`，保存字节数/SHA 和原 requests 前缀 SHA，不原地重置或删除。Secret scanner 由 Security 在本 UI 窗口交回后检查所有源码/报告/PNG和累计真实秘密；endpoint URL、对象 UUID、幂等 UUID 不误当秘密，config.key 和私钥应正确分类。

Security 后续用同原 actor/key/CID/WID核对真实 BFF/Native 配置、私钥/凭证保持、所有写审计和固定清理操作，给独立证据。UI 报告的 `pendingSecurityNativeComparison/pendingSecretScan` 不得被写成通过。Targets、六类 Consumer 凭证以及插件运行时行为只能引用已有准确 HTTP/专项证据，不能冒充这 178 次 UI 写入覆盖。若生产交付需要这几项额外 UI 操作，另制定固定独特意图后再执行。
