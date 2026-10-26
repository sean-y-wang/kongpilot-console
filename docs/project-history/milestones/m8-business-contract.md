# M8 配置快照、导入导出与 GitOps 业务合同

状态：**设计合同，仅文档**。M6 源码已冻结；本文件不添加产品代码、数据库迁移、CLI 发布或运行时能力。实施须等待 Root 按 M6→M7→M8 顺序放行。M8 的真实 Kong/decK 证据尚未产生，不能将本合同或离线格式验证列为端到端验收通过。

基线：[Kong 1.5 实际能力](../../reference/kong-1.5-compatibility.md)、[decK 固定版本调查](../../reference/deck-1.5-compatibility.md)、[M6 私有批准执行](../../architecture/security/m6-approved-execution-contract.md)。本文以当前源码的严格白名单为准：探测 `GET /` 的 version 和可选 root.endpoints，不新增 `GET /endpoints`，不调用新版插件 schema、企业工作区或全局凭证端点。

## 1. 交付边界与并行切分

| 文件/模块 | 实施职责 |
| --- | --- |
| `modules/config-jobs/**` | 不可变目标图、diff、确认/审批/执行、原始键回执、逐对象状态、故障恢复；固定业务 kind，禁止任意 method/path passthrough |
| `modules/snapshots/**` | 手动/定时捕获、加密存储、对比、保留期和基于精确 diff 的回滚；按页流式捕获，不复用回收站行作快照权限 |
| `modules/config-transfer/**` | 受限 YAML/JSON 解析、decK 1.1 serializer、导出 manifest、导入编译、秘密下载 |
| `modules/deck-adapter/**` | decK 1.1 固定协议适配、全局凭证列表转换、绑定已批准 diff 的短期会话；不能扩大 KongClient 白名单 |
| Storage | 新快照/对象/作业/逐对象回执 SQL、不可变 manifest 与秘密封装；现有 SQL000–009 **没有**配置快照表 |
| Root/私有执行所有者 | 当前授权、NativePolicy/PortalBoundary、精确批准能力的新版本与安装；普通业务不能自行构造批准上下文 |
| Front/Security/Devops | Diff/恢复能力/进度/原始键恢复页面；独立真实凭证与 decK 对照；受控 CLI runner、统一部署和故障注入 |

先冻结实际 serializer 与 manifest，再并行开发 capture/storage、编译/执行、UI、适配器及独立测试。业务路径已有明确入口：`EntityService.create/update/delete`、`create/update/deleteCredential`、`create/update/deleteTarget`；删除由现有 EntityService 进入 `RecycleService.archiveAndDelete`，恢复入口 `RecycleService.restore`。不直接调用 Kong.request 发原生写，也不外套同一个 physical mutation 锁。

## 2. 固定格式与完整对象集合

工具固定 **decK v1.1.0 (acdb161)**，当前只读可用二进制为 `/tmp/kongos-deck-cli/deck`。归档 SHA256 与 go-kong v0.11.0 来源见兼容性调查。再次本地检查的二进制 SHA256 为 `61394e30ebc92599fbccc9807e558cec018ab407d78e644c0bff5bcb0011554b`；YAML/JSON 的完整实体位置、Basic hash-looking 字符串语法、非法顶层 SNI/Target 和不支持的 OAuth hash_secret 共7项离线验证见 本地工具证据 (`artifacts/planning/M8-deck-local-verification.json`, not public)。这7项没有访问实际 Admin/Proxy，不能证明密码或证书真实可用。正式 runner 固定校验产物，不从运行时上传的工具或插件执行文件。设置 `DECK_ANALYTICS=off`，禁止 verbose=2、TLS skip verify 和企业 workspace flags；实际 CLI stderr/stdout 也按敏感内容处理。

YAML 固定 `_format_version: "1.1"`，保留 ID。部署 YAML 的格式结构如下，**包含 Targets 和 SNIs，但不新增 decK 拒绝的顶层 targets/snis**：

| 原生对象 | decK 1.1 文件位置 | 捕获来源 |
| --- | --- | --- |
| Service | `services[]` | `/services` 分页 |
| Route | `services[].routes[]`；无 Service 的合法 Route 在 `routes[]` | `/routes` 分页、真实 Service UUID |
| Consumer | `consumers[]` | `/consumers` 分页 |
| Plugin | `plugins[]`，使用明确 service/route/consumer UUID | `/plugins` 分页；组合绑定全部保留 |
| Upstream / 有效 Target | `upstreams[]` / `upstreams[].targets[]` | `/upstreams`、每父 `/targets` 分页 |
| Certificate / SNI | `certificates[]` / `certificates[].snis[]`，SNI 保留 id/name/tags | `/certificates`、`/snis` 分页，验证父证书 |
| CA Certificate | `ca_certificates[]` | `/ca_certificates` 分页 |
| Key-auth | `consumers[].keyauth_credentials[]` | `/consumers/:id/key-auth` 分页 |
| Basic-auth | `consumers[].basicauth_credentials[]` | `/consumers/:id/basic-auth` 分页及可信原密码存储 |
| JWT | `consumers[].jwt_secrets[]` | `/consumers/:id/jwt` 分页 |
| OAuth2 client | `consumers[].oauth2_credentials[]` | `/consumers/:id/oauth2` 分页 |
| HMAC | `consumers[].hmacauth_credentials[]` | `/consumers/:id/hmac-auth` 分页 |
| ACL | `consumers[].acls[]` | `/consumers/:id/acls` 分页 |

快照完整性 manifest 是独立加密/安全侧件，不能给 YAML 填入未知的控制台顶层字段。Workspaces、RBAC、Portal、metrics 历史归属和 workflow 元数据不是 Kong 实体，不能伪装成 decK workspace 或发送到 Kong。配置快照在 manifest 记录这些关联的存在/恢复限制；Native 配置导出不宣称已备份整个控制台 PostgreSQL。

### 实际 1.5 字段保留规则

所有对象先取已探测实体 schema；插件只用 `/plugins/schema/:name` 的旧 config schema。下面列出真实基线的重要字段，不将候选字段当成必然能力；schema 中没有的字段必须拒绝，而不是静默丢弃后称为无损导入。

| 对象 | 真实基线配置字段与特殊关系 |
| --- | --- |
| Service | name/retries/protocol/host/port/path/connect_timeout/write_timeout/read_timeout/tags/client_certificate；当前 1.5.1 不含 tls_verify/tls_verify_depth/ca_certificates |
| Route | name/protocols/methods/hosts/paths/headers/https_redirect_status_code/regex_priority/strip_path/path_handling/preserve_host/snis/sources/destinations/tags/service；保持 null 与空数组差异，不填 expression/priority |
| Plugin | name/route/service/consumer/config/run_on/protocols/enabled/tags；run_on 和协议限制来自实际旧插件 schema/版本规则，不能批量填 all；secret defaults 不进入导出 |
| Upstream | name/algorithm/hash_on/hash_fallback/header/cookie 配置/slots/healthchecks/tags/host_header；完整递归保留 active/passive 的真实字段 |
| Target | target/weight/tags；只导出有效集合，历史另入 manifest；不支持普通 PATCH |
| Certificate / CA / SNI | cert/key/tags；CA cert/tags；SNI name/certificate/tags；关系分解成显式受控 SNI 步骤，避免 certificate.snis replacement 隐式删除 |
| Consumer / 凭证 | username/custom_id/tags；六类 credential 的当前 schema、原 UUID/Consumer、key/password/secret/公钥、algorithm、client_id/client_secret/redirect_uris、group 等实际字段；当前1.5.1 OAuth schema没有hash_secret，不能提交 |

配置输出去掉 created_at/updated_at 等只读时间，保留可恢复的 id 和准确外键。不可恢复时间属性（如原生 TTL 的绝对失效时刻不明）写入 recovery capability；不能去掉 TTL 后默默延长有效期。Route.sources/destinations 是 set-of-record，map/array/嵌套 record 与插件配置均受限递归，拒绝 prototype key、秘密脱敏 marker、重复 ID 和非法外键。

## 3. 捕获、权限与完整性

所有入口绑定当前 CID/WID、actual transportScope、Kong version/schema fingerprint、当前权限 epoch 和所选明确范围。范围只允许 cluster、workspace 或有限 Service root 集合；cluster 捕获需要完整集群 snapshots 权限，workspace 缺省为既有 default 工作区，不以空 workspaceId 解释为全局。

`snapshots.read/write` 负责快照功能，实际 Native 配置内容仍校验每个真实对象的 read；部署秘密输出额外逐对象 `secrets.read`，包含 credential 自身的精确权限，不能从父 Consumer typed-ID 秘密权限推导子 Key 秘密读。references/级联也必须完整授权，不能用 snapshots 模块绕过配置读取。权限不足的安全 review 可明确列 omitted 数量及 incomplete，但禁止标记为 full/restorable deployment。部署导出缺任何授权对象或必需秘密时失败，不返回部分 YAML 冒充完整导出。

Workspace、tag_group 和 entity 的列表约束都在后端完成。每个 credential/Target 使用真实父归属，历史子 tags 不覆盖父有效工作区。保留标签通过现有物理编码器识别；导入的物理 tags 转为当前 EntityService 的输入表达，不能重复编码、自动工作区迁移或将 unknown/multi-workspace 对象纳入合法 scope。

捕获是显式异步作业。默认 native size=100 固定，读取 size/offset/next，流式写加密对象条目。建议硬上限每个 capture 100 pages/10,000 native records/32 MiB/120s；超限返回完整性错误与安全进度，不能将普通列表全量拉取或把半份快照设为 ready。新增六类凭证页与 Target 页均计入同一 aggregate budget；无需凭证的对象不假计零完整性。只有整体完成和最终当前权限/版本/physical scope 核验通过才发布 ready manifest。

Kong 无跨对象 snapshot/CAS。捕获前后检查受管 physical scope 变更 epoch、原生指纹及引用；控制台有写入或 node/version 变化则拒绝发布一致快照。跨外部 Admin 的瞬间一致性仍不可保证，界面与 README 明示 `consistency: console_fenced_best_effort`。完整 native graph 原文只存在加密存储，不进入作业日志、metrics、审计 diff 或浏览器缓存。

## 4. 秘密产物与恢复能力

产物明确区分三种模式，不能将 `***` 作为可 sync 的秘密：

| 模式 | 输出/用途 | 权限与完整性 |
| --- | --- | --- |
| review | 脱敏配置与安全 manifest；浏览/代码评审 | 非部署产物，secret marker 不可导入执行 |
| deployment | 一次显式授权下载的完整 decK YAML | 当前每个实体 read + 每个秘密 secrets.read；no-store；无 token/秘密进入响应日志 |
| encrypted_snapshot | 服务器加密原对象与 recovery material，明文不下载 | 回滚时重新授权，保存原密码等材料也不授予查看权限 |

下载请求使用 POST 创建短期、绑定当前 actor/session/scope/artifact revision 的单用途许可；最终流出前重新授权，撤权/停用/旋转使许可失效。秘密文件留存期限受控；普通 GET/download link 不自动触发秘密导出。

| 恢复能力 | 必须准确呈现的限制 |
| --- | --- |
| Basic-auth | Admin 返回 hash。`CredentialStore.getRestorePayload` 只有当前 remote hash 与保存的可信原密码证据一致时可重建。历史 hash 不逆推、不重复 hash；没有原密码为 requires_secret_input/rotation，不得破坏性删除后声称原密码仍有效 |
| OAuth2 | 当前1.5.1保存实际client_secret；只恢复client配置，不恢复已签发token、授权码、refresh session。现有CredentialStore的hash_secret分支是保守防御，不能据此宣称1.5支持该字段；未来适配版本确有hash_secret时还须可信原文和对应新格式验证 |
| JWT/HMAC/Key-auth | 保持原始密钥/算法/公钥，不生成替代秘密后声称无损；验证恢复后真实请求可用 |
| Target | weight POST 会产生新 effective ID。输出 originalId→effectiveId，恢复目标为 target/weight 语义，不复活所有历史记录 |
| Portal / 托管监控插件 | captured physical scope、数据库关联及当前私有 policy 必须一致；Native YAML 不是业务元数据恢复许可 |

Basic 原密码补录/轮换必须是单独明确步骤并进入加密计划；该步骤不能从模糊 YAML string 推断 hash/原文。decK 1.1 不检测 Basic 密码变更，所以控制台 diff 必须独立比较可信 credential 指纹与用户明确密码意图，真实认证验收不能被 CLI exit=0 替代。

## 5. 导入、DAG、审批与执行

流程为 **上传→解析/能力检查→完整当前捕获→不可变 diff→影响/回滚材料→二次确认→直接执行或审批→逐对象执行→实际验证**。上传只解析，无 native 写。YAML 只允许受限格式1.1、无 aliases/custom tags/重复键/外部 refs/文件路径解析；建议 body≤8MiB、节点≤50k、深度≤32。只支持固定对象 schema，不执行 Lua 或上传插件二进制；pre/post-function、自定义插件、file-log/local filesystem、受保护 proxy 目的地均保持当前 platform policy。

导入 mode 默认 merge，仅对明确对象新增/修改。sync 删除 mode 必须明确声明完全覆盖的受管范围和二次确认；范围之外对象、未授权对象或 referenced-only 父对象不得因 YAML 没出现被删除。任何列表不完整、未知继承、外键缺失、Portal 管理约束或无法恢复秘密都使计划不可执行。缺省值由当前 schema 决定，null、遗漏、空集合语义和秘密保留均在 diff 中固定，不由执行期随意重构 body。

回滚是一个新 immutable diff job，不是在旧成功回执上重放 native 请求。先检查当前漂移/ID 或名称冲突，用户确认目标 snapshot revision 和准确差异；原始快照只提供目标配置，不授予覆盖当前他人对象的权限。执行前再创建完整加密 rollback snapshot；若原状态不可恢复（如无 Basic 原密码），破坏性计划应阻断或经明确轮换计划处理，不能以回滚按钮掩盖限制。

恢复按真实拓扑：CA/证书→SNI→Upstream/有效Targets→Service→Route；Consumer 在所有引用它的 Plugin/凭证之前；所有父对象存在后再 Plugin；凭证最后。删除逆拓扑，并逐受影响对象进回收站，证书/SNI/父子删除不能隐式产生未列出的 native packet。共享 references 只核验不顺带删除。计划中的全部 ID/秘密预生成一次、加密冻结；after-await 再验证实际当前 before、父引用、权限、lease 和 native send fence。

### 大规模计划不扩张 M6 v1 权限

M6 v1 当前限制为16逻辑步骤、每个 native step 一个 packet、总32packet；此限制不悄悄放宽。M8 引入明确的 config DAG/批准计划版本及固定 registry，整体审批绑定 DAG/对象图/每个 exact native tuple 的 HMAC，再对每个当前逻辑操作按原 Mutation payload/before/key 证明。仍是私有 SQL 核验后的 opaque capability，不接受 jobId/workflowId、HTTP header boolean、`approved=true` 或客户端 callback。Root/私有执行所有者在 M8 release 后落实版本与 SQL 完整 FK，不由业务类自主 mint capability。

直接模式只使用普通 Entity/Mutation 路径；没有伪 self-approval，也不填批准绑定列。审批模式无真正批准不得发送，批准不跳过当前 native write/delete/RBAC/PortalBoundary。不得把大计划拆成多个自动自审的 v1 workflow，或为了 decK sync 临时把 cluster.execution_mode 改 direct。

作业持有不同 job 锁，受控 proof 可短暂取 physical mutation 锁后释放；每步 Mutation 自己获取共享 physical 锁。已发送未知结果立即停止后续 packet，parent uncertain/partial，原始 key 回执继续可读；不能用新 key重发、自动补偿 DELETE、用查询404推断未发送。每步审计关联 parent job/批准版本/实际 operationId/recycleEntryId。终态成功只在已证明完整逐对象结果及最后 metadata/audit 原子提交后发布。

## 6. Portal 与业务绑定的硬边界

Portal 所有历史 Consumer/Key/ACL IDs、其下的新凭证、published Service 的 ACL/key-auth 基线及 captured transportScope 继续由当前 Root PortalAuthBoundary 保护。工作区标签和 decK文件都不能解除该所有权。完整 export 可以按秘密权限备份这些对象，但 generic import/rollback/decK sync 对受保护对象变更必须返回精确限制，不绕过私有 Portal 业务步骤。

首版 M8 generic import/rollback **不支持重建/恢复被吊销的 Portal Key，也不支持 Native+Portal数据库整体时间回退**。这些对象可作为保持不变的 references；任何创建/删除/迁移/重绑/恢复必须已有明确批准的 Portal binding metadata plan，若该 handler 未实现则 fail closed。尤其旧 key 被 Native重建但 SQL仍revoked，或 pending/active grant在无 terminal execution 时显露秘密，都不能作为“快照恢复成功”。需要恢复门户访问时使用现有显式重新申请/审批，生成新 grant/Consumer/Key，保留历史。

托管 Prometheus/http-log channel 同样保留当前秘密 generation 和受保护 Collector URL 规则；普通导入不借 YAML 私自复制 managed provision capability。变更只能通过已有 Vitals setup 的固定流程，或 M8 后续明确注册的同级固定 handler。

## 7. decK 1.1 BFF 兼容适配器

外部 CLI 不获得 Kong 8001 网络权限。适配器独立固定前缀/内部监听范围，绑定CID、WID、actual physical scope、actor/session/权限 epoch、当前 capture/plan hash、读写 purpose 与短期限。Token通过受控 config文件/secret file注入，命令参数/日志不出现原值；不接收任意 Admin URL。

`GET /key-auths`、`/basic-auths`、`/jwts`、`/hmac-auths`、`/oauth2`、`/acls` **仅是 BFF 的 decK 协议路径**。服务端从当前授权 Consumer 页建立嵌套 credential scan cursor，向真实 Kong 只调用 `/consumers/:id/<kind>`。签名续游标同时绑定当前 Consumer游标/子游标、credential kind、size、actor、scope及权限版本；不能全量收集后分页，不能为CLI扩大原生白名单。decK无 tags 的凭证列表也不忽略 Consumer/child权限。

read会话支持 dump/diff；sync会话须提前确认精确 plan。适配器收到每个写 packet 时 canonicalize固定 path/method/body并与唯一待执行 manifest/HMAC匹配，只允许拓扑中已ready的具体步骤；未列出、换scope、body变化、额外删除、重复未知步骤均拒绝。Native实际执行仍委托 Entity/Recycle/Mutation；DELETE必须先持久完整回收图。PUT是否用于create/upsert须按固定 go-kong1.1 实际调用录制后转换成已计划 create/update，不能转发成通用upsert绕过before/absence证明。目标ID生成差异也须先密封重编译diff，不能在首次sync响应时自由选择。

执行回显给CLI采用固定工具预期安全协议形状，敏感运行结果只在已授权工具流内；浏览器/审计接收maskedDTO。每个adapter response发出前检查当前会话、role、CID/WID/physical和plan状态。设置 `--parallelism 1`，尊重统一限流/熔断/物理锁；CLI退出码与控制台parent回执分别记录，退出0不能证明Basic密码已对齐或旧credential仍可用。

## 8. 公开业务 API 与 DTO（实施冻结候选）

统一前缀 `/api/v1/clusters/:cid`，查询 workspaceId明确，所有写持原始 `X-Idempotency-Key`。客户端不能传native path、Admin URL、operator、transportScope、executionMode或approved标志。后端固定计划mode，缺失wid使用既有default工作区。

| 路径 | 固定输入与安全输出 |
| --- | --- |
| POST `/configuration/exports` | `{scope:'workspace'|'cluster'|'services',serviceIds?,mode:'review'|'deployment',confirmed?}` → jobSummary |
| GET `/configuration/jobs`、`/:id` | 当前scope分页/状态过滤；safe progress、完整性、恢复能力、影响、逐对象masked结果 |
| GET `/configuration/jobs/by-key/:key` | 原actor/CID/WID/key及body hash的安全parent/step回执；未知结果不自动继续 |
| POST `/configuration/exports/:id/download` | 确认部署秘密输出时再次授权 → 单次no-store文件或短期限许可；不返回数据库密文内部keys |
| POST `/configuration/imports` | `{scope,serviceIds?,mode:'merge'|'sync',format:'yaml',content}` → immutable diff job；只读预检 |
| POST `/configuration/imports/:id/execute` | `{revision,planHash,confirmed:true,confirm_name}` → direct结果或pending审批；sync删除另显式确认 |
| POST `/snapshots` | `{scope,serviceIds?,name,description?}` → readonly捕获作业；列表/详情/对比按当前权限 |
| GET `/snapshots`、`/:id`、`/:id/compare/:otherId` | metadata/manifest摘要和masked diff；不自动返回raw秘密 |
| POST `/snapshots/:id/rollback-plan` | 当前scope/revision → 新目标diff/执行前恢复能力提示，无native writes |
| POST `/snapshots/:id/archive` | revision+二次确认 → console软归档；保留期内不删历史审计/关联回执 |
| `/snapshots/schedules` 管理 | 显式范围/周期/owner，执行仅readonly捕获；当前账号禁用、授权改变、scope重绑使任务暂停 |
| POST `/configuration/deck-sessions` | 已授权读job或已确认plan ID，server生成短期purpose-bound session，不接受自选permissions |

`JobSummary` 核心：id/CID/WID/scope/kind/revision/planHash/state/executionMode/approvalRequired、createdAt、quality{complete,consistency,warnings}、progress{processed,succeeded,failed,remaining}、capabilities。状态区分 planning/ready/pending/approved/running/succeeded/partial/failed/uncertain/cancelled；safe detail未授权项不返回姓名或配置。删除确认值、剩余步骤、Target effective映射、Basic/OAuth不可恢复对象提示都由服务器实际结果生成。

scheduled snapshot使用已登记的受限服务主体及每次fresh授权，不能构造假的superAdmin或将HTTP帧转为systemread；新只读用途在M8独立安装、精确路径和budget，禁止native写。M11前不实现脱离当前有效主体的后台自动apply/rollback。GitOps使用完整部署YAML+控制台变更入口或已批准的短期adapter会话，diff/批准/执行原始回执可追踪；不把UI的secrets权限静态复制成永久token。

## 9. 实际验收与证据

1. 非空真实Kong配置含8核心类、有效Targets、SNIs/CA和6类Consumer凭证，至少第二页；部署export→固定deck validate→adapter diff无意外差异。
2. 通过受控adapter sync执行新增/修改/删除，逐对象Native状态吻合；删除100%有durable回收图和审计，direct/approval模式符合当前cluster配置。
3. Key-auth、Basic、JWT、OAuth2、HMAC实际代理认证；snapshotrollback后原credential继续可用，Basic没有原密码的历史对象明确blocked。OAuth2 按实际 1.5 schema 恢复 client 与原 client_secret，再重新获取有效 token；不引入不存在的 hash_secret 字段，不宣称恢复历史 token/session。
4. 随机工作区/标签/typed-ID限制、秘密scope、撤权duringawait、unknownresponse原key恢复、重复不同body冲突、currentScope重绑、unplannedCLIpacket及全局credential路径不会越权。
5. Portal历史旧Key genericrestore和别名攻击拒绝；published baseline不被sync删除ACL；合法普通非门户配置可应用，未实现Portalmetadata时间回退明确拒绝而非伪成功。M6已实际证明退役父缺席时Key归档恢复404/原键knownfailed且旧Key401，以及普通Consumer CREATE受管旧UUID的独立保护（该CREATE的真实验证仍待M6 tail）；没有称已验证wholeConsumer恢复。M8必须先以数据库完整历史归属对Consumer/ACL/Key及物理alias作只读preflight，任何restore/import callback或native发送前直接403，不能等逐节点native守卫后包装503/uncertain。实际复验完整Consumer归档和独立Key归档普通恢复均403、无已完成native写、全部原历史Key代理401；正常非Portal对象的依赖顺序恢复仍应通过。
6. Target删除恢复显示真实effectiveID映射，权重和Proxy路由验证；SNI/证书恢复、引用拓扑正确，未授权shared对象无隐式修改。
7. 大图预算、故障/lease丢失、数据库ledger提交丢ACK和CLI部分结果证明后续零包/partial/uncertain；任何artifact若不完整不能ready。
8. 所有日志、审计、diff、CLI证据和截图扫描无真实Key/原密码/私钥/managedchannel token；部署秘密文件不进入Git或普通产物目录。

证据分别标注 actualKong、actualBFF、actualdecK、offlinefixture、syntheticFault。可用CLI的 `version --help` 和已有离线schema结果只说明工具/格式已核对，M8运行验收必须在该阶段独占窗口完成。
