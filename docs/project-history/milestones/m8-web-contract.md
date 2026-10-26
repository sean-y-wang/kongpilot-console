# M8 前端合同：配置快照、Diff、导入导出与 GitOps

状态：**M7 已闭环，Root 已放行 M8 源码实施**。快照、配置导入导出、脱敏 Diff、逐对象结果与 GitOps 页面已落盘；当前在对齐实际后端安全 DTO，尚未运行 M8 浏览器、业务 HTTP、配置导出或 CLI sync。本文保留原设计依据；路径与字段最终以实际业务 controller 和安全 view 为准，下面旧提案不能冒充运行验证结果。

实现依据为现有 Console 身份/四维权限/范围捕获、原键未知写入恢复、M1 `graphOrder()` 与加密凭证保存、M6 immutable 工作流/Portal 受管边界，以及 [Kong 1.5 与 decK 1.x 兼容性调查](../../reference/deck-1.5-compatibility.md)。该调查已完成固定版本源码及离线格式验证，尚未完成真实网关 diff/sync，页面不得提前宣称兼容验收完成。

## 当前源码实现与真实接口

本节覆盖已落盘的 Web 和 ConfigurationController 合同，优先于后文留存的原始提案。所有接口加 `/api/v1/clusters/:cid`，固定 `workspaceId=:wid`，经 BFF；不同业务范围仍绑定原工作区锚点。页面组件均无必填 props，`GitOpsPage` 另接受可选 `embedded`。

| 页面路由 | 已实现行为 |
| --- | --- |
| `/snapshots` | 手动捕获、真实服务器游标列表、快照元数据回收站、定时策略 CRUD/暂停/恢复/永久停用 |
| `/snapshots/:id` | 同一详情接口的游标对象清单、恢复限制、同范围快照只读比较、从原版本导出、生成回滚 Diff |
| `/configuration` | 当前配置导出、临时 YAML 上传及 merge/sync 预检、真实作业列表、GitOps 标签 |
| `/configuration/plans/:id` | 不可变 `planRevision/planHash`、脱敏 JSON Patch/map 删除、删除数量 typed 确认、直接执行或真实工单登记 |
| `/configuration/jobs/:id` | 父状态、真实分页步骤/有效 ID/Native 回执/回收图、安全进度、单独确认下载 |
| `/configuration/gitops` | 安全仓库显示名、commit SHA、流水线引用和已有作业关联；无浏览器 Git/CLI 执行 |

| 实际接口（不含统一集群前缀） | Web 字段与行为 |
| --- | --- |
| GET/POST `/snapshots` | 列表 `scope/size/cursor/state/search`；Service roots 用 `serviceIds` 严格 UUID 逗号串；创建 body 为 `scope/serviceIds[]/name/description` |
| GET `/snapshots/:id` | 摘要与 `items/nextCursor/size`；对象查询不发送不存在的 type/search 参数 |
| GET `/snapshots/:id/compare/:otherId` | 同实际 scope 的只读安全 Diff；缺少 Services roots 时不借当前范围代替 |
| POST `/snapshots/:id/export` | `mode=review|deployment/confirmed/confirm_name`；完整秘密文件须明确确认，成功后到真实 export job |
| POST `/snapshots/:id/rollback-plan` | 原元数据 revision、typed 快照名称、`confirm_deletes:true`；只生成计划，不能当作执行完成 |
| POST `/snapshots/:id/archive|restore|purge` | 原 revision 和 typed 名称；所有按钮要求真实服务端 capability，不用假状态开关 |
| GET/POST `/snapshots/schedules` | 同真实 scope 游标及 state/search；flat 周期/时区/保留策略，周期 5–10080 分钟 |
| PATCH/DELETE `/snapshots/schedules/:id`；POST `/restore|purge` | 原 revision CAS；edit 的原 scope 固定，`paused` boolean；恢复后 paused，服务器 `nextRunAt` 仅照实际状态展示 |
| POST `/configuration/imports` | `yaml/scope/serviceIds[]/mode=merge|sync/basicPasswordIntents?/confirm_deletes?`，不是旧提案的 content/format；sync 先同意生成删除 Diff，执行仍另确认实际数量 |
| GET `/configuration/plans/:id[/changes]` | size/cursor；没有假 action/type 筛选，JSON Patch 值经后端及显示层脱敏，false/0/null/missing 分别保留 |
| POST `/configuration/plans/:id/apply` | `planRevision/planHash/confirmed/confirm_name/confirm_deletes?`；不是 job/root revision，无假 driver 选择器 |
| GET `/configuration/jobs[/by-key/:key|/:id|/:id/steps]` | 原 actor/CID/WID/key 固定；父终态和完整原回执才核验完成，waiting approval 仅证明登记 |
| POST `/configuration/exports` | `scope/serviceIds[]/mode/confirmed/confirm_name`，当前名称来自实际 Workspace |
| POST `/configuration/plans/:id/reconcile` | 原 revision/planHash，原键回执；只读观察 present/expectedFieldsMatch，`causalOutcomeUnproven`，不改执行状态或解除原未知写阻止 |
| POST `/configuration/exports/:id/download` | 单独 typed 确认，`revision` 必须是服务器 `exportRevision`，缺少该字段即禁止下载，不用 job revision 或默认 1 |
| GET/POST `/configuration/gitops/runs` | 真实 scope 分页；安全 ASCII 显示名、40/64 位 SHA、无 URL/token 的流水线引用、当前原作业 ID |

导入文件上限 8 MiB，明文只在 File/Form/当前发包内存中，上传前清空输入、结束再次清理；不进入 Query/路由/存储/错误/日志。下载同源 POST、固定原 key，响应逐块限额 32 MiB，原账号/权限/范围变化取消并忽略迟到数据，单次 object URL 在结束后销毁。导出 Job 只展示安全摘要和 `formatOmissions`；decK 1.1 optional null 的省略不表示 merge 清空字段，原加密快照保留 null。

所有配置写入 5xx、丢响应或未知父结果保留原 actor/CID/WID/key，阻止同范围新写；恢复只 GET 原 `configuration/jobs/by-key/:key`，不自动换 key 重放。仍为 partial/uncertain 的带工单作业不能因 workflowId 存在被误当作登记完成。共享引用、完整性、恢复能力和 capability 未由服务器返回时明确显示未提供，不补零、也不授予按钮权限。

前端 Source 验证使用 `tests/unit/m8-web-policy.test.ts`，包含实际 ConfigurationService.jobProjection、ConfigurationController comma query 和 repo.scheduleSummary 的内存 producer 合同；其余网络仅 fake fetch，不初始化运行态服务。当前仅源码/typecheck 证据，不代表真实 Kong/CLI/浏览器验收。已对齐实际 reconcilePlan 的逐对象只读观察（没有原操作因果证明）；scheduler/执行驱动以最终落盘源为准，未完成的运行验收不提前宣称通过。

## 原始设计留存（不能照此发包）

下面保留最初的设计理由与安全边界。具体路径、字段与页面只以上面的真实实现及实际 controller 为准。

## 1. 页面与交互流程

管理导航新增“配置快照”与“导入导出 / GitOps”；沿用集群、规范工作区和当前授权范围。M8 不提供原生 Admin URL、任意代理或用户输入 shell 命令。

| 路由提案 | 页面行为 |
| --- | --- |
| `/snapshots` | 手动快照、服务端列表、定时策略、快照回收站；展示真实范围、完整性与捕获时间 |
| `/snapshots/:id` | 对象清单、依赖图、凭证可恢复性、快照对比与当前配置对比、回滚预览 |
| `/configuration` | Export / Import / Diff / GitOps 四个标签；完整交互入口，不直接改变配置 |
| `/configuration/plans/:id` | 脱敏配置 diff、范围/引用冲突、依赖步骤、删除数量、审批及逐对象执行结果 |
| `/configuration/exports/:id` | 异步导出状态、覆盖对象和安全下载；不显示原始 YAML 秘密预览 |
| `/configuration/gitops` | 受控流水线凭据/许可、近期计划、执行记录与版本关联；不在浏览器登录 Git/执行 decK |

核心流程：选择真实授权范围 → 捕获/上传 → 服务端解析与比较 → 审阅 diff 和依赖 → 输入目标名称二次确认 → direct 执行或提交审批 → 查看父操作回执与逐步结果。删除与批量 apply 不能从“预览成功”自动进入执行；批准也不代表配置已生效。

版本、字段和格式错误在预览阶段显示。配置有效性由实际已探测 Kong 1.5 schema、固定 decK 映射及服务器最终检查决定；插件使用 `/plugins/schema/{name}`，不调用新版插件 schema、企业工作区或不存在实体。后端根信息缺少 `endpoints` 时用实际探测白名单，不假造能力。

## 2. 数据覆盖与真实 decK 1.1 格式

导出固定 `_format_version: "1.1"`。默认兼容验证工具为经官方校验的 **decK v1.1.0**，不泛指所有 decK 1.x；后续 1.x 可能查询企业实体或新 schema。工具输出、下载和执行各自记录版本及校验，`DECK_ANALYTICS=off`，不启用会打印凭证的 verbose 日志。

| 真实对象 | decK 1.1 YAML 位置 | 预览与恢复注意 |
| --- | --- | --- |
| Services | `services[]` | 仅当前 1.5 实际字段；client_certificate 指向已存在证书 |
| Routes | `services[].routes[]` 或合法 `routes[]` | Service 引用保持；不能混入表达式路由字段 |
| Consumers | `consumers[]` | username/custom_id 与原 ID；凭证均真实挂在 Consumer 下 |
| Plugins | `plugins[]` 或合法绑定对象下 | 四级/组合绑定依赖、enabled/config 与真实 schema；全局运行范围明确提示 |
| Upstreams / Targets | `upstreams[].targets[]` | 有效 Target 集合；历史行单独作为安全快照元信息，不冒充全部有效后端 |
| Certificates / SNIs | `certificates[].snis[]` | 包含证书私钥、SNI 原 ID/name/tags；引用与证书链/到期检查 |
| CA Certificates | `ca_certificates[]` | 独立实体仍必须覆盖，Service 是否支持 CA 字段按实际 schema |
| KeyAuth | `consumers[].keyauth_credentials[]` | 真实 key 原文只能授权秘密导出/受控恢复 |
| BasicAuth | `consumers[].basicauth_credentials[]` | Kong 返回哈希不能当原密码重建；原文恢复能力独立报告 |
| JWT | `consumers[].jwt_secrets[]` | secret/私钥保密，secret_is_base64 为公开 boolean 配置 |
| OAuth2 | `consumers[].oauth2_credentials[]` | 原 client_id/client_secret、redirect_uris 等实际 schema 字段 |
| HMAC | `consumers[].hmacauth_credentials[]` | 保留 username/secret 与原 Consumer 关系 |
| ACL | `consumers[].acls[]` | 真实 group 与原 ID；Portal 保留 ACL 不由普通 importer 重写 |

Targets 和 SNIs 必须作为父对象的嵌套内容包含。**不得为“包含全部实体”添加 decK 1.1 不支持的顶层 `targets` 或 `snis`**；UI 对象清单仍按独立类型统计和 Diff，因此用户能确认这两类已覆盖。

实际本环境 Kong 1.5.1 Service schema 没有 `tls_verify`、`tls_verify_depth`、`ca_certificates` 字段；不能根据候选需求清单硬填。其余 Service/Route/Upstream 可导出字段同样由真实版本 schema 决定。控制台软工作区是保留 tag，并非企业 `_workspace`；文件保留实际可用编码标签，页面可显示逻辑名称，但不会生成不存在的企业工作区接口/字段。

元数据只读摘要与可执行 decK 文件是不同产品。没有完整秘密授权或 BasicAuth 原文不可恢复时，不以 `[REDACTED]` 占位文件冒充可用备份；显示具体缺失/不可恢复对象和 blocker。用户可下载脱敏清单作为审阅材料，其类型明确为“配置摘要，不能直接 sync”，不能偷偷置换 YAML 里的秘密。

## 3. 快照捕获与范围

快照公开摘要提案：

```ts
interface SnapshotSummary {
  id: string; clusterId: string; workspaceId: string;
  name: string; revision: number; createdAt: string;
  state: 'capturing' | 'ready' | 'incomplete' | 'failed' | 'deleted' | 'expired';
  scope: { kind: 'workspace' | 'service' | 'cluster'; rootIds: string[] };
  source: { kongVersion: string; adapterVersion: string; observedAt: string };
  counts: Record<string, number> | null;
  consistency: 'verified' | 'changed_during_capture' | 'unverified';
  credentialRecovery: { complete: boolean; recoverable: number; unavailable: number };
  warnings: string[];
  capabilities: { read: boolean; compare: boolean; restore: boolean; delete: boolean; export: boolean };
}
```

`ready` 必须来自后端实际捕获完成，而非客户端轮询次数/等待秒数。捕获逐页使用 Kong `size/offset`，有总 pages/records/nodes/bytes/time 预算。预算耗尽或读取失败返回 incomplete 及真实覆盖情况，不叫“完整快照”。DB 模式在捕获期间可能发生变化；后端保存观察窗口、版本/指纹并必要时再次定向核验。不能宣称 Kong 1.5 多实体查询是原子数据库快照，控制台也不能直连 Kong PostgreSQL。

包含其他工作区引用时列为共享引用，保留必要身份但不自动纳入可写范围。无法完整证明读/秘密/依赖权限时阻止破坏性恢复或明确缩小范围；不为了完整导出借超级账号抓取未授权对象再交给普通用户。Whole-cluster 捕获只展示给完整集群权限，工作区锚点仍规范记录。

快照正文/凭证在后端加密保存，公开列表/详情只安全摘要和按页脱敏对象。secret/HMAC 指纹不作为浏览器可字典爆破的秘密摘要显示。未实现的定时策略不放假开关；正式实现 POST/PATCH revision、时区/下次执行/最近结果及 worker 状态后再展示。

快照删除进入元数据回收站，typed name 确认，保留期和恢复入口可见。到期只表示可清理；彻底销毁加密恢复材料仍显式二次确认，不与删除网关配置混用。已关联未决执行或作为回滚材料的快照不能悄悄清理。

## 4. Diff 与执行计划

后端先对输入规范化，按 typed ID/合法名称和真实父关系识别新增、修改、删除、未变、冲突、不可恢复，不在浏览器拉全量两边 JSON 算 diff。计划以 original actor/CID/WID、版本、当前权限版本、输入指纹、before 指纹、外部引用、immutable step 清单和 planHash 绑定；预览不是客户端可提交 approved flag 的执行许可。

Diff 页上部显示目标、来源版本、完整性、真实 change counts；下部服务端按 type/action/conflict 分页。行内显示对象安全名称、字段路径和脱敏 before/after。秘密变化只显示“已提供新值”“保留现有值”“来源不可恢复”，不显示秘密、其散列或 JSON 长度。`false`、`0`、`null`、缺失字段区别保持，map/array 深层变化不能被 collapsed 区块丢弃。

导入默认 `merge`，删除只在明确选择 reconcile/replace 范围后产生，并单独显示“拟删除 N 个对象，将先进入回收站”。只影响已审阅范围；外部引用/其他工作区/未授权/受管对象不因 YAML 缺少而成为删除对象。变更窗口、执行模式、凭证恢复可用性与影响面来自服务器；M11 尚未交付的多级定时流程不在 M8 伪称已可用。

执行前再次核验当前授权、workspace/cluster revision、before、依赖及计划期限；发现变化返回409，需要新预览和再次 typed 确认，不覆盖并发改动。服务端先创建执行前快照，ready 后才执行；每步经现有 EntityService/RecycleService/工作流私有 before-send 权限与锁，不建立直连 Admin 或 rawpath 旁路。

恢复依据 **依赖 DAG**，沿用实际 `graphOrder()`：证书/CA 先于引用它们的 Service/SNI；Upstream 先于 Target；Service 先于 Route；Consumer 先于其凭证和绑定它的 Plugin；Service/Route/Consumer 都完成后才恢复相应 Plugin。UI 可以展示分组顺序，但不能固定把 Consumer-bound Plugin 排在 Consumer 之前。删除为依赖逆序并先加密归档对象图。共享引用通常只读，不擅自重建覆盖。

能安全保留原 UUID 时保留；冲突配置不覆盖，同 ID 不同配置必须列 blocker。Target 权重变化在 Kong 1.5 产生历史行，恢复的是实际 target/weight 有效状态，不能承诺每条历史 UUID 重新成为有效 Target。凭证可用性不以 Admin GET 有一条数据代替代理真实认证；回滚结果明确哪些已核验、哪些尚待授权验证。

M6 管理的历史 Portal Consumer/Key/ACL UUID 持续受私有业务边界限制。普通快照、导入或 decK sync 不能恢复已撤销的旧 Key、改挂 Consumer 或破坏 SQL grant 状态；Metrics 受管全局插件也保留对应当前限制。计划必须显示受管 blocker，专用业务恢复需要当前有效 sealed handler，不以“全量回滚”绕过受管策略。旧 Key 撤销后恢复访问仍重新申请审批新 Key。

## 5. 导入、导出和秘密在浏览器的生命周期

导入：文件选择或短期粘贴 → 上传 → 服务器 YAML/JSON 安全解析 → 预览 ID → 清空本地文本 → 脱敏 Diff。限制文件字节、深度、节点、aliases/anchors 展开、对象数和重复 key；拒绝 prototype 键、未知格式/实体字段、外部引用和执行模板。浏览器不使用 `eval`、远端 `$ref`、任意 fetch 或 YAML 自定义类型。回显错误仅字段/行号和安全说明，不能将带 APIKey 的原始行展示。

上传期间 plaintext 只在 File/Form 临时内存；不进 TanStack Query、local/sessionStorage、路由 state、草稿、错误、Console 日志、截图或 receipt。已提交后删除上传输入值/临时解析文本；切换 actor/CID/WID/权限、离开页面或未知结果时同样清除。安全恢复持久化只有原账号、范围、原 key、plan/export/job ID 和时间，绝无 YAML/配置/凭证。

导出提供真实格式、范围和对象覆盖预览。完整备份包括全部普通实体和六类凭证，必须当前对应 read + 独立 secrets.read 授权；没有把父对象秘密 grant 继承为凭证 grant。下载明文私钥/密钥文件需要显式勾选和 typed 目标确认，先解释授权范围及存放责任。默认页面只展示安全摘要，不以一键预览原始 YAML 泄露秘密；完整导出选项可供有权用户操作，不静默排除 credentials。

后端生成受控同源流式文件/有界加密暂存 job，下载再次核验当前账号与权限，Content-Disposition/nosniff/no-store 正确；无 public blob URL、token query、跨域预签名链接。前端 Blob helper 复用当前账号单次刷新/取消规则、限制接收大小，仅临时 object URL，下载完成/关闭/切换后 revokeObjectURL；已下载到用户文件系统是明确授权产物，UI不假称能擦除用户保存的文件。

BasicAuth 等无法恢复原文的历史凭证是 blocker，不用哈希冒充明文；可选择明确轮换方案，但它是新的变更/审批，界面标注旧密码不保证继续可用。普通客户端不会将 `[REDACTED]` 或 maskedKey 当真实新值提交。未变秘密在服务器封存计划中保留，秘密数组/record 身份不确定时要求授权重新输入，不能盲猜绑定。

## 6. 拟议 HTTP 接口与原键回执

以下均为待冻结提案，不代表当前可调用端点。全部经 `/api/v1` BFF 标准 envelope；集群端点显式 `workspaceId`。任务状态只安全 DTO，不回原始配置。

| 方法与路径提案 | 输入/行为 |
| --- | --- |
| GET/POST `/clusters/:cid/snapshots` | 分页 scope/status/search 或 name/scope/roots；手动捕获返回安全 job/snapshot ID |
| GET `/snapshots/:id`、`/:id/objects` | 摘要或按 type/search/size/cursor 的脱敏对象；不全量正文 |
| POST `/:id/compare` | targetSnapshotId 或 compareWith=current；建立只读 masked diff 计划 |
| POST `/:id/rollback/plan` | 只读捕获当前 before、依赖与恢复检查，返回 immutable 恢复计划，不执行 |
| DELETE `/:id`、POST `/:id/restore`、POST `/:id/purge` | revision、confirmed、confirm_name；快照元数据软删除/恢复/显式销毁 |
| GET/POST/PATCH `/clusters/:cid/snapshot-schedules[/:id]` | 服务器策略列表及 revision CAS；是否启用真实 scheduler 由 M8 backend 冻结 |
| POST `/clusters/:cid/configuration/imports` | bounded multipart/file 或受限 text + format/scope；持久化加密输入并返回安全 import ID |
| GET `/configuration/imports/:id` | 安全解析状态、coverage、warnings；无 YAML 原文 |
| POST `/configuration/imports/:id/plan` | mode=merge/reconcile、显式 scope；只读比较，不能删除 |
| GET `/configuration/plans/:id`、`/:id/changes` | 计划摘要和 masked change cursor 列表；所有引用匹配原 CID/WID |
| POST `/configuration/plans/:id/apply` | revision、planHash、confirmed、confirm_name、明确 delete confirmation；正常 direct/workflow 策略 |
| POST `/configuration/plans/:id/reconcile` | planHash +确认；只读实际状态证据，不能接收客户端 outcome 或再发写包 |
| POST `/configuration/exports` | scope、format=deck-1.1、includeCredentials/includeSecrets、confirmed、confirm_name；建立有界 export job |
| GET `/configuration/exports/:id`、`/:id/download` | 当前授权的安全 job 状态和同源文件，permission revoke 后拒绝 |
| GET `/configuration/operations/by-key/:key` | 原 actor/CID/WID/key 解析真实捕获/import/apply/export 父回执，不按当前 mode 猜域 |
| GET `/configuration/gitops/runs`、`/runs/:id` | revision/commit 关联、safe plan/actor/state，无 Git credential |

捕获/import/upload/export 创建虽不写 Kong，也可能提交 SQL job/加密材料，需要真实 durable 原 key 回执。比较/生成 plan/reconcile 的确切端点可标为 gateway-readonly review，但有 DB 草稿状态时丢响应只重新读取/有界重建安全草稿，不制造 native完成证明。不能将全部 POST 归类为只读。

普通 apply/rollback 未知响应：显示“执行结果待核验”，保存原 parent key、plan/operation、原 CID/WID/actor，锁定新写；刷新浏览器/切换工作区后核验仍指向原范围。steps 单个成功、recycleEntry 存在、审批提交或自称 success 不证明全计划完成。父终态 +完整授权 +当前 planHash +每步 durable 证据才解除相应执行阻止；partial/uncertain 保留原计划。人工 reconcile 只观察真实 before/after，不将失败当成功；所有步骤已证明 terminal 后，用户显式新预览/typed 确认可恢复未完成部分，禁止自动换 key resume。

409 drift/revision、503 uncertain、超预算和过期有独立原因。DELETE/批量至少一次二次确认，不以 import 表单默认勾选代替。恢复使用当前审批模式，不因旧快照来自 direct 集群而自动获得执行权。

## 7. GitOps 与受控 decK 适配

计划采用 [兼容性调查](../../reference/deck-1.5-compatibility.md) 已选的 **BFF decK v1.1 兼容适配器**。原版 CLI 的 `/key-auths`、`/basic-auths`、`/jwts`、`/hmac-auths`、`/oauth2`、`/acls` 全局读取仅在 BFF 中翻译为当前调用者授权的 Consumer 和六类凭证逐页查询，不向 Kong 放宽白名单。未知 CLI 路径拒绝，不反向代理给 Admin API。

CLI diff 用独立最小只读流水线身份；sync 必须已有 UI 审阅的具体 immutable plan 和短期绑定 plan/actor/CID/WID/hash 的执行许可，服务端每包仍复验当前权限/会话、审批、租约和 before。许可不是用户输入 approved/workflowId，也不能成为跨计划 bearer。CLI DELETE 委托 RecycleService，不能物理删除绕过归档和审计。审批集群没有已批准计划不能 sync，Direct 也仍须 typed diff 确认。

Web提供固定的无秘密流水线说明：导出 API、配置版本/digest、plan endpoint、查询回执、受控 decK 命令结构。真实 token/短期许可仅显式授权领取一次并存流水线秘密库，不进入永久网页示例、下载 YAML、URL、日志或 Git 仓库。浏览器不读取任意 Git URL、不执行 hook/template/shell，不自动向外部 Git 服务提交配置；M8 核心是便于用户纳入 Git + CI 的 API，新增 Git push/PR 必须另有明确产品合同和发送授权。

GitOps 记录使用用户提供并校验的安全 commit SHA、repository display name、pipeline run reference，不能把原始含 userinfo/token 的 Git URL 原样展示。Commit 提示不代表真正已推送/已发布；状态来自真实 BFF执行。环境 Promote 默认排除凭证属于 M10，M8 不悄悄把 rollback 当跨环境 promote。

## 8. 权限、缓存与实现文件

模块按现有 `snapshots` / `gitops`，apply 同时需要每个真实对象动作，完整导出秘密另需 `secrets.read`。whole-workspace元数据、typed entity/tag scope 和共享依赖不能拼接为越权全量备份。只有监控/Portal业务读取而没有 native读的人不会借 M8 下载底层配置。操作能力由服务端 current row/plan投影，缺失为false；无法读取关系不显示为0对象。

所有列表 querykey包含 actor/permissionsVersion/CID/规范WID/scope/filter/cursor/source revision；比较还含两边snapshot/planHash。切换权限/actor/范围会取消旧GET、清掉摘要/secret panel并忽略迟到结果。OpenEditor按这些范围 remount，不能拿旧表单在新集群保存。普通 Query缓存仅安全摘要/脱敏diff，小容量有限可回收；rawfile、Key、密码、PEM私钥、许可不进缓存和路由。

拟议文件（release 后才创建）：`features/SnapshotsPage.tsx`、`SnapshotDetailPage.tsx`、`ConfigurationPage.tsx`、`ConfigurationPlanPage.tsx`、`GitOpsPage.tsx`、typed API/原键resolver和受控文件下载helper。复用 M6工作流导航/父回执证明，只有服务端正确标记的新handler/kind可执行；不将 snapshot计划假装 Portal工作流，也不绕过 approval 到 IAM直接发包。

## 9. 验证与稳定选择器

稳定标识提案：`snapshot-row-ID`、`snapshot-coverage`、`credential-recovery-state`、`configuration-import-upload`、`configuration-diff-row-ID`、`configuration-plan-state`、`configuration-step-ID`、`configuration-delete-summary`、`configuration-export-state`、`gitops-run-ID`。中文 aria：导出范围、配置文件、导入模式、快照来源、目标快照、对象类型、变更类型、确认目标名称。秘密不进入 aria/testid/截图/故障错误信息。

源码意味测试：actual decK1.1结构映射（SNIs/Targets必须嵌套）、缺失与null/0/false及复杂array/mapdiff、秘密与JSONPointer脱敏、无完整凭证不假称备份、未知写原key恢复/跨accountscope迟到结果、DAG Consumer-boundPlugin顺序、受管UUIDblocker、Blob过大/取消/accountchange/revokeURL、YAML aliases/重复key/prototype/外部ref拒绝。

真实阶段由 Security独占 HTTP→decK→browser，使用隔离测试cluster和现有BFF，完整八类核心对象/Targets/SNIs/CA/六类凭证。固定decK validate只是离线；实际diff/sync必须经受控适配器记录所有1.5路径，删除均归档，执行前快照ready，工单模式不能绕过审批，逐对象审计与原key重放不重复创建。BasicAuth密码变更不能依赖原版decK检测告警；后端明确显示独立变化和恢复能力，真实代理认证才作为凭证恢复验收。

回滚后真实KeyAuth/BasicAuth/JWT/OAuth/HMAC可用性按协议验证，不把YAML通过当作可用性证明；ACL允许/拒绝、证书/SNI和Upstream有效target/weight分别验证。权限撤销/IDOR、Portal历史revokedKey不复活、读写许可跨plan误用、snapshot与import未知状态都要有实际故障证据。UI人工检验依赖图/冲突/typed确认/移动端和下载后清理；私有文件/运行时秘密引用0600、所有截图/source/artifacts/reports/ZIP扫描完成后才销毁。

若有不可恢复历史BasicAuth、跨scope引用、预算或原生传播延迟，验收报告明确限制和未完成对象，不为了商用声明抹去blocker。M8完成声明必须同时说明真实decK版本、文件覆盖、受控adapter实际路径、秘密授权、删除归档、父回执与代理认证结果。
