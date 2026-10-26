# M9–M11 前端合同：运维工具、配置治理与审批工作流

状态：**仅设计，尚未实施**。M6 当前源码冻结、等待真实 HTTP→浏览器→手工交接；本文件不授权未来产品代码、SQL、后台执行、出站请求、全局构建或部署。所有新增 HTTP/DTO 为候选，Root 按 M9→M10→M11 的正式阶段门禁冻结，不能因写入本文就将功能标为可用。

基线为当前 Console `api()`、`scopeQuery()`、四维完整 `EffectiveGrant`、revision CAS、MutationConfirm、原 key 安全恢复标识、M1 Graph/RecycleService、M3 Migration、M5 Vitals provider、M6 immutable Workflow/private approved capability。Kong 1.5 不提供企业运维工具、表达式路由、Vitals/workspaces/event-hooks/clustering；新增控制台 API 必须调用当前探测白名单，不能做 raw Admin 代理。

## 1. 所有阶段共用的 UI/请求约束

- 页面和querykey绑定当前actor、permissionsVersion、clusterId、规范workspaceId、资源/过滤/cursor。双环境比较同时绑定明确source和target CID/WID，不能在请求发出后从可变选择器读取目标。
- 粗模块能力决定菜单；实际行能力由BFF fresh object projection提供，缺失false。metadata全工作区配置需要whole-workspace/global，typed entity/tag操作仍逐对象校验，不能拼不同授权行或推导秘密继承。
- 所有列表servercursor `{items,nextCursor,size,total:null}`，默认20上限100；只已访问页缓存的上一页/下一页，不全量取Kong。明确bounded jobs可在后端逐页执行，但必须给coverage/预算/不完整原因，不能静默截断称全部。
- 写确认使用当前安全对象name/ID、revision/planHash、confirmed；删除/批量/跨环境发布必须二次确认。普通配置删除经回收站，不物理删除；metadata草稿/规则/策略有可发现软回收入口。
- 网络中断、502/504、不可读成功或partial/uncertain保留**原账号、原CID/WID、原key、父plan/operation标识**。安全存储只有ID/状态/时间，没有config、凭证、密码、targetURL或请求header。reload、换集群后核验仍走原始范围，不能换key自动重发。
- 只读review的确切POST可归为NETWORK_REVIEW_INTERRUPTED；metadata/job创建虽不写Kong仍需要真实durable SQL回执，不能全部POST当只读。BFF父resolver据真实记录判IAM/workflow/native/job，不按当前executionMode猜。
- 当前M6 Workflow kind/subject/handler为Portal whitelist，计划原生步数有16上限；未来模块需要明确新增kind/handler和预算设计。不能假标Portal流程、盲目扩大数组或直接绕过IAM审批，也不提前宣称M11 scheduler已实现。

## 2. M9 运维工具箱

路由提案：`/toolbox`，标签为节点状态、缓存、路由调试、批量操作、我的草稿。模块`toolbox/batches/drafts`与每个真实对象动作独立。当前M5节点是registeredAdminEndpoint逻辑节点/transportScope，不声称发现完整Kong拓扑。

### 状态和缓存

GET `/clusters/:cid/toolbox/status?workspaceId` → `{clusterId,workspaceId,observedAt,available,status,quality,capabilities}`，实际来自`GET /status`。如果Kong返回的是整节点聚合，不支持workspace过滤，则只whole-cluster权限可见；工作区账号不能假借tag变成整集群连接/请求统计。失败显示不可用/过期时间，不填0或绿灯。

缓存按key定向查看：GET `/toolbox/cache?key=...&workspaceId` → `{key,found,observedAt,valueSafe?,truncated,capabilities:{invalidate}}`。先确认实际1.5 `/cache`能力，**不提供未经真实端点证明的“分页全部cache keys”列表**。Cache可能包含其他工作区/秘密配置，读取须当前全节点授权及服务器可信key解析；无法证明归属的key不授权给tag/entity范围。安全值在BFF二次脱敏，有byte/depth预算，无credential原文reveal旁路。

POST `/toolbox/cache/invalidate` 候选body `{key,revisionToken?,confirmed:true,confirm_name:key}`，真正网关调用`DELETE /cache/{key}`。这属于**缓存失效动作**，不是删除配置实体，UI不称“配置已删除/可回收”；记录真实审计、原key回执和node-local影响，默认不开放整节点cache清空。审批集群同样通过真实批准计划，不能以工具页旁路直接DELETE。key若包含秘密/任意path被拒，前端不会拼Admin路径。

### 路由匹配与真实代理探测

表单：method、scheme/host/port/path/query、允许的请求headers、source IP、可选SNI。endpointserver固定目标cluster，不接受任意Admin/proxyURL。候选POST `/toolbox/routes/debug`为只读review，body仅结构字段，不把`approved/system/rawPath`当能力。

```ts
interface RouteDebugView {
  clusterId: string; workspaceId: string; observedAt: string;
  engine: 'native_verified' | 'kong_1_5_simulation';
  complete: boolean; confidence: 'verified' | 'partial' | 'unsupported';
  route: { id: string; name: string | null } | null;
  service: { id: string; name: string | null } | null;
  candidates: Array<{ id: string; matched: boolean; reasons: string[] }>;
  selectionPrecedence: Array<{ plugin: string; scope: string; selected: boolean }>;
  executionOrder: Array<{ plugin: string; priority: number | null; phase?: string }>;
  warnings: string[]; budget: { pages: number; records: number; complete: boolean };
}
```

原生调试端点只能在实际1.5探测并进入白名单后使用，不能假设不存在版本也有`/debug/routes`。fallback依据1.5真实Router语义在后端模拟method/host/header/source/protocol、正则/regex_priority与路径前缀，不能只按最长path推断全部路由。PCRE/Lua匹配、路由并列或部分授权资料无法精确处理时给unsupported/partial，**“未发现授权范围命中”不等于网关不会匹配别区route**。

同名插件配置选择8层RSC→RC→SC→RS→C→R→S→Global与handler执行priority是不同概念，沿用M2分开展示。隐藏global插件/无权限Consumer上下文令complete=false，不声称完整执行链。插件有不同phase时显示实际phase，不捏造每插件耗时。

候选POST `/toolbox/probes`执行真实代理请求。目标由后端已批准cluster proxyOrigin固定、DNS/pin/无redirect/预算检查；URL只是host/path路由输入，不能向用户指定host任意发包。GET/HEAD默认可用；其他方法可能改变业务系统，只有已冻结权限与用户明确风险/目标确认后才提供，不自动跟随认证重定向或重试业务请求。

probe返回 `{requestId,method,matchedRoute?,status,headersSafe,bodySafe,truncated,timings:{dns?,connect?,tls?,ttfb,total},timingSource,observedAt}`。dns/connect/ttfb/total是BFF观测；无trusted instrumentation不假称Kong/上游各内部阶段真实耗时。header/body先脱敏并限制字节，仅text/JSON，不执行HTML/图片/外链。Authorization/apikey如确需测试只在临时表单内存，提交后清空，不进入query、草稿、report、receipt或截图。结果HTTP状态来自proxy，不把401当Console会话401触发自动refresh。

### 批量操作与草稿

批量仅显式当前已选择对象，roots<=50候选（最终后端预算冻结）。支持业务tags、plugins enabled、workspace迁移、删除；只允许固定action枚举，不执行客户端任意method/path/body。选择全页不是全库；服务端全过滤批量若实施必须固定selectionSnapshot、真实计数和预算，不能客户端偷偷扫所有页。

POST `/clusters/:cid/batches/plan` → immutable安全计划；GET `/:id`/`/:id/items` cursor查看diff；POST `/:id/apply` `{planHash,revision,confirmed,confirm_name}`；GET `/batches/receipts/by-key/:key`父回执。tag业务编码/reservedworkspace归属不能自由串改；workspace迁移复用M3DAG、目标typed name；插件启停保留危险/Portal/Metrics受管边界；删除完整对象图先归档。每对象结果succeeded/failed/uncertain/skipped，服务端逐步锁/限流，不以client Promise.all制造并发Admin写。partial不回滚标为成功，也不自动继续未决对象。

草稿为本人、原CID/WID、对象类型/ID和revision；GET/POST/PATCH/DELETE `/clusters/:cid/drafts[/:id]`候选，SQL owner-only且删除软归档。只保存公开非秘密表单字段；私钥/Key/密码/header/含凭证URL不进入浏览器持久草稿。若服务器提供加密秘密草稿，需明确独立授权/有效期与secretPresence安全提示，普通GET不回显原文。续编先fresh当前对象/schema和权限，再diff，不把旧before当已确认写入。创建draft的lost响应用SQL父ledger，正式提交另产生配置计划/操作key。

## 3. M10 配置治理中心

路由提案`/governance`，标签巡检、Lint规则、环境漂移、Promote。模块`governance/lint/drift/promote`，报告只读与修复write/delete分离；有报告权限不获得秘密/native写权限。

### 巡检与问题证据

POST `/clusters/:cid/governance/inspections`创建真实有界job；GET列表/`:id`；GET `/:id/findings?severity&ruleId&type&size&cursor`按页问题。计划基于真实观察窗口/指纹和当前授权，不能直连Kong库制造孤儿，也不能把缺read权限当引用不存在。

```ts
interface GovernanceFinding {
  id: string; ruleId: string; severity: 'error' | 'warn' | 'info';
  confidence: 'verified' | 'suspected' | 'unavailable';
  entity: { type: string; id: string; name?: string };
  path?: string; description: string; evidenceSafe: unknown;
  observedAt: string; fingerprint: string;
  capabilities: { read: boolean; fix: boolean };
  fixKind?: string;
}
interface InspectionSummary {
  id: string; clusterId: string; workspaceId: string; revision: number;
  state: 'queued' | 'running' | 'succeeded' | 'incomplete' | 'failed';
  coverage: { types: string[]; scanned: number; pages: number; complete: boolean };
  counts: Record<'error' | 'warn' | 'info', number> | null;
  sourceVersion: string; observedAt: string; reasonCodes: string[];
}
```

报告展示confirmed/suspected/unavailable，source/时间、真实coverage与问题定位；每项fix先POST `findings/:id/fix-plan`只读预览，再当前typed confirmation按mode执行。固定serverfix handler+fingerprint，禁止浏览器提交任意patch脚本。批量修复同M9真实plan/DAG/父回执，孤儿删除也先进回收站。

规则保持真实1.5语义：

- 无SNI引用证书可以是Service.client_certificate，不能仅因无SNI即确定孤儿可删；证书/引用集合未完全授权或预算不足只能suspected。
- SNI、Plugin的外键引用通常由Kong限制，模拟异常fixture不证明正常可通过AdminCRUD制造。读取404/不可用与403分别记录，不将权限隐藏判断为无效引用。
- `Service.host`可以是合法DNS/IP上游，不等于现存Upstream.name时不能一律“无效引用”。只有明确配置的Upstream意图/引用证明才error，否则info/warn并解释。
- 实际1.5 schema无CA相关Service字段时不输出对应缺失错误；HTTPRoute不能填tcp sources/destinations，条件能力按真实schema。
- 命名唯一/409约束与host/path/method语义冲突分开；潜在route shadow结合正则/priority/其他条件，不能用重复path就断言409或完整冲突。
- owner/description来源真实console annotations或约定业务tag，不能凭空向Kong字段写description；默认工作区历史untagged、reservedtag多重/已删除归属的隔离状态单独报告。

### Lint规则和安全预览

候选GET/POST/PATCH `/clusters/:cid/lint/rules[/:id]`、DELETE/restore软元数据；POST `/:id/test`只读在固定已授权sample运行；PUTenabledsets需revision+当前whole-scope权限与mode。

RuleView `{id,name,given,then,severity,description,enabled,revision,source:'builtin'|'custom',capabilities}`。given为受限JSONPath，then为服务器固定验证器（例如required/enum/pattern/min/max/referenceExists），不是JavaScript/Lua/SQL/HTTP模板。运行有path深度/样本/regex/time预算，regex先安全验证，未知validator拒绝。Rule编辑提供samplemasked预览和具体字段错误，不用浏览器eval；atleast-one/conditional checks按record上下文，不遗漏nestedarray/map。

内置Route必须HTTPS、Service超时设置、owner tag、安全baselinePlugins都依据真实schema/default/运行范围；全局安全插件存在不代表它覆盖全部特殊绑定，治理结果需明确层级和适用范围。启用规则不会自动修改所有历史配置；“一键修复”始终独立审阅计划。

### Drift和Promote

双环境选择器只列表当前可访问的cluster/workspace/minimalService，scope保留两边CID/WID。候选POST `/drift/comparisons` `{source:{clusterId,workspaceId,scope,roots},target:{...},ignoreFields?:approvedIds}`；GET`/:id`和`/:id/changes`cursor；定时策略revision CAS，阈值/最近观察/下次计划时间都真实。未启用scheduler/数据源不可用显示未知，不是“无漂移”。不同fields/IDs映射按稳定业务身份和版本适配，environment override明确列出不比较字段及原因，不能隐藏差异冒充一致。

Promote候选POST `/promote/plans`同source/target加options。默认**不发布凭证、私钥或环境相关配置**；includeCredentials/secretOverrides只能明确勾选+当前两边独立secret/action授权，不因源read自动获得目标write。跨集群ID映射、工作区保留tag重编码、Service/upstream环境DNS/证书引用冲突在预览显式展示。来源其他scope依赖列为共享引用，不能带走额外实体。

POST `/promote/plans/:id/apply`原目标typed name+planHash+revision，按**目标**executionMode执行，target执行前快照ready。Source变了、target有并发写或授权撤销则409需新preview，不自动rebase发布。Portal/Metrics受管身份保持独立sealed策略，不能Promote历史Portal Key或environmentsecret到新consumer。partial/uncertain按target父回执锁定，不用源操作成功证明目标完成。

建议治理resolver `/clusters/:cid/governance/operations/by-key/:key?workspaceId=原WID`解析真实job/IAM/workflow/promote parent（最终Root冻结）。双scope回执包含immutable source+target tuple，浏览器currentselector不能改挂。完成仅完整目标steps证据，漂移对比成功只证明读比较完成。

## 4. M11 多级审批与计划执行

复用M6引擎，新增模板/审批阶段/窗口/定时execution策略，不新建可伪造`approved=true`旁路。页面：`/workflows`保留列表，新增看板/模板/变更窗口，`/workflows/:id`提供阶段时间线、immutablediff、影响、回滚方案和实际每步日志。M6单级Portal计划继续可读执行，不强行把历史plan改成多级。

### 候选模板和工作流DTO

```ts
interface ApprovalStage {
  id: string; order: number; name: string;
  mode: 'any_one' | 'all' | 'quorum'; quorum?: number;
  approvers: Array<{ type: 'user' | 'team'; id: string }>;
  selfApprovalAllowed: false;
}
interface WorkflowV2View {
  id: string; clusterId: string; workspaceId: string;
  kind: string; name: string; revision: number; planRevision: number; planHash: string;
  state: 'draft' | 'pending' | 'approved' | 'scheduled' | 'executing' | 'succeeded'
    | 'partial' | 'uncertain' | 'failed' | 'rejected' | 'cancelled' | 'expired';
  template: { id: string; version: number }; approvalRequired: boolean;
  stages: Array<ApprovalStage & { state: string; decisions: Array<{
    id: string; actorId: string; decision: 'approve' | 'reject'; reasonSafe: string;
    decidedAt: string; planRevision: number; planHash: string;
  }> }>;
  schedule: { executeAt: string | null; timezone: string; windowId: string | null;
    windowStart: string | null; windowEnd: string | null; nextAttemptAt: string | null };
  impact: { routeCount: number | null; qps: number | null; metricsObservedAt: string | null;
    complete: boolean; reasonCodes: string[] };
  rollback: { snapshotId: string | null; state: string; credentialsRestorable: boolean | null };
  capabilities: { read: boolean; approve: boolean; reject: boolean; cancel: boolean;
    execute: boolean; schedule: boolean; replan: boolean; rollback: boolean };
}
```

Stage/user/team/角色查找全部bounded授权IAMlookup。模板含固定已审核处理器、作用域/阶段数/审批人上限和windowpolicy，不允许任意URL/script/hook/actionrawpath。模板revision CAS，发布产生新immutableversion；已提交plan绑定版本/hash，不追随修改模板。super-admin也不能以UI flag自审被禁止计划。

同user多team不重复计票；会签/法定人数由server当前membership+distinctactor判，独立动作audit，不靠前端checkbox完成审批。stageonlyactive可决，后stage不能提前approve；拒绝/撤销保留历史，不删decision。每个decision绑定确切planRevision/hash，replan生成新版本并重新审批，旧票不能授权新diff。Delegation/审批人更换有明确修改计划规则，不能管理员直接patchapproved_by绕过。

影响面来自实际关联route和currentmonitoring grant；无流量权限/无sample给null+reason，不造0调用量误导审批。secret diff只安全变化，相关调用方/业务owner按当前授权提示。回滚材料执行前真实snapshotready；snapshotID存在不证明密码可恢复，BasicAuth不可恢复/受管Portal历史Key等blocker显示。

### 时间、窗口与调度

界面输入本地时间+IANA timezone，并显示明确UTC执行时间/窗口边界；夏令时不存在/重复本地时间要校验选择，不能浏览器时区默认悄悄换执行日。executeAt必须serverwithin有效window+planexpiry，窗口冲突由实际执行预算和目标transportScope锁生成。计划时间到但审批未完成、窗口关闭、权限/来源已变均显示blocked原因；“计划已登记”不宣称已经执行。

Scheduler不保管浏览器Cookie/JWT当长期执行权。Root需冻结专门可信worker/服务执行principal、固定最小role、当前审批和source/targetscope proof：每包前复核审批stage/definition/planHash、实际currentactor/权限、before、ready快照和lease。普通外部HTTP不能创建内部frame/capability，计划也不能凭旧superAdmin claims执行。审批账号/角色撤销是否使既有计划无效由明确serverpolicy列出，并保守fresh验证；不在前端决定绕过。

到点CAS认领和分布式lease确保只有一个execution；前进状态和每stepreceipt先durable，再发原生包。Worker崩溃/网络失联scope保持uncertain/fence，不自动重新发DELETE/Keycreate；只原plan/key/实际graph GET核验后明确解除，不能多worker以新key各执行一遍。window到期时native已发步骤保留真实部分结果，不假回滚到未执行。

### 候选HTTP与确认

| 方法/路径提案 | 语义 |
| --- | --- |
| GET/POST/PATCH `/clusters/:cid/workflow-templates[/:id]` | currentwhole-scope read/write、revisionCAS；发布新模板版本，软delete/restore |
| POST `/workflows` | 固定已支持kind、explicitroots/desiredpublicfields、templateVersion、schedule；server编译immutableplan，不能客户端上传nativepermissioncapability |
| GET `/workflows/:id`、`/:id/steps`、`/:id/decisions` | masked分段/cursor，不因v2扩展全量日志body |
| POST `/:id/stages/:stageId/approve|reject` | revision、planHash、reason、typedname、confirmed；currentstage/actor/quorum核验 |
| POST `/:id/schedule` | revision、planHash、executeAt、timezone、windowId、confirmed、confirm_name；只登记，不自动提前execute |
| POST `/:id/execute` | currentactual执行权限+全部批准/窗口+immutablebefore，沿用M6privatecapFactory |
| POST `/:id/cancel`、`/:id/replan` | 原revision/hash、confirmedname；只terminal允许取消，新计划重新审批，不抹历史 |
| POST `/:id/rollback/plan`、`/rollback/execute` | 只读预览后当前确认/审批执行；不是点击立即覆盖所有配置 |
| GET `/workflows/receipts/by-key/:key` | 原actor/CID/WID/key，action含stage决策/计划登记/执行/回滚，分别durableproof |
| GET/POST/PATCH `/clusters/:cid/change-windows[/:id]` | whole-scope策略、UTC/IANA/规则、revisionCAS、软删除；不受客户端approvedflag影响 |
| GET `/workflows/board` | server当前授权“待我审批/我提交/计划待执行/逾期/窗口冲突”真实count和bounded列游标 |

详情按钮以capabilities为准；待我审批仍需要真实activeStage，而非只`workflows.approve`粗菜单。approve默认不同时execute，若明确勾选并具备当前execute能力则再次说明不同阶段。执行/回滚/窗口批量修改都有typedtarget/影响diff二次确认。审核原因是当前安全文字，不允许secret/rawHTML；未知决策用原key确认decision完成，不能因为一个decision完成清掉尚未执行的parent锁。

计划登记、审批决定、全部批准、executionclaim、nativeACK、父成功、rollback成功、通知投递都是独立状态/回执。M7通知中心只展示真实事件结果，approval成功不发“配置已完成”，投递失败也不倒改已执行业务成功。看板不以当前页推估总量，缺权限列隐藏，unknowncount不填0；拖拽只导航或经过正式transition确认，不能拖动卡片直接改state。

## 5. 各阶段源码与真实验收

M9拟议source：ToolboxPage/RouteDebugPage/BatchPlanPage/DraftsPage及对应typedhelpers；M10GovernancePage/LintRulesPage/DriftPage/PromotePlanPage；M11WorkflowBoard/TemplateEditor/StageTimeline/ChangeWindows和v2详情。均在各自正式release后创建，不预先activate所有导航。当前M6manual计划保持 [M6-manual-ui-plan.md](m6-manual-ui-plan.md) 不变。

源码意味测试重点：exactreview-vs-writeclassifier、完整4维授权/迟到actorscope、cachekeypath拒绝/当前node范围、Routerapprox-vsverifiedconfidence、probestatus401不刷新Console、secretrequest不存draft、batchDAG/原key/partialstate、Lint预算/proto/noeval、ServiceDNS合法不误判Upstream缺失、跨环境paircache和credentials默认排除、stage去重票/不同plan票失效、UTC/DST/window边界、decision≠executionproof、missingsnapshot/credentialrecoverability不能unlock。

真实逐阶段门禁由Security独占HTTP→browser，再Frontend人工desktop/mobile/typed确认，最后BFF-onlycleanup与运行时secret扫描。M9需真实/status/cachekey失效、真实代理探测与复杂Router对照、批量每对象audit、draftownerIDOR；M10用可通过白名单布置的坏配置或隔离解析fixture检出confirmed问题，不非法改Kong数据库，真实Lint/fix/archive/Drift/Promote验证；M11实际两级/会签/同人多team不重复票、计划窗口/跨时区、撤权和worker崩溃、一次native执行、前置快照/rollback代理认证及通知全链路。

稳定testids提案：`toolbox-status-quality`、`cache-result`、`route-debug-confidence`、`proxy-probe-timings`、`batch-parent-state`、`draft-row-ID`、`inspection-coverage`、`governance-finding-ID`、`lint-test-result`、`drift-change-ID`、`promote-source-target`、`workflow-stage-ID`、`workflow-board-column-state`、`workflow-window-conflict`。没有实际样本/权限时显示reason，审计/截图不含原请求秘密或第三方响应secret。

每阶段结果明确区分mock/unit、实际Kong/proxy/provider、worker调度和UI人工验证；已观察报告和执行回执不能替代全功能商用声明。未来未冻结provider/scheduler/crossenv受管规则仍记录限制，不能为提前展示功能隐藏真实blocker。
