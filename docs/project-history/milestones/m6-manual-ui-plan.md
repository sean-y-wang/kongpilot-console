# M6 手工 UI 验收计划（源码准备）

状态：**只读源码准备，不代表运行时通过**。运行需要 Root/Security 明确报告真实 HTTP 和浏览器全部通过，并把独占 manual 窗口交回 Frontend。当前没有登录、API 调用、截图、构建或写入。M6 产品源码保持冻结。

## 1. 前置条件与证据

- 真实部署 Console `http://127.0.0.1:8080`、独立 Portal `http://127.0.0.1:8082` 均 healthy，实际 bundle/hash 由 Devops 给出；不在手工阶段重新构建或切换 asset。
- `artifacts/M6/security-live.json` 与 `browser-verification.json` 的最终 failed 均为0，保留原 failed-harness 证据，不覆盖假装不存在。只读确认 fixture 与 scope 身份，不执行 harness 再播。
- 私有引用 `/tmp/kongos-m6-runtime-secrets.json` 已存在且 owner/current UID、0600、普通文件、非 symlink，通过现有 `privateReference()` 读取。**本轮主集群取当前 `reference.fixtures[0]`（隔离 C3）、次集群取当前 `fixtures[1]`（C2），不能硬编码UUID或复用 `priorFixtureRuns` 内C1/旧角色。** 公共 `fixturesForBrowser` 的 CID/WID/tenantSlug 必须与当前主fixture完全一致；当前testTag必须与最终HTTP报告一致。
- `developer-a` 按 label **以及当前tenant CID/WID**共同选择；`approver-only` 从当前 `accounts` 选，并核验role/binding CID/WID与当前主fixture相同。凭证先按当前 `activeCredentialId` 精确定位唯一 `tr[data-row-key]`，再取最近的 `ant-card` 祖先并核验实际 `publicationName`；同一 API 可同时保留当前及已吊销/已封存申请，不能按出版名称取整页第一张 Card 或要求名称只出现一次。当前 `activeGrantId` 用于完成申请定位，不能取旧grants数组first元素；已完成workflowId来自当前browser报告/当前fixture引用。密码只在进程内传给input，不打印、不作为失败断言实际值。
- 不新建或扩大 IAM permissions，不新建 cluster/workspace/Service/Route/Consumer/Key/ACL。既有 active grant 留给 Security sealed retireConsumer 清理；手工不做默认 revoke 后遗留 managed Consumer 的配置绕行。
- 最终安全报告 `artifacts/M6/UI-review.json` 包含 performedAt、checks、passed/failed、allPassed、screenshots、auditCoverage、testTag、fixtureJournal、workspaces、pageErrors/AdminRequests/missingScope。未运行项写 notPerformed 和理由，不制造 runtime PASS。

## 2. 独占顺序与具体检查

桌面 viewport 1440×960，移动端390×844。优先只读，新增对象只允许当前已证明 testTag/workspace 的非原生 Markdown 内容，所有写都从实际 UI/BFF 完成。

| 编号 | 操作与观察 | 成功证据 / 写边界 |
| --- | --- | --- |
| U01 | 匿名 `/apis?tenant=<实际 slug>`，目录与品牌及筛选 | 捕获当前 CID/WID 的真实分页 GET、安全 publication DTO；有实际分类时 DOM 输入该分类，无分类时保留全部分类并搜索实际已发布 API 名称。再次核验 GET query/返回对象/DOM 名称、未知总数及实际 scanIncomplete，留 `manual-portal-catalog-filter.png`；不创造分类元数据 |
| U02 | 打开实际 publication 文档 | `portal-document` / 文档标题与 METHOD/PATH 列表，认证范围 whole-Service 文案，无外部引用请求或 TryIt |
| U03 | 查看注册表单后不提交 | “待管理员审核后才能登录”说明，开发者与控制台账号分离；无新账号 |
| U04 | developer-a 实际登录 | `开发者账号`、`密码`、`登录开发者门户`；app入口成功，私有 Cookie/CSRF 加入0600引用 |
| U05 | owned应用已授权凭证 | 仅 `portal-credential-masked` 为••••••••；按 current B `activeCredentialId` 唯一行定位最近 Card，再核验出版名称，旧 grant 不误选 |
| U06 | 应用状态与撤销语义 | “停用 / 吊销”按钮、旧Key不恢复/新申请文案；不提交 revoke，不改变 Security active fixture |
| U07 | 轮换/吊销 typed确认只读 | 打开相关确认，填写错误名称执行禁用，正确名称仅检查按钮可用后取消；不点击确认执行 |
| U08 | 浏览器 reload 同一应用 | authenticated CSRF/me 恢复，保持同 developer/CID/WID；不删刷新Cookie或人工重复Security已做的真实 refresh oracle |
| U09 | 我的申请列表/已完成申请详情 | `portal-request-state`、实际步骤，approved≠有效key提示；游标 prev/next，没有伪 total |
| U10 | Portal profile | readonly username/email、displayName/currentPassword/newPassword可见，密码字段空；不修改密码和既有账号资料 |
| U11 | Portal手机应用/目录/文档 | 安全标题、换行/横向表格在局部，密钥面板关闭、390px布局可用 |
| U12 | Bootstrap Console 登录已捕获CID/WID | 显式选择同真实test workspace，API每次scope正确；不依赖默认工作区猜测 |
| U13 | `/portal` API发布列表 | 实际 publication名称/status/documentRevision，动态 current capability与whole-Service提示 |
| U14 | API编辑只读 | `配置 / 文档` Drawer，slug与授权Service不可改；真实文档可安全预览、upload不自动提交，不点生成文档/保存 |
| U15 | 开发者 / 应用 Configuration 和授权、申请关系 | owner唯一UUID行打开开发者详情，GET响应ID/CID/WID与安全DTO字段白名单一致、DOM Configuration逐项回显；当前应用唯一UUID行打开详情，GET核验developerId/capabilities并显示配置。授权tab只读分页GET，精确current activeGrantId行及publication，保留历史授权；申请tab只读分页GET核验应用/grant/publication/原CIDWID及actual workflowId、completed状态与`/workflows/:id`链接，不以点击tab替代验收。四张独立截图；不审核/停用/恢复/执行/读取Key |
| U16 | 门户设置表单 | 真实slug、品牌logoText/welcomeText/颜色和公开地址，不保存、不改公开入口 |
| U17 | 完成工作流详情 | `workflow-state`=已完成，安全 diff/impact/step回执，direct无批准记录，不用业务entityID导航 |
| U18 | approver-only 控制台只读复核 | 真实账号看同授权工作流，执行按钮缺失/禁用，未提升角色；如无符合current status对象明确只读结果 |
| U19 | Markdown新增编辑器 staged确认 | 精确title=`<testTag> Manual UI Page`、slug=`<testTag>-manual-ui-page`，safeMarkdown；输错“确认名称”时执行禁用，取消不发POST |
| U20 | 同一新增页面 typed确认并保存一次 | direct POST `/portal/pages`；捕获actual business entity.id≠顶层workflowId，receipt.state=succeeded，notice为执行完成/配置生效中；记录原key/请求ID/实际对象ID |
| U21 | notice父工作流链接 | 当前workflows.read时 href=/workflows/顶层UUID，永不使用页面entity.id；点链接查看真实plan。Portal-only无link的runtime只有存在已授权现成角色才测，否则保留unit覆盖不制造新角色 |
| U22 | 新页面发布一次 | fresh revision，typed title二次确认，POST `pages/:id/publish`；原父receipt成功后才公开 |
| U23 | Portal公开新页面 | `/pages/<实际 slug>`真实安全内容，断言h1标题、inline code `x < 2`、strong强调及Markdown容器无script；恶意HTML由后端拒绝的既有unit/HTTP证据覆盖，不称创建后sanitize，不发新恶意请求 |
| U24 | 新页面软删除一次 | typed title，DELETE `pages/:id`；回收站可见，匿名公开404/不可用；请求ID审计和普通删除区别于purge |
| U25 | 新页面从内容回收站恢复一次 | fresh revision，typed title，POST `pages/:id/restore`；恢复draft、不承诺自动公开；该对象留给Security后续BFF清理 |
| U26 | Console手机Portal列表/工作流 | 390×844，侧栏可开闭，长safeUUID/diff不撑破整页，按钮/确认可用 |
| U27 | 原始key recovery现成证据 | Security已完成应用失响应原key核验；若已清ref只读取其report，不重新POST造未知写；手工任何未知写仅dedicated原keyGET |
| U28 | 收尾检查 | pageerror0/Admin8001browser请求0/Portal请求无Consoleprefix/privatescope不缺失；截图没有Key/密码/CSRF/认证header |
| U29 | 审计读取 | 所有成功productwrite requestId用SQL只读查audit，覆盖100%；login/logout/refresh实际写亦统计独立操作类型，不把不存在requestId写成成功 |
| U30 | 明确交接 | 最终UI-review allPassed与真实checks一致，截图稳定、私有引用含所有新cookies、新增Markdown对象journal；通知Root/Security MANUAL_WINDOW_RELEASED |

U20/U22/U24/U25 合计四次新内容元数据写，均无原生网关变更；真实验证发现 known 409/CAS 等则先读取当前对象与原回执，不盲重试。任意未知中断停止后续同scope写入，保留key，并向Root报告安全status/code/原父receipt。删除/恢复成功可能201或其他标准2xx，以当前DTO/实际body核验，不因仅期待200而误报产品失败。

已准备执行器 `tests/security/manual-m6-ui.mjs` 与前置 journal `tests/security/lib/m6-manual-journal.mjs`，当前只有源码与合成单测验证，没有运行时结果。程序在读取私有引用或启动浏览器前要求明确的 `M6_MANUAL_READY=true` 独占窗口开关，并检查当前 HTTP/browser 终态报告与动态 fixture 身份。任何已存在的 `manualJournal` 或手工写入尝试都会阻止从头再播；中断后只能依据已保存的原 key/实际对象 ID 继续只读核验或精确后续阶段。当前审批账号用真实登录响应的 displayName 校验身份显示，不把用户名和显示名称误当同一字段。

### Chromium 启动与原零请求失败续行

首次实际启动在浏览器创建前失败，原公开报告保留为`artifacts/M6/UI-review-pre-launch-attempt.json`，SHA256固定为`eb7a57f7675f56ea5ebd1c6cc7dcba9c462b9a463e75ceb5189f7622d73d1f4b`。该次为preflight/Error、计划请求0、成功请求0、匿名刷新0、截图0、actions空；它不是完成的手工验收。原152源码证据及所有此前FAIL保留。本轮源修复不代表再次实际启动通过。

直接调用Chromium不会自动继承Playwright配置，因此手工runner显式采用相同启动策略：优先`CHROMIUM_EXECUTABLE_PATH`，否则仅当`/usr/bin/chromium`存在时使用该路径，其余情况保留正常bundled行为。路径选择单测只使用fake env/exists，不读取实际环境或启动浏览器。

Root仅授权此确切零请求失败的受控续行：除原`M6_MANUAL_READY=true`独占窗口外，还须明确`M6_MANUAL_ZERO_PACKET_CONTINUATION_READY=true`。纯门禁校验原FAIL完整bytes的固定SHA、actual-manual/preflight/唯一Error与全部零计数；当前私有旧journal须stopped-without-replay/manual-harness-stopped、nextIndex0、inFlight/pageId/pageRevision为空、authenticated/freshContexts/attempts为空，manualMetadata/WriteAttempts/WriteEvidence为空，并与当前可信三账号、C3集群/工作区、testTag及原内容意图完全一致。普通已有journal仍拒绝；任何非零尝试、foreign scope、旧continuation/history标记或更改报告都拒绝，不能续行登录或业务操作。

首次续行`retain`在同一次0600+fsync原子写中封存完整四份旧字段到`manualZeroPacketHistory.snapshot`并记录SHA，同时写入`manualZeroPacketContinuation`消费标记和新活动journal。旧stopped状态不在原地重置，其他历史/旧秘密/全局writeEvidence完整保留。后续保存验证相同history SHA、marker和activeJournalStartedAt；程序重入发现标记即拒绝，包括第二次零请求启动失败。保存失败或历史改变时不启动浏览器、不放出请求。新活动journal仍只允许原七个首次计划包及原有至多三次已知401匿名启动例外，源修复不增加预算、不重播原业务、不删除原记录。

### 发送前留证与限次范围

Root明确允许在尚未发出任何计划业务包之前，仅修改未来页面的Markdown为安全文字和inline code `x < 2`，title/slug保持原样。后端`PortalDocumentService.markdown`真实方法的内存测试证明新正文接受、原`<script>`意图以`PORTAL_MARKDOWN_UNSAFE`拒绝。续行prepared显式区分`originalContent`与`plannedContent`：旧两窗script正文按原样封存并校验，新活动journal绑定新正文；marker含`plannedContentSha256`，后续正文漂移拒绝。发布后的实际DOM验收只核对真实安全结构，不声称恶意HTML被sanitize；删除/恢复验收保留。

第二个实际窗口仅完成初始目录GET安全DTO核验，随后因`Input.Search`隐式searchbox与旧textbox定位不符停止；已改为实际aria-label的`getByLabel`定位，无产品改动。原报告另存`UI-review-pre-catalog-filter-attempt.json`，SHA256为`cce8f501b35e235f3958fe294f057f8603bccabe10934a89302eb6429d356d0e`，计划/成功业务请求及截图均0，仅一次真实owner匿名刷新401（requestId `89ddccd6-23ac-43cc-98b7-482b9fad6bc9`）。Root只允许明确`M6_MANUAL_CATALOG_FILTER_CONTINUATION_READY=true`的新首次业务窗口，不能同时启用旧zero续行标志；纯门禁绑定此原FAIL、原目录scope/publication、可信三账号、唯一已知401完整原body/key/query和旧zero历史。首次原子保存将这些原事实完整封存到`manualCatalogFilterHistory`并消费唯一marker，旧zero history/marker不改、不重新绑定新startedAt；重复入口、任何已发送planned、未知结果或历史变化都拒绝。新fresh contexts的正常匿名启动仍按原known401预算记录，旧401不算成功登录/元数据，不允许无限续行。

所有 `BrowserContext` 在创建页面前安装 `route` 边界。只有当前 owner、原 Console administrator、当前 approver-only 的三次首次登录，以及同一新增 Markdown 页按「创建→发布→软删除→恢复草稿」顺序的四次内容变更可放行，每一步只有一次网络包预算。登录 actor 的 ID 与账号来自既有可信引用，响应还须证明相同实际身份；页面 ID 必须来自原创建成功响应的唯一新 UUID，后续路径与 CAS revision 只能使用已核验的响应值。请求端点、origin、方法、全部 query、全部原始 JSON body/解析 body、原幂等 key、header、actor、CID/WID 都在放包前写入私有 journal。原始请求体也参与响应/中断事件匹配，不能把同 key 但不同正文的请求合入原回执。

私有文件写入使用独占 `wx`、0600 临时文件，先 `fsync` 文件再原子替换，最后 `fsync` 父目录；完成这些步骤后才允许 `route.continue()`。保存失败、重复包、错误身份/范围、已知失败或未知结果会停止整个手工窗口的后续非 GET 请求，包括其他 context；允许继续只读核验原 key，但不自动重放、不另起 retry key。任何新秘密、Cookie、旧 reference properties/history 都完整保留给最终扫描，公共报告仅记录安全的 action/state/status/requestId。

Root 另行明确允许真实客户端的匿名启动例外：每个全新 context 在其首次登录前，至多一次自动 `POST /auth/refresh`，与七个计划包分开记录为 `anonymous-bootstrap`，实际 actor 为 null，expectedLoginActorId 为可信的待登录账号。Context 创建后须实际证明 cookiejar 为空，放包前再次核验 cookiejar 与原 Cookie header 均没有任何 Console/Portal access/refresh Cookie；登录包前也重新核验，不能携带旧会话。只有真实 HTTP 401、确切 `PORTAL_SESSION_EXPIRED`（Portal）或 `SESSION_EXPIRED`（Console）且有实际 requestId 才允许继续该 context 的首次登录；任何其他结果仍停止全部后续写入。Console 匿名启动通常在 GET csrf 的 401 处停止，没有 refresh POST，不得人为制造。Portal 匿名目录/文档/注册/登录之间使用真实 DOM 的 SPA 链接，避免重复挂载带来第二次启动刷新；登录后的整页应用导航与 reload 仍保留，以验证租户与会话恢复。最终报告记录实际拒绝次数 0–3，不能预填为 3，也不把拒绝刷新算作成功业务写入或原生变更。

## 3. 当前稳定选择器与路由

| 页面 | 稳定入口 / 标签 |
| --- | --- |
| Portal目录 | `/apis?tenant=slug`；`portal-catalog`，搜索API、分类（实际catalog表单） |
| Portal登录 | `/login?tenant=slug`；开发者账号、密码、登录开发者门户 |
| 应用 | `/applications/:id`；刷新授权状态、编辑应用、`portal-credential-masked`；当前凭证唯一 `tr[data-row-key=activeCredentialId]` → 最近 `ant-card` → 核验 publicationName |
| 凭证轮换 | 轮换；dialog 确认申请轮换凭证；确认名 `轮换 UUID` |
| 停用/吊销 | 停用 / 吊销；dialog 确认申请停用 / 吊销凭证；确认名 `吊销 UUID` |
| Portal确认 | `PortalConfirmation` 的确认名称与确认执行；AntD双字button文字用空白兼容regex；取消不提交 |
| 临时密钥面板 | 临时查看 API Key、Input.Password 临时 API Key、关闭并清除；此计划不打开，任何截图都先断言dialog数为0 |
| Console工作流 | `/workflows/:id`；`workflow-state`，刷新状态、审批原因；批准变更 / 执行已确认计划由真实能力/状态控制 |
| Console门户 | `/portal`；API 发布、开发者审核、应用管理、Markdown 页面 / 回收站、门户设置 |
| Markdown创建 | 新增 Markdown 页面；页面编码、标题、Markdown 内容；Drawer保存页面 → Modal确认名称 / 确认执行 |
| 内容状态/回收 | 门户页面状态；当前页面 / 页面回收站；发布 / 撤回 / 移入回收站 / 恢复（双字AntD有空格） |
| 门户设置 | `portal-admin-save-settings`、公开门户编码、门户名称、品牌标题、主题颜色、欢迎文字；只读不保存 |
| 原key核验 | 核验操作、门户操作核验结果；Console按kind走Portal/Workflow dedicated parent路径 |

下拉使用确切 outer `.ant-select` class-token ancestor 的 `.ant-select-selector`，不能选祖先 `.ant-select-dropdown` 或FormItem。路径拦截使用 URL.pathname判定，不能漏掉显式CID/WID query；原key使用request header捕获一次。假如实际同名控件重复，限定visible Drawer/Modal/Card scope，不反复更换产品selector。

## 4. 私有引用、审计与安全截图

所有响应Set-Cookie和浏览器cookie值合入现有0600引用，保留原properties/writeAttempts/secrets/accounts/grants/fixtureJournal不覆盖。发送前完整正文（登录正文含私有密码）与原 key/method/path/query/CID/WID/actor/start/outcome保存在仅私有的 `manualJournal` 与 `manualWriteAttempts`；成功响应的 requestId 另加 `manualWriteEvidence`，并按requestId去重追加到最新`writeEvidence`，使最终cleanup审计包含三次成功登录及四次内容变更。原历史行（包括原重复行及失败/不确定历史）不改写、不删除，同requestId的method/path/status冲突停止后续写入，不用最后一行遮盖冲突。匿名认证缺失401不加入成功分母。这些正文、header、Cookie 不进入公共报告或截图，当前及原有秘密集合均保留供最终扫描。新Metadata创建实际ID加入 `manualMetadata` 与最终公开UI-review fixtureJournal（没有配置正文、密钥或Cookie）。不要删除现有ref，让Security在清理+终扫后统一处理。

安全截图包括：`manual-portal-catalog-filter.png`、`manual-console-developer-configuration.png`、`manual-console-application-configuration.png`、`manual-console-application-grants.png`、`manual-console-application-requests.png`，以及原`manual-console-portal.png`、`manual-console-page-confirmation.png`、`manual-console-parent-workflow-notice.png`、`manual-portal-document.png`、`manual-portal-owned-application.png`、`manual-portal-mobile.png`、`manual-console-mobile.png`。图片只包含已授权安全业务数据；没有自动Playwright失败trace/video/screenshot。截图前关闭所有秘密查看dialog并确保输入密码为空，先window.scrollTo(0,0)并等待顶部稳定，避免sticky导航从fullPage中部出现；不覆盖既有tail截图。失败现场若可能有secret则仅记录安全status/code/boolean，不保存整页。新`readEvidence`仅记录kind/path/requestId/原CIDWID/对象UUID/分页项数/真实筛选状态，不保存完整DTO或认证内容；凭证审批需求按实际approvalRequired显示，不从集群executionMode推导。

审计通过现有 `docker compose exec -T console-api node` + `pg` **只读 SELECT**，参数经stdin结构化JSON传入，使用 `audit_events.request_id=ANY($1::text[])`。原UUID不split/重编码；不使用 SQL mutate、新admin凭证、直接Kong数据库。三次成功登录和四次成功内容变更都须 requestId 100% 命中。可选的匿名启动认证缺失拒绝单独记录 requestId 与拒绝代码，不要求伪造成功审计或将其算入成功写入分母。记录distinct requestId数和实际命中，不以“页面无报错”代替审计。首次harness selector/状态码误判保留 pre-contract JSON，实际产品失败不通过改期望掩盖。

最终提交清单和显式窗口交接后，Security已获授权进行BFF-only fixture退役与最终运行时秘密扫描；Frontend不并行cleanup、不使用通用Consumer/旧Key回收恢复绕过Portal历史受管边界，不新增M7代码。当前与历史私有properties（包括priorFixtureRuns）始终保留供最终扫描，但不当作本轮可操作对象；不能覆盖旧运行时秘密或清理canonical C1/监控设置。

## 5. 第三次停点的剩余五步窗口

原真实结果 `UI-review-third-attempt.json`（SHA256 `85df06d7c7da28037b857c8fe68211e0e113cf348b9f73add1a914b3e02791b9`）保留 25 PASS、1 FAIL、5 张截图、3 个安全 GET 证据，只有一次已知匿名 401 和两次成功 201 登录。失败来自手工 `Descriptions` 定位器：`has` 内再次包含祖先 Drawer，无法从当前 `tr` 相对匹配。仅修改测试为唯一精确标签 `th`→直属 `tr`→内容 `td`，产品 Drawer/testid/字段显示保持原样。

Root 仅授权明确 `M6_MANUAL_READY=true M6_MANUAL_DETAIL_REMAINING_READY=true` 的一次剩余窗口，与旧 zero/catalog 标志互斥。门禁绑定确切失败完整 bytes、当前原三账号/集群/工作区/内容、stopped `nextIndex=2`、两次原成功登录、一条确切 known401、空 metadata/null inFlight/no unknown；原包通过真实 guard 只在内存验证，绝不重新发送。原完整 journal、key/body/header、成功证据、失败 bytes、两层既有 history/marker 在启动前同一次 0600+fsync 原子保存中封存，消费新唯一 marker。活动 journal 延续原始 attempts、authenticated、startedAt，仅允许四次尚未执行 Markdown 写和一次 approver 首次登录；重入、历史改变或任何未知结果都停止。

Portal owner 与 Console administrator 从原私有 Cookie 候选恢复当前原会话；独立只读 recovery reader 在 API 进程 RAM 验证 JWT 签名/实际 SID、当前未撤销 session、两次原登录 audit 与时间窗、refresh/CSRF hash，仅返回索引与安全 proof。恢复后真实 GET `/auth/me` 再校验原 actor/CID/WID，禁止重新登录。Root 另明确允许每个 restored role 至多一次、且只有 reader 的 `accessExpired=true` 时由真实客户端正常发起的同 SID refresh，独立记为 `continuation-session-refresh`，不推进七个 planned intents 的 `nextIndex`。原 Cookie/header、CSRF、body、scope、key 先私有持久化再放包；真实 2xx 必须证明当前原 actor 和同 SID 新 Cookie，Portal 新 CSRF 对齐响应。失败、异 SID、缺失响应或保存失败全局止发；未过期不主动刷新，不伪造刷新响应。

## 6. 原发布回执确认后的最后三步

第四次失败 `UI-review-pre-publish-receipt-attempt.json` SHA256 `707dcb2d00dbc9c640927b4cc9eba28091ead01f704ef4050f36355795c80211` 完整保留：50 PASS、11 张截图、7 条只读证据；publish 201 原包已由 Security 的只读诊断 `manual-publish-original-receipt-readonly-diagnostic.json`（SHA256 `82b89a7a6c7bb7232eeb37065fab9e481a6ca294a5527f9cd8483021a6836abc`）证明原 IAM 操作成功。产品已有对象的直接执行返回 `{entity}`；创建页面才返回复合 Workflow 回执。旧测试错误地要求发布也有 Workflow，不修改产品、不重发创建或发布。

唯一入口 `M6_MANUAL_READY=true M6_MANUAL_PUBLICATION_TAIL_READY=true node tests/security/continue-m6-manual-publication-tail.mjs` 与旧三个续验标志互斥。启动前原子封存全部旧 journal/包/证据/失败 bytes/history，消费一次 tail marker。原发布先用原 actor、原 key、CID/WID 的受保护 GET 核验真实 IAM 完成与安全 entity，才推进到归档、恢复草稿、审批账号首次登录这三个未发送意图；已有对象后两次写入也先保留 ACK 锁，再只读核验原 IAM 回执。未知、漂移、保存失败或重入全局停止。

原 owner/admin 仅恢复原 SID 的最新 Cookie，尾入口不刷新也不重新登录，过期即停止。Root 另授权 Security 在入口准备前、有效期不足 90 秒时进行独立一次正常会话续期：私有 `manualTailSessionRenewal` 必须 `state=completed/authWrites=2`，公共 `manual-tail-normal-session-renewal.json` 必须 SHA 一致、两次 auth 写有审计、零业务/Native/login/reveal。完整续期私有历史保留；tail 只输出安全计数与报告 SHA，独立列为外部 authWrites，不计入原七意图或两次旧刷新。

新截图只用 `manual-tail-*`。Admin 可查看原创建工单已完成；仅 workflows.read/approve 的 approver 没有 portal.read，原页面工单应返回精确 `PERMISSION_DENIED` 403，UI 显示权限拒绝且不显示计划/执行按钮，不增加权限。成功包按原请求 ID 查审计；当前直接 IAM 只有 requested/pending 审计，不能宣称验收第 11 条终态 before/after diff 完成，终态审计补齐留在 M7。

组合报告继承原 25 PASS/5 screenshots/3 readEvidence 和两次成功登录审计，原 FAIL 完整保存在 immutable archive 与私有 history；新的只读重复仅核验当前真实 DOM。新增截图使用 `manual-remaining-*`，不覆盖旧五图；后续审计包含原两次登录、剩余五次 planned 成功包及实际出现的同会话刷新，分开统计刷新与已知匿名拒绝。最终预算仍为七次 planned，仅新增已授权的至多两次原会话刷新，不允许 Native/reveal/IAM 或其他业务写入。Frontend只完成源码门禁与聚焦内存测试；实际命令只由 Security 在 Root 最终 gate 后运行。
