# 普通 EntityChange V3 真实验收执行合同

本交付只有验收 Source。作者未读取私有 ledger/PKI、未发送 HTTP、未执行 SQL/gh、未修改 Root Source 或运行环境。Root 是唯一实际 operator。纯测试中的 HTTP/SQL 行、网络响应与审批适配均为受控夹具，不是现场证据。测试用 PEM/私钥是新生成并公开的合成夹具，**不得用于真实验收**。

## 执行前的精确合同

平台已由 Root 部署并检查 ready；本脚本不部署、不升级、不调权限。Root 给脚本环境提供：

| 变量 | 值/用途 |
| --- | --- |
| `RELEASE_LAB_READY` | 原 ReleaseHarness 的 `true` 门禁，沿用原 API/private/report 绑定 |
| `RELEASE_LAB_M11_CURRENT_ORDINARY_V3_READY` | `true`，Root 本次显式授权 |
| `RELEASE_LAB_M11_CURRENT_ORDINARY_V3_DEPLOYMENT` | 下述 JSON；不是权限票据，只是 operator 的验收版本记录 |
| `RELEASE_LAB_M11_V3_CERT_FILE` | Root 已生成的 **绝对** certificate.pem 路径，仅 init-fixtures 时读取 |
| `RELEASE_LAB_M11_V3_KEY_FILE` | 同组 private-key.pem **绝对**路径；常规单链接文件、当前执行UID拥有、group/other权限为0，仅 init-fixtures 时读取 |
| `RELEASE_LAB_M11_CURRENT_ORDINARY_V3_CASE` | 可选的新验收批次标识，必须与下面的夹具字段同时提供；不填写时选择原批次 |
| `RELEASE_LAB_M11_CURRENT_ORDINARY_V3_FIXTURE` | 新批次在 `metadataAcceptance` 中明确选择的夹具字段，包含五个原 M9 对象 ID |

部署 JSON 字段：`operatorConfirmed:true`、`noUnknownReplay:true`、`productPatchSha256:"4a3a0f510d8bb6541111ee0b93eb358777b929906da746aede8d8f06d4d61f7f"`、`deployedSourceDigest`（Root 当前真实部署的完整64位 Source digest，当前已知前缀4118a2be，**不能补造剩余部分**）、`deployedAt`（实际部署时间 ISO）。后续各阶段必须沿用同一个产品patch和Source digest。

PKI 固定 CN/SAN：`kongpilot-v3-acceptance.invalid`。脚本验证 X509 与私钥匹配及该 SAN。读取仅在 Root 实际调用 CLI 时发生；不用把私钥或证书发给作者。Root 当前私有 PKI 路径由 Root 自己填入环境，不写入本手册。

采用 `new ReleaseHarness('M11',{resume:true})`。默认沿用原字段 `currentOrdinaryV3Acceptance20261018`，读取原 `cid/wid/sessions.admin`、`metadataAcceptance.reviewerSession` 和 `metadataAcceptance.m9PcreNativeActual20261018`。显式新批次使用独立字段 `currentOrdinaryV3AcceptanceCase_<caseId>`，生成独立凭证、请求键及阶段记录，并固定夹具选择与部署摘要；不会覆盖或续跑旧失败。两个会话必须真实且不同用户，access token 还剩至少120秒；脚本不登录或 refresh。

旧批次仅在 `init-fixtures` 阶段停止、尚未开始任何图变更时，新批次可以重新核验并使用同一组只读 M9 对象。只要旧批次开始过后续阶段，即使状态为失败或已恢复，也禁止共享任何一个图对象，新批次必须另建专属夹具。已分配的批次和阶段不能重新执行。

集群必须是1.5.x、approval模式；当前 native-change 必须是 format2、单级 any/threshold1、禁止自审、唯一指定当前 reviewer 的策略。脚本只验证策略，不修改策略或IAM。

M9 原夹具必须含 upstreamId/targetId/serviceId/routeId/pluginId。init 前会真实查询其当前对象和完整 Target history，要求该验收Upstream只有那一条原 Target 历史且仍 active；不接受把未知、已退役或权重0历史行冒充当前 Target。若此前别的验收已改这个Upstream，**先停下由 Root 重新决策；脚本不会修改 M9 域、补造active行或替换原ID**。

## 先完成五类回收闭环

Root 逐条执行，不能用自动 for 循环略过失败。每阶段使用独立新label/key，每次操作走真实 prepare→submit→detail当前 level/stageRevision/candidateVersion/revision/planHash→独立 vote→approved→execute→最终 detail 原201/204。不缓存投票tuple。

`node tests/security/m11-current-ordinary-v3-acceptance.mjs <stage>`

顺序：

1. `init-fixtures`：原 M9 对象只读；新 Consumer 一包、六种凭证一批六包、新 Certificate 一包、新 SNI 一包，共9个 Native create。
2. `delete-service` → Root readonly worker → `restore-service` → Root readonly worker。
3. `delete-route` → worker → `restore-route` → worker。
4. `delete-upstream` → worker → `restore-upstream` → worker。
5. `delete-consumer` → worker → `restore-consumer` → worker。
6. `delete-certificate` → worker → `restore-certificate` → worker。

受影响对象数量严格为 Service/Route/Plugin=3、Route/Plugin=2、Upstream/Target=2、Consumer及六凭证=7、Certificate/SNI=2。Service/Route 的真实 Upstream/Service **reference nodes另行完整保留与验证**，所以 archive.node_count 可大于受影响数量；不能为了符合数字丢掉引用。每次删除后检查全对象204、原点404、归档完整manifest；恢复要求每个原ID、原配置/secret、父关系和201回执一致。Basic额外要求原明文custody可完整恢复。

Consumer **包含 OAuth2**，不按 Source 样例假定实际只有360calls。准备后的完整graph规模、packet数量和请求原件都存私有记录。500 SDKcalls、100pages及原Source/Context期限全部保持；预算或权限失败会停止整个阶段，不能减少DAO/依赖、加预算、续期、拆成原工单重发或用新键重放未知结果。若现场超限需要新产品协议，经审核后另立新case。

任何已开始阶段均不可再调用；失败或未知使后续全部关闭。ReleaseHarness原 prepared/response_unknown/未关闭5xx仍优先阻断，不在本脚本中“解决”。即使所有写均成功，CLI报告仍把 SQL/AEAD 标为 pending，直到 Root 另行执行下述 worker。

## SQL/AEAD/原回执：必须单独由 Root 执行

导出纯函数 `ordinaryV3InspectionInput(g,stage)`，其中g就是上述新私有字段。它返回 exact cid/wid/workflow/execution/baseline/entry/affected原IDs，无会话或凭证。Root 在每个 delete/restore 成功后立即从自己持有的私有ledger调用该函数并保存输入；**不要等恢复后才核验此前delete的deleted状态**。

worker：`tests/security/m11-current-ordinary-v3-readonly-worker.mjs`。只接受stdin输入，不读ledger，不启动HTTP，不执行Native，不写SQL事实或恢复 metadata。

Root 在实际已部署 API 的执行空间/环境设置 `RELEASE_LAB_M11_V3_READONLY_WORKER_READY=true`、`RELEASE_LAB_M11_V3_API_DIST`（实际编译dist绝对目录）和控制台自身 `DATABASE_URL`；不得用Kong数据库。运行 worker 时把上一段输入送stdin。worker要求真实NOSU且无BYPASSRLS角色，`REPEATABLE READ READ ONLY`，每条SQL超时30秒。

worker只复用已部署产品的只读历史核验方法 `Facts.ready`、`RecycleFacts.binding/verifyStoredArchive/subset/packetRow`，未安装任何授权delegate、未构造原私有handle，也不调用其writer方法。检查真实 Source/baseline/pin、baseline与intent AEAD及规范化manifest、完整SQL23 graph/member与加密archive交叉HMA、每包原attempt/send/outcome事件AEAD、Mutation的before/payload/result AEAD、双向operation/receipt键、原204+404或201及parent/原ID、禁止V1/V2 namespace混用。失败只输出固定错误码，不输出原行、密文、解密值或异常操作数。

Root 保存每阶段实际 exit/stdout/Source版本，作为 `inspections[stage]`。这只是验收证据，不是新的权限证明或HTTP入口。worker不会替代执行时的 current/allparty/最后DNS门禁。

## 恢复后的真实凭证认证，独立于配置证明

五类循环均成功后，再执行 `create-probes`，其后等至少5秒，再执行 `probe-restored`。创建专用Service、六Route与八Route-only插件，避免扩大原Service回收图；检查全工作区global插件、Consumer/Service/Route绑定干扰。复用既有纯 helper 生成 key-auth/basic/jwt/hmac/ACL 正反请求；TLS/token不混入这些BFF安全GET探测。每个真实proxy只发一次；不以轮询写请求掩盖未知响应。要求200正例、401认证负例、ACL非匹配组403。

OAuth2另设严格Root显式TLS profile：

- `RELEASE_LAB_M11_RESTORED_OAUTH2_HTTPS_PROBES_READY=true`；
- `RELEASE_LAB_OAUTH2_HTTPS_ORIGIN` 为Root已发布的loopback **业务HTTPS** origin（显式port，拒8001/8444/5445）；
- `RELEASE_LAB_OAUTH2_TLS_SERVERNAME=kongpilot-v3-acceptance.invalid`；
- `RELEASE_LAB_OAUTH2_TLS_BASE_DIRECTORY` 为Root绝对公共CA目录；`RELEASE_LAB_M11_V3_CA_FILE` 可直接指定上述certificate.pem作为自签公共CA，不要求重命名为ca.pem；
- 全程真实CA/SNI验证，绝不 `rejectUnauthorized:false`、伪造TLS终止头或直连Admin。

执行 `create-oauth-probes`，再等至少5秒，执行 `probe-oauth-restored`。专用HTTPS Route与oauth2插件经同一个真实工单流程创建；原恢复client_id/client_secret经真实authorize-code→token→bearer200，并验证缺token/wrongtoken401及错误类型。全部headers/forms/code/token原件只在私有ledger；它们不是Admin回执，也没有代理幂等保证。任何TLS POST未知立即停止全局；不自动重试。此处不宣称已验OAuth refresh/历史token复活/Portal流程。

`ordinaryV3CombinedResult(g,inspections)` 只在15阶段全部成功、10份Root只读证据与原tuple严格匹配、六scheme真实功能结果齐全时返回该cohort通过。它**始终**输出 `overallM11Accepted:false/commercialAccepted:false`，configuration_v2 Target/DELETE、Portal P6、完整商用验收仍是不同目标。

所有公共报告是固定白名单状态/数量/摘要，wx创建且不覆盖；原密码、私钥、APIKey、client_secret、session cookie、签名请求和私有证明不进入公共文件或console输出。
