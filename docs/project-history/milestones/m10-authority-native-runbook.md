# M10 来源授权撤销与自然定时执行验收

此文件是 Root 操作合约和验收工具说明，**尚不表示真实验收已通过**。工具测试与语法检查不能代替实际 HTTP、原生 Kong、控制台数据库及自然到期回执。

仅在 `kongpilot-release-lab` 双 Kong 1.5.1 验收环境运行。工具不修改 API 源码或 SQL，不连接任何 Kong 数据库，不执行强制 tick、不修改 due 时间、不使用伪造 SID 或未来时钟。生产环境不运行这些造数工具。

## 操作顺序

从 `/opt/kongpilot-console` 运行。每次提供如下环境变量；SHA 必须来自当前 `artifacts/M10/runtime-deployment.json` 的 `apiSourceSha256`，不能使用旧候选版本：

```bash
RELEASE_LAB_READY=true \
RELEASE_LAB_M10_DEPLOYED=true \
RELEASE_LAB_M10_AUTHORITY_READY=true \
RELEASE_LAB_M10_RUNTIME_SOURCE_SHA=<当前部署回执的SHA256> \
node tests/security/m10-native-authority-actual.mjs --phase bootstrap
```

按顺序分别运行 `bootstrap`、`prepare`、`revoke`、`verify`、`timer-observe`、`restore`。必须串行操作 IAM 授权变更和 native apply/capture；IAM 元数据变更会改变全局 `iam_epoch`，可能使另一条正在捕获的授权句柄失效。已有正例治理定时任务应先完成真实观察，或先通过正式元数据接口审计暂停，完成新账号授权初始化后另建当前版本观察合约。禁止改变已记录的原始 occurrence 或验收结果。

| 阶段 | 实际操作与预期 |
| --- | --- |
| bootstrap | 管理员创建普通本地账号；分别创建来源、目标工作区角色，权限互不跨环境；真实初次登录，记录系统实际 `forcePasswordChange` 布尔策略。无论该值为 true 或 false，均单独实际修改密码，验证旧 session 已撤销，再以新密码真实再次登录，新用户必须 `superAdmin=false`。 |
| prepare | 管理员在两侧各创建独立同名 Service，只有 `connect_timeout` 为 5000/7000 的差异。新用户使用两个 Service 的 `services` 范围新建比较，明确包含环境字段，再创建具有实际 Service update 的非空发布计划。检查当前目标写入资格。用户最后注册自己的独立 5 分钟巡检任务，保存真实 BFF 的 owner、currentVersion、revision、未来 nextRunAt。 |
| revoke | 必须早于原始自然 due 至少 30 秒。管理员使用当前 binding revision 二次确认，仅撤销来源角色绑定；目标 binding 保持原 ID、权限和 revision。 |
| verify | 原用户来源 Service 读取 403；目标 Service 仍 200。旧发布计划读取与 apply 因 `GOVERNANCE_PROMOTE_SCOPE_DENIED` 被拒绝。实际控制台 READ ONLY 观察必须证明对应原 request/key/actor/目标范围没有新配置 job、mutation 或 remote started/completed。来源路径的旧 promotion 安全回执、目标原配置 job 安全回执仍可读。 |
| timer-observe | 真实时间等待原 due，每 10 秒仅读取管理员 BFF 回执。当前版本必须 `executionBlocked=true`，原 occurrence 为 `paused_authority`、`PERMISSION_DENIED`。实际 READ ONLY 观察验证唯一 occurrence 的原 owner/version/due、claim/failed 审计、未注册 inventory run、新用户两环境所有 mutation 为 0。 |
| restore | 管理员以 GET 得到的撤销 binding 当前 revision 单独恢复来源授权。来源实体重新可读，目标 binding 不变。旧计划不重写、不自动执行；旧 schedule/currentVersion/原 occurrence 保持阻断，不自动重启任务。若后续要重新启用，必须另行通过正式 schedule PATCH 创建新版本，该动作不属于本工具。 |

`prepare` 完成后立即执行 `revoke`，随后执行 `verify`，并在原 due 后 3 分钟以内启动/完成 `timer-observe`。工具自行以实际时间等待，不要求人为定时修改任何数据库字段。

每个阶段将原始 HTTP intent/key 写入已有 0600 私有 RAM WAL，再发送请求。已观察失败或未知的请求不能重放、不能更换键掩盖。阶段异常停下后，应由 Root 核查原回执及实际事实；不要删除私有 WAL 或失败产物，不要盲目重新运行阶段。已完整通过的阶段禁止重复执行。

## 准确 IAM 合约

前缀均为 `/api/v1`，管理员变更均带真实 Cookie、CSRF 和 `X-Idempotency-Key`：

```text
POST /iam/users
{ username, password, display_name, email }

POST /auth/login
{ username, password }

POST /auth/me/password
{ revision, current_password, new_password, confirmed: true }

POST /iam/roles
{ code, name, description, cluster_id, workspace_id }

PUT /iam/roles/:roleId/permissions
{ revision, permissions: [
  { module, action, scope_type: "workspace",
    cluster_id, workspace_id, scope_values: [workspace_id] }
] }

POST /iam/users/:userId/role-bindings
{ role_id, cluster_id, workspace_id }

GET /iam/users/:userId/role-bindings
?clusterId=...&workspaceId=...&status=active|revoked&size=100

DELETE /iam/users/:userId/role-bindings/:bindingId
{ revision, confirmed: true, confirm_name: role_name }

POST /iam/users/:userId/role-bindings/:bindingId/restore
{ revision, confirmed: true, confirm_name: role_name }
```

身份配置目前在 `approval` 集群返回 `APPROVAL_REQUIRED`。本合约要求两侧实际 `direct` 模式；撤销和恢复是独立、审计记录完整的管理员 IAM 元数据操作，**不宣称已走身份变更审批工单**。

自定义角色只包含所在工作区的八类原生实体 read/write、clusters/workspaces/annotations/mutations/secrets/drift read、snapshots/governance/promote read/write，不赋予用户、角色、团队或权限管理能力，不授予任何 global 权限，也不使用内置超级角色。来源角色与目标角色、binding、grant 的完整四维范围分别验证，禁止依赖超级账号身份完成被测行为。

## 回执与边界

阶段产物为 `artifacts/M10/native-authority-<phase>-attempt-N.json`，每次独立落盘且保留旧失败尝试。私有状态写入已有 M10 WAL 的 `authorityAcceptance`，新密码和 Cookie 仅保存在私有 RAM；原始实际密码请求也留在原 WAL，纳入最终 M10 secret scan，禁止把密码、Cookie、CSRF 写入公共产物。

控制台 READ ONLY 观察同时校验已部署 dist、SQL017/018 实际字节和 migration ledger，使用 `kongpilot_lab_app` 运行角色。没有独立网络抓包证明，不能把控制台 mutation=0 描述成独立 wire log。定时来源在授权检查处失败、没有 inventory run；正例的完整采集与真实指标/通知由其他 M10 验收工具负责。

本工具不更改已完成的 core/optin 正例，不修改主验收 phase，不宣布 M10、M11 或商用整体验收通过。独立 Service、用户和定时任务保留用于审计与回执核查；若后续清理，删除必须走正式回收站/元数据归档接口，并另记审计。
