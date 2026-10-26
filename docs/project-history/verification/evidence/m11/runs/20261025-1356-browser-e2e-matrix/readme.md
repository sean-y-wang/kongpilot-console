# M11 浏览器 E2E 矩阵（第二轮，2026-10-25 13:56 EDT）

- 运行器：`tests/e2e/m11-browser-matrix.mjs`（headless Chromium，`KP_LAB_E2E=true` + 0600 私有 secrets；密码、开发者密码、API Key 在写入前按值脱敏，仓库内无凭据）。
- 结果：**11/11 通过**，pageErrors=0，headSha=39fb98f（lab web 预览构建早于 39fb98f，UX 修复由单测覆盖）。`commercialClosed=false`。
- KP-003：真实 execute 在服务端 201 后，客户端连接被重置 → 未知结果横幅；(a) 未使用过的键回执 404 `WORKFLOW_RECEIPT_NOT_FOUND`；(b) 传输中篡改为不匹配回执（键/工作区）→ UI 拒绝、未知 journal 保留、不提供再次执行；(c) 原键真实回执核验后关闭；execute POST 总数=1（无重放），Kong Service 200。注意：(b) 的不匹配回执是浏览器侧注入，不是服务端产生的错配。
- KP-006：门户注册→待审开发者登录被拒→控制台审核通过→登录→建应用→申请 Key→审批人批准→管理员执行→掩码 `••••••••`→临时查看→Kong 代理：无 Key 401 / 错 Key 401 / Key1 200→轮换（审批+执行）Key2 200、Key1 401→吊销（审批+执行）Key2 401；匿名门户 API 401。
- 观察（未断言，待产品决策）：cluster B 上门户工单的审批人同时具备执行能力（execute 由集群 write 权限决定，无“审批人≠执行人”硬规则）；本轮均由 admin 执行。
- 已知缺口：旧 mutation 来源回收条目的审批模式恢复仍不支持（prepare 即 409 拒绝，文档化缺口）。
