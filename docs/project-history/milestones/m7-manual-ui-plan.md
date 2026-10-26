# M7 手工 UI 验收窗口

入口为 `tests/security/manual-m7-ui.mjs`。仅在 Root 明确放行且 Security 交接新的 M7 fixture 后执行：

```sh
M7_MANUAL_READY=true node tests/security/manual-m7-ui.mjs
```

源码准备不读取运行态、私有引用或环境文件。实际入口要求私有 `manualUiHandoff` 为 `ready`，同一 testTag、CID/WID、精确 12 项 `approvedActions`；`securityReportPath` 仅允许 `security-live.json`、`security-live-catalog-continuation.json`、`security-live-preference-continuation.json`、`security-live-late-ack-continuation.json` 或 `security-live-audit-download-continuation.json` 五个固定 M7 报告，并核对真实成功状态和文件 SHA。原失败报告永久保留，不能替代绿报告。引用阶段必须为 `http-complete` 或 `producers-complete`，且实际 `producersComplete=true`；按 HTTP→producer→UI 的顺序，不由手工入口重设阶段或生产者证明。存在未决包或已开始 UI 窗口均拒绝启动。

使用 Security 已有 `admin`、`owner`、`read-only` 三个会话，不登录、不刷新、不发送原生 Admin API 请求。交接会话必须剩余至少 300 秒；Jar 的 actor/SID/exp/CSRF 与交接一致，再通过真实 `GET /auth/me` 验证当前身份。JWT 解码只用于一致性校验，不能代替服务器的认证。后续过期即停止。

交接另绑定固定 `artifacts/M7/security-producers.json`、`artifacts/M7/security-producers-continuation.json` 或 `artifacts/M7/security-producers-cli-policy-continuation.json` 的 SHA，核对同 testTag、成功状态、严格报告 scope、完成阶段、同 CID/WID 下的真实证书/Upstream fixture、两个事件 ID、非合成观察输入和同一实时授权。接续报告必须严格验证原已知阻断采样：第一组原 267 包与 5 个 key 的封存摘要、SQL 观察/探测状态均为零、原内存观察和 stdout 仍未知；第二组保留原 CLI 未证明状态、首安全响应及一条独立后台观察事实，不能冒称 SQL 全局为零。复用固定来源 SHA 与严格两个 tuple 验证，原失败不重放。最终健康尾部还须保留原 275 包、已完成的证书样本、失败 healthy 包以及只读健康基线；各接续 marker 全部 completed，新证书不得复用两旧阻断 subject。其他采样均须完成。幂等 UUID 与测试接收器 URL 留在原私有请求中，不当作认证秘密；真正 token/password/secret/CSRF 与会话 Cookie 均保留给最终扫描。

新窗口只发送以下尚未执行的 12 个原请求，每项一次，所有个人操作属于 owner；共享操作与审计导出属于 admin：

| 顺序 | 操作 | 验证 |
| --- | --- | --- |
| 1 | 创建本人偏好 | 无对象过滤，订阅渠道测试、投递重放；省略空 nativeType |
| 2 | 创建 webhook 渠道 | 测试接收器与新 Bearer 只在表单 RAM；关闭后截图 |
| 3 | 渠道真实测试 | 原回执排队，真实投递读取为 succeeded |
| 4 | 重放上述投递 | 使用当前 revision，新的事件/投递代次实际成功 |
| 5 | 两条本人通知批量已读 | 原事件、同 CID/WID、两个实际 ID/revision；Bell 读取真实计数 |
| 6 | 编辑本人偏好 | inAppEnabled=false，无对象过滤 |
| 7 | 偏好移入回收站 | 当前 revision、名称确认、软删除 |
| 8 | 恢复偏好 | active，仍保留静音设置 |
| 9 | 创建审计 CSV 导出 | 操作人 owner、当前工作区；下载需任务 capability，检查字节与秘密 |
| 10 | 渠道移入回收站 | 名称确认、deleted |
| 11 | 恢复渠道 | disabled，不自动投递 |
| 12 | 明确启用渠道 | active，并验证跨工作区迟到回执恢复 |

浏览器 `route` 在每个非 GET 包发送前校验精确端点、query、正文、JSON 类型、actor、原 SID/CSRF、原 key 与动作顺序。完整原请求以 0600 文件写入、fsync、原子替换后才能 continue。未知请求、重复 key、失败、不确定或持久化失败全局止发，保留原事实，不重试、不换 key。原 HTTP 包、原会话与 handoff 另存不可变历史，所有已有秘密保留供最终扫描，新增实体登记供统一清理。

HTTP ACK 不代表成功：共享写读取 events 原 key ledger；个人写读取 notifications 原 key ledger；导出读取独立 audit-export ledger。校验实际生产 DTO、目标 ID、CAS revision、状态与配置。排队与远端成功分开验证。响应未知时只允许 Root 后续决定原 key 的只读核验，不在本脚本自动重放。

迟到回执场景只暂缓第 12 项的只读 ledger GET。写 ACK 后关闭该确认框、切换到另一工作区，再释放原 GET；原写由独立 ledger 证明，产品须保存仅原 actor/CID/WID/key 的恢复引用。通过界面“核验操作”只读解除，不再产生业务包。

审批仅浏览原 C2 已完成 workflow：实际状态、无批准/执行控件，不改集群模式、不新提交工单。另验证 read-only 控件与零写、移动端消息页。分页只访问有界游标页，不全量获取。

输出 `artifacts/M7/manual-ui.json` 与 `manual-*.png`，公开内容仅安全 ID、请求 ID、原范围、状态、截图 SHA、下载字节数/摘要。成功后将 12 个真实写请求 ID 交给 Security 作终态审计对账、fixture 清理与秘密扫描；本报告不冒称这些后续步骤已完成。任何失败不覆盖历史；同一入口禁止重入。


2026-10-11 原首次 manual 在 Select 的 root 与 combobox input 重复 aria-label 处停止，0业务包。精确原失败 SHA b91fd028f65451c39b3392d6d8328ff79d641090088a1cc8191b29942365fc96 以 wx+fsync 保留，完整旧 journal/history 在新窗口前独立封存。原三 SID 正常维护的 3 个 refresh 与其独立审计仅作为认证 suffix，固定维护报告 exact SHA/原 actor/SID/原280包 prefix 校验，UI 自身不登录或刷新；12 个原业务 intent 全部尚未执行，继续使用 M7_MANUAL_READY=true 原入口，不增加权限或批准门槛。所有 Select 仅匹配 labelled input[role=combobox]。
