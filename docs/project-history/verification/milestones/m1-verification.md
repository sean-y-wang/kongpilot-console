# M1 实体验收

本次使用真实 **Kong OSS 1.5.1**、PostgreSQL、Redis、API、Web 和隔离的测试上游。M1 交付八类实体、Targets、六类 Consumer 凭证和回收站；动态插件市场、工作区与完整 RBAC 仍按后续里程碑实施。

## 重现

```sh
docker compose --profile test up -d echo-upstream
node tests/security/live-m1.mjs
npx playwright test tests/e2e/m1.spec.ts
node tests/security/check-artifacts.mjs
```

管理员登录凭据读取本地 `.env`，脚本不打印凭据。证书私钥只在临时目录生成，测试结束删除。脚本保留带 `m1-security-*` 标签的配置用于演示；前端测试保留 `m1-browser-*` Service。测试上游返回方法、路径和 Consumer UUID，不回显请求头、查询参数、请求体或凭证。

功能脚本在 BFF 请求间隔 60ms、对象图步骤间隔 300ms，使用默认限流。应顺序执行 HTTP 与浏览器写入验收；集群变更锁会阻止竞争写入。开发挂载更新编译文件后，须重启 API Node 进程再进行最终验收。

## 已验证行为

真实 HTTP 验收 **336/336 通过**，明细与关联 requestId 在 `artifacts/M1/security-live.json`。

真实 Chromium 验收 **1/1 通过**：通过 UI 创建与编辑 Service、打开 Configuration / Routes / Plugins、验证错误确认名称禁止删除、确认归档和恢复后可见。浏览器无页面错误、无直连8001请求。截图位于 `artifacts/M1/services.png`、`service-details.png`、`recycle-bin.png`；认证 trace 关闭，登录密码不写入报告步骤。

| 范围 | 验证结果 |
| --- | --- |
| 八类核心实体 | Services、Routes、Consumers、Plugins、Upstreams、Certificates、CA、SNIs 创建、读取、修改、归档删除和原 ID 恢复 |
| 对象图恢复 | Plugin、Consumer、Service、Upstream、Certificate 五类图样本；Routes、绑定 Plugins、全部凭证、Targets、SNIs 保持关联 |
| Consumer 凭证 | key-auth、basic-auth、jwt、oauth2、hmac-auth、acls 均完成创建、分页读取、修改、独立归档与原 ID 恢复 |
| 代理可用性 | 原始 API Key 与 Basic 密码在 Consumer、Service 和独立凭证恢复后，通过真实 Kong proxy 访问测试上游成功 |
| 插件执行 | correlation-id、key-auth、basic-auth、Consumer rate-limiting 与 Route request-termination；状态码配置和启停对真实流量生效 |
| Targets | 修改权重产生新有效历史 ID；手动健康置位；归档删除产生零权重记录；恢复重新追加有效 ID并保留权重 |
| 分页与重放 | 三个真实 Service 使用 size=2 分两页，过滤保留且不重复；篡改游标和跨过滤重放被拒绝；幂等键重放返回同对象，换 payload 返回409 |
| 删除确认 | 未确认删除返回400，原实体保留；回收站预览不回显秘密 |
| 关系越权 | 使用另一真实 Consumer 的父 ID 读取、修改、删除凭证返回404；另一真实 Upstream 下修改、置位、删除 Target 返回404；原状态未变 |
| 版本及证书 | 新探测返回1.5.1；全部八类实时 schema 可读；不支持的 TLS 字段和 Vault 被拒绝；PEM 到期及私钥匹配有效；被 HTTPS Service 引用的证书删除返回409且未移除依赖 |
| 审批集群 | 未实现审批引擎前，approval 集群禁止直接写网关，真实网关没有产生被拒绝的对象 |

Target 的历史验证使用后端网络内、size=100 的只读 Admin API 探针；浏览器仍只访问 BFF。Kong 1.5 会在其最后有效 Target 变成零权重时清理全部冗余历史，测试保留第二个有效 Target 以验证零权重追加行为。Target 历史 ID 不可按普通实体原 ID 恢复，结果明确返回新的有效 ID。

恢复依据依赖图排序：Consumer 必须早于依赖它的 Plugin 和凭证；共享引用只验证，不随父对象删除或覆盖。基础凭证恢复使用控制台加密保存的原始密码，不能把 Kong 返回的密码哈希当作原密码再次提交。

## 安全与证据

基础认证和安全隔离回归 **75/75 通过**，报告在 `artifacts/M1/security-unit-results.json`。本次 npm audit 为 **0 项公告**，报告在 `artifacts/M1/dependency-audit.json`。秘密扫描涵盖 Git 跟踪文件、测试产物和浏览器 HTML 内嵌 ZIP 的解压内容。

四维角色权限、只读用户、tag_group/entity 范围和权限继承的真实攻击验证属于 M4；当前 M1 实体操作仅向平台管理员开放。上述结果覆盖实际执行的 M1 功能，不能替代后续模块验收、镜像漏洞扫描、负载和灾备演练。
