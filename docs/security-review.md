# M0 / M1 安全评审

本报告覆盖 M0 工程基座与 M1 核心实体/回收站。四维 RBAC、门户凭证工作流、审批和快照尚需对应里程碑的实现与攻击测试，当前结果不能作为完整产品商用认证。

## 已实现的边界

- 所有集群和数据源控制器要求平台管理员。浏览器使用 HttpOnly、SameSite=Strict 的会话 Cookie；Cookie 写请求校验服务端保存的 CSRF token 哈希。
- JWT 限定 HS256、issuer、audience 和 15 分钟有效期。每次请求读取 PostgreSQL 当前会话和用户状态，撤销会话立即阻止旧 JWT。
- Refresh token 保存 SHA-256 哈希，在数据库行锁内轮换。登录失败计数、临时锁定与 Redis 登录限流已经接入。
- 数据源读、写、连接测试和停用均同时限定 `cluster_id` 与对象 ID。DTO 使用严格字段校验；SQL 全部使用参数。
- 连接地址仅接受允许列表内的 HTTP(S) 主机；拒绝 URL 用户信息、查询参数、片段和编码路径分隔符。DNS 解析计入总超时，解析后的地址固定用于该次连接，HTTP 重定向不跟随。
- 元数据地址、链路本地、组播、IPv4-mapped IPv6 等目标受到额外阻止，允许列表不能覆盖这些地址检查。
- 连接认证材料使用 AES-256-GCM，并以集群/数据源上下文绑定 AAD。响应仅返回是否配置连接认证，不返回密文或明文。
- API 设置防 framing、nosniff、CSP 等安全响应头。审计 payload 脱敏；数据库拒绝修改、删除和截断审计记录。

## 回归测试与证据

`npm test` 中的安全测试覆盖匿名阻止、平台管理员要求、Cookie CSRF、Bearer 客户端、JWT 签名与声明、数据库会话撤销、刷新轮换、失败锁定、限流、跨集群数据源 IDOR，以及真实本地 HTTP 下的 DNS 固定、超时和重定向。

证据写入 `artifacts/M0/security-unit-results.json`。这些是隔离的单元/本地传输测试，不表示已访问真实 Kong。

运行 `node tests/security/live-m0.mjs` 对已启动的完整环境进行 HTTP 验证，结果写入 `artifacts/M0/security-live.json`。脚本从 `.env` 读取管理员凭证，不输出凭证；创建的测试集群和数据源完成后软停用。执行失败会记录未清理对象数量，便于检查。

运行 `npm run test:e2e` 验证实际浏览器登录、登记与探测集群、切换集群、配置与探测数据源，并检查浏览器没有直连 `8001`。截图位于 `artifacts/M0/`。认证用例禁用 Playwright trace；密码使用不会把参数写入步骤标题的输入方法，避免明文密码进入 HTML 报告。

本次验证：安全与认证隔离测试 **75/75 通过**；真实 Compose 环境 HTTP 检查 **33/33 通过**；真实 Chromium 端到端用例 **1/1 通过**。浏览器验证还覆盖移除 access cookie 后刷新页面的会话恢复，并确认 Prometheus 显示连接正常、没有 JavaScript 页面错误或浏览器直连 Admin API 请求。

M1 新增真实 Kong **336/336** HTTP 检查：八类 CRUD 与对象图回收恢复、六类凭证独立恢复、原始 Key/Basic 密码真实代理认证、错误父 ID 的凭证/Target 攻击、确认与幂等限制、审批模式阻断和证书引用保护。认证隔离75项再次通过。完整证据与测试局限见 the M1 verification notes kept with the release evidence (not in this public tree)；原始私钥和密码加密保存，响应及恢复预览默认脱敏。

`node tests/security/check-artifacts.mjs` 扫描 Git 已跟踪文件、生成证据以及 HTML 报告内嵌 ZIP 的解压内容。首次发现浏览器报告步骤标题泄露测试登录密码后，已删除旧报告并修复输入方式；重新生成后的扫描结果为零泄露，证据在 `artifacts/M0/secret-artifact-scan.json`。

## 依赖审计

升级前审计为 34 项：2 critical、11 high、21 moderate。安全修复涉及 NestJS 12、Swagger 12、Vitest 5、Vite 6.4.4、React Router 7、YAML 2.9.1，以及 LDAP/邮件依赖的新版本。React 与 Ant Design 保持 18/5。

ECharts 5 没有当前公告对应的修复版本，改用 6.1.0；这属于安全修复的技术栈调整。门户 Swagger UI 渲染器在 M6 实际选型时引入，避免当前引入存在持续公告的未使用依赖。

脱敏升级前后报告分别为 `artifacts/M0/dependency-audit-before.json` 与 `artifacts/M0/dependency-audit-after.json`。报告只是 npm registry 在执行时的依赖公告快照，不覆盖容器、操作系统、Kong 旧版组件或未知漏洞。

最后一次升级后 npm 审计为 **0 项公告**；需在每次发布时重新执行，不能将这一结果作为持续无漏洞承诺。

## 上线前必须验证

- 在 TLS 入口将 `COOKIE_SECURE=true`，配置精确 `PUBLIC_ORIGINS` 和可信代理层数；不把本地 HTTP 演示配置直接用于生产。
- 为每个生产连接配置最小的主机/端口允许列表；避免宽泛通配域。数据库、Redis 和 `8001` 保持无公开端口。
- 加密密钥与 JWT 签名密钥独立生成、备份和轮换；使用服务 secret 注入。
- 完成数据库最小运行权限、审计外部检查点、容器镜像扫描、备份恢复演练和负载测试。
- Kong 1.5.x 与其兼容旧 PostgreSQL 属于旧技术基线，生产需要明确的内部维护、补丁和风险接受流程。控制台网络隔离不能替代网关自身漏洞维护。
- M4 完成真实 read-only、tag_group、entity、权限继承专项；M1/M6/M8/M11 完成凭证和回滚闭环；之后才能对全部用户验收项作商用就绪结论。
