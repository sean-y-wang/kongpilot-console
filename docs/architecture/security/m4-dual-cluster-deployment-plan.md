# M4 双集群与 Admin ACL 部署计划

M3 提交 `12af2b5` 后先启用两套真实 Kong 和精确来源 ACL。先行网络验收通过34项检查，见 `artifacts/M4/admin-network-verification.json`，当时仍运行 M3 应用。M4 源码检查放行后已统一构建并启动新应用，完成005/006权限迁移和存储网络切换；最终部署边界27项、真实双集群网络37项通过，分别见 `artifacts/M4/deployment-boundary.json` 与 `artifacts/M4/admin-network-final-verification.json`。独立应用权限/IDOR验收随后执行；M10 可继续复用这两套环境验证漂移与 Promote。

## 两套真实数据面

复用 `deploy/compose/compose.multicluster-test.yml` 的 `multicluster-test` profile：第二个官方 `kong:1.5.1`、独立 PostgreSQL11 容器、数据库、账号、密码、数据卷和 storage 网络。两个 Kong 的 Admin8001 均不发布到宿主机；代理分别在 loopback8000/9000。console-api 只加入两个 Admin 网络，不加入任何 Kong storage 网络。共享无凭证 echo 上游用于真实代理验证。

启动前使用 `generate-multicluster-env.mjs` 创建不会覆盖的0600私密文件，Compose 命令始终保留基础文件、开发绑定和双集群补充文件。生产基础部署不会自行启用测试 profile。测试凭证扫描须同时私下读取 `.env` 与 `.env.multicluster` 的秘密值；两个文件本身继续由 git 和镜像上下文忽略。

## 有序、精确来源 ACL

两套 Admin server 已启用1.5实际支持的 `KONG_NGINX_ADMIN_INCLUDE`，各自的文件只含 `allow <本管理网络中的实际BFF IPv4>; deny all;`，保持 allow 在 deny 前。不允许 loopback，不允许整个网段，不给 Admin 或 HTTP/main 注入基于转发头的 real-IP 信任。BFF 使用固定管理 IPv4，避免 Kong 与 API 相互等待 DNS 导致启动依赖环。

部署前已检查路由及 Docker 网络，新增主管理网 `172.28.11.0/24` 与第二管理网 `172.28.12.0/24`；两网中 Kong 为 `.20`，BFF 为 `.10`。主管理网使用新的物理网络 `kongos-console_kong-admin-secure` 替换旧动态网络连接，全部数据库卷保持原样。网段/地址可通过环境变量成组配置，实际 BFF 地址须与 ACL 一致。Kong/API 分别以 `kong`/`node` 非 root 账号运行，丢弃全部 Linux capabilities 并启用 no-new-privileges。

已切换至主存储网 `172.28.21.0/24` 和第二存储网 `172.28.22.0/24`，两网中 Kong 为 `.10`、专属 PostgreSQL 为 `.20`。四个管理/存储地址范围不能重叠，31项配置检查核验范围而非只比较网段字符串。数据库固定地址作为精确受保护目标传给 BFF，弥补 BFF 不加入 Kong 数据库网络、无法从 DNS 解析数据库地址的限制；不会封禁整个私网。此次切换与005/006迁移和应用部署一起执行，原有两套 Kong 数据库数据卷保持不变；37项实际网络证据核验了真实数据库IP和运行中BFF保护配置。

实际生成的 Admin 配置仅监听本管理 IPv4 和 loopback8001，没有 wildcard 或 IPv6监听；loopback虽有监听，ACL仍拒绝。两节点自身经 loopback/管理地址及伪造 X-Forwarded-For/X-Real-IP/Forwarded 请求均403，BFF的 `/`、`/status`、`/plugins/enabled` 均200。Proxy server 自己的默认 real-IP 指令不作用于 Admin server。

原生 access log 改用仅含时间、方法、状态、字节数与耗时的格式，不含 URI/query/header/body。Kong1.5原生 request-context error log 会包含敏感查询，所以默认将 Admin/proxy/global error log 输出到 `/dev/null`，并关闭会注入外部 syslog error sink 的 anonymous reports。此取舍会丢失原生请求错误详情；保留控制台脱敏错误代码/请求ID与安全访问日志，若生产需要更详细原生日志，必须在落盘或采集前加入经过验证的脱敏通道。

控制台 Nginx 同样不使用默认 combined access log：只记录来源IP、方法、无query的路径、状态、字节数与耗时，省略OIDC callback的code/state、Referer、User-Agent、Cookie及正文。server原生error log输出到`/dev/null`，避免限流或上游故障再次把原query带入错误日志；安全access与BFF诊断保留。实际reload后，随机callback query/header哨兵及真实429路径检查10/10通过，Docker stdout和stderr都未包含哨兵，见`artifacts/M4/nginx-safe-log-verification.json`。首轮工具仅因未将未配置OIDC的合法503加入预期而9/10，修正测试契约后通过；原始记录保存在`artifacts/M4/nginx-safe-log-pre-contract-fix-verification.json`。

管理目标校验覆盖两套已注册 Admin 地址/端口以及控制台管理入口。能力探测、`/status`、CRUD 和后续 metrics 仍通过 BFF；fixture 录制、真实诊断也从 API 的管理连接执行。原先 Kong 容器内 loopback Admin 读取会按设计被拒绝。原生 `kong health` 检查进程，不依赖此 loopback 请求。

## 既有测试别名处理

主网关原有三条活跃的浏览器验收连接，均为本会话自动创建的 e2e 夹具，实际指向同一个 `http://kong:8001`；现在已审计后软停用：

| clusterId | 来源 |
| --- | --- |
| `f80cc384-20f5-43ff-961b-c750046be374` | 浏览器验收 e2e |
| `adfb4fa1-38d7-487f-86bc-d283a30e397b` | 浏览器验收 e2e |
| `13f36a78-5103-467b-b2d3-93c1b22f9377` | 浏览器验收 e2e |

M4 权限应用就绪后，工具先归档这三条连接的公开元数据、依赖行数及历史审计前缀，再通过正常认证/CSRF、名称和revision二次确认的 BFF 软停用。22项实际检查证明注册行仍保留、依赖行数和完整历史审计前缀不变、每次停用均有审计请求ID；证据见 `artifacts/M4/alias-deactivation-archive-before.json` 与 `artifacts/M4/alias-deactivation-verification.json`。没有 SQL 写入或该网关上的业务实体变更。首次只读归档检查因UUID/text参数比较缺少显式转换失败，尚未发起任何停用；修正工具SQL后通过，首轮失败证据保存在 `artifacts/M4/alias-deactivation-pre-fix-verification.json`，未更改应用或数据库结构。其他五条安全验收别名此前已软停用。默认真实连接 `dff45535-ed8d-4851-b7a6-6376feac7f59` 保持有效。第二真实连接已通过正常认证/CSRF/审计的 BFF 注册，为 `d1dfaec8-2a10-4170-8a15-20a600a4bd4f`，Admin URL 是 `http://kong-secondary:8001`；注册证据见 `artifacts/M4/dual-cluster-registration.json`。

相同物理 Admin 传输目标的注册别名须共享外层变更锁、内层网关写锁、限流和熔断状态，新注册应拒绝重复目标；只比较原始 URL 字符串或 `node_id` 不能保证传输目标唯一，需规范化 URL 并核对允许的实际管理端点。停用夹具不替代这些应用层检查。

## 实际验收要求

两套独立 Kong 分别创建相同 native UUID、名称和工作区编码；C1/C2 的授权、列表、详情和变更必须按真实 clusterId 隔离，不能拿同一网关的两个注册别名替代。分别验证 BFF 合法管理请求与健康、Kong 自身 loopback/本机 Admin403、伪造来源头无法绕过、网关公开 Route 无法转发访问 Admin、源/目标越权403及两套独立数据库/卷。仅清理带测试标记的对象，经回收站处理；不执行 `down -v`。

部署证据证明新应用、真实双集群和上述 ACL 已生效，不能代替独立 M4 IAM/IDOR 全链路验收；公开 Route 转发 Admin 和应用层越权还须由真实攻击用例验证。
