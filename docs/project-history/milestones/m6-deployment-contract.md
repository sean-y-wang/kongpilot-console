# M6 门户部署与测试材料合同

状态：M5 已提交 df98907，M6 源码实施已授权。部署配置、脚本与离线检查已实现；运行时启动须等待 Root 的统一源码 release。门户 workspace 已冻结为 `@kongpilot/portal-web`，独立 Origin 变量为 `PORTAL_PUBLIC_ORIGINS`。

## 入口和网络

门户为独立 `apps/portal-web` 应用及 `portal-web` Nginx 服务。演示监听 `127.0.0.1:8082`，生产使用独立 HTTPS 主机名。门户不导入 Console AuthContext、会话缓存、签名秘密或管理请求客户端。

生产默认 `docker-compose.yml` 新增 `portal-edge` 内部网络及门户服务：固定 `172.28.41.0/24`，仅API `.10`、门户 `.20`。另有 `portal-entry` 非internal bridge：固定 `172.28.42.0/24`，只有门户 `.20`，使Docker实际发布localhost8082；API绝不加入该入口。两网可显式配置，必须互不重叠。门户 Nginx 不带 Kong Admin、Console/Kong 数据库、Redis、telemetry 或 observability 接口；API保留已有受保护接口，普通出站同时保护门户两IP。无需迁移既有网络或重新创建 Kong/数据库；保持 M5采集器三接口及精确Admin ACL。

门户 Nginx 内部监听8080，仅 `^~ /api/v1/portal/` 代理到同网 API 的3000；其他 `/api/` 请求返回404，不提供管理 Swagger、health API、任意代理或内部9092/9093入口。`/healthz` 仅返回固定文本，静态路由采用 SPA fallback。Host 保留外部端口，X-Forwarded-For 用连接来源替换，日志只记录 method/path/status/time，不记录 query、Referer、UA、header、body；请求上下文 error 日志采用现有明确 tradeoff。

管理站 Nginx 同时拒绝公开门户 `/api/v1/portal/` 前缀；其 `/api/v1/clusters/:cid/portal` 管理接口仍由管理 API 处理。这使同主机演示的 Console 端口无法代理携带门户 Cookie 的私有 GET；生产独立主机名仍是浏览器 Cookie 隔离的必要部署边界。

门户响应 CSP 限制 self 脚本/连接，frame-ancestors/object-src 为 none；样式按 Ant Design 需要允许 inline，图片限制 self/data。Nginx 不解析 OpenAPI/Markdown，不提供任意远程 URL；应用自身仅渲染已脱敏的公开文档。

## 镜像和环境

构建采用现有 Node22、锁文件、workspace-only `npm ci`，保留可选 BuildKit `proxy_ca` 信任，禁止 TLS bypass。Portal runtime 使用经 Root 最终批准的 Nginx 基础镜像，非 root UID/GID101、8080端口、cap_drop ALL、NNP、只读根文件系统；PID/client/proxy 临时路径统一位于 tmpfs `/tmp`，自定义主配置避免非 root 写入默认 `/var/cache/nginx`。运行镜像只复制静态文件和公开 Nginx 配置，不含环境文件、源映射秘密或构建 CA。

Root 添加门户 workspace manifest、锁文件及全局 build/typecheck 脚本。API、ConsoleWeb、PortalWeb Docker builder 同步复制新的 workspace manifest，避免全局锁文件与 builder workspace 图不一致。门户不引入 ECharts、Swagger UI、HTML 执行器或额外 YAML 解析包。

`PORTAL_SECRET` 仅注入 API，不注入 Portal/Console bundle、Nginx或 collector。至少32随机字节，独立于 APP_SECRET 和加密密钥。生产base强制NODE_ENVproduction且Origin变量required；HTTP演示只由development override明确切换NODE_ENVdevelopment/COOKIE_SECUREfalse，认证策略不放宽。生成器只为缺少的新配置生成值；现有秘密不可静默覆盖。文件0600、原子替换、现有密钥保持验证只输出布尔值。迁移不生成门户登录秘密。

已新增 `PORTAL_PUBLIC_ORIGINS`，与 Console SSO 的 `PUBLIC_ORIGINS` 独立：演示仅 `http://127.0.0.1:8082,http://localhost:8082`，生产为显式 HTTPS 门户 Origin，不保留演示值。该名称已经认证所有者确认。不得以请求 Host/X-Forwarded-Host 自行决定被允许的 Origin；仅用两个不同端口也不能代替不同 Cookie 名称、签名、issuer/audience和会话表。

三个门户 Cookie 采用已有冻结合同：`kongos_portal_access`、`kongos_portal_refresh`、`kongos_portal_csrf`，Path=`/api/v1/portal`，HttpOnly、SameSite=Strict，生产 Secure。登录/注册、刷新/退出及 Cookie 写入发送 `X-Portal-CSRF`，Origin由服务器配置严格检查；管理守卫不接受门户JWT，门户守卫不接受管理JWT。

## 阶段流水线

M6 增加 `--portal` 阶段开关；本地验证仍用 API/Console/Portal dist 的只读目录绑定，独占一次全局 build，然后迁移008、重启 API、启动/重载 Portal与Console并验证 readiness。`prepare-development` 仅将公开 dist/Nginx/collector 文件修正为可读权限，不能遍历私有秘密目录。

后续阶段始终携带现有 `--multicluster --observability`，但将“监控材料注册”与“已配置服务保持运行”分开。M6 不重跑 enrollment、不改 Prom target/config或 token 文件、不轮换 generation；只检查当前材料与已有注册匹配、服务 healthy。Portal 配置不改变旧网络IPAM、collector身份或具名卷。

启动证据扩展为Portal健康、当前构建文件SHA、严格双网络及backend两成员/entry唯一门户、实际NetworkSettings.Ports与HostConfig都仅发布localhost8082、两接口IP出站保护、无Admin/storage/telemetry接口、未公开API3000/9092/9093、non-root/capdrop/readonly及被禁止的门户API路径。还从门户实际进程探测受保护服务的DNS、literalIP HTTP与TCP不可达。端到端凭证申请与真实认证由安全/Web所有者串行执行；部署readiness不代替批准工作流和网关凭证验收。

## 既有 M5 四用途密钥的测试取回

M5 最终扫描会删除原始私有测试引用。M6 必须按当前活动 generation 重新取回 C1/C2 的四类既有令牌，用于旧/新权限矩阵和整个 M6 artifact 扫描；不能为获得测试密钥而无谓轮换，也不能仅用三个宿主文件猜测 raw ingest。

已实现可信 CLI `dist/infrastructure/metrics-test-capture.js`，仅测试负责人显式启用，输入为有界 JSON stdin `{clusterIds: UUID[]}`，最多8集群；不提供HTTP端点，不接收任意输出路径或原始 token argv/env。CLI 使用 API 运行时现有数据库身份和加密上下文，在一致数据库快照内读取当前设置与活动四用途 family，逐项校验purpose/audience/generation、解密后指纹和四把秘密的互异性。错误只输出安全固定码，不包含行正文或解密值。

CLI 在固定 `/dev/shm` 创建随机0700目录及0600文件，验证为 tmpfs 后写入 `{tokens:[{clusterId,generation,purpose,audience,token}],secrets:[...],users:[]}`。stdout仅返回安全完成标识、随机捕获ID、路径、CID/generation/count，绝不返回 raw JSON bundle。可信宿主工具用 Docker copy 将文件复制至自己创建的0700临时目录，校验所有者/0600/无符号链接/大小，再原子写入 `/tmp/kongos-m6-runtime-secrets.json`。不存在会话或HTTP转发，不把原文送入工具输出、artifact或repo。

宿主和容器临时材料在 finally 清除；最终测试引用交 Security持有至全部HTTP、浏览器、人工截图、清理及扫描完成。Security的扫描同时覆盖 token 原值、Basic `base64(kongos:<token>)` 和完整 Basic header；最终删除此引用。阶段脚本与Docker日志只输出数量、generation及布尔检查。

Storage 已实现独立捕获 CLI，宿主入口为 `capture-existing-metrics-test-reference.mjs M6 --test-only --multicluster`。只有显式阶段标志 `--capture-existing-metrics-test-reference` 才触发；默认部署和 `--verify-only` 不捕获秘密。现有 enrollment/status CLI 不导出秘密。
