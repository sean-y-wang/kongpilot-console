# 生产 UI 补验的严格 TLS 初始化

本文是 **SOURCE-only 准备**。没有启动浏览器、读取当前用户 NSS 数据库或私有引用、注册/删除证书、发起 HTTP、登录或刷新。178 项 UI runner 和其冻结清单保持不变；M8 实际业务验收尚待真实 GREEN，不把本方案当作生产验收证据。

## 已检查的安装能力

2026-10-11 只读检查系统可执行路径、包版本、帮助和 Chromium 静态二进制字符串：

| 组件 | 已观察的本机安装 |
| --- | --- |
| Chromium | `/usr/bin/chromium`；包版本 `154.0.8037.57-1~deb13u1` |
| NSS 工具 | `/usr/bin/certutil`、`/usr/bin/modutil`；`libnss3-tools 2:3.110-1+deb13u4` |
| NSS 库 | `/usr/lib/x86_64-linux-gnu/libnss3.so`、`libnssutil3.so`、`libssl3.so` |
| 用户证书库路径线索 | 当前 Chromium 二进制包含 `.pki/nssdb`；实际使用路径仍由严格 TLS 正例证明 |
| certutil 操作 | `-A` 添加、`-L` 查看公开证书、`-D` 按 nickname 删除；`C,,` 仅信任其签发服务器证书 |

没有查询现有用户证书或 key 列表；没有修改 HOME、XDG 路径或现有信任配置。文件名字符串及已安装工具不能代替实际 TLS 验证成功。

## 实际窗口中的最小信任变更

由 Root 协调唯一实际信任配置窗口，在 M8 闭环后、生产验收新 HTTPS fixture 已确定时执行；Source 阶段不执行这些步骤。

1. DevOps/Security 交付本任务**公开**测试 Root CA PEM、DER SHA256、证书有效期和实际 HTTPS origin。Root CA 必须 `CA:TRUE`、具备签发用途；不能导入 CA 私钥。服务器 leaf 的 SAN 必须包含 origin 的精确 DNS 主机名；IP origin 必须有对应 IP SAN，不能用 CN 或 HTTP 跳转补偿。
2. 使用当前真实用户的 Chromium NSS SQL 数据库，显式传 `-d sql:<actual-current-user-home>/.pki/nssdb`。不给 HOME/XDG 重新赋值，不使用 certutil 隐式默认 `~/.netscape`，不假定 `--user-data-dir` 会隔离 NSS 信任库。对目录/文件执行实际 UID、符号链接、权限边界检查；不枚举或导出私钥。
3. friendly ID 固定为 `KongOS production-ui <testTag> <CA-SHA-prefix>`。保存注册前所有**公开**证书 DER 指纹、nickname 和 trust flags。若该 nickname 已存在，或相同 CA DER 在任何原 nickname 下已存在，停止而不覆盖、改 trust 或认领旧条目；应由 fixture owner 重新提供唯一测试 CA。
4. 对已存在且可访问的 NSS DB，仅执行 `certutil -A -d <exact-sql-db> -n <exact-friendly-id> -t C,, -i <public-root-ca.pem>`，再按 exact nickname 导出公开证书并比对 DER SHA/trust flags。不能 `-M` 修改旧信任，不能 merge/reset 数据库或读取密码材料。若库有密码、损坏或不可访问则停止；不得改密码。若用户库不存在，需在实际信任窗口明确记录新建数据库，只初始化全新 0700 目录，不能对既有数据库运行 `-N`；清理仍只删除本任务条目，不删除整库。
5. 同时准备任务公开 Node CA bundle，保留既有明确配置的额外**公开**根证书，再加入该测试 Root CA。绑定 bundle SHA、Root CA DER SHA、leaf SAN/有效期和实际 origin 到安全 TLS 报告；不输出或读取私钥。
6. 关闭本任务所有浏览器/Context 后再清理信任。清理前重新核对 nickname 对应相同 DER SHA，然后仅 `certutil -D -d <exact-sql-db> -n <exact-friendly-id>`。重新检查全部旧公开证书 fingerprint/trust 与注册前一致、本任务条目缺失。禁止删除其他 nickname、修改其 flags、恢复整库副本覆盖别人的变更或删除现有 NSS 目录。

如果注册前已有同 DER，不能以新 nickname 添加后再按 nickname 删除，因为 NSS 可能复用同一证书记录。必须在注册前阻止该情况。异常退出应留下 exact nickname、公开 DER SHA 和清理状态，由唯一信任配置 owner 完成窄清理；不能在失败时批量删除信任。

## 浏览器与 Node 两个严格 TLS 通道

生产 runner 调用 `chromium.launch` 和 `browser.newContext`，默认 TLS 校验保持启用，不依赖 `playwright.config.ts` 的启动选项继承。它使用已确认的 `/usr/bin/chromium` 或 Root 明确的同一系统 Chromium 路径；`serviceWorkers:'block'`、新临时浏览器 profile、空旧账号状态，之后才加入本次受信会话。

Chromium 的 NSS 信任**不能保证** Playwright `context.request.get` 的 Node 请求也信任该 Root CA。当前 runner 使用这个请求通道做 protected BFF GET，必须为该 Node 进程在启动时提供已绑定 SHA 的公开 CA bundle：

```text
NODE_EXTRA_CA_CERTS=<task-public-ca-bundle.pem>
PRODUCTION_UI_EXCLUSIVE_READY=true
node --import tsx tests/security/production-ui-lifecycle.mjs
```

这是示意参数，不是本阶段运行命令。NODE_EXTRA_CA_CERTS 由 Node 启动时读取，不能在已启动进程内赋值后声称生效；如果原来已有额外 CA 文件，任务 bundle 应保留其公开 roots，不能静默替换掉原信任。原 HOME、原环境配置文件和系统 CA bundle 不变。独立 unused-tail 采用同一个已验证公开 CA bundle。

禁止 `ignoreHTTPSErrors:true`、`--ignore-certificate-errors`、SPKI 忽略列表、`--allow-insecure-localhost`、`NODE_TLS_REJECT_UNAUTHORIZED=0`、`rejectUnauthorized:false` 或降低安全 TLS 校验的代理设置。`--user-data-dir` 不是 CA 配置；`NODE_EXTRA_CA_CERTS` 也不是 Chromium NSS 配置。严格校验失败时停止，不加临时忽略开关。

实际 HTTPS 预检必须先用无认证上下文证明 Chromium 对正确 hostname 的 TLS 与 UI 静态页面成功，再通过同来源无敏感请求证明 Node 请求通道成功。两者验证之后，Security 才交付新 production 原 SID 和近 15 分钟签名 access，避免把会话有效期消耗在信任配置阶段。禁止把 HTTPS 未验证的部分报告用作 UI handoff。

## 证书 hostname 与信任负例

负例使用**独立无认证** Chromium Context 和 Node 请求上下文，不加入账号 Cookie/CSRF，不运行178项 CRUD，不新登录、不修改原 journal。目标仅为 fixture owner 预先批准的 HTTPS 测试 listener，禁止访问 Admin API。178 runner 的来源边界会在 TLS 之前阻止外 origin，因此不使用该 runner 冒充 hostname 负例。

| 情况 | fixture 与检查 | 必需事实 |
| --- | --- | --- |
| 正确主机 | 任务可信 Root CA 签发、有效 leaf、SAN 包含精确 origin hostname | Chromium 与 Node 均严格成功；leaf/public root 指纹及 SAN 可核对，无校验忽略选项 |
| hostname 不匹配 | 相同 listener 与 leaf；批准的另一个 DNS alias 不在 leaf SAN 中。若需 DNS 定向，仅使用一次性测试进程的精确 resolver mapping，不改系统 hosts | Chromium 产生 `ERR_CERT_COMMON_NAME_INVALID`，Node 拒绝 hostname；不是 DNS 失败、路由拦截或任意超时，不进入业务 UI、不发送认证 Cookie |
| 不可信签发者 | 另一个未注册的公开 CA 签发有效匹配 leaf | Chromium/Node 拒绝 issuer；不能给第二 CA 注册 trust 来让负例变正例 |
| 已过期 leaf | 同可信测试 Root CA，匹配 SAN，但 leaf 的 notAfter 确已过去 | Chromium `ERR_CERT_DATE_INVALID`、Node 拒绝有效期；不能修改系统时钟或伪造 expiry |

每个负例记录请求 target hostname、批准 listener、公开 leaf/root SHA、错误分类、实际 UTC、认证写0/业务写0。只有预期 TLS 分类可算该负例通过；任意错误不能算成功。证据不能包含 Cookie、账号密码、私钥或 raw TLS keylog。

## 待实际完成的证据

本 Source 准备仅证明工具安装可行。生产补验还需 Root/Security/DevOps 的实际 origin/公开 Root CA、严格 Chromium/Node 正例、hostname 与 issuer/expiry 负例、任务唯一 CA 注册/精确删除、旧公开 trust 维持证明、真实 UI 当前签名会话交接以及178项实际原键闭环。当前不能声称 TLS 预检、178项 UI 或 M8 验收已通过。
