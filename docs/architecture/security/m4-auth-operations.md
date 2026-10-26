# M4 认证与操作恢复说明

本说明覆盖控制台账号和已实现的 LDAP/OIDC 可选提供方。开发者门户账号在 M6 单独实现。M4 的真实 HTTP/数据库验收以 `artifacts/M4` 中的最终证据为准；使用 mock 的单元测试不代表已连接企业 IdP。

## 部署配置

| 环境变量 | 默认值/作用 |
| --- | --- |
| `PASSWORD_BCRYPT_ROUNDS` | `12`；只允许 10–14，所有新增/重置密码共用策略 |
| `COOKIE_SECURE` | 本地 HTTP 演示显式 `false`；正式 HTTPS 部署必须 `true` |
| `PUBLIC_ORIGINS` | 逗号分隔的固定控制台来源，例如 `https://console.example.com` |
| `AUTH_PROVIDERS_JSON` | `[]`；仅在 API 容器配置，最多 16 个提供方、64 KiB |
| `AUTH_PROVIDER_ALLOWED_HOSTS` | 空；逗号分隔的固定主机或 `主机:端口`，推荐后者 |

提供方密钥只进入 API 环境，不进入浏览器构建、迁移日志或公开目录接口。需要自签企业 CA 时，通过 Node 的可信 CA 配置导入证书；不能关闭 TLS 证书校验。配置不合法会阻止认证模块启动，不降级为其他登录方式。

应用访问 Kong 仍经 BFF；认证提供方允许列表不会授予 Kong Admin API、Redis 或数据库访问权。配置的 IdP/LDAP 主机解析到回环、链路本地、元数据、多播或 IPv4 映射 IPv6 地址时拒绝连接。固定 DNS 结果绑定本次传输，HTTP 不跟随重定向，JSON 响应最多 1 MiB。

## 本地账号和会话

新密码至少 12 个 Unicode 字符，最多 72 个 UTF-8 字节，包含大写、小写、数字及符号；禁止 NUL，并禁止与当前密码相同。旧账号不会在迁移时自动轮换密码。管理员重置后要求用户先修改密码。

登录失败 5 次锁定 15 分钟，另有按来源 IP 和账号的限流。密码摘要使用 bcrypt；access JWT 固定 HS256、issuer/audience、15 分钟有效期，refresh 会话 7 天。每次认证读取当前账号状态、未撤销会话和 credential epoch，JWT 内的角色/admin 字段不能授权。

刷新按用户→会话的顺序锁定，旋转 refresh hash 并保留已使用 hash。已使用 refresh 重放会撤销该会话家族；任意错误 secret 不会仅凭猜中的 session UUID 撤销别人的会话。refresh token/hash、CSRF hash 不进入会话列表或审计。

每个账号最多保留 10 个有效登录会话。个人页面可分页查询和撤销自己的会话；跨用户管理需当前全局 `users` 权限，平台账号还需当前平台管理员身份。撤销请求必须提供 `confirmed:true` 和操作者当前用户名 `confirm_name`。重置/改密在同一 SQL 事务内递增 credential epoch、撤销全部会话并写审计。

个人资料 PATCH 只接受 `display_name`、`locale`、`timezone`、`revision`，目标始终是当前用户。修改密码只接受 `current_password`、`new_password`、`revision`、`confirmed`；外部认证账号应在 IdP 修改密码。

## LDAP

提供方 JSON 的 LDAP 条目接受以下固定字段：

```json
{
  "id": "corporate-ldap",
  "name": "企业 LDAP",
  "type": "ldap",
  "url": "ldaps://ldap.example.com:636",
  "bind_dn": "cn=console-reader,ou=system,dc=example,dc=com",
  "bind_password": "由部署密钥管理器注入",
  "base_dn": "ou=people,dc=example,dc=com",
  "username_attribute": "uid",
  "subject_attribute": "entryUUID",
  "groups_attribute": "memberOf",
  "group_roles": {}
}
```

仅支持 LDAPS。`subject_attribute` 必须返回唯一稳定字符串，不应使用会变化的显示名。服务账号执行最多两条结果、5 秒搜索；恰好一条合法记录才进行用户 bind。用户输入按 RFC 4515 转义，不支持客户端提供 LDAP filter/base DN/地址。

`group_roles` 是目录组字符串到现有控制台角色 UUID 数组的映射，按返回组精确匹配；没有映射的账号可以登录，但没有配置权限。TLS 连接/操作均有超时，失败统一报外部认证失败，不回显目录返回体。

## OIDC

OIDC 条目接受固定字段 `id,name,type,issuer,authorization_url,token_url,jwks_url,client_id,client_secret,callback_uri,groups_claim,group_roles`。issuer、授权、token、JWKS 地址必须是无账号/密码/query/hash 的固定 HTTPS URL，并登记在允许列表中。不能从请求参数替换 issuer 或 JWKS，也不通过动态 discovery 扩展访问地址。

示例回调为 `https://console.example.com/api/v1/auth/oidc/corporate-oidc/callback`，来源须登记在 `PUBLIC_ORIGINS`。授权请求使用 code + PKCE S256；state、nonce、verifier 仅保存在 Redis，5 分钟有效且 callback 原子 GETDEL。临时关联 cookie 使用 HttpOnly/SameSite=Lax，控制台登录 cookie 保持 SameSite=Strict。

验签支持 RS256、PS256、ES256；RSA 密钥限制 2048–8192 位，EC 限 P-256。同时核对 issuer、audience、多 audience 的 azp、nonce、iat、exp 和唯一 kid。只信已验证 ID token 的稳定 sub 与配置的组声明；不按 email/用户名关联现有账号。最终重定向仅允许 `/`、`/overview`、`/profile`。

本地 HTTP 的 Compose 演示不代表 OIDC 正式回调可用。正式容器要求 HTTPS 回调；仅非 production 且显式设置 `AUTH_ALLOW_INSECURE_CALLBACK_FOR_DEV=true` 时可用固定 HTTP 开发回调。

## 外部身份与角色同步

身份键由提供方类型、配置标识/issuer 指纹和稳定 subject 构成。首次认证创建独立 `ext-...` 非平台账号，不能占用已有管理员用户名；已撤销身份或停用/删除账号不能被外部登录复活。LDAP/OIDC 映射不得授予内置 super-admin 角色。

组角色在每次外部登录时同步，而非持续后台同步。同步只撤销该身份提供方创建并记录归属的绑定，保留人工授予的绑定；角色按原配置的 cluster/workspace 范围生效。组变化会撤销既有会话并更新权限版本，再创建此次新会话。紧急撤权使用控制台停用/撤销会话，不能依赖用户下一次外部登录。

## 密码重置与未知结果

管理员 `POST /api/v1/iam/users/:id/reset-password` 必须携带原始 `X-Idempotency-Key`（8–128 个字母、数字、点、下划线、冒号或短横线），正文为 `{revision,new_password,confirmed:true}`。中央服务重新核对当前全局权限、目标类型和 revision CAS；任何调用方不能注入独立事务或原始执行权。

密码/epoch/会话、requested/result 审计和 `iam_operations` 成功回执在同一 SQL 事务提交。明文密码不存入 ledger、回执、审计或可搜索 hash；请求绑定只用密钥 HMAC。相同 actor/key/目标/revision/password 输入只返回原回执，不重复 reset。可通过 IAM by-key 回执查询 `state` 和 `remote_completed`。

COMMIT 已完成但响应丢失时返回 `IAM_RESULT_UNCERTAIN`；不会把已成功 ledger 改写为 failed/uncertain。先查询原回执，不能换新 key 猜测重发。自助改密响应中断时结束本地会话，用户用新密码重新登录；个人资料以新 GET 返回的 revision 核验。

## 网关变更的持久化阻断

网关操作 `running/uncertain` 未得到可信证明前，同对象的新 key 写操作会被后端拒绝。影响面包含对象/自然名、Target 的 Upstream+地址、Plugin 多绑定、Consumer 凭证及完整归档/迁移图；匹配跨操作者、工作区和相同 Admin 地址的注册别名。浏览器恢复缓存过期/清空不会解除阻断。

影响列只保存 HMAC 标识，不保存配置或凭证明文。旧 NULL scope/impact 必须解密真实对象证明归属，无法证明时保守阻断，不能默认归入默认工作区。M4 只提供只读回执；通用手动改状态接口尚未提供。工作区迁移可用既有只读 reconcile，在物理锁内核对新鲜完整图后仅更新对应计划/回执。

真实不同 Admin 地址且未显式登记共同 `transport_scope` 的集群不能被声称自动发现共享数据库；控制台不会访问 Kong 数据库。正式部署必须确保外部写入遵循同一 BFF/锁机制。
