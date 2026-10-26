# Redis 配置

[English](redis.md)

控制台 API 用 Redis 做限流、分布式变更锁、会话吊销标记和短期 OIDC 登录状态。支持单机（默认）和 Redis Cluster。

| 变量 | 默认值 | 说明 |
|---|---|---|
| `REDIS_MODE` | `standalone` | `standalone` 或 `cluster`。 |
| `REDIS_URL` | — | 单机模式必填（`redis://[:密码@]主机:端口[/库号]`，TLS 用 `rediss://`）。集群模式下可作为种子节点和凭据来源，只允许 0 号库。 |
| `REDIS_CLUSTER_NODES` | — | 集群模式：逗号分隔的 `host:port` 种子节点（IPv6 写成 `[地址]:端口`）。未设置时取 `REDIS_URL` 的主机。 |
| `REDIS_PASSWORD` | — | 集群模式：节点密码（优先于 `REDIS_URL` 中的密码）。（自带 Compose 中它也是内置单机 Redis 的密码。） |
| `REDIS_USERNAME` | — | 可选 ACL 用户名。 |
| `REDIS_TLS` | `false`（`rediss://` 时为 `true`） | 对所有节点启用 TLS。 |
| `REDIS_KEY_PREFIX` | 空 | 所有键的前缀，例如 `hf-kong-dev:`。不能含空白或 `{}`。 |

集群示例（外部 DBaaS）：

```env
REDIS_MODE=cluster
REDIS_CLUSTER_NODES=redis.example.internal:6379
REDIS_PASSWORD=<secret>
REDIS_KEY_PREFIX=hf-kong-dev:
```

## 集群安全

所有 Redis 操作都是单键的（`SET NX PX`、`GET`、`GETDEL`、单键 `DEL`，以及只访问 `KEYS[1]` 的 Lua 脚本），不存在跨槽命令；应用不使用 `KEYS`/`SCAN`、`MULTI`、pipeline、多键命令或发布订阅。前缀由 ioredis 统一加到所有键参数上，包括 EVAL 的 `KEYS`。以后新增多键操作必须使用 hash tag（例如 `{lock:<id>}`），见 [ADR 0011](../decisions/0011-redis-cluster-and-key-prefix.md)。

验证：`scripts/verification/redis-cluster-test.sh` 会启动临时 3 主节点集群并运行集成测试（CI 中也会运行）。
