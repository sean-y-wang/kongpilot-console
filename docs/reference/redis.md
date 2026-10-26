# Redis configuration

[简体中文](redis.zh-CN.md)

The console API uses Redis for rate limiting, distributed change locks, session revocation hints and short-lived OIDC login state. It supports a standalone server (default) or Redis Cluster.

| Variable | Default | Description |
|---|---|---|
| `REDIS_MODE` | `standalone` | `standalone` or `cluster`. |
| `REDIS_URL` | — | Required in standalone mode (`redis://[:password@]host:port[/db]`, `rediss://` for TLS). In cluster mode it is an optional seed node and credential source; only database 0 is allowed. |
| `REDIS_CLUSTER_NODES` | — | Cluster mode: comma-separated `host:port` seed nodes (IPv6 as `[addr]:port`). Falls back to the `REDIS_URL` host. |
| `REDIS_PASSWORD` | — | Cluster mode: node password (takes precedence over a password in `REDIS_URL`). (In the bundled Compose it is also the password of the bundled standalone Redis.) |
| `REDIS_USERNAME` | — | Optional ACL user name. |
| `REDIS_TLS` | `false` (or `true` for `rediss://`) | Enable TLS to every node. |
| `REDIS_KEY_PREFIX` | empty | Prefix applied to every key, e.g. `hf-kong-dev:`. No whitespace or `{}`. |

Cluster example (external DBaaS):

```env
REDIS_MODE=cluster
REDIS_CLUSTER_NODES=redis.example.internal:6379
REDIS_PASSWORD=<secret>
REDIS_KEY_PREFIX=hf-kong-dev:
```

## Cluster safety

All Redis operations are single-key (`SET NX PX`, `GET`, `GETDEL`, `DEL key`, and Lua scripts that only touch `KEYS[1]`), so no cross-slot command exists. The application does not use `KEYS`/`SCAN`, `MULTI`, pipelines, multi-key commands or pub/sub. The prefix is applied by ioredis to all key arguments, including EVAL `KEYS`. Any future multi-key operation must use a hash tag (for example `{lock:<id>}`) — see [ADR 0011](../decisions/0011-redis-cluster-and-key-prefix.md).

Verification: `scripts/verification/redis-cluster-test.sh` starts a throwaway 3-master cluster and runs the integration suite (also run in CI).
