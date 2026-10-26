# 0011. Redis Cluster mode and key prefix

- Status: Accepted
- Date: 2026-10-26

## Context

Enterprise deployments use managed (DBaaS) Redis Cluster shared between environments. The API only supported a standalone `REDIS_URL` and wrote unprefixed `kongos:*` keys.

## Decision

- Add `REDIS_MODE=standalone|cluster` (default `standalone`, unchanged behaviour) using `ioredis.Cluster` in cluster mode, with `REDIS_CLUSTER_NODES`, `REDIS_PASSWORD`/`REDIS_USERNAME`, `REDIS_TLS`.
- Add `REDIS_KEY_PREFIX` (default empty) implemented with ioredis `keyPrefix`, so it applies uniformly to commands and EVAL `KEYS`.
- Keep every Redis interaction single-key; Lua scripts declare all keys in `KEYS`. The code does not use `KEYS`/`SCAN` (ioredis does not prefix patterns), pub/sub, `MULTI` or multi-key commands. Any future multi-key operation must co-locate keys with a hash tag and is reviewed against a real cluster.
- Keep `dnsLookup` identity so DBaaS hostnames (and TLS SNI) are used as given.

## Consequences

- Existing deployments need no change. Changing `REDIS_KEY_PREFIX` on a live system orphans in-flight locks/rate-limit windows (they expire within 30 s / one window) and OIDC states (5 min); session revocation is authoritative in PostgreSQL.
- CI runs a 3-master cluster integration suite (`scripts/verification/redis-cluster-test.sh`).
