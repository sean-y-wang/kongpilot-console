# §45 Bridge production compose without upstream DNS + fault injection (2026-10-25 UTC+8)

Stack: `docker-compose.yml` + `deploy/compose/compose.production.yml`, project `kp-bridge`, console-api image built from the §45 working tree (`kongpilot/console-api:m11-bridge-s45`). The env is the same private bridge env as in `20261025-1453-production-compose-bridge/` (see `bridge.env.redacted` there; only the API image tag changed).

**No upstream DNS.** The DNS-egress rules from §44 were removed. `iptables-docker-user.txt` shows that only bridge↔bridge forwarding is allowed (a box accommodation). Inside console-api, `dns.lookup('example.com')` returns EAI_AGAIN, and absent names hang for about 8 s.

| File | Result |
|---|---|
| bridge-smoke-concurrency-offline-dns-evidence.json | **22/22** with no upstream DNS (§44 got 17/22 here). 20 admins × 10 iterations = 800 requests, 0 errors, p50 63 ms, p95 638 ms, max 3.9 s (409 cluster-lock retries included) |
| bridge-fault-injection-evidence.json | **17/17**. 20 sequential writes: 201. The 409 lock message says it is a cluster-level lock. Redis stop: ready 503 NOT_READY and writes 503 REDIS_UNAVAILABLE, recovers after restart. Kong pause: ready stays 200, the write fails closed with 503 KONG_WRITE_RESULT_UNKNOWN, and the next write after unpause gets 201 |

## Root cause, as measured
In the offline container, two concurrent getaddrinfo calls for absent names delayed `dns.lookup('kong')` by about 7.9 s, even though the libuv pool still had free threads (a parallel fs read completed in 0 ms). Over the same window, c-ares `resolve4('kong')` answered in 0 ms. Capping threadpool concurrency alone did not fix it; this was verified with a first build. The fix moves the destination policy's protected-host probes off getaddrinfo:
- `/etc/hosts` is checked first;
- then the c-ares Resolver (timeout 1 s, 1 try, A+AAAA);
- getaddrinfo is used only after a definitive NXDOMAIN/NODATA, and then single-flight per host and capped at 2 concurrent;
- resolver timeouts are negatively cached for 30 s, and positive answers are not cached.

In-container check: protected IP literals and hostnames are still rejected (Kong Admin IP:8001 and redis both return PROTECTED_PROXY_DESTINATION).
