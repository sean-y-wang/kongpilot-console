# M11 production compose on bridge networks (2026-10-25 UTC+8, HEAD 3ffe860 + Kong worker fix)

Stack: `docker-compose.yml` + `deploy/compose/compose.production.yml`, project `kp-bridge`. Every service is on a user-defined bridge network, nothing uses host networking, and the only published ports are on 127.0.0.1 (console 48443, portal 49443, Kong proxy 47800). The real env and TLS material are kept in a private directory outside the repo. `bridge.env.redacted` contains the key names only, with secrets, usernames and private paths removed.

## Box-environment accommodations (not product changes)
- The box runs iptables-legacy with FORWARD policy DROP, which blocks traffic between bridges. Fix: `iptables-legacy -I DOCKER-USER 1 -i br-+ -o br-+ -j ACCEPT`.
- Run 2 only: DNS egress to the box resolver, via `-I DOCKER-USER 2 -i br-+ -o enp0s3 -p udp --dport 53 -j ACCEPT` and `-I DOCKER-USER 3 -i enp0s3 -o br-+ -p udp --sport 53 -j ACCEPT`. The box resolver is a fake-IP resolver that answers 198.18.0.1 for every name. Both rules can be removed with `-D`.

## Results
| File | Result |
|---|---|
| bridge-smoke-concurrency-evidence.json | **22/22**: topology, TLS, auth negatives, Kong probe via internal DNS, service+route write live on proxy, audit rows, 20 concurrent admins (800 req, 0 errors; p50 64 ms, p95 405 ms; reads p95 103 ms; writes p95 1436 ms incl. 409 RESOURCE_LOCKED retries), edge 429 engages, audit integrity verified |
| bridge-smoke-concurrency-no-upstream-dns-evidence.json | 17/22. The service and route writes ended `KONG_WRITE_RESULT_UNKNOWN` (DNS-starvation finding, below). Concurrency had 0 errors |
| pg-backup-restore-inplace-evidence.json | **9/9**: drop and restore of the bridge console-db. 189 tables / 6177 rows identical, audit chain 1605 events with 0 breaks, product integrity verified, login, IAM and a post-restore write all OK |
| pg-backup-restore-scratch-evidence.json | **4/4**: read-only snapshot dump of the lab DB (workflows 97, approvals 77, audit 2255) restored into a `--network none` scratch container. 189 tables / 35087 rows identical |
| grype-dry-run-summary.json | DRY RUN (grype 0.121.0, not the pinned 0.120.1; untagged). 0 Critical, 13 High, 0 fixable. Every match is covered by the acceptance list |

## Findings
1. **Fixed: Kong OOM.** Kong 1.5 `worker_processes auto` starts 8 workers of about 240 MiB each on this host, and the 1 GiB limit OOM-kills them, so the Admin API returns empty replies. The earlier host-network evidence compose hid this by running 1 worker. Fix: `KONG_NGINX_WORKER_PROCESSES` defaults to 2 in compose.production.yml. Verified: about 520 MiB, `/status` returns 200.
2. **OPEN: DNS starvation without upstream DNS.** The destination policy resolves configured private hosts that console-api cannot reach (each lookup hangs 8–16 s). The 1 s race does not cancel getaddrinfo, so the 4-thread libuv pool saturates and `lookup('kong')` hits its 5 s timeout. Kong writes then become uncertain, and later overlapping writes are blocked fail-closed with `MUTATION_RECONCILIATION_REQUIRED` (correct behaviour). This affects air-gapped hosts. Candidate fixes: a c-ares `Resolver` with a timeout, or skipping hosts that are not attached. Workaround: a working resolver.
3. Note: the 409 `RESOURCE_LOCKED` lock is per Kong cluster, but its message says "同一对象" (same object). That is misleading UX.
