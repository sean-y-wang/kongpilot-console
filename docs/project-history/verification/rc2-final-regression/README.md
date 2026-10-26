# §52 rc.2 clean single-pass final regression (2026-10-26 UTC+8)

Images `kongpilot/{console-api,console-web,portal-web}:v1.0.0-rc.2` (tag → 8ea549e), stack `kp-bridge` production compose (bridge), live Kong 1.5.1, offline DNS (EAI_AGAIN). Runner `single-pass-runner.sh` (private paths → `$PRIVATE`), one uninterrupted pass 00:55:52 → 01:07:48 UTC+8, no splicing.

| Suite | Result |
|---|---|
| bridge smoke (offline DNS) | **22/22** |
| concurrency (in smoke) | 20 admins × 10 iterations = 800 requests, **0 errors**, overall p95 281 ms (read p95 72 ms, write p95 562 ms) |
| fault injection (Redis stop / Kong pause) | **17/17** |
| PG backup/restore (in-place) | **9/9** |
| browser matrix (single process) | **11/11** |

## Harness changes (test only; product untouched, gates unchanged)
- `/audit/global/integrity` 1000-row budget + `nextCursor` is the documented contract (technical-operations-reference: "处理partial与nextCursor，不能只查第一页报complete"; `tests/security/lib/production-audit-integrity.mjs`). Smoke + PG now walk cursors to `status=verified, complete=true`; any non-budget reason / stale cursor = fail.
- Concurrency: shared client limiter 16 r/s (all simulated admins share 127.0.0.1 vs edge 20 r/s per-IP gate); limiter wait recorded and excluded from latency; thresholds (read p95<1 s, write p95<3 s, 0 errors) unchanged; 429 still counts as an error.
- Preconditions: fixture reset from pre-race console DB dump + Kong Admin residue cleanup, cluster-B overlay removed for smoke/fault/PG (port-minimality check), re-added for matrix; fault suite explicitly `PCE_PROJECT=kp-bridge REDIS_SERVICE=redis KONG_SERVICE=kong`.

Discarded attempts 0–4 are listed in `progress.log` (all harness/lab causes); their artifacts are kept privately and not counted.
commercialClosed = **false** (not flipped; owner decision).
