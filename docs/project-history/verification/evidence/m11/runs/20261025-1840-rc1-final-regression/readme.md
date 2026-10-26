# §47 rc.1 final consolidated regression (2026-10-25 18:35–18:50 UTC+8)

Images: built from tag `v1.0.0-rc.1` (8e9c5a3): console-api fb1c497c…, console-web f74022f1…, portal-web 6558a1b0… (the same IDs as §46). Stack: project `kp-bridge`, `docker-compose.yml` + `deploy/compose/compose.production.yml`, live Kong 1.5.1. Only the image tags changed in the private env. **No upstream DNS**: only the br↔br forward rule is present (`iptables-docker-user.txt`), and `dns.lookup('example.com')` inside console-api returns EAI_AGAIN. The client uses self-signed lab TLS (`NODE_TLS_REJECT_UNAUTHORIZED=0`, and `KP_E2E_SELF_SIGNED=true` for Chromium).

| Suite | Result |
|---|---|
| bridge-smoke-concurrency-evidence.json (offline DNS) | **22/22**. 20 admins × 10 iterations = 800 requests, 0 errors. p50 61 ms, p95 559 ms, max 3.85 s (217 cluster-lock 409 retries included). Edge 429 engages, audit integrity verified |
| bridge-fault-injection-evidence.json | **17/17**, 0 failed: Redis stop/start and Kong pause/unpause. Kong is healthy again afterwards |
| pg-backup-restore-inplace-evidence.json | **9/9**: in-place dump, drop and restore, checksums identical, audit chain intact, login/IAM/write after restore. API ready about 2.1 s after restore |
| browser-e2e/browser-e2e-matrix.json | **6/6 applicable checks pass** (8 executed: 6 pass, 2 blocked by fixtures, see below) |

## Browser matrix on the bridge stack
Bridge fixtures were created through the product API: approver and read-only users, a second workspace, and a fixture service with a route. The bridge cluster was then switched to `execution_mode=approval` through the API.

**Passed:**
- KP-007: bad password rejected;
- KP-007: read-only role has no write controls, and the backend returns 403;
- KP-004: two-person delete, with Kong returning 404;
- KP-004: restore keeps the original IDs;
- KP-003: an unknown execute result with a mismatching receipt is rejected, and nothing is replayed;
- KP-008: every successful write is audited.

**Blocked by fixtures (no product defect):**
- KP-007 IDOR: the test assumes the read-only user is a *global* auditor. On this stack that user's binding is workspace-scoped, and adding a global IAM binding is itself blocked with 409 APPROVAL_REQUIRED, which is stricter. Supplementary API check: as the read-only user, another workspace's workflows return 403 and a fake cluster returns 403. Access is denied in both cases, though the test expected 404.
- KP-004 legacy-origin restore: a fresh stack has no legacy mutation-origin recycle entry (400 instead of 409).

**Not run on the bridge stack:**
- KP-002 scheduling: off by production default (`ENTITY_SCHEDULES_ENABLED=false`).
- KP-006 portal full flow: needs a portal publication and the second-cluster fixture.

Both were covered in the lab matrices (§§ earlier).

The test harness reads Kong state through a temporary **GET-only** relay in console-api's network namespace. Kong Admin only allows the BFF IP, which is production hardening. The relay was removed after the run.

## State left behind
- The bridge cluster remains in `execution_mode=approval`. Switching it back requires an approval workflow.
- The rc.1 stack is still running.

commercialClosed=false. Remaining work: rebrand screenshots.
