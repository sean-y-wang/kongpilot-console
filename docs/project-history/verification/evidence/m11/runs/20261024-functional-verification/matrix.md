# kongpilot-console functional verification (2c084f4) — kp-fv stack (Kong 1.5.1 x2, PG16, Redis, BFF :33000)
| Feature | Result | Evidence | Kong calls | Latency |
|---|---|---|---|---|
| Login/session/refresh/CSRF/401/403 denial | PASS | p2.log | 0 | <100ms |
| IAM users/roles/bindings, read-only denial | PASS (approval-mode deadlock P1) | p2.log, lab-interventions.txt | 0 | <100ms |
| Cluster onboarding/probe | PASS | p1-crud.json | 11 | 80-230ms |
| CRUD services/routes/consumers/plugins/upstreams/targets/certs/SNIs/CA, 6 credential kinds (direct) | PASS 124/124 | p1-crud.json | 2-21/op | 50-370ms |
| Target weight 100->55 direct | PASS readback 55 | p1-crud.json | 13 | 210ms |
| Approval workflows (create/target weight/credential/recycle delete; self-approve, reject denial) | PASS | p3-approval.json | 14-79/exec | 1.2-2.7s |
| Recycle-bin list after parent deleted | FAIL (P1) | p4.log | - | - |
| Health/metrics/audit list/integrity/export | PASS | p4.log, p5*.log | 0 | <50ms |
| Snapshot small cluster B | PASS | p4.log | 25 | 1.3s |
| Snapshot/import/backup/scheduled config of realistic cluster A | FAIL CONFIGURATION_CAPTURE_LIMIT (P0) | p4.log, scheduled-target/ | 159 | 13s |
| Governance comparison A->B | PASS (slow) | p5*.log | 34-69 + 22-38 | 4.4-4.7s; detail 1.7-6s |
| Promote plan includeEnvironmentFields=true | FAIL GOVERNANCE_SCHEMA_UNAVAILABLE (P1) | p5.log | - | - |
| Promote plan 5 services (fieldOverrides) | FAIL CONFIGURATION_ORIGIN_PREFLIGHT_BUDGET_EXCEEDED (P1) | p5b.log | 34+46 | 8.9s |
| Promote plan+apply 1 service, Kong B readback, rollback from snapshot | PASS | p5c.log | plan 34+45, apply 126+40, rollback 0+37 | 9.4s / 10.4s / 2.5s |
| Portal settings/publish/dev register-approve-login/app/credential issue-reveal/proxy 200/revoke/proxy 401/IDOR | PASS 29 checks | portal/run2/ | - | full run ~10s |
| Portal rotate | NOT RUN | - | - | - |
| Delete of portal-published service | correctly blocked 403 PORTAL_PUBLISHED_OBJECT | portal/run2 | - | - |
| Scheduled target change | BLOCKED by P0 at import (known >800 calls) | scheduled-target/ | - | - |
| Workflow schedules, vitals, drafts, notifications | NOT VERIFIED | - | - | - |

## Re-verification r2 — fixed build (2c084f4 + fixes), 2026-10-25 00:26–00:36 (UTC+8)
| Feature | Result | Evidence | Kong calls | Latency |
|---|---|---|---|---|
| Snapshot of realistic cluster A (P0 global credential lists) | PASS (was FAIL CONFIGURATION_CAPTURE_LIMIT) | p4-r2.log | 102+8 (was 159 → fail) | 17.1s |
| Snapshot B / list | PASS | p4-r2.log | 27 | 2.3s |
| Promote plan+apply+rollback, includeEnvironmentFields=true (targets schema) | PASS (was FAIL GOVERNANCE_SCHEMA_UNAVAILABLE) | p5-r2-envf.log | plan 36+63, apply 104+48, rollback 0+47 | 10.9s / 11.8s / 3.9s |
| Promote plan 5 services | STILL FAIL CONFIGURATION_ORIGIN_PREFLIGHT_BUDGET_EXCEEDED (open P1, not fixed) | p5-r2-n5.log | 37+66 | 11.2s |
| Recycle-bin list A (orphan entries) | PASS (was FAIL) | p6.log | 12 | 246ms |
| Recycle-bin orphan: route recycled, parent deleted natively, list → 200 + unavailableCount | PASS | p6.log | 9 | 153ms |
| Break-glass CLI status / refuses when not deadlocked | PASS (eligibleApprovers=2 → BREAK_GLASS_NOT_DEADLOCKED) | CLI output | 0 | <1s |
| SQL046 built-in approver role migrated on live DB | PASS | psql | - | - |
| Portal rotate: request → approve/execute → new key proxy 200 → old key 401 → revoke → 401 | PASS 35/37 (2 = pre-existing settings 409 fixture + kp004 published-delete correctly blocked) | portal/run3, portal3.log | - | ~13s |
| Drafts create/list/update/get/archive/restore/cross-user 404 | PASS 7/7 | p6.log | 0 | 14-30ms |
| Notifications list/unread/catalog/preferences | PASS 4/4 | p6.log | 0 | <15ms |
| Notifications delivered to approver for pending workflows | NOT OBSERVED (n=0; delivery needs event worker/preferences — unverified) | p6.log | - | - |
| Audit cluster integrity / global CSV export create | PASS | p6.log | 0 | <45ms |
| Vitals capabilities | PASS; overview → 409 METRICS_CATALOG_CHANGED (no Prometheus in kp-fv lab: env limitation), entities query params rejected by script (script issue) | p6.log | 0 | - |
| Workflow (business) schedules on entity-change workflow | 403 WORKFLOW_BUSINESS_SCHEDULE_OPERATION_SUBJECT_INVALID — correct: entity changes use entity-schedules (scheduled Target path awaiting user decision, untouched); list PASS | p6.log | - | - |

## Re-verification r3 — notifications / real Prometheus vitals / audit export, 2026-10-25 00:48–01:17 (UTC+8)
Lab additions: `kp-fv-prom` (prom/prometheus v2.53.0, host network 127.0.0.1:39090) scraping the BFF metrics bridge (127.0.0.1:39092, METRICS_BRIDGE_ENABLED=true) with per-cluster bearer token files enrolled through the trusted `metrics-enroll.js` CLI (lab-native equivalent of `deploy/scripts/enroll-metrics.mjs`; tokens kept in a 0700 lab-private dir, never printed). No telemetry collector in lab (collector jobs `down`, `collectorEnabled=false`).

| Feature | Result | Evidence | Kong calls | Latency |
|---|---|---|---|---|
| Approver in-app notification for pending workflow (subscribed to workflow.*) | PASS — delivered 1.6s after submit, unread 20→21, mark-read 201 | p7-r2.log | 0 | 1.6s delivery |
| Notifications without a subscription | 0 by design (in-app notifications are opt-in per user subscription) — not a defect | p7.log, DB: 372 events dispatched / 0 subscriptions | - | - |
| Duplicate subscription name | **DEFECT FIXED**: was 500 INTERNAL_ERROR (unique violation leaked) → now 409 NOTIFICATION_PREFERENCE_NAME_EXISTS | p7-r2.log | 0 | 154ms |
| Data source create on approval-mode cluster (control-change prepare) | **DEFECT FIXED (P1)**: was 500 (SQL040 regressed SQL034 clock repair: `issued_at>now()` → every control-change prepare on approval clusters rejected 23514) → SQL047; prepare 201 → submit → approve → execute → succeeded | p8a.log | 0 | 43ms/55ms/73ms/412ms |
| Vitals setup native_prometheus (prepare → submit → approve → execute) | PASS — Kong A global `prometheus` plugin enabled by workflow | p8a.log | 4+1+6 | 112ms/125ms/1.9s |
| Vitals setup on direct-mode cluster B | 409 METRICS_SETUP_APPROVAL_SCOPE_REQUIRED (by design: global monitoring requires approval mode) | p8-B.log | 0 | - |
| Prometheus native scrape via bridge (A, B) | PASS up; samples attributed with cluster_id/node_id/service_id/workspace_id | Prometheus /api/v1/targets | - | - |
| Bridge auth negatives: no token / other cluster's token / wrong purpose token | 401 / 401 / 401 | curl | - | - |
| Vitals overview workspace + cluster (15m, ISO-Z start/end, step) with ~17 rps load | PASS qps≈21, p50≈0.5ms p95≈0.96ms p99≈1.0ms, bandwidth, onlineNodes=1 | p8b.log, p8b-vitals-out.json | ~134 | ~2.0s |
| Vitals overview filtered serviceId (svc-1 under load) | PASS qps≈8.0, topN = svc-1 only | p8c.log | 29 | 412ms |
| Vitals entities type=services/routes/consumers (workspaceId, scope, type, size, cursor, search) | PASS; search+cursor paging finds target (sparse pages) | p8b.log | 1 | 34-43ms |
| Vitals strict params: entities with start → 400; non-Z time → 400 | PASS | p8b.log | 0 | ~10ms |
| Approver (read) vitals overview | PASS | p8b.log | 134 | 2.2s |
| Audit global CSV export create → poll → download | PASS: succeeded, 320 rows, 107,586 B text/csv, download 105ms; header has no secret columns; password fields "[REDACTED]"; no formula-injection prefixes | p9.log | 0 | ~2s total |

Observations (not fixed, product decisions): (a) overview issues ~134 Kong Admin reads per request (~2s) — scales with entity count; (b) control-change approved workflows can only be executed/cancelled from the author's original session — if the author logs out they remain until intent expiry (≤24h); (c) notification title is generic "工单状态已更新" and the item links to the event, not the workflow; (d) notifications to approval candidates are opt-in rather than automatic.

## r4 (2026-10-25, Asia/Shanghai)

| Check | Result | Evidence | Kong calls | Latency |
|---|---|---|---|---|
| Vitals overview, small data (134 epochs), before | baseline | p10-vitals-perf-before-small.json | 134 | ~2.0s |
| Vitals overview, large data (+55 svc/+55 routes, 244 epochs), before | baseline | p10-vitals-perf-before-large.json | 244–273 | ~3.5s |
| Vitals overview, large data, after inventory prefetch | PASS; owner/approver/read-only response shape identical (p10-vitals-shape-*.json); per-entity authz/membership unchanged | p10-vitals-perf-after-large.json | 3 | ~1.5s |
| Approver auto-notification (default on), title names op/cluster/requester, link_kind=workflow | PASS: "待审批：网关实体变更 · 集群 fv-kong-a · 发起人 admin" | p11-approver-notif.mjs | – | – |
| Requester not notified; opt-out honored; stale revision 409; audit row; opt back in | PASS | p11-approver-notif.mjs | – | – |
| Malformed notification id → 404 (was 500) | PASS | unit tests | – | – |

Observation (b) above is resolved as "by design" — see progress doc r4 §Cancel session binding.
