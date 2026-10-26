# §48 rc.1 browser-matrix closure (2026-10-25 19:12–19:50 UTC+8)

Browser E2E matrix on v1.0.0-rc.1 images, kp-bridge production stack, live Kong: **11/11 PASS** (`browser-e2e/browser-e2e-matrix.json`, `run.log`, `shots/`).

## How the 4 previously non-passing items were closed
1. **KP-007 IDOR** — the intended contract (code: workspace/cluster scope resolution) is non-disclosing denial, **403 or 404**; the assertion is unchanged. The previous fixture made the read-only user a *global* read-only, which legitimately reads every workspace, so the cross-workspace probe was not an IDOR probe. The fixture now binds builtin `read-only` to cluster A / workspace A only, plus a custom global role with only `users:read` (global user directory is a global resource by design). Seeded via IAM API while all clusters were direct (global grants are blocked in approval mode).
2. **KP-004 legacy-origin** — legacy entry created by a real direct-mode DELETE (recycle entry with `mutation_id`), then the cluster was switched to approval; restore prepare refused with 409.
3. **KP-002** — `ENTITY_SCHEDULES_ENABLED=true` (opt-in; production default remains false).
4. **KP-006** — lab-only overlay `deploy/compose/compose.e2e-cluster-b.yml` adds a second Kong 1.5.1 cluster (own Postgres, admin bound to the BFF IP only, proxy 127.0.0.1:47810) and an http-echo upstream. Portal service/route/settings/publication seeded in direct mode; after the approval switch the publish ran as a two-person workflow (approver approves, admin executes) so the proof binds the final cluster revision. Portal origin used: configured `https://portal.kp.test:49443` (hosts entry on the test client).

## Lab-only settings (never production defaults)
`OUTBOUND_ALLOWED_HOSTS` += `kong-b,127.0.0.1:47800,127.0.0.1:47810`; `PROTECTED_DESTINATION_HOSTS` covers kong-b-db; GET-only Kong Admin relay for test readback, removed after the run. Private env/secrets stay under ${PRIVATE} (not committed).

## Honest notes
- Console DB was restored from the pre-matrix dump (18:41) twice as a **lab fixture reset** (approval-mode deadlock with one super-admin; and the publish issue below). Not a product recovery claim.
- Test change: KP-006 now approves+executes the developer-review workflow when approval mode produces one, and asserts `succeeded` (stricter, not weaker).
- Observation: re-publishing the same publication revision after a cluster revision bump left the publish step `uncertain` (proof primary-key collision) → later `PORTAL_PUBLICATION_RECOVERY_REQUIRED`. Fail-closed, but should be a clean 409 at prepare. Tracked as hardening candidate.
- commercialClosed=false.
