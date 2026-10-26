# §51 rc.2 final consolidated regression + formal rescan (2026-10-25 UTC+8)

Images: `kongpilot/{console-api,console-web,portal-web}:v1.0.0-rc.2` (built from tag worktree / pre-rc2-8492d0f retagged; commit 8ea549e). Stack: `kp-bridge` + production compose (+ lab cluster-B overlay for matrix). Offline DNS: `dns.lookup('example.com')` → EAI_AGAIN.

## Formal rescan (tag v1.0.0-rc.2)
- CI workflow_dispatch **40200167285**, job `immutable-images-amd64` success.
- grype **0.120.1**, DB v6.1.10, acceptance **39/39**, unaccepted 0, fixable 0, image Critical 0. Gates/waivers unchanged.
- Evidence: `formal-rescan/`.

## Suites
| Suite | Result |
|---|---|
| bridge smoke | **21/22** (audit single-page budget; see supplement) |
| concurrency | 20 admins × 10 = 800 requests, **0 errors**, p95 749 ms |
| fault injection | **17/17** |
| PG backup/restore | **7/9** (same audit budget on first page) |
| audit integrity cursor walk | **verified / complete** (2 pages → seq 1099) |
| browser matrix | **11/11** |

## Lab notes (not production defaults)
- `ENTITY_SCHEDULES_ENABLED=true` opt-in for KP-002; `TZ=Asia/Shanghai` for schedule wall-clock.
- Console DB fixture restore + Kong Admin residue cleanup + cluster-B overlay + GET-only Kong relay (removed after).
- KP-003 harness hardened for Playwright `route.abort` after `fetch` race; verify via `dispatchEvent` after force-closing confirm modal.

commercialClosed=**false** (not flipped). Progress ≈99.9%.
