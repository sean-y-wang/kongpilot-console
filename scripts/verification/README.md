# Verification scripts / 验证脚本

[English](#english) · [简体中文](#简体中文)

## English

Scripts used for the v1.0.0 release acceptance (M11). They run against a **running Docker Compose stack** (the [quickstart](../../docs/getting-started/quickstart.md) or `docker-compose.yml + deploy/compose/compose.production.yml`). All hosts, credentials and output directories come from environment variables; nothing is hardcoded. Never commit the env files you pass in.

| Script | What it proves | Key env |
|---|---|---|
| `production-smoke.mjs` | Production-compose smoke (22 checks) + light concurrency: 20 admins × 10 iterations behind a shared client rate limiter (edge limit is 20 r/s per IP); audit integrity walks `nextCursor` to `complete=true` | `BRIDGE_ENV`, `PCE_OUT` |
| `fault-injection.mjs` | Fault injection: Redis stop / Kong pause; writes fail closed and recover (17 checks) | `PCE_PROJECT`, `REDIS_SERVICE`, `KONG_SERVICE`, `BFF_BASE`, `FAULT_ENV_FILE`, `COMPOSE_FILES`, `PCE_OUT` |
| `pg-backup-restore-drill.mjs` | Console PostgreSQL backup → restore drill, then audit chain verified page by page (9 checks) | `DRILL_MODE=inplace`, `DRILL_OUT`, `DRILL_PRIVATE`, `BRIDGE_ENV` |
| `production-cold-start.mjs` | Cold start of the production compose with offline DNS | see header |
| `coordinated-backup.mjs`, `lab-restore.mjs`, `production-ram-*.mjs` | Coordinated backup / lab restore tooling used in production rehearsals | see header (guarded by explicit `*_READY=true` env) |
| `approval-*`, `recycle-bin-restore`, `credential-proxy-flow`, `promote-*`, `schedule-target-append`, `portal-*`, `tls-runtime-hardening`, `production-overlay`, `runtime-image-readiness`, `capacity-smoke`, `dr-rehearsal`, `platform-restore-second-env`, `frozen-tree-secret-scan` | Per-capability evidence drivers | see header |
| [`../release/regression-single-pass.sh`](../release/regression-single-pass.sh) | **Lab only.** The exact orchestration of the rc.2 clean single pass (fixture reset → smoke → fault → PG → browser matrix) | `REPO`, `OUT`, `PRIVATE`, `CONSOLE_DB_HOST` |

Lab-only compose overlays used by these drivers: `deploy/compose/compose.e2e-cluster-b.yml`, `deploy/compose/compose.*-evidence.yml`, `deploy/compose/compose.platform-source.yml`. Browser matrix: `tests/e2e/m11-browser-matrix.mjs` with the seeding helpers in [`tests/e2e/lab-harness`](../../tests/e2e/lab-harness/README.md). Published results: [rc.2 final regression](../../docs/project-history/verification/rc2-final-regression/README.md).

## 简体中文

这些是 v1.0.0 验收（M11）用到的脚本，要在**已启动的 Docker Compose 栈**上跑（[快速上手](../../docs/getting-started/quickstart.zh-CN.md)那套，或 `docker-compose.yml + deploy/compose/compose.production.yml`）。主机、凭据、输出目录都通过环境变量传，脚本里没有写死；传进去的 env 文件不要提交。

- 冒烟和轻量并发：`production-smoke.mjs`。客户端共享限速，审计完整性按 `nextCursor` 翻页。
- 故障注入：`fault-injection.mjs`。
- PG 备份恢复演练：`pg-backup-restore-drill.mjs`。
- 各能力的证据脚本：见上表。
- rc.2 单次全量回归编排：[`../release/regression-single-pass.sh`](../release/regression-single-pass.sh)，仅限实验环境。

`compose.*-evidence.yml` 和 `compose.e2e-cluster-b.yml` 只用于实验环境，不要用于生产。
