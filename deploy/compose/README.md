# Compose overlays / Compose 覆盖文件

Always layer on top of the root `docker-compose.yml` (relative paths resolve from the repo root), e.g. `docker compose -f docker-compose.yml -f deploy/compose/compose.production.yml up -d`.

| File | Purpose |
|---|---|
| `compose.production.yml`, `compose.production-*.yml` | Production hardening, GitOps, metrics |
| `compose.development.yml` | Local development with host-built `dist/` |
| `compose.metrics.yml`, `compose.gitops*.yml`, `compose.external-kong.yml` | Optional features |
| `compose.*-test.yml`, `compose.release-*.yml`, `compose.portal-acceptance.yml` | Test / release validation stacks |
| `compose.e2e-cluster-b.yml`, `compose.*-evidence.yml`, `compose.platform-source.yml` | **Lab only** — used by [`scripts/verification`](../../scripts/verification/README.md); never in production |

覆盖文件必须叠加在根目录 `docker-compose.yml` 之上；标注 Lab only 的只用于实验环境。
