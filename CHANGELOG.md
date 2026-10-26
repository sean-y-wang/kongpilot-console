# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Redis Cluster mode (`REDIS_MODE=cluster`, `REDIS_CLUSTER_NODES`, `REDIS_USERNAME`, `REDIS_TLS`) and a configurable key prefix (`REDIS_KEY_PREFIX`); standalone remains the default — [Redis reference](docs/reference/redis.md), [ADR 0011](docs/decisions/0011-redis-cluster-and-key-prefix.md).

## [1.0.0-rc.2] - 2026-10-26

First public release candidate of KongPilot, a self-hosted management console for Kong OSS 1.5.x.

### Features

- Multi-cluster management with a Kong 1.5 compatibility layer; the BFF is the only client of the Kong Admin API.
- Services, Routes, Upstreams/Targets, Consumers, Certificates, SNIs, six credential types; recycle bin with object-graph restore.
- Dynamic plugin center, workspaces (tag-based soft isolation), four-dimension RBAC, sessions, audited secret reveal.
- Change tickets with multi-stage / co-sign approvals, scheduled execution, diff / execute / rollback and explicit handling of unknown results.
- Snapshots, YAML import/export and decK 1.x-compatible GitOps.
- Vitals via Prometheus / Loki; developer portal; append-only, hash-chained audit log; event subscriptions (webhook / SMTP).

### Changed / fixed during release hardening

- Kong worker processes default to 2 (OOM with `auto`) — [ADR 0007](docs/decisions/0007-kong-worker-processes-default-2.md).
- Destination DNS via c-ares with bounded fallback for offline deployments — [ADR 0008](docs/decisions/0008-destination-dns-c-ares.md).
- Clear "cluster-level write lock" conflict message.
- Portal republish of an already-published revision rejected with `409` at prepare — [ADR 0006](docs/decisions/0006-portal-republish-same-revision-rejected.md).
- Scheduled configuration call budget 1000 (others 500) — [ADR 0009](docs/decisions/0009-scheduled-execution-call-budget.md).
- In-image `brotli-libs` upgrade for a CVE — [ADR 0010](docs/decisions/0010-brotli-libs-in-image-upgrade.md).
- Quickstart: loopback `http` portal origins accepted in production mode for the demo; all other origins still require `https`.
- Legacy product branding removed; manual screenshots re-shot.

### Verification

Performed on images built from the release candidate, production-style compose, real Kong 1.5.1, without upstream DNS, in one uninterrupted pass:

- Smoke 22/22
- Concurrency: 20 admins, 800 requests, 0 errors
- Fault injection 17/17
- PostgreSQL backup/restore 9/9
- Browser E2E 11/11
- grype 0.120.1: 0 Critical, 0 fixable; remaining High findings have no upstream fix and are waived until 2026-12-31 in `deploy/security/image-vulnerability-acceptance.json`.

See [project history](docs/project-history/README.md) for details.

[1.0.0-rc.2]: https://github.com/sean-y-wang/kongpilot-console/releases/tag/v1.0.0-rc.2
