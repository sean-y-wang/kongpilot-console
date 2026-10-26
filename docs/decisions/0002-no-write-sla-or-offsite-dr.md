# 0002. Write SLA and off-site disaster recovery are out of scope

- Status: Accepted
- Date: 2026-10-25

## Context

KongPilot is a control-plane console: it manages configuration, approvals and audit. Data-plane traffic goes directly through Kong and never passes through KongPilot. Load on the console comes from a small number of administrators.

## Decision

- No formal write-throughput SLA and no large-scale load testing.
- No off-site / geographic disaster recovery as part of the product.
- Kept: a lightweight concurrency check (20 concurrent administrators, 800 requests, 0 errors required) and a verified PostgreSQL backup/restore procedure, because configuration, approval records and the audit log live in PostgreSQL and cannot be rebuilt.

## Consequences

- Operators who need off-site DR should replicate PostgreSQL backups with their own infrastructure. See [console-postgres-backup-restore](../operations/console-postgres-backup-restore.md).
