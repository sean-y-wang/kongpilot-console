# Operations

| Topic | Document |
|---|---|
| Production deployment, upgrade, TLS, monitoring | [Production operations guide (zh-CN)](../manuals/production-operations-guide.md) |
| Environment template | [`deploy/production.env.example`](../../deploy/production.env.example) |
| Backup & restore | [Console PostgreSQL backup/restore](console-postgres-backup-restore.md) |
| Disaster recovery | [Platform recovery runbook](../manuals/platform-recovery-runbook.md) |
| Image build & vulnerability acceptance | [Immutable image acceptance](immutable-image-acceptance.md) |
| Approvals | [Approver vs. executor](approval-execution-separation.md), [break-glass](approval-break-glass.md) |
| Multi-cluster test environment | [Two Kong 1.5.1 clusters](multicluster-validation.md) |

Scope: KongPilot is a control-plane console. There is no write SLA and no built-in off-site DR — see [ADR 0002](../decisions/0002-no-write-sla-or-offsite-dr.md).
