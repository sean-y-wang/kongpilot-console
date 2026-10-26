# 架构决策记录（ADR）

[English](README.md)

| # | 决策 |
|---|---|
| 0001 | [拥有集群写权限的审批人可以执行自己审批过的工单（禁止自审批；需要严格职责分离时请分开授权）](0001-approver-may-execute-approved-tickets.md) |
| 0002 | [不提供写入 SLA 和异地容灾；保留 20 人轻量并发检查和 PostgreSQL 备份恢复](0002-no-write-sla-or-offsite-dr.md) |
| 0003 | [实体/业务定时任务需通过 `ENTITY_SCHEDULES_ENABLED` 显式开启，默认关闭](0003-entity-schedules-opt-in.md) |
| 0004 | [不支持恢复旧来源（直连删除）的回收站条目，返回 409](0004-legacy-origin-recycle-restore-unsupported.md) |
| 0005 | [审计完整性接口每页 1000 行，按 `nextCursor` 翻页到底才算结论](0005-audit-integrity-pagination.md) |
| 0006 | [门户重复发布已验证过的版本会在准备阶段以 409 拒绝](0006-portal-republish-same-revision-rejected.md) |
| 0007 | [Kong 1.5 工作进程默认 2 个（auto 会导致 OOM）](0007-kong-worker-processes-default-2.md) |
| 0008 | [目标地址 DNS 使用 c-ares 并有限回退，适配离线部署](0008-destination-dns-c-ares.md) |
| 0009 | [定时配置执行的 Kong 调用预算为 1000（其他 500），共享一次实时校验读取](0009-scheduled-execution-call-budget.md) |
| 0010 | [在 nginx 基础镜像更新前，镜像内升级 brotli-libs 修复 CVE](0010-brotli-libs-in-image-upgrade.md) |
| 0011 | [Redis Cluster 模式与键前缀](0011-redis-cluster-and-key-prefix.md) |
