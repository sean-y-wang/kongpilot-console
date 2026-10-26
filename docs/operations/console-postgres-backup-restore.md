# 控制台 PostgreSQL 备份与恢复（单机 compose）

适用：`docker-compose.yml` + `deploy/compose/compose.production.yml` 部署的控制台数据库 `console-db`（PostgreSQL 16）。
范围：控制台配置（集群登记、工作区、IAM、凭据引用）、工单/审批、审计链等全部 `public` 表。
不含：Kong 自身数据库 `kong-db`（网关配置以 Kong 为准，另行备份）；异地/第二机房 DR 不在验收范围（见进度 §44）。

## 必须同时保管的密钥

数据库里的凭据、会话等字段是用部署密钥加密或签名的。只备份数据库不够：
- `CONSOLE_ENCRYPTION_KEY`、`APP_SECRET`、`PORTAL_SECRET`，以及数据库口令（`CONSOLE_DATABASE_PASSWORD`、`CONSOLE_APP_PASSWORD`）。
- 这些密钥和数据库转储要分开存放，各自加密，各自设访问控制。转储文件本身也按敏感数据处理，权限设为 0600，不要进仓库。
- 恢复时必须使用备份时的同一套密钥，否则凭据无法解密，会话也会失效。

## 备份

```bash
DC="docker compose --env-file <私有env> -f docker-compose.yml -f deploy/compose/compose.production.yml"
# 在线备份即可：pg_dump 本身读取一致性快照。
# 如需与其他系统对齐时点，可先停写入方：$DC stop console-api
$DC exec -T console-db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc -Z6' > console-$(date +%Y%m%d-%H%M).dump
chmod 600 console-*.dump
sha256sum console-*.dump > console-dump.sha256
# 校验可读：应列出全部 TABLE DATA 条目
$DC exec -T console-db pg_restore -l < console-XXXX.dump | grep -c 'TABLE DATA'
```

建议每日备份并保留多份。备份后必须做恢复演练，演练方法见下文「抽检演练」。

## 恢复（同机，覆盖现有库）

```bash
$DC stop console-api                       # 停止所有写入方
$DC exec -T console-db sh -c 'psql -U "$POSTGRES_USER" -d postgres -c "DROP DATABASE \"$POSTGRES_DB\" WITH (FORCE)"'
$DC exec -T console-db sh -c 'psql -U "$POSTGRES_USER" -d postgres -c "CREATE DATABASE \"$POSTGRES_DB\" OWNER \"$POSTGRES_USER\""'
$DC exec -T console-db sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --exit-on-error --single-transaction' < console-XXXX.dump
$DC up -d console-api                      # 迁移服务会先运行，对已是最新的库不做改动
```

恢复后按顺序核验：
1. `GET /api/v1/health/ready` 返回 200。
2. 管理员能登录，集群、用户、工单列表与恢复前一致。
3. `GET /api/v1/audit/global/integrity` 返回 `status=verified`，且 `complete=true`。
4. 执行一次小写操作，确认审计链能继续追加，之后完整性校验仍为 verified。

恢复到较早时点后，控制台记录的状态可能落后于 Kong 当前配置。此时用治理/漂移比对核对，不要直接重放旧变更。

## 抽检演练（不影响生产库）

把转储恢复到一个临时容器里核对：`docker run --network none postgres:16-alpine`，然后执行 `pg_restore --no-owner --no-acl`。逐表比对行数和内容 md5，并检查审计链：每个 chain_scope 内 `sequence` 连续，且 `prev_hash` 等于前一条的 `event_hash`。

脚本：`scripts/verification/pg-backup-restore-drill.mjs`，有两种模式：
- `DRILL_MODE=scratch`：源库只读，在同一个一致性快照下导出并计算校验和。
- `DRILL_MODE=inplace`：对实验部署做破坏性的整库删除与恢复。

证据：`artifacts/M11/runs/20261025-1453-production-compose-bridge/pg-backup-restore-*.json`。
