# KongPilot 平台专用备份与隔离恢复操作草案

本文对应 `deploy/scripts/platform-recovery.mjs`。它服务于「KongPilot 管理已经存在的 Kong」以及随包网关场景，但**只处理平台存储**。工具本身不调用 Kong Admin/Proxy API，不读取、备份、停止或恢复 Kong 数据库，也不停止 Kong 网关。原有 `coordinated-backup.mjs` / `lab-restore.mjs` 是历史联合实验工具，不是本文的平台灾备入口。

本文与 Source 行为回归不等于现场恢复验收。发布前必须由实际生产操作者在隔离新站点演练，并记录最终发布包、原始退出码、RPO/RTO、平台审计、密文和真实凭证验证结果。恢复工具成功仅表示隔离存储恢复通过；报告中的 `productionReady` 保持 `false`。

## 数据与密钥边界

备份包含 Console PostgreSQL 的完整 custom-format dump，经独立备份密钥 AES-256-GCM 加密。外部 `manifest.json` 的身份、数据指纹、版本、应用 Source 树摘要、依赖锁摘要、每条 SQL migration 摘要、实际平台存储/API image ID、加密密钥版本引用及解密 canary 都作为 AAD 绑定。备份密钥和平台三个密钥不写入归档或 manifest。

平台持久业务事实、审批与排程、幂等回执、审计链、用户与门户会话以 PostgreSQL 为准。Redis 当前保存缓存、登录限流、短期会话缓存、OIDC state 和分布式租约。因此本工具**不重放 Redis 持久文件**：恢复用新空 Redis，撤销备份中的全部 Console/Portal SQL 会话。恢复后需要重新登录，进行中的 OIDC 流程作废，限流计数重新开始；锁的重置不授予任何已存在工单执行权。历史 uncertain 和原始回执完整保留，不能因恢复而重试、清锁、续期或改为成功。

独立备份密钥必须由离机/独立账户保管。平台 `CONSOLE_ENCRYPTION_KEY` 必须保留原版本，丢失后密文与加密快照无法恢复。工具同时核对 `APP_SECRET` 和 `PORTAL_SECRET` 的 keyed signature，不用更换签名密钥冒充会话撤销。密钥轮换应走另行验证过的产品流程。

## 准备材料

使用 Node.js 22 或发布包规定的更新兼容版本、Docker CLI 和本机 `/var/run/docker.sock`。工具仅使用该本机 daemon，忽略 `DOCKER_HOST` 等环境覆盖；它的操作者具有 Docker 管理权限。PostgreSQL/Redis 使用恢复点记录的 immutable image ID，异机恢复前须从同一已验收发布资产导入这些镜像并核验 image ID。工具在创建任何资源前要求本地 image inspect ID 精确一致，启动始终传 `--pull=never`；不自动拉取或解析远程镜像。

在持久、受控目录下创建一个仅操作者可读写的父目录，例如 `/srv/kongpilot-private/recovery`，权限 `0700`。备份和恢复每次使用全新子目录，不支持覆盖、复用、强制恢复或自动清理失败目标。禁止使用软链接路径；父目录必须属于当前用户且不可被组或其他用户写入。所有输入 JSON 文件必须属于当前用户、是普通文件且权限为 `0600`。工具生成的归档、配置和报告同样为 `0600`，输出目录为 `0700`。

站点配置 `source-site.json` 示例（siteId 为该站点首次登记后永久保存的 UUID）：

```json
{
  "format": "kongpilot-platform-site-v1",
  "siteId": "11111111-1111-4111-8111-111111111111",
  "project": "kongpilot-production",
  "database": {"user": "kongos", "name": "kongos"},
  "keyReferences": {
    "encryption": "vault:kongpilot/production/console-encryption@v1",
    "app": "vault:kongpilot/production/app-signing@v1",
    "portal": "vault:kongpilot/production/portal-signing@v1",
    "backup": "vault:kongpilot/recovery/archive@v1"
  }
}
```

`project` 必须与实际 Compose project 一致。工具只选择其 `console-db`、`redis`、运行中的 `console-api` 服务，核验实际容器 ID、labels 和运行状态；发现正在运行的 `console-migrations` 时拒绝备份。`database` 是 Console 数据库，禁止填 Kong 数据库。工具会校验全部 Console migrations；无法匹配时不会执行 dump。

从已有秘密管理器按版本导出 `recovery-secrets.json`，**不要把秘密放在命令行、终端输出或 shell history**。其四个固定字段为：

- `CONSOLE_ENCRYPTION_KEY`：原平台 32-byte lowercase hex 密钥。
- `APP_SECRET`：原平台独立签名秘密，至少 32 字符。
- `PORTAL_SECRET`：原门户独立签名秘密，至少 32 字符。
- `BACKUP_ENCRYPTION_KEY`：独立生成并离机保管的 32-byte lowercase hex 密钥。

四项必须互不相同。示例文件不提供可运行默认密码。JSON 内只存版本对应的真实值，工具不会打印这些内容。`keyReferences` 仅允许 vault/kms/secret-manager/file 引用；不能填含 userinfo/query 的 URL 或原始密钥。

## 执行平台备份

备份会短暂停止该站点全部运行中的 API 副本，前端可能返回 502/503。应预告维护窗口并停止流量入口；不需要停止 Kong。工具在 finally 中恢复相同原始 ID 的 API 副本；若启动命令失败，整个命令失败，操作者须立即检查平台 API。工具不操作其他网关或数据库服务。备份结果中的 `kongContacted:false` 作用域为 `kongContactScope:tool-direct-actions-only`：源 API 在 finally 恢复后，仍按其原配置执行启动能力探测、观察与自然 worker 策略；不能把工具没有直接请求 Kong 外推为重启后的整个平台永远不探测或执行业务。恢复副本则没有 API，因此不存在这类自动外联。

```sh
node deploy/scripts/platform-recovery.mjs backup \
  --config=/srv/kongpilot-private/recovery/source-site.json \
  --secrets-file=/srv/kongpilot-private/recovery/recovery-secrets.json \
  --output=/srv/kongpilot-private/recovery/backup-20261018T120000Z \
  --repository=/opt/kongpilot-console
```

全部 API 停止后，工具使用完全相同的只读 checkpoint SQL，最多观察 20 次、间隔不超过 250ms、总期限 5 秒，等待数据库连接正常清理；单次命令超时也受剩余总期限限制。只有所有其他客户端都为零才继续，持续存在则拒绝；不会忽略某个 appName、排除空闲连接、终止后端或修改数据库来凑零。随后核对发布 SQL 与安装校验和，再执行仅该 Console 库的 `pg_dump`。操作者必须在维护窗口关闭 API 自动拉起/扩缩容、外部平台数据库写入与运维写任务；这些外部写入器不能靠两次采样物理封锁。`pg_dump` 自身使用单一一致性快照。前后两次 checkpoint 必须完全一致，记录审计头、审计行数、凭证引用数和 SQL 版本。检测到并发客户端或变化时拒绝，不写成功 manifest。它不运行 `pg_dumpall`，不查询其他数据库，也不备份 PostgreSQL 全局角色。

成功输出只有非秘密摘要。完整的恢复点是同目录的 `manifest.json` 与 `console-postgres.kpgcm`。manifest 写入完成后才构成可使用备份。将两个文件复制到离机存储，校验摘要与访问控制；密钥从独立渠道保管。文件复制和对象存储持久性、跨账号可读取能力必须另行实际验证。未完整生成的目录保留作故障分析，不可复用。

## 恢复到新隔离站点

必须使用新的 siteId 和新的 project；即便异机也不沿用源 project。目标 project 下存在任何容器、网络或 volume 都拒绝继续，目标资源名已存在也拒绝。每次尝试生成随机 attempt nonce，创建后及启动存储前核验资源名称、project/site/nonce标签、新网络 ID、internal bridge、plain local volume 和空 driver options，避免 `volume create` 幂等行为在检查后复用他人资源。不会清空、覆盖或删除已有数据。失败后请保留原报告和资源检查原因；再次演练使用另一个新 project/新目录。

目标 `restore-site.json`：

```json
{
  "format": "kongpilot-platform-restore-v1",
  "siteId": "22222222-2222-4222-8222-222222222222",
  "project": "kongpilot-restore-20261018"
}
```

```sh
node deploy/scripts/platform-recovery.mjs restore \
  --backup=/srv/kongpilot-private/recovery/backup-20261018T120000Z \
  --secrets-file=/srv/kongpilot-private/recovery/recovery-secrets.json \
  --target-config=/srv/kongpilot-private/recovery/restore-site.json \
  --output=/srv/kongpilot-private/recovery/restore-20261018T130000Z \
  --repository=/opt/kongpilot-console
```

工具在接触 Docker 前核对同一发布包的版本、Source 树/依赖锁/SQL 摘要、keyed key signatures、加密 canary、归档摘要及 GCM 标签。格式使用独立裸 PGDMP payload，不解 tar、不接受归档内文件名或路径。

恢复只创建一个新的 `internal` 网络、两个新的持久 volume、平台 PostgreSQL 和 Redis；没有端口发布，不创建或启动 Console API、前端、migrator、collector、worker 或投递器。源站点可仍在运行，但恢复副本不能访问其 Kong；工具不把源集群地址改为空，不修改原始工单/审计/未知结果来伪造安全状态。

恢复顺序为：空库证明 → `pg_restore --single-transaction --no-owner --no-acl` → 原 checkpoint 对账 → 全量审计 hash/顺序/前驱/链头校验 → 真实已存密文抽样解密 → 撤销两类 SQL session → 启动新 Redis 并验证 `DBSIZE=0`。密文抽样分别最多覆盖 100 个 cluster connection、mutation before 和 recycle payload；只有计数和通过状态写报告，不返回明文。它是样本验证，不能代替所有配置/快照/门户凭证的应用层解密验收。

恢复目录保存新 DB/Redis 密码文件以及 `recovery-fence.json`、`restore-verification.json`。密码文件不可提交仓库，不可发聊天，不可放普通工单附件。失败时保存 `restore-failed.json`，不产生成功验证报告，不自动删除资源，也不启动 API。

## 解除隔离前的必要验证

工具故意不提供一键启动恢复 API：生产解除隔离涉及源站点单写者切换以及历史工单判断，不能仅靠数据库恢复成功自动执行。正式投产前至少完成：

1. 根据同一发布包为新库执行并验证 runtime/migrator 权限分离；`--no-acl` 恢复不会复制源环境 runtime 密码/全局角色授权。恢复检查使用数据库 owner，平台 API 不能使用 owner。
2. 先在隔离网络运行该发布 API 的离线验证进程，保持所有网关/通知外联禁止和全部 worker 关闭；校验全部所需配置/快照/回执密文、审计只追加约束、两类旧 session 拒绝及全新登录。
3. 对原待执行/已审批/过期/claimed/uncertain 工单逐项核对原不可变事实。恢复不授予重放权、不延长 deadline、不允许双站点同时调度。来源仍运行时，恢复副本必须持续封写。
4. 完成源站点停止平台写入与单写者接管证明，保留 Kong 运行；再按部署手册接入新的授权网络/私有 Admin API。明确最终启用的 `ENTITY_SCHEDULES_ENABLED`、`BUSINESS_SCHEDULES_ENABLED`、`EVENT_OUTBOX_WORKER_ENABLED`、`EVENT_DELIVERY_WORKER_ENABLED`，验证其他定时任务与外联防火墙。不要仅关闭两个 M11 flag 就声称所有写入已关闭。
5. 在受控真实 Kong 上验证当前权限、只读/IDOR、现有凭证仍有效、门户申请/轮换/吊销、回收恢复、快照、自然排程及通知。生产未知状态保持原样阻断。
6. 记录恢复点时间、最后源写入时间（RPO）、命令开始/数据恢复完成/应用可用与安全接管时间（RTO）；不能把仅恢复存储的耗时当业务恢复耗时。

本工具当前上限：PG custom dump 256 MiB；单次 SQL 验证输出 32 MiB；Source 清单最多 20,000 文件/256 MiB。超过上限直接失败并保持隔离，应先研发并验收流式/分页版本再为更大站点承诺容量。不会在超限后静默抽样审计或填补为通过。

## 必须由 Root/现场操作者完成的证据

Source 回归只证明脚本控制流、真实密码算法及拒绝行为，Docker/SQL 都采用独立注入适配器。最终还需：40 条实际 migration 的原 Console 库备份 → 新持久项目恢复 → 实际审计/密文/会话/worker验证；保留实际退出码、原始私有日志、公开脱敏报告、实际镜像 ID、最终 Source 摘要和离机恢复演练。没有这些实测不能把 C28 标为商用通过。

恢复 PostgreSQL readiness 使用 `pg_isready --host=127.0.0.1`，排除官方入口仅 Unix socket 的临时初始化服务器；随后真实只读 SQL 校验目标数据库名和用户。二者共享 15 秒单调总期限，单次命令不超过剩余期限。SQL 使用同容器本地 socket，不将新数据库密码放入命令参数、日志或公开结果；SQL 身份不匹配立即拒绝，初始化未完成则有界等待。
