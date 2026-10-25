# KongPilot 平台备份与恢复操作手册

适用产品：**KongPilot（Kong 网关管理平台）**。本文面向部署、值班与恢复操作人员，对应 `deploy/scripts/platform-recovery.mjs`。操作范围为 KongPilot PostgreSQL、平台密钥及恢复所需的新 Redis；不读取、备份或恢复 Kong 数据库，不修改 Kong 程序，也不停止 Kong 网关。

## 1. 当前证据与使用边界

2026-10-18 已完成一次实际平台加密备份、同宿主全新隔离存储恢复、实际最小权限角色重建/只读启动检查，以及该恢复库的完整应用密文验证。完整验证覆盖固定清单的 **66 个列域**，使用实际产品 SecretService、SnapshotCryptoService 和原始 AAD；逐行扫描全部现存值，包括明确列出无数据的域。实际 Node22 进程退出码为0，`allPresentCiphertextsVerified=true`、`allRecoverableCiphertextsVerified=true`，原恢复库40条迁移及 catalog 前后不变。实际扫描3371个列值，其中2523个现存密文全部真实解密、848个为NULL、失败0；这不是3371个唯一业务对象。公开结果为 `c28-all-cipher-actual-v3-third-original.json`；逐域行数、NULL/无数据状态和摘要以该原始报告为准。

这些证据证明本次恢复点在同宿主隔离 PostgreSQL 中能够恢复，且该批次全部现存应用密文可用原密钥解密。它们**不构成**异地灾备、完整 RPO/RTO、生产入口切换、真实网关凭证认证或没有数据的业务流程验收。恢复副本未启动 API、worker、collector 或通知投递，没有接入 Kong。备份/恢复和后续离线验收报告均不能单独用于宣布整个平台已可商用。

本次全密文检查绑定原 SQL000–039、同版发布材料与固定66列清单。当前041候选新增2个密文列、042候选新增1个密文列，候选总数为69列，尚不属于本次66列实测范围。即使新列暂时没有记录，也须登记为明确无数据域，不能省略。最终发布前要重新核对实际catalog。后续新增迁移或密文列，必须冻结新的完整清单、AAD/材料关联与验证工件并重新实测；不能把本次结论外推到另一数据库、版本或后来新增的数据。

## 2. 恢复点必须包含什么

一个可使用恢复点由同目录的 `manifest.json` 和 `console-postgres.kpgcm` 组成。后者是 Console PostgreSQL custom dump 的认证加密归档；manifest 身份、发布版本、Source/依赖锁/逐条迁移摘要、实际镜像 ID、checkpoint、密钥版本引用与解密 canary 受认证绑定。没有完整成功 manifest 的失败目录不能作为恢复点。

独立保管以下材料，建立恢复点、站点、密钥版本与发布包的对应关系：

| 材料 | 保管要求 |
| --- | --- |
| 加密归档、manifest、脱敏验证报告 | 独立持久存储；核对摘要、访问权限与实际可读取性 |
| 原 `CONSOLE_ENCRYPTION_KEY` | 按原版本独立安全备份；缺失后，快照、回收图、来源和秘密可能永久不可恢复 |
| 原 `APP_SECRET`、`PORTAL_SECRET` | 与归档分开保管，恢复时按版本核对 |
| 独立 `BACKUP_ENCRYPTION_KEY` | 与业务主密钥不同，离机或独立权限域保管 |
| 同一冻结发布包、依赖锁和所需镜像 | 恢复前核验 immutable image ID，异机须提前导入 |
| 原始审计与未知结果处置记录 | 保留不覆盖；恢复不重新授予旧请求执行权 |

禁止在 Git、公开工单、聊天、命令行或截图中放明文秘密。恢复专用 JSON 为当前操作者所有的普通文件，权限0600；父目录0700，禁止软链接。每次执行使用新的输出目录，失败后保留原目录与资源。

## 3. 准备备份配置

使用发布包规定的 Node22 工具链、Docker CLI 与本机 Docker daemon。当前验收工具链为 Node v22.23.3。工具固定使用本机 `/var/run/docker.sock`，不接受远程 daemon 覆盖；操作者因此必须是受控的主机管理员。

`source-site.json` 示例：

```json
{
  "format": "kongpilot-platform-site-v1",
  "siteId": "11111111-1111-4111-8111-111111111111",
  "project": "kongpilot-production",
  "database": {"user": "postgres", "name": "kongpilot"},
  "keyReferences": {
    "encryption": "secret-manager:kongpilot/production/encryption@v1",
    "app": "secret-manager:kongpilot/production/app@v1",
    "portal": "secret-manager:kongpilot/production/portal@v1",
    "backup": "secret-manager:kongpilot/recovery/archive@v1"
  }
}
```

将示例替换为本站真实 Compose project、Console 库与持久站点 UUID。`keyReferences` 只放秘密管理器的版本引用，不放原始值或 Kong Vault 端点。该工具不支持 Kong Enterprise Vaults。

从受控秘密管理器导出 `recovery-secrets.json`，只含四个固定字段：`CONSOLE_ENCRYPTION_KEY`、`APP_SECRET`、`PORTAL_SECRET`、`BACKUP_ENCRYPTION_KEY`。两类加密密钥为32-byte小写十六进制，两个签名秘密至少32字符，四项互不相同。不要为方便恢复生成新的平台主密钥，也不要在 shell 中展开文件内容。

## 4. 执行备份

安排平台维护窗口，暂停平台业务写入、自动扩缩容和外部数据库写任务。Kong 网关继续运行。备份会短暂停止选定站点的全部运行中 API 副本，平台入口可能出现502/503。

```sh
node deploy/scripts/platform-recovery.mjs backup \
  --config=/srv/kongpilot-private/recovery/source-site.json \
  --secrets-file=/srv/kongpilot-private/recovery/recovery-secrets.json \
  --output=/srv/kongpilot-private/recovery/backup-20261018T120000Z \
  --repository=/opt/kongpilot-console
```

工具核验真实服务 labels、容器 ID、迁移校验和与运行状态，拒绝活动 migrator。API 停止后，工具在固定总期限内用相同只读 checkpoint 等待全部其他 Console 数据库客户端退出；持续存在即失败，不过滤 appName/空闲连接，不取消或终止后端。随后 dump 仅选定的 Console 库，并核对前后 checkpoint。`pg_dump` 提供一致性快照，但工具不能替代操作者暂停外部写入器。

工具在 finally 中恢复相同原始 ID 的 API 副本；启动失败时整个命令失败，立即检查平台 readiness，不覆盖失败记录。备份工具自身不调用 Kong；API 恢复后仍会按原配置进行能力探测和原有后台任务，所以 `kongContacted:false` 只描述工具直接动作，不代表恢复 API 永远不会请求网关。

确认进程退出码0、成功 manifest 与归档均存在，再将恢复点复制至独立存储并实际验证读取和摘要。备份目录与密钥不能只保存在同一台主机。

## 5. 恢复到全新隔离存储

每次恢复使用新的 siteId、project 和输出目录。工具拒绝复用现有容器、网络、卷或同名资源，不提供覆盖与自动清理。

`restore-site.json` 示例：

```json
{
  "format": "kongpilot-platform-restore-v1",
  "siteId": "22222222-2222-4222-8222-222222222222",
  "project": "kp-recovery-20261018a"
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

工具先认证归档、秘密版本、canary 与同版发布摘要，再创建单一 internal bridge、两个新持久卷和 PostgreSQL/Redis。镜像必须提前存在且 immutable image ID 精确一致，始终 `--pull=never`。没有端口发布，没有 API、前端、migrator、worker、collector 或投递器。

PostgreSQL 就绪先用 TCP127.0.0.1 探测，避免官方入口仅 Unix socket 的临时初始化服务器被误判；随后真实只读 SQL 验证目标库与用户。恢复使用单事务 `pg_restore --no-owner --no-acl`，校验原 checkpoint、全量审计链，并完成有限存储密文抽样。恢复工具的抽样不等于第7节的全密文验收。

Redis 使用全新空库，不重放旧锁、OIDC state 或限流缓存。SQL 中旧 Console/Portal session **全部撤销并保留历史行**，不删除历史；恢复后必须重新登录。撤销判定为 `revoked_at IS NULL` 的行数必须为0，与会话是否自然过期无关。不能为符合验收而删除历史行。

成功目录保留 `recovery-fence.json`、`restore-verification.json` 和新存储密码文件；失败保留 `restore-failed.json`、日志及资源。始终保持隔离，不因恢复工具退出码0自动启动应用。

## 6. 恢复最小权限角色

`--no-acl` 恢复不会恢复 PostgreSQL 全局运行角色、密码和源授权。使用同版发布包真实 `provisionRuntimeRole` 重建目标库最小权限角色，随后用实际 NOSU 登录运行离线只读 schema 检查；平台 API 不能使用 owner。

至少核对 NOSUPERUSER、NOCREATEDB、NOCREATEROLE、NOINHERIT、NOREPLICATION、NOBYPASSRLS、无角色成员、无 public schema CREATE 或产品对象所有权。验证审计 UPDATE/DELETE/TRUNCATE、禁用触发器、迁移表写入、schema CREATE 与切换 owner 均被实际拒绝。保留权限建立前后的真实 catalog 和原迁移清单，不以旧 owner 的可读结果代替运行账号验收。

当前这一步已有实际隔离恢复库证据，范围是固定原40迁移版本；对新版本要重做。

## 7. 验证全部现存应用密文

使用与恢复点对应、经审核冻结的离线验证包。当前证据工件为 C28 `full-cipher-driver-v3`，绑定原 SQL000–039、实际恢复资源、专用最小权限角色及66列清单；这是验收工件，不能直接用于任意生产库或下一版 schema。

验证包运行前核对其 files manifest SHA。它只选择成功恢复报告记录的精确容器、新站点/project/attempt 和实际私有 IPv4，不接受 Kong 地址、任意 DNS、其他数据库、owner 或公开端口。所有扫描使用 REPEATABLE READ READ ONLY、固定 search_path、服务器超时与 FETCH1 游标；每个域计数并逐行检查，超预算失败而非静默抽样。原始 AAD、历史版本、receipt execution、快照材料和 DEK 身份必须精确匹配。reserved 无生产 codec 的列只允许NULL。

专用0600秘密文件只含原 `CONSOLE_ENCRYPTION_KEY` 和实际新建运行账号的 `CONSOLE_DB_RUNTIME_PASSWORD`，不用 source/eval，不把值放入 argv 或 stdout。前后新连接 checkpoint 核对原迁移/catalog、审计、全部会话行数和撤销状态；旧会话历史保留，任何未撤销会话或状态漂移均失败。

验收时检查：

- 真实子进程退出码为0，扫描完成且全部固定列域有状态；无数据域必须标为 `NO_ROWS_OBSERVED`。
- 每域 `totalRows = nullRows + nonnullRows`，并与 decrypted、failed、intentional erasure 和 verified NULL 的分类数守恒。
- `allPresentCiphertextsVerified` 表示所有**实际存在的密文**均真实解密。解密成功计数不包含已销毁 DEK。
- 已销毁且有明确状态/版本/时间证据的 DEK 是预期不可恢复，单独计数。它可被正确分类，但不能算“解密成功”；仍有对应密文时 `allPresentCiphertextsVerified=false`。
- `allRecoverableCiphertextsVerified` 只说明可恢复值通过、预期销毁被明确分类。任意认证失败、材料关联缺失/歧义或 reserved 非空均不得通过。
- 结果只保留计数、摘要和安全状态，不保留明文、密钥、凭证、行ID或原始异常。私有日志与配置按秘密材料保管。

本次实际全量结果两个标记均为true，且没有启动恢复 API 或接入 Kong。保留原始失败和修订链：V1 因 PostgreSQL inet 文本包含 `/32` 在扫描前拒绝，V2 因把已撤销历史会话误要求为零行而拒绝；V3 分别采用实际 host 投影与“零未撤销、历史不变”检查，未放宽目标、权限、密钥或加密认证。

## 8. 接管前验证与生产切换

存储和密文通过后，仍须在受控环境完成应用与业务验收：

1. 用冻结发布包验证独立域名/TLS、登录、角色权限、只读/越权/IDOR、全新会话与门户账号分离；原会话保持无效。
2. 审阅原待执行、已批准、claimed、过期及 uncertain 工单。恢复不延长 deadline，不把没有记录或 GET404 当未执行，不重造旧票/source/packet，不授予重试权。
3. 核对源站点仍在运行期间的单写者安排。切换前保持恢复副本封写和无外联；不得让两个站点同时调度、发证或投递。
4. 在受控真实 Kong1.5.x 上验证实体读写、审批、回收完整图恢复、快照与已有凭证认证、门户发证/轮换/吊销。密文可解不证明网关状态与恢复点一致，也不证明凭证当前可登录。
5. 根据已验收功能明确启用每个 worker/collector/通知出口和防火墙规则。不能只关两个排程 flag 就声称全部写入关闭；未知状态保持原样阻断。
6. 保存停写与接管事实、发布镜像/迁移 SHA、备份恢复点、实际代理/认证与审计结果，完成正常运行监测后开放入口。

异地灾备另需在独立主机/权限域使用离机材料实际恢复并验证镜像、秘密访问、网络与应用切换。RPO 应按最后已确认源写入与实际恢复点计算；RTO 应覆盖命令开始、存储恢复、应用验证和安全业务接管，不能用仅 `pg_restore` 或离线密文扫描耗时代替。 同机第二环境证据（`deploy/scripts/kp010-platform-second-env-restore-evidence.mjs`）**不等于**异地灾备。操作排练清单与探针见 `deploy/scripts/kp010-geographic-dr-rehearsal.mjs`（只读排练，不宣称关闭）。

## 9. 故障处理与容量

| 现象 | 处理 |
| --- | --- |
| 停 API 后仍有数据库客户端 | 查找外部写任务/自动拉起；保持失败记录，用新目录重做；不取消或过滤客户端 |
| PostgreSQL 临时服务器误就绪 | 确认使用已修订的 TCP 探测和实际库身份检查，不延长为无界等待 |
| migration/Source/image ID 不一致 | 使用该恢复点真正对应的冻结资产；不改历史 checksum 或忽略错误 |
| 密钥/AEAD/AAD/材料关联失败 | 保持隔离，找回原密钥与版本对应材料；不生成新密钥替代 |
| 有未撤销会话或会话状态漂移 | 保留历史，定位恢复撤销/外部写入原因，不删行凑零 |
| 归档、SQL输出或全量扫描超预算 | 原样失败；先研发并验收扩容/流式方案，不能改为抽样后宣布全量通过 |
| 应用可能已执行但回执未知 | 保留原事实、权限与审计，按固定领域恢复协议处理，不重新发送原变更 |

当前平台备份工具上限为 PG custom dump256MiB、单次 SQL 验证输出32MiB、Source清单20,000文件/256MiB。当前完整密文验收包上限为总计500万列值、单密文64MiB、wrapped DEK16KiB，带进程内存与总时限。超过上限应明确判失败。容量目标、现场外部提供者、离机存储和完整灾备指标由各生产站点另行验收。
