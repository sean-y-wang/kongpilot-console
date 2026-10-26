# M6 发布证明读取锁：最小部署计划

状态：仅源码方案与离线验证；等待 Root 明确释放实际部署。上一轮真实关闭请求在 PostgreSQL SQLSTATE42501 处失败，原发布证明表仅 SELECT/INSERT，`FOR SHARE OF proof` 要求额外 UPDATE 权限。修复只对 publication 主记录加共享锁，不扩大证明表权限；000–009、migrator与既有对象保持不变。

本轮固定新标签 `portal-proof-read-lock`，不覆盖 `portal-failed-issue-abandonment`、immutable-key、nullable 或其他历史证据。复用既有只读快照与 SQL-side SHA256；当前数据库必须已经应用完整000–009，前后校验和与 applied_at 完全相同。既有 abandoned-issue 证书表前后均0行，证书表与 publication_proofs runtime 均只有 SELECT/INSERT，其余五项权限 false。不会执行迁移、关闭、恢复、批准、执行、原生写或凭证查看请求。

连续性包含原12个非API进程、C3 Kong/PG/已成功退出bootstrap、原已退出console-migrations、API原容器/镜像/环境/网络/卷、当前私有引用（包括最近491次验证的journal）的inode/mode/mtime/大小/字节、全部环境与监控材料、generation/settings/catalog/epoch。首份active generation1及原成功native3/refs2、第二份pending grant及原failed Consumer/后三步pending/refs0，均以数据库内完整行、密文、计划、账本与审计SHA256核对；新fresh baseline与部署后事实必须完全一致。原失败确实发送过一次被拒绝的Consumer请求，本轮部署器不发送任何业务或原生写请求。

Root 释放后只执行以下六步。完整Compose参数仅用于定位现有同一个API容器，`restart`不重建配置或其他服务：

```sh
node deploy/scripts/verify-portal-proof-read-lock-continuity.mjs --before
npm run build -w @kongpilot/api
docker compose --env-file .env --env-file .env.multicluster --env-file .env.portal-acceptance -f docker-compose.yml -f deploy/compose/compose.development.yml -f deploy/compose/compose.multicluster-test.yml --profile multicluster-test -f deploy/compose/compose.metrics.yml --profile observability -f deploy/compose/compose.portal-acceptance.yml --profile portal-acceptance restart console-api
node deploy/scripts/stage-deploy.mjs M6 --multicluster --observability --portal --verify-only
node deploy/scripts/verify-portal-metadata-recovery-openapi.mjs portal-proof-read-lock --with-abandonment
node deploy/scripts/verify-portal-proof-read-lock-continuity.mjs --after
```

实际窗口开始时先以新文件名wx封存当前startup/boundary/Admin/metrics/Portal各门禁。任一步失败立即保留安全错误码与失败记录并停止。只编译API workspace；没有Console/Portal/global build、migration job、其他容器restart/recreate、环境或网络变更、enroll/rotate/recapture/私有引用写入。Swagger只GET公开schema，旧metadata恢复与新abandonment契约共16项，身份与原幂等键要求保持。

源码工具在运行态调用前验证封存的000–009实际文件SHA及历史报告未完成状态。`--before`使用wx创建新报告；`--after`保存失败或成功后均封存，不能再次覆写。预计真实连续性33项（离线合成测试仅1个保留服务时22项），另只读门禁startup15、boundary27、Admin37、metrics54、Portal79、Swagger16。记录实际源码/编译SHA、退出码和各报告，不把这些部署检查称为业务关闭成功；业务必须待Root审阅实际部署后另行交还Security。
