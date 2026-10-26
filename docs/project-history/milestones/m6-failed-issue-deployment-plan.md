# M6 已拒绝发放的预留关闭：最小部署计划

状态：Root明确释放后，本轮八步最小部署已完成，运行态已冻结交还Root。真实关闭及新申请由Security在后续明确释放的独占窗口执行，部署器未调用任何业务恢复/关闭/批准/原生写接口。

标签固定为`portal-failed-issue-abandonment`，所有旧nullable与immutable-key修复报告封存。新 `verify-failed-issue-repair-continuity.mjs` 复用C3-aware核心连续性：原12非API进程、C3 Kong/PG/已退出bootstrap、API原容器/镜像/配置/网络/卷、当前私有引用的inode/mode/mtime/bytes和全部监控材料/settings/generation/catalog/epoch保留。另保留原`console-migrations`退出容器的完整身份与进程；一次性`run --rm`不覆盖它。

仅追加`009_m6_failed_issue_abandonment.sql`，旧000–008校验和从上一份Root封存释放记录读取，009校验和必须取本次Root最终源码冻结值。工具在任何Docker/DB调用前校验实际源文件；部署前只允许已应用000–008且新表不存在，部署后只允许009一行新增、旧行包括applied_at原样。新证书表必须为空，runtime仅SELECT/INSERT，UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER全部拒绝。M7迁移顺延为010，本轮不实施M7。

只读业务快照从公开证明提取两份workflow/execution UUID，不读取或输出执行键。Node通过现有API运行时账户查询ConsoleDB，单个repeatable-read/read-only事务；不直连KongDB，不调用Admin API。固定查询只返回必要ID/状态/计数及数据库内SHA256。密钥密文、整行计划/执行/凭证/操作/审批/事件/引用在SQL内摘要，原文不出数据库；单集合最多32行，整体执行15秒/256KiB上限。部署前后要求：首份grant/credential继续active generation1，原native3成功和refs2不变；第二份grant继续pending generation0，原execution failed、仅Consumer KONG_VALIDATION_ERROR操作remote_started=true/remote_completed=false、后三步原始pending、引用0、未reveal、无关闭证明，完整事实摘要一致。

Root最终释放后按以下唯一序列执行；`M6_FAILED_ISSUE_SQL_SHA256`仅是公开源码校验和，实际值由冻结记录确定，不写任何环境文件：

```sh
node deploy/scripts/verify-failed-issue-repair-continuity.mjs --before "$M6_FAILED_ISSUE_SQL_SHA256"
npm run build -w @kongpilot/api
npm run build -w @kongpilot/web
docker compose --env-file .env --env-file .env.multicluster --env-file .env.portal-acceptance -f docker-compose.yml -f deploy/compose/compose.development.yml -f deploy/compose/compose.multicluster-test.yml --profile multicluster-test -f deploy/compose/compose.metrics.yml --profile observability -f deploy/compose/compose.portal-acceptance.yml --profile portal-acceptance run --rm --no-deps console-migrations
docker compose --env-file .env --env-file .env.multicluster --env-file .env.portal-acceptance -f docker-compose.yml -f deploy/compose/compose.development.yml -f deploy/compose/compose.multicluster-test.yml --profile multicluster-test -f deploy/compose/compose.metrics.yml --profile observability -f deploy/compose/compose.portal-acceptance.yml --profile portal-acceptance restart console-api
node deploy/scripts/stage-deploy.mjs M6 --multicluster --observability --portal --verify-only
node deploy/scripts/verify-portal-metadata-recovery-openapi.mjs portal-failed-issue-abandonment --with-abandonment
node deploy/scripts/verify-failed-issue-repair-continuity.mjs --after "$M6_FAILED_ISSUE_SQL_SHA256"
```

部署前用新文件名wx保留当前最终startup与各部署报告。八步逐一执行，任一失败保留证据并停止。迁移使用编译后的正式migration CLI与现有owner-only工作任务，在开发覆盖中SQL目录只读挂载且最新migrate.ts追加了新表immutable allowlist；不手工patch DB，不重建旧服务、不跑旧迁移、不改环境/网络、不全局编译或Portal编译、不enroll/rotate/recapture/修改私有引用。Console静态dist已只读绑定，Web编译无需Console重启。

Swagger只GET公开文档，验证既有`reconcile-metadata`八项契约仍通过，同时验证新`abandon-rejected-issue`八项：RejectedIssueAbandonment闭合原执行tuple、原幂等键、必填WID、ConsoleCookie身份和typed确认。不发送凭证或调用业务接口。最终汇总保存冻结源/编译/静态SHA、009实际checksum/权限、33项完整连续性以及15/27/37/54/79和Swagger16项运行态门禁；这些门禁不能替代后续关闭与完整门户业务验收。

实际结果在`artifacts/M6/portal-failed-issue-abandonment-deployment.json`：八步exit0，startup15/15、基础27/27、Admin37/37、监控54/54、Portal79/79、Swagger16/16、连续性33/33全部通过。009实际SHA为`39b2eaf3f0554407114add04aa90a2f197f8cb23b2991077cdc7e018f9dba7fd`；旧000–008包括applied_at完全保留，新证书表0行，runtime仅SELECT/INSERT且其余五项权限false。278份冻结源文件完全匹配，139份API编译文件和3份Console静态文件SHA分开记录于`portal-failed-issue-abandonment-api-source-proof.json`与`portal-failed-issue-abandonment-console-static-proof.json`，新入口为`index-C02dIsIA.js`。六份上轮门禁复制件完整，原12个非API进程/C3三容器/原已退出migrator、当前私有引用与环境、首份成功和第二份失败的所有账本/密文摘要、监控代次/settings/catalog/epoch均保留。没有任何业务关闭或原生写请求；业务验收仍待Security继续。
