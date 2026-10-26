# M6 不可变凭证激活与元数据恢复修复部署计划

状态：Root明确释放后，本轮七步最小部署已完成；运行态重新冻结并交还Root，真实恢复仍由Security在后续明确释放的独占窗口执行。M7仍仅设计。部署器未调用恢复、批准、发放或原生写接口。

新标签为 `portal-immutable-key-metadata`。连续性工具保留旧的默认 `nullable-portal-repair-continuity.json`，本轮写入独立 `portal-immutable-key-metadata-repair-continuity.json`。before使用wx，不覆盖已有基线；after只完成尚未终结的本标签基线，成功或失败结果均封存，再次修复必须新标签。上一轮nullable修复证据不更新。

连续性使用本轮新的当前基线，包含原12个非API运行服务、C3 Kong/PG及成功退出的bootstrap全部容器/进程/镜像/状态/环境摘要/网络/卷；API容器、镜像、环境、网络、卷不变，仅进程重启。`.env.portal-acceptance`与Security已冻结的当前私有M6引用记录inode/mode/mtime/size/bytes摘要；监控材料、generation/settings/catalog/epoch完全保留。该工具不导出原秘密或原生对象。

Front最后恢复UI需要刷新Console静态文件。`deploy/compose/compose.development.yml`已只读绑定`apps/console-web/dist`到`/usr/share/nginx/html`，因此单独Web workspace编译后新文件立即可见，Console/Portal无需重启或重建。API也只编译自己的workspace，不运行全局prepare-development；生产镜像重建仍属于最终独立验收，不在本轮。

明确释放后的唯一序列：

```sh
node deploy/scripts/verify-nullable-portal-repair-continuity.mjs --before portal-immutable-key-metadata
npm run build -w @kongpilot/api
npm run build -w @kongpilot/web
docker compose --env-file .env --env-file .env.multicluster --env-file .env.portal-acceptance -f docker-compose.yml -f deploy/compose/compose.development.yml -f deploy/compose/compose.multicluster-test.yml --profile multicluster-test -f deploy/compose/compose.metrics.yml --profile observability -f deploy/compose/compose.portal-acceptance.yml --profile portal-acceptance restart console-api
node deploy/scripts/stage-deploy.mjs M6 --multicluster --observability --portal --verify-only
node deploy/scripts/verify-portal-metadata-recovery-openapi.mjs portal-immutable-key-metadata
node deploy/scripts/verify-nullable-portal-repair-continuity.mjs --after portal-immutable-key-metadata
```

部署前以新文件名保留当前startup及各最终部署门禁。命令逐一执行，任一失败保留对应证据并停止；不迁移、不调整环境或网络、不重建容器、不启动C3 bootstrap、不enroll/rotate/recapture、不改私有引用。部署汇总记录实际源码/编译/静态资源SHA、各命令结果和continuity结果，不能把只读verify描述为重新部署全栈。

Swagger验证只GET固定本地`/api/docs-json`，不发送凭证，不调用业务恢复。结果仅八项布尔事实：唯一POST、必填IssueMetadataRecovery请求体、闭合原执行tuple、原execution UUID/正revision、planHash/typed确认、必填原`X-Idempotency-Key`、必填UUID `workspaceId`、仅Console Cookie身份。读取有界4MiB/5秒，失败不打印原文；本轮独立输出`portal-immutable-key-metadata-openapi-verification.json`，wx禁止覆盖。

离线源码证据为 `artifacts/M6/metadata-repair-deployment-unit.json`：87/87通过，含既有C3/私有文件约束、真实本机临时文件的标签/路径/基线/成功与失败封存，以及Swagger契约各字段退化拒绝。测试不执行Docker、不读取真实环境或私有引用、不连接任何服务。

实际证据为 `portal-immutable-key-metadata-deployment.json`：七步命令均exit0；startup15/15、基础27/27、Admin37/37、监控54/54、Portal79/79、Swagger8/8、连续性23/23。`portal-immutable-key-metadata-build-source-proof.json`记录21个已冻结源文件完全匹配、11个API编译文件与3个Console静态文件的SHA；新Console入口资源为`index-Df4JlR77.js`。六份此前门禁复制件字节未变，旧nullable连续性不更新。其他进程、C3退出bootstrap、私有环境/引用和全部监控材料保持不变；无迁移、容器重建、其他重启、轮换或业务恢复。一次工具层将成功restart命令的空session ID保存为undefined而报错，已记录安全说明，实际restart exit0且从未重放该命令。
