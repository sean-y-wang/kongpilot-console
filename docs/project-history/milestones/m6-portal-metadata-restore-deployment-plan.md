# M6 审批模式门户元数据恢复窄修部署

SOURCE ONLY / ACTUAL HOLD。审批模式恢复 page/publication 的计划必须允许严格封存的 `{archive:false}` 元数据动作；直接模式和原生配置声明不变。产品单测、独立审阅和隔离 PostgreSQL 由业务 owner 提供。此工具仅准备独立部署连续性，不代替功能验收；现不读取运行态、数据库、私有环境或凭证。

新标签固定为 `portal-metadata-restore`，Root gate 为 `artifacts/M6/source-portal-metadata-restore-release-gate.json`。源码 SHA、000–009 的冻结 checksum、after 所用 gate SHA 和未封存 baseline 校验全部先于私有文件、Docker 和 ConsoleDB 调用。Before baseline 使用 wx，已封存成功或失败 after 不能覆写；旧标签及历史工具不改、不重入。

复用已测试的 historical workflow-subject 只读程序和 read-features 连续性检查：原12保留服务+C3三容器、退出 bootstrap/migrator、同 API container/image/env/networks/volumes、私有引用/环境原字节、监控 generation/settings/catalog/epochs、原发行和旧失败全过程的行/密文/审计摘要、全部受管 grant/credential/ref/proof/certificate totals，以及000–009 checksum/applied_at保持。唯一允许 API 产物重编译及 API 进程重启，API产物数量按实际记录；Console/Portal产物完整路径与字节必须相同。真实连续性预计29项（原27项+两静态守恒），不重复原32项通用测试。

Root 明确冻结源码并释放唯一窗口后，仅顺序执行五步，任一步失败立即停并保留阶段证据：

```sh
node deploy/scripts/verify-portal-metadata-restore-continuity.mjs --before
npm run build -w @kongpilot/api
docker compose --env-file .env --env-file .env.multicluster --env-file .env.portal-acceptance -f docker-compose.yml -f deploy/compose/compose.development.yml -f deploy/compose/compose.multicluster-test.yml --profile multicluster-test -f deploy/compose/compose.metrics.yml --profile observability -f deploy/compose/compose.portal-acceptance.yml --profile portal-acceptance restart console-api
node deploy/scripts/stage-deploy.mjs M6 --multicluster --observability --portal --verify-only
node deploy/scripts/verify-portal-metadata-restore-continuity.mjs --after
```

不执行 Console/Portal/global build、migration、容器重建、env/network 修改、KongDB 访问、enrollment/capture/metrics rotation、业务或原生写。既有 verify-only 包含预期拒绝零行 audit DELETE 与被阻断公开 ingest POST，报告使用零业务/native写。完成后记录五命令开始/结束/退出码、源码和 API 编译 SHA、Console/Portal原样、startup15/boundary27/Admin37/metrics54/Portal79与连续性29；只交还 Root，业务审批恢复另由 Root 释放独占窗口。
