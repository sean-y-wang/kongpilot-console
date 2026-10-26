# M8 固定批量路径的边缘等待

本轮仅修改两份 Console 公共 Nginx 配置。实际部署仍 HOLD；生产环境尚未执行。Root 后续统一冻结 API、Web 和边缘配置后，以下命令仅作为该窗口的边缘步骤，不单独重启其他服务。

`default.conf` 与 `console-production.conf` 中两个相同正则 location 将等待限制为 310 秒，连接仍为 5 秒。所有 UUID 必须是完整的 8-4-4-4-12 十六进制路径段，无尾斜杠或额外段：

| 方法 | `/api/v1/clusters/:clusterId` 后的路径 |
| --- | --- |
| POST | `/snapshots` |
| POST | `/snapshots/:snapshotId/export`、`/snapshots/:snapshotId/rollback-plan` |
| POST | `/configuration/imports`、`/configuration/exports` |
| POST | `/configuration/plans/:planId/apply`、`/configuration/plans/:planId/reconcile` |
| POST | `/configuration/exports/:exportId/download` |
| POST | `/workflows/:workflowId/execute` |
| GET | `/snapshots/:snapshotId/compare/:otherId` |

上述路径的方法不匹配时，边缘直接返回 405，不访问 upstream。其余 API 仍使用 35 秒；Portal 的 `^~ /api/v1/portal/` 优先返回 404。查询参数不改变 location。限流 20r/s、burst40、429、XFF 替换、单一 nosniff、CSP、日志格式和 TLS 配置保持原样。310 秒是代理读写等待，不是新的业务执行许可或应用总时限。

## 已完成的源码验证

`tests/unit/m8-edge-bounded-waits.test.ts` 检查真实 Controller 路径、方法、错误 UUID、额外路径段、非 M8 路径及代理边界。`tests/integration/m8-edge-nginx-syntax.mjs` 使用既存 Nginx 镜像摘要，独立 UID101、network-none、只读根文件系统、cap-drop、tmpfs 容器执行两份配置的 `nginx -t`，不连接现役 API，不拉取或构建镜像。

首次隔离测试的失败报告保留在 `artifacts/M8/edge-bounded-waits-nginx-syntax.json`：源 checkout 的公共主配置为 0600，UID101 不能读取。最终测试只复制公共配置到临时目录、设 0444 并核对 SHA，模拟 Dockerfile 的 `COPY --chmod=0644` 可读性；临时合成 TLS 材料已删除。最终结果为 `artifacts/M8/edge-bounded-waits-nginx-syntax-final.json`。该结果证明 Nginx 配置语法，不宣称生产 bind 权限或生产运行验收通过。生产准备应使公共配置 0644，或以 SHA 相同的公共 0444 副本只读挂载；不调整私有 TLS key 的保护策略。

## 后续唯一边缘重载步骤

先按 Root 新 freeze 核对源码 SHA，并记录现役 Console Web 的容器/image/PID、加载配置 SHA、静态三文件 SHA 与保护基线。开发 overlay 已将 `default.conf` 只读挂载到 `/etc/nginx/conf.d/default.conf`，无需 COPY 或容器 recreate。使用原七份 Compose 文件、三个 env 路径和原 profiles，只清除冲突 Docker endpoint/context/TLS selectors，保留代理、CA 和 Docker 配置：

```bash
edge_compose=(
  --env-file .env --env-file .env.multicluster --env-file .env.portal-acceptance
  -f docker-compose.yml -f deploy/compose/compose.development.yml
  -f deploy/compose/compose.multicluster-test.yml -f deploy/compose/compose.metrics.yml
  -f deploy/compose/compose.portal-acceptance.yml -f deploy/compose/compose.notifications-test.yml
  -f deploy/compose/compose.proxy-tls-test.yml
  --profile multicluster-test --profile observability
  --profile portal-acceptance --profile notifications-test
)
env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock compose "${edge_compose[@]}" exec -T console-web nginx -t
env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock compose "${edge_compose[@]}" exec -T console-web nginx -s reload
```

必须先 `nginx -t` 成功才执行 reload；失败保留新证据并停止。reload 后核对加载配置 SHA、master PID、原容器/image/network/volumes、静态 SHA、其他服务与私有材料连续性，记录 worker 受控替换。不用业务 POST、登录或 Native 请求来验证部署，不重新构建或重启 Console Web。新 API/Web 的 Root 授权动作在统一窗口中另行记录；本文件的命令不授权这些动作。生产配置没有当前部署，本轮不执行其 reload。
