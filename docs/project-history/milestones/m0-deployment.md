# M0 部署与验证

本文件保留 M0 当时的部署与验收步骤。M6 增加独立门户和生产来源校验后，现行启动命令请使用 [README](../../README.md) 与 [M6 部署说明](m6-deployment.md)；本地 HTTP 演示需要显式 development override。

默认部署使用 Kong OSS **1.5.1** 与独立 PostgreSQL 11、控制台 PostgreSQL 16、Redis 7、Node.js 22 API 和 Nginx Web。Kong 与控制台数据库使用不同网络、卷及账号。API 没有 Kong 数据库连接配置，也不加入其存储网络。

## 启动

```sh
node deploy/scripts/generate-env.mjs
docker compose up --build -d
docker compose ps
```

生成器拒绝覆盖已有 `.env`，以 0600 权限保存随机凭据并且不打印它们。也可以复制 `.env.example` 并自行替换所有占位值。密码请使用随机字母数字或十六进制值；连接 URL 中的特殊字符需要 URL 编码。登录账号默认 `admin`，密码在本地 `.env` 的 `BOOTSTRAP_ADMIN_PASSWORD`。控制台打开 `http://localhost:8080`，浏览器只调用同源 `/api/v1`。

Kong bootstrap 和控制台 migration 是独立的一次性任务。控制台 migration 使用数据库 owner 账号创建、迁移、种子初始化以及授权；运行 API 只持有 `kongos_app` 非超级用户连接。API 对审计仅有 INSERT/SELECT，对迁移表仅有 SELECT。启动依赖任务成功和服务健康，重复启动不会清空数据。

Kong 代理端口 8000 与 Web 8080 只绑定宿主机回环地址。8001、PostgreSQL、Redis、API 3000 均不发布。Web 只加入 frontend 网络；Admin 网络仅由 Kong、API 及显式启用的测试 mock 使用。生产可在 Web 前添加 TLS 反向代理，并设置 `COOKIE_SECURE=true`、限制主机入站和出站地址、配置备份与监控。

## 管理式云环境构建

此环境的外部 HTTPS 经过代理，需要把平台 CA 以 BuildKit secret 传给 npm；证书不会复制到镜像，不关闭 TLS 校验：

```sh
node deploy/scripts/managed-build-override.mjs
docker compose -f docker-compose.yml -f /tmp/kongos-compose-managed-build.yml build
docker compose up -d
```

普通环境执行默认命令即可。代理 CA 只在依赖安装 RUN 阶段挂载。容器本机健康检查使用直达 loopback，不经过外部代理。

## 可选观测和测试

```sh
docker compose --profile observability up -d prometheus loki
docker compose --profile test up --build -d mock-kong
node tests/mock-kong/server.mjs
```

Prometheus/Loki 无宿主机端口。登记 `http://prometheus:9090` 或 `http://loki:3100` 为数据源后测试。M0 只验证数据源连接；网关指标接入在 M5。Prometheus 不加入 Admin 网络，后续通过 BFF 内部代理抓取 Kong 指标。

mock 默认绑定工作区 loopback 18001，Docker test profile 绑定测试 Admin 网络 8001。mock 使用真实 1.5.1 脱敏 fixture，并以独立模式提供合成分页及故障场景。mock 结果不替代真实 Kong 的验证。

## 验证与证据

```sh
node deploy/scripts/capture-kong-fixtures.mjs
node deploy/scripts/verify-deployment.mjs
node deploy/scripts/verify-observability.mjs
```

fixture capture 通过 Kong 容器自身 loopback 读取真实响应，`tests/fixtures/kong-1.5.1/manifest.json` 记录来源和时间。部署检查写入 `artifacts/M0/deployment-verification.json`，只记录网络、端口、健康、镜像和测试结果，不导出容器环境或凭据。浏览器截图和关键 BFF 请求记录由 M0 集成/e2e 验证补充。

重新录制前需在开发环境执行 `npm ci`、`npm run build -w @kongpilot/api` 并准备有效的本地 `.env`。录制器复用编译后的 BFF SecretService 与 schema-default 清理函数，对所有响应体脱敏并保留公开布尔默认值。`node deploy/scripts/verify-fixture-sanitization.mjs M2` 只使用随机合成秘密做离线回归，不调用 Kong、不改写已记录 fixture；已有基线不得作为普通启动步骤自动重录。

`verify-observability.mjs` 在可选服务已启动时，经真实 BFF 登录、登记并探测两种数据源，保存脱敏请求证据并注销测试会话；不会打印登录凭据。它会保留演示数据源供页面查看。

## 后续里程碑本地验证

M0 默认镜像启动验证通过后，可显式使用开发覆盖文件挂载编译结果，以避免管理式环境的 vfs 反复复制大型 Docker 构建层。首次启用：

```sh
node deploy/scripts/prepare-development.mjs
docker compose -f docker-compose.yml -f deploy/compose/compose.development.yml up --no-build --pull never -d console-api console-web
```

后续每次编译、迁移及重载：

```sh
node deploy/scripts/prepare-development.mjs
docker compose -f docker-compose.yml -f deploy/compose/compose.development.yml run --rm --no-deps console-migrations
docker compose -f docker-compose.yml -f deploy/compose/compose.development.yml restart console-api console-web
```

挂载均为只读，迁移任务仍使用 owner 账号，API 仍使用受限账号。它只能验证已有镜像所包含的依赖；依赖变化需要重新构建。最终整体验收必须重新构建完整镜像，执行默认 Compose，并确认 API/Web 没有代码绑定卷。

Kong 1.5.1 和 PostgreSQL 11 已停止上游维护。版本兼容是此任务的硬约束；生产部署需要组织批准历史软件风险、限定网络可达性并建立升级计划。M0 交付代表工程基座验证，不代表 M1–M11 已完成或已获得商业安全认证。

后续里程碑在模块负责人确认代码稳定后，可执行 `node deploy/scripts/stage-deploy.mjs M2`（替换阶段编号）：串行编译、执行控制台迁移、显式重启 API/Web、等待健康并验证进程启动晚于编译产物。它只使用开发绑定覆盖，不重建生产镜像、不删除业务数据、不发布服务；M11 生产镜像验证单独执行。`--dry-run` 显示步骤但不改变运行环境；`--verify-only` 只做最终启动/网络/运行时数据库权限边界检查。证据保存在对应 `artifacts/M*/`，只记录状态、请求 ID 和不含凭证的运行信息；最终复查文件独立保存，保留初次部署证据。业务功能、真实插件和浏览器验收由各阶段测试另行验证。

启动脚本会比对实际返回的 HTML、JS、CSS 与当前编译产物的 SHA256，确认 Web 独立构建后已提供新资源。`node deploy/scripts/verify-ingress.mjs M2` 用一次有界、本机、无凭证的健康请求突发验证 Nginx 20r/s 限流和恢复，不调用 Kong 实体端点；应与业务验收串行运行。最终截图和测试报告完成后，`node deploy/scripts/verify-stage-artifacts.mjs M2` 扫描 Git 跟踪文件、阶段证据、编译结果以及测试报告内嵌 ZIP，检查部署密码、应用密钥和加密密钥；测试期间动态生成的 Kong 凭证仍由对应测试程序保留在内存并独立扫描，扫描证据不包含秘密值。
