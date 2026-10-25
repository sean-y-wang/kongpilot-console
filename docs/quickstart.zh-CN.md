# 快速开始（Docker Compose 演示）

本流程启动**本地演示环境**：Kong 1.5.1 及其 PostgreSQL、KongPilot BFF、控制台、开发者门户、Redis、Prometheus、Loki。不是生产拓扑；生产部署见 [部署与运维手册](manuals/production-operations-guide.md)（`deploy/compose.production.yml`，接入已有 Kong 追加 `deploy/compose.external-kong.yml`）。

## 前置条件
- Docker Engine 与 Compose v2.24.4+
- Node.js（用于生成 env）、git
- 本机端口 8000、8080、8082 空闲；compose 使用固定私有网段 `172.28.0.0/16`、`172.21/16`、`172.22/16`，冲突时在 `.env` 中整组覆盖。

## 步骤
```bash
git clone https://github.com/sean-y-wang/kongpilot-console.git && cd kongpilot-console
node deploy/scripts/generate-env.mjs .env      # 生成随机密钥，.env 勿外泄
docker compose up -d --build
docker compose ps                              # 等待全部 healthy
```

- 控制台：http://127.0.0.1:8080 ，用户名 `admin`，密码为 `.env` 中 `BOOTSTRAP_ADMIN_PASSWORD`，首次登录后请修改。
- 开发者门户：http://127.0.0.1:8082
- Kong 代理：http://127.0.0.1:8000（Admin API 刻意不暴露到宿主机）。

在控制台中添加内置 Kong 集群（Admin 地址仅 BFF 网络可达，如 `http://kong-admin-endpoint:8001`）。

## 端口冲突
如果 8080/8082/8000 被占用，修改 `.env` 里的 `CONSOLE_WEB_PORT`、`PORTAL_WEB_PORT`、`KONG_PROXY_PORT`，并把 `PORTAL_PUBLIC_ORIGINS` 改成新的门户端口。只有回环地址（`127.0.0.1`、`localhost`、`[::1]`）允许使用 `http://`，其他主机必须用 HTTPS。

## 停止 / 重置
```bash
docker compose down          # 保留数据卷
docker compose down -v       # 仅限演示：删除全部数据
```
