# KongPilot

[English](README.md) | [简体中文](README.zh-CN.md)

KongPilot 是面向 **Kong OSS 1.5.x** 的自托管网关管理控制台。浏览器只访问独立的 NestJS BFF，不直接访问 Kong Admin API。提供多集群、工作区（标签软隔离）、实体与插件管理、RBAC、审批工单、配置快照与 GitOps、监控（Prometheus/Loki）、开发者门户、审计与通知。

> 状态：v1.0.0 发布候选版。界面目前仅有简体中文，英文语言包规划中。KongPilot 不修改 Kong 源码，也不连接 Kong 数据库。

## 功能

- 集群与环境、Kong 1.5 适配层、限流 / 熔断 / 锁
- Service、Route、Upstream/Target、Consumer、证书、SNI、六类凭证，回收站支持完整对象图恢复
- 插件中心：动态 schema、绑定、启停与优先级
- 用户 / 团队 / 角色、四维 RBAC、会话、带审计的秘密读取
- 多级 / 会签审批、定时变更、Diff / 执行 / 回滚
- 配置快照、YAML 导入导出、兼容 decK 的 GitOps
- Vitals：基于 Prometheus/Loki 的流量、延迟、带宽
- 开发者门户：文档、应用、凭证申请与生命周期
- 追加式审计、事件订阅与投递（Webhook / SMTP）

## 快速开始

Docker Compose 演示环境（Kong 1.5.1 + KongPilot）见 [docs/quickstart.zh-CN.md](docs/quickstart.zh-CN.md)：

```bash
node deploy/scripts/generate-env.mjs .env   # 生成随机密钥，切勿提交 .env
docker compose up -d --build
# 控制台 http://127.0.0.1:8080  门户 http://127.0.0.1:8082
```

## 开发

```bash
npm ci
npm run typecheck
npm test
npm run build
```

本地开发使用 `npm run dev:api`、`npm run dev:web`、`npm run dev:portal`，需自备 PostgreSQL 与 Redis。路由模拟依赖从源码构建的 PCRE1 原生助手（`apps/console-api/native-bin/`，不入库）。

## 文档

- [快速开始](docs/quickstart.zh-CN.md)
- [产品手册](docs/manuals/README.md)：部署运维、用户使用、恢复手册
- [Kong 1.5 对接](docs/kong-1.5-compatibility.md) / [decK 兼容](docs/deck-1.5-compatibility.md)

## 贡献与安全

见 [CONTRIBUTING.md](CONTRIBUTING.md)、[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。安全漏洞请按 [SECURITY.md](SECURITY.md) 私下报告。

## 许可证

[Apache License 2.0](LICENSE)。Kong 是 Kong Inc. 的商标；KongPilot 为独立项目，与 Kong Inc. 无隶属或背书关系。
