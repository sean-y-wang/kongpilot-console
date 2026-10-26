# 项目历程

[English](README.md)

本页概述 KongPilot 走到 v1.0.0 的过程，是原始开发记录的整理摘要；脱敏后的原始文档和证据摘要见文末“归档与证据”；原始实验日志和凭据不公开。

## 里程碑

| 里程碑 | 范围 |
|---|---|
| M0 | 部署基线：Kong OSS 1.5.1、独立数据库、Redis、Node.js 22 BFF、Nginx |
| M1 | 核心实体、六类凭证、回收站 |
| M2 | 动态插件中心（真实 HTTP 1,142 项） |
| M3 | 多工作区（标签软隔离） |
| M4 | 身份、四维权限、独立安全验收 |
| M5 | 监控（Prometheus / Loki） |
| M6 | 开发者门户 |
| M7 | 只追加审计、事件与通知 |
| M8 | 快照、YAML 导入导出、decK 兼容 GitOps、代理 TLS |
| M9 | 运维工具箱（路由模拟、缓存、批量变更） |
| M10 | 配置治理中心 |
| M11 | 变更工单与审批、定时执行、未知结果处置、发布加固；在 v1.0.0-rc.2 上完成验收 |

## M11 验收过程

1. 审批人可执行：定为权限规则并给出职责分离建议（ADR 0001）。
2. 范围调整：不做写入 SLA 和异地容灾，保留轻量并发和 PostgreSQL 备份恢复（ADR 0002）。
3. 生产方式部署：发现 Kong 工作进程 OOM，默认改为 2（ADR 0007）。
4. 离线 DNS：改用 c-ares 并有限回退，离线冒烟 17/22 → 22/22（ADR 0008）。
5. 锁冲突提示与故障注入 17/17。
6. v1.0.0-rc.1：修复偶发失败测试，打标签并正式复扫。
7. 浏览器端到端补齐到 11/11。
8. 门户重复发布加固（ADR 0006）。
9. 去旧品牌，重拍 15 张手册截图。
10. v1.0.0-rc.2：加固在 rc.1 之后合入，因此重新打标签、复扫并完整回归；审计分页确认为接口约定（ADR 0005）。
11. 一次性完整回归全部通过，验收关闭。

## 最终验证（v1.0.0-rc.2）

冒烟 22/22；20 人并发 800 请求 0 错误；故障注入 17/17；备份恢复 9/9；浏览器端到端 11/11。grype 0.120.1 复扫：0 个严重、0 个可修复；13 个无修复版本的高危漏洞已登记豁免，**2026-12-31 到期**。

## 已知缺口

界面暂只有中文；故障演练遗留的“结果不确定”创建操作暂无产品内对账路径；超大规模多服务推广受 500 次调用预算限制；仅支持 Kong OSS 1.5.x。

## 经验

不放宽门禁换绿灯；不同时间点的证据不等于发布，要在同一标签上一次性重跑；离线环境是真实环境；默认值很重要；区分实验环境问题和产品问题；有界接口就是契约。

## 归档与证据

- [里程碑文档](milestones/README.md) — M0–M11 plans, contracts, checkpoints
- [验收](acceptance/README.md) — M11 commercial acceptance checklist
- [验证证据](verification/README.md) — rc.2 final regression, milestone verification reports, release-candidate manifests
- [安全设计与评审](../architecture/security/README.md)
- [归档清单](ARCHIVE-MANIFEST.md) — published / covered / private for every internal path
