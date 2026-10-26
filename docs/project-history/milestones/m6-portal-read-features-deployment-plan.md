# M6 分类分页与管理详情补缺部署

本轮先完成 proof 权威的有界分类/搜索、开发者和应用安全详情、授权/申请关系导航，再做部署和真实 UI 验证。旧 000–009 不变；M7 尚未发布。

源码门禁包括后端/前端必要单测、真实隔离 PostgreSQL、全工作区类型检查和源码审查。原浏览器未完成部分需先验证完成；此时唯一业务执行者暂停，私有引用、会话和全部历史失败回执保留。

部署者仅按以下顺序执行一次，失败即停当前阶段并留原证据：

1. `node deploy/scripts/verify-portal-read-features-continuity.mjs --before`
2. `npm run build -w @kongpilot/api`
3. `npm run build -w @kongpilot/web`
4. `npm run build -w @kongpilot/portal-web`
5. 使用原 Compose/env/profile 清单，仅 `restart console-api`。
6. `node deploy/scripts/stage-deploy.mjs M6 --multicluster --observability --portal --verify-only`
7. `node deploy/scripts/verify-portal-read-features-continuity.mjs --after`

沿用已验证的历史 workflow-subject 只读程序及原连续性检查，核对原 15 个服务、网络/卷/密钥/监控代次和 epoch、全部 Portal 凭证/对象图/失败证书、000–009 和退出迁移服务保持不变；只允许 API 进程重启及三个 workspace 的构建产物更新。无迁移、网络或环境重建、秘密捕获/轮换、业务/原生写操作。verify-only 包含预期拒绝且零行变更的边界请求。

部署完成后，业务执行者在另一明确窗口运行手工 UI 和新增只读详情/分类验证；再清理、检查全部成功写审计、扫描新发放凭证及清理后的日志。部署检查不替代功能验收。
