# M3 部署与数据库验证

本阶段增加控制台工作区、实体 annotations 和迁移计划，Kong 仍使用 OSS 1.5.1。工作区能力依赖版本适配层的合法保留标签，不调用 Kong 企业工作区接口，不调整 M4 管理网络 ACL。

## 迁移前证据

```sh
node deploy/scripts/verify-workspace-migration.mjs --baseline
```

只使用 API 容器中的 `kongos_app` 受限连接执行 SELECT，拒绝在 004 已应用后伪造基线，也拒绝覆盖原有基线。`artifacts/M3/database-migration-baseline.json` 保存历史 mutation、recycle 和 audit 的 UUID 与原 workspace 归属，用于确认 004 不回填未知归属、不改写历史审计。它不读取加密 payload、凭证或 Kong 数据库。

## 模块稳定后部署

只有各模块负责人确认代码稳定后才执行：

```sh
node deploy/scripts/stage-deploy.mjs M3
node deploy/scripts/verify-workspace-migration.mjs
```

阶段脚本编译、以独立 owner job 执行 migration 和角色授权、显式重启 API/Web，等待健康并检查运行时加载当前编译产物。004 SQL 必须与已应用 checksum 一致；运行 API 持有受限账号，不接触 owner 密码。启动与隔离边界证据写入 `artifacts/M3/`。

数据库专项确认三张历史表的 ID 与 workspace 归属未变化、每个存续集群具有 active 默认工作区、六个工作区/操作复合外键以及进度行到计划的集群绑定外键。随机夹具和预期失败全部放在一个显式回滚事务中，验证跨集群引用、NULL 集群审计绕过、默认工作区保护、软删除保留字段、不可复用工作区编码和 annotations 类型/revision 约束。逐对象进度表还验证计划范围、重复 object_key、长度、实体类型、状态、指纹、错误码和 UUID。测试完成后检查夹具、审计行和临时链作用域均不存在；不执行网关写入，报告仅保存 UUID、检查结果与 SQLSTATE。

## 本轮实测结果

2026-10-10 的初次统一部署完成编译、独立 owner job 迁移和 API/Web 显式重启，启动验证 14/14、隔离边界 27/27 通过。API 新进程启动时间为 `15:57:42 UTC`，004 已应用且 checksum 与源码一致。初次证据保存在 `artifacts/M3/startup-verification-initial.json` 和 `deployment-boundary-initial.json`；后续兼容性修复的当前运行状态以最终复核证据为准。

`database-constraints.json` 的真实 PostgreSQL 检查 53/53 通过，包括七个复合外键与正常/拒绝场景。迁移前 759 条变更记录、85 条回收记录、2,144 条审计记录的 ID 和 NULL 工作区归属全部保留；所有数据库夹具及临时审计链已回滚清除。第一次验证在脚本的合成 INSERT 参数推断处收到 `42P08`，修正脚本的 UUID 显式转换后通过，初始失败保存在 `database-constraints-initial-verifier-error.json`；应用代码和 004 DDL 未因此调整。

## 阶段最终复核

真实 BFF、网关和浏览器验收由安全及 UI 测试单独完成，不能用数据库测试替代标签软隔离、迁移或凭证可用性验证。功能验收和截图完成后执行只读最终复核：

```sh
node deploy/scripts/stage-deploy.mjs M3 --verify-only
node deploy/scripts/verify-stage-artifacts.mjs M3
```

最终复核不重新部署；HTML/JS/CSS 的实际返回 SHA256 必须匹配最新资源。环境秘密扫描覆盖新旧源码、编译结果、证据和报告内嵌 ZIP；动态测试凭证由其生成测试程序单独扫描。阶段状态以实际证据的 `allPassed` 为准，不以本部署说明代替完成记录。

本阶段最终只读复核已经通过：启动 14/14、边界 27/27，实际提供的最新前端 bundle 为 `index-vLk5v3y7.js`，与磁盘编译文件 SHA256 一致。没有重新编译、执行 migration 或重启 API。`dependency-audit-final.json` 的依赖漏洞总数为0；环境及新旧源码/证据扫描未发现秘密泄漏，最终文件数量见 `environment-secret-artifact-scan.json`。安全测试另外完成运行时秘密扫描（338个文件、2个内嵌 ZIP 条目、零泄漏），并删除私密运行时参考文件。上述证据不替代 M4–M11 后续模块及最终生产镜像验收。
