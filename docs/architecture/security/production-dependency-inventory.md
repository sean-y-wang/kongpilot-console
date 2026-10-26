# 生产依赖早期清单

状态：**源码清单与公开 npm 公告查询，非最终镜像/SBOM/商用扫描**。生成时间为 2026-10-11 00:53 UTC；完整清单见 production-dependency-inventory.json (`artifacts/planning/production-dependency-inventory.json`, not public)。本轮没有安装、更新、补丁、锁文件变化、Docker/运行时探测或部署操作。

## 固定输入与查询结果

- `package-lock.json` 为 lockfileVersion 3，SHA256：`971553cd85c503e2d2b3cc034fd7adeca85cd87ba6dea6052d9cf647c04fae23`，查询前后完全一致；所读取的 package manifests、Dockerfiles 与 Compose 文件也保持原哈希。
- 清单记录 535 个 lock entries、530 个非 link package 记录，以及所有直接依赖的请求/实际版本、依赖 Node engines、锁路径和工作区生产可达关系。API 图为 167 包、Console Web 为 171 包、Portal Web 为 168 包；这些图有共享节点，不能相加当总量。
- 实际执行 `npm audit --omit=dev --package-lock-only --json --ignore-scripts`，registry 固定为 `https://registry.npmjs.org/`，TLS 验证开启、无 fetch 重试，超时上限 45 秒。使用独立空 user/global npm 配置，不读取仓库私有部署配置；原始响应与 stderr 不发布，失败仅保存安全错误类别。
- 本次 registry 查询 **731 ms、exit 0**，info/low/moderate/high/critical/total 均为 **0**。npm 元数据记录 prod 342、dev 192、optional 56、total 534；optional 是标记，不与 prod/dev 再相加。当前无可报告的受影响直接/传递依赖或工作区，不把空 findings 写成“已验证不可利用”。
- 查询工具为 Node **v24.19.0**、npm **11.9.0**；这不是生产容器 Node 的已观察版本。各工作区 manifest 未声明 `engines`，实际依赖的 engines 已逐包记录。

## 实际声明的版本

| 范围 | 源码声明 |
| --- | --- |
| API | NestJS common/core/platform-express 12.1.2、Swagger 12.0.2、pg 8.16.3、ioredis 5.8.1、jsonwebtoken 9.0.2、bcryptjs 3.0.2、ldapts 9.2.0、openid-client 5.7.1、nodemailer 10.1.0；其余依赖与精确版本见 JSON |
| Console Web | React/React DOM 18.3.1、Ant Design 5.27.6、TanStack Query 5.90.5、ECharts 6.1.0、react-router-dom 7.18.4 |
| Portal Web | React/React DOM 18.3.1、Ant Design 5.27.6、TanStack Query 5.90.5、react-router-dom 7.18.4；独立工作区 |
| 构建/测试 | TypeScript 5.7.3、Vite 6.4.4、Vitest 5.0.3、Playwright 1.56.1；本次 omit=dev 公告查询不覆盖这类 dev-only 包 |
| Node 镜像 | API build/runtime、Web/Portal build、collector/mock/test upstream 声明 `node:22-bookworm-slim` |
| Web 镜像 | Console Web 与 Portal Web runtime 声明 `nginx:1.27-alpine` |
| 网关与存储 | `kong:1.5.1`、Kong 专用 `postgres:11-alpine`、控制台 `postgres:16-alpine`、`redis:7-alpine` |
| 可选数据源 | `prom/prometheus:v3.3.1`、`grafana/loki:3.5.0` |

Compose 中的 `kongos/console-api:local`、`kongos/console-web:local`、`kongos/portal-web:local` 是本地构建标签。共 28 个 FROM/image 声明逐项附有源文件、行号、stage/service；所有这些声明都没有 digest pin。本轮不检查当前镜像 digest、Node patch 版本、系统包或实际容器文件。

API Dockerfile 的生产安装是 `npm ci --workspace @kongpilot/api --omit=dev`；Web/Portal runtime 为 Nginx 静态资源。锁图的“productionReachableFrom”表示包管理关系，不证明包一定进入 API 最终安装或前端 bundle，更不证明可达漏洞行为。若未来公告非零，清单按直接/传递关系与实际锁节点映射工作区，生产适用性保持 unresolved，另行核对真实代码路径。

## 第二批需要补齐的扫描证据

由 DevOps/Reviewer 在独立生产镜像总验收执行：记录最终 digest、实际安装包/前端 bundle 的 SBOM、OS 与应用镜像漏洞、届时锁文件哈希和公告结果；Root 在商用报告中说明实际适用范围和未消除项。该步骤与 [两批验收复核](two-batch-production-acceptance-review.md) B2-6～B2-8 对应。

本次 npm 的 0 公告不覆盖 Kong/OpenResty、PostgreSQL、Redis、Nginx 或基础系统库。Kong 1.5.1 与 PostgreSQL 11 的上游维护限制仍存在；没有把本报告作为自动升级指令或商业安全认证。
