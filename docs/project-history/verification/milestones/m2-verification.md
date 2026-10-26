# M2 动态插件中心验收

本里程碑使用真实 Kong OSS 1.5.1 验证插件市场、动态 schema 表单、实例筛选和绑定优先级。最终 HTTP 验收 **1,142/1,142 通过**，34 个实际安装插件全部完成生命周期测试，43 个插件测试实例最终确认禁用。明细与 requestId 在 `artifacts/M2/security-live.json`。

后端与前端逻辑单测 **351/351 通过**（`artifacts/M2/unit-results.json`）；其中基础认证、CSRF、会话、SSRF 和数据源隔离专项 **75/75 通过**（`security-unit-results.json`）。本次 npm audit **0 项公告**（`dependency-audit.json`）。部署与网络隔离边界 **27/27 通过**，入口请求限流仍为 20r/s、burst 40。

录制器安全加固另有15条离线回归通过，覆盖秘密清除与公开字段保留；本次未重新生成真实 Kong 响应夹具，不能把离线验证计为新的真实接口录制。

最后仅核验、未重启应用的部署复核有14项通过，27项隔离边界仍通过；入口实际资源与当前编译产物一致。新鲜依赖审计为0，最终环境秘密扫描覆盖354个文件和两个内嵌报告，未发现泄露。证据为 `startup-final-verification.json`、`deployment-boundary-final.json`、`dependency-audit-final.json` 和 `environment-secret-artifact-scan.json`。

真实 Chromium **1/1 通过**：Route 通过 UI 创建；已有 Route 只改名称后保留隐藏匹配头；StatsD 两个嵌套记录通过条件校验并实际写入；八层优先级图可见；丢失成功写入响应时保存被禁用、原键只读回执为 succeeded，实际 POST 仅一次。浏览器页面错误和直连 8001 请求均为零。结果在 `browser-verification.json`，截图为 `plugin-market.png`、`nested-plugin-form.png`、`plugin-precedence.png`。

补充人工浏览器验收完成 Datadog 十个嵌套指标、记录内 tags、Service→Route 绑定切换、启停与实际上下文选择，测试插件最终禁用。隐藏 Route 匹配头的显式清除验证名称输错被拒绝、保存前暂存、取消保留原值，以及确认后 `headers:null` 写入；无匹配头的真实代理请求从404变为200。两组结果在 `UI-review.json`、`UI-header-clear.json`，页面错误与直连8001仍为零。

自动化验收的秘密扫描覆盖当时的262个文件、两个浏览器 HTML 内嵌 ZIP，以及环境秘密、运行时假插件凭证与八个假匹配头，未发现泄露。匹配头扫描值只保存在仓库外的私有临时文件中，扫描完成后删除。结果为 `secret-artifact-scan.json`。随后生成的人工验收证据未读取匹配头、未生成新秘密，并接受环境秘密扫描；它们不属于此前已完成的运行时匹配头扫描范围。

## 重现

```sh
docker compose --profile test up -d echo-upstream
node tests/security/live-m2.mjs
npx playwright test tests/e2e/m2.spec.ts
node tests/security/check-artifacts.mjs
```

先执行 HTTP 插件扫测，再执行浏览器写入测试；同一集群写入由分布式锁串行化。脚本从本地 `.env` 读取登录凭据，BFF 请求间隔至少 70ms，遵守部署的请求限流。API 编译后须明确重启，避免 Node 进程继续使用旧代码。

## 验收设计

| 范围 | 真实验证方式 |
| --- | --- |
| 插件安装清单 | 启动能力探测的 `/plugins/enabled` 是唯一可配置插件清单；逐一读取 1.5 旧式 schema，中心包装保留其字段 |
| 全插件实例 | 每个已安装插件创建为禁用状态、读取回显、修改配置、启用再禁用、归档删除、原 ID 恢复，最后验证仍禁用 |
| 动态复杂表单 | 浏览器操作 StatsD 的两个 array-of-record 项，分别配置 unique_users/set 与 request_count/counter；缺少 sample_rate 时前端阻止提交，补齐后实际写入 Kong 并校验回显 |
| 八层优先级 | 为隔离的 Service、Route、Consumer 创建八种 request-termination 绑定，通过状态码逐层比较真实 proxy 与 BFF 选择结果 |
| 禁用回退 | 每次禁用最高层后验证下一层执行；全部禁用后回到真实测试上游 |
| 条件错误与限制 | 非法 StatsD 条件返回字段错误；插件不支持的 Consumer 绑定、Route 与 Service 不匹配、toggle 多余字段被拒绝 |
| 秘密与公开开关 | 默认实体响应、回收站预览和原幂等键回执不含运行时生成的假秘密；CORS credentials、JWT secret_is_base64 和 OAuth2 enable_password_grant 的布尔值准确保留 |
| 编辑隐藏请求头 | 创建仅含假 Authorization 值的 Route，默认响应显示脱敏标记；浏览器只改名称后，授权读取确认原匹配头仍完整。Upstream 主动检查 headers 仅在实时 schema 声明支持时测试，否则明确跳过该字段写入 |
| 服务端筛选 | 按插件名、四个基本绑定范围和标签，通过真实 size/offset 游标验证筛选与无重复 ID |
| 写入结果不确定 | 浏览器在服务端成功创建禁用插件后丢弃响应；保存按钮禁用，原集群和原幂等键核验返回 succeeded，客户端只发一次写入 |

测试用 AWS、Azure、OAuth 等秘密均为运行时随机假值。具有外部调用能力的插件绑定在没有 Route 的测试 Service 上；仅 kube injector 的真实 schema 要求全局绑定，其配置测试不发送 proxy 请求。真实 proxy 优先级测试只启用隔离的 key-auth 与 request-termination。HTTP 脚本即使失败也尝试将全部创建的插件禁用，并记录无法禁用的 UUID；不会打印秘密或远端错误正文。

## 结果边界

首次真实扫测发现 OAuth2 `config.provision_key` 在默认响应中未脱敏，立即停止测试，并确认当时创建的 11 个插件已禁用。该次 **285 条通过、1 条失败** 的原始记录保留在 `artifacts/M2/security-live-pre-fix.json`，不包含秘密值。修复同时覆盖 AWS access key、回执、索引、回收站和历史 JSON patch 的读取脱敏；公开布尔开关仍准确显示。最终重新运行的结果另列，避免把缺陷发现过程当成成功验收。

新增浏览器 Route 回归还检出：只修改名称时，表单把原来的 null `sources` / `destinations` 转为 `[]`，触发 Kong 对 HTTP 路由的条件校验。表单现保留未设置集合的状态，已有值的真实增删仍可提交；实际 UI 创建与修改均已通过。原始脱敏截图与失败说明保留为 `route-edit-pre-fix.png`、`browser-route-pre-fix.json`。

安装清单应来自当前 Kong 1.5.1 镜像，不能将其他版本的 grpc-gateway、degraphql、kafka-log 等插件声称为本版本内置插件。Prometheus 1.5 schema 没有可配置字段，其修改验收为合法空配置 PATCH。绑定优先级选择一个同名插件实例；不同插件的执行先后由对应版本 handler.PRIORITY 决定。优先级诊断会标注分页未完成、过滤范围受限或自定义优先级未知时的局限。

本次真实插件为：acl、aws-lambda、azure-functions、basic-auth、bot-detection、correlation-id、cors、datadog、file-log、hmac-auth、http-log、ip-restriction、jwt、key-auth、kubernetes-sidecar-injector、ldap-auth、loggly、oauth2、post-function、pre-function、prometheus、proxy-cache、rate-limiting、request-size-limiting、request-termination、request-transformer、response-ratelimiting、response-transformer、session、statsd、syslog、tcp-log、udp-log、zipkin。

实时 Upstream schema 确认没有 `healthchecks.active.headers`，该字段写入被明确跳过；支持范围由实际 schema 决定。隐藏 Route 匹配头的保留属于核心实体编辑回归，另以真实浏览器验证。

市场统计来自控制台索引，并显示观察时间，不能视为网关实时聚合。完整工作区与细粒度 RBAC 仍属于 M3/M4；本阶段只有平台管理员能够修改插件。外部日志投递、云函数实际调用、监控数据与安全授权全链路将在相应里程碑单独验收。
