# M4 身份、四维权限与独立安全验收

状态：M4验收通过。统一 M4 应用及005/006迁移已部署，新API进程和双集群网络已验证；依赖读取投影及IP主机引用修复后真实 HTTP 1,095项断言全通过，真实浏览器1项完整流程及人工界面49项检查通过；失败夹具归档、环境秘密及最终运行时凭证扫描通过，私有凭证引用已移除。本文件不将模拟结果、脚本语法检查或 M3 运行时作为 M4 功能验收。

| 验证 | 当前证据 | 范围 |
| --- | --- | --- |
| 完整单测回归 | unit-results-final.json (`artifacts/M4/unit-results-final.json`, not public) | 975/975，162个测试套件、71个测试文件；API/Web类型检查通过 |
| 独立安全回归 | independent-security-unit-results.json (`artifacts/M4/independent-security-unit-results.json`, not public) | 95/95；实际授权/传输组件，数据库、Redis或故障明确使用测试夹具 |
| PostgreSQL约束与IAM业务 | iam-postgres-constraints.json (`artifacts/M4/iam-postgres-constraints.json`, not public)、iam-business-postgres.json (`artifacts/M4/iam-business-postgres.json`, not public) | 各24/24；独立临时控制台数据库的真实约束与事务，不访问Kong库 |
| 最终进程与部署边界 | startup-final-verification.json (`artifacts/M4/startup-final-verification.json`, not public)、deployment-boundary.json (`artifacts/M4/deployment-boundary.json`, not public) | 启动15/15、边界27/27；新进程、005/006迁移与运行网络核验 |
| 真实双 Kong 管理网络 | admin-network-final-verification.json (`artifacts/M4/admin-network-final-verification.json`, not public) | 37/37；固定 BFF 来源200、其他来源及伪造转发头403 |
| Nginx实际日志脱敏 | nginx-safe-log-verification.json (`artifacts/M4/nginx-safe-log-verification.json`, not public) | 10/10；OAuth query、Referer、User-Agent随机探针与429拒绝均不进入stdout/stderr |
| 双集群登记 | dual-cluster-registration.json (`artifacts/M4/dual-cluster-registration.json`, not public) | 两个独立 Kong OSS 1.5.1 与存储；不是同一端点的别名 |
| 旧测试别名软停用 | alias-deactivation-verification.json (`artifacts/M4/alias-deactivation-verification.json`, not public) | 22/22；三条确切测试别名经BFF审计停用，历史与依赖保留，无原生Kong写入 |
| 真实 HTTP RBAC/IDOR | security-live.json (`artifacts/M4/security-live.json`, not public) | 1,095/1,095；两个独立Kong1.5.1，344次成功产品写入全部有RequestId审计 |
| 真实浏览器 | browser-verification.json (`artifacts/M4/browser-verification.json`, not public)、[m4.spec.ts](../../../../tests/e2e/m4.spec.ts) | 1/1完整流程、10张截图；12次成功产品写入全部关联RequestId审计，页面错误、直连Admin请求、缺失workspace查询均0 |
| 人工浏览器审阅 | UI-review.json (`artifacts/M4/UI-review.json`, not public) | 49/49、8张已视觉审阅截图；38次捕获的成功写入对应38个审计RequestId，另从审计恢复5个前序阶段RequestId；页面错误、直连Admin请求、缺失workspace查询均0 |
| 失败夹具安全归档 | failed-fixture-cleanup.json (`artifacts/M4/failed-fixture-cleanup.json`, not public) | 1,012项检查通过；94个根实体进回收站，118个普通测试账号软删除，74个实体确认已随捕获的级联回收移除；213次BFF写入全部关联审计 |
| 依赖审计 | dependency-audit-full.json (`artifacts/M4/dependency-audit-full.json`, not public)、dependency-audit-production.json (`artifacts/M4/dependency-audit-production.json`, not public) | 两份 npm audit 均0项已知漏洞 |
| 环境秘密扫描 | environment-secret-artifact-scan.json (`artifacts/M4/environment-secret-artifact-scan.json`, not public) | 635个文件、2个嵌入归档条目，已知部署环境秘密泄漏0；运行时测试凭证单独扫描 |
| 最终运行时凭证扫描 | runtime-secret-artifact-scan.json (`artifacts/M4/runtime-secret-artifact-scan.json`, not public) | 636个文件、2个嵌入归档条目，已知测试凭证泄漏0；含源码、85个编译文件及最终HTTP/浏览器/人工/归档证据，私有引用已移除 |

独立回归执行真实 `AuthorizationService`、`NativeKongPolicy`、`KongExecutionContextService`、`MutationService`、`KongService` 及前端权限函数。四维权限始终按同一授权行匹配，实际实体缺少已解析的集群或工作区直接拒绝；只用于上下文发现的粗检查不授予配置权限。Route任意已授权操作只派生实际所属Service的读取，写入、删除、秘密权限仍分别核验。

纯凭证ID/Target ID授权可以内部确认所属对象身份，并通过已发现子实体导航取得准确父ID，不能读取Consumer或Upstream的配置、访问同类型其他ID或跨凭证类型。Consumer父权限继承六类凭证仍要求子对象业务标签交集；秘密读取同时要求对象读取和独立`secrets.read`。Target追加历史记录产生新ID，旧ID白名单不能授权该新记录。

原生执行回归覆盖并发ALS隔离、伪造或序列化能力、已关闭生命周期、路径/请求/响应预算、持久化操作和归档证明、请求体与原始父关系不一致、恢复数据与加密图不一致，以及新实体ID生成后的原子授权记录。未知写入竞争使用明确标注的内存持久化/物理锁夹具：已执行而丢失响应时，新键、另一调用者、端点别名和新BFF实例均不能绕过未决操作；真正独立C2的同ID可以单独执行。这些不是实际Kong网络故障注入结果。

插件权限撤销回归经过实际Kong写调用、固定DNS和最后发送栅栏：DNS等待期间撤销当前平台权限，保留/新提交proto及保留/新提交file-log路径四种配置均发送零次Node HTTP请求。当前1.5.1自带插件清单不包含`grpc-gateway`，其安装按自定义插件平台权限处理；不据此宣称该插件在实际网关已启用。未绑定全局Plugin的写入/删除以及Serverless、自定义插件、允许任意本地文件追加的file-log需当前平台超级管理员，普通全局模块授权不能代替此标记。

真实HTTP验证覆盖普通已登录账号的Konga类字段越权修改与跨用户重置密码、严格DTO、同UUID/同名称跨真实集群和同UUID跨类型、工作区/标签OR与实体ID范围、原生和索引分页、作用域游标、依赖继承、六类凭证和Target的父IDOR、独立秘密读取、团队及直接绑定撤销、账号停用、密码重置及自身/他人会话撤销。344次成功产品写入按344个服务器RequestId全部关联到控制台追加审计，无缺失；检查的JSON patch均为数组，before/after/patch无已知测试秘密。该覆盖统计包括成功HTTP产品写入，受控原生夹具创建单独排除，不访问Kong数据库。原始API Key与Basic密码在真实代理仍可用，查询参数API Key未出现在Kong日志。

真实浏览器流程验证只读按钮及直接HTTP拒绝、标签范围、必要父实体读取、纯子ID授权而父配置不可见、可写但不可删除、真实C2同ID拒绝、普通账号自身资料字段越权拒绝，以及角色撤销后既有Cookie立即失权。实际同一浏览器切换账号时核验了Set-Cookie与当前身份；等待中的晚到刷新竞态另有明确模拟单测，不能把浏览器普通切换视为该故障注入。10张桌面及移动截图、12个成功产品写入及12个对应审计RequestId保存在浏览器证据中；只读权限评审POST不计为产品写入。

人工浏览器审阅实际完成用户、团队和角色创建/编辑、停用及软删除恢复、四类范围权限定义及角色克隆、成员和角色绑定撤销/恢复、自身资料与密码更改、会话撤销及管理员重置密码。8张桌面及移动截图已逐张视觉审阅。38个捕获的成功请求全部找到对应追加审计，前序中断阶段另恢复5个审计RequestId；统计保留捕获与补充证据的区别，不把缺少实时捕获的请求混入38项计数。18个生成的测试密码和浏览器Cookie在最终扫描前仅保留于0600私有引用，扫描通过后引用已移除。

网络证据的37项是直接来源探测。实际Service→loopback Admin及Upstream Target→管理IP Admin代理路径请求均403，伪造X-Forwarded-For/X-Real-IP仍403；同端点由授权BFF来源读取为200。代理POST没有创建Admin对象。危险历史夹具只由受控后端网络测试进程创建到隔离C2，不能经产品任意透传；最终实际运行已通过BFF归档回收这些危险历史夹具。

六次失败HTTP尝试的测试对象随后经已授权BFF统一归档：94个根实体进入回收站，118个普通账号软删除并撤销会话，74个其他实体经已捕获依赖图级联移除。归档另执行1,012项检查及213次成功BFF写入，213个不同RequestId全部有追加审计。清理不直接写Kong数据库、不执行受控原生物理清理，最终成功演示夹具继续保留。

```sh
# 仅在统一M4部署和运行进程确认完成后执行，串行独占写窗口。
M4_DEPLOYMENT_READY=true node tests/security/live-m4.mjs
node tests/security/run-m4-browser.mjs

npx vitest run tests/security/m4-*.test.ts tests/security/data-source-isolation.test.ts
```

测试不打印远端错误正文、密码、JWT、刷新令牌或凭证。秘密引用曾存于工作区外0600临时文件，贯穿HTTP、浏览器、人工截图和失败夹具归档；最终扫描覆盖源码、编译产物、证据、JSON转义/URL编码及报告嵌入ZIP，通过后引用已移除。扫描覆盖范围未变，完成状态和计数随后以无秘密的文字回写本文。HTTP之后的中间扫描不代表后来截图已覆盖。截图脱敏另有视觉审阅，文件字节扫描不进行OCR。M4验收范围是身份与授权；完整M5–M11功能、商用闭环验收仍需后续里程碑逐一完成。

六份真实HTTP失败证据完整保留，失败均不计为通过：

| 初次通过数 | 当时失败 | 处理与证据 |
| --- | --- | --- |
| 191 | 缺少current_password安全拒绝401，测试只接受400/403 | 修正拒绝状态断言；first-attempt (`artifacts/M4/security-live-first-attempt.json`, not public) |
| 352 | 纯Route.write的必要Service读取被自动关联查询403阻断 | 实体详情将无权限关联显示为不可用，保持显式关系接口拒绝；结束前重新核验实体、会话及权限版本。另对纯Service.write级联的私有父引用补充操作权限证明；route-inheritance (`artifacts/M4/security-live-pre-fix-route-inheritance.json`, not public) |
| 483 | 在另一Consumer路径使用原credential ID安全返回404，测试只接受403 | 接受不披露对象的403/404，并增加另一Consumer真实现存凭证的六类操作403；child-capabilities (`artifacts/M4/security-live-pre-fix-child-capabilities.json`, not public) |
| 653 | 外部标签凭证列表被安全投影为200空集合，测试误要求403 | 实际只读确认items为空、外部ID/已知秘密缺失，真实外部凭证详情reveal403；完整脚本补充六类外部凭证reveal403。保留empty-collection (`artifacts/M4/security-live-pre-fix-empty-collection-contract.json`, not public)及只读确认 (`artifacts/M4/collection-contract-clarification.json`, not public) |
| 807 | 另一Upstream路径使用原Target ID安全返回404，测试只接受403 | 接受不披露对象的403/404，并在该Upstream真实现存Target上独立验证403；target-parent-contract (`artifacts/M4/security-live-pre-fix-target-parent-contract.json`, not public) |
| 1082 | 回收IP地址Service时，把host127.0.0.1当作Upstream名称查询，Kong真实返回400 invalid unique name | IP地址主机不解析为命名Upstream；保留其他引用的真实校验错误，不把所有400视作不存在。修复覆盖实体、原生引用与对象图捕获；ip-upstream-reference (`artifacts/M4/security-live-pre-fix-ip-upstream-reference.json`, not public) |

读取关联投影只处理预期403/404，401、5xx和权限/会话在等待中撤销仍中止整个请求。空凭证集合没有解密任何凭证；实体详情及秘密读取仍独立授权。历史Basic、JWT等原值仅私有比较，错误正文不写入报告。

浏览器前两次尝试也保留失败证据：首次导航契约 (`artifacts/M4/browser-first-contract-attempt.json`, not public)、再次登录导航契约 (`artifacts/M4/browser-second-contract-attempt.json`, not public)。无总览授权的普通账号正确进入“我的账号”，测试原先误要求Overview；从资料页再次登录保留有权限的资料页路径，测试原先误要求跳转Overview。两处只修正测试导航预期，未改产品权限或路由，未观察到越权写入或披露；修正后完整浏览器流程通过。

人工审阅的201响应契约中断 (`artifacts/M4/UI-review-pre-contract.json`, not public)和只读审计查询工具中断 (`artifacts/M4/UI-review-pre-audit.json`, not public)分别保留34项、45项已完成检查及当时的失败。会话撤销实际成功返回Nest默认201，工具原先只接受200；随后只读SQL核验工具发生错误。确认原操作和审计后从已知状态继续，没有重放已成功的配置写入，最终49项通过。

日志工具第一次把未配置OIDC合法503误判为错误；保留日志工具修正前结果 (`artifacts/M4/nginx-safe-log-pre-contract-fix-verification.json`, not public)。修正预期后10项实际日志检查全通过，期间没有OIDC授权码或探针泄漏。

LDAP/OIDC是可选认证提供者：当前演示部署未配置外部IdP；已有协议、签名、组映射及竞态测试使用明确标注的提供者夹具，不能视为某个真实LDAP/OIDC服务已联调通过。
