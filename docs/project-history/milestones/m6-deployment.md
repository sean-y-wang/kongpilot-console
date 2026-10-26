# M6 门户部署

当前状态：实际启动与部署边界验证已通过，安全负责人正在独占执行真实HTTP/浏览器验收。启动验证不代表工作流与凭证端到端验收已经通过。M5 已封存为 `df98907`，本阶段不得改写此前证据。

## 服务和边界

生产默认 Compose 包含 `portal-web`。门户监听演示地址 `http://127.0.0.1:8082`，控制台仍为8080。门户 Nginx 使用两个独立网络：内部 `portal-edge` 默认 `172.28.41.0/24`，只含API `.10` 与门户 `.20`；入口 `portal-entry` 默认 `172.28.42.0/24`，只含门户 `.20`，提供localhost端口发布。API不会加入入口网络，也不公开3000/9092。门户不加入 Admin、存储或监控网络，API原有接口继续使用既有地址与权限。普通Service/Target/日志插件出站同时保护门户两接口IP和hostname。

门户仅代理精确 `/api/v1/portal/` 前缀到 API3000；其他 `/api/`、Swagger、Admin及内部采集路径404。Console Nginx拒绝门户前缀，管理侧 `/api/v1/clusters/:cid/portal` 保持原有身份守卫。Portal Host保留8082端口，代理替换来源IP头。日志不含query、Referer、UA、请求头或正文；请求错误日志明确送至 `/dev/null`，诊断使用BFF安全结构化日志。

Portal runtime 使用 UID/GID101、cap_drop ALL、NNP、只读根文件系统和32MiB `/tmp` tmpfs。主 Nginx配置将PID及五类临时目录移到tmpfs。CSP仅允许self脚本/连接，禁止iframe/object；Ant Design样式允许inline。生产应部署为独立HTTPS主机名，设置明确 `PORTAL_PUBLIC_ORIGINS` 和 `COOKIE_SECURE=true`。生产base固定 `NODE_ENV=production`，不提供HTTP Origin默认值；本地development override显式设为development/非Secure，仅用于HTTP演示验证。

`PORTAL_SECRET` 为独立32随机字节的64hex字符串，仅API持有，与APP_SECRET/CONSOLE_ENCRYPTION_KEY不同。`prepare-portal-environment.mjs` 只追加缺少的门户配置，拒绝非0600、非当前所有者、符号链接、重复KEY和非法旧值；保留既有数据库、Redis、管理密码和密钥。现有值绝不自动轮换。

生产生成器要求明确HTTPS Origin：

```sh
node deploy/scripts/generate-env.mjs .env.production \
  --production --portal-origin https://portal.example.com
```

未提供HTTPS Origin时不会写入文件；默认demo生成器只配合development override。`environment-generation.json` 已离线验证28/28，包括独立门户256-bit密钥、0600、禁止覆盖现有文件、生产HTTPS/Secure及现有.env字节保持。

## 授权后的启动命令

在Root明确统一源码release后，由唯一部署者执行：

```sh
node deploy/scripts/stage-deploy.mjs M6 \
  --multicluster --observability --portal \
  --capture-existing-metrics-test-reference
```

流水线先只读记录现有容器/具名卷/网络/密钥材料/数据库监控generation与epoch，再追加门户环境，单次编译API、Console与Portal，执行008迁移，并为API应用新增的Portal网络及环境。只启动Portal、刷新Console Nginx，不重新创建Kong、PG、Redis、Prometheus、Loki或collector，不运行监控enrollment/rotation/配置reload。

当前开发验证以只读绑定 dist 运行；`portal-web` 复用已缓存Nginx runtime。最终生产镜像由 `apps/portal-web/Dockerfile` 独立构建，其 Node22 workspace-only npm ci 使用锁文件和可选 BuildKit `proxy_ca`，全程保持TLS校验。M11在独立验证项目中完成无开发绑定的生产镜像启动，保留现有业务验证卷。

真实部署验证命令仅做只读请求和边界检查：

```sh
node deploy/scripts/stage-deploy.mjs M6 \
  --multicluster --observability --portal --verify-only
```

证据写入 `artifacts/M6`：启动、基础部署、37项双集群Admin边界、监控边界、门户API/网络/UID/安全响应头和当前静态资产SHA。M6的监控验证检查现有generation与DB当前family匹配，不重写M5证据。真实Portal认证、审批、API Key轮换/吊销由安全与Web所有者按独占窗口验收。

## 现有采集凭证的测试引用

显式测试标志通过独立可信 `dist/infrastructure/metrics-test-capture.js` 读取当前活动四用途密钥。它接收有界UUID列表stdin，校验当前generation、用途/audience、contextual AES解密和SHA指纹，然后仅在API `/dev/shm` tmpfs产生0700目录/0600文件。stdout只有捕获ID、安全路径、CID/generation/count，没有令牌。

宿主工具校验固定路径、文件类型/所有者/权限/大小和四用途family，原子无覆盖写入 `/tmp/kongos-m6-runtime-secrets.json`。本环境的Docker归档复制不能读取容器tmpfs，改由可信Node进程使用stdin传入的一次性AES-GCM密钥传输；stdout只含有界密文，AAD绑定M6/capture ID/路径/全部CID-generation/count。容器先验证0700私有父目录及0600 regular file，并以NOFOLLOW/NONBLOCK读取，拒绝符号链接、FIFO和超限文件；宿主只在RAM解密并校验完整当前family，随后0600原子发布。中间材料在finally清除，即使ack其他元数据无效也仅按独立固定路径规则清理tmpfs。秘密不进入argv、公开artifact或Docker日志。不会enroll或rotate。该引用由安全负责人保留至全部HTTP/浏览器/人工截图/清理扫描结束，扫描也覆盖Basic编码，然后立即删除。

首次实际启动已完成编译、008迁移、API/门户启动和13/13连续性检查，但在Docker tmpfs归档复制处失败；`startup-initial-capture-failure.json`保留该结果。修复仅涉及宿主捕获工具，恢复时只运行捕获和只读verify，避免重复构建、迁移、重建服务或重置监控数据。

后续只读验证发现Docker28.4.0不为仅连接internal网络的容器发布端口：HostConfig声明8082，但实际NetworkSettings.Ports为空。`startup-continuation-readiness-failure.json`保留该结果。修复增加独立门户入口bridge，只重新创建Portal及API；API仅为加载新入口IP的出站保护环境而重建，不加入入口。既有采集测试引用保持原0600文件，不重复捕获。无再次编译、迁移或Kong/PG/Redis/Prometheus/Loki/collector/Console重启；最终重新核对原连续性基线和全部只读边界。

恢复后的 `startup-verification.json` 明确列出两次失败、对应证据与实际继续执行命令；`deployment-continuation.json`记录无再次build/migrate、现有私有引用保持原inode/mtime/bytes。最终实际门禁：startup15/15、原连续性13/13、基础部署27/27、双集群Admin37/37、监控部署54/54、Portal79/79。两个`nc`正向对照成功，受保护Admin/数据库/Redis/collector/内部采集端口的所有literalIP TCP探测均不可达；不是把DNS失败或工具不支持误当网络隔离。门户localhost8082、静态SHA、精确API代理与禁止路径同时通过。

真实业务首轮随后定位到发布/退役扫描路径及已失败发布计划的显式重试规则，修复通过1954项全量测试后，仅编译API workspace并重启原API进程。`api-native-path-repair-deployment.json`记录源码/编译SHA与全部只读门禁：startup15/15、基础部署27/27、Admin37/37、监控54/54、Portal79/79。`api-repair-portal-strict-path-continuity.json`使用此次独占修复窗口的新基线，16/16通过：12个其他服务（包括Console/Portal）进程、镜像、环境摘要、网络及卷完全不变，API容器和配置不变，仅进程重启；当前监控generation/catalog/epoch及私有环境/采集材料字节保持不变。没有重新迁移、全局编译、服务重建、监控enrollment/rotation或测试引用捕获。上一份启动门禁保留为 `startup-before-native-path-repair.json`；此部署检查不替代仍需继续的真实业务验收。

为保持C1既有认证图完整，新增可选`deploy/compose/compose.portal-acceptance.yml`，提供专用真实Kong1.5.1/PG11验收C3；另一环境复用只读确认无key-auth/ACL的C2，不清理既有历史认证面。C3 Admin13.20仅允许BFF13.10、PG23.20独立卷且BFF不入存储，代理只发布127.0.0.1:10000，Admin未发布。实际单次部署只新增PG/bootstrap/Kong和必要API环境/网络重建；`isolated-c3-deployment.json`记录42/42新节点与21/21连续性及原M6全部门禁通过。现有12个非API进程、全部旧卷/网络/凭证和监控代次/epoch保持不变，私有M6引用不重捕获且inode/mtime/bytes不变。新增`.env.portal-acceptance`为0600独立文件，最终扫描私读。部署交接时未登记C3；随后由Security在独占窗口通过BFF登记并运行真实业务验收。详细拓扑、允许/保护列表及受控序列见`M6-isolated-acceptance-plan.md`。

新注册集群的 `transport_scope` 为NULL时，凭证申请编译器随后暴露了SQL类型推导问题。修复使用既有可信Admin地址的规范传输范围回退，保留完整认证图校验；源门禁为28项所有者测试、25项独立测试和14项隔离真实PG测试。`nullable-portal-api-repair-deployment.json`记录单次API workspace编译与原容器进程重启；没有迁移、环境/网络重建、其他服务重启或秘密重捕获。`nullable-portal-repair-continuity.json`23/23通过：原12个非API服务加C3的Kong、PG及已退出bootstrap容器全部不变，API仅进程启动时间改变，新增环境文件与私有M6引用的inode/mode/mtime/bytes完全保留。最终只读门禁仍为startup15/15、基础27/27、Admin37/37、监控54/54、Portal79/79；上一份startup保留为`startup-before-nullable-portal-repair.json`。这些部署门禁不替代后续业务HTTP、浏览器与人工验收。

后续不可变凭证激活及元数据恢复修复通过Root源码门禁后，使用独立标签`portal-immutable-key-metadata`单次编译API与Console Web，只重启原API进程。Console通过既有只读dist绑定更新静态文件，Portal与其他服务不重启。`portal-immutable-key-metadata-deployment.json`记录七步exit0及startup15/15、基础27/27、Admin37/37、监控54/54、Portal79/79、只读Swagger8/8、连续性23/23；21份冻结源SHA完全匹配，六份之前门禁复制件保持字节完整，旧nullable证据不改。当前私有引用/新环境、原12个非API服务与C3三个容器、监控设置/代次/epoch均完全保留。Swagger仅GET公开文档证明必填原执行键/WID/IssueMetadataRecovery及Console身份，没有执行恢复。详情见`M6-metadata-repair-deployment-plan.md`；业务continuation与浏览器仍需安全方独占验收。

首份凭证元数据实际恢复成功后，同一应用申请第二个API暴露Consumer.custom_id唯一性冲突。修复为新的独立grant UUID并正式增加无原生结果的失败申请关闭回执；旧000–008不改，追加009。`portal-failed-issue-abandonment-deployment.json`记录唯一八步最小部署全exit0：正式`run --rm --no-deps console-migrations`只添加009并恢复新表SELECT/INSERT-only授权，随后仅重启原API进程、更新Console静态dist。startup15/15、基础27/27、Admin37/37、监控54/54、Portal79/79、新旧Swagger16/16、扩展连续性33/33通过。原12个非API服务、C3三容器及原退出migrator、当前私有引用/环境/监控材料保留；首份active generation1/native3/refs2和第二份failed Consumer1/后三步pending/refs0完整行与密文摘要不变，新关闭证书表仍为空。278源SHA和139编译/3静态SHA见独立proof。详情见`M6-failed-issue-deployment-plan.md`；实际业务关闭、新申请与完整浏览器验收由Security随后独占完成，部署器未调用业务接口。

## 已完成的离线检查

- `portal-compose-verification.json`：45/45，生产默认与双集群监控开发配置、门户双网络精确成员/两接口保护/localhost发布、独立秘密、反向代理、CSP/日志/tmpfs、M6流水线无监控初始化命令。先前internal-only离线配置证据保留另名，该静态检查曾遗漏实际Docker端口发布差异。
- `portal-nginx-isolated-verification.json`：已缓存Nginx镜像，network none、UID101、readOnly/capdrop/NNP/tmpfs下实际 `nginx -t` 通过；未连接或重启已有服务。
- `environment-secret-collection.json`：13/13，包括新增PORTAL_SECRET及LDAP/OIDC秘密/Basic编码扫描覆盖。
- `stage-dry-run.json`：源码计划，未执行迁移、密钥捕获或部署。
- `deployment-helper-review-unit.json`：独立40/40，覆盖环境文件权限与生产TLS、无覆盖捕获、固定tmpfs路径、四用途family/generation校验，以及M6流水线保持监控进程与具名卷。
- `capture-transfer-independent-unit.json`：独立79/79（39项实际本机 Node 子进程传输检查加此前40项），覆盖完整 ACK 绑定、密文篡改、文件/目录权限与属主、硬链接/符号链接/过大文件、FIFO 非阻塞拒绝、失败清理与无覆盖引用；没有连接实际运行容器或处理真实令牌。
- `api-repair-continuity-unit.json`：15/15，使用合成事实验证API仅允许进程重启、门户/Console重启及API配置/网络/镜像变化均拒绝，私有环境仅输出摘要，材料/代次/epoch变化和非法参数拒绝；导入测试不执行Docker或数据库请求。
- `nullable-portal-repair-continuity-unit.json`：54/54，新增C3退出bootstrap的完整状态与进程/镜像/环境/网络/卷保留、两份私有文件严格regular/0600/属主/单硬链接/大小读取及exact元数据摘要验证；拒绝symlink、FIFO、其他服务变化与API重建，测试仅使用本地合成材料。

门户文档解析的最终源码证据在 `portal-document-review-final.json`，54/54通过（41项聚焦及13项独立安全用例）：语义保留密码/key描述、required和公开布尔字段，移除秘密默认/示例；敏感父对象及内部引用的私有语义传递到嵌套字段与引用目标。回调/webhooks均纳入操作预算，循环与过深引用受有界遍历保护。拒绝外部引用、YAML aliases/custom tags、归一化后的HTML/userinfo/危险URI、prototype和超预算文档。Markdown拒绝远程图片和危险URI，允许正常文档链接及自站图片。该解析检查不进行远程抓取。
