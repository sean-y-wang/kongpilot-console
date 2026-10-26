# M0–M8 独立生产验收执行计划

状态：**源码计划，尚未执行**。编写于 2026-10-11。M8 真实业务、审批、固定 decK 和浏览器闭环由原验收窗口继续；本计划只有在 M8 交付后、Root 另行释放生产执行窗口时运行。当前文档工作没有启动容器、读取部署秘密、构建、迁移、登录或发业务请求。

本次交付范围为 M0–M8。M9–M11 及原标准 9、10 明确 `deferred`，不以候选合同代替实现，也不要求此次提前编码。结果统一写入 [生产验收记录](../verification/milestones/m0-m8-production-verification.md)，操作说明见 [中文生产运维手册](../../manuals/production-operations-guide.md)。

## 1. 执行对象、资源与停止条件

验收对象是最终提交、锁文件、SQL000–011 和对应不可变镜像。当前开发项目的 22 个容器、数据卷、三集群、账户、TLS、12 个 metrics 凭证记录及秘密材料保持原样。新环境有独立 Compose project、数据库、卷、网段、私密材料、测试账户和代理对象，不能沿用当前业务 journal/原键或把旧生产状态改为测试模式。

| 条件 | 当前事实 / 待执行要求 |
| --- | --- |
| 本会话容量 | 最近已授权固定runner完成后的证据为944,197,632 bytes（约900.46 MiB）可用、Docker `vfs`；较早1,610,231,808 bytes已不是当前余量。RAM18 GB、约15 GB可用是较早观察，本SOURCE准备未复测 |
| 构建空间 | 当前API应用镜像约227 MB、dist约3.1 MB、lock未变；按共享cache逐镜像有界构建并测峰值，不并发复制全树。30 GiB宽裕空间/80–120 GiB SSD是建议，不是32 GB主机硬门槛 |
| 计算资源 | 独立验收主机建议 8 vCPU/16 GiB；记录真实机器规格，不把建议写成实测需求 |
| 工具 | Docker/Node/OpenSSL可用；Root已校验`/dev/shm/kongos-production-public-tools`内Trivy0.75.0/Syft1.54.1及Trivy DB。尚未扫描镜像；宿主无pg_dump，dump用匹配PG11/PG16镜像工具 |
| 生产源码 | 已提供UID101 Console Nginx、8443TLS、production/metrics/gitops overlays、collector image和参数化helpers；目前只做源码/离线核对，镜像实际验收仍pending |
| 运行隔离 | 新项目名、非重叠 IPAM、独立卷和 loopback 发布端口；不挂现役卷、Docker socket 或当前私密目录进应用容器 |
| 证据 | 每步 UTC 开始/结束、exit、源码/镜像 SHA、实际规模、失败安全码；结果 `passed/failed/not-tested/deferred/not-applicable` |

优先把镜像扫描archive、联合恢复副本和长时间日志放到独立存储，避免当前`vfs`额外完整复制。API与console-migrations使用同一镜像，只构建一次；冻结lock后保留可共享依赖层，按API→Web→Portal→collector→可选runner串行构建，每步记free space和实际增量/峰值/时长。不要把约227 MB image或3.1 MB dist当冷构建空间上限。只有实测/有界估算证明当前一步无法完成或破坏必要运行写入储备时停；不能因为未达到任意30 GiB直接判不可能，也不能猜峰值已通过。若另做multi-target共享依赖优化，仍保留`npm ci`/workspace闭包/CA secret/SQL/非root，不把未实施优化记为既有节省。

若只能用当前主机，后续授权窗口先获取只含 ID/日期/大小/refcount 的清单，逐个确认自有失败构建缓存 `Shared=false`、`Reclaimable=true`，以及镜像没有任何 running/stopped 容器引用、不属于现役/发布/回滚 digest。只按 Root 核准的精确 ID 回收；历史已授权/已删除 ID 不自动成为本轮候选。禁止 broad prune、删除数据卷、发布镜像、私有证据或固定 decK 资产。记录实际 reclaimed bytes 和容器/镜像/卷身份守恒，0 B 不能当已腾出空间。

任一步失败、未知写结果、未授权差异、迁移checksum不符或实际空间不足时保留报告并停。不能把failed改绿、重复未知请求或直接SQL修状态。源码单测、隔离PostgreSQL、镜像启动和真实协议分别计数；容量评估是每次有界执行的一部分，不另建与实际风险无关的审批链。

## 2. 冻结与构建前准备

M8收尾后记录最终Git commit、无未审产品变更、package-lock SHA、000–011 SQL SHA、所有Dockerfile/Compose/helper SHA、各阶段最终证据和未完成项。当前 API 为 222 份 compiled JS，新独立 17 步审批已通过；固定 decK 1.2.4 兼容修复仍在实际验收，不以历史编译清单冒充最终API。以下源码整改已经落地；最终freeze后实际核验，保留原源码报告与失败证据，不修改SQL000–011：

1. Console Dockerfile已固定UID101、custom nginx.conf的`/tmp` pid/cache；`compose.production.yml`设置RO/tmpfs/cap-drop/NNP及资源/日志限制，镜像实际非root待证明。
2. `compose.production-metrics.yml`用collector Dockerfile和`KONGOS_COLLECTOR_IMAGE`，`!override`移除应用源码bind，只保留专用材料RO挂载；实际源/镜像绑定待证明。
3. `enroll-metrics.mjs`/`prepare-metrics-storage.mjs`生产模式显式project/env/metrics-directory/output，四Compose顺序固定并委托production-policy；默认开发兼容，离线32/32已过，生产执行未跑。旧`rotate-metrics.mjs`不作为生产入口。
4. 已提供`console-production.conf`/`portal-production.conf`真正8443TLS与8080仅health；`compose.production-gitops.yml`固定真实TLS alias/publicCA，不能跳过证书验证或伪造XFP。直接使用仓库生产文件，按`production.env.example`补齐并冻结真实参数。

最终应用镜像不使用 development override、host dist/src/node_modules bind。允许的宿主只读挂载列白名单：受审配置、必要 Kong安全启动脚本、CA/TLS/密码与专用 metrics材料；数据仅独立 named volumes。镜像中的静态/编译 SHA 与冻结构建产物核对，不能把 bind 读取的源码当镜像证据。

源码检查在独立 checkout 执行，报告输出到新 `artifacts/Production/<run-id>/`，不覆盖历史：

```bash
set -eu
KOS_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$(node -e 'process.stdout.write(require("node:crypto").randomUUID())')"
test ! -e "artifacts/Production/$KOS_RUN_ID"
install -d -m 700 "artifacts/Production/$KOS_RUN_ID"
npm ci --strict-ssl=true
npm run typecheck
npm test -- --reporter=json --outputFile="artifacts/Production/$KOS_RUN_ID/source-unit.json"
npm run build
npm audit --omit=dev --package-lock-only --ignore-scripts --json
git diff --check
```

`KOS_RUN_ID`是本次唯一UTC/UUID，先创建目录并拒绝已有结果。这里的build仅核对源码；下一步仍须实际构建生产镜像。测试stderr/stdout对外只发布安全错误和计数，npm/tool网络失败记为未完成，不伪写零漏洞。运行中的Docker凭证、proxy/CA不发到证据。

## 3. 新私密环境与拓扑

在独立checkout用`umask 077`创建0700项目私密目录。生成器`wx`写新0600 `production.env`，明确HTTPS Portal Origin；对照仓库`deploy/production.env.example`合并项目/image/TLS/CA/HTTPS/网络非秘密参数，保留独立生成的每个secret，替换生成器测试allowlist/开发端口，补齐Console PUBLIC_ORIGINS。不得复制当前`.env`、bootstrap密码、APP/AES/Portal或metrics家庭，也不得直接使用模板占位值。

```bash
umask 077
install -d -m 700 deploy/private/kongos-production
node deploy/scripts/generate-env.mjs deploy/private/kongos-production/production.env --production --portal-origin https://portal.acceptance.example.com:19443
```

域名示例由实际企业DNS/证书替换；运行浏览器与 CLI 的机器必须信任专用 CA。设置 `COOKIE_SECURE=true`、`NODE_ENV=production`、Console 精确 HTTPS `PUBLIC_ORIGINS`、独立 `PORTAL_PUBLIC_ORIGINS`；不能用开发环境 HTTP origin 关闭生产验证。参数修改通过秘密管理工具，不 `source .env`，不将秘密放 shell argv 或打印 Compose完整配置。

验收拓扑示例（待查冲突后冻结，不是当前已创建网络）：

| 网络 | 示例 subnet / 固定节点 |
| --- | --- |
| 主 Kong Admin/存储 | 模板`172.30.11.0/24` BFF.10/Kong.20；`172.30.21.0/24` Kong.10/PG.20 |
| Portal edge/entry | 模板`172.30.41.0/24` API.10/Portal.20；`172.30.42.0/24`只有Portal.20 |
| telemetry | 模板`172.30.31.0/24` API.10/Prom.20/collector.30 |
| proxy/observability | 模板`172.30.51.0/24`、`172.30.52.0/24`；collector分别.30 |
| Console frontend/storage | 另选非重叠受审网络，不与现役 Docker 自动分配冲突 |

改网段时同步所有对应IP参数、由overlay组合的`COLLECTOR_SELF_IPS`、保护地址与allowlist，保持Admin精确BFFIP和独立存储隔离。模板发布KongHTTP18000、ConsoleTLS18443、PortalTLS19443，均loopback；Console/Portal容器内实际8443TLS、8080仅health。业务Kong8443由单独真实TLS入口按证书/SNI配置，不能借Console8443代替。Admin、PG、Redis、Prom、Loki、bridge、collector、runner无宿主端口。

本次最终生产镜像采用仓库单集群拓扑smoke，并核对已封存的双真实集群IDOR/同UUID与恢复边界证据，不重跑全部M0–M7 fixture。若实际发布目标是多集群，再对新增受管节点做针对性接入/隔离/逐库恢复；独立节点与资源清单需真实登记。不能把`compose.multicluster-test.yml`、C3、测试receiver或旧秘密整体加载成生产拓扑，也不能把两个指向同Admin的别名当两个物理节点。

本地 Docker 使用明确 socket，只去除冲突 Docker selectors，保留代理、CA和Docker认证：

```bash
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH
KOS_PROJECT=kongos-production
KOS_ENV=deploy/private/kongos-production/production.env
KOS_METRICS_DIR=deploy/private/kongos-production/metrics
dcprod() { docker --host=unix:///var/run/docker.sock compose -p "$KOS_PROJECT" --env-file "$KOS_ENV" -f docker-compose.yml -f deploy/compose/compose.production.yml "$@"; }
dcmetrics() { dcprod -f deploy/compose/compose.metrics.yml -f deploy/compose/compose.production-metrics.yml --profile observability "$@"; }
dcgitops() { dcmetrics -f deploy/compose/compose.gitops.yml -f deploy/compose/compose.production-gitops.yml --profile gitops-runner "$@"; }
dcprod config --quiet
```

这些文件都已在仓库，参数必须按`production.env.example`实际补齐并冻结；所有显式网络/卷名与文件内COMPOSE_PROJECT_NAME和命令project一致。把有效Compose JSON留RAM交`assertProductionComposition`验证（metrics用observability:true，runner再用gitops:true）；公开仅安全事实/hash/boolean、不输出Env，`runtimeVerified:false`不能代替下一阶段实际检查。

## 4. 最终镜像、工具扫描与冷启动

构建顺序API（migrator同镜像）→Console Web→Portal Web→collector→固定decK runner。沿同一冻结源码逐image构建、共享依赖cache并测空间峰值，保留回滚digest；不并发复制完整VFS层。企业代理使用BuildKit `proxy_ca` secret，包括Portal UID1000可读的0400 secret，保持strict-ssl；必要build-only CA配置单独冻结，不改变运行身份/秘密。`compose.gitops-managed.yml`只解决runner构建CA，`compose.production-gitops.yml`只挂运行publicCA，两者不能混同。

```bash
dcprod build console-api
dcprod build console-web
dcprod build portal-web
dcmetrics build telemetry-collector
dcgitops build console-deck-runner
```

生产overlay给每个构建设置明确发布tag并登记image ID。镜像推送后可换为对应registry digest，先验证最终Compose引用该digest与本次实际构建一致，再执行 `up --no-build`；不能换到未经实测的 `:local`。对API和migrator逐项核相同digest，不再单独构建migrator代码。dockerignore、镜像层、根目录与secretcanary检查由唯一scanner进行。

Root已从官方HTTPS下载并校验公开checksums、实际version exit0：Trivy **0.75.0**，binary SHA `93f9da8e4ba5e0c1c76d8234ed2494cf9afb0a96fd21953e424bb795f3299b8e`；Syft **1.54.1**，SHA `dbf75864e7a7ff9e1fbf00552c31483f693188632a9f68f343cd7653dac513d6`。工具位于`/dev/shm/kongos-production-public-tools/{trivy,syft}`，Trivy缓存同根`trivy-cache`，DB下载exit0、UpdatedAt `2026-10-11T13:06:05Z`、NextUpdate为2026-10-12约13:06 UTC（执行前按实际metadata复核）。tmpfs可用空间与RSS需记录，不能把RAM缓存当无限。当前只有工具/DB准备证据，没有镜像扫描结果；执行前重新确认DB时效，若该tmpfs已清空则按固定官方checksum重建，不能假设工具永久存在。

```bash
KOS_SCAN_TOOLS=/dev/shm/kongos-production-public-tools
: "${KOS_API_IMAGE_ID:?Set the sealed final API image ID}"
: "${KOS_RUN_ID:?Set a unique execution run ID}"
DOCKER_HOST=unix:///var/run/docker.sock "$KOS_SCAN_TOOLS/syft" scan "docker:$KOS_API_IMAGE_ID" -o cyclonedx-json > "artifacts/Production/$KOS_RUN_ID/api-sbom.json"
DOCKER_HOST=unix:///var/run/docker.sock "$KOS_SCAN_TOOLS/trivy" image --image-src docker --cache-dir "$KOS_SCAN_TOOLS/trivy-cache" --format json --output "artifacts/Production/$KOS_RUN_ID/api-vulnerabilities.json" "$KOS_API_IMAGE_ID"
```

每个应用、Kong1.5.1、PG11/16、Redis、Nginx、Prom、Loki、runner都针对准确最终image ID/digest扫描，可直接从本地daemon读取，无需当前磁盘上导出完整镜像tar；若另用archive则放独立scanner存储。示例`<final-image-id>`由实际sealed image manifest替换，不用未构建tag。daemon选择器只移除冲突项、保留代理/CA/DOCKER_CONFIG；Trivy daemon mode需按已固定版本确认显式本地socket设置。工具网络失败、DB过期或exit失败均是未完成。报告OS、Node传递依赖、CLI二进制、可利用条件和处置，不能以`npm audit=0`替代扫描，或预填Kong/PG11无风险。

分两阶段启动，避免监控材料缺失导致假失败：

```bash
dcgitops up -d --no-build kong-db kong-migrations kong console-db redis console-migrations console-api console-web portal-web
dcgitops ps -a
```

使用bounded readiness等待，记录running服务实际health；Kong与Console migration任务必须Exited0。从空新卷应用000–011，记录校验值/applied_at；runtime实际 `kongos_app` 非owner/nosuper/no成员/noCREATE，固定不可变表SELECT/INSERT、schema_migrations SELECT。API环境不存在owner/bootstrap密码，网络不连接KongDB；证据仅boolean/hash。

上例启用Vitals+GitOps，完整配置先让API拥有telemetry/9092和Console正确TLS hostname alias；显式只启动基础服务，不会因profile开关提前启动Prom/collector/runner。只做Vitals时用`dcmetrics`基础启动。所有TLS目录已提前放实际SAN匹配的链/私钥、UID101只读，runner公开CA文件UID1000可读。通过Console登记健康1.5集群/工作区和监控数据源，再用参数化helper创建独立四用途家庭、0400材料及准确新卷UID1000权限；output每次使用新路径，不能覆盖既有报告：

```bash
node deploy/scripts/enroll-metrics.mjs --production --project "$KOS_PROJECT" --env-file "$KOS_ENV" --metrics-directory "$KOS_METRICS_DIR" --output "artifacts/Production/$KOS_RUN_ID/metrics-enrollment.json" --discover
node deploy/scripts/prepare-metrics-storage.mjs --production --project "$KOS_PROJECT" --env-file "$KOS_ENV" --metrics-directory "$KOS_METRICS_DIR" --output "artifacts/Production/$KOS_RUN_ID/metrics-storage.json"
dcmetrics up -d --no-build prometheus loki telemetry-collector
```

helpers只解析安全project/volume/image事实，生产委托完整composition policy，不能print Env；生产不接收multicluster/test-private-reference，raw ingest不宿主落盘，不重用现役12个凭证。GitOps按base/production/metrics/production-metrics/gitops/production-gitops配置为受控stdin单次runner，frontend alias必须匹配Console证书SAN，`SSL_CERT_FILE`来自公开CA RO目录，无token/privatekey/env注入；真实CLI由唯一业务owner在该阶段运行，部署不常驻空任务。

真实操作每一步使用新的测试账号和原键journal，未知不重发。不用M5测试capture/旧token或生产部署命令冒充CLI业务调用。重启一次指定新环境服务，证明已应用SQL/数据/私密材料不被重生成；这不触当前22个服务。记录API/Portal/Console/collector/runner实际UID、RO/cap/NNP、写入目录、资源限制和sourcebind白名单；runtime权限按最终`provisionRuntimeRole`完整名单逐表核七项SELECT/INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER，不仅抽测数张表。任何缺项保持失败，最窄修复后独立续证。

## 5. HTTPS、安全与 M0–M8 功能出口

HTTPS必须实际握手并验证CA/hostname，不`curl -k`/TLS skip。以下矩阵由**最终生产镜像针对性smoke + 已封存M0–M8逐里程碑证据核对**组成，不机械重跑全部旧fixture；每项列明历史证据覆盖与本次新镜像执行范围，缺口真实补验。唯一业务测试owner持有新0600私有journal，密码/token/query/PEM和rawYAML不输出；BFF/API写带当前Cookie、CSRF和原key，成功请求ID/operationID逐条关联真实终态审计。

| 域 / 标准 | 具体执行与合格证据 |
| --- | --- |
| 一键启动与能力（1） | cold start、重复启动、version1.5.1/插件/旧schema实际探测、连接与监控通道分列；不调用企业/新版API |
| 八类实体/插件（2） | 核对历史八类CRUD/34插件覆盖矩阵；历史34插件生命周期是HTTP证明，浏览器只覆盖代表性复杂表单，须补齐八类实体与实际34插件的逐项UI生命周期/绑定清单。新镜像测试使用独立对象，外呼插件默认禁用并绑定无Route服务，必要全局实例也保持禁用；不向真实提供者发送测试消息。配置、nullable/秘密保留/records/Target均与BFF/实际Kong回显核对。任何未执行项保留not-tested，该标准不能提前标passed |
| 五类恢复图（3） | 新独立对象删除→回收→恢复原依赖/ID、冲突/partial/unknown控制；Service/Consumer/Certificate/Upstream/Plugin五类选定图的实际Proxy结果，Target只证明有效语义/新ID |
| 工作区软隔离（4） | 两工作区CRUD/list/cursor/annotations/recycle/snapshots/audit/events/Portal，不跨区；全局插件/共享namespace实际限制可见 |
| RBAC四维（5） | 核对四维/child/parent/read-only/write-only及两真实节点IDOR历史证明；新镜像当前权限/会话/scope拒绝smoke，新增多集群目标再针对性补测；await/DNS撤权不因生产overlay退化 |
| Vitals（6） | 固定同一UTC窗真实traffic与Prom原始counter/histogram、Loki已净化事件比对；QPS/错误率/p95/p99/双向bytes单位、Consumer近似TopN/缺失不补零，epoch/currentscope下钻 |
| Portal（7） | 真HTTPS独立Origin/Cookie/CSRF/tenant deep-link、公开文档/catalog、app申请→direct/approval→仅一次reveal→rotate/revoke真实Proxy；历史key/吊销不得通过配置恢复复活 |
| 快照/decK（8） | 非空至少两页capture完整对象/六凭证、格式1.1与CA/SNI/Targets；真实固定CLI validate/diff/sync→父job/精确packet/审批→回收与rollback，Basic原密码/六类Proxy认证；OAuth2新TLS token而非恢复旧session |
| 审计（11） | 新配置、approval、后台timer、metadata、清理结果逐requestId/operationId对账；before/after/diff脱敏、append-only权限/链与外部checkpoint；旧缺ID历史仍分列 |
| 越权（12） | 新snapshot/job/artifact/download/decksession/schedule/audit/notification/portal/worker IDOR、cursor绑定、秘密撤权/过期/错误purpose；拒绝请求零Native/ledger副作用 |
| 全源码/文档（13） | 最终适用unit/integration/typecheck/build及浏览器证据，实际范围、旧失败与修复清晰；手册命令和Swagger与实际部署核对 |
| 后续（9、10） | M9–M11治理/Lint/漂移/Promote与完整多级/定时工单本次deferred；M6–M8已交审批单独验收，不宣称覆盖全部标准10 |

网络攻击专项必须有同工具/同flags正向控制：Portal→API3000/自身8080正常，再检查**literal IP** KongAdmin8001、两独立PG5432、ConsoleDB/Redis、collector9093、API9092不可达或Admin明确403。不能把busybox参数失败/DNS失败当隔离通过。BFF Admin200、self-proxy/XFF/X-Real-IP spoof403、IPv6/wildcard监听不存在、Admin hostpublish不存在。Webhook/SMTP/managed collector例外只认固定私有目的地，普通Service/Target/plugin指向全部控制接口仍拒绝。

实际检查HTTPS安全头只有一个nosniff、CSP/Referrer/Permissions/Frame、Secure/HttpOnly/SameSite、no-store下载、CSRF/Origin/Host端口和OIDC回调安全query日志。Console不能代理Portal；Portal不能代理Console/Swagger/metrics/internal。任何callback/provider错误原文不得进Nginx/native日志。主API自身metrics/Swagger按受审生产ingress限制。

核对M7本地TLS/强制STARTTLS、55订阅fanout、intent/429/ACKlost/撤权/SMTP栅栏历史证据；新镜像做后台worker与已配置安全渠道的针对性smoke，无配置则诚实unavailable。若发现相关回归才用独立验收receiver补故障试验，测试overlay不能混入生产默认Compose。外部LDAP/OIDC/SMTP/Slack/飞书未配置则`not-tested`，本地协议不代替外部账号实测，不联系真实收件人。

## 6. 协调备份恢复演练

先在新验收环境制造可核验配置/RBAC/Portal/回收站/审计/通知/快照与六凭证，留安全ID/指纹/链头/真实Proxy预验证。给受管入口冻结写并暂停代理可能写库的OAuth流量，停止新环境API后台worker；备份Console、每个独立KongDB、稳定Redis和对应根密钥/部署材料，记录共同维护窗口，不宣称跨库事务一致。

```bash
umask 077
KOS_BACKUP="/secure-backups/kongos/$KOS_RUN_ID"
install -d -m 700 "$KOS_BACKUP"
dcprod stop console-api
dcprod exec -T console-db pg_dump -U kongos -d kongos -Fc > "$KOS_BACKUP/console.dump"
dcprod exec -T kong-db pg_dump -U kong -d kong -Fc > "$KOS_BACKUP/kong-primary.dump"
```

第二节点按其实际PG用户名/库逐库dump；PG globals含角色秘密单独加密，Redis AOF/卷使用停稳后的平台快照。dump在受控运维本机生成，BFF仍不获得KongDB访问。加密离机并记录安全尺寸/hash/exit；未成功dump不能继续伪造恢复。根AES/APP/Portal/TLS材料通过秘密系统备份，不进公开artifacts。

建第三个恢复project/新卷/新IPAM，固定原PGmajor和镜像digest，先恢复DB角色/库和private材料，再正式migrator验证checksum/运行权限，最后启动API/网关/Redis。恢复环境不得访问真实provider或旧Admin；先隔离发送队列，恢复后的unknown intent仍保留真实uncertain。恢复旧Redis后验证旧session不能重新获得写权，通过正式账号撤销流程让用户重登。

```bash
# dc_restore 已冻结为第三个独立项目，不是dcprod或原开发项目。
dc_restore exec -T console-db pg_restore -U kongos -d kongos --exit-on-error < "$KOS_BACKUP/console.dump"
dc_restore exec -T kong-db pg_restore -U kong -d kong --exit-on-error < "$KOS_BACKUP/kong-primary.dump"
```

验收必须从这些真实dump恢复，比较业务配置/关系/安全hash、AES解密、Portalactive/revoked生命周期、RBAC/账号、immutable证明/审计链/外部checkpoint、snapshot/回收站、metrics同generation，以及六凭证真实代理认证。OAuth只证明client新token，不声称旧session恢复；原未知投递不自动重发。记录恢复点、业务丢失边界、开始/完成/恢复流量UTC、**实际RPO/RTO**。仅dump文件存在或emptyDB启动不是通过。

还要测试备份缺AESkey失败、错误key解密失败并零写、角色最小权限保持、旧checksum不被改、应用版本不兼容时停止。恢复测试用新卷，结束按精确project资源清单软停/归档；不删除当前卷/证据。

## 7. 有界容量与故障测试

所有负载在新验收业务上游和独立路由运行，不调用当前集群。先确认对象规模/授权范围与预算：配置捕获/执行为100pages/10krecords/32MiB、300秒有限时间，租约最多305秒且受原身份及计划有效期截断；普通Native保持120秒。超限应明确不完整，不能以无上限吞吐承诺通过。

初始试验目标可定为20个操作员会话、后台采集开启、代理1,000req/s持续15min，另测BFF配置读取/受审写串行锁。它是**待测目标**，由实际资源与业务SLO调整，不是现已承诺的SLA。先小流量阶梯增加，记录成功率、p50/p95/p99、CPU/RSS/FD/网络、DB/Redis连接、磁盘增长、series数/outbox积压和collector丢失；入口20r/s burst40的429单列，不计成业务500。read与write性能分别报告。

故障仅控制新环境准确服务：单API进程重启、Redis/DB短断、Prom/Loki不可用、provider429/超时、磁盘预警或bounded测试目录满、DNS/lease/grant变化。记录熔断/锁/no blind retry、job/receipt/attempt持久恢复、敏感错误净化。不能在生产卷填满空间、改系统时钟、模拟直接写KongDB或把unknown当failed重播。

发布结论以实测SLO判断；建议的p95/吞吐只有制定并实际通过才登记。未达到目标先报告容量边界/配置限制，不通过降低断言把结果涂绿。

## 8. 证据封口与生产结论

公开证据最少包括：执行scope/commit、全部最终image digest、工具/DB版本时间、完整命令的去密模板、每步exit/时长、migration校验值与runtime权限、服务/network/sourcebind事实、TLS/headers/browser、功能13标准矩阵、业务审计对账、备份恢复/RPO/RTO、容量、SBOM/漏洞处置、已知限制和中文手册核对结果。rawdump/YAML/PEM/密码/token/cookie/SMTP内容/provider URL留私有受控存储，公开只安全计数/hash/UUID。

唯一scanner保留本次新0600私有canary参考直到所有浏览器/清理/日志收集完成，扫描源码与镜像编译资源、HTML/embeddedZIP、截图/公开报告及实际新服务日志；包括Base64/Basic等编码形态。失败报告原样保留；scanner最后删除临时参考并证实cleanup，备份库和生产秘密不能被这个测试清理动作删除。

原M0–M8证据标记为历史复用，新增真实prod结果独立发布，不能覆盖M8未知/失败，不能把生产部署成功当所有业务已验收。只有M8完整闭环和本计划适用项实际通过后作 **M0–M8范围** 生产就绪结论。EOL Kong1.5/PG11、tag软隔离、单节点架构、externalprovider未联调、根AES缺全库轮换工具等限制明确保留；没有商业安全认证或全M0–M11完成的表述。

执行完成后Root统一关闭验收窗口并给出部署/升级/回滚有效命令与实际资源值。当前计划仍 `not-tested`，不提供虚构通过数量、资源峰值、漏洞清零或RPO/RTO。

## 9. 最新有界执行准备（SOURCE，零实际生产操作）

`deploy/scripts/production-preparation.mjs`提供三个**纯函数**：`assessProductionBuildStep`核一步峰值/剩余空间，`assessOwnedBuildCache`筛精确候选，`productionPreparationPlan`生成argv数组与私有stdin/stdout路径。导入不读环境/文件、不连接Docker/数据库、不发请求；它不执行命令、不自动删除、不签发部署授权。离线负例检查共享cache、stopped容器引用、回滚引用、无峰值依据、跨项目/私密目录和恢复重enroll等边界。

现有944,197,632 bytes仅是上一runner阶段的实际结尾值，**第一个最终应用构建的空间仍unproven**。正式窗口开始后先记录当前free与所选Dockerfile/lock/基础image digest，再逐一步计算“构建峰值上界 + 尚需下载层 + 活跃库/日志写入储备”。上界只能来自同driver/同冻结构建的测量，或逐项保守分量清单；不能用Node基础镜像约227 MB、旧API应用镜像约293 MB或dist3.1 MB冒充。构建时有界采样free，结束记真实峰值与增量；缓存命中也要实测，源码变更会失效API的`COPY . .`及后续层。现有Dockerfile并未实现全应用共享npm multi-target，因此只复用真实命中的相同层，不能宣称所有依赖共用。

冷启动和第三恢复另算**容器rootfs/初始化数据库/TSDB/Loki增长**的峰值；`vfs`可复制完整层，不能把image已存在理解为新容器零占用。若第三完整运行项目不能与验收项目同时容纳，备份已加密到外部存储后，可精确停止本次独立验收项目、另用已准备恢复主机/存储；当前22容器和全部现役/回滚镜像不因此成为回收目标。生产和恢复实际完成前，空间/吞吐/RPO/RTO均不预填通过。

精确cache提案流程：唯一授权只读窗口取得builder缓存ID/日期/大小/Shared/Reclaimable与running+stopped容器、发布/回滚image清单；与本任务逐build日志核所有权和retired状态。纯筛选只返回审核候选和potential bytes，`actualReclaimedBytes=null`。Root确认确切ID后重新检查当前引用再用精确ID过滤；本机不支持时停，不退化为宽日期/unused过滤。删除后记录实际返回bytes和卷/image/container标识守恒；0 B仍是0 B。最初SOURCE窗口未读新清单；后续独立只读窗口已核对三项精确旧缓存的任务归属和当前引用，见RAM构建及缓存归属准备 (`artifacts/planning/production-ram-build-feasibility-and-cache-ownership.json`, not public)。候选为 `n0je14654pa2eevacajcm6g67`、`20ig7jleyreibghv8bpd877k8`、`itzwrasmm7bej7xgt9nfkt7a4`，仍只作提案，新增实际回收为零；先前精确回收结果为0 B，不能把potential bytes当作可用空间。RAM worker/独立daemon实际方案、最终镜像构建、load与新容器VFS峰值均待证明，不能先填容量通过。

可在SOURCE阶段生成公开的命令草案，所选路径全部为新项目参数，不含secret值：

```javascript
import {productionPreparationPlan} from './deploy/scripts/production-preparation.mjs';
const plan=productionPreparationPlan({
  project:'kongos-production-smoke', restoreProject:'kongos-production-restore',
  envFile:'/secure/kongos-production/production.env',
  restoreEnvFile:'/secure/kongos-restore/production.env',
  metricsDirectory:'/secure/kongos-production/metrics',
  restoreMetricsDirectory:'/secure/kongos-restore/metrics',
  backupDirectory:'/external-secure-backups/kongos/run-id',
  artifactDirectory:'/opt/kongpilot-console/artifacts/Production/run-id',
  publicCaFile:'/secure/public-trust/ca.crt',
  consoleOrigin:'https://console.acceptance.example.com:18443',
  portalOrigin:'https://portal.acceptance.example.com:19443', includeRunner:true,
});
// 仅保存source草案；每个preconditions都需真实证据后才按该阶段执行。
```

草案按固定生产文件生成：API一次构建并供migrator复用→Web→Portal→collector→可选runner；`--pull=false`避免暗中改变基础资产，缺少固定基础镜像时另行记录需要的受控下载和容量。当前已实测1.2.4 runner image若最终源码/固定资产/运行配置仍一致，可按准确image ID复用并实际扫描，不为改tag重复构建；不能把带dist bind的当前API/Web/Portal容器当最终镜像。所有下载保留受管proxy/CA，不TLS skip；云代理构建需要经审build-only CA overlay覆盖API、migrator、Web、Portal及runner，不能只给runner。

TLS准备仍使用独立专用CA或受管签发，两个SAN不同hostname、公开CA信任、真实8443 listener。`productionPreparationPlan`给出`openssl s_client -verify_return_error -verify_hostname ... -CAfile ...`命令，尚未执行。smoke由唯一验收owner对新项目检查两个`/healthz`、单nosniff/CSP/HSTS/Secure cookie、Console拒Portal/Portal拒Swagger/internal、API基础readiness、worker与真正metrics配置，然后核历史逐里程碑证据；不重跑全部旧业务fixture，也不采用忽略证书错误的浏览器。

协调dump顺序为新环境维护窗→stop新API/Kong/collector（停止OAuth和后台配置写）→PG16/PG11各自容器`pg_dump -Fc --no-owner --no-acl`→Redis SAVE/stop/私密复制。stdout必须接**新0600 wx私有文件**，CLI不能直发到公开报告；同时离机备份AES/APP/Portal/TLS、metrics目录与共同窗口。第三项目用新owner/app/Redis密码，但**还原原加密根key和同generation材料**，不执行enroll/rotate；新卷恢复dump后正式migrator校checksum并重新建立runtime最小权限，不能把角色ACL从dump直接继承当证明。

命令草案刻意停在第三项目DB/Redis/迁移核验，**不自动启动恢复API/网关/观测服务或开放入口**。当前observer/scheduler并没有一个通用“关闭全部后台”的环境开关；恢复启动前用受控网络/正式产品状态证明外部provider egress、旧session、未完成schedule/unknown投递已隔离，不造不存在的禁用参数或手动SQL改队列。通过后唯一业务owner验证真实AES/凭证/Portal/RBAC/审计checkpoint与安全解锁，再记录实际RPO/RTO。第三项目metrics目录可使用独立安全副本和原generation，helper不调用恢复enrollment。

Trivy/Syft及DB仍只有公开下载/版本准备证据。后续针对**最终准确image ID**实际执行SBOM/CVE，复核DBfresh时间，直接读daemon，报告失败与EOL处置；本节没有扫描、生产启动、dump、restore、清理或HTTP证据。

## 10. 独立 RAM daemon 执行分支（SOURCE，实际仍待释放）

为避免约900 MiB主盘上`vfs`的重复layer/rootfs复制，采用“现役daemon只创建一个任务工具容器→工具容器中独立RAM daemon→同daemon最终镜像/fresh/第三restore”分支，取代把全部最终镜像load回现役daemon。独立daemon不代表另起一套现役服务：它只承载本次新project，现役22容器、18健康服务、bootstrap、SQL000–011、12metrics族/代次、原Web/Portal/TLS和回滚runner保持。方案记录：独立RAM daemon SOURCE准备 (`artifacts/planning/production-private-ram-daemon-source-plan.json`, not public)；运维边界见[手册第15节](../../manuals/production-operations-guide.md)。

后续唯一实际窗口依次执行下列阶段，每项失败保留原结果并停止：

1. 封存最终SOURCE/image/tool清单；重核主盘、RAM、MemAvailable。证明唯一工具容器完整父rootfs分配量、公开报告/持久加密备份容量和主盘250 MiB储备，不把image.Size当上界；既有三cache只保留提案，未经确切授权不删。
2. 建立仅公开白名单文件的RAM构建context，同绝对路径映射；排除旧env/private/artifacts/fixture、symlink逃逸与HOME/npm/Docker认证配置。本次新prod/restore私密目录另挂，精确工具只读，工具容器只加入新build网络，无main socket/现役Admin/storage接口。
3. 在工具容器建立独立daemon/data/exec/containerd/socket，daemon `TMPDIR`、load解包、client配置与日志全部指向有界RAM而非父RW层；核Compose版本、socket权限、真实driver与网络边界。优先实测overlay2；fallback vfs重新计完整层/容器/卷峰值，容量无法证明即BLOCKED。原helpers在工具容器内执行，其固定`/var/run/docker.sock`只能指向这个新daemon。
4. 按准确ID逐个有界导出/load公开基础镜像；在私有daemon依次构建冻结API（migrator同image）、Web、Portal、collector，按条件准确复用runner。每阶段记录实际RAM/进程峰值、layer/image ID和退出码；不使用development dist bind、不把最终镜像load回主daemon。
5. 启动不同卷/网段/Origin的新fresh project，TLS固定TCP透传保持真实TLS/Host/XFP；仅绑定宿主localhost18443/19443，restore另用21443/22443。实际运行生产policy、UID/RO/caps/ACL、TLS/头、对应M0–M8 smoke与准确image SBOM/CVE；没有外部provider仍如实unavailable。
6. 新项目协调暂停写入和代理后导出PG/Redis/根key/metrics材料；认证加密备份离开RAM并实测可解密/hash。第三project用独立卷/env/端口和原冻结image恢复，不重enroll/rotate；先隔离旧session/定时任务/外部消息，再实测代理凭证、解密、权限/审计和RPO/RTO。
7. 完成秘密扫描、证据/镜像摘要与可恢复持久备份后，仅清理本次精确PID/容器/network/RAM路径；未批准不发布registry，不删现役镜像/卷。RAM实验结果只证明相应真实镜像/Compose/恢复步骤，持久化商业部署结论另需实际持久盘与运营参数。

当前拟RAM分区总7,012,876,288 B，来自5 GiB daemon数据、512 MiB单归档、512 MiB私有备份流、32 MiBcontext和512 MiB其他储备；不是实际峰值或保证。工具宿主临时特权、嵌套daemon、overlay2、固定TLS透传和该完整运行路径尚未执行；所有production build/start/scan/dump/restore结果保持not-tested。Node226,953,768 B逻辑Size与RAM可用量只作资源模型输入，严格保留“未知上界需实测”边界。
