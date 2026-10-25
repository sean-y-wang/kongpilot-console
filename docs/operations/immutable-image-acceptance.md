# KongPilot 不可变镜像构建与验收

这条流水线验证 Linux amd64 的 API、管理控制台、开发者门户镜像。它不发布镜像、不连接生产环境、不部署、不调用 Kong。ARM64 尚未执行实际构建与验收，不能据此声明支持。

## 执行入口

仓库的 `KongPilot source quality` 工作流在 pull request、向 `master`/`main` 推送、人工触发时运行。`immutable-images-amd64` 只在同一次运行的 `source-quality` 全部通过后启动，使用全新的 GitHub 托管 Ubuntu 24.04 runner 和仓库 `.node-version` 固定的 Node.js 22.23.3。

私有仓库中尚未合入默认分支的工作流不一定显示在 Actions 人工触发列表。维护者应先建立包含工作流的 PR，并确认实际产生了这两个检查；仅提交文件不代表 GitHub 已执行。流水线拒绝本机、自托管 runner、非 Linux amd64、Node 版本不匹配，防止在当前验收虚拟机上意外消耗 Docker 空间或选择已有资源。

执行顺序：

1. 无 Docker 的边界、OCI 完整性和 HTTP 时间预算测试。
2. 校验当前 HEAD 等于 GitHub 运行的 SHA，保存原始 lockfile SHA；所有构建使用这次 checkout。
3. 下载固定官方 Buildx 发行文件，校验 SHA-256，安装到专属临时 Docker 配置目录，不继承登录凭证。
4. 用固定 digest 的 BuildKit 新建专属构建器；关闭默认不安全 entitlement，限制构建并行数。
5. 分别构建三端的最终镜像，记录真实 Docker image ID；用同一固定输入导出包含最小 provenance 与 SPDX SBOM 的 OCI 布局。
6. 校验 OCI 索引、manifest、config、每层、每份 statement 的 size 与 SHA；OCI config 必须等于实际待运行的 image ID，statement subject 必须绑定该镜像 manifest。缺失或不完整证明直接失败。
7. 在实际最终 API 镜像中执行 Node 22、PCRE 原生 ABI、二进制与许可证 SHA、无特权与只读验证。
8. 使用固定官方 Grype 扫描三个最终 OCI 镜像和实际 PCRE 原生组件；先运行只含元数据的 PCRE 8.38/CVE-2016-3191 控制项，确认 CPE 查询通道实际工作。
9. 在全新 internal 网络和临时数据库中执行产品迁移、引导和运行角色配权，再启动三端并验收边界。
10. 检查 lockfile 与已跟踪源码没有变化，清理本次实际捕获并复核身份的资源；清理失败也判失败。

每个应用使用 `--read-only`、非 root UID、`--cap-drop ALL`、`no-new-privileges`，并限制内存、进程数、CPU；仅 `/tmp` 为带 `noexec,nosuid,nodev` 的 tmpfs。应用不绑定主机目录、不发布端口，测试只向此次 inspect 捕获的私有容器 IP 发请求。PostgreSQL、Redis 是该次 CI 的独立临时依赖，不属于生产资源。

数据库密码、Redis 密码、应用加密密钥和引导账号密码在 runner 内随机生成，只写入权限 0600 的专用临时文件。迁移进程使用 owner，API 使用实际迁移器创建的 NOSUPERUSER/NOINHERIT 运行角色；验收额外读取角色 catalog，确认无角色成员关系、无 public 表所有权、无 schema CREATE。API 设置 `SKIP_MIGRATIONS=true`；不登记默认 Kong 集群，后台调度与外部投递开关关闭。

## 固定依赖与原生组件

`deploy/images/toolchain.json` 是人工复核的固定清单。三个 Dockerfile 的 builder、Dockerfile frontend、最终运行镜像都必须与清单对应。构建阶段使用包含编译工具的固定 Node 22.23.3 bookworm 镜像，消除构建时 `apt-get` 漂移；Nginx 使用固定 digest，禁止通用 `apk upgrade`。依赖升级通过审阅新 digest 后重新完整构建与验收完成，不能在旧 digest 上静默升级包。唯一获批的例外是 `runtimePackageOverlays`：在官方 `nginx:stable-alpine` 尚未发布已含修复包的 digest 之前，web/portal Dockerfile 可用精确版本的 `apk add 'pkg=ver'` 覆盖单个已修复包（当前：Alpine v3.24 `brotli-libs=1.2.1-r0`，CVE-2026-111497，base 仍为 1.2.0-r1）。这不是风险接受清单条目；新 digest 合入后必须删除对应 overlay 与 Dockerfile `RUN`。

API 最终镜像继续使用固定 distroless Node 22 Debian 13 基底。PCRE 8.45 按固定上游源码和许可证 SHA 编译；PCRE 库静态链接到 helper，但 ELF 仍依赖 glibc，不能称为完全静态二进制。最终镜像必须实际执行原子分组、命名反向引用、未匹配、灾难回溯预算四个用例；在可写 Node 验收容器中的成功不能替代此验证。distroless 内真实 Node 若不等于 22.23.3，流水线直接失败，需更新正确的固定镜像，不能放宽检查。

BuildKit 的最终文件系统 SBOM 之外，脚本生成一个绑定实际 image ID、manifest、原生二进制/源码/许可证 SHA 的 SPDX 原生组件补充清单，避免静态 PCRE 因包管理器不可见而漏报。PCRE 8.45 已停止维护，固定版本与沙箱不能充当漏洞豁免；发布评审需持续检查适用漏洞、沙箱约束和替换计划。

## 证据与安全边界

工作流只使用 `contents: read`；checkout 不保留凭证。镜像任务不请求 secrets、不登录镜像仓库、不请求 OIDC 签名身份、不上传 artifact。Docker、npm、子进程使用白名单环境；不继承 GitHub、npm、数据库、代理认证或应用秘密。公共发行文件通过官方 HTTPS 和固定 SHA 校验，不关闭 TLS 验证。

子进程输出只保存在 runner 的私有临时目录，单流上限 4 MiB，超时终止本次进程组；HTTP 单请求有 2 秒绝对截止与 128 KiB 响应上限。标准输出仅包含阶段状态、时长、镜像/证明 SHA、数量和明确能力边界；不输出 inspect 原文、环境文件、连接串、依赖清单、密钥或原始日志。OCI/SBOM/provenance 原文不上传。原有 source-quality 仅上传其既有安全汇总，不改变其范围。

provenance 和 SBOM 经过 digest、subject、格式检查，**没有数字签名验证**。它们证明这次受控构建的输出关系，不证明任意仓库/任意构建者可信。构建工具及基础镜像 digest 当前通过官方匿名 registry/release 元数据核对；不能把元数据核对写成已完成的镜像构建。

检查失败时保留该次 GitHub 失败结论与安全 failureCode。脚本只删除本次捕获、标签/身份一致的容器、空网络和新建构建器，不使用全局 prune 或既有项目的 Compose down。runner 任务结束后临时实例销毁；本任务没有保存可供生产拉取的发行镜像。

## 必须通过的操作系统与原生组件漏洞扫描

工具固定为官方 Grype 0.120.1 Linux amd64 归档，SHA 与 Apache-2.0 许可证文本 SHA 位于固定清单。安装器只从固定官方 HTTPS 地址下载，先校验完整归档 SHA，受限内存解析 tar，仅选择二进制和许可证，不执行 archive 路径。没有在线安装脚本、自动升级或静默切换扫描器。

漏洞信息需要更新，不能把长期冻结的旧数据库当成安全证据。每次任务创建独立空缓存，从固定官方数据库源显式更新一次；检查实际 status 的有效状态、schema 6、构建时间不超过 72 小时、不明显来自未来。使用实际 cache 中的常规文件 SHA 作为这次扫描输入身份；五项扫描前后 SHA 必须相同。扫描期间关闭自动数据库更新、应用升级检查、外部 package 查询；不读取 inherited GRYPE/SYFT/registry 凭证或项目忽略配置。

控制项是一份 PCRE 8.38 的 SPDX/CPE 元数据，**不安装、不执行旧版本 PCRE**。必须由实际 Grype 的 stock/CPE matcher 找到 CVE-2016-3191；空结果、其他 matcher、被抑制结果均不能证明查询通道工作。随后扫描 API、控制台、门户的真实 OCI 输出，报告必须绑定先前运行过的 image config ID。每次同一条 Grype 命令同时输出漏洞 JSON 和完整 CycloneDX catalog；已核对固定上游 presenter 使用完整 SBOM 生成该 catalog，不能用零条漏洞记录代替库存证明。必须有实际 libc6/musl 的 OS 包库存；API 还必须包含该次 checkout 声明的每个生产直接 npm 依赖及精确版本。空 catalog、版本漏项、其他工具或单独复制的漏洞报告不能通过。PCRE 8.45 另用固定 CPE 描述，绑定此前最终镜像实测得到的 archive、binary、helper Source 和 license SHA；同次 catalog 必须恰好包含此版本及该 CPE，控制项也必须有精确 8.38 库存。不能仅靠镜像包管理器发现它。

OS 支持策略固定接受 Debian 13 与 Alpine 3.24，引用已核验的官方发布支持页及内容 SHA，策略必须在 2027-01-01 前重新审阅。其他版本、未知版本、旧/EOL 版本或过期策略全部拒绝，即使漏洞数组为空也不能放行。这一证明范围是 OS distribution 的 main 支持状态，不表示每个随镜像提供的库都有上游维护；PCRE1 已停止维护的事实与其治理要求保留。

数据库缺失/过期/变动、报告或库存无法解析、镜像或数据库身份不符、OS/直接依赖库存不完整、OS 支持策略拒绝、CPE 控制项失败均使任务失败。没有 `--ignore-unfixed`、仅扫描高危、凭0条日志放行或默认 waiver。有效匹配、工具内置 suppressed 结果、库存 EOL 告警全部保留计数；未解决项为零才通过。发现问题后完整完成其他扫描，给出三端及 native 的清单与状态，然后阻断后续验收；无法扫描时不声称已完成。

原始报告只在私有临时目录保留。安全汇总包含报告/数据库/工具 SHA、severity 计数、规范化 advisory ID、package 名称与版本、是否已有修复、是否被工具抑制，不复制描述、URL、源码路径、环境或任意异常文本；超过固定安全输出预算直接失败。持久留存原始 SBOM、漏洞报告与处置记录需通过另行授权的安全存储/发布流程完成，本任务不会自动上传原始材料。

所有扫描结果都只是指定时间、指定数据库和工具范围的已知漏洞识别。native CPE 匹配存在通告覆盖和版本映射限制，控制项也不能证明未知漏洞不存在。需要持续升级、复扫和人工处置，不能用沙箱或固定版本替代风险处理。

## 商用发布仍需的门禁

两项 CI 检查通过后，能证明该 revision 的源码质量与本条镜像启动验收通过。以下项目有独立证据要求：

- 确认本条真实镜像扫描已经执行且所有发现有处置结论，保存完整漏洞清单；原有 npm audit 只覆盖生产 npm 依赖。工具或数据库尚未实际联调时不能以 Source 测试代替扫描。
- 在受保护、显式授权的发布任务中重新执行同一构建验收，并发布**该次已验收的同一份镜像**及证明，记录远端实际 manifest digest；不能重建一份未经验证的镜像替代。签名/身份验证在发布流程另行完成。
- 在持久生产部署中验证 TLS、网络隔离、密钥托管、备份与离机恢复、回滚、监控告警和容量；本 CI 的临时数据库不能替代生产恢复演练。
- 在固定生产镜像中补做真实 Kong 1.5.x、Prometheus、门户凭证业务与浏览器 E2E/工作流回归；本条启动测试不会接触 Kong，不能代表这些链路通过。
- ARM64 若需要交付，新增其固定原生构建与同等实测，不能复用 amd64 的验收结论。

安全汇总始终保留 `commercialAcceptance:false`、`signaturesVerified:false`、`imagesPushed:false`、`productionDeploymentExecuted:false`。`osVulnerabilityScanExecuted` 和 `nativeVulnerabilityScanExecuted` 仅在实际扫描的三镜像、native、CPE控制项全部完成后标记 true；这些值不能由 Source 模拟测试或普通启动成功替代。
