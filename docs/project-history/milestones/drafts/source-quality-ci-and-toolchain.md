# KongPilot 源码质量 CI 与固定测试工具链

新增工作流 `.github/workflows/quality.yml` 只验证源码质量，不发布、不部署、不改任何 Kong 或平台生产站点。只有实际 GitHub workflow run 成功后，才能称远程 CI 通过；本次 Source 审查和本地行为回归不能代替 GitHub 的真实运行记录。

## 执行范围

触发为 `pull_request`、主分支 main/master 的 push 和手工 `workflow_dispatch`，不使用 `pull_request_target`。GitHub 权限只有 `contents: read`；checkout 禁止持久保存认证信息，不接入任何生产、云账号、镜像仓库或通知凭据。三个 GitHub actions 都固定完整 commit SHA。runner 使用 Ubuntu 24.04，Node.js 固定为 `.node-version` 中的 **22.23.3**，依赖以仓库 `package-lock.json` 和 `npm ci` 安装。该 Node 版本与本项目已留存平台 SBOM 中的 Node22 版本一致；实际 setup-node 下载/运行仍需 GitHub 实验确认。

`deploy/scripts/ci-quality.mjs` 按固定顺序执行：

1. `npm ci --no-audit --no-fund`。
2. 无参数运行固定 decK 1.2.4 测试工具准备器。
3. 无参数运行 `node deploy/scripts/prepare-pcre1-ci.mjs`：固定 PCRE1 8.45 归档只下载一次，核对 SHA 后编译独立 worker，并以同一归档执行 15 项真实 native sandbox 安全测试；缺少、失败或 skipped 均阻断测试。
4. `npm test -- --maxWorkers=2 --reporter=json --outputFile=<private file>`；范围为现有 Vitest 的 `tests/unit/**/*.test.ts` 与 `tests/security/**/*.test.ts`。成功但含 skipped/todo 的结果不会通过该门禁。
5. API、Console Web、Portal Web 分别执行 typecheck。
6. 三个 workspace 分别执行 build。
7. `npm audit --omit=dev --json`，已知生产 npm 依赖漏洞总数必须为零。

npm install 失败时后续步骤标为 blocked；decK 或 PCRE1 构建/安全验证失败时测试标为 blocked，独立 type/build/audit 仍执行。每个已执行步骤保留真实退出码、超时/输出上限标识。`npm ci` 前后锁文件摘要须相同。一次完整门禁的执行次数、通过/失败/跳过计数只能按这一批次完整报告读取，不能与历史版本专项测试相加。

外部生产环境变量不会透传给子进程：使用临时私有 HOME、空 npm user/global 配置和显式最小环境。HTTP/数据库/Redis/SSO/通知/Portal token、GitHub token、npm auth token等都不转发。这里没有配置带秘密的 workflow environment，也没有 `secrets.*`。CLI 不接受追加命令、URL、工作区或任意 flags。

## 固定 decK 准备器

```sh
node deploy/scripts/prepare-test-toolchain.mjs
```

只支持 Linux x86_64，安装到现有真实工具测试使用的 `/tmp/kongos-deck124-cli/deck`，不能用环境变量或参数替换 URL/版本/命令。下载固定官方地址：

```text
https://github.com/Kong/deck/releases/download/v1.2.4/deck_1.2.4_linux_amd64.tar.gz
archive SHA-256: 6eef6dc36a8c251f10f0e3ffa40ec5289d42de131ad043f76ad45d2de390beae
binary  SHA-256: 642f49fd64e83aff867939705dbd927c5e750b241a99e8539ab22d18930427ed
```

准备器使用 Node HTTPS，明确启用 TLS 校验，不读取认证头、环境代理凭据、`.netrc` 或 npm 配置。最多跟随六轮官方 HTTPS release/assets 主机重定向；拒绝 userinfo、非 443 端口、其他主机、HTTP downgrade 和 fragments。临时签名 asset query 保留在内存中，出错不打印 URL 或底层网络错误。

下载上限 16 MiB、总时间 90 秒；解压上限 32 MiB。首先核对整个 archive SHA，再在内存解析 tar，只接受 root-level `CHANGELOG.md`、`LICENSE`、`README.md`、`deck` 四个普通文件。检查 header checksum、类型、路径、mode、大小、重复条目、padding/trailer；不会调用 tar/shell 创建归档路径。随后核对固定 binary SHA 和实际字节数 10,498,048，写入私有同目录 staging inode，经 `link` 原子发布并设置 `0555`。若同时出现了其他 binary，拒绝覆盖并保留原文件。

路径每个已有组件不得为 symlink；准备器保留打开的目录 FD，并在下载返回及发布前后核对路径/FD的原始 device+inode。创建、chmod、link 使用原目录描述符路径/文件 FD，下载等待期间叶目录被替换时拒绝，不能写入替代目录；目的目录须由当前用户拥有且不可被其他用户写入。已有文件只在普通文件、单 hardlink、当前 owner、模式 `0555/0755`、精确字节数及 SHA 全匹配时复用；不存在自动 `--force`、修复未知可执行文件或跟随符号链接的路径。复用时不会再次下载。所有工具摘要只含版本和公开摘要，不含环境秘密。

这是测试工具准备器。生产 decK runner 继续使用现有隔离协议及执行器，准备器不会连接真实 BFF、Admin API、Proxy、PostgreSQL 或 Redis。Go CLI 本体风险和生产启用能力仍需相应发布门禁评估，不能以「测试准备成功」代替生产验收。

## 固定 PCRE1 原生准备与安全门禁

PCRE1 归档版本为 8.45，官方 SourceForge 地址与 SHA 固定在 `prepare-pcre1-engine.mjs`；BSD-3-Clause 原文随构建工件保存。CI wrapper 无 CLI 参数、无任意 URL/命令覆盖；仅使用隔离 HOME/TMPDIR 内的私有归档和报告。一次下载经 SHA 验证后分别供真正的生产 builder 与原生安全测试使用，不读取外部数据库、Kong、代理、GitHub/npm凭据。

原生安全测试用现有 Linux gcc/Python3 编译测试探针，包含真实高fd4096继承及关闭、低 NOFILE 高fd、有界fallback、活文件 mmap 禁止、匿名内存允许、EXEC mmap/mprotect 与 open/socket/execve/ptrace 的真实 SIGSYS、PCRE atomic/灾难回溯限制。15项必须实际通过，不能以 Source 正则测试代替。该阶段不含可选历史旧版漏洞对照；显式执行历史对照时另有第16项。wrapper 对原生子进程使用独立 Linux 进程组、60秒期限和每流2MiB限额，超限杀本组；私有日志不上传。公开摘要只带固定版本、公开归档/二进制摘要和计数。

Docker 的 API build 阶段安装只用于构建的 gcc/libc头/CA，并从同一固定源码编译；runtime distroless 只带 helper、build manifest、BSD license，无编译器、源码归档或Shell。`.dockerignore` 和 `.gitignore` 排除本地 native-bin，防止宿主产物进入构建上下文。生产仍必须采用现有只读根文件系统配置，并真实验证最终 distroless Node22 中的 helper、seccomp、动态加载器/ABI 与镜像扫描。当前仅 Source 与宿主原生验证，不能宣称镜像或 ARM64 已通过。

## 报告与故障定位

每次 job 在独立临时目录保存权限 `0600` 的私有 raw stdout/stderr 与 Vitest JSON；每个子进程 stdout/stderr 分别限制 4 MiB，超限或超时即失败。Linux 上每一步使用专属 detached 进程组，向本步骤的已知进程组依次发送 TERM/KILL，并等待组终止处理，避免仅结束 npm 而遗留 Vitest 孙进程占用输出管道。私有原始文件不上传。

GitHub artifact 只保留 `$RUNNER_TEMP/kongpilot-quality-report/summary.json`，有效期七天。该报告由固定 schema 生成，只包含固定 stage ID、状态、退出码、数值计数、公开工具摘要以及实际范围标识，不包含 test title/assertion、栈、URL、环境变量、原始日志、build 产物、历史验收材料或私有环境文件。artifact 不代表已跑全量集成/e2e。

排查失败时先看摘要确定 install/toolchain/test/type/build/audit 的失败项，再在受控临时 runner 环境按相同 pin 和命令复现。不要为排障把生产凭据、私有环境文件或部署 dump 加入 CI；不要把完整 raw 测试/编译/扫描日志作为公开 artifact。

## 可复现的含义与更新策略

工作流固定 Node 小版本、actions commit、decK archive/binary digest、npm lock 和命令，能复现同一源码门禁的依赖选择与执行范围。Ubuntu runner image、registry 服务、上游可用性及基础镜像更新仍会变化；不声称构建产物 bit-for-bit 完全相同，也不宣称仅凭 npm audit 覆盖了 OS/容器漏洞。

更新 Node/actions/decK 时必须作为普通代码变更审查：核对可信上游、记录旧新 hash/版本、执行完整门禁，并更新相应文档和平台镜像/SBOM 的真实扫描。不要通过 mutable action tags、`latest`、TLS bypass 或任意下载 URL 绕过固定工具链。若 GitHub SHA/工具版本在远程不可用，job 应失败；本地静态配置检查不表示这些远程依赖已实际解析。

## 发布时仍必须真实执行的门禁

当前 CI 不自动启动 Docker、Kong1.5、PostgreSQL/Redis 或外部 IdP/通知供应商，也不运行 Playwright 全站 e2e、生产安装、灾备恢复或自然工作流排程。因此必须另行在最终冻结发布上完成并留存：

- bundled/external-Kong 平台安装、migrator/runtime 分离、HTTPS/Cookie/CSRF/网络隔离、冷启动/升级/回退。
- Kong1.5 实体/插件/六种凭证、workspace/RBAC/IDOR、Portal 发证/轮换/禁用/吊销及实际代理认证。
- 工作流多级/会签/current权限/窗口/双 worker/未知结果安全处置、Target append/回收图、Promote 与快照回滚。
- 平台单独备份→全新隔离恢复→应用密文/审计/session/credential/worker/单写者接管，离机存储与实际 RPO/RTO。
- 最终镜像 digest/SBOM/OS 与应用依赖扫描、代表容量与故障演练、完整秘密扫描及全部当前 UI 业务回归。
- 最终手册、版本发布清单、commit/push 和远程 SHA；真实 GitHub CI run 链接与结果。

这些门禁未通过前，源码质量 CI 的绿色状态也不能将 `commercialAcceptance` 改为 true。
