# M7 通知投递部署

DeliveryPolicyService 已实现四个固定 provider。渠道保存只检查配置、operator authority、全部 DNS 地址和受保护目标；不在保存请求中连接 TLS、发送 HTTP、SMTP AUTH 或 DATA。外部 Slack、飞书、SMTP 账号当前未配置，本地验收不能证明外部账号已联调。

worker 使用 Core 的不可复制 claim，发送意图在 DNS/socket 前提交。每次准备发包都重读真实租约与两个创建人的当前权限、渠道/订阅 revision 和 credential generation。SMTP 强制 STARTTLS，证书验证后 AUTH 前和实际 DATA 正文前重新核验。HTTP 不跟随重定向，响应与 payload 均限制为8KiB。掉 ACK 保留 uncertain，同 delivery/key 自动重试，提供至少一次语义。

默认生产 Compose 开启内部 worker；没有有效渠道、订阅和当前授权时不会发包。operator 用 `EVENT_DELIVERY_ALLOWED_HOSTS` 登记精确 `host:port`。HTTPS CA、SMTP 密码与 CA 通过只读文件挂载；SMTP host、port、servername、sender 都是 operator 配置。tenant 只能提供固定 provider 配置或明确收件人，不能选择 SMTP authority、任意 headers/HTML/附件。策略同时保护注册 Admin/data sources、BFF 全部真实接口、存储和控制面的地址。

本地 `deploy/compose/compose.notifications-test.yml` 为合成 TLS 验收提供 internal `172.28.51.0/24` 网络：API `.10`，HTTPS receiver `.20:9087`，强制 STARTTLS receiver `.30:2465`。两个收件器仅接这一网络，无 host 端口、Admin、数据库、Redis、Portal 或 telemetry 接口；UID1000、rootfs 只读、cap_drop ALL、NNP、有限 tmpfs。新增三接口均列入 native sink 保护。

`prepare-event-receivers.mjs` 使用独立私有 CA 与精确 SAN。私有目录0700，receiver/API 文件0400、UID1000，合成 harness 材料0600，不复用 APP/Portal/metrics 凭证；输出只包含目录与安全状态。既有目录拒绝覆盖。收件器只记录 UUID、计数、时间与 body/key digest，不保存 Authorization、URL、JSON/MIME 正文或 SMTP 凭证。故障控制仅通过0600 Unix socket，不能通过产品网络调用。

正式部署需先完成所有 owner source gate，然后按唯一窗口执行：

1. `node tests/integration/m7-isolated-di.mjs --isolated`。编译至独立临时目录，使用自有随机 PG16/Redis7 容器，执行迁移和非 owner role provision，实际初始化 Nest DI 并验证 live/ready。只清理自己的容器和临时产物，零既有运行态访问。
2. `node deploy/scripts/verify-m7-runtime-continuity.mjs --before`。wx 保存 canonical 既有容器（含退出的 bootstrap/migrator）、volumes、000–009 checksum/applied_at、各 metrics generation 与私有材料元数据/hash；后台合法 catalog 进展单独列示。查询由实际非 owner 角色在 REPEATABLE READ READ ONLY 事务执行，只输出 SQL-side aggregate hash。
3. `node deploy/scripts/stage-deploy.mjs M7 --multicluster --observability --portal --portal-acceptance --notifications-test`。编译三 workspace，普通 migration job 只追加010，准备一次新合成材料并启动两个 receiver，然后只对 API 增加投递网络与固定配置。保留 C1/C2/C3 所有配置和 named volumes；无 metrics enrollment/rotation、Prom/Loki/collector 重启。
4. `node deploy/scripts/verify-m7-runtime-continuity.mjs --after`。确认原生网关、数据库、Redis、监控进程不变；API 只增加已批准的投递接口，Console/Portal 保留身份和材料，迁移仅追加010。startup、Admin、metrics、Portal、delivery-network/source 与此连续性门禁完成后，才交接唯一 Security 新 M7 fixture 窗口。不得复用已关闭的 M6 私有 reference 或业务恢复窗口。

首次材料准备失败或启动失败必须保存报告，不能无条件重跑整套生成脚本；`--verify-only` 不编译、迁移或生成材料。最终 M11 再独立构建生产镜像，不能以开发只读 bind mounts 代替生产镜像验收。

实际部署已完成，SQL010首次应用；startup15/15、后端边界27/27、Admin37/37、metrics54/54、Portal79/79、投递网络/源码30/30通过。两个receiver健康，实际provider发送另由独占Security窗口验证。

原连续性报告29/30通过，12条完整监控credential密文、三集群代次、旧服务进程/网络/存储、私有文件inode/mtime/bytes和000–009 checksum/applied_at均不变。唯一未通过项是包含观察字段last_verified_at的settings整体hash；before只有聚合hash，不能事后按稳定字段重建，所以部署前后settings配置本项保持“未证明”。原false报告保留。独立postdeployment-settings-stability-selector-corrected报告只证明部署后两次READ ONLY稳定配置与代次一致，不能替代缺失的部署前证据。

工具初次readonly程序解析错误及补验Docker短ID选择器错误均在任何DB读取前停止，原安全失败记录保留；修复后程序解析13项测试与补验通过，没有重复迁移、重启或生成材料。公开部署摘要为 artifacts/M7/deployment-ready-summary.json。

正式启动后补齐 Core 自动 outbox poller。真实隔离非owner PG21/21证明timer自动50+5分页、关闭续接及丢ACK后继续；生产修复只编译API并重启同一API容器进程，没有迁移、配置、材料或其他容器变化。独立 outbox-worker-repair-continuity 采用修复前就固定的稳定字段算法，32/32通过；API live/ready实际200、两个receiver健康。自动fanout完整业务仍由唯一Security新窗口验证，禁止手工SQL/claim代替闭环。原初始29/30报告保持不变。
