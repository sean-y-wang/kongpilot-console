# M8 decK 1.x BFF 适配器（YAML 格式 1.1）

当前证据包含源码测试、真实固定 CLI 对合成回环 Nest BFF 的协议验证，以及两代工具镜像的隔离校验。旧 1.1.0 镜像的合成 `validate` 实际退出0，但随后真实完整配置揭示工具 schema 的兼容问题。当前 1.2.4 镜像已通过完整合成图校验，真实集群 diff/sync 尚在接续验证；两代工具证据分别记录。

当前源码固定 decK 1.2.4 / 8e68931 / go-kong 0.13.0，YAML 仍为格式 1.1。二进制 SHA256 为 `642f49fd64e83aff867939705dbd927c5e750b241a99e8539ab22d18930427ed`，归档与来源见 `deploy/deck-runner/toolchain.json`。旧 1.1.0 工具无法接受 Kong 1.5 合法的 `healthchecks.passive.type`；原失败及独立离线诊断保留，不能删字段或凭证来通过校验。新镜像的完整合成图隔离验证已通过，实际 diff/sync 仍待接续。Runner 校验并通过已打开的文件描述符执行同一 inode，不在可写临时目录放置可执行文件；临时 config/state 为 0600，目录 0700，结束清除。父进程的 Viper `DECK_*` 地址、header、workspace、verbose、TLS 覆盖全部移除，analytics 强制关闭。

## 固定入口

| 路径 | 行为 |
| --- | --- |
| POST `/api/v1/clusters/:cid/configuration/deck-sessions?workspaceId=:wid` | 当前控制台账号/SID、既有 job，以及 read 或已确认 write-plan；首次返回 `tokenSecret`、ID、revision、过期时间 |
| DELETE 同路径 `/:id` | 当前权限 + 精确 revision + `confirmed:true,confirm_name:id`；撤销短期会话 |
| `/api/v1/deck/:id` | 专用 `Authorization: KongOS-Deck <token>`；不能使用 Console cookie/JWT/Basic 替代 |

协议只接受八类核心集合/UUID、Consumer 下六类凭证和 Upstream 下有效 Targets。全局 `/key-auths`、`/basic-auths`、`/jwts`、`/hmac-auths`、`/oauth2`、`/acls` 仅是 BFF 协议，逐 Consumer 页转换为受授权子集合，绝不扩展 Kong 的全局凭证白名单。每页最多100；go-kong 请求的1000被限制为100，续页使用加密、短期、绑定 actor/SID/CID/WID/物理集群/job/权限epoch/plan/path/size/tags 的 `offset`。空子页仍有可恢复游标，不能冒充全局已读完。

Root 提供实际 `CONFIGURATION_DECK_ACCESS`；Storage 提供实际 `CONFIGURATION_DECK_REPOSITORY`。适配器没有默认允许 provider 或通用反向代理。Root 重新验证真实用户/SID、当前权限、秘密子对象权限、物理范围、完整快照和已确认计划；并原子计费真正的底层读取及返回预算。每个响应发布前再次核验会话。只读会话无法写，写入只委托不可变计划中的唯一 ready packet；额外 packet、变更 body、scope、过期/撤权均拒绝。真正删除进入现有回收站，不转发裸 DELETE。

## Target 的固定工具兼容

decK 1.1 的 Target Update 发 `DELETE oldUUID` 后 `POST`（没有 ID）。工具收到真实新 UUID 时，其本地 ID-only Update 找不到旧记录；存在其他排队操作时可能停滞。合成 BFF 测试保留了这个失败及超时证据。

只有 Root 已密封的精确 Target 更新 pair 可使用协议逻辑身份投影：第一条 CLI DELETE 仅记录 pair 意图，第二条匹配的 POST 通过现有 Mutation 执行一次 append。给 CLI 的记录 ID 是原逻辑 UUID；实际新 effective UUID 独立记录在 parent job 映射。普通 BFF/UI/原生读回始终使用真实新 ID，不宣称复活了原 UUID。额外、未知或不匹配的 pair 不获得投影。真正的删除计划仍使用回收站。固定工具的 Basic 密码 diff 限制见 [兼容调查](../../reference/deck-1.5-compatibility.md)。

## Runner 与部署

`runDeck()` 接受固定 `validate|dump|diff|sync`，state YAML、专用会话 ID/秘密，经固定 BFF origin 调用；不接受 Admin URL、任意 flags、workspace、TLS skip 或 verbose 覆盖。diff/sync 固定 parallelism=1，但工具 dump 的并行读取仍受共享服务端预算。CLI 输出含潜在秘密，只保留受限 RAM Buffer，受信调用方加密保存后必须 `dispose()`；独立命令只输出安全退出码/字节数。CLI exit=0 不等同控制台 job 成功，必须分别查其原始回执。任何 timeout/非零 sync 表示可能部分执行，禁止自动换 key 重试。

可选 `deploy/compose/compose.gitops.yml` profile `gitops-runner` 只接 `frontend`，非 root、只读根文件系统、noexec tmpfs、cap_drop ALL、无 host 端口/宿主目录/Docker socket/Admin/storage 网络。M8 stage 增加 `--gitops-runner` 后构建固定镜像，再在 **network none** 下离线校验工具；不创建长期 token、不重登记/轮换监控、不重建 receiver。正式流水线 token 经 stdin/0600 config 注入，不放命令行/env/日志。完整部署 YAML 文件本身敏感，需按配置导出权限与流水线秘密留存策略管理。

源码测试：`tests/unit/m8-deck-adapter.test.ts`、`m8-deck-runner.test.ts`、`m8-deck-deployment.test.ts`。固定 CLI 验证包括格式1.1、六类凭证 dump、read-only diff、Service PUT、Target pair 投影及普通读回有效 ID；全部调用只到合成本地 BFF。报告：`artifacts/M8/deck-protocol-cli-unit.json`。

历史 1.1.0 镜像为 `sha256:2fa04b665d762cb17faf583ee085a616958e30694ea0cb2b982f0c900339fb6c`。其工具链和根所有权/权限证据见 `artifacts/M8/optional-runner-directory-fixed-gate-shape-corrected-verification.json`；22个核心容器完整保持。归档原0775、脚本原0600及新建目录0644造成的失败分别保留，修复只规范公开运行文件/目录权限，未放宽二进制FD、SHA或TLS校验。这不是新 1.2.4 镜像摘要。任一隔离 `validate` 通过均不表示真实BFF `diff/sync` 或控制台job成功。

当前 **1.2.4** 镜像为 `sha256:f9502473fd3c3fbd9f93535df86897fcaafe05c0a2d8e3def142b53a7b9df959`。实际固定工具和完整合成配置图已在 network none、UID1000、只读、cap_drop ALL、no-new-privileges、256m noexec tmpfs 下通过 `runDeck(validate)`，含非空 `passive.type` 和六类凭证。运行连续性 **35/35**，原 22 容器和 18 个健康服务保持，原工具镜像保留。证据 `artifacts/M8/deck124-fixed-runner-runtime-ready.json`，SHA `971658833a44e250a03b9cd9f996d254cdae812e348c1d40df94be743da7dc73`。第一次包装脚本未连接 stdin，在调用 CLI 前停止；原失败字节保留为 `deck124-fixed-runner-runtime-ready-pre-cli-wrapper-failure.json`，SHA `85c3f92c2946dde4ade2b887bbaa818e57592d8b8a1114805c52bfda03ebeb5f`。补齐包装参数后的单次独立验证没有重建镜像或重启 API，期间零业务、认证、Native、diff/sync 和生产构建。
