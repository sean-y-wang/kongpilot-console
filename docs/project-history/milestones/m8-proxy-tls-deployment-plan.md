# M8：Kong1.5 OAuth2 真实 TLS 入口

当前真实 OAuth2 token 请求返回 `HTTPS_REQUIRED`。基础 Compose 的 C1 proxy 只有 HTTP8000；新增真实 `8443 ssl` listener，保留 HTTP。生产基础配置不发布8443，测试覆盖文件仅发布 `127.0.0.1:8443:8443`。Admin8001不发布，精确 BFF IP ACL和安全日志策略保持。此处不添加可信 X-Forwarded-Proto，不关闭客户端 TLS 验证。

源码范围只有 `docker-compose.yml` 中 C1 的一行 `KONG_PROXY_LISTEN`、`deploy/compose/compose.proxy-tls-test.yml` 以及对应测试。C2/C3、Admin地址、数据库、网络定义和所有私有环境文件不改。现有 Security fixture Certificate/SNI由业务验收 owner使用；TLS客户端须用匹配的已知 CA并校验服务器名称，禁止 `--insecure`/`rejectUnauthorized:false`。

此文档只准备部署。实际操作须先收到 Root 对冻结 SHA 的明确 handoff；不能仅凭源码或 Compose 解析成功声明 OAuth2 可用。后续唯一窗口按以下最小顺序执行：

1. 新独立 wx 报告固定 source/Compose SHA，捕获当前22服务的安全 container/image/process/network/volume投影、SQL000–011 checksums和applied_at、12 metrics凭证 hash/generation、生产环境和私有材料 metadata/hash。不登录、不发业务/Native请求。
2. 用当前三 env和六既有 Compose覆盖文件，最后追加 TLS测试覆盖文件，`up -d --no-deps --no-build --force-recreate kong`，只重建 C1 Kong服务配置。不能运行 `down`、migration、重enroll/rotate或重建其他服务。
3. 等待 C1健康，读取生成的 Nginx安全 listener/ACL事实；真实TLS handshake校验证书，不记录PEM、token或请求内容。验证8001仍未hostpublish，BFF Admin读仍受原网络边界保护。
4. 捕获新 wx after并对账：其他21服务的 container/process/image/env/network/volumes必须不变；所有SQL/12凭证/generation/私有材料不变。C1新containerID、StartedAt及可能动态proxy-edgeIP变化逐项明确记录，固定Admin/storageIP、image和持久卷保持。初始和任何失败证据不能覆盖。

实际 controlled C1 recreate完成后的OAuth2恢复请求仍由唯一 Security业务owner执行。这个受控入口不改变既有fixture、账户、网关实体、配置快照或凭证材料。
