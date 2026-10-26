# Kong 1.5.1 Admin 代理绕过防护计划

这是 M4 的只读设计记录。没有改变当前 Kong 监听、网络、ACL 或容器配置，也不代表此专项已完成验收。

## 已确认的攻击路径

只把 Admin 绑定管理网卡和 loopback，不能阻止同一 Kong worker 向这些地址发起上游连接。有实体写权限的用户可能创建 `Service.host=127.0.0.1, port=8001` 及公开 Route，或用 Target、HTTP 日志插件等把请求送入 Admin。连接从 Kong 容器本身发起，宿主机未发布 8001 并不足以阻断。

因此，BFF 的实体目标校验与 Admin 接收端 ACL 应同时执行。任意 Lua 执行能力（pre-function 等）必须单独授权，不能随工作区普通实体写权限授予。

## 真实 1.5.1 源码结论

检查对象为当前运行的官方 `kong:1.5.1`，内含 OpenResty 1.15.8.2；只读取镜像源码，没有创建攻击对象或变更运行配置。源码哈希记录在 `artifacts/planning/M4-admin-listener-source.json`。

| 检查点 | 1.5.1 真实行为与源码位置 |
| --- | --- |
| 原生 `admin_listen` | `kong/conf_loader.lua:660–709` 要求地址具有数字端口，并重建为 `ip:port`。`unix:/path` 没有数字端口，不能作为原生配置值。 |
| Admin 指令注入 | `conf_loader.lua:74–75,712–729` 支持通用 `nginx_admin_` 前缀；`templates/nginx_kong.lua:243–246` 仅在 Admin server 中渲染。因此 `KONG_NGINX_ADMIN_INCLUDE=/opt/kongos/admin-access.conf` 可用于有序 ACL 文件。 |
| 注入指令顺序 | 动态配置遍历使用 Lua `pairs`。应使用一个 `include` 文件明确排列 `allow` 再 `deny`，不依赖两个独立环境变量的渲染顺序。 |
| 转发头信任 | 原生 `real_ip_header`、`real_ip_recursive`、`set_real_ip_from` 在 Proxy server 内 (`nginx_kong.lua:114–118`)，Admin server 没有这些指令。管理 ACL 依据连接来源，不信任客户端 `X-Forwarded-For`。 |
| 容器健康检查 | `kong/cmd/health.lua` 读取 pid 文件并检查 Nginx 进程存活，不请求 loopback Admin。因此 loopback Admin 被 ACL 拒绝不会直接破坏现有 `kong health`。 |
| `/status` | 保留 Admin 上的 `/status` 经 BFF 请求。独立 `status_listen` 原生存在，但没必要新增公开监听。 |
| Prometheus | `kong/plugins/prometheus/api.lua` 确认插件在 Admin 注册 `GET /metrics`。M5 应经有权 BFF 内部通道采集；不为 Prometheus 放宽整套 Admin ACL。 |
| 自定义 Nginx 模板 | `kong prepare --nginx-conf` 原生支持，`/docker-entrypoint.sh` 的 `kong docker-start` 会把剩余参数传入 prepare。但 Unix-only Admin 需要修改实际模板；不等同于原生 `admin_listen` 支持 Unix。 |

## 首选部署方案

保留专用 Admin 网络并为每个 Console API 管理网卡分配稳定 IPv4 地址，Kong Admin server 用原生 include 加载：

```nginx
allow <该管理网络中的实际 BFF IPv4>;
deny all;
```

只允许 BFF 的精确地址，不允许整个管理网段或 `127.0.0.1`。Kong 自己连接 loopback 或自己的管理 IP 会返回 403；Proxy 的外部调用者无法改变 TCP 来源为 BFF。需要多个 BFF 实例时逐个列出其管理地址。多集群管理网络分别生成允许列表。固定 IP 避免 Kong 等待 Console API DNS、Console API 又等待 Kong 健康造成启动依赖循环。

Admin server 不启用基于转发头的 real-IP 改写；尤其不向全局 `nginx_http_` 注入信任来改变 Admin 连接身份。应用及 Kong 使用非特权运行账号，不授予网络管理、原始报文或 transparent proxy 能力。

现有能力探测、分页、变更、`/status` 和后续 Metrics Provider 仍由 BFF 发起，能够通过 ACL。迁移任务无需访问 Admin。真实 fixture 录制、部署检查与诊断应改用 API 容器的管理连接；原先 Kong 容器内直接 loopback curl 会被拒绝，这是需要同步修改的测试路径。

## 更强隔离选项及局限

| 选项 | 作用 | 实施条件与限制 |
| --- | --- | --- |
| Kong 网络命名空间 OUTPUT 防护 | 拒绝 Kong worker 发起的、指向管理端口或注册管理地址的 TCP 新连接，覆盖 loopback、DNS 重绑定和本机管理 IP。允许已建立连接的回包，保留 BFF 入站 Admin 请求的响应。 | 主机或专用初始化任务安装规则，Kong runtime 不持有 `CAP_NET_ADMIN`。同时覆盖 IPv4/IPv6和多集群自定义端口；不能仅依赖宿主机 DOCKER-USER 链或普通 Kubernetes egress policy，它们未必覆盖本命名空间 loopback。不能为了规则安装让 Kong 长期特权运行。 |
| Unix-only Admin + 独立私有管理代理 | 自定义 1.5.1 Nginx 模板只保留 Unix Admin socket，独立管理代理持有 socket 并用来源 ACL 或双向 TLS 接受 BFF；Kong 不再有任何 TCP Admin listener。 | 这是需要单独镜像/模板验证的方案。Service/Target 原生字段只接受主机/IP和端口，不能把普通路由直接设为该 socket；有任意 Lua 执行权限的 Kong worker仍可能访问 socket，因此 Lua 权限边界依旧必要。BFF 可继续使用管理代理的 HTTP URL，无需新增 Kong API。 |

首选 ACL 可以直接使用 1.5.1 已确认能力；OUTPUT 和 Unix 方案作为高要求生产部署的额外选项，不能把未经部署验证的选项宣称已实现。

## M4 必须提供的真实验收

1. BFF 对原有管理 API、启动探测、实体读写和 `/status` 正常；`kong health` 正常。
2. 从 Kong 自身访问 loopback 和本机管理 IP 的 Admin 均被拒绝；代理网中的上游容器仍不可访问 Admin。
3. BFF 拒绝指向全部已注册 Admin 地址/端口的 Service、Target 及可配置远程端点；覆盖 IPv4、IPv6、规范化地址和 DNS 重绑定。
4. 隔离测试集群预置 Admin 上游的公开 Route，向 Proxy 请求得到拒绝，Admin 没有执行变更；结束后按回收站路径清理测试实体。
5. 请求伪造 `X-Forwarded-For`、`X-Real-IP` 等头不能绕过 Admin ACL。
6. 多个 BFF 管理地址和双集群均验证；监控由 BFF 内部采集，不放开 Admin 端口。
7. 工作区普通管理员不能配置任意 Lua 插件；独立授权的管理员操作有审计和确认。
