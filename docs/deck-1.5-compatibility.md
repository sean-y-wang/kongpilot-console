# Kong 1.5 与 decK 1.x 兼容性调查

本页是 M8 的实现输入。当前只完成源码审阅与离线格式验证，尚未完成真实网关的 `diff/sync` 验收。

## 选择与获取

使用官方 **decK v1.1.0** 作为 Kong 1.5 文件格式和受控验收基线。它使用 go-kong v0.11.0，支持 `_format_version: "1.1"`、CA、保留 ID 的 SNI、Targets 与六种 OSS Consumer 凭证；不会像后续版本一样主动查询企业 mTLS 实体或新的插件 schema 路径。

Linux amd64 官方获取办法：

```sh
mkdir -p /tmp/kongos-deck-1.1.0
cd /tmp/kongos-deck-1.1.0
curl -fsSL https://github.com/Kong/deck/releases/download/v1.1.0/checksums.txt -o checksums.txt
curl -fsSL https://github.com/Kong/deck/releases/download/v1.1.0/deck_1.1.0_linux_amd64.tar.gz -o deck_1.1.0_linux_amd64.tar.gz
rg 'deck_1.1.0_linux_amd64.tar.gz$' checksums.txt > selected.sha256
sha256sum --check selected.sha256
tar -xzf deck_1.1.0_linux_amd64.tar.gz
export DECK_ANALYTICS=off
./deck version
```

已核对归档 SHA256：`11c028f6dfa2435322d71df1aa7b133e6f4a22091b0c7d3f88f610a5da491700`；二进制输出 `decK v1.1.0 (acdb161)`。使用继承的网络代理和可信 CA；不关闭 TLS 校验。此发行版没有 Linux arm64 资产，其他架构需要从固定源码构建并另行记录工具链与产物校验值。

## 文件结构

| 对象 | decK 1.1 文件位置 |
| --- | --- |
| Service | `services[]` |
| Route | `services[].routes[]` 或 `routes[]`，保持 Service 引用 |
| Plugin | `plugins[]`，也可嵌套于绑定对象 |
| Consumer | `consumers[]` |
| Key / Basic / JWT / OAuth2 / HMAC / ACL | Consumer 下的 `keyauth_credentials` / `basicauth_credentials` / `jwt_secrets` / `oauth2_credentials` / `hmacauth_credentials` / `acls` |
| Upstream / Target | `upstreams[]` / `upstreams[].targets[]` |
| Certificate / SNI | `certificates[]` / `certificates[].snis[]`，SNI 为包含原 ID、name、tags 的对象 |
| CA Certificate | `ca_certificates[]` |

Targets 和 SNIs 必须随父对象嵌套导出，才能同时满足完整性和 decK 兼容性。**增加顶层 `snis` 或 `targets` 会被 decK 1.1 schema 拒绝**。

已用不可用的合成凭证、证书字符串验证上述全部对象，`DECK_ANALYTICS=off deck validate --kong-addr http://127.0.0.1:9 -s ...` 成功；同一文件添加顶层 `snis`、`targets` 后按预期失败。`validate` 的源码明确不访问 Kong，这不能证明证书或凭证在真实网关可用。必须设置 `DECK_ANALYTICS=off`：原版 CLI 默认会向外部 HTTP 地址上报命令名与 CLI 版本，包括 validate；验收和自动化均关闭该行为。也不要启用 `--verbose 2`，它会打印原始 HTTP 请求/响应中的凭证。

## 实际接口限制

1. **原版 CLI 的全局凭证列表超出本项目白名单。** decK 1.1 的 dump/diff 会通过 go-kong 调用 `/key-auths`、`/basic-auths`、`/jwts`、`/hmac-auths`、`/oauth2`、`/acls`。项目只允许 Consumer 下的六类嵌套凭证端点，不能为 CLI 放宽 KongClient 白名单。真实 M8 验收需选择受控适配层，把 CLI 的全局凭证读取转换成 Consumer 和凭证的逐页嵌套读取；或者构建同一固定版本的最小审阅补丁。适配层不能把未知路径直接转发 Kong。
2. **恢复与执行仍必须经过控制台策略。** decK `sync` 的物理删除会绕过回收站、审计和工单。在严格模式下不应给外部 CLI 直连 Admin API 的权限；外部 GitOps 应使用控制台导出与变更执行入口，或使用带相同策略的受控执行适配器。端到端验收要检查执行前快照、删除归档、工单和逐对象审计。
3. **BasicAuth 密码差异无法靠原版 decK 保证。** decK 1.1 源码明确告警：不会检测 BasicAuth 密码变更。Kong Admin 返回密码哈希，不能把它当原文重新创建；控制台创建/轮换时保存加密原文，历史不可恢复原文必须阻止破坏性删除或要求显式轮换。验收必须向 Kong Proxy 使用原凭证真实请求，而不能只检查 YAML 和 ID。
4. **仅导出真实 1.5 schema 中存在的字段。** 本环境 Kong 1.5.1 的 Service schema 不含 `tls_verify`、`tls_verify_depth`、`ca_certificates`；不得把用户列出的候选字段强行填入导出。CA 实体仍可独立导出。root 响应没有 `endpoints` 字段，应使用探测后的固定 1.5 白名单，不能推测该字段存在。
5. **有效 Target 与历史不同。** Target 权重变更产生新历史记录，快照取有效集合；恢复语义是还原 target/weight，不保证每条历史 ID 重新成为有效记录。
6. **Kong OSS workspace 不是 decK 企业 workspace。** 不能生成 `_workspace` 或调用工作区端点；控制台工作区按保留标签软隔离，导出时保留实际编码标签与必要引用。
7. **凭证读取必须由 BFF 再施加作用域。** decK 1.1 的全局凭证 dump 不附加 tags；适配器必须只遍历调用者可读的 Consumer，并保留工作区、tag_group、entity 的实体校验，不能因为 CLI 无 tags 参数而扩大可见范围。

较新版本不能仅凭“decK 1.x”判断兼容：v1.7.0 的 dump 无条件尝试企业 mTLS 凭证列表（虽容忍 403/404，也违反项目路径约束）；v1.12.4 的插件默认值渲染使用 `GetFullSchema`，会查询本项目禁止的新 schema 路径。后续更高 1.x 版本还包含更多新版实体，不作为 Kong 1.5 的默认验收版本。

已确定 M8 使用 **BFF decK 1.1 兼容适配器**：全局凭证 read 在 BFF 转换为 Consumer 分页，写入委托 EntityService/RecycleService；`diff` 可使用只读 token，`sync` 需要先在 UI 确认具体 diff 并获得短期、绑定执行计划的许可 header，删除对象须二次确认。这样 CLI 的协议兼容不会绕过集群权限、回收站、审计或工单。该适配器留到 M8 编码和真实验收。

## M8 应完成的真实验收

以独立测试集群为目标，从已知配置导出，执行离线 validate；再通过受控适配器 diff/apply，检查 CA、SNI、Target、所有六类凭证均进入差异与逐对象结果。创建后的 KeyAuth、BasicAuth、JWT/OAuth/HMAC 需按协议真实验证；回滚必须验证原 KeyAuth/BasicAuth 仍可用，凭证列表与审计仍脱敏。源码与离线验证证据见 `artifacts/planning/deck-1.5-compatibility.json`。

参考：[decK v1.1.0 发行版](https://github.com/Kong/deck/releases/tag/v1.1.0)、[格式结构](https://github.com/Kong/deck/blob/v1.1.0/file/types.go)、[BasicAuth 警告](https://github.com/Kong/deck/blob/v1.1.0/diff/basicAuth.go)、[dump 凭证读取](https://github.com/Kong/deck/blob/v1.1.0/dump/dump.go)、[go-kong v0.11.0](https://github.com/Kong/go-kong/tree/v0.11.0)。
