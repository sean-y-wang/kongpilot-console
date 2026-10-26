# M6 门户分类与管理详情窄修复

状态：Root 已授权源码实施；本计划不代表运行态验收。当前独占 Security 浏览器窗口继续使用已部署版本，本修复不构建、部署或调用当前数据库/API。

1. 仅修改 `portal-public.service.ts`、`portal-admin.service.ts`、`portal.controller.ts`，另增加聚焦单元/隔离数据库测试。000–009、Authorization、Workflow、原生能力与已部署资产不变。
2. 公开分类/搜索使用解密且 AEAD/HMAC 验证后的 publication proof。`portal_publications.category` 是草稿，revision `categories` 历史未填，metadata `safe_result` 不是权威索引，均不作分类预过滤。固定候选扫描预算，匹配填满 size 即停；签名游标只推进至最后实际检查候选。预算结束但未到 EOF 返回 `scanIncomplete` 和 `searchedRows`，客户端不能把这种空页描述为完整无匹配。无筛选保留单 SQL 有界分页。
3. 新增 Console GET 开发者详情、应用详情、应用 grants/requests 子列表与 `/portal/requests` 查询。开发者根对象只需当前 `developers.read` WholeWorkspace，应用根对象只需 `applications.read` WholeWorkspace。应用关系能力分别核验 WholeWorkspace `portal.read` / `workflows.read`，仅将明确 403 转为 false。
4. grants 子列表要求 `applications.read` + `portal.read` WholeWorkspace；requests 子列表要求 `applications.read` + `workflows.read` WholeWorkspace。独立 requests 查询只需 `workflows.read` WholeWorkspace，并限定三种 credential workflow kind。所有 SQL 精确 CID/WID/对象，历史 disabled/archived/已释放预留继续只读可见。不调用 native lookup、approved subject 活动状态门禁、计划解密或密钥仓库。
5. DTO 显式白名单，无密码/会话、cipher/HMAC、原生 Consumer/ACL/Key 标识或配置。关系独立绑定 actor/CID/WID/权限版本/应用/筛选/size 游标；查询后再核验当前授权与权限版本。请求历史按 immutable workflow subject → grant 关联，不跟随会被轮换/吊销改变的 grant.workflow_id。
6. 验证覆盖跨批次匹配与尾部不跳过、预算/字节边界、proof 篡改、游标错域、缺模块权限仅关闭关系、撤权异步竞态、历史 issue/rotate/revoke、DTO canary 及真实非 owner PostgreSQL 查询。源码冻结后由 Root 统一独立审阅与后续部署，旧运行态 source gate 不当作新版本发布证据。

## 实际接口

以下 Console GET 路径均以 `/api/v1/clusters/:clusterId/portal` 开头，必须显式提供 `workspaceId`；它与服务输入的 actor 工作区冲突时拒绝。所有关系分页允许 `size`、签名 `cursor`、可选 `state`，返回 `{items,size,total:null,nextCursor}`。

| 路径 | 必要当前 WholeWorkspace read | 返回字段 |
| --- | --- | --- |
| `developers/:id` | developers | `{entity}`：id、clusterId、workspaceId、username、email、displayName、status、revision、mustChangePassword、createdAt |
| `applications/:id` | applications | `{entity}`：id、clusterId、workspaceId、developerId、name、description、state、revision、createdAt、capabilities.readGrants/readRequests |
| `applications/:id/grants` | applications + portal | id、applicationId、publicationId、publicationName、state、generation、revision、reservationReleased、createdAt |
| `applications/:id/requests` | applications + workflows | id、clusterId、workspaceId、applicationId、grantId、publicationId、kind、state、revision、executionMode、approvalRequired、createdAt、expiresAt |
| `requests` | workflows | 同上，严格限定 issue/rotate/revoke 三种 credential workflow |

应用列表不传 `state` 表示所有历史状态，`archived` 对应数据库 `deleted`。详情与关系不会把历史状态当作必须 active 的执行前置条件。

公开 `/api/v1/portal/publications` 维持原 scope/size/search/category 输入；增加 `scanIncomplete`、`searchedRows`。有分类或搜索时每批最多 50 候选、最多 10 批 / 500 候选、每批 8 MiB / 整次 32 MiB ciphertext 元数据预算。无筛选只执行一条分页 SQL。候选数及字节 lookahead 不返回未处理 proof 内容，微秒时间戳与 UUID 共同作为最后已检查行的签名 cursor。

缺少早期 `publicationInfo` 的历史 proof 只保留不可变 revision 名称/说明与未知分类 null，不从后来草稿补分类。签名或密文无效直接拒绝。
