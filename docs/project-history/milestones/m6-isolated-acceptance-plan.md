# M6 独立真实 Kong 1.5.1 门户验收环境计划

状态：Root明确放行后已完成下述一次受控部署和全部只读门禁。C3尚未登记到控制台，业务验收窗口交回Root，等待其显式授权Security注册与执行。保留C1/C2全部既有实体及未归属的历史认证面，不为通过门户验收而禁用、删除或迁移这些对象。

## 当前事实

2026-10-10 22:40 UTC只读检查：现有14个服务均running/healthy；API、Admin、数据库、监控内部端口无宿主发布。Console8080、Portal8082、C1代理8000和C2代理9000均只绑定127.0.0.1。当前Kong镜像为已缓存`kong:1.5.1`，Kong数据库镜像为已缓存`postgres:11-alpine`，无需重拉或替换版本。磁盘可用6.7GiB，内存可用约15GiB，10000无监听。

已存在的显式子网为172.28.11/12（Admin）、21/22（KongDB）、31（遥测）、41/42（Portal）。拟用13与23均未与现有实际Docker子网重叠。已有frontend172.23/16和proxy-edge172.21/16与172.28.23/24不是同一地址空间。Security对C2做完9个工作区、19页的有界只读扫描：没有启用的key-auth/ACL，只有全局http-log/prometheus；Root决定只增加一个C3，另一测试环境复用C2。

## 最小拓扑

增加一个可选全新物理集群C3作为门户主验收环境，现有干净C2作为跨集群第二环境。保留C1/C2全部既有实体及认证配置；Security只创建有归属的新测试对象，不清理历史对象。本计划不会删除或重建任何既有非API容器。

新增文件拟为`deploy/compose/compose.portal-acceptance.yml`，必须排在现有metrics overlay之后，受显式`portal-acceptance`测试profile控制，生产默认Compose无变化。

| 项目 | 新验收C3 |
| --- | --- |
| Kong服务 / 镜像 | `kong-portal` / `kong:1.5.1` |
| Admin内部子网 | 172.28.13.0/24 |
| BFF精确Admin来源 | 172.28.13.10 |
| Kong Admin IPv4 | 172.28.13.20 |
| 仅Admin网的DNS别名 | `kong-portal-admin-endpoint` |
| 宿主代理入口 | 127.0.0.1:10000→8000 |
| PostgreSQL11服务 | `kong-portal-db` |
| 专用存储子网 | 172.28.23.0/24 |
| Kong存储IPv4 / PostgreSQL IPv4 | 172.28.23.10 / 172.28.23.20 |
| 新具名卷 | `kong_portal_db_data` |
| Native migration job | `kong-portal-migrations` |

新增Admin网与PG存储网均internal。Admin网仅BFF与新Kong；存储网仅新Kong、新PG以及完成后退出的bootstrap job。BFF不加入任何Kong存储网，Console/Portal/Prom/Loki/collector不加入新Admin或存储网。新Kong额外加入原proxy-edge以访问现有无状态echo-upstream，不重建该网络及其任何既有成员。

复用已验证`kong-secure-start.sh`，Admin仅监听固定管理IPv4以及受拒绝的127.0.0.1:8001；ACL严格`allow <该网BFF.10>; deny all;`，不允许子网或loopback，不信任XFF/X-Real-IP。Admin8001与PG5432无ports。Kong使用现有kong用户、cap_drop ALL、NNP、请求无关访问日志及/dev/null请求错误日志，`kong health`不依赖Admin循环请求。

## BFF配置与必要影响

新增Admin端点登记为`http://kong-portal-admin-endpoint:8001`，避免service多接口DNS语义。最终overlay保留现有`OUTBOUND_ALLOWED_HOSTS`并追加精确`kong-portal-admin-endpoint:8001`规则；不增加通配规则。

API只新增13.10网络接口，保留当前全部接口/IP与现有环境。最终overlay的`PROTECTED_DESTINATION_HOSTS`保留全部已保护目标，并额外包含新数据库主机及不可见literalIP23.20、新Admin13.20及端点别名、新BFF接口13.10，防止普通Service/Target/log-sink以固定IP绕过。不能用overlay替换掉既有Portal双接口和collector三个接口的保护。

由于API需要新增网络及允许主机环境，单纯restart不能生效，必须一次`up --no-deps --no-build --force-recreate console-api`；这也是本计划唯一允许重建的既有容器。可在同一次API编译/重建中装入已通过隔离PG测试的运行时查询修复。Console、Portal、C1/C2、全部PG/Redis/collector/Prom/Loki/echo均不restart/recreate；Nginx解析API同名地址的缓存通过实际health请求验证，若发现失效再由Root授权最小reload，不预先扩大变更。

新数据库秘密只写新的忽略文件`.env.portal-acceptance`，父目录由当前UID所有且无group/world写权限，0600文件、wx无覆盖，一套随机独立密码，不改变`.env`、`.env.multicluster`或任何metrics/Portal材料。启动参数加第三个env-file。数据库密码不进入API环境、argv或公开证据。最终安全扫描覆盖新文件秘密和既有私有测试引用。

## Migration与集群登记

新PG readiness→新Kong bootstrap job→新Kong PID health；只执行新的原生数据库bootstrap，不运行既有Kong migrations或Console migrator，Console数据库无新增DDL。

部署边界通过后，由Security独占窗口经现有有权限、CSRF和幂等记录的BFF集群注册API创建新登记并执行版本探测；不SQL直接写registry，不直接连接新KongDB。新URL解析到不同真实Admin IPv4，因此不触发别名重复登记。登记后默认工作区/角色通过现有控制台逻辑建立；验证GET `/`、`/status`、`/plugins/enabled`的版本与节点ID，不输出原始配置。

新测试集群不登记Prom/Loki、不enroll四用途密钥、不改变旧manifest/config/代次/epoch，不加入遥测。监控现有CID仍只为C1/C2；门户可在新CID执行完整认证图检查，无需放宽发布、审批或凭证约束。

## 授权后的唯一部署序列

1. Root冻结运行时查询修复与可选overlay、私有环境工具、专用只读边界验证；离线测试确认精确网络成员、版本、无Admin/DB发布、旧允许/保护环境保留及仅API重建。
2. 在部署窗口建立新的连续性基线：12个非API服务的container/process/image/env/networks/volumes；私有原环境与metrics材料字节；现有C1/C2数据库具名卷；当前监控family/settings/epoch摘要。已有真实业务验收已合法改变epochs，不能复用早期基线冒充本次窗口状态。
3. 单独API workspace编译；只生成新的private测试环境；只`up`新PG/bootstrap/Kong，明确服务名和profile，不使用全项目up/down，不触旧volumes。
4. 一次API环境/网络recreate装入源码修复；现有Portal/Console静态资产及配置完全不变。
5. C3/C2版本/节点独立性、精确来源ACL、self/loopback/伪造header403、PID健康、无Admin发布、独立PG网络/卷、BFF无新PG网、literal目标保护、代理入口及echo真实可达检查。
6. 现有M6只读启动/Admin37/metrics54/Portal79门禁与新集群专用门禁；现有12个进程及所有既有网络ID/IP/卷不变。API只允许本计划新增1个Admin接口及两项允许/保护环境扩展，原接口、其他环境/凭证摘要与镜像保持。`verify-portal-acceptance-continuity.mjs`同时核对既有私有reference的inode/mode/mtime/bytes；不重新捕获/轮换，安全测试进程自己的私有RAM也不重启。
7. 只将安全CID/端点/代理端口/证据路径交Root，由Root显式交Security唯一业务窗口。所有此前失败、capture与C1/C2配置保持；不承诺新的业务结果已经通过。

## 已执行的受控部署

`artifacts/M6/isolated-c3-deployment.json`记录唯一8步序列、实际source SHA和门禁：新C3部署42/42、此次连续性21/21、现有startup15/15、基础部署27/27、canonical Admin37/37、监控54/54、Portal79/79全部通过。新PG11单独卷/bootstrap完成，新Kong的8类实体集合最初均为空，与C2的原生node ID不同且版本均为1.5.1。Admin self/loopback/伪造来源均403；Portal采用同一nc正向对照后确认新Admin/PG literalIP TCP不可达。

仅单独编译API workspace、启动3个新服务（bootstrap正常退出）及一次API必要环境/网络重建。12个其他既有服务的container/process/image/environment/network/volume保持不变，API原其他环境/凭证/网络及镜像不变；既有metrics材料、generation/catalog/epoch和私有M6引用的inode/mode/mtime/bytes保持不变。原启动门禁保留`startup-before-isolated-c3-deployment.json`。未运行旧迁移、全局build、任何旧native对象变更、监控enrollment/rotation或凭证重新捕获。

新环境文件`.env.portal-acceptance`实际wx0600生成，不修改原`.env`或`.env.multicluster`；公开证据不含密码，最终扫描需要私读该新增文件。部署时只交接安全端点/代理入口；随后C3登记与门户真实业务验收由Security在Root明确授权的独占窗口通过BFF完成，本次部署门禁不替代该业务结果。
