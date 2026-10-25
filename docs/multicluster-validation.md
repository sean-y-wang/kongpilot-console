# 双 Kong 1.5.1 真实验收环境

第二套真实 Kong 已在 M4 用于 RBAC/IDOR 验收准备，之后用于 M10 漂移和 Promote。补充文件 `deploy/compose.multicluster-test.yml` 的 `multicluster-test` profile 默认为关闭；基础生产 Compose 不会自动启动它。执行 `node deploy/scripts/verify-multicluster-plan.mjs M4` 可重现31项只读配置检查，包括管理网与存储网地址范围不重叠；临时随机凭证会自动移除。网络先行部署通过34项，M4统一应用/固定存储网络部署后通过37项真实检查，分别见 `artifacts/M4/admin-network-verification.json` 与 `artifacts/M4/admin-network-final-verification.json`；这些部署证据不宣称独立 M4 权限测试或 M10 已验收。

第二集群使用独立 PG11 容器、`kong_secondary` 数据库、账号与密码、数据卷和内网。控制台只经 `http://kong-secondary:8001` 使用 Admin API，禁止连接该数据库。Admin8001 不发布到主机，仅监听第二集群专用 Admin IPv4与loopback，且 ACL 只放行精确的 BFF 管理 IPv4，拒绝自身和 loopback来源；该 Admin 网络仅含第二 Kong 和 console-api，代理在 `127.0.0.1:9000` 访问。共享 `proxy-edge` 让两个 Kong 可以访问同一无凭证 echo 上游，便于验证真实代理行为。

在新的环境启用可选集群：

```sh
node deploy/scripts/generate-multicluster-env.mjs
docker compose --env-file .env --env-file .env.multicluster \
  -f docker-compose.yml -f deploy/compose.multicluster-test.yml \
  --profile multicluster-test config --quiet
docker compose --env-file .env --env-file .env.multicluster \
  -f docker-compose.yml -f deploy/compose.multicluster-test.yml \
  --profile multicluster-test up -d kong-secondary-db kong-secondary-migrations kong-secondary
docker compose --env-file .env --env-file .env.multicluster \
  -f docker-compose.yml -f deploy/compose.multicluster-test.yml \
  up -d console-api
```

使用开发编译绑定时，在上述 `-f` 参数中保留 `-f deploy/compose.development.yml`，避免撤掉已部署代码挂载。生成器不会覆盖已有凭证或输出秘密；`.env.multicluster` 被 git/image 忽略，权限0600。合并配置对 API allowlist 添加 `kong-secondary`，并将两套独立 Kong 数据库的固定 IPv4 加入受保护管理目标。API 不连接这两套数据库网络，普通私有业务上游仍可用。

通过控制台注册该集群并选择所需环境；探测应显示真实 `1.5.1` 和34个已启用插件。本会话 M4 的真实连接是 `d1dfaec8-2a10-4170-8a15-20a600a4bd4f`，环境 `m4-secondary`；主连接是 `dff45535-ed8d-4851-b7a6-6376feac7f59`。M4 通过后仍须在 M10 完成以下真实检查并保存请求 ID、结果与截图，秘密不进入证据：

1. 相同实体名在两套集群分别创建，两边独立可见、修改互不影响；源和目标 `clusterId` 必须同时经过授权。
2. 创建相同工作区标签与同名 Service/Route，差异至少涵盖超时、Route paths、Plugin config、Target weight；漂移报告按名称与归一化引用比较，不能因跨环境 UUID/时间不同产生假漂移。
3. Promote 前显示 diff；默认排除凭证与环境相关字段，显式勾选后再验证需要的凭证变更。源和目标任何一个越权均返回403。
4. 在工单模式验证审批阻断、目标执行前快照、删除进入回收站、逐对象审计、失败停止与回滚。真实向8000/9000分别发代理请求，检查成功发布与回滚行为。
5. 验证两个 Kong DB、数据卷、Admin网络监听及主机端口。只清理带测试标签的对象；不使用 `down -v`，不删除主集群或控制台数据卷。

完成后停止第二集群可用 `docker compose ... stop kong-secondary kong-secondary-db`；保留独立数据卷供复测。本会话 M4 已执行 `node deploy/scripts/stage-deploy.mjs M4 --multicluster --transition-kong-storage`，在全部源码/单测就绪后将两套网关数据库迁移至互不重叠的固定网络，保持数据卷，再部署应用。新环境及后续阶段无需重复此切换，使用 `--multicluster` 即可；纯最终验证添加 `--verify-only`。私密扫描器同时读取两份私密环境的秘密值，并收集可选provider JSON内LDAP/OIDC秘密及OIDC Basic编码，不输出秘密。默认请求日志的脱敏策略与原生 error log 丢弃取舍见 the dual-cluster deployment notes in `docs/operations/` and this document。
