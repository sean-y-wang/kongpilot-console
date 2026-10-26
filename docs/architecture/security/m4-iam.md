# M4 身份与授权实现

`005_m4_iam.sql` 为用户、团队、角色、权限和绑定建立控制台侧模型。Kong OSS 不接收 IAM 请求。`iam_effective_grants` 的每一行保留完整的模块、操作、范围类型和范围值，并对权限、角色所属范围、绑定范围执行两两相交检查。不同权限行不能拼接出更大的权限。

全局内置角色为 `super-admin`、`admin`、`read-only`；每个工作区独立拥有三个工作区内置角色实例。只读角色默认没有 `secrets.read`，普通管理员也不自动读取凭证。工作区角色不能绑定其他工作区。超级管理员角色不能克隆或通过团队授予。它的直接绑定与受保护的 `users.super_admin` 标记在同一事务内修改，停用或撤销最后一个启用的超级管理员被拒绝。

权限定义 API 使用逻辑业务标签，例如 `team:pay`，存储时仅编码一次。禁止把工作区保留标签或已编码的标签当作业务授权输入。实体范围值为 `{entity_type,entity_id}`，必须带集群 ID；目标和六种凭证保留实际子实体类型。`secrets.read` 可授权准确的原生或凭证实体，注释权限可授权八种原生实体。全局权限定义的集群和工作区为空；通过角色绑定缩小全局权限的有效范围。工作区定义必须同时提供集群、工作区及唯一范围值 `[workspaceId]`。

权限定义读取需要 `roles.read` 和 `permissions.read`，编辑需要 `roles.write` 和 `permissions.write`。克隆配置过权限的角色同样需要权限编辑权限。任何授权、角色克隆、成员加入、恢复和重新启用都会重新检查授予者当前的完整权限上限。角色、用户、团队、成员和角色绑定均软删除或软撤销，并保留原 ID、版本和保留期；用户名、角色及团队编码在软删除后不复用。数据库触发器阻止物理删除 IAM 资源。

`iam_epoch` 在授权关系变化时立即递增。后端每次读取当前用户与有效授权，JWT 中的历史管理员标记不授予权限。IAM 游标绑定调用者、当前权限版本、筛选、父资源和分页大小，撤权会使旧游标失效。

身份元数据和集群登记变更使用独立的 `iam_operations` 持久化回执。所有写请求发送 `X-Idempotency-Key`。请求先加密保存并追加请求审计，随后在 SQL 事务内执行版本 CAS、原子业务审计和成功回执。未知提交结果标记 `uncertain`，客户端必须查询原回执，不应生成新键盲重试。`GET /api/v1/iam/operations/by-key/:key` 和 `/operations/:id` 只返回当前调用者的安全回执；只有 `succeeded/failed` 且 `remote_completed=true` 表示终态已被证明。账号密码重置由统一 AuthService 在同一 SQL 事务内处理策略、bcrypt、账号版本、会话撤销、审计及 IAM 成功回执；原键重放不会再次改密码。重置回执只保存密码的带密钥指纹，不保留新密码。

集群和数据源连通性测试的远程读取在 SQL 事务之前完成，检查结果及审计在事务内写入；原键重放不会再次探测。集群选择器只返回当前账号可访问的集群。普通账号的元数据不包含 Admin API 地址、认证配置标记或数据源地址。元数据读取在查询前后核验授权版本，期间撤权返回 `PERMISSIONS_CHANGED`。注册和修改 Admin API 地址需要当前全局 `clusters.write`；集群范围授权不能改写管理连接。连接必须满足允许列表，新的规范地址和可解析的 DNS 别名不能重复登记已存在的网关。已有历史别名保持可读。数据源属于集群共享配置，工作区权限不能越过该范围进行写操作。

复现数据库验收（使用临时 PostgreSQL，测试结束后移除，不访问运行中的控制台数据库）：

```sh
node tests/integration/iam-schema.mjs
npx tsx --tsconfig apps/console-api/tsconfig.json tests/integration/iam-service.ts
npx vitest run tests/unit/iam-policy.test.ts tests/unit/iam-mutations.test.ts tests/unit/kong-registry.test.ts
```

数据库验收同时执行 `006_m4_child_navigation.sql` 并验证子实体父关系的类型、集群外键和无凭证列约束。证据位于 `artifacts/M4/iam-postgres-constraints.json`、`iam-business-postgres.json` 和 `storage-unit-results.json`。真实 Kong、浏览器及外部认证验证由 M4 完整阶段验收单独记录。审批集群涉及的 IAM 配置写入在统一工作流接通前返回 `APPROVAL_REQUIRED`。
