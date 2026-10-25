# 审批死锁 Break-glass（单管理员 / 无第二审批人）

## 场景
集群处于 `approval` 执行模式，但平台只有 1 名可审批用户（超级管理员或拥有 `workflows:approve` 的用户）。
由于“申请人 ≠ 审批人”是不可绕过的规则，任何变更都无法被批准（`WORKFLOW_APPROVAL_CANDIDATES_UNSATISFIABLE`）。

## 预防（首选）
SQL046 新增受保护的内置全局角色 **`approver`**：所有控制台模块 `read` + `approve`，无 `write`/`delete`，无 `secrets`。
启用审批模式前，请在“角色绑定”中为第二名人员绑定 `approver`（或其它含 approve 的角色）。

## Break-glass（仅主机 / 数据库权限）
- **没有任何 HTTP/API 入口**；必须能在 API 容器内执行命令（即具备主机或 DB 级访问权限）。
- 不会把集群切到 direct，也不会批准任何工单；只把内置 `approver` 角色绑定给一名**已存在且 active** 的用户。
- 仅在**真实死锁**（可审批人数 < 2）时允许；否则返回 `BREAK_GLASS_NOT_DEADLOCKED`。
- 在 IAM epoch 行锁下事务执行；写入哈希链审计 `break_glass_grant_approver`（actor_type=system，记录 operator、reason、ticket、主机名、OS 用户、前后可审批人数）。审计写入失败则整体回滚。
- 参数仅经 stdin JSON（≤8 KiB），不接受 argv/环境变量。

```bash
# 查看状态
echo '{"action":"status"}' | docker compose exec -T console-api node dist/infrastructure/approval-break-glass.js
# 授予第二审批人
echo '{"action":"grant-approver","userId":"<uuid>","operator":"<值班人>","reason":"<≥20 字的原因>","ticket":"INC-1234"}' \
  | docker compose exec -T console-api node dist/infrastructure/approval-break-glass.js
```
错误码：`BREAK_GLASS_INVALID_COMMAND|INVALID_FIELDS|INVALID_USER|OPERATOR_REQUIRED|REASON_REQUIRED|TICKET_REQUIRED|NOT_DEADLOCKED|USER_NOT_ACTIVE|APPROVER_ROLE_MISSING|ALREADY_BOUND`。

## 事后
1. 在审计页筛选 `break_glass_grant_approver` 复核；2. 事件结束后如不再需要，通过正常 IAM 流程撤销绑定。
回滚 SQL046：`deploy/db-rollback/046_m11_builtin_approver_role.down.sql`（存在任一 approver 绑定时拒绝）。
