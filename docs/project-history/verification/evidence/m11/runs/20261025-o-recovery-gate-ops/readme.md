# O-recovery-gate — ops evidence（非 UI 截图）
恢复闸由 `deploy/scripts/platform-recovery.mjs` 的 `recovery-fence.json`（state=isolated-storage-only，apiStarted/writesEnabled/workersEnabled/deliveryEnabled=false）实现，无 UI。2026-10-25 实测：
- `kp010dst-containers.txt` / `kp010dst-inspect.txt`：恢复目标 kp010dst 仅 PostgreSQL + Redis，处于隔离网络 `kp010dst_restore_storage`，无发布端口，无 API 容器（闸未打开）。
- `restore-gate-checks.json`：引自 20261024 恢复证据的 api_not_started / production_ready_false / sessions_revoked / redis_fresh_empty / kong_not_contacted 均 passed。
- `fence-source-excerpt.txt`：fence 写出源码行。
限制：同机第二环境，≠异地灾备。commercialClosed=false。
