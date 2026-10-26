# Scripts

| Folder | Contents |
|---|---|
| [verification/](verification/README.md) | Release acceptance drivers: smoke, light concurrency, fault injection, PG backup/restore drill, per-feature flows, DR rehearsal |
| [release/](release/) | Release regression orchestration (`regression-single-pass.sh`, lab only) |

Build, CI, image and deploy-time helpers that Dockerfiles, compose files and CI invoke stay in [`deploy/scripts/`](../deploy/scripts/).

验证与发版脚本在此；被 Dockerfile、compose 和 CI 直接调用的部署脚本仍在 `deploy/scripts/`。
