# Contributing to KongPilot / 贡献指南

Thanks for your interest! 欢迎贡献。

## Workflow
1. Open an issue first for non-trivial changes (bug report or feature request templates).
2. Fork, create a branch, keep commits focused.
3. Run before opening a PR:
   ```bash
   npm ci && npm run typecheck && npm test && npm run build
   ```
4. Open a pull request using the template; describe behaviour change and tests.

## Ground rules
- Never commit secrets, `.env` files, real hostnames/IPs, tokens, or unredacted logs/screenshots.
- Do not break compatibility identifiers (`kongos_*` cookies, `KONGOS_*` env, DB schema) without a migration plan.
- Kong 1.5 behaviour must be backed by fixtures or tests (`tests/fixtures/kong-1.5.1/`).
- UI strings live in `apps/console-web/src/locales/`; English locale contributions welcome.

## 中文说明
提交前请运行上述命令确保类型检查、测试与构建通过；不得提交任何秘密、内网地址或未脱敏截图；兼容标识（`kongos_*`、`KONGOS_*`、数据库结构）变更需附迁移方案。

By contributing you agree your contributions are licensed under Apache-2.0.
