# Lab harness (lab only) / 实验环境脚手架

Seeding helpers for `tests/e2e/m11-browser-matrix.mjs`: `setup.mjs`/`seed.mjs` create approver and read-only users plus fixtures and write `secrets.json` (path: `KP_LAB_SECRETS`, default `./secrets.json`, mode 0600, git-ignored). `mode.mjs approval|direct [clusterId]` switches the publish mode; `publish-*.mjs`, `fixture.mjs`, `s49.mjs` prepare specific cases. `kong-readonly-tap.js` + `out.js` expose a GET-only Kong Admin tap over a unix socket (`KONG_ADMIN_HOST`, `KP_LAB_KONG_SOCK`). Admin credentials come from the stack env (`BOOTSTRAP_ADMIN_*`); generated passwords are random. Uses RFC 5737 documentation IPs for upstreams.

为 `m11-browser-matrix.mjs` 准备数据的脚本，只用于实验环境。生成的 `secrets.json` 已加入 `.gitignore`，不要提交。
