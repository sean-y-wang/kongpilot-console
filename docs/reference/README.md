# Reference

- **Configuration / environment variables:** [`.env.example`](../../.env.example) (demo) and [`deploy/production.env.example`](../../deploy/production.env.example) (production), generated with `node deploy/scripts/generate-env.mjs`. Details: [advanced configuration reference (zh-CN)](../manuals/advanced-configuration-reference.md). Notable switches: `ENTITY_SCHEDULES_ENABLED` (default `false`, [ADR 0003](../decisions/0003-entity-schedules-opt-in.md)), `KONG_NGINX_WORKER_PROCESSES` (default `2`, [ADR 0007](../decisions/0007-kong-worker-processes-default-2.md)).
- **API overview:** all endpoints are served by the BFF under `/api/`; request/response types are defined in [`packages/contracts`](../../packages/contracts). See the [technical operations reference (zh-CN)](../manuals/technical-operations-reference.md).
- [Kong 1.5 compatibility](kong-1.5-compatibility.md)
- [decK 1.x compatibility](deck-1.5-compatibility.md)
