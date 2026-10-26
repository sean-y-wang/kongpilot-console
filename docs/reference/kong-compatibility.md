# Kong compatibility

Single source of truth: `kongCapabilities(version)` in
`apps/console-api/src/infrastructure/kong/kong-capabilities.ts` (mirrored in
`packages/contracts/src/kong-capabilities.ts`). Unsupported features are hidden
in the UI and refused by the API; nothing else checks version strings.

| Line | Status | Reads | Writes | Portal credentials | deck credential import/export | Route simulator |
|---|---|---|---|---|---|---|
| 1.5.x | full | ✅ | ✅ | ✅ | ✅ | ✅ |
| 1.4.x | limited (有限支持) | ✅ | ✅ (1.5-only fields stripped) | ✅ | ✅ | hidden |
| 1.3.x | limited (有限支持) | ✅ | ✅ (`routes.path_handling`, `upstreams.host_header` stripped) | hidden — credentials have no tags before 1.4 | refused | hidden |

Console-only flows (IAM grants, workflow definitions, event/governance metadata)
no longer depend on the Kong version; they only require an enabled cluster and an
active workspace. Fixtures: `tests/fixtures/kong-1.3.0` (recorded from a disposable
`kong:1.3.0` DB-less container via `scripts/verification/kong-13-smoke.sh`).

Known gap: the console Credential manager and workspace migration do not yet
pre-block credential writes on 1.3; Kong rejects tag fields there.
