# Development

## Setup

Requires Node.js (version in [`.node-version`](../../.node-version)), npm, Docker.

```bash
npm ci
npm run dev:api      # NestJS BFF (needs PostgreSQL + Redis)
npm run dev:web      # console
npm run dev:portal   # developer portal
```

The route simulator uses a native PCRE1 helper built from source (`apps/console-api/native-bin/`, not committed).

## Repository layout

```
apps/console-api   NestJS BFF
apps/console-web   operator console (React)
apps/portal-web    developer portal (React)
packages/contracts shared types
deploy/            compose files, images, scripts, security waivers
tests/             unit, security, integration, e2e, image-ci
docs/              documentation
```

## Testing

```bash
npm run typecheck
npm test             # vitest: unit, security and integration suites
npm run build
npm run test:e2e     # Playwright specs in tests/e2e
```

CI (`.github/workflows/quality.yml`) runs `node deploy/scripts/ci-quality.mjs` in three shards.

The release browser matrix [`tests/e2e/m11-browser-matrix.mjs`](../../tests/e2e/m11-browser-matrix.mjs) runs against a real lab deployment and is opt-in: set `KP_LAB_E2E=true`, point `KP_LAB_SECRETS` at a mode-0600 JSON file outside the repo (keys listed at the top of the script) and `KP_E2E_OUT` at an output directory. The production-compose smoke, fault-injection and backup/restore harnesses used for release acceptance are not published; the backup/restore procedure itself is in [operations](../operations/console-postgres-backup-restore.md).

## Release process

1. All CI green on `main`; update [CHANGELOG.md](../../CHANGELOG.md).
2. Tag `vX.Y.Z[-rc.N]` on the release commit; images are scanned with pinned grype against [`deploy/security/image-vulnerability-acceptance.json`](../../deploy/security/image-vulnerability-acceptance.json) (waivers expire and must be re-reviewed; gates are never relaxed).
3. Run the regression suites on images built from the tag in one pass.
4. Publish a GitHub Release with notes from the changelog. Any fix after tagging requires a new tag.
