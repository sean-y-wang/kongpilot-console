#!/usr/bin/env bash
# Kong OSS 1.3 limited-support smoke: start a throwaway DB-less kong:1.3.0,
# re-record its Admin API wire shapes and require them to match the committed
# fixtures, then run the 1.3 contract and capability suites. Read-only.
set -euo pipefail
image="${KONG_13_IMAGE:-kong:1.3.0}"
name="kp-kong13-smoke-$$"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker run -d --name "$name" -e KONG_DATABASE=off -e KONG_ADMIN_LISTEN=0.0.0.0:8001 -p 127.0.0.1:18013:8001 "$image" >/dev/null
for _ in $(seq 1 60); do curl -fsS http://127.0.0.1:18013/ >/dev/null 2>&1 && break; sleep 1; done
npm run build -w @kongpilot/api >/dev/null
CONSOLE_ENCRYPTION_KEY="$(openssl rand -hex 32)" KONG_FIXTURE_VERSION=1.3.0 KONG_FIXTURE_ADMIN_URL=http://127.0.0.1:18013 node deploy/scripts/capture-kong-fixtures.mjs
# Volatile node identity/status files are excluded; schemas and list shapes must match.
git diff --exit-code -- 'tests/fixtures/kong-1.3.0/schema-*' 'tests/fixtures/kong-1.3.0/plugin-schema-*' 'tests/fixtures/kong-1.3.0/plugins-enabled.json' 'tests/fixtures/kong-1.3.0/list-*'
git checkout -- tests/fixtures/kong-1.3.0
npx vitest run tests/unit/kong-1.3-fixture-contract.test.ts tests/unit/kong-capabilities.test.ts tests/unit/m11-iam-workflow.service.test.ts
