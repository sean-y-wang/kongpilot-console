This test server serves recorded Kong OSS 1.5.1 responses from `../fixtures/kong-1.5.1`. `manifest.json` records provenance, paths and capture times. Root configuration secrets are redacted.

Run `node tests/mock-kong/server.mjs` (default loopback port 18001). Set `MOCK_KONG_PORT` and `MOCK_KONG_HOST` only for an isolated test network. `POST /__control` selects `normal`, `unavailable`, `validation`, `timeout`, `pagination` or `unsafe-next`; optional `version` and `delayMs` exercise compatibility and timeouts. `GET /__requests` lists methods and paths, never bodies or credential headers.

The pagination records and fault responses are synthetic. They verify defensive client behavior and are not evidence that real Kong returned those values. Production never includes this server.
