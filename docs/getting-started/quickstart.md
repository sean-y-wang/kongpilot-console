# Quick start (Docker Compose demo)

This brings up a **local demo**: Kong 1.5.1 with its own PostgreSQL, the KongPilot BFF, console and developer portal, Redis, Prometheus and Loki. It is not a production topology; for production see [docs/manuals/production-operations-guide.md](../manuals/production-operations-guide.md) (`deploy/compose/compose.production.yml`, and `deploy/compose/compose.external-kong.yml` to manage an existing Kong).

## Prerequisites
- Docker Engine with Compose v2.24.4+
- Node.js (for the env generator), git
- Free local ports 8000, 8080, 8082; the compose file uses fixed private subnets `172.28.0.0/16`, `172.21/16`, `172.22/16` — override them in `.env` if they collide with your network.

## Steps
```bash
git clone https://github.com/sean-y-wang/kongpilot-console.git && cd kongpilot-console
node deploy/scripts/generate-env.mjs .env      # writes random secrets; keep .env private
docker compose up -d --build
docker compose ps                              # wait until services are healthy
```

- Console: http://127.0.0.1:8080 — sign in as `admin` with `BOOTSTRAP_ADMIN_PASSWORD` from `.env`, then change it.
- Developer portal: http://127.0.0.1:8082
- Kong proxy: http://127.0.0.1:8000 (the Admin API is intentionally not published to the host).

Add the bundled Kong as a cluster in the console (Admin URL is reachable only from the BFF network, e.g. `http://kong-admin-endpoint:8001`).

## Port conflicts
If 8080/8082/8000 are taken, edit `CONSOLE_WEB_PORT`, `PORTAL_WEB_PORT` and `KONG_PROXY_PORT` in `.env`, and update `PORTAL_PUBLIC_ORIGINS` to the new portal port. Plain `http://` origins are accepted only for loopback hosts (`127.0.0.1`, `localhost`, `[::1]`); any other host must use HTTPS.

## Stop / reset
```bash
docker compose down          # keeps data volumes
docker compose down -v       # DEMO ONLY: deletes all data
```
