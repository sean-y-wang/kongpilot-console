# 0007. Kong 1.5 worker processes default to 2

- Status: Accepted
- Date: 2026-10-25

## Context

With `nginx_worker_processes=auto`, Kong 1.5 starts one worker per CPU. On an 8-core host this exceeded the container memory limit and the process was OOM-killed.

## Decision

- `KONG_NGINX_WORKER_PROCESSES` defaults to `2` in the bundled compose files (about 520 MiB). Operators can override it.

## Consequences

- Predictable memory use; raise the value only together with the memory limit.
