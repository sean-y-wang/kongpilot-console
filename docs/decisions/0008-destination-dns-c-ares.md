# 0008. Destination DNS via c-ares with bounded fallback

- Status: Accepted
- Date: 2026-10-25

## Context

In offline deployments without upstream DNS, concurrent pending `getaddrinfo` calls slowed even local lookups (e.g. `kong`) to several seconds, exhausting background workers and causing Kong writes to fail.

## Decision

- Resolve destinations by checking `/etc/hosts` first, then a c-ares resolver with a 1 s timeout.
- Fall back to `getaddrinfo` only after an explicit NXDOMAIN, single-flight per host with concurrency 2.
- Negative-cache timeouts only (30 s); never cache positive answers, so destination checks stay live.
- Aliases that resolve to protected addresses are still rejected.

## Consequences

- Offline smoke went from 17/22 to 22/22 with no security check relaxed.
