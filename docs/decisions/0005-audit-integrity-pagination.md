# 0005. Audit integrity endpoint is paginated (1000 rows + nextCursor)

- Status: Accepted
- Date: 2026-10-25

## Context

Verifying the hash chain of a large audit log in one request is unbounded in time and memory.

## Decision

- `/audit/global/integrity` verifies at most **1000 rows per page**. When more rows remain it reports `AUDIT_BUDGET_REACHED` with a `nextCursor`.
- Clients must follow `nextCursor` until the result is `verified/complete`. A first page that hits the budget is **not** a failure and **not** a pass.

## Consequences

- Smoke and backup/restore checks walk the cursor to the end; the gate itself was not relaxed.
