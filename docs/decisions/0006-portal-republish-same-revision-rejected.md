# 0006. Republishing an already-proven portal revision is rejected at prepare

- Status: Accepted
- Date: 2026-10-25

## Context

After a cluster revision change, republishing the same portal publication revision used to reach an `uncertain` step (proof key collision). It failed closed, but late and unclearly.

## Decision

- Such a republish is rejected before any plan/native step with `409 PORTAL_PUBLICATION_REVISION_ALREADY_PUBLISHED`, with in-transaction and handler-prepare rechecks. Users save a new revision and publish that.

## Consequences

- No more `uncertain` executions for this case; no gate was relaxed.
