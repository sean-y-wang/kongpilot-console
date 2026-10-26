# 0004. Restoring legacy-origin recycle-bin entries is unsupported

- Status: Accepted
- Date: 2026-10-25

## Context

Recycle-bin entries created by direct-mode deletes (outside the approval workflow, "legacy origin") lack the provenance material needed to restore them safely.

## Decision

- Restore of a legacy-origin entry is rejected with HTTP `409`. Entries created through the approval workflow can be restored normally.

## Consequences

- The limitation is documented and covered by an E2E assertion; operators recreate such objects through a new ticket.
