# 0001. Approvers with cluster write permission may execute tickets they approved

- Status: Accepted
- Date: 2026-10-25

## Context

KongPilot uses a two-person approval workflow for changes to Kong clusters. A strict separation-of-duties (SoD) rule would forbid any approver from also executing the ticket. In small teams this blocks routine work, because the only people with cluster write permission are often also the approvers.

## Decision

- Self-approval is always forbidden: the author of a ticket can never approve it (`403 WORKFLOW_SELF_APPROVAL_FORBIDDEN`).
- An approver who also holds cluster **write** permission may execute a ticket they approved. Execution is a permission check, not a hard SoD rule.
- Every execution re-checks current grants at execution time, and the whole flow is recorded in the tamper-evident audit log.

## Consequences

- Organizations that need strict SoD should grant approver and executor roles to disjoint groups, so that no approver holds cluster write permission. See [approval-execution-separation](../operations/approval-execution-separation.md).
- Review the audit log regularly for tickets where approver and executor are the same person.
