# 0003. Entity / business schedules are opt-in

- Status: Accepted
- Date: 2026-10-25

## Context

Scheduled execution of entity-level (business) changes adds background work and new failure modes that not every deployment needs.

## Decision

- Entity/business schedules are controlled by `ENTITY_SCHEDULES_ENABLED`, **default `false`**.
- Production deployments keep it off unless an operator explicitly enables it. The E2E suite enables it only for the schedule scenario.

## Consequences

- Enabling it is a deliberate operator decision; schedules still go through the same approval and audit flow.
