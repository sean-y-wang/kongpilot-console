# 0009. Scheduled configuration executions have a Kong call budget of 1000

- Status: Accepted
- Date: 2026-10-25

## Context

Every workflow execution has a fail-closed cap on Kong Admin API calls. Scheduled configuration executions perform extra fresh verification reads and could exceed the generic cap of 500.

## Decision

- Scheduled `configuration_v2` executions get a budget of **1000** calls; all other executions keep **500**. Both fail closed one call above the cap.
- Verification steps of one request round share **one fresh per-party read** instead of repeating it; replays re-check grants, and the final before-send check always does its own fresh read.

## Consequences

- Larger scheduled changes complete; authorization strength is unchanged.
