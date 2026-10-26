# M11 KP-003 / historical SQL042 — unknown-result disposition

Status: design + migration **044** (slice 1) on `work/m11-continue`. Original external V1+V2 candidate bytes are not in this repository (see KP-012 / `unintegrated-candidates.json`); this is a fresh re-implementation that reuses SQL027 Target observation and SQL039 disposition patterns.

## Numbering

| Name in docs / checkpoint | Meaning in this repo |
| --- | --- |
| Historical **SQL042** (KP-003) | Unknown-result safe verification & disposition |
| Repo migration **042** | Entity-annotation scheduled identity (owner 2026-10-24) |
| Repo migration **043** | Control/IAM scheduled identity |
| Repo migration **044** | This disposition ledger (lands KP-003 SQL under the next free number) |

041 (metadata schedules) remains a hard prerequisite in spirit: disposition binds to SQL026 schedule claims / execution origins that 041-kind schedules also use.

## Goals (from checkpoint KP-003)

- Provide a **safe verification flow** for subjects left `uncertain` after a scheduled (or nested) native/metadata attempt.
- **Never** replay the original Native write; **never** invent KnownNotSent from “config unchanged” or zero mutations.
- **Never** rewrite original `sent-unknown` / NULL `native_status` / early `remote_started` facts; disposition is **additive**.
- Closing a metadata state (`uncertain` → `succeeded`/`failed`) for a **schedule-origin** execution requires a matching **closing** disposition row.
- Failed verification is recorded as `verification-rejected` and **must not** unlock a state change.
- Functions pin `SET search_path = pg_catalog, public, pg_temp` (C042-R1).
- Rows are immutable; runtime role is SELECT/INSERT only.

## Non-goals (slice 1)

- Full original V1+V2 11-table candidate reconstruction.
- Changing terminal `workflow_schedule_progress` once it is already `uncertain` (SQL026 treats that as terminal); schedule progress closure remains future work.
- HTTP/UI surfaces beyond the Nest service API.
- Replacing SQL027 Target-specific observation (guard explicitly leaves that path alone).

## Schema (044)

`workflow_unknown_result_dispositions` (append-only):

- Binds `schedule_id` + `claim_id` + `workflow_execution_id` (+ optional `mutation_id`) to the exact `workflow_execution_origins` row.
- Snapshots original uncertain receipt fields (`original_*`) that Root verified before INSERT.
- `disposition ∈ {verified-applied, verified-not-applied, verification-rejected}`.
- At most one **closing** disposition per claim (`verified-applied` / `verified-not-applied`).
- Linked audit action `workflow.unknown-result.disposed`.

Guards:

- `m11_validate_unknown_result_disposition` — insert-time identity / liveness / origin / receipt match.
- `m11_unknown_result_state_guard` — for schedule-origin executions without a Target observation, `uncertain`→`succeeded|failed` on `workflow_executions` / `mutation_operations` requires the matching closing disposition.

## TS

- `unknown-result-disposition.ts` — pure evidence matcher / reject codes (unit-tested).
- `UnknownResultDispositionService` — records disposition after Root-supplied verification evidence; inserts audit + row; optional CAS of execution/mutation state when disposition closes. **Sends zero Native requests.**

## Verification

- Docker PG: `tests/unit/m11-sql044-unknown-result-disposition-pg.test.ts` (apply, pinned search_path, immutability, CHECK/unique, rollback refuse-with-evidence).
- Unit: `tests/unit/m11-unknown-result-disposition.test.ts` (evidence match positives/negatives, no-replay).

## Remaining after slice 1

- Wire HTTP route + console-web disposition UI.
- Real Kong readback certificates for configuration/portal uncertain cases.
- Optional progress unblocking if product later allows terminal schedule reinterpretation (would need an explicit SQL026 extension, not a silent rewrite).
