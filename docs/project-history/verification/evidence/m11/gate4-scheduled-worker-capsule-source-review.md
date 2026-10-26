# Source24 scheduled worker capsule: source review

This document records source inspection only. The reviewing agent performed
no runtime, SQL, HTTP, private harness, migration or native transport action.
Root owns the actual Source24 acceptance evidence. The first actual worker
attempt reported by Root created one NULL-SID scheduled Source/execution and
failed before baseline/native writes with `KONG_SCHEMA_PREPARATION_CONTEXT_REQUIRED`;
that original failed attempt must remain visible.

## Minimum genuine worker entry

1. Use the same deployed Source24 build and actual Console DB/Redis/secret
   configuration. Before the controlled invocation, verify through Root's
   read-only acceptance process that the due set contains only the expected
   schedule. `tick()` scans up to 25 due schedules across this Console DB.
2. Keep `ENTITY_SCHEDULES_ENABLED` different from the exact string `true` in
   the one-shot capsule. Create the application with `NestFactory.create`
   and install `NativeKongPolicyService` before `app.init()`. This mirrors
   production `main.ts:21–23`; `createApplicationContext` initializes lifecycle
   hooks before an external caller can install the fixed native policy.
3. After `app.init()` completes, assert `KongExecutionContextService.peek()`
   is null and invoke `app.get(EntityChangeScheduleWorker).tick()` exactly
   once outside HTTP/actor/internal/system context. Do not supply a Cookie,
   reconstructed actor/SID, copied claim or ad hoc SQL execution facts.
4. Record the safe worker counters and the exact schedule/workflow receipts,
   then close the capsule. Counters alone do not establish native success.

The code sequence, deliberately not executed by this review:

```ts
const app = await NestFactory.create(AppModule);
app.get(NativeKongPolicyService).install();
await app.init();
try {
  if (app.get(KongExecutionContextService).peek() !== null) throw new Error('Existing context');
  const counters = await app.get(EntityChangeScheduleWorker).tick();
  // Root verifies actual exact-ID SQL/HTTP receipts separately.
} finally {
  await app.close();
}
```

## Actual source path and completion

| Source | Actual method / behavior |
| --- | --- |
| `workflows/entity-change-schedule.worker.ts:17` | `tick()` → `repository.listDue(25)` → fixed delegate `acquireDueClaim(id)` → `executeClaim(originalHandle)`; local busy fence, no per-item native retry |
| `workflows/entity-change-schedule-bootstrap.service.ts:19` | `onModuleInit()` installs Authority repository policies, intent scheduling delegate and the worker's once fixed delegate |
| `workflows/entity-change-schedule-bootstrap.service.ts:26` | `onApplicationBootstrap()` enables a 5-second timer only when `ENTITY_SCHEDULES_ENABLED === 'true'`; manual `tick()` needs no timer flag |
| `workflows/entity-scheduled-authority.service.ts:259` | `acquireDueClaim()` requires no inherited frame, current owner/grants/reviewers, approved immutable plan, exact due window and physical reservation, then appends one generation-1 claim and returns a private original handle |
| `workflows/entity-scheduled-authority.service.ts:318` | `executeClaim()` spends the original handle before await, holds the workflow Redis lease and enters only Root's fixed executor |
| `workflows/entity-change-execution.service.ts:600` | `executeScheduledClaim()` → `Namespace.runOriginalClaim()` → real `Context.runEntityScheduledNamespace()`; creates original scheduled Source with SQL `session_id=NULL` and full delegation/claim/window bindings |
| `workflows/entity-change-execution.service.ts:677` | Shared `runExecution()` performs real baseline/schema/graph capture, SQL21 packet facts, fixed Writer/Mutation/Context/native transport checks, and truthful workflow/execution closure without reacquiring the workflow lease |
| `workflows/entity-change-execution.service.ts:657` | Private original completion verifier checks actual exact source/execution/workflow terminal facts; the same completion remains verifiable twice |
| `workflows/entity-scheduled-authority.service.ts:330` | Authority verifies original completion and actual packet/mutation facts, then Repository's fixed outcome verifier independently repeats original completion/fact verification in the same transaction |
| `workflows/entity-change-schedule.repository.ts:165` | `finishClaim()` locks impact then mutable progress, verifies fixed proof, writes terminal state/event/audit while preserving the immutable claim |

## Logout and scope

`AuthService.revoke` (`auth.service.ts:316`) revokes the actual HTTP session and
removes its Redis cache, without changing `users.credential_epoch`. A scheduled
owner delegation therefore survives ordinary logout, while its current active
user, credential epoch, current grants, workspace/cluster revisions and every
reviewer remain mandatory at claim/capture/packet/before-send checkpoints.
Password reset/change increments the credential epoch and invalidates the
delegation. A NULL SQL SID does not permit adopting an HTTP identity: Context,
Namespace and Root private original handles remain mandatory.

## Acceptance and operational limits

- `worker.completed` counts a resolved `executeClaim`, including a truthful
  terminal `failed` or `partial`; it is not a native-success count. Require
  actual exact-ID schedule/workflow/execution terminal state, scheduled Source
  with NULL SID, one original claim/occurrence, ready baseline, one attempt
  and send/outcome fact per actual packet, succeeded actual mutation/result
  and zero unresolved facts before declaring success. Preserve prior failed
  Source24 attempts separately.
- Manual one-shot verification does not validate the production timer. Timer
  enable/disable, boot/shutdown, competing replicas and in-flight lease loss
  need their own evidence. The Worker busy flag is local; durable claim and
  workflow/transport Redis locks enforce cross-instance safety.
- The claim is not reclaimed or extended automatically. After Native entry,
  unknown or metadata failures require dedicated truthful recovery; no new
  packet or retry is authorized by the outcome path.
- The reviewed no-callback closure uses private `callbackEntered === false`
  observation, five SQL existence checks and the exact original claim plus a
  fresh workflow lease. Its identified progress/impact lock inversion has been
  fixed at source level by acquiring authenticated schedule impact first.
  After Root callback entry this branch remains forbidden.
- All-native-success with incomplete metadata is a separate truthful partial
  case: the original Authority partial predicate rejected it. Root delegated
  its precise evidence-based repair separately; do not relabel it as failed
  known-unsent or infer native failure from a metadata exception.
- Scheduled recycle, Targets/health and legacy Portal/configuration/promotion
  write adapters remain closed until their specific original-origin adapters
  are delivered. No generic session waiver should be introduced for them.
- Current production manual text at `production-operations-guide.md:579`
  still describes SQL024 as not applied. Update it only against Root's actual
  accepted scope, including timer and error-path limits.

The source-only scheduled Portal preflight fix and its 65 focused checks are
recorded in `gate4-scheduled-portal-preflight-focused-frozen.md`; its preservation
of full Portal ownership/authentication protections is not runtime acceptance.
