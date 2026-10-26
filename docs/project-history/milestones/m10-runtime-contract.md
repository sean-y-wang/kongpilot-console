# M10 Runtime Contract

Status: implemented contract with M10 technical acceptance, 2026-10-13. M9 release gate passed (`0f03f50`). M10 V8 functional/native gates, full regression (406 files / 7,828 tests), browser (15 checks / 7 screenshots), audit, original execution-mode restoration and actual secret scanning have passed; the 21-evidence acceptance manifest (`artifacts/M10/milestone-acceptance.json`, not public) records technical accepted=true and production/commercial=false. M11 has not been coded. Exact evidence scope and retained limitations are in [M10 verification](../verification/milestones/m10-verification.md). SQL017 / SQL018 bytes remain frozen; standalone IAM / scanner-tool checks are separate from the full-suite count, and the original deployment record remains a historical candidate receipt.

## 1. HTTP conventions

All routes below are relative to `/api/v1/clusters/:clusterId/governance`. All queries include the actual `workspaceId`; BFF supplies actor/SID/requestId/IP and reads `x-idempotency-key` for POST/PATCH/DELETE. UUIDs/keys are validated; unknown fields, controls (`approved`, `sourceProof`, owner/superAdmin), arbitrary paths/callbacks and excessive JSON are rejected. Lists return `{items, nextCursor, size, total:null}`, default20/max100, stable signed keyset cursors bound to actor/permissionVersion/scope/filter.

Capabilities are advisory UI controls. Backend whole-scope and actual native object permissions remain authoritative. Every mutation returns a real receipt or a typed failure; response loss uses the original key. Analytical capture/report writes are read-only diagnostic observations, never native configuration writes.

| Method / path | Request | Safe response |
| --- | --- | --- |
| GET `capabilities` | query workspaceId | `{clusterId,workspaceId,executionMode,inspection,ruleRead,ruleWrite,ruleDelete,scheduleRead,scheduleWrite,scheduleDelete,driftRead,driftCompare,promotePlan,adapterAvailable}` |
| GET `catalog` | workspaceId | `{engineVersion,builtinRules,predicates,fixActions,limits}`; rules contain typed DSL, no arbitrary code |
| POST `inspections` | `{scope?:'cluster'|'workspace'|'services',serviceIds?:uuid[],ruleCodes?:string[]}` | `{entity:ReportSummary}`; existing exact original key returns same run/summary without rereading |
| GET `reports` | workspaceId,size,cursor,quality? | page of ReportSummary |
| GET `reports/:id` | workspaceId | `{entity:ReportSummary,coverage,ruleResults,reasonCodes,capabilities}`; no raw inventory/private fingerprints |
| GET `reports/:id/findings` | workspaceId,size,cursor,severity?,ruleCode? | page of `{id,ruleCode,severity,entityType,nativeId,parentId?,objectWorkspaceId?,fieldPath,reasonCode,description,safeEvidence,fixActions}` |
| POST `reports/:id/findings/:findingId/fix-plan` | `{action,values:{...fixed typed action fields}}` | actual M8 `{jobId,planId?,entity?,state,blockerCodes?}` or fixed annotation metadata receipt; never directly executes |
| GET `rules` | workspaceId,size,cursor,state? | page `{id,code,name,revision,currentVersion,state,enabled,severity,description,given,then,builtinOverride,capabilities}` |
| GET `rules/:id` | workspaceId | `{entity:RuleView}` |
| POST `rules` | `{code,name,description,severity,given,then,enabled?:boolean}` | MetadataReceipt |
| PATCH `rules/:id` | `{revision,name?,description?,severity?,given?,then?,enabled?}` | MetadataReceipt, new immutable version |
| POST `rules/:id/clone` | `{code,name}` | MetadataReceipt; clones current safe DSL with new identity |
| DELETE `rules/:id` | `{revision,confirmed:true,confirm_name}` | MetadataReceipt, soft archive |
| POST `rules/:id/restore` | `{revision,confirmed:true,confirm_name}` | MetadataReceipt |
| GET `schedules` | workspaceId,size,cursor,state? | page ScheduleView |
| GET `schedules/:id` | workspaceId | `{entity:ScheduleView}` |
| POST `schedules` | SchedulePayload | MetadataReceipt |
| PATCH `schedules/:id` | `{revision,...optional SchedulePayload fields}` | MetadataReceipt |
| DELETE `schedules/:id` / POST `schedules/:id/restore` | `{revision,confirmed:true,confirm_name}` | MetadataReceipt |
| POST `comparisons` | `{scope?:'workspace'|'services',serviceIds?:uuid[],target:{clusterId,workspaceId,scope?:'workspace'|'services',serviceIds?:uuid[]},threshold?:number,includeEnvironmentFields?:boolean}` | `{entity:ComparisonSummary}`; same logical identity can have different native IDs |
| GET `comparisons` | workspaceId,size,cursor,quality? | page ComparisonSummary; each item requires both sides current permissions |
| GET `comparisons/:id` | workspaceId,size,cursor | `{entity:ComparisonSummary,items:SafeDriftChange[],nextCursor,size,total:null}` |
| GET `comparisons/:id/source-objects` | workspaceId,size,cursor,entityType? | all authorized source descriptors, including unchanged Consumers; `{comparisonId,quality,capabilities,items,nextCursor,size,total:null}`; fixed native type filter, no payload/digest/credentials |
| POST `comparisons/:id/promote-plan` | `{selectedObjectKeys?:string[],mapping?:Record<sourceObjectKey,targetUUID>,fieldOverrides?:Record<sourceObjectKey,typedFields>,includeEnvironmentFields?:boolean,includeSecrets?:boolean,includeCredentials?:boolean,credentialKinds?:string[],confirmed:true,confirm_name}` | real target M8 `{jobId,planId?,state,targetClusterId,targetWorkspaceId,blockerCodes?}`; defaults all inclusion flags false |
| GET `operations/by-key/:key` | workspaceId | own original inspection/comparison/metadata/promotion receipt, never retries native or SQL action |
| POST `operations/by-key/:key/reconcile` | `{confirmed:true,confirm_name:'reconcile:'+originalKey}` | SQL-only original fix-parent linkage to an exact already registered child; no compiler, full re-capture, child registration, configuration apply or native replay |

`ReportSummary` = `{id,clusterId,workspaceId,kind:'inspection',state,quality:'complete'|'partial'|'incomplete',projection,objectCount,findingCount,counts:{error,warn,info},observedFrom,observedUntil,createdAt,capabilities:{read,fix}}`.

`ComparisonSummary` = `{id,clusterId,workspaceId,source:{clusterId,workspaceId,scope,serviceIds},target:{clusterId,workspaceId,scope,serviceIds},state,quality,counts:{added,modified,removed,unchanged},threshold,thresholdExceeded,createdAt,capabilities:{read,promotePlan},confirmationName}`. Returned only after dual-scope permission checks. Public source/target contain no Admin URLs/transports/material HMAC.

Source-object item = `{objectKey,entityType,nativeId,parentId?,name?,referenceOnly,objectWorkspaceId,eligible}`. Name is an existing native name or Consumer username, never a Target address, certificate fingerprint or inferred private match field. References and Portal/Vitals managed boundaries are ineligible. Eligibility means the row may be offered to the fixed compiler; it grants neither write authority nor a promise that a plan will compile. Server cursors bind the immutable comparison, actor/permission epoch, source CID/WID, type filter and size. Both environments remain currently authorized before returning any row, even unchanged Consumers.

`credentialKinds` is a nonempty unique whitelist from `key-auth/basic-auth/jwt/oauth2/hmac-auth/acls`, only with literal `includeCredentials:true`. Omitted means all supported kinds; selecting a smaller batch helps remain within actual private-read budgets and does not relax full source membership verification.

`SchedulePayload` = `{name,kind:'inspection'|'drift',scope?:'cluster'|'workspace'|'services',serviceIds?:uuid[],ruleCodes?:string[],target?:{clusterId,workspaceId,scope?:'workspace'|'services',serviceIds?:uuid[]},intervalMinutes:5..10080,timezone,threshold?:0..10000,includeEnvironmentFields?:boolean,paused?:boolean}`. A drift schedule requires a distinct physical target; inspection forbids target. Threshold applies to drift. Partial patches are validated after merging the actual persisted policy, including a roots-only update. Timer remains readonly and never applies repairs/Promote.

`ScheduleView` additionally exposes actual `ownerUserId,nextRunAt,executionBlocked`, and, when blocked, `blockingOccurrenceId,blockingState,blockingReasonCode,blockingVersion,scheduledAt`. Any original running/uncertain occurrence blocks later occurrences across policy versions. A revoked-authority occurrence blocks its current immutable version until the operator explicitly updates the policy. An expired lease becomes uncertain; it never becomes an inferred failure or a fresh retry.

`MetadataReceipt` = `{id,clusterId,workspaceId,domain:'iam'|'workflow',state,idempotencyKey,configurationCommitted,submissionCompleted,executionCompleted,workflowId?,entity?,result?}`. In approval mode metadata uses fixed `governance-metadata` plan kind / `governance.metadata` handler; root verifier binds actual persisted intent, not a client proof. Typed delete/restore confirmation and revision are required.

Every mutation receipt includes original `actorId,clusterId,workspaceId,idempotencyKey,kind,registrationCompleted,nativeExecutionRequested:false`. Rule code is at most 96 characters, name 128, description 500; an omitted/empty rule description uses its name. Pure DSL validation errors return a safe HTTP400 before any intent is created.

Fix parents are durably registered before fresh compilation, then seal their expected child domain/kind/material HMAC once before delegation. The child key is `governance-fix-${parentId}`. GET may expose a known actual child's job/plan link while the parent is uncertain, but does not mark the parent complete. Annotation fixes preserve the actual child `domain:'iam'|'workflow'` with the original governance parent key and `kind:'fix-plan'`, plus `governanceRequestId,governanceState,metadataOnlyResult,metadataOperationId,metadataChildKey,metadataReconciliationPending`. Parent completion requires `governanceState:'ready'` and `metadataReconciliationPending:false`; a submitted approval never claims execution completed. The reconcile POST only links an exact authenticated durable child in SQL with audit, never reissues the fix.

## 2. Inventory and pure engines

Inventory agent owns `governance-inventory.types.ts`, authority and capture. Agreed shape:

```ts
interface GovernanceScope {
  clusterId: string; workspaceId: string; kind: 'cluster'|'workspace'|'services';
  rootIds: string[]; transportScope: string;
}
interface GovernanceInventoryObject {
  entityType: string; nativeId: string; payload: Record<string,unknown>;
  parentId?: string; objectWorkspaceId?: string; sensitiveFields: string[];
  annotations?: {state:'readable'|'not_authorized'|'absent';description?:string;ownerUserId?:string};
  certificate?: Record<string,unknown>;
}
interface GovernanceInventory {
  id: string; scope: GovernanceScope; objects: GovernanceInventoryObject[];
  schemas: Record<string,unknown>; pluginSchemas: Record<string,unknown>;
  enabledPlugins: string[]; version: string;
  coverage: Record<string,{state:'complete'|'projected'|'incomplete'|'not_authorized';eof:boolean;pages:number;records:number;reasonCodes:string[]}>;
  completeness:'complete'|'incomplete'; projection:boolean;
  consistency:'console_fenced_best_effort'; observedFrom:string;observedUntil:string;
  usage:{calls:number;pages:number;records:number;bytes:number};reasonCodes:string[];
}
```

Exact TS authority methods are frozen by inventory agent: `acquireActor(cid,input,actor)`, `acquireDueSchedule(locator)`, `description(handle)`, `assertCurrent(handle)`, `runRead(handle,fn)`; inventory `capture(handle)` and `captureActor(...)->{inventory,handle,privateMaterial}`. `privateMaterial` is opaque/private handle, not controller JSON or raw stored credential.

No credentials collections are captured in ordinary governance inventory. Complete workspace/cluster statistics need whole native scope; tag/entity scans are **projections**, never negative existence proof. Captured safe payloads may be encrypted for immutable provenance but are never claimed to be restorable full M8 snapshots. Pure Lint/inspection receives inventory, effective rule versions and readable annotations; pure drift/promote receives two safe inventories and fixed field policy. Engines do no DB/network/authentication and never mint source proof or native authority.

New comparison ciphertexts use `{version:2,inventory,nativeFingerprints}` for **both** sides in existing `*_inventory_secret` columns; the matching `*_inventory_hmac` covers the whole envelope. The private map contains only exact `entityType:nativeId -> keyed64hex` for the original authorized raw responses, including hidden/environment fields. `GovernanceInventoryService.privateFingerprints(handle,actualInventory)` validates the same live handle, captured object identity/public HMAC and current grants. The map never becomes a public inventory property, DTO, log, safe diff or cursor data.

`governance-comparison-material.ts` is the sole private decoder used by repository and origin core. Legacy raw inventory history remains readable with `nativeFingerprints:null`; it cannot support a new Promote verification claim. The UI disables publication and the BFF requires a fresh comparison. Cross-cluster historical parent checks execute under a genuine current peer Governance read handle, without widening the generic cross-CID internal guard, minting a login session or re-capturing a report.

## 3. SQL017 candidate schema required by module

Names/columns below are authoritative integration requirements; Root owns actual migration, constraints, runtime grants and additional origin schema. IDs default UUID unless immutable version/composite PK. All CID/WID FK tuples reference actual clusters/workspaces with ON DELETE RESTRICT. JSON/type/HMAC/UUID/length bounds belong in SQL and application validation. No existing SQL000–016 changes.

| Table | Required columns and identity |
| --- | --- |
| `governance_rules` | `id,cluster_id,workspace_id,code,name,owner_user_id,state(active/deleted),enabled,current_version,revision,created_at,updated_at,deleted_at,retention_until`; unique(CID,WID,code), code/owner/scope immutable |
| `governance_rule_versions` | `cluster_id,workspace_id,rule_id,version,content JSONB,content_hmac,created_by,created_at`; PK(CID,WID,rule_id,version); append-only, composite rule FK; content has name/description/severity/given/then/enabled/builtinOverride |
| `governance_runs` | `id,cluster_id,workspace_id,actor_id,origin_session_id nullable,origin_type(http/schedule),schedule_run_id nullable,idempotency_key,request_hmac,kind(inspection/comparison),state(running/succeeded/incomplete/failed/uncertain),revision,input_secret,error_code,created_at,completed_at`; unique(actor_id,idempotency_key), scope/actor/input immutable |
| `governance_reports` | `id,cluster_id,workspace_id,run_id,inventory_secret,inventory_hmac,engine_version,rules_hmac,quality(complete/partial/incomplete),projection,object_count,finding_count,counts JSONB,coverage JSONB,rule_results JSONB,reason_codes text[],observed_from,observed_until,created_at`; run 1:1, append-only; exact composite run FK |
| `governance_findings` | `id,cluster_id,workspace_id,report_id,finding_order,rule_code,severity,entity_type,native_id nullable,parent_id nullable,object_workspace_id nullable,field_path,reason_code,description,safe_evidence JSONB,fix_actions JSONB,created_at`; append-only, unique(report_id,finding_order), composite report FK, final finding count guard |
| `governance_comparisons` | `id,cluster_id,workspace_id,run_id,target_cluster_id,target_workspace_id,source_inventory_secret,target_inventory_secret,source_inventory_hmac,target_inventory_hmac,policy JSONB,policy_hmac,quality,counts JSONB,threshold,threshold_exceeded,safe_changes JSONB,created_at`; append-only, run1:1; anchor=source; both side FK, no public private HMAC |
| `governance_promotions` | `id,cluster_id,workspace_id,comparison_id,target_cluster_id,target_workspace_id,actor_id,idempotency_key,request_hmac,selection_secret,selection_hmac,source_inventory_hmac,target_inventory_hmac,state(planning/ready/blocked/uncertain),configuration_job_id nullable,plan_id nullable,plan_revision nullable,plan_hash nullable,error_code,created_at,updated_at`; immutable identity/selection with monotonic result, unique(actor_id,key); typed target configuration tuple pinned by Root origin schema |
| `governance_fix_requests` | `id,cluster_id,workspace_id,target_workspace_id,report_id,finding_id,actor_id,idempotency_key,request_hmac,input_secret,state(planning/ready/blocked/uncertain),child_kind nullable(configuration/metadata),child_request_hmac nullable,child_request_secret nullable,configuration_job_id nullable,plan_id nullable,plan_revision nullable,plan_hash nullable,metadata_operation_id nullable,metadata_domain nullable(iam/workflow),workflow_id nullable,error_code,created_at,updated_at`; immutable original tuple/material; child descriptor set once; original-key recovery binds exact known child |
| `governance_fix_links` | `id,cluster_id,workspace_id,target_workspace_id,report_id,finding_id,actor_id,idempotency_key,request_hmac,configuration_job_id nullable,plan_id nullable,plan_revision nullable,plan_hash nullable,metadata_operation_id nullable,metadata_domain nullable,created_at`; append-only; exactly one authoritative configuration/metadata link, complete parent/actual child workspace FK |
| `governance_schedules` | `id,cluster_id,workspace_id,name,owner_user_id,transport_scope,state(active/paused/deleted),current_version,revision,next_run_at,created_at,updated_at,deleted_at,retention_until`; immutableowner/scope; CAS; version FK deferred |
| `governance_schedule_versions` | `cluster_id,workspace_id,schedule_id,version,payload JSONB,policy_hmac,created_by,created_at`; payload=SchedulePayload; append-only, composite schedule FK |
| `governance_schedule_runs` | `id,cluster_id,workspace_id,schedule_id,schedule_version,scheduled_at,creator_id,lease_generation,lease_until,state(running/succeeded/incomplete/failed/paused_authority/uncertain),run_id nullable,error_code,created_at,completed_at`; unique(schedule_id,schedule_version,scheduled_at), composite version/actual run FK; identity/occurrence immutable |
| `governance_drift_states` | `cluster_id,workspace_id,schedule_id,policy_hmac,last_comparison_id,last_diff_hmac,threshold_exceeded,revision,updated_at`; fixed scope/policy + CAS; actual complete comparison FK; one schedule baseline |
| `governance_metadata_requests` | `id,cluster_id,workspace_id,actor_id,resource_type(governance_rules/governance_schedules/entity_annotations),resource_id,operation(create/update/archive/restore),idempotency_key,request_hmac,payload_secret,payload_hmac,before_secret nullable,before_hmac,scope_secret,workflow_id,created_at`; annotation only create/update; append-only, unique(actor_id,key); source workflow reciprocal composite FK deferred |

Rules and schedules direct mode use existing IAM durable transaction/result + business audit. Approval mode first inserts immutable `governance_metadata_requests` intent and seals fixed workflow in the **same transaction**, without creating a active target record prematurely. Workflow subject/step entity type = `governance_metadata_requests`, ID = intent ID. Payload references exact fixed resource/ID/operation and before revision, never arbitrary table/path. `inspect` returns current target before / revision (0 for create), `apply` verifies intent/source/execution and current before then writes target+version+audit in its provided transaction. Root adds type/registry/subject checks; module owns handler implementation.

Runtime immutable tables have only SELECT/INSERT and prohibit UPDATE/DELETE/TRUNCATE. Report seal/finding count and origin required markers need deferred constraints so missing component rows cannot appear valid. Report/from-key lookups cannot disclose foreign actor/report/source-target material. Analytical failed attempts remain in runs with original input HMAC; response unknown never silently reruns.

## 4. Private target-origin bridge and verifier

Root freezes exact TS exports before integration. Desired fixed API (names are agreed integration candidates until Root publishes the final code):

```ts
interface GovernancePromotionLocator {
  promotionId:string; sourceClusterId:string;sourceWorkspaceId:string;
  targetClusterId:string;targetWorkspaceId:string;
}
// Root loads the immutable persisted promotion/comparison/selection, not a DTO proof.
ConfigurationService.createGovernancePromotionPlan(locator, actor): Promise<real M8 job/plan receipt>;
```

Fixed repairs use actual existing `ConfigurationService.importDocument` (merge) / `createToolboxBatchPlan` (archive with the full M9 recycle graph); descriptions use fixed `GovernanceMetadataService.mutate('entity_annotations')`, never a fictitious Kong `description` field. Their durable expected child request is encrypted under `governance:fix-child:${parentId}`. Metadata scopes encrypt the exact original request tuple for historical HMAC/key verification.

`ConfigurationService.installGovernancePromotionSourcePolicy` installs once a fixed server-only provider with `acquire(promotionId,actualActor)`, `refresh(promotionId,opaqueHandle,actualActor)`, `fingerprints(promotionId,opaqueHandle,actualInventory)`, `assertCurrent(promotionId,opaqueHandle)`, and SQL-only `assertGrants(promotionId,actorId,action,tx?)`. Acquire performs fresh actual source **and target** inventory captures and supplies their private maps. Refresh reuses the same live source handle and cumulative budget; the separate private accessor binds that exact refreshed inventory. It never resets limits or impersonates a reviewer. Ordinary public inventory contains no raw credentials; explicit secret/credential inclusion requires a real separately authorized recovery capture or blocks.

Root may use a one-time installed fixed promotion compiler/source-read delegate to keep Governance imports acyclic. The delegate only reads matching persisted promotion/comparison tuple, compiles target merge YAML and verifies live readonly source; it cannot apply native or supply `approved:true`. Only original actor owns private locators; compiler output is data, never permit. New root bridge must acquire real target ConfigurationAccess capability, validate source before building, freeze origin-required plan marker/binding atomically, and return actual targetreceipt.

The frame-free `ConfigurationAccessService.verifyHandle` boundary uses a dedicated private ALS marker only for a genuine WeakMap job handle. `ConfigurationOriginService.assertJobVerifier` and the source provider's SQL-only `assertVerifierCurrent` bind the current job SID, actor, immutable origin material, live original frame and current IAM. This boundary does not capture, send a Kong request, mint a source handle or reset its budget. Ordinary refresh and every native-send hook still require the actual ambient execution frame. An outer apply/reconcile anchors the source handle before nested plan reads, so a finished nested read cannot invalidate an otherwise live outer execution. Read-only target planning preserves its private lineage through nested capture jobs; a closed planning frame cannot escape as a detached job.

Strong origin checks are mandatory on **generic M8 plan read/apply, apply-plan copying, workflow read/approve/execute, direct exec, every native before-send**, and deck (or reject Promote deck driver). Source grants/material/actual selected fields/children drift or physical target change blocks packets. Missing binding with required marker fails closed. Safe original native facts remain recoverable after source revocation, without source diff/material leakage. Detailed mandatory matrix is [M10 plan §5.4](m10-implementation-plan.md#54-promote-原点是所有目标执行入口的强制围栏).

Private source verification recognizes only the two existing, fixed 1.5 adapter identities, `kong-1.5` and `kong-oss-1.5-v1`; the actual Kong version must still be 1.5.x and match the captured inventory/material version. This does not accept arbitrary adapter labels, unknown versions or changed raw fields. Scope, material HMAC, selected object membership and current authorization checks remain exact.

### Rollback schema capture (V8 candidate)

An older complete M8 snapshot may omit a plugin that exists only in the current target. V8 derives the required plugin-name set from the actual normalized desired snapshot, then supplies a server-only `requiredPluginSchemas` capture option. The fresh, genuinely authorized baseline loads the union of current and desired plugin schemas through `/plugins/schema/{name}`, under the same opaque capture handle, cumulative meter and deadline. Names are deduplicated before the 200 unique-name limit; duplicate instances remain subject to the 10,000-record budget. Enabled-plugin probing and final schema sealing use real 1.5 responses. No client schema proof, global schema cache or fabricated DiffOptions sidecar supplies missing evidence.

Only a rollback with a verified fresh baseline may include current-only plugin definitions needed to delete those instances. All entity definitions, common plugin definitions, enabled-plugin set, scope, Kong version and adapter must remain compatible; a desired plugin schema must have been loaded into the actual fresh capture. Generic merge/sync compatibility remains strict. The old snapshot ciphertext, version and HMAC are never rewritten. The new baseline graph and schema HMAC are sealed normally and preserved by plan copying/apply as the exact `baselineSnapshotId` / version referenced by execution; apply does not silently replace that baseline.

This contract fixes the V7 preview rejection documented in the real schema diagnostic (`artifacts/M10/native-rollback-schema-beforefix.json`, not public). The separate V8 actual rollback report (`artifacts/M10/native-optin-rollback-attempt-3.json`, not public) confirms two native steps, recycle routing and real proxy outcomes; deployment and source tests alone are not that proof.

## 5. Timer storage handshake

1. Scheduler reads <=10 due active schedules ordered next_run_at/id, acquires Redis lock per actual schedule.
2. SQL transaction locks root, checks immutable version/hash/owner/scope, inserts `governance_schedule_runs` occurrence, sets lease generation/until, advances next_run_at CAS. No fake actor/SID.
3. Authority `acquireDueSchedule` receives `{scheduleId,clusterId,workspaceId,ownerUserId,version,revision,scheduledAt,runId,leaseGeneration}` and validates actual running run/lease/owner/grants; description supplies DB identity.
4. Readonly capture/evaluate persists actual governance run/report/comparison and binds run_id to scheduled occurrence. Both source and drift target authorities reference same actual occurrence/version/policy, not a fabricated target schedule.
5. Result/failure audit and original immutable fact are written transactionally; incomplete captures retain state `incomplete`. Unknown persistence failures retain `uncertain`, no new occurrence/replay. Late/expired running occurrences become uncertain and block later occurrence claims. Operators can inspect the original occurrence and archive the blocked schedule before creating an explicitly new policy; no automatic analysis re-send after unknown and no old receipt is relabeled as successful. Exact terminal evidence reconciliation may be added through an explicitly constrained metadata path; the candidate does not invent such evidence.

Drift notification maps fixed successful audit action `governance.drift.threshold_crossed` to `config.drift` with safe opaque subject and no other-side names/diff/counts. Existing M7 outbox owns fanout/delivery. The isolated actual threshold audit → event → dispatched outbox → exact own in-app notification association has passed read-only database verification (`artifacts/M10/drift-notification-verification.json`, not public); no external-channel delivery claim follows from it.

## 6. Ownership and acceptance

Inventory agent owns its TS types and private GET origin; Lint/Compare own pure files; integration owner owns governance module/controller/input/storage/business/metadata/scheduler and fixed drift mapping/catalog edits; Root owns SQL/core/app.module/private promotion-origin fences; Web owns new UI/navigation/API client. No agent builds dist/deploys/writes actual gateway without Root ownership.

Required acceptance includes readonly/projection/IDOR/secret budgets; metadata direct+approval+CAS/archive/restore/clone; actual timer owner revocation; two independent physical 1.5 clusters; default credentials/environment preservation; M8 plan bypass and source revocation/drift before every packet; genuine original receipts; full source/storage/native/browser/audit/secret evidence. M10 is complete only when these pass, not when tables or menus exist.

Evidence ownership is separate from application authority. Real test requests keep their original body/key/status and actual persisted facts; fixed software receives an explicit fresh intent rather than replaying old unknown writes. The private test ledger now rejects stale writers with digest CAS and a short exclusive save lock. One operator auth-refresh packet/token was lost before that fix while the application audit remained intact; its exact limitation is retained in the concurrency verification (`artifacts/M10/auth-journal-concurrency-verification.json`, not public). Scanning retained actual tokens must not be represented as scanning every historical token.

The final real browser cycle retains three closed earlier UI-tool failures and all originally observed auth packets. It performs no new browser writes, imports cookies from a separately recorded actual same-SID Root refresh, and validates them with an actual `GET /auth/me`; JWT decoding alone grants no authority. Original journal/material/report bytes stay hash-bound and unchanged. Source/target/global append-only chains, every successful business request, redacted RFC 6902 diffs and known native completions have separate actual database audit evidence (`artifacts/M10/audit-verification.json`, not public). A scanner preflight report with zero files/bytes is not a secret-leak result, irrespective of its empty findings array.

The final actual scan (`artifacts/M10/secret-scan-verification.json`, not public) covers 266 retained secrets / 881 patterns across 318,423,722 bytes with zero findings; both earlier zero-byte preflight failures stay archived. Exact proven control metadata is normalized only in the collector clone, leaving original packets and credential leaves intact. A retained M9 auth-only unknown response remains unresolved, and the separate overwritten M10 auth-refresh token remains unavailable; these facts are not reclassified by technical acceptance. The 5 standalone IAM checks (`artifacts/M10/audit-tools-supplemental-verification.json`, not public) and 4 scanner-tool checks (`artifacts/M10/secret-tools-supplemental-verification.json`, not public) add no platform API / SQL changes and are not added to 7,828.
