# M11 SQL041 — metadata-domain business schedules

Status: DB layer for all nine metadata kinds landed (slice 1 entity-annotation, slice 2 the other eight; 041 widened in place because it has never been deployed) on `work/m11-continue`. The original 041/042 candidates were lost, so this is a fresh re-implementation.

## Scope
SQL026–029 only allow `configuration_v2` and `portal-credential-issue` as scheduled kinds. SQL041 adds them in slices, one domain at a time:

1. **entity-annotation** (this slice): approval mode only, Console requester only.
2. Later slices: control-, configuration-, governance-, workflow-policy-, iam-, portal-metadata, portal-developer-review and event-metadata.

## Migration rules
- Kind CHECKs on `workflow_executor_delegations` and `workflow_schedules` are dropped and re-created as supersets of the old ones.
- New CHECK `workflow_executor_delegations_metadata_subject_check`: an entity-annotation delegation must have subject_type `entity_annotation_requests`, requester `console`, requester = owner, and the same credential epoch.
- Three functions are rewritten from `pg_get_functiondef` by exact substitution (the DO block raises if the match count is not 1). The rewritten functions are `pointer_advance`, `revision_complete` and `origin_permission`.
- Each rewritten function gets `SET search_path = pg_catalog, public, pg_temp`.
- At execution, the generic SQL028 recheck still applies: user active, credential_epoch, and permission_version `id:permissions_epoch:iam_epoch`.

## Verification
`tests/unit/m11-sql041-metadata-schedules.test.ts` runs against a disposable postgres:16-alpine with `--network none`:
- Migrations 000–040 apply, then 041 inside BEGIN/ROLLBACK leaves the catalog unchanged.
- After the real apply, search_path is pinned and every original validation line is preserved.
- Positive and negative cases for the CHECK.
- pointer_advance: approval mode returns true, direct mode false, configuration_v2 behaviour is unchanged, and unknown kinds return false.

## Remaining (TS slice)
- Add `entity-annotation` to `WorkflowScheduledKind` and the subject seal driver.
- Annotation executor in workflow-business-schedules with a permission/epoch recheck before write.
- Unit tests for expiry, revoked permission, double claim and tampered seal.

## Slice 2 (DB layer, remaining eight kinds)
Kind → allowed subject_type (mirrors the SQL010–040 workflow validators). All approval-only, Console requester = owner, same epoch:
- control-metadata → control_metadata_requests
- configuration-metadata → config_snapshots / config_snapshot_schedules / configuration_gitops_runs
- governance-metadata → governance_metadata_requests
- workflow-policy-metadata → workflow_policy_requests
- iam-metadata → iam_metadata_requests
- portal-metadata → portal_settings / portal_developers / portal_applications / portal_publications / portal_content
- portal-developer-review → portal_developers
- event-metadata → notification_channels / event_subscriptions / event_deliveries
The PG test checks the full kind × subject matrix plus developer/foreign-owner/epoch negatives in a single psql round-trip, and checks that pointer_advance is approval-only for every kind.
Still TS-only work: kinds stay out of `WorkflowScheduledKind` until per-kind executors and recheck guards exist (fail-closed).
