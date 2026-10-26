import { compare } from 'fast-json-patch';
import type { CaptureGraph, CaptureObject } from '../configuration/configuration.types';
import { canonicalJson } from '../../infrastructure/secret.service';
import { workspaceTag } from '../../infrastructure/kong/tags';
import { normalizeEntityPayload, writableCapturedPayload, schemaFields, entitySchema, generatedFieldsMissing } from './schema-normalization';
import { assertCompleteCaptureGraph } from './deck-serializer';
import { configurationNativeIdentity } from './deck-normalizer';
import type { DiffOptions, NormalizedTransferGraph, TransferDiff, TransferChange, TransferObject } from './transfer.types';
import { transferFail } from './transfer.types';
import {compareCapturedSchemas} from './schema-comparison';
import {rollbackSchemasCompatible} from './rollback-schema-comparison';

const equal = (a: unknown, b: unknown): boolean => canonicalJson(a) === canonicalJson(b);
function sameScope(a: CaptureGraph['scope'], b: CaptureGraph['scope']): boolean {
  return a.clusterId === b.clusterId && a.workspaceId === b.workspaceId && a.transportScope === b.transportScope && a.kind === b.kind && equal([...a.rootIds].sort(), [...b.rootIds].sort());
}
function mergeRecord(before: unknown, patch: unknown): unknown {
  if (patch === null || typeof patch !== 'object') return structuredClone(patch);
  if (Array.isArray(patch)) return patch.map((item, i) => mergeRecord(Array.isArray(before) ? before[i] : undefined, item));
  const output = before && typeof before === 'object' && !Array.isArray(before) ? structuredClone(before) as Record<string, unknown> : {};
  for (const [key, value] of Object.entries(patch)) output[key] = mergeRecord((before as any)?.[key], value);
  return output;
}
/** Imported records are PATCHes of schema-defined fields. Collections and
 * references remain replacements, and null is an explicit clear. Snapshot
 * rollback bypasses this merge so an exact captured record stays exact. */
function mergeEntityRecord(before: unknown, patch: unknown, definition: Record<string, any>): unknown {
  if (definition.type !== 'record' || !definition.fields || patch === null
    || !patch || typeof patch !== 'object' || Array.isArray(patch)) return structuredClone(patch);
  const output: Record<string, unknown> = before && typeof before === 'object' && !Array.isArray(before)
    ? structuredClone(before) as Record<string, unknown> : {};
  const fields = schemaFields(definition);
  for (const [name, value] of Object.entries(patch)) {
    output[name] = fields[name] ? mergeEntityRecord(output[name], value, fields[name]) : structuredClone(value);
  }
  return output;
}
function currentPayload(object: CaptureObject, graph: CaptureGraph): Record<string, unknown> {
  return normalizeEntityPayload(writableCapturedPayload(object.payload, object.entityType), graph.schemas, object.entityType, object.credentialKind);
}
function addCreateTags(object: TransferObject, target: NormalizedTransferGraph, body: Record<string, unknown>): void {
  if (!Object.hasOwn(schemaFields(entitySchema(target.schemas, object.entityType, object.credentialKind)), 'tags')) {
    // Kong <1.4 credential DAOs have no tags column. A credential is always scoped by its
    // tag-scoped parent Consumer, so the sealed body carries no tags (Kong rejects unknown fields).
    if (object.entityType === 'credentials') { delete body.tags; return; }
    transferFail('CONFIGURATION_WORKSPACE_SCHEMA_UNSUPPORTED');
  }
  const code = target.workspaceCodesById[object.objectWorkspaceId];
  if (!code) transferFail('CONFIGURATION_UNKNOWN_WORKSPACE_TAG');
  body.tags = [...new Set([...(Array.isArray(body.tags) ? body.tags : []), workspaceTag(code)])].sort();
}

/** merge touches explicit objects only; sync absence is destructive only after complete coverage. */
export function diffTransferGraphs(baseline: CaptureGraph, target: NormalizedTransferGraph, options: DiffOptions = {}): TransferDiff {
  assertCompleteCaptureGraph(baseline);
  const mode = options.mode ?? 'merge';
  if (mode === 'rollback' && options.rollbackBaselineVerified !== true) transferFail('CONFIGURATION_FRESH_ROLLBACK_BASELINE_REQUIRED');
  const schemaCompatible=mode==='rollback'?rollbackSchemasCompatible(baseline.schemas,target.schemas,target.objects.filter(object=>object.entityType==='plugins').map(object=>object.payload.name as string)):compareCapturedSchemas(baseline.schemas,target.schemas).kong15ValidationEquivalent;
  if (!sameScope(baseline.scope, target.scope) || baseline.kongVersion !== target.schemas.kongVersion || baseline.adapterVersion !== target.schemas.adapterVersion
    || !schemaCompatible) transferFail('CONFIGURATION_DIFF_SCOPE_MISMATCH');
  if (mode === 'sync' && options.syncConfirmed !== true) transferFail('CONFIGURATION_SYNC_CONFIRMATION_REQUIRED');
  const existing = new Map(baseline.objects.map(object => [object.objectKey, object])), desired = new Map(target.objects.map(object => [object.objectKey, object]));
  const nativeIdentities = new Map(baseline.objects.map(object => [configurationNativeIdentity(object.entityType, object.nativeId, object.credentialKind), object]));
  if (desired.size !== target.objects.length) transferFail('CONFIGURATION_DUPLICATE_NATIVE_ID');
  const changes: TransferChange[] = [], blockers = new Set<string>(); let unchangedCount = 0;
  const append = (entry: TransferChange): void => { changes.push(entry); for (const code of entry.blockerCodes) blockers.add(code); };
  for (const after of target.objects) {
    const before = existing.get(after.objectKey) ?? null;
    const foundSameId = nativeIdentities.get(configurationNativeIdentity(after.entityType, after.nativeId, after.credentialKind));
    if (!before && foundSameId) transferFail('CONFIGURATION_PARENT_REFERENCE_IMMUTABLE');
    if (before && before.objectWorkspaceId !== after.objectWorkspaceId) transferFail('CONFIGURATION_WORKSPACE_MIGRATION_FORBIDDEN');
    const codes = new Set<string>();
    let effective: Record<string, unknown>, write: Record<string, unknown>;
    const current = before ? currentPayload(before, baseline) : {};
    if (!before) {
      effective = normalizeEntityPayload(after.payload, target.schemas, after.entityType, after.credentialKind, true);
      addCreateTags(after, target, effective); write = structuredClone(effective);
      if (generatedFieldsMissing(effective, entitySchema(target.schemas, after.entityType, after.credentialKind)).length) codes.add('CONFIGURATION_GENERATED_MATERIAL_NOT_FROZEN');
      if (after.credentialKind === 'basic-auth' && after.passwordIntent !== 'replace') codes.add('CONFIGURATION_BASIC_PASSWORD_INTENT_REQUIRED');
    } else {
      effective = { ...current, ...structuredClone(after.payload) }; write = {};
      if (target.semantics === 'merge') {
        const fields = schemaFields(entitySchema(target.schemas, after.entityType, after.credentialKind));
        for (const [name, value] of Object.entries(after.payload)) {
          if (fields[name]?.type === 'record' && fields[name].fields)
            effective[name] = mergeEntityRecord(current[name], value, fields[name]);
        }
      }
      if (after.entityType === 'plugins' && Object.hasOwn(after.payload, 'config')) {
        // Configuration jobs use Root's exact approved PATCH handler. The
        // ordinary entity form still merges, but a complete snapshot is exact.
        effective.config = target.semantics === 'complete' ? structuredClone(after.payload.config) : mergeRecord(current.config, after.payload.config);
      }
      if (after.credentialKind === 'basic-auth') {
        if (after.passwordIntent === 'replace') {
          const trusted = before.recovery.state === 'complete' ? before.recovery.restorePayload?.password : undefined;
          if (typeof trusted === 'string') current.password = trusted;
        } else { effective.password = current.password; }
      }
      // EntityService inherited updates always stamp their parent's current workspace.
      // A payload carrying only its id is a pure retention marker (e.g. toolbox batch delete keeping
      // unselected children); it has no update for EntityService to inherit-stamp.
      if ((after.entityType === 'credentials' || after.entityType === 'targets') && Object.keys(after.payload).some(key => key !== 'id')) addCreateTags(after, target, effective);
      effective = normalizeEntityPayload(effective, target.schemas, after.entityType, after.credentialKind);
      for (const [key, value] of Object.entries(effective)) if (!Object.hasOwn(current, key) || !equal(current[key], value)) write[key] = value;
      if (after.entityType === 'targets' && !equal(current.target, effective.target)) codes.add('CONFIGURATION_TARGET_ADDRESS_IMMUTABLE');
      if (before.referenceOnly || !before.affected) {
        if (Object.keys(write).length) codes.add('CONFIGURATION_REFERENCE_ONLY_MUTATION');
      }
      if (!Object.keys(write).length) { unchangedCount++; continue; }
      // Real prepareInheritedUpdate always emits the full effective tag set,
      // even for a password-only or weight-only input. Freeze that exact tuple.
      if ((after.entityType === 'credentials' || after.entityType === 'targets') && effective.tags !== undefined) write.tags = structuredClone(effective.tags);
      if (before.recovery.state !== 'complete') codes.add('CONFIGURATION_BEFORE_NOT_RECOVERABLE');
    }
    if (before?.managedBoundary && before.managedBoundary !== 'none') codes.add('CONFIGURATION_MANAGED_BOUNDARY');
    if (before?.recovery.absoluteExpiresAt || before?.payload.ttl !== undefined && before.payload.ttl !== null) codes.add('CONFIGURATION_TTL_APPLY_UNSUPPORTED');
    const known = new Set([...existing.keys(), ...desired.keys()]);
    for (const dependency of after.dependencies) if (!known.has(dependency)) codes.add('CONFIGURATION_REFERENCE_NOT_CAPTURED');
    const patch = compare(current, effective);
    const clearMap = patch.filter(operation => operation.op === 'remove' && operation.path.startsWith('/config/')).map(operation => operation.path);
    append({ objectKey: after.objectKey, entityType: after.entityType, nativeId: after.nativeId, parentType: after.parentType, parentId: after.parentId, credentialKind: after.credentialKind, action: before ? 'update' : 'create', before, after, effectivePayload: effective, writePayload: write, dependencies: after.dependencies, blockerCodes: [...codes].sort(), patch, clearMap });
  }
  if (mode === 'sync' || mode === 'rollback') for (const before of baseline.objects) {
    if (desired.has(before.objectKey) || before.referenceOnly || !before.affected) continue;
    const codes = new Set<string>();
    if (before.recovery.state !== 'complete') codes.add('CONFIGURATION_BEFORE_NOT_RECOVERABLE');
    if (before.managedBoundary && before.managedBoundary !== 'none') codes.add('CONFIGURATION_MANAGED_BOUNDARY');
    if (before.recovery.absoluteExpiresAt || before.payload.ttl !== undefined && before.payload.ttl !== null) codes.add('CONFIGURATION_TTL_APPLY_UNSUPPORTED');
    append({ objectKey: before.objectKey, entityType: before.entityType, nativeId: before.nativeId, parentType: before.parentType, parentId: before.parentId, credentialKind: before.credentialKind, action: 'delete', before, after: null, effectivePayload: null, writePayload: null, dependencies: before.dependencies, blockerCodes: [...codes].sort(), patch: compare(currentPayload(before, baseline), {}), clearMap: [] });
  }
  const deleting = new Set(changes.filter(change => change.action === 'delete').map(change => change.objectKey));
  for (const object of baseline.objects) {
    if (deleting.has(object.objectKey)) continue;
    const dependencies = desired.get(object.objectKey)?.dependencies ?? object.dependencies;
    if (dependencies.some(key => deleting.has(key))) blockers.add('CONFIGURATION_RETAINED_DEPENDENCY_DELETE');
  }
  // Freeze uniqueness across kept objects as well as imported ones (including plugin tuple bindings).
  const final = new Map(baseline.objects.filter(object => !deleting.has(object.objectKey)).map(object => [object.objectKey, currentPayload(object, baseline)]));
  for (const change of changes) if (change.effectivePayload) final.set(change.objectKey, change.effectivePayload);
  const unique = new Set<string>();
  for (const [key, payload] of final) {
    const object = desired.get(key) ?? existing.get(key)!;
    const fields = schemaFields(entitySchema(target.schemas, object.entityType, object.credentialKind));
    for (const [field, definition] of Object.entries(fields)) if (definition.unique === true && payload[field] !== null && payload[field] !== undefined) {
      const identity = `${object.entityType}:${object.credentialKind ?? ''}:${field}:${canonicalJson(payload[field])}`;
      if (unique.has(identity)) blockers.add('CONFIGURATION_UNIQUE_CONFLICT'); unique.add(identity);
    }
    if (object.entityType === 'plugins') {
      const identity = `plugin:${canonicalJson([payload.name, payload.service ?? null, payload.route ?? null, payload.consumer ?? null])}`;
      if (unique.has(identity)) blockers.add('CONFIGURATION_PLUGIN_BINDING_CONFLICT'); unique.add(identity);
    }
    if (object.entityType === 'targets') {
      const identity = `target:${object.parentId}:${canonicalJson(payload.target)}`;
      if (unique.has(identity)) blockers.add('CONFIGURATION_EFFECTIVE_TARGET_CONFLICT'); unique.add(identity);
    }
  }
  return { scope: baseline.scope, mode, baseline, target, changes, unchangedCount, referenceCount: baseline.objects.filter(object => object.referenceOnly).length, blockerCodes: [...blockers].sort(), recoveryComplete: !changes.some(change => change.before && change.before.recovery.state !== 'complete') };
}
