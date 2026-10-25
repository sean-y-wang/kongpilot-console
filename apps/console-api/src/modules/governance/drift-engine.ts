import { createHash } from 'node:crypto';
import { canonicalJson } from '../../infrastructure/secret.service';
import { comparisonFail } from './comparison-types';
import type { ComparisonInventory, DriftFieldChange, DriftObjectChange, DriftOptions, DriftResult, LogicalObject } from './comparison-types';
import { normalizeLogicalGraph, pointerSegment, safeComparisonValue } from './logical-graph';

const equal = (a: unknown, b: unknown): boolean => canonicalJson(a) === canonicalJson(b);
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);

function fields(before: LogicalObject | null, after: LogicalObject | null): DriftFieldChange[] {
  const output: DriftFieldChange[] = [], sensitive = [...new Set([...(before?.sensitiveFields ?? []), ...(after?.sensitiveFields ?? [])])];
  const record = (path: string, action: DriftFieldChange['action'], x: unknown, y: unknown): void => {
    const safeBefore = x === undefined ? undefined : safeComparisonValue(x, path, sensitive), safeAfter = y === undefined ? undefined : safeComparisonValue(y, path, sensitive);
    output.push({ path, action, ...(x === undefined ? {} : { before: safeBefore }), ...(y === undefined ? {} : { after: safeAfter }),
      redacted: x !== undefined && !equal(x, safeBefore) || y !== undefined && !equal(y, safeAfter) });
  };
  const visit = (x: Record<string, unknown>, y: Record<string, unknown>, path = ''): void => {
    for (const name of [...new Set([...Object.keys(x), ...Object.keys(y)])].sort()) {
      const current = `${path}/${pointerSegment(name)}`, hasBefore = Object.hasOwn(x,name), hasAfter = Object.hasOwn(y,name);
      if (!hasBefore) record(current,'add',undefined,y[name]);
      else if (!hasAfter) record(current,'remove',x[name],undefined);
      else if (!equal(x[name],y[name])) {
        if (object(x[name]) && object(y[name])) visit(x[name],y[name],current);
        else record(current,'replace',x[name],y[name]);
      }
    }
  };
  // Output direction describes target -> source, the state Promote would propose.
  visit(after?.payload ?? {}, before?.payload ?? {});
  return output;
}

/** Pure, bidirectional comparison. An incomplete projection cannot evaluate a threshold. */
export function compareLogicalEnvironments(source: ComparisonInventory, target: ComparisonInventory, options: DriftOptions = {}): DriftResult {
  if ((options.sourcePolicy?.includeSecrets || options.targetPolicy?.includeSecrets) && typeof options.fingerprint !== 'function') comparisonFail('GOVERNANCE_KEYED_FINGERPRINT_REQUIRED');
  const threshold = options.threshold ?? { maxChangedObjects: 0 };
  if (!Number.isSafeInteger(threshold.maxChangedObjects) || threshold.maxChangedObjects < 0 || threshold.maxChangedObjects > 10_000
    || threshold.maxChangedFields !== undefined && (!Number.isSafeInteger(threshold.maxChangedFields) || threshold.maxChangedFields < 0 || threshold.maxChangedFields > 100_000)) comparisonFail('GOVERNANCE_DRIFT_THRESHOLD_INVALID');
  const left = normalizeLogicalGraph(source, options.sourcePolicy), right = normalizeLogicalGraph(target, options.targetPolicy);
  const a = new Map(left.objects.map(item => [item.logicalKey,item])), b = new Map(right.objects.map(item => [item.logicalKey,item]));
  const changes: DriftObjectChange[] = [];
  let unchanged = 0;
  for (const key of [...new Set([...a.keys(),...b.keys()])].sort()) {
    const x = a.get(key) ?? null, y = b.get(key) ?? null;
    if (x && y && equal(x.payload,y.payload)) { unchanged++; continue; }
    changes.push({ logicalKey:key, entityType:(x ?? y)!.entityType, action:!y ? 'source_only' : !x ? 'target_only' : 'changed',
      ...(x ? {sourceNativeId:x.nativeId}:{}), ...(y ? {targetNativeId:y.nativeId}:{}), fields:fields(x,y) });
  }
  const compatibleVersion=source.version===target.version&&(source.adapterVersion??'kong-1.5')===(target.adapterVersion??'kong-1.5');
  const complete = left.complete && right.complete && source.scope.kind === target.scope.kind&&compatibleVersion;
  const issues = [...left.issues,...right.issues,...(source.scope.kind !== target.scope.kind ? [{code:'GOVERNANCE_COMPARISON_SCOPE_KIND_MISMATCH'}] : []),...(!compatibleVersion?[{code:'GOVERNANCE_COMPARISON_VERSION_CAPABILITY_MISMATCH'}]:[])];
  const counts = { sourceOnly:changes.filter(item => item.action === 'source_only').length, targetOnly:changes.filter(item => item.action === 'target_only').length,
    changed:changes.filter(item => item.action === 'changed').length, unchanged, changedObjects:changes.length, changedFields:changes.reduce((total,item) => total + item.fields.length,0) };
  const exceeded = complete && (counts.changedObjects > threshold.maxChangedObjects || threshold.maxChangedFields !== undefined && counts.changedFields > threshold.maxChangedFields);
  // The default hash contains only public, redacted diff values. Secret-aware
  // comparison delegates to the server's keyed digest over private material.
  const material = { sourceScope:source.scope, targetScope:target.scope, sourcePolicy:options.sourcePolicy ?? {}, targetPolicy:options.targetPolicy ?? {},
    objects:options.fingerprint ? {source:left.objects.map(({logicalKey,payload})=>({logicalKey,payload})),target:right.objects.map(({logicalKey,payload})=>({logicalKey,payload}))} : changes.map(({sourceNativeId:_s,targetNativeId:_t,...change}) => change) };
  const fingerprint = complete ? (options.fingerprint ? options.fingerprint(material) : createHash('sha256').update(canonicalJson(material)).digest('hex')) : null;
  if (fingerprint !== null && (typeof fingerprint !== 'string' || fingerprint.length > 256 || !/^[\w.-]+$/.test(fingerprint))) comparisonFail('GOVERNANCE_DRIFT_FINGERPRINT_INVALID');
  return { completeness:complete ? 'complete':'incomplete', changes, issues, exclusions:{source:left.exclusions,target:right.exclusions}, counts,
    threshold:{evaluated:complete,exceeded,notify:exceeded && fingerprint !== options.previousFingerprint}, fingerprint };
}
