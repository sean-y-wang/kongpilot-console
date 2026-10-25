import type { ConfigPlan, ConfigurationPlanStep, ConfigurationNativeRequest } from '../configuration/configuration.types';
import { entitySchema, nativeId, schemaFields } from './schema-normalization';
import type { CompileOptions, TransferChange, TransferDiff } from './transfer.types';
import { transferFail } from './transfer.types';

const rank: Record<string, number> = { ca_certificates: 0, certificates: 1, snis: 2, upstreams: 3, targets: 4, services: 5, routes: 6, consumers: 7, plugins: 8, credentials: 9 };
function label(before: Record<string, unknown>, id: string): string {
  return String(before.name || before.username || before.target || before.client_id || id);
}
function path(change: TransferChange, append = false): string {
  if (change.entityType === 'credentials') {
    const base = `/consumers/${nativeId(change.parentId)}/${change.credentialKind}`;
    return change.action === 'create' ? base : `${base}/${nativeId(change.nativeId)}`;
  }
  if (change.entityType === 'targets') {
    const base = `/upstreams/${nativeId(change.parentId)}/targets`;
    return change.action === 'create' || append ? base : `${base}/${nativeId(change.nativeId)}`;
  }
  return change.action === 'create' ? `/${change.entityType}` : `/${change.entityType}/${nativeId(change.nativeId)}`;
}

/** Compiler emits a fixed, frozen DAG. It never authorizes, allocates, sends or retries a packet. */
export function compileTransferDag(diff: TransferDiff, options: CompileOptions): ConfigPlan {
  if (diff.blockerCodes.length || diff.changes.some(change => change.blockerCodes.length)) transferFail('CONFIGURATION_PLAN_BLOCKED');
  if (!diff.recoveryComplete) transferFail('CONFIGURATION_RECOVERY_NOT_COMPLETE');
  if (typeof options.fingerprint !== 'function' || typeof options.redact !== 'function' || !options.sourceManifestHmac || !options.baselineManifestHmac || !Number.isFinite(Date.parse(options.expiresAt))) transferFail('CONFIGURATION_PLAN_BINDING_REQUIRED');
  const changes = new Map(diff.changes.map(change => [change.objectKey, change]));
  if (changes.size !== diff.changes.length) transferFail('CONFIGURATION_DUPLICATE_PLAN_OBJECT');
  const edges = new Map<string, Set<string>>([...changes].map(([key]) => [key, new Set<string>()]));
  const baseline = new Map(diff.baseline.objects.map(object => [object.objectKey, object]));
  for (const change of changes.values()) {
    if (change.before?.referenceOnly || change.before && !change.before.affected) transferFail('CONFIGURATION_REFERENCE_ONLY_MUTATION');
    if (change.action !== 'delete') for (const dependency of change.dependencies) {
      const parentChange = changes.get(dependency);
      if (parentChange?.action === 'delete') transferFail('CONFIGURATION_RETAINED_DEPENDENCY_DELETE');
      if (parentChange) edges.get(change.objectKey)!.add(dependency);
      else if (!baseline.has(dependency)) transferFail('CONFIGURATION_REFERENCE_NOT_CAPTURED');
    }
    if (change.action === 'delete') for (const child of diff.baseline.objects) if (child.dependencies.includes(change.objectKey)) {
      const childChange = changes.get(child.objectKey);
      if (!childChange || childChange.action !== 'delete' && childChange.dependencies.includes(change.objectKey)) transferFail('CONFIGURATION_RETAINED_DEPENDENCY_DELETE');
      edges.get(change.objectKey)!.add(child.objectKey);
    }
  }
  const ordered: TransferChange[] = [], pending = new Set(changes.keys());
  while (pending.size) {
    const ready = [...pending].filter(key => [...edges.get(key)!].every(parent => !pending.has(parent))).sort((a, b) => {
      const x = changes.get(a)!, y = changes.get(b)!;
      const diffRank = (x.action === 'delete' ? -rank[x.entityType] : rank[x.entityType]) - (y.action === 'delete' ? -rank[y.entityType] : rank[y.entityType]);
      return diffRank || (a < b ? -1 : a > b ? 1 : 0);
    });
    if (!ready.length) transferFail('CONFIGURATION_DEPENDENCY_CYCLE');
    for (const key of ready) { pending.delete(key); ordered.push(changes.get(key)!); }
  }
  const stepIds = new Set<string>();
  const steps: ConfigurationPlanStep[] = ordered.map((change, stepOrder) => {
    const stepId = nativeId(options.stepIds[change.objectKey]);
    if (stepIds.has(stepId)) transferFail('CONFIGURATION_DUPLICATE_STEP_ID'); stepIds.add(stepId);
    const appendTarget = change.action === 'update' && change.entityType === 'targets';
    const allocatedId = appendTarget ? nativeId(options.allocatedTargetIds?.[change.objectKey]) : change.action === 'create' ? change.nativeId : null;
    if (appendTarget && (allocatedId === change.nativeId || diff.baseline.objects.some(object => object.entityType === 'targets' && object.nativeId === allocatedId))) transferFail('CONFIGURATION_TARGET_APPEND_ID_REQUIRED');
    const body = change.action === 'delete' ? { confirmed: true, confirm_name: label(change.before!.payload, change.nativeId), parentId: change.parentId ?? undefined, credentialKind: change.credentialKind ?? undefined } : structuredClone(change.writePayload!);
    if (change.action === 'create') {
      if (Object.hasOwn(body, 'id') && body.id !== change.nativeId) transferFail('CONFIGURATION_CREATE_ID_MISMATCH');
      body.id = change.nativeId;
    }
    if (change.entityType === 'targets' || change.entityType === 'credentials') delete body[change.entityType === 'targets' ? 'upstream' : 'consumer'];
    if (Array.isArray(body.tags)) body.tags = [...body.tags.filter(tag => typeof tag === 'string' && !tag.startsWith('kos-ws-')), ...body.tags.filter(tag => typeof tag === 'string' && tag.startsWith('kos-ws-'))];
    if (appendTarget) {
      body.id = allocatedId; body.target = change.effectivePayload!.target; body.weight = change.effectivePayload!.weight;
      if (body.weight === undefined || body.weight === null) transferFail('CONFIGURATION_TARGET_WEIGHT_REQUIRED');
    }
    const nativeBody = change.action === 'delete' ? null : structuredClone(body);
    // The dedicated configuration handler sends this exact full config,
    // including removals; ordinary EntityService deep-merge is not this handler.
    if (change.entityType === 'plugins' && change.action === 'update' && Object.hasOwn(body, 'config')) body.config = nativeBody!.config = structuredClone(change.effectivePayload!.config);
    const deckWirePayload = change.action === 'delete' ? undefined : structuredClone(change.effectivePayload!);
    const deckWireSetFields = deckWirePayload ? Object.entries(schemaFields(entitySchema(diff.baseline.schemas, change.entityType, change.credentialKind)))
      .filter(([key, definition]) => definition.type === 'set' && Object.hasOwn(deckWirePayload, key)).map(([key]) => key).sort() : undefined;
    if (deckWirePayload) {
      deckWirePayload.id = change.nativeId;
      if (Array.isArray(deckWirePayload.tags)) deckWirePayload.tags = [...deckWirePayload.tags.filter(tag => typeof tag === 'string' && !tag.startsWith('kos-ws-')), ...deckWirePayload.tags.filter(tag => typeof tag === 'string' && tag.startsWith('kos-ws-'))];
      if (change.credentialKind === 'basic-auth' && change.action === 'update' && !Object.hasOwn(nativeBody!, 'password')) {
        // Native reads expose a hash, while decK exports trusted recovery
        // plaintext. This proof does not add a native password rewrite.
        const trusted = change.before?.recovery.restorePayload?.password;
        if (typeof trusted !== 'string') delete deckWirePayload.password;
        else deckWirePayload.password = trusted;
      }
    }
    const nativeRequests: ConfigurationNativeRequest[] = [{ method: change.action === 'delete' ? 'DELETE' : change.action === 'create' || appendTarget ? 'POST' : 'PATCH', canonicalPath: path(change, appendTarget), body: nativeBody, bodyHmac: options.fingerprint(nativeBody), beforeHmac: change.before?.beforeHmac ?? options.fingerprint(null) }];
    // Root's dedicated configuration handler uses physical tags directly;
    // ordinary EntityService's logical-tag API is not this execution path.
    return { stepId, stepOrder: stepOrder + 1, objectKey: change.objectKey, entityType: change.entityType, objectWorkspaceId: change.after?.objectWorkspaceId ?? change.before!.objectWorkspaceId, clearMap: [...change.clearMap], nativeId: change.action === 'create' ? null : change.nativeId, allocatedNativeId: allocatedId, parentType: change.parentType, parentId: change.parentId, credentialKind: change.credentialKind, permissionAction: change.action === 'delete' ? 'delete' : 'write', mutationAction: change.action, dependencies: [...edges.get(change.objectKey)!].sort().map(key => options.stepIds[key]), body, before: structuredClone(change.before?.payload ?? null), ...(deckWirePayload ? { deckWirePayload, deckWireSetFields } : {}), bodyHmac: options.fingerprint(body), beforeHmac: change.before?.beforeHmac ?? options.fingerprint(null), nativeRequests, referenceOnly: false, blockerCodes: [], maskedDiff: structuredClone(options.redact(change.patch)) as readonly unknown[] };
  });
  return { scope: structuredClone(diff.scope), mode: diff.mode, steps, sourceManifestHmac: options.sourceManifestHmac, baselineManifestHmac: options.baselineManifestHmac, schemaHmac: diff.baseline.schemaHmac, permissionVersion: diff.baseline.permissionVersion, clusterRevision: diff.baseline.clusterRevision, workspaceRevision: diff.baseline.workspaceRevision, kongVersion: diff.baseline.kongVersion, recoveryComplete: diff.recoveryComplete, expiresAt: options.expiresAt };
}
