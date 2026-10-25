import { randomUUID } from 'node:crypto';
import { expect } from 'vitest';
import { SnapshotCryptoService } from '../../../apps/console-api/src/modules/config-storage/snapshot-crypto.service';
import { ConfigurationOriginService } from '../../../apps/console-api/src/modules/configuration/configuration-origin.service';
import { governanceComparisonEnvelope } from '../../../apps/console-api/src/modules/governance/governance-comparison-material';
import { transportScopeFor } from '../../../apps/console-api/src/infrastructure/kong/transport-scope';

/** Actual two independent AEAD plan materials and actual configurationMaterial
 * decoding, over exact scoped SQL doubles. No live DB, timer or transport. */
export async function promotionForkFixture(f: any): Promise<any> {
  const sourceCid = randomUUID(), sourceWid = randomUUID(), sourceObjectId = randomUUID(), promotionId = randomUUID(), comparisonId = randomUUID();
  const created = new Date(Date.now() - 60000).toISOString(), srcTransport = transportScopeFor('http://kong-dev:8001', null);
  const inventory = (source: boolean): any => ({ id: randomUUID(), scope: { clusterId: source ? sourceCid : f.cid, workspaceId: source ? sourceWid : f.wid,
    kind: 'workspace', rootIds: [], transportScope: source ? srcTransport : f.plan.scope.transportScope },
    objects: source ? [{ entityType: 'services', nativeId: sourceObjectId, payload: { id: sourceObjectId, name: 'fixture-source', host: 'echo', tags: ['workspace:default'] },
      objectWorkspaceId: sourceWid, sensitiveFields: [] }] : [], schemas: { services: { fields: [] } }, pluginSchemas: {}, enabledPlugins: ['key-auth'], version: '1.5.1',
    coverage: { services: { state: 'complete', extent: 'workspace', eof: true, pages: 1, records: source ? 1 : 0, reasonCodes: [] } }, completeness: 'complete', projection: false,
    consistency: 'console_fenced_best_effort', observedFrom: created, observedUntil: created, usage: { calls: 2, pages: 1, records: source ? 1 : 0, bytes: 100 }, reasonCodes: [] });
  const source = inventory(true), target = inventory(false), selection = { targetWorkspaceCode: 'default', includeSecrets: false, includeCredentials: false };
  const sourceEnvelope = governanceComparisonEnvelope(source, { [`services:${sourceObjectId}`]: f.secrets.fingerprint({ id: sourceObjectId, name: 'fixture-source', host: 'echo', tags: ['kos-ws-default'] }) });
  const targetEnvelope = governanceComparisonEnvelope(target, {}), parentJobId = randomUUID(), parentPlanId = randomUUID();
  const comparison: any = { id: comparisonId, cluster_id: sourceCid, workspace_id: sourceWid, target_cluster_id: f.cid, target_workspace_id: f.wid,
    quality: 'complete', source_inventory_secret: f.secrets.encrypt(sourceEnvelope, `governance:comparison-source:${comparisonId}`),
    target_inventory_secret: f.secrets.encrypt(targetEnvelope, `governance:comparison-target:${comparisonId}`), source_inventory_hmac: f.secrets.fingerprint(sourceEnvelope),
    target_inventory_hmac: f.secrets.fingerprint(targetEnvelope), policy: selection, policy_hmac: f.secrets.fingerprint(selection) };
  const row: any = { id: promotionId, cluster_id: sourceCid, workspace_id: sourceWid, comparison_id: comparisonId, target_cluster_id: f.cid, target_workspace_id: f.wid,
    actor_id: f.actor, request_hmac: 'f'.repeat(64), selection_secret: f.secrets.encrypt(selection, `governance:promotion-selection:${promotionId}`),
    selection_hmac: f.secrets.fingerprint(selection), source_inventory_hmac: comparison.source_inventory_hmac, target_inventory_hmac: comparison.target_inventory_hmac,
    state: 'ready', configuration_job_id: parentJobId, plan_id: parentPlanId, plan_revision: 1, plan_hash: f.job.plan_hash };
  f.tables.governance_promotions = [row]; f.tables.governance_comparisons = [comparison]; f.tables.promotion_recovery_bindings = [];
  const originalOne = f.db.one.getMockImplementation();
  f.db.one.mockImplementation(async (sql: string, args: any[] = []) => {
    if (sql === 'SELECT * FROM configuration_job_origin_bindings WHERE cluster_id=$1 AND workspace_id=$2 AND job_id=$3') {
      expect(args).toHaveLength(3); return f.tables.configuration_job_origin_bindings.find((r: any) => r.cluster_id === args[0] && r.workspace_id === args[1] && r.job_id === args[2]) ?? null;
    }
    if (sql === 'SELECT * FROM configuration_plan_origin_bindings WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4 AND plan_hash=$5') {
      expect(args).toHaveLength(5); return f.tables.configuration_plan_origin_bindings.find((r: any) => r.cluster_id === args[0] && r.workspace_id === args[1]
        && r.plan_id === args[2] && r.plan_revision === args[3] && r.plan_hash === args[4]) ?? null;
    }
    if (sql === 'SELECT * FROM governance_comparisons WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3')
      return f.tables.governance_comparisons.find((r: any) => r.id === args[0] && r.cluster_id === args[1] && r.workspace_id === args[2]) ?? null;
    return originalOne(sql, args);
  });
  const origin = new ConfigurationOriginService(f.db, f.secrets, {} as any), loaded = await (origin as any).load(promotionId, f.db);
  f.nested.originRef = loaded.ref;
  f.job.plan_hash = f.secrets.fingerprint(f.nested); f.job.state = 'waiting_approval'; row.plan_hash = f.job.plan_hash;
  Object.assign(f.job, { required_origin_kind: loaded.ref.kind, required_origin_id: promotionId, required_origin_hmac: loaded.ref.materialHmac });
  const originalJob: any = { ...structuredClone(f.job), id: parentJobId, kind: 'import', state: 'succeeded', origin_session_id: randomUUID(),
    idempotency_key: `governance-promote-${promotionId}`, plan_id: parentPlanId, workflow_id: null, approval_required: false,
    expires_at: new Date(Date.parse(f.nested.expiresAt) - 5000).toISOString(), authority_expires_at: new Date(Date.parse(f.nested.expiresAt) - 5000).toISOString() };
  f.tables.configuration_jobs.push(originalJob);
  const applyInput: any = { planId: parentPlanId, planRevision: 1, planHash: row.plan_hash, driver: 'bff', confirmed: true, confirm_deletes: false };
  const bindInput = () => { f.job.input_secret = f.secrets.encrypt(applyInput, `configuration-job:${f.job.id}`);
    f.job.request_hmac = f.secrets.fingerprint({ scope: f.nested.scope, kind: f.job.kind, input: applyInput, originRef: loaded.ref }); };
  bindInput();
  f.tables.configuration_plans = []; f.tables.configuration_plan_versions = []; f.tables.configuration_materials = []; f.tables.configuration_plan_objects = [];
  const crypto = new SnapshotCryptoService(f.secrets);
  const freeze = async (job: any): Promise<void> => {
    const identity = { clusterId: f.cid, workspaceId: f.wid, jobId: job.id, materialId: randomUUID(), artifactId: randomUUID(), artifactKind: 'plan' as const };
    const wrapped = crypto.createWrappedKey(identity), common = { cluster_id: f.cid, workspace_id: f.wid }, hash = f.secrets.fingerprint(f.nested);
    const material = { ...common, id: identity.materialId, job_id: job.id, artifact_id: identity.artifactId, artifact_kind: 'plan', wrapped_key_secret: wrapped, state: 'available' };
    f.tables.configuration_materials.push(material);
    f.tables.configuration_plans.push({ ...common, id: job.plan_id, created_by: job.actor_id, source_job_id: job.id, current_revision: 1, transport_scope: job.transport_scope });
    await crypto.withKey(identity, wrapped, async key => {
      f.tables.configuration_plan_versions.push({ ...common, plan_id: job.plan_id, plan_revision: 1, plan_hash: hash, input_hmac: hash, source_job_id: job.id,
        material_id: identity.materialId, artifact_id: identity.artifactId, steps_hmac: f.secrets.fingerprint(f.nested.steps), schema_hmac: f.nested.schemaHmac,
        source_manifest_hmac: f.nested.sourceManifestHmac, baseline_manifest_hmac: f.nested.baselineManifestHmac, step_count: f.nested.steps.length,
        native_packet_count: f.nested.steps.reduce((n: number, s: any) => n + s.nativeRequests.length, 0), recovery_complete: true,
        manifest_ciphertext: crypto.encrypt(key, identity, { section: 'manifest', key: 'plan' }, f.nested), created_at: created, expires_at: f.nested.expiresAt });
      for (const s of f.nested.steps) f.tables.configuration_plan_objects.push({ ...common, plan_id: job.plan_id, plan_revision: 1, plan_hash: hash,
        step_id: s.stepId, step_order: s.stepOrder, object_workspace_id: s.objectWorkspaceId, entity_type: s.entityType, mutation_action: s.mutationAction,
        body_hmac: s.bodyHmac, before_hmac: s.beforeHmac, reference_only: false, blocker_codes: [], dependencies: s.dependencies,
        native_id: s.nativeId, allocated_native_id: s.allocatedNativeId, parent_id: s.parentId, credential_kind: s.credentialKind,
        payload_ciphertext: crypto.encrypt(key, identity, { section: 'plan-step', key: s.stepId, entityType: s.entityType, nativeId: s.nativeId ?? s.allocatedNativeId,
          parentId: s.parentId ?? null, credentialKind: s.credentialKind ?? null }, s),
        native_requests: s.nativeRequests.map((r: any) => ({ method: r.method, path_hmac: f.secrets.fingerprint(r.canonicalPath), body_hmac: r.bodyHmac, before_hmac: r.beforeHmac })) });
    });
    f.tables.configuration_job_origin_bindings.push({ ...common, job_id: job.id, origin_kind: loaded.ref.kind, origin_id: promotionId, material_hmac: loaded.ref.materialHmac,
      source_cluster_id: sourceCid, source_workspace_id: sourceWid, comparison_id: comparisonId });
    f.tables.configuration_plan_origin_bindings.push({ ...common, plan_id: job.plan_id, plan_revision: 1, plan_hash: hash, job_id: job.id,
      origin_kind: loaded.ref.kind, origin_id: promotionId, material_hmac: loaded.ref.materialHmac });
  };
  await freeze(originalJob); await freeze(f.job);
  Object.assign(f.plan.steps[0].metadata, { planHash: row.plan_hash }); f.plan.steps[0].metadataPayloadHmac = f.secrets.fingerprint(f.plan.steps[0].metadata); f.persist();
  f.tables.clusters.push({ ...f.cluster, id: sourceCid, admin_url: 'http://kong-dev:8001' });
  f.tables.workspaces.push({ ...f.workspace, id: sourceWid, cluster_id: sourceCid });
  const grant = (action: string) => ({ user_id: f.actor, module: 'promote', action, cluster_id: null, workspace_id: null, scope_type: 'global', scope_values: [] });
  f.tables.iam_effective_grants.push(grant('read'), grant('write')); f.input.principal.grants = structuredClone(f.tables.iam_effective_grants);
  const m = structuredClone(await f.compiler.configurationMaterial(f.job.id, f.db));
  f.input.draft.binding.subjectSeal = m.subjectSeal; f.input.draft.binding.workflowPlanHash = f.secrets.fingerprint(f.plan);
  const parentVersion = f.tables.configuration_plan_versions.find((v: any) => v.plan_id === parentPlanId), childVersion = f.tables.configuration_plan_versions.find((v: any) => v.plan_id === f.job.plan_id);
  const parentMaterial = f.tables.configuration_materials.find((v: any) => v.id === parentVersion.material_id);
  return { ...f, m, source, target, row, comparison, sourceCid, sourceWid, sourceObjectId, loaded, originalJob, parentVersion, childVersion, parentMaterial, applyInput, bindInput };
}
