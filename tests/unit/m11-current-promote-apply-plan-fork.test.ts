// @ts-nocheck -- controlled repository/HTTP projections only, never runtime SQL or authority evidence.
import {randomUUID} from 'node:crypto';
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';
import {ConfigurationRepositoryService} from '../../apps/console-api/src/modules/config-storage/configuration-repository.service';
import {SnapshotCryptoService} from '../../apps/console-api/src/modules/config-storage/snapshot-crypto.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {currentPromoteApplyBinding} from '../security/m11-current-promote-natural-http.mjs';

const now = Date.parse('2026-10-15T20:00:00.000Z'), hash = (c = 'a') => c.repeat(64);
beforeEach(() => {vi.useFakeTimers(); vi.setSystemTime(new Date(now)); vi.stubEnv('CONSOLE_ENCRYPTION_KEY', '6'.repeat(64));});
afterEach(() => {vi.unstubAllEnvs(); vi.useRealTimers(); vi.restoreAllMocks();});

function publicFixture() {
  const targetCid = randomUUID(), targetWid = randomUUID(), actorId = randomUUID(), serviceId = randomUUID();
  const importJobId = randomUUID(), applyJobId = randomUUID(), importPlanId = randomUUID(), applyPlanId = randomUUID(), workflowId = randomUUID();
  const expiresAt = new Date(now + 12 * 60000).toISOString(), planHash = hash(), key = randomUUID();
  const g = {sourceCid: randomUUID(), sourceWid: randomUUID(), targetCid, targetWid, fixtures: {target: {nativeId: serviceId}},
    subjects: {admin: {id: actorId}}, importJobId, planId: importPlanId, plan: {id: importPlanId, planRevision: 1, planHash, name: `配置计划 ${importPlanId}`},
    commands: {'apply:register-workflow': {key}}};
  const result = {id: applyJobId, jobId: applyJobId, actorId, clusterId: targetCid, workspaceId: targetWid,
    domain: 'configuration', durable: true, kind: 'apply', planId: applyPlanId, planRevision: 1, planHash,
    workflowId, executionMode: 'approval', approvalRequired: true, state: 'waiting_approval', executionId: null,
    registrationCompleted: true, submissionCompleted: true, executionCompleted: false, idempotencyKey: key,
    originalScope: {clusterId: targetCid, workspaceId: targetWid}};
  const view = (id, jobId, state) => ({entity: {id, planId: id, jobId, planRevision: 1, planHash, clusterId: targetCid,
    workspaceId: targetWid, name: `配置计划 ${id}`, scope: 'services', mode: 'merge', state, revision: 2,
    executionMode: 'approval', approvalRequired: true, expiresAt, stepCount: 1, nativePacketCount: 1, deleteCount: 0,
    recoveryComplete: true, blockers: [], counts: {create: 0, update: 1, delete: 0, conflict: 0}, capabilities: {apply: true}},
  items: [{id: randomUUID(), stepId: randomUUID(), stepOrder: 1, objectKey: `services:${serviceId}`, entityType: 'services',
    objectWorkspaceId: targetWid, nativeId: serviceId, mutationAction: 'update', action: 'update', referenceOnly: false,
    blockerCodes: [], patch: [{op: 'replace', path: '/retries', value: 1}]}], nextCursor: null});
  const workflow = {entity: {id: workflowId, clusterId: targetCid, workspaceId: targetWid, kind: 'configuration_v2',
    state: 'pending', revision: 1, planRevision: 1, planHash: hash('e'), executionMode: 'approval', approvalRequired: true,
    expiresAt, approval: {format: 2, candidateVersion: 1, stages: [{level: 1, revision: 1, state: 'active'}]},
    capabilities: {approve: false, execute: false}}, decisions: [],
  steps: [{id: randomUUID(), name: 'configuration_v2', order: 1, kind: 'metadata', state: 'pending', operationId: null,
    recycleEntryId: null, errorCode: null}],
  impact: {subject: {type: 'configuration_jobs', id: applyJobId}, nativeRequests: 0, rollback: '回收站与执行前受限快照'},
  diff: [{id: randomUUID(), kind: 'metadata', operation: 'configuration_v2', entityType: 'configuration_jobs', entityId: applyJobId,
    before: {id: applyJobId, kind: 'apply'}, after: {jobId: applyJobId}}]};
  workflow.diff[0].id = workflow.steps[0].id;
  return {g, result, observations: {importPlan: view(importPlanId, importJobId, 'ready'), applyPlan: view(applyPlanId, applyJobId, 'pending_approval'), workflow}};
}

/** Real freezePlan/readPlanSummary/listChanges and real AES-GCM run against
 * explicitly controlled SQL, storage-access and origin callbacks. These mocks
 * do not establish actual PostgreSQL locks, private WeakMap authority or native
 * execution. Unexpected repository SQL fails instead of receiving a fake row. */
async function repositoryFixture() {
  const f = publicFixture(), {g} = f, secrets = new SecretService(), crypto = new SnapshotCryptoService(secrets);
  const scope = {clusterId: g.targetCid, workspaceId: g.targetWid, transportScope: hash('b'), kind: 'services', rootIds: [g.fixtures.target.nativeId]};
  const originRef = {version: 1, kind: 'governance-promote', originId: randomUUID(), materialHmac: hash('c')};
  const manifest = {scope, mode: 'merge', sourceManifestHmac: hash('d'), baselineManifestHmac: hash('e'), schemaHmac: hash('f'),
    permissionVersion: 'synthetic-permission-version', clusterRevision: 3, workspaceRevision: 4, kongVersion: '1.5.1', recoveryComplete: true,
    expiresAt: f.observations.importPlan.entity.expiresAt, originRef,
    steps: [{stepId: randomUUID(), stepOrder: 1, objectKey: `services:${g.fixtures.target.nativeId}`, entityType: 'services',
      objectWorkspaceId: g.targetWid, nativeId: g.fixtures.target.nativeId, clearMap: [], permissionAction: 'write', mutationAction: 'update',
      dependencies: [], body: {retries: 1}, before: {id: g.fixtures.target.nativeId, retries: 4}, bodyHmac: hash('a'), beforeHmac: hash('b'),
      nativeRequests: [{method: 'PATCH', canonicalPath: `/services/${g.fixtures.target.nativeId}`, body: {retries: 1}, bodyHmac: hash('a'), beforeHmac: hash('b')}],
      referenceOnly: false, blockerCodes: [], maskedDiff: [{op: 'replace', path: '/retries', value: 1}]}]};
  const jobs = new Map([g.importJobId, f.result.jobId].map((id, index) => [id, {id, actor_id: g.subjects.admin.id,
    cluster_id: scope.clusterId, workspace_id: scope.workspaceId, transport_scope: scope.transportScope, scope_kind: scope.kind,
    root_ids: [...scope.rootIds], kind: index ? 'apply' : 'import', required_origin_kind: originRef.kind,
    required_origin_id: originRef.originId, required_origin_hmac: originRef.materialHmac}]));
  const plans = new Map(), versions = new Map(), materials = new Map(), objects = new Map(), trace = [];
  const tx = {exec: vi.fn(async (sql, p) => {
    trace.push(sql.split(' ').slice(0, 3).join(' '));
    if (sql.startsWith('INSERT INTO configuration_materials(')) {
      materials.set(p[0], {id: p[0], cluster_id: p[1], workspace_id: p[2], job_id: p[3], artifact_id: p[4], artifact_kind: 'plan', wrapped_key_secret: p[5]});
    } else if (sql.startsWith('INSERT INTO configuration_plans(')) {
      plans.set(p[0], {id: p[0], cluster_id: p[1], workspace_id: p[2], transport_scope: p[3], created_by: p[4], source_job_id: p[5],
        mode: p[6], state: 'draft', current_revision: 1, revision: 1});
    } else if (sql.startsWith('INSERT INTO configuration_plan_versions(')) {
      versions.set(p[2], {plan_id: p[2], plan_hash: p[3], source_job_id: p[4], material_id: p[5], artifact_id: p[6], manifest_ciphertext: p[7],
        step_count: p[16], native_packet_count: p[17], delete_count: p[18], recovery_complete: p[19], expires_at: p[20]});
    } else if (sql.startsWith('INSERT INTO configuration_plan_objects(')) {
      objects.set(p[2], [{step_id: p[4], step_order: p[5], object_key: p[6], entity_type: p[7], native_id: p[8], allocated_native_id: p[9],
        parent_type: p[10], parent_id: p[11], credential_kind: p[12], permission_action: p[13], mutation_action: p[14],
        reference_only: p[20], blocker_codes: p[21], masked_diff: JSON.parse(p[22]), object_workspace_id: p[23]}]);
    } else if (sql.startsWith("UPDATE configuration_plans SET state='ready'")) {
      Object.assign(plans.get(p[0]), {state: 'ready', revision: 2});
    } else if (sql.startsWith('UPDATE configuration_jobs SET plan_id=')) {
      Object.assign(jobs.get(p[0]), {plan_id: p[1], plan_revision: 1, plan_hash: p[2]});
    } else throw Error('UNEXPECTED_CONTROLLED_REPOSITORY_WRITE');
    return 1;
  }), one: vi.fn(async (sql, p) => {
    if (sql === 'SELECT * FROM configuration_jobs WHERE id=$1 FOR UPDATE') return structuredClone(jobs.get(p[0]));
    if (sql === 'SELECT * FROM configuration_materials WHERE id=$1') return structuredClone(materials.get(p[0]));
    if (sql.startsWith('SELECT p.*,v.plan_hash,v.step_count')) {
      const row = plans.get(p[2]); expect([p[0], p[1], p[4]]).toEqual([row.cluster_id, row.workspace_id, row.transport_scope]);
      return structuredClone({...row, ...versions.get(p[2])});
    }
    if (sql.startsWith('SELECT cluster_id,workspace_id,transport_scope,scope_kind,root_ids FROM configuration_jobs')) {
      const row = jobs.get(p[2]); expect(p.slice(0, 2)).toEqual([row.cluster_id, row.workspace_id]); return structuredClone(row);
    }
    if (sql.startsWith('SELECT source_job_id FROM configuration_plans')) return {source_job_id: plans.get(p[2]).source_job_id};
    throw Error('UNEXPECTED_CONTROLLED_REPOSITORY_READ');
  }), query: vi.fn(async (sql, p) => {
    expect(sql.startsWith('SELECT step_id,step_order,object_key,entity_type,object_workspace_id')).toBe(true);
    expect(p.slice(0, 2)).toEqual([scope.clusterId, scope.workspaceId]); return structuredClone(objects.get(p[2]));
  })};
  const db = {transaction: vi.fn(async work => work(tx))}, handle = Object.freeze({});
  const access = {assertStorage: vi.fn(async (candidate, input, transaction) => {
    expect(candidate).toBe(handle); expect(transaction).toBe(tx); expect(input.scope).toEqual(scope);
    return {actorId: g.subjects.admin.id, scope, expiresAt: now + 15 * 60000, permissionVersion: manifest.permissionVersion};
  })};
  const origin = {bindJob: vi.fn(), verifyPlan: vi.fn(), beforeFreeze: vi.fn(async (candidate, job, plan, transaction) => {
    expect(candidate).toBe(handle); expect(transaction).toBe(tx); expect(plan).toBe(manifest);
    expect(job.required_origin_id).toBe(plan.originRef.originId);
  }), bindPlan: vi.fn(async (candidate, job, plan, identity, transaction) => {
    expect(candidate).toBe(handle); expect(transaction).toBe(tx); expect(plan).toBe(manifest);
    expect(identity.jobId).toBe(job.id); expect(plans.get(identity.planId).source_job_id).toBe(job.id);
  })};
  const repo = new ConfigurationRepositoryService(db, secrets, crypto, access); repo.installOriginPolicy(origin);
  const imported = await repo.freezePlan(handle, {jobId: g.importJobId, plan: manifest});
  const applied = await repo.freezePlan(handle, {jobId: f.result.jobId, plan: manifest});
  const view = async identity => {
    const summary = await repo.readPlanSummary(handle, {scope, planId: identity.planId});
    const changes = await repo.listChanges(handle, {scope, planId: identity.planId, planRevision: identity.planRevision, planHash: identity.planHash, size: 100});
    return {entity: {...summary, clusterId: scope.clusterId, workspaceId: scope.workspaceId, name: `配置计划 ${identity.planId}`, scope: scope.kind,
      executionMode: 'approval', approvalRequired: true, blockers: [], capabilities: {apply: true}, counts: {create: 0, update: 1, delete: 0, conflict: 0}},
    ...changes, items: changes.items.map(item => ({...item, action: item.mutationAction, patch: item.diff}))};
  };
  f.observations.importPlan = await view(imported); f.observations.applyPlan = await view(applied);
  // Controlled model of createWrapper's SQL state change, not its execution.
  f.observations.applyPlan.entity.state = 'pending_approval';
  g.planId = imported.planId; g.plan = {id: imported.planId, planRevision: imported.planRevision, planHash: imported.planHash, name: `配置计划 ${imported.planId}`};
  Object.assign(f.result, {planId: applied.planId, planRevision: applied.planRevision, planHash: applied.planHash});
  return {...f, repo, imported, applied, manifest, plans, versions, materials, jobs, origin, access, trace};
}

describe('Promote apply owns a new frozen plan rather than reusing the import artifact', () => {
  it('uses real freezePlan twice with the original manifest and public repository projections', async () => {
    const f = await repositoryFixture(), before = JSON.stringify(f.g);
    expect(f.imported.planId).not.toBe(f.applied.planId); expect(f.imported.planHash).toBe(f.applied.planHash);
    expect(f.imported.planRevision).toBe(1); expect(f.applied.planRevision).toBe(1);
    expect(f.plans.get(f.imported.planId).source_job_id).toBe(f.g.importJobId);
    expect(f.plans.get(f.applied.planId).source_job_id).toBe(f.result.jobId);
    expect(f.versions.get(f.imported.planId).material_id).not.toBe(f.versions.get(f.applied.planId).material_id);
    expect(f.versions.get(f.imported.planId).manifest_ciphertext).not.toBe(f.versions.get(f.applied.planId).manifest_ciphertext);
    expect(f.origin.beforeFreeze).toHaveBeenCalledTimes(2); expect(f.origin.bindPlan).toHaveBeenCalledTimes(2);
    const bound = currentPromoteApplyBinding(f.g, f.result, f.observations);
    expect(bound).toEqual({importPlanId: f.imported.planId, applyPlanId: f.applied.planId, applyJobId: f.result.jobId,
      workflowId: f.result.workflowId, planRevision: 1, planHash: f.imported.planHash});
    expect(Object.isFrozen(bound)).toBe(true); expect(JSON.stringify(f.g)).toBe(before);
  });
  it('accepts the actual public wrapper shape without private binding, step metadata or after.planId', () => {
    const f = publicFixture(); expect(f.observations.workflow).not.toHaveProperty('binding');
    expect(f.observations.workflow.steps[0]).not.toHaveProperty('metadata'); expect(f.observations.workflow.diff[0].after).toEqual({jobId: f.result.jobId});
    expect(f.observations.workflow.entity.planHash).not.toBe(f.result.planHash);
    expect(currentPromoteApplyBinding(f.g, f.result, f.observations).applyPlanId).toBe(f.result.planId);
  });
  it('supports the explicit importPlanId alias only when it agrees with the retained original tuple', () => {
    const f = publicFixture(); f.g.importPlanId = f.g.planId;
    expect(currentPromoteApplyBinding(f.g, f.result, f.observations).importPlanId).toBe(f.g.planId);
    f.g.importPlanId = randomUUID(); expect(() => currentPromoteApplyBinding(f.g, f.result, f.observations)).toThrow();
  });
  it.each(['reused-plan', 'reused-job', 'result-id', 'wrong-key', 'wrong-actor', 'direct', 'completed', 'wrong-scope'])('rejects a %s apply receipt before accepting its new IDs', variant => {
    const f = publicFixture();
    if (variant === 'reused-plan') f.result.planId = f.g.planId;
    if (variant === 'reused-job') {f.result.jobId = f.g.importJobId; f.result.id = f.g.importJobId;}
    if (variant === 'result-id') f.result.id = randomUUID();
    if (variant === 'wrong-key') f.result.idempotencyKey = randomUUID();
    if (variant === 'wrong-actor') f.result.actorId = randomUUID();
    if (variant === 'direct') f.result.executionMode = 'direct';
    if (variant === 'completed') f.result.executionCompleted = true;
    if (variant === 'wrong-scope') f.result.originalScope.workspaceId = randomUUID();
    expect(() => currentPromoteApplyBinding(f.g, f.result, f.observations)).toThrow();
  });
  it.each(['import-source-job', 'apply-source-job', 'hash', 'revision', 'expiry', 'foreign-native', 'more-pages'])('rejects an independently read %s mismatch', variant => {
    const f = publicFixture(), {importPlan, applyPlan} = f.observations;
    if (variant === 'import-source-job') importPlan.entity.jobId = f.result.jobId;
    if (variant === 'apply-source-job') applyPlan.entity.jobId = f.g.importJobId;
    if (variant === 'hash') applyPlan.entity.planHash = hash('f');
    if (variant === 'revision') applyPlan.entity.planRevision = 2;
    if (variant === 'expiry') applyPlan.entity.expiresAt = new Date(now + 13 * 60000).toISOString();
    if (variant === 'foreign-native') applyPlan.items[0].nativeId = randomUUID();
    if (variant === 'more-pages') applyPlan.nextCursor = 'synthetic-unread-page';
    expect(() => currentPromoteApplyBinding(f.g, f.result, f.observations)).toThrow();
  });
  it('requires a complete one-Service nondeleting recoverable plan on both sides of the fork', () => {
    for (const side of ['importPlan', 'applyPlan']) for (const field of ['stepCount', 'nativePacketCount', 'deleteCount', 'recoveryComplete']) {
      const f = publicFixture(); f.observations[side].entity[field] = field === 'recoveryComplete' ? false : field === 'deleteCount' ? 1 : 2;
      expect(() => currentPromoteApplyBinding(f.g, f.result, f.observations)).toThrow();
    }
  });
  it('rejects foreign scopes, blockers and an extra changed Service rather than relying on hash alone', () => {
    for (const mutate of [v => {v.entity.clusterId = randomUUID();}, v => {v.entity.workspaceId = randomUUID();},
      v => {v.entity.blockers = ['SYNTHETIC_BLOCKER'];}, v => {v.items[0].blockerCodes = ['SYNTHETIC_BLOCKER'];},
      v => {v.items.push({...v.items[0], nativeId: randomUUID()});}]) {
      const f = publicFixture(); mutate(f.observations.applyPlan);
      expect(() => currentPromoteApplyBinding(f.g, f.result, f.observations)).toThrow();
    }
  });
  it('requires independently observed public wrapper subject/diff to name this exact new apply job', () => {
    for (const mutate of [w => {w.impact.subject.id = randomUUID();}, w => {w.impact.subject.type = 'services';},
      w => {w.diff[0].entityId = randomUUID();}, w => {w.diff[0].after.jobId = randomUUID();},
      w => {w.diff[0].operation = 'configuration-metadata';}, w => {w.impact.nativeRequests = 1;}]) {
      const f = publicFixture(); mutate(f.observations.workflow);
      expect(() => currentPromoteApplyBinding(f.g, f.result, f.observations)).toThrow();
    }
  });
  it('rejects a voted, executed, non-format2 or wrong-scope workflow without manufacturing private fields', () => {
    for (const mutate of [w => {w.decisions.push({decision: 'approve'});}, w => {w.steps[0].operationId = randomUUID();},
      w => {w.steps[0].state = 'succeeded';}, w => {w.entity.approval.format = 1;},
      w => {w.entity.workspaceId = randomUUID();}, w => {w.entity.id = randomUUID();}, w => {w.entity.state = 'approved';}]) {
      const f = publicFixture(); mutate(f.observations.workflow);
      expect(() => currentPromoteApplyBinding(f.g, f.result, f.observations)).toThrow();
    }
  });
});
