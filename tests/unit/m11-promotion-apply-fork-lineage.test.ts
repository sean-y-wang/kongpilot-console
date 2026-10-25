import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { businessAbsenceFixture } from './helpers/workflow-business-absence-fixture';
import { promotionForkFixture } from './helpers/m11-promotion-fork-fixture';

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ca'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());
const fixture = async () => promotionForkFixture(await businessAbsenceFixture());
const rejected = (f: any) => expect(f.compiler.promotionMaterial(f.m, f.db)).rejects.toBeDefined();

describe('Promote original import plan and separately frozen apply plan lineage', () => {
  it('accepts the real fork graph, authenticates both AEAD manifests and retains the original parent identities/deadlines', async () => {
    const f = await fixture(), parent = structuredClone(f.row), decoded = await f.compiler.promotionMaterial(f.m, f.db);
    expect(f.originalJob.id).not.toBe(f.job.id); expect(f.row.plan_id).not.toBe(f.job.plan_id);
    expect(f.parentVersion.plan_hash).toBe(f.childVersion.plan_hash); expect(f.parentVersion.source_job_id).toBe(f.originalJob.id);
    expect(f.childVersion.source_job_id).toBe(f.job.id); expect(f.m.planRow.source_job_id).toBe(f.job.id);
    expect(f.tables.configuration_materials.map((m: any) => m.job_id)).toEqual([f.originalJob.id, f.job.id]);
    expect(decoded.configurationLineage).toEqual({ importJobId: f.originalJob.id, importPlanId: f.row.plan_id,
      authorityExpiresAt: f.originalJob.authority_expires_at, expiresAt: f.originalJob.expires_at, planExpiresAt: f.parentVersion.expires_at });
    expect(decoded.source).toEqual(f.source); expect(f.row).toEqual(parent); expect(f.db.exec).not.toHaveBeenCalled();
    await expect(f.compiler.assertCurrent(f.input)).resolves.toBeUndefined();
  });
  it.each(['configuration_job_id', 'plan_id', 'plan_revision', 'plan_hash'])('rejects a parent %s that does not designate its immutable import anchor', async field => {
    const f = await fixture(); f.row[field] = field === 'plan_revision' ? 99 : field === 'plan_hash' ? '0'.repeat(64) : randomUUID();
    await rejected(f); expect(f.db.exec).not.toHaveBeenCalled();
  });
  it.each(['kind', 'state', 'actor_id', 'cluster_id', 'workspace_id', 'transport_scope', 'idempotency_key', 'required_origin_id', 'required_origin_hmac', 'plan_id', 'scope_kind', 'root_ids'])('rejects a foreign or changed original import %s', async field => {
    const f = await fixture(); f.originalJob[field] = field === 'kind' ? 'apply' : field === 'state' ? 'running' : field === 'required_origin_hmac' ? '0'.repeat(64) : randomUUID();
    await rejected(f); expect(f.db.exec).not.toHaveBeenCalled();
  });
  it.each(['created_by', 'source_job_id', 'transport_scope', 'current_revision'])('keeps the original plan %s attached to its import job', async field => {
    const f = await fixture(), plan = f.tables.configuration_plans[0]; plan[field] = field === 'current_revision' ? 99 : randomUUID(); await rejected(f);
  });
  it.each(['job', 'plan'])('requires both actual original %s Origin bindings rather than accepting the same marker alone', async side => {
    const f = await fixture(), table = side === 'job' ? 'configuration_job_origin_bindings' : 'configuration_plan_origin_bindings';
    f.tables[table] = f.tables[table].filter((row: any) => row.job_id !== f.originalJob.id);
    await rejected(f); expect(f.db.exec).not.toHaveBeenCalled();
  });
  it.each(['origin_id', 'material_hmac', 'source_cluster_id', 'source_workspace_id', 'comparison_id'])('rejects the old job Origin %s being copied from another promotion', async field => {
    const f = await fixture(), binding = f.tables.configuration_job_origin_bindings.find((b: any) => b.job_id === f.originalJob.id);
    binding[field] = field === 'material_hmac' ? '0'.repeat(64) : randomUUID(); await rejected(f);
  });
  it.each(['job_id', 'plan_id', 'plan_revision', 'plan_hash', 'origin_id', 'material_hmac'])('rejects the old plan Origin %s mismatch', async field => {
    const f = await fixture(), binding = f.tables.configuration_plan_origin_bindings.find((b: any) => b.job_id === f.originalJob.id);
    binding[field] = field === 'plan_revision' ? 99 : ['plan_hash', 'material_hmac'].includes(field) ? '0'.repeat(64) : randomUUID(); await rejected(f);
  });
  it.each(['apply', 'rollback', 'reconcile'])('only the actual distinct apply job can continue, refusing changed %s graph', async kind => {
    const f = await fixture();
    if (kind === 'apply') f.m.job.id = f.row.configuration_job_id; else f.m.job.kind = kind;
    await rejected(f);
  });
  it.each(['job', 'plan', 'material', 'version'])('refuses a missing original %s rather than falling back to child identifiers', async kind => {
    const f = await fixture(), table = { job: 'configuration_jobs', plan: 'configuration_plans', material: 'configuration_materials', version: 'configuration_plan_versions' }[kind]!;
    const value = kind === 'job' ? f.originalJob : kind === 'plan' ? f.tables.configuration_plans[0] : kind === 'material' ? f.parentMaterial : f.parentVersion;
    f.tables[table] = f.tables[table].filter((row: any) => row !== value); await rejected(f);
  });
  it.each(['source_job_id', 'input_hmac', 'steps_hmac', 'schema_hmac', 'source_manifest_hmac', 'baseline_manifest_hmac', 'expires_at'])('keeps original plan version %s unchanged across the fork', async field => {
    const f = await fixture(); f.parentVersion[field] = field === 'expires_at' ? new Date(Date.parse(f.parentVersion.expires_at) + 1000).toISOString() : '0'.repeat(64);
    await rejected(f);
  });
  it.each(['parent-ciphertext', 'parent-material-job', 'parent-wrapped-key', 'child-input-aad', 'child-input-missing'])('authenticates actual %s with its own original AEAD identity', async failure => {
    const f = await fixture();
    if (failure === 'parent-ciphertext') f.parentVersion.manifest_ciphertext = f.childVersion.manifest_ciphertext;
    else if (failure === 'parent-material-job') f.parentMaterial.job_id = f.job.id;
    else if (failure === 'parent-wrapped-key') f.parentMaterial.wrapped_key_secret = f.tables.configuration_materials[1].wrapped_key_secret;
    else if (failure === 'child-input-aad') f.m.job.input_secret = f.secrets.encrypt(f.applyInput, `configuration-job:${f.originalJob.id}`);
    else f.m.job.input_secret = null;
    await rejected(f); expect(f.db.exec).not.toHaveBeenCalled();
  });
  it.each(['planId', 'planRevision', 'planHash', 'driver', 'confirmed', 'confirm_deletes', 'extra'])('requires exact authenticated child apply request %s pointing to the old import plan', async field => {
    const f = await fixture();
    if (field === 'planRevision') f.applyInput[field] = 2;
    else if (field === 'confirmed') f.applyInput[field] = false;
    else if (field === 'confirm_deletes') f.applyInput[field] = 'false';
    else if (field === 'driver') f.applyInput[field] = 'deck';
    else f.applyInput[field] = randomUUID();
    f.bindInput(); f.m.job = structuredClone(f.job); await rejected(f);
  });
  it('requires the original request HMAC even if re-encrypted payload is structurally plausible', async () => {
    const f = await fixture(); f.m.job.request_hmac = '0'.repeat(64); await rejected(f);
  });
  it.each(['authority_expires_at', 'expires_at'])('never revives the old import %s through a new child deadline', async field => {
    const f = await fixture(); f.originalJob[field] = new Date(Date.now() - 1000).toISOString(); await rejected(f);
  });
  it('keeps the business window capped by the earlier import authority even when the child plan is still live', async () => {
    const f = await fixture(); f.originalJob.expires_at = new Date(Date.now() + 1000).toISOString();
    await expect(f.compiler.assertCurrent(f.input)).rejects.toMatchObject({ response: { code: 'WORKFLOW_BUSINESS_OLD_DEADLINE_NOT_RENEWABLE' } });
    expect(f.db.exec).not.toHaveBeenCalled();
  });
});
