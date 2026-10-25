import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash, randomUUID } from 'node:crypto';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { PortalCredentialsService } from '../../apps/console-api/src/modules/portal/portal-credentials.service';
import { PortalNativeService } from '../../apps/console-api/src/modules/portal/portal-native.service';
import { WorkspaceResolverService } from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import { WorkflowRegistryService } from '../../apps/console-api/src/modules/workflows/workflow-registry.service';
import { publicationProofAad } from '../../apps/console-api/src/modules/portal/portal-proof';
import { validateWorkflowPlan } from '../../apps/console-api/src/modules/workflows/workflow-validation';
import type { WorkflowPlanV1 } from '../../apps/console-api/src/modules/workflows/workflow.types';

// Independent oracle: the Kong transport contract hashes canonical HTTP origin,
// an explicit effective port and a trailing-slash-normalized Admin base path.
const canonicalEndpoint = 'http://kong-portal-admin-endpoint:8001';
const endpointScope = createHash('sha256').update(`${canonicalEndpoint}/`).digest('hex');
function fixture() {
  const cid = randomUUID(), wid = randomUUID(), appId = randomUUID(), publicationId = randomUUID(), developerId = randomUUID(), serviceId = randomUUID(), workflowId = randomUUID(), executionId = randomUUID();
  const secrets = new SecretService(), cluster: any = { id: cid, revision: 1, execution_mode: 'direct', transport_scope: null, status: 'healthy', admin_url: canonicalEndpoint };
  const workspace: any = { id: wid, cluster_id: cid, code: 'review', is_default: false, status: 'active', revision: 1 };
  const application: any = { id: appId, cluster_id: cid, workspace_id: wid, developer_id: developerId, status: 'active', revision: 1 };
  const publication: any = { id: publicationId, cluster_id: cid, workspace_id: wid, service_id: serviceId, state: 'published', published_revision: 2, transport_scope: endpointScope, acl_group: `kos-portal-api-${publicationId}` };
  const schema = (names: string[]) => ({ fields: names.map(name => ({ [name]: { type: name === 'tags' ? 'set' : 'string' } })) });
  const proof: any = { version: 1, clusterId: cid, workspaceId: wid, publicationId, publicationRevision: 2, transportScope: endpointScope, clusterRevision: 1, workspaceRevision: 1, executionMode: 'direct',
    workflowId, executionId, planRevision: 1, planHash: 'a'.repeat(64), verifiedAt: new Date().toISOString(), serviceId, aclGroup: publication.acl_group, aclPluginId: randomUUID(), keyAuthPluginId: randomUUID(),
    service: { id: serviceId, tags: ['kos-ws-review'] }, aclPlugin: {}, keyAuthPlugin: {}, schemas: { consumers: schema(['id', 'username', 'custom_id', 'tags']), acls: schema(['id', 'group', 'tags']), keyAuth: schema(['id', 'key', 'tags']) },
    definitions: { 'portal-credential-issue': { id: randomUUID(), version: 1, policyHash: 'b'.repeat(64) } } };
  const proofRow: any = { cluster_id: cid, workspace_id: wid, publication_id: publicationId, publication_revision: 2, transport_scope: endpointScope, workflow_id: workflowId, workflow_execution_id: executionId, workflow_plan_revision: 1, workflow_plan_hash: proof.planHash };
  const reseal = () => { proofRow.publication_proof_secret = secrets.encrypt(proof, publicationProofAad(cid, wid, publicationId, 2)); proofRow.publication_proof_hmac = secrets.fingerprint(proof); };
  reseal(); let grant: any = null, plan: WorkflowPlanV1 | undefined, sourceTerminal = true;
  const db: any = { one: vi.fn(async (sql: string, params: any[]) => {
    if (sql.includes('FROM portal_applications')) return params[0] === appId && params[1] === cid && params[2] === wid && params[3] === developerId ? application : null;
    if (sql.includes('FROM portal_publications')) return params[0] === publicationId && params[1] === cid && params[2] === wid && publication.state === 'published' ? publication : null;
    if (sql.includes('FROM portal_publication_proofs')) return sourceTerminal && params[0] === publicationId && params[1] === proofRow.publication_revision ? proofRow : null;
    if (sql.includes('FROM clusters')) return params[0] === cid ? cluster : null;
    if (sql.includes('FROM workspaces')) return (params[0] === wid && params[1] === cid) || (params[0] === cid && (params[1] === wid || params[1] === 'review')) ? workspace : null;
    if (sql.includes('FROM portal_application_grants')) return grant;
    throw new Error('Unexpected compiler DB read');
  }), query: vi.fn(async () => []), exec: vi.fn(async (sql: string, params: any[]) => {
    if (sql.startsWith('UPDATE portal_application_grants g SET')) return 0;
    if (sql.startsWith('INSERT INTO portal_application_grants')) grant = { id: params[0], cluster_id: params[1], workspace_id: params[2], transport_scope: params[3], application_id: params[4], publication_id: params[5], developer_id: params[6], consumer_id: params[7], acl_group: params[8], acl_id: params[9], workflow_id: params[10], state: 'pending', current_generation: 0, revision: 1 };
    return 1;
  }) };
  const principal: any = { kind: 'portal_developer', developerId, clusterId: cid, workspaceId: wid, sessionId: randomUUID(), credentialEpoch: 1 };
  const auth: any = { assertCurrent: vi.fn(async () => ({ id: developerId, status: 'active' })), executeMetadata: vi.fn(async (_principal: any, _mutation: any, callback: any) => callback(db, randomUUID())) };
  const kong: any = { request: vi.fn(() => { throw new Error('Compiler must never use native transport'); }), transportScope: vi.fn(() => { throw new Error('Developer may not obtain an actor/system context'); }) };
  const context: any = { runActor: vi.fn(() => { throw new Error('Compiler must not mint a console actor'); }), runInternalRead: vi.fn(() => { throw new Error('Compiler must not use system reads'); }) };
  const plans: any = { persist: vi.fn(async (value: WorkflowPlanV1) => { validateWorkflowPlan(value); plan = structuredClone(value); return { id: value.workflowId, state: 'pending', revision: 1, plan_hash: secrets.fingerprint(value) }; }) };
  const native = new PortalNativeService(db, secrets, kong, context, {} as any, new WorkspaceResolverService(db));
  const service = new PortalCredentialsService(db, secrets, {} as any, { append: vi.fn() } as any, auth, {} as any, {} as any, plans, new WorkflowRegistryService(), native);
  const request = () => service.request(principal, { clusterId: cid, workspaceId: wid, applicationId: appId, publicationId, reason: 'Independent compiler review' }, { idempotencyKey: 'm6-transport-review-original-key' });
  return { request, cluster, workspace, application, publication, proof, proofRow, reseal, db, kong, context, plans, getPlan: () => plan!, sourceTerminal: (value: boolean) => { sourceTerminal = value; } };
}
function noNative(f: ReturnType<typeof fixture>) { expect(f.kong.request).not.toHaveBeenCalled(); expect(f.kong.transportScope).not.toHaveBeenCalled(); expect(f.context.runActor).not.toHaveBeenCalled(); expect(f.context.runInternalRead).not.toHaveBeenCalled(); }
async function rejectedBeforeReservation(f: ReturnType<typeof fixture>, code: string) {
  await expect(f.request()).rejects.toMatchObject({ response: { code } }); noNative(f); expect(f.plans.persist).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
}
beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'de'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());

describe('M6 independent new-registration credential transport proof', () => {
  it('compiles the actual new-cluster NULL transport case without backfill, using the canonical proof scope and approval-required native IDs', async () => {
    const f = fixture(), originalCluster = structuredClone(f.cluster), result: any = await f.request();
    expect(result.approvalRequired).toBe(true); expect(result.state).toBe('pending'); expect(f.cluster).toEqual(originalCluster);
    expect(f.getPlan().scope).toEqual({ transportScope: endpointScope, clusterRevision: 1, workspaceRevision: 1 });
    expect(f.getPlan().approvalRequired).toBe(true); expect(f.getPlan().executionMode).toBe('direct');
    expect(f.getPlan().steps.map(step => [step.entityType, step.credentialKind])).toEqual([['consumers', undefined], ['credentials', 'acls'], ['credentials', 'key-auth'], ['portal_application_grants', undefined]]);
    noNative(f); expect(f.db.exec.mock.calls.some((row: any[]) => /UPDATE\s+clusters/i.test(row[0]))).toBe(false);
    expect(f.db.one.mock.calls.some((row: any[]) => row[0].includes('admin_url') && row[0].includes('FROM clusters'))).toBe(true);
    expect(JSON.stringify(result)).not.toContain(f.getPlan().generated!.key);
  });
  it.each(['http://KONG-PORTAL-ADMIN-ENDPOINT:8001/', 'http://kong-portal-admin-endpoint:8001////'])('uses the same canonical endpoint identity for %s', adminUrl => {
    const f = fixture(); f.cluster.admin_url = adminUrl;
    return f.request().then(() => { expect(f.getPlan().scope.transportScope).toBe(endpointScope); noNative(f); });
  });
  it('honors an explicit registered physical scope without replacing it with an Admin URL digest', async () => {
    const f = fixture(), registered = 'c'.repeat(64); f.cluster.transport_scope = registered; f.proof.transportScope = registered; f.proofRow.transport_scope = registered; f.publication.transport_scope = registered; f.reseal();
    await f.request(); expect(f.getPlan().scope.transportScope).toBe(registered); noNative(f);
  });
  it.each(['http://different-admin:8001', 'https://kong-portal-admin-endpoint:8001', 'http://kong-portal-admin-endpoint:8002', 'http://kong-portal-admin-endpoint:8001/other-base'])('rejects a changed current endpoint %s while transport scope is NULL', async adminUrl => {
    const f = fixture(); f.cluster.admin_url = adminUrl; await rejectedBeforeReservation(f, 'PORTAL_PUBLICATION_REVALIDATION_REQUIRED');
  });
  it('rejects a registered scope mismatch even when URL-derived scope would match the old proof', async () => {
    const f = fixture(); f.cluster.transport_scope = 'f'.repeat(64); await rejectedBeforeReservation(f, 'PORTAL_PUBLICATION_REVALIDATION_REQUIRED');
  });
  it.each(['', 'short', 'A'.repeat(64), '0'.repeat(65)])('fails closed on malformed explicit physical scope rather than falling back: %s', async registered => {
    const f = fixture(); f.cluster.transport_scope = registered; await rejectedBeforeReservation(f, 'INVALID_TRANSPORT_SCOPE');
  });
  it.each(['not-an-admin-url', 'ftp://kong-portal-admin-endpoint:8001', 'http://user:password@kong-portal-admin-endpoint:8001', 'http://kong-portal-admin-endpoint:8001/?query=1'])('rejects malformed or credential-bearing nullable-scope endpoint %s', async adminUrl => {
    const f = fixture(); f.cluster.admin_url = adminUrl; await rejectedBeforeReservation(f, 'INVALID_ADMIN_ENDPOINT');
  });
  it.each(['cluster-revision', 'workspace-revision', 'cluster-disabled', 'workspace-disabled', 'publication-scope', 'proof-null-scope'])('does not relax current revision/status/proof checks: %s', async variant => {
    const f = fixture();
    if (variant === 'cluster-revision') f.cluster.revision = 2;
    if (variant === 'workspace-revision') f.workspace.revision = 2;
    if (variant === 'cluster-disabled') f.cluster.status = 'disabled';
    if (variant === 'workspace-disabled') f.workspace.status = 'disabled';
    if (variant === 'publication-scope') f.publication.transport_scope = 'd'.repeat(64);
    if (variant === 'proof-null-scope') { f.proof.transportScope = null; f.proofRow.transport_scope = null; f.publication.transport_scope = null; f.reseal(); }
    await rejectedBeforeReservation(f, 'PORTAL_PUBLICATION_REVALIDATION_REQUIRED');
  });
  it('still requires an actual published subject and succeeded publication workflow/execution proof', async () => {
    const unpublished = fixture(); unpublished.publication.state = 'draft'; await rejectedBeforeReservation(unpublished, 'PORTAL_PUBLICATION_NOT_FOUND');
    const unknown = fixture(); unknown.sourceTerminal(false); await rejectedBeforeReservation(unknown, 'PORTAL_PUBLICATION_PROOF_UNAVAILABLE');
  });
  it('rejects a tampered proof independently of nullable transport resolution', async () => {
    const f = fixture(); f.proofRow.publication_proof_hmac = '0'.repeat(64); await rejectedBeforeReservation(f, 'PORTAL_PUBLICATION_PROOF_INVALID');
  });
});
