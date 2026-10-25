import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { ENTITIES } from '../../apps/console-api/src/infrastructure/kong/policy';
import { approvedNativePacketScope, KongExecutionContextService, type KongExecutionFrame } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { assertWorkspaceMigrationWorkflowPlan, migrationNativeRequests } from '../../apps/console-api/src/modules/workflows/workspace-migration-workflow';
import { validateWorkflowPlan } from '../../apps/console-api/src/modules/workflows/workflow-validation';
import type { WorkflowPlanV1 } from '../../apps/console-api/src/modules/workflows/workflow.types';

// These are independent plan and execution-context invariant tests. Explicit
// synthetic policy hooks do not establish live SQL, RBAC or gateway evidence.
const credentialKinds = ['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'] as const;
const digest = 'a'.repeat(64);

function fixture() {
  const secrets = new SecretService(), subjectId = randomUUID(), sourceId = randomUUID(), targetId = randomUUID();
  const before = { id: subjectId, workspace_id: sourceId };
  const payload = { plan_id: subjectId, plan_hash: digest, confirmed: true, confirm_name: '目标工作区' };
  const serviceId = randomUUID(), consumerId = randomUUID(), credentialId = randomUUID();
  const body = { tags: ['team-pay', 'kos-ws-target'] };
  const request = (nativeType: string, nativeId: string, parentId?: string) => ({
    method: 'PATCH' as const,
    canonicalPath: parentId ? `/consumers/${parentId}/${nativeType}/${nativeId}` : `/${nativeType}/${nativeId}`,
    nativeType, nativeId, ...(parentId ? { parentId, credentialKind: nativeType } : {}),
    body: structuredClone(body), bodyHmac: secrets.fingerprint(body), beforeHmac: digest,
  });
  const plan = {
    version: 1, clusterId: randomUUID(), workspaceId: sourceId, workflowId: randomUUID(), planRevision: 1,
    kind: 'workspace-migration', executionMode: 'approval', approvalRequired: true,
    subject: { type: 'workspace_migration_plans', id: subjectId }, requester: { type: 'console', id: randomUUID() },
    definition: { id: randomUUID(), version: 1, policyHash: digest },
    issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString(),
    scope: { transportScope: digest, clusterRevision: 1, workspaceRevision: 1 },
    migration: { sourceWorkspaceId: sourceId, targetWorkspaceId: targetId, targetWorkspaceRevision: 1, materialHmac: digest },
    prerequisites: [],
    steps: [{ id: randomUUID(), key: 'workspace-migration', order: 1, kind: 'native', entityType: 'workspace_migration',
      entityId: subjectId, permissionAction: 'write', dependencies: [], mutationAction: 'migrate',
      mutationPayload: payload, mutationPayloadHmac: secrets.fingerprint(payload), mutationIdempotencyKey: `migration-${randomUUID()}`,
      before, beforeFingerprint: secrets.fingerprint(before),
      nativeRequests: [request('services', serviceId), request('consumers', consumerId), request('key-auth', credentialId, consumerId)] }],
  } as unknown as WorkflowPlanV1 & { migration: { sourceWorkspaceId: string; targetWorkspaceId: string; targetWorkspaceRevision: number; materialHmac: string } };
  return { plan, secrets, request, sourceId, targetId, subjectId, serviceId, consumerId, credentialId };
}

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'cf'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());

describe('M9 sealed workspace migration plan', () => {
  it('accepts an exact multi-packet tag migration without changing normal workflow validation', () => {
    const f = fixture();
    expect(assertWorkspaceMigrationWorkflowPlan(f.plan)).toBe(f.plan.steps[0]);
    expect(() => validateWorkflowPlan(f.plan)).not.toThrow();
  });

  it('accepts all eight root types and all six Consumer credential kinds', () => {
    const f = fixture();
    f.plan.steps[0].nativeRequests = [...ENTITIES.map(type => f.request(type, randomUUID())),
      ...credentialKinds.map(type => f.request(type, randomUUID(), f.consumerId))];
    expect(() => assertWorkspaceMigrationWorkflowPlan(f.plan)).not.toThrow();
    expect(() => validateWorkflowPlan(f.plan)).not.toThrow();
  });

  it('compiles credential tags only and omits inherited Targets without exposing native secrets', () => {
    const f = fixture(), targetId = randomUUID(), upstreamId = randomUUID();
    const nodes = [
      { type: 'consumers', id: f.consumerId, path: `/consumers/${f.consumerId}`, beforeFingerprint: digest,
        afterTags: ['kos-ws-target'], inheritedOnly: false, data: { username: 'client' } },
      { type: 'key-auth', id: f.credentialId, path: `/consumers/${f.consumerId}/key-auth/${f.credentialId}`,
        beforeFingerprint: digest, afterTags: ['kos-ws-target'], inheritedOnly: false, data: { key: 'private-captured-key' } },
      { type: 'targets', id: targetId, path: `/upstreams/${upstreamId}/targets/${targetId}`,
        beforeFingerprint: digest, afterTags: ['kos-ws-source'], inheritedOnly: true, data: { target: 'backend:8080' } },
    ];
    const packets = migrationNativeRequests({ nodes } as any, f.secrets);
    expect(packets).toHaveLength(2);
    expect(packets[1]).toMatchObject({ canonicalPath: nodes[1].path, nativeId: f.credentialId,
      nativeType: 'key-auth', parentId: f.consumerId, credentialKind: 'key-auth', beforeHmac: digest,
      body: { tags: ['kos-ws-target'] }, bodyHmac: f.secrets.fingerprint({ tags: ['kos-ws-target'] }) });
    expect(packets.every(packet => packet.method === 'PATCH' && Object.keys(packet.body as object).join(',') === 'tags')).toBe(true);
    expect(JSON.stringify(packets)).not.toContain('private-captured-key');
    expect(nodes[1].data.key).toBe('private-captured-key');
  });

  it('accepts the maximum 32 write packets and rejects 65 prerequisites before execution', () => {
    const f = fixture(); f.plan.steps[0].nativeRequests = Array.from({ length: 32 }, () => f.request('services', randomUUID()));
    expect(() => validateWorkflowPlan(f.plan)).not.toThrow();
    f.plan.prerequisites = Array.from({ length: 65 }, () => {
      const id = randomUUID(), before = { id, tags: ['kos-ws-source'] };
      return { type: 'services', id, path: `/services/${id}`, before, fingerprint: f.secrets.fingerprint(before) };
    });
    expect(() => validateWorkflowPlan(f.plan)).toThrow();
  });

  it('permits exact bounded root, Consumer credential and inherited Target reference paths', () => {
    const f = fixture();
    f.plan.prerequisites = [...ENTITIES, ...credentialKinds, 'targets'].map(type => {
      const id = randomUUID(), parent = randomUUID(), root = (ENTITIES as readonly string[]).includes(type);
      const before = { id, tags: ['kos-ws-source'], ...(!root ? type === 'targets' ? { upstream: { id: parent } } : { consumer: { id: parent } } : {}) };
      const path = root ? `/${type}/${id}` : type === 'targets' ? `/upstreams/${parent}/targets/${id}` : `/consumers/${parent}/${type}/${id}`;
      return { type, id, path, before, fingerprint: f.secrets.fingerprint(before) };
    });
    expect(() => assertWorkspaceMigrationWorkflowPlan(f.plan)).not.toThrow();
  });

  it.each([
    ['extra reference field', (r: any) => { r.allowWrite = true; }],
    ['missing before', (r: any) => { delete r.before; }],
    ['null before', (r: any) => { r.before = null; }],
    ['array before', (r: any) => { r.before = []; }],
    ['wrong before ID', (r: any) => { r.before.id = randomUUID(); }],
    ['non-UUID ID', (r: any) => { r.id = r.before.id = 'service-name'; r.path = '/services/service-name'; }],
    ['wrong native type', (r: any) => { r.type = 'routes'; }],
    ['wrong path ID', (r: any) => { r.path = `/services/${randomUUID()}`; }],
    ['wrong fingerprint format', (r: any) => { r.fingerprint = 'public-sha'; }],
    ['cache read', (r: any) => { r.type = 'cache'; r.path = '/cache/private'; }],
    ['future-version path', (r: any) => { r.type = 'vaults'; r.path = `/vaults/${r.id}`; }],
    ['relationship path', (r: any) => { r.path = `/routes/${r.id}/service`; }],
    ['embedded query', (r: any) => { r.path += '?size=100'; }],
    ['trailing slash', (r: any) => { r.path += '/'; }],
    ['encoded ID', (r: any) => { r.path = '/services/%2e%2e'; }],
  ] as const)('rejects a prerequisite containing %s', (_name, change) => {
    const f = fixture(), id = randomUUID();
    const reference = { type: 'services', id, path: `/services/${id}`, before: { id }, fingerprint: digest };
    change(reference); f.plan.prerequisites = [reference];
    expect(() => assertWorkspaceMigrationWorkflowPlan(f.plan)).toThrow();
  });

  it.each(['credential', 'Target'])('rejects a prerequisite with a different %s parent', kind => {
    const f = fixture(), id = randomUUID(), parent = randomUUID();
    const reference = kind === 'credential'
      ? { type: 'key-auth', id, path: `/consumers/${parent}/key-auth/${id}`, before: { id, consumer: { id: randomUUID() } }, fingerprint: digest }
      : { type: 'targets', id, path: `/upstreams/${parent}/targets/${id}`, before: { id, upstream: { id: randomUUID() } }, fingerprint: digest };
    f.plan.prerequisites = [reference];
    expect(() => assertWorkspaceMigrationWorkflowPlan(f.plan)).toThrow();
  });

  it.each(['duplicate', 'native overlap'])('rejects %s prerequisite paths', reason => {
    const f = fixture(), id = reason === 'native overlap' ? f.serviceId : randomUUID();
    const reference = { type: 'services', id, path: `/services/${id}`, before: { id }, fingerprint: digest };
    f.plan.prerequisites = reason === 'duplicate' ? [reference, structuredClone(reference)] : [reference];
    expect(() => assertWorkspaceMigrationWorkflowPlan(f.plan)).toThrow();
  });

  it.each([
    ['foreign kind', (p: any) => { p.kind = 'portal-publication'; }],
    ['foreign subject', (p: any) => { p.subject.type = 'portal_publications'; }],
    ['developer requester', (p: any) => { p.requester.type = 'developer'; }],
    ['direct execution mode', (p: any) => { p.executionMode = 'direct'; }],
    ['approval omitted', (p: any) => { p.approvalRequired = false; }],
    ['second logical step', (p: any) => { p.steps.push({ ...p.steps[0], id: randomUUID(), order: 2 }); }],
    ['missing logical step', (p: any) => { p.steps = []; }],
    ['metadata step', (p: any) => { p.steps[0].kind = 'metadata'; }],
    ['foreign entity type', (p: any) => { p.steps[0].entityType = 'services'; }],
    ['foreign entity ID', (p: any) => { p.steps[0].entityId = randomUUID(); }],
    ['foreign action', (p: any) => { p.steps[0].mutationAction = 'update'; }],
    ['foreign step key', (p: any) => { p.steps[0].key = 'native-operation'; }],
    ['delete permission', (p: any) => { p.steps[0].permissionAction = 'delete'; }],
    ['step handler', (p: any) => { p.steps[0].handler = 'toolbox.execute'; }],
    ['root parent ID', (p: any) => { p.steps[0].parentId = randomUUID(); }],
    ['root credential kind', (p: any) => { p.steps[0].credentialKind = 'key-auth'; }],
    ['logical dependency', (p: any) => { p.steps[0].dependencies = [randomUUID()]; }],
    ['generated credential', (p: any) => { p.generated = { key: 'forbidden-secret' }; }],
    ['metadata body', (p: any) => { p.steps[0].metadata = { arbitrary: true }; }],
    ['metadata revision', (p: any) => { p.steps[0].metadataRevision = 1; }],
    ['metadata before hash', (p: any) => { p.steps[0].metadataBeforeHmac = digest; }],
    ['metadata payload hash', (p: any) => { p.steps[0].metadataPayloadHmac = digest; }],
    ['missing migration scope', (p: any) => { delete p.migration; }],
    ['foreign source workspace', (p: any) => { p.migration.sourceWorkspaceId = randomUUID(); }],
    ['same source and target', (p: any) => { p.migration.targetWorkspaceId = p.workspaceId; }],
    ['invalid target ID', (p: any) => { p.migration.targetWorkspaceId = 'foreign'; }],
    ['invalid target revision', (p: any) => { p.migration.targetWorkspaceRevision = 0; }],
    ['invalid material digest', (p: any) => { p.migration.materialHmac = 'public-hash'; }],
    ['extra migration field', (p: any) => { p.migration.skipPermissions = true; }],
    ['foreign payload plan ID', (p: any) => { p.steps[0].mutationPayload.plan_id = randomUUID(); }],
    ['unconfirmed payload', (p: any) => { p.steps[0].mutationPayload.confirmed = false; }],
    ['empty confirmation', (p: any) => { p.steps[0].mutationPayload.confirm_name = ''; }],
    ['invalid plan hash', (p: any) => { p.steps[0].mutationPayload.plan_hash = 'public-sha'; }],
    ['extra mutation field', (p: any) => { p.steps[0].mutationPayload.allowCrossWorkspace = true; }],
    ['foreign before ID', (p: any) => { p.steps[0].before.id = randomUUID(); }],
    ['foreign before workspace', (p: any) => { p.steps[0].before.workspace_id = randomUUID(); }],
    ['extra before field', (p: any) => { p.steps[0].before.tags = []; }],
  ] as const)('rejects %s', (_name, change) => {
    const { plan } = fixture(); change(plan);
    expect(() => assertWorkspaceMigrationWorkflowPlan(plan)).toThrow();
    expect(() => validateWorkflowPlan(plan)).toThrow();
  });

  it.each([
    ['POST', (r: any) => { r.method = 'POST'; }],
    ['DELETE', (r: any) => { r.method = 'DELETE'; }],
    ['PUT', (r: any) => { r.method = 'PUT'; }],
    ['cache endpoint', (r: any) => { r.canonicalPath = '/cache/anything'; }],
    ['foreign version endpoint', (r: any) => { r.canonicalPath = '/vaults/secret'; }],
    ['collection path', (r: any) => { r.canonicalPath = '/services'; }],
    ['nested relationship path', (r: any) => { r.canonicalPath = `/routes/${randomUUID()}/service`; }],
    ['Target patch', (r: any) => { r.canonicalPath = `/upstreams/${randomUUID()}/targets/${r.nativeId}`; r.nativeType = 'targets'; }],
    ['query embedded in path', (r: any) => { r.canonicalPath += '?size=100'; }],
    ['trailing slash', (r: any) => { r.canonicalPath += '/'; }],
    ['encoded path ID', (r: any) => { r.canonicalPath = '/services/%2e%2e'; }],
    ['foreign native type', (r: any) => { r.nativeType = 'routes'; }],
    ['foreign native ID', (r: any) => { r.nativeId = randomUUID(); }],
    ['root parent binding', (r: any) => { r.parentId = randomUUID(); }],
    ['root credential binding', (r: any) => { r.credentialKind = 'key-auth'; }],
    ['secret mutation', (r: any) => { r.body.key = 'unaudited-key'; }],
    ['missing tags', (r: any) => { r.body = {}; }],
    ['empty tags', (r: any) => { r.body.tags = []; }],
    ['duplicate tags', (r: any) => { r.body.tags.push(r.body.tags[0]); }],
    ['non-string tag', (r: any) => { r.body.tags.push(0); }],
    ['missing physical workspace tag', (r: any) => { r.body.tags = ['team-pay']; }],
    ['multiple physical workspace tags', (r: any) => { r.body.tags.push('kos-ws-second'); }],
    ['logical workspace tag', (r: any) => { r.body.tags = ['workspace:target']; }],
    ['invalid before digest', (r: any) => { r.beforeHmac = 'unknown'; }],
    ['missing before digest', (r: any) => { delete r.beforeHmac; }],
    ['invalid body digest', (r: any) => { r.bodyHmac = 'unknown'; }],
    ['extra request field', (r: any) => { r.skipBefore = true; }],
  ] as const)('rejects a packet containing %s', (_name, change) => {
    const { plan } = fixture(); change(plan.steps[0].nativeRequests[0]);
    expect(() => assertWorkspaceMigrationWorkflowPlan(plan)).toThrow();
  });

  it.each(['parent mismatch', 'kind mismatch', 'missing parent', 'missing kind'])('rejects credential %s', reason => {
    const { plan } = fixture(), request = plan.steps[0].nativeRequests[2];
    if (reason === 'parent mismatch') request.parentId = randomUUID();
    if (reason === 'kind mismatch') request.credentialKind = 'jwt';
    if (reason === 'missing parent') delete request.parentId;
    if (reason === 'missing kind') delete request.credentialKind;
    expect(() => assertWorkspaceMigrationWorkflowPlan(plan)).toThrow();
  });

  it.each(['empty', 'duplicate', 'over budget'])('rejects %s native manifests', reason => {
    const f = fixture();
    if (reason === 'empty') f.plan.steps[0].nativeRequests = [];
    if (reason === 'duplicate') f.plan.steps[0].nativeRequests.push(structuredClone(f.plan.steps[0].nativeRequests[0]));
    if (reason === 'over budget') f.plan.steps[0].nativeRequests = Array.from({ length: 33 }, () => f.request('services', randomUUID()));
    expect(() => assertWorkspaceMigrationWorkflowPlan(f.plan)).toThrow();
  });

  it('preserves the generic plan prohibition on migration authority and multiple packets', () => {
    const f = fixture();
    (f.plan as any).kind = 'portal-publication'; (f.plan as any).subject.type = 'portal_publications';
    expect(() => validateWorkflowPlan(f.plan)).toThrow();
    delete (f.plan as any).migration;
    f.plan.steps[0].entityType = 'services'; f.plan.steps[0].mutationAction = 'update';
    expect(() => validateWorkflowPlan(f.plan)).toThrow();
  });
});

describe('M9 migration packet identity in the private execution context', () => {
  const identityFixture = (kind = 'workspace_migration', action = 'migrate') => {
    const actor = { id: randomUUID(), username: 'migration-test', superAdmin: false }, workspaceId = randomUUID();
    return { actor, workspaceId, frame: { kind: 'operation', actor, sessionId: 'synthetic-session', workspaceId,
      operation: { actor, clusterId: randomUUID(), workspaceId, operationId: randomUUID(), entityType: kind, action },
      limits: { maxCalls: 10, maxPages: 1, maxRecords: 1, maxBytes: 10000, timeoutMs: 5000 } } as KongExecutionFrame };
  };

  it.each(credentialKinds)('derives the actual %s Consumer from the exact canonical packet', kind => {
    const { frame, workspaceId } = identityFixture(), parentId = randomUUID();
    expect(approvedNativePacketScope(frame, 'PATCH', `/consumers/${parentId}/${kind}/${randomUUID()}`))
      .toEqual({ workspaceId, parentId, credentialKind: kind });
  });

  it.each(ENTITIES)('keeps %s root packets anchored to the source workspace without a parent', type => {
    const { frame, workspaceId } = identityFixture();
    expect(approvedNativePacketScope(frame, 'PATCH', `/${type}/${randomUUID()}`))
      .toEqual({ workspaceId, parentId: undefined, credentialKind: undefined });
  });

  it.each([
    ['POST', `/services/${randomUUID()}`],
    ['PATCH', '/services'],
    ['PATCH', `/upstreams/${randomUUID()}/targets/${randomUUID()}`],
    ['PATCH', `/consumers/${randomUUID()}/key-auth/${randomUUID()}?offset=foreign`],
    ['PATCH', `/consumers/${randomUUID()}/key-auth/${randomUUID()}/`],
    ['PATCH', `/consumers/${randomUUID()}/credentials/${randomUUID()}`],
    ['PATCH', `/services/${randomUUID()}/routes`],
    ['PATCH', `/SERVICES/${randomUUID()}`],
    ['PATCH', '/cache/key'],
  ])('rejects a non-migration packet %s %s', (method, path) => {
    expect(() => approvedNativePacketScope(identityFixture().frame, method, path)).toThrow();
  });

  it.each(['action', 'parent', 'kind', 'workspace'])('rejects a conflicting logical migration %s', field => {
    const { frame } = identityFixture();
    if (field === 'action') (frame.operation as any).action = 'update';
    if (field === 'parent') (frame.operation as any).parentId = randomUUID();
    if (field === 'kind') (frame.operation as any).credentialKind = 'jwt';
    if (field === 'workspace') (frame.operation as any).workspaceId = randomUUID();
    expect(() => approvedNativePacketScope(frame, 'PATCH', `/services/${randomUUID()}`)).toThrow();
  });

  it('keeps ordinary entity packet parent and credential identity unchanged', () => {
    const { frame, workspaceId } = identityFixture('credentials', 'update'), parentId = randomUUID();
    Object.assign(frame.operation!, { parentId, credentialKind: 'key-auth' });
    expect(approvedNativePacketScope(frame, 'PATCH', `/consumers/${randomUUID()}/jwt/${randomUUID()}`))
      .toEqual({ workspaceId, parentId, credentialKind: 'key-auth' });
  });

  it('uses the same source and nested identity in authorize, prepare, before-send and response checks', async () => {
    const context = new KongExecutionContextService(), actor = { id: randomUUID(), username: 'migration-test', superAdmin: false };
    const clusterId = randomUUID(), workspaceId = randomUUID(), operationId = randomUUID(), parentId = randomUUID(), credentialId = randomUUID();
    const cluster = { id: clusterId, admin_url: 'http://kong:8001', execution_mode: 'approval', version: '1.5.1' };
    const before = { id: credentialId, consumer: { id: parentId }, tags: ['kos-ws-source'] };
    const proof = Object.freeze({ executionId: randomUUID(), workflowId: randomUUID(), clusterId, workspaceId,
      actorId: actor.id, sessionId: 'synthetic-session', permissionVersion: 'epoch-1', expiresAt: Date.now() + 60_000 });
    const stepId = randomUUID();
    const approved: any = { verifyExecution: vi.fn(async () => proof),
      verifyStep: vi.fn(async () => Object.freeze({ execution: proof, stepId, kind: 'native' })),
      mutationBinding: vi.fn(), bindOperation: vi.fn(), assertNative: vi.fn(), assertMetadata: vi.fn() };
    context.installPolicy({ authorizeRequest: async () => ({ before }), authorizeResponse: async (_ticket, result) => result });
    context.installApprovedPolicy(approved);
    await context.runHttp({ requestId: 'migration-context-test' }, async () => {
      context.bindHttpActor(actor, 'synthetic-session'); const close = context.captureHttpCloser();
      try {
        await context.runActor({ actor, clusterId, workspaceId, module: 'workspaces', action: 'write' }, () =>
          context.runApprovedWorkflow(Object.freeze({}) as any, () => context.runApprovedStep(stepId, () =>
            context.runOperation({ actor, clusterId, workspaceId, operationId, entityType: 'workspace_migration', action: 'migrate' }, async () => {
              const ticket = await context.authorizeRequest(cluster, 'PATCH', `/consumers/${parentId}/key-auth/${credentialId}`, { tags: ['kos-ws-target'] }, {});
              await context.assertApprovedNativeRequest(ticket, 'authorize');
              await context.assertApprovedNativeRequest(ticket, 'prepare');
              await context.beforeNativeSend(ticket);
              await context.authorizeResponse(ticket, { ...before, tags: ['kos-ws-target'] });
            }))));
      } finally { close(); }
    });
    expect(approved.assertNative.mock.calls.map(call => call[2])).toEqual(['authorize', 'prepare', 'before-send', 'before-send', 'response']);
    for (const [, input] of approved.assertNative.mock.calls) expect(input).toMatchObject({
      workspaceId, parentId, credentialKind: 'key-auth', operationId, mutationAction: 'migrate', before,
    });
  });
});
