import 'reflect-metadata';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { VitalsService } from '../../apps/console-api/src/modules/vitals/vitals.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
const cid = 'ad897cb7-3f50-444b-bc5a-3bd447c989ac', wid = 'e677ed44-ec97-4b10-8779-949068694ed0', namedWid = 'b5c909bb-7dfa-470b-8f9a-01fe91406522', sid = 'fd8c5f36-d82e-4355-8f2d-bc6b665c531a';
const actor = { user: { id: sid, username: 'platform', superAdmin: true }, idempotencyKey: 'setup-complete-123' };
const body = { sourceId: sid, mode: 'collector', confirmed: true, confirm_name: 'fixture-cluster' };
afterEach(() => vi.unstubAllEnvs());
function fixture() {
  const execution = new KongExecutionContextService(), token = 't'.repeat(43), stored: any[] = [];
  const authz: any = { assertCluster: vi.fn(async () => undefined), isPlatformAdmin: vi.fn(async () => true) };
  const db: any = { one: vi.fn(async sql => /FROM (?:mutation_operations|iam_operations)/.test(sql) ? null : ({ id: cid, name: 'fixture-cluster', version: '1.5.1', enabled_plugins: ['prometheus'], execution_mode: 'direct', status: 'healthy', revision: 1 })) };
  const sources: any = { read: vi.fn(async () => ({ id: sid, type: 'prometheus', revision: 1 })), assertCurrent: vi.fn(async () => undefined) };
  const settings: any = { get: vi.fn(async () => ({ revision: 1, collectorEnabled: false, credentialGeneration: 1 })), configure: vi.fn(async () => ({ revision: 2 })) };
  const entities: any = { create: vi.fn(async (_cid, _kind, value, query) => { const entity = { id: sid, ...value, tags: [query.workspaceId] }; stored.push(entity); return { entity }; }), update: vi.fn(async (_cid, _kind, id, value, query) => ({ entity: { id, ...value, tags: [query.workspaceId] } })) };
  const workspaces: any = { resolve: vi.fn(async (_cid, id) => ({ id: id || wid })), classify: vi.fn(async () => ({ state: 'resolved', workspace: { id: namedWid } })) };
  const kong: any = { list: vi.fn(async () => ({ items: [], nextCursor: null })) }, credentials: any = { getActiveIngestCredential: vi.fn(async () => ({ token, generation: 1 })) };
  const metadata: any = { completed: vi.fn(async () => null), execute: vi.fn(async (_context, fn) => fn(db)) };
  vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32));
  const scope: any = { workspace: vi.fn(async (_cid, _actor, id) => id || wid), stable: vi.fn(async () => undefined) };
  authz.permissionVersion = vi.fn(async () => 'p1'); authz.assertEntity = vi.fn(async () => undefined);
  const secrets = new SecretService(), service = new VitalsService(scope, sources, settings, authz, db, {} as any, kong, execution, entities, workspaces, credentials, metadata, secrets);
  const http = (fn: () => Promise<any>) => execution.runHttp({}, async () => { execution.bindHttpActor(actor.user); return fn(); });
  const run = () => http(() => service.setup(cid, { workspaceId: namedWid }, body, actor));
  return { run, http, execution, entities, credentials, sources, metadata, settings, kong, token, stored, db, secrets, service, scope, authz };
}
describe('M5 setup uses normal audited mutation steps and safe durable replay', () => {
  it('creates global monitoring plugins in default workspace and returns no enrollment secrets', async () => {
    const f = fixture(), result = await f.run(); expect(f.entities.create).toHaveBeenCalledTimes(2);
    for (const call of f.entities.create.mock.calls) { expect(call[3]).toEqual({ workspaceId: wid }); expect(call[4].idempotencyKey).toMatch(/^metrics:[a-f\d]{64}$/); expect(call[2].service).toBeUndefined(); }
    expect(f.stored[1].config.http_endpoint).toBe(`http://kongos:${f.token}@telemetry-collector:9093/ingest/${cid}`);
    expect(JSON.stringify(result)).not.toContain(f.token); expect(f.metadata.execute.mock.calls[0][0].payload).toEqual({ sourceId: sid, mode: 'collector', workspaceAnchorId: namedWid, sourceRevision: 1, credentialGeneration: 1 });
  });
  it('updates an existing global plugin at its actual workspace without migrating tags', async () => {
    const f = fixture(); f.kong.list.mockResolvedValue({ items: [{ id: sid, name: 'prometheus', tags: ['existing-workspace'] }], nextCursor: null }); await f.run();
    expect(f.entities.update.mock.calls[0][3]).toEqual({ enabled: true, config: {} }); expect(f.entities.update.mock.calls[0][4]).toEqual({ workspaceId: namedWid });
  });
  it('replays a completed overall setup receipt before any native or token step', async () => {
    const f = fixture(), receipt = { mode: 'collector', sourceId: sid, pluginId: sid, settingsRevision: 2 };
    f.metadata.completed.mockResolvedValue({ result: receipt }); expect(await f.run()).toEqual(receipt);
    expect(f.kong.list).not.toHaveBeenCalled(); expect(f.entities.create).not.toHaveBeenCalled(); expect(f.entities.update).not.toHaveBeenCalled(); expect(f.credentials.getActiveIngestCredential).not.toHaveBeenCalled();
  });
  it('refuses completed replay if the credential family rotated during the completed lookup', async () => {
    const f = fixture(); f.metadata.completed.mockImplementation(async () => { f.settings.get.mockResolvedValue({ revision: 1, collectorEnabled: false, credentialGeneration: 2 }); return { result: { mode: 'collector', sourceId: sid } }; });
    await expect(f.run()).rejects.toMatchObject({ status: 409, response: { code: 'METRICS_GENERATION_CHANGED' } });
    expect(f.kong.list).not.toHaveBeenCalled(); expect(f.entities.create).not.toHaveBeenCalled(); expect(f.entities.update).not.toHaveBeenCalled(); expect(f.credentials.getActiveIngestCredential).not.toHaveBeenCalled(); expect(f.metadata.execute).not.toHaveBeenCalled();
  });
  it('skips an already succeeded create step instead of resending it as update', async () => {
    const f = fixture(), prior: any = { id: sid, entity_type: 'plugins', action: 'create', entity_id: sid, workspace_id: namedWid, state: 'succeeded', remote_completed: true };
    const old = f.db.one.getMockImplementation()!;
    f.db.one.mockImplementation(async (sql, params) => sql.includes('FROM mutation_operations') && params[2] === `metrics:${createHash('sha256').update(`${actor.idempotencyKey}:prometheus`).digest('hex')}` ? prior : old(sql, params));
    f.kong.request = vi.fn(async () => ({ id: sid, name: 'prometheus', enabled: true, config: {}, tags: ['existing'] }));
    await f.run(); expect(f.entities.update).not.toHaveBeenCalled(); expect(f.entities.create.mock.calls).toHaveLength(1); expect(f.entities.create.mock.calls[0][2].name).toBe('http-log');
  });
  it.each(['running', 'uncertain', 'failed'])('does not resend an existing %s native step', async state => {
    const f = fixture(), old = f.db.one.getMockImplementation()!;
    f.db.one.mockImplementation(async (sql, params) => sql.includes('FROM mutation_operations') ? { id: sid, entity_type: 'plugins', action: 'create', state, remote_completed: false } : old(sql, params));
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'METRICS_SETUP_STEP_NOT_TERMINAL', operationId: sid, state: 'uncertain', setupReceipt: true } }); expect(f.entities.create).not.toHaveBeenCalled(); expect(f.entities.update).not.toHaveBeenCalled();
  });
  it('rejects family rotation before committing final settings after native steps', async () => {
    const f = fixture(); f.settings.get.mockResolvedValueOnce({ revision: 1, collectorEnabled: false, credentialGeneration: 1 }).mockResolvedValue({ revision: 1, collectorEnabled: false, credentialGeneration: 2 });
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'METRICS_GENERATION_CHANGED' } }); expect(f.settings.configure).not.toHaveBeenCalled();
  });
  it('keeps a source revision and original workspace in the durable parent payload', async () => {
    const f = fixture(); await f.run(); const context = f.metadata.execute.mock.calls[0][0]; expect(context.workspace_id).toBe(namedWid); expect(context.payload).toMatchObject({ workspaceAnchorId: namedWid, sourceRevision: 1, credentialGeneration: 1 });
  });
  it('returns a partial parent receipt for lost response with safe step IDs and no configuration', async () => {
    const f = fixture(), parent: any = { id: sid, module: 'monitoring', action: 'write', workspace_id: namedWid, state: 'succeeded' };
    parent.payload_secret = f.secrets.encrypt({ workspaceAnchorId: namedWid, sourceId: sid, mode: 'collector', sourceRevision: 1, credentialGeneration: 1 }, `iam:${sid}:payload`);
    f.db.one.mockImplementation(async (sql, params) => sql.includes('FROM iam_operations') && params[2] === `metrics:${createHash('sha256').update(`${actor.idempotencyKey}:parent`).digest('hex')}` ? parent : sql.includes('FROM mutation_operations') && params[2] === `metrics:${createHash('sha256').update(`${actor.idempotencyKey}:prometheus`).digest('hex')}` ? { id: sid, state: 'succeeded', remote_completed: true, workspace_id: wid, entity_type: 'plugins', action: 'create' } : null);
    const result = await f.http(() => f.service.setupReceipt(cid, actor.idempotencyKey, { workspaceId: namedWid }, actor));
    expect(result.parentState).toBe('partial'); expect(result.steps[0]).toMatchObject({ id: sid, state: 'succeeded', workspaceId: wid }); expect(JSON.stringify(result)).not.toContain(f.token); expect(JSON.stringify(result)).not.toContain('sourceRevision');
    await expect(f.http(() => f.service.setupReceipt(cid, actor.idempotencyKey, { workspaceId: wid }, actor))).rejects.toMatchObject({ status: 403 });
  });
  it('has no receipt for another original actor even with the same caller-supplied key', async () => {
    const f = fixture(); f.db.one.mockResolvedValue(null); const result = await f.http(() => f.service.setupReceipt(cid, actor.idempotencyKey, { workspaceId: namedWid }, actor)); expect(result.parentState).toBe('not_sent'); expect(f.db.one.mock.calls[0][1]).toEqual([actor.user.id, cid, expect.any(String)]); expect(result.steps).toEqual([]);
  });
});
