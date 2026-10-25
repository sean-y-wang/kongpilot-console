import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { configurationSelection, configurationPath, configurationReceiptPath, configurationReceiptResult, configurationQueryIdentity, configurationConfirmation, configurationDetailEntity, safeConfigurationValue, gitOpsMetadata, sameConfigurationIdentity, snapshotScheduleUpdate, basicPasswordIntentMap, configurationDownloadIntent, configurationSelectionQuery, configurationReconcileResult } from '../../apps/console-web/src/features/m8.model';
import { uploadConfiguration } from '../../apps/console-web/src/features/m8.upload';
import { safeRecoveryReferences } from '../../apps/console-web/src/api/workspace-scope';
import { currentCursor, nextCursorPage } from '../../apps/console-web/src/features/m7.cursor';

const cid = 'f5b9aef6-1900-4698-a66c-c8e7bc173766', wid = '15e68b33-3572-4f42-9896-544978d57d0f', actor = 'af5a7db5-2f84-47c0-98e9-e3635efec9b6', other = '9a6b81b9-e3b4-4880-9388-707f9f36ef30', id = '211d1b33-421d-41fa-963d-9e4563e87416', key = '8c993049-0086-4a53-9659-2e24b0a9cd98';
const identity = { actor, version: 'current:3', cid, wid }, ref = { kind: 'configuration', clusterId: cid, workspaceId: wid, idempotencyKey: key };
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('M8 safe scope, Diff, source material and original-key policy', () => {
  it('rejects missing/foreign anchors and uses original configuration key without current fallback', () => {
    expect(configurationReceiptPath(ref)).toBe(`/clusters/${cid}/configuration/jobs/by-key/${key}?workspaceId=${wid}`);
    expect(configurationPath(identity, 'snapshots', { size: '20', scope: 'cluster' })).toContain(`workspaceId=${wid}`);
    for (const change of [{ workspaceId: undefined }, { clusterId: undefined }, { idempotencyKey: 'https://kong:8001' }, { kind: 'vaults' }]) expect(() => configurationReceiptPath({ ...ref, ...change })).toThrow();
    for (const resource of ['configuration/../services', 'https://kong:8001', 'configuration?token=unsafe', 'snapshots#token']) expect(() => configurationPath(identity, resource)).toThrow();
    expect(() => configurationPath(identity, 'snapshots', { workspaceId: other })).toThrow();
  });
  it('validates exact Service roots, actual comma GET parsing and cached cursor authority', async () => {
    expect(configurationSelection({ scope: 'services', serviceIds: [other, id] }).serviceIds).toEqual([id, other]);
    const { ConfigurationController } = await import('../../apps/console-api/src/modules/configuration/configuration.controller');
    const controller = Object.create(ConfigurationController.prototype);
    for (const serviceIds of [[id], [other, id]]) { const filters = configurationSelectionQuery({ scope: 'services', serviceIds }), query = Object.assign(Object.create(null), filters, { workspaceId: wid }); expect((controller as any).q(query, ['scope', 'serviceIds']).serviceIds).toEqual([...serviceIds].sort()); }
    expect(configurationSelectionQuery({ scope: 'cluster', serviceIds: [] })).toEqual({ scope: 'cluster' });
    expect(() => (controller as any).q({ serviceIds: [id] }, ['scope', 'serviceIds'])).toThrow();
    for (const selection of [{ scope: 'services', serviceIds: [] }, { scope: 'workspace', serviceIds: [id] }, { scope: 'services', serviceIds: [id, id] }, { scope: 'services', serviceIds: ['invalid'] }]) expect(() => configurationSelection(selection as any)).toThrow();
    const original = configurationQueryIdentity(identity, 'snapshots', { scope: 'workspace' }), state = nextCursorPage({ key: original, page: 0, cursors: [undefined] }, 'server-cursor');
    for (const change of [{ actor: other }, { version: 'current:4' }, { cid: other }, { wid: other }]) expect(currentCursor(state, configurationQueryIdentity({ ...identity, ...change }, 'snapshots', { scope: 'workspace' })).page).toBe(0);
    expect(currentCursor(state, configurationQueryIdentity(identity, 'snapshots', { scope: 'services' })).page).toBe(0); expect(sameConfigurationIdentity(identity, { ...identity, wid: other })).toBe(false);
  });
  it('normalizes actual unmounted FormStore Service fields only for workspace or cluster scope', async () => {
    const { FormStore } = await import('rc-field-form/lib/useForm');
    for (const scope of ['workspace', 'cluster', 'services'] as const) {
      const form = new FormStore(() => {}).getForm(), hooks = form.getInternalHooks('RC_FORM_INTERNAL_HOOKS');
      hooks.setInitialValues({ scope, serviceIds: [], name: 'memory-only-form' }, true);
      for (const name of ['scope', 'name']) hooks.registerField({ props: {}, getNamePath: () => [name], onStoreChange: () => {}, isListField: () => false, getMeta: () => ({ touched: false }) } as any);
      const values = await form.validateFields(); expect(values).not.toHaveProperty('serviceIds');
      if (scope === 'services') expect(() => configurationSelection(values as any)).toThrow();
      else expect(configurationSelection(values as any)).toEqual({ scope, serviceIds: [] });
    }
    for (const scope of ['workspace', 'cluster', 'services']) for (const serviceIds of [null, 'not-an-array', { 0: id }, 1]) expect(() => configurationSelection({ scope, serviceIds } as any)).toThrow();
    expect(() => configurationSelection({ scope: 'services', serviceIds: [] })).toThrow(); expect(configurationSelection({ scope: 'services', serviceIds: [id] })).toEqual({ scope: 'services', serviceIds: [id] });
  });
  it('uses the actual schedule summary and preserves every policy binding when toggling pause', async () => {
    const { ConfigurationRepositoryService } = await import('../../apps/console-api/src/modules/config-storage/configuration-repository.service');
    const repository = new ConfigurationRepositoryService({} as any, {} as any, {} as any, {} as any);
    const summary = (repository as any).scheduleSummary({ id, cluster_id: cid, workspace_id: wid, name: 'hourly', owner_user_id: actor, state: 'active', revision: 3, current_version: 2, scope_kind: 'services', root_ids: [other], interval_minutes: 60, timezone: 'UTC', retention_days: 30, next_run_at: '2026-10-11T12:00:00.000Z', created_at: '2026-10-11T10:00:00.000Z', updated_at: '2026-10-11T11:00:00.000Z' });
    expect(snapshotScheduleUpdate(summary, true)).toEqual({ scope: 'services', serviceIds: [other], name: 'hourly', intervalMinutes: 60, timezone: 'UTC', retentionDays: 30, revision: 3, paused: true, confirmed: true, confirm_name: 'hourly' });
    expect(summary).not.toHaveProperty('rule'); expect(summary).not.toHaveProperty('workerState');
    expect(() => snapshotScheduleUpdate({ ...summary, state: 'deleted' }, false)).toThrow();
  });
  it('preserves false/zero/null/missing and nested Diff values while hiding escaped secret fields', () => {
    expect(safeConfigurationValue({ path: '/config/enabled' }, false)).toBe('false'); expect(safeConfigurationValue({ path: '/weight' }, 0)).toBe('0'); expect(safeConfigurationValue({ path: '/path' }, null)).toBe('null'); expect(safeConfigurationValue({ path: '/path' }, undefined)).toBe('（字段缺失）');
    expect(safeConfigurationValue({ path: '/config' }, [{ record: { value: false } }])).toContain('false');
    const connection = safeConfigurationValue({ path: '/config/http_endpoint' }, { endpoints: ['https://user:synthetic-password@fixture.invalid/hook'] });
    expect(connection).toContain('https://REDACTED@fixture.invalid/hook'); expect(connection).not.toContain('synthetic-password');
    expect(safeConfigurationValue({ path: '/config/http_endpoint' }, 'http://broken:synthetic-password@[invalid@')).toBe('"[REDACTED]"');
    for (const path of ['/config/client_secret', '/config/a~1b/password', '/key']) expect(safeConfigurationValue({ path }, 'must-not-render')).not.toContain('must-not-render');
    expect(safeConfigurationValue({ path: '/safe', secret: true, secretChange: 'preserved' }, 'never')).toBe('保留现有值'); expect(safeConfigurationValue({ path: '/bad~7' }, 'never')).toBe('[字段路径无效]');
  });
  it('requires exact plan/delete confirmations and safe GitOps metadata without token URLs', () => {
    const plan = { revision: 3, planRevision: 2, planHash: 'a'.repeat(64), name: 'approved-diff', deleteCount: 5, deleteConfirmName: 'DELETE 5' };
    expect(configurationConfirmation(plan, plan.name, 'DELETE 5')).toMatchObject({ confirmed: true, confirm_deletes: true, planRevision: 2 });
    for (const value of [undefined, 'DELETE', 'DELETE 4']) expect(() => configurationConfirmation(plan, plan.name, value)).toThrow(); expect(() => configurationConfirmation(plan, 'wrong', 'DELETE 5')).toThrow();
    expect(gitOpsMetadata({ repositoryLabel: 'payments/config', commitSha: 'F'.repeat(40), pipelineReference: 'build/42', jobId: id }).commitSha).toBe('f'.repeat(40));
    for (const pipelineReference of ['https://example/pipeline?token=never', 'git@example:private', 'build/42#never', 'token=never', 'ssh://private/build', 'secret:never', 'authorization:never', 'api_key:never']) expect(() => gitOpsMetadata({ repositoryLabel: 'safe', commitSha: 'a'.repeat(40), pipelineReference, jobId: id })).toThrow();
  });
  it('unpacks only the actual entity envelope and exact authority tuple without reflective error text', () => {
    const entity = { id, clusterId: cid, workspaceId: wid, name: 'safe-summary' };
    expect(configurationDetailEntity({ entity, items: ['not-retained'], capabilities: { apply: true, download: 'yes' } }, identity, id)).toEqual({ ...entity, capabilities: { apply: true } });
    for (const value of ['private-yaml-never-error', { entity: 'private-yaml-never-error' }, { entity: { ...entity, clusterId: other } }, { entity: { ...entity, workspaceId: other } }, { entity: { ...entity, id: other } }]) {
      expect(() => configurationDetailEntity(value, identity, id)).toThrow();
      try { configurationDetailEntity(value, identity, id); } catch (error) { expect((error as Error).message).not.toContain('private-yaml'); }
    }
  });
  it('reads the actual service receipt producer and distinguishes registration, approval, execution and foreign proofs', async () => {
    const { ConfigurationService } = await import('../../apps/console-api/src/modules/configuration/configuration.service');
    let workflowId: string | null = null;
    const service = Object.assign(Object.create(ConfigurationService.prototype), { failureLedger: { abandonmentIntent: async () => null }, access: { description: async () => ({ actor: { id: actor }, scope: { clusterId: cid, workspaceId: wid } }) }, db: { one: async (sql: string) => sql.includes('FROM configuration_exports') ? { revision: 8, state: 'ready', material_state: 'available', expires_at: new Date(Date.now() + 600000) } : ({ idempotency_key: key, actor_id: actor, plan_id: null, workflow_id: workflowId, execution_mode: workflowId ? 'approval' : 'direct', approval_required: !!workflowId }) } });
    const job = { id, clusterId: cid, workspaceId: wid, kind: 'apply', revision: 1, state: 'running', safeProgress: {}, errorCode: null, createdAt: '2026-10-11T00:00:00.000Z', completedAt: null };
    const prove = async (patch: Record<string, unknown> = {}) => service.jobProjection({}, { ...job, ...patch });
    const expected = { ...ref, actorId: actor };
    expect(configurationReceiptResult(await prove(), expected)).toMatchObject({ complete: false, pending: true });
    workflowId = other; expect(configurationReceiptResult(await prove({ state: 'waiting_approval' }), expected)).toMatchObject({ complete: true, workflowId: other, success: true });
    for (const state of ['uncertain', 'partial']) expect(configurationReceiptResult(await prove({ state }), expected).complete).toBe(false); workflowId = null;
    expect(configurationReceiptResult(await prove({ state: 'succeeded' }), expected)).toMatchObject({ complete: true, success: true });
    const imported = await prove({ kind: 'import', state: 'succeeded' }); expect(configurationReceiptResult(imported, expected).label).toContain('未执行网关变更');
    expect(configurationReceiptResult(await prove({ state: 'failed' }), expected)).toMatchObject({ complete: true, success: false });
    for (const foreign of [{ actorId: other }, { clusterId: other }, { workspaceId: other }, { idempotencyKey: other }]) expect(configurationReceiptResult(imported, { ...expected, ...foreign }).complete).toBe(false);
    expect(configurationReceiptResult({ ...imported, state: 'uncertain' }, expected).complete).toBe(false);
    const exported = await prove({ kind: 'export', state: 'succeeded', revision: 3, safeProgress: { exportId: other, exportRevision: 8, format: 'deck-1.1', confirmationName: 'source-name' } });
    expect(configurationDownloadIntent(exported.job)).toEqual({ id: other, revision: 8, name: 'source-name', format: 'deck-1.1' });
    for (const patch of [{ exportRevision: undefined }, { exportRevision: 0 }, { state: 'running' }, { confirmationName: null }, { capabilities: { download: false } }]) expect(configurationDownloadIntent({ ...exported.job, ...patch })).toBeUndefined();
    expect(configurationDownloadIntent((await prove({ kind: 'export', state: 'succeeded', safeProgress: { ...exported.job.safeProgress, downloadPermitConsumed: true } })).job)).toBeUndefined();
  });
  it('reads actual reconcile observations without proving or advancing the original write outcome', async () => {
    const { ConfigurationService } = await import('../../apps/console-api/src/modules/configuration/configuration.service');
    const plan = { id, stepCount: 2 }, job = { id: other, clusterId: cid, workspaceId: wid, kind: 'reconcile', revision: 1, state: 'running', safeProgress: {}, errorCode: null, createdAt: '2026-10-11T00:00:00.000Z', completedAt: null };
    const packet = vi.fn(async (_cid: string, method: string, path: string) => { expect(method).toBe('GET'); return path.startsWith('/services/') ? { id: other, retries: 0 } : { id, enabled: false, privateMaterial: 'never-return' }; });
    const summary = { revision: 3, planRevision: 2, planHash: 'a'.repeat(64), workspaceId: wid }, source = { scope_kind: 'workspace', root_ids: [] };
    const service = Object.assign(Object.create(ConfigurationService.prototype), {
      withActor: async (_cid: string, _actor: unknown, permission: string, fn: () => Promise<unknown>) => { expect(permission).toBe('read'); return fn(); }, plan: async () => ({ entity: summary }),
      db: { one: async (sql: string) => sql.includes('JOIN configuration_jobs') ? source : { idempotency_key: key, actor_id: actor, plan_id: id, workflow_id: null, execution_mode: 'direct', approval_required: false } },
      newJob: async () => ({ handle: {}, job, scope: { kind: 'workspace', rootIds: [], clusterId: cid, workspaceId: wid } }),
      repo: { readPlan: async () => ({ steps: [{ stepId: id, mutationAction: 'update', entityType: 'services', nativeId: other, body: { retries: 0 } }, { stepId: other, mutationAction: 'create', entityType: 'plugins', allocatedNativeId: id, body: { enabled: false } }] }) },
      assertPlanGrants: vi.fn(), access: { runRead: async (_handle: unknown, _roots: unknown, fn: () => Promise<unknown>) => fn(), assertObject: vi.fn(), description: async () => ({ actor: { id: actor }, scope: { clusterId: cid, workspaceId: wid } }) }, kong: { request: packet },
      finish: async (_handle: unknown, _id: string, state: string, safeProgress: unknown) => ({ ...job, state, safeProgress })
    });
    const receipt = await service.reconcilePlan(cid, id, { revision: 3, planHash: summary.planHash }, { user: { id: actor }, idempotencyKey: key, workspaceId: wid });
    const expected = { ...ref, actorId: actor }, result = configurationReconcileResult(receipt, expected, plan);
    expect(result.jobId).toBe(other); expect(result.observations).toHaveLength(2); expect(result.observations.every(row => row.causalOutcomeUnproven && row.expectedFieldsMatch)).toBe(true); expect(JSON.stringify(result)).not.toContain('never-return'); expect(packet).toHaveBeenCalledTimes(2);
    expect(receipt.job.safeProgress).toMatchObject({ readOnly: true, executionChanged: false });
    expect(receipt.state).toBe('succeeded'); expect(receipt.executionCompleted).toBe(true);
    for (const state of ['pending', 'running']) {
      const initial = await service.jobProjection({}, { ...job, state });
      expect(configurationReceiptResult(initial, expected)).toMatchObject({ complete: true, success: true });
      expect(initial.executionCompleted).toBe(false); expect(() => configurationReconcileResult(initial, expected, plan)).toThrow();
      const staleObservations = await service.jobProjection({}, { ...job, state, safeProgress: receipt.job.safeProgress });
      expect(configurationReceiptResult(staleObservations, expected)).toMatchObject({ complete: true, success: true });
      expect(() => configurationReconcileResult(staleObservations, expected, plan)).toThrow();
    }
    for (const state of ['uncertain', 'partial', 'failed', 'cancelled']) {
      const unproven = await service.jobProjection({}, { ...job, state, safeProgress: receipt.job.safeProgress });
      expect(() => configurationReconcileResult(unproven, expected, plan)).toThrow();
    }
    for (const executionCompleted of [false, undefined]) expect(() => configurationReconcileResult({ ...receipt, executionCompleted }, expected, plan)).toThrow();
    for (const patch of [{ readOnly: false }, { executionChanged: true }, { reconciledPlanId: other }, { observations: [receipt.job.safeProgress.observations[0]] }, { observations: receipt.job.safeProgress.observations.map((row: any) => ({ ...row, causalOutcomeUnproven: false })) }]) expect(() => configurationReconcileResult({ ...receipt, job: { ...receipt.job, safeProgress: { ...receipt.job.safeProgress, ...patch } } }, expected, plan)).toThrow();
    for (const foreign of [{ actorId: other }, { clusterId: other }, { workspaceId: other }, { idempotencyKey: other }]) expect(() => configurationReconcileResult(receipt, { ...expected, ...foreign }, plan)).toThrow();
    expect(() => configurationReconcileResult({ ...receipt, job: { ...receipt.job, kind: 'apply' } }, expected, plan)).toThrow();
    await expect(service.reconcilePlan(cid, id, { revision: 2, planHash: summary.planHash }, { user: { id: actor }, idempotencyKey: key, workspaceId: wid })).rejects.toThrow(); expect(packet).toHaveBeenCalledTimes(2);
  });
  it('sends actual yaml/sync intent fields and exact Basic password intention map while clearing all plaintext', async () => {
    const intents = basicPasswordIntentMap([{ key: 'consumers[0].basicauth_credentials[0]', intent: 'replace' }]), upload = vi.fn(async body => body.mode), clear = vi.fn();
    await expect(uploadConfiguration({ selection: { scope: 'workspace', serviceIds: [] }, mode: 'sync', confirmDeletes: true, basicPasswordIntents: intents, content: 'memory-only-yaml', clearMaterial: clear, assertCurrent: () => {}, upload })).resolves.toBe('sync');
    expect(upload.mock.calls[0][0]).toEqual({ scope: 'workspace', serviceIds: [], mode: 'sync', yaml: 'memory-only-yaml', confirm_deletes: true, basicPasswordIntents: intents }); expect(upload.mock.calls[0][0]).not.toHaveProperty('content'); expect(upload.mock.calls[0][0]).not.toHaveProperty('format');
    await expect(uploadConfiguration({ selection: { scope: 'workspace', serviceIds: [] }, mode: 'sync', content: 'unused', clearMaterial: clear, assertCurrent: () => {}, upload })).rejects.toThrow('明确确认'); expect(upload).toHaveBeenCalledTimes(1);
    expect(() => basicPasswordIntentMap([{ key: 'https://fixture.invalid?token=private', intent: 'replace' }])).toThrow(); expect(() => basicPasswordIntentMap([{ key: 'consumers[0].basicauth_credentials[0]', intent: 'keep' }, { key: 'consumers[0].basicauth_credentials[0]', intent: 'replace' }])).toThrow();
  });
  it('clears plaintext before the real upload callback and again on rejection without retaining it in a result', async () => {
    const sequence: string[] = [], clear = vi.fn(() => sequence.push('clear')), upload = vi.fn(async body => { sequence.push('packet'); expect(body.yaml).toBe('_format_version: "1.1"\nservices: []'); return { jobId: id }; });
    const result = await uploadConfiguration({ selection: { scope: 'workspace', serviceIds: [] }, mode: 'merge', content: '_format_version: "1.1"\nservices: []', assertCurrent: () => sequence.push('scope'), clearMaterial: clear, upload });
    expect(sequence).toEqual(['scope', 'scope', 'clear', 'packet', 'clear']); expect(result).toEqual({ jobId: id });
    await expect(uploadConfiguration({ selection: { scope: 'workspace', serviceIds: [] }, mode: 'sync', confirmDeletes: true, content: 'secret-only-in-RAM', assertCurrent: () => {}, clearMaterial: clear, upload: async () => { throw Error('closed'); } })).rejects.toThrow('closed'); expect(clear).toHaveBeenCalledTimes(4);
  });
  it('does not upload after delayed file read changes identity and enforces UTF8 byte limits before packet', async () => {
    let current = true; const upload = vi.fn(), clear = vi.fn();
    await expect(uploadConfiguration({ selection: { scope: 'workspace', serviceIds: [] }, mode: 'merge', file: { size: 4, text: async () => { current = false; return 'safe'; } }, assertCurrent: () => { if (!current) throw Error('changed'); }, clearMaterial: clear, upload })).rejects.toThrow('changed');
    await expect(uploadConfiguration({ selection: { scope: 'workspace', serviceIds: [] }, mode: 'merge', content: '界'.repeat(3 * 1024 * 1024), assertCurrent: () => {}, clearMaterial: clear, upload })).rejects.toThrow('8 MiB'); expect(upload).not.toHaveBeenCalled(); expect(clear).toHaveBeenCalledTimes(2);
  });
  it('persists only original actor/scope/key for configuration uncertainty, discarding YAML and secrets', () => {
    const row = { actor_id: actor, cid, wid, kind: 'configuration', scope: 'workspace', idempotencyKey: key, state: 'uncertain', created_at: new Date().toISOString(), content: 'secret', artifact: { key: 'secret' } };
    const values = safeRecoveryReferences([row, { ...row, actor_id: other }, { ...row, wid: undefined }, { ...row, scope: 'global' }, { ...row, scope: 'cluster' }], actor); expect(values).toHaveLength(1); expect(JSON.stringify(values)).not.toContain('secret'); expect(values[0].kind).toBe('configuration');
  });
});

describe('M8 authenticated POST file transfer uses actual client with memory-only fetch', () => {
  let client: typeof import('../../apps/console-web/src/api/client'), events: ReturnType<typeof vi.fn>;
  const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
  const path = `/clusters/${cid}/configuration/exports/${id}/download?workspaceId=${wid}`, body = { revision: 3, confirmed: true as const, confirm_name: 'safe-export' };
  beforeEach(async () => { vi.resetModules(); events = vi.fn(); vi.stubGlobal('window', { dispatchEvent: events }); vi.stubGlobal('crypto', { randomUUID: () => key }); vi.stubGlobal('CustomEvent', class extends Event { detail: unknown; constructor(type: string, options?: { detail?: unknown }) { super(type); this.detail = options?.detail; } }); client = await import('../../apps/console-web/src/api/client'); client.setApiActorId(actor); client.setCsrfToken('memory-only-csrf'); });
  it('preserves original POST body/key across one authentication renewal and denies raw or token download URLs', async () => {
    const fetch = vi.fn().mockResolvedValueOnce(json({ error: { code: 'SESSION_EXPIRED' } }, 401)).mockResolvedValueOnce(json({ data: {} })).mockResolvedValueOnce(new Response('safe-yaml', { headers: { 'content-type': 'application/yaml' } })); vi.stubGlobal('fetch', fetch);
    const result = await client.apiConfigurationBlob(path, body, key); expect(await result.blob.text()).toBe('safe-yaml'); expect(fetch.mock.calls.map(call => call[0])).toEqual([`/api/v1${path}`, '/api/v1/auth/refresh', `/api/v1${path}`]);
    expect(fetch.mock.calls[0][1].method).toBe('POST'); expect(fetch.mock.calls[0][1].body).toBe(JSON.stringify(body)); expect(fetch.mock.calls[2][1].body).toBe(JSON.stringify(body)); expect(fetch.mock.calls[2][1].headers.get('X-Idempotency-Key')).toBe(key);
    for (const invalid of ['https://kong:8001/cache', path + '&token=never', path + `&workspaceId=${wid}`, path.replace('configuration', 'vaults')]) expect(() => client.apiConfigurationBlob(invalid, body, key)).toThrow(); expect(fetch).toHaveBeenCalledTimes(3);
  });
  it('ignores late authority responses and creates/revokes exactly one transient Blob URL on successful save', async () => {
    const create = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:memory-only'), revoke = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {}), click = vi.fn(), remove = vi.fn(); vi.stubGlobal('document', { createElement: () => ({ style: {}, click, remove }), body: { appendChild: vi.fn() } });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('safe', { headers: { 'content-type': 'application/yaml' } }))); const { downloadConfigurationExport } = await import('../../apps/console-web/src/features/m8.download');
    await downloadConfigurationExport({ id, revision: 3, name: 'safe-export', format: 'deck-1.1', identity, current: () => identity }); expect(click).toHaveBeenCalledTimes(1); expect(remove).toHaveBeenCalledTimes(1); expect(revoke).toHaveBeenCalledWith('blob:memory-only');
    let reads = 0; await expect(downloadConfigurationExport({ id, revision: 3, name: 'safe-export', format: 'deck-1.1', identity, current: () => ++reads === 1 ? identity : { ...identity, version: 'new' } })).rejects.toThrow('范围或权限'); expect(create).toHaveBeenCalledTimes(1);
  });
  it('stops oversized streaming and preserves original download key as unknown without automatic resend', async () => {
    const cancel = vi.fn(), stream = new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(new TextEncoder().encode('safe')); }, cancel }); vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(stream, { headers: { 'content-length': String(33 * 1024 * 1024) } })));
    await expect(client.apiConfigurationBlob(path, body, key)).rejects.toMatchObject({ code: 'WRITE_RESULT_UNKNOWN', recovery: { kind: 'configuration', clusterId: cid, workspaceId: wid, idempotencyKey: key } }); expect(cancel).toHaveBeenCalledTimes(1); expect(events).toHaveBeenCalledTimes(1);
  });
  it('does not expose original YAML/private fields in rejected API responses, and loss sends only one original packet', async () => {
    const fetch = vi.fn().mockResolvedValueOnce(json({ error: { code: 'INVALID_CONFIGURATION_YAML', message: 'secret leaked in raw YAML', fields: { content: 'private-key-never-render' }, state: 'secret-state', operationId: 'secret-operation', entryId: 'secret-entry', requestId: 'secret-request' } }, 400)).mockResolvedValueOnce(json({ error: { code: 'INTERNAL_SERVER_ERROR' } }, 500)).mockRejectedValueOnce(Error('transport')); vi.stubGlobal('fetch', fetch);
    const rejected = await client.api(`/clusters/${cid}/configuration/imports?workspaceId=${wid}`, { method: 'POST', body: '{"content":"short-term-secret"}' }).catch(error => error); expect(rejected.message).not.toContain('secret leaked'); expect(rejected.fields).toBeUndefined(); expect(rejected.requestId).toBeUndefined(); expect(rejected.recovery.state).toBeUndefined(); expect(rejected.recovery.operationId).toBeUndefined(); expect(rejected.recovery.entryId).toBeUndefined();
    const serverUnknown = await client.api(`/clusters/${cid}/snapshots?workspaceId=${wid}`, { method: 'POST', body: '{}' }).catch(error => error); expect(serverUnknown).toMatchObject({ code: 'WRITE_RESULT_UNKNOWN', recovery: { kind: 'configuration', idempotencyKey: key, state: 'uncertain' } });
    const unknown = await client.api(`/clusters/${cid}/snapshots?workspaceId=${wid}`, { method: 'POST', body: '{}' }).catch(error => error); expect(unknown).toMatchObject({ code: 'WRITE_RESULT_UNKNOWN', recovery: { kind: 'configuration', idempotencyKey: key, clusterId: cid, workspaceId: wid } }); expect(fetch).toHaveBeenCalledTimes(3); expect(events.mock.calls.at(-1)?.[0].detail.actorId).toBe(actor);
  });
});
