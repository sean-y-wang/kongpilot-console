// @ts-nocheck -- synthetic contracts only; no private ledger or runtime access.
import { createHash, randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { parse as parseYaml } from 'yaml';
import { BUSINESS_SAFETY_CASES, businessSafetySelection, businessSafetyWindow, businessSafetyDesiredYaml,
  businessSafetyAssertPlan, businessSafetyVoteBody, businessSafetyCommand } from '../security/m11-current-business-schedule-safety-http.mjs';

// Pure export/window/DTO checks and an explicitly controlled command journal.
// No main(), ReleaseHarness, actual HTTP, Docker, PostgreSQL or timer is run.
const now = Date.parse('2026-10-15T20:00:00.000Z');
const ready = { RELEASE_LAB_M11_BUSINESS_SAFETY_READY: 'true', RELEASE_LAB_M11_BUSINESS_SAFETY_FIXTURE: 'businessSafetyFreshFixture' };
const serviceId = '10000000-0000-4000-8000-000000000001';
const yaml = (overrides = {}) => JSON.stringify({ _format_version: '1.1', services: [{ id: serviceId, name: 'synthetic-only-service',
  host: 'source.invalid', retries: 3, tags: ['workspace:default', 'owner:source-test'] }], ...overrides });
function plan() {
  const id = randomUUID();
  return { entity: { id, name: `配置计划 ${id}`, planRevision: 1, planHash: 'a'.repeat(64), executionMode: 'approval',
    approvalRequired: true, stepCount: 1, deleteCount: 0, nativePacketCount: 1, capabilities: { apply: true },
    counts: { create: 0, update: 1, delete: 0, conflict: 0 } },
  items: [{ entityType: 'services', nativeId: serviceId, action: 'update', referenceOnly: false, blockerCodes: [],
    patch: [{ op: 'replace', path: '/retries', value: 4 }] }], nextCursor: null };
}
function voteDetail() {
  return { entity: { id: randomUUID(), kind: 'configuration_v2', state: 'pending', revision: 7, planRevision: 2,
    planHash: 'b'.repeat(64), approvalRequired: true, capabilities: { approve: true },
    approval: { format: 2, candidateVersion: 3, stages: [{ level: 1, revision: 5, state: 'active' }] } } };
}
function commandFixture() {
  const clusterId = randomUUID(), workspaceId = randomUUID();
  const session = () => {
    const user = { id: randomUUID() }, sid = randomUUID();
    const claims = Buffer.from(JSON.stringify({ sub: user.id, sid, exp: Math.floor(now / 1000) + 3600 })).toString('base64url');
    return { user, sid, cookie: `kongos_access=synthetic.${claims}.synthetic`, csrf: 'SyntheticCommandCsrf' };
  };
  const admin = session(), reviewer = session();
  const g = { scenario: 'cancel-before-due', clusterId, workspaceId, commands: {},
    subjects: { admin: { id: admin.user.id, sid: admin.sid }, reviewer: { id: reviewer.user.id, sid: reviewer.sid } } };
  const control = { status: 201, data: { jobId: randomUUID(), state: 'succeeded' }, error: null, alterPacket: null };
  const h = { state: { sessions: { admin }, metadataAcceptance: { reviewerSession: reviewer }, requests: [] },
    save: vi.fn(), assertWritable: vi.fn(), once: vi.fn(async (label, who, path, method, body, options) => {
      // This is a synthetic observed packet, never a transport receipt claim.
      expect(h.save).toHaveBeenCalled();
      const selected = Object.values(g.commands).find(command => command.key === options.key);
      expect(selected).toBeDefined();
      const requestId = randomUUID(), packet = { key: options.key, path, method, actorId: who.user.id, sessionId: who.sid,
        label, state: 'response_observed', status: control.status, requestId,
        bodyHash: createHash('sha256').update(JSON.stringify(body)).digest('hex') };
      control.alterPacket?.(packet); h.state.requests.push(packet);
      if (control.error) throw control.error;
      expect(options.expected).toContain(control.status);
      return { status: control.status, data: control.data, payload: { data: control.data }, requestId };
    }) };
  const path = resource => `/clusters/${clusterId}/${resource}?workspaceId=${workspaceId}`;
  return { h, g, control, admin, reviewer, path };
}

beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date(now)); });
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

describe('business safety scenario and immutable original window contracts', () => {
  it('exports only the three explicitly scoped safety cases', () => {
    expect(BUSINESS_SAFETY_CASES).toEqual(['cancel-before-due', 'restart-expiry', 'overlap']);
  });
  it.each(['cancel-before-due', 'restart-expiry', 'overlap'])('requires an explicit own-field selector for %s', scenario => {
    expect(businessSafetySelection(ready, scenario, 'preflight')).toEqual({ scenario, fixtureField: 'businessSafetyFreshFixture' });
  });
  it.each([
    [{ ...ready, RELEASE_LAB_M11_BUSINESS_SAFETY_READY: 'false' }, 'cancel-before-due', 'preflight'],
    [ready, 'borrowed-case', 'preflight'],
    [{ ...ready, RELEASE_LAB_M11_BUSINESS_SAFETY_FIXTURE: 'metadata.fixture' }, 'cancel-before-due', 'preflight'],
    [{ RELEASE_LAB_M11_BUSINESS_SAFETY_READY: 'true' }, 'cancel-before-due', 'preflight'],
  ])('refuses an unready, unknown or ambiguous selection', (environment, scenario, stage) => {
    expect(() => businessSafetySelection(environment, scenario, stage)).toThrow();
  });
  it('rejects stages that would turn a safety scenario into another action', () => {
    for (const [scenario, stage] of [['overlap', 'activate'], ['overlap', 'cancel'], ['restart-expiry', 'cancel'],
      ['cancel-before-due', 'overlap-check'], ['restart-expiry', 'overlap-check'], ['cancel-before-due', 'execute']]) {
      expect(() => businessSafetySelection(ready, scenario, stage)).toThrow();
    }
  });
  it('fixes a three-minute lead and a two-minute window without changing its inputs', () => {
    const deadlines = [new Date(now + 720000).toISOString(), new Date(now + 600000).toISOString()], original = [...deadlines];
    expect(businessSafetyWindow(deadlines, now)).toEqual({ notBefore: new Date(now + 180000).toISOString(),
      windowStart: new Date(now + 180000).toISOString(), windowEnd: new Date(now + 300000).toISOString() });
    expect(deadlines).toEqual(original);
  });
  it('accepts the exact original five-second margin and refuses to shorten or renew a tight deadline', () => {
    expect(businessSafetyWindow([new Date(now + 305000).toISOString()], now).windowEnd).toBe(new Date(now + 300000).toISOString());
    expect(() => businessSafetyWindow([new Date(now + 304999).toISOString()], now)).toThrow();
  });
  it.each([[], ['not-an-original-deadline']])('fails closed without complete original deadline evidence', deadlines => {
    expect(() => businessSafetyWindow(deadlines, now)).toThrow();
  });
});

describe('business safety export and exact one-Service plan contracts', () => {
  it('derives only the original Service UUID and intended retry field from a full export', () => {
    const raw = yaml(), result = businessSafetyDesiredYaml(raw, { serviceId }, 3, 4);
    expect(parseYaml(result)).toEqual({ _format_version: '1.1', services: [{ id: serviceId, retries: 4 }] });
    expect(JSON.parse(raw).services[0].retries).toBe(3);
    expect(result).not.toContain('source.invalid'); expect(result).not.toContain('synthetic-only-service');
  });
  it.each(['wrong-format', 'foreign-service', 'wrong-before', 'multiple-services'])('rejects a %s export instead of inventing an original', variant => {
    let raw = yaml();
    if (variant === 'wrong-format') raw = yaml({ _format_version: '3.0' });
    if (variant === 'foreign-service') raw = yaml({ services: [{ id: randomUUID(), retries: 3 }] });
    if (variant === 'wrong-before') raw = yaml({ services: [{ id: serviceId, retries: 9 }] });
    if (variant === 'multiple-services') raw = yaml({ services: [{ id: serviceId, retries: 3 }, { id: randomUUID(), retries: 3 }] });
    expect(() => businessSafetyDesiredYaml(raw, { serviceId }, 3, 4)).toThrow();
  });
  it('returns only the independently checked approval-ready one-update plan entity', () => {
    const view = plan(), before = structuredClone(view);
    expect(businessSafetyAssertPlan(view, serviceId, 4)).toEqual(view.entity); expect(view).toEqual(before);
  });
  it.each(['extra-field-patch', 'foreign-native-id', 'delete', 'unavailable-apply', 'more-pages'])('refuses a %s plan before apply', variant => {
    const view = plan();
    if (variant === 'extra-field-patch') view.items[0].patch.push({ op: 'replace', path: '/host', value: 'different.invalid' });
    if (variant === 'foreign-native-id') view.items[0].nativeId = randomUUID();
    if (variant === 'delete') view.entity.deleteCount = 1;
    if (variant === 'unavailable-apply') view.entity.capabilities.apply = false;
    if (variant === 'more-pages') view.nextCursor = 'original-next-page';
    expect(() => businessSafetyAssertPlan(view, serviceId, 4)).toThrow();
  });
});

describe('business safety independent real-V2 approval DTO', () => {
  it('uses the current independent stage/revision and explicitly disables immediate execution', () => {
    const detail = voteDetail(), before = structuredClone(detail);
    expect(businessSafetyVoteBody(detail)).toMatchObject({ revision: 7, planHash: detail.entity.planHash,
      confirmed: true, confirm_name: 'configuration_v2', execute: false, level: 1, stageRevision: 5, candidateVersion: 3 });
    expect(detail).toEqual(before);
  });
  it.each(['wrong-kind', 'format-one', 'not-authorized', 'multiple-active'])('refuses %s rather than borrowing an old approval', variant => {
    const detail = voteDetail();
    if (variant === 'wrong-kind') detail.entity.kind = 'portal-credential-issue';
    if (variant === 'format-one') detail.entity.approval.format = 1;
    if (variant === 'not-authorized') detail.entity.capabilities.approve = false;
    if (variant === 'multiple-active') detail.entity.approval.stages.push({ level: 2, revision: 1, state: 'active' });
    expect(() => businessSafetyVoteBody(detail)).toThrow();
  });
});

describe('business safety command journal and original actor boundary (controlled packets)', () => {
  it.each([false, true])('selects the original key before once and uses only the fixed reviewer=%s session', async reviewer => {
    const f = commandFixture(), path = reviewer ? f.path(`workflows/${randomUUID()}/approve`) : f.path('snapshots');
    const stage = reviewer ? 'approve' : 'prepare', commandLabel = reviewer ? 'vote' : 'capture';
    const body = reviewer ? businessSafetyVoteBody(voteDetail()) : { scope: 'services', serviceIds: [serviceId], name: 'synthetic capture' };
    const result = await businessSafetyCommand(f.h, f.g, stage, commandLabel, path, body, { reviewer });
    expect(f.h.assertWritable).toHaveBeenCalled(); expect(f.h.once).toHaveBeenCalledOnce();
    const [label, who, actualPath, method, actualBody, options] = f.h.once.mock.calls[0];
    expect(label).toBe(`m11-business-safety:cancel-before-due:${stage}:${commandLabel}`);
    expect(who).toBe(reviewer ? f.reviewer : f.admin); expect(actualPath).toBe(path); expect(method).toBe('POST');
    expect(actualBody).toEqual(body); expect(options.key).toBe(f.g.commands[`${stage}:${commandLabel}`].key);
    expect(result).toMatchObject({ status: 201, data: f.control.data });
  });
  it('cannot bypass the shared unknown-operation fence by choosing a new safety command', async () => {
    const f = commandFixture(), failure = new Error('ORIGINAL_GLOBAL_UNKNOWN_NO_REPLAY');
    f.h.assertWritable.mockImplementation(() => { throw failure; });
    await expect(businessSafetyCommand(f.h, f.g, 'prepare', 'capture', f.path('snapshots'), {})).rejects.toBe(failure);
    expect(f.g.commands).toEqual({}); expect(f.h.save).not.toHaveBeenCalled(); expect(f.h.once).not.toHaveBeenCalled();
  });
  it('keeps a completed selected command immutable and cannot select a replacement key', async () => {
    const f = commandFixture(), path = f.path('snapshots');
    await businessSafetyCommand(f.h, f.g, 'prepare', 'capture', path, {});
    const before = structuredClone(f.g.commands['prepare:capture']);
    await expect(businessSafetyCommand(f.h, f.g, 'prepare', 'capture', path, {})).rejects.toThrow();
    expect(f.g.commands['prepare:capture']).toEqual(before); expect(f.h.once).toHaveBeenCalledOnce();
  });
  it.each(['auth/refresh', `workflows/${randomUUID()}/execute`, 'entities/services'])('rejects the non-safety resource %s without a packet', async resource => {
    const f = commandFixture();
    await expect(businessSafetyCommand(f.h, f.g, 'prepare', 'forbidden', f.path(resource), {})).rejects.toThrow();
    expect(f.g.commands).toEqual({}); expect(f.h.once).not.toHaveBeenCalled();
  });
  it('does not adopt a new SID from the shared administrator slot', async () => {
    const f = commandFixture(); f.h.state.sessions.admin = { ...f.admin, sid: randomUUID() };
    await expect(businessSafetyCommand(f.h, f.g, 'prepare', 'capture', f.path('snapshots'), {})).rejects.toThrow();
    expect(f.h.once).not.toHaveBeenCalled(); expect(f.g.commands).toEqual({});
  });
  it.each(['actorId', 'bodyHash', 'requestId'])('requires the actual packet %s instead of accepting an unrelated returned response', async field => {
    const f = commandFixture(); f.control.alterPacket = packet => { packet[field] = field === 'bodyHash' ? 'f'.repeat(64) : randomUUID(); };
    await expect(businessSafetyCommand(f.h, f.g, 'prepare', 'capture', f.path('snapshots'), {})).rejects.toThrow();
    expect(f.h.once).toHaveBeenCalledOnce(); const key = f.g.commands['prepare:capture'].key;
    await expect(businessSafetyCommand(f.h, f.g, 'prepare', 'capture', f.path('snapshots'), {})).rejects.toThrow();
    expect(f.g.commands['prepare:capture'].key).toBe(key); expect(f.h.once).toHaveBeenCalledOnce();
  });
  it('records a specifically expected 409 response against its original key', async () => {
    const f = commandFixture(); f.g.scenario = 'overlap'; f.control.status = 409; f.control.data = null;
    const result = await businessSafetyCommand(f.h, f.g, 'overlap-check', 'activate-second', f.path(`workflow-schedules/${randomUUID()}/activate`),
      { revision: 1, confirmed: true, confirm_name: 'activate-schedule' }, { expected: [409] });
    expect(result.status).toBe(409); expect(f.g.commands['overlap-check:activate-second'].key).toBe(f.h.state.requests[0].key);
    expect(f.h.once.mock.calls[0][5].expected).toEqual([409]);
  });
  it('retains an original unknown/5xx command and forbids a replacement attempt or expected-5xx bypass', async () => {
    const f = commandFixture(), failure = new Error('ORIGINAL_RESPONSE_UNKNOWN'); f.control.status = 503; f.control.error = failure;
    await expect(businessSafetyCommand(f.h, f.g, 'prepare', 'capture', f.path('snapshots'), {})).rejects.toBe(failure);
    const original = structuredClone(f.g.commands['prepare:capture']);
    await expect(businessSafetyCommand(f.h, f.g, 'prepare', 'capture', f.path('snapshots'), {})).rejects.toThrow();
    expect(f.g.commands['prepare:capture']).toEqual(original); expect(f.h.once).toHaveBeenCalledOnce();
    await expect(businessSafetyCommand(f.h, f.g, 'prepare', 'accept-server-error', f.path('snapshots'), {}, { expected: [503] })).rejects.toThrow();
    expect(f.g.commands).not.toHaveProperty('prepare:accept-server-error'); expect(f.h.once).toHaveBeenCalledOnce();
  });
});
