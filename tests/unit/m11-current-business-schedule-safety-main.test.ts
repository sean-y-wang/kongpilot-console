// @ts-nocheck -- controlled BFF observations only; no runtime/private ledger.
import {createHash, randomUUID} from 'node:crypto';
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';
import {parse, stringify} from 'yaml';
const runtime = vi.hoisted(() => ({construct: vi.fn(), open: vi.fn(() => 23), write: vi.fn(), close: vi.fn(), directory: vi.fn()}));
vi.mock('node:fs', async original => ({...(await original()), openSync: runtime.open, writeSync: runtime.write, closeSync: runtime.close}));
vi.mock('../security/lib/release-private-directory.mjs', () => ({selectReleaseReportDirectory: () => ({custom: true, directory: '/synthetic-safety/reports'}), assertReleaseReportDirectory: runtime.directory}));
vi.mock('../security/lib/release-harness.mjs', () => ({ReleaseHarness: class {constructor(...args) {return runtime.construct(...args);}},
  releaseScope: (cid, wid, path, extra = {}) => `/clusters/${cid}/${path}?${new URLSearchParams({workspaceId: wid, ...extra})}`}));
import {main} from '../security/m11-current-business-schedule-safety-http.mjs';
const now = Date.parse('2026-10-15T20:00:00.000Z'), sha = value => createHash('sha256').update(value).digest('hex');
const environment = {RELEASE_LAB_M11_BUSINESS_SAFETY_READY: 'true', RELEASE_LAB_M11_BUSINESS_SAFETY_FIXTURE: 'businessSafetyFreshFixture'};
function fixture(scenario) {
  const cid = randomUUID(), wid = randomUUID(), serviceId = randomUUID();
  const auth = () => {const user = {id: randomUUID()}, sid = randomUUID(), claims = Buffer.from(JSON.stringify({sub: user.id, sid, exp: Math.floor(now / 1000) + 3600})).toString('base64url');
    return {user, sid, cookie: `kongos_access=synthetic.${claims}.synthetic`, csrf: 'SyntheticOnlyCsrf'};};
  const admin = auth(), reviewer = auth(), service = {id: serviceId, name: 'isolated-source-service', host: 'source.invalid', retries: 5, tags: []};
  const definition = {id: randomUUID(), kind: 'configuration_v2', format: 2, status: 'active', version: 2, policyHash: 'a'.repeat(64),
    policy: {version: 2, kind: 'configuration_v2', allowSelfApproval: false, distinctAcrossStages: true,
      stages: [{level: 1, mode: 'any', threshold: 1, selector: {users: [reviewer.user.id]}}]}};
  const state = {cid, wid, requests: [], sessions: {admin}, metadataAcceptance: {reviewerSession: reviewer,
    service: {id: randomUUID()}, businessSafetyFreshFixture: {clusterId: cid, workspaceId: wid, serviceId}}};
  const control = {overlapCode: 'WORKFLOW_SCHEDULE_PHYSICAL_IMPACT_CONFLICT', activationUnknown: false, refreshOnGet: false,
    failBReadAfterConflict: false, conflictObserved: false};
  const jobs = new Map(), byKey = new Map(), snapshots = new Map(), exports = new Map(), plans = new Map(), workflows = new Map(), schedules = new Map();
  const methods = [], h = {state, save: vi.fn(), assertWritable: vi.fn(() => {
    if (state.requests.some(p => p.state === 'response_unknown' || p.status >= 500)) throw Error('ORIGINAL_GLOBAL_UNKNOWN_NO_REPLAY');
  })};
  const result = (data, status = 201, extra = {}) => ({data: structuredClone(data), status, requestId: randomUUID(), payload: {data}, ...extra});
  const receipt = (who, key, kind, more) => {const jobId = more?.jobId ?? randomUUID(); return {domain: 'configuration', durable: true, kind, id: jobId, jobId,
    actorId: who.user.id, clusterId: cid, workspaceId: wid, originalScope: {clusterId: cid, workspaceId: wid},
    idempotencyKey: key, registrationCompleted: true, submissionCompleted: true, ...more};};
  const handle = async (who, path, method, body, options) => {
    const uri = new URL(`http://synthetic.invalid${path}`), r = uri.pathname.slice(`/clusters/${cid}/`.length);
    if (method === 'GET') {
      if (control.refreshOnGet) return h.request(who, '/auth/refresh', 'POST');
      if (uri.pathname === `/clusters/${cid}`) return result({id: cid, revision: 1, execution_mode: 'approval', version: '1.5.1', status: 'healthy'}, 200);
      if (r === `entities/services/${serviceId}`) return result({entity: service}, 200);
      if (r === 'workflow-definitions') return result({items: [definition], nextCursor: null}, 200);
      if (r.startsWith('configuration/plans/')) return result(plans.get(r.split('/')[2]), 200);
      if (r.startsWith('configuration/jobs/by-key/')) return result(byKey.get(r.split('/')[3]), 200);
      if (r.startsWith('configuration/jobs/')) return result({entity: jobs.get(r.split('/')[2])}, 200);
      if (r.startsWith('workflows/')) return result(workflows.get(r.split('/')[1]), 200);
      if (r.startsWith('workflow-schedules/')) {
        if (control.failBReadAfterConflict && control.conflictObserved) {control.failBReadAfterConflict = false; throw Error('SYNTHETIC_POST_CONFLICT_READ_FAILURE');}
        return result({entity: schedules.get(r.split('/')[1])}, 200);
      }
      throw Error('UNEXPECTED_SYNTHETIC_GET');
    }
    const key = options.key;
    if (r === 'snapshots') {const snapshotId = randomUUID(); snapshots.set(snapshotId, {name: body.name}); return result(receipt(who, key, 'capture', {state: 'succeeded', snapshotId}));}
    if (/^snapshots\/[^/]+\/export$/.test(r)) {
      const name = snapshots.get(r.split('/')[1]).name; expect(body.confirm_name).toBe(name);
      const exportId = randomUUID(); exports.set(exportId, {name, yaml: stringify({_format_version: '1.1', services: [service]})});
      return result(receipt(who, key, 'export', {state: 'succeeded', exportId, exportRevision: 1, confirmationName: name, capabilities: {download: true}}));
    }
    if (/^configuration\/exports\/[^/]+\/download$/.test(r)) {
      const id = r.split('/')[2], exported = exports.get(id); expect(body.confirm_name).toBe(exported.name);
      const bytes = Buffer.from(exported.yaml), download = receipt(who, key, 'export', {state: 'succeeded', exportId: id, downloadPermitConsumed: true, byteCount: bytes.length});
      byKey.set(key, download); return result(null, 201, {bytes, headers: new Headers({'Cache-Control': 'no-store', 'Content-Type': 'application/yaml; charset=utf-8', 'X-Content-Type-Options': 'nosniff'})});
    }
    if (r === 'configuration/imports') {
      expect(body.mode).toBe('merge'); expect(body.scope).toBe('services'); expect(body.serviceIds).toEqual([serviceId]);
      const document = parse(body.yaml); expect(Object.keys(document.services[0]).sort()).toEqual(['id', 'retries']); expect(document.services[0].id).toBe(serviceId);
      const planId = randomUUID(), hash = sha(planId), jobId = randomUUID();
      const plan = {entity: {id: planId, name: `配置计划 ${planId}`, planRevision: 1, planHash: hash, executionMode: 'approval', approvalRequired: true,
        capabilities: {apply: true}, stepCount: 1, nativePacketCount: 1, deleteCount: 0, expiresAt: new Date(Date.now() + 14 * 60000).toISOString()},
        items: [{entityType: 'services', nativeId: serviceId, action: 'update', referenceOnly: false, blockerCodes: [],
          patch: [{op: 'replace', path: '/retries', value: document.services[0].retries}]}], nextCursor: null}; plans.set(planId, plan);
      const imported = receipt(who, key, 'import', {state: 'succeeded', jobId, planId}); jobs.set(jobId, imported); return result(imported);
    }
    if (/^configuration\/plans\/[^/]+\/apply$/.test(r)) {
      const planId = r.split('/')[2], plan = plans.get(planId).entity; expect(body.planHash).toBe(plan.planHash);
      const workflowId = randomUUID(), jobId = randomUUID(), hash = sha(workflowId);
      const detail = {entity: {id: workflowId, kind: 'configuration_v2', state: 'pending', revision: 1, planRevision: 1, planHash: hash,
        expiresAt: plan.expiresAt, approvalRequired: true, capabilities: {approve: true, execute: false},
        approval: {format: 2, candidateVersion: 1, stages: [{level: 1, revision: 1, state: 'active', votes: 0}]}},
        decisions: [], steps: [{id: randomUUID(), kind: 'metadata', state: 'pending', operationId: null}]}; workflows.set(workflowId, detail);
      const applied = receipt(who, key, 'apply', {state: 'waiting_approval', workflowId, jobId, planId, executionCompleted: false, executionId: null});
      jobs.set(jobId, applied); return result(applied);
    }
    if (r === 'workflow-schedules') {
      const detail = workflows.get(body.workflowId), row = detail.entity;
      expect(body.revision).toBe(row.revision); expect(body.planHash).toBe(row.planHash); expect(detail.decisions).toHaveLength(0);
      expect(Object.keys(body.spec).sort()).toEqual(['notBefore', 'windowEnd', 'windowStart']);
      row.planRevision++; row.revision++; row.planHash = sha(`${row.id}:scheduled`); row.scheduled = true;
      detail.steps.push({id: randomUUID(), kind: 'metadata', state: 'pending', operationId: null});
      const s = {id: randomUUID(), workflowId: row.id, workflowPlanHash: row.planHash, revision: 1, state: 'pending-approval',
        executorId: admin.user.id, claimId: null, nativeAuthority: false, ...body.spec}; schedules.set(s.id, s); return result({entity: s, commandCompleted: true});
    }
    if (/^workflows\/[^/]+\/approve$/.test(r)) {
      const detail = workflows.get(r.split('/')[1]), row = detail.entity; expect(who.user.id).toBe(reviewer.user.id);
      expect(row.scheduled).toBe(true); expect(body.execute).toBe(false); expect(body.planHash).toBe(row.planHash);
      detail.decisions.push({userId: who.user.id}); row.state = 'approved'; row.revision++; return result({entity: row, decisionCompleted: true});
    }
    if (/^workflow-schedules\/[^/]+\/(activate|cancel)$/.test(r)) {
      const s = schedules.get(r.split('/')[1]); expect(body.revision).toBe(s.revision); expect(body.confirmed).toBe(true);
      if (r.endsWith('/activate')) {
        expect(body.confirm_name).toBe('activate-schedule');
        if (control.activationUnknown) {s.state = 'active'; s.revision++; throw Error('SYNTHETIC_UNKNOWN_RESPONSE');}
        if ([...schedules.values()].some(other => other !== s && other.state === 'active')) {
          control.conflictObserved = true; return result(null, 409, {errorCode: control.overlapCode, payload: {error: {code: control.overlapCode}}});
        }
        s.state = 'active'; s.revision++;
      } else {expect(body.confirm_name).toBe('cancel-schedule'); s.state = 'cancelled'; s.revision++;}
      return result({entity: s, commandCompleted: true}, 200);
    }
    throw Error('UNEXPECTED_SYNTHETIC_POST');
  };
  h.request = vi.fn(async (who, path, method = 'GET', body, options = {}) => {
    methods.push({method, path}); let packet;
    if (method === 'POST') {h.assertWritable(); packet = {key: options.key, method, path, actorId: who.user.id, sessionId: who.sid,
      bodyHash: sha(JSON.stringify(body)), state: 'prepared'}; state.requests.push(packet); h.save();}
    try {const out = await handle(who, path, method, body, options);
      if (packet) Object.assign(packet, {state: 'response_observed', status: out.status, requestId: out.requestId, errorCode: out.errorCode ?? null});
      expect(options.expected ?? [200, 201]).toContain(out.status); return out;
    } catch (error) {if (packet?.state === 'prepared') packet.state = 'response_unknown'; throw error;}
  });
  h.once = vi.fn(async (label, who, path, method, body, options) => {
    const out = await h.request(who, path, method, body, options); state.requests.find(p => p.key === options.key).label = label; return out;
  });
  runtime.construct.mockImplementation(() => h);
  const run = async stage => {const prior = process.exitCode; try {await main(environment, scenario, stage);} finally {process.exitCode = prior;}
    return JSON.parse(runtime.write.mock.calls.at(-1)[1]);};
  const ready = async () => {for (const stage of ['preflight', 'prepare', 'author', 'approve']) expect((await run(stage)).passed).toBe(true);};
  return {h, state, control, schedules, workflows, methods, service, run, ready, admin, reviewer};
}
beforeEach(() => {vi.useFakeTimers(); vi.setSystemTime(new Date(now)); runtime.construct.mockReset(); runtime.write.mockClear(); runtime.open.mockClear();
  vi.spyOn(console, 'log').mockImplementation(() => {}); vi.spyOn(console, 'error').mockImplementation(() => {});});
afterEach(() => {vi.useRealTimers(); vi.restoreAllMocks();});

describe('business safety real runner main against controlled BFF contracts (no runtime acceptance)', () => {
  it.each(['cancel-before-due', 'restart-expiry', 'overlap'])('runs only original scheduled metadata commands for %s then observes after the original window', async scenario => {
    const f = fixture(scenario); await f.ready();
    const g = f.state.currentBusinessScheduleSafetyCases[scenario], originalDeadline = g.deadlines[0], spec = structuredClone(g.window);
    if (scenario === 'overlap') {
      expect((await f.run('overlap-check')).passed).toBe(true);
      expect(g.overlapObservation).toMatchObject({status: 409, errorCode: 'WORKFLOW_SCHEDULE_PHYSICAL_IMPACT_CONFLICT', exactConflict: true});
      expect([...f.schedules.values()].map(s => s.state)).toEqual(['cancelled', 'cancelled']);
    } else {
      expect((await f.run('activate')).passed).toBe(true);
      if (scenario === 'cancel-before-due') expect((await f.run('cancel')).passed).toBe(true);
    }
    vi.setSystemTime(new Date(Date.parse(spec.windowEnd) + 1));
    if (scenario === 'restart-expiry') {
      // Explicit controlled server observation, not an actual process restart,
      // worker tick or invocation of any product expiry implementation.
      for (const s of f.schedules.values()) {s.state = 'expired'; s.reasonCode = 'WORKFLOW_SCHEDULE_WINDOW_EXPIRED'; s.revision++;}
    }
    const start = f.methods.length, report = await f.run('observe'); expect(report.passed).toBe(true);
    expect(f.methods.slice(start).every(call => call.method === 'GET')).toBe(true);
    expect(report).toMatchObject({rootSqlFactsVerified: false, rootRestartTimelineVerified: false, overallM11Accepted: false,
      workflowExecuteInvoked: false, manualWorkerInvoked: false, originalDeadlineExtended: false});
    expect(g.window).toEqual(spec); expect(g.deadlines[0]).toBe(originalDeadline); expect(f.service.retries).toBe(5);
    expect(f.methods.some(call => /\/execute|tick|clustering|\/plugins\/schema/.test(call.path))).toBe(false);
    expect(f.h.once.mock.calls.every(([, , , method]) => method === 'POST')).toBe(true);
  });
  it('treats a different observed 409 as failed while cancelling both known pending/active schedules', async () => {
    const f = fixture('overlap'); await f.ready(); f.control.overlapCode = 'REVISION_CONFLICT';
    const report = await f.run('overlap-check'); expect(report.passed).toBe(false);
    expect([...f.schedules.values()].every(s => s.state === 'cancelled')).toBe(true);
    const count = f.h.once.mock.calls.length, original = structuredClone(f.state.currentBusinessScheduleSafetyCases.overlap.commands);
    expect((await f.run('overlap-check')).passed).toBe(false); expect(f.h.once).toHaveBeenCalledTimes(count);
    expect(f.state.currentBusinessScheduleSafetyCases.overlap.commands).toEqual(original);
  });
  it('retains an unknown activation without replacing its key or bypassing the global fence for cleanup', async () => {
    const f = fixture('overlap'); await f.ready(); f.control.activationUnknown = true;
    const report = await f.run('overlap-check'); expect(report.passed).toBe(false);
    const g = f.state.currentBusinessScheduleSafetyCases.overlap, command = structuredClone(g.commands['overlap-check:A-activate']);
    expect(f.state.requests.at(-1).state).toBe('response_unknown'); expect(g.commands).not.toHaveProperty('overlap-check:A-cancel');
    expect(g.commands).not.toHaveProperty('overlap-check:B-activate'); const count = f.h.once.mock.calls.length;
    expect((await f.run('overlap-check')).passed).toBe(false); expect(f.h.once).toHaveBeenCalledTimes(count);
    expect(g.commands['overlap-check:A-activate']).toEqual(command);
  });
  it('cancels both original schedules if a pure post-conflict read fails after A activation', async () => {
    const f = fixture('overlap'); await f.ready(); f.control.failBReadAfterConflict = true;
    const report = await f.run('overlap-check'); expect(report.passed).toBe(false);
    expect(report.errorCode).toBe('SYNTHETIC_POST_CONFLICT_READ_FAILURE');
    expect([...f.schedules.values()].every(s => s.state === 'cancelled')).toBe(true);
    const commands = f.state.currentBusinessScheduleSafetyCases.overlap.commands;
    expect(commands['overlap-check:A-cancel'].state).toBe('response_observed'); expect(commands['overlap-check:B-cancel'].state).toBe('response_observed');
  });
  it('keeps a readonly observer from silently refreshing an original SID', async () => {
    const f = fixture('cancel-before-due'); await f.ready(); await f.run('activate'); await f.run('cancel');
    vi.setSystemTime(new Date(Date.parse(f.state.currentBusinessScheduleSafetyCases['cancel-before-due'].window.windowEnd) + 1));
    f.control.refreshOnGet = true; const start = f.methods.length, writes = f.h.once.mock.calls.length;
    const report = await f.run('observe'); expect(report.passed).toBe(false);
    expect(report.errorCode).toBe('IMPLICIT_BUSINESS_SAFETY_AUTH_TRANSPORT_FORBIDDEN');
    expect(f.methods.slice(start).every(call => call.method === 'GET')).toBe(true); expect(f.h.once).toHaveBeenCalledTimes(writes);
  });
  it('does not start another case on a previously owned Service or override the original fixture', async () => {
    const f = fixture('cancel-before-due'); expect((await f.run('preflight')).passed).toBe(true);
    const original = structuredClone(f.state.currentBusinessScheduleSafetyCases['cancel-before-due']);
    const prior = process.exitCode; try {await main({...environment, RELEASE_LAB_M11_BUSINESS_SAFETY_FIXTURE: 'businessSafetyFreshFixture'}, 'restart-expiry', 'preflight');}
    finally {process.exitCode = prior;}
    const report = JSON.parse(runtime.write.mock.calls.at(-1)[1]); expect(report.passed).toBe(false);
    expect(f.state.currentBusinessScheduleSafetyCases['cancel-before-due']).toEqual(original);
    expect(f.state.currentBusinessScheduleSafetyCases).not.toHaveProperty('restart-expiry');
  });
  it('does not emit private YAML, cookie, CSRF, request bodies or a raw error message', async () => {
    const f = fixture('cancel-before-due'); await f.ready(); f.h.assertWritable.mockImplementation(() => {throw Error('SyntheticPrivateCookie key: SyntheticPrivateKey');});
    const report = await f.run('activate'), encoded = JSON.stringify(report);
    expect(report.passed).toBe(false); expect(report.errorCode).toBe('BUSINESS_SAFETY_STAGE_FAILED');
    for (const secret of ['SyntheticPrivateCookie', 'SyntheticPrivateKey', f.admin.cookie, f.admin.csrf, '_format_version']) expect(encoded).not.toContain(secret);
    expect(report).not.toHaveProperty('commands'); expect(report).not.toHaveProperty('binding');
  });
  it('does not copy historical requests into a pre-stage global-fence failure report', async () => {
    const f = fixture('cancel-before-due');
    f.state.requests.push({method: 'POST', path: '/private-historical-request', key: randomUUID(), state: 'response_unknown'});
    const report = await f.run('preflight'); expect(report.passed).toBe(false); expect(report.requests).toEqual([]);
    expect(JSON.stringify(report)).not.toContain('private-historical-request'); expect(f.state).not.toHaveProperty('currentBusinessScheduleSafetyCases');
  });
});
