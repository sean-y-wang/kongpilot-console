// @ts-nocheck -- pure isolation and controlled main contracts; no runtime/private I/O.
import {createHash, randomUUID} from 'node:crypto';
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';

const runtime = vi.hoisted(() => ({construct: vi.fn(), open: vi.fn(() => 29), write: vi.fn(), close: vi.fn(), directory: vi.fn()}));
vi.mock('node:fs', async original => ({...(await original()), openSync: runtime.open, writeSync: runtime.write, closeSync: runtime.close}));
vi.mock('../security/lib/release-private-directory.mjs', () => ({selectReleaseReportDirectory: () => ({custom: true, directory: '/synthetic-case-safety/reports'}), assertReleaseReportDirectory: runtime.directory}));
vi.mock('../security/lib/release-harness.mjs', () => ({ReleaseHarness: class {constructor(...args) {return runtime.construct(...args);}},
  releaseScope: (cid, wid, path, extra = {}) => `/clusters/${cid}/${path}?${new URLSearchParams({workspaceId: wid, ...extra})}`}));
import {businessSafetySelection, businessSafetySelectedFixture, businessSafetyBindCase, businessSafetyOnceLabel,
  businessSafetyCaseOwnership, businessSafetyCommand, main} from '../security/m11-current-business-schedule-safety-http.mjs';

const now = Date.parse('2026-10-15T20:00:00.000Z');
const namedId = 'post-restart-20261015';
const environment = {RELEASE_LAB_M11_BUSINESS_SAFETY_READY: 'true', RELEASE_LAB_M11_BUSINESS_SAFETY_FIXTURE: 'freshFixture'};
const select = (...args) => {
  const [scenario = 'overlap', field = 'freshFixture'] = args, caseId = args.length < 3 ? namedId : args[2];
  return {scenario, fixtureField: field, ...(caseId === undefined ? {} : {caseId})};
};
function refreshSyntheticCookie(value) {
  const claims = Buffer.from(JSON.stringify({sub: value.user.id, sid: value.sid, exp: Math.floor(now / 1000) + 3600})).toString('base64url');
  value.cookie = `kongos_access=synthetic.${claims}.synthetic`;
}
function session() {
  const value = {user: {id: randomUUID()}, sid: randomUUID(), csrf: 'SyntheticCaseOnlyCsrf'};
  refreshSyntheticCookie(value); return value;
}
function fixture() {
  const cid = randomUUID(), wid = randomUUID(), admin = session(), reviewer = session();
  const state = {cid, wid, requests: [], sessions: {admin}, metadataAcceptance: {reviewerSession: reviewer, service: {id: randomUUID()},
    freshFixture: {clusterId: cid, workspaceId: wid, serviceId: randomUUID()},
    otherFixture: {clusterId: cid, workspaceId: wid, serviceId: randomUUID()},
    thirdFixture: {clusterId: cid, workspaceId: wid, serviceId: randomUUID()}}};
  const h = {state, save: vi.fn(), assertWritable: vi.fn(() => {
    if (state.requests.some(p => p.state === 'response_unknown' || p.status >= 500)) throw Error('ORIGINAL_GLOBAL_UNKNOWN_NO_REPLAY');
  }), once: vi.fn(async () => {throw Error('UNEXPECTED_SYNTHETIC_COMMAND');})};
  const methods = [], definition = {id: randomUUID(), kind: 'configuration_v2', format: 2, status: 'active', version: 2, policyHash: 'a'.repeat(64),
    policy: {version: 2, kind: 'configuration_v2', allowSelfApproval: false, distinctAcrossStages: true,
      stages: [{level: 1, mode: 'any', threshold: 1, selector: {users: [reviewer.user.id]}}]}};
  h.request = vi.fn(async (who, path, method = 'GET') => {
    methods.push({method, path});
    if (method !== 'GET') throw Error('UNEXPECTED_SYNTHETIC_NON_READ');
    const uri = new URL(`http://synthetic.invalid${path}`), resource = uri.pathname.slice(`/clusters/${cid}/`.length);
    let data;
    if (uri.pathname === `/clusters/${cid}`) data = {id: cid, revision: 1, execution_mode: 'approval', version: '1.5.1', status: 'healthy'};
    else if (resource === 'workflow-definitions') data = {items: [definition], nextCursor: null};
    else {
      const field = ['freshFixture', 'otherFixture', 'thirdFixture'].find(k => resource === `entities/services/${state.metadataAcceptance[k].serviceId}`);
      if (!field) throw Error('UNEXPECTED_SYNTHETIC_READ');
      data = {entity: {id: state.metadataAcceptance[field].serviceId, name: field, host: 'source.invalid', retries: 5, tags: []}};
    }
    return {status: 200, data: structuredClone(data), requestId: randomUUID()};
  });
  runtime.construct.mockImplementation(() => h);
  const run = async (selection, stage) => {
    const env = {...environment, RELEASE_LAB_M11_BUSINESS_SAFETY_FIXTURE: selection.fixtureField,
      ...(selection.caseId === undefined ? {} : {RELEASE_LAB_M11_BUSINESS_SAFETY_CASE: selection.caseId})};
    const prior = process.exitCode;
    try {await main(env, selection.scenario, stage);} finally {process.exitCode = prior;}
    return JSON.parse(runtime.write.mock.calls.at(-1)[1]);
  };
  return {state, h, methods, admin, reviewer, run};
}
function subjects(f) {return {admin: {id: f.admin.user.id, sid: f.admin.sid}, reviewer: {id: f.reviewer.user.id, sid: f.reviewer.sid}};}
function group(f, selection = select(), originalSubjects = subjects(f)) {
  const binding = businessSafetySelectedFixture(f.state, selection), named = selection.caseId !== undefined;
  return {version: named ? 2 : 1, scenario: selection.scenario, clusterId: binding.clusterId, workspaceId: binding.workspaceId, binding,
    subjects: structuredClone(originalSubjects), ...(named ? {caseBinding: businessSafetyBindCase(selection, binding, originalSubjects)} : {}),
    runs: {}, commands: {}, lanes: {}, deadlines: [], observations: []};
}
function store(f, selection, g = group(f, selection)) {
  if (selection.caseId === undefined) {
    f.state.currentBusinessScheduleSafetyCases ??= {}; f.state.currentBusinessScheduleSafetyCases[selection.scenario] = g;
  } else {
    f.state.currentBusinessScheduleSafetyNamedCases ??= {};
    f.state.currentBusinessScheduleSafetyNamedCases[selection.scenario] ??= {};
    f.state.currentBusinessScheduleSafetyNamedCases[selection.scenario][selection.caseId] = g;
  }
  return g;
}
function observedOnce(f) {
  f.h.once.mockImplementation(async (label, who, path, method, body, options) => {
    const requestId = randomUUID();
    f.state.requests.push({key: options.key, label, path, method, actorId: who.user.id, sessionId: who.sid,
      state: 'response_observed', status: 201, bodyHash: createHash('sha256').update(JSON.stringify(body)).digest('hex'), requestId});
    return {status: 201, data: {synthetic: true}, requestId};
  });
}

beforeEach(() => {
  vi.useFakeTimers(); vi.setSystemTime(new Date(now)); runtime.construct.mockReset();
  for (const value of [runtime.open, runtime.write, runtime.close, runtime.directory]) value.mockClear();
  vi.spyOn(console, 'log').mockImplementation(() => {}); vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => {vi.useRealTimers(); vi.restoreAllMocks();});

describe('optional safety named-case selector and sealed namespace (Source only)', () => {
  it('preserves the exact default selector and legacy label', () => {
    const selected = businessSafetySelection(environment, 'overlap', 'inspect');
    expect(selected).toEqual({scenario: 'overlap', fixtureField: 'freshFixture'}); expect(Object.hasOwn(selected, 'caseId')).toBe(false);
    const f = fixture(), g = group(f, selected);
    expect(businessSafetyOnceLabel(g, 'prepare:A-snapshot')).toBe('m11-business-safety:overlap:prepare:A-snapshot');
  });
  it('includes only a validated explicit caseId and clones the sealed original subjects', () => {
    const selected = businessSafetySelection({...environment, RELEASE_LAB_M11_BUSINESS_SAFETY_CASE: namedId}, 'overlap', 'preflight');
    const f = fixture(), binding = businessSafetySelectedFixture(f.state, selected), before = subjects(f);
    const sealed = businessSafetyBindCase(selected, binding, before);
    expect(selected).toEqual(select()); expect(sealed).toEqual({version: 1, caseId: namedId, ...binding, subjects: subjects(f)});
    before.admin.sid = randomUUID(); expect(sealed.subjects.admin.sid).toBe(f.admin.sid);
    expect(Object.keys(binding).sort()).toEqual(['clusterId', 'fixtureField', 'scenario', 'serviceId', 'version', 'workspaceId']);
  });
  it.each(['', 'original', 'constructor', 'prototype', '__proto__', 'UpperCase', 'a'.repeat(49), null])('rejects an explicit unsafe case selector %j', caseId => {
    expect(() => businessSafetySelection({...environment, RELEASE_LAB_M11_BUSINESS_SAFETY_CASE: caseId}, 'overlap', 'preflight')).toThrow();
    expect(runtime.construct).not.toHaveBeenCalled();
  });
  it('requires an own exact metadata fixture rather than an inherited or expanded object', () => {
    const f = fixture(), selected = select(), source = structuredClone(f.state.metadataAcceptance.freshFixture);
    const inherited = Object.create({freshFixture: source}); f.state.metadataAcceptance = inherited;
    expect(() => businessSafetySelectedFixture(f.state, selected)).toThrow();
    inherited.freshFixture = {...source, extra: 'synthetic-private'};
    expect(() => businessSafetySelectedFixture(f.state, selected)).toThrow();
  });
  it('separates default, scenario and case label namespaces', () => {
    const f = fixture(), first = group(f), second = group(f, select('overlap', 'otherFixture', 'another-case'));
    const third = group(f, select('restart-expiry', 'thirdFixture', namedId));
    const labels = [businessSafetyOnceLabel(first, 'prepare:A-snapshot'), businessSafetyOnceLabel(second, 'prepare:A-snapshot'),
      businessSafetyOnceLabel(third, 'prepare:A-snapshot'), businessSafetyOnceLabel(group(f, select('overlap', 'freshFixture', undefined)), 'prepare:A-snapshot')];
    expect(new Set(labels).size).toBe(4); expect(labels[0]).toBe(`m11-business-safety.case:overlap:${namedId}:prepare:A-snapshot`);
  });
  it('rejects a changed subject, scope or incomplete named binding before making a once label', () => {
    for (const mutation of [g => {g.subjects.admin.sid = randomUUID();}, g => {g.subjects.reviewer.id = randomUUID();},
      g => {g.workspaceId = randomUUID();}, g => {delete g.caseBinding;}, g => {g.caseBinding = {...g.caseBinding, scenario: 'restart-expiry'};}]) {
      const f = fixture(), g = group(f); mutation(g); expect(() => businessSafetyOnceLabel(g, 'prepare:A-snapshot')).toThrow();
    }
  });
  it('rejects extra binding fields and ambiguous subjects instead of sealing them', () => {
    const f = fixture(), selected = select(), binding = businessSafetySelectedFixture(f.state, selected);
    expect(() => businessSafetyBindCase(selected, {...binding, extra: true}, subjects(f))).toThrow();
    const extra = subjects(f); extra.admin.cookie = 'synthetic-not-a-subject';
    expect(() => businessSafetyBindCase(selected, binding, extra)).toThrow();
    const sameActor = subjects(f); sameActor.reviewer.id = sameActor.admin.id;
    expect(() => businessSafetyBindCase(selected, binding, sameActor)).toThrow();
  });
});

describe('all-case independent fixture ownership (Source only)', () => {
  it('accepts separate old and new fixtures without requiring historical subjects to equal current sessions', () => {
    const f = fixture(), current = select(), old = select('cancel-before-due', 'otherFixture', undefined);
    store(f, old); const prior = select('restart-expiry', 'thirdFixture', 'historical-case'), historical = subjects(f);
    historical.admin.sid = randomUUID(); historical.reviewer.sid = randomUUID();
    store(f, prior, group(f, prior, historical)); const g = store(f, current);
    expect(() => businessSafetyCaseOwnership(f.state, g.binding, current)).not.toThrow();
  });
  it('checks selected entries too, against independent original metadata', () => {
    const f = fixture(), selected = select(), g = store(f, selected);
    g.binding = {...g.binding, serviceId: randomUUID()}; g.caseBinding = businessSafetyBindCase(selected, g.binding, g.subjects);
    expect(() => businessSafetyCaseOwnership(f.state, businessSafetySelectedFixture(f.state, selected), selected)).toThrow();
  });
  it('rejects an incoming binding that no longer equals independently selected metadata', () => {
    const f = fixture(), selected = select(), binding = {...businessSafetySelectedFixture(f.state, selected), serviceId: randomUUID()};
    expect(() => businessSafetyCaseOwnership(f.state, binding, selected)).toThrow();
  });
  it.each(['top-array', 'scenario-array', 'unknown-scenario', 'null-entry', 'version-mismatch', 'key-mismatch'])('fails closed for a %s named store', variant => {
    const f = fixture(), selected = select(), g = store(f, selected);
    if (variant === 'top-array') f.state.currentBusinessScheduleSafetyNamedCases = [];
    if (variant === 'scenario-array') f.state.currentBusinessScheduleSafetyNamedCases.overlap = [];
    if (variant === 'unknown-scenario') f.state.currentBusinessScheduleSafetyNamedCases.unknown = {};
    if (variant === 'null-entry') f.state.currentBusinessScheduleSafetyNamedCases.overlap[namedId] = null;
    if (variant === 'version-mismatch') g.version = 1;
    if (variant === 'key-mismatch') g.caseBinding = {...g.caseBinding, caseId: 'another-case'};
    expect(() => businessSafetyCaseOwnership(f.state, businessSafetySelectedFixture(f.state, selected), selected)).toThrow();
  });
  it('rejects malformed legacy cases even when selecting a different new case', () => {
    const f = fixture(), selected = select(); f.state.currentBusinessScheduleSafetyCases = {'cancel-before-due': null};
    expect(() => businessSafetyCaseOwnership(f.state, businessSafetySelectedFixture(f.state, selected), selected)).toThrow();
  });
  it('retains fixture-field ownership across different scenarios and old/new stores', () => {
    const f = fixture(), selected = select(); store(f, select('cancel-before-due', 'freshFixture', undefined));
    expect(() => businessSafetyCaseOwnership(f.state, businessSafetySelectedFixture(f.state, selected), selected)).toThrow();
  });
  it('rejects a second field alias for the same Service UUID regardless of UUID casing', () => {
    const f = fixture(), selected = select(); f.state.metadataAcceptance.otherFixture.serviceId = f.state.metadataAcceptance.freshFixture.serviceId.toUpperCase();
    store(f, select('restart-expiry', 'otherFixture', 'historical-case'));
    expect(() => businessSafetyCaseOwnership(f.state, businessSafetySelectedFixture(f.state, selected), selected)).toThrow();
  });
  it('rejects Service reuse by baseline, Portal original/named and Promote fixture owners', () => {
    for (const occupy of [(s, id) => {s.metadataAcceptance.service.id = id;},
      (s, id) => {s.currentPortalNaturalOriginal = {fixture: {serviceId: id}};},
      (s, id) => {s.currentPortalNaturalCases = {other: {fixture: {serviceId: id}}};},
      (s, id) => {s.currentPromoteNaturalOriginal = {fixtures: {source: {nativeId: id}}};},
      (s, id) => {s.currentPromoteNaturalOriginal = {fixtures: {target: {nativeId: id}}};}]) {
      const f = fixture(), selected = select(), binding = businessSafetySelectedFixture(f.state, selected); occupy(f.state, binding.serviceId);
      expect(() => businessSafetyCaseOwnership(f.state, binding, selected)).toThrow();
    }
  });
  it('retains Portal named fixture-field ownership even after its metadata Service has been reassigned', () => {
    const f = fixture(), selected = select(), binding = businessSafetySelectedFixture(f.state, selected);
    f.state.currentPortalNaturalCases = {historical: {fixture: {serviceId: randomUUID()}, caseBinding: {fixtureField: selected.fixtureField}}};
    expect(() => businessSafetyCaseOwnership(f.state, binding, selected)).toThrow();
  });
});

describe('new named main journal without runtime or private artifacts', () => {
  it('preserves default inspect namespace and performs zero POSTs or reads for empty lanes', async () => {
    const f = fixture(), selected = select('overlap', 'freshFixture', undefined), g = store(f, selected), binding = structuredClone(g.binding);
    const report = await f.run(selected, 'inspect'); expect(report.passed).toBe(true); expect(report).not.toHaveProperty('caseId');
    expect(f.methods).toEqual([]); expect(f.h.once).not.toHaveBeenCalled(); expect(f.state).not.toHaveProperty('currentBusinessScheduleSafetyNamedCases');
    expect(g.binding).toEqual(binding); expect(g.version).toBe(1); expect(g).not.toHaveProperty('caseBinding');
    expect(runtime.open.mock.calls.at(-1)).toEqual(['/synthetic-case-safety/reports/business-schedule-safety-overlap-inspect.json', 'wx', 0o644]);
    expect(JSON.parse(console.log.mock.calls.at(-1)[0])).not.toHaveProperty('caseId');
  });
  it('creates a new explicit preflight case without changing legacy bytes and reports only the public caseId', async () => {
    const f = fixture(), old = select('overlap', 'otherFixture', undefined); store(f, old);
    const oldBytes = JSON.stringify(f.state.currentBusinessScheduleSafetyCases), selected = select();
    const report = await f.run(selected, 'preflight'); expect(report.passed).toBe(true); expect(report.caseId).toBe(namedId);
    expect(JSON.stringify(f.state.currentBusinessScheduleSafetyCases)).toBe(oldBytes);
    expect(f.state.currentBusinessScheduleSafetyNamedCases.overlap[namedId]).toMatchObject({version: 2, binding: {serviceId: f.state.metadataAcceptance.freshFixture.serviceId}});
    expect(f.methods).toHaveLength(3); expect(f.methods.every(call => call.method === 'GET')).toBe(true); expect(f.h.once).not.toHaveBeenCalled();
    const text = JSON.stringify(report); expect(text).not.toContain(f.admin.cookie); expect(text).not.toContain(f.reviewer.cookie);
    expect(text).not.toContain(f.admin.csrf); expect(text).not.toContain('caseBinding'); expect(text).not.toContain('subjects');
    expect(report).toMatchObject({rootSqlFactsVerified: false, rootRestartTimelineVerified: false, overallM11Accepted: false});
    expect(JSON.parse(console.log.mock.calls.at(-1)[0]).caseId).toBe(namedId);
  });
  it('uses the explicit named inspect report filename while keeping all HTTP absent', async () => {
    const f = fixture(), selected = select(); store(f, selected);
    expect((await f.run(selected, 'inspect')).passed).toBe(true); expect(f.methods).toEqual([]); expect(f.h.once).not.toHaveBeenCalled();
    expect(runtime.open.mock.calls.at(-1)).toEqual([`/synthetic-case-safety/reports/business-schedule-safety-overlap-${namedId}-inspect.json`, 'wx', 0o644]);
  });
  it('rejects changing the selected case fixture field before saving or transport', async () => {
    const f = fixture(), selected = select(); store(f, selected); const bytes = JSON.stringify(f.state);
    expect((await f.run({...selected, fixtureField: 'otherFixture'}, 'inspect')).passed).toBe(false);
    expect(JSON.stringify(f.state)).toBe(bytes); expect(f.h.save).not.toHaveBeenCalled(); expect(f.methods).toEqual([]);
  });
  it('rejects a changed Service metadata assignment rather than trusting its stored self-consistent caseBinding', async () => {
    const f = fixture(), selected = select(); store(f, selected); f.state.metadataAcceptance.freshFixture.serviceId = randomUUID();
    const bytes = JSON.stringify(f.state); expect((await f.run(selected, 'inspect')).passed).toBe(false);
    expect(JSON.stringify(f.state)).toBe(bytes); expect(f.h.save).not.toHaveBeenCalled(); expect(f.methods).toEqual([]);
  });
  it.each([['admin', 'id'], ['admin', 'sid'], ['reviewer', 'id'], ['reviewer', 'sid']])('rejects changed current %s %s even with a fresh internally valid synthetic cookie', async (role, field) => {
    const f = fixture(), selected = select(); store(f, selected); const actor = f[role];
    if (field === 'id') actor.user.id = randomUUID(); else actor.sid = randomUUID(); refreshSyntheticCookie(actor);
    const bytes = JSON.stringify(f.state); const report = await f.run(selected, 'inspect'); expect(report.passed).toBe(false);
    expect(JSON.stringify(f.state)).toBe(bytes); expect(f.h.save).not.toHaveBeenCalled(); expect(f.methods).toEqual([]); expect(f.h.once).not.toHaveBeenCalled();
  });
  it('does not replay a failed stage or replace its original command key', async () => {
    const f = fixture(), selected = select(), g = store(f, selected);
    g.runs.prepare = {state: 'failed', errorCode: 'SYNTHETIC_FAILURE'};
    g.commands['prepare:A-snapshot'] = {key: randomUUID(), state: 'selected'}; const bytes = JSON.stringify(f.state);
    expect((await f.run(selected, 'prepare')).passed).toBe(false); expect(JSON.stringify(f.state)).toBe(bytes);
    expect(f.methods).toEqual([]); expect(f.h.once).not.toHaveBeenCalled(); expect(f.h.save).not.toHaveBeenCalled();
  });
  it('cannot use a new case name to bypass any historical unknown write', async () => {
    const f = fixture(), selected = select(); f.state.requests.push({method: 'POST', path: '/historical/private', key: 'synthetic-private-key', state: 'response_unknown'});
    const bytes = JSON.stringify(f.state), report = await f.run(selected, 'preflight'); expect(report.passed).toBe(false);
    expect(report.requests).toEqual([]); expect(JSON.stringify(f.state)).toBe(bytes); expect(f.h.save).not.toHaveBeenCalled(); expect(f.methods).toEqual([]);
    expect(JSON.stringify(report)).not.toContain('/historical/private');
  });
});

describe('named once commands retain original journal and global fence', () => {
  it('uses the named prefix and refuses reselecting the same command even after a known response', async () => {
    const f = fixture(), g = group(f); observedOnce(f);
    const path = `/clusters/${g.clusterId}/snapshots?workspaceId=${g.workspaceId}`, body = {name: 'synthetic-snapshot'};
    expect((await businessSafetyCommand(f.h, g, 'prepare', 'A-snapshot', path, body)).status).toBe(201);
    const command = structuredClone(g.commands['prepare:A-snapshot']); expect(command.label).toBe(`m11-business-safety.case:overlap:${namedId}:prepare:A-snapshot`);
    await expect(businessSafetyCommand(f.h, g, 'prepare', 'A-snapshot', path, body)).rejects.toThrow();
    expect(g.commands['prepare:A-snapshot']).toEqual(command); expect(f.h.once).toHaveBeenCalledTimes(1);
  });
  it('keeps case-specific once labels independent without reusing either original key', async () => {
    const f = fixture(), first = group(f), second = group(f, select('overlap', 'otherFixture', 'another-case')); observedOnce(f);
    const path = `/clusters/${first.clusterId}/snapshots?workspaceId=${first.workspaceId}`;
    await businessSafetyCommand(f.h, first, 'prepare', 'A-snapshot', path, {name: 'first'});
    await businessSafetyCommand(f.h, second, 'prepare', 'A-snapshot', path, {name: 'second'});
    expect(f.h.once).toHaveBeenCalledTimes(2); expect(new Set(f.state.requests.map(p => p.label)).size).toBe(2);
    expect(first.commands['prepare:A-snapshot'].key).not.toBe(second.commands['prepare:A-snapshot'].key);
  });
  it('checks the global unknown fence before selecting any new case command key', async () => {
    const f = fixture(), g = group(f); f.state.requests.push({state: 'response_unknown'});
    const path = `/clusters/${g.clusterId}/snapshots?workspaceId=${g.workspaceId}`;
    await expect(businessSafetyCommand(f.h, g, 'prepare', 'A-snapshot', path, {})).rejects.toThrow('ORIGINAL_GLOBAL_UNKNOWN_NO_REPLAY');
    expect(g.commands).toEqual({}); expect(f.h.once).not.toHaveBeenCalled(); expect(f.h.save).not.toHaveBeenCalled();
  });
});
