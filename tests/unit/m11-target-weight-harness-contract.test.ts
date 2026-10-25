import { describe, expect, it } from 'vitest';
import { targetWeightInvocation, targetWeightSession, targetWeightApprovalPolicy, targetWeightPrepared,
  targetWeightExecution, targetWeightRows } from '../security/m11-target-weight-http.mjs';

// Import-safe pure contract tests: no harness constructor/private read/fetch.
const id = '109621c2-cf81-4e25-b87b-4cdecc148ad5', next = 'b06ca9f4-98cf-49de-aa71-f58220d5375b', parent = 'd0350b4a-f011-4c8a-9eb3-5e65479e4d6b';
const sid = '83b737fc-f02f-4dc3-b5f0-470fdb4c82c7';
const subjects = { admin: id, a: next, b: parent, c: sid };
const env = { RELEASE_LAB_READY: 'true', RELEASE_LAB_M11_TARGET_WEIGHT_READY: 'true' };
const session = (remaining: number, now: number) => ({ user: { id }, sid, csrf: 'synthetic-source-csrf',
  cookie: `kongos_access=x.${Buffer.from(JSON.stringify({ sub: id, sid, exp: (now + remaining * 1000) / 1000 })).toString('base64url')}.x; kongos_csrf=synthetic-source-csrf` });
const definition = () => ({ format: 2, policy: { version: 2, kind: 'native-change', allowSelfApproval: false, distinctAcrossStages: true,
  stages: [{ level: 1, mode: 'any', threshold: 1, selector: { users: [subjects.a] } }, { level: 2, mode: 'all', threshold: null, selector: { users: [subjects.b, subjects.c] } }] } });
const operation = { kind: 'target', action: 'weight', upstreamId: parent, targetId: id, body: { weight: 80 } };
const prepared = () => ({ id: sid, revision: 1, review: { impact: { nativePackets: 1 }, changes: [{ entityType: 'targets', action: 'update', nativeId: next, originalNativeId: id,
  before: { id, target: 'echo:8080', weight: 100 }, after: { id: next, target: 'echo:8080', weight: 80 } }] } });
const receipt = { state: 'succeeded', executionId: sid, baselineId: parent };
const detail = () => ({ entity: { state: 'succeeded', capabilities: { rollbackPrepare: false } }, nativeChange: { executionId: sid,
  packets: [{ state: 'succeeded', nativeStatus: 201, entityId: next, operationId: id }], baseline: { nativeAuthority: false, baseline: { baselineId: parent, objectCount: 3 } } } });
const row = (nativeId: string, weight: number) => ({ id: nativeId, upstream: { id: parent }, target: 'echo:8080', weight });

describe('Source-only Target acceptance harness contracts', () => {
  it('requires both explicit flags and exactly one canonical stage', () => {
    expect(targetWeightInvocation(['node', 'script', 'create'], env)).toBe('create');
    for (const args of [['node', 'script'], ['node', 'script', 'health'], ['node', 'script', 'create', 'retry']]) expect(() => targetWeightInvocation(args, env)).toThrow();
    expect(() => targetWeightInvocation(['node', 'script', 'readonly'], {})).toThrow();
  });
  it('stops at120s without altering cookies, expiry, SID or requesting a refresh', () => {
    const now = 1000000, current = session(121, now); expect(targetWeightSession(current, id, now)).toBe(current);
    for (const seconds of [120, 119, 0]) expect(() => targetWeightSession(session(seconds, now), id, now)).toThrow();
    expect(() => targetWeightSession(current, next, now)).toThrow(); expect(current.sid).toBe(sid);
  });
  it('checks the actual current two-stage independent three-vote selector instead of modifying policy', () => {
    expect(() => targetWeightApprovalPolicy(definition(), subjects)).not.toThrow();
    const changed = definition(); changed.policy.stages[1].selector.users = [subjects.b, subjects.admin];
    expect(() => targetWeightApprovalPolicy(changed, subjects)).toThrow();
    const self = definition(); self.policy.allowSelfApproval = true; expect(() => targetWeightApprovalPolicy(self, subjects)).toThrow();
  });
  it('requires a new server UUID bound to the original target and exact weight review', () => {
    expect(targetWeightPrepared(prepared(), operation, id)).toBe(next);
    const changed = prepared(); changed.review.changes[0].nativeId = id;
    expect(() => targetWeightPrepared(changed, operation, id)).toThrow();
    const wrong = prepared(); wrong.review.changes[0].originalNativeId = parent; expect(() => targetWeightPrepared(wrong, operation, id)).toThrow();
  });
  it('requires genuine packet native201, immutable baseline and closed rollback capability', () => {
    expect(targetWeightExecution(detail(), receipt, { nativeId: next }, 3).nativeStatus).toBe(201);
    for (const status of [null, 200, 204]) { const changed = detail(); changed.nativeChange.packets[0].nativeStatus = status as any; expect(() => targetWeightExecution(changed, receipt, { nativeId: next }, 3)).toThrow(); }
    const old = detail(); old.nativeChange.packets[0].entityId = id; expect(() => targetWeightExecution(old, receipt, { nativeId: next }, 3)).toThrow();
    const rollback = detail(); rollback.entity.capabilities.rollbackPrepare = true; expect(() => targetWeightExecution(rollback, receipt, { nativeId: next }, 3)).toThrow();
  });
  it('distinguishes live physical history from effective selection and rejects modified old rows', () => {
    const history = { selection: 'history', current_selection: false, items: [row(id, 100), row(next, 80)] };
    const expected = [{ id, weight: 100 }, { id: next, weight: 80 }];
    expect(() => targetWeightRows(history, { items: [row(next, 80)] }, expected, parent, 'echo:8080', next, 80)).not.toThrow();
    expect(() => targetWeightRows(history, { items: [row(id, 100)] }, expected, parent, 'echo:8080', next, 80)).toThrow();
    const changed = structuredClone(history); changed.items[0].weight = 99;
    expect(() => targetWeightRows(changed, { items: [row(next, 80)] }, expected, parent, 'echo:8080', next, 80)).toThrow();
  });
  it('requires weight0 in history and absence from effective selection rather than a fabricated current row', () => {
    const history = { selection: 'history', current_selection: false, items: [row(id, 100), row(next, 0)] };
    const expected = [{ id, weight: 100 }, { id: next, weight: 0 }];
    expect(() => targetWeightRows(history, { items: [] }, expected, parent, 'echo:8080', next, 0)).not.toThrow();
    expect(() => targetWeightRows(history, { items: [row(next, 0)] }, expected, parent, 'echo:8080', next, 0)).toThrow();
  });
  it('accepts native-cleaned physical history only after an original zero-weight result and actual effective absence',()=>{
    const history={selection:'history',current_selection:false,items:[]},expected=[{id,weight:100},{id:next,weight:0}];
    expect(()=>targetWeightRows(history,{items:[]},expected,parent,'echo:8080',next,0)).not.toThrow();
    expect(()=>targetWeightRows(history,{items:[row(id,100)]},expected,parent,'echo:8080',next,0)).toThrow();
    expect(()=>targetWeightRows(history,{items:[]},[{id,weight:100}],parent,'echo:8080',next,0)).toThrow();
    expect(()=>targetWeightRows(history,{items:[]},expected,parent,'echo:8080',id,80)).toThrow();
  });
});
