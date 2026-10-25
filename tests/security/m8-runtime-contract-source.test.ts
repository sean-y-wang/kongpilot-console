// @ts-nocheck: actual ESM helpers with synthetic RAM DTOs; no HTTP or env.
import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { assertConfigurationReceipt, boundedSnapshotObjects, configurationWrite, completeConfigurationWorkflow } from './lib/m8-configuration-acceptance.mjs';
import { hmacAuthorization, jwtAuthorization } from './lib/m8-native-acceptance.mjs';

const area = { cid: randomUUID(), wid: randomUUID() }, actor = { user: { id: randomUUID() }, sid: randomUUID() }, key = randomUUID(), jobId = randomUUID();
const check = (condition, label) => { if (!condition) throw Error(label); };
const receipt = () => ({ domain: 'configuration', durable: true, id: jobId, jobId, actorId: actor.user.id, clusterId: area.cid, workspaceId: area.wid, originalScope: { clusterId: area.cid, workspaceId: area.wid }, idempotencyKey: key, kind: 'capture', state: 'succeeded' });
const h = () => ({ check, state: { configurationOperations: [], workflowOperations: [] }, save: vi.fn(), data: v => v.payload.data,
  poll: async (read, predicate) => { const value = await read(); check(predicate(value), 'predicate'); return value; } });
describe('actual M8 acceptance contracts with RAM-only replies', () => {
  it('original receipt cannot borrow another actor, job, key or either scope', () => {
    for (const changed of [{actorId: randomUUID()}, {id: randomUUID()}, {jobId: randomUUID()}, {idempotencyKey: randomUUID()}, {workspaceId: randomUUID()}, {clusterId: randomUUID()}, {originalScope: {clusterId: area.cid, workspaceId: randomUUID()}}, {domain:'workflow'}, {durable:false}]) {
      expect(() => assertConfigurationReceipt(h(), {...receipt(), ...changed}, {actor, area, key, jobId, kind:'capture'})).toThrow();
    }
    expect(assertConfigurationReceipt(h(), receipt(), {actor, area, key, jobId, kind:'capture'})).toEqual(receipt());
  });
  it('known failed or uncertain configuration job never becomes successful or permits another POST', async () => {
    for (const state of ['failed','uncertain','partial']) {
      const harness = h(); harness.request = vi.fn(async (_actor, path, method, _body, options) => ({payload:{data:{...receipt(),idempotencyKey: options?.key ?? harness.state.configurationOperations[0].key,state}}}));
      await expect(configurationWrite(harness, actor, area, 'snapshots', {scope:'workspace',name:'synthetic'}, {kind:'capture'})).rejects.toThrow('succeeds');
      expect(harness.request.mock.calls.filter(c=>c[2]==='POST')).toHaveLength(1);
    }
  });
  it('foreign current by-key receipt fails even after a genuine initial success', async () => {
    const harness=h(); harness.request=vi.fn(async (_a,_p,method='GET',_b,options)=>({payload:{data:{...receipt(),idempotencyKey:options?.key??harness.state.configurationOperations[0].key,...(method==='GET'?{actorId:randomUUID()}: {})}}}));
    await expect(configurationWrite(harness,actor,area,'snapshots',{}, {kind:'capture'})).rejects.toThrow('original actor');
    expect(harness.request.mock.calls.filter(c=>c[2]==='POST')).toHaveLength(1);
  });
  it('bounded snapshot pages prove terminal EOF and unique typed IDs', async () => {
    const id=randomUUID(),summary={id,clusterId:area.cid,workspaceId:area.wid},harness=h();let n=0;
    harness.request=vi.fn(async()=>({payload:{data:{entity:summary,items:[{objectKey:`services:${++n}`}],nextCursor:n===1?'next':null}}}));
    const result=await boundedSnapshotObjects(harness,actor,area,id,1);
    expect(result.pages).toBe(2);expect(result.terminalObserved).toBe(true);expect(result.objects).toHaveLength(2);
  });
  it('duplicated typed object or non-advancing cursor cannot pass actual EOF proof', async () => {
    for(const mode of ['duplicate','cursor']) {
      const harness=h(),id=randomUUID();let n=0;harness.request=vi.fn(async()=>({payload:{data:{entity:{id,clusterId:area.cid,workspaceId:area.wid},items:[{objectKey: mode==='duplicate'?'services:reused':`services:${++n}`}],nextCursor:'same'}}}));
      await expect(boundedSnapshotObjects(harness,actor,area,id,1)).rejects.toThrow();
      expect(harness.request.mock.calls.length).toBeLessThanOrEqual(2);
    }
  });
  it('V1 native steps or wrong fixed handler never reach approval or execute', async () => {
    for(const kind of ['native','wrong-handler']) {
      const harness=h(),workflowId=randomUUID();harness.request=vi.fn(async()=>({payload:{data:{entity:{id:workflowId,clusterId:area.cid,workspaceId:area.wid,kind:'configuration_v2',planHash:'a'.repeat(64)},steps:[{kind:kind==='native'?'native':'metadata',handler:kind==='native'?'configuration_v2':'configuration.metadata',nativeRequests:[]}]}}}));
      await expect(completeConfigurationWorkflow(harness,{admin:actor,approver:{user:{id:randomUUID()}}},area,{workflowId,state:'waiting_approval'},'configuration_v2','configuration_v2')).rejects.toThrow(kind==='native'?'configuration public wrapper':'explicitly exposed workflow packet');
      expect(harness.request).toHaveBeenCalledTimes(1);
      expect(harness.request.mock.calls.some(c=>c[2]==='POST')).toBe(false);
    }
  });
  it('JWT/HMAC proofs are produced from the exact fresh input, not a canned token', () => {
    const input={username:'synthetic',key:'issuer',secret:'SyntheticOwnedSecret'};
    const token=jwtAuthorization(input); expect(token).toMatch(/^Bearer [^.]+\.[^.]+\.[^.]+$/);
    expect(jwtAuthorization({...input,secret:'OtherSyntheticSecret'})).not.toBe(token);
    const date='Sun, 11 Oct 2026 12:00:00 GMT';expect(hmacAuthorization(input,date)).not.toBe(hmacAuthorization(input,'Sun, 11 Oct 2026 12:00:01 GMT'));
  });
});
