import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { CONFIGURATION_TIMEOUT_MS } from '../../apps/console-api/src/infrastructure/kong/configuration-budget';
import { WorkflowScheduledAuthorityService } from '../../apps/console-api/src/modules/workflows/workflow-scheduled-authority.service';
import { WorkflowScheduledNamespaceService } from '../../apps/console-api/src/modules/workflows/workflow-scheduled-namespace.service';
import { workflowScheduledFixture } from './helpers/workflow-scheduled-fixture';

/** Real Authority/private handles -> Namespace -> Context.make with controlled
 * SQL/lease/completion adapters. No real SQL, HTTP, mutation, native execution
 * or production scheduler acceptance is asserted by this Source fixture. */
function fixture(kind: 'configuration_v2' | 'portal-credential-issue' = 'configuration_v2') {
  const f = workflowScheduledFixture(kind), context = new KongExecutionContextService();
  const authority = new WorkflowScheduledAuthorityService(f.db, f.secrets, f.redis, context, f.plans, f.approvals, f.repository);
  const namespaces = new WorkflowScheduledNamespaceService(authority, f.secrets, f.redis);
  let lastNamespace: object | undefined, actualCallback: (() => Promise<void>) | undefined,lastBegin:((handle:object)=>void)|undefined;
  const faults={construction:false,beforeBusiness:false,forgedNamespace:false};
  context.installWorkflowScheduledNamespacePolicy({ assertLive: namespaces.assertLive.bind(namespaces), verifyHandle: namespaces.verifyHandle.bind(namespaces) });
  namespaces.installContextRunner({ assertNoFrame() { if (context.peek() !== null) throw new ForbiddenException({ code: 'REAL_EMPTY_CONTEXT_REQUIRED' }); },
    run(handle, fn) { lastNamespace = handle;
      // Controlled bad runner configuration invokes the real Context.make
      // validation. It never calls the callback or creates a replacement SID.
      if(faults.construction)return context.runSystemRead(f.cid,'probe',fn,{timeoutMs:120001});
      return context.runWorkflowScheduledNamespace(handle, fn);
    } });
  authority.installBusinessPolicy(kind, f.policy); authority.installRepositoryPolicies('a'.repeat(64));
  const executor = { executeClaim: vi.fn(async (handle: object,begin:(namespace:object)=>void) => {
    lastBegin=begin;
    await namespaces.runOriginalClaim(handle, async () => {
      if(faults.beforeBusiness)throw new ForbiddenException({code:'SOURCE_BEFORE_BUSINESS_CALLBACK'});
      begin(faults.forgedNamespace?{}:context.requireWorkflowScheduledNamespaceHandle());await actualCallback?.();
    });
    return f.complete();
  }), verifyCompletion: f.executor.verifyCompletion };
  authority.installExecutor(executor);
  const acquire = () => authority.acquireDueClaim(f.scheduleId);
  const execute = (handle: object, callback: () => Promise<void>) => { actualCallback = callback; return authority.executeClaim(handle); };
  const run = async (callback: () => Promise<void>) => { const handle = await acquire(); expect(handle).not.toBeNull(); await execute(handle!, callback); return handle!; };
  return { ...f, context, authority, namespaces, executor, acquire, execute, run,faults,lastBegin:()=>lastBegin!, lastNamespace: () => lastNamespace! };
}
beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-14T14:00:00Z')); });
afterEach(() => { vi.restoreAllMocks();vi.useRealTimers(); vi.unstubAllEnvs(); });

describe('original business namespace budget through real Context.make', () => {
  it.each(['construction','beforeBusiness','forgedNamespace']as const)('closes only the actual zero-execution %s failure before the private business callback',async fault=>{
    const f=fixture(),handle=await f.acquire(),callback=vi.fn(async()=>undefined);f.faults[fault]=true;
    await expect(f.execute(handle!,callback)).rejects.toMatchObject({response:{code:fault==='construction'?'KONG_EXECUTION_BUDGET_INVALID':fault==='beforeBusiness'?'SOURCE_BEFORE_BUSINESS_CALLBACK':'WORKFLOW_SCHEDULE_BUSINESS_CALLBACK_REQUIRED'}});
    expect(callback).not.toHaveBeenCalled();expect(f.state.stored.progress.state).toBe('failed');expect(f.state.workflowState).toBe('approved');expect(f.state.completionRow).toBeNull();
    expect(f.state.stored.progress.claimId).toBe(f.state.stored.claim.id);expect(f.state.outcomeEvidence.provenance).toBe('callback-not-entered');expect(f.repository.finishClaim).toHaveBeenCalledOnce();
    expect(f.executor.verifyCompletion).not.toHaveBeenCalled();expect(f.context.peek()).toBeNull();
    const absence=f.db.one.mock.calls.find(([sql]:any[])=>sql.includes('AS execution,')&&sql.includes('AS configuration_origin,'));expect(absence).toBeDefined();
    await expect(f.authority.executeClaim(handle!)).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_ORIGINAL_HANDLE_REQUIRED'}});
    expect(()=>f.lastBegin()(f.lastNamespace())).toThrow();
  });
  it.each(['execution','origin','configuration_origin','mutation','configuration_execution','missing','sql-unavailable','step-already-started'])('retains an original unresolved claim when %s prevents complete zero-execution proof after a construction error',async fault=>{
    const f=fixture(),handle=await f.acquire(),callback=vi.fn(async()=>undefined);f.faults.construction=true;
    if(fault==='missing')f.state.lifecycleFacts.execution=null;
    else if(fault==='sql-unavailable'){const original=f.db.one.getMockImplementation()!;f.db.one.mockImplementation(async(sql:string,p:any[])=>{if(sql.includes('AS execution,')&&sql.includes('AS configuration_origin,'))throw Error('SOURCE_ABSENCE_READ_UNAVAILABLE');return original(sql,p);});}
    else if(fault==='step-already-started'){const original=f.db.query.getMockImplementation()!;f.db.query.mockImplementation(async(sql:string,p:any[])=>{const rows=await original(sql,p);return sql.includes('FROM workflow_steps')?rows.map((row:any)=>({...row,started_at:new Date().toISOString()})):rows;});}
    else f.state.lifecycleFacts[fault]=true;
    await expect(f.execute(handle!,callback)).rejects.toMatchObject({response:{code:'KONG_EXECUTION_BUDGET_INVALID'}});
    expect(callback).not.toHaveBeenCalled();expect(f.state.stored.progress.state).toBe('claimed');expect(f.repository.finishClaim).not.toHaveBeenCalled();expect(f.executor.verifyCompletion).not.toHaveBeenCalled();expect(f.state.outcomeEvidence).toBeUndefined();
    expect(f.context.peek()).toBeNull();await expect(f.authority.executeClaim(handle!)).rejects.toThrow();
  });
  it('requires the private original namespace at the one-shot callback boundary and closes the closure after return',async()=>{
    const f=fixture();await f.run(async()=>{
      expect(()=>f.lastBegin()(f.lastNamespace())).toThrow(); // consumed exactly once
      expect(()=>f.lastBegin()({...f.lastNamespace()})).toThrow();
    });
    expect(f.state.stored.progress.state).toBe('succeeded');expect(()=>f.lastBegin()(f.lastNamespace())).toThrow();
  });
  it('does not accept even an authentic completion when the private business callback was never entered',async()=>{
    const f=fixture(),handle=await f.acquire(),callback=vi.fn(async()=>undefined);let captured:((namespace:object)=>void)|undefined;
    f.executor.executeClaim.mockImplementation(async(_original,begin)=>{captured=begin;return f.complete();});
    await expect(f.execute(handle!,callback)).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_BUSINESS_CALLBACK_REQUIRED'}});
    expect(callback).not.toHaveBeenCalled();expect(f.executor.verifyCompletion).not.toHaveBeenCalled();expect(f.repository.finishClaim).not.toHaveBeenCalled();expect(f.state.stored.progress.state).toBe('claimed');
    expect(f.state.outcomeEvidence).toBeUndefined();expect(()=>captured!({})).toThrow();
  });
  it('admits a real configuration namespace with more than 120 seconds of original lease/window', async () => {
    const f = fixture(); await f.run(async () => {
      const frame = f.context.current(), proof = await f.namespaces.verifyHandle(f.lastNamespace(), 'capture');
      expect(Date.parse(proof.expiresAt) - Date.now()).toBe(240000);
      expect(frame.kind).toBe('scheduled-workflow'); expect(frame.purpose).toBe('configuration');
      expect(frame.sessionId).toBeUndefined(); expect(proof.sessionId).toBeNull();
      expect(frame.limits).toEqual({ maxCalls: 1000, maxPages: 100, maxRecords: 10000, maxBytes: 32 * 1024 * 1024, timeoutMs: 240000 }); // user-approved 2026-10-24 scheduled configuration budget
      expect(frame.limits.timeoutMs).toBeLessThanOrEqual(CONFIGURATION_TIMEOUT_MS);
      expect(f.context.requireWorkflowScheduledNamespaceHandle()).toBe(f.lastNamespace());
      vi.advanceTimersByTime(120001);
      expect(f.context.current()).toBe(frame); await f.context.verifyWorkflowScheduledNamespace('before-send');
    });
    expect(f.executor.executeClaim).toHaveBeenCalledOnce(); expect(f.state.stored.progress.state).toBe('succeeded'); expect(f.context.peek()).toBeNull();
  });
  it('uses the sealed original Portal deadline without replacing it by a new 120-second root', async () => {
    const f = fixture('portal-credential-issue'); await f.run(async () => {
      const frame = f.context.current(),proof=await f.namespaces.verifyHandle(f.lastNamespace(),'capture');
      expect(frame.purpose).toBeUndefined();expect(frame.limits.timeoutMs).toBe(240000);
      expect(Date.parse(proof.expiresAt)-Date.now()).toBe(frame.limits.timeoutMs);
      vi.advanceTimersByTime(120001);expect(f.context.current()).toBe(frame);
      await f.context.verifyWorkflowScheduledNamespace('before-send');
    });expect(f.state.stored.progress.state).toBe('succeeded');expect(f.context.peek()).toBeNull();
  });
  it('uses the remaining original expiry when it is shorter than either product cap', async () => {
    const f = fixture(), handle = await f.acquire();
    vi.advanceTimersByTime(200000);
    await f.execute(handle!, async () => {
      expect(f.context.current().limits.timeoutMs).toBe(40000);
      expect(Date.parse((await f.namespaces.verifyHandle(f.lastNamespace(), 'packet')).expiresAt) - Date.now()).toBe(40000);
    });
    expect(f.context.peek()).toBeNull();
  });
  it('never extends the real namespace past its sealed window or lease', async () => {
    const f = fixture();
    await expect(f.run(async () => {
      const frame = f.context.current(); vi.advanceTimersByTime(frame.limits.timeoutMs);
      f.context.current();
    })).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_NAMESPACE_EXPIRED' } });
    expect(f.repository.finishClaim).not.toHaveBeenCalled(); expect(f.state.stored.progress.state).toBe('claimed');
  });
  it('checks real lease ownership after creating the configuration context', async () => {
    const f = fixture();
    await expect(f.run(async () => { f.state.lease = false; f.context.current(); })).rejects.toMatchObject({ response: { code: 'LIVE_LEASE_REQUIRED' } });
    expect(f.repository.finishClaim).not.toHaveBeenCalled(); expect(f.state.stored.progress.state).toBe('claimed');
  });
  it('keeps inherited child budgets charged to the actual configuration namespace deadline', async () => {
    const f = fixture(); await f.run(async () => {
      const root = f.context.current();
      await f.context.runInternalRead(f.cid, 'configuration', async () => {
        expect(f.context.current().limits.timeoutMs).toBe(CONFIGURATION_TIMEOUT_MS);
        expect(f.context.requireWorkflowScheduledNamespaceHandle()).toBe(f.lastNamespace());
        vi.advanceTimersByTime(120001); expect(f.context.current().actor?.id).toBe(f.owner);
      });
      expect(f.context.current()).toBe(root);
    });
  });
  it('closes the original frame and handle after callback completion', async () => {
    const f = fixture(); let late!: () => void;
    await f.run(async () => { late = () => f.context.current(); });
    expect(f.context.peek()).toBeNull(); expect(() => f.namespaces.assertLive(f.lastNamespace())).toThrow();
    await expect(f.context.runWorkflowScheduledNamespace(f.lastNamespace(), async () => true)).rejects.toThrow();
    expect(() => late()).toThrow();
  });
  it.each(['proof-copy', 'actor-copy', 'fake-kind', 'fake-null-sid'] as const)('does not admit a %s instead of an original namespace handle', async cause => {
    const f = fixture(), callback = vi.fn(async () => true);
    const forged = cause === 'fake-kind' ? { kind: 'configuration_v2', purpose: 'configuration' }
      : cause === 'fake-null-sid' ? { origin: 'scheduled-workflow', kind: 'configuration_v2', sessionId: null }
      : cause === 'actor-copy' ? { ...f.actor.user } : { ...f.plan, sessionId: null };
    await expect(f.context.runWorkflowScheduledNamespace(forged, callback)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_ORIGINAL_NAMESPACE_REQUIRED' } });
    expect(callback).not.toHaveBeenCalled(); expect(f.executor.executeClaim).not.toHaveBeenCalled(); expect(f.context.peek()).toBeNull();
  });
  it('rejects an inherited HTTP parent and cannot reset it to gain the longer budget', async () => {
    const f = fixture(), handle = await f.acquire(), callback = vi.fn(async () => {});
    await f.context.runHttp({ requestId: 'source-only' }, async () => {
      const original = f.context.current();
      await expect(f.execute(handle!, callback)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_BACKGROUND_CONTEXT_REQUIRED' } });
      expect(f.context.current()).toBe(original); expect(original.limits.timeoutMs).toBe(120000);
    });
    expect(callback).not.toHaveBeenCalled(); expect(f.executor.executeClaim).not.toHaveBeenCalled();
  });
  it('keeps ordinary purpose caps closed rather than broadening Context.make', async () => {
    const context = new KongExecutionContextService();
    await expect(Promise.resolve().then(() => context.runSystemRead(randomUUID(), 'probe', async () => {}, { timeoutMs: 120001 }))).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_BUDGET_INVALID' } });
    await expect(Promise.resolve().then(() => context.runSystemRead(randomUUID(), 'probe', async () => {}, { maxCalls: 501 }))).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_BUDGET_INVALID' } });
    await context.runHttp({}, async () => { expect(context.current().limits.timeoutMs).toBe(120000); });
  });
  it('keeps an errored already-entered original claim unresolved and never replays it', async () => {
    const f = fixture(), handle = await f.acquire();
    await expect(f.execute(handle!, async () => { throw new Error('controlled failure after original Namespace entry'); })).rejects.toThrow();
    expect(f.state.stored.progress.state).toBe('claimed'); expect(f.repository.finishClaim).not.toHaveBeenCalled();
    await expect(f.execute(handle!, async () => {})).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_ORIGINAL_HANDLE_REQUIRED' } });
    expect(f.executor.executeClaim).toHaveBeenCalledOnce(); expect(f.context.peek()).toBeNull();
  });
  it.each(['configuration_v2','portal-credential-issue'] as const)('keeps ordinary %s actor and operation caps within the original absolute deadline',async kind=>{
    const f=fixture(kind);await f.run(async()=>{
      const root=f.context.current(),original=Date.parse((await f.namespaces.verifyHandle(f.lastNamespace(),'capture')).expiresAt);
      vi.advanceTimersByTime(30000);
      const scope={actor:root.actor!,clusterId:f.cid,workspaceId:f.wid,module:'consumers',action:'write'};
      await f.context.runActor(scope,async()=>{
        expect(f.context.current().purpose).toBeUndefined();expect(f.context.current().limits.timeoutMs).toBe(120000);expect(f.context.current().limits.timeoutMs).toBeLessThan(original-Date.now());
        vi.advanceTimersByTime(60000);expect(f.context.current().limits.timeoutMs).toBe(120000);
        await f.context.runOperation({...scope,operationId:randomUUID(),entityType:'consumers',entityId:randomUUID()},async()=>{
          expect(f.context.current().limits.timeoutMs).toBe(60000);expect(f.context.requireWorkflowScheduledNamespaceHandle()).toBe(f.lastNamespace());
          vi.advanceTimersByTime(1000);expect(f.context.current().actor?.id).toBe(f.owner);
        });
      });expect(f.context.current()).toBe(root);
    });expect(f.state.stored.progress.state).toBe('succeeded');
  });
  it.each(['configuration_v2','portal-credential-issue'] as const)('does not renew %s when a late actor reaches the original end',async kind=>{
    const f=fixture(kind);await expect(f.run(async()=>{
      const root=f.context.current();vi.advanceTimersByTime(200000);
      await f.context.runActor({actor:root.actor!,clusterId:f.cid,workspaceId:f.wid},async()=>{
        expect(f.context.current().limits.timeoutMs).toBe(40000);vi.advanceTimersByTime(40001);
      });
    })).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CONTEXT_EXPIRED'}});
    expect(f.repository.finishClaim).not.toHaveBeenCalled();expect(f.state.stored.progress.state).toBe('claimed');
  });
  it.each(['configuration_v2','portal-credential-issue'] as const)('preserves a shorter %s ancestor and its expiry at the outer await',async kind=>{
    const f=fixture(kind);await expect(f.run(()=>f.context.runInternalRead(f.cid,'operation-check',async()=>{
      const parent=f.context.current();await f.context.runActor({actor:parent.actor!,clusterId:f.cid,workspaceId:f.wid},async()=>{
        expect(f.context.current().limits.timeoutMs).toBe(5000);vi.advanceTimersByTime(5001);
      });
    },{timeoutMs:5000}))).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CONTEXT_EXPIRED'}});
    expect(f.repository.finishClaim).not.toHaveBeenCalled();
  });
  it.each(['configuration_v2','portal-credential-issue'] as const)('does not reset %s original calls/pages/rows/bytes between fresh actor frames',async kind=>{
    const f=fixture(kind);f.context.installPolicy({async authorizeRequest(){return{};},async authorizeResponse(_ticket,result){return result;}});
    const cluster:any={id:f.cid,admin_url:'http://kong:8001',version:'1.5.1',execution_mode:'approval'};
    await f.run(async()=>{const root=f.context.current(),response={data:[{id:randomUUID()},{id:randomUUID()}],next:null};
      for(let i=1;i<=3;i++){
        await f.context.runActor({actor:root.actor!,clusterId:f.cid,workspaceId:f.wid},async()=>{
          expect(f.context.currentUsage()).toEqual({calls:0,pages:0,records:0,bytes:0});
          const ticket=await f.context.authorizeRequest(cluster,'GET','/consumers',undefined,{size:2});
          await f.context.authorizeResponse(ticket,response);
          expect(f.context.currentUsage()).toEqual({calls:1,pages:1,records:2,bytes:Buffer.byteLength(JSON.stringify(response))});
        });expect(f.context.currentUsage()).toEqual({calls:i,pages:i,records:i*2,bytes:i*Buffer.byteLength(JSON.stringify(response))});
        vi.advanceTimersByTime(40000);
      }
      expect(root.limits).toMatchObject({maxCalls:kind==='configuration_v2'?1000:500,maxPages:100,maxRecords:10000,maxBytes:32*1024*1024});
    });
  });
  it.each(['configuration_v2','portal-credential-issue'] as const)('rejects %s detached late actor entry instead of resurrecting a closed namespace',async kind=>{
    const f=fixture(kind);let release!:()=>void,late!:Promise<unknown>;const gate=new Promise<void>(resolve=>{release=resolve;});
    const callback=vi.fn(async()=>undefined);await f.run(async()=>{
      const original=f.context.current();late=(async()=>{await gate;return f.context.runActor({actor:original.actor!,clusterId:f.cid,workspaceId:f.wid},callback);})();
    });release();await expect(late).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CONTEXT_EXPIRED'}});expect(callback).not.toHaveBeenCalled();
  });
  it.each(['configuration_v2','portal-credential-issue'] as const)('keeps %s grant and lease revalidation after extending no authority',async kind=>{
    const f=fixture(kind);await expect(f.run(async()=>{
      const original=f.context.current();vi.advanceTimersByTime(120001);f.state.lease=false;
      await f.context.runActor({actor:original.actor!,clusterId:f.cid,workspaceId:f.wid},async()=>undefined);
    })).rejects.toMatchObject({response:{code:'LIVE_LEASE_REQUIRED'}});expect(f.repository.finishClaim).not.toHaveBeenCalled();
  });
  it('does not let an unrelated workspace buy the original delegated actor envelope',async()=>{
    const f=fixture('portal-credential-issue');await f.run(async()=>{
      const original=f.context.current();await f.context.runActor({actor:original.actor!,clusterId:f.cid,workspaceId:randomUUID()},async()=>{
        expect(f.context.current().limits.timeoutMs).toBe(120000);
      });
    });
  });
  it('preserves ordinary HTTP actor and operation 120-second limits without genuine namespace provenance',async()=>{
    const context=new KongExecutionContextService(),actor:any={id:randomUUID()},scope={actor,clusterId:randomUUID(),workspaceId:randomUUID()};
    await context.runHttp({},async()=>{context.bindHttpActor(actor,'real-source-sid');await context.runActor(scope,async()=>{
      expect(context.current().limits.timeoutMs).toBe(120000);await context.runOperation({...scope,operationId:randomUUID(),entityType:'consumers'},async()=>{
        expect(context.current().limits.timeoutMs).toBe(120000);
      });
    });});
  });

  it.each(['configuration_v2','portal-credential-issue'] as const)('charges every retry to the original %s call meter (configuration_v2 1000, others 500) across two actor frames',async kind=>{
    const f=fixture(kind),half=kind==='configuration_v2'?500:250;f.context.installPolicy({async authorizeRequest(){return{};},async authorizeResponse(_ticket,result){return result;}});
    const cluster:any={id:f.cid,admin_url:'http://kong:8001',version:'1.5.1',execution_mode:'approval'};
    await expect(f.run(async()=>{const root=f.context.current();for(let frame=0;frame<2;frame++){
      await f.context.runActor({actor:root.actor!,clusterId:f.cid,workspaceId:f.wid},async()=>{
        const ticket=await f.context.authorizeRequest(cluster,'GET','/consumers',undefined,{size:1});
        for(let retry=0;retry<half-1;retry++)f.context.chargeRetry(ticket);
        expect(f.context.currentUsage().calls).toBe(half);
        const usage=f.context.currentScheduledWorkflowUsage();
        expect(usage.calls).toBe((frame+1)*half);expect(Object.isFrozen(usage)).toBe(true);
        expect(Object.keys(usage).sort()).toEqual(['bytes','calls','pages','records']);
        if(frame===1)f.context.chargeRetry(ticket);
      });expect(f.context.currentUsage().calls).toBe(half);vi.advanceTimersByTime(120001);
    }})).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CALL_LIMIT'}});
    expect(f.repository.finishClaim).not.toHaveBeenCalled();
    expect(()=>f.context.currentScheduledWorkflowUsage()).toThrow();
  });
  it.each(['configuration_v2','portal-credential-issue'] as const)('rechecks current %s approval grants after the original 120-second boundary',async kind=>{
    const f=fixture(kind);await expect(f.run(async()=>{
      vi.advanceTimersByTime(120001);f.state.reviewerActive=false;await f.context.verifyWorkflowScheduledNamespace('before-send');
    })).rejects.toThrow();expect(f.repository.finishClaim).not.toHaveBeenCalled();
  });
  it.each(['configuration_v2','portal-credential-issue'] as const)('fences %s expiry in the callback-return microtask gap',async kind=>{
    const f=fixture(kind);await expect(f.run(async()=>{
      // This continuation runs after the callback's final synchronous work,
      // before Context.run resumes from the ALS Promise.
      queueMicrotask(()=>vi.advanceTimersByTime(240001));
    })).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CONTEXT_EXPIRED'}});
    expect(f.repository.finishClaim).not.toHaveBeenCalled();
  });
});

/** User-approved 2026-10-24: scheduled configuration_v2 workflow executions get
 * their own 1000-call Kong budget; every other execution stays at 500 and both
 * fail closed one call above their cap. */
describe('scheduled configuration 1000-call budget versus the 500-call default', () => {
  const cluster=(cid:string):any=>({id:cid,admin_url:'http://kong:8001',version:'1.5.1',execution_mode:'approval'});
  const allow=(context:KongExecutionContextService)=>context.installPolicy({async authorizeRequest(){return{};},async authorizeResponse(_t,r){return r;}});
  it('admits exactly 1000 scheduled configuration_v2 calls and fails closed at 1001',async()=>{
    const f=fixture('configuration_v2');allow(f.context);
    await expect(f.run(async()=>{const root=f.context.current();expect(root.limits.maxCalls).toBe(1000);
      await f.context.runActor({actor:root.actor!,clusterId:f.cid,workspaceId:f.wid,purpose:'configuration'},async()=>{
        expect(f.context.current().limits.maxCalls).toBe(1000);
        const ticket=await f.context.authorizeRequest(cluster(f.cid),'GET','/consumers',undefined,{size:1});
        for(let i=0;i<999;i++)f.context.chargeRetry(ticket);
        expect(f.context.currentScheduledWorkflowUsage().calls).toBe(1000);
        f.context.chargeRetry(ticket);
      });
    })).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CALL_LIMIT'}});
    expect(f.repository.finishClaim).not.toHaveBeenCalled();
  });
  it('rejects an explicit request above 1000 even inside scheduled configuration_v2',async()=>{
    const f=fixture('configuration_v2');
    await f.run(async()=>{expect(()=>f.context.runInternalRead(f.cid,'capture',async()=>undefined,{maxCalls:1001})).toThrow();});
  });
  it('keeps non-configuration scheduled kinds at 500 and fails closed at 501',async()=>{
    const f=fixture('portal-credential-issue');allow(f.context);
    await expect(f.run(async()=>{const root=f.context.current();expect(root.limits.maxCalls).toBe(500);
      await f.context.runActor({actor:root.actor!,clusterId:f.cid,workspaceId:f.wid,purpose:'configuration'},async()=>{
        expect(f.context.current().limits.maxCalls).toBe(500);
        const ticket=await f.context.authorizeRequest(cluster(f.cid),'GET','/consumers',undefined,{size:1});
        for(let i=0;i<499;i++)f.context.chargeRetry(ticket);
        expect(f.context.currentUsage().calls).toBe(500);f.context.chargeRetry(ticket);
      });
    })).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CALL_LIMIT'}});
  });
  it('keeps non-scheduled interactive configuration executions at 500, fails at 501 and rejects 1000',async()=>{
    const context=new KongExecutionContextService();allow(context);const cid=randomUUID();
    const user:any={id:randomUUID(),username:'alice',role:'admin'};
    await expect(context.runHttp({requestId:'r',configurationWait:true},async()=>{context.bindHttpActor(user,randomUUID());
      expect(context.current().limits.maxCalls).toBe(500);
      expect(()=>context.runInternalRead(cid,'capture',async()=>undefined,{maxCalls:1000})).toThrow();
      await context.runActor({actor:user,clusterId:cid,workspaceId:'w',purpose:'configuration'},async()=>{
        expect(context.current().limits.maxCalls).toBe(500);
        const ticket=await context.authorizeRequest(cluster(cid),'GET','/consumers',undefined,{size:1});
        for(let i=0;i<499;i++)context.chargeRetry(ticket);
        expect(context.currentUsage().calls).toBe(500);context.chargeRetry(ticket);
      });
    })).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CALL_LIMIT'}});
  });
});
