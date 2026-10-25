import 'reflect-metadata';
import {randomUUID} from 'node:crypto';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {KongActorScope,isEntityActorDomainScope} from '../../apps/console-api/src/infrastructure/kong/actor-scope';
import {approvedOriginalDeadlineFixture} from './helpers/m11-approved-original-deadline-fixture';

beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-18T09:00:00Z'));});
afterEach(()=>{vi.restoreAllMocks();vi.useRealTimers();vi.unstubAllEnvs();});
const expired={response:{code:'KONG_EXECUTION_CONTEXT_EXPIRED'}};
function domain(f:ReturnType<typeof approvedOriginalDeadlineFixture>,fn:()=>Promise<unknown>){
 const descriptor:PropertyDescriptor={value:async function(){return fn();},configurable:true,writable:true};
 KongActorScope({module:'consumers',action:'write',queryArg:2})({},'create',descriptor);
 const service={execution:f.context,create:descriptor.value};
 return (workspaceId=f.wid)=>service.create(f.cid,{}, {workspaceId},{user:f.actor,workspaceId});
}
function capture(f:ReturnType<typeof approvedOriginalDeadlineFixture>){
 const original=f.context.runActor.bind(f.context);let scope:any;
 vi.spyOn(f.context,'runActor').mockImplementation((options,fn)=>{scope=options;return original(options,fn);});
 return ()=>scope;
}
/** Actual fixed decorator provenance, Authority/Namespace/Approved private
 * handles, AEAD plan and Context. SQL/current grants and outbound GET remain
 * controlled adapters; this is not real HTTP or a production claim. */
describe('fixed entity decorator retains only an authentic Portal Native deadline',()=>{
 it('keeps decorator, Mutation, operation and final fresh Native verification within the original absolute deadline',async()=>{
  const f=approvedOriginalDeadlineFixture('portal-credential-issue');f.rows[0].state='running';
  await f.run(()=>f.context.runApprovedStep(f.rows[0].id,domain(f,async()=>{
   expect(f.context.current().limits.timeoutMs).toBe(240000);vi.advanceTimersByTime(120001);
   const mutation=f.nativeContext(),step=f.context.currentApprovedStep();
   await f.context.runMutationActor(mutation,async()=>{
    expect(f.context.current().limits.timeoutMs).toBe(119999);
    const binding=await f.context.approvedMutationBinding(mutation),operation=f.operation();
    expect(binding).not.toBeNull();await f.context.bindApprovedOperation(mutation,binding!,operation.id,f.db);operation.remote_started=true;
    await f.context.runOperation({...mutation,operationId:operation.id},async()=>{
     expect(f.context.current().limits.timeoutMs).toBe(119999);const request=f.plan.steps[0].nativeRequests[0];
     await f.verifier.assertNative(step,{clusterId:f.cid,workspaceId:f.wid,transportScope:f.plan.scope.transportScope,operationId:operation.id,
      method:request.method,canonicalPath:request.canonicalPath,body:request.body,before:null,mutationAction:'create',frame:f.context.current(),cluster:f.cluster,query:{}},'before-send');
    });
   });
  })));
  expect(f.state.validationRoles.some((r:any)=>r.role==='reviewer')).toBe(true);
  expect(f.kong.request.mock.calls.every(call=>call[1]==='GET')).toBe(true);expect(f.context.peek()).toBeNull();
 });
 it('keeps a genuine earlier ordinary actor at 120 seconds through the decorated Native and Mutation descendants',async()=>{
  const f=approvedOriginalDeadlineFixture('portal-credential-issue');f.rows[0].state='running';let entered=false;
  await expect(f.run(()=>f.context.runApprovedStep(f.rows[0].id,()=>f.context.runActor({actor:f.actor,clusterId:f.cid,workspaceId:f.wid},domain(f,async()=>{
   entered=true;expect(f.context.current().limits.timeoutMs).toBe(120000);
   await f.context.runMutationActor(f.nativeContext(),async()=>{expect(f.context.current().limits.timeoutMs).toBe(120000);
    vi.advanceTimersByTime(120001);expect(()=>f.context.current()).toThrow();});
  }))))).rejects.toMatchObject(expired);
  expect(entered).toBe(true);expect(f.original.repository.finishClaim).not.toHaveBeenCalled();
 });
 it('does not accept a copied or closed decorator scope even while the original Native step remains active',async()=>{
  const f=approvedOriginalDeadlineFixture('portal-credential-issue');f.rows[0].state='running';const scope=capture(f);let registered:any;
  await f.run(()=>f.context.runApprovedStep(f.rows[0].id,async()=>{
   await domain(f,async()=>{const original=registered=scope();expect(Object.isFrozen(original)).toBe(true);expect(isEntityActorDomainScope(original)).toBe(true);
    expect(isEntityActorDomainScope({...original})).toBe(false);
    await f.context.runActor({...original},async()=>{expect(f.context.current().limits.timeoutMs).toBe(120000);});
   })();
   const closed=registered;expect(isEntityActorDomainScope(closed)).toBe(false);
   await f.context.runActor(closed,async()=>{expect(f.context.current().limits.timeoutMs).toBe(120000);});
  }));
 });
 it.each(['configuration_v2','portal-credential-issue'] as const)('does not lend a longer deadline to %s without a genuine Native step',async kind=>{
  const f=approvedOriginalDeadlineFixture(kind);
  await expect(f.run(domain(f,async()=>{expect(f.context.current().limits.timeoutMs).toBe(120000);vi.advanceTimersByTime(120001);
   expect(()=>f.context.current()).toThrow();}))).rejects.toMatchObject(expired);
 });
 it('keeps a configuration metadata step on an ordinary entity-domain deadline',async()=>{
  const f=approvedOriginalDeadlineFixture('configuration_v2');f.rows[0].state='running';
  await expect(f.run(()=>f.context.runApprovedStep(f.rows[0].id,domain(f,async()=>{expect(f.context.currentApprovedStep().kind).toBe('metadata');
   expect(f.context.current().limits.timeoutMs).toBe(120000);vi.advanceTimersByTime(120001);expect(()=>f.context.current()).toThrow();})))).rejects.toMatchObject(expired);
 });
 it('does not extend a foreign object workspace by registering an otherwise authentic decorator scope',async()=>{
  const f=approvedOriginalDeadlineFixture('portal-credential-issue');f.rows[0].state='running';
  await f.run(()=>f.context.runApprovedStep(f.rows[0].id,()=>domain(f,async()=>{expect(f.context.current().limits.timeoutMs).toBe(120000);})(randomUUID())));
 });
 it.each(['callback-error','return-expiry'] as const)('revokes the original decorator registration on %s',async reason=>{
  const f=approvedOriginalDeadlineFixture('portal-credential-issue');f.rows[0].state='running';const scope=capture(f);
  const run=f.run(()=>f.context.runApprovedStep(f.rows[0].id,domain(f,async()=>{
   expect(isEntityActorDomainScope(scope())).toBe(true);
   if(reason==='callback-error')throw Error('CONTROLLED_DOMAIN_CALLBACK_FAILURE');
   queueMicrotask(()=>vi.advanceTimersByTime(240001));
  })));
  if(reason==='callback-error')await expect(run).rejects.toThrow('CONTROLLED_DOMAIN_CALLBACK_FAILURE');else await expect(run).rejects.toMatchObject(expired);
  expect(isEntityActorDomainScope(scope())).toBe(false);expect(f.context.peek()).toBeNull();expect(f.original.repository.finishClaim).not.toHaveBeenCalled();
 });
});
