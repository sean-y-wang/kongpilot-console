import {afterEach,describe,expect,it,vi} from 'vitest';
import {KongExecutionContextService,type ConfigurationJobExecutionProof} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {configurationHttpWait} from '../../apps/console-api/src/infrastructure/kong/configuration-budget';
import {KongScopeInterceptor} from '../../apps/console-api/src/modules/authorization/kong-scope.interceptor';
import {defer,lastValueFrom} from 'rxjs';

const id=(n:number)=>`62000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const actor={id:id(1),username:'synthetic-budget-actor',superAdmin:false};
const base=`/api/v1/clusters/${id(3)}`;
afterEach(()=>vi.useRealTimers());
function clock(){vi.useFakeTimers();const start=Date.UTC(2026,9,11);vi.setSystemTime(start);return(ms:number)=>vi.setSystemTime(start+ms);}
function fixture(){
 const context=new KongExecutionContextService(),handle=Object.freeze({});
 const proof:ConfigurationJobExecutionProof={actor,sessionId:id(2),clusterId:id(3),workspaceId:id(4),module:'snapshots',purpose:'apply',jobId:id(5),permissionVersion:'current',credentialEpoch:1,leaseGeneration:1,expiresAt:Date.now()+600000,readOnly:false};
 const hooks={authorizeRequest:vi.fn(async()=>({})),authorizeResponse:vi.fn(async(_ticket:unknown,result:unknown)=>result)};
 context.installPolicy(hooks);context.installConfigurationJobPolicy({verifyHandle:async(candidate:object)=>{if(candidate!==handle)throw Error('invalid private handle');return{...proof};}});
 const cluster={id:id(3),admin_url:'http://kong:8001',version:'1.5.1',execution_mode:'direct'};
 return{context,handle,proof,hooks,cluster};
}
describe('bounded M8 execution and independent HTTP receipt wait',()=>{
 it('waits past 120 seconds for a verified private M8 job and rejects it at 300 seconds',async()=>{
  const advance=clock(),f=fixture();await f.context.runConfigurationJob(f.handle,async()=>{
   advance(121000);const ticket=await f.context.authorizeRequest(f.cluster,'GET','/services',undefined,{});await f.context.authorizeResponse(ticket,{data:[]});
   advance(300001);await expect(f.context.authorizeRequest(f.cluster,'GET','/services',undefined,{})).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CONTEXT_EXPIRED'}});
  });expect(f.hooks.authorizeRequest).toHaveBeenCalledTimes(1);
 });
 it('does not prolong the original private authority or credential expiry',async()=>{
  const advance=clock(),f=fixture();f.proof.expiresAt=Date.now()+80000;
  await f.context.runConfigurationJob(f.handle,async()=>{advance(80001);await expect(f.context.authorizeRequest(f.cluster,'GET','/services',undefined,{})).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CONTEXT_EXPIRED'}});});
  expect(f.hooks.authorizeRequest).not.toHaveBeenCalled();
 });
 it('keeps an ordinary workflow actor at 120 seconds inside an extended HTTP wait',async()=>{
  const advance=clock(),f=fixture();await f.context.runHttp({configurationWait:true},async()=>{
   f.context.bindHttpActor(actor,id(2));await f.context.runActor({actor,clusterId:id(3),module:'workflows'},async()=>{
    advance(120001);await expect(f.context.authorizeRequest(f.cluster,'GET','/services',undefined,{})).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CONTEXT_EXPIRED'}});
   });
  });expect(f.hooks.authorizeRequest).not.toHaveBeenCalled();
 });
 it('still closes the M8 HTTP chain on disconnect and cannot adopt another actor',async()=>{
  const f=fixture();await f.context.runHttp({configurationWait:true},async()=>{
   f.context.bindHttpActor(actor,id(2));const close=f.context.captureHttpCloser();
   expect(()=>f.context.runActor({actor:{...actor,id:id(9)},clusterId:id(3),purpose:'configuration'},async()=>undefined)).toThrow();
   await f.context.runActor({actor,clusterId:id(3),module:'snapshots',purpose:'configuration'},async()=>{close();await expect(f.context.authorizeRequest(f.cluster,'GET','/services',undefined,{})).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CONTEXT_EXPIRED'}});});
  });expect(f.hooks.authorizeRequest).not.toHaveBeenCalled();
 });
 it('retains the 500-call cap even when the time envelope is longer',async()=>{
  const f=fixture();await f.context.runConfigurationJob(f.handle,async()=>{
   for(let n=0;n<500;n++){const ticket=await f.context.authorizeRequest(f.cluster,'GET','/services',undefined,{});await f.context.authorizeResponse(ticket,{});}
   await expect(f.context.authorizeRequest(f.cluster,'GET','/services',undefined,{})).rejects.toMatchObject({status:403});
  });expect(f.hooks.authorizeRequest).toHaveBeenCalledTimes(500);
 });
 it('keeps the real controller subscription waiting while its ordinary actor remains separately bounded',async()=>{
  const advance=clock(),f=fixture();await f.context.runHttp({configurationWait:true},async()=>{
   f.context.bindHttpActor(actor,id(2));const req={user:actor,params:{clusterId:id(3)},query:{},method:'POST',path:`${base}/workflows/${id(8)}/execute`};
   const interceptor=new KongScopeInterceptor(f.context);
   await lastValueFrom(interceptor.intercept({switchToHttp:()=>({getRequest:()=>req})}as any,{handle:()=>defer(async()=>{
    advance(121000);expect(f.context.current().actor?.id).toBe(actor.id);
    return f.context.runActor({actor,clusterId:id(3),module:'workflows'},async()=>{advance(242001);await expect(f.context.authorizeRequest(f.cluster,'GET','/services',undefined,{})).rejects.toMatchObject({status:403});return true;});
   })}));
  });expect(f.hooks.authorizeRequest).not.toHaveBeenCalled();
 });
 it.each([
  ['POST',`${base}/snapshots`,true],['POST',`${base}/snapshots/${id(5)}/rollback-plan`,true],
  ['POST',`${base}/configuration/imports`,true],['POST',`${base}/configuration/plans/${id(5)}/apply`,true],
  ['GET',`${base}/snapshots/${id(5)}/compare/${id(6)}`,true],['POST',`${base}/workflows/${id(5)}/execute`,true],
  ['GET',`${base}/configuration/plans/${id(5)}/apply`,false],['DELETE',`${base}/snapshots`,false],
  ['POST','/api/v1/portal/workflows/execute',false],['POST',`${base}/services`,false],
  ['POST',`${base}/configuration/imports/extra`,false],['POST',`${base}/workflows/not-a-uuid/execute`,false],
  ['POST',`${base}/snapshots/../configuration/imports`,false],['POST',`${base}/snapshots%2F`,false],
 ])('assigns HTTP wait by the fixed method and full path: %s %s', (method,path,expected)=>{
  expect(configurationHttpWait(method,path)).toBe(expected);
 });
});
