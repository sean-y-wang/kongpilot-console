import {describe,it,expect,vi} from 'vitest';
import {KongExecutionContextService,type ConfigurationJobExecutionProof} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
const id=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
function fixture(){
  const ctx=new KongExecutionContextService(),handle=Object.freeze({}),proof:ConfigurationJobExecutionProof={actor:{id:id(1),username:'actor',superAdmin:false},sessionId:id(2),clusterId:id(3),workspaceId:id(4),module:'snapshots',purpose:'capture',jobId:id(5),permissionVersion:'v1',credentialEpoch:1,leaseGeneration:1,expiresAt:Date.now()+60000,readOnly:true};
  const verify=vi.fn(async(input:object)=>{if(input!==handle)throw new Error('private handle required');return {...proof};});
  const hooks={authorizeRequest:vi.fn(async()=>({})),authorizeResponse:vi.fn(async(_:unknown,result:unknown)=>result)};
  ctx.installConfigurationJobPolicy({verifyHandle:verify});ctx.installPolicy(hooks);
  const cluster={id:proof.clusterId,admin_url:'http://kong:8001',version:'1.5.1',execution_mode:'direct'};
  return{ctx,handle,proof,verify,hooks,cluster};
}
describe('M8 private detached configuration frames',()=>{
  it('rejects forged handles and replacing private job policy',async()=>{const f=fixture();await expect(f.ctx.runConfigurationJob({},async()=>undefined)).rejects.toThrow();expect(()=>f.ctx.installConfigurationJobPolicy({verifyHandle:f.verify})).toThrow();});
  it('creates fresh authority after closed HTTP without adopting its actor or closed parent',async()=>{const f=fixture();await f.ctx.runHttp({requestId:id(9)},async()=>{
    f.ctx.bindHttpActor({id:id(8),username:'foreign',superAdmin:true},id(7));f.ctx.captureHttpCloser()();
    await f.ctx.runConfigurationJob(f.handle,async()=>{expect(f.ctx.current().actor?.id).toBe(id(1));expect(f.ctx.current().sessionId).toBe(id(2));const ticket=await f.ctx.authorizeRequest(f.cluster,'GET','/services',undefined,{});await f.ctx.authorizeResponse(ticket,{data:[]});});
  });expect(f.ctx.peek()).toBeNull();});
  it('requires explicit readonly for SID-less schedules and rejects native writes before policy',async()=>{const f=fixture();f.proof.sessionId=null;
    await f.ctx.runConfigurationJob(f.handle,async()=>{await expect(f.ctx.authorizeRequest(f.cluster,'POST','/services',{host:'bad'},{})).rejects.toMatchObject({response:{code:'CONFIGURATION_JOB_READ_ONLY'}});});expect(f.hooks.authorizeRequest).not.toHaveBeenCalled();
    f.proof.readOnly=false;f.proof.purpose='apply';await expect(f.ctx.runConfigurationJob(f.handle,async()=>undefined)).rejects.toMatchObject({response:{code:'CONFIGURATION_JOB_AUTHORITY_INVALID'}});
  });
  it.each(['actor','sessionId','clusterId','workspaceId','jobId','permissionVersion','credentialEpoch','leaseGeneration','expiresAt','readOnly','requestId','ip','idempotencyKey'])("rejects changed private %s before a subsequent packet",async(field)=>{const f=fixture();await f.ctx.runConfigurationJob(f.handle,async()=>{
    if(field==='actor')f.proof.actor={...f.proof.actor,id:id(10)};else (f.proof as any)[field]=['credentialEpoch','leaseGeneration','expiresAt'].includes(field)?(f.proof as any)[field]+1:field==='readOnly'?false:field==='permissionVersion'?'v2':['requestId','ip','idempotencyKey'].includes(field)?'changed':id(10);
    await expect(f.ctx.authorizeRequest(f.cluster,'GET','/services',undefined,{})).rejects.toThrow();expect(f.hooks.authorizeRequest).not.toHaveBeenCalled();
  });});
  it('rechecks revoke between authorization and actual send, and before returning response',async()=>{const f=fixture();await f.ctx.runConfigurationJob(f.handle,async()=>{
    const ticket=await f.ctx.authorizeRequest(f.cluster,'GET','/services',undefined,{});f.proof.credentialEpoch++;
    await expect(f.ctx.beforeNativeSend(ticket)).rejects.toThrow();await expect(f.ctx.authorizeResponse(ticket,{data:[]})).rejects.toThrow();expect(f.hooks.authorizeResponse).not.toHaveBeenCalled();
  });});
  it('currentUsage includes child/retry counts and is immutable with no exposed state',async()=>{const f=fixture();await f.ctx.runConfigurationJob(f.handle,async()=>{
    await f.ctx.runInternalRead(id(3),'capture',async()=>{const ticket=await f.ctx.authorizeRequest(f.cluster,'GET','/services',undefined,{});f.ctx.chargeRetry(ticket);await f.ctx.authorizeResponse(ticket,{data:[{id:id(10)}]});});
    const usage=f.ctx.currentUsage();expect(usage).toMatchObject({calls:2,pages:1,records:1});expect(usage.bytes).toBeGreaterThan(0);expect(Object.isFrozen(usage)).toBe(true);expect(Object.keys(usage)).toEqual(['calls','pages','records','bytes']);
  });expect(()=>f.ctx.currentUsage()).toThrow();});
});
