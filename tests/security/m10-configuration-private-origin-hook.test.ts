import 'reflect-metadata';
import {describe,it,expect,vi} from 'vitest';
import {ForbiddenException} from '@nestjs/common';
import {KongExecutionContextService,ConfigurationJobExecutionProof} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
const cid='c3a7a9ef-03bd-44e4-b32b-024fdff6f4a7',wid='169dbf40-dfcf-45d8-8aaa-f72999f1b853',uid='9bcb3a4e-66b1-4da3-a702-5c457782dd53',sid='2fae3a2c-0c73-4f7c-80b3-06d27c7a6806',jobId='de3020fd-8e3a-44fc-91e2-0d3a98d2d5ba',operationId='c6794c1f-c8bd-4651-9e2a-a1de8db83aaa',entityId='84c4c640-2b78-4784-b3d7-dca4c6e39c6b';
const actor={id:uid,username:'private-origin-test',superAdmin:false},cluster={id:cid,admin_url:'http://kong:8001',version:'1.5.1',execution_mode:'direct'};
// Only hook dispatch/liveness is exercised here; synthetic SQL policy does
// not claim to authorize actual configuration jobs or native changes.
describe('M10 configuration private origin before-send hook',()=>{
  const setup=()=>{
    const execution=new KongExecutionContextService(),handle=Object.freeze({}),hook=vi.fn(async()=>{});let live=true;
    const proof:ConfigurationJobExecutionProof={actor,sessionId:sid,clusterId:cid,workspaceId:wid,module:'snapshots',purpose:'apply',jobId,permissionVersion:'original-epoch',credentialEpoch:1,leaseGeneration:1,expiresAt:Date.now()+60000,readOnly:false};
    execution.installConfigurationJobPolicy({verifyHandle:async candidate=>{if(candidate!==handle||!live)throw new ForbiddenException({code:'CONFIGURATION_JOB_AUTHORITY_CHANGED'});return proof;},beforeNativeSend:hook});
    execution.installPolicy({authorizeRequest:async()=>({}),authorizeResponse:async(_ticket,result)=>result});
    const request=()=>execution.runOperation({actor,clusterId:cid,workspaceId:wid,operationId,entityType:'services',entityId,action:'update'},async()=>{
      const ticket=await execution.authorizeRequest(cluster,'PATCH',`/services/${entityId}`,{name:'approved-name'},{});await execution.beforeNativeSend(ticket);
    });
    return{execution,handle,hook,request,revoke:()=>{live=false;}};
  };
  it('calls the hook with the genuine handle and exact immutable native packet',async()=>{
    const s=setup();await s.execution.runConfigurationJob(s.handle,s.request);expect(s.hook).toHaveBeenCalledOnce();expect(s.hook).toHaveBeenCalledWith(s.handle,{clusterId:cid,method:'PATCH',path:`/services/${entityId}`,body:{name:'approved-name'},query:{}});
  });
  it('does not dispatch an origin hook from caller JSON or a purpose label',async()=>{
    const s=setup();await s.execution.runHttp({},async()=>{s.execution.bindHttpActor(actor,sid);await s.execution.runActor({actor,clusterId:cid,workspaceId:wid,module:'snapshots',purpose:'configuration'},s.request);});expect(s.hook).not.toHaveBeenCalled();
  });
  it('rechecks the actual job after the asynchronous source hook and fails closed on revoked authority',async()=>{
    const s=setup();s.hook.mockImplementation(async()=>s.revoke());await expect(s.execution.runConfigurationJob(s.handle,s.request)).rejects.toMatchObject({response:{code:'CONFIGURATION_JOB_AUTHORITY_CHANGED'}});expect(s.hook).toHaveBeenCalledOnce();
  });
  it('a copied handle cannot cause dispatch or mint a job context',async()=>{
    const s=setup();await expect(s.execution.runConfigurationJob({...s.handle},s.request)).rejects.toBeInstanceOf(ForbiddenException);expect(s.hook).not.toHaveBeenCalled();
  });
});
