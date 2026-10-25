import {randomUUID} from 'node:crypto';
import {describe,expect,it,vi} from 'vitest';
import {KongExecutionContextService,type ConfigurationJobExecutionProof,type PromotionPlanningProof} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {transportScopeFor} from '../../apps/console-api/src/infrastructure/kong/transport-scope';

// Independent component review of the actual kernel. These fixed synthetic
// provider claims are neither deployed HTTP nor native Kong/SQL evidence.
function fixture(readOnly:boolean){
 const context=new KongExecutionContextService(),actor={id:randomUUID(),username:'independent-review',superAdmin:false};
 const sid=randomUUID(),sourceCid=randomUUID(),sourceWid=randomUUID(),targetCid=randomUUID(),targetWid=randomUUID();
 const planningHandle=Object.freeze({}),jobHandle=Object.freeze({}),dispatch=vi.fn(async()=>undefined);
 let planningProof:PromotionPlanningProof;
 const jobProof:ConfigurationJobExecutionProof={actor,sessionId:sid,clusterId:targetCid,workspaceId:targetWid,module:'snapshots',
  purpose:readOnly?'capture':'apply',jobId:randomUUID(),permissionVersion:'current-review-policy',credentialEpoch:1,leaseGeneration:1,expiresAt:Date.now()+60000,readOnly};
 const verifyJob=vi.fn(async(handle:object)=>{if(handle!==jobHandle)throw new Error('Unknown synthetic provider handle');return jobProof;});
 context.installConfigurationJobPolicy({verifyHandle:verifyJob});
 context.installPromotionPlanningPolicy({verifyHandle:async handle=>{if(handle!==planningHandle)throw new Error('Unknown synthetic planning handle');return planningProof;}});
 const run=<T>(fn:()=>Promise<T>)=>context.runHttp({requestId:randomUUID()},async()=>{
  context.bindHttpActor(actor,sid);const close=context.captureHttpCloser();try{
   return await context.runActor({actor,clusterId:sourceCid,workspaceId:sourceWid,module:'promote',action:'write'},async()=>{
    planningProof={promotionId:randomUUID(),actor,sessionId:sid,sourceClusterId:sourceCid,sourceWorkspaceId:sourceWid,clusterId:targetCid,workspaceId:targetWid,
     transportScope:transportScopeFor('http://independent-target.invalid:8001'),permissionVersion:'current-review-policy',credentialEpoch:1,expiresAt:Date.now()+60000,originFrame:context.current()};
    return fn();
   });
  }finally{close();}
 });
 return{context,planningHandle,jobHandle,dispatch,verifyJob,run};
}

describe('independent M10 verifier and detached planning boundary',()=>{
 it.each([true,false])('rejects a closed planning async continuation before minting a detached %s job frame',async(readOnly)=>{
  const f=fixture(readOnly);let release!:()=>void;const gate=new Promise<void>(resolve=>{release=resolve;});let continuation!:Promise<void>;
  await f.run(async()=>{
   await f.context.runPromotionPlanning(f.planningHandle,async()=>{
    continuation=(async()=>{await gate;await f.context.runConfigurationJob(f.jobHandle,f.dispatch);})();
   });
   // The source HTTP actor remains live. Only the inner planning namespace
   // has ended, so a broad check for a closed HTTP caller would miss this.
   expect(f.context.current().actor).toBeDefined();release();
   await expect(continuation).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CONTEXT_EXPIRED'}});
  });
  expect(f.verifyJob).not.toHaveBeenCalled();expect(f.dispatch).not.toHaveBeenCalled();
 });
 it('rejects a copied planning frame as a governance liveness proof',async()=>{
  const f=fixture(true);await f.run(()=>f.context.runPromotionPlanning(f.planningHandle,async()=>{
   const frame=f.context.current();
   expect(()=>f.context.assertGovernanceOrigin({...frame},frame.actor!.id,frame.sessionId!)).toThrow(expect.objectContaining({response:expect.objectContaining({code:'KONG_EXECUTION_CONTEXT_EXPIRED'})}));
   expect(()=>f.context.assertGovernanceOrigin(frame,randomUUID(),frame.sessionId!)).toThrow(expect.objectContaining({response:expect.objectContaining({code:'GOVERNANCE_ORIGIN_INVALID'})}));
   expect(()=>f.context.assertGovernanceOrigin(frame,frame.actor!.id,randomUUID())).toThrow(expect.objectContaining({response:expect.objectContaining({code:'GOVERNANCE_ORIGIN_INVALID'})}));
  }));expect(f.dispatch).not.toHaveBeenCalled();
 });
});
