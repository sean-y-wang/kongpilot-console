import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {releaseScope} from './release-harness.mjs';

export function assertM10MetadataApprovalScope(state,clusterId,workspaceId){
 const uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
 assert([state?.cid,state?.wid,state?.targetCid,state?.targetWid,clusterId,workspaceId].every(value=>typeof value==='string'&&uuid.test(value)),'REAL_TWO_SCOPE_METADATA_HANDOFF_REQUIRED');
 assert.notEqual(state.cid,state.targetCid,'REAL_INDEPENDENT_CLUSTER_HANDOFF_REQUIRED');
 assert((clusterId===state.cid&&workspaceId===state.wid)||(clusterId===state.targetCid&&workspaceId===state.targetWid),'EXACT_BOUND_METADATA_SCOPE_REQUIRED');
}

/** No top-level IO. Root supplies the isolated M10 ledger and actual current
 * sessions after configuring an approval cluster. All writes retain their
 * original key. A failed/unknown write stops; no replacement intent is minted. */
export async function runM10MetadataApproval(h,{admin,approver,clusterId,workspaceId}){
 assert.equal(h.milestone,'M10');assert.equal(process.env.RELEASE_M10_METADATA_APPROVAL_READY,'true');
 assert(admin?.user?.id&&approver?.user?.id&&admin.user.id!==approver.user.id);
 assertM10MetadataApprovalScope(h.state,clusterId,workspaceId);
 const scoped=path=>releaseScope(clusterId,workspaceId,path),ruleCode=`${h.state.tag}-approved-rule`,ruleName='M10 approval acceptance rule';
 const steps=h.state.metadataApproval??={version:1,clusterId,workspaceId,ownerId:admin.user.id,reviewerId:approver.user.id,operations:[]};
 assert.equal(steps.clusterId,clusterId);assert.equal(steps.workspaceId,workspaceId);assert.equal(steps.ownerId,admin.user.id);assert.equal(steps.reviewerId,approver.user.id);h.save();
 const ruleBody={code:ruleCode,name:ruleName,description:'Isolated acceptance rule',given:{entityTypes:['services']},then:{path:'tags',op:'required'},severity:'warn',enabled:true};
 const deniedOnce=async(label,session,path,body,status)=>{
  const old=h.state.requests.find(p=>p.label===label);
  if(old){assert.equal(old.path,path);assert.equal(old.method,'POST');assert.equal(old.actorId,session.user.id);assert.equal(old.state,'response_observed');assert.equal(old.status,status);
   assert.equal(old.bodyHash,createHash('sha256').update(JSON.stringify(body)).digest('hex'));return;}
  await h.once(label,session,path,'POST',body,{expected:[status]});
 };
 const submitted=(await h.once('metadata-rule-create-submit',admin,scoped('governance/rules'),'POST',ruleBody)).data;
 assert.equal(submitted.domain,'workflow');assert.equal(submitted.state,'pending');assert.equal(submitted.submissionCompleted,true);assert.equal(submitted.executionCompleted,false);assert.equal(submitted.nativeExecutionRequested,false);
 assert(submitted.workflowId);steps.ruleId??=submitted.entity?.id??null;h.save();
 const approveAndExecute=async(label,submission,{negative=false}={})=>{
  const path=scoped(`workflows/${submission.workflowId}`);let wf=(await h.request(admin,path)).data.entity;
  assert.equal(wf.kind,'governance-metadata');const confirm=()=>({revision:wf.revision,planHash:wf.planHash,confirmed:true,confirm_name:'governance-metadata'});
  if(wf.state==='pending'){
   if(negative){
    await deniedOnce(`${label}-self-approve-denied`,admin,scoped(`workflows/${wf.id}/approve`),{...confirm(),execute:false},403);
    await deniedOnce(`${label}-unapproved-execute-denied`,admin,scoped(`workflows/${wf.id}/execute`),confirm(),409);
   }
   const approved=(await h.once(`${label}-approve`,approver,scoped(`workflows/${wf.id}/approve`),'POST',{...confirm(),execute:false})).data;
   assert.equal(approved.entity.state,'approved');assert.equal(approved.entity.kind,'governance-metadata');wf=(await h.request(admin,path)).data.entity;
  }
  if(wf.state==='approved'){
   if(negative)await deniedOnce(`${label}-foreign-executor-denied`,approver,scoped(`workflows/${wf.id}/execute`),confirm(),403);
   const executed=(await h.once(`${label}-execute`,admin,scoped(`workflows/${wf.id}/execute`),'POST',confirm())).data;
   assert.equal(executed.state,'succeeded');assert.equal(executed.workflowId,wf.id);assert.equal(executed.steps.length,1);assert.equal(executed.steps[0].operationId,null);
   assert.equal(executed.steps[0].state,'succeeded');assert.equal(executed.steps[0].name,'governance.metadata');
   const packet=h.state.requests.find(p=>p.label===`${label}-execute`);assert(packet?.key&&packet.state==='response_observed'&&packet.status===201);
   const receipt=(await h.request(admin,scoped(`workflows/receipts/by-key/${packet.key}`))).data;
   assert.equal(receipt.state,'succeeded');assert.equal(receipt.executionId,executed.executionId);assert.equal(receipt.steps.length,1);assert.equal(receipt.steps[0].operationId,null);
   steps.operations.push({label,workflowId:wf.id,executionId:executed.executionId,originalExecutionKey:packet.key,originalRequestId:packet.requestId,planHash:wf.planHash,state:'succeeded'});h.save();
  }else assert.equal(wf.state,'succeeded','Only the exact existing successful workflow can resume without writes');
  const submitPacket=h.state.requests.find(p=>p.responseData?.workflowId===submission.workflowId&&p.path.includes('/governance/'));
  assert(submitPacket?.key);const receipt=(await h.request(admin,scoped(`governance/operations/by-key/${submitPacket.key}`))).data;
  assert.equal(receipt.nativeExecutionRequested,false);assert.equal(receipt.configurationCommitted,true);assert.equal(receipt.executionCompleted,true);assert.equal(receipt.workflowId,submission.workflowId);
  assert(receipt.entity?.id);return receipt.entity;
 };
 if(!steps.ruleId){
  const detail=(await h.request(admin,scoped(`workflows/${submitted.workflowId}`))).data;
  const resourceId=detail.diff?.[0]?.after?.resourceId;assert(resourceId,'Fixed safe diff must identify its metadata resource');steps.ruleId=resourceId;h.save();
  await h.request(admin,scoped(`governance/rules/${resourceId}`),'GET',undefined,{expected:[404]});
 }
 let rule=await approveAndExecute('metadata-rule-create',submitted,{negative:true});assert.equal(rule.id,steps.ruleId);assert.equal(rule.code,ruleCode);assert.equal(rule.state,'active');
 h.check(true,'a governance rule stays absent until independent workflow approval and requester execution');
 const update=(await h.once('metadata-rule-update-submit',admin,scoped(`governance/rules/${rule.id}`),'PATCH',{revision:rule.revision,name:`${ruleName} updated`,description:'Updated by exact approved intent'})).data;
 rule=await approveAndExecute('metadata-rule-update',update);assert.equal(rule.name,`${ruleName} updated`);assert.equal(rule.currentVersion,2);
 const archive=(await h.once('metadata-rule-archive-submit',admin,scoped(`governance/rules/${rule.id}`),'DELETE',{revision:rule.revision,confirmed:true,confirm_name:rule.name})).data;
 rule=await approveAndExecute('metadata-rule-archive',archive);assert.equal(rule.state,'deleted');assert.equal(rule.currentVersion,3);
 const restore=(await h.once('metadata-rule-restore-submit',admin,scoped(`governance/rules/${rule.id}/restore`),'POST',{revision:rule.revision,confirmed:true,confirm_name:rule.name})).data;
 rule=await approveAndExecute('metadata-rule-restore',restore);assert.equal(rule.state,'active');assert.equal(rule.currentVersion,4);
 h.check(true,'rule update, soft archive and restore use the same fixed metadata workflow engine with immutable versions');
 steps.completed=true;h.save();return{resourceId:rule.id,workflowIds:steps.operations.map(o=>o.workflowId),operations:steps.operations.length};
}
