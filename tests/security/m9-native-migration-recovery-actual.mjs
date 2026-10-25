import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { ReleaseHarness, releaseScope } from './lib/release-harness.mjs';

const h=new ReleaseHarness('M9',{resume:true});
try{
  assert.equal(process.env.RELEASE_LAB_MIGRATION_RECOVERY_READY,'true');
  assert.equal(h.state.phase,'native-migration-approval-stopped');
  const beforeBytes=readFileSync('artifacts/M9/native-migration-v2-before-recovery-api.json'),before=JSON.parse(beforeBytes);
  const proofBytes=readFileSync('artifacts/M9/native-migration-v2-known-native-proof.json'),proof=JSON.parse(proofBytes);
  assert.equal(proof.source,'own-lab-readonly-sql');assert.equal(proof.nativeComplete,true);
  assert.equal(proof.workflow.id,before.workflow.id);assert.equal(proof.workflow.state,'uncertain');assert.equal(proof.workflow.revision,before.workflow.revision);
  assert.equal(proof.execution.state,'uncertain');assert.equal(proof.execution.snapshotState,'ready');
  assert.equal(proof.migration.state,'succeeded');assert.equal(proof.mutation.state,'succeeded');assert.equal(proof.mutation.remoteStarted,true);assert.equal(proof.mutation.remoteCompleted,true);
  assert.equal(proof.step.state,'succeeded');assert.equal(proof.step.operationId,proof.mutation.id);
  assert(proof.components.length>=1&&proof.components.every(component=>component.state==='succeeded'));
  const original=h.state.requests.find(packet=>packet.requestId===proof.execution.originalRequestId);
  assert(original&&original.state==='response_observed'&&original.status===503&&original.errorCode==='WORKFLOW_EXECUTION_FAILED');
  assert.equal(original.key,proof.execution.originalIdempotencyKey);assert.equal(original.actorId,h.state.sessions.admin.user.id);
  const admin=h.state.sessions.admin,approver=h.state.sessions.approver,cid=h.state.cid,source=h.state.workspaceFixtures.target,target=h.state.workspaceFixtures.other;
  assert.equal(proof.scope.clusterId,cid);assert.equal(proof.scope.sourceWorkspaceId,source.id);assert.equal(proof.scope.targetWorkspaceId,target.id);
  const scoped=(wid,suffix)=>releaseScope(cid,wid,suffix),workflowId=proof.workflow.id;
  // A fresh real owner session closes historical metadata; it cannot renew the
  // original native execution capability or replace its failed response.
  const currentAdmin=await h.login('admin',admin.username,admin.password);
  let workflow=(await h.request(currentAdmin,scoped(source.id,`workflows/${workflowId}`))).data.entity;
  assert.equal(workflow.state,'uncertain');assert.equal(workflow.planHash,before.workflow.planHash);
  const receiptPath=scoped(source.id,`workflows/receipts/by-key/${original.key}`),receipt=(await h.request(currentAdmin,receiptPath)).data;
  assert.equal(receipt.executionId,proof.execution.id);assert.equal(receipt.state,'uncertain');assert.equal(receipt.metadataRecovery?.kind,'workspace-migration');
  assert.equal(receipt.metadataRecovery.eligible,true);assert.equal(receipt.metadataRecovery.knownNativeComplete,true);
  assert.equal(receipt.steps.length,1);assert.equal(receipt.steps[0].state,'succeeded');assert.equal(receipt.steps[0].remoteCompleted,true);
  original.resolution={...(original.resolution??{}),knownNativeComplete:true,responseResolved:false,factProofSha256:createHash('sha256').update(proofBytes).digest('hex'),
    metadataRecovery:{kind:'workspace-migration',clusterId:cid,workspaceId:source.id,workflowId,executionId:proof.execution.id,planHash:workflow.planHash,revision:workflow.revision}};h.save();
  const recoveryBody={revision:workflow.revision,planHash:workflow.planHash,executionId:proof.execution.id,confirmed:true,confirm_name:'workspace-migration'};
  const recovered=(await h.request(currentAdmin,scoped(source.id,`workflows/${workflowId}/reconcile-metadata`),'POST',recoveryBody,{key:original.key,metadataOnlyFor:original.requestId})).data;
  assert.equal(recovered.state,'succeeded');assert.equal(recovered.executionId,proof.execution.id);assert.equal(recovered.metadataRecovery.completed,true);
  const finalReceipt=(await h.request(currentAdmin,receiptPath)).data;
  assert.equal(finalReceipt.state,'succeeded');assert.equal(finalReceipt.idempotencyKey,original.key);assert.equal(finalReceipt.executionId,proof.execution.id);
  assert.equal(finalReceipt.metadataRecovery.completed,true);assert(finalReceipt.steps.every(step=>step.state==='succeeded'&&step.remoteCompleted===true));
  original.resolution={...original.resolution,metadataRecovered:true,receiptVerified:true,finalState:'succeeded',responseResolved:false};h.save();
  h.check(true,'original known-success migration closes only its parent ledger using the original execution key');
  writeFileSync('artifacts/M9/native-migration-recovery-verification.json',JSON.stringify({passed:true,originalWorkflowId:workflowId,originalExecutionId:proof.execution.id,
    original503Retained:true,originalResponseRewritten:false,nativeExecutionReplayed:false,metadataRecovered:true,readOnlyAdminValidation:true,knownOriginalReceipt:finalReceipt,
    beforeProofSha256:createHash('sha256').update(proofBytes).digest('hex')},null,2)+'\n');

  // A distinct, previously restored Consumer verifies normal execution of the
  // corrected terminal path. The recovered original execution is never rerun.
  const consumer=h.state.requests.find(packet=>packet.label===`composite-${source.code}-consumer`).responseData.entity;
  const credential=h.state.requests.find(packet=>packet.label===`composite-${source.code}-key`).responseData.entity;
  const currentConsumer=(await h.request(currentAdmin,scoped(source.id,`entities/consumers/${consumer.id}`))).data.entity;
  assert(currentConsumer.tags.includes(`workspace:${source.code}`));
  const prefix='approval-migration-normal-final',migration=(await h.once(`${prefix}-plan`,currentAdmin,scoped(source.id,'batches/plan'),'POST',
    {action:'workspace-move',roots:[{type:'consumers',id:consumer.id}],targetWorkspaceId:target.id})).data.entity;
  assert.equal(migration.conflicts.length,0);assert(migration.affected.some(node=>node.id===credential.id));
  const submitted=(await h.once(`${prefix}-submit`,currentAdmin,scoped(source.id,`workspace-migrations/${migration.id}/submit`),'POST',
    {plan_hash:migration.plan_hash,confirmed:true,confirm_name:target.name})).data;workflow=submitted.entity;
  const confirmation=()=>({revision:workflow.revision,planHash:workflow.planHash,confirmed:true,confirm_name:'workspace-migration'});
  await h.once(`${prefix}-approve`,approver,scoped(source.id,`workflows/${workflow.id}/approve`),'POST',confirmation());
  workflow=(await h.request(currentAdmin,scoped(source.id,`workflows/${workflow.id}`))).data.entity;
  assert.equal(workflow.state,'approved');
  const normal=(await h.once(`${prefix}-execute`,currentAdmin,scoped(source.id,`workflows/${workflow.id}/execute`),'POST',confirmation())).data;
  assert.equal(normal.state,'succeeded');assert(normal.steps.every(step=>step.state==='succeeded'&&step.remoteCompleted===true));
  h.check(true,'a distinct approved native migration commits its normal terminal workflow and execution state');
  const moved=(await h.request(currentAdmin,scoped(target.id,`entities/consumers/${consumer.id}`))).data.entity;
  assert.equal(moved.id,consumer.id);assert(moved.tags.includes(`workspace:${target.code}`));
  await h.request(currentAdmin,scoped(source.id,`entities/consumers/${consumer.id}`),'GET',undefined,{expected:[403]});
  const credentials=(await h.request(currentAdmin,scoped(target.id,`consumers/${consumer.id}/credentials/key-auth`))).data.items;
  assert(credentials.some(value=>value.id===credential.id));
  h.check(true,'normal approved migration preserves the exact original Consumer and credential IDs and changes workspace visibility');
  const route=h.state.requests.find(packet=>packet.label==='recycle-v2-auth-route').responseData.entity;
  for(const key of [h.state.recycleFixture_v2.key,h.state.compositeWorkspaceFixtures[source.id].key]){
    const input={method:'GET',url:`http://pilot.example.com/${h.state.tag}-v2-auth/native`,headers:{apikey:key}};
    await h.poll(async()=>(await h.request(currentAdmin,scoped(h.state.wid,'toolbox/probes'),'POST',{routeId:route.id,input,confirmed:true,confirm_name:route.name})).data,
      value=>value.status===200,'APPROVED_MIGRATIONS_ORIGINAL_KEYS_MUST_AUTHENTICATE');
  }
  h.check(true,'original API Keys authenticate after both the ledger-recovered and normal approved native migrations');
  h.state.phase='native-migration-approval-passed';h.save();h.report(true);console.log(JSON.stringify({passed:true,phase:h.state.phase,checks:h.state.checks.length}));
}catch(error){h.state.phase='native-migration-approval-stopped';h.save();h.report(false,'NATIVE_MIGRATION_RECOVERY_FAILED');console.error(JSON.stringify({passed:false,errorType:error.name,message:String(error.message).slice(0,500)}));process.exitCode=1;}
