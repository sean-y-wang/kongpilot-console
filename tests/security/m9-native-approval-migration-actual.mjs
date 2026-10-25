import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { ReleaseHarness, releaseScope } from './lib/release-harness.mjs';

const h=new ReleaseHarness('M9',{resume:true});
try{
  assert(['native-composite-workspaces-passed','native-migration-approval-stopped'].includes(h.state.phase),'Verified native workspace fixtures required');
  const admin=h.state.sessions.admin,approver=h.state.sessions.approver,cid=h.state.cid,source=h.state.workspaceFixtures.target,target=h.state.workspaceFixtures.other;
  const consumer=h.state.requests.find(p=>p.label==='recycle-v2-consumer').responseData.entity;
  const credential=h.state.requests.find(p=>p.label==='recycle-v2-key').responseData.entity;
  const scoped=(wid,suffix)=>releaseScope(cid,wid,suffix);
  const freshIntent=process.argv.includes('--fresh-after-proven-no-send'),prefix=freshIntent?'approval-migration-v2':'approval-migration';
  if(freshIntent){
    const proofBytes=readFileSync('artifacts/M9/native-migration-execution-beforefix.json'),proof=JSON.parse(proofBytes);
    assert.equal(proof.scope.clusterId,cid);assert.equal(proof.scope.sourceWorkspaceId,source.id);assert.equal(proof.workflow.state,'failed');assert.equal(proof.execution.state,'failed');
    assert.equal(proof.mutationCount,0);assert.equal(proof.nativeStartedCount,0);assert(proof.steps.every(step=>step.state==='pending'&&!step.operationLinked&&!step.remoteStarted&&!step.remoteCompleted));
    const originalExecution=h.state.requests.find(packet=>packet.requestId===proof.execution.originalRequestId);
    assert(originalExecution&&originalExecution.key===proof.execution.originalIdempotencyKey&&originalExecution.status===403&&originalExecution.errorCode==='PERMISSION_DENIED');
    assert.equal((await h.request(admin,scoped(source.id,`workflows/${proof.scope.workflowId}`))).data.entity.state,'failed');
    const before=(await h.request(admin,scoped(source.id,`entities/consumers/${consumer.id}`))).data.entity;
    assert(before.tags.includes(`workspace:${source.code}`),'A new intent requires the exact original Consumer still in its source workspace');
    h.state.approvalMigrationFreshIntent??={version:2,previousWorkflowId:proof.scope.workflowId,previousExecutionId:proof.execution.id,proofSha256:createHash('sha256').update(proofBytes).digest('hex'),authorizedAt:new Date().toISOString(),originalFailedExecutionReplayed:false};h.save();
  }
  const cluster=(await h.request(admin,`/clusters/${cid}`)).data;
  if(cluster.execution_mode!=='approval'){
    h.state.approvalMigrationModeBody??={revision:cluster.revision,execution_mode:'approval'};h.save();
    await h.once('migration-cluster-approval',admin,`/clusters/${cid}`,'PATCH',h.state.approvalMigrationModeBody);
  }
  const migration=(await h.once(`${prefix}-plan`,admin,scoped(source.id,'batches/plan'),'POST',{action:'workspace-move',roots:[{type:'consumers',id:consumer.id}],targetWorkspaceId:target.id})).data.entity;
  assert.equal(migration.conflicts.length,0);assert(migration.affected.some(node=>node.id===credential.id));
  const migrationBody={plan_hash:migration.plan_hash,confirmed:true,confirm_name:target.name};
  await h.request(admin,scoped(source.id,`workspace-migrations/${migration.id}/apply`),'POST',migrationBody,{expected:[409]});
  h.check(true,'approval-mode migration rejects direct execution before sending a native tag update');
  const submitPath=scoped(source.id,`workspace-migrations/${migration.id}/submit`);
  const rejectedSubmit=h.state.requests.find(packet=>packet.path===submitPath&&packet.status===403&&packet.errorCode==='KONG_EXECUTION_CONTEXT_REQUIRED');
  if(rejectedSubmit)assert(rejectedSubmit.resolution?.knownNoNativeSend===true&&rejectedSubmit.resolution?.workflowReceiptStatus===404,'An original rejected submission must be checked by its owner key before continuing');
  const submitted=(await h.once(`${prefix}-submit`,admin,submitPath,'POST',migrationBody,...(rejectedSubmit?[{key:rejectedSubmit.key}]:[]))).data;
  let workflow=submitted.entity;assert.equal(workflow.kind,'workspace-migration');assert.equal(workflow.state,'pending');
  const original=(await h.request(admin,scoped(source.id,`entities/consumers/${consumer.id}`))).data.entity;
  assert(original.tags.includes(`workspace:${source.code}`));
  await h.request(admin,scoped(target.id,`entities/consumers/${consumer.id}`),'GET',undefined,{expected:[403]});
  h.check(true,'migration submission preserves source configuration while awaiting independent approval');
  const confirmation=()=>({revision:workflow.revision,planHash:workflow.planHash??workflow.plan_hash,confirmed:true,confirm_name:workflow.kind});
  await h.request(admin,scoped(source.id,`workflows/${workflow.id}/approve`),'POST',confirmation(),{expected:[403]});
  await h.request(admin,scoped(source.id,`workflows/${workflow.id}/execute`),'POST',confirmation(),{expected:[409]});
  await h.request(admin,scoped(target.id,`workflows/${workflow.id}`),'GET',undefined,{expected:[403,404]});
  h.check(true,'migration approval rejects requester self-approval, unapproved execution and another-workspace workflow lookup');
  await h.once(`${prefix}-approve`,approver,scoped(source.id,`workflows/${workflow.id}/approve`),'POST',confirmation());
  workflow=(await h.request(admin,scoped(source.id,`workflows/${workflow.id}`))).data.entity;
  assert.equal(workflow.state,'approved');
  await h.request(approver,scoped(source.id,`workflows/${workflow.id}/execute`),'POST',confirmation(),{expected:[403]});
  h.check(true,'approved migration retains the original requester as its execution owner');
  const executed=(await h.once(`${prefix}-execute`,admin,scoped(source.id,`workflows/${workflow.id}/execute`),'POST',confirmation())).data;
  assert.equal(executed.entity?.state??executed.state,'succeeded');
  const finalWorkflow=(await h.request(admin,scoped(source.id,`workflows/${workflow.id}`))).data;
  assert.equal(finalWorkflow.entity.state,'succeeded');assert(finalWorkflow.steps.every(step=>step.state==='succeeded'));
  const migrated=(await h.request(admin,scoped(target.id,`entities/consumers/${consumer.id}`))).data.entity;
  assert.equal(migrated.id,consumer.id);assert(migrated.tags.includes(`workspace:${target.code}`));
  await h.request(admin,scoped(source.id,`entities/consumers/${consumer.id}`),'GET',undefined,{expected:[403]});
  const credentials=(await h.request(admin,scoped(target.id,`consumers/${consumer.id}/credentials/key-auth`))).data.items;
  assert(credentials.some(value=>value.id===credential.id));
  h.check(true,'approved native migration keeps original Consumer and credential IDs and moves visibility to the exact target workspace');
  const route=h.state.requests.find(p=>p.label==='recycle-v2-auth-route').responseData.entity;
  const input={method:'GET',url:`http://pilot.example.com/${h.state.tag}-v2-auth/native`,headers:{apikey:h.state.recycleFixture_v2.key}};
  await h.poll(async()=>(await h.request(admin,scoped(h.state.wid,'toolbox/probes'),'POST',{routeId:route.id,input,confirmed:true,confirm_name:route.name})).data,value=>value.status===200,'APPROVED_MIGRATION_ORIGINAL_KEY_MUST_AUTHENTICATE');
  h.check(true,'original API Key remains usable after the approved workspace migration');
  h.state.phase='native-migration-approval-passed';h.save();h.report(true);
  console.log(JSON.stringify({passed:true,phase:h.state.phase,checks:h.state.checks.length}));
}catch(error){
  h.state.phase='native-migration-approval-stopped';h.save();h.report(false,'NATIVE_APPROVAL_MIGRATION_FAILED');
  console.error(JSON.stringify({passed:false,errorType:error.name,message:String(error.message).slice(0,500)}));process.exitCode=1;
}
