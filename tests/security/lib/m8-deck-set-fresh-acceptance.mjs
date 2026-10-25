import{randomUUID}from'node:crypto';
import{parse,stringify}from'yaml';
import{entity,scope,sha256}from'./m8-harness.mjs';
import{configurationRead,configurationWrite,assertConfigurationReceipt}from'./m8-configuration-acceptance.mjs';
import{assertM8DeckSession}from'./m8-deck-acceptance.mjs';
import{runM8FixedDeckPrivateStderr}from'./m8-deck-pool-continuation.mjs';
import{nativeRead,sixCredentialProxyAcceptance}from'./m8-native-acceptance.mjs';
import{M8_DECK_SET_CHECKPOINT as c}from'./m8-deck-set-continuation.mjs';
const uuid=v=>typeof v==='string'&&/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(v);
export function assertM8FreshRetry4Plan(value,imported,area){
 const plan=entity(value),s=value?.items?.[0];
 if(plan?.id!==imported.planId||plan.planHash!==imported.planHash||plan.planRevision!==imported.planRevision||plan.clusterId!==area.cid||plan.workspaceId!==area.wid
  ||plan.executionMode!=='direct'||plan.stepCount!==1||plan.nativePacketCount!==1||plan.deleteCount!==0||value.items?.length!==1||value.nextCursor!==null
  ||s.entityType!=='services'||s.nativeId!==c.serviceId||s.objectWorkspaceId!==area.wid||s.action!=='update'||s.referenceOnly===true||s.blockerCodes?.length
  ||s.patch?.length!==1||s.patch[0].op!=='replace'||s.patch[0].path!=='/retries'||s.patch[0].value!==4)throw Error('M8_EXACT_NEW_RETRY4_SINGLE_PLAN_REQUIRED');
 return plan;
}
async function submitFreshDeckApply(h,actor,area,imported){
 const plan=entity(await configurationRead(h,actor,area,`configuration/plans/${imported.planId}`));
 h.check(plan.id===imported.planId&&plan.planHash===imported.planHash&&plan.planRevision===imported.planRevision&&plan.capabilities?.apply===true&&plan.executionMode==='direct','new deck apply uses the current exact source plan');
 const key=randomUUID(),body={planRevision:plan.planRevision,planHash:plan.planHash,revision:plan.revision,driver:'deck',confirmed:true,confirm_name:plan.name};
 const op={key,area:{...area},path:`configuration/plans/${plan.id}/apply`,method:'POST',bodySha256:sha256(JSON.stringify(body)),actorId:actor.user.id,sessionId:actor.sid,state:'prepared'};
 h.state.configurationOperations.push(op);h.save();
 const initial=h.data(await h.request(actor,scope(area.cid,area.wid,op.path),'POST',body,{key,expected:[201]}));assertConfigurationReceipt(h,initial,{actor,area,key,kind:'apply'});
 h.check(initial.state==='running'&&initial.executionCompleted===false&&initial.driver==='deck'&&uuid(initial.executionId)&&uuid(initial.planId)
  &&initial.planId!==plan.id&&initial.planHash===plan.planHash&&initial.planRevision===plan.planRevision&&initial.jobId!==c.jobId,'new actual running receipt exposes genuine driver/execution and its immutable job-local plan');
 Object.assign(op,{jobId:initial.jobId,state:'submitted',receipt:initial});h.save();
 const page=await configurationRead(h,actor,area,`configuration/plans/${initial.planId}/changes`,{size:100}),local=assertM8FreshRetry4Plan(page,initial,area);
 const steps=await configurationRead(h,actor,area,`configuration/jobs/${initial.jobId}/steps`,{size:100}),s=steps.items?.[0];
 h.check(steps.items?.length===1&&steps.nextCursor===null&&s.executionId===initial.executionId&&uuid(s.id)&&s.planStepId===page.items[0].stepId&&s.state==='pending'
  &&s.objectWorkspaceId===area.wid&&s.originalId===c.serviceId&&s.type==='services'&&s.action==='update'&&s.operationId===null&&s.verified===false,'new execution and cloned plan are joined by one real pending typed step before any write session');
 return{receipt:initial,plan:local,operation:op,step:s};
}
export async function m8DeckFreshRetry4Acceptance(h,actors){
 h.assertWritable();const m=h.state.deckSetContinuation,actor=actors.admin,area=actors.direct;
 h.check(m?.state==='original-uncertain-closed'&&!h.state.deckAcceptance&&!m.newImportKey,'new retry4 intent starts only after original prepared execution is explicitly closed');
 const current=await nativeRead(h,actor,area,'services',c.serviceId);h.check(current.id===c.serviceId&&current.retries===0,'independent new Service intent begins from current BFF fields, not a replay of retries2');
 const desired=parse(h.state.baseline.yaml),service=desired.services?.find(v=>v.id===c.serviceId);h.check(service?.retries===0,'original deployment material retains the baseline value');service.retries=4;
 const importedDocument=structuredClone(desired),keep={};for(const consumer of importedDocument.consumers??[])for(const credential of consumer.basicauth_credentials??[]){delete credential.password;keep[`credentials:basic-auth:${consumer.id}:${credential.id}`]='keep';}
 const key=randomUUID(),body={scope:'workspace',mode:'merge',yaml:stringify(importedDocument),basicPasswordIntents:keep};
 m.newImportKey=key;m.newImportBodySha256=sha256(JSON.stringify(body));m.newCurrentBefore=structuredClone(current);m.state='new-retry4-preview-once';h.save();
 const imported=await configurationWrite(h,actor,area,'configuration/imports',body,{kind:'import',key});
 h.check(imported.jobId!==c.jobId&&![c.planId].includes(imported.planId)&&imported.counts?.create===0&&imported.counts.update===1&&imported.counts.delete===0&&imported.counts.conflict===0,'new independent retry4 preview has exactly one update and no other changes');
 assertM8FreshRetry4Plan(await configurationRead(h,actor,area,`configuration/plans/${imported.planId}/changes`,{size:100}),imported,area);
 m.newImportJobId=imported.jobId;m.state='new-retry4-direct-deck-apply';h.save();const e=await submitFreshDeckApply(h,actor,area,imported);
 m.newApplyJobId=e.receipt.jobId;m.newExecutionId=e.receipt.executionId;h.save();
 const session=assertM8DeckSession(h,h.data(await h.request(actor,scope(area.cid,area.wid,'configuration/deck-sessions'),'POST',
  {jobId:e.receipt.jobId,purpose:'write',planId:e.plan.id,planRevision:e.plan.planRevision,planHash:e.plan.planHash})),{purpose:'write',jobId:e.receipt.jobId,actor,area});
 h.state.deckSessions.push(session);h.state.fixtures.push({...area,type:'configuration_deck_sessions',id:session.id,name:session.id});m.newWriteSessionId=session.id;m.state='new-retry4-standard-sync';h.save();
 await runM8FixedDeckPrivateStderr(h,actor,area,{command:'sync',sessionId:session.id,tokenSecret:session.tokenSecret,stateYaml:stringify(desired)},{jobId:e.receipt.jobId});
 const terminal=await configurationRead(h,actor,area,`configuration/jobs/by-key/${e.receipt.idempotencyKey}`);assertConfigurationReceipt(h,terminal,{actor,area,key:e.receipt.idempotencyKey,jobId:e.receipt.jobId,kind:'apply'});
 h.check(terminal.state==='succeeded'&&terminal.executionCompleted===true&&terminal.driver==='deck'&&terminal.executionId===e.receipt.executionId&&terminal.completedSteps===1
  &&terminal.planId===e.plan.id&&terminal.planRevision===e.plan.planRevision&&terminal.planHash===e.plan.planHash,'actual terminal receipt independently proves original new CLI execution and cloned plan, beyond exit0');
 const steps=await configurationRead(h,actor,area,`configuration/jobs/${terminal.jobId}/steps`,{size:100}),s=steps.items?.[0];
 h.check(steps.items?.length===1&&steps.nextCursor===null&&s.id===e.step.id&&s.executionId===e.receipt.executionId&&s.planStepId===e.step.planStepId&&s.state==='succeeded'
  &&s.verified===true&&uuid(s.operationId)&&s.objectWorkspaceId===area.wid&&s.originalId===c.serviceId,'one exact actual verified Native step closes the new standard runner execution');
 const actual=await nativeRead(h,actor,area,'services',c.serviceId);
 h.check(actual.id===c.serviceId&&actual.retries===4&&['name','host','port','protocol','connect_timeout','read_timeout','write_timeout'].every(k=>JSON.stringify(actual[k])===JSON.stringify(current[k])),
  'current Kong Service proves retries4 and unchanged SDK extra fields');await sixCredentialProxyAcceptance(h,h.state.nativeFixture,'actual-deck-retry4-sync');
 Object.assign(e.operation,{state:'succeeded',receipt:terminal});h.save();
 const revoked=h.data(await h.request(actor,scope(area.cid,area.wid,`configuration/deck-sessions/${session.id}`),'DELETE',{revision:session.revision,confirmed:true,confirm_name:session.id}));
 h.check(revoked.revoked===true,'new actual write session is revoked by its original current-authorized owner');session.revoked=true;
 h.state.deckAcceptance={captureJobId:h.state.deckPoolContinuation.selectedCaptureJobId,importJobId:imported.jobId,applyJobId:terminal.jobId,writeSessionId:session.id,
  nativeOperationId:s.operationId,actualProxyCredentialKinds:6,desiredRetries:4,originalPreparedJobId:c.jobId,originalPreparedState:'uncertain',originalNativeStepNotStarted:true,originalCliIssued:true,originalUnknownCliRetained:true};
 m.state='cli-completed';h.public??={};h.public.deckAcceptance={...h.state.deckAcceptance,toolVersion:'1.2.4',toolBinarySha256:'642f49fd64e83aff867939705dbd927c5e750b241a99e8539ab22d18930427ed',formatVersion:'1.1',actualDiffPreviouslyProved:true,actualSync:true,CLIExitAloneAccepted:false,nativeAdminBypassRequests:0};h.save();return h.state.deckAcceptance;
}
