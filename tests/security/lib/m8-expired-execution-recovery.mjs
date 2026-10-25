import {randomUUID} from 'node:crypto';
import {parse,stringify} from 'yaml';
import {sha256,entity,scope} from './m8-harness.mjs';
import {configurationRead,configurationWrite,assertConfigurationReceipt,completeConfigurationWorkflow} from './m8-configuration-acceptance.mjs';
import {applyImportedJob} from './m8-transfer-acceptance.mjs';
import {restoreClusterMode} from './m8-fixtures.mjs';

export const M8_EXPIRED_EXECUTION=Object.freeze({count:121,prefix:'c998bb14dfb49dd1527e18244063330de2225fc12a58fe6a6483f29cec579f40',
 prefix115:'b19d7ed70b8ae1817af37dee7e52afde6f77be3e0354b9859ae32aa35e996788',
 failurePath:'artifacts/M8/security-live-reciprocal-binding-repair.json',failureSha256:'f547486ab8d4c867fdb72931006f9e8ff3816297e729a5a22daafbdb1c5c8413',
 diagnosisPath:'artifacts/M8/v2-edge-timeout-readonly-diagnosis.json',diagnosisSha256:'553bf8a503b9f89dbe99c18c71543faec1885a35f56dae494be9531cf75d4b7d',
 timingPath:'artifacts/M8/v2-edge-timeout-objects-timing-corrected-readonly.json',timingSha256:'9d9946184caab871e3ed0f7e8d962905cdc1cd309c5f9d5edd42e645c1999076',
 packetSha256:'c66367285e9065e4b3d8fa635d5deddeed87fafb7170ad0a587e12b7eb14ea96',
 key:'0210c766-c6dc-4e79-9208-798c06eb068f',submissionKey:'df72dfb0-8344-4425-948b-2514a090d4ee',
 cid:'d1dfaec8-2a10-4170-8a15-20a600a4bd4f',wid:'b999a4ef-250a-4d20-8418-66cfc024d690',
 actorId:'b5f796fa-9515-47de-9123-89a903a48224',sid:'81eb0903-bc6f-447b-a9a7-7cadf55faa77',
 jobId:'847ec484-16f6-4a8f-9e1c-38fa8861a1da',workflowId:'a42c85a5-9192-4e9c-acd9-418a897b199f',planId:'6514adbc-daeb-4412-9796-47054e7b63e1',
 executionId:'f3c93d16-cb24-400e-925b-0bd36ac2f33e',workflowExecutionId:'5ecb3dd4-2125-4c42-94ad-1f94b9285fe6',
 planHash:'2203556e6b1a03bb0a5e797642812708ae1a2780c753510d24aaaea614c0c21a',lastId:'f63e330b-48e8-4198-8f32-a5acd8f671fd'});
const uuid=v=>typeof v==='string'&&/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(v);
const reject=()=>{throw Error('M8_EXACT_EXPIRED_EXECUTION_CHECKPOINT_REQUIRED');};
export function assertM8ExpiredExecutionCheckpoint(r,failureBytes,diagnosisBytes,timingBytes){
 const c=M8_EXPIRED_EXECUTION,f=JSON.parse(failureBytes),d=JSON.parse(diagnosisBytes),t=JSON.parse(timingBytes),p=r.requests?.[120],submitted=r.requests?.[117],source=r.requests?.[116];
 if(sha256(failureBytes)!==c.failureSha256||sha256(diagnosisBytes)!==c.diagnosisSha256||sha256(timingBytes)!==c.timingSha256
  ||r.version!==1||r.milestone!=='M8'||r.testTag!==f.testTag||r.requests?.length!==c.count||sha256(JSON.stringify(r.requests))!==c.prefix
  ||sha256(JSON.stringify(r.requests.slice(0,115)))!==c.prefix115||sha256(JSON.stringify(p))!==c.packetSha256
  ||f.passed!==1383||f.failed!==1||f.unknownWrites!==0||f.allPassed!==false||r.phase!=='stopped-failure'||r.inFlight!==null
  ||r.expiredExecutionRecovery||r.approvalTransfer||r.c2ModeRestored||r.cliIntents?.length||!r.directTransfer||r.fiveClassRecovery?.length!==5
  ||r.requests.some(v=>v.state!=='response_observed')||p.status!==504||p.requestId!==null||p.key!==c.key||p.actorId!==c.actorId||p.sessionId!==c.sid
  ||submitted.key!==c.submissionKey||submitted.status!==201||submitted.responseData?.jobId!==c.jobId||submitted.responseData.workflowId!==c.workflowId
  ||submitted.responseData.planId!==c.planId||submitted.responseData.planHash!==c.planHash||source.status!==201||source.body?.mode!=='merge'
  ||source.body?.scope!=='workspace'||source.responseData?.counts?.create!==17||typeof source.body.yaml!=='string'
  ||r.scopes?.approval?.cid!==c.cid||r.scopes.approval.wid!==c.wid||r.sessions?.admin?.user?.id!==c.actorId||r.sessions.admin.sid!==c.sid
  ||d.currentPrefix121!==c.prefix||d.originalPacketSha256!==c.packetSha256||d.sql?.ok!==true||d.sql.nonOwnerReadOnly!==true
  ||d.sql.job?.id!==c.jobId||d.sql.job.state!=='running'||d.sql.job.same_sid!==true||d.sql.job.same_actor!==true
  ||d.sql.workflow?.id!==c.workflowId||d.sql.workflow.state!=='failed'||d.sql.executions?.length!==1||d.sql.executions[0].id!==c.executionId
  ||d.sql.executions[0].state!=='executing'||d.sql.steps?.length!==17||d.sql.steps.filter(v=>v.state==='succeeded').length!==16
  ||d.sql.steps[16].state!=='running'||d.sql.operations?.filter(v=>v.state==='succeeded'&&v.remote_completed===true).length!==16
  ||d.sql.workflowExecutions?.length!==1||d.sql.workflowExecutions[0].id!==c.workflowExecutionId||d.sql.workflowExecutions[0].state!=='failed'
  ||t.newBusinessWrites!==0||t.newAuthWrites!==0||t.newNativeWrites!==0)reject();
 const services=parse(source.body.yaml)?.services;
 if(!Array.isArray(services)||services.length!==17||new Set(services.map(v=>v.name)).size!==17)reject();
 return{failed:f,diagnosis:d,timing:t,source,submission:submitted,services};
}
export function m8FreshBudgetServices(testTag,nonce,oldIds=[],oldNames=[]){
 if(typeof testTag!=='string'||!/^m8-security-[a-f\d]{8}$/.test(testTag)||!uuid(nonce))throw Error('M8_FRESH_BUDGET_SCENARIO_IDENTITY_REQUIRED');
 const services=Array.from({length:17},(_,n)=>({id:randomUUID(),name:`${testTag}-budget-${nonce.slice(0,8)}-${n}`,host:'echo-upstream',port:8081,protocol:'http',retries:0,tags:[testTag]}));
 if(new Set(services.map(v=>v.id)).size!==17||services.some(v=>oldIds.includes(v.id)||oldNames.includes(v.name)))throw Error('M8_FRESH_BUDGET_SCENARIO_COLLISION');
 return services;
}
export function m8ServiceFieldsMatch(current,expected,testTag){return current?.id===expected.id&&current.name===expected.name&&current.host===expected.host
 &&current.port===expected.port&&current.protocol===expected.protocol&&current.retries===expected.retries&&Array.isArray(current.tags)&&current.tags.includes(testTag);}
async function allSteps(h,actor,area,jobId){
 const rows=[],seen=new Set();let cursor;
 for(let page=0;page<3;page++){
  const data=await configurationRead(h,actor,area,`configuration/jobs/${jobId}/steps`,{size:10,...(cursor?{cursor}:{})});
  h.check(Array.isArray(data.items)&&data.items.length<=10&&data.total===null,'configuration step evidence uses bounded server cursor pages');rows.push(...data.items);
  if(!data.nextCursor){h.check(rows.length===17&&rows.every((v,n)=>v.stepOrder===n+1),'seventeen typed step proofs reach actual terminal EOF');return rows;}
  h.check(typeof data.nextCursor==='string'&&!seen.has(data.nextCursor),'step cursor advances without replay');seen.add(data.nextCursor);cursor=data.nextCursor;
 }
 throw Error('M8_STEP_EOF_REQUIRED');
}
export function assertM8OriginalAbandonIntent(job,actor,area){
 const c=M8_EXPIRED_EXECUTION,i=job?.abandonmentIntent;
 if(job?.domain!=='configuration'||job.durable!==true||job.idempotencyKey!==c.submissionKey||job.jobId!==c.jobId||job.id!==c.jobId
  ||job.actorId!==actor.user.id||actor.user.id!==c.actorId||actor.sid!==c.sid||job.clusterId!==area.cid||job.workspaceId!==area.wid
  ||area.cid!==c.cid||area.wid!==c.wid||job.state!=='running'||job.workflowId!==c.workflowId||job.planId!==c.planId||job.capabilities?.abandon!==true
  ||i?.jobId!==c.jobId||i.executionId!==c.executionId||i.workflowExecutionId!==c.workflowExecutionId||i.planHash!==c.planHash
  ||i.revision!==job.revision||!Number.isSafeInteger(i.executionRevision)||i.executionRevision<1||!Number.isSafeInteger(i.planRevision)||i.planRevision<1
  ||!Number.isSafeInteger(i.leaseGeneration)||i.leaseGeneration<1||i.confirmationName!==`abandon:${c.jobId}`)throw Error('M8_CURRENT_ORIGINAL_ABANDONMENT_INTENT_REQUIRED');
 return i;
}
export function assertM8ClosedOriginalJob(job,original,intent,actor,area,requestId){
 const c=M8_EXPIRED_EXECUTION;
 if(job?.idempotencyKey!==c.submissionKey||job.jobId!==c.jobId||job.actorId!==actor.user.id||job.clusterId!==area.cid||job.workspaceId!==area.wid
  ||job.state!=='uncertain'||job.revision!==original.revision+1||job.workflowId!==c.workflowId||job.planId!==c.planId
  ||job.executionId!==c.executionId||job.executionRevision!==intent.executionRevision+1||job.planRevision!==intent.planRevision||job.planHash!==intent.planHash
  ||job.leaseGeneration!==intent.leaseGeneration||job.workflowExecutionId!==c.workflowExecutionId||job.abandoned!==true||job.terminalFailureRecorded!==true
  ||job.executionCompleted!==true||job.abandonmentSessionMatches!==true||job.abandonRequestId!==requestId||job.completedSteps!==16||job.unresolvedSteps!==1)
  throw Error('M8_EXACT_UNCERTAIN_ORIGINAL_CLOSURE_REQUIRED');
 return job;
}
export async function closeM8OriginalExpiredExecution(h,actors,original){
 const c=M8_EXPIRED_EXECUTION,area=actors.approval,actor=actors.admin,marker=h.state.expiredExecutionRecovery;
 const mode=entity(h.data(await h.request(actor,`/clusters/${area.cid}`)));h.check(mode.execution_mode==='approval','original C2 stays in approval through failure closure and independent validation');
 const wf=await configurationRead(h,actor,area,`workflows/receipts/by-key/${c.key}`);
 h.check(wf.workflowId===c.workflowId&&wf.executionId===c.workflowExecutionId&&wf.idempotencyKey===c.key&&wf.state==='failed','original failed wrapper remains terminal without another approve or execute');
 const job=await configurationRead(h,actor,area,`configuration/jobs/by-key/${c.submissionKey}`),intent=assertM8OriginalAbandonIntent(job,actor,area),before=await allSteps(h,actor,area,c.jobId);
 h.check(before.filter(v=>v.state==='succeeded'&&v.verified===true).length===16&&before[16].state==='running','old partial execution has sixteen verified receipts and one unresolved running step');
 const ids=original.diagnosis.sql.steps.map(v=>v.original_native_id),currentFacts=[];
 for(const [n,id] of ids.entries()){
  const response=await h.request(actor,scope(area.cid,area.wid,`entities/services/${id}`),'GET',undefined,{expected:n===16?[200,404]:[200]});
  const current=response.status===200?entity(h.data(response)):null;
  if(current){const spec=original.services.find(v=>v.name===current.name);h.check(!!spec&&m8ServiceFieldsMatch(current,{...spec,id},h.state.testTag),'old Service is verified by its actual name and fields, independently of UUID-sorted step order or unproved transport outcome');
   if(!h.state.fixtures.some(v=>v.type==='services'&&v.id===id&&v.cid===area.cid&&v.wid===area.wid))h.state.fixtures.push({...area,type:'services',id,name:current.name});}
  currentFacts.push({id,status:response.status,exists:current!==null,fieldsMatch:current!==null,neverSentProven:false});h.save();
 }
 marker.originalCurrentObjects=currentFacts;marker.originalSuccessfulStepSha256=sha256(JSON.stringify(before.slice(0,16)));marker.state='original-abandon-once';
 const body={revision:intent.revision,executionId:intent.executionId,executionRevision:intent.executionRevision,planRevision:intent.planRevision,planHash:intent.planHash,
  leaseGeneration:intent.leaseGeneration,workflowExecutionId:intent.workflowExecutionId,confirmed:true,confirm_name:intent.confirmationName};
 const key=randomUUID();marker.abandonAttempt={idempotencyKey:key,bodySha256:sha256(JSON.stringify(body)),body,actorId:actor.user.id,sessionId:actor.sid,area:{...area},state:'prepared'};h.save();
 const response=await h.request(actor,scope(area.cid,area.wid,`configuration/jobs/${c.jobId}/abandon`),'POST',body,{key}),ack=h.data(response);
 h.check(ack.jobId===c.jobId&&ack.executionId===c.executionId&&ack.clusterId===area.cid&&ack.workspaceId===area.wid&&ack.state==='uncertain'
  &&ack.abandoned===true&&ack.originalWorkflowUnchanged===true&&ack.originalNativeReceiptsUnchanged===true,'explicit abandonment records uncertainty without replaying any Native operation');
 const packet=h.state.requests.at(-1),result=await configurationRead(h,actor,area,`configuration/jobs/by-key/${c.submissionKey}`);
 assertM8ClosedOriginalJob(result,job,intent,actor,area,response.requestId);
 const after=await allSteps(h,actor,area,c.jobId),wfAfter=await configurationRead(h,actor,area,`workflows/receipts/by-key/${c.key}`);
 h.check(sha256(JSON.stringify(after.slice(0,16)))===marker.originalSuccessfulStepSha256&&after[16].state==='uncertain'&&after[16].revision===before[16].revision+1
  &&after[16].operationId===before[16].operationId&&after[16].verified===false,'failure closure leaves sixteen actual success receipts unchanged and marks only the unresolved step uncertain');
 h.check(wfAfter.workflowId===wf.workflowId&&wfAfter.executionId===wf.executionId&&wfAfter.state===wf.state&&JSON.stringify(wfAfter.steps)===JSON.stringify(wf.steps),'old immutable failed workflow and its Native budget remain unchanged');
 Object.assign(marker.abandonAttempt,{state:'completed',index:packet.index,packetSha256:sha256(JSON.stringify(packet)),requestId:response.requestId,originalJob:result,intent});
 marker.originalFailureClosure={originalJobState:'uncertain',originalWorkflowState:'failed',oldCompletedSteps:16,oldUnresolvedSteps:1,originalNativeReplayed:false,
  originalUnknownOutcomeRetained:true,neverSentProven:false,abandonRequestId:response.requestId,jobId:c.jobId,executionId:c.executionId};marker.state='original-uncertain-closed';h.save();return result;
}
export function isM8ProvenFailureClosurePacket(r,packet,index){
 const c=M8_EXPIRED_EXECUTION,m=r.expiredExecutionRecovery,a=m?.abandonAttempt,j=a?.originalJob,i=a?.intent;
 if(!a||a.state!=='completed'||m.originalPrefixSha256!==c.prefix||m.originalPacketCount!==121||index!==a.index||packet!==r.requests[index]
  ||sha256(JSON.stringify(r.requests.slice(0,121)))!==c.prefix||sha256(JSON.stringify(packet))!==a.packetSha256
  ||packet.method!=='POST'||packet.path!==`/api/v1/clusters/${c.cid}/configuration/jobs/${c.jobId}/abandon`||packet.query!==`?workspaceId=${c.wid}`
  ||packet.key!==a.idempotencyKey||packet.actorId!==c.actorId||packet.sessionId!==c.sid||packet.clusterId!==c.cid||packet.workspaceId!==c.wid||packet.state!=='response_observed'
  ||packet.status!==201||packet.requestId!==a.requestId||!uuid(packet.requestId)||packet.bodySha256!==a.bodySha256
  ||sha256(JSON.stringify(packet.body))!==a.bodySha256||JSON.stringify(packet.body)!==JSON.stringify(a.body)
  ||packet.body.executionId!==c.executionId||packet.body.workflowExecutionId!==c.workflowExecutionId||packet.body.planHash!==c.planHash
  ||packet.body.planRevision!==i?.planRevision||packet.body.executionRevision!==i?.executionRevision||packet.body.leaseGeneration!==i?.leaseGeneration
  ||packet.body.confirmed!==true||packet.body.confirm_name!==`abandon:${c.jobId}`
  ||Object.keys(packet.body).some(k=>!['revision','executionId','executionRevision','planRevision','planHash','leaseGeneration','workflowExecutionId','confirmed','confirm_name'].includes(k))
  ||typeof packet.headers?.Cookie!=='string'||!/(?:^|;\s*)kongos_access=[^;\s]+(?:;|$)/.test(packet.headers.Cookie)
  ||typeof packet.headers?.['X-CSRF-Token']!=='string'||!packet.headers['X-CSRF-Token']||packet.headers['X-Idempotency-Key']!==packet.key
  ||packet.responseData?.jobId!==c.jobId||packet.responseData.executionId!==c.executionId||packet.responseData.state!=='uncertain'||packet.responseData.abandoned!==true
  ||packet.responseData.originalWorkflowUnchanged!==true||packet.responseData.originalNativeReceiptsUnchanged!==true)return false;
 try{assertM8ClosedOriginalJob(j,{revision:packet.body.revision},i,{user:{id:c.actorId}},{cid:c.cid,wid:c.wid},packet.requestId);}catch{return false;}
 return true;
}
export async function validateM8FreshBudget17(h,actors){
 const marker=h.state.expiredExecutionRecovery,area=actors.approval;
 h.check(marker.state==='original-uncertain-closed'&&!h.state.approvalTransfer,'independent seventeen-step scenario starts only after exact original uncertainty is durably closed');
 const nonce=randomUUID(),services=m8FreshBudgetServices(h.state.testTag,nonce,marker.originalCurrentObjects.map(v=>v.id)),body={scope:'workspace',mode:'merge',yaml:stringify({_format_version:'1.1',services})};
 marker.newScenario={nonce,services,bodySha256:sha256(JSON.stringify(body)),state:'prepared',originalIntentReplayed:false};h.save();
 const imported=await configurationWrite(h,actors.admin,area,'configuration/imports',body,{kind:'import'});h.check(imported.counts?.create===17,'new independent UUID/name plan creates seventeen additional objects while preserving the old sixteen');
 const applied=await applyImportedJob(h,actors,area,imported,{approval:true});
 h.check(applied.jobId!==M8_EXPIRED_EXECUTION.jobId&&applied.workflowId!==M8_EXPIRED_EXECUTION.workflowId&&applied.state==='succeeded'&&applied.completedSteps===17,'actual new seventeen-step approval finishes fully inside the dedicated configuration budget');
 const steps=await allSteps(h,actors.admin,area,applied.jobId);h.check(steps.every(v=>v.state==='succeeded'&&v.verified===true)&&new Set(steps.map(v=>v.effectiveId)).size===17
  &&services.every(s=>steps.some(v=>v.effectiveId===s.id)),'all seventeen new allocated UUIDs have independent verified terminal receipts');
 for(const spec of services){const current=entity(h.data(await h.request(actors.admin,scope(area.cid,area.wid,`entities/services/${spec.id}`))));
  h.check(m8ServiceFieldsMatch(current,spec,h.state.testTag),'each new approved Service has its original allocated UUID and exact current configuration');h.state.fixtures.push({...area,type:'services',id:current.id,name:current.name});h.save();}
 marker.newScenario={...marker.newScenario,state:'succeeded',jobId:applied.jobId,workflowId:applied.workflowId,planId:applied.planId,stepIds:steps.map(v=>v.id),nativeSteps:17,actualCompleteNativeReceipts:17};h.save();
 const metadata=await configurationWrite(h,actors.admin,area,'snapshots/schedules',{scope:'workspace',name:`${h.state.testTag} approval schedule`,intervalMinutes:60,timezone:'UTC',retentionDays:7},{kind:'compare',allowApproval:true});
 const complete=await completeConfigurationWorkflow(h,actors,area,metadata,'configuration-metadata','configuration.metadata');
 const schedules=await configurationRead(h,actors.admin,area,'snapshots/schedules',{scope:'workspace',size:100}),schedule=schedules.items.find(s=>s.name===`${h.state.testTag} approval schedule`);
 h.check(schedule?.ownerUserId===actors.admin.user.id,'fixed configuration metadata approval creates its genuine current owner resource');h.state.fixtures.push({...area,type:'config_snapshot_schedules',id:schedule.id,name:schedule.name});h.save();
 await restoreClusterMode(h,actors.admin,area);
 h.state.approvalTransfer={jobId:applied.jobId,workflowId:applied.workflowId,nativeSteps:17,metadataJobId:complete.jobId,metadataWorkflowId:complete.workflowId,
  originalFailedPartialJobRetained:M8_EXPIRED_EXECUTION.jobId,originalFailureClosure:true,independentNamesAndAllocatedIds:true};
 marker.state='completed';for(const key of['reciprocalBindingRepairTail','nullCreateBeforeRepairTail','currentApproverRepairTail','v2PreparationRepairTail','v2WrapperUnusedTail'])h.state[key].state='completed';h.save();
 return h.state.approvalTransfer;
}
