// @ts-nocheck -- actual helper and UI journal functions, synthetic RAM only.
import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { M8Harness, sha256 } from './lib/m8-harness.mjs';
import { M8_UI_ACTIONS, createM8UiJournal, m8UiCookies, m8UiExpected, beforeM8UiPacket, proveM8UiActor, observeM8UiAck, confirmM8UiReceipt, m8UiReceiptPath, bindM8UiEntity } from './lib/m8-manual-journal.mjs';
import { m8ManualUiAuditAcceptance, finalizeM8ManualUiAuditAcceptance } from './lib/m8-manual-audit-acceptance.mjs';

function fixture(change=''){
 const now=Math.floor(Date.now()/1000)*1000,cid=randomUUID(),wid=randomUUID(),ids={snapshot:randomUUID(),schedule:randomUUID(),export:randomUUID(),gitops:randomUUID(),noopPlan:randomUUID()},tag='m8-security-aabb1122';
 const session=label=>{const actor=randomUUID(),sid=randomUUID(),csrf=`synthetic-${label}-csrf`,access=`unsigned.${Buffer.from(JSON.stringify({sub:actor,sid,exp:now/1000+900})).toString('base64url')}.synthetic`;
  return{label,user:{id:actor,username:`synthetic-${label}`},sid,csrf,expiresAt:now+900000,cookie:`kongos_access=${access}; kongos_refresh=${sid}.synthetic-refresh; kongos_csrf=${csrf}`};};
 const sessions={admin:session('admin'),owner:session('owner'),readonly:session('read-only')},bootstrap=session('bootstrap-provisioner'),actors={admin:sessions.admin,owner:sessions.owner,bootstrap};
 const handoff={version:1,phase:'ready',testTag:tag,approvedActions:[...M8_UI_ACTIONS],direct:{cid,wid},directWorkspaceName:'synthetic-M8',snapshotId:randomUUID(),planId:randomUUID(),jobId:randomUUID(),exportId:randomUUID(),approvalWorkflowId:randomUUID(),approvalMode:'completed-read-only'};
 const journal=createM8UiJournal({handoff,sessions,now}),persist=()=>{},receipts=new Map(),audit=new Map(),calls=[],saves=[];
 proveM8UiActor(journal,'admin',{user:{...sessions.admin.user,permissionsVersion:'synthetic:current'},csrfToken:sessions.admin.csrf},persist);
 bindM8UiEntity(journal,'plan',{id:handoff.planId,clusterId:cid,workspaceId:wid,revision:3,planRevision:2,planHash:'a'.repeat(64),stepCount:1},persist);
 let snapshot={id:ids.snapshot,clusterId:cid,workspaceId:wid,revision:2,name:journal.names.snapshot,state:'ready'},schedule;
 const view=(a,type,id,action,after)=>({id:randomUUID(),actorId:a.actorId,actorType:'console',sourceIp:'127.0.0.1',clusterId:cid,workspaceId:wid,entityType:type,entityId:id,action,before:null,after,
  jsonPatch:[{op:'replace',path:'',value:structuredClone(after)}],workflowId:null,result:'success',requestId:a.requestId,occurredAt:new Date(now).toISOString(),scopeQuality:'verified'});
 for(let i=0;i<12;i++){
  const expected=m8UiExpected(journal),key=randomUUID(),packet={method:expected.method,url:`http://127.0.0.1:8080${expected.path}?workspaceId=${wid}`,rawBody:JSON.stringify(expected.body),headers:{'content-type':'application/json','x-idempotency-key':key,'x-csrf-token':sessions.admin.csrf,cookie:sessions.admin.cookie,'accept':'application/json'}};
  const a=beforeM8UiPacket(journal,'admin',packet,m8UiCookies(sessions.admin,now),persist,now),jobId=randomUUID();let progress={},entity,extras={};
  if(i===0)progress={snapshotId:ids.snapshot};
  if(i===1)progress={exportId:ids.export,mode:'review',confirmationName:'synthetic export',format:'deck-1.1'};
  if(i===2)progress={exportId:ids.export,mode:'review',downloadPermitConsumed:true,byteCount:42,fileDeliveryUnconfirmed:true};
  if(i>=3&&i<=6){const operation=i===3?'create':i===4?'update':i===5?'archive':'restore';schedule={id:ids.schedule,clusterId:cid,workspaceId:wid,name:journal.names.schedule,revision:i-2,state:i===3?'active':i===5?'deleted':'paused',scopeKind:'workspace',rootIds:[],ownerUserId:a.actorId};entity=structuredClone(schedule);progress={resourceId:ids.schedule,resourceType:'config_snapshot_schedules',operation};}
  if(i===7){entity={id:ids.gitops,clusterId:cid,workspaceId:wid,jobId:handoff.jobId,createdBy:a.actorId,repositoryLabel:journal.names.repository,commitSha:'a'.repeat(40),pipelineReference:'manual-ui/source-check'};progress={resourceId:ids.gitops,resourceType:'configuration_gitops_runs',operation:'create'};}
  if(i===8||i===9){snapshot={...snapshot,revision:snapshot.revision+1,state:i===8?'deleted':'ready'};entity=structuredClone(snapshot);progress={resourceId:ids.snapshot,resourceType:'config_snapshots',operation:i===8?'archive':'restore'};}
  if(i===10)progress={planId:ids.noopPlan,stepCount:0,deleteCount:0};
  if(i===11)progress={reconciledPlanId:handoff.planId,readOnly:true,executionChanged:false,observations:[{causalOutcomeUnproven:true,originalId:randomUUID()}]};
  if(i===1)extras={exportRevision:4,capabilities:{download:true}};
  const job={id:jobId,jobId,actorId:a.actorId,clusterId:cid,workspaceId:wid,revision:2,kind:a.kind,state:'succeeded',safeProgress:structuredClone(progress),...progress,...extras,executionMode:'direct',approvalRequired:false,workflowId:null};
  const receipt={...job,domain:'configuration',durable:true,registrationCompleted:true,submissionCompleted:true,executionCompleted:true,idempotencyKey:key,originalScope:{clusterId:cid,workspaceId:wid},job:structuredClone(job)};
  const binary=i===2?{bytes:42,sha256:'b'.repeat(64),yaml:true,noStore:true,nosniff:true,exportId:ids.export}:undefined;
  observeM8UiAck(journal,a,{status:expected.method==='POST'?201:200,requestId:randomUUID(),data:i===2?null:{...receipt,...(entity?{entity}:{})},...(binary?{binary}:{})},persist);
  expect(confirmM8UiReceipt(journal,'admin',{method:'GET',url:`http://127.0.0.1:8080${m8UiReceiptPath(journal,a)}`},receipt,randomUUID(),persist)).toBe(true);
  if(i===0)bindM8UiEntity(journal,'snapshot',snapshot,persist);
  receipts.set(key,structuredClone(receipt));const rows=[view(a,'configuration_jobs',jobId,i===0?'configuration.capture':'configuration.job.complete',{id:jobId,kind:a.kind,clusterId:cid,workspaceId:wid,state:'succeeded',safeProgress:progress})];
  if(entity)rows.push(view(a,progress.resourceType,entity.id,`configuration.${progress.operation}`,entity));
  if(i===0)rows.push(view(a,'config_snapshots',ids.snapshot,'snapshot.capture',snapshot));
  if(i===2)rows.push(view(a,'configuration_exports',ids.export,'configuration.download.consume',{state:'consumed',byteCount:42,exportId:ids.export}));
  audit.set(a.requestId,rows);
 }
 const prior={index:0,key:randomUUID(),method:'POST',path:'/api/v1/source-fixture',body:{},bodySha256:sha256('{}'),state:'response_observed',status:201,requestId:randomUUID()};
 const packets=journal.attempts.map(row=>({index:1+row.index,source:'manual-ui',manualIndex:row.index,action:row.action,key:row.key,method:row.method,path:row.path,query:row.query,body:structuredClone(row.body),bodySha256:row.bodySha256,actorId:row.actorId,sessionId:row.sessionId,clusterId:row.clusterId,workspaceId:row.workspaceId,headers:structuredClone(row.headers),state:'response_observed',startedAt:row.startedAt,expected:[200,201,202],status:row.status,requestId:row.requestId,responseData:structuredClone(row.responseData),receiptRequestId:row.receiptRequestId,binary:structuredClone(row.binary)}));
 const state={version:1,milestone:'M8',testTag:tag,phase:'ui-complete',inFlight:null,requests:[prior,...packets],secrets:[],privateHistoryRefs:[{file:'synthetic-retained.json',sha256:'a'.repeat(64),bytes:1}],scopes:{direct:{cid,wid}},sessions:{admin:sessions.admin,owner:sessions.owner,'read-only':sessions.readonly,'bootstrap-provisioner':bootstrap},manualUiJournal:journal,
  manualUiHistory:{version:1,originalRequestCount:1,originalPrefixSha256:sha256(JSON.stringify([prior])),originalSessions:structuredClone(journal.sessions),originalHandoff:structuredClone(handoff)}};
 const h={state,public:{},checks:[],check:M8Harness.prototype.check,data:M8Harness.prototype.data,save(extra={}){Object.assign(state,extra);saves.push(structuredClone(state.manualUiAuditProof));},
  async request(actor,path,method,body,options){expect(method).toBe('GET');expect(body).toBeUndefined();expect(options).toEqual({expected:[200],renew:false});expect(saves.at(-1).finalization?.inFlight??saves.at(-1).inFlight).toMatchObject({method:'GET',state:'prepared',actorId:actor.user.id,sessionId:actor.sid});calls.push({actorId:actor.user.id,sid:actor.sid,path,method});
   if(change==='unknown'&&calls.length===1)throw Error('synthetic unknown read');const url=new URL(path,'http://source.invalid');let data;
   if(path.includes('/configuration/jobs/by-key/')){expect(actor.user.id).toBe(journal.sessions.admin.user.id);expect(actor.sid).toBe(journal.sessions.admin.sid);data=structuredClone(receipts.get(url.pathname.split('/').at(-1)));
    if(change==='freshForeignActor')data.actorId=randomUUID();if(change==='freshWrongResource'&&data.resourceType)data.resourceType='config_snapshots';if(change==='freshBinaryBytes'&&data.downloadPermitConsumed)data.byteCount=43;
   }else if(/\/audit\/[a-f\d-]{36}$/.test(url.pathname)){expect(actor.user.id).toBe(bootstrap.user.id);data=structuredClone([...audit.values()].flat().find(v=>v.id===url.pathname.split('/').at(-1)));if(change==='changedImmutable')data.sourceIp='192.0.2.1';}
   else{expect(url.searchParams.get('workspaceId')).toBe(wid);expect(url.searchParams.get('size')).toBe('100');expect(url.searchParams.get('result')).toBe('success');const rows=structuredClone(audit.get(url.searchParams.get('requestId')));data={items:rows,size:100,total:null,nextCursor:null,scanLimitReached:false};
    if(change==='foreignAudit')data.items[0].workspaceId=randomUUID();if(change==='badPatch')data.items[0].jsonPatch=[];if(change==='missingTerminal')data.items=data.items.filter(v=>!['configuration.capture','configuration.job.complete'].includes(v.action));if(change==='cursorCycle')data={...data,items:[],nextCursor:'same-cursor'};
    if(change==='twoPages'&&!url.searchParams.has('cursor'))data={...data,items:rows.slice(0,1),nextCursor:'synthetic-next'};if(change==='twoPages'&&url.searchParams.has('cursor'))data.items=rows.slice(1);
   }
   return{status:200,requestId:change==='oldReadIdentity'?journal.attempts[0].receiptRequestId:randomUUID(),payload:{success:true,data}};
  }};
 return{h,state,actors,bootstrap,journal,calls,receipts,audit,originalRequests:JSON.stringify(state.requests),originalJournal:JSON.stringify(journal)};
}

describe('independent SOURCE M8 active original UI receipt and immutable audit closure',()=>{
 it('re-reads all twelve actual by-key receipts and full paginated audits before cleanup, then only bootstrap immutable IDs afterward',async()=>{
  const f=fixture('twoPages');f.state.cleanupJournal={version:1,testTag:f.state.testTag,phase:'starting',inFlight:null,metadata:[],archives:[],identity:[],operations:[{method:'GET'}]};
  const result=await m8ManualUiAuditAcceptance(f.h,f.actors);expect(result.confirmedWrites).toBe(12);expect(result.auditEventIds.length).toBeGreaterThan(12);expect(f.calls.filter(c=>c.path.includes('/by-key/'))).toHaveLength(12);
  expect(f.state.manualUiAuditProof.records.every(r=>r.auditReadRequestIds.length===2&&r.terminalEOF)).toBe(true);expect(f.state.manualUiAuditProof.state).toBe('complete');
  expect(JSON.stringify(f.state.requests)).toBe(f.originalRequests);expect(JSON.stringify(f.journal)).toBe(f.originalJournal);
  f.state.cleanup={businessCompleted:true,identitySoftDeleted:true};f.state.cleanupStarted=true;const before=f.calls.length;const closed=await finalizeM8ManualUiAuditAcceptance(f.h,f.bootstrap);
  expect(closed).toMatchObject({confirmedWrites:12,afterCleanup:true,allImmutableViewsUnchanged:true,originalActorByKeyReadsAfterCleanup:0,zeroBusinessWrites:true});expect(f.calls.slice(before).every(c=>c.actorId===f.bootstrap.user.id&&c.path.includes('/audit/')&&!c.path.includes('/by-key/'))).toBe(true);
  const n=f.calls.length;await expect(finalizeM8ManualUiAuditAcceptance(f.h,f.bootstrap)).rejects.toThrow();expect(f.calls).toHaveLength(n);
 });
 it('rejects raw body, complete headers, global tuple, SID, action and old request-ID mismatches before any transport',async()=>{
  for(const mutate of[f=>{f.journal.attempts[0].rawBody+=' ';},f=>{delete f.state.requests[1].headers.accept;},f=>{f.state.requests[1].receiptRequestId=randomUUID();},f=>{f.actors.admin.sid=randomUUID();},f=>{f.journal.attempts[0].action='snapshot.restore';},f=>{f.state.requests[1].state='prepared';},f=>{const a=f.journal.attempts[8],p=f.state.requests[9];a.body.revision=0;a.rawBody=JSON.stringify(a.body);a.bodySha256=sha256(a.rawBody);p.body=structuredClone(a.body);p.bodySha256=a.bodySha256;}]){
   const f=fixture();mutate(f);await expect(m8ManualUiAuditAcceptance(f.h,f.actors)).rejects.toThrow();expect(f.calls).toHaveLength(0);
  }
 });
 it('requires actual fresh served authority rather than trusting the retained succeeded client JSON',async()=>{
  for(const change of['freshForeignActor','freshWrongResource','freshBinaryBytes','oldReadIdentity']){const f=fixture(change);await expect(m8ManualUiAuditAcceptance(f.h,f.actors)).rejects.toThrow('STOP_NO_REPLAY');expect(f.state.manualUiAuditProof.state).toBe('stopped-original-retained');expect(f.calls.every(c=>c.method==='GET')).toBe(true);}
 });
 it('rejects foreign audit scope, invalid full RFC6902, missing semantic terminal and a cursor cycle',async()=>{
  for(const change of['foreignAudit','badPatch','missingTerminal','cursorCycle']){const f=fixture(change);await expect(m8ManualUiAuditAcceptance(f.h,f.actors)).rejects.toThrow('STOP_NO_REPLAY');expect(f.state.manualUiAuditProof.state).toBe('stopped-original-retained');expect(f.state.manualUiAuditProof.records).toHaveLength(0);}
 });
 it('unknown GET preserves every original and permanently stops without write or whole helper replay',async()=>{
  const f=fixture('unknown');await expect(m8ManualUiAuditAcceptance(f.h,f.actors)).rejects.toThrow('STOP_NO_REPLAY');expect(f.calls).toHaveLength(1);expect(f.state.manualUiAuditProof.inFlight.state).toBe('response_unknown');expect(JSON.stringify(f.state.requests)).toBe(f.originalRequests);
  await expect(m8ManualUiAuditAcceptance(f.h,f.actors)).rejects.toThrow();expect(f.calls).toHaveLength(1);
 });
 it('cannot begin after cleanup and cannot finalize without exact actual bootstrap, prefix and completed proof',async()=>{
  const f=fixture();f.state.cleanupStarted=true;await expect(m8ManualUiAuditAcceptance(f.h,f.actors)).rejects.toThrow();expect(f.calls).toHaveLength(0);
  const running=fixture();running.state.cleanupJournal={version:1,testTag:running.state.testTag,phase:'configuration-running',inFlight:null,metadata:[],archives:[],identity:[],operations:[]};await expect(m8ManualUiAuditAcceptance(running.h,running.actors)).rejects.toThrow();expect(running.calls).toHaveLength(0);
  for(const mutate of[q=>{q.bootstrap.sid=randomUUID();},q=>{q.state.requests[0].body.changed=true;},q=>{q.state.manualUiAuditProof.records[0].tupleSha256='0'.repeat(64);},q=>{q.state.manualUiAuditProof.state='building';}]){
   const q=fixture();await m8ManualUiAuditAcceptance(q.h,q.actors);q.state.cleanup={businessCompleted:true,identitySoftDeleted:true};const n=q.calls.length;mutate(q);await expect(finalizeM8ManualUiAuditAcceptance(q.h,q.bootstrap)).rejects.toThrow();expect(q.calls).toHaveLength(n);
  }
 });
 it('retains a changed post-cleanup immutable audit as a STOP without reading disabled actors or replaying',async()=>{
  const f=fixture('changedImmutable');await m8ManualUiAuditAcceptance(f.h,f.actors);f.state.cleanup={businessCompleted:true,identitySoftDeleted:true};const n=f.calls.length;
  await expect(finalizeM8ManualUiAuditAcceptance(f.h,f.bootstrap)).rejects.toThrow('STOP_NO_REPLAY');expect(f.calls).toHaveLength(n+1);expect(f.state.manualUiAuditProof.finalization.state).toBe('stopped-original-retained');
  await expect(finalizeM8ManualUiAuditAcceptance(f.h,f.bootstrap)).rejects.toThrow();expect(f.calls).toHaveLength(n+1);
 });
});
