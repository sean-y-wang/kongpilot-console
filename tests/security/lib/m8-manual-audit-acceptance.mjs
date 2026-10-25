import { isDeepStrictEqual } from 'node:util';
import { createHmac } from 'node:crypto';
import { sha256 } from './m8-harness.mjs';
import { M8_UI_ACTIONS, m8UiExpected, m8UiReceiptPath, m8UiUuid as uuid, confirmM8UiReceipt } from './m8-manual-journal.mjs';
import { m8AuditPatchMatches } from './m8-audit-acceptance.mjs';
import { isM8ProvenConsumedUnknownDownload } from './m8-consumed-review-download.mjs';

const positive=v=>Number.isSafeInteger(v)&&v>0;
const hash=v=>sha256(JSON.stringify(v));
const safeHash=value=>{const normalize=v=>Array.isArray(v)?v.map(normalize):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,normalize(v[k])])):v;return hash(normalize(value));};
const packetTuple=(p,a)=>({index:p.index,manualIndex:p.manualIndex,action:p.action,idempotencyKey:p.key,method:p.method,path:p.path,query:p.query,rawBody:a.rawBody,body:p.body,bodySha256:p.bodySha256,
 headers:p.headers,actorId:p.actorId,sessionId:p.sessionId,clusterId:p.clusterId,workspaceId:p.workspaceId,status:p.status,requestId:p.requestId,receiptRequestId:p.receiptRequestId,binary:p.binary??null});
function sessionMatches(h,actor,original){h.check(uuid(actor?.user?.id)&&uuid(actor.sid)&&actor.user.id===original?.user?.id&&actor.user.username===original.user.username&&actor.sid===original.sid
 &&actor.cookie===original.cookie&&actor.csrf===original.csrf,'manual audit GET uses the actual original named actor SID and cookies without renewal');}
function cookieProof(h,headers,session){let claims;const parse=value=>typeof value==='string'?value.split(';').map(p=>{const at=p.indexOf('=');return[p.slice(0,at).trim(),p.slice(at+1)];}):[];
 const sent=parse(headers.cookie),original=parse(session.cookie),names=['kongos_access','kongos_csrf'];
 try{claims=JSON.parse(Buffer.from(original.find(([n])=>n==='kongos_access')[1].split('.')[1],'base64url').toString());}catch{}
 h.check(sent.length>0&&sent.every(([n,v])=>n&&v)&&new Set(sent.map(([n])=>n)).size===sent.length&&names.every(n=>sent.find(([k])=>k===n)?.[1]===original.find(([k])=>k===n)?.[1]&&original.find(([k])=>k===n)?.[1])
  &&sent.every(([n,v])=>original.some(([k,value])=>k===n&&value===v))&&headers['x-csrf-token']===session.csrf&&typeof session.csrf==='string'&&session.csrf.length>0&&claims?.sub===session.user.id&&claims.sid===session.sid,
 'manual original wire retains exact access/CSRF cookies, actual actor SID and full headers');}
function expectedOriginal(journal,attempt){const copy=structuredClone(journal);copy.nextIndex=attempt.index;
 if(attempt.action.startsWith('schedule.')&&attempt.action!=='schedule.create')copy.bindings.schedule=structuredClone(journal.attempts[attempt.index-1].responseData?.entity);
 if(attempt.action==='snapshot.archive')copy.bindings.snapshot={...copy.bindings.snapshot,revision:attempt.body.revision};
 if(attempt.action==='snapshot.restore')copy.bindings.snapshot=structuredClone(journal.attempts[attempt.index-1].responseData?.entity);
 return m8UiExpected(copy);}
function resource(attempt){const action=attempt.action;
 if(action.startsWith('schedule.'))return{type:'config_snapshot_schedules',operation:action==='schedule.pause'?'update':action.split('.')[1]};
 if(['snapshot.archive','snapshot.restore'].includes(action))return{type:'config_snapshots',operation:action.split('.')[1]};
 if(action==='gitops.record')return{type:'configuration_gitops_runs',operation:'create'};return null;}
function receiptMatches(h,journal,attempt,data){const old=attempt.receipt,job=data?.job,originalJob=old?.job;
 h.check(data?.domain==='configuration'&&data.durable===true&&data.registrationCompleted===true&&data.submissionCompleted===true&&data.executionCompleted===true&&data.state==='succeeded'&&job?.state==='succeeded'
  &&data.workflowId==null&&data.idempotencyKey===attempt.key&&data.actorId===attempt.actorId&&data.clusterId===attempt.clusterId&&data.workspaceId===attempt.workspaceId
  &&data.originalScope?.clusterId===attempt.clusterId&&data.originalScope.workspaceId===attempt.workspaceId&&data.kind===attempt.kind&&job.kind===attempt.kind&&uuid(data.jobId)
  &&data.id===data.jobId&&job.id===data.jobId&&data.jobId===attempt.jobId&&data.jobId===old?.jobId&&job.actorId===attempt.actorId&&job.clusterId===attempt.clusterId&&job.workspaceId===attempt.workspaceId
  &&data.executionMode==='direct'&&data.approvalRequired===false&&isDeepStrictEqual(job.safeProgress,originalJob?.safeProgress),'actual current configuration receipt proves the original namespace, key, immutable job, actor, scope and completed result');
 const r=resource(attempt);if(r){const e=attempt.responseData?.entity;h.check(uuid(data.resourceId)&&data.resourceId===old.resourceId&&e?.id===data.resourceId&&data.resourceType===r.type&&data.operation===r.operation
  &&job.safeProgress?.resourceId===data.resourceId&&job.safeProgress.resourceType===r.type&&job.safeProgress.operation===r.operation,'actual metadata receipt retains its exact original typed resource and operation');
  if(r.operation!=='create')h.check(positive(attempt.body?.revision)&&e.revision===attempt.body.revision+1,'original metadata ACK proves the exact positive CAS revision and one increment');}
 if(attempt.action==='snapshot.capture')h.check(uuid(data.snapshotId)&&data.snapshotId===old.snapshotId&&data.snapshotId===journal.bindings.captureId,'actual capture receipt retains the original snapshot identity');
 if(attempt.action==='review.export')h.check(uuid(data.exportId)&&data.exportId===old.exportId&&data.exportId===journal.bindings.export.exportId&&data.mode==='review'&&data.exportRevision===old.exportRevision&&positive(data.exportRevision),'actual review export retains original artifact mode and revision');
 if(attempt.binary)h.check(data.exportId===attempt.binary.exportId&&data.exportId===journal.bindings.export.exportId&&data.mode==='review'&&data.downloadPermitConsumed===true&&data.byteCount===attempt.binary.bytes,
  'actual consumed download receipt agrees with the original bounded received binary');
 if(attempt.action==='noop.import')h.check(data.deleteCount===0&&data.stepCount===0&&uuid(data.planId)&&data.planId===old.planId,'actual empty merge receipt proves zero native steps and its original plan');
 if(attempt.action==='plan.reconcile'){const p=job.safeProgress;h.check(p?.readOnly===true&&p.executionChanged===false&&p.reconciledPlanId===journal.seed.planId&&Array.isArray(p.observations)&&p.observations.length===journal.bindings.plan.stepCount&&p.observations.every(v=>v.causalOutcomeUnproven===true),'actual reconcile receipt proves only the original read-only observations');}
}
function strictOriginal(h){const s=h.state,j=s.manualUiJournal,history=s.manualUiHistory,packets=s.requests.filter(p=>p.source==='manual-ui'&&p.index>=history?.originalRequestCount);
 h.check(s.version===1&&s.milestone==='M8'&&s.inFlight==null&&s.requests.every((p,index)=>p.state==='response_observed'&&Number.isInteger(p.status)&&p.status>=100&&p.status<=599||isM8ProvenConsumedUnknownDownload(s,p,index)),
  'manual audit refuses unproven unresolved or fabricated write status; the separately proven historical file delivery stays unconfirmed');
 h.check(j?.version===1&&j.milestone==='M8'&&j.source==='manual-ui'&&j.testTag===s.testTag&&j.phase==='complete'&&j.inFlight===null&&j.nextIndex===12&&j.attempts?.length===12&&packets.length===12
  &&uuid(j.scope?.cid)&&uuid(j.scope.wid)&&j.scope.cid===s.scopes.direct.cid&&j.scope.wid===s.scopes.direct.wid&&history?.version===1&&Number.isSafeInteger(history.originalRequestCount)
  &&history.originalRequestCount>=0&&hash(s.requests.slice(0,history.originalRequestCount))===history.originalPrefixSha256&&isDeepStrictEqual(history.originalSessions,j.sessions)
  &&isDeepStrictEqual(history.originalHandoff?.approvedActions,M8_UI_ACTIONS)&&history.originalHandoff.testTag===j.testTag&&history.originalHandoff.direct?.cid===j.scope.cid&&history.originalHandoff.direct?.wid===j.scope.wid
  &&history.originalHandoff.directWorkspaceName===j.workspaceName&&j.seed.jobId===history.originalHandoff.jobId&&j.seed.planId===history.originalHandoff.planId&&j.seed.snapshotId===history.originalHandoff.snapshotId,
  'manual audit requires the complete original twelve-intent M8 journal and retained original HTTP prefix and handoff');
 const rows=[],keys=new Set(),requestIds=new Set();
 for(let i=0;i<12;i++){const a=j.attempts[i],matches=packets.filter(p=>p.manualIndex===i),p=matches[0],session=a.originalSession??j.sessions.admin,auth=j.authenticated.admin;
  h.check(matches.length===1&&a.index===i&&a.action===M8_UI_ACTIONS[i]&&a.role==='admin'&&a.state==='succeeded'&&p.index===(a.globalPacketIndex??history.originalRequestCount+i)&&p.index>=history.originalRequestCount&&s.requests[p.index]===p
   &&p.action===a.action&&p.state==='response_observed'&&isDeepStrictEqual(p.expected,[200,201,202]),'manual audit has one exact succeeded original action and one observed global packet at each index');
  const fields=['key','method','path','query','body','bodySha256','actorId','sessionId','clusterId','workspaceId','headers','startedAt','status','requestId','responseData','receiptRequestId','binary'];
  const restoredReceipt=s.manualRestoreReceiptContinuation;
  const separatelyConfirmedRestore=i===9&&p.index===193&&a.action==='snapshot.restore'&&p.status===201&&p.requestId==='7dfd52d6-19dd-4692-bd09-5fe2143bd347'
   &&p.key==='80df68e5-12e8-402b-acb1-507f5d9fafb8'&&hash(p)==='494e7f073f9e61674ff0cd21138250c75a1ec54ac542e200c928d3e798e8b3fb'
   &&restoredReceipt?.state==='original-restore-confirmed'&&restoredReceipt.originalWriteReplayed===false&&restoredReceipt.originalAckRequestId===p.requestId
   &&restoredReceipt.currentProtectedReceiptRequestId===a.receiptRequestId&&a.receiptRequestId==='3d481714-617e-4992-bbdd-0cda8e8d7bb1';
  h.check(fields.every(k=>isDeepStrictEqual(p[k],a[k])||k==='receiptRequestId'&&separatelyConfirmedRestore)&&a.actorId===session?.user?.id&&a.sessionId===session.sid&&auth?.id===a.actorId&&auth.sid===a.sessionId
   &&uuid(a.actorId)&&uuid(a.sessionId)&&uuid(a.key)&&uuid(a.requestId)&&uuid(a.receiptRequestId)&&uuid(a.jobId)&&!keys.has(a.key)&&!requestIds.has(a.requestId)&&!j.priorKeys.includes(a.key)
   &&s.requests.filter(v=>v.key===a.key).length===1&&s.requests.filter(v=>v.requestId===a.requestId).length===1,'manual audit binds the full global packet to its original journal actor SID, header set, unique key and server identities');
  keys.add(a.key);requestIds.add(a.requestId);let url,body;try{url=new URL(a.url);body=JSON.parse(a.rawBody);}catch{}
  const expected=expectedOriginal(j,a);h.check(url?.origin==='http://127.0.0.1:8080'&&!url.username&&!url.password&&!url.hash&&url.pathname===a.path&&url.search===a.query
   &&a.query===`?workspaceId=${j.scope.wid}`&&a.clusterId===j.scope.cid&&a.workspaceId===j.scope.wid&&a.method===expected?.method&&a.path===expected.path&&a.kind===expected.kind
   &&typeof a.rawBody==='string'&&sha256(a.rawBody)===a.bodySha256&&isDeepStrictEqual(body,a.body)&&isDeepStrictEqual(body,expected.body)&&(expected.binary===true)===(i===2),
   'manual audit retains the exact original URL, canonical query, raw-body hash and action-specific wire body');
  h.check([200,201,202].includes(a.status)&&Object.keys(a.headers??{}).every(k=>k===k.toLowerCase())&&a.headers['x-idempotency-key']===a.key&&/^application\/json(?:\s*;|$)/i.test(a.headers['content-type']??'')&&!Object.hasOwn(a.headers,'authorization'),
   'manual audit requires successful original ACK and complete original JSON headers');cookieProof(h,a.headers,session);
  const binary=i===2;h.check(binary?positive(a.binary?.bytes)&&a.binary.bytes<=33554432&&/^[a-f\d]{64}$/.test(a.binary.sha256)&&a.binary.noStore===true&&a.binary.nosniff===true&&a.binary.yaml===true&&a.binary.exportId===j.bindings.export.exportId:a.binary===false,'manual audit preserves the one exact bounded download binary mapping');
  const replay=structuredClone(j);replay.phase='ready';replay.inFlight=i;replay.nextIndex=i;replay.attempts[i].state='acknowledged';
  let confirmed=false;try{confirmed=confirmM8UiReceipt(replay,'admin',{method:'GET',url:`http://127.0.0.1:8080${m8UiReceiptPath(replay,replay.attempts[i])}`},a.receipt,a.receiptRequestId,()=>{});}catch{}
  h.check(confirmed===true,'retained original receipt satisfies the actual manual-journal validator without mutating it');receiptMatches(h,j,a,a.receipt);
  rows.push({attempt:a,packet:p,tupleSha256:hash(packetTuple(p,a))});
 }return{journal:j,rows};
}
function immutable(h,proof){h.check(hash(h.state.manualUiJournal)===proof.journalSha256&&h.state.requests.length===proof.originalRequestCount&&hash(h.state.requests)===proof.originalRequestsSha256
 &&hash(h.state.manualUiHistory)===proof.originalHistorySha256&&hash(h.state.privateHistoryRefs??[])===proof.originalHistoryRefsSha256,'manual audit reads never change any original journal, wire packet, history or secret reference');}
function stop(h,proof){if(proof){proof.state='stopped-original-retained';if(proof.inFlight)proof.inFlight.state='response_unknown';h.save({phase:'stopped-manual-ui-audit-original-retained'});}const e=Error('M8_MANUAL_AUDIT_ORIGINAL_STOP_NO_REPLAY');e.safeEvidenceMessage=true;return e;}
async function read(h,proof,actor,path){immutable(h,proof);h.check(proof.inFlight===null,'unknown manual audit read cannot be replayed');proof.inFlight={method:'GET',path,actorId:actor.user.id,sessionId:actor.sid,state:'prepared'};h.save();
 const identity={id:actor.user.id,sid:actor.sid,cookie:actor.cookie,csrf:actor.csrf};const result=await h.request(actor,path,'GET',undefined,{expected:[200],renew:false});h.check(result.status===200&&uuid(result.requestId)
 &&actor.user.id===identity.id&&actor.sid===identity.sid&&actor.cookie===identity.cookie&&actor.csrf===identity.csrf,'manual audit proof is an actual successful new protected GET with an unchanged original session and server request ID');immutable(h,proof);
 h.check(!proof.readRequestIds.includes(result.requestId)&&!(proof.forbiddenReadRequestIds??[]).includes(result.requestId)&&!h.state.requests.some(p=>p.requestId===result.requestId||p.receiptRequestId===result.requestId),'manual audit cannot substitute any old client acknowledgement or protected read identity');
 proof.readRequestIds.push(result.requestId);proof.inFlight=null;h.save();return{data:h.data(result),requestId:result.requestId,status:result.status};}
function viewMatches(h,v,attempt){h.check(uuid(v?.id)&&v.requestId===attempt.requestId&&v.actorId===attempt.actorId&&v.clusterId===attempt.clusterId&&v.workspaceId===attempt.workspaceId&&v.scopeQuality==='verified'&&v.result==='success'
 &&!['sequence','eventHash','event_hash','prevHash','prev_hash','history_scope_hmac','sourceScopeHmac'].some(k=>Object.hasOwn(v,k))&&m8AuditPatchMatches(v),'actual original-workspace audit has the exact actor/request/scope, safe DTO and independently valid full RFC6902 patch');}
/** Independently verify the keyed redaction of one public recovery count.
 * All other metadata stays exact; arbitrary masking is never accepted. */
export function m8SnapshotAuditAckMatches(after,ack){
 if(isDeepStrictEqual(after,ack))return true;
 const count=ack?.recovery?.requires_secret_input,masked=after?.recovery?.requires_secret_input;
 if(!Number.isSafeInteger(count)||count<0||count>10000||!/^\[REDACTED:[a-f\d]{16}\]$/.test(masked??''))return false;
 const raw=process.env.CONSOLE_ENCRYPTION_KEY;if(!raw)return false;
 const key=Buffer.from(raw,/^[a-f\d]{64}$/i.test(raw)?'hex':'base64');if(key.length!==32)return false;
 const hide=value=>`[REDACTED:${createHmac('sha256',key).update('kongos-fingerprint:v1:').update(JSON.stringify(value)).digest('hex').slice(0,16)}]`;
 const stored=hide(count),projected=hide(stored);key.fill(0);
 if(masked!==stored&&masked!==projected)return false;const normalized=structuredClone(ack);normalized.recovery.requires_secret_input=masked;return isDeepStrictEqual(after,normalized);
}
function terminal(h,views,attempt){const terminalAction=attempt.action==='snapshot.capture'?'configuration.capture':'configuration.job.complete';const job=views.filter(v=>v.entityType==='configuration_jobs'&&v.entityId===attempt.jobId&&v.action===terminalAction&&v.after?.state==='succeeded'
 &&v.after.id===attempt.jobId&&v.after.kind===attempt.kind&&v.after.clusterId===attempt.clusterId&&v.after.workspaceId===attempt.workspaceId&&isDeepStrictEqual(v.after.safeProgress,attempt.receipt.job.safeProgress));
 h.check(job.length===1,'actual original job has one successful terminal completion audit');const r=resource(attempt);
 if(r)h.check(views.filter(v=>v.entityType===r.type&&v.entityId===attempt.receipt.resourceId&&v.after?.id===attempt.receipt.resourceId&&v.action===`configuration.${r.operation}`&&(r.type==='config_snapshots'?m8SnapshotAuditAckMatches(v.after,attempt.responseData.entity):isDeepStrictEqual(v.after,attempt.responseData.entity))).length===1,'actual original metadata resource has its exact typed operation and independently verified complete ACK redaction');
 if(attempt.action==='snapshot.capture')h.check(views.filter(v=>v.entityType==='config_snapshots'&&v.entityId===attempt.receipt.snapshotId&&v.action==='snapshot.capture').length===1,'actual UI capture has its original snapshot audit');
 if(attempt.binary)h.check(views.filter(v=>v.entityType==='configuration_exports'&&v.entityId===attempt.binary.exportId&&v.action==='configuration.download.consume'&&v.after?.state==='consumed'&&v.after.byteCount===attempt.binary.bytes).length===1,'actual one-use download has a consumed permit audit matching its received bytes');}

/** Active original actor, GET-only, before any cleanup. No constructor/env/IO. */
export async function m8ManualUiAuditAcceptance(h,actors,{resumeKnownEight=false}={}){const cleanup=h.state.cleanupJournal;h.check(!h.state.cleanupStarted&&!h.state.cleanup?.businessCompleted&&(!h.state.manualUiAuditProof||resumeKnownEight)
 &&(!cleanup||cleanup.version===1&&cleanup.testTag===h.state.testTag&&['starting','prepared'].includes(cleanup.phase)&&cleanup.inFlight===null
  &&[cleanup.metadata,cleanup.archives,cleanup.identity].every(v=>Array.isArray(v)&&v.length===0)&&cleanup.operations.every(v=>v.method==='GET')),
 'manual UI audit is built exactly once before any business cleanup, including its original read-only preparation hook');const {journal,rows}=strictOriginal(h);
 const actor=actors.admin;sessionMatches(h,actor,journal.currentSessions?.admin??journal.sessions.admin);sessionMatches(h,h.state.sessions.admin,journal.currentSessions?.admin??journal.sessions.admin);
 let proof=h.state.manualUiAuditProof;
 if(resumeKnownEight){const original=hash(proof)==='84474b25fd2cd72f5be3845df56b17a063ec6d251cd3b5dff55bcfdbf898f685'&&proof.readRequestIds?.length===18&&proof.originalRequestCount===199&&proof.originalRequestsSha256==='da63a9a2076c38e84bfbec7d4b2703e4684d46cebbb80381702e56925303a666';
  const maintained=hash(proof)==='accb6f13ab64c6a7c9da8358ef707bd005a287014790af635011a0d66242c1ca'&&proof.readRequestIds?.length===20&&proof.originalRequestCount===200&&h.state.manualAuditSessionMaintenance?.state==='completed'&&h.state.manualAuditSessionMaintenance.completedRecordsSha256==='671faeed0fada8ba0c42bcbed746fc4c788177021ebcef090662b573488ab76e';
  h.check(proof?.state==='stopped-original-retained'&&proof.inFlight===null&&proof.records?.length===8&&(original||maintained)&&hash(proof.records)==='671faeed0fada8ba0c42bcbed746fc4c788177021ebcef090662b573488ab76e','only the exact eight completed reads and recorded normal same-SID maintenance may resume GET-only');immutable(h,proof);proof.state='building';proof.knownValidationResume={originalCompletedRecords:8,originalReadIds:proof.readRequestIds.length,originalWritesReplayed:0};}
 else{proof={version:1,milestone:'M8',testTag:h.state.testTag,state:'building',journalSha256:hash(journal),originalRequestCount:h.state.requests.length,originalRequestsSha256:hash(h.state.requests),
  originalHistorySha256:hash(h.state.manualUiHistory),originalHistoryRefCount:(h.state.privateHistoryRefs??[]).length,originalHistoryRefsSha256:hash(h.state.privateHistoryRefs??[]),inFlight:null,readRequestIds:[],records:[]};h.state.manualUiAuditProof=proof;}h.save();
 try{for(const {attempt,tupleSha256}of rows.slice(proof.records.length)){sessionMatches(h,actor,journal.currentSessions?.admin??journal.sessions.admin);const path=m8UiReceiptPath(journal,attempt).replace(/^\/api\/v1/,'');const served=await read(h,proof,actor,path);receiptMatches(h,journal,attempt,served.data);
  const auditReads=[],views=[],seen=new Set(),ids=new Set();let cursor=null;for(let i=0;i<12;i++){const query=new URLSearchParams({workspaceId:attempt.workspaceId,requestId:attempt.requestId,result:'success',size:'100',...(cursor?{cursor}:{})});
   const page=await read(h,proof,actor,`/clusters/${attempt.clusterId}/audit?${query}`);const dto=page.data;h.check(Array.isArray(dto?.items)&&dto.items.length<=100&&dto.size===100&&dto.total===null&&typeof dto.scanLimitReached==='boolean','manual audit reads actual bounded size-100 workspace pages');auditReads.push(page.requestId);
   for(const view of dto.items){viewMatches(h,view,attempt);h.check(!ids.has(view.id),'manual audit EOF has no duplicate immutable event');ids.add(view.id);views.push(view);}
   cursor=dto.nextCursor;h.check(cursor===null||typeof cursor==='string'&&cursor.length>0&&cursor.length<=24576&&!seen.has(cursor)&&i<11,'manual audit cursor reaches explicit bounded EOF without cycling');if(cursor===null)break;seen.add(cursor);
  }h.check(views.length>0,'original UI write has actual server audit rows');terminal(h,views,attempt);
  proof.records.push({manualIndex:attempt.index,action:attempt.action,tupleSha256,confirmed:true,receiptRead:{method:'GET',path,actorId:actor.user.id,sessionId:actor.sid,requestId:served.requestId,status:served.status,jobId:served.data.jobId,contentSha256:safeHash(served.data)},
   auditReadRequestIds:auditReads,terminalEOF:true,views:views.map(v=>({auditId:v.id,requestId:v.requestId,actorId:v.actorId,clusterId:v.clusterId,workspaceId:v.workspaceId,action:v.action,entityType:v.entityType,entityId:v.entityId,contentSha256:safeHash(v)}))});h.save();
 }immutable(h,proof);proof.state='complete';proof.recordsSha256=hash(proof.records);h.save();const result={confirmedWrites:12,auditEventIds:proof.records.flatMap(r=>r.views.map(v=>v.auditId)),allOriginalReceiptsRead:true,allOriginalAuditsRead:true,zeroBusinessWrites:true};h.public??={};h.public.manualUiAuditProof=result;return result;
 }catch{throw stop(h,proof);}}

/** After business cleanup, only the same immutable audit IDs are re-read. */
export async function finalizeM8ManualUiAuditAcceptance(h,bootstrap){const proof=h.state.manualUiAuditProof;h.check(proof?.version===1&&proof.milestone==='M8'&&proof.testTag===h.state.testTag&&proof.state==='complete'&&!proof.finalization
 &&h.state.cleanup?.businessCompleted===true&&h.state.cleanup?.identitySoftDeleted===true,'manual audit closure follows known business cleanup and complete active-actor proof exactly once');
 h.check(bootstrap?.label==='bootstrap-provisioner'&&uuid(bootstrap.user?.id)&&uuid(bootstrap.sid)&&h.state.sessions['bootstrap-provisioner']?.user.id===bootstrap.user.id&&h.state.sessions['bootstrap-provisioner'].sid===bootstrap.sid,'immutable audit closure uses only the existing actual bootstrap actor SID');
 cookieProof(h,{'cookie':bootstrap.cookie,'x-csrf-token':bootstrap.csrf},bootstrap);
 const original=strictOriginal(h);h.check(hash(original.journal)===proof.journalSha256&&proof.records.length===12&&hash(proof.records)===proof.recordsSha256
 &&h.state.requests.length>=proof.originalRequestCount&&hash(h.state.requests.slice(0,proof.originalRequestCount))===proof.originalRequestsSha256
 &&hash(h.state.manualUiHistory)===proof.originalHistorySha256&&(h.state.privateHistoryRefs??[]).length>=proof.originalHistoryRefCount
 &&hash((h.state.privateHistoryRefs??[]).slice(0,proof.originalHistoryRefCount))===proof.originalHistoryRefsSha256,'manual audit closure retains every original UI action and active-proof original packet/history prefixes');
 const receiptRows=proof.records;for(const {attempt,tupleSha256}of original.rows){const matched=receiptRows.filter(v=>v.manualIndex===attempt.index),r=matched[0];h.check(matched.length===1&&r.confirmed===true&&r.tupleSha256===tupleSha256&&r.action===attempt.action&&r.terminalEOF===true&&uuid(r.receiptRead?.requestId)&&r.receiptRead.actorId===attempt.actorId&&r.receiptRead.sessionId===attempt.sessionId&&r.receiptRead.jobId===attempt.jobId&&r.views?.length>0,'bootstrap closure binds every prior actual read to the exact original tuple');}
 // Cleanup appends legitimate packets. Freeze that current prefix for final
 // read-only closure, preserving the pre-cleanup originals above as evidence.
 const closure={state:'building',originalRequestCount:h.state.requests.length,originalRequestsSha256:hash(h.state.requests),journalSha256:proof.journalSha256,originalHistorySha256:proof.originalHistorySha256,
  originalHistoryRefsSha256:hash(h.state.privateHistoryRefs??[]),inFlight:null,readRequestIds:[],forbiddenReadRequestIds:[...proof.readRequestIds],records:[]};proof.finalization=closure;h.save();
 try{for(const row of receiptRows)for(const view of row.views){const path=`/clusters/${view.clusterId}/audit/${view.auditId}?workspaceId=${view.workspaceId}`,served=await read(h,closure,bootstrap,path);
  const attempt=original.rows[row.manualIndex].attempt;viewMatches(h,served.data,attempt);h.check(served.data.id===view.auditId&&safeHash(served.data)===view.contentSha256,'bootstrap re-read proves the same complete immutable safe audit content after cleanup');
  closure.records.push({auditId:view.auditId,requestId:served.requestId,contentSha256:safeHash(served.data),actorId:bootstrap.user.id,sessionId:bootstrap.sid});h.save();
 }closure.state='complete';h.save();const result={confirmedWrites:12,immutableAuditsReRead:closure.records.length,auditEventIds:closure.records.map(r=>r.auditId),afterCleanup:true,allImmutableViewsUnchanged:true,originalActorByKeyReadsAfterCleanup:0,zeroBusinessWrites:true};h.public??={};h.public.manualUiAuditClosure=result;return result;
 }catch{closure.state='stopped-original-retained';throw stop(h,closure);}}
