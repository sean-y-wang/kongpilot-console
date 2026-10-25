// @ts-nocheck -- actual helper predicates and real receipt/session methods; RAM only.
import {describe,expect,it,vi} from 'vitest';
import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {runInNewContext} from 'node:vm';
import {parse,stringify} from 'yaml';
import {M8Harness,entity,scope,sha256} from './lib/m8-harness.mjs';
import {configurationRead,configurationWrite,assertConfigurationReceipt} from './lib/m8-configuration-acceptance.mjs';
import {assertM8DeckSession} from './lib/m8-deck-acceptance.mjs';

const source=readFileSync(new URL('./lib/m8-deck-wire-body-continuation.mjs',import.meta.url),'utf8')
 .replace(/^import[^\n]*\n/gm,'').replace(/\bexport\s+(?=(?:async\s+)?function|const)/g,'');
const check=(value,label)=>{if(!value)throw Error(label);};
/** Pinned historical/file hashes are simulated only for exact synthetic bytes;
 * no historical packet, artifact proof, environment or runtime is opened.
 * Mutated bytes use real SHA256. All production predicates remain untouched. */
function fixture(options={}){
 let c;const hashMap=new Map(),events=[],saved=[],cliCalls=[],fileRead=vi.fn(()=>{if(options.changedRelease)return Buffer.from(JSON.stringify({sourceOnly:true,validation:{apiTypecheckExitCode:0,apiBuildExitCode:0}}));throw Error('NO_ACTUAL_FILE_READ');});
 const newSourceId=randomUUID(),newLocalId=randomUUID(),newImportId=randomUUID(),newJobId=randomUUID(),newExecutionId=randomUUID(),newStepId=randomUUID(),newPlanStepId=randomUUID(),sessionId=randomUUID();
 let actor,area,importKey,applyKey,closed=false,synced=false;
 const service={id:'9e5adb4a-0964-4e77-a01b-a6a4347138d7',retries:0,name:'Synthetic Service',host:'source.example.invalid',port:443,protocol:'https',connect_timeout:60000,read_timeout:60000,write_timeout:60000};
 const nativeRead=vi.fn(async(_h,who,where,type,id)=>{expect(who).toEqual(actor);expect(where).toEqual(area);expect(type).toBe('services');expect(id).toBe(c.serviceId);events.push({type:'native'});return{...service,retries:synced?3:0,...(synced?options.nativeAfter:{})};});
 const sixCredentialProxyAcceptance=vi.fn(async()=>{check(synced,'SYNTHETIC_PROXY_BEFORE_SYNC');events.push({type:'six-auth'});});
 const runM8FixedDeckPrivateStderr=vi.fn(async(h,who,where,input,{jobId})=>{
  h.assertWritable();expect(who).toEqual(actor);expect(where).toEqual(area);expect(jobId).toBe(newJobId);expect(input.command).toBe('sync');
  const intent={state:'prepared',command:input.command};h.state.cliIntents.push(intent);cliCalls.push(structuredClone(input));h.save();
  if(options.syncUnknown){intent.state='response_unknown';h.save({phase:'stopped-cli-unknown'});throw Error('M8_ORIGINAL_CLI_UNKNOWN_NO_REPLAY');}
  intent.state='response_observed';synced=true;h.save();return{exitCode:0};
 });
 // Replace only the evidence dependency constants for this synthetic missing
 // or changed-proof case. The actual release predicate is never rewritten.
 const fixtureSource=options.missingRelease?source.replace(/sourceFreezeSha256:(?:null|'[a-f\d]{64}')/,'sourceFreezeSha256:null').replace(/continuitySha256:(?:null|'[a-f\d]{64}')/,'continuitySha256:null'):options.changedRelease?source.replace(/sourceFreezeSha256:(?:null|'[a-f\d]{64}')/,`sourceFreezeSha256:'${'f'.repeat(64)}'`):source;
 const actual=runInNewContext(`${fixtureSource}\n({M8_DECK_WIRE_BODY_CONTINUATION,assertM8DeckWireBodyCheckpoint,assertM8DeckWireBodyRelease,assertM8PendingPreparedDeckStep,assertM8PreparedDeckAbandonIntent,assertM8ClosedPreparedDeckJob,closeM8OriginalPreparedDeck,isM8ProvenPreparedDeckClosurePacket,assertM8FreshRetry3Plan,m8DeckFreshRetry3Acceptance})`,{
  randomUUID,readFileSync:fileRead,parse,stringify,entity,scope,sha256:v=>hashMap.get(typeof v==='string'?v:Buffer.from(v).toString())??sha256(v),configurationRead,configurationWrite,assertConfigurationReceipt,assertM8DeckSession,
  assertM8DeckPoolRelease:vi.fn(),runM8FixedDeckPrivateStderr,nativeRead,sixCredentialProxyAcceptance,structuredClone,Buffer,Date,Object,JSON,Error,
 });c=actual.M8_DECK_WIRE_BODY_CONTINUATION;actor={user:{id:c.actorId},sid:c.sid};area={cid:c.cid,wid:c.wid};
 const oldBody={revision:1,driver:'deck',planRevision:1,planHash:c.planHash,confirmed:true,confirm_name:'Synthetic original source plan'};
 const pending={id:c.jobStepId,executionId:c.executionId,planStepId:c.planStepId,revision:1,stepOrder:1,state:'pending',objectWorkspaceId:c.wid,type:'services',action:'update',originalId:c.serviceId,operationId:null,verified:false,startedAt:null,completedAt:null};
 const intent={jobId:c.jobId,revision:2,executionId:c.executionId,executionRevision:1,workflowExecutionId:null,planRevision:1,planHash:c.planHash,leaseGeneration:1,confirmationName:`abandon:${c.jobId}`};
 const receipt=(kind,key,id,extra={})=>({domain:'configuration',durable:true,id,jobId:id,idempotencyKey:key,actorId:actor.user.id,clusterId:area.cid,workspaceId:area.wid,originalScope:{clusterId:area.cid,workspaceId:area.wid},kind,state:'succeeded',...extra});
 const oldJob=receipt('apply',c.key,c.jobId,{revision:2,state:'running',executionCompleted:false,workflowId:null,executionMode:'direct',approvalRequired:false,planId:c.executionPlanId,planRevision:1,planHash:c.planHash,capabilities:{abandon:true},abandonmentIntent:intent});
 let abandonRequestId;
 const closedJob=()=>receipt('apply',c.key,c.jobId,{revision:3,state:'uncertain',workflowId:null,planId:c.executionPlanId,planRevision:1,planHash:c.planHash,executionId:c.executionId,executionRevision:2,workflowExecutionId:null,leaseGeneration:1,completedSteps:0,unresolvedSteps:1,abandoned:true,terminalFailureRecorded:true,executionCompleted:true,abandonmentSessionMatches:true,abandonRequestId,...options.closedJob});
 const imported=key=>receipt('import',key,newImportId,{planId:newSourceId,planRevision:1,planHash:'a'.repeat(64),counts:{create:0,update:1,delete:0,conflict:0}});
 const plan=id=>({id,planHash:'a'.repeat(64),planRevision:1,revision:1,name:'Synthetic retries3 plan',clusterId:area.cid,workspaceId:area.wid,executionMode:'direct',stepCount:1,nativePacketCount:1,deleteCount:0,capabilities:{apply:true}});
 const changes=id=>({entity:plan(id),items:[{stepId:newPlanStepId,entityType:'services',nativeId:c.serviceId,objectWorkspaceId:area.wid,action:'update',referenceOnly:false,blockerCodes:[],patch:[{op:'replace',path:'/retries',value:3}]}],nextCursor:null});
 const newStep=(state='pending')=>({id:newStepId,executionId:newExecutionId,planStepId:newPlanStepId,state,objectWorkspaceId:area.wid,originalId:c.serviceId,type:'services',action:'update',operationId:state==='pending'?null:randomUUID(),verified:state==='succeeded'});
 const r={version:1,milestone:'M8',phase:'stopped-failure',inFlight:null,requests:Array.from({length:145},()=>({state:'response_observed',status:200})),proxyChecks:[],cliIntents:Array.from({length:4},()=>({state:'response_observed',command:'diff'})),deckSessions:Array.from({length:3},()=>({id:randomUUID(),purpose:'read',revoked:true})),configurationOperations:[],fixtures:[],sessions:{admin:actor},scopes:{direct:area},c2ModeRestored:true,approvalTransfer:{nativeSteps:17},deckRecordMergeContinuation:{state:'unused-direct-deck-apply'},deckPoolContinuation:{selectedCaptureJobId:randomUUID()},baseline:{yaml:stringify({_format_version:'1.1',services:[service],upstreams:[],consumers:[{id:randomUUID(),basicauth_credentials:[{id:randomUUID(),username:'synthetic',password:'ONLY_SOURCE_SYNTHETIC_PASSWORD'}]}]})},nativeFixture:{service}};
 r.requests[144]={index:144,state:'response_observed',status:201,key:c.key,requestId:c.requestId,method:'POST',path:`/api/v1/clusters/${c.cid}/configuration/plans/${c.sourcePlanId}/apply`,query:`?workspaceId=${c.wid}`,actorId:c.actorId,sessionId:c.sid,clusterId:c.cid,workspaceId:c.wid,body:oldBody,bodySha256:c.bodySha256,responseData:{jobId:c.jobId,planId:c.executionPlanId,planHash:c.planHash,planRevision:1,state:'running',executionCompleted:false}};
 r.runningDeckApplyReadonlyDiagnosis={state:'completed',original145PrefixSha256:c.prefix,originalFailedReportSha256:c.failureSha256,originalApplyKey:c.key,actorId:c.actorId,sessionId:c.sid,clusterId:c.cid,workspaceId:c.wid,jobId:c.jobId,executionPlanId:c.executionPlanId,planHash:c.planHash,planRevision:1,executionId:c.executionId,jobStepId:c.jobStepId,planStepId:c.planStepId,reads:Array.from({length:3},(_,index)=>({method:'GET',state:'response_observed',status:200,actorId:c.actorId,sessionId:c.sid,privateData:index===1?{items:[pending],nextCursor:null}:{}}))};
 const prefixJSON=JSON.stringify(r.requests),prefix142JSON=JSON.stringify(r.requests.slice(0,142));hashMap.set(prefixJSON,c.prefix);hashMap.set(prefix142JSON,c.prefix142);hashMap.set(JSON.stringify(oldBody),c.bodySha256);
 const failedBytes=Buffer.from(JSON.stringify({allPassed:false,passed:1842,failed:1,successfulWrites:133,unknownWrites:0})),diagnosisBytes=Buffer.from(JSON.stringify({allPassed:true,original145PrefixUnchanged:true,newAuthWrites:0,newBusinessWrites:0,newNativeWrites:0,newCliIntents:0})),sdkBytes=Buffer.from('SYNTHETIC_FIXED_SDK_WIRE_PROOF');
 for(const[bytes,digest]of[[failedBytes,c.failureSha256],[diagnosisBytes,c.diagnosisSha256],[sdkBytes,c.sdkProofSha256]])hashMap.set(bytes.toString(),digest);
 const h={state:r,check,data:(result,label)=>M8Harness.prototype.data.call(h,result,label),assertWritable:()=>M8Harness.prototype.assertWritable.call(h),
  save(extra={}){Object.assign(r,extra);saved.push(structuredClone(r));events.push({type:'save'});},async poll(read,predicate){const v=await read();check(predicate(v),'SYNTHETIC_NONTERMINAL');return v;}};
 h.request=vi.fn(async(who,path,method='GET',body,opts={})=>{
  if(method!=='GET')h.assertWritable();expect(who).toEqual(actor);const url=new URL(path,'http://synthetic.invalid'),base=`/clusters/${c.cid}/`;
  expect(url.searchParams.get('workspaceId')).toBe(c.wid);events.push({type:'request',method,path,body:structuredClone(body),key:opts.key,before:structuredClone(saved.at(-1))});let data;const requestId=randomUUID();
  if(method==='GET'&&url.pathname===`${base}configuration/jobs/by-key/${c.key}`)data=closed?closedJob():{...oldJob,...options.oldJob};
  else if(method==='GET'&&url.pathname===`${base}configuration/jobs/${c.jobId}/steps`)data={items:[closed?{...pending,state:'uncertain',revision:2,completedAt:new Date().toISOString()}:pending],nextCursor:null};
  else if(method==='POST'&&url.pathname===`${base}configuration/jobs/${c.jobId}/abandon`){abandonRequestId=requestId;closed=true;data={jobId:c.jobId,executionId:c.executionId,clusterId:c.cid,workspaceId:c.wid,state:'uncertain',completedSteps:0,unresolvedSteps:1,abandoned:true,terminalFailureRecorded:true,originalWorkflowUnchanged:true,originalNativeReceiptsUnchanged:true};}
  else if(method==='POST'&&url.pathname===`${base}configuration/imports`){importKey=opts.key;expect(parse(body.yaml).services[0].retries).toBe(3);expect(parse(body.yaml).consumers[0].basicauth_credentials[0].password).toBeUndefined();data=imported(importKey);}
  else if(method==='GET'&&url.pathname===`${base}configuration/jobs/by-key/${importKey}`)data=imported(importKey);
  else if(method==='GET'&&url.pathname===`${base}configuration/plans/${newSourceId}/changes`)data=options.change?options.change(changes(newSourceId)):changes(newSourceId);
  else if(method==='GET'&&url.pathname===`${base}configuration/plans/${newSourceId}`)data={entity:plan(newSourceId)};
  else if(method==='POST'&&url.pathname===`${base}configuration/plans/${newSourceId}/apply`){applyKey=opts.key;data=receipt('apply',applyKey,newJobId,{state:'running',executionCompleted:false,driver:'deck',executionId:newExecutionId,planId:newLocalId,planHash:'a'.repeat(64),planRevision:1,...options.running});}
  else if(method==='GET'&&url.pathname===`${base}configuration/plans/${newLocalId}/changes`)data=changes(newLocalId);
  else if(method==='GET'&&url.pathname===`${base}configuration/jobs/${newJobId}/steps`)data={items:[{...newStep(synced?'succeeded':'pending'),...(!synced?options.pending:{})}],nextCursor:null};
  else if(method==='POST'&&url.pathname===`${base}configuration/deck-sessions`){expect(body).toEqual({jobId:newJobId,purpose:'write',planId:newLocalId,planRevision:1,planHash:'a'.repeat(64)});data={id:sessionId,revision:1,purpose:'write',basePath:`/api/v1/deck/${sessionId}`,authorizationScheme:'KongOS-Deck',tokenSecret:'S'.repeat(43),expiresAt:new Date(Date.now()+180000).toISOString(),...options.session};}
  else if(method==='GET'&&url.pathname===`${base}configuration/jobs/by-key/${applyKey}`){check(synced,'SYNTHETIC_NO_TERMINAL_POLL_BEFORE_SYNC');data=receipt('apply',applyKey,newJobId,{executionCompleted:true,driver:'deck',executionId:newExecutionId,completedSteps:1,planId:newLocalId,planRevision:1,planHash:'a'.repeat(64),...options.terminal});}
  else if(method==='DELETE'&&url.pathname===`${base}configuration/deck-sessions/${sessionId}`)data={revoked:true};
  else throw Error('SYNTHETIC_UNEXPECTED_ROUTE');
  const packet={index:r.requests.length,state:'response_observed',status:method==='POST'?201:200,method,path:`/api/v1${url.pathname}`,query:url.search,key:opts.key,requestId,actorId:who.user.id,sessionId:who.sid,clusterId:c.cid,workspaceId:c.wid,body:structuredClone(body),bodySha256:body===undefined?null:sha256(JSON.stringify(body)),headers:{Cookie:'kongos_access=ONLY_SYNTHETIC_COOKIE','X-CSRF-Token':'ONLY_SYNTHETIC_CSRF','X-Idempotency-Key':opts.key},responseData:data};r.requests.push(packet);return{status:packet.status,payload:{data},requestId};
 });
 const prepare=()=>{r.phase='synthetic-ready';r.deckWireBodyContinuation={state:'prepared',originalPacketCount:145,originalPrefixSha256:c.prefix};};
 return{actual,c,r,h,actor,area,events,saved,cliCalls,fileRead,nativeRead,sixCredentialProxyAcceptance,runM8FixedDeckPrivateStderr,pending,intent,oldJob,closedJob,changes,imported,newSourceId,newLocalId,newJobId,newExecutionId,prefixJSON,failedBytes,diagnosisBytes,sdkBytes,prepare,
  close:()=>actual.closeM8OriginalPreparedDeck(h,{admin:actor,direct:area}),fresh:()=>actual.m8DeckFreshRetry3Acceptance(h,{admin:actor,direct:area})};
}

describe('independent sealed wire-body continuation SOURCE contracts',()=>{
 it('locks the exact synthetic 145 prefix/proofs and rejects changed prefix, extra packets, issued session, sync or existing Native op',()=>{
  const f=fixture();const validate=r=>f.actual.assertM8DeckWireBodyCheckpoint(r,f.failedBytes,f.diagnosisBytes,f.sdkBytes);expect(validate(f.r).packet.key).toBe(f.c.key);
  for(const mutate of[r=>r.requests[0].status=201,r=>r.requests.push({state:'response_observed',status:200}),r=>r.deckSessions[0].purpose='write',r=>r.cliIntents[0].command='sync',r=>r.runningDeckApplyReadonlyDiagnosis.reads[1].privateData.items[0].operationId=randomUUID()]){const r=structuredClone(f.r);mutate(r);expect(()=>validate(r)).toThrow();}
  expect(()=>f.actual.assertM8DeckWireBodyCheckpoint(f.r,f.failedBytes,Buffer.from('changed'),f.sdkBytes)).toThrow();
 });
 it('fails release closed with synthetic missing or changed SHA proof before any permission or transport',()=>{
  const f=fixture({missingRelease:true});expect(f.c.sourceFreezeSha256).toBeNull();expect(f.c.continuitySha256).toBeNull();expect(()=>f.actual.assertM8DeckWireBodyRelease(f.h)).toThrow('must be frozen');expect(f.fileRead).not.toHaveBeenCalled();expect(f.h.request).not.toHaveBeenCalled();
  const changed=fixture({changedRelease:true});expect(()=>changed.actual.assertM8DeckWireBodyRelease(changed.h)).toThrow('exact immutable SHA-bound facts');expect(changed.fileRead).toHaveBeenCalledTimes(1);expect(changed.h.request).not.toHaveBeenCalled();expect(changed.cliCalls).toHaveLength(0);
 });
 it('closes only the current original sameSID server intent and records uncertain zero-Native closure exactly once',async()=>{
  const f=fixture();f.prepare();await f.close();const writes=f.events.filter(e=>e.type==='request'&&e.method!=='GET');expect(writes).toHaveLength(1);expect(writes[0].path).toContain(`/configuration/jobs/${f.c.jobId}/abandon`);
  expect(writes[0].before.deckWireBodyContinuation.abandonAttempt).toMatchObject({state:'prepared',actorId:f.c.actorId,sessionId:f.c.sid,bodySha256:sha256(JSON.stringify(writes[0].body))});
  expect(f.r.deckWireBodyContinuation.originalClosure).toMatchObject({state:'uncertain',completedSteps:0,unresolvedSteps:1,preparedNotIssued:true,nativeSuccessClaimed:false});expect(f.cliCalls).toHaveLength(0);
  const a=f.r.deckWireBodyContinuation.abandonAttempt,p=f.r.requests[a.index];expect(f.actual.isM8ProvenPreparedDeckClosurePacket(f.r,p,a.index)).toBe(true);
  const calls=f.h.request.mock.calls.length;await expect(f.close()).rejects.toThrow('close is unused');expect(f.h.request).toHaveBeenCalledTimes(calls);
 });
 it('does not classify generic HTTP201 uncertain JSON or changed SID/intent/evidence as proved closure',async()=>{
  const f=fixture();f.prepare();await f.close();const a=f.r.deckWireBodyContinuation.abandonAttempt;
  for(const mutate of[r=>delete r.deckWireBodyContinuation.abandonAttempt,r=>r.requests[a.index].sessionId=randomUUID(),r=>r.requests[a.index].body.executionRevision++,r=>r.requests[a.index].responseData.originalNativeReceiptsUnchanged=false,r=>r.deckWireBodyContinuation.abandonAttempt.originalJob.completedSteps=1,r=>r.requests[a.index].headers.Cookie='other=SYNTHETIC']){const r=structuredClone(f.r);mutate(r);expect(f.actual.isM8ProvenPreparedDeckClosurePacket(r,r.requests[a.index],a.index)).toBe(false);}
 });
 it('rejects foreign current SID or lease/plan intent before sending abandonment',async()=>{
  const f=fixture();f.prepare();expect(()=>f.actual.assertM8PreparedDeckAbandonIntent(f.oldJob,{...f.actor,sid:randomUUID()},f.area)).toThrow('CURRENT_ORIGINAL');
  const bad={...f.oldJob,abandonmentIntent:{...f.intent,planHash:'b'.repeat(64)}};expect(()=>f.actual.assertM8PreparedDeckAbandonIntent(bad,f.actor,f.area)).toThrow('CURRENT_ORIGINAL');expect(f.h.request).not.toHaveBeenCalled();
 });
 it('runs only a fresh retries3 one-step preview/apply and uses the returned cloned execution plan for session/sync',async()=>{
  const f=fixture();f.prepare();await f.close();await f.fresh();expect(JSON.stringify(f.r.requests.slice(0,145))).toBe(f.prefixJSON);
  const writes=f.events.filter(e=>e.type==='request'&&e.method!=='GET');expect(writes.map(e=>e.method)).toEqual(['POST','POST','POST','POST','DELETE']);
  expect(writes[1].before.deckWireBodyContinuation).toMatchObject({state:'new-retry3-preview-once',newImportKey:writes[1].key});expect(writes[2].path).toContain(f.newSourceId);expect(writes[3].body.planId).toBe(f.newLocalId);expect(writes[3].body.planId).not.toBe(f.newSourceId);
  expect(f.cliCalls.map(v=>v.command)).toEqual(['sync']);expect(parse(f.cliCalls[0].stateYaml).services[0].retries).toBe(3);expect(f.sixCredentialProxyAcceptance).toHaveBeenCalledTimes(1);expect(f.r.deckAcceptance).toMatchObject({desiredRetries:3,originalPreparedState:'uncertain',originalPreparedNotIssued:true});
  const calls=f.h.request.mock.calls.length;await expect(f.fresh()).rejects.toThrow('only after');expect(f.h.request).toHaveBeenCalledTimes(calls);
 });
 it.each(['two-steps','wrong-retries','foreign-workspace'])('refuses new preview %s before apply/session/CLI',async(kind)=>{
  const f=fixture({change:v=>{if(kind==='two-steps')v.items.push(structuredClone(v.items[0]));if(kind==='wrong-retries')v.items[0].patch[0].value=2;if(kind==='foreign-workspace')v.items[0].objectWorkspaceId=randomUUID();return v;}});f.prepare();await f.close();await expect(f.fresh()).rejects.toThrow('M8_EXACT_NEW_RETRY3_SINGLE_PLAN_REQUIRED');expect(f.cliCalls).toHaveLength(0);expect(f.events.filter(e=>e.type==='request'&&e.method==='POST')).toHaveLength(2);
 });
 it('rejects source-plan reuse as the running execution plan without issuing a write session',async()=>{
  const f=fixture();f.prepare();await f.close();const request=f.h.request;request.mockImplementationOnce(request.getMockImplementation());
  const implementation=request.getMockImplementation();request.mockImplementation(async(...args)=>{const response=await implementation(...args);if(args[2]==='POST'&&args[1].includes(`/configuration/plans/${f.newSourceId}/apply`))response.payload.data.planId=f.newSourceId;return response;});
  await expect(f.fresh()).rejects.toThrow('immutable job-local plan');expect(f.events.some(e=>e.type==='request'&&e.path.includes('deck-sessions'))).toBe(false);expect(f.cliCalls).toHaveLength(0);
 });
 it.each(['expired-session','foreign-pending-execution','foreign-terminal-execution'])('rejects %s at the actual boundary',async(kind)=>{
  const opts=kind==='expired-session'?{session:{expiresAt:new Date(Date.now()-1000).toISOString()}}:kind==='foreign-pending-execution'?{pending:{executionId:randomUUID()}}:{terminal:{executionId:randomUUID()}};
  const f=fixture(opts);f.prepare();await f.close();await expect(f.fresh()).rejects.toThrow();expect(f.sixCredentialProxyAcceptance).not.toHaveBeenCalled();expect(f.r.deckAcceptance).toBeUndefined();expect(f.cliCalls.length).toBe(kind==='foreign-terminal-execution'?1:0);
 });
 it('stops unknown sync with no terminal polling, proxy success or retry',async()=>{
  const f=fixture({syncUnknown:true});f.prepare();await f.close();await expect(f.fresh()).rejects.toThrow('M8_ORIGINAL_CLI_UNKNOWN_NO_REPLAY');expect(f.sixCredentialProxyAcceptance).not.toHaveBeenCalled();const calls=f.h.request.mock.calls.length;await expect(f.fresh()).rejects.toThrow('M8_ORIGINAL_UNRESOLVED_REQUEST_NO_FURTHER_WRITE');expect(f.h.request).toHaveBeenCalledTimes(calls);expect(f.runM8FixedDeckPrivateStderr).toHaveBeenCalledTimes(1);
 });
 it('does not accept CLI success when unchanged full Service extra fields differ',async()=>{
  const f=fixture({nativeAfter:{host:'foreign.example.invalid'}});f.prepare();await f.close();await expect(f.fresh()).rejects.toThrow('unchanged SDK extra fields');expect(f.sixCredentialProxyAcceptance).not.toHaveBeenCalled();expect(f.r.deckAcceptance).toBeUndefined();
 });
});
