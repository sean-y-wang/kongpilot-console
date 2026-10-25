// @ts-nocheck -- actual continuation functions, explicitly synthetic ports only.
import {describe,it,expect,vi} from 'vitest';
import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
import {randomUUID} from 'node:crypto';
import {sha256,entity,scope} from './lib/m8-harness.mjs';
import {assertM8DeckSession} from './lib/m8-deck-acceptance.mjs';
const source=readFileSync(new URL('./lib/m8-deck-wire-body-continuation.mjs',import.meta.url),'utf8');
const check=(v,n)=>{if(!v)throw Error(n)};
function fixture(release={}){
 const c={actorId:'b5f796fa-9515-47de-9123-89a903a48224',sid:'81eb0903-bc6f-447b-a9a7-7cadf55faa77',cid:'dff45535-ed8d-4851-b7a6-6376feac7f59',wid:'eb8bf868-2caf-46aa-a935-b368bf9f3105',
  serviceId:'9e5adb4a-0964-4e77-a01b-a6a4347138d7',jobId:'8f1dee53-4657-45eb-8018-dcc792660d05',key:'de367631-8c76-4d27-b9d9-36275467c59f',executionId:'e681af39-c49c-40f6-bcff-549c2bec3722',
  executionPlanId:'ffb07cd8-018a-470a-b1c5-aadc7886fdb0',planStepId:'74240988-dfbb-4a81-b3ec-e6c2e5c95185',jobStepId:'30828448-beca-48c4-a63b-5358993247da',planHash:'ee2697ae14388bdc96f2bfb545e6e5bd85c8bde76c08c26e6068a9002e840c55'};
 const actor={user:{id:c.actorId},sid:c.sid},area={cid:c.cid,wid:c.wid},service={id:c.serviceId,name:'synthetic',host:'synthetic-upstream',port:80,protocol:'http',retries:0,connect_timeout:60000,read_timeout:60000,write_timeout:60000};
 const step={id:c.jobStepId,executionId:c.executionId,planStepId:c.planStepId,stepOrder:1,state:'pending',objectWorkspaceId:c.wid,type:'services',action:'update',originalId:c.serviceId,operationId:null,verified:false,startedAt:null,completedAt:null,revision:1};
 const intent={jobId:c.jobId,revision:2,executionId:c.executionId,executionRevision:2,planRevision:1,planHash:c.planHash,leaseGeneration:1,workflowExecutionId:null,confirmationName:`abandon:${c.jobId}`};
 const job={domain:'configuration',durable:true,id:c.jobId,jobId:c.jobId,idempotencyKey:c.key,actorId:c.actorId,clusterId:c.cid,workspaceId:c.wid,kind:'apply',state:'running',revision:2,workflowId:null,
  executionMode:'direct',approvalRequired:false,executionCompleted:false,planId:c.executionPlanId,planHash:c.planHash,planRevision:1,capabilities:{abandon:true},abandonmentIntent:intent};
 const requestId=randomUUID(),closed={...job,state:'uncertain',revision:3,executionId:c.executionId,executionRevision:3,workflowExecutionId:null,leaseGeneration:1,
  completedSteps:0,unresolvedSteps:1,abandoned:true,terminalFailureRecorded:true,executionCompleted:true,abandonmentSessionMatches:true,abandonRequestId:requestId};
 const after={...step,state:'uncertain',revision:2,completedAt:'2026-10-11T21:00:00Z'},ack={jobId:c.jobId,executionId:c.executionId,clusterId:c.cid,workspaceId:c.wid,state:'uncertain',completedSteps:0,unresolvedSteps:1,abandoned:true,terminalFailureRecorded:true,originalWorkflowUnchanged:true,originalNativeReceiptsUnchanged:true};
 const requests=Array.from({length:145},(_,index)=>({index,state:'response_observed',status:201})),originalPrefixSha256=sha256(JSON.stringify(requests));
 const r={requests,cliIntents:[{command:'validate'},{command:'validate'},{command:'diff'},{command:'diff'}],deckSessions:[{purpose:'read'},{purpose:'read'},{purpose:'read'}],fixtures:[],configurationOperations:[],
  deckWireBodyContinuation:{state:'prepared',originalPacketCount:145,originalPrefixSha256},baseline:{yaml:JSON.stringify({services:[service],consumers:[]})},nativeFixture:{service},deckPoolContinuation:{selectedCaptureJobId:randomUUID()}};
 const read=vi.fn(async(_h,_a,_s,path)=>path.includes('/steps')?(read.mock.calls.filter(v=>v[3].includes('/steps')).length===1?{items:[step],nextCursor:null}:{items:[after],nextCursor:null}):read.mock.calls.filter(v=>v[3].includes('/by-key/')).length===1?job:closed);
 const native=vi.fn(async()=>structuredClone(service)),write=vi.fn(),run=vi.fn(),proxy=vi.fn(),save=vi.fn();
 const request=vi.fn(async(_actor,url,method,body,options={})=>{
  const u=new URL('/api/v1'+url,'http://synthetic.invalid'),p={index:r.requests.length,state:'response_observed',status:201,requestId,key:options.key,method,path:u.pathname,query:u.search,
   body:structuredClone(body),bodySha256:sha256(JSON.stringify(body)),actorId:c.actorId,sessionId:c.sid,clusterId:c.cid,workspaceId:c.wid,
   headers:{Cookie:'kongos_access=synthetic-private-cookie','X-CSRF-Token':'synthetic-csrf','X-Idempotency-Key':options.key},responseData:ack};
  r.requests.push(p);return{status:201,requestId,payload:{data:ack}};
 });
 const h={state:r,check,save,assertWritable:vi.fn(),request,data:v=>v.payload.data,public:{}};
 const releaseSource=Buffer.from(JSON.stringify({sourceOnly:true,validation:{apiTypecheckExitCode:release.sourceBad?1:0,apiBuildExitCode:0}})),releaseRuntime=Buffer.from(JSON.stringify({allPassed:release.actualFalse!==true}));
 const fileRead=vi.fn(path=>path.includes('fix-freeze')?releaseSource:releaseRuntime),inheritedRelease=vi.fn();
 let vmSource=source.replace(/^import[^\n]*\n/gm,'').replace(/\bexport\s+/g,'').replace('e6109c07e5a4689e86f3a5eef2cc7655568d1d2876fbbced76b2aa0e09cfb9ac',originalPrefixSha256)
  .replace('99a8c42cacfb65850467886969cf309478b43724715d850a8155e6520ad45152',sha256(releaseSource)).replace('87329ea75d28601766aeee34326dd2fb47845b85fd683081b4b2e7ba9fab92e4',release.wrongDigest?'d'.repeat(64):sha256(releaseRuntime));
 if(release.missing)vmSource=vmSource.replace(/sourceFreezeSha256:'[a-f\d]{64}'/,'sourceFreezeSha256:null');
 const api=runInNewContext(vmSource+'\n({M8_DECK_WIRE_BODY_CONTINUATION,assertM8DeckWireBodyCheckpoint,assertM8DeckWireBodyRelease,assertM8PendingPreparedDeckStep,assertM8PreparedDeckAbandonIntent,assertM8ClosedPreparedDeckJob,maintainM8PreparedDeckOriginalSession,closeM8OriginalPreparedDeck,isM8ProvenPreparedDeckClosurePacket,assertM8FreshRetry3Plan,m8DeckFreshRetry3Acceptance})',
  {Buffer,Object,JSON,Date,Error,Number,Array,structuredClone,randomUUID,parse:JSON.parse,stringify:JSON.stringify,sha256,entity,scope,readFileSync:fileRead,configurationRead:read,configurationWrite:write,assertConfigurationReceipt:vi.fn(),assertM8DeckSession,assertM8DeckPoolRelease:inheritedRelease,runM8FixedDeckPrivateStderr:run,nativeRead:native,sixCredentialProxyAcceptance:proxy});
 return{api,h,r,c,actor,area,service,step,intent,job,closed,after,ack,requestId,read,native,write,run,proxy,request,fileRead,inheritedRelease};
}
describe('expired original145 prepared deck close cannot issue Native or replay',()=>{
 it('exact server intent allows one original close, then actual protected current receipt proves uncertain with no bound operation',async()=>{
  const f=fixture(),prefix=JSON.stringify(f.r.requests);await f.api.closeM8OriginalPreparedDeck(f.h,{admin:f.actor,direct:f.area});
  expect(f.request).toHaveBeenCalledOnce();expect(f.request.mock.calls[0][1]).toContain(`/configuration/jobs/${f.c.jobId}/abandon`);
  expect(f.request.mock.calls[0][3].workflowExecutionId).toBeNull();expect(f.read).toHaveBeenCalledTimes(4);
  expect(JSON.stringify(f.r.requests.slice(0,145))).toBe(prefix);expect(f.run).not.toHaveBeenCalled();expect(f.write).not.toHaveBeenCalled();expect(f.r.deckWireBodyContinuation.originalClosure.preparedNotIssued).toBe(true);
  expect(f.api.isM8ProvenPreparedDeckClosurePacket(f.r,f.r.requests[145],145)).toBe(true);
 });
 for(const[name,change]of[
  ['wrong actor',f=>f.actor.user.id=randomUUID()],['different actual SID',f=>f.actor.sid=randomUUID()],['wrong CID',f=>f.area.cid=randomUUID()],['wrong WID',f=>f.area.wid=randomUUID()],
  ['lease not available',f=>f.job.capabilities.abandon=false],['already terminal job',f=>f.job.state='uncertain'],['wrong origin key',f=>f.job.idempotencyKey=randomUUID()],['wrong execution',f=>f.intent.executionId=randomUUID()],
  ['wrong cloned plan',f=>f.job.planId=randomUUID()],['wrong plan hash',f=>f.intent.planHash='a'.repeat(64)],['wrong plan revision',f=>f.intent.planRevision=2],['wrong confirmation',f=>f.intent.confirmationName='abandon:other'],
  ['non-null workflow',f=>f.intent.workflowExecutionId=randomUUID()],['wrong current revision',f=>f.intent.revision=3],['invalid lease generation',f=>f.intent.leaseGeneration=0],['only fake public capability',f=>delete f.job.abandonmentIntent],
  ['bound original operation',f=>f.step.operationId=randomUUID()],['step running',f=>f.step.state='running'],['wrong original step',f=>f.step.id=randomUUID()],['extra step',f=>f.read.mockImplementation(async(_h,_a,_s,path)=>path.includes('/steps')?{items:[f.step,f.step],nextCursor:null}:f.job)],
  ['old sync intent exists',f=>f.r.cliIntents.push({command:'sync'})],['original write session exists',f=>f.r.deckSessions.push({purpose:'write'})],['actual retries2 already present',f=>f.service.retries=2],
 ])it(name+' refuses before any metadata POST or CLI',async()=>{const f=fixture();change(f);await expect(f.api.closeM8OriginalPreparedDeck(f.h,{admin:f.actor,direct:f.area})).rejects.toThrow();expect(f.request).not.toHaveBeenCalled();expect(f.run).not.toHaveBeenCalled()});
 it('unknown close retains the one original key/body and never advances to new preview',async()=>{const f=fixture();f.request.mockRejectedValue(Error('M8_RESPONSE_UNKNOWN'));await expect(f.api.closeM8OriginalPreparedDeck(f.h,{admin:f.actor,direct:f.area})).rejects.toThrow('UNKNOWN');expect(f.r.deckWireBodyContinuation.abandonAttempt.state).toBe('prepared');expect(f.request).toHaveBeenCalledOnce();expect(f.write).not.toHaveBeenCalled();expect(f.read).toHaveBeenCalledTimes(2)});
 for(const[name,change]of[
  ['new current session not matching',f=>f.closed.abandonmentSessionMatches=false],['wrong closed hash',f=>f.closed.planHash='a'.repeat(64)],['marked succeeded',f=>f.closed.state='succeeded'],['fake Native success',f=>f.closed.completedSteps=1],
  ['wrong request',f=>f.closed.abandonRequestId=randomUUID()],['wrong closed revision',f=>f.closed.executionRevision=9],['bound op after close',f=>f.after.operationId=randomUUID()],
 ])it(name+' rejects closure proof after the sole POST without replay',async()=>{const f=fixture();change(f);await expect(f.api.closeM8OriginalPreparedDeck(f.h,{admin:f.actor,direct:f.area})).rejects.toThrow();expect(f.request).toHaveBeenCalledOnce();expect(f.r.deckWireBodyContinuation.abandonAttempt.state).toBe('prepared');expect(f.run).not.toHaveBeenCalled()});
 it('repeat close cannot emit another GET or POST',async()=>{const f=fixture();await f.api.closeM8OriginalPreparedDeck(f.h,{admin:f.actor,direct:f.area});f.read.mockClear();f.request.mockClear();await expect(f.api.closeM8OriginalPreparedDeck(f.h,{admin:f.actor,direct:f.area})).rejects.toThrow('unused');expect(f.request).not.toHaveBeenCalled();expect(f.read).not.toHaveBeenCalled()});
 it('synthetically missing immutable repair proof is fail closed before any file or runtime read',()=>{const f=fixture({missing:true});expect(()=>f.api.assertM8DeckWireBodyRelease(f.h)).toThrow('must be frozen');expect(f.fileRead).not.toHaveBeenCalled();expect(f.request).not.toHaveBeenCalled()});
 it('exact green synthetic Source/actual runtime files are checked before inherited fixed runner proof',()=>{const f=fixture();f.api.assertM8DeckWireBodyRelease(f.h);expect(f.fileRead).toHaveBeenCalledTimes(2);expect(f.inheritedRelease).toHaveBeenCalledOnce();expect(f.request).not.toHaveBeenCalled()});
 for(const[name,options]of[['changed runtime bytes',{wrongDigest:true}],['actual runtime report false',{actualFalse:true}],['Source build proof false',{sourceBad:true}]])it(name+' prevents transport',()=>{const f=fixture(options);expect(()=>f.api.assertM8DeckWireBodyRelease(f.h)).toThrow('SHA-bound');expect(f.inheritedRelease).not.toHaveBeenCalled();expect(f.request).not.toHaveBeenCalled()});
});
function maintenanceFixture(refresh=true){
 const f=fixture();f.actor.user.username='synthetic-original';f.actor.csrf='synthetic-csrf';f.actor.expiresAt=Date.now()+(refresh?-1000:600000);
 const auditId=randomUUID(),authRequestId=randomUUID(),meRequestId=randomUUID();
 const refreshPacket={index:145,method:'POST',path:'/api/v1/auth/refresh',state:'response_observed',status:201,requestId:authRequestId,body:{},bodySha256:sha256('{}'),actorId:f.c.actorId,sessionId:f.c.sid};
 const audit={id:auditId,requestId:authRequestId,actorId:f.c.actorId,entityType:'auth_sessions',entityId:f.c.sid,action:'refresh',result:'success'};
 f.h.renewIfNeeded=vi.fn(async a=>{if(a.expiresAt<Date.now()+90000){f.r.requests.push(refreshPacket);a.expiresAt=Date.now()+900000;}});
 f.request.mockImplementation(async(_actor,path)=>({requestId:path==='/auth/me'?meRequestId:randomUUID(),payload:{data:path==='/auth/me'?{user:f.actor.user,csrfToken:f.actor.csrf}:{items:[audit],nextCursor:null}}}));
 return{...f,audit,auditId,refreshPacket,authRequestId,meRequestId};
}
describe('independent close-only normal original session maintenance',()=>{
 it('expired access uses only one standard product refresh and current-user/audit GETs',async()=>{const f=maintenanceFixture();const m=await f.api.maintainM8PreparedDeckOriginalSession(f.h,f.actor);expect(m.state).toBe('completed');expect(m.normalAuthenticationWrites).toBe(1);expect(m.sameSID).toBe(true);expect(m.auditEventIds).toEqual([f.auditId]);expect(f.request).toHaveBeenCalledTimes(2);expect(f.run).not.toHaveBeenCalled();expect(f.write).not.toHaveBeenCalled()});
 it('still-valid access does not refresh or force identical expiry',async()=>{const f=maintenanceFixture(false),expiry=f.actor.expiresAt;const m=await f.api.maintainM8PreparedDeckOriginalSession(f.h,f.actor);expect(m.normalAuthenticationWrites).toBe(0);expect(f.actor.expiresAt).toBe(expiry);expect(f.request).toHaveBeenCalledOnce()});
 for(const[name,change]of[
  ['changed actor',f=>f.actor.user.id=randomUUID()],['changed SID',f=>f.actor.sid=randomUUID()],['repeat window',f=>f.r.deckWireBodyContinuation.sessionMaintenance={state:'completed'}],
  ['wrong refresh path',f=>f.refreshPacket.path='/api/v1/auth/login'],['wrong refresh actor',f=>f.refreshPacket.actorId=randomUUID()],['wrong refresh SID',f=>f.refreshPacket.sessionId=randomUUID()],
  ['unknown auth packet',f=>f.refreshPacket.state='response_unknown'],['normal refresh was rejected',f=>f.refreshPacket.status=401],['different refresh body',f=>f.refreshPacket.body={fake:'session'}],
  ['missing actual auth audit',f=>f.audit.action='other'],['wrong audit SID',f=>f.audit.entityId=randomUUID()],['wrong audit request',f=>f.audit.requestId=randomUUID()],
 ])it(name+' stops and cannot silently create a new identity',async()=>{const f=maintenanceFixture();change(f);await expect(f.api.maintainM8PreparedDeckOriginalSession(f.h,f.actor)).rejects.toThrow();expect(f.run).not.toHaveBeenCalled();expect(f.write).not.toHaveBeenCalled();if(name!=='repeat window')expect(f.r.deckWireBodyContinuation.sessionMaintenance?.state).not.toBe('completed');else expect(f.r.deckWireBodyContinuation.sessionMaintenance.state).toBe('completed')});
 it('unknown refresh retains its one marker and cannot proceed to current-user or abandon',async()=>{const f=maintenanceFixture();f.h.renewIfNeeded.mockRejectedValue(Error('M8_RESPONSE_UNKNOWN'));await expect(f.api.maintainM8PreparedDeckOriginalSession(f.h,f.actor)).rejects.toThrow('UNKNOWN');expect(f.request).not.toHaveBeenCalled();expect(f.r.deckWireBodyContinuation.sessionMaintenance.state).toBe('prepared')});
});
describe('strict prepared closure singleton for uncertain audit, not Native success',()=>{
 for(const[name,change]of[
  ['other job',f=>f.r.requests[145].path=f.r.requests[145].path.replace(f.c.jobId,randomUUID())],['wrong actor',f=>f.r.requests[145].actorId=randomUUID()],['wrong SID',f=>f.r.requests[145].sessionId=randomUUID()],
  ['wrong body',f=>f.r.requests[145].body.planHash='f'.repeat(64)],['missing cookie',f=>delete f.r.requests[145].headers.Cookie],['missing CSRF',f=>delete f.r.requests[145].headers['X-CSRF-Token']],
  ['wrong fixed original prefix',f=>f.r.requests[1].status=500],['pending became Native receipt',f=>f.r.deckWireBodyContinuation.originalPendingStep.operationId=randomUUID()],['fake posted success',f=>f.r.requests[145].responseData.state='succeeded'],
  ['no real protected receipt',f=>delete f.r.deckWireBodyContinuation.abandonAttempt.originalJob],['no sameSID proof',f=>f.r.deckWireBodyContinuation.abandonAttempt.originalJob.abandonmentSessionMatches=false],
 ])it(name+' is never counted as proved closure',async()=>{const f=fixture();await f.api.closeM8OriginalPreparedDeck(f.h,{admin:f.actor,direct:f.area});change(f);expect(f.api.isM8ProvenPreparedDeckClosurePacket(f.r,f.r.requests[145],145)).toBe(false)});
});
function freshFixture(){
 const f=fixture();f.r.deckWireBodyContinuation.state='prepared-original-closed';
 const sourceId=randomUUID(),localId=randomUUID(),jobId=randomUUID(),executionId=randomUUID(),stepId=randomUUID(),jobStepId=randomUUID(),hash='b'.repeat(64),sessionId=randomUUID(),opId=randomUUID();
 const imported={jobId:randomUUID(),planId:sourceId,planRevision:1,planHash:hash,counts:{create:0,update:1,delete:0,conflict:0}},base={clusterId:f.c.cid,workspaceId:f.c.wid,planRevision:1,planHash:hash,executionMode:'direct',stepCount:1,nativePacketCount:1,deleteCount:0};
 const patch={stepId,entityType:'services',nativeId:f.c.serviceId,objectWorkspaceId:f.c.wid,action:'update',patch:[{op:'replace',path:'/retries',value:3}],blockerCodes:[]};
 const sourcePlan={...base,id:sourceId,revision:1,name:'synthetic-retry3',capabilities:{apply:true}},localPlan={...base,id:localId,revision:1};
 const initial={domain:'configuration',durable:true,id:jobId,jobId,idempotencyKey:randomUUID(),actorId:f.c.actorId,originalScope:{clusterId:f.c.cid,workspaceId:f.c.wid},clusterId:f.c.cid,workspaceId:f.c.wid,kind:'apply',state:'running',executionCompleted:false,driver:'deck',executionId,planId:localId,planHash:hash,planRevision:1};
 const step={id:jobStepId,executionId,planStepId:stepId,state:'pending',objectWorkspaceId:f.c.wid,originalId:f.c.serviceId,type:'services',action:'update',operationId:null,verified:false};
 const terminal={...initial,state:'succeeded',executionCompleted:true,completedSteps:1};
 const finalStep={...step,state:'succeeded',verified:true,operationId:opId};
 let bykey=0;f.read.mockImplementation(async(_h,_a,_s,path)=>{
  if(path.includes('/by-key/')){bykey++;return terminal;}
  if(path.includes('/steps'))return{items:[f.run.mock.calls.length?finalStep:step],nextCursor:null};
  if(path===`configuration/plans/${sourceId}`)return{entity:sourcePlan};
  return{entity:path.includes(sourceId)?sourcePlan:localPlan,items:[patch],nextCursor:null};
 });
 f.write.mockResolvedValue(imported);
 f.request.mockImplementation(async(_a,path,method,body,options={})=>{
  if(path.endsWith('/apply?workspaceId='+f.c.wid)){initial.idempotencyKey=options.key;terminal.idempotencyKey=options.key;return{status:201,payload:{data:initial}};}
  if(method==='DELETE')return{payload:{data:{revoked:true}}};
  return{payload:{data:{id:sessionId,revision:1,purpose:'write',basePath:`/api/v1/deck/${sessionId}`,authorizationScheme:'KongOS-Deck',tokenSecret:'a'.repeat(43),expiresAt:new Date(Date.now()+120000).toISOString()}}};
 });
 f.native.mockImplementation(async()=>({...f.service,retries:f.run.mock.calls.length?3:f.service.retries}));f.run.mockResolvedValue({exitCode:0});
 return{...f,imported,sourcePlan,localPlan,initial,step,terminal,finalStep,patch,sessionId,opId};
}
describe('new retries3 has one immutable job-local clone and actual fixed sync proof',()=>{
 it('only sends new preview/apply/session/sync once and uses actual clone ID, not original source ID',async()=>{
  const f=freshFixture(),before=JSON.stringify(f.r.requests);await f.api.m8DeckFreshRetry3Acceptance(f.h,{admin:f.actor,direct:f.area});
  expect(f.write).toHaveBeenCalledOnce();expect(JSON.parse(f.write.mock.calls[0][4].yaml).services[0].retries).toBe(3);
  expect(f.request.mock.calls[1][3].planId).toBe(f.localPlan.id);expect(f.request.mock.calls[1][3].planId).not.toBe(f.sourcePlan.id);
  expect(f.run).toHaveBeenCalledOnce();expect(f.run.mock.calls[0][3].command).toBe('sync');expect(f.proxy).toHaveBeenCalledOnce();expect(f.r.deckAcceptance.desiredRetries).toBe(3);
  expect(f.r.deckSessions.at(-1).revoked).toBe(true);expect(JSON.stringify(f.r.requests)).toBe(before);
 });
 for(const[name,change]of[
  ['not closed original',f=>f.r.deckWireBodyContinuation.state='prepared'],['preview already started',f=>f.r.deckWireBodyContinuation.newImportKey=randomUUID()],
  ['original retries2 became current',f=>f.service.retries=2],['two updates',f=>f.imported.counts.update=2],['unknown extra field patch',f=>f.patch.patch.push({op:'replace',path:'/host',value:'wrong'})],
  ['wrong cloned plan hash',f=>f.localPlan.planHash='c'.repeat(64)],['foreign step',f=>f.step.executionId=randomUUID()],['bound operation too soon',f=>f.step.operationId=randomUUID()],
  ['missing genuine initial driver',f=>delete f.initial.driver],['missing initial executionId',f=>delete f.initial.executionId],['initial source ID was not cloned',f=>f.initial.planId=f.sourcePlan.id],
 ])it(name+' stops before any sync',async()=>{const f=freshFixture();change(f);await expect(f.api.m8DeckFreshRetry3Acceptance(f.h,{admin:f.actor,direct:f.area})).rejects.toThrow();expect(f.run).not.toHaveBeenCalled()});
 it('unknown new preview keeps its unused key and does not apply, issue or sync',async()=>{const f=freshFixture();f.write.mockRejectedValue(Error('M8_RESPONSE_UNKNOWN'));await expect(f.api.m8DeckFreshRetry3Acceptance(f.h,{admin:f.actor,direct:f.area})).rejects.toThrow('UNKNOWN');expect(f.r.deckWireBodyContinuation.newImportKey).toBeTruthy();expect(f.request).not.toHaveBeenCalled();expect(f.run).not.toHaveBeenCalled()});
 it('unknown sync is not revoked, replayed or treated as a successful job',async()=>{const f=freshFixture();f.run.mockRejectedValue(Error('M8_ORIGINAL_CLI_UNKNOWN'));await expect(f.api.m8DeckFreshRetry3Acceptance(f.h,{admin:f.actor,direct:f.area})).rejects.toThrow('UNKNOWN');expect(f.run).toHaveBeenCalledOnce();expect(f.request).toHaveBeenCalledTimes(2);expect(f.r.deckAcceptance).toBeUndefined();expect(f.proxy).not.toHaveBeenCalled()});
 for(const[name,change]of[
  ['terminal uncertain',f=>f.terminal.state='uncertain'],['wrong terminal execution',f=>f.terminal.executionId=randomUUID()],['wrong terminal plan',f=>f.terminal.planId=f.sourcePlan.id],['two completed steps',f=>f.terminal.completedSteps=2],
  ['failed Native verification',f=>f.finalStep.verified=false],['different operation actor step',f=>f.finalStep.objectWorkspaceId=randomUUID()],
 ])it(name+' refuses CLI exit0 as actual Native proof',async()=>{const f=freshFixture();change(f);await expect(f.api.m8DeckFreshRetry3Acceptance(f.h,{admin:f.actor,direct:f.area})).rejects.toThrow();expect(f.run).toHaveBeenCalledOnce();expect(f.proxy).not.toHaveBeenCalled()});
 it('SDK extra field change is detected by protected Native readback',async()=>{const f=freshFixture();f.native.mockImplementation(async()=>({...f.service,retries:f.run.mock.calls.length?3:0,host:f.run.mock.calls.length?'wrong':f.service.host}));await expect(f.api.m8DeckFreshRetry3Acceptance(f.h,{admin:f.actor,direct:f.area})).rejects.toThrow('unchanged SDK extra fields');expect(f.proxy).not.toHaveBeenCalled()});
});
