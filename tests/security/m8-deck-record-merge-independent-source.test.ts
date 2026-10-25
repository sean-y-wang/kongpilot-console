// @ts-nocheck -- actual continuation/receipt/plan/apply/session functions in RAM.
import {describe,expect,it,vi} from 'vitest';
import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {runInNewContext} from 'node:vm';
import {parse,stringify} from 'yaml';
import {M8Harness,entity,scope,sha256} from './lib/m8-harness.mjs';
import {configurationRead,configurationWrite,assertConfigurationReceipt} from './lib/m8-configuration-acceptance.mjs';
import {assertM8DeckSession,submitM8DeckApply} from './lib/m8-deck-acceptance.mjs';

const source=readFileSync(new URL('./lib/m8-deck-record-merge-continuation.mjs',import.meta.url),'utf8')
 .replace(/^import[^\n]*\n/gm,'').replace(/\bexport\s+(?=(?:async\s+)?function|const)/g,'');
const check=(value,label)=>{if(!value)throw Error(label);};
/** All packets, YAML, actors and release bytes are synthetic. Only the already
 * independently tested pinned body/file digest prerequisites are substituted:
 * actual predicates and all new receipt/wire/plan/session logic stay unchanged.
 * No current private artifact, env, filesystem proof, process or HTTP is read. */
function fixture(options={}){
 const actor={user:{id:randomUUID()},sid:randomUUID()},area={cid:randomUUID(),wid:randomUUID()};
 const events=[],saved=[],reads=[],cliCalls=[];let applyKey,applyDone=false,newImportKey,c;
 const planId=randomUUID(),localPlanId=randomUUID(),executionId=randomUUID(),stepId=randomUUID(),planStepId=randomUUID(),importJobId=randomUUID(),applyJobId=randomUUID(),sessionId=randomUUID();
 const body={scope:'workspace',mode:'merge',yaml:stringify({_format_version:'1.1',services:[{id:'9e5adb4a-0964-4e77-a01b-a6a4347138d7',retries:2}],upstreams:[]}),basicPasswordIntents:{}};
 const bodyJSON=JSON.stringify(body),releaseBytes=new Map();
 const syntheticHash=value=>{
  if(typeof value==='string'&&value===bodyJSON)return c.importBodySha256;
  for(const [path,bytes]of releaseBytes)if(value===bytes)return options.badReleaseHash?'0'.repeat(64):path===c.sourceFreezePath?c.sourceFreezeSha256:c.continuitySha256;
  return sha256(value);
 };
 const poolRelease=vi.fn();
 const nativeRead=vi.fn(async(h,who,where,type,id)=>{
  events.push({type:'native-read'});expect(who).toEqual(actor);expect(where).toEqual(area);expect(type).toBe('services');expect(id).toBe(c.serviceId);
  return{id,retries:options.nativeMismatch?0:2};
 });
 const sixCredentialProxyAcceptance=vi.fn(async()=>{events.push({type:'six-auth'});check(applyDone,'SYNTHETIC_NATIVE_BEFORE_SYNC');});
 const runM8FixedDeckPrivateStderr=vi.fn(async(h,who,where,input,{jobId})=>{
  h.assertWritable();events.push({type:'cli',input:structuredClone(input),jobId,actor:structuredClone(who),area:structuredClone(where)});cliCalls.push(structuredClone(input));
  const intent={state:'prepared',command:input.command};h.state.cliIntents.push(intent);h.save();
  if(options.syncUnknown){intent.state='response_unknown';h.save({phase:'stopped-cli-unknown'});throw Error('M8_ORIGINAL_CLI_UNKNOWN_NO_REPLAY');}
  intent.state='response_observed';applyDone=true;h.save();return{exitCode:0};
 });
 const actual=runInNewContext(`${source}\n({M8_DECK_RECORD_MERGE_CONTINUATION,assertM8DeckRecordMergeRelease,assertM8SingleServiceRetryPlan,m8DeckRecordMergeUnusedAcceptance})`,{
  randomUUID:options.reuseOldKey?()=>c.importKey:randomUUID,readFileSync:path=>{reads.push(path);if(!releaseBytes.has(path))throw Error('SYNTHETIC_PROOF_MISSING');return releaseBytes.get(path);},
  parse,stringify,entity,scope,sha256:syntheticHash,configurationRead,configurationWrite,assertConfigurationReceipt,assertM8DeckSession,submitM8DeckApply,
  assertM8DeckPoolRelease:poolRelease,runM8FixedDeckPrivateStderr,nativeRead,sixCredentialProxyAcceptance,structuredClone,Buffer,Date,Object,JSON,Error,
 });c=actual.M8_DECK_RECORD_MERGE_CONTINUATION;
 releaseBytes.set(c.sourceFreezePath,Buffer.from(JSON.stringify({sourceOnly:true,stage:'SOURCE_READY_DECK_SCHEMA_RECORD_MERGE_ROUNDTRIP',validation:{apiTypecheckExitCode:0,apiBuildExitCode:0,gitDiffCheckExitCode:0}})));
 releaseBytes.set(c.continuityPath,Buffer.from(JSON.stringify({allPassed:true,businessWrites:0,nativeWrites:0,authRequests:0,cliExecutions:0,...options.continuity})));
 const receipt=(kind,key,jobId,extra={})=>({domain:'configuration',durable:true,id:jobId,jobId,idempotencyKey:key,actorId:actor.user.id,originalScope:{clusterId:area.cid,workspaceId:area.wid},clusterId:area.cid,workspaceId:area.wid,kind,state:'succeeded',...extra});
 const imported=key=>receipt('import',key,importJobId,{planId,planRevision:1,planHash:'a'.repeat(64),counts:{update:1,create:0,delete:0,conflict:0},...options.importReceipt});
 const plan={id:planId,planHash:'a'.repeat(64),planRevision:1,revision:1,name:'Synthetic one-service plan',clusterId:area.cid,workspaceId:area.wid,counts:{create:0,update:1,delete:0,conflict:0},deleteCount:0,stepCount:1,capabilities:{apply:true},executionMode:'direct'};
 const changes={entity:plan,items:[{stepId:planStepId,entityType:'services',nativeId:c.serviceId,objectWorkspaceId:area.wid,action:'update',referenceOnly:false,blockerCodes:[],patch:[{op:'replace',path:'/retries',value:2}]}],nextCursor:null};
 const h={state:{phase:'synthetic-ready',inFlight:null,requests:Array.from({length:142},()=>({state:'response_observed'})),proxyChecks:[],cliIntents:[{command:'validate',state:'response_observed'},{command:'diff',state:'response_observed'},{command:'validate',state:'response_observed'},{command:'diff',state:'response_observed'}],configurationOperations:[],deckSessions:[{id:randomUUID(),revoked:true},{id:randomUUID(),revoked:true},{id:randomUUID(),revoked:true}],fixtures:[],nativeFixture:{service:{id:c.serviceId,retries:0}},baseline:{yaml:stringify({_format_version:'1.1',services:[{id:c.serviceId,retries:0}],upstreams:[]})},deckRecordMergeContinuation:{state:'prepared'}},
  check,data(result,label){return M8Harness.prototype.data.call(h,result,label);},assertWritable(){return M8Harness.prototype.assertWritable.call(h);},
  save(extra={}){Object.assign(h.state,extra);saved.push(structuredClone(h.state));events.push({type:'save'});},
  async poll(read,predicate){const value=await read();check(predicate(value),'SYNTHETIC_NONTERMINAL');return value;}};
 h.state.requests[141]={state:'response_observed',key:c.importKey,body:structuredClone(body)};
 h.request=vi.fn(async(who,path,method='GET',requestBody,opts={})=>{
  if(method!=='GET')h.assertWritable();expect(who).toEqual(actor);
  const url=new URL(path,'http://synthetic.invalid');expect(url.searchParams.get('workspaceId')).toBe(area.wid);expect(url.pathname.startsWith(`/clusters/${area.cid}/`)).toBe(true);
  events.push({type:'request',method,path,body:structuredClone(requestBody),key:opts.key,before:structuredClone(saved.at(-1))});let data;
  const base=`/clusters/${area.cid}/`;
  if(method==='GET'&&url.pathname===`${base}configuration/jobs/by-key/${c.importKey}`)data=receipt('import',c.importKey,c.importJobId,{planId:c.planId,planRevision:1,planHash:c.planHash,counts:{update:2},...options.oldReceipt});
  else if(method==='POST'&&url.pathname===`${base}configuration/imports`){newImportKey=opts.key;check(newImportKey!==c.importKey,'SYNTHETIC_OLD_IMPORT_REPLAY');expect(requestBody).toEqual(body);data=imported(newImportKey);}
  else if(method==='GET'&&url.pathname===`${base}configuration/jobs/by-key/${newImportKey}`)data=imported(newImportKey);
  else if(method==='GET'&&url.pathname===`${base}configuration/plans/${planId}/changes`)data=options.change?options.change(structuredClone(changes)):changes;
  else if(method==='GET'&&url.pathname===`${base}configuration/plans/${localPlanId}/changes`)data={...changes,entity:{...plan,id:localPlanId}};
  else if(method==='GET'&&url.pathname===`${base}configuration/plans/${planId}`)data={entity:{...plan,...options.applyPlan}};
  else if(method==='POST'&&url.pathname===`${base}configuration/plans/${planId}/apply`){applyKey=opts.key;data=receipt('apply',applyKey,applyJobId,{state:'running',driver:'deck',planId:options.sourcePlanReceipt?planId:localPlanId,planRevision:1,planHash:plan.planHash,executionCompleted:false,executionId,...options.runningReceipt});}
  else if(method==='POST'&&url.pathname===`${base}configuration/deck-sessions`){expect(requestBody).toEqual({jobId:applyJobId,purpose:'write',planId:localPlanId,planRevision:1,planHash:plan.planHash});data={id:sessionId,revision:1,purpose:'write',basePath:`/api/v1/deck/${sessionId}`,authorizationScheme:'KongOS-Deck',tokenSecret:'S'.repeat(43),expiresAt:new Date(Date.now()+180000).toISOString(),...options.session};}
  else if(method==='GET'&&url.pathname===`${base}configuration/jobs/by-key/${applyKey}`){check(applyDone,'SYNTHETIC_TERMINAL_POLLED_BEFORE_CLI');data=receipt('apply',applyKey,applyJobId,{planId:localPlanId,driver:'deck',completedSteps:1,executionCompleted:true,...options.terminal});}
  else if(method==='GET'&&url.pathname===`${base}configuration/jobs/${applyJobId}/steps`)data={items:[{id:stepId,executionId,planStepId,state:applyDone?'succeeded':'pending',verified:applyDone,operationId:applyDone?randomUUID():null,objectWorkspaceId:area.wid,type:'services',action:'update',originalId:c.serviceId}],nextCursor:null};
  else if(method==='DELETE'&&url.pathname===`${base}configuration/deck-sessions/${sessionId}`){expect(requestBody).toEqual({revision:1,confirmed:true,confirm_name:sessionId});data={revoked:true};}
  else throw Error(`SYNTHETIC_UNEXPECTED_ROUTE ${method}`);
  h.state.requests.push({state:'response_observed',method,path,key:opts.key});return{status:method==='POST'?201:200,payload:{data},requestId:randomUUID()};
 });
 const original=JSON.stringify(h.state.requests),originalCli=JSON.stringify(h.state.cliIntents);
 return{actual,c,h,actor,area,events,saved,reads,poolRelease,nativeRead,sixCredentialProxyAcceptance,runM8FixedDeckPrivateStderr,cliCalls,changes,imported:imported(randomUUID()),original,originalCli,
  run:()=>actual.m8DeckRecordMergeUnusedAcceptance(h,{admin:actor,direct:area})};
}

describe('independent record-merge unused continuation SOURCE contracts',()=>{
 it('uses one durable fresh import intent and one sync, preserving the original import and successful diff',async()=>{
  const f=fixture();await f.run();const requests=f.events.filter(e=>e.type==='request'),writes=requests.filter(e=>e.method!=='GET');
  expect(writes.map(e=>[e.method,new URL(e.path,'http://synthetic.invalid').pathname.split('/').at(-1)])).toEqual([['POST','imports'],['POST','apply'],['POST','deck-sessions'],['DELETE',f.h.state.deckSessions.at(-1).id]]);
  const fresh=writes[0];expect(fresh.key).not.toBe(f.c.importKey);expect(fresh.before.deckRecordMergeContinuation).toMatchObject({state:'new-independent-import-preview',newImportKey:fresh.key,originalImportReplayed:false,successfulDiffReplayed:false});
  expect(fresh.before.configurationOperations[0]).toMatchObject({key:fresh.key,state:'prepared',actorId:f.actor.user.id,sessionId:f.actor.sid,area:f.area,bodySha256:sha256(JSON.stringify(fresh.body))});
  expect(f.cliCalls.map(v=>v.command)).toEqual(['sync']);expect(parse(f.cliCalls[0].stateYaml).services[0].retries).toBe(2);
  expect(JSON.stringify(f.h.state.requests.slice(0,142))).toBe(f.original);expect(JSON.stringify(f.h.state.cliIntents.slice(0,4))).toBe(f.originalCli);
  expect(f.nativeRead).toHaveBeenCalledTimes(1);expect(f.sixCredentialProxyAcceptance).toHaveBeenCalledTimes(1);expect(f.h.state.deckSessions.at(-1).revoked).toBe(true);
  expect(f.h.public.deckAcceptance).toMatchObject({actualDiff:true,actualSync:true,successfulDiffReplayed:false,CLIExitAloneAccepted:false,nativeAdminBypassRequests:0});
  const calls=f.h.request.mock.calls.length;await expect(f.run()).rejects.toThrow('may continue once');expect(f.h.request).toHaveBeenCalledTimes(calls);
 });
 it.each(['idempotencyKey','actorId','workspaceId'])('rejects the old original receipt with foreign %s before any fresh write',async(field)=>{
  const f=fixture({oldReceipt:{[field]:randomUUID()}});await expect(f.run()).rejects.toThrow('original actor, key, job and exact scope');expect(f.events.filter(e=>e.type==='request'&&e.method!=='GET')).toHaveLength(0);expect(f.cliCalls).toHaveLength(0);
 });
 it('refuses to recycle the old import key even with an exact intended body',async()=>{
  const f=fixture({reuseOldKey:true});await expect(f.run()).rejects.toThrow('independent key');expect(f.events.filter(e=>e.type==='request'&&e.method!=='GET')).toHaveLength(0);
 });
 it('rejects a fresh import receipt attributed to another original key',async()=>{
  const f=fixture({importReceipt:{idempotencyKey:randomUUID()}});await expect(f.run()).rejects.toThrow('original actor, key, job and exact scope');expect(f.events.filter(e=>e.type==='request'&&e.method==='POST')).toHaveLength(1);expect(f.cliCalls).toHaveLength(0);
 });
 it.each(['two-step','foreign-plan','foreign-workspace','wrong-patch'])('refuses %s changes before submitting apply',async(kind)=>{
  const f=fixture({change:v=>{if(kind==='two-step'){v.items.push(structuredClone(v.items[0]));v.entity.counts.update=2;}if(kind==='foreign-plan')v.entity.id=randomUUID();if(kind==='foreign-workspace')v.items[0].objectWorkspaceId=randomUUID();if(kind==='wrong-patch')v.items[0].patch[0].value=3;return v;}});
  await expect(f.run()).rejects.toThrow('M8_EXACT_SINGLE_SERVICE_RETRIES_PLAN_REQUIRED');expect(f.events.filter(e=>e.type==='request'&&e.method==='POST')).toHaveLength(1);expect(f.cliCalls).toHaveLength(0);
 });
 it('rejects an apply receipt that incorrectly reuses the source plan before issuing a session',async()=>{
  const f=fixture({sourcePlanReceipt:true});await expect(f.run()).rejects.toThrow('job-local cloned plan');expect(f.events.some(e=>e.type==='request'&&e.path.includes('deck-sessions'))).toBe(false);expect(f.cliCalls).toHaveLength(0);
 });
 it('rejects an issued read session at the write-only sync boundary',async()=>{
  const f=fixture({session:{purpose:'read'}});await expect(f.run()).rejects.toThrow('fixed namespace');expect(f.cliCalls).toHaveLength(0);
 });
 it('does not poll a terminal receipt, read Native state or replay after an unknown sync',async()=>{
  const f=fixture({syncUnknown:true});await expect(f.run()).rejects.toThrow('M8_ORIGINAL_CLI_UNKNOWN_NO_REPLAY');expect(f.nativeRead).not.toHaveBeenCalled();expect(f.sixCredentialProxyAcceptance).not.toHaveBeenCalled();
  const calls=f.h.request.mock.calls.length;await expect(f.run()).rejects.toThrow('M8_ORIGINAL_UNRESOLVED_REQUEST_NO_FURTHER_WRITE');expect(f.h.request).toHaveBeenCalledTimes(calls);expect(f.runM8FixedDeckPrivateStderr).toHaveBeenCalledTimes(1);
 });
 it('does not accept zero CLI exit when Native readback contradicts the intended retries',async()=>{
  const f=fixture({nativeMismatch:true});await expect(f.run()).rejects.toThrow('independently matches');expect(f.sixCredentialProxyAcceptance).not.toHaveBeenCalled();expect(f.h.state.deckAcceptance).toBeUndefined();
 });
 it.each(['hash','dirty-continuity'])('fails release closed for %s before BFF or CLI transport',async(kind)=>{
  const f=fixture(kind==='hash'?{badReleaseHash:true}:{continuity:{nativeWrites:1}});await expect(f.run()).rejects.toThrow('fixed exact SHA');expect(f.h.request).not.toHaveBeenCalled();expect(f.cliCalls).toHaveLength(0);expect(f.poolRelease).not.toHaveBeenCalled();
 });
 it('accepts only a terminal single exact service replace/retries=2 plan, including no conflict/delete',()=>{
  const f=fixture();expect(f.actual.assertM8SingleServiceRetryPlan(f.changes,f.imported,f.area).id).toBe(f.imported.planId);
  for(const mutate of[v=>v.nextCursor='next',v=>v.entity.counts.conflict=1,v=>v.entity.deleteCount=1,v=>v.items[0].referenceOnly=true,v=>v.items[0].blockerCodes=['BLOCKED'],v=>v.items[0].patch.push({op:'replace',path:'/retries',value:2})]){
   const v=structuredClone(f.changes);mutate(v);expect(()=>f.actual.assertM8SingleServiceRetryPlan(v,f.imported,f.area)).toThrow('M8_EXACT_SINGLE_SERVICE_RETRIES_PLAN_REQUIRED');
  }
 });
});
