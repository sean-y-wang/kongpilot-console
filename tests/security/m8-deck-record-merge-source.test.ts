// @ts-nocheck -- actual helper source with explicitly synthetic runtime ports.
import {describe,it,expect,vi} from 'vitest';
import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
import {randomUUID} from 'node:crypto';
import {sha256,entity,scope} from './lib/m8-harness.mjs';
const source=readFileSync(new URL('./lib/m8-deck-record-merge-continuation.mjs',import.meta.url),'utf8');
const check=(value,name)=>{if(!value)throw Error(name)};
function fixture(){
 const actor={user:{id:randomUUID()},sid:randomUUID()},area={cid:randomUUID(),wid:randomUUID()},newPlan=randomUUID(),newJob=randomUUID(),newKey=randomUUID(),applyId=randomUUID(),applyKey=randomUUID(),sid=randomUUID(),opId=randomUUID();
 const oldKey='e8823efd-4e22-4189-927c-a6c63f292b59',oldJob='d04994bd-e3a6-49c7-b95b-e670353c5a00',oldPlan='e82be558-030f-48ca-a446-b7d958eb1fd3',hash='8e33b4f360912fe2d0874baf0c978eab5d4e14c7baf67e581aad75dcd25a25a5',service='9e5adb4a-0964-4e77-a01b-a6a4347138d7';
 const baseline={services:[{id:service,retries:0}]},body={scope:'workspace',mode:'merge',yaml:JSON.stringify({services:[{id:service,retries:2}]}),basicPasswordIntents:{}};
 const previous={id:oldJob,jobId:oldJob,idempotencyKey:oldKey,planId:oldPlan,planRevision:1,planHash:hash,state:'succeeded',counts:{update:2}};
 const imported={id:newJob,jobId:newJob,planId:newPlan,planRevision:1,planHash:'a'.repeat(64),state:'succeeded',counts:{create:0,update:1,delete:0,conflict:0}};
 const plan={entity:{id:newPlan,planRevision:1,planHash:imported.planHash,clusterId:area.cid,workspaceId:area.wid,counts:{...imported.counts},deleteCount:0},nextCursor:null,items:[{entityType:'services',nativeId:service,objectWorkspaceId:area.wid,action:'update',patch:[{op:'replace',path:'/retries',value:2}],blockerCodes:[]}]};
 const terminal={id:applyId,jobId:applyId,idempotencyKey:applyKey,state:'succeeded',executionCompleted:true,driver:'deck',completedSteps:1};
 const execution={receipt:{jobId:applyId,idempotencyKey:applyKey},plan:{id:newPlan,planRevision:1,planHash:imported.planHash},operation:{state:'submitted'}};
 const r={requests:Array.from({length:142},(_,index)=>({index})),deckRecordMergeContinuation:{state:'prepared'},baseline:{yaml:JSON.stringify(baseline)},nativeFixture:{service:{id:service,retries:0}},deckSessions:[{},{},{id:randomUUID(),revoked:true}],fixtures:[]};r.requests[141]={body};
 const read=vi.fn(async(_h,_a,_s,path)=>path.includes(`by-key/${oldKey}`)?previous:path.includes('/plans/')?plan:path.includes('/steps')?{items:[{state:'succeeded',verified:true,operationId:opId,objectWorkspaceId:area.wid}]}:terminal);
 const write=vi.fn(async()=>imported),apply=vi.fn(async()=>execution),run=vi.fn(async()=>({exitCode:0})),native=vi.fn(async()=>({id:service,retries:2})),proxy=vi.fn(async()=>{}),save=vi.fn(),request=vi.fn(async(_a,path,method)=>({status:201,payload:{data:method==='DELETE'?{revoked:true}:{id:sid,revision:1,tokenSecret:'a'.repeat(43)}}}));
 const h={state:r,check,save,assertWritable:vi.fn(),data:x=>x.payload.data,request,public:{}};
 const freeze=Buffer.from(JSON.stringify({stage:'SOURCE_READY_DECK_SCHEMA_RECORD_MERGE_ROUNDTRIP',sourceOnly:true,validation:{apiTypecheckExitCode:0,apiBuildExitCode:0,gitDiffCheckExitCode:0}})),continuity=Buffer.from(JSON.stringify({allPassed:true,businessWrites:0,nativeWrites:0,authRequests:0,cliExecutions:0}));
 let vmSource=source.replace(/^import[^\n]*\n/gm,'').replace(/\bexport\s+/g,'').replace('789d22d72cd7ca11fce9eb9a19a5e5de7d1d8ce6edb7f982dc1d652e4088fe87',sha256(freeze)).replace('ec8c727cc50388fb76ff65d02cd59ffcbebc79cd62ad84e4d64716c9004e5570',sha256(continuity)).replace('58e3b879c7e426e044d774e611f4b986702a5b89d2e34b656c25bbc943b8155e',sha256(JSON.stringify(body)));
 const files=vi.fn(path=>path.includes('fix-freeze')?freeze:continuity),runtime=vi.fn();
 const api=runInNewContext(vmSource+'\n({assertM8SingleServiceRetryPlan,m8DeckRecordMergeUnusedAcceptance,assertM8DeckRecordMergeRelease})',{Buffer,Object,JSON,Date,Error,Number,structuredClone,parse:JSON.parse,stringify:JSON.stringify,randomUUID:()=>newKey,entity,scope,sha256,readFileSync:files,assertM8DeckPoolRelease:runtime,configurationRead:read,configurationWrite:write,assertConfigurationReceipt:vi.fn(),submitM8DeckApply:apply,assertM8DeckSession:(_h,v)=>v,runM8FixedDeckPrivateStderr:run,nativeRead:native,sixCredentialProxyAcceptance:proxy});
 return{actor,area,r,h,plan,previous,imported,execution,terminal,newKey,newJob,applyId,oldKey,body,api,read,write,apply,run,native,proxy,request,files,runtime};
}
describe('schema-record merge independent preview and exact one-step apply',()=>{
 it('uses a new preview key, preserves old body/plan, runs only sync and independently verifies job/Native/proxy',async()=>{
  const f=fixture(),old=JSON.stringify(f.r.requests[141]);const value=await f.api.m8DeckRecordMergeUnusedAcceptance(f.h,{admin:f.actor,direct:f.area});
  expect(f.write).toHaveBeenCalledOnce();expect(f.write.mock.calls[0][3]).toBe('configuration/imports');expect(f.write.mock.calls[0][4]).toEqual(f.body);expect(f.write.mock.calls[0][5].key).toBe(f.newKey);expect(f.newKey).not.toBe(f.oldKey);
  expect(JSON.stringify(f.r.requests[141])).toBe(old);expect(f.run).toHaveBeenCalledOnce();expect(f.run.mock.calls[0][3].command).toBe('sync');expect(f.run.mock.calls[0][3].stateYaml).toContain('"retries":2');
  expect(f.apply).toHaveBeenCalledOnce();expect(f.native).toHaveBeenCalledOnce();expect(f.proxy).toHaveBeenCalledOnce();expect(value.applyJobId).toBe(f.applyId);expect(f.r.deckSessions.at(-1).revoked).toBe(true);
  expect(f.r.deckRecordMergeContinuation.successfulDiffReplayed).toBe(false);expect(f.r.deckRecordMergeContinuation.originalImportReplayed).toBe(false);
 });
 for(const [name,change]of[
  ['new preview still has two updates',f=>f.imported.counts.update=2],['new preview has create',f=>f.imported.counts.create=1],['new preview has delete',f=>f.imported.counts.delete=1],['new preview has conflict',f=>f.imported.counts.conflict=1],
  ['old job returned',f=>f.imported.jobId=f.previous.jobId],['old plan returned',f=>f.imported.planId=f.previous.planId],['old receipt state changed',f=>f.previous.state='running'],['old immutable hash changed',f=>f.previous.planHash='f'.repeat(64)],
 ])it(name+' stops before apply or issuing write capability',async()=>{const f=fixture();change(f);await expect(f.api.m8DeckRecordMergeUnusedAcceptance(f.h,{admin:f.actor,direct:f.area})).rejects.toThrow();expect(f.apply).not.toHaveBeenCalled();expect(f.request).not.toHaveBeenCalled();expect(f.run).not.toHaveBeenCalled()});
 it('unknown new preview preserves its exact key and stops before all later actions',async()=>{const f=fixture();f.write.mockRejectedValue(Error('M8_RESPONSE_UNKNOWN'));await expect(f.api.m8DeckRecordMergeUnusedAcceptance(f.h,{admin:f.actor,direct:f.area})).rejects.toThrow('UNKNOWN');expect(f.r.deckRecordMergeContinuation.newImportKey).toBe(f.newKey);expect(f.apply).not.toHaveBeenCalled();expect(f.run).not.toHaveBeenCalled()});
 it('unknown sync never checks completion, retries sync, or revokes the uncertain session',async()=>{const f=fixture();f.run.mockRejectedValue(Error('M8_ORIGINAL_CLI_UNKNOWN_NO_REPLAY'));await expect(f.api.m8DeckRecordMergeUnusedAcceptance(f.h,{admin:f.actor,direct:f.area})).rejects.toThrow('UNKNOWN');expect(f.run).toHaveBeenCalledOnce();expect(f.read).toHaveBeenCalledTimes(2);expect(f.request).toHaveBeenCalledOnce();expect(f.native).not.toHaveBeenCalled();expect(f.proxy).not.toHaveBeenCalled()});
 for(const [name,change]of[
  ['job did not succeed',f=>f.terminal.state='uncertain'],['job step count differs',f=>f.terminal.completedSteps=2],['job is not deck driver',f=>f.terminal.driver='native'],['job not completed',f=>f.terminal.executionCompleted=false],
 ])it(name+' cannot substitute CLI exit for actual execution',async()=>{const f=fixture();change(f);await expect(f.api.m8DeckRecordMergeUnusedAcceptance(f.h,{admin:f.actor,direct:f.area})).rejects.toThrow();expect(f.run).toHaveBeenCalledOnce();expect(f.native).not.toHaveBeenCalled();expect(f.proxy).not.toHaveBeenCalled()});
 it('a preexisting unresolved original packet prevents any read/write/CLI',async()=>{const f=fixture();f.h.assertWritable.mockImplementation(()=>{throw Error('UNRESOLVED')});await expect(f.api.m8DeckRecordMergeUnusedAcceptance(f.h,{admin:f.actor,direct:f.area})).rejects.toThrow('UNRESOLVED');expect(f.read).not.toHaveBeenCalled();expect(f.write).not.toHaveBeenCalled();expect(f.run).not.toHaveBeenCalled()});
});
describe('actual frozen one-Service diff predicate',()=>{
 it('accepts the exact one-step typed plan',()=>{const f=fixture();expect(f.api.assertM8SingleServiceRetryPlan(f.plan,f.imported,f.area).id).toBe(f.imported.planId)});
 for(const [name,change]of[
  ['wrong plan',f=>f.plan.entity.id=randomUUID()],['wrong hash',f=>f.plan.entity.planHash='b'.repeat(64)],['wrong revision',f=>f.plan.entity.planRevision=2],['wrong CID',f=>f.plan.entity.clusterId=randomUUID()],['wrong WID',f=>f.plan.entity.workspaceId=randomUUID()],
  ['extra step',f=>f.plan.items.push(structuredClone(f.plan.items[0]))],['no step',f=>f.plan.items=[]],['more pages',f=>f.plan.nextCursor='next'],['different type',f=>f.plan.items[0].entityType='upstreams'],['different Service',f=>f.plan.items[0].nativeId=randomUUID()],
  ['wrong object WID',f=>f.plan.items[0].objectWorkspaceId=randomUUID()],['delete action',f=>f.plan.items[0].action='delete'],['reference-only',f=>f.plan.items[0].referenceOnly=true],['wrong path',f=>f.plan.items[0].patch[0].path='/healthchecks/active/https_sni'],
  ['remove rather than replace',f=>f.plan.items[0].patch[0].op='remove'],['wrong retries',f=>f.plan.items[0].patch[0].value=3],['extra patch',f=>f.plan.items[0].patch.push({op:'replace',path:'/name',value:'synthetic'})],['conflict',f=>f.plan.items[0].blockerCodes=['CONFLICT']],
 ])it(name+' is rejected',()=>{const f=fixture();change(f);expect(()=>f.api.assertM8SingleServiceRetryPlan(f.plan,f.imported,f.area)).toThrow('EXACT_SINGLE')});
});
describe('actual repair release proof predicate',()=>{
 it('passes both exact green SHA proofs then the unchanged fixed image/current pool release',()=>{const f=fixture();f.api.assertM8DeckRecordMergeRelease(f.h);expect(f.files).toHaveBeenCalledTimes(2);expect(f.runtime).toHaveBeenCalledOnce()});
 it('rejects missing or changed actual proof before inherited runner release',()=>{const f=fixture();f.files.mockReturnValue(Buffer.from('{}'));expect(()=>f.api.assertM8DeckRecordMergeRelease(f.h)).toThrow();expect(f.runtime).not.toHaveBeenCalled()});
});
