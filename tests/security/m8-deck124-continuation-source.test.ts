// @ts-nocheck -- exact source in a synthetic VM. Only immutable public-test
// anchors are substituted; production has no DTO/env/runtime override.
import {describe,it,expect,vi} from 'vitest';
import {readFileSync} from 'node:fs';
import {Script,runInNewContext} from 'node:vm';
import {randomUUID} from 'node:crypto';
import {sha256,M8_COMPOSE} from './lib/m8-harness.mjs';
const source=readFileSync(new URL('./lib/m8-deck124-continuation.mjs',import.meta.url),'utf8');
const check=(v,n)=>{if(!v)throw Error(n);};
function fixture(){
 const actor={user:{id:randomUUID()},sid:randomUUID()},area={cid:randomUUID(),wid:randomUUID()};
 const jobId='5441fe66-833a-4625-8493-e7b66afd5d4c',snapshotId='9363f644-d6b1-4c2c-a1a2-94ec4076d433',key='c2051f8a-f379-44a6-b9a4-ac625c81d625';
 const receipt={jobId,snapshotId,idempotencyKey:key,actorId:actor.user.id,clusterId:area.cid,workspaceId:area.wid,kind:'capture'};
 const authority={ok:true,nonOwnerReadOnly:true,job:{id:jobId,kind:'capture',state:'succeeded',same_sid:true,same_actor:true,same_scope:true,same_key:true,same_snapshot:true,authority_expired:false,job_expired:false}};
 const input={command:'validate',stateYaml:'x'.repeat(15722)},oldHash='61394e30ebc92599fbccc9807e558cec018ab407d78e644c0bff5bcb0011554b';
 const requests=Array.from({length:133},(_,index)=>({index,state:'response_observed',status:201}));requests[132]={...requests[132],actorId:actor.user.id,sessionId:actor.sid,clusterId:area.cid,workspaceId:area.wid,responseData:{jobId,snapshotId}};
 const r={version:1,milestone:'M8',phase:'stopped-failure',inFlight:null,requests,scopes:{direct:area},sessions:{admin:actor},configurationOperations:[{jobId,key,state:'succeeded',receipt}],
  finalHttpUnusedTail:{state:'fixed-cli-unused'},expiredExecutionRecovery:{state:'completed'},approvalTransfer:{nativeSteps:17},c2ModeRestored:true,
  cliIntents:[{command:'validate',state:'response_observed',dockerExitCode:1,safeResult:{exitCode:1,toolBinarySha256:oldHash,possibleUnknown:false,stderrBytes:141},input,inputSha256:sha256(JSON.stringify(input))}],
  cliDiagnostics:[{state:'response_observed',classification:'DECK11_PASSIVE_TYPE_UNSUPPORTED'}]};
 const failure=Buffer.from(JSON.stringify({allPassed:false,passed:1711,failed:1,unknownWrites:0}));
 const diagnosis=Buffer.from(JSON.stringify({classification:'DECK11_PASSIVE_TYPE_UNSUPPORTED',exitCode:1,network:'none',newBusinessWrites:0,newAuthWrites:0,newNativeRequests:0,originalPrefixUnchanged:true}));
 const runtime=Buffer.from(JSON.stringify({allPassed:true,imageId:'sha256:'+ 'c'.repeat(64),toolVersion:'1.2.4',toolCommit:'8e68931',toolBinarySha256:'642f49fd64e83aff867939705dbd927c5e750b241a99e8539ab22d18930427ed',networkNoneValidatePassed:true,sourceFreezeSha256:'d'.repeat(64)}));
 let vmSource=source.replace(/^import[^\n]*\n/gm,'').replace(/\bexport\s+/g,'');
 for(const [anchor,value] of [
  ['b0940124842772fc9957198d84bac425d6fb698bc84f6ffe77fc094319a63bf9',sha256(JSON.stringify(requests))],
  ['7085a43f89462bfb3cc49af801b417b1a56c3c011db7e58a05585ff60e3d1417',sha256(JSON.stringify(requests[132]))],
  ['44b215d5189c9742e6d4b7bea2c4d0dfe5bee340c6c16dd8a68b07bc4c510456',sha256(failure)],
  ['7e775841a348104507fc063e18ec0732d601d683ef45987658b0e335aa4874da',sha256(diagnosis)],
  ['89fcd51dd141b46a48cdd1a83775f5285a2b3bfaa32be942fa3be20b75ca9d3a',sha256(JSON.stringify(input))],
  [source.match(/freezeSha256:'([^']+)'/)[1],'d'.repeat(64)],[source.match(/runtimeSha256:'([^']+)'/)[1],sha256(runtime)],[source.match(/imageId:'([^']+)'/)[1],'sha256:'+'c'.repeat(64)]])vmSource=vmSource.replace(anchor,value);
 const exec=vi.fn((program,args,options)=>{if(args.includes('inspect'))return 'sha256:'+'c'.repeat(64);new Script(args.at(-1));return JSON.stringify(authority);});
 const h={check,state:r,save:vi.fn()},fileRead=vi.fn(()=>runtime);
 const api=runInNewContext(`${vmSource}\n({assertM8Deck124Checkpoint,assertM8Deck124Runtime,assertM8DeckCaptureAuthority,readM8DeckCaptureAuthority})`,{Buffer,Object,Date,Error,JSON,sha256,M8_COMPOSE,readFileSync:fileRead,execFileSync:exec,process:{env:{DOCKER_HOST:'synthetic-bad',DOCKER_CONTEXT:'synthetic-bad',SAFE:'test'}},configurationRead:vi.fn(),configurationWrite:vi.fn(),assertConfigurationReceipt:vi.fn(),runM8FixedDeck:vi.fn(),m8DeckReadSyncUnusedTail:vi.fn()});
 return{r,actor,area,receipt,authority,failure,diagnosis,runtime,h,api,exec,fileRead};
}
describe('fixed133 known CLI failure continuation',()=>{
 it('accepts only the complete synthetic original tuple without any transport',()=>{const f=fixture();expect(f.api.assertM8Deck124Checkpoint(f.r,f.failure,f.diagnosis).capture.jobId).toBe(f.receipt.jobId);expect(f.exec).not.toHaveBeenCalled();});
 for(const [name,change] of [
  ['count',(r)=>r.requests.pop()],['prepared',(r)=>r.requests[0].state='prepared'],['unknown',(r)=>r.requests[0].state='response_unknown'],['changedSID',(r)=>r.sessions.admin.sid=randomUUID()],
  ['priorTail',(r)=>r.deck124Continuation={state:'prepared'}],['usedDiff',(r)=>r.cliIntents.push({command:'diff'})],['missingActualDiagnostic',(r)=>r.cliDiagnostics=[]],['NativeIncomplete',(r)=>r.approvalTransfer.nativeSteps=16],
  ['wrongCapture',(r)=>r.configurationOperations[0].receipt.snapshotId=randomUUID()],['wrongOldTool',(r)=>r.cliIntents[0].safeResult.toolBinarySha256='0'.repeat(64)],['unknownCLI',(r)=>r.cliIntents[0].state='response_unknown'],['RBACStarted',(r)=>r.rbacJournal={phase:'prepared'}],
 ] as const)it(name+' refuses before any transport',()=>{const f=fixture();change(f.r);expect(()=>f.api.assertM8Deck124Checkpoint(f.r,f.failure,f.diagnosis)).toThrow();expect(f.exec).not.toHaveBeenCalled();});
 it('mutated failed or diagnosis artifact cannot authorize continuation',()=>{const f=fixture();expect(()=>f.api.assertM8Deck124Checkpoint(f.r,Buffer.from('{}'),f.diagnosis)).toThrow();expect(()=>f.api.assertM8Deck124Checkpoint(f.r,f.failure,Buffer.from('{}'))).toThrow();expect(f.exec).not.toHaveBeenCalled();});
});
describe('current expired capture proof is metadata only',()=>{
 it('distinguishes current authority from safe historical receipt and chooses expiry only from actual booleans',()=>{const f=fixture();expect(f.api.assertM8DeckCaptureAuthority(f.authority,f.receipt,f.actor,f.area)).toBe(false);f.authority.job.authority_expired=true;expect(f.api.assertM8DeckCaptureAuthority(f.authority,f.receipt,f.actor,f.area)).toBe(true);f.authority.job.authority_expired=false;f.authority.job.job_expired=true;expect(f.api.assertM8DeckCaptureAuthority(f.authority,f.receipt,f.actor,f.area)).toBe(true);});
 for(const field of ['same_sid','same_actor','same_scope','same_key','same_snapshot'])it(field+' false refuses even when expiry is true',()=>{const f=fixture();f.authority.job.authority_expired=true;f.authority.job[field]=false;expect(()=>f.api.assertM8DeckCaptureAuthority(f.authority,f.receipt,f.actor,f.area)).toThrow();});
 for(const field of ['authority_expired','job_expired'])it(field+' nonboolean refuses',()=>{const f=fixture();f.authority.job[field]='true';expect(()=>f.api.assertM8DeckCaptureAuthority(f.authority,f.receipt,f.actor,f.area)).toThrow();});
 it('protects exact current receipt owner and scope',()=>{const f=fixture();for(const [field,value]of [['actorId',randomUUID()],['workspaceId',randomUUID()],['jobId',randomUUID()],['snapshotId',randomUUID()]])expect(()=>f.api.assertM8DeckCaptureAuthority(f.authority,{...f.receipt,[field]:value},f.actor,f.area)).toThrow();});
 it('compiles the real bounded child source and uses only seven fixed SQL parameters over the trusted local Docker socket',()=>{const f=fixture();expect(f.api.readM8DeckCaptureAuthority(f.h,f.actor,f.area)).toMatchObject({nonOwnerReadOnly:true});const[program,args,opts]=f.exec.mock.calls[0];expect(program).toBe('docker');expect(args[0]).toBe('--host=unix:///var/run/docker.sock');expect(opts.env).toEqual({SAFE:'test'});const text=args.at(-1);expect(text).toContain('READ ONLY');expect(text).toContain("who.role!=='kongos_app'");expect(text).not.toMatch(/\b(?:UPDATE|INSERT|DELETE)\b/);expect(JSON.parse(opts.input)).toMatchObject({cid:f.area.cid,wid:f.area.wid,actorId:f.actor.user.id,sid:f.actor.sid,jobId:f.receipt.jobId,idempotencyKey:f.receipt.idempotencyKey,snapshotId:f.receipt.snapshotId});expect(opts.maxBuffer).toBe(4096);});
});
describe('fixed tool runtime proof',()=>{
 it('requires the actual producer artifact and independently inspects the current fixed tag',()=>{const f=fixture();expect(f.api.assertM8Deck124Runtime(f.h).toolVersion).toBe('1.2.4');expect(f.exec.mock.calls[0][1]).toContain('kongos/deck-runner:1.2.4');});
 it('a modified readiness proof refuses before image inspection',()=>{const f=fixture();f.fileRead.mockReturnValue(Buffer.from('{}'));expect(()=>f.api.assertM8Deck124Runtime(f.h)).toThrow();expect(f.exec).not.toHaveBeenCalled();});
 it('current image mismatch refuses without CLI or network execution',()=>{const f=fixture();f.exec.mockReturnValue('sha256:'+'e'.repeat(64));expect(()=>f.api.assertM8Deck124Runtime(f.h)).toThrow();expect(f.exec).toHaveBeenCalledTimes(1);});
});
