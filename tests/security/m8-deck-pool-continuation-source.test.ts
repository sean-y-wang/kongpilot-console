// @ts-nocheck -- actual immutable-guard code with synthetic-only SHA anchors.
import {describe,it,expect,vi} from 'vitest';
import {readFileSync} from 'node:fs';
import {Script,runInNewContext} from 'node:vm';
import {randomUUID} from 'node:crypto';
import {sha256,M8_COMPOSE} from './lib/m8-harness.mjs';
const source=readFileSync(new URL('./lib/m8-deck-pool-continuation.mjs',import.meta.url),'utf8');
const check=(v,n)=>{if(!v)throw Error(n)};
function fixture(){
 const actor={user:{id:randomUUID()},sid:randomUUID()},area={cid:randomUUID(),wid:randomUUID()},jobId='0d420e8a-2dc8-44db-ae9c-eecf282700ac',key='ac7fabb3-0530-4520-b720-5d0c321f70be',snapshotId='55c5f346-64a8-448b-b163-c5c9cfcd543f';
 const receipt={jobId,idempotencyKey:key,snapshotId,actorId:actor.user.id,clusterId:area.cid,workspaceId:area.wid},token='a'.repeat(43),sessionId=randomUUID(),yaml='synthetic harmless state';
 const cli=[{command:'validate',state:'response_observed',safeResult:{toolVersion:'1.1.0',exitCode:1}},
  {command:'validate',state:'response_observed',safeResult:{exitCode:0,toolBinarySha256:'642f49fd64e83aff867939705dbd927c5e750b241a99e8539ab22d18930427ed'},input:{stateYaml:yaml}},
  {command:'diff',state:'response_observed',safeResult:{exitCode:1,possibleUnknown:false},input:{stateYaml:yaml}}];
 const input={command:'diff',sessionId,tokenSecret:token,stateYaml:yaml};
 const diagnostic={state:'completed',originalPrefixSha256:'6b5b4f60de043e8a6328c6509a52ff04b222f0808544c4f95b8ebcc8c9a11693',actorId:actor.user.id,sessionId:actor.sid,captureJobId:jobId,deckSessionId:sessionId,input,inputSha256:sha256(JSON.stringify(input))};
 const requests=Array.from({length:137},(_,index)=>({index,state:'response_observed',status:201}));requests[136]={...requests[136],requestId:'d0c4321b-29ec-430a-9a44-b57be784b0de',actorId:actor.user.id,sessionId:actor.sid,clusterId:area.cid,workspaceId:area.wid};
 const r={version:1,milestone:'M8',phase:'stopped-readonly-diff-diagnosis',inFlight:null,requests,deckDiffReadonlyDiagnosis:diagnostic,cliIntents:cli,
  scopes:{direct:area},sessions:{admin:actor},configurationOperations:[{jobId,key,state:'succeeded',receipt}],deckSessions:[{id:randomUUID()},{id:sessionId,tokenSecret:token}],
  baseline:{yaml},c2ModeRestored:true,expiredExecutionRecovery:{state:'completed'},approvalTransfer:{nativeSteps:17},finalHttpUnusedTail:{state:'fixed-cli-unused'},deck124Continuation:{state:'unused-diff-sync'}};
 const failed=Buffer.from(JSON.stringify({allPassed:false,passed:1745,failed:1,unknownWrites:0})),diagnosis=Buffer.from(JSON.stringify({allDiagnosticTransportPassed:true,exitCode:1,newMetadataWrites:1,newAuthWrites:0,newNativeWrites:0})),logs=Buffer.from(JSON.stringify({classification:'SAFE_CAUSE_UNAVAILABLE',currentPacketCount:137}));
 let vmSource=source.replace(/^import[^\n]*\n/gm,'').replace(/\bexport\s+/g,'');
 for(const [old,value]of[
  ['6eb9da45cfe27d28338c34c1c8dc6ba8597ceb6c4891294ade93e75e15016029',sha256(JSON.stringify(requests))],
  ['47cbe0fce649f22f3ca648ccf74234fae0f514fa4d6230dceffdd92f8cfa5495',sha256(JSON.stringify(requests[136]))],
  ['c077b385cafead3166f60b361d7d8d749667e23d04e8c6021b0b92c4f1600d24',sha256(JSON.stringify(diagnostic))],
  ['498e34f2e222e898b74f5ececbd433fc31407c9e122ffc71a66f1d8a2e5e186a',sha256(failed)],
  ['f55b8f68d32beb11d307a5414ab1fa0840e68835a51972274b1e63b181fa1fa2',sha256(diagnosis)],
  ['5b9b29dab73389218e17772f77010d37412d132983168f78052934343b930f90',sha256(logs)],
 ])vmSource=vmSource.replace(old,value);
 const authority={ok:true,nonOwnerReadOnly:true,job:{id:jobId,kind:'capture',state:'succeeded',actor_matches:true,sid_matches:true,key_matches:true,snapshot_matches:true,authority_expired:false,job_expired:false}};
 const exec=vi.fn((p,a,o)=>{new Script(a.at(-1));return JSON.stringify(authority)}),image=vi.fn(),files=vi.fn(),h={check,state:r,save:vi.fn()};
 const api=runInNewContext(vmSource+'\n({assertM8DeckPoolCheckpoint,assertM8DeckPoolCaptureAuthority,readM8DeckPoolCaptureAuthority,assertM8DeckPoolRelease})',
  {Buffer,Object,JSON,Date,Error,Number,sha256,M8_COMPOSE,M8_DECK124_CONTINUATION:{binarySha256:'642f49fd64e83aff867939705dbd927c5e750b241a99e8539ab22d18930427ed'},execFileSync:exec,readFileSync:files,assertM8Deck124Runtime:image,process:{env:{DOCKER_HOST:'synthetic',DOCKER_CONTEXT:'synthetic',SAFE:'synthetic'}},configurationRead:vi.fn(),configurationWrite:vi.fn(),assertConfigurationReceipt:vi.fn(),m8DeckReadSyncUnusedTail:vi.fn()});
 return{r,actor,area,receipt,authority,failed,diagnosis,logs,exec,image,files,h,api};
}
describe('fixed137 standard-origin unused continuation',()=>{
 it('accepts exact synthetic original prefix and known diagnostic without transport',()=>{const f=fixture();expect(f.api.assertM8DeckPoolCheckpoint(f.r,f.failed,f.diagnosis,f.logs).capture.jobId).toBe(f.receipt.jobId);expect(f.exec).not.toHaveBeenCalled()});
 for(const [name,change]of[
  ['packet removed',r=>r.requests.pop()],['packet prepared',r=>r.requests[0].state='prepared'],['packet unknown',r=>r.requests[0].state='response_unknown'],['in flight',r=>r.inFlight=136],
  ['same actor changed',r=>r.sessions.admin.user.id=randomUUID()],['same SID changed',r=>r.sessions.admin.sid=randomUUID()],['capture key changed',r=>r.configurationOperations[0].key=randomUUID()],
  ['snapshot changed',r=>r.configurationOperations[0].receipt.snapshotId=randomUUID()],['RBAC started',r=>r.rbacJournal={}],['continuation reused',r=>r.deckPoolContinuation={state:'prepared'}],
  ['CLI unknown',r=>r.cliIntents[2].state='response_unknown'],['validation absent',r=>r.cliIntents[1].safeResult.exitCode=1],['validation wrong tool',r=>r.cliIntents[1].safeResult.toolBinarySha256='f'.repeat(64)],
  ['new CLI already started',r=>r.cliIntents.push({command:'sync'})],['opaque diagnostic token changed',r=>r.deckSessions[1].tokenSecret='b'.repeat(43)],['original private yaml changed',r=>r.baseline.yaml='changed'],
  ['fresh17 incomplete',r=>r.approvalTransfer.nativeSteps=16],['original failure closure not complete',r=>r.expiredExecutionRecovery.state='prepared'],
 ])it(name+' rejects before transport',()=>{const f=fixture();change(f.r);expect(()=>f.api.assertM8DeckPoolCheckpoint(f.r,f.failed,f.diagnosis,f.logs)).toThrow();expect(f.exec).not.toHaveBeenCalled()});
 it('rejects changed historical reports independently',()=>{const f=fixture();for(let i=0;i<3;i++){const a=[f.failed,f.diagnosis,f.logs];a[i]=Buffer.from('{}');expect(()=>f.api.assertM8DeckPoolCheckpoint(f.r,...a)).toThrow()}expect(f.exec).not.toHaveBeenCalled()});
});
describe('current capture expiry uses only exact non-owner metadata',()=>{
 it('does not infer expiry from safe receipt and accepts only actual boolean expiry',()=>{const f=fixture();expect(f.api.assertM8DeckPoolCaptureAuthority(f.authority,f.receipt,f.actor,f.area)).toBe(false);f.authority.job.authority_expired=true;expect(f.api.assertM8DeckPoolCaptureAuthority(f.authority,f.receipt,f.actor,f.area)).toBe(true);f.authority.job.authority_expired=false;f.authority.job.job_expired=true;expect(f.api.assertM8DeckPoolCaptureAuthority(f.authority,f.receipt,f.actor,f.area)).toBe(true)});
 for(const key of['actor_matches','sid_matches','key_matches','snapshot_matches'])it(key+' false never licenses fresh capture',()=>{const f=fixture();f.authority.job.authority_expired=true;f.authority.job[key]=false;expect(()=>f.api.assertM8DeckPoolCaptureAuthority(f.authority,f.receipt,f.actor,f.area)).toThrow()});
 it('executes exactly one bounded readonly program with original seven scope parameters and no Docker override',()=>{const f=fixture();expect(f.api.readM8DeckPoolCaptureAuthority(f.h,f.actor,f.area)).toEqual(f.authority);const [p,a,o]=f.exec.mock.calls[0];expect(a[0]).toBe('--host=unix:///var/run/docker.sock');expect(a).toContain('console-api');expect(o.env).toEqual({SAFE:'synthetic'});expect(JSON.parse(o.input)).toEqual({cid:f.area.cid,wid:f.area.wid,actorId:f.actor.user.id,sid:f.actor.sid,jobId:f.receipt.jobId,key:f.receipt.idempotencyKey,snapshotId:f.receipt.snapshotId});expect(a.at(-1)).toContain('READ ONLY');expect(a.at(-1)).not.toMatch(/UPDATE |INSERT |DELETE |decrypt/i)});
 it('runtime release remains fail-closed with missing or altered producer evidence',()=>{const f=fixture();f.files.mockReturnValue(Buffer.from('{}'));expect(()=>f.api.assertM8DeckPoolRelease(f.h)).toThrow();expect(f.image).not.toHaveBeenCalled();expect(f.exec).not.toHaveBeenCalled()});
});
