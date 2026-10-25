import {describe,expect,it,vi} from 'vitest';
import {ConfigurationService} from '../../apps/console-api/src/modules/configuration/configuration.service';
import {ConfigurationFailureLedgerService} from '../../apps/console-api/src/modules/configuration/configuration-failure-ledger.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {CONFIGURATION_JOB_PROJECTION_QUERY} from '../../apps/console-api/src/modules/configuration/configuration-job-queries';

const id=(n:number)=>`a8010000-0000-4000-8000-${String(n).padStart(12,'0')}`;
/** Real projection method, real actor frames, and a real unused ledger. This
 * narrow layer substitutes only a server-owned read descriptor/SQL row/current
 * boolean grants; it mints no AccessService, workflow or Native capability.
 * Upstream AccessService anti-IDOR remains covered by its separate tests. */
function fixture(approval=true){
 const owner={id:id(1),username:'synthetic-projection-owner',superAdmin:false},sid=id(2),cid=id(3),wid=id(4),jobId=id(5),ctx=new KongExecutionContextService();
 const job:any={id:jobId,clusterId:cid,workspaceId:wid,kind:'apply',state:'uncertain',revision:5,
  safeProgress:{executionId:id(6),executionRevision:4,planRevision:2,planHash:'a'.repeat(64),leaseGeneration:1,workflowExecutionId:approval?id(7):null,
   abandoned:true,terminalFailureRecorded:true,completedSteps:1,unresolvedSteps:2}};
 const row={idempotency_key:'synthetic-projection-original',workflow_id:approval?id(8):null,plan_id:id(9),actor_id:owner.id,origin_session_id:sid,
  execution_mode:approval?'approval':'direct',approval_required:approval};
 const scope=Object.freeze({clusterId:cid,workspaceId:wid,kind:'workspace',rootIds:[],transportScope:'b'.repeat(64)});
 const state={snapshotsWrite:true,workflowsWrite:true};
 const access:any={description:vi.fn(async()=>Object.freeze({actor:Object.freeze({...owner}),sessionId:sid,scope}))};
 const db:any={one:vi.fn(async(sql:string,p:any[])=>{
  expect(sql).toBe(CONFIGURATION_JOB_PROJECTION_QUERY);
  expect(p).toEqual([jobId,cid,wid,owner.id]);return structuredClone(row);
 }),query:vi.fn(async()=>{throw Error('unexpected projection query');}),exec:vi.fn(async()=>{throw Error('projection may not write');}),transaction:vi.fn(async()=>{throw Error('projection may not enter a transaction');})};
 const authz:any={hasWholeWorkspace:vi.fn(async(actor:any,c:string,w:string,module:string,action:string)=>{
  expect(actor.id).toBe(owner.id);expect([c,w,action]).toEqual([cid,wid,'write']);
  if(module==='snapshots')return state.snapshotsWrite;if(module==='workflows')return state.workflowsWrite;throw Error('unexpected projection permission');
 })};
 const redis:any={},secrets:any={},audit:any={append:vi.fn(async()=>{throw Error('projection may not append audit');})},workspaces:any={};
 const repo:any={createJob:vi.fn(),finishJob:vi.fn()},capture:any={},native:any={execute:vi.fn(),receipt:vi.fn()},workflowPlans:any={},registry:any={},approved:any={},kong:any={request:vi.fn()};
 const ledger=new ConfigurationFailureLedgerService(db,secrets,audit,access,ctx,authz);
 const ledgerCalls=['arm','recordFailure','release','abandon','abandonmentIntent'].map(name=>vi.spyOn(ledger,name as keyof ConfigurationFailureLedgerService));
 const service=new ConfigurationService(db,redis,secrets,ctx,audit,authz,workspaces,access,repo,capture,native,workflowPlans,registry,approved,kong,ledger);
 const descriptor=Object.freeze({});
 const frame=<T>(fn:()=>Promise<T>,options:any={})=>ctx.runHttp({requestId:id(10)},async()=>{
  ctx.bindHttpActor(options.actor??owner,options.sid??sid);const close=ctx.captureHttpCloser();
  try{return await ctx.runActor({actor:options.actor??owner,clusterId:options.cid??cid,workspaceId:options.wid??wid,module:'snapshots',action:'read'},fn);}finally{close();}
 });
 const project=(options:any={})=>frame(()=>service.jobProjection(descriptor as any,job),options);
 const zeroWrites=()=>{
  expect((service as any).failureLedger).toBeInstanceOf(ConfigurationFailureLedgerService);
  for(const spy of ledgerCalls)expect(spy).not.toHaveBeenCalled();
  for(const fn of[db.query,db.exec,db.transaction,audit.append,repo.createJob,repo.finishJob,native.execute,native.receipt,kong.request])expect(fn).not.toHaveBeenCalled();
 };
 return{service,ctx,ledger,authz,access,db,row,job,state,owner,sid,cid,wid,project,zeroWrites};
}

describe('M8 abandoned job current-session projection independent SOURCE',()=>{
 it.each([false,true])('returns only a true safe boolean for exact original current session in approval=%s',async(approval)=>{
  const f=fixture(approval);f.state.workflowsWrite=approval;
  const value=await f.project();expect(value.abandonmentSessionMatches).toBe(true);expect(value.job.abandonmentSessionMatches).toBe(true);
  expect(value).toMatchObject({state:'uncertain',executionCompleted:true,capabilities:{abandon:false,download:false},domain:'configuration',originalScope:{clusterId:f.cid,workspaceId:f.wid}});
  expect(f.authz.hasWholeWorkspace).toHaveBeenCalledTimes(approval?2:1);f.zeroWrites();
 });
 it.each(['sid','actor','cid','wid'])('rejects a foreign current %s using the real actor frame',async(which)=>{
  const f=fixture(),options:any={};options[which]=which==='actor'?{...f.owner,id:id(99)}:id(99);
  const value=await f.project(options);expect(value.abandonmentSessionMatches).toBe(false);expect(value.job.abandonmentSessionMatches).toBe(false);
  expect(f.authz.hasWholeWorkspace).not.toHaveBeenCalled();f.zeroWrites();
 });
 it.each(['snapshotsWrite','workflowsWrite'])('rejects revoked current %s rather than trusting original approval',async(permission)=>{
  const f=fixture();f.state[permission as keyof typeof f.state]=false;const value=await f.project();expect(value.abandonmentSessionMatches).toBe(false);
  expect(f.authz.hasWholeWorkspace).toHaveBeenCalledWith(f.owner,f.cid,f.wid,permission==='snapshotsWrite'?'snapshots':'workflows','write');f.zeroWrites();
 });
 it.each(['partial','plain-uncertain','not-terminal','string-abandoned','string-terminal'])('does not signal abandonment for %s',async(which)=>{
  const f=fixture();if(which==='partial')f.job.state='partial';if(which==='plain-uncertain')delete f.job.safeProgress.abandoned;
  if(which==='not-terminal')f.job.safeProgress.terminalFailureRecorded=false;if(which==='string-abandoned')f.job.safeProgress.abandoned='true';
  if(which==='string-terminal')f.job.safeProgress.terminalFailureRecorded='true';
  const value=await f.project();expect(value.abandonmentSessionMatches).toBe(false);expect(f.authz.hasWholeWorkspace).not.toHaveBeenCalled();f.zeroWrites();
 });
 it('does not match an anonymous real HTTP frame',async()=>{
  const f=fixture(),value=await f.ctx.runHttp({requestId:id(10)},async()=>{const close=f.ctx.captureHttpCloser();try{return await f.service.jobProjection({}as any,f.job);}finally{close();}});
  expect(value.abandonmentSessionMatches).toBe(false);expect(f.authz.hasWholeWorkspace).not.toHaveBeenCalled();f.zeroWrites();
 });
 it('never exposes the original session ID in either public DTO level',async()=>{
  const f=fixture(),value=await f.project();const serialized=JSON.stringify(value);
  expect(serialized).not.toContain(f.sid);expect(serialized).not.toMatch(/origin_session_id|originSessionId|sessionId|session_id/);
  expect(value).not.toHaveProperty('origin_session_id');expect(value.job).not.toHaveProperty('originSessionId');f.zeroWrites();
 });
});
