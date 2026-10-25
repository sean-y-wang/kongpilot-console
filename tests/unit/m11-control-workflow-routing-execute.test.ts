import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {createControlWorkflowRoutingFixture,CONTROL_ROUTING_SQL005_SEED} from '../fixtures/m11-control-workflow-routing.fixture';

beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','6d'.repeat(32));vi.stubEnv('APP_SECRET','control-routing-test-key-more-than-32-bytes');vi.stubEnv('OUTBOUND_ALLOWED_HOSTS','192.0.2.11,192.0.2.12,192.0.2.13');});
afterEach(()=>vi.unstubAllEnvs());

/** Actual Root WorkflowService entry/recursive routing/snapshot/dispatch/
 * metadata terminal tail, actual Main/Business/private completion and real
 * shared validator. SQL, approval-set transport and Root Approved issuance
 * are fixtures; these assertions are not runtime SQL or HTTP acceptance. */
describe('M11 real Root control workflow execution and original-key receipts',()=>{
 it('executes the actual Root dispatcher and private Main completion after a cluster mode switch',async()=>{
  const f=createControlWorkflowRoutingFixture(),prepared=await f.prepare();await f.submit(prepared);f.approveFixture();
  const completion=vi.spyOn(f.workflow,'verifyMetadataCompletion'),receipt=await f.executeRoot();
  expect(receipt).toMatchObject({kind:'control-metadata',state:'succeeded',propagation:'acknowledged',steps:[{operationId:null,remoteStarted:false,remoteCompleted:true}]});
  expect(f.state().cluster).toMatchObject({execution_mode:'direct',revision:3,name:'Approved production'});expect(f.state().facts.size).toBe(1);expect(completion).toHaveBeenCalledOnce();
  expect(completion.mock.calls[0][0].transaction).toBe(f.tx);expect(f.state().rootExecutions.size).toBe(1);expect([...f.state().rootExecutions.values()][0]).toMatchObject({state:'succeeded',snapshot_state:'ready'});
  expect(f.approved.assertNative).not.toHaveBeenCalled();expect(f.approved.mutationBinding).not.toHaveBeenCalled();expect(f.operations.execute).not.toHaveBeenCalled();expect(f.mutations.execute).not.toHaveBeenCalled();
  const writes=f.writes.length,replay=await f.receiptRoot();expect(replay).toMatchObject({state:'succeeded',kind:'control-metadata',idempotencyKey:'control-root-execute-key',action:'execute'});expect(f.writes).toHaveLength(writes);
 });
 it('lets original-key GET locate a completed soft-deactivated cluster without re-adopting its old scope authority',async()=>{
  const f=createControlWorkflowRoutingFixture(),p=await f.prepare({resource:'clusters',operation:'deactivate',resourceId:f.cid,input:{revision:2,confirm:true,confirm_name:'Production'}});await f.submit(p);f.approveFixture();await f.executeRoot();
  expect(f.state().cluster).toMatchObject({status:'disabled',revision:3});expect(f.state().cluster.deleted_at).toBeTruthy();
  const writes=f.writes.length,receipt=await f.receiptRoot(),detail=await f.http(()=>f.root.get(f.cid,f.plan().workflowId,f.author));
  expect(receipt).toMatchObject({state:'succeeded',action:'execute',kind:'control-metadata'});expect(detail).toMatchObject({entity:{state:'succeeded',capabilities:{approve:false,execute:false}},diff:[],impact:{nativeRequests:0}});
  expect(f.writes).toHaveLength(writes);expect(JSON.stringify([receipt,detail])).not.toContain('192.0.2.11');expect(JSON.stringify([receipt,detail])).not.toContain('connection_secret');
 });
 it('commits the exact SQL005 workspace seed plus the true Root metadata terminal tail in one original transaction',async()=>{
  const f=createControlWorkflowRoutingFixture(),p=await f.prepare({resource:'workspaces',operation:'create',input:{code:'root_team',name:'Root workspace'}});await f.submit(p);f.approveFixture();const receipt=await f.executeRoot();
  expect(receipt.state).toBe('succeeded');expect(f.state().epoch).toBe(10+CONTROL_ROUTING_SQL005_SEED.epochDelta);expect(f.state().seedRoles.size).toBe(3);expect(f.state().seedPermissions.size).toBe(265);
  const fact:any=[...f.state().facts.values()][0];expect(fact.before_permission_version).toBe(`${f.userId}:7:10`);expect(fact.after_permission_version).toBe(`${f.userId}:7:278`);
  const terminalWrites=f.calls.filter(c=>c.sql.includes("SET state='succeeded'"));expect(terminalWrites).toHaveLength(3);expect(terminalWrites.every(c=>c.name==='tx')).toBe(true);expect(f.approved.assertNative).not.toHaveBeenCalled();
  const e:any=[...f.state().rootExecutions.values()][0],snapshot=f.secrets.decrypt<any>(e.snapshot_secret,`workflow:${f.cid}:${f.wid}:${f.plan().workflowId}:${e.id}:snapshot`);
  expect(snapshot).toMatchObject({version:1,objects:[],workflowId:f.plan().workflowId,executionId:e.id});
 });
 it('routes the genuinely deleted target selector into its default anchor using an original HTTP child with target-only grants',async()=>{
  const f=createControlWorkflowRoutingFixture();Object.assign(f.state().workspaces.get(f.targetWid),{status:'deleted',deleted_at:new Date().toISOString(),retention_until:new Date(Date.now()+86400000).toISOString()});
  const grant=(module:string,action:string)=>({module,action,scope_type:'workspace',cluster_id:f.cid,workspace_id:f.targetWid,scope_values:[f.targetWid]});
  f.state().grants.set(f.userId,['workspaces','workflows'].flatMap(m=>['read','write'].map(a=>grant(m,a))));
  const p=await f.prepare({resource:'workspaces',operation:'restore',resourceId:f.targetWid,input:{revision:5,confirmed:true,confirm_name:'Payments'}});await f.submit(p);f.approveFixture();
  const actor={...f.author,workspaceId:f.targetWid,idempotencyKey:'restore-target-execution-key'},runHttp=vi.spyOn(f.context,'runHttp'),bind=vi.spyOn(f.context,'bindHttpActor'),frames:any[]=[],original=f.context.runActor.bind(f.context);
  vi.spyOn(f.context,'runActor').mockImplementation((options,fn)=>original(options,async()=>{const frame=f.context.current();frames.push({frame,workspaceId:frame.workspaceId,sessionId:frame.sessionId,limits:{...frame.limits}});return fn();}));
  const receipt=await f.executeRoot(actor);expect(receipt).toMatchObject({state:'succeeded',workspaceId:f.wid,scopeSelectorWorkspaceId:f.targetWid});expect(f.state().workspaces.get(f.targetWid)).toMatchObject({status:'active',revision:6});
  expect(runHttp).toHaveBeenCalledOnce();expect(bind).toHaveBeenCalledOnce();expect(frames.some(v=>v.workspaceId===f.targetWid)).toBe(true);expect(frames.some(v=>v.workspaceId===f.wid)).toBe(true);expect(frames.every(v=>v.sessionId===f.sid)).toBe(true);
  expect(frames.every(v=>v.limits.timeoutMs===frames[0].limits.timeoutMs&&v.limits.maxCalls===frames[0].limits.maxCalls)).toBe(true);expect(f.approved.assertNative).not.toHaveBeenCalled();
  expect(f.plans.load.mock.calls.some(([cid,wid]:any[])=>cid===f.cid&&wid===f.wid)).toBe(true);
  const writes=f.writes.length;expect(await f.receiptRoot(actor.idempotencyKey,actor)).toMatchObject({state:'succeeded',scopeSelectorWorkspaceId:f.targetWid,action:'execute'});expect(f.writes).toHaveLength(writes);
 });
 it('returns the original target-selector receipt after the actual workspace has been archived',async()=>{
  const f=createControlWorkflowRoutingFixture(),p=await f.prepare({resource:'workspaces',operation:'archive',resourceId:f.targetWid,input:{revision:5,confirmed:true,confirm_name:'Payments'}});await f.submit(p);f.approveFixture();const actor={...f.author,workspaceId:f.targetWid,idempotencyKey:'archive-target-execution-key'};
  await f.executeRoot(actor);expect(f.state().workspaces.get(f.targetWid)).toMatchObject({status:'deleted',revision:6});expect(f.kong.list).toHaveBeenCalledTimes(8);
  const writes=f.writes.length,receipt=await f.receiptRoot(actor.idempotencyKey,actor);expect(receipt).toMatchObject({state:'succeeded',scopeSelectorWorkspaceId:f.targetWid,action:'execute'});expect(f.writes).toHaveLength(writes);
 });
});
