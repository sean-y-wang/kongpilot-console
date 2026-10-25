import 'reflect-metadata';
import {beforeEach,afterEach,describe,it,expect,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {createControlWorkflowRoutingFixture} from '../fixtures/m11-control-workflow-routing.fixture';

/** The real shared WorkflowService routes through the frozen genuine Control
 * service, business compiler, SQL005 seed verifier and Context ALS. Storage,
 * Redis and Root's private Approval issuer are explicit fixture transports.
 * This suite is not real SQL, HTTP or deployment acceptance. */
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','6d'.repeat(32));vi.stubEnv('APP_SECRET','control-metadata-test-signing-key-more-than-32-bytes');vi.stubEnv('OUTBOUND_ALLOWED_HOSTS','192.0.2.11,192.0.2.12,192.0.2.13');});
afterEach(()=>vi.unstubAllEnvs());

const workspaceGrant=(cid:string,wid:string,module:string,action:string)=>({module,action,scope_type:'workspace',cluster_id:cid,workspace_id:wid,scope_values:[wid]});
async function restoredTargetPlan(){
 const f=createControlWorkflowRoutingFixture();Object.assign(f.state().workspaces.get(f.targetWid),{status:'deleted',deleted_at:new Date().toISOString(),retention_until:new Date(Date.now()+86400000).toISOString()});
 f.state().grants.set(f.userId,['workspaces','workflows'].flatMap(module=>['read','write'].map(action=>workspaceGrant(f.cid,f.targetWid,module,action))));
 f.state().grants.set(f.reviewerId,['workspaces','workflows'].flatMap(module=>(module==='workflows'?['read','approve']:['read']).map(action=>workspaceGrant(f.cid,f.targetWid,module,action))));
 const prepared=await f.prepare({resource:'workspaces',operation:'restore',resourceId:f.targetWid,input:{revision:5,confirmed:true,confirm_name:'Payments'}});await f.submit(prepared);
 return {f,prepared,actor:{...f.author,workspaceId:f.targetWid},reviewer:{...f.reviewer,workspaceId:f.targetWid}};
}

describe('M11 shared Control read routing and exact scope admission',()=>{
 it('loads and reviews a genuine archived target using only target grants and its default plan anchor',async()=>{
  const {f,actor}=await restoredTargetPlan(),plan=f.plan(),read=await f.http(()=>f.root.get(f.cid,plan.workflowId,actor),actor);
  expect(read.entity).toMatchObject({id:plan.workflowId,kind:'control-metadata',workspaceId:f.wid,scopeSelectorWorkspaceId:f.targetWid,state:'pending'});
  expect(read.diff).toEqual(expect.arrayContaining([expect.objectContaining({kind:'metadata',operation:'restore',entityType:'workspaces',entityId:f.targetWid})]));
  expect(read.impact).toMatchObject({affectedScopes:[expect.objectContaining({workspaceId:f.targetWid})]});
  expect(f.state().grants.get(f.userId).every((g:any)=>g.workspace_id===f.targetWid)).toBe(true);
  expect(f.kong.list).not.toHaveBeenCalled();expect(f.state().facts.size).toBe(0);
 });
 it('returns a read-only target-bound review to its currently authorized reviewer',async()=>{
  const {f,reviewer}=await restoredTargetPlan(),read=await f.http(()=>f.root.get(f.cid,f.plan().workflowId,reviewer),reviewer);
  expect(read.entity.capabilities.execute).toBe(false);expect(read.entity.scopeSelectorWorkspaceId).toBe(f.targetWid);
  expect(read.diff[0].entityId).toBe(f.targetWid);expect(f.state().facts.size).toBe(0);
 });
 it.each(['actor-wid','frame-wid','frame-cluster'])('does not reinterpret a foreign %s as the default anchor on a get',async variant=>{
  const {f,actor}=await restoredTargetPlan(),foreign=randomUUID(),actual={...actor,workspaceId:variant==='actor-wid'?foreign:actor.workspaceId};
  if(variant==='actor-wid')await expect(f.http(()=>f.root.get(f.cid,f.plan().workflowId,actual),actual)).rejects.toThrow();
  else await expect(f.http(()=>f.context.runActor({actor:actual.user,clusterId:variant==='frame-cluster'?foreign:f.cid,workspaceId:variant==='frame-wid'?foreign:f.targetWid,module:'workflows',action:'read'},
   ()=> (f.root as any).loadForAction(f.cid,f.plan().workflowId,actual,'read')),actual)).rejects.toThrow();
  expect(f.kong.list).not.toHaveBeenCalled();expect(f.state().facts.size).toBe(0);
 });
 it.each(['read','workflow-read','revoked-sid','credential-epoch'])('checks current %s before returning historical review content',async variant=>{
  const {f,actor}=await restoredTargetPlan();
  if(variant==='read')f.state().grants.set(f.userId,f.state().grants.get(f.userId).filter((g:any)=>g.module!=='workspaces'||g.action!=='read'));
  if(variant==='workflow-read')f.state().grants.set(f.userId,f.state().grants.get(f.userId).filter((g:any)=>g.module!=='workflows'||g.action!=='read'));
  if(variant==='revoked-sid')f.state().sessions.get(f.sid).revoked_at=new Date().toISOString();
  if(variant==='credential-epoch')f.state().users.get(f.userId).credential_epoch++;
  await expect(f.http(()=>f.root.get(f.cid,f.plan().workflowId,actor),actor)).rejects.toThrow();expect(f.state().facts.size).toBe(0);
 });
 it('rejects another owner trying to execute or inspect a known original Control intent receipt',async()=>{
  const {f,prepared,reviewer}=await restoredTargetPlan();
  await expect(f.http(()=>f.workflow.receipt(f.cid,prepared.intentId as string,reviewer),reviewer)).rejects.toMatchObject({response:{code:'CONTROL_INTENT_OWNER_REQUIRED'}});
  await expect(f.http(()=>f.root.execute(f.cid,f.plan().workflowId,{revision:1,planHash:f.secrets.fingerprint(f.plan()),confirmed:true,confirm_name:'control-metadata'},reviewer),reviewer)).rejects.toThrow();
  expect(f.state().facts.size).toBe(0);expect(f.kong.list).not.toHaveBeenCalled();
 });
});

describe('M11 bounded Control list routing',()=>{
 it.each(['mode-switch','archive'])('keeps an original-author %s completion visible as minimal read-only facts',async variant=>{
  const f=createControlWorkflowRoutingFixture();
  const p=variant==='mode-switch'?await f.prepare():await f.prepare({resource:'workspaces',operation:'archive',resourceId:f.targetWid,input:{revision:5,confirmed:true,confirm_name:'Payments'}});
  await f.submit(p);f.approveFixture();const actor=variant==='archive'?{...f.author,workspaceId:f.targetWid,idempotencyKey:'terminal-list-original-key'}:f.author;
  await f.executeRoot(actor);const writes=f.writes.length;
  const list=await f.http(()=>f.root.list(f.cid,{size:5,view:'submitted'},actor),actor);
  expect(list.items).toHaveLength(1);expect(list.items[0]).toMatchObject({id:f.plan().workflowId,state:'succeeded',scopeSelectorWorkspaceId:actor.workspaceId,capabilities:{approve:false,reject:false,cancel:false,execute:false}});
  expect(list.items[0]).not.toHaveProperty('approval');expect(list.items[0]).not.toHaveProperty('diff');
  expect(f.writes).toHaveLength(writes);expect(JSON.stringify(list)).not.toContain('192.0.2.11');
 });
 it('filters a stale current domain scope for other readers instead of failing the whole bounded page',async()=>{
  const f=createControlWorkflowRoutingFixture(),p=await f.prepare();await f.submit(p);f.approveFixture();await f.executeRoot();
  const list=await f.http(()=>f.root.list(f.cid,{size:5},f.reviewer),f.reviewer);
  expect(list.items).toEqual([]);expect(f.mutations.execute).not.toHaveBeenCalled();
 });
 it('never converts plan corruption into a filtered historical row',async()=>{
  const f=createControlWorkflowRoutingFixture(),p=await f.prepare();await f.submit(p);f.approveFixture();await f.executeRoot();
  f.state().workflows.get(f.plan().workflowId).plan_hash='a'.repeat(64);
  await expect(f.http(()=>f.root.list(f.cid,{size:5},f.author))).rejects.toMatchObject({response:{code:'FIXTURE_PLAN_HASH_CHANGED'}});
 });
 it('does not expose terminal facts to the same user through a different authoring session',async()=>{
  const f=createControlWorkflowRoutingFixture(),p=await f.prepare();await f.submit(p);f.approveFixture();await f.executeRoot();
  const list=await f.http(()=>f.root.list(f.cid,{size:5},f.author),f.author,f.otherSid);expect(list.items).toEqual([]);
 });
 it('includes the sealed restoration target from its real intent without granting default-workspace reads',async()=>{
  const {f,actor}=await restoredTargetPlan(),result=await f.http(()=>f.root.list(f.cid,{size:5,view:'all'},actor),actor);
  expect(result.items).toHaveLength(1);expect(result.items[0]).toMatchObject({id:f.plan().workflowId,workspaceId:f.wid,scopeSelectorWorkspaceId:f.targetWid});
  expect(result.total).toBeNull();expect(result.size).toBe(5);expect(f.state().grants.get(f.userId).some((g:any)=>g.workspace_id===f.wid)).toBe(false);
  const call=f.db.query.mock.calls.find(([sql]:any)=>sql.includes('SELECT * FROM workflows w'));
  expect(call?.[0]).toContain('EXISTS(SELECT 1 FROM control_change_intents');expect(call?.[0]).toContain('i.resource_id=$2');expect(call?.[0]).toContain('LIMIT $6 OFFSET $7');
  expect(call?.[1]).toEqual([f.cid,f.targetWid,null,'all',f.userId,5,0,true]);
 });
 it('filters a coarse-discovered Control plan if the real target READ privilege is missing',async()=>{
  const {f,actor}=await restoredTargetPlan();f.state().grants.set(f.userId,f.state().grants.get(f.userId).filter((g:any)=>g.module!=='workspaces'||g.action!=='read'));
  const result=await f.http(()=>f.root.list(f.cid,{size:5},actor),actor);expect(result.items).toEqual([]);expect(f.state().facts.size).toBe(0);
 });
 it('does not list the archived target intent under a foreign workspace grant',async()=>{
  const {f,actor}=await restoredTargetPlan(),foreign=randomUUID();f.state().workspaces.set(foreign,{...f.state().workspaces.get(f.targetWid),id:foreign,code:'foreign',status:'active',deleted_at:null});
  f.state().grants.set(f.userId,['workspaces','workflows'].map(module=>workspaceGrant(f.cid,foreign,module,'read')));
  const selected={...actor,workspaceId:foreign},result=await f.http(()=>f.root.list(f.cid,{size:5},selected),selected);expect(result.items).toEqual([]);expect(f.kong.list).not.toHaveBeenCalled();
 });
 it('lists only real eligible target approvals and never a self-approval',async()=>{
  const {f,actor,reviewer}=await restoredTargetPlan(),authorRows=await f.http(()=>f.root.list(f.cid,{size:5,view:'pending-my-approval'},actor),actor),reviewRows=await f.http(()=>f.root.list(f.cid,{size:5,view:'pending-my-approval'},reviewer),reviewer);
  expect(authorRows.items).toEqual([]);expect(reviewRows.items.map((r:any)=>r.id)).toEqual([f.plan().workflowId]);expect(reviewRows.items[0].capabilities.approve).toBe(true);
 });
 it.each(['permission-epoch','session-revoke'])('rejects an asynchronous %s change before returning a bounded list',async variant=>{
  const {f,actor}=await restoredTargetPlan(),original=f.plans.load.getMockImplementation()!;
  f.plans.load.mockImplementation(async(...args:any[])=>{const loaded=await original(...args);if(variant==='permission-epoch')f.state().users.get(f.userId).permissions_epoch++;else f.state().sessions.get(f.sid).revoked_at=new Date().toISOString();return loaded;});
  await expect(f.http(()=>f.root.list(f.cid,{size:5},actor),actor)).rejects.toThrow();expect(f.state().facts.size).toBe(0);
 });
});

describe('M11 genuine Control decision admission',()=>{
 it.each(['self-approval','foreign-selector','revoked-approve','wrong-plan-hash','missing-stage'])('rejects %s before recording any vote or mutation',async variant=>{
  const {f,actor,reviewer}=await restoredTargetPlan(),plan=f.plan(),actual={...(variant==='self-approval'?actor:reviewer),idempotencyKey:'control-routing-decision-key'},body:any={revision:1,planHash:f.secrets.fingerprint(plan),confirmed:true,confirm_name:'control-metadata',level:1,stageRevision:1,candidateVersion:1};
  if(variant==='foreign-selector')actual.workspaceId=randomUUID();
  if(variant==='revoked-approve')f.state().grants.set(f.reviewerId,f.state().grants.get(f.reviewerId).filter((g:any)=>g.module!=='workflows'||g.action!=='approve'));
  if(variant==='wrong-plan-hash')body.planHash='a'.repeat(64);if(variant==='missing-stage')delete body.candidateVersion;
  const before=f.writes.length;await expect(f.http(()=>f.root.decide(f.cid,plan.workflowId,'approve',body,actual),actual)).rejects.toThrow();
  expect(f.writes).toHaveLength(before);expect(f.state().facts.size).toBe(0);expect(f.kong.list).not.toHaveBeenCalled();
 });
});
