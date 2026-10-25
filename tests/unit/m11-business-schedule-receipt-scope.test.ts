import 'reflect-metadata';
import {randomUUID} from 'node:crypto';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {WorkflowScheduledAuthorityService} from '../../apps/console-api/src/modules/workflows/workflow-scheduled-authority.service';
import {m11ScheduleReceiptFixture} from './helpers/m11-schedule-receipt-fixture';

beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','d2'.repeat(32));vi.stubEnv('APP_SECRET','source-receipt-scope-'.repeat(3));
 vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-15T08:00:00.000Z'));});
afterEach(()=>{vi.useRealTimers();vi.unstubAllEnvs();});

type Fixture=ReturnType<typeof m11ScheduleReceiptFixture>;
function closedExecution(f:Fixture){
 expect(f.approvalFacts).not.toHaveBeenCalled();
 expect(f.native).not.toHaveBeenCalled();expect(f.plans.load).not.toHaveBeenCalled();expect(f.approved.assertSubject).not.toHaveBeenCalled();
 expect(f.db.exec).not.toHaveBeenCalled();expect(f.audit.append).not.toHaveBeenCalled();expect(f.redis.assertLeaseOwnership).not.toHaveBeenCalled();
 expect(f.schedules.receiptReadActive()).toBe(false);
}
const get=(f:Fixture)=>f.run(()=>f.schedules.get(f.cid,f.entry.stored.draft.scheduleId,f.actor));

describe('real schedule receipt scope authorizes historical DTOs without executable subjects',()=>{
 it.each(['configuration_v2','portal-credential-issue'] as const)('returns current safe %s DTOs through get/list/key lookup with current SQL grants',async kind=>{
  const f=m11ScheduleReceiptFixture(kind),rootRead=vi.spyOn(f.runtime as any,'assertReceiptRead');
  const expected=f.receipt(f.entry.stored);
  await expect(get(f)).resolves.toEqual({entity:expected});
  const list:any=await f.run(()=>f.schedules.list(f.cid,{workspaceId:f.wid,size:10},f.actor));expect(list.items).toEqual([expected]);
  await expect(f.run(()=>f.schedules.receiptByKey(f.cid,f.entry.key,f.actor))).resolves.toEqual({entity:expected,commandCompleted:true});
  expect(rootRead.mock.calls.length).toBeGreaterThanOrEqual(9);
  expect(f.repository.get).toHaveBeenCalledTimes(3);expect(f.db.query.mock.calls.some(([sql]:any[])=>sql.includes('iam_effective_grants'))).toBe(true);
  expect(expected.nativeAuthority).toBe(false);expect(JSON.stringify(expected)).not.toContain('controlled-receipt-key');
  expect(f.entry.version.created_by).toBe(f.owner);expect(f.entry.version.created_by_developer_id).toBeNull();closedExecution(f);
 });

 it.each(['succeeded','partial','failed','uncertain','blocked','cancelled','expired'] as const)('keeps %s history readable after the original window and owner epoch expire',async terminal=>{
  const f=m11ScheduleReceiptFixture();f.entry.stored.progress.state=terminal;f.entry.jobState=terminal;
  expect(f.state.credentialEpoch).not.toBe(f.entry.originalDelegationEpoch);
  vi.setSystemTime(new Date(Date.parse(f.entry.stored.plan.expiresAt)+60000));
  const result:any=await get(f);expect(result.entity.state).toBe(terminal);expect(result.entity.nativeAuthority).toBe(false);closedExecution(f);
 });

 it('projects current repository state rather than arbitrary historical audit receipt fields',async()=>{
  const f=m11ScheduleReceiptFixture();f.entry.stored.progress.state='partial';
  const result:any=await f.run(()=>f.schedules.receiptByKey(f.cid,f.entry.key,f.actor));
  expect(result).toEqual({entity:f.receipt(f.entry.stored),commandCompleted:true});
  expect(result.entity.state).toBe('partial');expect(JSON.stringify(result)).not.toContain('must-never-project');closedExecution(f);
 });

 it('reads an actual sealed Promote receipt without reopening its old source origin',async()=>{
  const f=m11ScheduleReceiptFixture('configuration_v2',true),seal=f.entry.stored.draft.binding.subjectSeal;
  expect(seal.driver).toBe('governance-promote');expect(seal.sourceScopes).toHaveLength(1);
  expect(f.entry.stored.draft.delegation.subjectSealHmac).toBe(f.secrets.fingerprint(seal));
  vi.setSystemTime(new Date(Date.parse(f.entry.stored.plan.expiresAt)+60000));
  await expect(get(f)).resolves.toEqual({entity:f.receipt(f.entry.stored)});closedExecution(f);
 });

 it.each(['inactive user','password-change restriction'] as const)('rejects a current %s despite possession of the old receipt ID',async changed=>{
  const f=m11ScheduleReceiptFixture();if(changed==='inactive user')f.state.userActive=false;else f.state.forcePasswordChange=true;
  await expect(get(f)).rejects.toBeDefined();closedExecution(f);
 });

 it('reads the old immutable version after a later workflow revision exists',async()=>{
  const f=m11ScheduleReceiptFixture();f.entry.workflow.plan_revision=2;f.entry.workflow.plan_hash='a'.repeat(64);
  const result:any=await get(f);expect(result.entity.workflowPlanRevision).toBe(1);closedExecution(f);
 });

 it.each(['workflows','snapshots','portal'] as const)('requires current whole-workspace %s read rather than a copied or partial grant',async module=>{
  const f=m11ScheduleReceiptFixture(module==='portal'?'portal-credential-issue':'configuration_v2');
  f.state.grants=f.state.grants.filter((g:any)=>g.module!==module);
  await expect(get(f)).rejects.toBeDefined();closedExecution(f);
 });

 it('does not accept an unrelated workspace snapshots read grant',async()=>{
  const f=m11ScheduleReceiptFixture();f.state.grants=f.state.grants.map((g:any)=>g.module==='snapshots'?f.grant('snapshots','read',randomUUID()):g);
  await expect(get(f)).rejects.toBeDefined();closedExecution(f);
 });

 it.each(['SID','permission version','workflows grant','snapshots grant'] as const)('rechecks %s after entering the actual repository read',async changed=>{
  const f=m11ScheduleReceiptFixture();f.state.onGet=async()=>{
   if(changed==='SID')f.state.sessionLive=false;
   else if(changed==='permission version')f.state.permissionsEpoch='8';
   else f.state.grants=f.state.grants.filter((g:any)=>g.module!==changed.split(' ')[0]);
  };
  await expect(get(f)).rejects.toBeDefined();closedExecution(f);
 });

 it.each(['workflow subject','version counter','job actor','configuration tuple'] as const)('rejects corrupted current %s bindings even for a terminal receipt',async changed=>{
  const f=m11ScheduleReceiptFixture();
  if(changed==='workflow subject')f.entry.workflow.subject_id=randomUUID();
  else if(changed==='version counter')f.entry.version.native_request_count=1;
  else if(changed==='job actor')f.entry.job.actor_id=randomUUID();
  else f.entry.configuration.plan_hash='e'.repeat(64);
  await expect(get(f)).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_RECEIPT_BINDING_INVALID'}});closedExecution(f);
 });

 it.each(['developer','publication','credential generation','key fingerprint'] as const)('rejects changed Portal %s bindings without Native access',async changed=>{
  const f=m11ScheduleReceiptFixture('portal-credential-issue');
  if(changed==='developer')f.entry.portal.application.developer_id=randomUUID();
  else if(changed==='publication')f.entry.portal.publication.service_id=randomUUID();
  else if(changed==='credential generation')f.entry.portal.credential.generation=2;
  else f.entry.portal.credential.key_fingerprint='d'.repeat(64);
  await expect(get(f)).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_RECEIPT_BINDING_INVALID'}});closedExecution(f);
 });

 it('detects valid-shaped SQL changes between the two binding reads',async()=>{
  const f=m11ScheduleReceiptFixture();let reads=0;
  f.state.onSql=async(sql:string)=>{if(sql.includes('FROM workflows')&&++reads===2){f.entry.workflow.plan_revision=2;f.entry.workflow.plan_hash='c'.repeat(64);}};
  await expect(get(f)).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_MATERIAL_CHANGED'}});
  expect(reads).toBe(2);closedExecution(f);
 });

 it('filters a revoked item from list instead of disclosing its terminal DTO',async()=>{
  const f=m11ScheduleReceiptFixture();f.state.onGet=async()=>{f.state.grants=f.state.grants.filter((g:any)=>g.module!=='snapshots');};
  const result:any=await f.run(()=>f.schedules.list(f.cid,{workspaceId:f.wid,size:10},f.actor));expect(result.items).toEqual([]);closedExecution(f);
 });
});

describe('receipt capabilities stay private to the actual callback and frame',()=>{
 it('rejects the old incomplete business callback contract at installation',()=>{
  const f=m11ScheduleReceiptFixture();
  const authority=new WorkflowScheduledAuthorityService(f.db,f.secrets,f.redis,f.context,f.plans,{} as any,f.repository);
  expect(()=>authority.installBusinessPolicy('configuration_v2',{assertDraft:async()=>{},assertRequester:async()=>{},assertSubject:async()=>{},assertReviewer:async()=>{}} as any)).toThrow();
  closedExecution(f);
 });

 it('cannot mint a scope from copied stored DTOs outside a real Service read',async()=>{
  const f=m11ScheduleReceiptFixture();
  await f.run(()=>expect(f.schedules.assertReceiptReadScope(structuredClone(f.entry.stored),f.actor,f.db)).rejects.toBeDefined());
  await get(f);await f.run(()=>expect(f.scope()).rejects.toBeDefined());closedExecution(f);
 });

 it('keeps a no-scope command with an old receipt key on ordinary subject authorization before replay',async()=>{
  const f=m11ScheduleReceiptFixture();f.actor.idempotencyKey=f.entry.key;
  await expect(f.run(()=>f.schedules.command(f.cid,f.entry.stored.draft.scheduleId,'activate',
   {revision:5,confirmed:true,confirm_name:'activate-schedule'},f.actor))).rejects.toThrow('OLD_PROMOTE_ORIGIN_LOAD_FORBIDDEN');
  expect(f.schedules.receiptReadActive()).toBe(false);expect(f.plans.load).toHaveBeenCalledOnce();
  expect(f.repository.get).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();expect(f.native).not.toHaveBeenCalled();
 });

 it.each(['actor object','transaction','schedule ID','workflow ID','cluster ID','workspace ID','sealed material'] as const)('rejects copied or mismatched %s within the original scope',async changed=>{
  const f=m11ScheduleReceiptFixture();let checked=false;
  f.state.onGet=async()=>{
   const stored=structuredClone(f.entry.stored);let actor=f.actor,tx=f.db;
   if(changed==='actor object')actor={...f.actor};else if(changed==='transaction')tx={...f.db};
   else if(changed==='schedule ID')stored.draft.scheduleId=randomUUID();else if(changed==='workflow ID')stored.plan.workflowId=randomUUID();
   else if(changed==='cluster ID')stored.plan.clusterId=randomUUID();else if(changed==='workspace ID')stored.plan.workspaceId=randomUUID();
   else stored.draft.delegation.statement='copied-different-statement';
   await expect(f.schedules.assertReceiptReadScope(stored,actor,tx)).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_ORIGINAL_RECEIPT_SCOPE_REQUIRED'}});checked=true;
  };
  await get(f);expect(checked).toBe(true);closedExecution(f);
 });

 it('does not lend its scope to a second authenticated schedule DTO',async()=>{
  const f=m11ScheduleReceiptFixture(),other=f.add('failed',f.entry.stored);
  f.state.onGet=async()=>{await expect(f.schedules.assertReceiptReadScope(other.stored,f.actor,f.db)).rejects.toBeDefined();};
  await get(f);closedExecution(f);
 });

 it('rejects a different real Actor frame while the receipt callback is suspended',async()=>{
  const f=m11ScheduleReceiptFixture();
  f.state.onGet=async()=>{await f.context.runActor({actor:f.user,clusterId:f.cid,workspaceId:f.wid,module:'workflows',action:'read'},
   ()=>expect(f.scope()).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_ORIGINAL_RECEIPT_SCOPE_REQUIRED'}}));};
  await get(f);closedExecution(f);
 });

 it('closes actual HTTP/Actor frame loss during an awaited SQL read',async()=>{
  const f=m11ScheduleReceiptFixture();let closed=false;
  f.state.onSql=async(sql:string)=>{if(!closed&&sql.includes('FROM configuration_plan_versions')){closed=true;await Promise.resolve();f.context.captureHttpCloser()();}};
  await expect(get(f)).rejects.toBeDefined();expect(closed).toBe(true);closedExecution(f);
 });

 it('drops its active scope after a callback failure',async()=>{
  const f=m11ScheduleReceiptFixture();f.state.onGet=async()=>{throw Error('CONTROLLED_RECEIPT_GET_FAILURE');};
  await expect(get(f)).rejects.toThrow('CONTROLLED_RECEIPT_GET_FAILURE');
  f.state.onGet=null;await get(f);closedExecution(f);
 });

 it('keeps closed inherited scopes closed instead of falling back to ordinary subject authorization',async()=>{
  const f=m11ScheduleReceiptFixture();let release!:()=>void,detached!:Promise<unknown>;
  const gate=new Promise<void>(resolve=>{release=resolve;});
  f.state.onGet=async()=>{detached=gate.then(async()=>{
   expect(f.schedules.receiptReadActive()).toBe(true);await expect(f.scope()).rejects.toBeDefined();
   await expect((f.authority as any).actualActor(f.entry.stored.draft,f.entry.stored.plan,f.actor,'write',f.db))
    .rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_RECEIPT_READ_ONLY'}});
   return 'closed';
  });};
  await get(f);release();await expect(detached).resolves.toBe('closed');closedExecution(f);
 });

 it('keeps concurrent receipt scopes separate when they finish in opening order',async()=>{
  const f=m11ScheduleReceiptFixture(),other=f.add('partial',f.entry.stored);
  const waits=new Map<string,()=>void>(),started=new Map<string,()=>void>();
  const firstEntered=new Promise<void>(resolve=>started.set(f.entry.stored.draft.scheduleId,resolve));
  const secondEntered=new Promise<void>(resolve=>started.set(other.stored.draft.scheduleId,resolve));
  f.state.onGet=async(e:any)=>{const id=e.stored.draft.scheduleId;started.get(id)!();await new Promise<void>(resolve=>waits.set(id,resolve));
   await f.schedules.assertReceiptReadScope(e.stored,f.actor,f.db);};
  const first=get(f);await firstEntered;
  const second=f.run(()=>f.schedules.get(f.cid,other.stored.draft.scheduleId,f.actor));await secondEntered;
  waits.get(f.entry.stored.draft.scheduleId)!();await expect(first).resolves.toMatchObject({entity:{id:f.entry.stored.draft.scheduleId,state:'failed'}});
  waits.get(other.stored.draft.scheduleId)!();await expect(second).resolves.toMatchObject({entity:{id:other.stored.draft.scheduleId,state:'partial'}});closedExecution(f);
 });

 it('never turns an active receipt into write/approve authority, a Namespace, or a Native packet',async()=>{
  const f=m11ScheduleReceiptFixture();let checked=false;
  f.state.onGet=async()=>{
   for(const action of ['write','approve'])await expect((f.authority as any).actualActor(f.entry.stored.draft,f.entry.stored.plan,f.actor,action,f.db))
    .rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_RECEIPT_READ_ONLY'}});
   await expect((f.schedules as any).operation(f.cid,f.actor,'write','activate','before',f.db,f.entry.stored.plan.workflowId,f.entry.stored.draft.scheduleId)).rejects.toBeDefined();
   expect(()=>f.context.requireWorkflowScheduledNamespaceHandle()).toThrow();
   await expect(f.authority.verifyClaim({},'packet')).rejects.toBeDefined();
   await expect(f.context.authorizeRequest({id:f.cid,admin_url:'http://controlled-kong:8001',version:'1.5.1',execution_mode:'approval'},'POST','/services',{id:randomUUID()},{})).rejects.toBeDefined();checked=true;
  };
  await get(f);expect(checked).toBe(true);closedExecution(f);
 });
});
