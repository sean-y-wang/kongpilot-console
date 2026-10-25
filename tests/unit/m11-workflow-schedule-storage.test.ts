import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {ForbiddenException} from '@nestjs/common';
import {workflowScheduledFixture} from './helpers/workflow-scheduled-fixture';
import {WorkflowScheduleRepository,normalizeWorkflowScheduleDraft,normalizeWorkflowScheduleSpec,assertWorkflowScheduledPlan,workflowScheduleDraftAad,workflowDelegationAad} from '../../apps/console-api/src/modules/workflows/workflow-schedule.repository';
import {planAad} from '../../apps/console-api/src/modules/workflows/workflow.types';

// Real repository + AES/HMA, controlled SQL row/transaction adapter and opaque
// test Root proofs. No PostgreSQL, runtime claim, SID or Kong native permission.
function fixture(kind:'configuration_v2'|'portal-credential-issue'='configuration_v2'){
 const f=workflowScheduledFixture(kind),{draft,plan,secrets,actor}=f,rows=new Map<string,any[]>(),proofs=new WeakMap<object,{kind:string;value:string}>();let current=true,conflict=false;
 const table=(name:string)=>{if(!rows.has(name))rows.set(name,[]);return rows.get(name)!;};
 const db:any={one:vi.fn(async(sql:string,p:any[]=[])=>{
  if(sql.includes('FROM iam_epoch'))return{version:'1'};
  if(sql.includes('SELECT s.*,p.state')){const s=table('workflow_schedules').find(s=>s.id===p[0]),r=table('workflow_schedule_progress').find(s=>s.schedule_id===p[0]);return s&&r?{...structuredClone(s),...structuredClone(r),id:s.id,payload_secret:secrets.encrypt(plan,planAad(draft.binding.clusterId,draft.binding.workspaceId,draft.binding.workflowId,1))}:null;}
  if(sql.includes('SELECT id FROM workflow_schedules'))return table('workflow_schedules').find(s=>s.workflow_id===p[0]&&s.workflow_plan_revision===p[1])??null;
  if(sql.includes('FROM workflow_executor_delegations'))return structuredClone(table('workflow_executor_delegations').find(s=>s.id===p[0])??null);
  if(sql.includes('FROM workflow_schedule_progress'))return table('workflow_schedule_progress').find(s=>s.schedule_id===p[0])??null;
  if(sql.includes('FROM workflow_schedule_activations'))return structuredClone(table('workflow_schedule_activations').find(s=>s.schedule_id===p[0])??null);
  if(sql.includes('FROM workflow_schedule_claims'))return structuredClone(table('workflow_schedule_claims').find(s=>s.id===p[0]&&(!p[1]||s.schedule_id===p[1]))??null);
  if(sql.includes('FROM workflow_schedule_leases'))return structuredClone(table('workflow_schedule_leases').filter(s=>s.claim_id===p[0]).sort((a,b)=>b.lease_version-a.lease_version)[0]??null);
  throw Error('Unexpected controlled storage read');
 }),exec:vi.fn(async(sql:string,p:any[]=[])=>{
  if(sql.includes('pg_advisory_xact_lock'))return 1;
  if(sql.startsWith('INSERT INTO ')){
   const m=/INSERT INTO (\w+)\(([^)]+)\)\s+VALUES\(([^)]+)\)/.exec(sql);if(!m)throw Error('Unsupported controlled insert');
   const columns=m[2].split(','),values=m[3].split(','),row:any={};columns.forEach((c,i)=>{const token=values[i].trim();row[c]=token==='1'?1:token==='NULL'?null:p[Number(/\$(\d+)/.exec(token)?.[1])-1];});
   for(const field of ['spec','impact','activation','claim'])if(typeof row[field]==='string')row[field]=JSON.parse(row[field]);
   if(m[1]==='workflow_executor_delegations'||m[1]==='workflow_schedules')row.version=1;
   if(m[1]==='workflow_schedule_progress')Object.assign(row,{state:'pending-approval',revision:1,claim_id:null,reason_code:null});
   if(m[1]==='workflow_schedule_activations')row.approval_required=true;
   if(m[1]==='workflow_schedule_claims'){row.schedule_version=1;if(table(m[1]).some(s=>s.schedule_id===row.schedule_id||s.occurrence_id===row.occurrence_id))throw Error('once occurrence conflict');}
   if(m[1]==='workflow_schedule_outcomes'&&table(m[1]).some(s=>s.claim_id===row.claim_id))throw Error('immutable terminal conflict');
   table(m[1]).push(row);return 1;
  }
  if(sql.startsWith('UPDATE workflow_schedule_progress')){const row=table('workflow_schedule_progress').find(s=>s.schedule_id===p[0]&&s.revision===p[1]);if(!row)return 0;Object.assign(row,{state:p[2],claim_id:p[3]??row.claim_id,reason_code:p[4],revision:row.revision+1});return 1;}
  throw Error('Unexpected controlled storage write');
 }),query:vi.fn(async(sql:string,p:any[]=[])=>{if(!sql.includes('LIMIT $1'))throw Error('Unbounded scan');return table('workflow_schedules').filter(s=>table('workflow_schedule_progress').some(r=>r.schedule_id===s.id&&r.state==='active'&&!r.claim_id)&&Date.parse(s.not_before)<=Date.now()).slice(0,p[0]).map(s=>({id:s.id}));})};
 db.transaction=vi.fn(async(fn:any)=>{const snapshot=structuredClone([...rows]);try{return await fn(db);}catch(e){rows.clear();snapshot.forEach(([k,v]:any)=>rows.set(k,v));throw e;}});
 const audit:any={append:vi.fn(async()=>({id:randomUUID()}))},repository=new WorkflowScheduleRepository(db,secrets,audit),proof=(kind:string,value:any)=>{const p=Object.freeze({});proofs.set(p,{kind,value:secrets.fingerprint(value)});return p;};
 const verify=(p:object,kind:string,value:any)=>{const actual=proofs.get(p);if(!actual||actual.kind!==kind||actual.value!==secrets.fingerprint(value))throw new ForbiddenException({code:'TEST_ORIGINAL_ROOT_PROOF_REQUIRED'});};
 const assertCurrent=()=>{if(!current)throw new ForbiddenException({code:'TEST_EXECUTOR_REVOKED'});};
 const delegate:any={verifyDraft:vi.fn(async(d:any,a:any,p:object)=>{verify(p,'draft',d);assertCurrent();if(a.user.id!==d.delegation.ownerId)throw new ForbiddenException();}),
  verifyApproved:vi.fn(async(id:string,a:any,p:object,_tx:any,actualActor:any)=>{verify(p,'activation',{id,a,actorId:actualActor.user.id});assertCurrent();}),verifyClaim:vi.fn(async(id:string,c:any,p:object)=>{verify(p,'claim',{id,c});assertCurrent();}),
  verifyLease:vi.fn(async(id:string,owner:string,generation:number,until:string,p:object)=>{verify(p,'lease',{id,owner,generation,until});assertCurrent();}),
  verifyCancellation:vi.fn(async(_id:string,a:any)=>{assertCurrent();if(a.user.id!==actor.user.id)throw new ForbiddenException();}),
  verifyPhysicalReservation:vi.fn(async()=>{if(conflict)throw new ForbiddenException({code:'TEST_PHYSICAL_RESERVED'});}),
  verifyOutcome:vi.fn(async(id:string,outcome:string,p:object)=>{verify(p,'outcome',{id,outcome});return{version:1,provenance:'original-execution',evidenceHmac:secrets.fingerprint({id,outcome})};}),verifyBlocked:vi.fn(async(id:string,reason:string,p:object)=>verify(p,'blocked',{id,reason})),
  assertRead:vi.fn(async(_id:string,a:any)=>{assertCurrent();if(a.user.id!==actor.user.id)throw new ForbiddenException();})};
 const install=()=>repository.installFixedDelegate(delegate),persist=()=>repository.persistDraft(draft,actor,proof('draft',draft)),activation=f.state.stored.activation,
  activate=()=>repository.activate(draft.scheduleId,activation,proof('activation',{id:draft.scheduleId,a:activation,actorId:actor.user.id}),undefined,actor),claim=()=>({id:randomUUID(),scheduleId:draft.scheduleId,scheduleVersion:1,occurrenceId:draft.occurrenceId,generation:1,
   workerOwnerHmac:secrets.fingerprint('worker'),workflowId:plan.workflowId,workflowPlanRevision:1,workflowPlanHash:secrets.fingerprint(plan),issuedAt:new Date().toISOString(),authorityExpiresAt:new Date(Date.now()+150000).toISOString(),initialLeaseUntil:new Date(Date.now()+60000).toISOString()});
 return {...f,repository,db,audit,rows,table,delegate,proof,install,persist,activate,activation,claim,setCurrent:(v:boolean)=>{current=v;},setConflict:(v:boolean)=>{conflict=v;}};
}
describe('M11 business schedule contract/storage (Source-only controlled adapters)',()=>{
 beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
 it.each(['configuration_v2','portal-credential-issue'] as const)('seals %s into version1 before approval without substituting developer/requester identity',kind=>{
  const f=fixture(kind);expect(()=>assertWorkflowScheduledPlan(f.plan,f.draft,f.secrets)).not.toThrow();const normalized=normalizeWorkflowScheduleDraft(f.draft,f.secrets);
  expect(Object.isFrozen(normalized)).toBe(true);expect(Object.isFrozen(normalized.binding.subjectSeal)).toBe(true);
  if(kind==='portal-credential-issue'){expect(f.draft.binding.requester.type).toBe('developer');expect(f.draft.binding.requester.id).not.toBe(f.actor.user.id);expect(f.plan.steps.filter((s:any)=>s.kind==='native')).toHaveLength(3);}
 });
 it('has no circular plan hash and rejects post-vote-shaped executor/window/impact or uncommitted plan changes',()=>{
  const f=fixture(),{scheduling,...base}=f.plan;expect(f.secrets.fingerprint(base)).toBe(f.draft.binding.basePlanHash);expect(f.secrets.fingerprint(f.plan)).toBe(f.draft.binding.workflowPlanHash);
  for(const mutate of [(d:any)=>{d.spec.windowEnd=d.spec.notBefore;},(d:any)=>{d.delegation.executorId=randomUUID();},(d:any)=>{d.impact.keys=[];},(d:any)=>{d.delegation.ownerCredentialEpoch='2';},(d:any)=>{d.binding.requester.type='developer';}]){
   const copy=structuredClone(f.draft);mutate(copy);expect(()=>normalizeWorkflowScheduleDraft(copy,f.secrets)).toThrow();}
  expect(()=>assertWorkflowScheduledPlan({...f.plan,generated:{extra:'unapproved'}},f.draft,f.secrets)).toThrow();expect(scheduling.basePlanHash).toBe(f.secrets.fingerprint(base));
 });
 it('rejects empty Promote sources, non-Promote source aliases, native impact junk and noncanonical UTC windows',()=>{
  const f=fixture(),copy=structuredClone(f.draft);copy.binding.subjectSeal.driver='governance-promote';expect(()=>normalizeWorkflowScheduleDraft(copy,f.secrets)).toThrow();
  copy.binding.subjectSeal.driver='configuration-apply';copy.binding.subjectSeal.sourceScopes=[{clusterId:randomUUID(),workspaceId:randomUUID(),materialHmac:'1'.repeat(64)}];expect(()=>normalizeWorkflowScheduleDraft(copy,f.secrets)).toThrow();
  expect(()=>normalizeWorkflowScheduleDraft({...f.draft,impact:{...f.draft.impact,rawSecret:'unit-secret'}},f.secrets)).toThrow();
  expect(()=>normalizeWorkflowScheduleSpec({...f.draft.spec,notBefore:f.draft.spec.windowEnd},f.owner)).toThrow();expect(()=>normalizeWorkflowScheduleSpec({...f.draft.spec,windowStart:'2026-10-13T13:00:00+00:00'},f.owner)).toThrow();
 });
 it('defaults closed; rejects copied Root proof before storage and binds installation once',async()=>{
  const f=fixture();await expect(f.persist()).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_POLICY_UNAVAILABLE'}});expect(f.db.exec).not.toHaveBeenCalled();f.install();expect(()=>f.install()).toThrow();
  const original=f.proof('draft',f.draft);await expect(f.repository.persistDraft(f.draft,f.actor,{...original})).rejects.toMatchObject({response:{code:'TEST_ORIGINAL_ROOT_PROOF_REQUIRED'}});expect(f.rows.size).toBe(0);
  const result=await f.persist();expect(result).toMatchObject({state:'pending-approval',nativeAuthority:false,claimId:null});expect(await f.repository.listDue()).toEqual([]);expect(f.audit.append).toHaveBeenCalledTimes(1);
  expect(f.db.exec.mock.calls.every(([sql]:any)=>!sql.includes('auth_sessions')&&!sql.includes('mutation_operations')&&!sql.includes('workflow_executions'))).toBe(true);
 });
 it.each(['spec','impact','owner_id','requester_credential_epoch','policy_hash'] as const)('authenticates stored %s before any reservation caller can consume it',async field=>{
  const f=fixture('portal-credential-issue');f.install();await f.persist();const row=f.table('workflow_schedules')[0];
  if(field==='spec')row.spec.executorId=randomUUID();else if(field==='impact')row.impact.keys=[];else row[field]=field==='owner_id'?randomUUID():field==='policy_hash'?'0'.repeat(64):'2';
  await expect(f.repository.inspectStored(f.draft.scheduleId)).rejects.toThrow();
 });
 it('authenticates delegation ciphertext/AAD and all normalized identities independently',async()=>{
  const f=fixture();f.install();await f.persist();const row=f.table('workflow_executor_delegations')[0];row.executor_id=randomUUID();await expect(f.repository.inspectStored(f.draft.scheduleId)).rejects.toThrow();row.executor_id=f.owner;
  row.delegation_ciphertext=f.secrets.encrypt(f.draft.delegation,workflowDelegationAad(f.cid,randomUUID(),row.id));await expect(f.repository.inspectStored(f.draft.scheduleId)).rejects.toThrow();
  expect(()=>f.secrets.decrypt(f.table('workflow_schedules')[0].draft_ciphertext,workflowScheduleDraftAad(f.cid,randomUUID(),f.scheduleId))).toThrow();
 });
 it('requires current eligibility and physical reservation for activation and original once claim; unknown cannot become due again',async()=>{
  const f=fixture();f.install();await f.persist();f.setConflict(true);await expect(f.activate()).rejects.toMatchObject({response:{code:'TEST_PHYSICAL_RESERVED'}});expect((await f.repository.inspectStored(f.scheduleId)).progress.state).toBe('pending-approval');
  f.setConflict(false);await f.activate();expect(await f.repository.listDue()).toEqual([f.scheduleId]);const c=f.claim() as any,p=f.proof('claim',{id:f.scheduleId,c});
  f.setCurrent(false);await expect(f.repository.appendDueClaim(f.scheduleId,c,p)).rejects.toMatchObject({response:{code:'TEST_EXECUTOR_REVOKED'}});expect(f.table('workflow_schedule_claims')).toHaveLength(0);
  f.setCurrent(true);await f.repository.appendDueClaim(f.scheduleId,c,p);expect(await f.repository.listDue()).toEqual([]);await expect(f.repository.appendDueClaim(f.scheduleId,c,p)).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_OCCURRENCE_ALREADY_CLAIMED'}});
  f.setCurrent(false);const result=await f.repository.finishClaim(c.id,'uncertain',f.proof('outcome',{id:c.id,outcome:'uncertain'}));expect(result).toMatchObject({state:'uncertain',claimId:c.id,nativeAuthority:false});
  expect(f.table('workflow_schedule_claims')).toHaveLength(1);expect(f.table('workflow_schedule_outcomes')).toHaveLength(1);expect(await f.repository.listDue()).toEqual([]);
  await expect(f.repository.finishClaim(c.id,'succeeded',f.proof('outcome',{id:c.id,outcome:'succeeded'}))).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_OUTCOME_ALREADY_CLOSED'}});
 });
 it('does not reuse an expired lease; records authentic historical outcome even after credential revocation/expiry',async()=>{
  const f=fixture();f.install();await f.persist();await f.activate();const c=f.claim() as any;await f.repository.appendDueClaim(f.scheduleId,c,f.proof('claim',{id:f.scheduleId,c}));
  const row=f.table('workflow_schedule_leases')[0];row.lease_until=new Date(Date.now()-1000).toISOString();const until=new Date(Date.now()+90000).toISOString();
  await expect(f.repository.extendLease(c.id,c.workerOwnerHmac,1,until,f.proof('lease',{id:c.id,owner:c.workerOwnerHmac,generation:1,until}))).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_LEASE_CANNOT_RECLAIM'}});
  f.setCurrent(false);expect((await f.repository.finishClaim(c.id,'succeeded',f.proof('outcome',{id:c.id,outcome:'succeeded'}))).state).toBe('succeeded');expect(f.table('workflow_schedule_leases')).toHaveLength(1);
 });
 it('records the actual qualified activation operator and rejects a copied activation actor',async()=>{
  const f=fixture();f.install();await f.persist();const approver:any={...f.actor,user:{id:randomUUID(),username:'actual-approver'},requestId:randomUUID(),ip:'192.0.2.5'},p=f.proof('activation',{id:f.scheduleId,a:f.activation,actorId:approver.user.id});
  await expect(f.repository.activate(f.scheduleId,f.activation,p,undefined,f.actor)).rejects.toMatchObject({response:{code:'TEST_ORIGINAL_ROOT_PROOF_REQUIRED'}});
  await expect(f.repository.activate(f.scheduleId,f.activation,p)).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_ACTUAL_ACTIVATION_ACTOR_REQUIRED'}});
  await f.repository.activate(f.scheduleId,f.activation,p,undefined,approver);expect(f.table('workflow_schedule_events').at(-1).actor_id).toBe(approver.user.id);
  expect(f.audit.append.mock.calls.at(-1)[0]).toMatchObject({actorId:approver.user.id,requestId:approver.requestId,ip:approver.ip});expect(f.delegate.verifyApproved).toHaveBeenCalledTimes(3);
 });
 it('accepts only Root-authenticated failed no-callback evidence and keeps the original claim without execution writes',async()=>{
  const f=fixture();f.install();await f.persist();await f.activate();const c=f.claim() as any;await f.repository.appendDueClaim(f.scheduleId,c,f.proof('claim',{id:f.scheduleId,c}));
  const original=f.delegate.verifyOutcome.getMockImplementation()!;
  f.delegate.verifyOutcome.mockImplementation(async(...args:any[])=>{const e=await original(...args);return{...e,provenance:'callback-not-entered'};});
  await expect(f.repository.finishClaim(c.id,'succeeded',f.proof('outcome',{id:c.id,outcome:'succeeded'}))).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_ORIGINAL_OUTCOME_REQUIRED'}});
  f.setCurrent(false);expect((await f.repository.finishClaim(c.id,'failed',f.proof('outcome',{id:c.id,outcome:'failed'}))).state).toBe('failed');
  expect(f.table('workflow_schedule_outcomes')[0]).toMatchObject({claim_id:c.id,outcome:'failed',provenance:'callback-not-entered'});expect(f.table('workflow_schedule_claims')).toHaveLength(1);
  expect(f.db.exec.mock.calls.every(([sql]:any)=>!sql.includes('INSERT INTO workflow_executions')&&!sql.includes('INSERT INTO configuration_executions')&&!sql.includes('INSERT INTO mutation_operations'))).toBe(true);
 });
 it('fails closed on a missing verifier certificate and rolls back if outcome evidence changes during the transaction',async()=>{
  const f=fixture();f.install();await f.persist();await f.activate();const c=f.claim() as any;await f.repository.appendDueClaim(f.scheduleId,c,f.proof('claim',{id:f.scheduleId,c}));
  f.delegate.verifyOutcome.mockResolvedValueOnce(undefined);
  await expect(f.repository.finishClaim(c.id,'failed',f.proof('outcome',{id:c.id,outcome:'failed'}))).rejects.toThrow();expect(f.table('workflow_schedule_outcomes')).toHaveLength(0);
  f.delegate.verifyOutcome.mockResolvedValueOnce({version:1,provenance:'original-execution',evidenceHmac:'1'.repeat(64)}).mockResolvedValueOnce({version:1,provenance:'original-execution',evidenceHmac:'2'.repeat(64)});
  await expect(f.repository.finishClaim(c.id,'failed',f.proof('outcome',{id:c.id,outcome:'failed'}))).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_MATERIAL_CHANGED'}});
  expect(f.table('workflow_schedule_outcomes')).toHaveLength(0);expect((await f.repository.inspectStored(f.scheduleId)).progress.state).toBe('claimed');expect(f.table('workflow_schedule_claims')).toHaveLength(1);
 });
 it('rejects tampered normalized claim or activation records, bounds due reads, and denies cross-account receipt access',async()=>{
  const f=fixture();f.install();await f.persist();await f.activate();const a=f.table('workflow_schedule_activations')[0];a.activation.approvalSetId=randomUUID();await expect(f.repository.inspectStored(f.scheduleId)).rejects.toThrow();a.activation=f.activation;
  const c=f.claim() as any;await f.repository.appendDueClaim(f.scheduleId,c,f.proof('claim',{id:f.scheduleId,c}));f.table('workflow_schedule_claims')[0].claim.workflowPlanHash='0'.repeat(64);await expect(f.repository.inspectStored(f.scheduleId)).rejects.toThrow();
  await expect(f.repository.listDue(26)).rejects.toThrow();await expect(f.repository.get(f.scheduleId,{...f.actor,user:{id:randomUUID()}} as any)).rejects.toMatchObject({status:403});
 });
});
describe('SQL026 candidate Source invariants (not executed PostgreSQL evidence)',()=>{
 const sql=readFileSync(new URL('../../apps/console-api/src/infrastructure/migrations/026_m11_workflow_schedules.sql',import.meta.url),'utf8');
 it('declares immutable facts, one occurrence/generation and coordinated physical locks with old schedules',()=>{
  expect(sql).toContain('generation=1');expect(sql).toContain('schedule_id uuid NOT NULL UNIQUE');expect(sql).toContain('occurrence_id uuid NOT NULL UNIQUE');expect(sql).toContain("'entity-schedule-impact:'||p_scope");
  expect(sql).toContain("p.state IN('active','claimed','running','uncertain')");expect(sql).toContain("p.state='uncertain' OR");expect(sql).toContain('entity_schedule_business_reservation');expect(sql).toContain('BEFORE TRUNCATE');expect(sql).toContain('DEFERRABLE INITIALLY DEFERRED');
 });
 it('keeps genuine wrapper and nested execution references distinct and forbids post-vote sidecars',()=>{
  expect(sql).toContain('REFERENCES workflow_executions(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash)');expect(sql).toContain('REFERENCES configuration_executions(cluster_id,workspace_id,id,job_id,plan_revision,plan_hash)');
  expect(sql).toContain('configuration_execution_id uuid NOT NULL UNIQUE');expect(sql).toContain('workflow_step_id uuid NOT NULL REFERENCES workflow_steps(id)');expect(sql).toContain('FROM workflow_approvals WHERE workflow_id=NEW.workflow_id AND plan_revision=NEW.workflow_plan_revision');
  expect(sql).not.toMatch(/DROP (?:TABLE|CONSTRAINT)|ALTER TABLE .*DROP|CREATE OR REPLACE FUNCTION/);expect(sql).not.toContain('session_id');
 });
 it('uses a distinct authenticated no-callback fact and conservatively holds unresolved native effects',()=>{
  expect(sql).toContain("provenance IN('original-execution','callback-not-entered')");expect(sql).toContain("provenance<>'callback-not-entered' OR outcome='failed'");expect(sql).toContain('No-callback outcome cannot hide any actual execution or physical effect');
  expect(sql).toContain("AND m.state IN('pending','running','uncertain')");expect(sql).toContain('NOT has_success AND(ce.id IS NULL');expect(sql).toContain('workflow_business_event BEFORE INSERT');expect(sql).toContain('NEW.event_kind IS DISTINCT FROM p.state');
 });
});
