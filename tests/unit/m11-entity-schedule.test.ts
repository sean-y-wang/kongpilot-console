import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ConflictException, ForbiddenException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { EntityChangeScheduleRepository, normalizeEntityScheduleSpec } from '../../apps/console-api/src/modules/workflows/entity-change-schedule.repository';
import { EntityChangeScheduleWorker } from '../../apps/console-api/src/modules/workflows/entity-change-schedule.worker';
import type { EntityScheduledDraft, EntityScheduleActivation, EntityScheduleClaim, EntityScheduleRepositoryDelegate } from '../../apps/console-api/src/modules/workflows/entity-change-schedule.contract';

// This is a bounded SQL/Root-proof domain adapter, not an actual PostgreSQL
// constraint test or Root private namespace. Actual DDL/native/due evidence is
// independently owned by Root. The worker uses no fake actor or fake session.
function fixture(){
  const secrets=new SecretService(),cid=randomUUID(),wid=randomUUID(),uid=randomUUID(),sid=randomUUID(),intent=randomUUID(),
    actor:any={user:{id:uid,username:'actual-owner'},workspaceId:wid,requestId:randomUUID()},now=Date.now(),
    spec={version:1 as const,executorId:uid,notBefore:new Date(now-1000).toISOString(),windowStart:new Date(now-2000).toISOString(),windowEnd:new Date(now+240000).toISOString()},
    impact={version:1 as const,keyId:'aa'.repeat(32),keys:['bb'.repeat(32)],domains:['cc'.repeat(32)],wildcards:[]},
    delegation={version:1 as const,id:randomUUID(),revision:1 as const,clusterId:cid,workspaceId:wid,intentId:intent,intentRevision:1,changeDigest:'11'.repeat(32),packetManifestHmac:'22'.repeat(32),policyHash:'33'.repeat(32),
      ownerId:uid,executorId:uid,ownerCredentialEpoch:'1',executorCredentialEpoch:'1',issuedAt:new Date(now-3000).toISOString(),expiresAt:new Date(now+3600000).toISOString(),specHmac:secrets.fingerprint(spec),statement:'execute-this-exact-approved-entity-intent-with-my-current-authority' as const},
    draft:EntityScheduledDraft={binding:{clusterId:cid,workspaceId:wid,intentId:intent,intentRevision:1,materialHmac:'44'.repeat(32),changeDigest:delegation.changeDigest,packetManifestHmac:delegation.packetManifestHmac},scheduleId:sid,scheduleVersion:1,spec,specHmac:secrets.fingerprint(spec),delegation,delegationHmac:secrets.fingerprint(delegation),impactHmac:secrets.fingerprint(impact),transportScope:'55'.repeat(32),impact};
  const schedules=new Map<string,any>(),delegations=new Map<string,any>(),progress=new Map<string,any>(),activations=new Map<string,any>(),claims=new Map<string,any>(),leases:any[]=[],events:any[]=[],proofs=new WeakMap<object,any>();let current=true,conflict=false;
  const record=(names:string[],values:any[])=>Object.fromEntries(names.map((name,index)=>[name,values[index]]));
  const load=(id:string)=>{const s=schedules.get(id);if(!s)return null;const d=delegations.get(s.delegation_id);return {...s,...progress.get(id),id:s.id,workflow_id:activations.get(id)?.workflow_id??null,delegation_ciphertext:d.delegation_ciphertext,policy_hash:d.policy_hash,executor_id:d.executor_id,executor_credential_epoch:d.executor_credential_epoch,delegation_issued_at:d.issued_at};};
  const db:any={one:vi.fn(async(sql:string,p:any[]=[])=>{
    if(/FROM entity_change_schedule_(claims|leases).*FOR (UPDATE|SHARE|KEY SHARE)/.test(sql))throw Object.assign(new Error('Immutable schedule facts have no UPDATE grant'),{code:'42501'});
    if(sql.includes('FROM iam_epoch'))return{version:'1'};
    if(sql.includes('SELECT s.*,p.state'))return load(p[0]);
    if(sql.includes('FROM entity_change_schedules'))return [...schedules.values()].find(r=>r.cluster_id===p[0]&&r.workspace_id===p[1]&&r.intent_id===p[2]&&r.intent_revision===p[3])??null;
    if(sql.includes('FROM entity_change_schedule_progress'))return progress.get(p[0])??null;
    if(sql.includes('FROM entity_change_schedule_claims'))return sql.includes('schedule_id=$1 OR occurrence_id=$2')?[...claims.values()].find(r=>r.schedule_id===p[0]||r.occurrence_id===p[1])??null:claims.get(p[0])??null;
    if(sql.includes('FROM entity_change_schedule_leases'))return [...leases].filter(r=>r.claim_id===p[0]).sort((a,b)=>b.lease_version-a.lease_version)[0]??null;
    throw new Error('Unexpected schedule domain read');
  }),query:vi.fn(async(sql:string,p:any[])=>sql.includes('WHERE p.state=')?[...schedules.values()].filter(r=>progress.get(r.id)?.state==='active'&&Date.parse(r.not_before)<=Date.now()).slice(0,p[0]).map(r=>({id:r.id})):[]),exec:vi.fn(async(sql:string,p:any[]=[])=>{
    if(sql.includes('pg_advisory_xact_lock'))return1();
    else if(sql.startsWith('INSERT INTO entity_change_owner_delegations')){const d=record(['id','cluster_id','workspace_id','intent_id','intent_revision','material_hmac','change_digest','packet_manifest_hmac','policy_hash','owner_id','owner_credential_epoch','spec_hmac','delegation_hmac','delegation_ciphertext','issued_at','expires_at'],p);d.version=1;d.executor_id=d.owner_id;d.executor_credential_epoch=d.owner_credential_epoch;delegations.set(d.id,d);}
    else if(sql.startsWith('INSERT INTO entity_change_schedules')){const s=record(['id','cluster_id','workspace_id','intent_id','intent_revision','material_hmac','change_digest','packet_manifest_hmac','owner_id','owner_credential_epoch','delegation_id','delegation_hmac','spec_hmac','spec','not_before','window_start','window_end','expires_at','occurrence_id','transport_scope','impact_hmac','impact'],p);s.version=1;s.delegation_version=1;s.spec=JSON.parse(s.spec);s.impact=JSON.parse(s.impact);schedules.set(s.id,s);}
    else if(sql.startsWith('INSERT INTO entity_change_schedule_progress'))progress.set(p[0],{schedule_id:p[0],cluster_id:p[1],workspace_id:p[2],schedule_version:1,state:'pending-approval',revision:1,claim_id:null,reason_code:null});
    else if(sql.startsWith('INSERT INTO entity_change_schedule_activations'))activations.set(p[0],record(['schedule_id','cluster_id','workspace_id','intent_id','intent_revision','material_hmac','change_digest','packet_manifest_hmac','workflow_id','workflow_plan_revision','workflow_plan_hash','approval_format','approval_required','approval_set_id','approval_set_hmac'],p));
    else if(sql.startsWith('INSERT INTO entity_change_schedule_claims')){const c=record(['id','cluster_id','workspace_id','schedule_id','occurrence_id','worker_owner_hmac','workflow_id','workflow_plan_revision','workflow_plan_hash','owner_id','owner_credential_epoch','delegation_id','delegation_hmac','spec_hmac','window_start','window_end','issued_at','authority_expires_at','initial_lease_until'],p);c.generation=1;claims.set(c.id,c);}
    else if(sql.startsWith('INSERT INTO entity_change_schedule_leases'))leases.push(sql.includes('1,NULL')?{id:p[0],cluster_id:p[1],workspace_id:p[2],claim_id:p[3],generation:1,worker_owner_hmac:p[4],lease_version:1,previous_id:null,lease_until:p[5]}:record(['id','cluster_id','workspace_id','claim_id','generation','worker_owner_hmac','lease_version','previous_id','lease_until'],p));
    else if(sql.startsWith('INSERT INTO entity_change_schedule_events'))events.push(record(['id','cluster_id','workspace_id','schedule_id','event_kind','actor_id','claim_id','reason_code'],p));
    else if(sql.startsWith('UPDATE entity_change_schedule_progress')){const r=progress.get(p[0]);if(!r)return 0;
      if(sql.includes("SET state='active'"))r.state='active';
      else if(sql.includes("SET state='claimed'")){r.state='claimed';r.claim_id=p[1];}
      else if(sql.includes("SET state='cancelled'"))r.state='cancelled';
      else{r.state=p[1];if(sql.includes('reason_code=$3'))r.reason_code=p[2];}r.revision++;}
    else throw new Error('Unexpected schedule domain write');return 1;
  })};function return1(){return 1;}db.transaction=vi.fn(async(fn:any)=>fn(db));
  const audit:any={append:vi.fn(async()=>({id:randomUUID()}))},proof=(kind:string,value:any)=>{const token={};proofs.set(token,{kind,hmac:secrets.fingerprint(value)});return token;},
    check=(token:object,kind:string,value:any)=>{const stored=proofs.get(token);if(!stored||stored.kind!==kind||stored.hmac!==secrets.fingerprint(value))throw new ForbiddenException({code:'COPIED_SCHEDULE_PROOF'});};
  const policy:EntityScheduleRepositoryDelegate={verifyDraft:vi.fn(async(d,a)=>{if(!current||a.user.id!==d.delegation.ownerId)throw new ForbiddenException({code:'OWNER_REVOKED'});}),
    verifyApproved:vi.fn(async(id,a,p)=>{check(p,'activation',{id,activation:a});if(!current)throw new ForbiddenException({code:'REVIEWER_REVOKED'});}),
    verifyClaim:vi.fn(async(id,c,p)=>{check(p,'claim',{id,claim:c});if(!current)throw new ForbiddenException({code:'OWNER_REVOKED'});}),
    verifyLease:vi.fn(async(id,owner,generation,until,p)=>check(p,'lease',{id,owner,generation,until})),verifyCancellation:vi.fn(async(id,a)=>{if(a.user.id!==uid)throw new ForbiddenException();}),
    verifyPhysicalReservation:vi.fn(async()=>{if(conflict)throw new ConflictException({code:'PHYSICAL_WINDOW_CONFLICT'});}),
    verifyOutcome:vi.fn(async(id,outcome,p)=>check(p,'outcome',{id,outcome})),verifyBlocked:vi.fn(async(id,reason,p)=>check(p,'blocked',{id,reason})),assertRead:vi.fn(async(_id,a)=>{if(a.user.id!==uid)throw new ForbiddenException();})};
  const service=new EntityChangeScheduleRepository(db,secrets,audit),activation:EntityScheduleActivation={workflowId:randomUUID(),workflowPlanRevision:1,workflowPlanHash:'66'.repeat(32),approvalFormat:2,approvalRequired:true,approvalSetId:randomUUID(),approvalSetHmac:'77'.repeat(32)};
  const install=()=>service.installFixedDelegate(policy),persist=()=>service.persistDraft(draft,actor),activate=()=>service.activate(sid,activation,proof('activation',{id:sid,activation})),
    claim=():EntityScheduleClaim=>({id:randomUUID(),scheduleId:sid,scheduleVersion:1,occurrenceId:schedules.get(sid).occurrence_id,generation:1,workerOwnerHmac:'88'.repeat(32),
      issuedAt:new Date().toISOString(),authorityExpiresAt:new Date(Date.now()+180000).toISOString(),initialLeaseUntil:new Date(Date.now()+90000).toISOString(),workflowId:activation.workflowId,workflowPlanRevision:1,workflowPlanHash:activation.workflowPlanHash});
  return{service,db,secrets,audit,actor,draft,activation,policy,proof,install,persist,activate,claim,schedules,progress,claims,leases,events,setCurrent:(v:boolean)=>{current=v;},setConflict:(v:boolean)=>{conflict=v;}};
}
describe('M11 scheduled entity metadata (explicit SQL/Root-proof domain adapter)',()=>{
  beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','de'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
  it('requires a fixed verifier and seals a draft without due authority, sources, actors or SID writes',async()=>{
    const f=fixture();await expect(f.persist()).rejects.toMatchObject({response:{code:'ENTITY_SCHEDULE_POLICY_UNAVAILABLE'}});f.install();expect(()=>f.install()).toThrow();
    const receipt=await f.persist();expect(receipt.state).toBe('pending-approval');expect(receipt.nativeAuthority).toBe(false);expect(await f.service.listDue()).toEqual([]);
    expect(f.claims.size).toBe(0);expect(f.db.exec.mock.calls.every(([sql]:any[])=>!sql.includes('auth_sessions')&&!sql.includes('INSERT INTO entity_change_execution_sources'))).toBe(true);
    expect(f.audit.append).toHaveBeenCalledTimes(1);
  });
  it('fences UTC half-open instants, cross-executor delegation and mutated material before SQL writes',async()=>{
    const f=fixture();f.install();expect(()=>normalizeEntityScheduleSpec({...f.draft.spec,notBefore:f.draft.spec.windowEnd},f.actor.user.id)).toThrow();
    expect(()=>normalizeEntityScheduleSpec({...f.draft.spec,windowStart:'2026-10-13T13:00:00+00:00'},f.actor.user.id)).toThrow();
    await expect(f.service.persistDraft({...f.draft,delegation:{...f.draft.delegation,executorId:randomUUID()}},f.actor)).rejects.toMatchObject({response:{code:'ENTITY_SCHEDULE_FACT_INVALID'}});
    await expect(f.service.persistDraft({...f.draft,impactHmac:'00'.repeat(32)},f.actor)).rejects.toMatchObject({response:{code:'ENTITY_SCHEDULE_FACT_INVALID'}});expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('rejects copied approval proofs and physical collision before activation and makes no native operation',async()=>{
    const f=fixture();f.install();await f.persist();await expect(f.service.activate(f.draft.scheduleId,f.activation,{})).rejects.toMatchObject({response:{code:'COPIED_SCHEDULE_PROOF'}});
    f.setConflict(true);await expect(f.activate()).rejects.toMatchObject({response:{code:'PHYSICAL_WINDOW_CONFLICT'}});expect(f.progress.get(f.draft.scheduleId).state).toBe('pending-approval');
    f.setConflict(false);await f.activate();expect(await f.service.listDue()).toEqual([f.draft.scheduleId]);expect(f.claims.size).toBe(0);
  });
  it('rechecks actual owner at due time and fences once claims, leases and terminal unknown without replay',async()=>{
    const f=fixture();f.install();await f.persist();await f.activate();const c=f.claim(),p=f.proof('claim',{id:f.draft.scheduleId,claim:c});
    f.setCurrent(false);await expect(f.service.appendDueClaim(f.draft.scheduleId,c,p)).rejects.toMatchObject({response:{code:'OWNER_REVOKED'}});expect(f.claims.size).toBe(0);
    f.setCurrent(true);await f.service.appendDueClaim(f.draft.scheduleId,c,p);expect(f.leases).toHaveLength(1);expect(await f.service.listDue()).toEqual([]);
    await expect(f.service.appendDueClaim(f.draft.scheduleId,c,p)).rejects.toMatchObject({response:{code:'ENTITY_SCHEDULE_OCCURRENCE_ALREADY_CLAIMED'}});
    const until=new Date(Date.parse(c.initialLeaseUntil)+10000).toISOString();await expect(f.service.extendLease(c.id,'00'.repeat(32),1,until,{})).rejects.toMatchObject({response:{code:'ENTITY_SCHEDULE_LEASE_OWNER_CHANGED'}});
    await f.service.extendLease(c.id,c.workerOwnerHmac,1,until,f.proof('lease',{id:c.id,owner:c.workerOwnerHmac,generation:1,until}));expect(f.leases).toHaveLength(2);
    f.setCurrent(false);await f.service.finishClaim(c.id,'uncertain',f.proof('outcome',{id:c.id,outcome:'uncertain'}));
    await expect(f.service.finishClaim(c.id,'succeeded',f.proof('outcome',{id:c.id,outcome:'succeeded'}))).rejects.toMatchObject({response:{code:'ENTITY_SCHEDULE_OUTCOME_ALREADY_CLOSED'}});
    await expect(f.service.cancel(f.draft.scheduleId,f.actor)).rejects.toMatchObject({response:{code:'ENTITY_SCHEDULE_CANCEL_NOT_AVAILABLE'}});expect(f.claims.size).toBe(1);
  });
  it('records owner-bound cancellation or genuine due blocking with transactional safe audit and no claimed occurrence',async()=>{
    const f=fixture();f.install();await f.persist();await f.activate();const reason='ENTITY_SCHEDULE_OWNER_REVOKED';
    await expect(f.service.appendBlocked(f.draft.scheduleId,reason,{})).rejects.toMatchObject({response:{code:'COPIED_SCHEDULE_PROOF'}});
    const receipt=await f.service.appendBlocked(f.draft.scheduleId,reason,f.proof('blocked',{id:f.draft.scheduleId,reason}));expect(receipt.state).toBe('blocked');expect(receipt.claimId).toBeNull();
    expect(f.events.at(-1).reason_code).toBe(reason);expect(f.audit.append.mock.calls.at(-1)[0].after.reasonCode).toBe(reason);expect(await f.service.listDue()).toEqual([]);
    await expect(f.service.get(f.draft.scheduleId,{...f.actor,user:{id:randomUUID()}})).rejects.toMatchObject({status:403});
    const cancel=fixture();cancel.install();await cancel.persist();expect((await cancel.service.cancel(cancel.draft.scheduleId,cancel.actor)).state).toBe('cancelled');expect(cancel.claims.size).toBe(0);
  });
  it.each(['failed','partial'] as const)('keeps the claim and failure reason and records %s as a failed audit result',async outcome=>{
    const f=fixture();f.install();await f.persist();await f.activate();const c=f.claim();
    await f.service.appendDueClaim(f.draft.scheduleId,c,f.proof('claim',{id:f.draft.scheduleId,claim:c}));
    const reason='ENTITY_SCHEDULE_OWNER_REVOKED';f.progress.get(f.draft.scheduleId).reason_code=reason;
    const receipt=await f.service.finishClaim(c.id,outcome,f.proof('outcome',{id:c.id,outcome}));
    expect(receipt.state).toBe(outcome);expect(receipt.claimId).toBe(c.id);expect(f.claims.size).toBe(1);
    expect(f.events.at(-1)).toMatchObject({event_kind:outcome,claim_id:c.id,reason_code:reason});
    expect(f.audit.append.mock.calls.at(-1)[0]).toMatchObject({action:`workflow.schedule.${outcome}`,result:'failed',after:{claimId:c.id,reasonCode:reason}});
    await expect(f.service.appendDueClaim(f.draft.scheduleId,c,f.proof('claim',{id:f.draft.scheduleId,claim:c}))).rejects.toMatchObject({response:{code:'ENTITY_SCHEDULE_OCCURRENCE_ALREADY_CLAIMED'}});
  });
});
describe('M11 schedule worker orchestration (disabled unless Root installs a genuine delegate)',()=>{
  it('fails closed without a delegate and passes original opaque handles once, including concurrent tick exclusion',async()=>{
    const repository:any={listDue:vi.fn(async()=>['schedule-a','schedule-b'])},worker=new EntityChangeScheduleWorker(repository);
    await expect(worker.tick()).rejects.toMatchObject({response:{code:'ENTITY_SCHEDULE_WORKER_NOT_ENABLED'}});expect(repository.listDue).not.toHaveBeenCalled();
    const handle=Object.freeze({}),seen:any[]=[],delegate={acquireDueClaim:vi.fn(async(id:string)=>id==='schedule-a'?handle:null),executeClaim:vi.fn(async(h:object)=>{seen.push(h);expect((await worker.tick()).busy).toBe(true);})};
    worker.installFixedDelegate(delegate);expect(()=>worker.installFixedDelegate(delegate)).toThrow();expect(await worker.tick()).toEqual({checked:2,claimed:1,completed:1,blocked:1,busy:false});expect(seen).toEqual([handle]);expect(seen[0]).toBe(handle);
  });
});
