import { afterEach,beforeEach,describe,expect,it,vi } from 'vitest';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { HistoricalEventAccessService } from '../../apps/console-api/src/modules/authorization/historical-event-access.service';
import { DeliveryRepositoryService } from '../../apps/console-api/src/modules/event-core/delivery-repository.service';
import { eventAuditScopeDigest,eventSourceScopeDigest } from '../../apps/console-api/src/modules/event-core/event-utils';
import type { EventRecord } from '../../apps/console-api/src/modules/event-core/event.types';
import type { EffectiveGrant } from '../../apps/console-api/src/common/authorization.types';

const cid='11111111-1111-4111-8111-111111111111',wid='22222222-2222-4222-8222-222222222222',uid='33333333-3333-4333-8333-333333333333',eid='44444444-4444-4444-8444-444444444444',aid='55555555-5555-4555-8555-555555555555',nid='66666666-6666-4666-8666-666666666666';
const user={id:uid,username:'operator',superAdmin:false};
const grant=(module:string,action:'read'|'write'='read'):EffectiveGrant=>({module,action,cluster_id:cid,workspace_id:wid,scope_type:'workspace',scope_values:[wid]});
function fixture(){
 const secrets=new SecretService(),scope={version:1 as const,quality:'verified' as const,module:'services',nativeType:'services',nativeId:nid,before:null,after:{workspaceId:wid,physicalTags:['mine']}};
 const payload={version:1 as const,title:'配置变更',summary:'配置变更',eventType:'entity.created',phase:'terminal' as const,result:'success',subject:{type:'services',id:nid}};
 const event:EventRecord={id:eid,clusterId:cid,workspaceId:wid,eventType:'entity.created',phase:'terminal',sourceKind:'audit',sourceId:aid,actorType:'user',actorId:uid,developerId:null,occurredAt:new Date().toISOString(),sourceScope:scope,sourceScopeHmac:'',payloadSafe:payload,payloadDigest:secrets.fingerprint(payload),auditEventId:aid,auditEventHash:'a'.repeat(64)};
 event.sourceScopeHmac=eventSourceScopeDigest(secrets,event);
 const eventRow={id:eid,cluster_id:cid,workspace_id:wid,event_type:event.eventType,phase:event.phase,source_kind:event.sourceKind,source_id:aid,actor_type:'user',actor_id:uid,developer_id:null,occurred_at:event.occurredAt,source_scope:scope,source_scope_hmac:event.sourceScopeHmac,payload_safe:payload,payload_digest:event.payloadDigest,audit_event_id:aid,audit_event_hash:event.auditEventHash};
 const row:any={id:'77777777-7777-4777-8777-777777777777',event_id:eid,cluster_id:cid,workspace_id:wid,delivery_kind:'test',subscription_id:null,subscription_revision:null,channel_id:'88888888-8888-4888-8888-888888888888',channel_revision:2,credential_generation:3,creator_id:uid,state:'claimed',lease_owner_hash:secrets.fingerprint('worker'),lease_generation:1,lease_until:new Date(Date.now()+30000),attempt_count:0,intent_attempt_no:null,idempotency_key:'delivery-key',payload_safe:payload,payload_digest:event.payloadDigest,channel_status:'active',current_channel_revision:2,current_generation:3,channel_creator:uid,subscription_status:null,current_subscription_revision:null,subscription_channel_id:null,occurred_at:event.occurredAt,source_id:aid};
 const grants=[grant('audit'),grant('events'),grant('events','write'),grant('notifications')];
 const auth:any={snapshot:vi.fn(async()=>({user,grants,version:`${uid}:1:1`})),permissionVersion:vi.fn(async()=>`${uid}:1:1`)};
 const db:any={one:vi.fn(async(sql:string)=>{
  if(sql.includes('SELECT true AS valid'))return {valid:true};
  if(sql.includes('SELECT d.*'))return structuredClone(row);
  if(sql.includes('FROM event_records'))return structuredClone(eventRow);
  if(sql.includes('FROM users'))return {id:uid,username:'operator',super_admin:false};
  if(sql.includes('FROM clusters'))return {id:cid};
  if(sql.includes('FROM workspaces'))return {status:'deleted'};
  return null;
 }),query:vi.fn(async()=>[row]),exec:vi.fn().mockResolvedValue(1)};
 db.transaction=vi.fn(async(fn:any)=>fn(db));
 const observation={assertCurrent:vi.fn().mockResolvedValue(undefined)};
 const access=new HistoricalEventAccessService(db,auth,secrets,observation);
 return {access,db,auth,secrets,event,eventRow,row,grants,observation};
}
describe('M7 EventAccess immutable source and private worker binding',()=>{
 beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
 it('reads original deleted WID with its current grant without resolving a native entity',async()=>{
  const f=fixture();await f.access.assertSourceRead(user,f.event,'events');
  expect(f.db.one.mock.calls.some((c:any[])=>String(c[0]).includes('FROM event_records'))).toBe(true);
  expect(f.auth.snapshot).toHaveBeenCalledWith(user);
 });
 it('does not trust a caller modified source or payload when DB source is authentic',async()=>{
  const f=fixture();await f.access.assertSourceRead(user,{...f.event,clusterId:'foreign',sourceScopeHmac:'forged'} as any,'events');
  expect(f.db.one).toHaveBeenCalledWith(expect.stringContaining('WHERE e.id=$1'),[eid]);
 });
 it.each(['scope','context','payload'])('rejects persisted %s tampering rather than swallowing it as an empty result',async type=>{
  const f=fixture();if(type==='scope')f.eventRow.source_scope.after!.physicalTags=['foreign'];if(type==='context')f.eventRow.audit_event_hash='b'.repeat(64);if(type==='payload')f.eventRow.payload_safe.title='tampered';
  await expect(f.access.canSourceRead(user,f.event,'events')).rejects.toThrow();
 });
 it('only filters a genuine permission denial and propagates database errors',async()=>{
  const f=fixture();f.grants.splice(0);expect(await f.access.canSourceRead(user,f.event,'events')).toBe(false);
  f.db.one.mockRejectedValueOnce(new Error('database unavailable'));await expect(f.access.canSourceRead(user,f.event,'events')).rejects.toThrow('database unavailable');
 });
 it('validates audit annotation exact audit ID/hash/context before a restricted matcher',()=>{
  const f=fixture(),scope=f.event.sourceScope;
  const row:any={id:aid,entity_type:'services',cluster_id:cid,workspace_id:wid,event_hash:f.event.auditEventHash,history_audit_hash:f.event.auditEventHash,history_scope:scope,
   history_scope_hmac:eventAuditScopeDigest(f.secrets,{auditEventId:aid,auditEventHash:f.event.auditEventHash!,clusterId:cid,workspaceId:wid,scope})};
  expect(f.access.canAuditReadSnapshot({user,grants:f.grants,version:'x'},row)).toBe(true);row.id=eid;
  expect(()=>f.access.canAuditReadSnapshot({user,grants:f.grants,version:'x'},row)).toThrow();
 });
 it('strongly delegates observations to the real private issuer with the supplied transaction',async()=>{
  const f=fixture(),input={sourceProof:'HTTP cannot issue this'} as any,tx={} as any;
  await f.access.assertObservationCurrent(input,tx);expect(f.observation.assertCurrent).toHaveBeenCalledExactlyOnceWith(input,tx);
  f.observation.assertCurrent.mockRejectedValueOnce(new Error('private proof invalid'));await expect(f.access.assertObservationCurrent(input,tx)).rejects.toThrow('private proof invalid');
 });
 it('rejects HTTP/spread claims before any DB permission check',async()=>{
  const f=fixture();await expect(f.access.assertDeliveryCurrent({deliveryId:f.row.id} as any)).rejects.toThrow();expect(f.db.one).not.toHaveBeenCalled();
 });
 it('binds a Core-minted lease to active real authors and rechecks final config after author awaits',async()=>{
  const f=fixture();const original=f.db.one.getMockImplementation()!;f.db.one.mockImplementation(async(sql:string,...args:any[])=>sql.includes('FROM workspaces')?{status:'active'}:original(sql,...args));
  const repo=new DeliveryRepositoryService(f.db,f.secrets,f.access);const [claim]=await repo.claimDue({owner:'worker',limit:1,leaseMs:30000});
  const proof=await f.access.assertDeliveryCurrent(claim);expect(proof.actorId).toBe(uid);expect(proof.credentialGeneration).toBe(3);
  await expect(f.access.assertDeliveryCurrent({...claim})).rejects.toThrow();
  f.db.one.mockImplementation(async(sql:string,...args:any[])=>sql.includes('SELECT true AS valid')?null:sql.includes('FROM workspaces')?{status:'active'}:original(sql,...args));
  await expect(f.access.assertDeliveryCurrent(claim)).rejects.toThrow();
 });
 it.each(['revision','lease','grant'])('stops a real Core claim after %s change',async change=>{
  const f=fixture();const original=f.db.one.getMockImplementation()!;f.db.one.mockImplementation(async(sql:string,...args:any[])=>sql.includes('FROM workspaces')?{status:'active'}:original(sql,...args));
  const [claim]=await new DeliveryRepositoryService(f.db,f.secrets,f.access).claimDue({owner:'worker',limit:1,leaseMs:30000});
  if(change==='revision')f.row.current_channel_revision++;if(change==='lease')f.row.lease_until=new Date(0);if(change==='grant')f.grants.splice(0);
  await expect(f.access.assertDeliveryCurrent(claim)).rejects.toThrow();
 });
});
