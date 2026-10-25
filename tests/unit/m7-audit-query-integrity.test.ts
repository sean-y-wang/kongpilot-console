import { afterEach,beforeEach,describe,expect,it,vi } from 'vitest';
import { createHash } from 'node:crypto';
import { SecretService,canonicalJson } from '../../apps/console-api/src/infrastructure/secret.service';
import { AuditCursorService } from '../../apps/console-api/src/modules/audit/audit-cursor.service';
import { AuditIntegrityService,auditCanonicalRecord } from '../../apps/console-api/src/modules/audit/audit-integrity.service';
import { AuditQueryService } from '../../apps/console-api/src/modules/audit/audit-query.service';
import { auditQuery,type AuditRow } from '../../apps/console-api/src/modules/audit/audit.types';
import { auditCsvCell } from '../../apps/console-api/src/modules/audit/audit-export.service';

const cid='11111111-1111-4111-8111-111111111111',wid='22222222-2222-4222-8222-222222222222',uid='33333333-3333-4333-8333-333333333333';
const user={id:uid,username:'reader',superAdmin:false};
const snapshot={user,grants:[],version:'v1'};
function row(n:number,prev='GENESIS'):AuditRow{
 const r:AuditRow={id:`44444444-4444-4444-8444-${String(n).padStart(12,'0')}`,chain_scope:`cluster:${cid}`,sequence:String(n),actor_id:uid,actor_type:'user',source_ip:null,
 cluster_id:cid,workspace_id:wid,entity_type:'services',entity_id:null,action:'update',before:{config:{provision_key:'s3cr3t'},enabled:false},after:{config:{provision_key:'s3cr3t'},enabled:true},json_patch:[{op:'replace',path:'/enabled',value:true}],workflow_id:null,result:'success',request_id:'request',prev_hash:prev,event_hash:'0'.repeat(64),occurred_at:new Date(`2026-01-01T00:00:${String(n).padStart(2,'0')}.000Z`),millisecond_precision:true,record_bytes:400,history_scope:null,history_scope_hmac:null,history_audit_hash:null};
 r.event_hash=createHash('sha256').update(canonicalJson(auditCanonicalRecord(r))).digest('hex');return r;
}
function access(){return {assertWholeAudit:vi.fn().mockResolvedValue(snapshot),assertAuditScope:vi.fn().mockResolvedValue(snapshot),assertVersion:vi.fn().mockResolvedValue(undefined),permissionVersion:vi.fn().mockResolvedValue('v1'),isWholeAudit:vi.fn().mockReturnValue(false),canAuditReadSnapshot:vi.fn().mockReturnValue(true)};}
describe('M7 audit cursor, projection and original chain',()=>{
 beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
 it('encrypts cursor bounds and rejects actor, permission, filter, kind and scope changes',()=>{
  const c=new AuditCursorService(new SecretService()),binding={actorId:uid,permissionVersion:'v1',scope:{cid,wid},filter:{action:'read'},size:20};
  const token=c.seal('list',binding,{upperSequence:'123456789012345678',last:{id:'hidden'}});
  expect(token).not.toContain('123456789012345678');expect(c.open('list',binding,token)).toEqual({upperSequence:'123456789012345678',last:{id:'hidden'}});
  for(const b of [{...binding,actorId:'other'},{...binding,permissionVersion:'v2'},{...binding,scope:{cid,wid:'other'}},{...binding,filter:{action:'delete'}}])expect(()=>c.open('list',b,token)).toThrow();
  expect(()=>c.open('integrity',binding,token)).toThrow();const at=Math.floor(token.length/2),changed=token.slice(0,at)+(token[at]==='A'?'B':'A')+token.slice(at+1);expect(()=>c.open('list',binding,changed)).toThrow();
 });
 it('never expands omitted WID into a cluster query and rejects invalid bounded input',()=>{
  expect(()=>auditQuery(cid,{})).toThrow();expect(()=>auditQuery(cid,{workspaceId:wid,size:101})).toThrow();
  expect(()=>auditQuery(cid,{scope:'cluster',workspaceId:wid})).toThrow();expect(()=>auditQuery(null,{workspaceId:wid})).toThrow();
  expect(auditQuery(cid,{workspaceId:wid,size:'20'}).mode).toBe('workspace');
 });
 it('recomputes public patch after current redaction and reduces cascade identities',()=>{
  const s=new AuditQueryService({} as any,new SecretService(),access() as any,{} as any),r=row(1);
  r.after={config:{provision_key:'new-secret'},deleted:[{id:'unproved-child'}]};r.json_patch=[{op:'add',path:'/config/provision_key',value:'stored-unredacted'}];
  const view=s.safeView(r,false),text=JSON.stringify(view);
  expect(text).not.toContain('new-secret');expect(text).not.toContain('stored-unredacted');expect(text).not.toContain('unproved-child');
  expect((view.after as any).deleted).toEqual({count:1});expect(view).not.toHaveProperty('sequence');expect(view).not.toHaveProperty('event_hash');
 });
 it('verifies a real canonical nineteen-field two-row chain and distinguishes partial interval',async()=>{
  const a=row(1),b=row(2,a.event_hash),rows=[a,b];
  const db={one:vi.fn(async(sql:string)=>sql.includes('audit_chain_heads')?{last_sequence:'2',last_hash:b.event_hash}:{event_hash:a.event_hash}),query:vi.fn(async(_sql:string,p:any[])=>rows.filter(r=>BigInt(r.sequence)>=BigInt(p[1])&&BigInt(r.sequence)<=BigInt(p[2])))};
  const service=new AuditIntegrityService(db as any,access() as any,new AuditCursorService(new SecretService()));
  expect(await service.verify(user,cid,{})).toMatchObject({status:'verified',complete:true,intervalComplete:true,checkedRows:2});
  expect(await service.verify(user,cid,{fromSequence:'2',toSequence:'2'})).toMatchObject({status:'verified',complete:false,intervalComplete:true,checkedRows:1});
 });
 it.each(['content','previous','precision','gap','head'])('detects %s tampering without updating history',async kind=>{
  const a=row(1),b=row(2,a.event_hash);let rows=[a,b],head=b.event_hash;
  if(kind==='content')b.after={enabled:'tampered'};if(kind==='previous')b.prev_hash='a'.repeat(64);if(kind==='precision')b.millisecond_precision=false;if(kind==='gap')rows=[b];if(kind==='head')head='a'.repeat(64);
  const db={one:vi.fn(async()=>({last_sequence:'2',last_hash:head})),query:vi.fn(async()=>rows),exec:vi.fn()};
  const result=await new AuditIntegrityService(db as any,access() as any,new AuditCursorService(new SecretService())).verify(user,cid,{});
  expect(result.status).toBe('mismatch');expect(result.complete).toBe(false);expect(db.exec).not.toHaveBeenCalled();
 });
 it('uses bigint strings and UTC milliseconds without safe projection or added annotations in the hash',()=>{
  const r=row(1);r.sequence='9223372036854775806';r.history_scope={version:1,quality:'legacy_unknown',module:'audit',before:null,after:null};
  const record=auditCanonicalRecord(r);expect(Object.keys(record)).toHaveLength(19);expect(record.sequence).toBe('9223372036854775806');expect(record.occurred_at).toBe('2026-01-01T00:00:01.000Z');expect(record).not.toHaveProperty('history_scope');expect(record).not.toHaveProperty('event_hash');
 });
 it('honestly reports an indivisible oversized row without an endless same-position continuation',async()=>{
  const r=row(1);r.record_bytes=3*1024*1024;
  const db={one:vi.fn(async()=>({last_sequence:'1',last_hash:r.event_hash})),query:vi.fn(async()=>[r])};
  expect(await new AuditIntegrityService(db as any,access() as any,new AuditCursorService(new SecretService())).verify(user,cid,{})).toMatchObject({status:'unavailable',complete:false,checkedRows:0,nextCursor:null});
 });
 it.each(['=IMPORTXML("evil")',' +SUM(1,2)','\t@cmd','-1+2','\r=cmd'])('escapes CSV formula %j',value=>{expect(auditCsvCell(value)).toContain('"\'');});
 it('server-side scans past unauthorized rows and returns only the page without total or sequence',async()=>{
  const first=row(1),second=row(2),a=access();a.canAuditReadSnapshot.mockImplementation((_s:any,r:AuditRow)=>r.id===second.id);
  const db={one:vi.fn(async()=>({last_sequence:'2'})),query:vi.fn().mockResolvedValueOnce([first,second]).mockResolvedValueOnce([])};
  const service=new AuditQueryService(db as any,new SecretService(),a as any,new AuditCursorService(new SecretService()));
  const result=await service.list(user,auditQuery(cid,{workspaceId:wid,from:'2026-01-01T00:00:00Z',to:'2026-01-01T00:01:00Z',size:1}));
  expect(result.items.map(r=>r.id)).toEqual([second.id]);expect(result.total).toBeNull();expect(JSON.stringify(result)).not.toContain('sequence');
 });
 it('denies a page whose current permissions changed during the SQL read',async()=>{
  const a=access();a.permissionVersion.mockResolvedValueOnce('v1').mockResolvedValueOnce('v2');
  const db={one:vi.fn(async()=>({last_sequence:'1'})),query:vi.fn().mockResolvedValueOnce([row(1)])};
  await expect(new AuditQueryService(db as any,new SecretService(),a as any,new AuditCursorService(new SecretService())).list(user,auditQuery(cid,{workspaceId:wid}))).rejects.toThrow();
 });
});
