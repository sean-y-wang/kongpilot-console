import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {portalInspectionProducerFixture} from './helpers/m11-portal-inspection-producer-fixture';
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-18T11:00:00Z'));});
afterEach(()=>{vi.restoreAllMocks();vi.useRealTimers();vi.unstubAllEnvs();});
function expiring(source:'user'|'team',databaseDate='2026-10-18T11:00:00.000Z'){
 const f=portalInspectionProducerFixture(),old=f.db.query.getMockImplementation()!,roleId=randomUUID(),bindingId=randomUUID(),teamId=randomUUID(),userBindings=new Map<string,string>();
 const current={databaseDate,expiresAt:new Date(Date.parse(databaseDate)+10000).toISOString(),bindingCurrent:true};
 f.db.query.mockImplementation(async(sql:string,args:any[])=>{
  if(!sql.includes('FROM iam_effective_grants'))return old(sql,args);
  const actualBinding=source==='team'?bindingId:(userBindings.get(args[0])??(userBindings.set(args[0],randomUUID()),userBindings.get(args[0])!));
  const grant={user_id:args[0],role_id:roleId,binding_id:actualBinding,binding_source:source,module:'portal',action:'write',scope_type:'global',scope_values:[],cluster_id:null,workspace_id:null};
  if(!sql.includes('binding_current'))return[grant];
  return[{grant,binding:{id:actualBinding,role_id:roleId,...(source==='team'?{team_id:teamId}:{user_id:args[0]}),status:'active',expires_at:current.expiresAt},binding_expires_at:current.expiresAt,binding_current:current.bindingCurrent,observed_at:current.databaseDate}];
 });return{...f,grant:current};
}
describe('original Portal grant expiry remains a final Context/Namespace fence',()=>{
 it.each(['user','team']as const)('denies natural %s expiry after SQL consumption with no fresh DB query or IAM bump',async source=>{
  const f=expiring(source);await expect(f.run(async(handle,ns)=>{
   await f.context.verifyWorkflowScheduledNamespace('packet');await f.namespace.consumeFreshPortalInspection(handle,ns,'packet',f.db);
   const queries=f.db.query.mock.calls.length,time=performance.now();vi.spyOn(performance,'now').mockReturnValue(time+10001);
   expect(()=>f.namespace.assertLive(handle)).toThrow();expect(()=>f.context.current()).toThrow();expect(f.db.query.mock.calls).toHaveLength(queries);
   f.context.current();
   // Expired ancestors stay expired even after this callback returns.
  })).rejects.toBeDefined();
 });
 it('converts DB-relative remaining life rather than comparing the binding expiry with the application wall clock',async()=>{
  const f=expiring('user','2040-01-01T00:00:00.000Z');await expect(f.run(async(handle,ns)=>{
   await f.context.verifyWorkflowScheduledNamespace('packet');await f.namespace.consumeFreshPortalInspection(handle,ns,'packet',f.db);
   const time=performance.now();vi.spyOn(performance,'now').mockReturnValue(time+10001);expect(()=>f.context.current()).toThrow();f.context.current();
  })).rejects.toBeDefined();
 });
 it('never expands the original Namespace grant deadline after a later binding extension',async()=>{
  const f=expiring('team');await expect(f.run(async(handle,ns)=>{
   await f.context.verifyWorkflowScheduledNamespace('packet');await f.namespace.consumeFreshPortalInspection(handle,ns,'packet',f.db);
   f.grant.expiresAt=new Date(Date.parse(f.grant.databaseDate)+60000).toISOString();
   await f.context.verifyWorkflowScheduledNamespace('before-send');await f.namespace.consumeFreshPortalInspection(handle,ns,'before-send',f.db);
   const time=performance.now();vi.spyOn(performance,'now').mockReturnValue(time+10001);expect(()=>f.context.current()).toThrow();f.context.current();
  })).rejects.toBeDefined();
 });
});
