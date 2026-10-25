import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {performance} from 'node:perf_hooks';
import {randomUUID} from 'node:crypto';
import {portalInspectionProducerFixture} from './helpers/m11-portal-inspection-producer-fixture';
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-18T11:00:00Z'));});
afterEach(()=>{vi.restoreAllMocks();vi.useRealTimers();vi.unstubAllEnvs();});
// Fixed SQL adapter models actual SQL005 view: now() is transaction-stable and
// expiry columns are absent from the view. All provenance has authentic shape;
// a stronger join would see clock_timestamp and expired original binding.
describe('independent Portal natural binding expiry in an open transaction',()=>{
 it.each(['user','team'] as const)('denies %s grant expiry before the original inspection closes',async source=>{
  const f=portalInspectionProducerFixture(),old=f.db.query.getMockImplementation()!;
  const bindingId=randomUUID(),roleId=randomUUID(),permissionId=randomUUID(),teamId=randomUUID(),userBindings=new Map<string,string>();
  let expired=false;
  f.db.query.mockImplementation(async(sql:string,args:any[])=>{
   if(!sql.includes('FROM iam_effective_grants'))return old(sql,args);
   const actualBinding=source==='team'?bindingId:(userBindings.get(args[0])??(userBindings.set(args[0],randomUUID()),userBindings.get(args[0])!));
   const grant={user_id:args[0],role_id:roleId,role_code:'fixture',permission_id:permissionId,binding_id:actualBinding,binding_source:source,cluster_id:null,workspace_id:null,module:'portal',action:'write',scope_type:'global',scope_values:[]};
   if(sql.includes('binding_current'))return[{grant,binding:{id:actualBinding,role_id:roleId,...(source==='user'?{user_id:args[0]}:{team_id:teamId}),status:'active',expires_at:'2026-10-18T11:00:00.050Z'},binding_expires_at:'2026-10-18T11:00:00.050Z',binding_current:!expired,observed_at:expired?'2026-10-18T11:00:00.100Z':'2026-10-18T11:00:00.000Z'}];
   return[grant];
  });
  await expect(f.run(async(handle,ns)=>{
   await f.context.verifyWorkflowScheduledNamespace('packet');
   expired=true;vi.setSystemTime(new Date('2026-10-18T11:00:00.100Z'));const time=performance.now();vi.spyOn(performance,'now').mockReturnValue(time+100);
   await f.namespace.consumeFreshPortalInspection(handle,ns,'packet',f.db);
  })).rejects.toBeDefined();
 });
 it.each(['user','team'] as const)('denies %s expiry across awaits inside its newly opened SQL closing transaction',async source=>{
  const f=portalInspectionProducerFixture(),old=f.db.query.getMockImplementation()!;
  const bindingId=randomUUID(),roleId=randomUUID(),permissionId=randomUUID(),teamId=randomUUID(),userBindings=new Map<string,string>();
  let closing=false,closingReads=0,expired=false;
  f.db.query.mockImplementation(async(sql:string,args:any[])=>{
   if(!sql.includes('FROM iam_effective_grants'))return old(sql,args);
   const actualBinding=source==='team'?bindingId:(userBindings.get(args[0])??(userBindings.set(args[0],randomUUID()),userBindings.get(args[0])!));
   const grant={user_id:args[0],role_id:roleId,role_code:'fixture',permission_id:permissionId,binding_id:actualBinding,binding_source:source,cluster_id:null,workspace_id:null,module:'portal',action:'write',scope_type:'global',scope_values:[]};
   const result=sql.includes('binding_current')?[{grant,binding:{id:actualBinding,role_id:roleId,...(source==='user'?{user_id:args[0]}:{team_id:teamId}),status:'active',expires_at:'2026-10-18T11:00:00.050Z'},binding_expires_at:'2026-10-18T11:00:00.050Z',binding_current:!expired,observed_at:expired?'2026-10-18T11:00:00.100Z':'2026-10-18T11:00:00.000Z'}]:[grant];
   // The closing transaction begins while the binding is live. Its first
   // complete all-party observation returns live facts. During a later await
   // the binding expires, while PostgreSQL now() remains the transaction start.
   if(closing&&++closingReads===4){expired=true;vi.setSystemTime(new Date('2026-10-18T11:00:00.100Z'));const time=performance.now();vi.spyOn(performance,'now').mockReturnValue(time+100);}
   return result;
  });
  await expect(f.run(async(handle,ns)=>{
   await f.context.verifyWorkflowScheduledNamespace('packet');closing=true;
   await f.namespace.consumeFreshPortalInspection(handle,ns,'packet',f.db);
  })).rejects.toBeDefined();
 });

 it.each(['user','team'] as const)('accepts the exact %s binding adapter while its original short deadline is live',async source=>{
  const f=portalInspectionProducerFixture(),old=f.db.query.getMockImplementation()!;
  const teamBinding=randomUUID(),roleId=randomUUID(),permissionId=randomUUID(),teamId=randomUUID(),userBindings=new Map<string,string>();
  f.db.query.mockImplementation(async(sql:string,args:any[])=>{
   if(!sql.includes('FROM iam_effective_grants'))return old(sql,args);
   const bindingId=source==='team'?teamBinding:(userBindings.get(args[0])??(userBindings.set(args[0],randomUUID()),userBindings.get(args[0])!));
   const grant={user_id:args[0],role_id:roleId,role_code:'fixture',permission_id:permissionId,binding_id:bindingId,binding_source:source,cluster_id:null,workspace_id:null,module:'portal',action:'write',scope_type:'global',scope_values:[]};
   return sql.includes('binding_current')?[{grant,binding:{id:bindingId,role_id:roleId,...(source==='user'?{user_id:args[0]}:{team_id:teamId}),status:'active',expires_at:'2026-10-18T11:00:00.500Z'},binding_expires_at:'2026-10-18T11:00:00.500Z',binding_current:true,observed_at:'2026-10-18T11:00:00.000Z'}]:[grant];
  });
  await f.run(async(handle,ns)=>{
   await f.context.verifyWorkflowScheduledNamespace('packet');
   expect(await f.namespace.consumeFreshPortalInspection(handle,ns,'packet',f.db)).toEqual({approvalSet:f.approvalSet});
  });
 });

});
