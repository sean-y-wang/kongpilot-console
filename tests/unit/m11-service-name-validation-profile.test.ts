import 'reflect-metadata';
import {randomUUID} from 'node:crypto';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {serviceNameValidationFixture} from './helpers/m11-service-name-validation-fixture';

beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-14T01:00:00Z'));});
afterEach(()=>{vi.restoreAllMocks();vi.useRealTimers();vi.unstubAllEnvs();});
const code=(value:string)=>({response:{code:value}});
/** Real Validation original handle/request/SDK-witness maps and shape/SQL
 * closing logic. Its SQL and SDK observer issuer remain controlled adapters,
 * so these cases do not establish a genuine HTTP404 or database acceptance. */
function fixture(host='service-backend.local',domain:any='scoped-points-v1'){
 const f=serviceNameValidationFixture(),serviceId=randomUUID(),upstreamId=randomUUID();
 const resource:any={clusterId:f.cid,workspaceId:f.wid,path:`/upstreams/${encodeURIComponent(host)}`,kind:'point',entityType:'upstreams',secrets:false,allowAbsent:true,required:false,serviceHostReference:{host,serviceIds:[serviceId]}};
 f.values.resources=[resource];f.values.domain=domain;
 return{...f,resource,serviceId,upstreamId,raw:{id:upstreamId,name:host,tags:[]}};
}
describe('fixed Service-name Validation SDK response profile',()=>{
 it.each(['scoped-points-v1',undefined])('accepts an original exact-name200 UUID for %s',async domain=>{
  const f=fixture('service-backend.local',domain);f.install();await f.selectedRun([f.resource],async(handle:any)=>{expect(await f.actualRead(handle,f.resource,f.raw)).toEqual(f.raw);});
 });
 it.each(['scoped-points-v1',undefined])('authenticates original404 without inventing an unrelated full EOF for %s',async domain=>{
  const f=fixture('external-service.local',domain);f.install();await f.selectedRun([f.resource],async(handle:any)=>{
   await f.actualAbsent(handle,f.resource);const original=await f.service.observedServiceHostAbsence(handle,f.resource);expect(original.response).toEqual({message:'Not found'});expect(Object.keys(original.originalWitness)).toEqual([]);
  });
 });
 it.each(['health','enabled'])('keeps legal Service host %s on the fixed exact name profile',async host=>{
  const f=fixture(host);f.install();await f.selectedRun([f.resource],async(handle:any)=>{await f.actualRead(handle,f.resource,f.raw);});
 });
 it('never turns a read-denied real200 into404 or DNS absence',async()=>{
  const f=fixture();f.install();await expect(f.selectedRun([f.resource],async(handle:any)=>{f.values.scopeChanged=true;return f.actualRead(handle,f.resource,f.raw);})).rejects.toMatchObject(code('ACTUAL_OBJECT_SCOPE_CHANGED'));
 });
 it.each([{name:'other-host.local'},{id:'not-a-uuid'},{id:undefined}])('requires exact name and realUUID for raw200 %j',async patch=>{
  const f=fixture();f.install();await expect(f.selectedRun([f.resource],(handle:any)=>f.actualRead(handle,f.resource,{...f.raw,...patch}))).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_RESPONSE_INVALID'));
 });
 it('rejects caller status404 and plain error object as observer proof',async()=>{
  const f=fixture();f.install();await expect(f.selectedRun([f.resource],async(handle:any)=>{const token=await f.service.authorizeRequest(handle,f.packetFor(f.resource));return f.service.authorizeResponse(token,{message:'Not found'},404 as any);})).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_ABSENT_OBSERVATION_REQUIRED'));
 });
 it('cannot mint an absence merely by catching a404-shaped exception',async()=>{
  const f=fixture();f.install();await expect(f.selectedRun([f.resource],(handle:any)=>f.service.observedServiceHostAbsence(handle,f.resource))).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_ABSENCE_REQUIRED'));
 });
 it('rejects copied original absence proof and mismatched raw body',async()=>{
  const f=fixture();f.install();await expect(f.selectedRun([f.resource],async(handle:any)=>{const token=await f.service.authorizeRequest(handle,f.packetFor(f.resource)),observed=f.original404(token);
   return f.service.authorizeResponse(token,{message:'Not found'},observed.original);
  })).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_ABSENT_OBSERVATION_REQUIRED'));
 });
 it.each(['required','allowAbsent','entityId','path','serviceIds','marker','secrets'])('denies uncompiled %s substitutions before any read dispatch',async field=>{
  const f=fixture(),changed:any={...f.resource};if(field==='required')changed.required=true;else if(field==='allowAbsent')changed.allowAbsent=false;else if(field==='entityId')changed.entityId=randomUUID();
  else if(field==='path')changed.path='/upstreams/another.local';else if(field==='serviceIds')changed.serviceHostReference={...changed.serviceHostReference,serviceIds:[randomUUID()]};
  else if(field==='marker')delete changed.serviceHostReference;else changed.secrets=true;
  f.install();await expect(f.selectedRun([changed],async()=>true)).rejects.toBeDefined();expect(f.runner.run).not.toHaveBeenCalled();
 });
 it.each(['required','allowAbsent','entityId','parentId','query','serviceIds-order'])('rejects malformed compiled selector %s rather than broadening the generic domain',async field=>{
  const f=fixture();if(field==='required')f.resource.required=true;else if(field==='allowAbsent')f.resource.allowAbsent=false;else if(field==='entityId')f.resource.entityId=randomUUID();
  else if(field==='parentId')f.resource.parentId=randomUUID();else if(field==='query')f.resource.query={size:100};else f.resource.serviceHostReference.serviceIds.push(f.serviceId);
  f.install();await expect(f.selectedRun([f.resource],async()=>true)).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_READ_SCOPE_INVALID'));
 });
 it('does not expose an observation after its original capsule closes',async()=>{
  const f=fixture();f.install();let original:any;await f.selectedRun([f.resource],async(handle:any)=>{original=handle;await f.actualAbsent(handle,f.resource);});
  await expect(f.service.observedServiceHostAbsence(original,f.resource)).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_HANDLE_REQUIRED'));
 });
});
