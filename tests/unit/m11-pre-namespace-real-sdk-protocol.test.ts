import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {preNamespaceApprovalFixture} from './helpers/workflow-pre-namespace-approval-fixture';
import {KongService} from '../../apps/console-api/src/infrastructure/kong/kong.service';
import * as transport from '../../apps/console-api/src/infrastructure/kong/outbound';
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','cb'.repeat(32));});
afterEach(()=>{vi.restoreAllMocks();vi.unstubAllEnvs();});
describe('pre-Namespace exact point observations use the real SDK protocol',()=>{
 it('uses real SDK 404 provenance and FK-derived child absence without nested child HTTP',async()=>{
  const f=await preNamespaceApprovalFixture('portal-credential-issue',2),nativeAbsence=vi.spyOn(f.kong,'verifyScheduledReadAbsentTransport'),derived=vi.spyOn(f.compiler,'authorizeScopedParentAbsence');
  expect(f.kong).toBeInstanceOf(KongService);await f.run('before-send');
  expect(nativeAbsence).toHaveBeenCalled();expect(derived).toHaveBeenCalled();
  const parentPath=`/consumers/${f.plan.generated.consumerId}`;
  expect(f.state.native.filter((r:any)=>r.path===parentPath).map((r:any)=>r.actorId)).toEqual([f.actor,...f.reviewers]);
  expect(f.state.native.filter((r:any)=>r.path.startsWith(parentPath+'/'))).toEqual([]);
  expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['collection-200','occupied-200','forbidden-403','unparsed-404','spoofed-error'] as const)('rejects %s in place of a genuine allocated point absence',async reason=>{
  const f=await preNamespaceApprovalFixture('configuration_v2'),wire=vi.mocked(transport.outboundJson),old=wire.getMockImplementation()!;
  let exercised=false;wire.mockImplementation(async(...args:any[])=>{
   const response=await (old as any)(...args);if(args[1]!==`/services/${f.service.id}`)return response;exercised=true;
   if(reason==='spoofed-error')throw Object.assign(new Error('Not found'),{status:404,response:{status:404,body:{message:'Not found'}}});
   if(reason==='collection-200')return{...response,status:200,body:{data:[],next:null}};
   if(reason==='occupied-200')return{...response,status:200,body:{...f.service}};
   if(reason==='forbidden-403')return{...response,status:403,body:{message:'Not found'}};
   return{...response,status:404,jsonParsed:false,body:'Not found'};
  });
  await expect(f.run()).rejects.toBeDefined();expect(exercised).toBe(true);
  expect(f.state.rootReads.filter((r:any)=>r.action==='approve')).toEqual([]);expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('does not turn a publication Service 404 into an authorized missing create',async()=>{
  const f=await preNamespaceApprovalFixture('portal-credential-issue'),wire=vi.mocked(transport.outboundJson),old=wire.getMockImplementation()!;
  wire.mockImplementation(async(...args:any[])=>{const r=await (old as any)(...args);return args[1]===`/services/${f.service.id}`?{...r,status:404,body:{message:'Not found'}}:r;});
  await expect(f.run()).rejects.toBeDefined();expect(f.db.exec).not.toHaveBeenCalled();
 });
});
