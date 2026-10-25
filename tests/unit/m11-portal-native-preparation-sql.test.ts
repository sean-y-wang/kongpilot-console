import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {performance} from 'node:perf_hooks';
import {portalInspectionApprovedSeamFixture} from './helpers/m11-portal-inspection-approved-seam-fixture';

beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32)));
afterEach(()=>{vi.restoreAllMocks();vi.useRealTimers();vi.unstubAllEnvs();});
/** This exercises actual private Context/Authority/Namespace/Approved objects.
 * Canonical SQL/grants and subject SDK scans remain the existing explicitly
 * controlled Source adapters; the full engine SDK counter is separate. */
function fixture(){const f=portalInspectionApprovedSeamFixture();
 const verifier=f.approved.installPortalInspectionInvocationVerifier();f.authority.installPortalInspectionInvocationVerifier(verifier);
 const cluster={id:f.cid,admin_url:'http://kong:8001',version:'1.5.1',execution_mode:'approval',revision:1};
 const ticket=()=>{const request=f.plan.steps[0].nativeRequests[0];return f.context.authorizeRequest(cluster,'POST',request.canonicalPath,request.body,{});};
 return{...f,cluster,ticket};}

describe('original Portal native preparation has current SQL facts and no final Native authority',()=>{
 it('uses real same-ticket private preparation to avoid repeated subject SDK scans, and keeps final SDK verification',async()=>{
  const f=fixture();let selected:any;await f.run(async()=>{const ticket=await f.ticket(),before={...f.scan};
   f.flags.beforeConsume=()=>{selected=f.context.scheduledPortalPreparationPhase();expect(selected?.ticket).toBe(ticket);expect(selected?.stage).toBe('sql-preflight');};
   await f.context.assertApprovedNativeRequest(ticket,'authorize');expect(f.scan).toEqual(before);expect(selected).toBeDefined();
   expect(f.context.scheduledPortalPreparationPhase()).toBeNull();expect(()=>f.context.assertScheduledPortalPreparationPhase(selected)).toThrow();
   f.flags.beforeConsume=null;await f.context.beforeNativeSend(ticket);expect(f.scan.executor-before.executor).toBe(1);expect(f.scan.reviewer-before.reviewer).toBe(3);
  });
 });
 it('keeps response validation in its own final SDK and SQL closing boundary',async()=>{
  const f=fixture();await f.run(async()=>{const ticket=await f.ticket(),before={...f.scan};
   const response={...f.plan.steps[0].nativeRequests[0].body};expect(await f.context.authorizeResponse(ticket,response)).toEqual(response);
   expect(f.scan.executor-before.executor).toBe(1);expect(f.scan.reviewer-before.reviewer).toBe(3);expect(f.context.scheduledPortalFinalNativePhase()).toBeNull();
  });
 });
 it('derives the only permitted schema path from the original ticket and closes the schema preparation',async()=>{
  const f=fixture();let original:any;await f.run(async()=>{const ticket=await f.ticket(),before={...f.scan};
   await f.context.runPortalWriteSchemaRead(ticket,async()=>{original=f.context.scheduledPortalPreparationPhase();expect(original?.purpose).toBe('schema');
    const schemaTicket=await f.context.authorizeRequest(f.cluster,'GET','/schemas/consumers',undefined,{});await f.context.authorizeResponse(schemaTicket,{fields:[]});
   });expect(f.scan).toEqual(before);expect(f.context.scheduledPortalPreparationPhase()).toBeNull();expect(()=>f.context.assertScheduledPortalPreparationPhase(original)).toThrow();
  });
 });
 it('cannot use the original Consumer ticket schema capsule to read another schema',async()=>{
  const f=fixture();await expect(f.run(async()=>{const ticket=await f.ticket();await f.context.runPortalWriteSchemaRead(ticket,()=>
   f.context.authorizeRequest(f.cluster,'GET','/schemas/acls',undefined,{}));
  })).rejects.toBeDefined();
 });
 it('does not allow a copied ticket to select SQL preparation',async()=>{
  const f=fixture();await f.run(async()=>{const ticket=await f.ticket(),before={...f.scan};
   await expect(f.context.assertApprovedNativeRequest({...ticket}as any,'authorize')).rejects.toBeDefined();expect(f.scan).toEqual(before);expect(f.context.scheduledPortalPreparationPhase()).toBeNull();
  });
 });
 it.each(['membership','approval','requester','reviewer','IAM','lease'])('denies current %s revocation in SQL preparation',async reason=>{
  const f=fixture();let entered=false;await expect(f.run(async()=>{const ticket=await f.ticket();f.flags.beforeConsume=()=>{entered=true;
   if(reason==='membership')f.flags.membershipRevoked=true;else if(reason==='approval')f.flags.approvalChanged=true;else if(reason==='requester')f.state.requesterActive=false;
   else if(reason==='reviewer')f.state.reviewerActive=false;else if(reason==='IAM')f.state.principalVersion='2';else f.state.lease=false;
  };await f.context.assertApprovedNativeRequest(ticket,'authorize');})).rejects.toBeDefined();expect(entered).toBe(true);
 });
 it('does not treat a successful SQL preparation as final SDK authorization after subject revocation',async()=>{
  const f=fixture();await expect(f.run(async()=>{const ticket=await f.ticket();await f.context.assertApprovedNativeRequest(ticket,'authorize');
   f.state.scopeAllowed=false;await f.context.beforeNativeSend(ticket);
  })).rejects.toBeDefined();
 });
 it('requires the original DB transaction while consuming a SQL-only preparation fact',async()=>{
  const f=fixture();let entered=false;await expect(f.run(async()=>{const ticket=await f.ticket();f.flags.beforeConsume=async()=>{entered=true;
   const phase=f.context.scheduledPortalPreparationPhase();expect(phase).not.toBeNull();const args=f.consume.mock.calls.at(-1)!;
   await f.namespace.consumeFreshPortalInspection(args[0],args[1],args[2],{...f.db});
  };await f.context.assertApprovedNativeRequest(ticket,'authorize');})).rejects.toBeDefined();expect(entered).toBe(true);
 });
 it('cannot copy or extend the private preparation deadline',async()=>{
  const f=fixture();await expect(f.run(async()=>{const ticket=await f.ticket();f.flags.beforeConsume=()=>{const original=f.context.scheduledPortalPreparationPhase()!;
   expect(()=>f.context.assertScheduledPortalPreparationPhase({...original})).toThrow();const now=performance.now();f.context.limitScheduledPortalPreparation(original,now+20);
   f.context.limitScheduledPortalPreparation(original,Infinity);vi.spyOn(performance,'now').mockReturnValue(now+21);f.context.assertScheduledPortalPreparationPhase(original);
  };await f.context.assertApprovedNativeRequest(ticket,'authorize');})).rejects.toBeDefined();
 });
 it.each(['user','team']as const)('cannot consume an expired %s binding after an awaited SQL-only preparation',async kind=>{
  // Exercise expiry after the real SQL consume, independent of runner load.
  // The original 50ms bound is unchanged; only clocks are deterministic.
  vi.useFakeTimers({toFake:['Date']});vi.setSystemTime(new Date('2026-10-20T00:00:00Z'));
  let monotonic=10000;vi.spyOn(performance,'now').mockImplementation(()=>monotonic);
  const f=fixture();f.flags.bindingKind=kind;let entered=false;await expect(f.run(async()=>{const ticket=await f.ticket();
   f.flags.bindingExpiresAt=new Date(Date.now()+50).toISOString();f.flags.afterConsume=()=>{entered=true;monotonic+=51;};
   await f.context.assertApprovedNativeRequest(ticket,'authorize');
  })).rejects.toBeDefined();expect(entered).toBe(true);
 });
});
