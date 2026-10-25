import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {portalOriginalMutationSupportFixture} from './helpers/m11-portal-original-mutation-support-fixture';
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32)));afterEach(()=>{vi.restoreAllMocks();vi.unstubAllEnvs();});
/** These Source cases exercise the real private Core frame/Approved invocation.
 * SQL, grants and subject scans are the explicitly controlled seam adapters. */
describe('only the original Portal Native mutation actor selects a create container',()=>{
 it('selects current SQL for actual create mutationBinding and bindOperation, without an SDK authority permit',async()=>{
  let f:any,before:any,original:any;f=portalOriginalMutationSupportFixture(false,async()=>{original=f.context.current();expect(original.action).toBe('create');expect(f.context.isOriginalPortalNativeMutationFrame(original)).toBe(true);before={...f.scan};});
  f.authority.installPortalInspectionInvocationVerifier(f.approved.installPortalInspectionInvocationVerifier());
  await f.run(async()=>{expect(f.scan).toEqual(before);expect(f.context.isOriginalPortalNativeMutationFrame(original)).toBe(false);expect(f.context.isOriginalPortalNativeMutationFrame({...original})).toBe(false);});
 });
 it('keeps an ordinary caller-created create actor on full SDK checks despite the current genuine NativeStep',async()=>{
  let f:any;f=portalOriginalMutationSupportFixture(false,async()=>{const parent=f.context.current();await f.context.runActor({actor:parent.actor,clusterId:f.cid,workspaceId:f.wid,module:'consumers',action:'create'},async()=>{
   expect(f.context.currentApprovedStep().kind).toBe('native');expect(f.context.isOriginalPortalNativeMutationFrame(f.context.current())).toBe(false);const before={...f.scan};await f.verify();expect(f.scan.executor-before.executor).toBeGreaterThanOrEqual(1);expect(f.scan.reviewer-before.reviewer).toBeGreaterThanOrEqual(3);
  });});f.authority.installPortalInspectionInvocationVerifier(f.approved.installPortalInspectionInvocationVerifier());await f.run(async()=>{});
 });
 it('never selects a create container for a real current MetadataStep',async()=>{
  const f=portalOriginalMutationSupportFixture(true);f.authority.installPortalInspectionInvocationVerifier(f.approved.installPortalInspectionInvocationVerifier());await f.run(async()=>{
   expect(f.context.currentApprovedStep().kind).toBe('metadata');expect(f.context.isOriginalPortalNativeMutationFrame(f.context.current())).toBe(false);const before={...f.scan};await f.verify();expect(f.scan.executor-before.executor).toBe(1);expect(f.scan.reviewer-before.reviewer).toBe(3);
  });
 });
 it.each(['grants','membership','lease'])('rejects current %s revocation during actual create binding SQL closure',async reason=>{
  let f:any,entered=false;f=portalOriginalMutationSupportFixture(false,async()=>{f.flags.beforeConsume=()=>{entered=true;if(reason==='grants')f.flags.grantsChanged=true;else if(reason==='membership')f.flags.membershipRevoked=true;else f.state.lease=false;};});
  f.authority.installPortalInspectionInvocationVerifier(f.approved.installPortalInspectionInvocationVerifier());await expect(f.run(async()=>{})).rejects.toBeDefined();expect(entered).toBe(true);
 });
});
