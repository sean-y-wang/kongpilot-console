import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import {portalInspectionApprovedSeamFixture} from './helpers/m11-portal-inspection-approved-seam-fixture';
import {PortalAuthBoundaryService} from '../../apps/console-api/src/modules/portal-boundary/portal-auth-boundary.service';

beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32)));
afterEach(()=>{vi.restoreAllMocks();vi.unstubAllEnvs();});
/** Original private Authority/Namespace/Approved/Step/M/ticket/permit and real
 * Boundary ownership->exact paths verifier. SQL/grants/subject scans and the
 * Native policy hook are explicit Source adapters. No SDK/wire or HTTP claim. */
function fixture(probe:(f:any,permit:any,boundary:PortalAuthBoundaryService)=>Promise<void>){
 let f:any,boundary:PortalAuthBoundaryService;
 f=portalInspectionApprovedSeamFixture({beforeNativeSend:async(...args:any[])=>{await probe(f,args[7],boundary);}});
 const query=f.db.query.getMockImplementation();f.db.query.mockImplementation(async(sql:string,args:any[])=>{
  if(sql.includes('FROM portal_publications p LEFT JOIN')||sql.includes('FROM portal_application_grants WHERE transport_scope')||sql.includes('FROM portal_credentials c JOIN'))return[];
  return query(sql,args);
 });
 const verifier=f.approved.installPortalInspectionInvocationVerifier();f.authority.installPortalInspectionInvocationVerifier(verifier);
 boundary=new PortalAuthBoundaryService(f.db,f.secrets,{}as any,f.context,{}as any,f.approved);
 const run=()=>f.run(async()=>{const r=f.plan.steps[0].nativeRequests[0],ticket=await f.context.authorizeRequest({id:f.cid,admin_url:'http://kong:8001',version:'1.5.1',execution_mode:'approval',revision:1},'POST',r.canonicalPath,r.body,{});await f.context.prepareNativeSend(ticket);});
 return{f,boundary,run};
}
const extra='/services/00000000-0000-4000-8000-000000000099';
it('rejects a last-index accessor that appends an unverified path on its second read',async()=>{
 let reads=0,entered=false;const source=fixture(async(f,permit)=>{
  entered=true;const paths=['/services','/routes','/plugins'];Object.defineProperty(paths,'2',{enumerable:true,configurable:true,get(){if(++reads===2)paths.push(extra);return'/plugins';}});
  await expect(f.context.runPortalBoundaryRead(permit,paths,async()=>f.context.current().limits.paths)).rejects.toMatchObject({response:{code:'PORTAL_BOUNDARY_READ_PATH_INVALID'}});
 });await source.run();expect(entered).toBe(true);expect(reads).toBe(0);
});
it('uses its own frozen path snapshot after the real verifier succeeds and the caller array changes',async()=>{
 let entered=false;const source=fixture(async(f,permit,boundary)=>{
  entered=true;const paths=['/services','/routes','/plugins'],expected=[...paths];
  const verify=(boundary as any).assertPreparationSupportPaths.bind(boundary);
  vi.spyOn(boundary as any,'assertPreparationSupportPaths').mockImplementation(async(...args:any[])=>{await verify(...args);queueMicrotask(()=>paths.push(extra));});
  const observed=await f.context.runPortalBoundaryRead(permit,paths,async()=>({paths:[...f.context.current().limits.paths],frozen:Object.isFrozen(f.context.current().limits.paths)}));
  expect(paths).toContain(extra);expect(observed.paths).toEqual(expected);expect(observed.frozen).toBe(true);
 });await source.run();expect(entered).toBe(true);
});
it.each([{paths:['/services',,'/plugins']},{paths:['/services','/routes',42]}])('rejects sparse or non-string support path data %j',async({paths})=>{
 const source=fixture(async(f,permit)=>{await expect(f.context.runPortalBoundaryRead(permit,paths as any,async()=>{})).rejects.toMatchObject({response:{code:'PORTAL_BOUNDARY_READ_PATH_INVALID'}});});await source.run();
});
