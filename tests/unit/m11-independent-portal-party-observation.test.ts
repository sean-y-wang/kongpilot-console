import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {performance} from 'node:perf_hooks';
import {randomUUID} from 'node:crypto';
import {validGrant} from '../../apps/console-api/src/modules/authorization/grant-policy';
import {portalPartyObservationFixture} from './helpers/m11-portal-party-observation-fixture';

/** Actual Authority/Runtime/Material/Validation/Context/Kong SDK. Namespace
 * issuance, SQL/lease and outbound are controlled Source adapters. These cases
 * do not issue a Native packet or claim a production deadline acceptance. */
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-18T12:00:00Z'));const now=performance.now();vi.spyOn(performance,'now').mockReturnValue(now);});
afterEach(()=>{vi.restoreAllMocks();vi.useRealTimers();vi.unstubAllEnvs();});
function grants(f:any,id:string,serviceScope:any){
 f.tables.users.find((u:any)=>u.id===id).super_admin=false;
 for(const [module,action]of [['workflows','approve'],['portal','read'],['services','read'],['plugins','read'],['consumers','read'],['secrets','read']])
  {const grant={user_id:id,module,action,cluster_id:null,workspace_id:null,scope_type:'global',scope_values:[],...(module==='services'?serviceScope:{})};expect(validGrant(grant)).toBe(true);f.tables.iam_effective_grants.push(grant);}
}
describe('independent private raw round ownership and per-reviewer scope',()=>{
 it.each(['tag_group','entity','workspace'])('cannot borrow executor permissions for reviewer %s scoped Service READ',async kind=>{
  const f=await portalPartyObservationFixture(1),id=f.reviewers[0];let replay=false;
  const real=f.compiler.authorizeResponse.bind(f.compiler);vi.spyOn(f.compiler,'authorizeResponse').mockImplementation(async input=>{if(input.principal.user.id===id&&input.resource.entityType==='services')replay=true;return real(input);});
  await f.runInNamespace(async()=>{const foreignWorkspace=randomUUID();grants(f,id,kind==='tag_group'?{cluster_id:f.plan.clusterId,workspace_id:f.plan.workspaceId,scope_type:kind,scope_values:['team-no-service-access']}:kind==='entity'?{cluster_id:f.plan.clusterId,workspace_id:f.plan.workspaceId,scope_type:kind,scope_values:[{entity_type:'services',entity_id:randomUUID()}]}:{cluster_id:f.plan.clusterId,scope_type:kind,scope_values:[foreignWorkspace],workspace_id:foreignWorkspace});
   await expect(f.run('before-send')).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_RESPONSE_READ_DENIED'}});
  });expect(replay).toBe(true);
 });
 it('allows the exact entity-scoped Service READ without a global Service grant',async()=>{
  const f=await portalPartyObservationFixture(1),id=f.reviewers[0];await f.runInNamespace(async()=>{grants(f,id,{cluster_id:f.plan.clusterId,workspace_id:f.plan.workspaceId,scope_type:'entity',scope_values:[{entity_type:'services',entity_id:f.service.id}]});
   await expect(f.run('before-send').catch((error:any)=>{const code=error?.getResponse?.()?.code;throw Error('SOURCE_EXACT_ENTITY_POSITIVE_DENIED:'+(/^[A-Z0-9_]{1,128}$/.test(code??'')?code:'UNCLASSIFIED'));})).resolves.toMatchObject({plan:{workflowId:f.plan.workflowId}});
  });
 });
 it('requires the exact current checkpoint despite the same genuine namespace and transaction',async()=>{
  const f=await portalPartyObservationFixture(1);let entered=false;
  await f.runInNamespace(async()=>{f.state.afterReviewer=async(id:string)=>{entered=true;await(f.runtime as any).subject(f.plan,id,'approve','step',f.db);};
   await expect(f.run('before-send')).rejects.toMatchObject({response:{code:'WORKFLOW_PORTAL_OBSERVATION_PARTY_REQUIRED'}});
  });expect(entered).toBe(true);
 });
 it('checks actual original round identity inside the live frame and closes inherited asynchronous tails',async()=>{
  const f=await portalPartyObservationFixture(1);let release!:()=>void,tail!:Promise<void>,entered=false;
  await f.runInNamespace(async()=>{f.state.afterReviewer=()=>{entered=true;const original=f.verifier().current();expect(original).toBe(f.rounds.at(-1));expect(()=>f.verifier().assert({...original})).toThrow();
    tail=new Promise<void>(resolve=>{release=resolve;}).then(()=>f.verifier().assert(original));};
   await f.run('before-send');release();await expect(tail).rejects.toMatchObject({response:{code:'WORKFLOW_PORTAL_OBSERVATION_ORIGINAL_REQUIRED'}});
  });expect(entered).toBe(true);
 });
 it('cannot use a previously closed round in a new otherwise authorized fresh checkpoint',async()=>{
  const f=await portalPartyObservationFixture(1);await f.runInNamespace(async()=>{await f.run('step');const prior=f.rounds.at(-1);f.state.afterReviewer=()=>f.verifier().assert(prior);
   await expect(f.run('packet')).rejects.toMatchObject({response:{code:'WORKFLOW_PORTAL_OBSERVATION_ORIGINAL_REQUIRED'}});
  });
 });
 it('rejects exact approval-set invalidation after the last real reviewer replay',async()=>{
  const f=await portalPartyObservationFixture(2);let last=false;await f.runInNamespace(async()=>{f.state.afterReviewer=(id:string)=>{if(id===f.reviewers.at(-1)){last=true;f.state.invalidated=true;}};
   await expect(f.run('before-send')).rejects.toMatchObject({response:{code:'WORKFLOW_APPROVAL_SET_INVALIDATED'}});
  });expect(last).toBe(true);
 });
});
