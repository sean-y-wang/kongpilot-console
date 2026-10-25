import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {performance} from 'node:perf_hooks';
import {portalPartyObservationFixture} from './helpers/m11-portal-party-observation-fixture';
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-18T12:00:00Z'));const now=performance.now();vi.spyOn(performance,'now').mockReturnValue(now);});
afterEach(()=>{vi.restoreAllMocks();vi.useRealTimers();vi.unstubAllEnvs();});
describe('same checkpoint immutable SDK observations with independent current party authorization',()=>{
 it('reads actual SDK points once while every reviewer independently evaluates the complete actual observations',async()=>{
  const f=await portalPartyObservationFixture(),authorize=vi.spyOn(f.compiler,'authorizeResponse'),grants=vi.spyOn(f.compiler,'assertCurrentReadGrants');
  await f.runInNamespace(async()=>{f.wire.length=0;authorize.mockClear();grants.mockClear();await f.run('before-send');
   expect(f.wire).toHaveLength(7);expect(new Set(f.wire.map(r=>r.actorId))).toEqual(new Set([f.actor]));
   for(const id of f.reviewers){expect(authorize.mock.calls.some(([input])=>input.principal.user.id===id&&input.resource.entityType==='services')).toBe(true);expect(grants.mock.calls.some(([input])=>input.principal.user.id===id)).toBe(true);}
  });expect(f.verifier().current()).toBeNull();expect(()=>f.verifier().assert(f.rounds.at(-1))).toThrow();expect(()=>f.verifier().assert({...f.rounds.at(-1)})).toThrow();
 });
 it('opens fresh SDK observations for the next checkpoint and cannot mutate the captured raw alias',async()=>{
  const f=await portalPartyObservationFixture();let changed=false;
  await f.runInNamespace(async()=>{f.state.afterReviewer=()=>{if(!changed){changed=true;f.nativeService.host='source-external-drift.invalid';}};f.wire.length=0;await f.run('before-send');expect(f.wire).toHaveLength(7);
   await expect(f.run('packet')).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_PORTAL_NATIVE_PUBLICATION_CHANGED'}});expect(f.wire.length).toBeGreaterThan(7);
  });
 });
 it.each(['services','secrets'])('keeps a non-superadmin reviewer current %s READ independent of the executor',async missing=>{
  const f=await portalPartyObservationFixture(1),id=f.reviewers[0];let replay=false;const response=f.compiler.authorizeResponse.bind(f.compiler);
  vi.spyOn(f.compiler,'authorizeResponse').mockImplementation(async input=>{if(input.principal.user.id===id)replay=true;return response(input);});
  await f.runInNamespace(async()=>{f.tables.users.find((u:any)=>u.id===id)!.super_admin=false;
   for(const [module,action]of [['workflows','approve'],['portal','read'],['services','read'],['plugins','read'],['consumers','read'],['secrets','read']])if(module!==missing)
    f.tables.iam_effective_grants.push({user_id:id,module,action,cluster_id:null,workspace_id:null,scope_type:'global',scope_values:[]});
   await expect(f.run('before-send')).rejects.toMatchObject({response:{code:missing==='services'?'WORKFLOW_BUSINESS_RESPONSE_READ_DENIED':'WORKFLOW_BUSINESS_SUBJECT_SECRET_DENIED'}});
  });expect(replay).toBe(true);
 });
 it('accepts a non-superadmin reviewer with all six current grants in its own response scope',async()=>{
  const f=await portalPartyObservationFixture(1),id=f.reviewers[0];await f.runInNamespace(async()=>{f.tables.users.find((u:any)=>u.id===id)!.super_admin=false;
   for(const [module,action]of [['workflows','approve'],['portal','read'],['services','read'],['plugins','read'],['consumers','read'],['secrets','read']])
    f.tables.iam_effective_grants.push({user_id:id,module,action,cluster_id:null,workspace_id:null,scope_type:'global',scope_values:[]});
   const result=await f.run('before-send').catch((error:any)=>{throw Error('SOURCE_FULL_GRANT_REVIEWER_DENIED:'+error?.getResponse?.()?.code)});expect(result).toMatchObject({plan:{workflowId:f.plan.workflowId}});
  });
 });
 it('rejects a reviewer scope that adds an unobserved required resource without inventing SDK, EOF or absence',async()=>{
  const f=await portalPartyObservationFixture();await f.runInNamespace(async()=>{
   const resolve=f.compiler.resolveAbsenceReadScope.bind(f.compiler);
   vi.spyOn(f.compiler,'resolveAbsenceReadScope').mockImplementation(async input=>{const scope=await resolve(input);return input.role==='reviewer'?{...scope,resources:[...scope.resources,{...scope.resources[0],path:'/schemas/routes'}]}:scope;});
   await expect(f.run('before-send')).rejects.toMatchObject({response:{code:'WORKFLOW_PORTAL_OBSERVATION_SCOPE_CHANGED'}});
  });
 });
 it('rejects a copied transaction inside an otherwise current original round',async()=>{
  const f=await portalPartyObservationFixture(1);await f.runInNamespace(async()=>{f.state.afterReviewer=async(id:string)=>{await(f.runtime as any).subject(f.plan,id,'approve','before-send',{...f.db});};
   await expect(f.run('before-send')).rejects.toMatchObject({response:{code:'WORKFLOW_PORTAL_OBSERVATION_PARTY_REQUIRED'}});
  });
 });
 it('keeps canonical last-party membership revocation after all raw observation evaluations',async()=>{
  const f=await portalPartyObservationFixture();await f.runInNamespace(async()=>{f.state.afterReviewer=(id:string)=>{if(id===f.reviewers.at(-1))f.state.invalidated=true;};
   await expect(f.run('before-send')).rejects.toBeDefined();
  });
 });
 it('closes an expired private round instead of reviving the observations after an awaited reviewer check',async()=>{
  const f=await portalPartyObservationFixture(1);await f.runInNamespace(async()=>{f.state.afterReviewer=()=>{const now=performance.now();vi.spyOn(performance,'now').mockReturnValue(now+30001);};
   await expect(f.run('before-send')).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_PORTAL_INSPECTION_CLOSED'}});
  });
 });
 it('keeps a real executor without Consumer WRITE denied and cannot turn it into a reviewer through a role DTO',async()=>{
  const f=await portalPartyObservationFixture(1);f.user.super_admin=false;f.tables.iam_effective_grants=f.tables.iam_effective_grants.filter((g:any)=>!(g.user_id===f.actor&&g.module==='consumers'&&g.action==='write'));
  await f.runInNamespace(async()=>{
   await expect(f.compiler.currentReadInput(f.plan,f.draft,f.actor,'reviewer',f.db)).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_READ_BINDING_CHANGED'}});
   await expect(f.run('before-send')).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_ABSENT_SUBJECT_READ_DENIED'}});
  });
 });
 it.each(['user','team']as const)('pins the original %s binding DB-relative deadline across an awaited reviewer replay',async source=>{
  const f=await portalPartyObservationFixture(1);let replay=false;await f.runInNamespace(async()=>{f.grantState.source=source;f.grantState.expiresAt=new Date(Date.now()+5000).toISOString();
   f.state.afterReviewer=()=>{replay=true;const now=performance.now();vi.spyOn(performance,'now').mockReturnValue(now+5001);};
   await expect(f.run('before-send')).rejects.toMatchObject({response:{code:'WORKFLOW_PORTAL_OBSERVATION_ORIGINAL_REQUIRED'}});
  });expect(replay).toBe(true);
 });
 it('allows a new independently fresh round after an old 30-second token closes when its grants have not expired',async()=>{
  const f=await portalPartyObservationFixture(1);await f.runInNamespace(async()=>{await f.run('step');const old=f.rounds.at(-1);const now=performance.now();vi.spyOn(performance,'now').mockReturnValue(now+30001);
   await expect(f.run('packet')).resolves.toMatchObject({plan:{workflowId:f.plan.workflowId}});expect(()=>f.verifier().assert(old)).toThrow();
  });
 });

});
