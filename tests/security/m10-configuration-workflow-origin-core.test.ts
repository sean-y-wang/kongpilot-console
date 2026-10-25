import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {ForbiddenException} from '@nestjs/common';
import {configurationApprovedFixture as fixture,id} from './m8-configuration-approved-fixture';
import {WorkflowPlansService} from '../../apps/console-api/src/modules/workflows/workflow-plans.service';
import {WorkflowService} from '../../apps/console-api/src/modules/workflows/workflow.service';
import {WorkflowRegistryService} from '../../apps/console-api/src/modules/workflows/workflow-registry.service';
import {configurationOriginMarker} from '../../apps/console-api/src/modules/workflows/approved-execution.types';

// Actual private V2 proof verifier + encrypted plans. The fixed source-grant
// delegate below is an explicit synthetic boundary; root tests/real SQL own
// provenance binding and the current source-side reviewer grant evaluation.
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.stubEnv('APP_SECRET','synthetic-secret-with-at-least-thirty-two-characters');});
afterEach(()=>vi.unstubAllEnvs());
async function marked(){const f=await fixture({actualAuthorization:true});Object.assign(f.job,{required_origin_kind:'governance-promote',required_origin_id:id(77),required_origin_hmac:'d'.repeat(64)});
 (f.plan as any).originRef={version:1,kind:'governance-promote',originId:id(77),materialHmac:'d'.repeat(64)};await f.seal();return f;}
describe('M10 configuration workflow provenance core',()=>{
 it('denies a marked original private V2 execution when no source-origin callback is installed',async()=>{
  const f=await marked();await expect(f.run(()=>f.verifier.runConfigurationExecution(f.executionId,async()=>undefined))).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_POLICY_UNAVAILABLE'}});expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('verifies the real current requester and separate reviewer while retaining the executor SID',async()=>{
  const f=await marked(),origin=vi.fn(async(plan:any,actorId:string,action:string,tx:any)=>{
   expect(plan.workflowId).toBe(f.workflow.id);expect(tx).toBe(f.db);expect(f.context.current().actor!.id).toBe(f.actor.id);expect(f.context.current().sessionId).toBe(f.sid);
   expect(actorId).toBe(action==='approve'?f.approval.approver_id:f.actor.id);
  });(f.delegate as any).assertOrigin=origin;
  await expect(f.run(()=>f.verifier.runConfigurationExecution(f.executionId,async()=>undefined))).resolves.toBeUndefined();
  expect(origin.mock.calls.map(c=>[c[1],c[2]])).toEqual([[f.actor.id,'write'],[f.approval.approver_id,'approve'],[f.actor.id,'write'],[f.approval.approver_id,'approve']]);expect(f.kong.request).not.toHaveBeenCalled();
 });
 it.each(['missing','kind','id','hmac','version','extra'])('rejects %s originRef despite a correctly resealed configuration plan',async(which)=>{
  const f=await marked();(f.delegate as any).assertOrigin=vi.fn(async()=>{});const ref=(f.plan as any).originRef;
  if(which==='missing')delete(f.plan as any).originRef;if(which==='kind')ref.kind='caller-origin';if(which==='id')ref.originId=id(78);if(which==='hmac')ref.materialHmac='e'.repeat(64);if(which==='version')ref.version=2;if(which==='extra')ref.approved=true;
  await f.seal();await expect(f.run(()=>f.verifier.runConfigurationExecution(f.executionId,async()=>undefined))).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_PLAN_MISMATCH'}});expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('rejects an originRef pasted onto a legacy unmarked job',async()=>{
  const f=await fixture();(f.plan as any).originRef={version:1,kind:'governance-promote',originId:id(77),materialHmac:'d'.repeat(64)};await f.seal();
  await expect(f.run(()=>f.verifier.runConfigurationExecution(f.executionId,async()=>undefined))).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_PLAN_MISMATCH'}});
 });
 it.each(['requester','reviewer'])('a %s source-grant revocation stops private capability creation without native send',async(which)=>{
  const f=await marked();(f.delegate as any).assertOrigin=vi.fn(async(_p:any,_id:string,action:string)=>{if(action===(which==='requester'?'write':'approve'))throw new ForbiddenException({code:'GOVERNANCE_SOURCE_REVOKED'});});
  await expect(f.run(()=>f.verifier.runConfigurationExecution(f.executionId,async()=>undefined))).rejects.toMatchObject({response:{code:'GOVERNANCE_SOURCE_REVOKED'}});expect(f.kong.request).not.toHaveBeenCalled();
 });
 it.each(['read','write','approve']as const)('the workflow subject %s check always invokes its fixed origin callback',async(action)=>{
  const f=await marked(),origin=vi.fn(async()=>{throw new ForbiddenException({code:'GOVERNANCE_SOURCE_REVOKED'});});(f.delegate as any).assertOrigin=origin;
  await expect(f.run(()=>f.verifier.assertSubject(f.wrapper,f.actor,action))).rejects.toMatchObject({response:{code:'GOVERNANCE_SOURCE_REVOKED'}});expect(origin).toHaveBeenCalledWith(f.wrapper,f.actor.id,action,f.db);
 });
 it('the fixed workflow engine authorization cannot bypass origin through a permissive registered handler',async()=>{
  const f=await marked(),registry=new WorkflowRegistryService(),authorize=vi.fn(async()=>{});
  registry.register('configuration_v2',{authorize,inspect:async()=>({before:null,revision:1}),apply:async()=>({})});
  const workflow=new WorkflowService(f.db,{}as any,f.secrets,f.kong,f.context,f.authz,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,registry,f.verifier,{}as any);
  await expect(f.run(()=>(workflow as any).authorize(f.wrapper,{user:f.actor,workspaceId:f.wid},'read'))).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_POLICY_UNAVAILABLE'}});expect(authorize).not.toHaveBeenCalled();
 });
 it('stored-plan verification fails closed without the static origin hook and permits exact static verification without assuming an actor',async()=>{
  const f=await marked(),plans=new WorkflowPlansService(f.db,f.secrets,{}as any);
  await expect((plans as any).storedConfigurationOrigin(f.wrapper,f.db)).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_POLICY_UNAVAILABLE'}});
  const staticCheck=vi.fn(async(plan:any,tx:any)=>{expect(plan).toBe(f.wrapper);expect(tx).toBe(f.db);});plans.installConfigurationOriginDelegate({assertStoredOrigin:staticCheck});
  await expect((plans as any).storedConfigurationOrigin(f.wrapper,f.db)).resolves.toBeUndefined();expect(staticCheck).toHaveBeenCalledOnce();
  expect(()=>plans.installConfigurationOriginDelegate({assertStoredOrigin:staticCheck})).toThrow();
 });
 it('an unmarked legacy job still executes and invokes an installed callback for stray-origin validation',async()=>{
  const f=await fixture(),origin=vi.fn(async()=>{});(f.delegate as any).assertOrigin=origin;
  await expect(f.run(()=>f.verifier.runConfigurationExecution(f.executionId,async()=>undefined))).resolves.toBeUndefined();expect(origin.mock.calls.map(c=>c[2])).toEqual(['write','approve','write','approve']);
 });
 it.each([
  {required_origin_kind:'governance-promote'},
  {required_origin_id:id(77),required_origin_hmac:'d'.repeat(64)},
  {required_origin_kind:'governance-promote',required_origin_id:'not-a-uuid',required_origin_hmac:'d'.repeat(64)},
  {required_origin_kind:'governance-promote',required_origin_id:id(77),required_origin_hmac:'D'.repeat(64)},
  {required_origin_kind:'unknown',required_origin_id:id(77),required_origin_hmac:'d'.repeat(64)},
 ])('partial/malformed origin marker is never downgraded to legacy: %j',job=>expect(()=>configurationOriginMarker(job)).toThrow());
 it('absent and all-null legacy markers remain compatible',()=>{expect(configurationOriginMarker({})).toBeNull();expect(configurationOriginMarker({required_origin_kind:null,required_origin_id:null,required_origin_hmac:null})).toBeNull();});
});
