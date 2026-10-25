import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {ConfigurationService} from '../../apps/console-api/src/modules/configuration/configuration.service';
import {DURABLE_CONFIGURATION_PRESENCE_QUERY} from '../../apps/console-api/src/modules/configuration/configuration-durable.repository';
import {ConflictException,ForbiddenException} from '@nestjs/common';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {configurationApprovedFixture as fixture,id} from './m8-configuration-approved-fixture';

beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.stubEnv('APP_SECRET','synthetic-secret-with-at-least-thirty-two-characters');});
afterEach(()=>vi.unstubAllEnvs());

async function installed(row:unknown){
  const f=await fixture(),db={one:vi.fn(async(sql:string,args:unknown[])=>{
    expect(args).toEqual([f.job.id,f.wrapper.clusterId,f.wrapper.workspaceId]);
    if(sql===DURABLE_CONFIGURATION_PRESENCE_QUERY)return row;
    const originQuery=`SELECT j.required_origin_kind,j.required_origin_id,j.required_origin_hmac,
      EXISTS(SELECT 1 FROM configuration_job_origin_bindings b WHERE b.job_id=j.id) AS has_job_origin,
      EXISTS(SELECT 1 FROM configuration_plan_origin_bindings b WHERE b.job_id=j.id OR b.plan_id=j.plan_id) AS has_plan_origin
      FROM configuration_jobs j WHERE j.id=$1 AND j.cluster_id=$2 AND j.workspace_id=$3`;
    if(sql===originQuery)return row;throw new Error('UNEXPECTED_ORIGIN_ABSENCE_SQL');
  })},approved:any={},stored:any={};
  const service=Object.assign(Object.create(ConfigurationService.prototype),{db,context:f.context,
    repo:{installEvidenceWriter:vi.fn(),installScheduledExecutionOriginPolicy:vi.fn()},registry:{register:vi.fn()},
    approved:{installConfigurationDelegate:(delegate:any)=>Object.assign(approved,delegate)},
    workflowPlans:{installConfigurationOriginDelegate:(delegate:any)=>Object.assign(stored,delegate)}});
  service.onModuleInit();return{f,db,approved,stored};
}

describe('M10 actual installed origin callbacks without ConfigurationOriginService',()=>{
  const legacy={authority_domain:null,durable_issue_id:null,has_durable_issue:false,has_durable_binding:false,required_origin_kind:null,required_origin_id:null,required_origin_hmac:null,has_job_origin:false,has_plan_origin:false};
  it('retains only an actual unmarked, unbound legacy job and performs the scoped SQL check',async()=>{
    const s=await installed(legacy);
    await expect(s.approved.assertOrigin(s.f.wrapper,s.f.actor.id,'read',s.db)).resolves.toBeUndefined();
    await expect(s.approved.assertStoredOrigin(s.f.wrapper,s.db)).resolves.toBeUndefined();
    await expect(s.stored.assertStoredOrigin(s.f.wrapper,s.db)).resolves.toBeUndefined();
    expect(s.db.one).toHaveBeenCalledTimes(9);
    for(const [sql,args]of s.db.one.mock.calls as any){
      if(sql===DURABLE_CONFIGURATION_PRESENCE_QUERY){expect(sql).toContain('configuration_durable_issues');expect(sql).toContain('configuration_durable_bindings');}
      else{expect(sql).toContain('configuration_job_origin_bindings');expect(sql).toContain('configuration_plan_origin_bindings');}
      expect(args).toEqual([s.f.job.id,s.f.wrapper.clusterId,s.f.wrapper.workspaceId]);
    }
    expect(s.f.kong.request).not.toHaveBeenCalled();
  });
  it.each([
    {case:'marked',row:{...legacy,required_origin_kind:'governance-promote',required_origin_id:id(77),required_origin_hmac:'d'.repeat(64)}},
    {case:'partial kind',row:{...legacy,required_origin_kind:'governance-promote'}},
    {case:'partial id',row:{...legacy,required_origin_id:id(77)}},
    {case:'partial hash',row:{...legacy,required_origin_hmac:'d'.repeat(64)}},
    {case:'invalid blank marker',row:{...legacy,required_origin_kind:''}},
    {case:'stray job binding',row:{...legacy,has_job_origin:true}},
    {case:'stray plan binding',row:{...legacy,has_plan_origin:true}},
    {case:'missing actual job',row:null},
  ])('fails closed for $case through each installed workflow callback',async({row})=>{
    const s=await installed(row);
    for(const callback of [()=>s.approved.assertOrigin(s.f.wrapper,s.f.actor.id,'approve',s.db),
      ()=>s.approved.assertStoredOrigin(s.f.wrapper,s.db),()=>s.stored.assertStoredOrigin(s.f.wrapper,s.db)])
      await expect(callback()).rejects.toMatchObject({response:{code:row===null?'CONFIGURATION_DURABLE_PROVIDER_UNAVAILABLE':'CONFIGURATION_ORIGIN_PROVIDER_UNAVAILABLE'}});
    expect(s.f.kong.request).not.toHaveBeenCalled();
  });
  it('does not replace a failed stored-origin query with a permissive callback',async()=>{
    const s=await installed(legacy);s.db.one.mockRejectedValue(new Error('storage unavailable'));
    await expect(s.approved.assertOrigin(s.f.wrapper,s.f.actor.id,'write',s.db)).rejects.toThrow('storage unavailable');
    expect(s.f.kong.request).not.toHaveBeenCalled();
  });
});

describe('M10 original Promote receipt before child registration',()=>{
  async function bridge(error:unknown,child:any=null){
    const secrets=new SecretService(),parent:any={id:id(600),actor_id:id(601),cluster_id:id(602),workspace_id:id(603),target_cluster_id:id(604),target_workspace_id:id(605),state:'planning',configuration_job_id:null,plan_id:null};
    const selection={includeSecrets:false,includeCredentials:false,targetWorkspaceCode:'target'};
    parent.selection_secret=secrets.encrypt(selection,`governance:promotion-selection:${parent.id}`);parent.selection_hmac=secrets.fingerprint(selection);
    const actor={user:{id:parent.actor_id,username:'fixture',superAdmin:false},requestId:'original-parent-receipt'},audit={append:vi.fn(async()=>{})};
    const db:any={one:vi.fn(async(sql:string)=>sql.includes('governance_promotions')?{...parent}:sql.includes('FROM configuration_jobs')?child:null),
      exec:vi.fn(async(sql:string,p:any[])=>{if(sql.includes('UPDATE governance_promotions')){parent.state='blocked';parent.error_code=p[1];return 1;}throw new Error('Unexpected write');}),transaction:async(fn:any)=>fn(db)};
    const service=Object.assign(Object.create(ConfigurationService.prototype),{db,secrets,audit,
      origins:{run:(fn:any)=>fn(),runTargetPlanning:async(_id:any,_actor:any,fn:any)=>fn(),compile:vi.fn(async()=>{throw error;})},
      withActor:async(_cid:any,_actor:any,_action:any,fn:any)=>{await Promise.resolve();return fn();}});
    const locator={promotionId:parent.id,sourceClusterId:parent.cluster_id,sourceWorkspaceId:parent.workspace_id,targetClusterId:parent.target_cluster_id,targetWorkspaceId:parent.target_workspace_id};
    return{service,db,parent,audit,actor,locator,error};
  }
  it('persists the known asynchronous source drift rejection as blocked with the original parent, without registering or executing another child',async()=>{
    const s=await bridge(new ConflictException({code:'CONFIGURATION_ORIGIN_SOURCE_CHANGED'}));
    await expect(s.service.createGovernancePromotionPlan(s.locator,s.actor)).rejects.toBe(s.error);
    expect(s.parent).toMatchObject({state:'blocked',error_code:'CONFIGURATION_ORIGIN_SOURCE_CHANGED'});expect(s.audit.append).toHaveBeenCalledOnce();
    const childQuery=s.db.one.mock.calls.find(([sql]:any)=>sql.includes('FROM configuration_jobs')) as any;
    expect(childQuery[1]).toEqual([s.parent.target_cluster_id,s.parent.target_workspace_id,s.parent.actor_id,`governance-promote-${s.parent.id}`,s.parent.id]);
    expect(s.db.exec.mock.calls.every(([sql]:any)=>sql.includes('UPDATE governance_promotions'))).toBe(true);
  });
  it('does not infer a failed child or replay work when an actual child already exists',async()=>{
    const s=await bridge(new ConflictException({code:'CONFIGURATION_ORIGIN_SOURCE_CHANGED'}),{id:id(610)});
    await expect(s.service.createGovernancePromotionPlan(s.locator,s.actor)).rejects.toBe(s.error);expect(s.parent.state).toBe('planning');expect(s.db.exec).not.toHaveBeenCalled();expect(s.audit.append).not.toHaveBeenCalled();
  });
  it('preserves unknown commit errors and the original recoverable planning receipt',async()=>{
    const s=await bridge(new Error('Commit acknowledgement unavailable'));
    await expect(s.service.createGovernancePromotionPlan(s.locator,s.actor)).rejects.toBe(s.error);expect(s.parent.state).toBe('planning');expect(s.db.exec).not.toHaveBeenCalled();expect(s.audit.append).not.toHaveBeenCalled();
  });
  it('cannot mark an arbitrary caller-selected parent as blocked',async()=>{
    const s=await bridge(new ConflictException({code:'CONFIGURATION_ORIGIN_SOURCE_CHANGED'}));
    await expect(s.service.createGovernancePromotionPlan(s.locator,{...s.actor,user:{...s.actor.user,id:id(620)}})).rejects.toBeInstanceOf(ForbiddenException);
    expect(s.db.exec).not.toHaveBeenCalled();expect(s.audit.append).not.toHaveBeenCalled();
  });
});
