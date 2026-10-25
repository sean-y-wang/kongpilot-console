import{describe,it,expect,beforeEach,afterEach,vi}from'vitest';
import{configurationApprovedFixture as approvedFixture,id}from'./m8-configuration-approved-fixture';
import{validateWorkflowPlan}from'../../apps/console-api/src/modules/workflows/workflow-validation';
import{WorkflowPlansService}from'../../apps/console-api/src/modules/workflows/workflow-plans.service';
import{WorkflowRegistryService}from'../../apps/console-api/src/modules/workflows/workflow-registry.service';
import{DURABLE_CONFIGURATION_PRESENCE_QUERY}from'../../apps/console-api/src/modules/configuration/configuration-durable.repository';
/** This suite models an explicitly proven legacy SQL011 wrapper. Never turn a
 * missing/partial SQL038 observation into negative facts, or replace a provider. */
async function fixture(){
  const f=await approvedFixture(),original=f.db.one.getMockImplementation()!;
  Object.assign(f.job,{authority_domain:null,durable_issue_id:null,required_origin_kind:null,required_origin_id:null,required_origin_hmac:null});
  f.db.one.mockImplementation(async(sql:string,params:any[])=>{
    if(sql===DURABLE_CONFIGURATION_PRESENCE_QUERY){
      if(JSON.stringify(params)!==JSON.stringify([f.job.id,f.cid,f.wid]))return null;
      return{authority_domain:f.job.authority_domain,durable_issue_id:f.job.durable_issue_id,has_durable_issue:false,has_durable_binding:false};
    }
    if(sql==='SELECT * FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3'&&JSON.stringify(params)!==JSON.stringify([f.job.id,f.cid,f.wid]))return null;
    if(sql==='SELECT * FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3'&&JSON.stringify(params)!==JSON.stringify([f.cid,f.wid,f.job.id]))return null;
    return original(sql,params);
  });return f;
}
describe('M8 metadata-only V1 configuration approval wrapper',()=>{
  beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','cd'.repeat(32));vi.stubEnv('APP_SECRET','synthetic-config-secret-with-at-least-32-characters');});afterEach(()=>vi.unstubAllEnvs());
  it('allows only a fixed registered server handler for a valid small wrapper',async()=>{const f=await fixture();expect(()=>validateWorkflowPlan(f.wrapper)).not.toThrow();
    const registry=new WorkflowRegistryService(),handler={authorize:vi.fn(),inspect:vi.fn(),apply:vi.fn()};registry.register('configuration_v2',handler);expect(registry.get('configuration_v2')).toBeTruthy();expect(()=>registry.register('configuration.any-native',handler)).toThrow();expect(()=>registry.register('configuration_v2',handler)).toThrow();
  });
  it.each(['native','secondStep','secondPacket','portalKind','portalSubject','foreignJob','extraPayload','foreignHandler','generated','parent','credential','mutationPayload','dependency','invalidHash'])("rejects wrapper %s escalation",async(which)=>{const f=await fixture(),p:any=f.wrapper,step=p.steps[0];
    if(which==='native')step.kind='native';if(which==='secondStep')p.steps.push({...step,id:id(77),order:2});if(which==='secondPacket')step.nativeRequests.push({method:'POST',canonicalPath:'/consumers'});if(which==='portalKind')p.kind='portal-metadata';if(which==='portalSubject')p.subject.type='portal_content';if(which==='foreignJob')step.metadata.jobId=id(77);if(which==='extraPayload')step.metadata.approved=true;if(which==='foreignHandler')step.handler='portal.credential.activate';if(which==='generated')p.generated={key:'synthetic-secret'};if(which==='parent')step.parentId=id(77);if(which==='credential')step.credentialKind='key-auth';if(which==='mutationPayload')step.mutationPayload={};if(which==='dependency')step.dependencies=[id(77)];if(which==='invalidHash')step.metadata.planHash='client-hash';
    expect(()=>validateWorkflowPlan(p)).toThrow();
  });
  it('binds actual job owner/plan tuple before any SQL workflow INSERT',async()=>{const f=await fixture();const repository=new WorkflowPlansService(f.db,f.secrets,{append:vi.fn()}as any);f.job.actor_id=id(99);
    await expect(repository.persist(f.wrapper,'original-wrapper-key',{},f.db,{requestId:id(66),ip:'127.0.0.1'})).rejects.toMatchObject({response:{code:'CONFIGURATION_WORKFLOW_BINDING_INVALID'}});expect(f.db.exec).not.toHaveBeenCalled();
  });
  it.each(['owner','plan-id','plan-revision','plan-hash','transport','cluster-revision','workspace-revision','mode','approval','workflow-id'] as const)('retains original %s binding refusal after explicit legacy-domain proof',async changed=>{
    const f=await fixture(),repository=new WorkflowPlansService(f.db,f.secrets,{append:vi.fn()}as any);
    const patch:any=changed==='owner'?{actor_id:id(99)}:changed==='plan-id'?{plan_id:id(99)}:changed==='plan-revision'?{plan_revision:2}:changed==='plan-hash'?{plan_hash:'f'.repeat(64)}:changed==='transport'?{transport_scope:'f'.repeat(64)}:changed==='cluster-revision'?{cluster_revision:2}:changed==='workspace-revision'?{workspace_revision:2}:changed==='mode'?{execution_mode:'direct'}:changed==='approval'?{approval_required:false}:{workflow_id:id(99)};
    Object.assign(f.job,patch);await expect(repository.persist(f.wrapper,'original-wrapper-key',{},f.db,{requestId:id(66),ip:'127.0.0.1'})).rejects.toMatchObject({response:{code:'CONFIGURATION_WORKFLOW_BINDING_INVALID'}});
    expect(f.db.one.mock.calls.some(([sql]:any)=>sql===DURABLE_CONFIGURATION_PRESENCE_QUERY)).toBe(true);expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('rejects a different frozen version or metadata body/before hash before persisting',async()=>{const f=await fixture();const repository=new WorkflowPlansService(f.db,f.secrets,{append:vi.fn()}as any);f.wrapper.steps[0].metadataBeforeHmac='0'.repeat(64);
    await expect(repository.persist(f.wrapper,'original-wrapper-key',{},f.db,{requestId:id(66),ip:'127.0.0.1'})).rejects.toMatchObject({response:{code:'CONFIGURATION_WORKFLOW_BINDING_INVALID'}});expect(f.db.exec).not.toHaveBeenCalled();
  });
});
