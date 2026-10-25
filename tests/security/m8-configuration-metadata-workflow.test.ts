import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {configurationApprovedFixture as fixture,id} from './m8-configuration-approved-fixture';
import {validateWorkflowPlan} from '../../apps/console-api/src/modules/workflows/workflow-validation';
import {assertConfigurationMetadataWorkflowPlan,configurationMetadataAction,configurationMetadataLedgerInput,type ConfigurationMetadataResource,type ConfigurationMetadataOperation} from '../../apps/console-api/src/modules/workflows/configuration-metadata-workflow';
import {WorkflowPlansService,workflowMetadataProjection} from '../../apps/console-api/src/modules/workflows/workflow-plans.service';
import {WorkflowRegistryService} from '../../apps/console-api/src/modules/workflows/workflow-registry.service';
async function metadataPlan(resource:ConfigurationMetadataResource='config_snapshot_schedules',operation:ConfigurationMetadataOperation='create'){
  const f=await fixture(),plan=structuredClone(f.wrapper),resourceId=id(77),payload:any=operation==='create'?resource==='configuration_gitops_runs'
    ?{sourceJobId:id(78),repositoryLabel:'project/configs',commitSha:'a'.repeat(40),pipelineReference:'release/CI:42'}
    :{name:'每日快照',intervalMinutes:30,timezone:'Asia/Shanghai',retentionDays:30}
    :operation==='update'?{revision:3,name:'生产快照',intervalMinutes:60,timezone:'UTC',retentionDays:45,paused:false}
    :operation==='restore'?{revision:3}:{revision:3,confirmed:true,confirm_name:'原对象'};
  const metadata={jobId:f.jobId,resourceType:resource,resourceId,operation,payload};
  plan.kind='configuration-metadata';plan.subject={type:resource,id:resourceId};
  Object.assign(plan.steps[0],{handler:'configuration.metadata',entityType:resource,entityId:resourceId,permissionAction:configurationMetadataAction(metadata),metadata,before:operation==='create'?null:{id:resourceId,revision:3,state:operation==='restore'||operation==='purge'?'deleted':'ready'},metadataRevision:operation==='create'?0:3});
  plan.steps[0].metadataBeforeHmac=f.secrets.fingerprint(plan.steps[0].before);plan.steps[0].metadataPayloadHmac=f.secrets.fingerprint(metadata);
  const input=configurationMetadataLedgerInput(metadata);Object.assign(f.job,{scope_kind:'workspace',root_ids:[],input_secret:f.secrets.encrypt(input,`configuration-job:${f.jobId}`),request_hmac:f.secrets.fingerprint({scope:{...f.plan.scope},kind:'compare',input})});
  return{f,plan,payload,metadata,resourceId};
}
describe('M8 separate fixed metadata approval contract',()=>{
  beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','bc'.repeat(32));vi.stubEnv('APP_SECRET','synthetic-metadata-unit-secret-at-least-thirty-two-characters');});afterEach(()=>vi.unstubAllEnvs());
  it.each([['config_snapshots','archive'],['config_snapshots','restore'],['config_snapshots','purge'],['config_snapshot_schedules','create'],['config_snapshot_schedules','update'],['config_snapshot_schedules','archive'],['config_snapshot_schedules','restore'],['config_snapshot_schedules','purge'],['configuration_gitops_runs','create']] as const)('supports only real %s %s metadata with no native packet',async(resource,operation)=>{
    const {plan}=await metadataPlan(resource,operation);expect(()=>validateWorkflowPlan(plan)).not.toThrow();expect(assertConfigurationMetadataWorkflowPlan(plan).nativeRequests).toEqual([]);
  });
  it.each(['foreignKind','v2Kind','jobSubject','portalSubject','foreignSubject','foreignResource','extraEnvelope','nativeStep','secondStep','nativePacket','generatedSecret','credential','parent','mutationBody','mutationAction','dependency','callback','sql','yaml','secret','wrongCreateRevision','presentCreateBefore','foreignHandler','deleteAsWrite','extraPayload','absentName','badInterval','badRetention','badTimezone','invalidUUID','nonBooleanPaused','revisionMismatch','unconfirmed','gitopsArchive','snapshotCreate'])('rejects %s escalation at plan validation',async(which)=>{
    const type=which==='gitopsArchive'?'configuration_gitops_runs':which==='snapshotCreate'||which==='unconfirmed'||which==='deleteAsWrite'?'config_snapshots':'config_snapshot_schedules';
    const operation=which==='revisionMismatch'||which==='nonBooleanPaused'?'update':which==='unconfirmed'||which==='deleteAsWrite'?'archive':'create';
    const {plan,payload,metadata}=await metadataPlan(type,operation),p=plan as any,s=p.steps[0];
    if(which==='foreignKind')p.kind='portal-metadata';if(which==='v2Kind')p.kind='configuration_v2';if(which==='jobSubject')p.subject.type='configuration_jobs';if(which==='portalSubject')p.subject.type='portal_content';
    if(which==='foreignSubject')p.subject.id=id(88);if(which==='foreignResource')metadata.resourceType='config_snapshots';if(which==='extraEnvelope')Object.assign(metadata,{approved:true});
    if(which==='nativeStep')s.kind='native';if(which==='secondStep')p.steps.push({...s,id:id(88),order:2});if(which==='nativePacket')s.nativeRequests=[{method:'POST',canonicalPath:'/consumers'}];if(which==='generatedSecret')p.generated={key:'synthetic-secret'};
    if(which==='credential')s.credentialKind='key-auth';if(which==='parent')s.parentId=id(88);if(which==='mutationBody')s.mutationPayload={};if(which==='mutationAction')s.mutationAction='create';if(which==='dependency')s.dependencies=[id(88)];
    if(['callback','sql','yaml','secret','extraPayload'].includes(which))payload[which]='forbidden field';if(which==='wrongCreateRevision')s.metadataRevision=1;if(which==='presentCreateBefore')s.before={id:p.subject.id};if(which==='foreignHandler')s.handler='configuration_v2';
    if(which==='deleteAsWrite')s.permissionAction='write';if(which==='absentName')delete payload.name;if(which==='badInterval')payload.intervalMinutes=1;if(which==='badRetention')payload.retentionDays=10000;if(which==='badTimezone')payload.timezone='invalid/time-zone';
    if(which==='invalidUUID')metadata.jobId='not-a-server-job';if(which==='nonBooleanPaused')payload.paused='false';if(which==='revisionMismatch')payload.revision=4;if(which==='unconfirmed')payload.confirmed=false;if(which==='gitopsArchive')metadata.operation='archive';
    expect(()=>validateWorkflowPlan(p)).toThrow();
  });
  it('rejects accessor/prototype/class payloads before invoking their executable properties',async()=>{
    const {plan}=await metadataPlan(),calls=vi.fn(),metadata=plan.steps[0].metadata as any;
    metadata.payload=Object.defineProperty({},'name',{get:calls,enumerable:true});expect(()=>assertConfigurationMetadataWorkflowPlan(plan)).toThrow();expect(calls).not.toHaveBeenCalled();
    metadata.payload=Object.assign(Object.create({callback:'inherited'}),{name:'daily',intervalMinutes:5,timezone:'UTC',retentionDays:30});expect(()=>assertConfigurationMetadataWorkflowPlan(plan)).toThrow();
    metadata.payload=JSON.parse('{"__proto__":{},"name":"daily","intervalMinutes":5,"timezone":"UTC","retentionDays":30}');expect(()=>assertConfigurationMetadataWorkflowPlan(plan)).toThrow();
  });
  it('registers one fixed metadata handler, without opening arbitrary config handlers',async()=>{
    const registry=new WorkflowRegistryService(),h={authorize:vi.fn(),inspect:vi.fn(),apply:vi.fn()};registry.register('configuration.metadata',h);expect(registry.get('configuration.metadata')).toBeTruthy();expect(()=>registry.register('configuration.metadata.native',h)).toThrow();
  });
  it('keeps approval review diff populated while excluding secrets and executable fields',()=>{
    const projected=workflowMetadataProjection({jobId:id(1),resourceType:'config_snapshot_schedules',resourceId:id(2),operation:'update',payload:{name:'每日快照',revision:2,intervalMinutes:60,timezone:'UTC',retentionDays:30,paused:true,password:'synthetic-secret',callback:'code',yaml:'content'},secret:'hidden'});
    expect(projected).toMatchObject({operation:'update',payload:{name:'每日快照',revision:2,intervalMinutes:60,timezone:'UTC',retentionDays:30,paused:true}});expect(JSON.stringify(projected)).not.toMatch(/password|synthetic-secret|callback|yaml|hidden/);
  });
  it.each(['owner','nativePlan','kind','scope','beforeHmac','payloadHmac'])('refuses actual ledger %s before workflow INSERT',async(which)=>{
    const {f,plan}=await metadataPlan();Object.assign(f.job,{kind:'compare',plan_id:null});if(which==='owner')f.job.actor_id=id(88);if(which==='nativePlan')f.job.plan_id=id(88);if(which==='kind')f.job.kind='apply';if(which==='scope')f.job.transport_scope='0'.repeat(64);if(which==='beforeHmac')plan.steps[0].metadataBeforeHmac='0'.repeat(64);if(which==='payloadHmac')plan.steps[0].metadataPayloadHmac='0'.repeat(64);
    const repo=new WorkflowPlansService(f.db,f.secrets,{append:vi.fn()}as any);await expect(repo.persist(plan,'original-metadata-key',{},f.db,{requestId:id(66),ip:'127.0.0.1'})).rejects.toMatchObject({response:{code:'CONFIGURATION_METADATA_WORKFLOW_BINDING_INVALID'}});expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('allows an absent new resource only through a separately owned metadata ledger; requires module write',async()=>{
    const {f,plan}=await metadataPlan();Object.assign(f.job,{kind:'compare',plan_id:null});const one=f.db.one;f.db.one=vi.fn(async(sql:string,p:any[])=>sql.includes('FROM config_snapshot_schedules')?null:one(sql,p));
    await expect(f.verifier.assertSubject(plan,f.actor,'write')).resolves.toBeUndefined();expect(f.authz.assertWholeWorkspace).toHaveBeenCalledWith(f.actor,f.cid,f.wid,'snapshots','write');expect(f.kong.request).not.toHaveBeenCalled();
    await expect(f.verifier.assertSubject(plan,{...f.actor,id:id(88)},'write')).rejects.toThrow();
  });
  it('does not reuse configuration-metadata as V2 or Portal native execution authority',async()=>{
    const {f,plan}=await metadataPlan();Object.assign(f.job,{kind:'compare',plan_id:null});f.wrapper.kind=plan.kind;f.wrapper.subject=plan.subject;f.wrapper.steps=plan.steps;await f.seal();
    await expect(f.run(()=>f.verifier.runConfigurationExecution(f.executionId,async()=>undefined))).rejects.toThrow();expect(f.kong.request).not.toHaveBeenCalled();
  });
  it.each(['owner','physical','revision','deleted','purged','wrongLedgerWorkflow','cancelledLedger','createOccupied'])('rejects current metadata %s facts without any native request',async(which)=>{
    const {f,plan,resourceId}=await metadataPlan('config_snapshot_schedules',which==='createOccupied'?'create':'update');Object.assign(f.job,{kind:'compare',plan_id:null});
    const row:any={id:resourceId,cluster_id:f.cid,workspace_id:f.wid,transport_scope:f.job.transport_scope,owner_user_id:f.actor.id,revision:3,state:'active',purged_at:null};
    if(which==='owner')row.owner_user_id=id(88);if(which==='physical')row.transport_scope='0'.repeat(64);if(which==='revision')row.revision=4;if(which==='deleted')row.state='deleted';if(which==='purged')row.purged_at=new Date();if(which==='wrongLedgerWorkflow')f.job.workflow_id=id(88);if(which==='cancelledLedger')f.job.state='cancelled';
    const one=f.db.one;f.db.one=vi.fn(async(sql:string,p:any[])=>sql.includes('FROM config_snapshot_schedules')?row:one(sql,p));
    await expect(f.verifier.assertSubject(plan,f.actor,'write')).rejects.toThrow();expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('requires snapshots.delete for an exact archived purge and cannot turn it into a native restore',async()=>{
    const {f,plan,resourceId}=await metadataPlan('config_snapshots','purge');Object.assign(f.job,{kind:'compare',plan_id:null});
    const row={id:resourceId,cluster_id:f.cid,workspace_id:f.wid,transport_scope:f.job.transport_scope,created_by:f.actor.id,revision:3,state:'deleted'};
    const one=f.db.one;f.db.one=vi.fn(async(sql:string,p:any[])=>sql.includes('FROM config_snapshots')?row:one(sql,p));
    await expect(f.verifier.assertSubject(plan,f.actor,'write')).resolves.toBeUndefined();expect(f.authz.assertWholeWorkspace).toHaveBeenCalledWith(f.actor,f.cid,f.wid,'snapshots','delete');expect(f.kong.request).not.toHaveBeenCalled();
    f.authz.assertWholeWorkspace.mockImplementation(async(_actor:any,_cid:any,_wid:any,module:any,action:any)=>{if(module==='snapshots'&&action==='delete')throw Error('deleted grant');});
    await expect(f.verifier.assertSubject(plan,f.actor,'write')).rejects.toThrow();expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('rejects a sealed V2 handler under a Portal kind in the actual original M6 capability reader',async()=>{
    const f=await fixture();f.wrapper.kind='portal-metadata';f.wrapper.subject.type='portal_settings';f.workflow.kind=f.wrapper.kind;f.workflow.subject_type=f.wrapper.subject.type;await f.seal();
    await expect(f.run(()=>f.verifier.runApprovedExecution(f.wrapperExecution.id,async()=>undefined))).rejects.toMatchObject({response:{code:'APPROVED_SUBJECT_MISMATCH'}});expect(f.authz.assertWholeWorkspace).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
  });
  it.each(['resource','operation','body','requestHmac'])('rejects a valid metadata plan borrowing a different sealed ledger %s',async(which)=>{
    const {f,plan,metadata}=await metadataPlan();Object.assign(f.job,{kind:'compare',plan_id:null});const input:any=structuredClone(configurationMetadataLedgerInput(metadata));
    if(which==='resource')input.resourceId=id(88);if(which==='operation')input.operation='purge';if(which==='body')input.payload.intervalMinutes=120;
    if(which==='requestHmac')f.job.request_hmac='0'.repeat(64);else f.job.input_secret=f.secrets.encrypt(input,`configuration-job:${f.jobId}`);
    const repo=new WorkflowPlansService(f.db,f.secrets,{append:vi.fn()}as any);await expect(repo.persist(plan,'original-ledger-key',{},f.db,{requestId:id(66),ip:'127.0.0.1'})).rejects.toThrow();expect(f.db.exec).not.toHaveBeenCalled();
    await expect(f.verifier.assertSubject(plan,f.actor,'write')).rejects.toThrow();expect(f.kong.request).not.toHaveBeenCalled();
  });
});
