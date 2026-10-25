import {DURABLE_REJECTION_CONFLICT_QUERY,DURABLE_REJECTION_INSERT,DURABLE_REJECTION_QUERY,DURABLE_REJECTION_CODE} from '../../apps/console-api/src/modules/configuration/configuration-durable-rejection';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import type {DbService} from '../../apps/console-api/src/infrastructure/db.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {ConfigurationDurableService} from '../../apps/console-api/src/modules/configuration/configuration-durable.service';
import {ConfigurationDurableRepository,DURABLE_ISSUE_QUERY,DURABLE_BINDING_QUERY} from '../../apps/console-api/src/modules/configuration/configuration-durable.repository';
import {ConfigurationDurableCodec,durableConfigurationLocator} from '../../apps/console-api/src/modules/configuration/configuration-durable.codec';
import type {ConfigurationAccessService} from '../../apps/console-api/src/modules/configuration/configuration-access.service';
import type {CaptureGraph,ConfigPlan,ConfigurationAccessHandle} from '../../apps/console-api/src/modules/configuration/configuration.types';
import {normalizeWorkflowApprovalPolicy} from '../../apps/console-api/src/modules/workflows/workflow-approval-policy';
import type {EntityActor} from '../../apps/console-api/src/modules/entities/entities.types';
import {planAad,type WorkflowPlanV1} from '../../apps/console-api/src/modules/workflows/workflow.types';

const NOW=Date.parse('2026-10-15T20:00:00.000Z');
const HISTORY=`SELECT id,input_secret FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2
     AND kind IN('apply','rollback') ORDER BY created_at,id LIMIT 5001`;
const POLICY=`SELECT v.*,d.kind FROM workflow_definition_versions v JOIN workflow_definitions d
   ON d.id=v.definition_id AND d.cluster_id=v.cluster_id AND d.workspace_id=v.workspace_id AND d.current_version=v.version
   JOIN clusters c ON c.id=d.cluster_id AND c.deleted_at IS NULL AND c.execution_mode='approval' AND c.revision=$3
   WHERE d.cluster_id=$1 AND d.workspace_id=$2 AND d.kind='configuration_v2' AND d.status='active'`;
const CLOCK='SELECT clock_timestamp() AS observed_at';
function fixture(){
 const secrets=new SecretService(),context=new KongExecutionContextService();
 const ids={owner:randomUUID(),sid:randomUUID(),cluster:randomUUID(),workspace:randomUUID(),job:randomUUID(),plan:randomUUID(),definition:randomUUID(),reviewer:randomUUID()};
 const actor:EntityActor={user:{id:ids.owner,username:'durable-admission-fixture',superAdmin:true},workspaceId:ids.workspace,requestId:randomUUID(),ip:'127.0.0.1'};
 const scope={clusterId:ids.cluster,workspaceId:ids.workspace,transportScope:secrets.fingerprint('admission-fixture-transport'),kind:'workspace' as const,rootIds:[]};
 const expiresAt=new Date(NOW+600_000).toISOString(),handle=Object.freeze({}) as ConfigurationAccessHandle;
 const proof=Object.freeze({actorId:ids.owner,sessionId:ids.sid,permissionVersion:`${ids.owner}:1:1`,scope,expiresAt:NOW+90_000,
  captureEpoch:secrets.fingerprint('admission-capture'),clusterRevision:1,workspaceRevision:1,credentialEpoch:1,origin:'http' as const});
 const plan:ConfigPlan={scope,mode:'merge',steps:[],sourceManifestHmac:secrets.fingerprint('admission-source'),baselineManifestHmac:secrets.fingerprint('admission-baseline'),
  schemaHmac:secrets.fingerprint('admission-schema'),permissionVersion:proof.permissionVersion,clusterRevision:1,workspaceRevision:1,kongVersion:'1.5.1',recoveryComplete:true,expiresAt};
 const source:any={id:ids.job,cluster_id:ids.cluster,workspace_id:ids.workspace,plan_id:ids.plan,plan_revision:1,plan_hash:secrets.fingerprint(plan),
  actor_id:ids.owner,origin_session_id:ids.sid,origin_type:'http',state:'succeeded',kind:'import',authority_expires_at:expiresAt,expires_at:expiresAt,
  authority_domain:null,durable_issue_id:null,required_origin_kind:null,required_origin_id:null,required_origin_hmac:null,
  input_secret:secrets.encrypt({mode:'merge',documentHmac:secrets.fingerprint({fixture:'import-document'})},`configuration-job:${ids.job}`)};
 const policy=normalizeWorkflowApprovalPolicy({version:2,kind:'configuration_v2',allowSelfApproval:false,intentTtlHours:24,distinctAcrossStages:true,
  stages:[{level:1,name:'Configuration reviewer',mode:'any',threshold:1,selector:{users:[ids.reviewer]}}]},'configuration_v2');
 const data:{history:any[];definition:any;clock:any}={history:[],definition:{definition_id:ids.definition,version:1,kind:'configuration_v2',approval_format:2,
  policy:structuredClone(policy),policy_hash:secrets.fingerprint(policy)},clock:{observed_at:new Date(NOW)}};
 const query=vi.fn(async(sql:string,args:unknown[])=>{if(sql!==HISTORY)throw Error('UNEXPECTED_ADMISSION_SQL_QUERY');
  expect(args).toEqual([ids.cluster,ids.workspace]);return structuredClone(data.history);});
 const one=vi.fn(async(sql:string,args?:unknown[])=>{
  if(sql===DURABLE_REJECTION_CONFLICT_QUERY){expect(args?.slice(0,4)).toEqual([ids.plan,ids.cluster,ids.workspace,ids.owner]);expect(args?.[4]).toMatch(/^[A-Za-z\d._:-]{8,128}$/);return null;}
  if(sql===POLICY){expect(args).toEqual([ids.cluster,ids.workspace,proof.clusterRevision]);return structuredClone(data.definition);}
  if(sql===CLOCK){expect(args).toBeUndefined();return structuredClone(data.clock);}
  throw Error('UNEXPECTED_ADMISSION_SQL_ONE');
 });
 const exec=vi.fn(async()=>{throw Error('UNEXPECTED_ADMISSION_SQL_EXEC');}),transaction=vi.fn(async()=>{throw Error('UNEXPECTED_ADMISSION_SQL_TRANSACTION');});
 const db={one,query,exec,transaction} as unknown as DbService;
 let installed:any;
 const installDurableConfigurationPolicy=vi.fn((policy:any)=>{if(installed)throw Error('DURABLE_ACCESS_POLICY_ALREADY_INSTALLED');
  if(typeof policy?.verifyJob!=='function'||typeof policy?.verifyPlan!=='function')throw Error('INVALID_DURABLE_ACCESS_POLICY');installed=policy;});
 const assertCurrent=vi.fn(async(actual:ConfigurationAccessHandle,input:unknown)=>{expect(actual).toBe(handle);expect(input).toEqual({phase:'read'});return proof;});
 const access={assertCurrent,installDurableConfigurationPolicy} as unknown as ConfigurationAccessService;
 const redis={assertLeaseOwnership:vi.fn(async()=>{})};
 const repository=new ConfigurationDurableRepository(secrets),service=new ConfigurationDurableService(db,secrets,context,access,repository,redis as any);
 const run=<T>(fn:()=>Promise<T>,options:{sid?:string|null;clusterId?:string;workspaceId?:string;bind?:boolean;actor?:EntityActor}={})=>
  context.runHttp({requestId:actor.requestId},async()=>{
   const bound=options.actor??actor;if(options.bind!==false)context.bindHttpActor(bound.user,options.sid===null?undefined:options.sid??ids.sid);
   return context.runActor({actor:bound.user,clusterId:options.clusterId??ids.cluster,workspaceId:options.workspaceId??ids.workspace,module:'snapshots',action:'write',purpose:'configuration'},fn);
  });
 const begin=()=>service.begin(handle,source,plan,actor,'durable-admission-original-key');
 return{secrets,context,ids,actor,scope,proof,handle,plan,source,data,query,one,exec,transaction,assertCurrent,installDurableConfigurationPolicy,service,run,begin,db,redis};
}
/** Synthetic storage only. The real service, repository, AEAD/HMAC codec and
 * fixed publication interface remain unmocked; no Native client is present. */
function publicationFixture(f:ReturnType<typeof fixture>,d:ReturnType<ConfigurationDurableService['describe']>,writerFails=false){
 const serviceId=randomUUID(),freshPlanId=randomUUID(),workflowId=randomUUID(),observedAt=new Date(NOW).toISOString();
 const before={id:serviceId,name:'fresh-service',host:'fresh-upstream',port:80,protocol:'http',retries:5,tags:['workspace:fixture']};
 const entities=Object.fromEntries(['services','routes','consumers','plugins','upstreams','targets','certificates','ca_certificates','snis'].map(type=>[type,{fields:[]}])) as Record<string,unknown>;
 const schemaBase={entities,plugins:{},enabledPlugins:[],kongVersion:'1.5.1',adapterVersion:'kong-1.5-v1'},schemaHmac=f.secrets.fingerprint(schemaBase);
 const collections=['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis'].map(entityType=>({collectionKey:`/${entityType}`,
  entityType:entityType as CaptureGraph['collections'][number]['entityType'],queryHmac:f.secrets.fingerprint({path:`/${entityType}`,size:100}),pageSize:100,pageCount:1,
  recordCount:entityType==='services'?1:0,terminalObserved:true,cursorChainHmac:f.secrets.fingerprint({path:`/${entityType}`,offset:null,next:null}),coverageHmac:f.secrets.fingerprint({path:`/${entityType}`,eof:true})}));
 const baseline:CaptureGraph={scope:structuredClone(f.scope),objects:[{objectKey:`services:${serviceId}`,entityType:'services',nativeId:serviceId,objectWorkspaceId:f.ids.workspace,
  ownershipTags:before.tags,affected:true,referenceOnly:false,dependencies:[],payload:before,beforeHmac:f.secrets.fingerprint(before),schemaHmac,observedAt,
  recovery:{state:'complete',blockerCodes:[]},workspaceRevision:1}],collections,completeness:'complete',consistency:'console_fenced_best_effort',kongVersion:'1.5.1',
  adapterVersion:'kong-1.5-v1',schemaHmac,permissionVersion:f.proof.permissionVersion,captureEpoch:f.proof.captureEpoch,observedFrom:observedAt,observedUntil:observedAt,
  pageCount:collections.length,recordCount:1,byteCount:Buffer.byteLength(JSON.stringify(before)),nativeCallCount:collections.length+1,warningCodes:[],
  requiredCollections:collections.map(c=>c.collectionKey),schemas:{...schemaBase,schemaHmac},credentialEpoch:1,clusterRevision:1,workspaceRevision:1,
  jobId:randomUUID(),snapshotId:randomUUID(),versionId:randomUUID(),materialId:randomUUID()};
 const body={retries:4},recipeHmac=f.secrets.fingerprint({mode:'merge',fixture:'freshly-recompiled-import'});
 const step={stepId:randomUUID(),stepOrder:1,objectKey:`services:${serviceId}`,entityType:'services' as const,objectWorkspaceId:f.ids.workspace,clearMap:[],nativeId:serviceId,
  permissionAction:'write' as const,mutationAction:'update' as const,dependencies:[],body,before,bodyHmac:f.secrets.fingerprint(body),beforeHmac:f.secrets.fingerprint(before),
  nativeRequests:[{method:'PATCH' as const,canonicalPath:`/services/${serviceId}`,body,bodyHmac:f.secrets.fingerprint(body),beforeHmac:f.secrets.fingerprint(before)}],
  referenceOnly:false,blockerCodes:[],maskedDiff:[]};
 const plan:ConfigPlan={...structuredClone(f.plan),durableRef:{version:1,domain:'durable-configuration-v1',issueId:d.issueId},steps:[step],sourceManifestHmac:recipeHmac,
  baselineManifestHmac:f.secrets.fingerprint(baseline),schemaHmac,expiresAt:d.expiresAt};
 const identity={jobId:d.jobId,planId:freshPlanId,planRevision:1,planHash:f.secrets.fingerprint(plan)};
 const workflow:WorkflowPlanV1={version:1,clusterId:f.ids.cluster,workspaceId:f.ids.workspace,workflowId,planRevision:1,kind:'configuration_v2',executionMode:'approval',
  approvalRequired:true,subject:{type:'configuration_jobs',id:d.jobId},requester:{type:'console',id:f.ids.owner},definition:{id:f.ids.definition,version:1,policyHash:f.data.definition.policy_hash},
  issuedAt:d.issuedAt,expiresAt:d.expiresAt,scope:{transportScope:f.scope.transportScope,clusterRevision:1,workspaceRevision:1},prerequisites:[],
  steps:[{id:randomUUID(),key:'configuration',order:1,kind:'metadata',handler:'configuration_v2',entityType:'configuration_jobs',entityId:d.jobId,permissionAction:'write',
   dependencies:[],nativeRequests:[],metadata:{jobId:d.jobId,planId:freshPlanId,planRevision:1,planHash:identity.planHash}}]};
 const rows:any={};
 const ISSUE_INSERT=`INSERT INTO configuration_durable_issues(id,cluster_id,workspace_id,job_id,owner_id,authoring_session_id,credential_epoch,permission_version,
    source_job_id,source_plan_id,source_plan_revision,source_plan_hash,source_kind,prepare_key,request_hmac,issued_at,expires_at,definition_id,definition_version,policy_hash,intent_ttl_hours,admission_expires_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`;
 const JOB_INSERT=`INSERT INTO configuration_jobs(id,cluster_id,workspace_id,transport_scope,actor_id,origin_session_id,authority_expires_at,kind,idempotency_key,
    request_hmac,request_id,scope_kind,root_ids,input_secret,permission_version,credential_epoch,cluster_revision,workspace_revision,capture_epoch,execution_mode,approval_required,
    expires_at,origin_type,authority_domain,durable_issue_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,'approval',true,$7,'http',$20,$21)`;
 const BINDING_INSERT=`INSERT INTO configuration_durable_bindings(issue_id,cluster_id,workspace_id,job_id,plan_id,plan_revision,plan_hash,
      workflow_id,workflow_plan_revision,workflow_plan_hash,baseline_snapshot_id,baseline_version,baseline_manifest_hmac,material_hmac,envelope_ciphertext)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`;
 (f.exec as any).mockImplementation(async(sql:string,args:unknown[])=>{
  const put=(name:string,keys:string[])=>{expect(args).toHaveLength(keys.length);rows[name]=Object.fromEntries(keys.map((key,index)=>[key,structuredClone(args[index])]));};
  if(sql==='SELECT pg_advisory_xact_lock(hashtextextended($1,0))'){expect([[`configuration-source-plan:${f.ids.plan}`],[`configuration-durable-command:${f.ids.owner}:durable-admission-original-key`]]).toContainEqual(args);return 1;}
  if(sql===DURABLE_REJECTION_INSERT){put('rejection',['id','cluster_id','workspace_id','owner_id','authoring_session_id','credential_epoch','permission_version','source_job_id','source_plan_id',
   'source_plan_revision','source_plan_hash','source_kind','prepare_key','request_hmac','admission_issued_at','admission_expires_at','rejected_at','fresh_plan_hmac','baseline_snapshot_id','baseline_version','baseline_manifest_hmac','rejection_hmac']);
   Object.assign(rows.rejection,{code:DURABLE_REJECTION_CODE,effect_scope:'durable-registration'});return 1;}
  if(sql===ISSUE_INSERT){put('issue',['id','cluster_id','workspace_id','job_id','owner_id','authoring_session_id','credential_epoch','permission_version','source_job_id','source_plan_id',
   'source_plan_revision','source_plan_hash','source_kind','prepare_key','request_hmac','issued_at','expires_at','definition_id','definition_version','policy_hash','intent_ttl_hours','admission_expires_at']);
   expect(args.slice(0,8)).toEqual([d.issueId,f.ids.cluster,f.ids.workspace,d.jobId,f.ids.owner,f.ids.sid,1,f.proof.permissionVersion]);return 1;}
  if(sql===JOB_INSERT){put('job',['id','cluster_id','workspace_id','transport_scope','actor_id','origin_session_id','authority_expires_at','kind','idempotency_key','request_hmac',
   'request_id','scope_kind','root_ids','input_secret','permission_version','credential_epoch','cluster_revision','workspace_revision','capture_epoch','authority_domain','durable_issue_id']);
   Object.assign(rows.job,{execution_mode:'approval',approval_required:true,expires_at:args[6],origin_type:'http',required_origin_kind:null,required_origin_id:null,required_origin_hmac:null});
   expect(f.secrets.decrypt(rows.job.input_secret,`configuration-job:${d.jobId}`)).toEqual({durableIssueId:d.issueId,sourcePlanId:f.ids.plan,sourcePlanRevision:1,sourcePlanHash:f.source.plan_hash,confirmed:true,driver:'bff'});return 1;}
  if(sql===BINDING_INSERT){put('binding',['issue_id','cluster_id','workspace_id','job_id','plan_id','plan_revision','plan_hash','workflow_id','workflow_plan_revision','workflow_plan_hash',
   'baseline_snapshot_id','baseline_version','baseline_manifest_hmac','material_hmac','envelope_ciphertext']);return 1;}
  throw Error('UNEXPECTED_PUBLICATION_SQL_EXEC');
 });
 const previousOne=f.one.getMockImplementation()!;
 f.one.mockImplementation(async(sql:string,args?:unknown[])=>{
  const answer=(expected:unknown[],name:string)=>{expect(args).toEqual(expected);return structuredClone(rows[name]??null);};
  if(sql==='SELECT * FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 FOR SHARE'){
   expect(args).toEqual([f.ids.job,f.ids.cluster,f.ids.workspace]);return structuredClone(f.source);}
  if(sql==='SELECT id FROM configuration_jobs WHERE actor_id=$1 AND idempotency_key=$2 LIMIT 1'){expect(args).toEqual([f.ids.owner,'durable-admission-original-key']);return rows.keyJob?{id:rows.keyJob.id}:null;}
  if(sql===DURABLE_REJECTION_QUERY){expect(args).toEqual([f.ids.cluster,f.ids.workspace,f.ids.owner,'durable-admission-original-key']);return rows.rejection?{...structuredClone(rows.rejection),scope_kind:f.scope.kind,root_ids:[],transport_scope:f.scope.transportScope,source_owner_id:f.ids.owner,has_registration:!!rows.issue,has_job:!!rows.keyJob}:null;}
  if(sql==='SELECT id FROM configuration_durable_issues WHERE(source_plan_id=$1 AND cluster_id=$2 AND workspace_id=$3) OR(owner_id=$4 AND prepare_key=$5)'){expect(args).toEqual([f.ids.plan,f.ids.cluster,f.ids.workspace,f.ids.owner,'durable-admission-original-key']);return rows.issue?{id:rows.issue.id}:null;}
  if(sql===DURABLE_REJECTION_CONFLICT_QUERY){expect(args?.slice(0,4)).toEqual([f.ids.plan,f.ids.cluster,f.ids.workspace,f.ids.owner]);return rows.rejection?{id:rows.rejection.id}:null;}
  if(sql==='SELECT * FROM configuration_jobs WHERE id=$1')return answer([d.jobId],'job');
  if(sql===DURABLE_ISSUE_QUERY)return answer([d.issueId,f.ids.cluster,f.ids.workspace,d.jobId],'issue');
  if(sql===DURABLE_BINDING_QUERY)return answer([d.issueId,f.ids.cluster,f.ids.workspace,d.jobId],'binding');
  if(sql==='SELECT * FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4'){
   expect(args).toEqual([f.ids.cluster,f.ids.workspace,f.ids.definition,1]);return structuredClone(f.data.definition);}
  if(sql==='SELECT * FROM configuration_plan_versions WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4')return answer([f.ids.cluster,f.ids.workspace,freshPlanId,1],'plan');
  if(sql==='SELECT v.manifest_hmac,v.consistency,v.completeness,s.state AS snapshot_state,m.state AS material_state FROM config_snapshot_versions v JOIN config_snapshots s ON s.id=v.snapshot_id AND s.cluster_id=v.cluster_id AND s.workspace_id=v.workspace_id JOIN configuration_materials m ON m.id=v.material_id AND m.cluster_id=v.cluster_id AND m.workspace_id=v.workspace_id WHERE v.cluster_id=$1 AND v.workspace_id=$2 AND v.snapshot_id=$3 AND v.version=$4')return answer([f.ids.cluster,f.ids.workspace,baseline.snapshotId,1],'snapshot');
  return previousOne(sql,args);
 });
 (f.transaction as any).mockImplementation(async(fn:(tx:DbService)=>Promise<unknown>)=>{
  const prior=structuredClone(rows);try{return await fn(f.db);}catch(error){for(const key of Object.keys(rows))delete rows[key];Object.assign(rows,prior);throw error;}
 });
 const persist=vi.fn(async(tx:DbService,input:any)=>{
  expect(tx).toBe(f.db);expect(input.handle).toBe(f.handle);expect(input).toEqual({handle:f.handle,jobId:d.jobId,issueId:d.issueId,sourcePlanId:f.ids.plan,
   expiresAt:d.expiresAt,plan,baseline,actor:f.actor});expect(f.context.current().operation).toBeUndefined();
  if(writerFails)throw Error('FIXED_WRITER_FAILED');
  Object.assign(rows.job,{plan_id:freshPlanId,plan_revision:1,plan_hash:identity.planHash,workflow_id:workflowId,state:'waiting_approval'});
  rows.plan={source_job_id:d.jobId,plan_hash:identity.planHash,steps_hmac:f.secrets.fingerprint(plan.steps),schema_hmac:plan.schemaHmac,
   source_manifest_hmac:plan.sourceManifestHmac,baseline_manifest_hmac:plan.baselineManifestHmac,expires_at:plan.expiresAt};
  rows.snapshot={manifest_hmac:f.secrets.fingerprint(baseline),consistency:baseline.consistency,completeness:baseline.completeness,snapshot_state:'ready',material_state:'available'};
  rows.workflow={plan_hash:f.secrets.fingerprint(workflow),payload_secret:f.secrets.encrypt(workflow,planAad(f.ids.cluster,f.ids.workspace,workflowId,1))};
  return{identity,workflow};
 });
 const recordRejection=vi.fn(async(tx:DbService,fact:any)=>{expect(tx).toBe(f.db);expect(fact).toMatchObject({ownerId:f.ids.owner,sourceJobId:f.ids.job,sourcePlanId:f.ids.plan,sourcePlanHash:f.source.plan_hash,code:DURABLE_REJECTION_CODE});});
 f.service.installPublicationWriter({persist,recordRejection});
 return{plan,baseline,recipeHmac,rows,persist,recordRejection,identity,workflow};
}
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','9a'.repeat(32));vi.useFakeTimers();vi.setSystemTime(NOW);});
afterEach(()=>{vi.useRealTimers();vi.unstubAllEnvs();vi.restoreAllMocks();});
describe('M11 independent durable admission: real HTTP Context, SecretService and service with short access-proof adapter',()=>{
 it('issues a fresh hour-scale tuple from a genuine current HTTP source while retaining the original short proof and old plan',async()=>{
  const f=fixture(),proofBefore=structuredClone(f.proof),sourceBefore=structuredClone(f.source),planBefore=structuredClone(f.plan);
  await f.run(async()=>{const h=await f.begin(),d=f.service.describe(h);
   expect(d.sourceKind).toBe('import');expect(d.issueId).toMatch(/^[0-9a-f-]{36}$/);expect(d.jobId).not.toBe(f.ids.job);
   expect(d.issuedAt).toBe(new Date(NOW).toISOString());expect(Date.parse(d.expiresAt)-Date.parse(d.issuedAt)).toBe(24*3_600_000);
   expect(Object.isFrozen(h)).toBe(true);expect(Object.isFrozen(d)).toBe(true);expect(f.proof.expiresAt).toBe(NOW+90_000);
  });
  expect(f.proof).toEqual(proofBefore);expect(f.source).toEqual(sourceBefore);expect(f.plan).toEqual(planBefore);
  expect(f.query).toHaveBeenCalledWith(HISTORY,[f.ids.cluster,f.ids.workspace]);expect(f.one.mock.calls.map(c=>c[0])).toEqual([DURABLE_REJECTION_CONFLICT_QUERY,POLICY,CLOCK]);
  expect(f.exec).not.toHaveBeenCalled();expect(f.transaction).not.toHaveBeenCalled();
 });
 it.each(['failed','uncertain','running','pending'])('rejects an original %s source without new policy issuance',async state=>{
  const f=fixture();f.source.state=state;await expect(f.run(f.begin)).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_SOURCE_UNAVAILABLE'}});expect(f.one).not.toHaveBeenCalled();
 });
 it.each(['authority_expires_at','expires_at'])('rejects an expired original source %s without renewing it',async field=>{
  const f=fixture();f.source[field]=new Date(NOW).toISOString();await expect(f.run(f.begin)).rejects.toThrow();expect(f.one).not.toHaveBeenCalled();
 });
 it('rejects an expired original plan even with its authentic HMAC',async()=>{
  const f=fixture();f.plan.expiresAt=new Date(NOW).toISOString();f.source.plan_hash=f.secrets.fingerprint(f.plan);await expect(f.run(f.begin)).rejects.toThrow();
 });
 it('rejects genuine HTTP without a SID and unbound copied actor data',async()=>{
  const f=fixture();await expect(f.run(f.begin,{sid:null})).rejects.toThrow();
  await expect(f.context.runHttp({},()=>f.service.begin(f.handle,f.source,f.plan,{...f.actor,user:{...f.actor.user}},'copied-actor'))).rejects.toThrow();
 });
 it.each(['cluster','workspace'])('rejects a genuine actor frame for a foreign %s',async field=>{
  const f=fixture();await expect(f.run(f.begin,field==='cluster'?{clusterId:randomUUID()}:{workspaceId:randomUUID()})).rejects.toThrow();expect(f.one).not.toHaveBeenCalled();
 });
 it('rejects another real bound actor attempting to use the original owner’s preview',async()=>{
  const f=fixture(),other={...f.actor,user:{...f.actor.user,id:randomUUID()}};await expect(f.run(f.begin,{actor:other})).rejects.toThrow();expect(f.one).not.toHaveBeenCalled();
 });
 it.each(['promote','source-domain','source-issue','plan-domain'])('rejects an already durable or Promote source: %s',async kind=>{
  const f=fixture();if(kind==='promote')f.source.required_origin_kind='governance-promote';
  if(kind==='source-domain')f.source.authority_domain='durable-configuration-v1';if(kind==='source-issue')f.source.durable_issue_id=randomUUID();
  if(kind==='plan-domain'){f.plan.durableRef={version:1,domain:'durable-configuration-v1',issueId:randomUUID()};f.source.plan_hash=f.secrets.fingerprint(f.plan);}
  await expect(f.run(f.begin)).rejects.toThrow();expect(f.one).not.toHaveBeenCalled();
 });
 it('admits a well-formed V2 Target append and still fail-closes a malformed append packet',async()=>{
  const f=fixture(),nativeId=randomUUID(),allocatedNativeId=randomUUID(),parentId=randomUUID();
  const before={id:nativeId,target:'upstream.internal:80',weight:50,upstream:{id:parentId}};
  const body={id:allocatedNativeId,target:'upstream.internal:80',weight:80};
  const packet={method:'POST' as const,canonicalPath:`/upstreams/${parentId}/targets`,body,bodyHmac:f.secrets.fingerprint(body),beforeHmac:f.secrets.fingerprint(before)};
  f.plan.steps=[{entityType:'targets',mutationAction:'update',nativeId,allocatedNativeId,parentId,before,body,bodyHmac:packet.bodyHmac,beforeHmac:packet.beforeHmac,nativeRequests:[packet]}] as any;
  f.source.plan_hash=f.secrets.fingerprint(f.plan);
  expect(f.service.unsupportedReason(f.plan)).toBeNull();
  await expect(f.run(f.begin)).resolves.toBeTruthy();
  await expect(f.run(()=>f.service.canSubmit(f.handle,f.source,f.plan,f.actor))).resolves.toBe(true);
  const broken=fixture();
  broken.plan.steps=[{entityType:'targets',mutationAction:'update',nativeId:randomUUID(),allocatedNativeId:randomUUID()}] as any;
  broken.source.plan_hash=broken.secrets.fingerprint(broken.plan);
  expect(broken.service.unsupportedReason(broken.plan)).toEqual({code:'CONFIGURATION_DURABLE_TARGET_APPEND_UNSUPPORTED',message:'当前配置的 Target 权重变更封存包不完整，暂不能创建配置工单'});
  await expect(broken.run(broken.begin)).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_TARGET_APPEND_UNSUPPORTED'}});
  expect(broken.query).not.toHaveBeenCalled();expect(broken.one).not.toHaveBeenCalled();
 });
 it('rejects unsupported toolbox kind or compare recipe instead of inventing an import recipe',async()=>{
  const f=fixture();f.source.kind='toolbox-operation';await expect(f.run(f.begin)).rejects.toThrow();
  f.source.kind='compare';f.source.input_secret=f.secrets.encrypt({action:'toolbox-operation'},`configuration-job:${f.ids.job}`);
  await expect(f.run(f.begin)).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_RECIPE_UNSUPPORTED'}});expect(f.one).not.toHaveBeenCalled();
 });
 it('rejects an existing ordinary derived apply even with a different new submission key',async()=>{
  const f=fixture(),oldJob=randomUUID();f.data.history=[{id:oldJob,input_secret:f.secrets.encrypt({planId:f.ids.plan},`configuration-job:${oldJob}`)}];
  await expect(f.run(()=>f.service.begin(f.handle,f.source,f.plan,f.actor,'different-key-does-not-replay'))).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_SOURCE_ALREADY_SUBMITTED'}});
  expect(f.one).not.toHaveBeenCalled();
 });
 it.each(['planId','sourcePlanId'])('rejects a different authorized author consuming the same source via %s before new policy or publication',async(field)=>{
  const f=fixture(),consumer=randomUUID(),job=randomUUID();
  f.data.history=[{id:job,actor_id:consumer,input_secret:f.secrets.encrypt({[field]:f.ids.plan},`configuration-job:${job}`)}];
  expect(consumer).not.toBe(f.ids.owner);
  await expect(f.run(f.begin)).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_SOURCE_ALREADY_SUBMITTED'}});
  expect(f.query).toHaveBeenCalledExactlyOnceWith(HISTORY,[f.ids.cluster,f.ids.workspace]);
  expect(f.one).not.toHaveBeenCalled();expect(f.exec).not.toHaveBeenCalled();expect(f.transaction).not.toHaveBeenCalled();
 });
 it('keeps the 5000 whole-workspace history budget fail-closed across different authors',async()=>{
  const f=fixture();f.data.history=Array.from({length:5001},()=>({id:randomUUID(),actor_id:randomUUID(),input_secret:'not-decrypted-before-budget-fence'}));
  await expect(f.run(f.begin)).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_SOURCE_HISTORY_BUDGET'}});
  expect(f.one).not.toHaveBeenCalled();expect(f.exec).not.toHaveBeenCalled();expect(f.transaction).not.toHaveBeenCalled();
 });
 it('rejects an existing durable-derived submission and corrupt source history',async()=>{
  const f=fixture(),oldJob=randomUUID();f.data.history=[{id:oldJob,input_secret:f.secrets.encrypt({sourcePlanId:f.ids.plan},`configuration-job:${oldJob}`)}];
  await expect(f.run(f.begin)).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_SOURCE_ALREADY_SUBMITTED'}});
  f.data.history=[{id:oldJob,input_secret:'corrupted'}];await expect(f.run(f.begin)).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_SOURCE_HISTORY_INVALID'}});
 });
 it('rejects copied opaque admission handles and closes the original handle at its unextended short admission expiry',async()=>{
  const f=fixture();await f.run(async()=>{const h=await f.begin();expect(()=>f.service.describe({...h})).toThrow();
   vi.setSystemTime(f.proof.expiresAt);expect(()=>f.service.describe(h)).toThrow();
  });
 });
 it('rejects a copied original handle used in another real HTTP frame',async()=>{
  const f=fixture();let h:Readonly<object>|undefined;await f.run(async()=>{h=await f.begin();});
  await expect(f.run(async()=>f.service.describe(h!))).rejects.toThrow();
 });
 it('installs the fixed Access policy at bootstrap and refuses a second installation',()=>{
  const f=fixture();f.service.onModuleInit();expect(f.installDurableConfigurationPolicy).toHaveBeenCalledTimes(1);
  expect(f.installDurableConfigurationPolicy.mock.calls[0][0]).toEqual({verifyJob:expect.any(Function),verifyPlan:expect.any(Function)});
  expect(()=>f.service.onModuleInit()).toThrow('DURABLE_ACCESS_POLICY_ALREADY_INSTALLED');
 });
 it('installs one publication writer and rejects replacement',()=>{
  const f=fixture(),persist=vi.fn(async()=>{throw Error('WRITER_MUST_NOT_RUN');});f.service.installPublicationWriter({persist});
  expect(()=>f.service.installPublicationWriter({persist})).toThrow();expect(persist).not.toHaveBeenCalled();
 });
 it('refuses publishing without the fixed bootstrap writer before touching a transaction',async()=>{
  const f=fixture();await f.run(async()=>{const h=await f.begin();await expect(f.service.publish(h,f.plan,{} as CaptureGraph,f.secrets.fingerprint('recipe')))
   .rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_WRITER_UNAVAILABLE'}});});
  expect(f.transaction).not.toHaveBeenCalled();expect(f.exec).not.toHaveBeenCalled();
 });
 it('rejects bad V2 policy integrity, unsupported format and absent policy without clock issuance',async()=>{
  for(const bad of ['hash','format','missing']){const f=fixture();if(bad==='hash')f.data.definition.policy_hash='0'.repeat(64);if(bad==='format')f.data.definition.approval_format=1;if(bad==='missing')f.data.definition=null;
   await expect(f.run(f.begin)).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_V2_POLICY_REQUIRED'}});expect(f.one.mock.calls.map(c=>c[0])).toEqual([DURABLE_REJECTION_CONFLICT_QUERY,POLICY]);}
 });
 it('makes every SQL adapter reject unknown statements and swapped tenant arguments',async()=>{
  const f=fixture();await expect(f.db.query(`${HISTORY} `,[f.ids.cluster,f.ids.workspace,f.ids.owner])).rejects.toThrow('UNEXPECTED_ADMISSION_SQL_QUERY');
  await expect(f.db.query(HISTORY,[f.ids.workspace,f.ids.cluster,f.ids.owner])).rejects.toThrow();await expect(f.db.one('SELECT 1')).rejects.toThrow('UNEXPECTED_ADMISSION_SQL_ONE');
  await expect(f.db.exec('DELETE FROM configuration_jobs')).rejects.toThrow('UNEXPECTED_ADMISSION_SQL_EXEC');
 });
 it('publishes a genuinely admitted fresh J/P/W and verifies the real durable envelope through exact synthetic SQL storage',async()=>{
  const f=fixture(),oldSource=structuredClone(f.source),oldPlan=structuredClone(f.plan),oldProof=structuredClone(f.proof);
  await f.run(async()=>{
   const handle=await f.begin(),description=f.service.describe(handle),p=publicationFixture(f,description);
   const result=await f.service.publish(handle,p.plan,p.baseline,p.recipeHmac);
   expect(result).toEqual({jobId:description.jobId,workflowId:p.workflow.workflowId});expect(p.persist).toHaveBeenCalledTimes(1);
   expect(f.transaction).toHaveBeenCalledTimes(1);expect(f.exec).toHaveBeenCalledTimes(5);
   expect(p.rows.job.expires_at).toBe(description.expiresAt);expect(p.rows.job.authority_expires_at).toBe(description.expiresAt);
   expect(Date.parse(p.rows.job.expires_at)-Date.parse(p.rows.issue.issued_at)).toBe(24*3_600_000);
   const codec=new ConfigurationDurableCodec(f.secrets),locator={domain:'durable-configuration-v1',envelopeVersion:1,issueId:description.issueId,
    clusterId:f.ids.cluster,workspaceId:f.ids.workspace,jobId:description.jobId,planId:p.identity.planId,planRevision:1,planHash:p.identity.planHash};
   const envelope=codec.open({ciphertext:p.rows.binding.envelope_ciphertext,materialHmac:p.rows.binding.material_hmac},locator,NOW);
   expect(durableConfigurationLocator(envelope)).toEqual(locator);expect(envelope.recipeHmac).toBe(p.recipeHmac);
   expect(envelope.baseline.manifestHmac).toBe(f.secrets.fingerprint(p.baseline));expect(envelope.provenance.jobId).toBe(f.ids.job);
   expect(envelope.plan.planHash).toBe(f.secrets.fingerprint(p.plan));expect(envelope.plan.stepsHmac).toBe(f.secrets.fingerprint(p.plan.steps));
   expect(f.one.mock.calls.some(call=>call[0]===DURABLE_BINDING_QUERY)).toBe(true);
   expect(()=>f.service.describe(handle)).toThrow();await expect(f.service.publish(handle,p.plan,p.baseline,p.recipeHmac)).rejects.toThrow();
   expect(p.persist).toHaveBeenCalledTimes(1);expect(f.context.current().operation).toBeUndefined();
  });
  expect(f.source).toEqual(oldSource);expect(f.plan).toEqual(oldPlan);expect(f.proof).toEqual(oldProof);
 });
 it('rechecks source consumption under the same SQL transaction after taking the shared source mutex',async()=>{
  const f=fixture();await f.run(async()=>{const handle=await f.begin(),p=publicationFixture(f,f.service.describe(handle));
   const originalTransaction=f.transaction.getMockImplementation()!;
   f.transaction.mockImplementation(async(fn:any)=>{const consumer=randomUUID();f.data.history=[{id:consumer,input_secret:f.secrets.encrypt({planId:f.ids.plan},`configuration-job:${consumer}`)}];return originalTransaction(fn);});
   await expect(f.service.publish(handle,p.plan,p.baseline,p.recipeHmac)).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_SOURCE_ALREADY_SUBMITTED'}});
   expect(f.exec).toHaveBeenNthCalledWith(1,'SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`configuration-source-plan:${f.ids.plan}`]);
   expect(f.exec).toHaveBeenNthCalledWith(2,'SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`configuration-durable-command:${f.ids.owner}:durable-admission-original-key`]);expect(f.exec).toHaveBeenCalledTimes(2);
   expect(p.persist).not.toHaveBeenCalled();expect(p.rows.issue).toBeUndefined();
  });
 });
 it('rolls back a publication if final SQL material verification crosses the original short admission deadline',async()=>{
  const f=fixture();await f.run(async()=>{const handle=await f.begin(),p=publicationFixture(f,f.service.describe(handle));
   const oldOne=f.one.getMockImplementation()!;
   f.one.mockImplementation(async(sql:string,args?:unknown[])=>{const result=await oldOne(sql,args);if(sql.startsWith('SELECT v.manifest_hmac'))vi.setSystemTime(f.proof.expiresAt);return result;});
   await expect(f.service.publish(handle,p.plan,p.baseline,p.recipeHmac)).rejects.toThrow();
   expect(p.rows.issue).toBeUndefined();expect(p.rows.binding).toBeUndefined();expect(p.rows.job).toBeUndefined();
  });
 });
 it('requires genuine Redis ownership before any durable SQL registration',async()=>{
  const f=fixture();await f.run(async()=>{const handle=await f.begin(),p=publicationFixture(f,f.service.describe(handle));
   f.redis.assertLeaseOwnership.mockRejectedValueOnce(new Error('LOCK_LOST'));
   await expect(f.service.publish(handle,p.plan,p.baseline,p.recipeHmac)).rejects.toThrow('LOCK_LOST');
   expect(f.exec).not.toHaveBeenCalled();expect(p.rows.issue).toBeUndefined();
  });
 });
 it('does not replay a spent admitted publication after the fixed writer fails and never enters a Native operation',async()=>{
  const f=fixture();await f.run(async()=>{const handle=await f.begin(),p=publicationFixture(f,f.service.describe(handle),true);
   await expect(f.service.publish(handle,p.plan,p.baseline,p.recipeHmac)).rejects.toThrow('FIXED_WRITER_FAILED');
   await expect(f.service.publish(handle,p.plan,p.baseline,p.recipeHmac)).rejects.toThrow();
   expect(p.persist).toHaveBeenCalledTimes(1);expect(f.transaction).toHaveBeenCalledTimes(1);expect(p.rows.binding).toBeUndefined();expect(p.rows.job).toBeUndefined();
   expect(f.context.current().operation).toBeUndefined();
  });
 });
 it('records only a fresh semantic refusal on the original tuple/key, audits atomically and publishes no durable J/P/W',async()=>{
  const f=fixture();await f.run(async()=>{const admission=await f.begin(),p=publicationFixture(f,f.service.describe(admission));
   const receipt=await f.service.rejectFreshDiff(admission,p.plan,p.baseline,p.recipeHmac);
   expect(receipt).toMatchObject({receiptKind:'durable-submission-rejected-v1',domain:'configuration',authorityDomain:'durable-configuration-v1',result:'rejected',commandCompleted:true,
    registrationCompleted:false,registrationRejected:true,submissionCompleted:false,knownNoEffect:true,effectScope:'durable-registration',nativeWrites:'none',idempotencyKey:'durable-admission-original-key',
    actorId:f.ids.owner,clusterId:f.ids.cluster,workspaceId:f.ids.workspace,sourceJobId:f.ids.job,sourcePlanId:f.ids.plan,sourcePlanRevision:1,sourcePlanHash:f.source.plan_hash,code:DURABLE_REJECTION_CODE,newPreviewRequired:true});
   expect(p.rows.issue).toBeUndefined();expect(p.rows.job).toBeUndefined();expect(p.rows.binding).toBeUndefined();expect(p.persist).not.toHaveBeenCalled();expect(p.recordRejection).toHaveBeenCalledOnce();
   expect(f.exec.mock.calls.map(c=>c[0])).toEqual(['SELECT pg_advisory_xact_lock(hashtextextended($1,0))','SELECT pg_advisory_xact_lock(hashtextextended($1,0))',DURABLE_REJECTION_INSERT]);
   expect((await f.service.rejectionReceipt('durable-admission-original-key',f.actor,f.ids.cluster,f.ids.workspace))?.receipt).toEqual(receipt);
   await expect(f.service.publish(admission,p.plan,p.baseline,p.recipeHmac)).rejects.toThrow();
   await expect(f.service.begin(f.handle,f.source,f.plan,f.actor,'another-key-must-not-revive-old-source')).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_SOURCE_REJECTED'}});
  });
 });
 it('keeps a proven original-key refusal readable as history after original admission/source expiry without execution authority',async()=>{
  const f=fixture();let expected:any;await f.run(async()=>{const h=await f.begin(),p=publicationFixture(f,f.service.describe(h));expected=await f.service.rejectFreshDiff(h,p.plan,p.baseline,p.recipeHmac);});
  vi.setSystemTime(NOW+3_600_000);await f.run(async()=>{const read=await f.service.rejectionReceipt('durable-admission-original-key',f.actor,f.ids.cluster,f.ids.workspace);expect(read?.receipt).toEqual(expected);},{sid:randomUUID()});
 });
 it('never turns an already published issue into a known rejection',async()=>{
  const f=fixture();await f.run(async()=>{const h=await f.begin(),p=publicationFixture(f,f.service.describe(h));p.rows.issue={id:randomUUID()};
   await expect(f.service.rejectFreshDiff(h,p.plan,p.baseline,p.recipeHmac)).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_REGISTRATION_EXISTS'}});
   expect(p.rows.rejection).toBeUndefined();expect(p.recordRejection).not.toHaveBeenCalled();
  });
 });
 it('rolls back the refusal if the required audit callback fails',async()=>{
  const f=fixture();await f.run(async()=>{const h=await f.begin(),p=publicationFixture(f,f.service.describe(h));p.recordRejection.mockRejectedValueOnce(new Error('AUDIT_UNAVAILABLE'));
   await expect(f.service.rejectFreshDiff(h,p.plan,p.baseline,p.recipeHmac)).rejects.toThrow('AUDIT_UNAVAILABLE');expect(p.rows.rejection).toBeUndefined();expect(p.rows.job).toBeUndefined();
  });
 });
 it('refuses to certify an equivalent fresh plan as rejected',async()=>{
  const f=fixture();f.plan.steps=[{stepId:randomUUID(),stepOrder:1,objectKey:'services:'+randomUUID(),entityType:'services',nativeId:randomUUID(),objectWorkspaceId:f.ids.workspace,
   clearMap:[],permissionAction:'write',mutationAction:'update',body:{name:'same'},before:{name:'before'},bodyHmac:f.secrets.fingerprint({name:'same'}),beforeHmac:f.secrets.fingerprint({name:'before'}),nativeRequests:[],dependencies:[],referenceOnly:false,blockerCodes:[],maskedDiff:[]}];
  const entities=Object.fromEntries(['services','routes','consumers','plugins','upstreams','targets','certificates','ca_certificates','snis'].map(type=>[type,{fields:[]}]))as Record<string,unknown>;
  f.plan.schemaHmac=f.secrets.fingerprint({entities,plugins:{},enabledPlugins:[],kongVersion:'1.5.1',adapterVersion:'kong-1.5-v1'});f.source.plan_hash=f.secrets.fingerprint(f.plan);
  await f.run(async()=>{const h=await f.begin(),d=f.service.describe(h),p=publicationFixture(f,d),same={...p.plan,...structuredClone(f.plan),durableRef:p.plan.durableRef,expiresAt:d.expiresAt,baselineManifestHmac:p.plan.baselineManifestHmac,sourceManifestHmac:p.recipeHmac};
   await expect(f.service.rejectFreshDiff(h,same,p.baseline,p.recipeHmac)).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_REJECTION_NOT_PROVEN'}});expect(f.transaction).not.toHaveBeenCalled();
  });
 });
 it('never returns a refusal if stored HMAC or original ownership was tampered',async()=>{
  const f=fixture();await f.run(async()=>{const h=await f.begin(),p=publicationFixture(f,f.service.describe(h));await f.service.rejectFreshDiff(h,p.plan,p.baseline,p.recipeHmac);
   p.rows.rejection.rejection_hmac='0'.repeat(64);await expect(f.service.rejectionReceipt('durable-admission-original-key',f.actor,f.ids.cluster,f.ids.workspace)).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_REJECTION_INVALID'}});
  });
 });

 it('does not certify a rejection when a generic configuration job already owns the original key',async()=>{
  const f=fixture();await f.run(async()=>{const h=await f.begin(),p=publicationFixture(f,f.service.describe(h));p.rows.keyJob={id:randomUUID()};
   await expect(f.service.rejectFreshDiff(h,p.plan,p.baseline,p.recipeHmac)).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_COMMAND_KEY_IN_USE'}});
   expect(p.rows.rejection).toBeUndefined();expect(p.recordRejection).not.toHaveBeenCalled();expect(p.persist).not.toHaveBeenCalled();
  });
 });

});
