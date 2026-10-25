import 'reflect-metadata';
import {ForbiddenException} from '@nestjs/common';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {AuthorizationService} from '../../apps/console-api/src/modules/authorization/authorization.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {WorkflowBusinessSchedulesService} from '../../apps/console-api/src/modules/workflows/workflow-business-schedules.service';
import {WorkflowBusinessSchedulesController} from '../../apps/console-api/src/modules/workflows/workflow-business-schedules.controller';
import {WorkflowBusinessSchedulesWorker} from '../../apps/console-api/src/modules/workflows/workflow-business-schedules.worker';
import {WorkflowPlansService,WORKFLOW_SCHEDULE_REVISION_ZERO_HISTORY_SQL} from '../../apps/console-api/src/modules/workflows/workflow-plans.service';
import {normalizeWorkflowScheduleDraft,assertWorkflowScheduledPlan} from '../../apps/console-api/src/modules/workflows/workflow-schedule.repository';
import {planAad} from '../../apps/console-api/src/modules/workflows/workflow.types';
const id=(n:number)=>`bc000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const time=(ms:number)=>new Date(Date.now()+ms).toISOString();
const contract={name:'029_m11_business_schedule_revisions.sql',checksum:'c'.repeat(64)};
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ad'.repeat(32));vi.stubEnv('APP_SECRET','fixture-business-schedule-'.repeat(2));});
afterEach(()=>{vi.useRealTimers();vi.unstubAllEnvs();});
/** Explicit SQL/Authority doubles test actual authoring and codec ordering.
 * They do not mint a genuine runtime Namespace, browser SID or Kong permit. */
function fixture(kind:'configuration_v2'|'portal-credential-issue'='configuration_v2',realPlans=false,executionMode:'approval'|'direct'='approval'){
 const secrets=new SecretService(),actor:any={user:{id:id(1),username:'fixture',superAdmin:false},workspaceId:id(2),requestId:id(3),ip:'127.0.0.1',idempotencyKey:'fixture-author-once'},
  cid=id(4),wf=id(5),subject=id(6),sid=id(7),plan:any={version:1,clusterId:cid,workspaceId:actor.workspaceId,workflowId:wf,planRevision:1,kind,
   executionMode,approvalRequired:true,subject:{type:kind==='configuration_v2'?'configuration_jobs':'portal_application_grants',id:subject},
   requester:{type:kind==='configuration_v2'?'console':'developer',id:kind==='configuration_v2'?actor.user.id:id(8)},definition:{id:id(9),version:1,policyHash:'a'.repeat(64)},
   issuedAt:time(-5000),expiresAt:time(120000),scope:{transportScope:'b'.repeat(64),clusterRevision:1,workspaceRevision:1},prerequisites:[],steps:[]};
 if(kind==='configuration_v2'){const metadata={jobId:subject,planId:id(10),planRevision:1,planHash:'d'.repeat(64)};
  plan.steps=[{id:id(11),key:'apply',order:1,kind:'metadata',handler:'configuration_v2',entityType:'configuration_jobs',entityId:subject,permissionAction:'write',dependencies:[],nativeRequests:[],
   metadata,before:{revision:1},metadataRevision:1,metadataBeforeHmac:secrets.fingerprint({revision:1}),metadataPayloadHmac:secrets.fingerprint(metadata)}];
 }else{for(const [i,credentialKind]of [undefined,'acls','key-auth'].entries()){const body={id:id(30+i),...(credentialKind?{consumer:{id:id(30)},tags:['kos-ws-default']}:{username:'fixture',tags:['kos-ws-default']})};
   plan.steps.push({id:id(11+i),key:`native-${i}`,order:i+1,kind:'native',entityType:i?'credentials':'consumers',permissionAction:'write',dependencies:i?[id(10+i)]:[],
    mutationAction:'create',mutationPayload:body,mutationPayloadHmac:secrets.fingerprint(body),mutationIdempotencyKey:`fixture-native-${i}`,before:null,beforeFingerprint:secrets.fingerprint(null),
    ...(credentialKind?{parentId:id(30),credentialKind}:{}),nativeRequests:[{method:'POST',canonicalPath:credentialKind?`/consumers/${id(30)}/${credentialKind}`:'/consumers',nativeType:credentialKind??'consumers',
     nativeId:body.id,body,bodyHmac:secrets.fingerprint(body),...(credentialKind?{parentId:id(30),credentialKind}:{})}]});}
  const metadata={action:'issue'};plan.steps.push({id:id(14),key:'activate',order:4,kind:'metadata',handler:'portal.credential.activate',entityType:'portal_application_grants',entityId:subject,
   permissionAction:'write',dependencies:[id(13)],nativeRequests:[],metadata,before:{revision:1},metadataRevision:1,metadataBeforeHmac:secrets.fingerprint({revision:1}),metadataPayloadHmac:secrets.fingerprint(metadata)});
 }
 const row:any={id:wf,cluster_id:cid,workspace_id:actor.workspaceId,kind,subject_type:plan.subject.type,subject_id:subject,requester_type:plan.requester.type,
  requester_user_id:kind==='configuration_v2'?actor.user.id:null,requester_developer_id:kind==='configuration_v2'?null:plan.requester.id,
  revision:1,execution_mode:executionMode,approval_required:true,plan_revision:1,plan_hash:secrets.fingerprint(plan),state:'pending',approval_format:2,approved_by:null,approved_at:null,approval_set_id:null,approval_set_hmac:null,
  candidate_version:1,candidate_manifest_hmac:'f'.repeat(64),not_before:null,window_start:null,window_end:null,definition_id:plan.definition.id,definition_version:1,expires_at:plan.expiresAt};
 const version:any={cluster_id:cid,workspace_id:actor.workspaceId,workflow_id:wf,plan_revision:1,plan_hash:row.plan_hash,steps_hash:secrets.fingerprint(plan.steps),
  payload_secret:secrets.encrypt(plan,planAad(cid,actor.workspaceId,wf,1)),safe_diff:[],safe_impact:{subject:plan.subject}};
 const state:any={frame:{kind:'actor',actor:actor.user,sessionId:sid,clusterId:cid,workspaceId:actor.workspaceId},sessionEpoch:'1',permissionsEpoch:'1',iamEpoch:'1',
  currentPlan:plan,stored:undefined,operationCalls:[],checksum:contract.checksum,blocked:false,casRows:1,schedules:[],events:[],versions:[version],steps:[],order:[],delegate:null,appended:[],policyCalls:[],readDeny:false};
 const db:any={transaction:vi.fn(async(fn:any)=>fn(db)),one:vi.fn(async(sql:string,p:any[]=[])=>{
  if(sql.includes('schema_migrations'))return{checksum:state.checksum};if(sql.includes('FROM auth_sessions'))return state.frame?.sessionId?{id:state.frame.sessionId,credential_epoch:state.sessionEpoch,permissions_epoch:state.permissionsEpoch,iam_version:state.iamEpoch}:null;
  if(sql===WORKFLOW_SCHEDULE_REVISION_ZERO_HISTORY_SQL)return{blocked:state.blocked};
  if(sql.includes('FROM workflow_schedules s'))return state.schedules.find((r:any)=>r.id===p[0]&&r.cluster_id===p[1]&&r.workspace_id===p[2])??null;
  if(sql.includes('FROM workflows'))return row.id===p[0]&&row.cluster_id===p[1]&&row.workspace_id===p[2]||p.length===1&&p[0]===wf?structuredClone(row):null;
  if(sql.includes('FROM workflow_versions'))return state.versions.find((v:any)=>v.workflow_id===p[0]&&v.cluster_id===p[1]&&v.workspace_id===p[2]&&v.plan_revision===p[3])??null;
  if(sql.includes('FROM workflow_definition_versions'))return{definition_id:plan.definition.id,version:1,policy_hash:plan.definition.policyHash};
  if(sql.includes('FROM configuration_jobs'))return{id:subject,required_origin_kind:null,required_origin_id:null,required_origin_hmac:null};
  if(sql.includes('audit_events'))return state.events.find((e:any)=>e.after?.keyHmac===p[3])??null;
  if(sql.includes('iam_epoch'))return{version:state.iamEpoch};if(sql.includes('workflow_schedule_progress'))return{schedule_id:p[0]};throw Error(`Unexpected query ${sql.slice(0,90)}`);
 }),exec:vi.fn(async(sql:string,p:any[])=>{
  state.order.push(sql.startsWith('UPDATE workflows')?'pointer':sql.includes('INSERT INTO workflow_versions')?'version':sql.includes('INSERT INTO workflow_steps')?'step':'lock');
  if(sql.startsWith('UPDATE workflows')){if(state.casRows===1){row.plan_revision=p[3];row.plan_hash=p[4];row.not_before=p[5];row.window_start=p[6];row.window_end=p[7];row.revision++;row.candidate_version=null;row.candidate_manifest_hmac=null;}return state.casRows;}
  if(sql.includes('INSERT INTO workflow_versions'))state.versions.push({cluster_id:p[0],workspace_id:p[1],workflow_id:p[2],plan_revision:p[3],plan_hash:p[4],payload_secret:p[6],steps_hash:p[10],safe_diff:JSON.parse(p[11]),safe_impact:JSON.parse(p[12])});
  if(sql.includes('INSERT INTO workflow_steps'))state.steps.push({id:p[0],planRevision:p[4],dependencies:p[24]});return 1;
 }),query:vi.fn(async(sql:string)=>{if(sql.includes('SELECT id,created_at FROM workflow_schedules'))return state.schedules.map((r:any)=>({id:r.id,created_at:r.created_at}));throw Error('Unexpected list query');})};
 const context:any={peek:()=>state.frame,current:()=>{if(!state.frame)throw new ForbiddenException();return state.frame;},runActor:vi.fn(async(input:any,fn:any)=>{const before=state.frame;state.frame={...before,kind:'actor',actor:input.actor,clusterId:input.clusterId,workspaceId:input.workspaceId,module:input.module,action:input.action};try{return await fn();}finally{state.frame=before;}})},
  redis:any={withLock:vi.fn(async(_key:any,fn:any)=>fn()),assertLeaseOwnership:vi.fn(async()=>{})},authz:any={assertCluster:vi.fn(async()=>{}),assertWholeWorkspace:vi.fn(async()=>{}),permissionVersion:vi.fn(async()=>`${actor.user.id}:${state.permissionsEpoch}:${state.iamEpoch}`)},
  audit:any={append:vi.fn(async(e:any)=>{state.events.push(e);state.order.push('audit');return{id:id(80+state.events.length),chainScope:`cluster:${e.clusterId}`,sequence:String(state.events.length),eventHash:'a'.repeat(64),occurredAt:new Date().toISOString()};})},approval:any={formatForDefinition:vi.fn(async()=>2),freezeSubmission:vi.fn(async(p:any)=>{state.order.push('freeze');
   if(!state.schedules.length)throw Error('Schedule must exist before candidates');row.candidate_version=1;row.candidate_manifest_hmac=secrets.fingerprint(p);return{};})};
 const real=new WorkflowPlansService(db,secrets,audit,approval),plans:any=realPlans?real:{load:vi.fn(async()=>({row:structuredClone(row),version,plan:state.currentPlan})),installScheduledRevisionDelegate:vi.fn((d:any)=>{state.delegate=d;}),
  appendScheduledRevision:vi.fn(async(p:any,d:any,a:any,proof:any,tx:any)=>{const old={row:structuredClone(row),version,plan};await state.delegate.verifyRevision(proof,old,p,d,a,tx);state.currentPlan=p;row.plan_revision=p.planRevision;row.plan_hash=secrets.fingerprint(p);row.revision++;await state.delegate.beforeApprovalFreeze(proof,p,d,a,tx);
   state.appended.push({plan:p,draft:d,proof});await state.delegate.verifyRevision(proof,old,p,d,a,tx);return row;})};
 const repository:any={inspectStored:vi.fn(async(scheduleId:string)=>{if(!state.stored||state.stored.draft.scheduleId!==scheduleId)throw new Error('Missing actual stored draft');return state.stored;}),get:vi.fn(async(scheduleId:string,a:any)=>{if(state.readDeny)throw new ForbiddenException();const r=state.schedules.find((r:any)=>r.id===scheduleId&&r.cluster_id===cid&&r.workspace_id===a.workspaceId);
  if(!r)throw new Error('Missing schedule');return{id:r.id,state:r.state,revision:r.revision,workflowId:wf,workflowPlanRevision:r.workflow_plan_revision,workflowPlanHash:r.workflow_plan_hash,nativeAuthority:false};}),cancel:vi.fn(async(id:string)=>{const r=state.schedules.find((r:any)=>r.id===id);r.state='cancelled';r.revision++;return repository.get(id,actor);})};
 const authority:any={persistPreparedDraft:vi.fn(async(d:any)=>{normalizeWorkflowScheduleDraft(d,secrets);state.stored={draft:d,plan:state.currentPlan,progress:{state:'pending-approval',revision:1,claimId:null,reasonCode:null},activation:null,claim:null,latestLease:null};if(realPlans)state.stored.plan=secrets.decrypt(state.versions.at(-1).payload_secret,planAad(cid,actor.workspaceId,wf,d.binding.workflowPlanRevision));state.order.push('draft');state.schedules.push({id:d.scheduleId,cluster_id:cid,workspace_id:actor.workspaceId,
  owner_id:actor.user.id,workflow_id:wf,workflow_plan_revision:d.binding.workflowPlanRevision,workflow_plan_hash:d.binding.workflowPlanHash,transport_scope:d.transportScope,state:'pending-approval',revision:1,claim_id:null,created_at:new Date().toISOString()});return repository.get(d.scheduleId,actor);}),
  activateApproved:vi.fn(async(id:string)=>{const r=state.schedules.find((r:any)=>r.id===id);r.state='active';r.revision++;return repository.get(id,actor);})};
 const service=new WorkflowBusinessSchedulesService(db,secrets,redis,context,authz,audit,plans,repository,authority),root:any={prepareRevision:vi.fn(async(input:any)=>({subjectSeal:{version:1,
  driver:kind==='configuration_v2'?'configuration-apply':'portal-credential-issue',subjectId:subject,materialHmac:'d'.repeat(64),nativeManifestHmac:secrets.fingerprint(input.basePlan.steps),sourceScopes:[]},
  requesterCredentialEpoch:'1',impact:{version:1,keyId:'e'.repeat(64),keys:[],domains:['f'.repeat(64)],wildcards:[]}})),
  assertProposal:vi.fn(async(input:any)=>{state.policyCalls.push(input.checkpoint);if(input.actor.user.id!==actor.user.id)throw new Error('Not original actor');})};
 const body:any={workflowId:wf,revision:1,planRevision:1,planHash:row.plan_hash,spec:{notBefore:time(5000),windowStart:time(1000),windowEnd:time(60000)},confirmed:true,confirm_name:'schedule-workflow'};
 const operations={assertOperation:vi.fn(async(input:any)=>{state.operationCalls.push(input);})};
 return{service,root,operations,plans,real,repository,authority,context,authz,audit,redis,db,secrets,actor,cid,wf,plan,row,version,state,body,install:()=>{service.installProposalPolicy(root,contract);service.installWorkflowOperationPolicy(operations);}};
}

/** A fixed Source adapter resolves the business subject to a server-owned
 * Service row, then runs the real operational grant checker. SQL, subject
 * lookup and workspace classification are explicit doubles; this does not
 * establish a runtime claim, native GET, Portal approval or real session. */
function scopedOperationFixture(scope:'tag_group'|'entity'='tag_group',kind:'configuration_v2'|'portal-credential-issue'='portal-credential-issue'){
 const f=fixture(kind),service:any={id:id(60),tags:['kos-ws-default','team-pay']},state:any={service,workspaceId:f.actor.workspaceId,grants:[]};
 const grant=(module:string,action:string)=>({module,action,scope_type:scope,cluster_id:f.cid,workspace_id:f.actor.workspaceId,
  scope_values:scope==='tag_group'?['team-pay']:[{entity_type:'services',entity_id:service.id}]});
 state.grants=[grant('workflows','read'),grant('workflows','write'),grant('workflows','approve'),grant('portal','write')];
 const db:any={one:vi.fn(async(sql:string,p:any[])=>{
  if(sql.includes('FROM users'))return{id:p[0],username:'source-scoped-author',super_admin:false,status:'active',deleted_at:null,
   permissions_epoch:f.state.permissionsEpoch,credential_epoch:f.state.sessionEpoch,force_password_change:false,revision:1};
  if(sql.includes('FROM auth_sessions'))return f.state.frame.sessionId===p[0]?{id:p[0]}:null;
  if(sql.includes('FROM iam_epoch'))return{version:f.state.iamEpoch};if(sql.includes('FROM clusters'))return p[0]===f.cid?{id:f.cid}:null;
  throw Error('UNEXPECTED_SCOPED_SOURCE_SQL');
 }),query:vi.fn(async(sql:string)=>{if(!sql.includes('iam_effective_grants'))throw Error('UNEXPECTED_SCOPED_GRANT_SQL');return structuredClone(state.grants);})},
 workspaces:any={get:vi.fn(async()=>({id:state.workspaceId,status:'active'})),classify:vi.fn(async()=>({state:'resolved',workspace:{id:state.workspaceId,status:'active'}}))},
 kong:any={request:vi.fn(async()=>{throw Error('NO_NATIVE_AUTHORITY_IN_SOURCE_ADAPTER');})},authz=new AuthorizationService(db,workspaces,kong,f.context);
 f.operations.assertOperation.mockImplementation(async(input:any)=>{
  f.state.operationCalls.push(input);
  if(input.plan.subject.id!==f.plan.subject.id||input.plan.subject.type!==f.plan.subject.type)throw new ForbiddenException({code:'SOURCE_SUBJECT_NOT_FOUND'});
  if(input.plan.kind==='configuration_v2'){
   await authz.assertWholeWorkspace(input.actor.user,input.plan.clusterId,input.plan.workspaceId,'workflows',input.action);
   if(input.action!=='approve')await authz.assertWholeWorkspace(input.actor.user,input.plan.clusterId,input.plan.workspaceId,'snapshots',input.action);
  }else{
   if(!state.service)throw new ForbiddenException({code:'SOURCE_ACTUAL_SERVICE_MISSING'});
   await authz.assertScopedResource(input.actor.user,input.plan.clusterId,'workflows',input.action,'services',state.service,input.plan.workspaceId);
   if(input.action==='write')await authz.assertScopedResource(input.actor.user,input.plan.clusterId,'portal','write','services',state.service,input.plan.workspaceId);
  }
 });
 return{...f,operational:state,actualAuthorization:authz,authorizationDb:db,workspaces,kong,grant};
}

describe('genuine HTTP business authoring boundary with explicit doubles',()=>{
 it.each(['configuration_v2','portal-credential-issue']as const)('seals %s window/delegation/new revision before any approval while preserving requester identity',async kind=>{
  const f=fixture(kind);f.install();const result:any=await f.service.author(f.cid,f.body,f.actor),a=f.state.appended[0];
  expect(result.entity.nativeAuthority).toBe(false);expect(a.plan.planRevision).toBe(2);expect(a.plan.expiresAt).toBe(f.plan.expiresAt);
  expect(a.plan.scheduling.ownerId).toBe(f.actor.user.id);expect(a.plan.scheduling.executorId).toBe(f.actor.user.id);expect(a.plan.scheduling.requester.id).toBe(f.plan.requester.id);
  if(kind==='portal-credential-issue')expect(a.plan.requester.id).not.toBe(a.plan.scheduling.executorId);
  assertWorkflowScheduledPlan(a.plan,a.draft,f.secrets);expect(f.plan.steps.every((s:any)=>a.plan.steps.every((n:any)=>n.id!==s.id))).toBe(true);
  for(const [i,s]of a.plan.steps.entries()){expect(s.dependencies).toEqual(f.plan.steps[i].dependencies.map((old:any)=>a.plan.steps[f.plan.steps.findIndex((n:any)=>n.id===old)].id));
   expect(s.nativeRequests).toEqual(f.plan.steps[i].nativeRequests);if(s.kind==='native')expect(s.mutationIdempotencyKey).not.toBe(f.plan.steps[i].mutationIdempotencyKey);}
  expect(f.authority.persistPreparedDraft).toHaveBeenCalledTimes(1);expect(f.authority.activateApproved).not.toHaveBeenCalled();
  expect(f.audit.append.mock.calls.at(-1)[0].after.authoringSessionId).toBe(f.state.frame.sessionId);
 });
 it('requires fixed Root policy and exact SQL029 before preparing any plan',async()=>{
  const f=fixture();await expect(f.service.author(f.cid,f.body,f.actor)).rejects.toThrow();expect(f.root.prepareRevision).not.toHaveBeenCalled();
  f.install();f.state.checksum='0'.repeat(64);await expect(f.service.author(f.cid,f.body,f.actor)).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_SCHEDULE_STORAGE_UNAVAILABLE'}});
  expect(f.authority.persistPreparedDraft).not.toHaveBeenCalled();
 });
 it.each(['actor','sessionId','executorId','ownerId','plan','claim','subjectSeal','impact'])('rejects user-injected %s before any write',async field=>{
  const f=fixture();f.install();f.body[field]={forged:true};await expect(f.service.author(f.cid,f.body,f.actor)).rejects.toThrow();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('rejects caller-selected executor in spec',async()=>{const f=fixture();f.install();f.body.spec.executorId=id(999);await expect(f.service.author(f.cid,f.body,f.actor)).rejects.toThrow();});
 it.each(['missing-session','foreign-user','background-context','disabled-permission','foreign-workspace','wrong-revision','approved','wrong-plan-hash','extended-window'])('rejects %s without persisting a draft',async mode=>{
  const f=fixture();f.install();if(mode==='missing-session')delete f.state.frame.sessionId;if(mode==='foreign-user')f.state.frame.actor={id:id(999)};
  if(mode==='background-context')f.state.frame.kind='scheduled-workflow';if(mode==='disabled-permission')f.authz.assertCluster.mockRejectedValueOnce(new ForbiddenException());
  if(mode==='foreign-workspace')f.actor.workspaceId=id(999);if(mode==='wrong-revision')f.body.revision=2;if(mode==='approved')f.row.state='approved';
  if(mode==='wrong-plan-hash')f.body.planHash='0'.repeat(64);if(mode==='extended-window')f.body.spec.windowEnd=time(240000);
  await expect(f.service.author(f.cid,f.body,f.actor)).rejects.toThrow();expect(f.authority.persistPreparedDraft).not.toHaveBeenCalled();
 });
 it('same original key returns current-authorized receipt without appending another revision/draft',async()=>{
  const f=fixture();f.install();const first=await f.service.author(f.cid,f.body,f.actor),second=await f.service.author(f.cid,f.body,f.actor);
  expect(second).toEqual(first);expect(f.state.appended).toHaveLength(1);expect(f.authority.persistPreparedDraft).toHaveBeenCalledTimes(1);
  f.state.readDeny=true;await expect(f.service.author(f.cid,f.body,f.actor)).rejects.toThrow();expect(f.state.appended).toHaveLength(1);
 });
 it('changed original-key body conflicts instead of changing the window',async()=>{
  const f=fixture();f.install();await f.service.author(f.cid,f.body,f.actor);f.body.spec.windowEnd=time(70000);
  await expect(f.service.author(f.cid,f.body,f.actor)).rejects.toMatchObject({response:{code:'IDEMPOTENCY_CONFLICT'}});expect(f.state.appended).toHaveLength(1);
 });
 it('authoring epoch change after Root preparation rejects before append/draft',async()=>{
  const f=fixture();f.install();f.root.prepareRevision.mockImplementationOnce(async(input:any)=>{f.state.sessionEpoch='2';return{subjectSeal:{version:1,driver:'configuration-apply',subjectId:f.plan.subject.id,
   materialHmac:'d'.repeat(64),nativeManifestHmac:f.secrets.fingerprint(input.basePlan.steps),sourceScopes:[]},requesterCredentialEpoch:'1',impact:{version:1,keyId:'e'.repeat(64),keys:[],domains:[],wildcards:[]}};});
  await expect(f.service.author(f.cid,f.body,f.actor)).rejects.toThrow();expect(f.authority.persistPreparedDraft).not.toHaveBeenCalled();
 });
 it('copied proposal token is not accepted by the private WeakMap registry',async()=>{
  const f=fixture();f.install();await f.service.author(f.cid,f.body,f.actor);const a=f.state.appended[0];
  await expect(f.state.delegate.verifyRevision({...a.proof},{row:f.row,version:f.version,plan:f.plan},a.plan,a.draft,f.actor,f.db)).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_ORIGINAL_PROPOSAL_REQUIRED'}});
 });
 it('same original-key receipt lookup never exposes another actor or calls the executor',async()=>{
  const f=fixture();f.install();const first=await f.service.author(f.cid,f.body,f.actor);
  expect(await f.service.receiptByKey(f.cid,f.actor.idempotencyKey,f.actor)).toEqual(first);expect(f.authority.activateApproved).not.toHaveBeenCalled();
  await expect(f.service.receiptByKey(f.cid,'unallocated-original-key',f.actor)).rejects.toThrow();
 });
});

describe('fixed actual-subject business operation authorization',()=>{
 it('requires the once-installed complete operation policy even for an empty list',async()=>{
  const f=fixture();f.service.installProposalPolicy(f.root,contract);
  await expect(f.service.author(f.cid,f.body,f.actor)).rejects.toMatchObject({status:503,response:{code:'WORKFLOW_BUSINESS_SCHEDULE_OPERATION_POLICY_UNAVAILABLE'}});
  await expect(f.service.list(f.cid,{workspaceId:f.actor.workspaceId},f.actor)).rejects.toMatchObject({status:503});
  expect(f.root.prepareRevision).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();expect(f.authority.persistPreparedDraft).not.toHaveBeenCalled();
  expect(()=>f.service.installWorkflowOperationPolicy({}as any)).toThrow();
  expect(()=>f.service.installWorkflowOperationPolicy({assertOperation:async()=>{},selectSubject:()=>({})}as any)).toThrow();
  f.service.installWorkflowOperationPolicy(f.operations);expect(()=>f.service.installWorkflowOperationPolicy(f.operations)).toThrow();
 });
 it.each(['tag_group','entity']as const)('admits a %s Portal author through actual Service scope without a whole-workspace waiver',async scope=>{
  const f=scopedOperationFixture(scope);f.install();
  await expect(f.actualAuthorization.assertWholeWorkspace(f.actor.user,f.cid,f.actor.workspaceId,'workflows','write')).rejects.toMatchObject({status:403});
  const result:any=await f.service.author(f.cid,f.body,f.actor);expect(result.entity.nativeAuthority).toBe(false);
  expect(f.authz.assertWholeWorkspace).not.toHaveBeenCalled();expect(f.authority.persistPreparedDraft).toHaveBeenCalledTimes(1);
  expect(f.authorizationDb.query).toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
  const inputs=f.state.operationCalls;expect(inputs[0].plan.planRevision).toBe(1);expect(inputs[0].schedule).toBeNull();
  expect(inputs.some((input:any)=>input.plan.planRevision===2&&input.schedule===null)).toBe(true);
  expect(inputs.at(-1).schedule.draft.binding.workflowPlanRevision).toBe(2);expect(inputs.at(-1).schedule.plan).toEqual(inputs.at(-1).plan);
  expect(inputs.every((input:any)=>input.actor.user.id===f.actor.user.id&&input.acceptance.sessionId===id(7)&&input.plan.requester.id===id(8))).toBe(true);
 });
 it.each(['foreign-tag','foreign-entity','wrong-entity-type','foreign-workspace','missing-service','portal-write-missing']as const)('denies %s despite coarse workflow write admission',async reason=>{
  const scope=reason==='foreign-tag'?'tag_group':'entity',f=scopedOperationFixture(scope);f.install();
  if(reason==='foreign-tag')f.operational.service.tags=['kos-ws-default','team-sales'];
  if(reason==='foreign-entity')f.operational.service.id=id(999);
  if(reason==='wrong-entity-type')f.operational.grants=f.operational.grants.map((grant:any)=>({...grant,scope_values:[{entity_type:'routes',entity_id:f.operational.service.id}]}));
  if(reason==='foreign-workspace')f.operational.workspaceId=id(999);
  if(reason==='missing-service')f.operational.service=null;
  if(reason==='portal-write-missing')f.operational.grants=f.operational.grants.filter((grant:any)=>grant.module!=='portal');
  await expect(f.service.author(f.cid,f.body,f.actor)).rejects.toMatchObject({status:403});
  expect(f.authz.assertCluster).toHaveBeenCalled();expect(f.root.prepareRevision).not.toHaveBeenCalled();expect(f.authority.persistPreparedDraft).not.toHaveBeenCalled();
 });
 it('does not take native payload tags or the developer requester as an operational scope selector',async()=>{
  const f=scopedOperationFixture();f.install();expect(f.plan.steps[0].mutationPayload.tags).not.toContain('team-pay');
  await f.service.author(f.cid,f.body,f.actor);expect(f.operational.service.tags).toContain('team-pay');
  expect(f.state.operationCalls.every((input:any)=>input.actor.user.id===id(1)&&input.plan.requester.id===id(8))).toBe(true);
 });
 it('keeps configuration tag/entity authors closed while fixed Core policy requires a complete workspace grant',async()=>{
  const f=scopedOperationFixture('tag_group','configuration_v2');f.install();
  await expect(f.service.author(f.cid,f.body,f.actor)).rejects.toMatchObject({status:403});
  expect(f.root.prepareRevision).not.toHaveBeenCalled();expect(f.authority.persistPreparedDraft).not.toHaveBeenCalled();
 });
 it.each(['permissionsEpoch','iamEpoch','sessionEpoch']as const)('rechecks current %s around the fixed operation callback before preparing',async field=>{
  const f=fixture();f.install();f.operations.assertOperation.mockImplementationOnce(async()=>{f.state[field]='2';});
  await expect(f.service.author(f.cid,f.body,f.actor)).rejects.toMatchObject({status:403,response:{code:'WORKFLOW_BUSINESS_SCHEDULE_OPERATION_PERMISSIONS_CHANGED'}});
  expect(f.root.prepareRevision).not.toHaveBeenCalled();expect(f.authority.persistPreparedDraft).not.toHaveBeenCalled();
 });
 it('does not accept a plan pointer changed while the concrete subject verifier is awaited',async()=>{
  const f=fixture();f.install();f.operations.assertOperation.mockImplementationOnce(async()=>{f.row.plan_hash='0'.repeat(64);});
  await expect(f.service.author(f.cid,f.body,f.actor)).rejects.toMatchObject({status:403,response:{code:'WORKFLOW_BUSINESS_SCHEDULE_OPERATION_SUBJECT_CHANGED'}});
  expect(f.root.prepareRevision).not.toHaveBeenCalled();expect(f.authority.persistPreparedDraft).not.toHaveBeenCalled();
 });
 it('provides immutable actual plans and stored drafts to the fixed operation callback',async()=>{
  const f=fixture();f.install();f.operations.assertOperation.mockImplementationOnce(async(input:any)=>{expect(Object.isFrozen(input.plan)).toBe(true);
   expect(Object.isFrozen(input.plan.steps[0])).toBe(true);expect(()=>{input.plan.subject.id=id(999);}).toThrow();});
  await f.service.author(f.cid,f.body,f.actor);const last=f.state.operationCalls.at(-1);
  expect(Object.isFrozen(last.schedule.draft)).toBe(true);expect(last.transaction).toBe(f.db);expect(last.action).toBe('write');
 });
 it.each(['get','receipt','replay','list']as const)('uses current actual READ grants for %s after a role loses the Service',async command=>{
  const f=scopedOperationFixture();f.install();const created:any=await f.service.author(f.cid,f.body,f.actor);
  f.operational.grants=f.operational.grants.filter((grant:any)=>!(grant.module==='workflows'&&grant.action==='read'));
  if(command==='get')await expect(f.service.get(f.cid,created.entity.id,f.actor)).rejects.toMatchObject({status:403});
  if(command==='receipt')await expect(f.service.receiptByKey(f.cid,f.actor.idempotencyKey,f.actor)).rejects.toMatchObject({status:403});
  if(command==='replay')await expect(f.service.author(f.cid,f.body,f.actor)).rejects.toMatchObject({status:403});
  if(command==='list'){const result:any=await f.service.list(f.cid,{size:1,workspaceId:f.actor.workspaceId},f.actor);expect(result.items).toEqual([]);expect(result.total).toBeNull();}
  expect(f.state.appended).toHaveLength(1);expect(f.authority.activateApproved).not.toHaveBeenCalled();
 });
 it.each(['activate','cancel']as const)('denies read-only %s before a metadata command changes state',async command=>{
  const f=scopedOperationFixture();f.install();const created:any=await f.service.author(f.cid,f.body,f.actor);
  f.operational.grants=f.operational.grants.filter((grant:any)=>grant.action==='read');
  await expect(f.service.command(f.cid,created.entity.id,command,{revision:1,confirmed:true,confirm_name:`${command}-schedule`},
   {...f.actor,idempotencyKey:`source-read-only-${command}`})).rejects.toMatchObject({status:403});
  expect(f.state.schedules[0].state).toBe('pending-approval');expect(f.authority.activateApproved).not.toHaveBeenCalled();expect(f.repository.cancel).not.toHaveBeenCalled();
 });
 it('rechecks actual scoped write grants after proposal preparation rather than borrowing an earlier author grant',async()=>{
  const f=scopedOperationFixture();f.install();const prepare=f.root.prepareRevision.getMockImplementation()!;
  f.root.prepareRevision.mockImplementationOnce(async(input:any)=>{const material=await prepare(input);f.operational.service.tags=['team-sales'];return material;});
  await expect(f.service.author(f.cid,f.body,f.actor)).rejects.toMatchObject({status:403});expect(f.authority.persistPreparedDraft).not.toHaveBeenCalled();expect(f.state.appended).toHaveLength(0);
 });
 it('uses approve on a genuine nonowner activation and repeats the same stored actual subject after the command',async()=>{
  const f=scopedOperationFixture('entity');f.install();const created:any=await f.service.author(f.cid,f.body,f.actor),user={...f.actor.user,id:id(71)};
  f.state.frame={...f.state.frame,actor:user,sessionId:id(72)};const reviewer={...f.actor,user,idempotencyKey:'source-reviewer-activate'};
  await f.service.command(f.cid,created.entity.id,'activate',{revision:1,confirmed:true,confirm_name:'activate-schedule'},reviewer);
  const calls=f.state.operationCalls.filter((input:any)=>input.command==='activate'&&input.action==='approve');
  expect(calls.map((input:any)=>input.checkpoint)).toEqual(['before','after']);expect(calls.every((input:any)=>input.actor.user.id===user.id&&input.schedule.draft.delegation.ownerId===id(1))).toBe(true);
  expect(f.authority.activateApproved).toHaveBeenCalledTimes(1);expect(f.kong.request).not.toHaveBeenCalled();
 });
});

describe('actual WorkflowPlans append algorithm against relational SQL doubles',()=>{
 it('retains old version/candidates/stages and writes fresh facts in version→draft→candidate order',async()=>{
  const f=fixture('portal-credential-issue',true);f.install();const result:any=await f.service.author(f.cid,f.body,f.actor);
  expect(result.entity.workflowPlanRevision).toBe(2);expect(f.state.versions).toHaveLength(2);expect(f.state.versions[0]).toEqual(f.version);
  const fresh=f.state.versions[1],plan=f.secrets.decrypt<any>(fresh.payload_secret,planAad(f.cid,f.actor.workspaceId,f.wf,2));
  expect(plan.requester).toEqual(f.plan.requester);expect(plan.expiresAt).toBe(f.plan.expiresAt);expect(f.state.steps.map((s:any)=>s.id)).toEqual(plan.steps.map((s:any)=>s.id));
  expect(f.state.order.indexOf('pointer')).toBeLessThan(f.state.order.indexOf('version'));expect(f.state.order.indexOf('version')).toBeLessThan(f.state.order.indexOf('draft'));
  expect(f.state.order.indexOf('draft')).toBeLessThan(f.state.order.indexOf('freeze'));
  expect(f.db.exec.mock.calls.every(([sql]:any)=>!/^DELETE|DROP|TRUNCATE/.test(sql))).toBe(true);expect(f.row.approved_by).toBeNull();expect(f.row.candidate_version).toBe(1);
  expect(f.state.policyCalls).toContain('before-version');expect(f.state.policyCalls).toContain('after-version');
 });
 it.each(['prior-vote-or-execution','legacy-window','missing-format2','candidate-cas','wrong-contract'])('rejects %s rather than amending old immutable facts',async mode=>{
  const f=fixture('portal-credential-issue',true);f.install();if(mode==='prior-vote-or-execution')f.state.blocked=true;
  if(mode==='legacy-window')f.row.not_before=time(5000);if(mode==='missing-format2')f.row.approval_format=1;if(mode==='candidate-cas')f.state.casRows=0;if(mode==='wrong-contract')f.state.checksum='0'.repeat(64);
  await expect(f.service.author(f.cid,f.body,f.actor)).rejects.toThrow();expect(f.state.versions).toHaveLength(1);expect(f.authority.persistPreparedDraft).not.toHaveBeenCalled();
 });
 it('queries actual configuration_executions and all historical native/workflow facts for zero-history',()=>{
  expect(WORKFLOW_SCHEDULE_REVISION_ZERO_HISTORY_SQL).toContain('FROM configuration_executions WHERE workflow_id=$1');
  expect(WORKFLOW_SCHEDULE_REVISION_ZERO_HISTORY_SQL).not.toContain('configuration_job_executions');
  for(const table of ['workflow_approvals','workflow_executions','mutation_operations','workflow_steps','workflow_schedules'])expect(WORKFLOW_SCHEDULE_REVISION_ZERO_HISTORY_SQL).toContain(table);
 });
});

describe('business schedule safe HTTP commands and scoped discovery',()=>{
 it('activate/cancel require separate confirmed original keys and return stable receipt only',async()=>{
  const f=fixture();f.install();const created:any=await f.service.author(f.cid,f.body,f.actor),sid=created.entity.id;
  const activateActor={...f.actor,idempotencyKey:'fixture-activate-once'},activation={revision:1,confirmed:true,confirm_name:'activate-schedule'};
  const activated=await f.service.command(f.cid,sid,'activate',activation,activateActor);expect(await f.service.command(f.cid,sid,'activate',activation,activateActor)).toEqual(activated);
  expect(f.authority.activateApproved).toHaveBeenCalledTimes(1);
  const cancelActor={...f.actor,idempotencyKey:'fixture-cancel-once'},cancel={revision:2,confirmed:true,confirm_name:'cancel-schedule'};
  const cancelled:any=await f.service.command(f.cid,sid,'cancel',cancel,cancelActor);expect(cancelled.entity.state).toBe('cancelled');expect(f.repository.cancel).toHaveBeenCalledTimes(1);
  await expect(f.service.command(f.cid,sid,'activate',{revision:3,confirmed:false,confirm_name:'activate-schedule'},activateActor)).rejects.toThrow();
 });
 it('denies cross-cluster and cross-workspace IDs before get/activation',async()=>{
  const f=fixture();f.install();const created:any=await f.service.author(f.cid,f.body,f.actor);
  await expect(f.service.get(id(999),created.entity.id,f.actor)).rejects.toThrow();await expect(f.service.get(f.cid,created.entity.id,{...f.actor,workspaceId:id(999)})).rejects.toThrow();
  expect(f.authority.activateApproved).not.toHaveBeenCalled();
 });
 it('lists one bounded metadata page, with no count or raw plan/credential projection',async()=>{
  const f=fixture();f.install();await f.service.author(f.cid,f.body,f.actor);const result:any=await f.service.list(f.cid,{workspaceId:f.actor.workspaceId,size:1},f.actor);
  expect(result.items).toHaveLength(1);expect(result.total).toBeNull();expect(f.db.query.mock.calls[0][1].at(-1)).toBe(2);
  expect(JSON.stringify(result)).not.toMatch(/payload_secret|sessionId|generated|key_secret/);
 });
 it('controller takes real request actor and rejects extra scope parameters',async()=>{
  const service:any={author:vi.fn(async()=>({})),list:vi.fn(async()=>({}))},controller=new WorkflowBusinessSchedulesController(service),actor=fixture().actor;
  await controller.author(id(4),{workspaceId:actor.workspaceId},{confirmed:true},actor.idempotencyKey,actor);
  expect(service.author.mock.calls[0][2].user).toBe(actor.user);expect(()=>controller.list(id(4),{workspaceId:actor.workspaceId,actorId:id(999)},actor)).toThrow();
 });
});

describe('default-closed scheduler delegates original opaque claims only',()=>{
 it('requires an installed actual executor and leaves the default timer off',async()=>{
  const repo:any={listDue:vi.fn(async()=>[])},worker=new WorkflowBusinessSchedulesWorker(repo);worker.onApplicationBootstrap();await expect(worker.tick()).rejects.toThrow();
  expect(repo.listDue).not.toHaveBeenCalled();worker.onModuleDestroy();
 });
 it('passes exact original handle unchanged; null/unknown failures produce no retry or fabricated completion',async()=>{
  const handle=Object.freeze({}),repo:any={listDue:vi.fn(async()=>[id(1),id(2),id(3)])},acquire=vi.fn(async(idValue:string)=>idValue===id(1)?handle:idValue===id(2)?null:Promise.reject(Error('held unknown'))),execute=vi.fn(async()=>{}),worker=new WorkflowBusinessSchedulesWorker(repo);
  worker.installFixedDelegate({acquireDueClaim:acquire,executeClaim:execute});expect(await worker.tick()).toEqual({checked:3,claimed:1,completed:1,blocked:2,busy:false});
  expect(execute).toHaveBeenCalledExactlyOnceWith(handle);expect(acquire).toHaveBeenCalledTimes(3);expect(repo.listDue).toHaveBeenCalledExactlyOnceWith(25);
 });
 it('guards overlapping ticks and starts opt-in timer only after Root installation',async()=>{
  vi.useFakeTimers();vi.stubEnv('BUSINESS_SCHEDULES_ENABLED','true');let release:any;const repo:any={listDue:vi.fn(()=>new Promise(resolve=>{release=resolve;}))},worker=new WorkflowBusinessSchedulesWorker(repo);
  worker.onApplicationBootstrap();await vi.advanceTimersByTimeAsync(5000);expect(repo.listDue).not.toHaveBeenCalled();
  worker.installFixedDelegate({acquireDueClaim:vi.fn(async()=>null),executeClaim:vi.fn(async()=>{})});await vi.advanceTimersByTimeAsync(5000);
  expect(repo.listDue).toHaveBeenCalledTimes(1);expect((await worker.tick()).busy).toBe(true);release([]);await vi.advanceTimersByTimeAsync(0);worker.onModuleDestroy();
 });
});

describe('real Context authoring identity propagation',()=>{
 it('inherits the original real Context HTTP identity/SID without runHttp replacement or caller actor adoption',async()=>{
  const f=fixture(),context=new KongExecutionContextService(),service=new WorkflowBusinessSchedulesService(f.db,f.secrets,f.redis,context,f.authz,f.audit,f.plans,f.repository,f.authority);
  service.installProposalPolicy(f.root,contract);service.installWorkflowOperationPolicy(f.operations);
  await context.runHttp({requestId:f.actor.requestId,ip:f.actor.ip},async()=>{
   context.bindHttpActor(f.actor.user,f.state.frame.sessionId);const parent=context.current();
   const result:any=await service.author(f.cid,f.body,f.actor);expect(result.entity.nativeAuthority).toBe(false);
   expect(context.current()).toBe(parent);expect(f.root.prepareRevision.mock.calls[0][0].acceptance.sessionId).toBe(parent.sessionId);
  });expect(context.peek()).toBeNull();
 });
 it('cannot swap a live HTTP actor using an EntityActor DTO',async()=>{
  const f=fixture(),context=new KongExecutionContextService(),service=new WorkflowBusinessSchedulesService(f.db,f.secrets,f.redis,context,f.authz,f.audit,f.plans,f.repository,f.authority);
  service.installProposalPolicy(f.root,contract);service.installWorkflowOperationPolicy(f.operations);
  await context.runHttp({requestId:f.actor.requestId,ip:f.actor.ip},async()=>{
   context.bindHttpActor(f.actor.user,f.state.frame.sessionId);
   await expect(service.author(f.cid,f.body,{...f.actor,user:{...f.actor.user,id:id(999)}})).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_ACTUAL_HTTP_OWNER_REQUIRED'}});
  });expect(f.root.prepareRevision).not.toHaveBeenCalled();expect(f.authority.persistPreparedDraft).not.toHaveBeenCalled();
 });
 it('cannot author after an actual HTTP closer invalidates the frame',async()=>{
  const f=fixture(),context=new KongExecutionContextService(),service=new WorkflowBusinessSchedulesService(f.db,f.secrets,f.redis,context,f.authz,f.audit,f.plans,f.repository,f.authority);
  service.installProposalPolicy(f.root,contract);service.installWorkflowOperationPolicy(f.operations);
  await context.runHttp({requestId:f.actor.requestId,ip:f.actor.ip},async()=>{
   context.bindHttpActor(f.actor.user,f.state.frame.sessionId);context.captureHttpCloser()();await expect(service.author(f.cid,f.body,f.actor)).rejects.toThrow();
  });expect(f.root.prepareRevision).not.toHaveBeenCalled();
 });
 it('original-key receipt lookup remains usable after the planned time, while a fresh expired-window author request is rejected',async()=>{
  const f=fixture();f.install();await f.service.author(f.cid,f.body,f.actor);vi.useFakeTimers();vi.setSystemTime(Date.now()+70000);
  const receipt:any=await f.service.author(f.cid,f.body,f.actor);expect(receipt.entity.nativeAuthority).toBe(false);expect(f.state.appended).toHaveLength(1);
  await expect(f.service.author(f.cid,f.body,{...f.actor,idempotencyKey:'fresh-expired-window'})).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_WINDOW_EXPIRED'}});
 });
});

describe('Portal mandatory approval preserves actual direct cluster mode',()=>{
 it('appends actual direct-mode Portal plan with fresh V2 approval candidates, without claiming direct writes need no review',async()=>{
  const f=fixture('portal-credential-issue',true,'direct');f.install();const result:any=await f.service.author(f.cid,f.body,f.actor),fresh=f.state.versions[1],plan=f.secrets.decrypt<any>(fresh.payload_secret,planAad(f.cid,f.actor.workspaceId,f.wf,2));
  expect(plan.executionMode).toBe('direct');expect(plan.approvalRequired).toBe(true);expect(f.row.execution_mode).toBe('direct');expect(result.entity.state).toBe('pending-approval');
  expect(f.authority.activateApproved).not.toHaveBeenCalled();expect(f.state.order).toContain('freeze');expect(f.row.approved_by).toBeNull();
 });
});
