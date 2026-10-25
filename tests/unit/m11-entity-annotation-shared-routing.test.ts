import 'reflect-metadata';
import {randomUUID} from 'node:crypto';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {ForbiddenException} from '@nestjs/common';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {ApprovedWorkflowExecutionService} from '../../apps/console-api/src/modules/workflows/approved-workflow-execution.service';
import {WorkflowPlansService} from '../../apps/console-api/src/modules/workflows/workflow-plans.service';
import {WorkflowService} from '../../apps/console-api/src/modules/workflows/workflow.service';
import {WorkflowRegistryService} from '../../apps/console-api/src/modules/workflows/workflow-registry.service';
import {EntityAnnotationWorkflowBootstrapService} from '../../apps/console-api/src/modules/workflows/entity-annotation-workflow-bootstrap.service';
import {validateWorkflowPlan} from '../../apps/console-api/src/modules/workflows/workflow-validation';
import {WORKFLOW_KINDS,type WorkflowPlanV1} from '../../apps/console-api/src/modules/workflows/workflow.types';
import {approvedFixture,actor,cid,wid,wf,eid,sid,serviceId,subjectId} from '../security/m6-approved-fixture';
import {annotationWorkflowFixture} from '../fixtures/m11-annotation-workflow.fixture';

/** Shared repository/Approved/Context routing is real. The fixed domain
 * delegate, SQL and complete V2 approval-set reader are explicit fixtures;
 * Main's native entity proof/SQL035, live HTTP and deployment need their own
 * acceptance. No test here grants an entity proof by returning a boolean. */
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32)));
afterEach(()=>vi.unstubAllEnvs());

function annotationPlan(secrets=new SecretService()):WorkflowPlanV1 {
 const intent=randomUUID(),metadata={intentId:intent,entityType:'services',entityId:serviceId,operation:'set',materialHmac:'a'.repeat(64)},before=null;
 return {version:1,clusterId:cid,workspaceId:wid,workflowId:wf,planRevision:1,kind:'entity-annotation',executionMode:'approval',approvalRequired:true,
  subject:{type:'entity_annotation_requests',id:intent},requester:{type:'console',id:actor.id},definition:{id:randomUUID(),version:1,policyHash:'b'.repeat(64)},
  issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+300000).toISOString(),scope:{transportScope:'a'.repeat(64),clusterRevision:1,workspaceRevision:1},prerequisites:[],
  steps:[{id:sid,key:'entity.annotation',handler:'entity.annotation',order:1,kind:'metadata',entityType:'entity_annotation_requests',entityId:intent,permissionAction:'write',dependencies:[],nativeRequests:[],
   before,metadataRevision:0,metadataBeforeHmac:secrets.fingerprint(before),metadata,metadataPayloadHmac:secrets.fingerprint(metadata)}]};
}
function fixedDelegate(){return {verifyIntent:vi.fn(async()=>undefined),assertSubject:vi.fn(async()=>undefined),verifyReviewer:vi.fn(async()=>undefined),assertWorkflowAdmission:vi.fn(async()=>undefined)};}

describe('entity annotation is one strict shared metadata domain',()=>{
 it('accepts its exact metadata-only plan and registers just the fixed handler',()=>{
  const plan=annotationPlan();expect(()=>validateWorkflowPlan(plan)).not.toThrow();const registry=new WorkflowRegistryService(),handler={authorize:vi.fn(),inspect:vi.fn(),apply:vi.fn()};
  registry.register('entity.annotation',handler);expect(registry.get('entity.annotation')).toBe(handler);expect(()=>registry.register('entity.annotation',handler)).toThrow();
 });
 it.each(WORKFLOW_KINDS.filter(kind=>kind!=='entity-annotation'))('refuses annotation selectors in another kind %s',kind=>{
  const plan=annotationPlan();plan.kind=kind;expect(()=>validateWorkflowPlan(plan)).toThrow();
 });
 it.each(['subject','handler','entity-type','native','generated','scheduled','migration','parent','credential','extra-step','different-intent','delete-action','direct'])('refuses %s confusion before shared persistence',variant=>{
  const plan:any=annotationPlan();
  if(variant==='subject')plan.subject.type='iam_metadata_requests';if(variant==='handler')plan.steps[0].handler='iam.metadata';if(variant==='entity-type')plan.steps[0].entityType='control_metadata_requests';
  if(variant==='native')plan.steps[0].nativeRequests=[{method:'DELETE',canonicalPath:`/services/${serviceId}`,nativeType:'services',nativeId:serviceId,bodyHmac:'a'.repeat(64)}];
  if(variant==='generated')plan.generated={consumerId:randomUUID()};if(variant==='scheduled')plan.scheduling={version:1};if(variant==='migration')plan.migration={sourceWorkspaceId:wid};
  if(variant==='parent')plan.steps[0].parentId=randomUUID();if(variant==='credential')plan.steps[0].credentialKind='key-auth';if(variant==='extra-step')plan.steps.push({...plan.steps[0],id:randomUUID(),order:2});
  if(variant==='different-intent')plan.steps[0].metadata.intentId=subjectId;if(variant==='delete-action')plan.steps[0].permissionAction='delete';if(variant==='direct'){plan.executionMode='direct';plan.approvalRequired=false;}
  expect(()=>validateWorkflowPlan(plan)).toThrow();
 });
 it('requires once-installed exact domain delegates and never accepts a native method in either shared installer',()=>{
  const f=approvedFixture(),plans=new WorkflowPlansService(f.db,f.secrets,{}as any),delegate=fixedDelegate();
  for(const target of [plans,f.verifier]){
   expect(()=>target.installEntityAnnotationDelegate({...delegate,nativeWorkspace:()=>wid}as any)).toThrow();
   target.installEntityAnnotationDelegate(delegate);expect(()=>target.installEntityAnnotationDelegate(delegate)).toThrow();
  }
 });
 it('denies foreign or absent selected workspace before the domain admission delegate',async()=>{
  const f=approvedFixture(),delegate=fixedDelegate(),plan=annotationPlan(f.secrets);f.verifier.installEntityAnnotationDelegate(delegate);
  for(const workspaceId of [undefined,randomUUID()])await expect(f.verifier.assertEntityAnnotationWorkflowAdmission(plan,{user:actor,workspaceId},'read')).rejects.toMatchObject({response:{code:'ANNOTATION_SCOPE_SELECTOR_DENIED'}});
  expect(delegate.verifyIntent).not.toHaveBeenCalled();expect(delegate.assertWorkflowAdmission).not.toHaveBeenCalled();
  await f.verifier.assertEntityAnnotationWorkflowAdmission(plan,{user:actor,workspaceId:wid},'read');expect(delegate.verifyIntent).toHaveBeenCalledWith(plan,f.db);expect(delegate.assertWorkflowAdmission).toHaveBeenCalledWith(plan,{user:actor,workspaceId:wid},'read',f.db);
 });
});

function repositoryFixture(){
 const secrets=new SecretService(),plan=annotationPlan(secrets),request={entityType:'services',entityId:serviceId,operation:'set',input:{description:'Owner reviewed change'}},key='annotation-fixed-original-key',delegate=fixedDelegate();
 const edge:any={actor_id:actor.id,workflow_id:wf,idempotency_key:key,request_hmac:secrets.fingerprint(request)},state:any={workflow:null,version:null,steps:[]};
 const db:any={one:vi.fn(async(sql:string,p:any[])=>{
  if(sql==='SELECT actor_id,workflow_id,idempotency_key,request_hmac FROM entity_annotation_requests WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3'){expect(p).toEqual([plan.subject.id,cid,wid]);return structuredClone(edge);}
  if(sql==='SELECT * FROM workflows WHERE cluster_id=$1 AND workspace_id=$2 AND requester_user_id=$3 AND idempotency_key=$4'){expect(p).toEqual([cid,wid,actor.id,key]);return null;}
  if(sql==='SELECT * FROM workflows WHERE id=$1'){expect(p).toEqual([wf]);return state.workflow;}
  if(sql==='SELECT * FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3'){expect(p).toEqual([wf,cid,wid]);return state.workflow;}
  if(sql==='SELECT * FROM workflow_versions WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4'){expect(p).toEqual([wf,cid,wid,1]);return state.version;}
  throw Error(`UNEXPECTED_ANNOTATION_REPOSITORY_READ:${sql}`);
 }),exec:vi.fn(async(sql:string,p:any[])=>{
  if(sql.startsWith('INSERT INTO workflows(')){state.workflow={id:p[0],cluster_id:p[1],workspace_id:p[2],kind:p[3],plan_revision:p[11],plan_hash:p[12],state:'pending',approval_format:p[18]};return 1;}
  if(sql.startsWith('INSERT INTO workflow_versions(')){state.version={payload_secret:p[7],steps_hash:p[11],plan_hash:p[4],safe_diff:JSON.parse(p[12]),safe_impact:JSON.parse(p[13]),approval_format:p[17]};return 1;}
  if(sql.startsWith('INSERT INTO workflow_steps(')){state.steps.push({id:p[0],kind:p[10],nativeRequests:JSON.parse(p[21])});return 1;}
  throw Error(`UNEXPECTED_ANNOTATION_REPOSITORY_WRITE:${sql}`);
 })},audit:any={append:vi.fn(async(_event:any,tx:any)=>{expect(tx).toBe(db);return{id:randomUUID()};})},approval:any={formatForDefinition:vi.fn(async()=>2),freezeSubmission:vi.fn(async()=>({approvalFormat:2}))};
 const plans=new WorkflowPlansService(db,secrets,audit,approval);return{secrets,plan,request,key,delegate,edge,state,db,audit,approval,plans,
  persist:()=>plans.persist(plan,key,request,db,{requestId:randomUUID(),ip:'192.0.2.8'})};
}
describe('annotation original sealed request binding in the real shared repository',()=>{
 it('persists and reloads the same sealed Native-zero V2 plan through the fixed delegate',async()=>{
  const f=repositoryFixture();f.plans.installEntityAnnotationDelegate(f.delegate);await f.persist();const stored=await f.plans.load(cid,wid,wf);
  expect(stored.plan).toEqual(f.plan);expect(f.state.workflow.approval_format).toBe(2);expect(f.state.version.approval_format).toBe(2);expect(f.state.steps).toEqual([{id:sid,kind:'metadata',nativeRequests:[]}]);
  expect(f.delegate.verifyIntent).toHaveBeenCalledTimes(2);expect(f.approval.freezeSubmission).toHaveBeenCalledWith(f.plan,f.db);expect(f.audit.append).toHaveBeenCalledOnce();
 });
 it.each(['missing-policy','actor','workflow','original-key','request-hmac'])('refuses %s substitution before any INSERT',async variant=>{
  const f=repositoryFixture();if(variant!=='missing-policy')f.plans.installEntityAnnotationDelegate(f.delegate);
  if(variant==='actor')f.edge.actor_id=randomUUID();if(variant==='workflow')f.edge.workflow_id=randomUUID();if(variant==='original-key')f.edge.idempotency_key='different-key';if(variant==='request-hmac')f.edge.request_hmac='f'.repeat(64);
  await expect(f.persist()).rejects.toMatchObject({response:{code:variant==='missing-policy'?'ENTITY_ANNOTATION_POLICY_UNAVAILABLE':'ENTITY_ANNOTATION_SUBMISSION_BINDING_INVALID'}});
  expect(f.db.exec).not.toHaveBeenCalled();expect(f.audit.append).not.toHaveBeenCalled();expect(f.approval.freezeSubmission).not.toHaveBeenCalled();
 });
 it('propagates unavailable durable binding reads rather than treating them as an unobserved original submission',async()=>{
  const f=repositoryFixture();f.plans.installEntityAnnotationDelegate(f.delegate);f.db.one.mockRejectedValueOnce(Error('BOUND_SOURCE_UNAVAILABLE'));
  await expect(f.persist()).rejects.toThrow('BOUND_SOURCE_UNAVAILABLE');expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['legacy-format','missing-authority'])('never persists an annotation via %s V1 fallback',async variant=>{
  const f=repositoryFixture(),plans=variant==='missing-authority'?new WorkflowPlansService(f.db,f.secrets,f.audit):f.plans;
  if(variant==='legacy-format')f.approval.formatForDefinition.mockResolvedValue(1);plans.installEntityAnnotationDelegate(f.delegate);
  await expect(plans.persist(f.plan,f.key,f.request,f.db,{requestId:randomUUID(),ip:'192.0.2.8'})).rejects.toMatchObject({response:{code:'ENTITY_ANNOTATION_APPROVAL_FORMAT_REQUIRED'}});expect(f.db.exec).not.toHaveBeenCalled();
 });
});

function approvedAnnotationFixture(kind:'entity-annotation'|'iam-metadata'='entity-annotation'){
 const f=approvedFixture(),plan=annotationPlan(f.secrets);
 if(kind==='iam-metadata'){
  plan.kind=kind;plan.subject.type='iam_metadata_requests';Object.assign(plan.steps[0],{key:'iam.metadata',handler:'iam.metadata',entityType:'iam_metadata_requests',metadata:{intentId:plan.subject.id,resource:'roles',operation:'create',materialHmac:'a'.repeat(64)}});
  plan.steps[0].metadataPayloadHmac=f.secrets.fingerprint(plan.steps[0].metadata);
 }
 Object.assign(f.plan,plan);Object.assign(f.workflow,{requester_type:'console',requester_user_id:actor.id,requester_developer_id:null,definition_id:plan.definition.id});f.seal();
 const set={format:2,setId:randomUUID(),setHmac:'c'.repeat(64)},approvals:any={installScheduledConfigurationCanonicalSqlPolicy:vi.fn(),installReviewerPolicy:vi.fn(),verifyApprovalSet:vi.fn(async()=>set)};
 for(const row of [f.execution,f.workflow,f.version])Object.assign(row,{approval_format:2,approval_set_id:set.setId,approval_set_hmac:set.setHmac});
 const context=new KongExecutionContextService(),resolver:any={resolve:vi.fn(async()=>f.workspace)},verifier=new ApprovedWorkflowExecutionService(f.db,f.secrets,f.authz,resolver,f.kong,f.redis,context,approvals);
 verifier.onModuleInit();context.installPolicy(f.hooks);const delegate=fixedDelegate();
 if(kind==='entity-annotation')verifier.installEntityAnnotationDelegate(delegate);
 else verifier.installIamMetadataDelegate({verifyIntent:delegate.verifyIntent,assertSubject:delegate.assertSubject,verifyReviewer:delegate.verifyReviewer});
 const run=(fn:()=>Promise<unknown>)=>context.runHttp({},async()=>{context.bindHttpActor(actor,'annotation-original-session');return context.runActor({actor,clusterId:cid,workspaceId:wid,module:'workflows',action:'write'},()=>verifier.runApprovedExecution(eid,()=>context.runApprovedStep(sid,fn)));});
 return{...f,context,verifier,delegate,resolver,approvals,run};
}
describe('annotation shared Approved proofs retain ordinary Kong version/transport boundaries',()=>{
 it('keeps a genuine IAM plan in its own branch instead of attaching its cross-kind guard to Metrics',async()=>{
  const f=approvedAnnotationFixture('iam-metadata'),callback=vi.fn(async()=>{expect(f.context.currentApprovedStep().kind).toBe('metadata');});
  await f.run(callback);expect(callback).toHaveBeenCalledOnce();expect(f.delegate.verifyIntent).toHaveBeenCalled();expect(f.delegate.assertSubject).toHaveBeenCalledWith(f.plan,actor.id,'write',f.db);
  expect(f.kong.request).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('uses a real private approved metadata step with no native packets and the original actor SID',async()=>{
  const f=approvedAnnotationFixture();await f.run(async()=>{
   await f.verifier.assertStep({handler:'entity.annotation',actor,clusterId:cid,workspaceId:wid,entityType:'entity_annotation_requests',entityId:f.plan.subject.id,before:null,revision:0,payload:f.plan.steps[0].metadata},f.db);
   expect(f.context.current().sessionId).toBe('annotation-original-session');expect(f.context.currentApprovedStep().kind).toBe('metadata');
  });
  expect(f.delegate.verifyIntent).toHaveBeenCalled();expect(f.delegate.assertSubject).toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['wrong-version','disabled-cluster','cluster-revision','transport','workspace-revision','deleted-workspace'])('refuses %s without inheriting Control repair exceptions',async variant=>{
  const f=approvedAnnotationFixture(),callback=vi.fn(async()=>undefined);
  if(variant==='wrong-version')f.cluster.version='2.8.0';if(variant==='disabled-cluster')f.cluster.status='disabled';if(variant==='cluster-revision')f.cluster.revision++;if(variant==='transport')f.cluster.transport_scope='f'.repeat(64);
  if(variant==='workspace-revision')f.workspace.revision++;if(variant==='deleted-workspace')f.workspace.status='deleted';
  await expect(f.run(callback)).rejects.toMatchObject({response:{code:'APPROVED_PLAN_STALE'}});expect(callback).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('keeps current reviewer validation on the fixed domain delegate without adopting the reviewer SID',async()=>{
  const f=approvedAnnotationFixture(),reviewer=randomUUID();await (f.verifier as any).verifyCurrentReviewer(reviewer,f.plan,f.db);
  expect(f.delegate.verifyReviewer).toHaveBeenCalledWith(reviewer,f.plan,f.db);expect(f.context.peek()).toBeNull();
  f.delegate.verifyReviewer.mockRejectedValueOnce(new ForbiddenException({code:'ANNOTATION_NATIVE_SCOPE_DENIED'}));await expect((f.verifier as any).verifyCurrentReviewer(reviewer,f.plan,f.db)).rejects.toMatchObject({response:{code:'ANNOTATION_NATIVE_SCOPE_DENIED'}});
 });
 it('rejects an annotation resealed under the old V1 single-decision format',async()=>{
  const f=approvedAnnotationFixture(),callback=vi.fn(async()=>undefined);for(const row of [f.version,f.workflow,f.execution])row.approval_format=1;
  await expect(f.run(callback)).rejects.toMatchObject({response:{code:'ENTITY_ANNOTATION_APPROVAL_FORMAT_REQUIRED'}});expect(callback).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
 });
});

describe('fixed annotation bootstrap and original completion routing',()=>{
 it('routes a real Main intent through the shared detail loader and uses its current safe entity review',async()=>{
  const f=annotationWorkflowFixture(),prepared:any=await f.prepare(),submitted:any=await f.submit(prepared),plan:any=f.state().plans.get(submitted.workflowId),row=f.state().workflows.get(plan.workflowId);
  Object.assign(row,{kind:'entity-annotation',approval_format:2,approval_required:true,requester_user_id:f.userId,execution_mode:'approval',created_at:new Date().toISOString(),expires_at:plan.expiresAt});
  const original=f.db.one.getMockImplementation()!;
  f.db.one.mockImplementation(async(sql:string,p:any[])=>{
   if(sql==="SELECT workspace_id FROM workflows WHERE id=$1 AND cluster_id=$2 AND kind='control-metadata' AND state='succeeded' AND requester_user_id=$3"){expect(p).toEqual([plan.workflowId,f.cid,f.userId]);return null;}
   if(sql==='SELECT kind,workspace_id FROM workflows WHERE id=$1 AND cluster_id=$2'){expect(p).toEqual([plan.workflowId,f.cid]);return {kind:'entity-annotation',workspace_id:f.wid};}
   return original(sql,p);
  });
  f.resolver.resolve=vi.fn(async(c:string,w:string)=>{expect([c,w]).toEqual([f.cid,f.wid]);return structuredClone(f.state().workspace);});
  f.plans.load=vi.fn(async(c:string,w:string,id:string)=>{expect([c,w,id]).toEqual([f.cid,f.wid,plan.workflowId]);return {row:structuredClone(row),plan,version:{safe_diff:[{mustNotUse:'historical-source-only-placeholder'}],safe_impact:{nativeRequests:0}}};});
  const approvals:any={projection:vi.fn(async()=>({format:2}))},approved=new ApprovedWorkflowExecutionService(f.db,f.secrets,f.authz,f.resolver,f.kong,f.redis,f.context,approvals);
  approved.installEntityAnnotationDelegate(f.workflow.approvedDelegate());
  const root=new WorkflowService(f.db,f.redis,f.secrets,f.kong,f.context,f.authz,f.audit,{}as any,f.mutations,{}as any,f.resolver,f.plans,f.registry,approved,{}as any,undefined,undefined,approvals);
  root.installEntityAnnotationCompletionDelegate(f.workflow.completionDelegate());
  const result=await f.http(()=>root.get(f.cid,plan.workflowId,f.author));
  expect(result.entity).toMatchObject({kind:'entity-annotation',clusterId:f.cid,workspaceId:f.wid,state:'pending',capabilities:{execute:false,cancel:true}});
  expect(result.diff).toEqual([expect.objectContaining({kind:'metadata',entityType:'services',entityId:f.entityId,operation:'set'})]);
  expect(result.impact).toMatchObject({nativeRequests:0,affectedScopes:[expect.objectContaining({clusterId:f.cid,workspaceId:f.wid})]});
  expect(JSON.stringify(result)).not.toContain('Synthetic-fixture-secret');expect(JSON.stringify(result)).not.toContain('historical-source-only-placeholder');
  expect(f.state().annotation).toBeNull();expect(f.nativeCalls.every((call:any)=>call.method==='GET')).toBe(true);expect(f.state().facts.size).toBe(0);
 });
 it('registers the same fixed domain once and no arbitrary execution bridge',()=>{
  const approved=fixedDelegate(),completion={verifyMetadataCompletion:vi.fn(),terminalReceipt:vi.fn(),reviewPreview:vi.fn()},main:any={approvedDelegate:vi.fn(()=>approved),completionDelegate:vi.fn(()=>completion)},plans:any={installEntityAnnotationDelegate:vi.fn()},verifier:any={installEntityAnnotationDelegate:vi.fn()},workflows:any={installEntityAnnotationCompletionDelegate:vi.fn()};
  const bootstrap=new EntityAnnotationWorkflowBootstrapService(main,plans,verifier,workflows);bootstrap.onModuleInit();bootstrap.onModuleInit();
  expect(plans.installEntityAnnotationDelegate).toHaveBeenCalledExactlyOnceWith(approved);expect(verifier.installEntityAnnotationDelegate).toHaveBeenCalledExactlyOnceWith(approved);expect(workflows.installEntityAnnotationCompletionDelegate).toHaveBeenCalledExactlyOnceWith(completion);expect(Object.keys(approved)).toEqual(['verifyIntent','assertSubject','verifyReviewer','assertWorkflowAdmission']);
 });
 it('denies a completed annotation receipt under a foreign selector before invoking completion',async()=>{
  const f=approvedFixture(),service=new WorkflowService(f.db,f.redis,f.secrets,f.kong,f.context,f.authz,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,{}as any,f.verifier,{}as any),plan=annotationPlan(f.secrets),completion={verifyMetadataCompletion:vi.fn(),terminalReceipt:vi.fn(),reviewPreview:vi.fn()};service.installEntityAnnotationCompletionDelegate(completion);
  await expect((service as any).receiptFor({state:'succeeded'},plan,{user:actor,workspaceId:randomUUID()})).rejects.toMatchObject({response:{code:'ANNOTATION_SCOPE_SELECTOR_DENIED'}});expect(completion.terminalReceipt).not.toHaveBeenCalled();
 });
});
