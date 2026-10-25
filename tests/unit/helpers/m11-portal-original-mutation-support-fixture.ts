import 'reflect-metadata';
import {randomUUID} from 'node:crypto';
import {vi,expect} from 'vitest';
import {workflowScheduledFixture} from './workflow-scheduled-fixture';
import {KongExecutionContextService} from '../../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {WorkflowScheduledAuthorityService} from '../../../apps/console-api/src/modules/workflows/workflow-scheduled-authority.service';
import {WorkflowScheduledNamespaceService} from '../../../apps/console-api/src/modules/workflows/workflow-scheduled-namespace.service';
import {ApprovedWorkflowExecutionService} from '../../../apps/console-api/src/modules/workflows/approved-workflow-execution.service';
import {normalizedNativeRequests} from '../../../apps/console-api/src/modules/workflows/approved-execution.types';
import {planAad,snapshotAad} from '../../../apps/console-api/src/modules/workflows/workflow.types';

/** Genuine same-source Authority -> Namespace -> Context -> Approved private
 * proof/Step/binding -> canonical-load -> fresh inspection -> consume seam.
 * SQL tables, current-grant issuer, canonical SQL reader and subject scans are
 * explicit Source adapters. There is NO Kong SDK/HTTP, live SQL or Native send.
 * The controlled executor completion is test teardown, not business success.
 */
export function portalOriginalMutationSupportFixture(metadataStep=false,beforeBinding?:()=>Promise<void>){
 const f=workflowScheduledFixture('portal-credential-issue'),context=new KongExecutionContextService(),h=(v:unknown)=>f.secrets.fingerprint(v);
 const plan=f.plan,executionId=randomUUID(),originId=randomUUID(),serviceId=randomUUID(),applicationId=randomUUID(),publicationId=randomUUID();
 const rows=plan.steps.map((step:any)=>({id:step.id,cluster_id:f.cid,workspace_id:f.wid,workflow_id:plan.workflowId,plan_revision:plan.planRevision,plan_hash:h(plan),
  step_key:step.key,step_order:step.order,kind:step.kind,entity_type:step.entityType,entity_id:step.entityId,parent_id:step.parentId??null,credential_kind:step.credentialKind??null,
  permission_action:step.permissionAction,mutation_action:step.mutationAction??null,handler:step.handler??null,mutation_payload_hmac:step.mutationPayloadHmac??null,
  mutation_idempotency_key:step.mutationIdempotencyKey??null,before_fingerprint:step.beforeFingerprint??null,dependencies:step.dependencies,
  native_requests:normalizedNativeRequests(step.nativeRequests,f.secrets),metadata_before_hmac:step.metadataBeforeHmac??null,metadata_payload_hmac:step.metadataPayloadHmac??null,
  metadata_revision:step.metadataRevision??null,execution_mode:'approval',approval_required:true,state:'pending',revision:1,operation_id:null,
  receipt_secret:null,recycle_entry_id:null,after_fingerprint:null,started_at:null,completed_at:null}));
 const w:any={id:plan.workflowId,cluster_id:f.cid,workspace_id:f.wid,state:'executing',kind:plan.kind,subject_type:plan.subject.type,subject_id:plan.subject.id,
  plan_revision:plan.planRevision,plan_hash:h(plan),requester_type:'developer',requester_user_id:null,requester_developer_id:f.developer,
  definition_id:plan.definition.id,definition_version:plan.definition.version,approved_by:f.approvalSet.reviewers[0].userId,approval_required:true,execution_mode:'approval',
  expires_at:plan.expiresAt,approval_format:2,approval_set_id:f.approvalSet.setId,approval_set_hmac:f.approvalSet.setHmac};
 const e:any={...w,id:executionId,workflow_id:plan.workflowId,execution_actor_id:f.owner,permission_version:`${f.owner}:1:${f.state.principalVersion}`,snapshot_state:'ready',started_at:new Date().toISOString()};
 const version:any={...w,workflow_id:plan.workflowId,policy_version:plan.definition.version,step_count:plan.steps.length,steps_hash:h(plan.steps),native_request_count:3,
  payload_secret:f.secrets.encrypt(plan,planAad(f.cid,f.wid,plan.workflowId,plan.planRevision))};
 const snapshot:any={version:1,workflowId:plan.workflowId,executionId,clusterId:f.cid,workspaceId:f.wid,planRevision:plan.planRevision,planHash:h(plan),capturedAt:new Date().toISOString(),
  objects:plan.steps.flatMap((step:any)=>step.nativeRequests.map((r:any)=>({type:r.nativeType,id:r.nativeId,path:`${r.canonicalPath}/${r.nativeId}`,before:null,absent:true,fingerprint:h(null)})))};
 e.snapshot_hash=h(snapshot);e.snapshot_secret=f.secrets.encrypt(snapshot,snapshotAad(f.cid,f.wid,plan.workflowId,executionId));
 const scan={executor:0,reviewer:0},flags:any={membershipRevoked:false,approvalChanged:false,grantsChanged:false,afterConsume:null,beforeConsume:null,bindingKind:'user',bindingExpiresAt:null},operations=new Map<string,any>();
 let currentNamespace:any,namespaceHandle:object|undefined;
 const priorOne=f.db.one.getMockImplementation()!,priorQuery=f.db.query.getMockImplementation()!,priorExec=f.db.exec.getMockImplementation()!;
 const bindings=new Map<string,{id:string;roleId:string}>(),teamBinding={id:randomUUID(),roleId:randomUUID(),teamId:randomUUID()};
 f.db.one.mockImplementation(async(sql:string,args:any[]=[])=>{
  if(sql.trimStart().startsWith('SELECT s.kind FROM workflow_steps s'))return{kind:rows.find((row:any)=>row.id===args[4])?.kind??null};
  if(sql.startsWith('SELECT * FROM workflow_executions'))return structuredClone(e);
  if(sql.startsWith('SELECT * FROM workflow_versions'))return structuredClone(version);
  if(sql.startsWith('SELECT * FROM workflows'))return structuredClone(w);
  if(sql.includes('FROM workflow_execution_origins')&&!sql.includes('SELECT m.id'))return{...f.state.stored.claim&&{claim_id:f.state.stored.claim.id},id:originId,cluster_id:f.cid,workspace_id:f.wid,
   workflow_id:plan.workflowId,workflow_plan_revision:plan.planRevision,workflow_plan_hash:h(plan),execution_id:executionId,executor_id:f.owner,schedule_id:f.scheduleId};
  if(sql.startsWith('SELECT * FROM mutation_operations'))return operations.get(args[0])??null;
  if(sql.includes('FROM portal_application_grants'))return{id:plan.subject.id,cluster_id:f.cid,workspace_id:f.wid,developer_id:f.developer,application_id:applicationId,publication_id:publicationId,
   state:'pending',transport_scope:plan.scope.transportScope,revision:1};
  if(sql.includes('FROM portal_publications'))return{id:publicationId,state:'published',service_id:serviceId,transport_scope:plan.scope.transportScope};
  if(sql.includes('FROM portal_applications'))return{id:applicationId,status:'active',developer_id:f.developer};
  if(sql.includes('FROM portal_developers'))return f.state.requesterActive?{id:f.developer,status:'active',credential_epoch:'1',must_change_password:false}:null;
  return priorOne(sql,args);
 });
 f.db.query.mockImplementation(async(sql:string,args:any[]=[])=>{
  if(sql.includes('FROM workflow_steps'))return structuredClone(rows);
  if(sql.includes('FROM iam_effective_grants')){
   let bound=bindings.get(args[0]);if(!bound){bound={id:randomUUID(),roleId:randomUUID()};bindings.set(args[0],bound);}
   if(flags.bindingKind==='team')bound=teamBinding;
   const grant={user_id:args[0],role_id:bound.roleId,binding_id:bound.id,binding_source:flags.bindingKind,module:'portal',action:flags.grantsChanged?'read':'write',scope_type:'global',scope_values:[],cluster_id:null,workspace_id:null};
   const binding={id:bound.id,role_id:bound.roleId,status:'active',expires_at:flags.bindingExpiresAt,...(flags.bindingKind==='team'?{team_id:teamBinding.teamId}:{user_id:args[0]})};
   return sql.includes('binding_current')?[{grant,binding,binding_expires_at:flags.bindingExpiresAt,binding_current:flags.bindingExpiresAt==null||Date.parse(flags.bindingExpiresAt)>Date.now(),observed_at:new Date().toISOString()}]:[grant];
  }
  return priorQuery(sql,args);
 });
 f.db.exec.mockImplementation(async(sql:string,args:any[]=[])=>{
  if(sql.startsWith('UPDATE workflow_steps SET operation_id=')){const row=rows.find((r:any)=>r.id===args[0]);if(!row||row.revision!==args[2]||row.operation_id)return 0;row.operation_id=args[1];row.revision++;return 1;}
  return priorExec(sql,args);
 });
 f.policy.assertSubject.mockImplementation(async()=>{if(!f.state.scopeAllowed)throw Error('SOURCE_CURRENT_SUBJECT_DENIED');scan.executor++;});
 f.policy.assertReviewer.mockImplementation(async()=>{if(!f.state.reviewerActive)throw Error('SOURCE_CURRENT_REVIEWER_REVOKED');scan.reviewer++;});
 f.approvals.installScheduledPortalInspectionSqlReader=vi.fn((verifier:any)=>async(token:object,p:any,input:any,tx:any)=>{
  await verifier.enter(token,p,input.checkpoint,tx);try{
   if(flags.membershipRevoked||!f.state.reviewerActive)throw Error('SOURCE_CURRENT_CANDIDATE_REVOKED');
   return flags.approvalChanged?{...f.approvalSet,setHmac:'e'.repeat(64)}:structuredClone(f.approvalSet);
  }finally{await verifier.leave(token,p,input.checkpoint,tx);}
 });
 f.approvals.installReviewerPolicy=vi.fn();f.approvals.installScheduledConfigurationCanonicalSqlPolicy=vi.fn();
 const authority=new WorkflowScheduledAuthorityService(f.db,f.secrets,f.redis,context,f.plans,f.approvals,f.repository);
 const namespace=new WorkflowScheduledNamespaceService(authority,f.secrets,f.redis,context);
 context.installWorkflowScheduledNamespacePolicy({verifyHandle:(handle,phase)=>namespace.verifyHandle(handle,phase),assertLive:handle=>namespace.assertLive(handle)});
 namespace.installContextRunner({assertNoFrame(){if(context.peek())throw Error('SOURCE_EMPTY_ORIGINAL_CONTEXT_REQUIRED');},run:(handle,fn)=>context.runWorkflowScheduledNamespace(handle,fn)});
 const authz:any={snapshot:vi.fn(async(actor:any)=>({user:actor,version:`${f.owner}:1:${f.state.principalVersion}`})),permissionVersion:vi.fn(async()=>`${f.owner}:1:${f.state.principalVersion}`),
  assertScopedResource:vi.fn(async()=>{if(!f.state.scopeAllowed)throw Error('SOURCE_CURRENT_SCOPE_REVOKED');}),assertWholeWorkspace:vi.fn()};
 const workspaces:any={resolve:vi.fn(async()=>({id:f.wid,status:'active',revision:1}))};
 const kong:any={request:vi.fn(async(_cid:string,method:string,path:string)=>{
  if(method!=='GET'||path!==`/services/${serviceId}`)throw Error('NO_KONG_SDK_OR_NATIVE_SEND_IN_SOURCE_SEAM');return{id:serviceId,name:'source-seam-service',tags:[]};
 })};
 const approved=new ApprovedWorkflowExecutionService(f.db,f.secrets,authz,workspaces,kong,f.redis,context,f.approvals);
 context.installPolicy({async authorizeRequest(){return{};},async authorizeResponse(_ticket,value){return value;}});
 approved.onModuleInit();approved.installWorkflowScheduledDelegate({assertConfigurationOrigin:async()=>{throw Error('NO_CONFIGURATION_IN_PORTAL_SEAM');},
  runValidationRead:async(handle,cid,paths,tx,fn)=>{expect(handle).toBe(namespaceHandle);expect(cid).toBe(f.cid);expect(paths).toEqual([`/services/${serviceId}`]);expect(tx).toBe(f.db);return fn();}});
 const consume=vi.spyOn(namespace,'consumeFreshPortalInspection'),canonicalLoad=vi.spyOn(namespace,'readPortalOperationApprovalSet');
 approved.installWorkflowScheduledAuthorityInspectionPolicy({loadApprovalSet:(p,id,handle,tx)=>namespace.readPortalOperationApprovalSet(p,id,handle,tx),
  consume:async(handle,ns,checkpoint,tx)=>{await flags.beforeConsume?.();const result=await namespace.consumeFreshPortalInspection(handle,ns,checkpoint,tx);await flags.afterConsume?.();return result;}});
 authority.installBusinessPolicy('portal-credential-issue',f.policy);authority.installRepositoryPolicies('a'.repeat(64));
 let callback:()=>Promise<void>=async()=>{};
 const executor={executeClaim:async(handle:object,begin:(namespace:object)=>void)=>{
  await namespace.runOriginalClaim(handle,async()=>{
   namespaceHandle=context.requireWorkflowScheduledNamespaceHandle();currentNamespace=context.requireWorkflowScheduledCurrentPrincipal(namespaceHandle).namespace;begin(namespaceHandle);e.permission_version=currentNamespace.permissionVersion;e.started_at=new Date().toISOString();
   await approved.runApprovedBusinessExecution(namespaceHandle,executionId,async()=>{
    if(metadataStep){
     // Explicit committed-history SQL adapters for this component-only
     // metadata guard test. No historical native send is claimed here.
     for(const [index,row]of rows.slice(0,3).entries()){const operationId=randomUUID();Object.assign(row,{state:'succeeded',operation_id:operationId});
      operations.set(operationId,{id:operationId,state:'succeeded',remote_completed:true,workflow_execution_id:executionId,workflow_step_id:row.id,workflow_plan_hash:h(plan)});}
     rows[3].state='running';return context.runApprovedStep(plan.steps[3].id,callback);
    }
    rows[0].state='running';await context.runApprovedStep(plan.steps[0].id,()=>{
     const step=plan.steps[0],mutation:any={actor:currentNamespace.actor,clusterId:f.cid,workspaceId:f.wid,entityType:step.entityType,entityId:step.entityId,
      action:step.mutationAction,payload:step.mutationPayload,before:null,idempotencyKey:step.mutationIdempotencyKey};
     return context.runMutationActor(mutation,async()=>{await beforeBinding?.();
      const binding=await context.approvedMutationBinding(mutation),operationId=randomUUID(),operation:any={id:operationId,actor_id:f.owner,cluster_id:f.cid,workspace_id:f.wid,
       workflow_id:plan.workflowId,workflow_execution_id:executionId,workflow_step_id:step.id,workflow_plan_revision:plan.planRevision,workflow_plan_hash:h(plan),state:'running',remote_started:false,remote_completed:false,
       payload_secret:f.secrets.encrypt(step.mutationPayload,`mutation:${operationId}:payload`),before_secret:f.secrets.encrypt(null,`mutation:${operationId}:before`)};
      operations.set(operationId,operation);await context.bindApprovedOperation(mutation,binding!,operationId,f.db);operation.remote_started=true;
      return context.runOperation({...mutation,operationId},callback);
     });
    });
   });
  });return f.complete();
 },verifyCompletion:f.executor.verifyCompletion};
 authority.installExecutor(executor);
 const run=async(fn:()=>Promise<void>)=>{callback=fn;const handle=await authority.acquireDueClaim(f.scheduleId);if(!handle)throw Error('SOURCE_ACTUAL_CLAIM_REQUIRED:'+f.state.stored.progress.reasonCode);await authority.executeClaim(handle);};
 const verify=()=>approved.verifyWorkflowScheduledExecution(context.currentApprovedStep().execution,namespaceHandle!);
 const verifyNative=(stage:'packet'|'before-send'='before-send')=>{const proof=context.currentApprovedStep(),frame=context.current(),request=plan.steps[0].nativeRequests[0];return approved.assertNative(proof,{clusterId:f.cid,workspaceId:f.wid,transportScope:plan.scope.transportScope,operationId:frame.operation!.operationId,method:request.method,canonicalPath:request.canonicalPath,body:request.body,before:null,mutationAction:plan.steps[0].mutationAction,query:{},frame,cluster:{id:f.cid,admin_url:'http://kong:8001',version:'1.5.1'}} as any,stage);};
 return{...f,authority,namespace,context,approved,consume,canonicalLoad,authz,kong,rows,w,e,version,operations,scan,flags,run,verify,verifyNative,
  currentNamespace:()=>currentNamespace,originalNamespaceHandle:()=>namespaceHandle!};
}
