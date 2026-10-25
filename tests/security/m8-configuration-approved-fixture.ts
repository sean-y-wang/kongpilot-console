import {vi} from 'vitest';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {SnapshotCryptoService} from '../../apps/console-api/src/modules/config-storage/snapshot-crypto.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {ApprovedWorkflowExecutionService} from '../../apps/console-api/src/modules/workflows/approved-workflow-execution.service';
import {AuthorizationService} from '../../apps/console-api/src/modules/authorization/authorization.service';
import {planAad,snapshotAad,type WorkflowPlanV1} from '../../apps/console-api/src/modules/workflows/workflow.types';
import {configurationMutationKey} from '../../apps/console-api/src/modules/workflows/configuration-workflow';
import type {ConfigPlan} from '../../apps/console-api/src/modules/configuration/configuration.types';
import {CONFIGURATION_APPROVED_OPERATION_LINK_SQL} from '../../apps/console-api/src/modules/workflows/configuration-approved-verifier';
export const id=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
export async function configurationApprovedFixture(options:{actualAuthorization?:boolean}={}){
  const secrets=new SecretService(),crypto=new SnapshotCryptoService(secrets),context=new KongExecutionContextService();
  const actor={id:id(1),username:'executor',superAdmin:false},sid=id(2),cid=id(3),wid=id(4),jobId=id(5),executionId=id(6),planId=id(7),workflowId=id(8),nativeId=id(9),stepId=id(10),jobStepId=id(11),materialId=id(12),artifactId=id(13),scope='a'.repeat(64),permission=options.actualAuthorization?`${actor.id}:1:1`:'actor:v1';
  const expires=new Date(Date.now()+300000).toISOString(),body={id:nativeId,name:'controlled',host:'example.internal'},before=null;
  const step:any={stepId,stepOrder:1,objectKey:`services:${nativeId}`,entityType:'services',objectWorkspaceId:wid,clearMap:[],allocatedNativeId:nativeId,parentType:null,parentId:null,credentialKind:null,permissionAction:'write',mutationAction:'create',dependencies:[],body,before,
    bodyHmac:secrets.fingerprint(body),beforeHmac:secrets.fingerprint(before),nativeRequests:[{method:'POST',canonicalPath:'/services',body,bodyHmac:secrets.fingerprint(body),beforeHmac:secrets.fingerprint(before)}],referenceOnly:false,blockerCodes:[],maskedDiff:[]};
  const plan:ConfigPlan={scope:{clusterId:cid,workspaceId:wid,transportScope:scope,kind:'workspace',rootIds:[]},mode:'merge',steps:[step],sourceManifestHmac:'b'.repeat(64),baselineManifestHmac:'c'.repeat(64),schemaHmac:'d'.repeat(64),permissionVersion:permission,clusterRevision:1,workspaceRevision:1,kongVersion:'1.5.1',recoveryComplete:true,expiresAt:expires};
  const identity={clusterId:cid,workspaceId:wid,jobId:id(14),materialId,artifactId,artifactKind:'plan'as const};
  const material:any={id:materialId,cluster_id:cid,workspace_id:wid,job_id:identity.jobId,artifact_id:artifactId,artifact_kind:'plan',state:'available',wrapped_key_secret:crypto.createWrappedKey(identity)};
  const cluster:any={id:cid,admin_url:'http://kong:8001',transport_scope:scope,execution_mode:'approval',status:'healthy',version:'1.5.1',revision:1},ws={id:wid,cluster_id:cid,status:'active',revision:1};
  const job:any={id:jobId,cluster_id:cid,workspace_id:wid,state:'running',actor_id:actor.id,origin_session_id:sid,execution_mode:'approval',approval_required:true,plan_id:planId,plan_revision:1,workflow_id:workflowId,lease_generation:1,lease_owner_hash:'e'.repeat(64),lease_until:expires,permission_version:permission,credential_epoch:1,cluster_revision:1,workspace_revision:1,transport_scope:scope,expires_at:expires,authority_expires_at:expires};
  const execution:any={id:executionId,cluster_id:cid,workspace_id:wid,job_id:jobId,actor_id:actor.id,plan_id:planId,plan_revision:1,workflow_id:workflowId,approved_version:1,execution_mode:'approval',state:'executing',claim_hash:'f'.repeat(64),permission_version:permission,lease_generation:1,expires_at:expires,before_snapshot_id:id(15),before_snapshot_version:1};
  const version:any={material_id:materialId,source_job_id:identity.jobId,artifact_id:artifactId,step_count:1,native_packet_count:1,expires_at:expires,schema_hmac:plan.schemaHmac,source_manifest_hmac:plan.sourceManifestHmac,baseline_manifest_hmac:plan.baselineManifestHmac};
  const planRow:any={id:planId,current_revision:1,state:'executing',transport_scope:scope};
  const rows:any[]=[{id:jobStepId,cluster_id:cid,workspace_id:wid,job_id:jobId,execution_id:executionId,plan_id:planId,plan_revision:1,object_workspace_id:wid,plan_step_id:stepId,step_order:1,approval_required:true,before_hmac:step.beforeHmac,state:'running',operation_id:null,revision:1}];
  const objects:any[]=[];
  const wrapper:WorkflowPlanV1={version:1,clusterId:cid,workspaceId:wid,workflowId,planRevision:1,kind:'configuration_v2',executionMode:'approval',approvalRequired:true,subject:{type:'configuration_jobs',id:jobId},requester:{type:'console',id:actor.id},definition:{id:id(16),version:1,policyHash:'6'.repeat(64)},issuedAt:new Date().toISOString(),expiresAt:expires,scope:{transportScope:scope,clusterRevision:1,workspaceRevision:1},prerequisites:[],steps:[{id:id(17),key:'configuration',order:1,kind:'metadata',handler:'configuration_v2',entityType:'configuration_jobs',entityId:jobId,permissionAction:'write',dependencies:[],nativeRequests:[],metadata:{jobId,planId,planRevision:1,planHash:''},before:{id:jobId},metadataRevision:1,metadataBeforeHmac:secrets.fingerprint({id:jobId}),metadataPayloadHmac:''}]};
  const workflow:any={id:workflowId,cluster_id:cid,workspace_id:wid,state:'executing',kind:'configuration_v2',subject_type:'configuration_jobs',subject_id:jobId,requester_type:'console',requester_user_id:actor.id,approval_required:true,execution_mode:'approval',plan_revision:1,approved_by:id(18),definition_id:wrapper.definition.id,definition_version:1,expires_at:expires};
  const wrapperVersion:any={step_count:1,native_request_count:0,execution_mode:'approval',approval_required:true,policy_version:1,expires_at:expires};
  const wrapperRows:any[]=[];
  const wrapperExecution:any={id:id(20),cluster_id:cid,workspace_id:wid,workflow_id:workflowId,plan_revision:1,state:'executing',execution_mode:'approval',approval_required:true,execution_actor_id:actor.id,approved_by:id(18),snapshot_state:'ready',snapshot_id:id(21),expires_at:expires};
  const wrapperSnapshot:any={version:1,clusterId:cid,workspaceId:wid,workflowId,executionId:wrapperExecution.id,planRevision:1,objects:[],capturedAt:new Date().toISOString()};
  const approval:any={approver_id:id(18),decision:'approve',level:1,status:'active',deleted_at:null,force_password_change:false,super_admin:false},stage:any={state:'approved',level:1,required_approvals:1};
  const approvalGrants:any[]=[{module:'workflows',action:'approve',scope_type:'workspace',cluster_id:cid,workspace_id:wid,scope_values:[wid]}];
  const executorGrants:any[]=[{module:'snapshots',action:'write',scope_type:'workspace',cluster_id:cid,workspace_id:wid,scope_values:[wid]}];
  const actorRow:any={id:actor.id,username:actor.username,super_admin:false,status:'active',deleted_at:null,credential_epoch:1,permissions_epoch:1,force_password_change:false},iamEpoch={version:1};
  const definition={mode:'single',allow_self_approval:false,policy_hash:wrapper.definition.policyHash};
  const baseline:any={completeness:'complete',consistency:'console_fenced_best_effort',manifest_hmac:plan.baselineManifestHmac};
  const session:any={id:sid,credential_epoch:1,user_epoch:1},operations=new Map<string,any>();
  const claim:any={claimHash:execution.claim_hash,jobId,actorId:actor.id,sessionId:sid,leaseGeneration:1,permissionVersion:permission,expiresAt:new Date(expires).getTime(),workflowExecutionId:wrapperExecution.id};
  const db:any={one:vi.fn(async(sql:string,params:any[])=>{
    if(sql.includes('FROM configuration_executions'))return execution;if(sql.includes('FROM configuration_jobs'))return job;if(sql.includes('FROM configuration_plan_versions'))return version;if(sql.includes('FROM configuration_plans'))return planRow;
    if(sql.includes('FROM configuration_materials'))return material;if(sql.includes('FROM auth_sessions'))return session;if(sql.includes('FROM clusters'))return cluster;if(sql.includes('FROM workspaces'))return ws;
    if(sql.includes('FROM config_snapshot_versions'))return baseline;if(sql.includes('FROM workflow_executions'))return wrapperExecution;if(sql.includes('FROM workflow_versions'))return wrapperVersion;if(sql.includes('FROM workflows'))return workflow;if(sql.includes('FROM workflow_definition_versions'))return definition;
    if(sql.includes('FROM mutation_operations'))return operations.get(params[0]);if(sql.includes('FROM configuration_job_steps'))return rows.find(row=>row.id===params[0]);if(sql.includes('iam_epoch'))return iamEpoch;if(sql.includes('FROM users'))return params[0]===actor.id?actorRow:null;return null;
  }),query:vi.fn(async(sql:string,p:any[])=>{if(sql.includes('configuration_job_steps'))return rows;if(sql.includes('configuration_plan_objects'))return objects;if(sql.includes('workflow_steps'))return wrapperRows;if(sql.includes('workflow_approvals'))return[approval];if(sql.includes('workflow_stages'))return[stage];if(sql.includes('iam_effective_grants'))return p[0]===id(18)?approvalGrants:p[0]===actor.id?executorGrants:[];return[];}),exec:vi.fn(async(sql:string,p:any[])=>{
    if(sql===CONFIGURATION_APPROVED_OPERATION_LINK_SQL){
      const row=rows[0],object=objects[0],op=operations.get(p[1]);
      if(!op||row.operation_id||row.state!=='running'||row.revision!==p[2]||row.id!==p[0]||row.cluster_id!==p[3]||row.workspace_id!==p[4]
        ||row.job_id!==p[5]||row.execution_id!==p[6]||row.plan_revision!==p[7]||row.plan_hash!==p[8]||execution.workflow_id!==p[9]
        ||execution.actor_id!==p[10]||job.origin_session_id!==p[11]||execution.permission_version!==p[12]||row.object_workspace_id!==p[13]
        ||execution.state!=='executing'||job.state!=='running'||workflow.state!=='executing'||!row.approval_required
        ||op.remote_started!==false||op.remote_completed!==false||op.result_secret!=null||op.state!=='running'
        ||op.actor_id!==p[10]||op.cluster_id!==p[3]||op.workspace_id!==p[13]||op.workflow_id!==p[9]||op.configuration_job_id!==p[5]
        ||op.configuration_execution_id!==p[6]||op.configuration_step_id!==p[0]||op.configuration_plan_revision!==p[7]||op.configuration_plan_hash!==p[8]
        ||['workflow_execution_id','workflow_step_id','workflow_plan_revision','workflow_plan_hash'].some(k=>op[k]!=null)
        ||op.transport_scope!==job.transport_scope||op.idempotency_key!==p[14]||op.action!==p[15]||op.entity_type!==p[16]
        ||(op.entity_id??null)!==p[17]||(op.parent_id??null)!==p[18]||(op.credential_kind??null)!==p[19]
        ||object.before_hmac!==p[20]||object.body_hmac!==p[21])return 0;
      row.operation_id=p[1];row.revision++;return 1;
    }
    return 0;
  })};
  db.transaction=async(fn:any)=>{
    const previousRows=structuredClone(rows),previousOperations=structuredClone([...operations]);
    try{return await fn(db);}catch(error){rows.splice(0,rows.length,...previousRows);operations.clear();for(const [key,value]of previousOperations)operations.set(key,value);throw error;}
  };
  const kong:any={request:vi.fn(async()=>{const e:any=new Error('absent');e.status=404;throw e;})},redis:any={assertLeaseOwnership:vi.fn(async()=>undefined)};
  const authz:any=options.actualAuthorization?new AuthorizationService(db,{get:vi.fn(async()=>ws),resolve:vi.fn(async()=>ws),classify:vi.fn(async()=>({state:'resolved',workspace:ws}))}as any,kong,context):{snapshot:vi.fn(async()=>({user:actor,version:permission})),permissionVersion:vi.fn(async()=>permission),assertWholeWorkspace:vi.fn(async()=>undefined)};
  const verifier=new ApprovedWorkflowExecutionService(db,secrets,authz,{}as any,kong,redis,context);verifier.onModuleInit();const delegate={verifyExecution:vi.fn(async()=>({...claim}))};verifier.installConfigurationDelegate(delegate);
  const seal=async()=>{
    const hash=secrets.fingerprint(plan);for(const x of[execution,job,version])x.plan_hash=hash;version.input_hmac=hash;version.steps_hmac=secrets.fingerprint(plan.steps);
    (wrapper.steps[0].metadata as any).planHash=hash;wrapper.steps[0].metadataPayloadHmac=secrets.fingerprint(wrapper.steps[0].metadata);
    workflow.plan_hash=execution.workflow_plan_hash=wrapperVersion.plan_hash=secrets.fingerprint(wrapper);wrapperVersion.steps_hash=secrets.fingerprint(wrapper.steps);wrapperVersion.payload_secret=secrets.encrypt(wrapper,planAad(cid,wid,workflowId,1));
    const w=wrapper.steps[0];wrapperRows.splice(0,wrapperRows.length,{id:w.id,cluster_id:cid,workspace_id:wid,workflow_id:workflowId,plan_revision:1,plan_hash:workflow.plan_hash,state:'running',execution_mode:'approval',approval_required:true,step_key:w.key,step_order:1,kind:'metadata',handler:'configuration_v2',entity_type:'configuration_jobs',entity_id:jobId,permission_action:'write',operation_id:null,parent_id:null,credential_kind:null,mutation_action:null,mutation_payload_hmac:null,mutation_idempotency_key:null,before_fingerprint:null,native_requests:[],dependencies:[],metadata_revision:w.metadataRevision,metadata_before_hmac:w.metadataBeforeHmac,metadata_payload_hmac:w.metadataPayloadHmac});
    wrapperExecution.plan_hash=workflow.plan_hash;wrapperSnapshot.planHash=workflow.plan_hash;wrapperExecution.snapshot_hash=secrets.fingerprint(wrapperSnapshot);wrapperExecution.snapshot_secret=secrets.encrypt(wrapperSnapshot,snapshotAad(cid,wid,workflowId,wrapperExecution.id));
    rows[0].plan_hash=hash;await crypto.withKey(identity,material.wrapped_key_secret,async key=>{
      version.manifest_ciphertext=crypto.encrypt(key,identity,{section:'manifest',key:'plan'},plan);
      objects.splice(0,objects.length,...plan.steps.map(s=>({cluster_id:cid,workspace_id:wid,plan_id:planId,plan_revision:1,step_id:s.stepId,step_order:s.stepOrder,plan_hash:hash,object_key:s.objectKey,object_workspace_id:s.objectWorkspaceId,entity_type:s.entityType,native_id:s.nativeId??null,allocated_native_id:s.allocatedNativeId??null,parent_id:s.parentId??null,parent_type:s.parentType??null,credential_kind:s.credentialKind??null,permission_action:s.permissionAction,mutation_action:s.mutationAction,before_hmac:s.beforeHmac,body_hmac:s.bodyHmac,dependencies:[...s.dependencies],native_requests:s.nativeRequests.map(r=>({method:r.method,path_hmac:secrets.fingerprint(r.canonicalPath),body_hmac:r.bodyHmac,before_hmac:r.beforeHmac})),reference_only:s.referenceOnly,blocker_codes:[...s.blockerCodes],payload_ciphertext:crypto.encrypt(key,identity,{section:'plan-step',key:s.stepId,entityType:s.entityType,nativeId:s.nativeId??s.allocatedNativeId??null,parentId:s.parentId??null,credentialKind:s.credentialKind??null},s)})));
    });
  };await seal();
  const mutation:any={actor,clusterId:cid,workspaceId:wid,entityType:'services',entityId:nativeId,action:'create',payload:body,before:null,idempotencyKey:configurationMutationKey(jobId,jobStepId)};
  const run=async<T>(fn:()=>Promise<T>)=>context.runHttp({},async()=>{context.bindHttpActor(actor,sid);try{return await context.runActor({actor,clusterId:cid,workspaceId:wid,module:'snapshots',action:'write'},fn);}finally{context.captureHttpCloser()();}});
  const op=(binding:any,operationId=id(19))=>({id:operationId,actor_id:actor.id,cluster_id:cid,workspace_id:wid,workflow_id:workflowId,state:'running',remote_started:false,remote_completed:false,result_secret:null,transport_scope:scope,configuration_job_id:jobId,configuration_execution_id:executionId,configuration_step_id:jobStepId,configuration_plan_revision:1,configuration_plan_hash:binding.configurationPlanHash,action:'create',entity_type:'services',entity_id:nativeId,parent_id:null,credential_kind:null,idempotency_key:mutation.idempotencyKey,before_secret:secrets.encrypt(null,`mutation:${operationId}:before`),payload_secret:secrets.encrypt(body,`mutation:${operationId}:payload`)});
  return{verifier,context,secrets,db,authz,kong,redis,actor,sid,cid,wid,jobId,executionId,jobStepId,nativeId,claim,execution,job,version,planRow,material,cluster,ws,plan,step,rows,objects,wrapper,workflow,wrapperVersion,wrapperRows,wrapperExecution,wrapperSnapshot,approval,approvalGrants,executorGrants,actorRow,iamEpoch,stage,definition,baseline,session,operations,mutation,delegate,seal,run,op};
}
