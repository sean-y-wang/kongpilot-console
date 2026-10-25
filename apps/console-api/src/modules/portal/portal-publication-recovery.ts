import { ConflictException, NotFoundException } from '@nestjs/common';
import type { DbService } from '../../infrastructure/db.service';
import type { SecretService } from '../../infrastructure/secret.service';
import { planAad, type WorkflowPlanV1 } from '../workflows/workflow.types';
import { validateWorkflowPlan } from '../workflows/workflow-validation';

export interface PublicationRecoveryProof {
  readonly allowed:boolean;
  readonly state:string;
  readonly workflowId:string|null;
  readonly summary?:Readonly<{workflow:string;executions:string;steps:string;nativeOperations:string;metadataOperations:string}>;
}

/** Private DB evidence for an explicitly confirmed new publication plan after
 * a known failed attempt. This grants no execution capability, releases no
 * historical Portal ownership, and never suppresses the complete auth graph. */
async function loadPublicationWorkflow(db:DbService,secrets:SecretService,cid:string,wid:string,id:string):Promise<{row:any;plan:WorkflowPlanV1;version:any}>{
  const row=await db.one<any>('SELECT * FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[id,cid,wid]);
  if(!row)throw new NotFoundException({code:'WORKFLOW_NOT_FOUND'});
  const version=await db.one<any>('SELECT * FROM workflow_versions WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4',[id,cid,wid,row.plan_revision]);
  if(!version)throw new ConflictException({code:'WORKFLOW_PLAN_INVALID'});
  const plan=secrets.decrypt<WorkflowPlanV1>(version.payload_secret,planAad(cid,wid,id,row.plan_revision));validateWorkflowPlan(plan);
  if(plan.workflowId!==row.id||plan.clusterId!==cid||plan.workspaceId!==wid||plan.planRevision!==row.plan_revision||plan.executionMode!==row.execution_mode||plan.approvalRequired!==row.approval_required||secrets.fingerprint(plan)!==row.plan_hash||version.plan_hash!==row.plan_hash||secrets.fingerprint(plan.steps)!==version.steps_hash)throw new ConflictException({code:'WORKFLOW_PLAN_INVALID'});
  return{row,plan,version};
}

export async function publicationRetryProof(tx:DbService,secrets:SecretService,cid:string,wid:string,before:any,options:{lock?:boolean}={}):Promise<PublicationRecoveryProof>{
  const lock=options.lock===true;
  const denied:PublicationRecoveryProof={allowed:false,state:'uncertain',workflowId:typeof before.workflow_id==='string'?before.workflow_id:null};if(!before.workflow_id)return denied;
  if(lock)await tx.one('SELECT id FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 FOR UPDATE',[before.workflow_id,cid,wid]);
  let loaded:Awaited<ReturnType<typeof loadPublicationWorkflow>>;try{loaded=await loadPublicationWorkflow(tx,secrets,cid,wid,before.workflow_id);}catch(error){if(error instanceof ConflictException||error instanceof NotFoundException)return denied;throw error;}
  const {row,plan}=loaded,blocked:PublicationRecoveryProof={allowed:false,state:row.state,workflowId:row.id};
  if(row.state!=='failed'||plan.kind!=='portal-publication'||plan.subject.type!=='portal_publications'||plan.subject.id!==before.id||plan.scope.transportScope!==before.transport_scope)return blocked;
  const executions=await tx.query<any>('SELECT * FROM workflow_executions WHERE workflow_id=$1 ORDER BY started_at,id LIMIT 2',[row.id]);
  const steps=await tx.query<any>('SELECT * FROM workflow_steps WHERE workflow_id=$1 ORDER BY step_order LIMIT 17',[row.id]);
  if(executions.length!==1||steps.length!==plan.steps.length)return blocked;
  const execution=executions[0];if(execution.cluster_id!==cid||execution.workspace_id!==wid||execution.plan_revision!==row.plan_revision||execution.plan_hash!==row.plan_hash||execution.execution_mode!==plan.executionMode||execution.approval_required!==plan.approvalRequired||execution.state!=='failed'||plan.approvalRequired&&!execution.approved_by||!plan.approvalRequired&&execution.approved_by)return blocked;
  if(typeof execution.execution_actor_id!=='string'||typeof execution.idempotency_key!=='string')return blocked;
  const metadataKeys=plan.steps.filter(step=>step.kind==='metadata').map(step=>`metadata-${secrets.fingerprint({id:row.id,step:step.id,key:execution.idempotency_key}).slice(0,48)}`);
  if((await tx.query<any>('SELECT id FROM iam_operations WHERE cluster_id=$1 AND workspace_id=$2 AND actor_id=$3 AND idempotency_key=ANY($4::text[]) LIMIT 17',[cid,wid,execution.execution_actor_id,metadataKeys])).length)return blocked;
  const native=plan.steps.filter(step=>step.kind==='native'),keys=native.map(step=>step.mutationIdempotencyKey),ids=steps.flatMap(step=>[step.operation_id,step.safe_result?.nativeOperationId].filter(Boolean));
  const operations=await tx.query<any>('SELECT * FROM mutation_operations WHERE cluster_id=$1 AND (workflow_id=$2 OR idempotency_key=ANY($3::text[]) OR id=ANY($4::uuid[])) LIMIT 33',[cid,row.id,keys,ids]);
  if(operations.length>native.length)return blocked;
  const matched=new Set<string>();
  for(const expected of plan.steps){
    const step=steps.find(item=>item.id===expected.id);if(!step||step.cluster_id!==cid||step.workspace_id!==wid||step.workflow_id!==row.id||step.plan_revision!==row.plan_revision||step.plan_hash!==row.plan_hash||step.kind!==expected.kind||step.entity_type!==expected.entityType||(step.entity_id??null)!==(expected.entityId??null)||(step.parent_id??null)!==(expected.parentId??null)||(step.credential_kind??null)!==(expected.credentialKind??null)||step.mutation_action!==(expected.mutationAction??null)||step.mutation_idempotency_key!==(expected.mutationIdempotencyKey??null)||!['pending','failed'].includes(step.state)||step.after_fingerprint||step.recycle_entry_id||step.safe_result?.remoteCompleted===true)return blocked;
    if(step.state==='pending'&&(step.started_at||step.completed_at||step.receipt_secret||Object.keys(step.safe_result??{}).length)||step.state==='failed'&&!step.completed_at)return blocked;
    if(expected.kind==='metadata'){if(step.operation_id||step.safe_result?.nativeOperationId||step.state!=='pending')return blocked;continue;}
    const candidates=operations.filter(operation=>operation.idempotency_key===expected.mutationIdempotencyKey);if(candidates.length>1)return blocked;
    const operation=candidates[0];if(!operation){if(step.operation_id||step.safe_result?.nativeOperationId||step.safe_result?.remoteStarted===true||step.receipt_secret)return blocked;continue;}
    if(step.state!=='failed'||operation.actor_id!==execution.execution_actor_id||operation.cluster_id!==cid||operation.workspace_id!==wid||operation.transport_scope!==plan.scope.transportScope||operation.state!=='failed'||operation.remote_completed!==false||operation.action!==expected.mutationAction||operation.entity_type!==expected.entityType||(operation.parent_id??null)!==(expected.parentId??null)||(operation.credential_kind??null)!==(expected.credentialKind??null)||step.operation_id&&step.operation_id!==operation.id||step.safe_result?.nativeOperationId&&step.safe_result.nativeOperationId!==operation.id)return blocked;
    const bound=operation.workflow_execution_id!=null;if(bound!==plan.approvalRequired||bound&&(operation.workflow_id!==row.id||operation.workflow_execution_id!==execution.id||operation.workflow_plan_revision!==row.plan_revision||operation.workflow_plan_hash!==row.plan_hash||operation.workflow_step_id!==expected.id)||!bound&&[operation.workflow_id,operation.workflow_plan_revision,operation.workflow_plan_hash,operation.workflow_step_id].some(value=>value!=null))return blocked;
    let payload:any,original:any;try{payload=secrets.decrypt(operation.payload_secret,`mutation:${operation.id}:payload`);original=secrets.decrypt(operation.before_secret,`mutation:${operation.id}:before`);}catch{return blocked;}
    if(secrets.fingerprint(payload)!==expected.mutationPayloadHmac||secrets.fingerprint(original)!==expected.beforeFingerprint)return blocked;
    const binding=bound?{workflowId:row.id,executionId:execution.id,planRevision:row.plan_revision,planHash:row.plan_hash,stepId:expected.id,beforeHmac:expected.beforeFingerprint}:null;
    const hash=secrets.fingerprint({actor:execution.execution_actor_id,clusterId:cid,workspaceId:wid,entityType:expected.entityType,entityId:expected.mutationAction==='create'?null:expected.entityId??null,action:expected.mutationAction,payload:expected.mutationPayload??null,parentId:expected.parentId??null,credentialKind:expected.credentialKind??null,...(binding?{approvedWorkflow:binding}:{})});
    if(operation.request_hash!==hash||operation.entity_id&&operation.entity_id!==(expected.mutationAction==='create'?(expected.mutationPayload as any)?.id:expected.entityId))return blocked;matched.add(operation.id);
  }
  return{allowed:matched.size===operations.length,state:row.state,workflowId:row.id,summary:Object.freeze({workflow:secrets.fingerprint(row),executions:secrets.fingerprint(executions),steps:secrets.fingerprint(steps),nativeOperations:secrets.fingerprint(operations),metadataOperations:secrets.fingerprint([])})};
}
