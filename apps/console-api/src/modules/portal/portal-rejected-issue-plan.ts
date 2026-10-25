import { ConflictException } from '@nestjs/common';
import type { SecretService } from '../../infrastructure/secret.service';
import { normalizedNativeRequests } from '../workflows/approved-execution.types';
import { planAad, snapshotAad, type WorkflowPlanV1, type WorkflowSnapshotV1 } from '../workflows/workflow.types';
import { validateWorkflowPlan } from '../workflows/workflow-validation';
import { portalKeyAad } from './portal-proof';

export interface RejectedIssuePlanFacts {
  grant: any; workflow: any; execution: any; version: any; steps: any[]; operation: any; credential: any;
}
const invalid=()=>new ConflictException({code:'PORTAL_REJECTED_ISSUE_PROOF_INVALID',message:'失败发放的原始不可变计划证明不完整'});

/** Private validation of the failed original plan. It neither repairs the plan
 * nor mints an approved execution or a native write capability. */
export function validateRejectedIssuePlan(facts:RejectedIssuePlanFacts,secrets:SecretService):WorkflowPlanV1 {
  const {grant:g,workflow:w,execution:e,version:v,steps:rows,operation:op,credential:c}=facts;
  let plan:WorkflowPlanV1,snapshot:WorkflowSnapshotV1,key:any,before:any,payload:any;
  try{
    plan=secrets.decrypt(v.payload_secret,planAad(g.cluster_id,g.workspace_id,w.id,w.plan_revision));validateWorkflowPlan(plan);
    snapshot=secrets.decrypt(e.snapshot_secret,snapshotAad(g.cluster_id,g.workspace_id,w.id,e.id));
    key=secrets.decrypt(c.key_secret,portalKeyAad(g.cluster_id,g.workspace_id,c.id,1));
    before=secrets.decrypt(op.before_secret,`mutation:${op.id}:before`);payload=secrets.decrypt(op.payload_secret,`mutation:${op.id}:payload`);
  }catch{throw invalid();}
  const same=(a:unknown,b:unknown)=>secrets.fingerprint(a??null)===secrets.fingerprint(b??null);
  if(plan.kind!=='portal-credential-issue'||plan.subject.type!=='portal_application_grants'||plan.subject.id!==g.id
    ||plan.clusterId!==g.cluster_id||plan.workspaceId!==g.workspace_id||plan.workflowId!==w.id||plan.planRevision!==w.plan_revision
    ||plan.requester.type!=='developer'||plan.requester.id!==g.developer_id||w.requester_type!=='developer'||w.requester_developer_id!==g.developer_id
    ||plan.approvalRequired!==true||w.approval_required!==true||e.approval_required!==true||v.approval_required!==true
    ||plan.executionMode!==w.execution_mode||e.execution_mode!==w.execution_mode||v.execution_mode!==w.execution_mode
    ||plan.scope.transportScope!==g.transport_scope||w.plan_hash!==secrets.fingerprint(plan)||v.plan_hash!==w.plan_hash||e.plan_hash!==w.plan_hash
    ||v.steps_hash!==secrets.fingerprint(plan.steps)||v.step_count!==4||v.native_request_count!==3||plan.steps.length!==4||rows.length!==4
    ||plan.definition.id!==w.definition_id||plan.definition.version!==w.definition_version||v.policy_version!==plan.definition.version
    ||typeof key?.key!=='string'||secrets.fingerprint(key.key)!==c.key_fingerprint||c.generation!==1||c.grant_id!==g.id
    ||c.consumer_id!==g.consumer_id||c.workflow_id!==w.id||!plan.generated||plan.generated.key!==key.key
    ||plan.generated.consumerId!==g.consumer_id||plan.generated.aclId!==g.acl_id||plan.generated.credentialId!==c.kong_id
    ||plan.prerequisites.length!==1||plan.prerequisites[0].type!=='services')throw invalid();
  for(const [index,step]of plan.steps.entries()){
    const row=rows[index],kind=index===1?'acls':index===2?'key-auth':undefined,nativeId=index===0?g.consumer_id:index===1?g.acl_id:c.kong_id;
    if(row.id!==step.id||row.cluster_id!==g.cluster_id||row.workspace_id!==g.workspace_id||row.workflow_id!==w.id||row.plan_revision!==w.plan_revision||row.plan_hash!==w.plan_hash
      ||row.step_order!==step.order||row.step_key!==step.key||row.kind!==step.kind||row.entity_type!==step.entityType
      ||(row.entity_id??null)!==(step.entityId??null)||(row.parent_id??null)!==(step.parentId??null)||(row.credential_kind??null)!==(step.credentialKind??null)
      ||row.permission_action!==step.permissionAction||(row.mutation_action??null)!==(step.mutationAction??null)||(row.handler??null)!==(step.handler??null)
      ||(row.mutation_payload_hmac??null)!==(step.mutationPayloadHmac??null)||(row.mutation_idempotency_key??null)!==(step.mutationIdempotencyKey??null)
      ||(row.before_fingerprint??null)!==(step.beforeFingerprint??null)||(row.metadata_before_hmac??null)!==(step.metadataBeforeHmac??null)
      ||(row.metadata_revision??null)!==(step.metadataRevision??null)||(row.metadata_payload_hmac??null)!==(step.metadataPayloadHmac??null)
      ||row.execution_mode!==plan.executionMode||row.approval_required!==true||!same(row.dependencies,step.dependencies)
      ||!same(row.native_requests,normalizedNativeRequests(step.nativeRequests,secrets)))throw invalid();
    if(index<3){
      const request=step.nativeRequests[0];
      if(step.kind!=='native'||step.entityType!==(index?'credentials':'consumers')||step.mutationAction!=='create'||step.entityId!=null
        ||step.permissionAction!=='write'||step.before!=null||step.beforeFingerprint!==secrets.fingerprint(null)
        ||step.parentId!==(index?g.consumer_id:undefined)||step.credentialKind!==kind||step.nativeRequests.length!==1
        ||!same(step.dependencies,index?[plan.steps[index-1].id]:[])||request.method!=='POST'||request.nativeId!==nativeId
        ||request.nativeType!==(kind??'consumers')||request.parentId!==step.parentId||request.credentialKind!==kind
        ||request.canonicalPath!==(index?`/consumers/${g.consumer_id}/${kind}`:'/consumers')||(request.body as any)?.id!==nativeId
        ||step.mutationPayloadHmac!==secrets.fingerprint(step.mutationPayload)||request.bodyHmac!==step.mutationPayloadHmac||!same(request.body,step.mutationPayload))throw invalid();
    }else{
      const metadata:any=step.metadata;
      if(step.kind!=='metadata'||step.handler!=='portal.credential.activate'||step.entityType!=='portal_application_grants'||step.entityId!==g.id
        ||step.nativeRequests.length||step.permissionAction!=='write'||!same(step.dependencies,[plan.steps[2].id])
        ||step.metadataBeforeHmac!==secrets.fingerprint(step.before)||step.metadataRevision!==(step.before as any)?.revision
        ||step.metadataPayloadHmac!==secrets.fingerprint(metadata)||metadata?.action!=='issue'||metadata.generation!==1
        ||metadata.credentialId!==c.id||metadata.kongId!==c.kong_id||metadata.consumerId!==g.consumer_id||metadata.aclId!==g.acl_id||metadata.keyFingerprint!==c.key_fingerprint)throw invalid();
    }
  }
  const first=plan.steps[0],binding={workflowId:w.id,executionId:e.id,planRevision:w.plan_revision,planHash:w.plan_hash,stepId:first.id,beforeHmac:first.beforeFingerprint};
  if(before!==null||!same(payload,first.mutationPayload)||op.request_hash!==secrets.fingerprint({actor:e.execution_actor_id,clusterId:g.cluster_id,workspaceId:g.workspace_id,
    entityType:'consumers',entityId:null,action:'create',payload:first.mutationPayload??null,parentId:null,credentialKind:null,approvedWorkflow:binding})
    ||op.idempotency_key!==first.mutationIdempotencyKey||op.transport_scope!==plan.scope.transportScope||op.result_secret)throw invalid();
  if(!snapshot||snapshot.version!==1||snapshot.workflowId!==w.id||snapshot.executionId!==e.id||snapshot.clusterId!==g.cluster_id||snapshot.workspaceId!==g.workspace_id
    ||snapshot.planRevision!==w.plan_revision||snapshot.planHash!==w.plan_hash||secrets.fingerprint(snapshot)!==e.snapshot_hash
    ||!Array.isArray(snapshot.objects)||snapshot.objects.length!==4||e.snapshot_state!=='ready')throw invalid();
  const expected=[...plan.prerequisites.map(p=>({path:p.path,type:p.type,id:p.id,before:p.before,fingerprint:p.fingerprint})),...plan.steps.slice(0,3).map(s=>({path:`${s.nativeRequests[0].canonicalPath}/${s.nativeRequests[0].nativeId}`,type:s.nativeRequests[0].nativeType,id:s.nativeRequests[0].nativeId,before:null,fingerprint:secrets.fingerprint(null)}))];
  const seen=new Set<string>();for(const object of snapshot.objects){
    const match=expected.find(item=>item.path===object.path);if(!match||seen.has(object.path)||object.type!==match.type||object.id!==match.id||object.absent!==(match.before===null)
      ||!same(object.before,match.before)||object.fingerprint!==match.fingerprint||object.fingerprint!==secrets.fingerprint(object.before??null))throw invalid();seen.add(object.path);
  }
  return plan;
}
