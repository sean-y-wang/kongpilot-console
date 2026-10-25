import {randomUUID} from 'node:crypto';
import type {DbService} from '../../apps/console-api/src/infrastructure/db.service';
import type {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {planAad} from '../../apps/console-api/src/modules/workflows/workflow.types';

/** Structural SQL fixture only. It supplies committed, distinct approval rows
 * and encrypted wrapper metadata to exercise actual PostgreSQL constraints.
 * It never mints Root authority or sends a native request. */
export async function installConfigurationSqlWrapper(input:{db:DbService;secrets:SecretService;clusterId:string;workspaceId:string;transportScope:string;actorId:string;jobId:string;planId:string;planRevision:number;planHash:string}){
 const{db,secrets,clusterId:cid,workspaceId:wid,actorId,jobId}=input,definitionId=randomUUID(),workflowId=randomUUID(),stepId=randomUUID(),approverId=randomUUID(),expiresAt=new Date(Date.now()+300000).toISOString();
 const metadata={jobId,planId:input.planId,planRevision:input.planRevision,planHash:input.planHash},before={id:jobId},policy={mode:'single',allowSelfApproval:false},policyHash=secrets.fingerprint(policy);
 const step={id:stepId,key:'configuration',order:1,kind:'metadata',handler:'configuration_v2',entityType:'configuration_jobs',entityId:jobId,permissionAction:'write',dependencies:[],nativeRequests:[],metadata,before,metadataRevision:input.planRevision,metadataBeforeHmac:secrets.fingerprint(before),metadataPayloadHmac:secrets.fingerprint(metadata)};
 const payload={version:1,clusterId:cid,workspaceId:wid,workflowId,planRevision:1,kind:'configuration_v2',executionMode:'approval',approvalRequired:true,subject:{type:'configuration_jobs',id:jobId},requester:{type:'console',id:actorId},definition:{id:definitionId,version:1,policyHash},issuedAt:new Date().toISOString(),expiresAt,scope:{transportScope:input.transportScope,clusterRevision:1,workspaceRevision:1},prerequisites:[],steps:[step]},wrapperHash=secrets.fingerprint(payload);
 await db.transaction(async tx=>{
  await tx.exec("INSERT INTO users(id,username,password_hash,status) VALUES($1,$2,$3,'active')",[approverId,'synthetic-m8-approver-'+approverId,secrets.fingerprint('synthetic-password-hash')]);
  await tx.exec("INSERT INTO workflow_definitions(id,cluster_id,workspace_id,code,name,kind,created_by) VALUES($1,$2,$3,$4,'Synthetic SQL wrapper','configuration_v2',$5)",[definitionId,cid,wid,'sql-'+definitionId,actorId]);
  await tx.exec('INSERT INTO workflow_definition_versions(cluster_id,workspace_id,definition_id,version,policy,policy_hash,created_by) VALUES($1,$2,$3,1,$4::jsonb,$5,$6)',[cid,wid,definitionId,JSON.stringify(policy),policyHash,actorId]);
  await tx.exec("INSERT INTO workflow_definition_stages(cluster_id,workspace_id,definition_id,definition_version,level,name) VALUES($1,$2,$3,1,1,'Synthetic distinct approval')",[cid,wid,definitionId]);
  await tx.exec(`INSERT INTO workflows(id,cluster_id,workspace_id,kind,subject_type,subject_id,requester_type,requester_user_id,definition_id,definition_version,plan_revision,plan_hash,execution_mode,approval_required,state,request_hash,idempotency_key,approved_by,approved_at,expires_at)
   VALUES($1,$2,$3,'configuration_v2','configuration_jobs',$4,'console',$5,$6,1,1,$7,'approval',true,'executing',$8,$9,$10,now(),$11)`,[workflowId,cid,wid,jobId,actorId,definitionId,wrapperHash,secrets.fingerprint(metadata),randomUUID(),approverId,expiresAt]);
  await tx.exec(`INSERT INTO workflow_versions(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,payload_secret,policy_version,step_count,native_request_count,steps_hash,expires_at,created_by)
   VALUES($1,$2,$3,1,$4,'approval',true,$5,1,1,0,$6,$7,$8)`,[cid,wid,workflowId,wrapperHash,secrets.encrypt(payload,planAad(cid,wid,workflowId,1)),secrets.fingerprint(payload.steps),expiresAt,actorId]);
  await tx.exec(`INSERT INTO workflow_steps(id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,step_key,step_order,kind,handler,entity_type,entity_id,permission_action,metadata_before_hmac,metadata_revision,metadata_payload_hmac,state)
   VALUES($1,$2,$3,$4,1,$5,'approval',true,'configuration',1,'metadata','configuration_v2','configuration_jobs',$6,'write',$7,$8,$9,'running')`,[stepId,cid,wid,workflowId,wrapperHash,jobId,step.metadataBeforeHmac,input.planRevision,step.metadataPayloadHmac]);
  await tx.exec("INSERT INTO workflow_stages(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level,state) VALUES($1,$2,$3,1,$4,1,'approved')",[cid,wid,workflowId,wrapperHash]);
  await tx.exec("INSERT INTO workflow_approvals(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level,approver_id,decision,idempotency_key) VALUES($1,$2,$3,1,$4,1,$5,'approve',$6)",[cid,wid,workflowId,wrapperHash,approverId,randomUUID()]);
  await tx.exec('UPDATE configuration_jobs SET workflow_id=$2,revision=revision+1 WHERE id=$1',[jobId,workflowId]);
 });
 return{workflowId,wrapperHash};
}
