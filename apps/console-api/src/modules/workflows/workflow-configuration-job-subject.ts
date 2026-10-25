import { ForbiddenException } from '@nestjs/common';

const fail=(code:string)=>new ForbiddenException({code});
const iso=(value:unknown):string=>{const time=new Date(value as any).getTime();if(!Number.isFinite(time))throw fail('WORKFLOW_SCHEDULE_CONFIGURATION_TIME_INVALID');return new Date(time).toISOString();};
const epoch=(value:unknown):number=>{const n=typeof value==='number'?value:typeof value==='string'&&/^[1-9][0-9]{0,9}$/.test(value)?Number(value):NaN;
  if(!Number.isSafeInteger(n)||n<1||n>2_147_483_647)throw fail('WORKFLOW_SCHEDULE_CONFIGURATION_EPOCH_INVALID');return n;};

/** Canonical immutable authoring facts shared by candidate sealing and the
 * original scheduled Origin. No current grant, execution state, renewed SID
 * or deadline is inferred. Preserve absent legacy domain keys byte-for-byte;
 * marked/partial domains are independently checked by the durable verifier. */
export function configurationJobSubjectMaterial(job:Readonly<Record<string,any>>):Readonly<Record<string,unknown>>{
  return{id:job.id,clusterId:job.cluster_id,workspaceId:job.workspace_id,actorId:job.actor_id,
    originType:job.origin_type,authoringSessionId:job.origin_session_id,authorityExpiresAt:iso(job.authority_expires_at),expiresAt:iso(job.expires_at),
    kind:job.kind,key:job.idempotency_key,requestHmac:job.request_hmac,inputCiphertext:job.input_secret??null,
    scopeKind:job.scope_kind,rootIds:job.root_ids,transportScope:job.transport_scope,permissionVersion:job.permission_version,
    credentialEpoch:epoch(job.credential_epoch),clusterRevision:job.cluster_revision,workspaceRevision:job.workspace_revision,
    captureEpoch:job.capture_epoch,executionMode:job.execution_mode,approvalRequired:job.approval_required,
    planId:job.plan_id,planRevision:job.plan_revision,planHash:job.plan_hash,workflowId:job.workflow_id,
    ...(job.authority_domain!=null||job.durable_issue_id!=null?{authorityDomain:job.authority_domain,durableIssueId:job.durable_issue_id}:{}),
    requiredOriginKind:job.required_origin_kind??null,requiredOriginId:job.required_origin_id??null,requiredOriginHmac:job.required_origin_hmac??null,
    createdAt:iso(job.created_at)};
}
