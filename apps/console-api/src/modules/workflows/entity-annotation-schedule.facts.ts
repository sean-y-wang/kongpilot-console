import {EntityAnnotationScheduleRejected,ENTITY_ANNOTATION_SCHEDULED_KIND,ENTITY_ANNOTATION_SUBJECT_TYPE,type EntityAnnotationExecutionRecheck} from './entity-annotation-schedule.guard';
import type {WorkflowScheduleStored} from './workflow-schedule.contract';

/** SQL041 entity-annotation: production `load` port for the scheduled executor.
 * Every "current" fact is read from SQL inside the executor transaction:
 *  - users.status/deleted_at/force_password_change/credential_epoch/permissions_epoch (row locked FOR SHARE),
 *  - iam_epoch.version (FOR SHARE, same lock order as m11_business_claim),
 *  - entity_annotation_requests.material_hmac re-sealed through `seal` (HMAC domain owned by SecretService).
 * The sealed side comes only from the immutable stored schedule (draft/delegation/spec + sealed permission version).
 * `hasAnnotationWrite` is evaluated by the caller inside the original scheduled
 * namespace (AuthorizationService.assertCluster(...,'annotations','write',...)),
 * because current identity there is bound to that namespace, never to a copied principal. */
export interface EntityAnnotationFactsSql{one<T>(sql:string,params:readonly unknown[]):Promise<T|null>}
export interface EntityAnnotationFactsInput{
  readonly stored:Readonly<WorkflowScheduleStored>;
  readonly sealedPermissionVersion:string;
  readonly hasAnnotationWrite:()=>Promise<boolean>;
  readonly seal:(material:Readonly<{subjectId:string;materialHmac:string;workflowId:string}>)=>string;
}
const reject=(code:string):never=>{throw new EntityAnnotationScheduleRejected(code);};

export async function loadEntityAnnotationScheduleFacts(sql:EntityAnnotationFactsSql,input:EntityAnnotationFactsInput):Promise<Readonly<Omit<EntityAnnotationExecutionRecheck,'claim'>>>{
  const {draft,plan}=input.stored,b=draft.binding,d=draft.delegation;
  if(b.kind!==ENTITY_ANNOTATION_SCHEDULED_KIND||d.kind!==ENTITY_ANNOTATION_SCHEDULED_KIND||b.subjectType!==ENTITY_ANNOTATION_SUBJECT_TYPE
    ||d.subjectType!==ENTITY_ANNOTATION_SUBJECT_TYPE||b.subjectId!==d.subjectId||plan.kind!==ENTITY_ANNOTATION_SCHEDULED_KIND)reject('ANNOTATION_SCHEDULE_KIND');
  await sql.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE',[]);
  const iam=await sql.one<{version:string|number}>('SELECT version FROM iam_epoch WHERE singleton=true',[]);
  const user=await sql.one<{status:string;deleted_at:unknown;force_password_change:boolean;credential_epoch:string|number;permissions_epoch:string|number}>(
    'SELECT status,deleted_at,force_password_change,credential_epoch,permissions_epoch FROM users WHERE id=$1 FOR SHARE',[d.ownerId]);
  const request=await sql.one<{material_hmac:string;workflow_id:string;cluster_id:string;workspace_id:string}>(
    'SELECT material_hmac,workflow_id,cluster_id,workspace_id FROM entity_annotation_requests WHERE id=$1',[b.subjectId]);
  if(!iam||!user)reject('ANNOTATION_SCHEDULE_REQUESTER_INACTIVE');
  if(!request||request.cluster_id!==b.clusterId||request.workspace_id!==b.workspaceId||request.workflow_id!==b.workflowId)reject('ANNOTATION_SCHEDULE_SUBJECT_CHANGED');
  const active=user!.status==='active'&&user!.deleted_at==null&&user!.force_password_change!==true;
  return Object.freeze({
    admission:Object.freeze({kind:b.kind,executionMode:plan.executionMode,approvalRequired:plan.approvalRequired,subjectType:b.subjectType,subjectId:b.subjectId,
      requester:Object.freeze({...b.requester}),ownerId:d.ownerId,ownerCredentialEpoch:d.ownerCredentialEpoch,subjectSealHmac:d.subjectSealHmac,
      windowStart:draft.spec.windowStart,notBefore:draft.spec.notBefore,windowEnd:draft.spec.windowEnd,expiresAt:d.expiresAt}),
    sealedPermissionVersion:input.sealedPermissionVersion,
    currentSubjectSealHmac:input.seal({subjectId:b.subjectId,materialHmac:request!.material_hmac,workflowId:request!.workflow_id}),
    current:Object.freeze({userActive:active,credentialEpoch:String(user!.credential_epoch),permissionsEpoch:String(user!.permissions_epoch),
      iamEpoch:String(iam!.version),hasAnnotationWrite:active&&await input.hasAnnotationWrite()}),
  });
}
